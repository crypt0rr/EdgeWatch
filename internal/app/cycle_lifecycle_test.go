package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// lifecycleScanner is a deterministic resumable scanner. Unit 1 fails with a
// transient error on its first call, so the first trigger leaves a paused
// cycle behind. Every call records the job it received so tests can assert
// which scanner-profile arguments a resumed unit used.
type lifecycleScanner struct {
	mu    sync.Mutex
	calls map[int]int
	jobs  []config.Job
}

func (s *lifecycleScanner) Version(context.Context) string { return "lifecycle" }
func (s *lifecycleScanner) Scan(context.Context, config.Job) (model.Snapshot, error) {
	return model.Snapshot{}, errors.New("ordinary scan path is not expected")
}
func (s *lifecycleScanner) Plan(context.Context, config.Job) (scanner.WorkPlan, error) {
	target := []scanner.ResolvedTarget{{Name: "192.0.2.1", ConfiguredTarget: "192.0.2.1", Addresses: []string{"192.0.2.1"}}}
	return scanner.WorkPlan{CreatedAt: time.Now().UTC(), Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-2"}}, Units: []scanner.WorkUnit{
		{Sequence: 0, Protocol: "tcp", Family: 4, Targets: target, Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1},
		{Sequence: 1, Protocol: "tcp", Family: 4, Targets: target, Addresses: []string{"192.0.2.1"}, Ports: "2", PortCount: 1, Probes: 1},
	}, TotalUnits: 2, TotalProbes: 2}, nil
}
func (s *lifecycleScanner) ScanWorkUnit(_ context.Context, job config.Job, unit scanner.WorkUnit, _ scanner.ProgressReporter) (model.Snapshot, error) {
	s.mu.Lock()
	if s.calls == nil {
		s.calls = map[int]int{}
	}
	s.calls[unit.Sequence]++
	call := s.calls[unit.Sequence]
	s.jobs = append(s.jobs, job)
	s.mu.Unlock()
	if unit.Sequence == 1 && call == 1 {
		return model.Snapshot{}, errors.New("nmap failed: transient connection reset")
	}
	port, err := strconv.Atoi(unit.Ports)
	if err != nil {
		return model.Snapshot{}, err
	}
	return model.Snapshot{Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Addresses: unit.Addresses, Ports: []model.PortState{{Port: port, State: "open"}}}}}, nil
}

func (s *lifecycleScanner) lastJob() config.Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.jobs) == 0 {
		return config.Job{}
	}
	return s.jobs[len(s.jobs)-1]
}

func newLifecycleTestApp(t *testing.T, sc Scanner, logs io.Writer) (*App, *store.Store) {
	t.Helper()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if logs == nil {
		logs = io.Discard
	}
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Scanner = sc
	return a, db
}

func lifecycleJob(name string) config.Job {
	return config.NormalizeJob(config.Job{Name: name, Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1-2", Mode: "connect"}, Timeout: config.Duration(time.Minute), ResumeWindow: config.Duration(time.Hour), Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}})
}

func hasEventType(events []model.Event, eventType string) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func TestAcceptedIncidentDuringPausedCycleStartsFreshCycle(t *testing.T) {
	ctx := context.Background()
	a, db := newLifecycleTestApp(t, &lifecycleScanner{}, nil)
	record, err := db.CreateJob(ctx, lifecycleJob("accept-paused"))
	if err != nil {
		t.Fatal(err)
	}
	key := "port|192.0.2.1|tcp|2"
	now := time.Now().UTC()
	if _, err := db.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-2"}}, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}}}}}
		state.BaselineConfigHash = record.Job.SecurityHash()
		state.Incidents[key] = model.Incident{Change: model.Change{Key: key, Kind: "port", Target: "192.0.2.1", Protocol: "tcp", Port: 2, Old: "not-open", New: "open", Severity: "critical"}, ScanID: "seed-scan", OpenedAt: now, LastSeenAt: now}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}

	paused, _, pausedErr := a.runJobRecord(ctx, record, false)
	if pausedErr == nil || paused.CycleStatus != "paused" {
		t.Fatalf("first trigger = %#v, err=%v", paused, pausedErr)
	}
	if _, err := db.AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, key, store.AuditEntry{Action: "incident.accepted", Detail: key}); err != nil {
		t.Fatal(err)
	}
	before, err := db.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}

	next, events, nextErr := a.runJobRecord(ctx, record, false)
	if nextErr != nil || next.Status == "failed" {
		t.Fatalf("trigger after accept = %#v, err=%v", next, nextErr)
	}
	if hasEventType(events, "scan-failure") {
		t.Fatalf("trigger after accept emitted a scan failure: %#v", events)
	}
	if next.CycleID == "" || next.CycleID == paused.CycleID {
		t.Fatalf("trigger after accept did not start a fresh cycle: %#v", next)
	}
	after, err := db.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.ConsecutiveFailures != before.ConsecutiveFailures {
		t.Fatalf("consecutive failures changed from %d to %d", before.ConsecutiveFailures, after.ConsecutiveFailures)
	}
	old, err := db.GetScanCycle(ctx, paused.CycleID)
	if err != nil {
		t.Fatal(err)
	}
	if old.Status != "discarded" || !strings.Contains(old.LastError, "incident accepted") {
		t.Fatalf("paused cycle after accept = status %q last_error %q", old.Status, old.LastError)
	}
}

func TestResumedCycleRecordsPinnedScannerProfileRevision(t *testing.T) {
	ctx := context.Background()
	probe := &lifecycleScanner{}
	a, db := newLifecycleTestApp(t, probe, nil)
	job := lifecycleJob("profile-pinned")
	job.TCP.ProfileID, job.TCP.ProfileRevision = "custom", 1
	job.TCP.NmapArgs = []string{config.PlaceholderAddress, config.PlaceholderPorts, config.PlaceholderStructuredOutput, "--max-rate", "1000"}
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	paused, _, pausedErr := a.runJobRecord(ctx, record, false)
	if pausedErr == nil || paused.CycleStatus != "paused" {
		t.Fatalf("first trigger = %#v, err=%v", paused, pausedErr)
	}

	edited := record.Job
	edited.TCP = &config.Protocol{}
	*edited.TCP = *record.Job.TCP
	edited.TCP.ProfileRevision = 2
	edited.TCP.NmapArgs = []string{config.PlaceholderAddress, config.PlaceholderPorts, config.PlaceholderStructuredOutput, "--max-rate", "10"}
	updated, _, err := db.UpdateJob(ctx, record.ID, record.Revision, edited, true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if cycle, err := db.GetActiveScanCycle(ctx, record.ID); err != nil || cycle.ID != paused.CycleID {
		t.Fatalf("execution-only edit did not keep the paused cycle: %#v, %v", cycle, err)
	}

	resumed, _, resumedErr := a.runJobRecord(ctx, updated, false)
	if resumedErr != nil || resumed.Status != "success" || resumed.CycleID != paused.CycleID {
		t.Fatalf("resumed trigger = %#v, err=%v", resumed, resumedErr)
	}
	used := probe.lastJob()
	if used.TCP == nil || strings.Join(used.TCP.NmapArgs, " ") != "{address} {ports} {structured_output} --max-rate 1000" || used.TCP.ProfileRevision != 1 {
		t.Fatalf("resumed unit job = %#v", used.TCP)
	}
	var jobRevision, profileRevision int64
	var profileID string
	if err := db.DB.QueryRowContext(ctx, `SELECT job_revision,scanner_profile_id,scanner_profile_revision FROM scans WHERE id=?`, resumed.ID).Scan(&jobRevision, &profileID, &profileRevision); err != nil {
		t.Fatal(err)
	}
	if profileID != "custom" || profileRevision != used.TCP.ProfileRevision || jobRevision != record.Revision {
		t.Fatalf("stored scan provenance = job revision %d profile %s revision %d; resumed units ran job revision %d profile revision %d", jobRevision, profileID, profileRevision, record.Revision, used.TCP.ProfileRevision)
	}
}

func TestStalledCyclePastResumeWindowExpiresOnScheduledTrigger(t *testing.T) {
	ctx := context.Background()
	probe := &lifecycleScanner{}
	a, db := newLifecycleTestApp(t, probe, nil)
	record, err := db.CreateJob(ctx, lifecycleJob("stalled-expiry"))
	if err != nil {
		t.Fatal(err)
	}
	paused, _, pausedErr := a.runJobRecord(ctx, record, false)
	if pausedErr == nil || paused.CycleStatus != "paused" {
		t.Fatalf("first trigger = %#v, err=%v", paused, pausedErr)
	}
	if _, err := db.MarkScanCycleStalled(ctx, paused.CycleID, "operator attention required"); err != nil {
		t.Fatal(err)
	}
	// Inside the resume window a scheduled trigger still waits for an
	// operator decision.
	if _, _, err := a.runJobRecord(ctx, record, false); !errors.Is(err, ErrScanCycleStalled) {
		t.Fatalf("scheduled trigger inside the resume window = %v, want %v", err, ErrScanCycleStalled)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE scan_cycles SET expires_at=? WHERE id=?`, time.Now().UTC().Add(-time.Hour).Format("2006-01-02T15:04:05.000000000Z07:00"), paused.CycleID); err != nil {
		t.Fatal(err)
	}

	expired, events, expiredErr := a.runJobRecord(ctx, record, false)
	if errors.Is(expiredErr, ErrScanCycleStalled) || expired.Status != "timed_out" || expired.CycleID != paused.CycleID || expired.CycleStatus != "expired" {
		t.Fatalf("scheduled trigger after the resume window = %#v, err=%v", expired, expiredErr)
	}
	if !hasEventType(events, "scan-failure") {
		t.Fatalf("expiry was not reported: %#v", events)
	}
	if cycle, err := db.GetScanCycle(ctx, paused.CycleID); err != nil || cycle.Status != "expired" {
		t.Fatalf("stalled cycle after expiry = %#v, %v", cycle, err)
	}

	fresh, _, freshErr := a.runJobRecord(ctx, record, false)
	if errors.Is(freshErr, ErrScanCycleStalled) || fresh.CycleID == "" || fresh.CycleID == paused.CycleID {
		t.Fatalf("trigger after recorded expiry = %#v, err=%v", fresh, freshErr)
	}
	scans, err := db.ListJobScans(ctx, record.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	expiryRecords := 0
	for _, scan := range scans {
		if scan.CycleID == paused.CycleID && scan.CycleStatus == "expired" {
			expiryRecords++
		}
	}
	if expiryRecords != 1 {
		t.Fatalf("expiry records = %d, want 1", expiryRecords)
	}
}

// waitForQueuedRun blocks until a run for key has marked itself active, which
// happens before it waits for a scan slot.
func waitForQueuedRun(t *testing.T, a *App, key string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := a.active.Load(key); ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("run for %s never queued", key)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestQueuedRunsUseJobEditedWhileWaitingForSlot(t *testing.T) {
	for _, manual := range []bool{false, true} {
		name := "scheduled"
		if manual {
			name = "manual"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			a, db := newLifecycleTestApp(t, schedulerFake{}, nil)
			record, err := db.CreateJob(ctx, lifecycleJob("queued-"+name))
			if err != nil {
				t.Fatal(err)
			}
			releaseSlot := holdScanSlot(t, a)
			type result struct {
				scan model.Scan
				err  error
			}
			done := make(chan result, 1)
			if manual {
				if err := a.StartManagedRun(record.ID, func(scan model.Scan, _ []model.Event, err error) {
					done <- result{scan, err}
				}); err != nil {
					t.Fatal(err)
				}
			} else {
				go func() {
					scan, _, err := a.runJobRecord(ctx, record, false)
					done <- result{scan, err}
				}()
			}
			waitForQueuedRun(t, a, record.ID)
			edited := record.Job
			edited.Name = "queued-" + name + "-renamed"
			edited.Schedule = "30 * * * *"
			updated, _, err := db.UpdateJob(ctx, record.ID, record.Revision, edited, true, false, false)
			if err != nil {
				t.Fatal(err)
			}
			releaseSlot()
			got := <-done
			if got.err != nil || got.scan.ID == "" || got.scan.JobRevision != updated.Revision || got.scan.Job != edited.Name {
				t.Fatalf("queued run = %#v, err=%v", got.scan, got.err)
			}
			scans, err := db.ListJobScans(ctx, record.ID, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(scans) != 1 || scans[0].JobRevision != updated.Revision {
				t.Fatalf("persisted scans = %#v", scans)
			}
		})
	}
}

func TestQueuedScheduledRunSkipsJobArchivedOrPausedWhileWaiting(t *testing.T) {
	for _, archive := range []bool{false, true} {
		name := "paused"
		if archive {
			name = "archived"
		}
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			var logMu sync.Mutex
			a, db := newLifecycleTestApp(t, schedulerFake{}, &lockedWriter{mu: &logMu, w: &logs})
			ctx, _ := a.BeginRun(context.Background())
			defer a.StopRun()
			record, err := db.CreateJob(ctx, lifecycleJob("queued-skip-"+name))
			if err != nil {
				t.Fatal(err)
			}
			releaseSlot := holdScanSlot(t, a)
			a.startManagedScheduled(ctx, record.ID)
			waitForQueuedRun(t, a, record.ID)
			if archive {
				err = db.SetJobArchived(ctx, record.ID, true)
			} else {
				err = db.SetJobEnabled(ctx, record.ID, false)
			}
			if err != nil {
				t.Fatal(err)
			}
			releaseSlot()
			a.wg.Wait()
			scans, err := db.ListJobScans(ctx, record.ID, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(scans) != 0 {
				t.Fatalf("skipped run persisted scans: %#v", scans)
			}
			logMu.Lock()
			output := logs.String()
			logMu.Unlock()
			if !strings.Contains(output, "scheduled run skipped") || !strings.Contains(output, name) {
				t.Fatalf("skip log = %q", output)
			}
		})
	}
}

// holdScanSlot takes a scan slot as a job would, so queued runs wait for it.
func holdScanSlot(t *testing.T, a *App) func() {
	t.Helper()
	release, err := a.slots.Acquire(context.Background(), defaultSlotKey)
	if err != nil {
		t.Fatal(err)
	}
	return release
}

// waitForSlotQueue blocks until n runs wait for a scan slot.
func waitForSlotQueue(t *testing.T, a *App, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for a.slots.CapacitySnapshot().Queued != n {
		if time.Now().After(deadline) {
			t.Fatalf("%d runs never queued for a scan slot: %#v", n, a.slots.CapacitySnapshot())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// gatedScanner reports each scan it starts and holds it until the test lets
// it finish.
type gatedScanner struct {
	started chan string
	finish  chan struct{}
}

func (gatedScanner) Version(context.Context) string { return "gated" }
func (s gatedScanner) Scan(ctx context.Context, job config.Job) (model.Snapshot, error) {
	s.started <- job.Name
	select {
	case <-s.finish:
		return model.Snapshot{}, nil
	case <-ctx.Done():
		return model.Snapshot{}, ctx.Err()
	}
}

func TestQueuedRunsStartInArrivalOrderWithOneSlot(t *testing.T) {
	ctx := context.Background()
	sc := gatedScanner{started: make(chan string, 2), finish: make(chan struct{})}
	a, db := newLifecycleTestApp(t, sc, nil)
	first, err := db.CreateJob(ctx, lifecycleJob("slot-first"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.CreateJob(ctx, lifecycleJob("slot-second"))
	if err != nil {
		t.Fatal(err)
	}
	releaseSlot := holdScanSlot(t, a)
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go func() {
		_, _, err := a.runJobRecord(ctx, first, false)
		firstDone <- err
	}()
	waitForSlotQueue(t, a, 1)
	go func() {
		_, _, err := a.runJobRecord(ctx, second, false)
		secondDone <- err
	}()
	waitForSlotQueue(t, a, 2)
	releaseSlot()

	receiveStarted := func() string {
		t.Helper()
		select {
		case name := <-sc.started:
			return name
		case <-time.After(10 * time.Second):
			t.Fatal("no queued run started")
			return ""
		}
	}
	if got := receiveStarted(); got != first.Job.Name {
		t.Fatalf("first scan started = %q, want %q", got, first.Job.Name)
	}
	// max_concurrent_scans is 1, so the second run waits while the first scans.
	want := slotSnapshot{Capacity: 1, InUse: 1, Queued: 1, Keys: map[string]slotUsage{defaultSlotKey: {InUse: 1, Queued: 1, Limit: 1}}}
	if got := a.slots.CapacitySnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("slots while the first run scans = %#v, want %#v", got, want)
	}
	sc.finish <- struct{}{}
	if err := <-firstDone; err != nil {
		t.Fatalf("first run: %v", err)
	}
	if got := receiveStarted(); got != second.Job.Name {
		t.Fatalf("second scan started = %q, want %q", got, second.Job.Name)
	}
	sc.finish <- struct{}{}
	if err := <-secondDone; err != nil {
		t.Fatalf("second run: %v", err)
	}
	if got := a.slots.CapacitySnapshot(); got.InUse != 0 || got.Queued != 0 || len(got.Keys) != 0 {
		t.Fatalf("slots after both runs = %#v", got)
	}
}

func TestCanceledQueuedManualRunReleasesNoSlot(t *testing.T) {
	a, db := newLifecycleTestApp(t, schedulerFake{}, nil)
	ctx, _ := a.BeginRun(context.Background())
	record, err := db.CreateJob(ctx, lifecycleJob("slot-canceled"))
	if err != nil {
		t.Fatal(err)
	}
	releaseSlot := holdScanSlot(t, a)
	done := make(chan error, 1)
	if err := a.StartManagedRun(record.ID, func(_ model.Scan, _ []model.Event, err error) {
		done <- err
	}); err != nil {
		t.Fatal(err)
	}
	waitForSlotQueue(t, a, 1)
	// Stopping cancels the queued manual run and waits for it to return.
	a.StopRun()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled queued run error = %v, want %v", err, context.Canceled)
	}
	// The run never held a slot, so the slot this test holds is still in use
	// and nobody else can take it.
	want := slotSnapshot{Capacity: 1, InUse: 1, Keys: map[string]slotUsage{defaultSlotKey: {InUse: 1, Limit: 1}}}
	if got := a.slots.CapacitySnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("slots after cancel = %#v, want %#v", got, want)
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if release, err := a.slots.Acquire(waitCtx, defaultSlotKey); !errors.Is(err, context.DeadlineExceeded) {
		if release != nil {
			release()
		}
		t.Fatalf("acquire while the slot is held = %v, want %v", err, context.DeadlineExceeded)
	}
	releaseSlot()
	if got := a.slots.CapacitySnapshot(); got.InUse != 0 || got.Queued != 0 || len(got.Keys) != 0 {
		t.Fatalf("slots after release = %#v", got)
	}
	scans, err := db.ListJobScans(context.Background(), record.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 0 {
		t.Fatalf("canceled queued run persisted scans: %#v", scans)
	}
}

func TestQueuedManagedJobKeepsUnchangedRevisionAndManualRunsOfPausedJobs(t *testing.T) {
	ctx := context.Background()
	a, db := newLifecycleTestApp(t, schedulerFake{}, nil)
	record, err := db.CreateJob(ctx, lifecycleJob("queued-helper"))
	if err != nil {
		t.Fatal(err)
	}
	// An unchanged revision keeps the definition the caller captured.
	captured := record.Job
	captured.Timing = "fast"
	job, revision, err := a.queuedManagedJob(ctx, captured, record.ID, record.Revision, false)
	if err != nil || revision != record.Revision || job.Timing != "fast" {
		t.Fatalf("unchanged revision = %q revision %d, %v", job.Timing, revision, err)
	}
	if err := db.SetJobEnabled(ctx, record.ID, false); err != nil {
		t.Fatal(err)
	}
	// A manual run may start a paused job, so it continues with the current
	// revision; a scheduled run is skipped.
	job, revision, err = a.queuedManagedJob(ctx, record.Job, record.ID, record.Revision, true)
	if err != nil || revision != record.Revision+1 || job.Name != record.Job.Name {
		t.Fatalf("manual run of paused job = %q revision %d, %v", job.Name, revision, err)
	}
	if _, _, err := a.queuedManagedJob(ctx, record.Job, record.ID, record.Revision, false); !errors.Is(err, ErrQueuedRunSkipped) {
		t.Fatalf("scheduled run of paused job error = %v, want %v", err, ErrQueuedRunSkipped)
	}
	if _, _, err := a.queuedManagedJob(ctx, record.Job, "missing-job", 1, true); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing job error = %v, want %v", err, store.ErrNotFound)
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}
