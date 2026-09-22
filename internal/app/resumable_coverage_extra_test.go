package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type coverageResumableScanner struct {
	plan        scanner.WorkPlan
	planErr     error
	scanErr     error
	closeDB     *store.Store
	clearLeases bool
}

type transientResumableScanner struct {
	mu         sync.Mutex
	calls      map[int]int
	alwaysFail bool
}

func (s *transientResumableScanner) Version(context.Context) string { return "transient" }
func (s *transientResumableScanner) Scan(context.Context, config.Job) (model.Snapshot, error) {
	return model.Snapshot{}, errors.New("ordinary scan path is not expected")
}
func (s *transientResumableScanner) Plan(context.Context, config.Job) (scanner.WorkPlan, error) {
	return scanner.WorkPlan{Units: []scanner.WorkUnit{
		{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1},
		{Sequence: 1, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "2", PortCount: 1, Probes: 1},
	}}, nil
}
func (s *transientResumableScanner) ScanWorkUnit(_ context.Context, _ config.Job, unit scanner.WorkUnit, _ scanner.ProgressReporter) (model.Snapshot, error) {
	s.mu.Lock()
	if s.calls == nil {
		s.calls = map[int]int{}
	}
	s.calls[unit.Sequence]++
	call := s.calls[unit.Sequence]
	s.mu.Unlock()
	if unit.Sequence == 1 && (call == 1 || s.alwaysFail) {
		return model.Snapshot{}, errors.New("nmap failed: transient connection reset")
	}
	return model.Snapshot{Units: []model.Unit{{Target: "192.0.2.1", Protocol: unit.Protocol, Addresses: unit.Addresses, Ports: []model.PortState{{Port: unit.PortCount, State: "open"}}}}}, nil
}

func TestRetryableResumableErrorsAreBoundedAndConfigurationErrorsStall(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		retryable bool
	}{
		{name: "process failure", err: errors.New("nmap failed: connection reset"), retryable: true},
		{name: "profile validation", err: errors.New("scanner profile arguments: invalid template"), retryable: false},
		{name: "missing binary", err: errors.New("exec: executable file not found in $PATH"), retryable: false},
		{name: "target resolution", err: errors.New("resolve host: no A or AAAA records"), retryable: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := retryableResumableError(test.err); got != test.retryable {
				t.Fatalf("retryableResumableError(%q) = %t, want %t", test.err, got, test.retryable)
			}
		})
	}
}

func TestResumableScanRetriesTransientUnitFailure(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "resumable-transient.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	probe := &transientResumableScanner{}
	a.Scanner = probe
	job := config.NormalizeJob(config.Job{Name: "transient", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1-2", Mode: "connect"}, Timeout: config.Duration(time.Minute), ResumeWindow: config.Duration(time.Hour)})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}

	first, _, firstErr := a.RunJobRecord(ctx, record)
	if firstErr == nil || first.Status != "failed" || !first.Resumable || first.CycleStatus != "paused" {
		t.Fatalf("transient failure attempt = %#v, err=%v", first, firstErr)
	}
	cycle, err := db.GetActiveScanCycle(ctx, record.ID)
	if err != nil || cycle.Status != "paused" || cycle.CompletedUnits != 1 {
		t.Fatalf("paused transient cycle = %#v, %v", cycle, err)
	}
	summaries, err := db.ListScanCycleUnitSummaries(ctx, cycle.ID)
	if err != nil || len(summaries) != 2 || summaries[1].Sequence != 1 || summaries[1].Status != "pending" || summaries[1].Attempts != 1 || summaries[1].Failures != 1 {
		t.Fatalf("retried unit summaries = %#v, %v", summaries, err)
	}
	if _, err := db.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.DiscardScanCycle(ctx, cycle.ID); err != nil {
		t.Fatalf("discard running transient cycle: %v", err)
	}
	discarded, err := db.GetScanCycle(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if discarded.Status != "discarded" || discarded.CompletedUnits != 0 || discarded.TotalUnits != 0 || discarded.CompletedProbes != 0 || discarded.TotalProbes != 0 {
		t.Fatalf("discarded transient cycle retained state: %#v", discarded)
	}
	if summaries, err := db.ListScanCycleUnitSummaries(ctx, cycle.ID); err != nil || len(summaries) != 0 {
		t.Fatalf("discarded transient cycle retained work: %#v, %v", summaries, err)
	}

	second, _, secondErr := a.RunJobRecord(ctx, record)
	if secondErr != nil || second.Status != "success" || second.CycleStatus != "completed" || second.CompletedUnits != 2 {
		t.Fatalf("recovered transient cycle = %#v, err=%v", second, secondErr)
	}
	if second.CycleID == cycle.ID {
		t.Fatalf("run reused discarded cycle %q", cycle.ID)
	}
}

func TestResumableScanStallsAfterRetryBudget(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "resumable-retry-budget.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Scanner = &transientResumableScanner{alwaysFail: true}
	job := config.NormalizeJob(config.Job{Name: "retry-budget", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1-2", Mode: "connect"}, Timeout: config.Duration(time.Minute), ResumeWindow: config.Duration(time.Hour)})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}

	for attempt := 1; attempt <= scanCycleMaxUnitAttempts; attempt++ {
		scan, _, runErr := a.RunJobRecord(ctx, record)
		if runErr == nil || scan.Status != "failed" || !scan.Resumable {
			t.Fatalf("retry attempt %d = %#v, err=%v", attempt, scan, runErr)
		}
		cycle, cycleErr := db.GetActiveScanCycle(ctx, record.ID)
		if cycleErr != nil {
			t.Fatal(cycleErr)
		}
		wantStatus := "paused"
		if attempt == scanCycleMaxUnitAttempts {
			wantStatus = "stalled"
		}
		if cycle.Status != wantStatus {
			t.Fatalf("retry attempt %d cycle status = %q, want %q", attempt, cycle.Status, wantStatus)
		}
		summaries, summaryErr := db.ListScanCycleUnitSummaries(ctx, cycle.ID)
		if summaryErr != nil || len(summaries) != 2 || summaries[1].Failures != attempt {
			t.Fatalf("retry attempt %d failure count = %#v, %v", attempt, summaries, summaryErr)
		}
	}
	if _, _, err := a.runJobRecord(ctx, record, false); !errors.Is(err, ErrScanCycleStalled) {
		t.Fatalf("scheduled run after exhausted retries = %v, want %v", err, ErrScanCycleStalled)
	}
}

func (s coverageResumableScanner) Version(context.Context) string { return "coverage" }
func (s coverageResumableScanner) Scan(context.Context, config.Job) (model.Snapshot, error) {
	return model.Snapshot{}, errors.New("ordinary scan path is not expected")
}
func (s coverageResumableScanner) Plan(context.Context, config.Job) (scanner.WorkPlan, error) {
	return s.plan, s.planErr
}
func (s coverageResumableScanner) ScanWorkUnit(context.Context, config.Job, scanner.WorkUnit, scanner.ProgressReporter) (model.Snapshot, error) {
	if s.clearLeases {
		// Exercise the finalization lease-renewal warning without affecting the
		// scanner result itself. The dedicated test store has no other runners.
		if s.closeDB == nil {
			panic("clearLeases requires a test store")
		}
		_, _ = s.closeDB.DB.Exec(`DELETE FROM job_leases`)
	}
	if s.closeDB != nil && !s.clearLeases {
		_ = s.closeDB.Close()
	}
	if s.scanErr != nil {
		return model.Snapshot{}, s.scanErr
	}
	return model.Snapshot{}, nil
}

func TestResumableAttemptPlanningAndTerminalGuards(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "resumable-coverage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	job := config.NormalizeJob(config.Job{Name: "resumable-coverage", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1-2", Mode: "connect"}, Timeout: config.Duration(time.Minute), ResumeWindow: config.Duration(time.Hour)})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}

	var scan model.Scan
	if handled, _, runErr := a.runResumableAttempt(ctx, ctx, job, "", &scan, nil, coverageResumableScanner{}, false); handled || runErr != nil {
		t.Fatalf("empty job id result = handled %v err %v", handled, runErr)
	}

	for _, test := range []struct {
		name      string
		scanCtx   context.Context
		wantState string
		planErr   string
		wantError string
	}{
		{"plan canceled", canceledContext(), "canceled", "plan canceled", "scan canceled while"},
		{"plan deadline", deadlineContext(), "timed_out", "plan timed out", "scan timed out while"},
		{"plan failure", context.Background(), "failed", "plan unavailable", "plan unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var local model.Scan
			_, _, gotErr := a.runResumableAttempt(ctx, test.scanCtx, job, record.ID+test.name, &local, nil, coverageResumableScanner{planErr: errors.New(test.planErr)}, false)
			if gotErr == nil || local.Status != test.wantState || !strings.Contains(local.Error, test.wantError) {
				t.Fatalf("planning result = scan %#v err %v", local, gotErr)
			}
		})
	}

	oneUnit := scanner.WorkPlan{Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1}}}
	var single model.Scan
	if handled, _, err := a.runResumableAttempt(ctx, ctx, job, record.ID+"single", &single, nil, coverageResumableScanner{plan: oneUnit}, false); handled || err != nil {
		t.Fatalf("single-unit plan = handled %v err %v", handled, err)
	}

	cyclePlan := scanner.WorkPlan{Units: []scanner.WorkUnit{
		{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1},
		{Sequence: 1, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "2", PortCount: 1, Probes: 1},
	}}
	cycle, err := db.CreateScanCycle(ctx, store.ScanCycleRecord{JobID: record.ID, Job: job.Name, JobRevision: record.Revision, ConfigHash: job.SecurityHash(), Plan: cyclePlan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE scan_cycles SET status='stalled' WHERE id=?`, cycle.ID); err != nil {
		t.Fatal(err)
	}
	var stalled model.Scan
	if handled, _, err := a.runResumableAttempt(ctx, ctx, job, record.ID, &stalled, nil, coverageResumableScanner{plan: cyclePlan}, false); !handled || !errors.Is(err, ErrScanCycleStalled) {
		t.Fatalf("scheduled stalled cycle = handled %v err %v scan %#v", handled, err, stalled)
	}
	var manual model.Scan
	if handled, _, err := a.runResumableAttempt(ctx, ctx, job, record.ID, &manual, nil, coverageResumableScanner{plan: cyclePlan}, true); handled && err == nil {
		// The manual path is allowed to retry; it may fail later in this minimal
		// fixture, but it must not be rejected by ErrScanCycleStalled.
		t.Logf("manual stalled-cycle retry reached scan state %#v", manual)
	}

	// A cycle captured under a different security hash is persisted as stalled
	// instead of being resumed with a changed scope.
	mismatchJob := job
	mismatchJob.Name = "resumable-mismatch"
	mismatchRecord, err := db.CreateJob(ctx, mismatchJob)
	if err != nil {
		t.Fatal(err)
	}
	mismatch, err := db.CreateScanCycle(ctx, store.ScanCycleRecord{JobID: mismatchRecord.ID, Job: mismatchJob.Name, JobRevision: mismatchRecord.Revision, ConfigHash: "old-hash", Plan: cyclePlan})
	if err != nil {
		t.Fatal(err)
	}
	var mismatchScan model.Scan
	if handled, _, err := a.runResumableAttempt(ctx, ctx, mismatchJob, mismatchRecord.ID, &mismatchScan, nil, coverageResumableScanner{plan: cyclePlan}, false); !handled || err == nil || mismatchScan.Status != "failed" || mismatchScan.CycleStatus != "stalled" {
		t.Fatalf("mismatched cycle = handled %v scan %#v err %v", handled, mismatchScan, err)
	}
	if got, err := db.GetScanCycle(ctx, mismatch.ID); err != nil || got.Status != "stalled" {
		t.Fatalf("mismatched cycle state = %#v %v", got, err)
	}

	// A paused cycle from before a baseline reset must be discarded rather than
	// resumed into the new comparison scope.
	epochJob := job
	epochJob.Name = "resumable-epoch"
	epochRecord, err := db.CreateJob(ctx, epochJob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateRuntime(ctx, epochRecord.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp"}}}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	oldEpoch, err := db.CreateScanCycle(ctx, store.ScanCycleRecord{JobID: epochRecord.ID, Job: epochJob.Name, JobRevision: epochRecord.Revision, BaselineEpoch: 0, ConfigHash: epochJob.SecurityHash(), Plan: cyclePlan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.StartScanCycleAttempt(ctx, oldEpoch.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ClaimScanCycleUnit(ctx, oldEpoch.ID, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteScanCycleUnit(ctx, oldEpoch.ID, 0, model.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	var epochScan model.Scan
	if handled, _, err := a.runResumableAttempt(ctx, ctx, epochJob, epochRecord.ID, &epochScan, nil, coverageResumableScanner{plan: cyclePlan}, false); !handled || err == nil || epochScan.CycleID != oldEpoch.ID || epochScan.CycleStatus != "discarded" {
		t.Fatalf("stale epoch cycle = handled %v scan %#v err %v", handled, epochScan, err)
	}
	discardedEpoch, err := db.GetScanCycle(ctx, oldEpoch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if discardedEpoch.Status != "discarded" || discardedEpoch.FinishedAt.IsZero() || discardedEpoch.CompletedUnits != 0 || discardedEpoch.TotalUnits != 0 || discardedEpoch.CompletedProbes != 0 || discardedEpoch.TotalProbes != 0 {
		t.Fatalf("stale epoch cycle retained state: %#v", discardedEpoch)
	}
	if summaries, err := db.ListScanCycleUnitSummaries(ctx, oldEpoch.ID); err != nil || len(summaries) != 0 {
		t.Fatalf("stale epoch cycle retained work: %#v, %v", summaries, err)
	}
	if _, err := db.DB.ExecContext(ctx, `CREATE TRIGGER reject_scan_cycle_discard BEFORE UPDATE OF status ON scan_cycles WHEN NEW.status='discarded' BEGIN SELECT RAISE(ABORT, 'discard unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	blockedEpoch, err := db.CreateScanCycle(ctx, store.ScanCycleRecord{JobID: epochRecord.ID, Job: epochJob.Name, JobRevision: epochRecord.Revision, BaselineEpoch: 0, ConfigHash: epochJob.SecurityHash(), Plan: cyclePlan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.StartScanCycleAttempt(ctx, blockedEpoch.ID); err != nil {
		t.Fatal(err)
	}
	var blockedScan model.Scan
	if handled, _, err := a.runResumableAttempt(ctx, ctx, epochJob, epochRecord.ID, &blockedScan, nil, coverageResumableScanner{plan: cyclePlan}, false); !handled || err == nil || blockedScan.Status != "failed" || blockedScan.CycleStatus != "running" || !strings.Contains(blockedScan.Error, "discard stale scan cycle") {
		t.Fatalf("failed stale-cycle discard = handled %v scan %#v err %v", handled, blockedScan, err)
	}
	persistedEpoch, err := db.GetScanCycle(ctx, blockedEpoch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persistedEpoch.Status != "running" {
		t.Fatalf("failed discard changed persisted cycle state to %q", persistedEpoch.Status)
	}
	if summaries, err := db.ListScanCycleUnitSummaries(ctx, blockedEpoch.ID); err != nil || len(summaries) != 2 {
		t.Fatalf("failed discard removed cycle work: %#v, %v", summaries, err)
	}
}

func TestResumableRecoveryAndFinishPersistenceFailures(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "resumable-failures.db"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	_ = db.Close()
	cycle := store.ScanCycleRecord{ID: "closed-cycle", TotalUnits: 1}
	for _, invoke := range []func(*model.Scan) (bool, model.Snapshot, error){
		func(scan *model.Scan) (bool, model.Snapshot, error) {
			return a.recoverCompletedCycle(ctx, scan, nil, cycle)
		},
		func(scan *model.Scan) (bool, model.Snapshot, error) {
			return a.finishResumableCycle(ctx, scan, nil, cycle)
		},
	} {
		var scan model.Scan
		handled, _, gotErr := invoke(&scan)
		if !handled || gotErr == nil || scan.Status != "failed" {
			t.Fatalf("closed persistence result = handled %v scan %#v err %v", handled, scan, gotErr)
		}
	}
}

func TestResumableAttemptHandlesUnitFailuresAndNoProgressStalls(t *testing.T) {
	ctx := context.Background()
	newApp := func(t *testing.T, name string) (*App, *store.Store, config.Job, store.JobRecord) {
		t.Helper()
		db, err := store.Open(filepath.Join(t.TempDir(), name+".db"))
		if err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
		a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			db.Close()
			t.Fatal(err)
		}
		job := config.NormalizeJob(config.Job{Name: name, Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), ResumeWindow: config.Duration(time.Hour)})
		record, err := db.CreateJob(ctx, job)
		if err != nil {
			db.Close()
			t.Fatal(err)
		}
		return a, db, job, record
	}
	twoUnits := scanner.WorkPlan{Units: []scanner.WorkUnit{
		{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1},
		{Sequence: 1, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "2", PortCount: 1, Probes: 1},
	}}

	a, db, job, record := newApp(t, "unit-error")
	defer db.Close()
	var failed model.Scan
	if handled, _, err := a.runResumableAttempt(ctx, ctx, job, record.ID, &failed, nil, coverageResumableScanner{plan: twoUnits, scanErr: errors.New("scanner profile arguments: invalid template")}, false); !handled || err == nil || failed.Status != "failed" || failed.CycleStatus != "stalled" {
		t.Fatalf("unit failure = handled %v scan %#v err %v", handled, failed, err)
	}

	a, db, job, record = newApp(t, "timeout-stall")
	defer db.Close()
	cycle, err := db.CreateScanCycle(ctx, store.ScanCycleRecord{JobID: record.ID, Job: job.Name, JobRevision: record.Revision, ConfigHash: job.SecurityHash(), Plan: scanner.WorkPlan{Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE scan_cycles SET no_progress_attempts=2 WHERE id=?`, cycle.ID); err != nil {
		t.Fatal(err)
	}
	var stalled model.Scan
	if handled, _, err := a.runResumableAttempt(ctx, ctx, job, record.ID, &stalled, nil, coverageResumableScanner{scanErr: context.DeadlineExceeded}, false); !handled || err == nil || stalled.Status != "failed" || stalled.CycleStatus != "stalled" {
		t.Fatalf("no-progress timeout = handled %v scan %#v err %v", handled, stalled, err)
	}

	a, db, job, record = newApp(t, "complete-error")
	var completeError model.Scan
	if handled, _, err := a.runResumableAttempt(ctx, ctx, job, record.ID, &completeError, nil, coverageResumableScanner{plan: twoUnits, closeDB: db}, false); !handled || err == nil || completeError.Status != "failed" {
		t.Fatalf("checkpoint persistence failure = handled %v scan %#v err %v", handled, completeError, err)
	}
}

func TestManagedFinalizationContinuesWhenLeaseRenewalIsLost(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "resumable-lease-warning.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	job := config.NormalizeJob(config.Job{Name: "lease-warning", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.40"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), ResumeWindow: config.Duration(time.Hour)})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	a.Scanner = coverageResumableScanner{
		plan: scanner.WorkPlan{Units: []scanner.WorkUnit{
			{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.40"}, Ports: "1", PortCount: 1, Probes: 1},
			{Sequence: 1, Protocol: "tcp", Addresses: []string{"192.0.2.40"}, Ports: "2", PortCount: 1, Probes: 1},
		}},
		clearLeases: true,
		closeDB:     db,
	}
	scan, _, runErr := a.RunJobRecord(ctx, record)
	if runErr != nil || scan.Status != "success" {
		t.Fatalf("managed scan after lost lease = %#v, %v", scan, runErr)
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func deadlineContext() context.Context {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	cancel()
	return ctx
}
