package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/robfig/cron/v3"
)

type schedulerFake struct{}

func (schedulerFake) Version(context.Context) string { return "fake" }
func (schedulerFake) Scan(context.Context, config.Job) (model.Snapshot, error) {
	return model.Snapshot{}, nil
}

type failingScanner struct{ err error }

func (s failingScanner) Version(context.Context) string { return "failing" }
func (s failingScanner) Scan(context.Context, config.Job) (model.Snapshot, error) {
	return model.Snapshot{}, s.err
}

type deadlineScanner struct{}

func (deadlineScanner) Version(context.Context) string { return "deadline" }
func (deadlineScanner) Scan(ctx context.Context, _ config.Job) (model.Snapshot, error) {
	<-ctx.Done()
	return model.Snapshot{}, ctx.Err()
}

type blockingScanner struct {
	started chan struct{}
	release chan struct{}
}

type progressBlockingScanner struct {
	started chan struct{}
}

func (s *progressBlockingScanner) Version(context.Context) string { return "progress" }
func (s *progressBlockingScanner) Scan(ctx context.Context, job config.Job) (model.Snapshot, error) {
	return s.ScanWithProgress(ctx, job, nil)
}
func (s *progressBlockingScanner) ScanWithProgress(ctx context.Context, _ config.Job, report scanner.ProgressReporter) (model.Snapshot, error) {
	if report != nil {
		report(scanner.Progress{TotalProbes: 2, TotalInvocations: 1, Phase: "scanning"})
	}
	close(s.started)
	<-ctx.Done()
	return model.Snapshot{}, ctx.Err()
}

func (s *blockingScanner) Version(context.Context) string { return "blocking" }
func (s *blockingScanner) Scan(ctx context.Context, _ config.Job) (model.Snapshot, error) {
	close(s.started)
	select {
	case <-s.release:
		return model.Snapshot{}, nil
	case <-ctx.Done():
		return model.Snapshot{}, ctx.Err()
	}
}

type releaseOnlyScanner struct {
	started chan struct{}
	release chan struct{}
}

func TestScanWorkBudgetIsCheckedBeforeLease(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1, MaxProbeCount: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, s, "missing", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	record, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "budget", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1-2", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced"}))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = a.RunJobRecord(ctx, record)
	var budgetErr *ScanWorkBudgetError
	if !errors.As(err, &budgetErr) {
		t.Fatalf("expected budget error, got %v", err)
	}
	active, err := s.JobActive(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("budget rejection acquired a lease")
	}
	if _, err := s.ListJobScans(ctx, record.ID, 10); err != nil {
		t.Fatal(err)
	}
}

func (s *releaseOnlyScanner) Version(context.Context) string { return "release-only" }
func (s *releaseOnlyScanner) Scan(context.Context, config.Job) (model.Snapshot, error) {
	close(s.started)
	<-s.release
	return model.Snapshot{}, nil
}

func TestStopRunWaitsForManualManagedRun(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, s, "missing", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	blocking := &releaseOnlyScanner{started: make(chan struct{}), release: make(chan struct{})}
	a.Scanner = blocking
	record, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "shutdown", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, owned := a.BeginRun(ctx); !owned {
		t.Fatal("expected test to own the run context")
	}
	completed := make(chan error, 1)
	if err := a.StartManagedRun(record.ID, func(_ model.Scan, _ []model.Event, runErr error) { completed <- runErr }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocking.started:
	case <-time.After(2 * time.Second):
		t.Fatal("manual scan did not start")
	}
	stopped := make(chan struct{})
	go func() {
		a.StopRun()
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("shutdown returned before the manual scan finished")
	case <-time.After(100 * time.Millisecond):
	}
	close(blocking.release)
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not wait for the manual scan")
	}
	select {
	case runErr := <-completed:
		if runErr != nil {
			t.Fatalf("manual scan failed: %v", runErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("manual scan callback did not run")
	}
	scans, err := s.ListJobScans(ctx, record.ID, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 1 || scans[0].Status != "success" {
		t.Fatalf("manual scan was not persisted before shutdown: %#v", scans)
	}
}

func TestDaemonReturnsWhenLeaseIsLost(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, s, "missing", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.heartbeatInterval = 10 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- a.Daemon(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var owner string
		if scanErr := s.DB.QueryRowContext(ctx, `SELECT owner FROM daemon_lease WHERE id=1`).Scan(&owner); scanErr == nil && owner != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon did not acquire its lease")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE daemon_lease SET owner='other' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "daemon lease lost") {
			t.Fatalf("daemon returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not return after losing its lease")
	}
}

func TestManagedScanLeaseBlocksScopeEditUntilScanCompletes(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, s, "missing", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	blocking := &blockingScanner{started: make(chan struct{}), release: make(chan struct{})}
	a.Scanner = blocking
	record, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "locked", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced"}))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, runErr := a.RunJobRecord(ctx, record)
		done <- runErr
	}()
	select {
	case <-blocking.started:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not start")
	}
	changed := record.Job
	changed.Targets = []string{"127.0.0.2"}
	if _, _, updateErr := s.UpdateJob(ctx, record.ID, record.Revision, changed, true, false, true); !errors.Is(updateErr, store.ErrJobScanActive) {
		t.Fatalf("scope edit was allowed during active scan: %v", updateErr)
	}
	close(blocking.release)
	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("scan failed: %v", runErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not complete")
	}
}

func TestActiveScansReportsInFlightManagedScan(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, s, "missing", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	blocking := &blockingScanner{started: make(chan struct{}), release: make(chan struct{})}
	a.Scanner = blocking
	record, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "active", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced"}))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, runErr := a.RunJobRecord(ctx, record)
		done <- runErr
	}()
	select {
	case <-blocking.started:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not start")
	}
	active := a.ActiveScans()
	if len(active) != 1 || active[0].ID == "" || active[0].JobID != record.ID || active[0].Job != record.Job.Name {
		t.Fatalf("unexpected active scan snapshot: %#v", active)
	}
	close(blocking.release)
	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("scan failed: %v", runErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not complete")
	}
	if active := a.ActiveScans(); len(active) != 0 {
		t.Fatalf("completed scan remained active: %#v", active)
	}
}

func TestHighCostManagedScanReportsProgressAndCanBeCanceled(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1, MaxProbeCount: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, s, "missing", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	blocking := &progressBlockingScanner{started: make(chan struct{})}
	a.Scanner = blocking
	record, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "high-cost", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1-2", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced", AllowHighCost: true}))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var scan model.Scan
	go func() {
		scan, _, _ = a.RunJobRecord(ctx, record)
		close(done)
	}()
	select {
	case <-blocking.started:
	case <-time.After(2 * time.Second):
		t.Fatal("high-cost scan did not start")
	}
	active := a.ActiveScans()
	if len(active) != 1 || active[0].TotalProbes != 2 || active[0].ProgressPercent != 0 || active[0].Phase != "scanning" {
		t.Fatalf("unexpected progress snapshot: %#v", active)
	}
	if err := a.CancelScan(active[0].ID); err != nil {
		t.Fatalf("cancel scan: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled scan did not finish")
	}
	if scan.Status != "canceled" || scan.Error != "scan canceled" {
		t.Fatalf("unexpected canceled scan: %#v", scan)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline != nil || state.CandidateCount != 0 || len(state.Incidents) != 0 {
		t.Fatalf("canceled scan mutated baseline state: %#v", state)
	}
	if active := a.ActiveScans(); len(active) != 0 {
		t.Fatalf("canceled scan remained active: %#v", active)
	}
}

func TestManagedTerminalOutcomesQueueNotifications(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{
		Version:   1,
		Database:  "test",
		Retention: config.Duration(24 * time.Hour),
		Scheduler: config.Scheduler{MaxConcurrent: 1},
		Web:       config.Web{Listen: "127.0.0.1:8080"},
		Notifications: config.Notifications{URLs: []string{
			"generic://localhost/edgewatch?disabletls=yes&template=json",
		}},
	}
	a, err := New(cfg, s, "missing", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	job := config.NormalizeJob(config.Job{
		Name: "terminal-outcomes", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"},
		TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timing: "balanced", Timeout: config.Duration(time.Minute),
		Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	})
	record, err := s.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}

	a.Scanner = failingScanner{err: errors.New("network unavailable")}
	failed, events, runErr := a.RunJobRecord(ctx, record)
	if runErr == nil || failed.Status != "failed" || len(events) != 1 || events[0].Type != "scan-failure" {
		t.Fatalf("failed run = scan=%#v events=%#v err=%v", failed, events, runErr)
	}

	blocking := &blockingScanner{started: make(chan struct{}), release: make(chan struct{})}
	a.Scanner = blocking
	canceledDone := make(chan struct{})
	var canceled model.Scan
	var canceledEvents []model.Event
	var canceledErr error
	go func() {
		canceled, canceledEvents, canceledErr = a.RunJobRecord(ctx, record)
		close(canceledDone)
	}()
	select {
	case <-blocking.started:
	case <-time.After(2 * time.Second):
		t.Fatal("cancellable scan did not start")
	}
	active := a.ActiveScans()
	if len(active) != 1 {
		t.Fatalf("active scans = %#v", active)
	}
	if err := a.CancelScan(active[0].ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceledDone:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled scan did not finish")
	}
	if !errors.Is(canceledErr, context.Canceled) || canceled.Status != "canceled" || len(canceledEvents) != 1 || canceledEvents[0].Type != "scan-canceled" {
		t.Fatalf("canceled run = scan=%#v events=%#v err=%v", canceled, canceledEvents, canceledErr)
	}

	rows, err := s.DB.QueryContext(ctx, `SELECT payload_json FROM outbox ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var types []string
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var event model.Event
		if err := json.Unmarshal(raw, &event); err != nil {
			t.Fatal(err)
		}
		types = append(types, event.Type)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(types) != 2 || types[0] != "scan-failure" || types[1] != "scan-canceled" {
		t.Fatalf("terminal outcome notifications = %v", types)
	}
}

func TestManagedTimeoutIsPersistedAsDistinctTerminalStatus(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, s, "missing", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Scanner = deadlineScanner{}
	job := config.NormalizeJob(config.Job{
		Name: "timeout", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"},
		TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timing: "balanced", Timeout: config.Duration(time.Second),
		Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	})
	record, err := s.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	scan, events, runErr := a.RunJobRecord(ctx, record)
	if !errors.Is(runErr, context.DeadlineExceeded) || scan.Status != "timed_out" || scan.Error != "scan timed out" {
		t.Fatalf("timeout run = scan=%#v events=%#v err=%v", scan, events, runErr)
	}
	if len(events) != 1 || events[0].Type != "scan-failure" || !strings.Contains(events[0].Message, "Scan timed out") {
		t.Fatalf("timeout event = %#v", events)
	}
	stored, err := s.ListJobScans(ctx, record.ID, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].Status != "timed_out" {
		t.Fatalf("stored timeout = %#v", stored)
	}
}

func TestManagedSchedulerReconcilesCreateUpdateAndArchive(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, s, "missing", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Scanner = schedulerFake{}
	c := cron.New(cron.WithParser(cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)))
	a.cron = c
	job := config.NormalizeJob(config.Job{Name: "hourly", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced"})
	record, err := s.CreateJob(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.reconcileSchedules(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(a.entries) != 1 {
		t.Fatalf("entries after create: %d", len(a.entries))
	}
	entryBeforeUpdate := a.entries[record.ID]
	if err := a.reconcileSchedules(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if a.entries[record.ID] != entryBeforeUpdate {
		t.Fatalf("unchanged reconciliation replaced cron entry %d with %d", entryBeforeUpdate, a.entries[record.ID])
	}
	updated := record.Job
	updated.Schedule = "15 * * * *"
	if _, _, err := s.UpdateJob(context.Background(), record.ID, record.Revision, updated, true, false, false); err != nil {
		t.Fatal(err)
	}
	if err := a.reconcileSchedules(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(a.entries) != 1 {
		t.Fatalf("entries after update: %d", len(a.entries))
	}
	if err := s.SetJobArchived(context.Background(), record.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := a.reconcileSchedules(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(a.entries) != 0 {
		t.Fatalf("entries after archive: %d", len(a.entries))
	}
}

func TestManagedSchedulerRejectsInvalidDesiredSetWithoutUnscheduling(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, s, "missing", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	c := cron.New(cron.WithParser(cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)))
	a.cron = c
	job := config.NormalizeJob(config.Job{Name: "stable", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced"})
	record, err := s.CreateJobWithEnabled(ctx, job, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.reconcileSchedules(ctx, false); err != nil {
		t.Fatal(err)
	}
	entry := a.entries[record.ID]
	otherJob := job
	otherJob.Name = "other"
	otherRecord, err := s.CreateJobWithEnabled(ctx, otherJob, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.reconcileSchedules(ctx, false); err != nil {
		t.Fatal(err)
	}
	otherEntry := a.entries[otherRecord.ID]
	invalid := job
	invalid.Schedule = "not a cron expression"
	raw, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE jobs SET definition_json=? WHERE id=?`, raw, record.ID); err != nil {
		t.Fatal(err)
	}
	if err := a.reconcileSchedules(ctx, false); err == nil {
		t.Fatal("invalid desired schedule was accepted")
	}
	if got := a.entries[record.ID]; got != entry {
		t.Fatalf("failed reconciliation changed the active entry from %d to %d", entry, got)
	}
	if got := a.entries[otherRecord.ID]; got != otherEntry {
		t.Fatalf("failed reconciliation disturbed a healthy entry from %d to %d", otherEntry, got)
	}
}

func TestManagedScanPublishesLifecycleEvents(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, s, "missing", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Scanner = schedulerFake{}
	record, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "events", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced"}))
	if err != nil {
		t.Fatal(err)
	}
	var events []model.Event
	a.SetEventHandler(func(event model.Event) { events = append(events, event) })
	if _, _, err := a.RunJobRecord(ctx, record); err != nil {
		t.Fatal(err)
	}
	if len(events) < 2 || events[0].Type != "scan.started" {
		t.Fatalf("unexpected lifecycle events: %#v", events)
	}
	var completed *model.Event
	for i := range events {
		if events[i].Type == "scan.completed" {
			completed = &events[i]
			break
		}
	}
	if completed == nil || events[0].ScanID == "" || events[0].ScanID != completed.ScanID || events[0].JobID != record.ID {
		t.Fatalf("lifecycle event metadata not linked: %#v", events)
	}
}
