package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestDaemonRetentionMaintenanceKeepsHeartbeatAndScheduleResponsive(t *testing.T) {
	t.Parallel()
	a, db := newLifecycleTestApp(t, schedulerFake{}, io.Discard)
	a.ReleaseChecker = nil
	a.heartbeatInterval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	pruneStarted := make(chan struct{})
	a.pruneHistory = func(ctx context.Context, _ time.Time) (store.PruneStats, error) {
		close(pruneStarted)
		<-ctx.Done()
		return store.PruneStats{}, ctx.Err()
	}
	done := make(chan error, 1)
	go func() { done <- a.Daemon(ctx) }()
	finished := false
	defer func() {
		cancel()
		if finished {
			return
		}
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("daemon returned during cleanup: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("daemon did not stop during cleanup")
		}
	}()

	select {
	case <-pruneStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("startup retention pass did not start")
	}
	lease, err := db.System().DaemonLeaseStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lastHeartbeat := lease.Heartbeat
	heartbeatAdvances := 0
	// The loops stop as soon as their condition holds. Their deadlines only
	// bound a failing run, so they leave room for a runner that is busy with
	// the package's other parallel tests under the race detector.
	heartbeatDeadline := time.Now().Add(5 * time.Second)
	for heartbeatAdvances < 3 && time.Now().Before(heartbeatDeadline) {
		lease, err = db.System().DaemonLeaseStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if lease.Heartbeat.After(lastHeartbeat) {
			heartbeatAdvances++
			lastHeartbeat = lease.Heartbeat
		}
		time.Sleep(5 * time.Millisecond)
	}

	record, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("maintenance-schedule-refresh"))
	if err != nil {
		t.Fatal(err)
	}
	a.RefreshSchedules()
	scheduled := false
	scheduleDeadline := time.Now().Add(5 * time.Second)
	for !scheduled && time.Now().Before(scheduleDeadline) {
		a.scheduleMu.Lock()
		_, scheduled = a.entries[record.ID]
		a.scheduleMu.Unlock()
		if !scheduled {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if heartbeatAdvances < 3 {
		t.Errorf("daemon heartbeat advanced %d times while retention was blocked; want at least 3", heartbeatAdvances)
	}
	if !scheduled {
		t.Error("schedule refresh did not reconcile a new job while retention was blocked")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("daemon returned unexpected error after cancellation: %v", err)
		}
		finished = true
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not cancel blocked retention and stop within 2 seconds")
	}
}

func TestRunMaintenancePassLogsSuccessfulCleanup(t *testing.T) {
	t.Parallel()
	a, db := newLifecycleTestApp(t, schedulerFake{}, io.Discard)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateSession(ctx, "expired-maintenance-session", "csrf", now.Add(-time.Hour), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	job, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("expired-maintenance-cycle"))
	if err != nil {
		t.Fatal(err)
	}
	plan := scanner.WorkPlan{Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1}}}
	if _, err := db.System().CreateScanCycle(ctx, store.ScanCycleRecord{
		ID: "expired-maintenance-cycle", JobID: job.ID, Job: job.Job.Name, Plan: plan, ExpiresAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	a.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	a.runMaintenancePass(ctx, db.System(), func(context.Context, time.Time) (store.PruneStats, error) {
		return store.PruneStats{Scans: 1}, nil
	}, false)
	for _, expected := range []string{"expired sessions pruned", "history pruned", "expired scan cycles", "cycles=1"} {
		if !strings.Contains(logs.String(), expected) {
			t.Errorf("maintenance log missing %q: %s", expected, logs.String())
		}
	}

	// The worker is also usable before the application configures a logger.
	a.Logger = nil
	a.runMaintenancePass(ctx, db.System(), func(context.Context, time.Time) (store.PruneStats, error) {
		return store.PruneStats{}, nil
	}, true)
}

func TestRunMaintenancePassContinuesAfterFailures(t *testing.T) {
	t.Parallel()
	a, db := newLifecycleTestApp(t, schedulerFake{}, io.Discard)
	ctx := context.Background()
	for _, table := range []string{"sessions", "scan_cycles"} {
		if _, err := db.DB.ExecContext(ctx, "DROP TABLE "+table); err != nil {
			t.Fatalf("drop %s to simulate cleanup failure: %v", table, err)
		}
	}
	var logs bytes.Buffer
	a.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	pruneCalled := false
	a.runMaintenancePass(ctx, db.System(), func(context.Context, time.Time) (store.PruneStats, error) {
		pruneCalled = true
		return store.PruneStats{}, errors.New("injected retention failure")
	}, true)
	if !pruneCalled {
		t.Fatal("retention pruning was skipped after session cleanup failed")
	}
	for _, expected := range []string{"startup expired-session cleanup failed", "startup history pruning failed", "startup scan-cycle expiry failed"} {
		if !strings.Contains(logs.String(), expected) {
			t.Errorf("maintenance log missing %q: %s", expected, logs.String())
		}
	}
}

// syncBuffer is a log sink that a background worker and the test can use at
// the same time.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// One panicking pass must not stop the maintenance worker: it logs the
// panic, retries after its backoff, and keeps running until the daemon
// stops.
func TestMaintenanceWorkerContinuesAfterAPanickingPass(t *testing.T) {
	t.Parallel()
	var logs syncBuffer
	a, db := newLifecycleTestApp(t, schedulerFake{}, &logs)
	a.maintenanceRetry = 10 * time.Millisecond
	var calls atomic.Int32
	secondPass := make(chan struct{})
	a.pruneHistory = func(context.Context, time.Time) (store.PruneStats, error) {
		switch calls.Add(1) {
		case 1:
			panic("injected retention defect")
		case 2:
			close(secondPass)
		}
		return store.PruneStats{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := a.startMaintenanceWorker(ctx, db.System())
	select {
	case <-secondPass:
	case <-time.After(5 * time.Second):
		t.Fatal("the maintenance pass after a panic did not run")
	}
	select {
	case <-done:
		t.Fatal("the maintenance worker stopped after a panicking pass")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the maintenance worker did not stop with its context")
	}
	for _, expected := range []string{"background goroutine panic recovered", "goroutine=history-maintenance-retention", "injected retention defect", "history maintenance pass panicked; retrying", "retry_in=10ms"} {
		if !strings.Contains(logs.String(), expected) {
			t.Errorf("maintenance log missing %q: %s", expected, logs.String())
		}
	}
}

// A step that panics does not skip the steps after it.
func TestRunMaintenancePassRunsEveryStepAfterAPanic(t *testing.T) {
	t.Parallel()
	a, db := newLifecycleTestApp(t, schedulerFake{}, io.Discard)
	ctx := context.Background()
	job, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("maintenance-after-panic"))
	if err != nil {
		t.Fatal(err)
	}
	plan := scanner.WorkPlan{Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1}}}
	cycle, err := db.System().CreateScanCycle(ctx, store.ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, Plan: plan, ExpiresAt: time.Now().UTC().Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	panicked := a.runMaintenancePass(ctx, db.System(), func(context.Context, time.Time) (store.PruneStats, error) {
		panic("injected retention defect")
	}, false)
	if !panicked {
		t.Fatal("a pass with a panicking step reported no panic")
	}
	if expired, err := defaultTenant(db).GetScanCycle(ctx, cycle.ID); err != nil || expired.Status != "expired" {
		t.Fatalf("cycle after a panicking retention step = %#v, %v; want expired", expired, err)
	}
	if a.runMaintenancePass(ctx, db.System(), func(context.Context, time.Time) (store.PruneStats, error) {
		return store.PruneStats{}, nil
	}, false) {
		t.Fatal("a pass without a panic reported one")
	}
}
