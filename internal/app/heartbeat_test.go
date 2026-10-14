package app

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// startTestDaemon runs the daemon of a until the test ends and returns its
// result channel once it holds the daemon lease.
func startTestDaemon(t *testing.T, a *App, db *store.Store) (context.CancelFunc, chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Daemon(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("daemon did not stop")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for a.currentDaemonOwner() == "" {
		if time.Now().After(deadline) {
			t.Fatal("daemon did not acquire its lease")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cancel, done
}

// holdExternalWriter takes SQLite's writer lock through a separate store
// handle, as a host command does beside the daemon.
func holdExternalWriter(t *testing.T, db *store.Store) func() {
	t.Helper()
	external, err := store.OpenExisting(db.FilePath())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := external.DB.Conn(context.Background())
	if err != nil {
		_ = external.Close()
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), `BEGIN IMMEDIATE`); err != nil {
		_ = conn.Close()
		_ = external.Close()
		t.Fatal(err)
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
			t.Errorf("release external SQLite writer: %v", err)
		}
		if err := conn.Close(); err != nil {
			t.Errorf("close external SQLite connection: %v", err)
		}
		if err := external.Close(); err != nil {
			t.Errorf("close external SQLite store: %v", err)
		}
	}
	t.Cleanup(release)
	return release
}

// A scan finalization holds SQLite's only writer for its work budget, which
// can exceed the two minutes after which the daemon heartbeat is stale. The
// daemon's finalization therefore renews the lease for that budget when it
// takes the writer.
func TestManagedFinalizationRenewsTheDaemonLeaseForItsWorkBudget(t *testing.T) {
	t.Parallel()
	a, db := newLifecycleTestApp(t, immediateSnapshotScanner{}, nil)
	a.ReleaseChecker = nil
	// The regular heartbeat would record the current time again.
	a.heartbeatInterval = time.Hour
	const workBudget = 10 * time.Minute
	a.persistenceBudget = func(int) time.Duration { return workBudget }
	startTestDaemon(t, a, db)
	record, err := defaultTenant(db).CreateJob(context.Background(), lifecycleJob("finalization-renews-daemon-lease"))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC()
	completed := make(chan error, 1)
	if err := a.StartManagedRun(defaultTenant(db), record.ID, func(_ model.Scan, _ []model.Event, err error) { completed <- err }); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-completed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("managed scan did not finish")
	}
	lease, err := db.System().DaemonLeaseStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if lease.Owner != a.currentDaemonOwner() || lease.Heartbeat.Before(started.Add(workBudget)) {
		t.Fatalf("daemon lease after finalization = %#v, want renewed until at least %s", lease, started.Add(workBudget))
	}
	health, err := db.System().HealthStatus(context.Background())
	if err != nil || health.Status != "ready" || health.UpdatedAt.After(time.Now().UTC()) {
		t.Fatalf("health after a renewed lease = %#v, %v", health, err)
	}
}

// While a scan finalization of the daemon holds the writer, the heartbeat
// cannot write. Its bounded wait must not stop the daemon loop from
// reconciling schedules, must not count as a missed heartbeat, and the
// renewed lease keeps the health check healthy.
func TestDaemonLoopKeepsServingWhileAFinalizationHoldsTheWriter(t *testing.T) {
	t.Parallel()
	var logs syncBuffer
	a, db := newLifecycleTestApp(t, schedulerFake{}, nil)
	a.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	a.ReleaseChecker = nil
	a.heartbeatInterval = 20 * time.Millisecond
	a.heartbeatTimeout = 50 * time.Millisecond
	ctx := context.Background()
	record, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("held-writer-schedule"))
	if err != nil {
		t.Fatal(err)
	}
	_, done := startTestDaemon(t, a, db)
	initialSpec := "CRON_TZ=" + record.Job.Timezone + " " + record.Job.Schedule
	updatedSpec := "CRON_TZ=" + record.Job.Timezone + " 15 * * * *"
	scheduleSpec := func() string {
		a.scheduleMu.Lock()
		defer a.scheduleMu.Unlock()
		return a.scheduleSpecs[record.ID]
	}
	deadline := time.Now().Add(5 * time.Second)
	for scheduleSpec() != initialSpec && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := scheduleSpec(); got != initialSpec {
		t.Fatalf("the daemon's initial schedule = %q, want %q", got, initialSpec)
	}
	updated := record.Job
	updated.Schedule = "15 * * * *"
	record, _, err = defaultTenant(db).UpdateJob(ctx, record.ID, record.Revision, updated, true, false, false)
	if err != nil {
		t.Fatal(err)
	}

	holding, release := make(chan struct{}), make(chan struct{})
	finalized := make(chan error, 1)
	const workBudget = 10 * time.Minute
	go func() {
		now := time.Now().UTC()
		scan := model.Scan{ID: "held-finalization", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: now, FinishedAt: now, Status: "canceled", Error: "scan canceled", ConfigHash: record.Job.SecurityHash()}
		_, err := db.System().FinalizeManagedScanWithOptions(ctx, &scan, record.ID, scan.ConfigHash, nil, store.ManagedScanFinalizationOptions{
			WriterWaitTimeout: 5 * time.Second, WorkTimeout: workBudget, DaemonOwner: a.currentDaemonOwner(),
		}, func(*model.JobState, *model.Scan, store.IncidentReminderSettings) ([]model.Event, error) {
			close(holding)
			<-release
			return nil, nil
		})
		finalized <- err
	}()
	select {
	case <-holding:
	case <-time.After(10 * time.Second):
		t.Fatal("the simulated finalization did not take the writer")
	}
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()

	if lease, err := db.System().DaemonLeaseStatus(ctx); err != nil || lease.Heartbeat.Before(time.Now().UTC().Add(workBudget-time.Minute)) {
		t.Fatalf("daemon lease while the finalization holds the writer = %#v, %v; want renewed for the work budget", lease, err)
	}
	if health, err := db.System().HealthStatus(ctx); err != nil || health.Status != "ready" {
		t.Fatalf("health while the finalization holds the writer = %#v, %v", health, err)
	}
	a.RefreshSchedules()
	deadline = time.Now().Add(5 * time.Second)
	for scheduleSpec() != updatedSpec && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := scheduleSpec(); got != updatedSpec {
		t.Fatalf("the daemon loop schedule while the writer was held = %q, want %q", got, updatedSpec)
	}
	// Several heartbeats time out meanwhile; none counts as a miss.
	deadline = time.Now().Add(5 * time.Second)
	for strings.Count(logs.String(), "daemon heartbeat waits while a scan finalization holds the database writer") < 4 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("daemon stopped while the writer was held: %v", err)
	default:
	}
	if waits := strings.Count(logs.String(), "daemon heartbeat waits while a scan finalization holds the database writer"); waits < 4 {
		t.Fatalf("heartbeats that waited for the writer = %d, want at least 4: %s", waits, logs.String())
	}
	if strings.Contains(logs.String(), "daemon lease heartbeat failed") {
		t.Fatalf("a heartbeat that waited for the writer counted as a failure: %s", logs.String())
	}

	close(release)
	released = true
	if err := <-finalized; err != nil {
		t.Fatal(err)
	}
	// Once the writer is free the regular heartbeat records the current time.
	deadline = time.Now().Add(5 * time.Second)
	for {
		lease, err := db.System().DaemonLeaseStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if lease.Heartbeat.Before(time.Now().UTC().Add(time.Minute)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("heartbeat did not resume after the writer was released: %#v", lease)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A heartbeat that times out without a renewed lease is still not a missed
// heartbeat, but it is worth a warning.
func TestHeartbeatTimeoutWithoutRenewedLeaseWarns(t *testing.T) {
	t.Parallel()
	var logs syncBuffer
	a, db := newLifecycleTestApp(t, schedulerFake{}, nil)
	a.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	ctx := context.Background()
	if err := db.System().AcquireLease(ctx, "owner"); err != nil {
		t.Fatal(err)
	}
	a.logHeartbeatWait(ctx, db.System(), "owner")
	if !strings.Contains(logs.String(), "daemon heartbeat timed out waiting for the database writer") {
		t.Fatalf("log = %s", logs.String())
	}
	a.heartbeatTimeout = time.Nanosecond
	conn, err := db.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := a.heartbeat(ctx, db.System(), "owner"); !errors.Is(err, errHeartbeatTimedOut) {
		t.Fatalf("heartbeat while the writer is held = %v, want %v", err, errHeartbeatTimedOut)
	}
}

// A separate host process uses SQLite's busy handler, which can return
// SQLITE_BUSY before the daemon heartbeat context reaches its longer deadline.
// That is still a writer wait, not a missed heartbeat.
func TestHeartbeatTreatsExternalSQLiteBusyAsWriterWait(t *testing.T) {
	t.Parallel()
	a, db := newLifecycleTestApp(t, schedulerFake{}, nil)
	ctx := context.Background()
	if err := db.System().AcquireLease(ctx, "external-writer-heartbeat"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `PRAGMA busy_timeout=50`); err != nil {
		t.Fatal(err)
	}
	a.heartbeatTimeout = time.Second
	release := holdExternalWriter(t, db)
	err := a.heartbeat(ctx, db.System(), "external-writer-heartbeat")
	if !errors.Is(err, errHeartbeatTimedOut) || !store.IsSQLiteBusy(err) {
		t.Fatalf("heartbeat under an external writer lock = %v, want a busy writer wait", err)
	}
	release()
	if err := a.heartbeat(ctx, db.System(), "external-writer-heartbeat"); err != nil {
		t.Fatalf("heartbeat after external writer released: %v", err)
	}
}

func TestDaemonLoopRetriesExternalSQLiteBusyHeartbeats(t *testing.T) {
	t.Parallel()
	var logs syncBuffer
	a, db := newLifecycleTestApp(t, schedulerFake{}, nil)
	a.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	a.ReleaseChecker = nil
	a.heartbeatInterval = 20 * time.Millisecond
	a.heartbeatTimeout = time.Second
	if _, err := db.DB.ExecContext(context.Background(), `PRAGMA busy_timeout=50`); err != nil {
		t.Fatal(err)
	}
	_, done := startTestDaemon(t, a, db)
	ctx := context.Background()
	before, err := db.System().DaemonLeaseStatus(ctx)
	if err != nil || !before.Active {
		t.Fatalf("initial daemon lease = %#v, %v", before, err)
	}
	release := holdExternalWriter(t, db)
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	deadline := time.Now().Add(4 * time.Second)
	for strings.Count(logs.String(), "daemon heartbeat timed out waiting for the database writer") < 4 && time.Now().Before(deadline) {
		select {
		case err := <-done:
			done <- err
			t.Fatalf("daemon stopped during external writer contention: %v", err)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if waits := strings.Count(logs.String(), "daemon heartbeat timed out waiting for the database writer"); waits < 4 {
		t.Fatalf("external-writer heartbeat waits = %d, want at least 4: %s", waits, logs.String())
	}
	select {
	case err := <-done:
		done <- err
		t.Fatalf("daemon stopped before writer release: %v", err)
	default:
	}
	release()
	released = true
	deadline = time.Now().Add(4 * time.Second)
	for {
		lease, err := db.System().DaemonLeaseStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if lease.Heartbeat.After(before.Heartbeat) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon heartbeat did not recover after writer release: before=%s after=%s", before.Heartbeat, lease.Heartbeat)
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case err := <-done:
		done <- err
		t.Fatalf("daemon stopped after writer release: %v", err)
	default:
	}
	if strings.Contains(logs.String(), "daemon lease heartbeat failed") {
		t.Fatalf("external writer contention was counted as a failed heartbeat: %s", logs.String())
	}
}

func TestHeartbeatPreservesLeaseLossAndCancellation(t *testing.T) {
	t.Parallel()
	a, db := newLifecycleTestApp(t, schedulerFake{}, nil)
	if err := db.System().AcquireLease(context.Background(), "current-owner"); err != nil {
		t.Fatal(err)
	}
	if err := a.heartbeat(context.Background(), db.System(), "other-owner"); !errors.Is(err, store.ErrLeaseLost) || errors.Is(err, errHeartbeatTimedOut) {
		t.Fatalf("lost lease heartbeat = %v, want unwrapped ErrLeaseLost", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.heartbeat(canceled, db.System(), "current-owner"); !errors.Is(err, context.Canceled) || errors.Is(err, errHeartbeatTimedOut) {
		t.Fatalf("canceled heartbeat = %v, want unwrapped context cancellation", err)
	}
}
