package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// lifecycleEvents records the live updates of an App.
type lifecycleEvents struct {
	mu     sync.Mutex
	events []model.Event
}

func recordLifecycleEvents(a *App) *lifecycleEvents {
	recorder := &lifecycleEvents{}
	a.SetEventHandler(func(event model.Event) {
		recorder.mu.Lock()
		defer recorder.mu.Unlock()
		recorder.events = append(recorder.events, event)
	})
	return recorder
}

// take returns the recorded events and starts a new recording.
func (r *lifecycleEvents) take() []model.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	events := r.events
	r.events = nil
	return events
}

func countEvents(events []model.Event, eventType string) int {
	count := 0
	for _, event := range events {
		if event.Type == eventType {
			count++
		}
	}
	return count
}

// waitForPhase waits until the job's active scan reports phase and returns
// the scan.
func waitForPhase(t *testing.T, a *App, jobID, phase string) model.ActiveScan {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, active := range a.ActiveScans(store.DefaultTenantScope()) {
			if active.JobID == jobID && active.Phase == phase {
				return active
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s never reached phase %q: %#v", jobID, phase, a.ActiveScans(store.DefaultTenantScope()))
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// A cancellation that arrives as the queued run is granted its slot either
// ends the wait, so the run never starts and reports ErrQueuedRunCanceled,
// or is refused because the run has taken its slot, which then runs to its
// one completion.
func TestRunLifecycleCancelDuringQueueHandoff(t *testing.T) {
	t.Parallel()
	a, db := newLifecycleTestApp(t, schedulerFake{}, nil)
	record, err := defaultTenant(db).CreateJob(context.Background(), lifecycleJob("queue-handoff-cancel"))
	if err != nil {
		t.Fatal(err)
	}
	recorder := recordLifecycleEvents(a)
	scope := store.DefaultTenantScope()
	for i := range 8 {
		releaseSlot := holdScanSlot(t, a)
		result := make(chan error, 1)
		go func() {
			_, _, err := a.RunJobRecord(context.Background(), record)
			result <- err
		}()
		waitForSlotQueue(t, a, 1)
		released := make(chan struct{})
		go func() {
			releaseSlot()
			close(released)
		}()
		cancelErr := a.CancelQueuedRun(scope, record.ID)
		<-released
		var runErr error
		select {
		case runErr = <-result:
		case <-time.After(10 * time.Second):
			t.Fatalf("iteration %d: run did not return", i)
		}
		events := recorder.take()
		switch {
		case cancelErr == nil:
			if !errors.Is(runErr, ErrQueuedRunCanceled) || countEvents(events, "scan.started") != 0 || countEvents(events, "scan.completed") != 0 || countEvents(events, "scan.skipped") != 1 {
				t.Fatalf("iteration %d: canceled run = %v, events %#v", i, runErr, events)
			}
		case errors.Is(cancelErr, ErrRunNotQueued):
			if runErr != nil || countEvents(events, "scan.started") != 1 || countEvents(events, "scan.completed") != 1 {
				t.Fatalf("iteration %d: run that took its slot = %v, events %#v", i, runErr, events)
			}
		default:
			t.Fatalf("iteration %d: cancel = %v", i, cancelErr)
		}
		if queued := a.QueuedRuns(scope); len(queued) != 0 {
			t.Fatalf("iteration %d: queued runs = %#v", i, queued)
		}
	}
}

// While a scan saves its result, cancelling it is refused with
// ErrScanFinalizing, and the scan completes once.
func TestRunLifecycleCancelDuringFinalization(t *testing.T) {
	t.Parallel()
	probe := &blockingScanner{started: make(chan struct{}), release: make(chan struct{})}
	a, db := newLifecycleTestApp(t, probe, nil)
	record, err := defaultTenant(db).CreateJob(context.Background(), lifecycleJob("finalization-cancel"))
	if err != nil {
		t.Fatal(err)
	}
	recorder := recordLifecycleEvents(a)
	type outcome struct {
		scan model.Scan
		err  error
	}
	result := make(chan outcome, 1)
	go func() {
		scan, _, err := a.RunJobRecord(context.Background(), record)
		result <- outcome{scan, err}
	}()
	select {
	case <-probe.started:
	case <-time.After(10 * time.Second):
		t.Fatal("scan did not start")
	}
	// Hold SQLite's only writer, so the finalization waits for it.
	writer, err := db.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Close() }()
	close(probe.release)
	active := waitForPhase(t, a, record.ID, "finalizing")
	if err := a.CancelScan(store.DefaultTenantScope(), active.ID); !errors.Is(err, ErrScanFinalizing) {
		t.Fatalf("cancel during finalization = %v, want %v", err, ErrScanFinalizing)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	finished := <-result
	if finished.err != nil || finished.scan.Status != "success" || finished.scan.ID != active.ID {
		t.Fatalf("finalized scan = %#v, %v", finished.scan, finished.err)
	}
	assertBalancedScanLifecycle(t, recorder.take(), record.ID)
}

// A manual run that arrives while a scheduled run of the job is running is
// refused with scanner.ErrBusy, whether the web console or a direct caller
// starts it, and so is a second scheduled run.
func TestRunLifecycleManualRunDuringScheduledRun(t *testing.T) {
	t.Parallel()
	probe := &blockingScanner{started: make(chan struct{}), release: make(chan struct{})}
	a, db := newLifecycleTestApp(t, probe, nil)
	ctx, _ := a.BeginRun(context.Background())
	defer a.StopRun()
	record, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("manual-during-scheduled"))
	if err != nil {
		t.Fatal(err)
	}
	recorder := recordLifecycleEvents(a)
	result := make(chan error, 1)
	go func() {
		_, _, err := a.runJobRecord(ctx, record, false)
		result <- err
	}()
	select {
	case <-probe.started:
	case <-time.After(10 * time.Second):
		t.Fatal("scheduled scan did not start")
	}
	if err := a.StartManagedRun(defaultTenant(db), record.ID, func(model.Scan, []model.Event, error) {
		t.Error("a refused manual run called back")
	}); !errors.Is(err, scanner.ErrBusy) {
		t.Fatalf("web-triggered run during a scheduled run = %v, want %v", err, scanner.ErrBusy)
	}
	if _, _, err := a.RunJobRecord(ctx, record); !errors.Is(err, scanner.ErrBusy) {
		t.Fatalf("direct manual run during a scheduled run = %v, want %v", err, scanner.ErrBusy)
	}
	if _, _, err := a.runJobRecord(ctx, record, false); !errors.Is(err, scanner.ErrBusy) {
		t.Fatalf("second scheduled run = %v, want %v", err, scanner.ErrBusy)
	}
	close(probe.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	events := recorder.take()
	assertBalancedScanLifecycle(t, events, record.ID)
	if skipped := countEvents(events, "scan.skipped"); skipped != 0 {
		t.Fatalf("refused runs reported %d skips: %#v", skipped, events)
	}
}

// Every run that starts a scan publishes exactly one scan.completed event,
// whatever its outcome.
func TestRunLifecycleEveryOutcomeCompletesOnce(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		scanner Scanner
		prepare func(*App, *blockingScanner)
		status  string
	}{
		{name: "success", scanner: schedulerFake{}, status: "success"},
		{name: "scanner failure", scanner: failingScanner{err: errors.New("nmap exited")}, status: "failed"},
		{name: "finalization failure", scanner: schedulerFake{}, prepare: func(a *App, _ *blockingScanner) {
			a.persistenceBudget = func(int) time.Duration { return time.Nanosecond }
		}, status: "failed"},
		{name: "canceled", status: "canceled"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			probe := &blockingScanner{started: make(chan struct{}), release: make(chan struct{})}
			sc := test.scanner
			if sc == nil {
				sc = probe
			}
			a, db := newLifecycleTestApp(t, sc, nil)
			if test.prepare != nil {
				test.prepare(a, probe)
			}
			record, err := defaultTenant(db).CreateJob(context.Background(), lifecycleJob("complete-once-"+test.name))
			if err != nil {
				t.Fatal(err)
			}
			recorder := recordLifecycleEvents(a)
			type outcome struct {
				scan model.Scan
				err  error
			}
			result := make(chan outcome, 1)
			go func() {
				scan, _, err := a.RunJobRecord(context.Background(), record)
				result <- outcome{scan, err}
			}()
			if test.scanner == nil {
				select {
				case <-probe.started:
				case <-time.After(10 * time.Second):
					t.Fatal("scan did not start")
				}
				active := waitForPhase(t, a, record.ID, "starting")
				if err := a.CancelScan(store.DefaultTenantScope(), active.ID); err != nil {
					t.Fatal(err)
				}
			}
			var finished outcome
			select {
			case finished = <-result:
			case <-time.After(10 * time.Second):
				t.Fatal("run did not return")
			}
			if finished.scan.Status != test.status {
				t.Fatalf("scan = %#v, err %v; want status %s", finished.scan, finished.err, test.status)
			}
			assertBalancedScanLifecycle(t, recorder.take(), record.ID)
		})
	}

	// A web-triggered run leaves its completion event to the console's
	// callback, which runs once.
	t.Run("web-triggered", func(t *testing.T) {
		t.Parallel()
		a, db := newLifecycleTestApp(t, schedulerFake{}, nil)
		record, err := defaultTenant(db).CreateJob(context.Background(), lifecycleJob("complete-once-web"))
		if err != nil {
			t.Fatal(err)
		}
		recorder := recordLifecycleEvents(a)
		calls := make(chan model.Scan, 2)
		if err := a.StartManagedRun(defaultTenant(db), record.ID, func(scan model.Scan, _ []model.Event, _ error) { calls <- scan }); err != nil {
			t.Fatal(err)
		}
		select {
		case scan := <-calls:
			if scan.Status != "success" {
				t.Fatalf("web-triggered scan = %#v", scan)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("web-triggered run did not call back")
		}
		a.StopRun()
		if len(calls) != 0 {
			t.Fatalf("completion callbacks = %d, want 1", 1+len(calls))
		}
		events := recorder.take()
		if countEvents(events, "scan.started") != 1 || countEvents(events, "scan.completed") != 0 {
			t.Fatalf("web-triggered run events = %#v", events)
		}
	})
}

// After the application stops its runs, none of them is left in its run
// bookkeeping: not a reservation, a claim, a queued wait or a running scan.
func TestRunLifecycleLeavesNoEntryAfterShutdown(t *testing.T) {
	t.Parallel()
	probe := &blockingScanner{started: make(chan struct{}), release: make(chan struct{})}
	a, db := newLifecycleTestApp(t, probe, nil)
	ctx, _ := a.BeginRun(context.Background())
	running, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("shutdown-running"))
	if err != nil {
		t.Fatal(err)
	}
	queued, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("shutdown-queued"))
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for _, record := range []store.JobRecord{running, queued} {
		if err := a.StartManagedRun(defaultTenant(db), record.ID, func(_ model.Scan, _ []model.Event, err error) { results <- err }); err != nil {
			t.Fatal(err)
		}
		if record.ID == running.ID {
			select {
			case <-probe.started:
			case <-time.After(10 * time.Second):
				t.Fatal("scan did not start")
			}
		}
	}
	waitForSlotQueue(t, a, 1)
	if entries := runEntries(a); entries == 0 {
		t.Fatal("the runs left no bookkeeping while they ran")
	}
	a.StopRun()
	for range 2 {
		if err := <-results; err == nil {
			t.Fatal("a run stopped by shutdown reported no error")
		}
	}
	if entries := runEntries(a); entries != 0 {
		t.Fatalf("run bookkeeping after shutdown has %d entries", entries)
	}
	if active, queuedRuns := a.ActiveScans(store.DefaultTenantScope()), a.QueuedRuns(store.DefaultTenantScope()); len(active) != 0 || len(queuedRuns) != 0 {
		t.Fatalf("after shutdown: active %#v, queued %#v", active, queuedRuns)
	}
	if snapshot := a.slots.CapacitySnapshot(); snapshot.InUse != 0 || snapshot.Queued != 0 {
		t.Fatalf("scan slots after shutdown = %#v", snapshot)
	}
}

// runEntries counts the run bookkeeping entries of a.
func runEntries(a *App) int {
	return a.runs.size()
}
