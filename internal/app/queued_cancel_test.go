package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestCancelQueuedRunEndsTheWaitAndReportsTheSkip(t *testing.T) {
	t.Parallel()
	a, db := newLifecycleTestApp(t, schedulerFake{}, nil)
	ctx, _ := a.BeginRun(context.Background())
	record, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("queued-cancel"))
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan model.Event, 8)
	a.SetEventHandler(func(event model.Event) { events <- event })
	releaseSlot := holdScanSlot(t, a)
	defer releaseSlot()
	done := make(chan error, 1)
	if err := a.StartManagedRun(defaultTenant(db), record.ID, func(_ model.Scan, _ []model.Event, err error) { done <- err }); err != nil {
		t.Fatal(err)
	}
	waitForSlotQueue(t, a, 1)
	scope := store.DefaultTenantScope()
	if queued := a.QueuedRuns(scope); len(queued) != 1 || queued[0].JobID != record.ID {
		t.Fatalf("queued runs = %#v", queued)
	}

	// A scope without a unit cannot cancel the run.
	if err := a.CancelQueuedRun(store.TenantScope{}, record.ID); !errors.Is(err, ErrRunNotQueued) {
		t.Fatalf("cancel without a unit = %v, want ErrRunNotQueued", err)
	}
	if err := a.CancelQueuedRun(scope, record.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrQueuedRunCanceled) {
			t.Fatalf("canceled queued run result = %v, want ErrQueuedRunCanceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled queued run did not return")
	}
	if queued := a.QueuedRuns(scope); len(queued) != 0 {
		t.Fatalf("queued runs after cancel = %#v", queued)
	}
	if err := a.CancelQueuedRun(scope, record.ID); !errors.Is(err, ErrRunNotQueued) {
		t.Fatalf("second cancel = %v, want ErrRunNotQueued", err)
	}
	// The run never took a slot; the slot this test holds is still the only
	// one in use.
	want := slotSnapshot{Capacity: 1, InUse: 1, Keys: map[string]slotUsage{defaultSlotKey: {InUse: 1, Limit: 1}}}
	if got := a.slots.CapacitySnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("slots after cancel = %#v, want %#v", got, want)
	}
	var skipped []model.Event
	for len(events) > 0 {
		event := <-events
		if event.Type == "scan.started" {
			t.Fatalf("canceled queued run started: %+v", event)
		}
		if event.Type == "scan.skipped" {
			skipped = append(skipped, event)
		}
	}
	if len(skipped) != 1 || skipped[0].Reason != "canceled" || skipped[0].JobID != record.ID {
		t.Fatalf("skip events = %+v, want one canceled skip", skipped)
	}
	scans, err := defaultTenant(db).ListJobScans(context.Background(), record.ID, 10)
	if err != nil || len(scans) != 0 {
		t.Fatalf("canceled queued run persisted scans: %#v, %v", scans, err)
	}
}

func TestCancelQueuedRunRefusesARunThatTookItsSlot(t *testing.T) {
	t.Parallel()
	a := &App{}
	scope := store.DefaultTenantScope()
	canceled := false
	entry := &queuedRun{run: model.QueuedRun{JobID: "job", TenantID: scope.ID()}, cancel: func(error) { canceled = true }}
	a.runs.enqueue("job", entry)
	if !entry.start() {
		t.Fatal("an uncanceled run could not start")
	}
	if err := a.CancelQueuedRun(scope, "job"); !errors.Is(err, ErrRunNotQueued) || canceled {
		t.Fatalf("cancel after start = %v (canceled %v), want ErrRunNotQueued", err, canceled)
	}
	if err := a.CancelQueuedRun(scope, "missing"); !errors.Is(err, ErrRunNotQueued) {
		t.Fatalf("cancel of a job without a queued run = %v", err)
	}
	foreign := &queuedRun{run: model.QueuedRun{JobID: "foreign", TenantID: "another-unit"}, cancel: func(error) { canceled = true }}
	a.runs.enqueue("foreign", foreign)
	if err := a.CancelQueuedRun(scope, "foreign"); !errors.Is(err, ErrRunNotQueued) || canceled {
		t.Fatalf("cancel of another unit's run = %v (canceled %v), want ErrRunNotQueued", err, canceled)
	}

	late := &queuedRun{run: model.QueuedRun{JobID: "late", TenantID: scope.ID()}, cancel: func(error) {}}
	a.runs.enqueue("late", late)
	if err := a.CancelQueuedRun(scope, "late"); err != nil {
		t.Fatal(err)
	}
	if late.start() {
		t.Fatal("a run canceled as its slot was granted still started")
	}
	if got := scanSkipReason(ErrQueuedRunCanceled); got != "canceled" {
		t.Fatalf("skip reason = %q, want canceled", got)
	}
}
