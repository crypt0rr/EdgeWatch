package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCancelScheduledChangeWindowRechecksStartAfterWriterWait(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "cancel-scheduled-writer-race", "UTC")
	start := time.Now().UTC().Add(2 * time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	before := tenantJobDigest(t, s, ts.scope)

	release := holdWriteLock(t, s.FilePath())
	released := false
	releaseLock := func() {
		if !released {
			release()
			released = true
		}
	}
	defer releaseLock()

	type result struct {
		changed bool
		err     error
	}
	started := make(chan struct{})
	completed := make(chan result, 1)
	go func() {
		close(started)
		_, changed, err := ts.CancelScheduledChangeWindow(ctx, job.ID, window.ID, "actor", "Operator", AuditEntry{})
		completed <- result{changed: changed, err: err}
	}()
	<-started
	// The cancellation request is blocked behind the separate writer. Release
	// only after its scheduled start so the store must decide from the time
	// sampled after acquiring the transaction, not from a preflight check.
	if wait := time.Until(start.Add(100 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	releaseLock()

	select {
	case got := <-completed:
		if got.changed || !errors.Is(got.err, ErrConflict) {
			t.Fatalf("cancel after scheduled start = changed %v, err %v; want unchanged ErrConflict", got.changed, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scheduled cancellation did not finish after writer lock release")
	}
	if after := tenantJobDigest(t, s, ts.scope); after != before {
		t.Fatal("refused scheduled cancellation changed tenant state")
	}
	got, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || got.ClosedAt != nil || got.Status != "active" {
		t.Fatalf("window after refused cancel = %+v, %v; want still-open active window", got, err)
	}
}
