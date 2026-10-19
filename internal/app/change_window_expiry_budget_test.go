package app

import (
	"context"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestExpireChangeWindowsStopsAtHeartbeatBudgetWhenWriterIsBusy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, db := newLifecycleTestApp(t, schedulerFake{}, nil)
	ts := defaultTenant(db)
	job, err := ts.CreateJob(ctx, lifecycleJob("window-expiry-write-budget"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	window, err := ts.CreateChangeWindow(ctx, job.ID, now.Add(-time.Hour), now.Add(time.Hour), true, "planned maintenance", "expiry-test", "Expiry Test")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.System().QueueEvent(ctx, "window-expiry-budget-alert", model.Event{
		Type: "changes-detected", JobID: job.ID, Job: job.Job.Name, ScanID: "window-expiry-budget-scan", CreatedAt: now,
		Changes: []model.Change{{Key: "window-expiry-budget-change", Kind: "port", Target: "192.0.2.92", Port: 443}},
	}); err != nil {
		t.Fatal(err)
	}
	end := now.Add(-time.Second)
	if _, err := db.DB.ExecContext(ctx, `UPDATE change_windows SET end_at=? WHERE id=?`, end.Format(time.RFC3339Nano), window.ID); err != nil {
		t.Fatal(err)
	}
	a.clock = func() time.Time { return now }
	a.heartbeatInterval = 200 * time.Millisecond

	writer, err := db.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	a.expireChangeWindows(ctx, db.System(), false)
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("expiry pass with a held writer took %s; want it bounded by the 100 ms heartbeat budget", elapsed)
	}
	if _, err := writer.ExecContext(ctx, `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	open, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || open.ClosedAt != nil || open.Summary != nil {
		t.Fatalf("busy expiry changed the window: %+v, %v", open, err)
	}
	if got := countRowsForExpiryTest(t, db, `SELECT COUNT(*) FROM outbox WHERE change_window_id=? AND coalesced_at<>''`, window.ID); got != 0 {
		t.Fatalf("busy expiry coalesced %d held alerts; want zero", got)
	}
	// The first pass deliberately has a 100 ms budget. The retry exercises
	// the normal expiry work after the competing writer has released its lock.
	a.heartbeatInterval = 0
	a.expireChangeWindows(ctx, db.System(), false)
	closed, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || closed.ClosedAt == nil || closed.Summary == nil || closed.Summary.SuppressedEventCount != 1 {
		t.Fatalf("expiry retry after writer release = %+v, %v; want a closed window with its held alert", closed, err)
	}
}
