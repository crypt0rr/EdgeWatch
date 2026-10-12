package app

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestExpireChangeWindowsLogsAndRollsBackCloseFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var logs strings.Builder
	a, db := newLifecycleTestApp(t, schedulerFake{}, &logs)
	ts := defaultTenant(db)
	job, err := ts.CreateJob(ctx, lifecycleJob("expiry-close-write-failure"))
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().UTC().Add(time.Hour)
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, end, true, "planned maintenance", "expiry-test", "Expiry Test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `CREATE TRIGGER fail_change_window_expiry BEFORE UPDATE OF closed_at ON change_windows BEGIN SELECT RAISE(ABORT,'synthetic close failure'); END`); err != nil {
		t.Fatal(err)
	}
	a.clock = func() time.Time { return end.Add(time.Second) }
	a.expireChangeWindows(ctx, db.System(), false)

	if !strings.Contains(logs.String(), "planned change window expiry failed") || !strings.Contains(logs.String(), window.ID) || !strings.Contains(logs.String(), "synthetic close failure") {
		t.Fatalf("expiry write failure was not logged with its window context: %q", logs.String())
	}
	stillOpen, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stillOpen.ClosedAt != nil || stillOpen.ReviewState != "none" || stillOpen.Summary != nil {
		t.Fatalf("failed close left partial window state: %+v", stillOpen)
	}
	var summaries int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE type='change-window-summary' AND job_id=?`, job.ID).Scan(&summaries); err != nil {
		t.Fatal(err)
	}
	if summaries != 0 {
		t.Fatalf("failed close persisted %d summary events", summaries)
	}
}

func TestExpireChangeWindowsDoesNotLogCanceledLookup(t *testing.T) {
	t.Parallel()
	var logs strings.Builder
	a, db := newLifecycleTestApp(t, schedulerFake{}, &logs)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.expireChangeWindows(ctx, db.System(), true)
	if strings.Contains(logs.String(), "planned change window expiry lookup failed") {
		t.Fatalf("canceled expiry lookup was logged as an operational failure: %q", logs.String())
	}
}
