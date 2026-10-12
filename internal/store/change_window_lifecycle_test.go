package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestCancelBeforeStartDetachesPendingAlertWithoutCoalescing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-cancel-backlog", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "cancel-backlog-destination", job.ID, "changes-detected", "cancel-backlog-scan", time.Now().UTC(), []model.Change{{Key: "cancel-backlog-change", Kind: "port", Target: "192.0.2.20", Port: 443}}, false, 0)

	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	var associated string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id FROM outbox WHERE event_type='changes-detected' AND event_job_id=?`, job.ID).Scan(&associated); err != nil {
		t.Fatal(err)
	}
	if associated != window.ID {
		t.Fatalf("pending pre-window alert associated with %q; want %q", associated, window.ID)
	}

	listed, err := ts.ListChangeWindows(ctx, job.ID)
	if err != nil || len(listed) != 1 || listed[0].ID != window.ID || listed[0].Status != "scheduled" {
		t.Fatalf("scheduled window list = %+v, %v", listed, err)
	}
	loaded, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || loaded.Status != "scheduled" {
		t.Fatalf("scheduled window detail = %+v, %v", loaded, err)
	}

	cancelled, changed, err := ts.CancelChangeWindow(ctx, job.ID, window.ID, "operator-id", "Operator", nil, AuditEntry{})
	if err != nil || !changed {
		t.Fatalf("cancel scheduled window = %+v, changed %v, err %v", cancelled, changed, err)
	}
	if cancelled.Status != "cancelled" || cancelled.EndReason != "cancelled-before-start" || cancelled.ReviewState != "none" || cancelled.Summary != nil || cancelled.EffectiveEnd != nil {
		t.Fatalf("cancelled future window = %+v; expected cancellation without a summary", cancelled)
	}
	loaded, err = ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || loaded.Status != "cancelled" || loaded.EndReason != "cancelled-before-start" {
		t.Fatalf("cancelled window detail = %+v, %v", loaded, err)
	}

	var linked, coalesced, claim, started string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,coalesced_at,claim_token,attempt_started_at FROM outbox WHERE event_type='changes-detected' AND event_job_id=?`, job.ID).Scan(&linked, &coalesced, &claim, &started); err != nil {
		t.Fatal(err)
	}
	if linked != "" || coalesced != "" || claim != "" || started != "" {
		t.Fatalf("pre-start cancellation left outbox linked=%q coalesced=%q claim=%q started=%q", linked, coalesced, claim, started)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM events WHERE type='change-window-summary' AND job_id=?`, job.ID) != 0 {
		t.Fatal("pre-start cancellation emitted a summary")
	}

	deliveries, err := s.System().ClaimDueDeliveries(ctx, 10, "cancel-backlog-worker")
	if err != nil || len(deliveries) != 1 || deliveries[0].Event.Type != "changes-detected" {
		t.Fatalf("detached pending alert was not eligible for normal delivery: %#v, %v", deliveries, err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, deliveries[0].ID, deliveries[0].ClaimToken); err != nil {
		t.Fatalf("detached pending alert could not cross the delivery boundary: %v", err)
	}
}

func TestDueChangeWindowOrderingAndEvidenceFreeExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	firstJob := createWindowTestJob(t, ts, "window-due-first", "UTC")
	secondJob := createWindowTestJob(t, ts, "window-due-second", "UTC")
	now := time.Now().UTC().Truncate(time.Second)

	createActive := func(jobID string) ChangeWindow {
		t.Helper()
		window, err := ts.CreateChangeWindow(ctx, jobID, time.Time{}, now.Add(time.Hour), true, "maintenance", "operator-id", "Operator")
		if err != nil {
			t.Fatal(err)
		}
		return window
	}
	first := createActive(firstJob.ID)
	second := createActive(secondJob.ID)
	firstEnd := now.Add(10 * time.Minute)
	secondEnd := now.Add(15 * time.Minute)
	dueAt := now.Add(20 * time.Minute)
	for _, item := range []struct {
		id  string
		end time.Time
	}{{first.ID, firstEnd}, {second.ID, secondEnd}} {
		if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET end_at=? WHERE id=?`, sqliteTimestamp(item.end), item.id); err != nil {
			t.Fatal(err)
		}
	}

	due, err := s.System().DueChangeWindows(ctx, dueAt, 1)
	if err != nil || len(due) != 1 || due[0].ID != first.ID || due[0].TenantID != ts.scope.id || due[0].JobID != firstJob.ID {
		t.Fatalf("oldest due window = %+v, %v", due, err)
	}
	due, err = s.System().DueChangeWindows(ctx, dueAt, 0)
	if err != nil || len(due) != 2 || due[0].ID != first.ID || due[1].ID != second.ID {
		t.Fatalf("default-batch due windows = %+v, %v", due, err)
	}

	if summary, changed, err := ts.ExpireChangeWindow(ctx, first.ID, func() time.Time { return firstEnd.Add(-time.Second) }, nil); !errors.Is(err, ErrConflict) || changed || !emptyChangeWindowSummary(summary) {
		t.Fatalf("early expiry = summary %+v, changed %v, err %v; want unchanged conflict", summary, changed, err)
	}
	stillOpen, err := ts.GetChangeWindow(ctx, firstJob.ID, first.ID)
	if err != nil || stillOpen.ClosedAt != nil || stillOpen.ReviewState != "none" {
		t.Fatalf("early expiry changed window state: %+v, %v", stillOpen, err)
	}

	closedSummary, changed, err := ts.ExpireChangeWindow(ctx, first.ID, func() time.Time { return firstEnd.Add(time.Second) }, nil)
	if err != nil || !changed || !emptyChangeWindowSummary(closedSummary) {
		t.Fatalf("evidence-free expiry = summary %+v, changed %v, err %v", closedSummary, changed, err)
	}
	closed, err := ts.GetChangeWindow(ctx, firstJob.ID, first.ID)
	if err != nil || closed.EndReason != "expired" || closed.ReviewState != "none" || closed.Summary != nil || closed.ClosedAt == nil {
		t.Fatalf("evidence-free closed window = %+v, %v", closed, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM events WHERE type='change-window-summary' AND job_id=?`, firstJob.ID) != 0 {
		t.Fatal("evidence-free expiry emitted a summary")
	}
	due, err = s.System().DueChangeWindows(ctx, dueAt, 10)
	if err != nil || len(due) != 1 || due[0].ID != second.ID {
		t.Fatalf("due queue after first expiry = %+v, %v", due, err)
	}
}

func emptyChangeWindowSummary(summary ChangeWindowSummary) bool {
	return summary.NewCount == 0 && summary.RecoveredCount == 0 && summary.StillOpenCount == 0 &&
		summary.SuppressedEventCount == 0 && summary.InFlightEventCount == 0 && summary.UnknownOutcomeEventCount == 0 &&
		summary.IncompleteEventCount == 0 && summary.IncompleteReportedChangeCount == 0 &&
		!summary.KnownChangeDetailsTruncated && !summary.StillOpenDetailsTruncated &&
		len(summary.KnownChanges) == 0 && len(summary.StillOpen) == 0
}
