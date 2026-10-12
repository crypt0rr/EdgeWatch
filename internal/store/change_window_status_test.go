package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestChangeWindowStatusProjectionLifecycleAndReviewConflicts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)

	scheduledJob := createWindowTestJob(t, ts, "window-status-scheduled", "UTC")
	start := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	scheduled := createTestChangeWindow(t, ts, scheduledJob.ID, start, start.Add(time.Hour))
	listed, err := ts.ListChangeWindows(ctx, scheduledJob.ID)
	if err != nil || len(listed) != 1 || listed[0].Status != "scheduled" {
		t.Fatalf("scheduled ListChangeWindows status = %+v, %v", listed, err)
	}
	loaded, err := ts.GetChangeWindow(ctx, scheduledJob.ID, scheduled.ID)
	if err != nil || loaded.Status != "scheduled" {
		t.Fatalf("scheduled GetChangeWindow status = %+v, %v", loaded, err)
	}
	for _, tc := range []struct {
		name string
		now  time.Time
		want string
	}{
		{name: "before start", now: start.Add(-time.Nanosecond), want: "scheduled"},
		{name: "exact start", now: start, want: "active"},
		{name: "exact end", now: scheduled.EndAt, want: "expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			projection, err := ts.LatestChangeWindowSummaries(ctx, false, tc.now)
			if err != nil {
				t.Fatal(err)
			}
			status, ok := projection[scheduledJob.ID]
			if !ok || status.ID != scheduled.ID || status.Status != tc.want {
				t.Fatalf("projection at %s = %+v, present %v; want %q", tc.now, status, ok, tc.want)
			}
		})
	}
	cancelledBeforeStart, changed, err := ts.CancelChangeWindow(ctx, scheduledJob.ID, scheduled.ID, "operator", "Operator", nil, AuditEntry{})
	if err != nil || !changed || cancelledBeforeStart.Status != "cancelled" || cancelledBeforeStart.ReviewState != "none" {
		t.Fatalf("pre-start cancellation status = %+v, changed %v, err %v", cancelledBeforeStart, changed, err)
	}
	loaded, err = ts.GetChangeWindow(ctx, scheduledJob.ID, scheduled.ID)
	if err != nil || loaded.Status != "cancelled" || loaded.EndReason != "cancelled-before-start" {
		t.Fatalf("cancelled GetChangeWindow status = %+v, %v", loaded, err)
	}

	activeJob := createWindowTestJob(t, ts, "window-status-active-cancelled", "UTC")
	active, err := ts.CreateChangeWindow(ctx, activeJob.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	activeRead, err := ts.GetChangeWindow(ctx, activeJob.ID, active.ID)
	if err != nil || activeRead.Status != "active" {
		t.Fatalf("active GetChangeWindow status = %+v, %v", activeRead, err)
	}
	queueWindowTestEvent(t, context.Background(), s, "status-window-destination", activeJob.ID, "changes-detected", "status-window-scan", time.Now().UTC(), []model.Change{{Key: "status-change", Kind: "port", Target: "192.0.2.30", Port: 443}}, false, 0)
	closed, changed, err := ts.CancelChangeWindow(ctx, activeJob.ID, active.ID, "operator", "Operator", nil, AuditEntry{})
	if err != nil || !changed || closed.Status != "cancelled" || closed.ReviewState != "due" || closed.Summary == nil {
		t.Fatalf("active cancellation with evidence = %+v, changed %v, err %v", closed, changed, err)
	}
	projection, err := ts.LatestChangeWindowSummaries(ctx, false, time.Now().UTC())
	if err != nil || projection[activeJob.ID].ID != active.ID || projection[activeJob.ID].Status != "cancelled" || projection[activeJob.ID].ReviewState != "due" {
		t.Fatalf("cancelled review projection = %+v, %v", projection, err)
	}
	if _, err := ts.ReviewChangeWindow(ctx, activeJob.ID, active.ID, closed.Revision-1, "reviewer-id", "Reviewer", AuditEntry{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale review revision error = %v; want ErrConflict", err)
	}
	if _, err := ts.ReviewChangeWindow(ctx, activeJob.ID, active.ID, closed.Revision, "reviewer-id", " ", AuditEntry{}); !errors.Is(err, ErrValidation) {
		t.Fatalf("empty reviewer label error = %v; want ErrValidation", err)
	}
	reviewed, err := ts.ReviewChangeWindow(ctx, activeJob.ID, active.ID, closed.Revision, "reviewer-id", "Reviewer", AuditEntry{})
	if err != nil || reviewed.ReviewState != "reviewed" || reviewed.Status != "cancelled" {
		t.Fatalf("reviewed cancellation = %+v, %v", reviewed, err)
	}
	if _, err := ts.ReviewChangeWindow(ctx, activeJob.ID, active.ID, closed.Revision, "reviewer-id", "Reviewer", AuditEntry{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("repeat stale review revision error = %v; want ErrConflict", err)
	}
	if _, changed, err := ts.CancelChangeWindow(ctx, activeJob.ID, active.ID, "operator", "Operator", nil, AuditEntry{}); !errors.Is(err, ErrConflict) || changed {
		t.Fatalf("cancel already-closed window = changed %v, err %v; want conflict", changed, err)
	}
}

func TestGetAndLatestProjectExpiredUnclosedWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-status-expired", "UTC")
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	start := end.Add(-time.Hour)
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=?,end_at=? WHERE id=?`, sqliteTimestamp(start), sqliteTimestamp(end), window.ID); err != nil {
		t.Fatal(err)
	}
	loaded, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || loaded.Status != "expired" || loaded.ClosedAt != nil {
		t.Fatalf("expired-unclosed detail = %+v, %v", loaded, err)
	}
	listed, err := ts.ListChangeWindows(ctx, job.ID)
	if err != nil || len(listed) != 1 || listed[0].Status != "expired" {
		t.Fatalf("expired-unclosed list = %+v, %v", listed, err)
	}
	projection, err := ts.LatestChangeWindowSummaries(ctx, false, time.Now().UTC())
	if err != nil || projection[job.ID].ID != window.ID || projection[job.ID].Status != "expired" {
		t.Fatalf("expired-unclosed latest projection = %+v, %v", projection, err)
	}
}

func TestCancelAfterWindowEndClosesAsExpired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-cancel-after-end", "UTC")
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	start := end.Add(-time.Hour)
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=?,end_at=? WHERE id=?`, sqliteTimestamp(start), sqliteTimestamp(end), window.ID); err != nil {
		t.Fatal(err)
	}
	closed, changed, err := ts.CancelChangeWindow(ctx, job.ID, window.ID, "operator", "Operator", nil, AuditEntry{})
	if err != nil || !changed || closed.Status != "expired" || closed.EndReason != "expired" || closed.ReviewState != "none" || closed.Summary != nil || closed.EffectiveEnd == nil || !closed.EffectiveEnd.Equal(end) {
		t.Fatalf("cancel after end = %+v, changed %v, err %v; want a summary-free expiry close", closed, changed, err)
	}
}

func TestCreateChangeWindowUsesUTCForLegacyEmptyZoneAndRejectsInvalidZone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	now := time.Now().UTC()

	emptyZoneJob := createWindowTestJob(t, ts, "window-empty-legacy-zone", "UTC")
	legacyDefinition := emptyZoneJob.Job
	legacyDefinition.Timezone = ""
	raw, err := marshalJob(legacyDefinition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE jobs SET definition_json=? WHERE id=? AND tenant_id=?`, raw, emptyZoneJob.ID, ts.scope.id); err != nil {
		t.Fatal(err)
	}
	window, err := ts.CreateChangeWindow(ctx, emptyZoneJob.ID, time.Time{}, now.Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil || window.Timezone != "UTC" {
		t.Fatalf("window for legacy empty timezone = %+v, %v; want UTC", window, err)
	}

	invalidZoneJob := createWindowTestJob(t, ts, "window-invalid-legacy-zone", "UTC")
	invalidDefinition := invalidZoneJob.Job
	invalidDefinition.Timezone = "Mars/Olympus_Mons"
	raw, err = marshalJob(invalidDefinition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE jobs SET definition_json=? WHERE id=? AND tenant_id=?`, raw, invalidZoneJob.ID, ts.scope.id); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.CreateChangeWindow(ctx, invalidZoneJob.ID, time.Time{}, now.Add(time.Hour), true, "maintenance", "operator", "Operator"); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid stored job timezone error = %v; want ErrValidation", err)
	}
}

func TestLatestChangeWindowProjectionDefaultsZeroTimeToCurrentClock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-zero-projection-clock", "UTC")
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}

	projection, err := ts.LatestChangeWindowSummaries(ctx, false, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	status, ok := projection[job.ID]
	if !ok || status.ID != window.ID || status.Status != "active" {
		t.Fatalf("zero-time projection = %+v, present %v; want active window %q using the current clock", status, ok, window.ID)
	}
}

func TestActiveWindowCancelAuditFailureRollsBackCloseAndSummary(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-cancel-audit-rollback", "UTC")
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	queueWindowTestEvent(t, context.Background(), s, "rollback-change-destination", job.ID, "changes-detected", "rollback-change-scan", time.Now().UTC(), []model.Change{{Key: "rollback-change", Kind: "port", Target: "192.0.2.40", Port: 443}}, false, 0)
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_change_window_cancel_audit BEFORE INSERT ON security_audit WHEN NEW.action='change_window.cancelled' BEGIN SELECT RAISE(ABORT,'synthetic cancel audit failure'); END`); err != nil {
		t.Fatal(err)
	}

	if cancelled, changed, err := ts.CancelChangeWindow(ctx, job.ID, window.ID, "operator", "Operator", []string{"rollback-summary-destination"}, AuditEntry{}); !errors.Is(err, ErrAuditUnavailable) || changed || cancelled.ID != "" {
		t.Fatalf("cancel with audit failure = %+v, changed %v, err %v; want a rolled-back audit error", cancelled, changed, err)
	}
	var closedAt, summaryJSON, reviewState string
	var revision int64
	if err := s.DB.QueryRowContext(ctx, `SELECT closed_at,summary_json,review_state,revision FROM change_windows WHERE id=?`, window.ID).Scan(&closedAt, &summaryJSON, &reviewState, &revision); err != nil {
		t.Fatal(err)
	}
	if closedAt != "" || summaryJSON != "" || reviewState != "none" || revision != window.Revision {
		t.Fatalf("failed cancel left window closed=%q summary=%q review=%q revision=%d; want original open state revision=%d", closedAt, summaryJSON, reviewState, revision, window.Revision)
	}
	var linked, coalesced, sent string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,coalesced_at,COALESCE(sent_at,'') FROM outbox WHERE event_type='changes-detected' AND event_job_id=?`, job.ID).Scan(&linked, &coalesced, &sent); err != nil {
		t.Fatal(err)
	}
	if linked != window.ID || coalesced != "" || sent != "" {
		t.Fatalf("failed cancel changed pending alert link=%q coalesced=%q sent=%q", linked, coalesced, sent)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM events WHERE type='change-window-summary' AND job_id=?`, job.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE event_type='change-window-summary' AND event_job_id=?`, job.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM security_audit WHERE action='change_window.cancelled' AND detail LIKE ?`, "%"+window.ID+"%") != 0 {
		t.Fatal("failed cancel persisted a summary or cancellation audit despite transaction rollback")
	}
}
