package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestChangeWindowReadsFailClosedWhenWindowTableIsUnavailable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-read-schema-failure", "UTC")
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))

	if _, err := s.DB.ExecContext(ctx, `ALTER TABLE change_windows RENAME TO unavailable_change_windows`); err != nil {
		t.Fatal(err)
	}
	if windows, err := ts.ListChangeWindows(ctx, job.ID); err == nil || windows != nil {
		t.Fatalf("ListChangeWindows with unavailable table = %+v, %v; want an error and no data", windows, err)
	}
	if loaded, err := ts.GetChangeWindow(ctx, job.ID, window.ID); err == nil || errors.Is(err, ErrNotFound) || loaded.ID != "" {
		t.Fatalf("GetChangeWindow with unavailable table = %+v, %v; want a storage error and no data", loaded, err)
	}
	if latest, err := ts.LatestChangeWindowSummaries(ctx, false, time.Now().UTC()); err == nil || latest != nil {
		t.Fatalf("LatestChangeWindowSummaries with unavailable table = %+v, %v; want an error and no data", latest, err)
	}
	if due, err := s.System().DueChangeWindows(ctx, time.Now().UTC().Add(2*time.Hour), 10); err == nil || due != nil {
		t.Fatalf("DueChangeWindows with unavailable table = %+v, %v; want an error and no data", due, err)
	}
	if count := countRows(t, s.DB, `SELECT COUNT(*) FROM unavailable_change_windows WHERE id=?`, window.ID); count != 1 {
		t.Fatalf("renamed backing table contains %d windows; want the original row preserved", count)
	}
}

func TestChangeWindowMethodsFailClosedWhenPurgeMetadataIsUnavailable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-purge-schema-failure", "UTC")
	window := createTestChangeWindow(t, ts, job.ID, time.Now().UTC().Add(time.Hour), time.Now().UTC().Add(2*time.Hour))
	ended := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	started := ended.Add(-time.Hour)
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=?,end_at=? WHERE id=?`, sqliteTimestamp(started), sqliteTimestamp(ended), window.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TABLE job_history_purges`); err != nil {
		t.Fatal(err)
	}

	newStart := time.Now().UTC().Add(3 * time.Hour).Truncate(time.Second)
	if created, err := ts.CreateChangeWindow(ctx, job.ID, newStart, newStart.Add(time.Hour), false, "maintenance", "operator", "Operator"); err == nil || created.ID != "" {
		t.Fatalf("CreateChangeWindow with missing purge metadata = %+v, %v; want a storage error and no result", created, err)
	}
	if windows, err := ts.ListChangeWindows(ctx, job.ID); err == nil || windows != nil {
		t.Fatalf("ListChangeWindows with missing purge metadata = %+v, %v; want a storage error and no data", windows, err)
	}
	if due, err := s.System().DueChangeWindows(ctx, time.Now().UTC(), 10); err == nil || due != nil {
		t.Fatalf("DueChangeWindows with missing purge metadata = %+v, %v; want a storage error and no data", due, err)
	}
	if summary, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return ended.Add(time.Second) }, nil); err == nil || changed || summary.NewCount != 0 || summary.RecoveredCount != 0 || summary.StillOpenCount != 0 || summary.KnownChanges != nil || summary.StillOpen != nil {
		t.Fatalf("ExpireChangeWindow with missing purge metadata = %+v, changed %v, err %v; want failure without a result", summary, changed, err)
	}
	if cancelled, changed, err := ts.CancelChangeWindow(ctx, job.ID, window.ID, "operator", "Operator", nil, AuditEntry{}); err == nil || changed || cancelled.ID != "" {
		t.Fatalf("CancelChangeWindow with missing purge metadata = %+v, changed %v, err %v; want failure without a result", cancelled, changed, err)
	}

	loaded, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || loaded.ClosedAt != nil || loaded.Summary != nil || loaded.ReviewState != "none" || loaded.Revision != window.Revision {
		t.Fatalf("storage failures changed the existing window: %+v, %v", loaded, err)
	}
	if count := countRows(t, s.DB, `SELECT COUNT(*) FROM change_windows WHERE job_id=?`, job.ID); count != 1 {
		t.Fatalf("failed create left %d windows; want the original only", count)
	}
	if count := countRows(t, s.DB, `SELECT COUNT(*) FROM security_audit WHERE action IN ('change_window.created','change_window.cancelled') AND detail LIKE ?`, "%"+job.ID+"%"); count != 1 {
		t.Fatalf("storage failures left %d create/cancel audit rows; want only the original create", count)
	}
}

func TestCloseUpdateFailureRollsBackCapturedWindowEvidence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-close-update-failure", "UTC")
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	queueWindowTestEvent(t, context.Background(), s, "close-update-failure-destination", job.ID, "changes-detected", "close-update-failure-scan", time.Now().UTC(), []model.Change{{Key: "close-update-failure-change", Kind: "port", Target: "192.0.2.61", Port: 443}}, false, 0)
	priorEventRefs := countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID)
	priorChangeRefs := countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_refs WHERE window_id=?`, window.ID)
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_change_window_close_update BEFORE UPDATE OF status ON change_windows WHEN NEW.id='`+window.ID+`' AND NEW.status='closed' BEGIN SELECT RAISE(ABORT,'synthetic close update failure'); END`); err != nil {
		t.Fatal(err)
	}

	closed, changed, err := ts.CancelChangeWindow(ctx, job.ID, window.ID, "operator", "Operator", nil, AuditEntry{})
	if err == nil || changed || closed.ID != "" {
		t.Fatalf("CancelChangeWindow with close update failure = %+v, changed %v, err %v; want an atomic failure", closed, changed, err)
	}
	loaded, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || loaded.ClosedAt != nil || loaded.Summary != nil || loaded.ReviewState != "none" || loaded.Revision != window.Revision {
		t.Fatalf("failed close update partially closed the window: %+v, %v", loaded, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID) != priorEventRefs ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_refs WHERE window_id=?`, window.ID) != priorChangeRefs ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM events WHERE type='change-window-summary' AND job_id=?`, job.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE event_type='change-window-summary' AND event_job_id=?`, job.ID) != 0 {
		t.Fatal("failed close update persisted captured evidence or a summary")
	}
	var linked, coalesced string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,coalesced_at FROM outbox WHERE event_type='changes-detected' AND event_job_id=?`, job.ID).Scan(&linked, &coalesced); err != nil {
		t.Fatal(err)
	}
	if linked != window.ID || coalesced != "" {
		t.Fatalf("failed close update changed pending backlog link=%q coalesced=%q", linked, coalesced)
	}
}

func TestSummaryEventFailureRollsBackCloseAndBacklog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-summary-event-failure", "UTC")
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	queueWindowTestEvent(t, context.Background(), s, "summary-event-failure-destination", job.ID, "changes-detected", "summary-event-failure-scan", time.Now().UTC(), []model.Change{{Key: "summary-event-failure-change", Kind: "port", Target: "192.0.2.62", Port: 443}}, false, 0)
	priorEventRefs := countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID)
	priorChangeRefs := countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_refs WHERE window_id=?`, window.ID)
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_change_window_summary_event BEFORE INSERT ON events WHEN NEW.type='change-window-summary' BEGIN SELECT RAISE(ABORT,'synthetic summary event failure'); END`); err != nil {
		t.Fatal(err)
	}

	closed, changed, err := ts.CancelChangeWindow(ctx, job.ID, window.ID, "operator", "Operator", []string{"summary-event-failure-destination"}, AuditEntry{})
	if err == nil || changed || closed.ID != "" {
		t.Fatalf("CancelChangeWindow with summary event failure = %+v, changed %v, err %v; want an atomic failure", closed, changed, err)
	}
	loaded, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || loaded.ClosedAt != nil || loaded.Summary != nil || loaded.ReviewState != "none" || loaded.Revision != window.Revision {
		t.Fatalf("failed summary event insertion partially closed the window: %+v, %v", loaded, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID) != priorEventRefs ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_refs WHERE window_id=?`, window.ID) != priorChangeRefs ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM events WHERE type='change-window-summary' AND job_id=?`, job.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE event_type='change-window-summary' AND event_job_id=?`, job.ID) != 0 {
		t.Fatal("failed summary event insertion persisted close evidence or a summary")
	}
	var linked, coalesced string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,coalesced_at FROM outbox WHERE event_type='changes-detected' AND event_job_id=?`, job.ID).Scan(&linked, &coalesced); err != nil {
		t.Fatal(err)
	}
	if linked != window.ID || coalesced != "" {
		t.Fatalf("failed summary event insertion changed pending backlog link=%q coalesced=%q", linked, coalesced)
	}
}

func TestGetChangeWindowRejectsCorruptSummaryJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-corrupt-summary", "UTC")
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	queueWindowTestEvent(t, context.Background(), s, "corrupt-summary-destination", job.ID, "changes-detected", "corrupt-summary-scan", time.Now().UTC(), []model.Change{{Key: "corrupt-summary-change", Kind: "port", Target: "192.0.2.63", Port: 443}}, false, 0)
	closed, changed, err := ts.CancelChangeWindow(ctx, job.ID, window.ID, "operator", "Operator", nil, AuditEntry{})
	if err != nil || !changed || closed.Summary == nil {
		t.Fatalf("setup close = %+v, changed %v, err %v", closed, changed, err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET summary_json=? WHERE id=?`, []byte("{"), window.ID); err != nil {
		t.Fatal(err)
	}

	loaded, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err == nil || loaded.Summary != nil {
		t.Fatalf("GetChangeWindow with corrupt summary JSON = %+v, %v; want an error and no decoded summary", loaded, err)
	}
}

func TestReviewUpdateFailureLeavesSummaryDue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-review-update-failure", "UTC")
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	queueWindowTestEvent(t, context.Background(), s, "review-update-failure-destination", job.ID, "changes-detected", "review-update-failure-scan", time.Now().UTC(), []model.Change{{Key: "review-update-failure-change", Kind: "port", Target: "192.0.2.64", Port: 443}}, false, 0)
	closed, changed, err := ts.CancelChangeWindow(ctx, job.ID, window.ID, "operator", "Operator", nil, AuditEntry{})
	if err != nil || !changed || closed.ReviewState != "due" || closed.Summary == nil {
		t.Fatalf("setup close = %+v, changed %v, err %v", closed, changed, err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_change_window_review_update BEFORE UPDATE OF review_state ON change_windows WHEN NEW.id='`+window.ID+`' AND NEW.review_state='reviewed' BEGIN SELECT RAISE(ABORT,'synthetic review update failure'); END`); err != nil {
		t.Fatal(err)
	}

	if reviewed, err := ts.ReviewChangeWindow(ctx, job.ID, window.ID, closed.Revision, "reviewer", "Reviewer", AuditEntry{}); err == nil || reviewed.ID != "" {
		t.Fatalf("ReviewChangeWindow with update failure = %+v, %v; want a storage error and no result", reviewed, err)
	}
	stillDue, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || stillDue.ReviewState != "due" || stillDue.Revision != closed.Revision || stillDue.ReviewedAt != nil || stillDue.ReviewerLabel != "" || stillDue.Summary == nil {
		t.Fatalf("failed review update changed durable due state: %+v, %v", stillDue, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM security_audit WHERE action='change_window.reviewed' AND detail LIKE ?`, "%"+window.ID+"%") != 0 {
		t.Fatal("failed review update nevertheless persisted an audit entry")
	}
}

func TestCreateWindowRejectsCorruptJobDefinitionWithoutMutation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-corrupt-job-definition", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "corrupt-job-definition-destination", job.ID, "changes-detected", "corrupt-job-definition-scan", time.Now().UTC(), []model.Change{{Key: "corrupt-job-definition-change", Kind: "port", Target: "192.0.2.65", Port: 443}}, false, 0)
	var linkedBefore, coalescedBefore string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,coalesced_at FROM outbox WHERE event_type='changes-detected' AND event_job_id=?`, job.ID).Scan(&linkedBefore, &coalescedBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE jobs SET definition_json=? WHERE id=?`, []byte("{"), job.ID); err != nil {
		t.Fatal(err)
	}

	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	if created, err := ts.CreateChangeWindow(ctx, job.ID, start, start.Add(time.Hour), false, "maintenance", "operator", "Operator"); err == nil || created.ID != "" {
		t.Fatalf("CreateChangeWindow with corrupt job definition = %+v, %v; want a storage error and no result", created, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_windows WHERE job_id=?`, job.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM security_audit WHERE action='change_window.created' AND detail LIKE ?`, "%"+job.ID+"%") != 0 {
		t.Fatal("failed creation from corrupt job data left a window or audit")
	}
	var linkedAfter, coalescedAfter string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,coalesced_at FROM outbox WHERE event_type='changes-detected' AND event_job_id=?`, job.ID).Scan(&linkedAfter, &coalescedAfter); err != nil {
		t.Fatal(err)
	}
	if linkedAfter != linkedBefore || coalescedAfter != coalescedBefore {
		t.Fatalf("corrupt job definition changed pending alert link/coalescing from %q/%q to %q/%q", linkedBefore, coalescedBefore, linkedAfter, coalescedAfter)
	}
}

func TestCreateWindowInsertFailurePreservesPendingBacklog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-insert-failure", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "window-insert-failure-destination", job.ID, "changes-detected", "window-insert-failure-scan", time.Now().UTC(), []model.Change{{Key: "window-insert-failure-change", Kind: "port", Target: "192.0.2.66", Port: 443}}, false, 0)
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_change_window_insert BEFORE INSERT ON change_windows WHEN NEW.job_id='`+job.ID+`' BEGIN SELECT RAISE(ABORT,'synthetic window insert failure'); END`); err != nil {
		t.Fatal(err)
	}

	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	if created, err := ts.CreateChangeWindow(ctx, job.ID, start, start.Add(time.Hour), false, "maintenance", "operator", "Operator"); err == nil || created.ID != "" {
		t.Fatalf("CreateChangeWindow with insert failure = %+v, %v; want an error and no result", created, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_windows WHERE job_id=?`, job.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM security_audit WHERE action='change_window.created' AND detail LIKE ?`, "%"+job.ID+"%") != 0 {
		t.Fatal("failed window insert left a window or audit")
	}
	var linked, coalesced string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,coalesced_at FROM outbox WHERE event_type='changes-detected' AND event_job_id=?`, job.ID).Scan(&linked, &coalesced); err != nil {
		t.Fatal(err)
	}
	if linked != "" || coalesced != "" {
		t.Fatalf("failed window insert changed pending backlog link=%q coalesced=%q", linked, coalesced)
	}
}

func TestMissingWindowOperationsPreserveErrorContractsAndLatestUsesCurrentTime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-missing-row-contracts", "UTC")

	if windows, err := ts.ListChangeWindows(ctx, "unknown-job"); !errors.Is(err, ErrNotFound) || windows != nil {
		t.Fatalf("ListChangeWindows for unknown job = %+v, %v; want ErrNotFound", windows, err)
	}
	if window, err := ts.GetChangeWindow(ctx, job.ID, "unknown-window"); !errors.Is(err, ErrNotFound) || window.ID != "" {
		t.Fatalf("GetChangeWindow for unknown id = %+v, %v; want ErrNotFound", window, err)
	}
	if summary, changed, err := ts.ExpireChangeWindow(ctx, "unknown-window", nil, nil); !errors.Is(err, ErrNotFound) || changed || summary.NewCount != 0 || summary.KnownChanges != nil {
		t.Fatalf("ExpireChangeWindow for unknown id = %+v, changed %v, err %v; want ErrNotFound", summary, changed, err)
	}
	if window, changed, err := ts.CancelChangeWindow(ctx, job.ID, "unknown-window", "operator", "Operator", nil, AuditEntry{}); !errors.Is(err, ErrNotFound) || changed || window.ID != "" {
		t.Fatalf("CancelChangeWindow for unknown id = %+v, changed %v, err %v; want ErrNotFound", window, changed, err)
	}
	if window, err := ts.ReviewChangeWindow(ctx, job.ID, "unknown-window", 1, "reviewer", "Reviewer", AuditEntry{}); !errors.Is(err, ErrConflict) || window.ID != "" {
		t.Fatalf("ReviewChangeWindow for unknown id = %+v, %v; want ErrConflict", window, err)
	}
	if due, err := s.System().DueChangeWindows(ctx, time.Now().UTC(), 10); err != nil || len(due) != 0 {
		t.Fatalf("DueChangeWindows without due rows = %+v, %v; want an empty result", due, err)
	}
	if latest, err := ts.LatestChangeWindowSummaries(ctx, false, time.Now().UTC()); err != nil || len(latest) != 0 {
		t.Fatalf("LatestChangeWindowSummaries without windows = %+v, %v; want an empty result", latest, err)
	}
}

func TestExpireChangeWindowUsesClockFallbackAndClosesDueWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-expiry-clock-fallback", "UTC")
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	queueWindowTestEvent(t, context.Background(), s, "expiry-clock-fallback-destination", job.ID, "changes-detected", "expiry-clock-fallback-scan", time.Now().UTC(), []model.Change{{Key: "expiry-clock-fallback-change", Kind: "port", Target: "192.0.2.67", Port: 443}}, false, 0)
	ended := time.Now().UTC().Add(-time.Second).Truncate(time.Second)
	started := ended.Add(-time.Hour)
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=?,end_at=? WHERE id=?`, sqliteTimestamp(started), sqliteTimestamp(ended), window.ID); err != nil {
		t.Fatal(err)
	}

	summary, changed, err := ts.ExpireChangeWindow(ctx, window.ID, nil, nil)
	if err != nil || !changed || summary.SuppressedEventCount != 1 {
		t.Fatalf("ExpireChangeWindow with nil clock = %+v, changed %v, err %v; want the due window closed from the fallback clock", summary, changed, err)
	}
	closed, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || closed.ClosedAt == nil || closed.EndReason != "expired" || closed.ReviewState != "due" || closed.Summary == nil {
		t.Fatalf("nil-clock expiry persisted state = %+v, %v", closed, err)
	}
}

func TestCreateWindowAuditFailureRollsBackAssociationAndWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-create-audit-failure", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "create-audit-failure-destination", job.ID, "changes-detected", "create-audit-failure-scan", time.Now().UTC(), []model.Change{{Key: "create-audit-failure-change", Kind: "port", Target: "192.0.2.71", Port: 443}}, false, 0)
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_change_window_create_audit BEFORE INSERT ON security_audit WHEN NEW.action='change_window.created' BEGIN SELECT RAISE(ABORT,'synthetic create audit failure'); END`); err != nil {
		t.Fatal(err)
	}

	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	if created, err := ts.CreateChangeWindow(ctx, job.ID, start, start.Add(time.Hour), false, "maintenance", "operator", "Operator"); err == nil || created.ID != "" {
		t.Fatalf("CreateChangeWindow with audit failure = %+v, %v; want an error and no result", created, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_windows WHERE job_id=?`, job.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM security_audit WHERE action='change_window.created' AND detail LIKE ?`, "%"+job.ID+"%") != 0 {
		t.Fatal("failed creation audit left a window or audit row")
	}
	var linked, coalesced string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,coalesced_at FROM outbox WHERE event_type='changes-detected' AND event_job_id=?`, job.ID).Scan(&linked, &coalesced); err != nil {
		t.Fatal(err)
	}
	if linked != "" || coalesced != "" {
		t.Fatalf("failed creation audit changed pending backlog link=%q coalesced=%q", linked, coalesced)
	}
}

func TestCancelBeforeStartDetachFailureRollsBackWindowAndBacklog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-cancel-detach-failure", "UTC")
	start := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	queueWindowTestEvent(t, context.Background(), s, "cancel-detach-failure-destination", job.ID, "changes-detected", "cancel-detach-failure-scan", time.Now().UTC(), []model.Change{{Key: "cancel-detach-failure-change", Kind: "port", Target: "192.0.2.72", Port: 443}}, false, 0)
	var linkedBefore string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id FROM outbox WHERE event_type='changes-detected' AND event_job_id=?`, job.ID).Scan(&linkedBefore); err != nil || linkedBefore != window.ID {
		t.Fatalf("scheduled window association = %q, %v; want %q", linkedBefore, err, window.ID)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_change_window_detach BEFORE UPDATE OF change_window_id ON outbox WHEN OLD.change_window_id='`+window.ID+`' AND NEW.change_window_id='' BEGIN SELECT RAISE(ABORT,'synthetic detach failure'); END`); err != nil {
		t.Fatal(err)
	}

	if cancelled, changed, err := ts.CancelChangeWindow(ctx, job.ID, window.ID, "operator", "Operator", nil, AuditEntry{}); err == nil || changed || cancelled.ID != "" {
		t.Fatalf("CancelChangeWindow with detach failure = %+v, changed %v, err %v; want an atomic failure", cancelled, changed, err)
	}
	loaded, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || loaded.ClosedAt != nil || loaded.Status != "scheduled" || loaded.Revision != window.Revision {
		t.Fatalf("failed detach changed scheduled window: %+v, %v", loaded, err)
	}
	var linkedAfter, coalesced string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,coalesced_at FROM outbox WHERE event_type='changes-detected' AND event_job_id=?`, job.ID).Scan(&linkedAfter, &coalesced); err != nil {
		t.Fatal(err)
	}
	if linkedAfter != window.ID || coalesced != "" || countRows(t, s.DB, `SELECT COUNT(*) FROM security_audit WHERE action='change_window.cancelled' AND detail LIKE ?`, "%"+window.ID+"%") != 0 {
		t.Fatalf("failed detach changed backlog/audit link=%q coalesced=%q", linkedAfter, coalesced)
	}
}

func TestSummaryOutboxFailureRollsBackCloseAndEvent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-summary-outbox-failure", "UTC")
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	queueWindowTestEvent(t, context.Background(), s, "summary-outbox-failure-destination", job.ID, "changes-detected", "summary-outbox-failure-scan", time.Now().UTC(), []model.Change{{Key: "summary-outbox-failure-change", Kind: "port", Target: "192.0.2.73", Port: 443}}, false, 0)
	priorEventRefs := countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID)
	priorChangeRefs := countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_refs WHERE window_id=?`, window.ID)
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_change_window_summary_outbox BEFORE INSERT ON outbox WHEN NEW.event_type='change-window-summary' AND NEW.event_job_id='`+job.ID+`' BEGIN SELECT RAISE(ABORT,'synthetic summary outbox failure'); END`); err != nil {
		t.Fatal(err)
	}

	if closed, changed, err := ts.CancelChangeWindow(ctx, job.ID, window.ID, "operator", "Operator", []string{"summary-outbox-failure-destination"}, AuditEntry{}); err == nil || changed || closed.ID != "" {
		t.Fatalf("CancelChangeWindow with summary outbox failure = %+v, changed %v, err %v; want an atomic failure", closed, changed, err)
	}
	loaded, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || loaded.ClosedAt != nil || loaded.Summary != nil || loaded.ReviewState != "none" || loaded.Revision != window.Revision {
		t.Fatalf("failed summary queue partially closed window: %+v, %v", loaded, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID) != priorEventRefs ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_refs WHERE window_id=?`, window.ID) != priorChangeRefs ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM events WHERE type='change-window-summary' AND job_id=?`, job.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE event_type='change-window-summary' AND event_job_id=?`, job.ID) != 0 {
		t.Fatal("failed summary queue persisted close mutations or summary rows")
	}
	var linked, coalesced string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,coalesced_at FROM outbox WHERE event_type='changes-detected' AND event_job_id=?`, job.ID).Scan(&linked, &coalesced); err != nil {
		t.Fatal(err)
	}
	if linked != window.ID || coalesced != "" {
		t.Fatalf("failed summary queue changed pending backlog link=%q coalesced=%q", linked, coalesced)
	}
}

func TestCloseRejectsCorruptChangeReferenceWithoutClosingWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-corrupt-change-reference", "UTC")
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	queueWindowTestEvent(t, context.Background(), s, "corrupt-change-reference-destination", job.ID, "changes-detected", "corrupt-change-reference-scan", time.Now().UTC(), []model.Change{{Key: "corrupt-change-reference-key", Kind: "port", Target: "192.0.2.74", Port: 443}}, false, 0)
	result, err := s.DB.ExecContext(ctx, `UPDATE change_window_refs SET change_json=X'7B' WHERE window_id=?`, window.ID)
	if err != nil {
		t.Fatal(err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		t.Fatalf("corrupted %d change details; want exactly one referenced change", changed)
	}
	priorEventRefs := countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID)
	priorChangeRefs := countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_refs WHERE window_id=?`, window.ID)

	if closed, changed, err := ts.CancelChangeWindow(ctx, job.ID, window.ID, "operator", "Operator", nil, AuditEntry{}); err == nil || changed || closed.ID != "" {
		t.Fatalf("CancelChangeWindow with corrupt stored change detail = %+v, changed %v, err %v; want fail-closed behavior", closed, changed, err)
	}
	loaded, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || loaded.ClosedAt != nil || loaded.Summary != nil || loaded.ReviewState != "none" || loaded.Revision != window.Revision {
		t.Fatalf("corrupt detail partially closed the window: %+v, %v", loaded, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID) != priorEventRefs ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_refs WHERE window_id=?`, window.ID) != priorChangeRefs ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM events WHERE type='change-window-summary' AND job_id=?`, job.ID) != 0 {
		t.Fatal("corrupt detail failure persisted a close or summary")
	}
}
