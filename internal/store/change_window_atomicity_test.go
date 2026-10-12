package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestCreateWindowAssociationFailureRollsBackWindowAuditAndBacklog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-create-association-rollback", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "create-rollback-destination", job.ID, "changes-detected", "create-rollback-scan", time.Now().UTC(), []model.Change{{Key: "create-rollback-change", Kind: "port", Target: "192.0.2.50", Port: 443}}, false, 0)
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_change_window_association BEFORE UPDATE OF change_window_id ON outbox WHEN NEW.event_job_id='`+job.ID+`' AND NEW.change_window_id<>'' BEGIN SELECT RAISE(ABORT,'synthetic association failure'); END`); err != nil {
		t.Fatal(err)
	}

	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	if _, err := ts.CreateChangeWindow(ctx, job.ID, start, start.Add(time.Hour), false, "maintenance", "operator", "Operator"); err == nil {
		t.Fatal("window creation succeeded despite a failed pending-alert association")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_windows WHERE job_id=?`, job.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM security_audit WHERE action='change_window.created' AND detail LIKE ?`, "%"+job.ID+"%") != 0 {
		t.Fatal("failed window creation left a window or creation audit")
	}
	var linked, coalesced string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,coalesced_at FROM outbox WHERE event_type='changes-detected' AND event_job_id=?`, job.ID).Scan(&linked, &coalesced); err != nil {
		t.Fatal(err)
	}
	if linked != "" || coalesced != "" {
		t.Fatalf("failed creation changed pending backlog link=%q coalesced=%q", linked, coalesced)
	}
}

func TestExpiryReferenceFailureRollsBackCapturedEvidenceAndClose(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-expiry-reference-rollback", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "expiry-reference-destination", job.ID, "changes-detected", "expiry-reference-scan", time.Now().UTC(), []model.Change{{Key: "expiry-reference-change", Kind: "port", Target: "192.0.2.51", Port: 443}}, false, 0)
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_change_window_reference BEFORE INSERT ON change_window_refs WHEN NEW.category='new' BEGIN SELECT RAISE(ABORT,'synthetic reference failure'); END`); err != nil {
		t.Fatal(err)
	}

	closeAt := window.EndAt.Add(time.Second)
	if summary, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return closeAt }, []string{"expiry-summary-destination"}); err == nil || changed || summary.NewCount != 0 {
		t.Fatalf("expiry with failed evidence insert = %+v, changed %v, err %v; want an atomic failure", summary, changed, err)
	}
	loaded, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ClosedAt != nil || loaded.ReviewState != "none" || loaded.Summary != nil || loaded.Revision != window.Revision {
		t.Fatalf("failed expiry partially closed the window: %+v", loaded)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_refs WHERE window_id=?`, window.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM events WHERE type='change-window-summary' AND job_id=?`, job.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE event_type='change-window-summary' AND event_job_id=?`, job.ID) != 0 {
		t.Fatal("failed expiry persisted evidence or a summary outside its rolled-back transaction")
	}
	var linked, coalesced string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,coalesced_at FROM outbox WHERE event_type='changes-detected' AND event_job_id=?`, job.ID).Scan(&linked, &coalesced); err != nil {
		t.Fatal(err)
	}
	if linked != window.ID || coalesced != "" {
		t.Fatalf("failed expiry changed backlog link=%q coalesced=%q", linked, coalesced)
	}
}

func TestReviewAuditFailureLeavesSummaryDueAndRevisionUnchanged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-review-audit-rollback", "UTC")
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	queueWindowTestEvent(t, context.Background(), s, "review-audit-destination", job.ID, "changes-detected", "review-audit-scan", time.Now().UTC(), []model.Change{{Key: "review-audit-change", Kind: "port", Target: "192.0.2.52", Port: 443}}, false, 0)
	closed, changed, err := ts.CancelChangeWindow(ctx, job.ID, window.ID, "operator", "Operator", nil, AuditEntry{})
	if err != nil || !changed || closed.ReviewState != "due" || closed.Summary == nil {
		t.Fatalf("close before review audit fault = %+v, changed %v, err %v", closed, changed, err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_change_window_review_audit BEFORE INSERT ON security_audit WHEN NEW.action='change_window.reviewed' BEGIN SELECT RAISE(ABORT,'synthetic review audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if reviewed, err := ts.ReviewChangeWindow(ctx, job.ID, window.ID, closed.Revision, "reviewer", "Reviewer", AuditEntry{}); !errors.Is(err, ErrAuditUnavailable) || reviewed.ID != "" {
		t.Fatalf("review with audit failure = %+v, err %v; want an audit error", reviewed, err)
	}
	stillDue, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || stillDue.ReviewState != "due" || stillDue.Revision != closed.Revision || stillDue.ReviewedAt != nil || stillDue.ReviewerLabel != "" || stillDue.Summary == nil {
		t.Fatalf("failed review changed durable due state: %+v, %v", stillDue, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM security_audit WHERE action='change_window.reviewed' AND detail LIKE ?`, "%"+window.ID+"%") != 0 {
		t.Fatal("failed review audit was nevertheless persisted")
	}
}
