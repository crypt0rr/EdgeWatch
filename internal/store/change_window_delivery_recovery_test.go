package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestReleaseDeliveryClaimsRetriesUnlinkedChangeAlert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-unlinked-recovery", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "unlinked-recovery-destination", job.ID, "changes-detected", "unlinked-recovery-scan", time.Now().UTC(), []model.Change{{Key: "unlinked-recovery-change", Kind: "port", Target: "192.0.2.68", Port: 443}}, false, 0)
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "unlinked-recovery-owner")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim unlinked change alert = %d deliveries, %v", len(claimed), err)
	}
	item := claimed[0]
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
		t.Fatal(err)
	}
	var windowID string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id FROM outbox WHERE id=?`, item.ID).Scan(&windowID); err != nil || windowID != "" {
		t.Fatalf("unlinked change alert window association = %q, %v; want no window", windowID, err)
	}

	if released, err := s.System().ReleaseDeliveryClaims(ctx); err != nil || released != 1 {
		t.Fatalf("release unlinked change alert = %d, %v; want one retryable claim", released, err)
	}
	var sentAt, claim, startedAt, coalescedAt string
	var attempts, deferrals int
	if err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(sent_at,''),claim_token,attempt_started_at,coalesced_at,attempts,deferrals FROM outbox WHERE id=?`, item.ID).Scan(&sentAt, &claim, &startedAt, &coalescedAt, &attempts, &deferrals); err != nil {
		t.Fatal(err)
	}
	if sentAt != "" || claim != "" || startedAt != "" || coalescedAt != "" || attempts != 0 || deferrals != 0 {
		t.Fatalf("released unlinked alert lost retryability: sent=%q claim=%q started=%q coalesced=%q attempts=%d deferrals=%d", sentAt, claim, startedAt, coalescedAt, attempts, deferrals)
	}
	retried, err := s.System().ClaimDueDeliveries(ctx, 1, "unlinked-recovery-retry")
	if err != nil || len(retried) != 1 || retried[0].ID != item.ID {
		t.Fatalf("claim released unlinked alert again = %+v, %v; want the same alert", retried, err)
	}
}

func TestWindowDeliveryResultAndRecoveryFailClosedWhenWindowMetadataIsUnavailable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-metadata-recovery-failure", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "window-metadata-recovery-destination", job.ID, "changes-detected", "window-metadata-recovery-scan", time.Now().UTC(), []model.Change{{Key: "window-metadata-recovery-change", Kind: "port", Target: "192.0.2.69", Port: 443}}, false, 0)
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "window-metadata-recovery-owner")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim window-linked alert = %d deliveries, %v", len(claimed), err)
	}
	item := claimed[0]
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	var linkedWindowID string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id FROM outbox WHERE id=?`, item.ID).Scan(&linkedWindowID); err != nil || linkedWindowID != window.ID {
		t.Fatalf("recovery row window association = %q, %v; want %q", linkedWindowID, err, window.ID)
	}
	if _, err := s.DB.ExecContext(ctx, `ALTER TABLE change_windows RENAME TO unavailable_change_windows`); err != nil {
		t.Fatal(err)
	}
	if released, err := s.System().ReleaseDeliveryClaims(ctx); err == nil || released != 0 {
		t.Fatalf("recovery without window metadata = %d released, %v; want a storage error and rollback", released, err)
	}
	if err := s.System().DeliveryResultClaim(ctx, item.ID, item.ClaimToken, nil); err == nil {
		t.Fatal("provider result committed without associated window metadata")
	}
	var sentAt, claim, startedAt, coalescedAt string
	var attempts, deferrals, coalesceAfter int
	if err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(sent_at,''),claim_token,attempt_started_at,coalesced_at,attempts,deferrals,coalesce_after_attempt FROM outbox WHERE id=?`, item.ID).Scan(&sentAt, &claim, &startedAt, &coalescedAt, &attempts, &deferrals, &coalesceAfter); err != nil {
		t.Fatal(err)
	}
	if sentAt != "" || claim != item.ClaimToken || startedAt == "" || coalescedAt != "" || attempts != 0 || deferrals != 0 || coalesceAfter != 0 {
		t.Fatalf("metadata failure partially mutated attempt sent=%q claim=%q started=%q coalesced=%q attempts=%d deferrals=%d coalesce-after=%d", sentAt, claim, startedAt, coalescedAt, attempts, deferrals, coalesceAfter)
	}
	if window.ID == "" {
		t.Fatal("test setup created an empty window ID")
	}
}

func TestDeferDeliveryCoalesceWriteFailureLeavesClosedWindowAttemptUnchanged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-defer-coalesce-failure", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "window-defer-coalesce-destination", job.ID, "changes-detected", "window-defer-coalesce-scan", time.Now().UTC(), []model.Change{{Key: "window-defer-coalesce-change", Kind: "port", Target: "192.0.2.70", Port: 443}}, false, 0)
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "window-defer-coalesce-owner")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim before close = %d deliveries, %v", len(claimed), err)
	}
	item := claimed[0]
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	summary, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return window.EndAt.Add(time.Second) }, nil)
	if err != nil || !changed || summary.UnknownOutcomeEventCount != 1 {
		t.Fatalf("close after prior provider invocation = %+v, changed %v, err %v; want one unknown-outcome event", summary, changed, err)
	}
	var failuresBefore int
	var lastFailureBefore, lastErrorBefore string
	if err := s.DB.QueryRowContext(ctx, `SELECT terminal_failures,last_failure_at,last_error_code FROM notification_delivery_health WHERE destination_identity=?`, "window-defer-coalesce-destination").Scan(&failuresBefore, &lastFailureBefore, &lastErrorBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_window_defer_coalesce BEFORE UPDATE OF coalesced_at ON outbox WHEN OLD.destination='window-defer-coalesce-destination' AND NEW.coalesced_at<>'' BEGIN SELECT RAISE(ABORT,'synthetic coalesce write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.System().DeferDeliveryWithError(ctx, item.ID, item.ClaimToken, ErrDeliveryIndeterminate, time.Minute); err == nil {
		t.Fatal("coalescing indeterminate result unexpectedly succeeded after the close transaction")
	}
	var sentAt, claim, startedAt, coalescedAt, lastError string
	var attempts, deferrals, coalesceAfter int
	if err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(sent_at,''),claim_token,attempt_started_at,coalesced_at,last_error,attempts,deferrals,coalesce_after_attempt FROM outbox WHERE id=?`, item.ID).Scan(&sentAt, &claim, &startedAt, &coalescedAt, &lastError, &attempts, &deferrals, &coalesceAfter); err != nil {
		t.Fatal(err)
	}
	if sentAt != "" || claim != item.ClaimToken || startedAt == "" || coalescedAt != "" || lastError != "" || attempts != 0 || deferrals != 0 || coalesceAfter != 1 {
		t.Fatalf("failed coalescing changed outbox row sent=%q claim=%q started=%q coalesced=%q error=%q attempts=%d deferrals=%d coalesce-after=%d", sentAt, claim, startedAt, coalescedAt, lastError, attempts, deferrals, coalesceAfter)
	}
	var failuresAfter int
	var lastFailureAfter, lastErrorAfter string
	if err := s.DB.QueryRowContext(ctx, `SELECT terminal_failures,last_failure_at,last_error_code FROM notification_delivery_health WHERE destination_identity=?`, "window-defer-coalesce-destination").Scan(&failuresAfter, &lastFailureAfter, &lastErrorAfter); err != nil {
		t.Fatal(err)
	}
	if failuresAfter != failuresBefore || lastFailureAfter != lastFailureBefore || lastErrorAfter != lastErrorBefore {
		t.Fatalf("failed coalescing changed destination health from %d/%q/%q to %d/%q/%q", failuresBefore, lastFailureBefore, lastErrorBefore, failuresAfter, lastFailureAfter, lastErrorAfter)
	}
}

func TestBeginDeliveryAttemptFailsClosedWhenLinkedWindowCannotBeRead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-attempt-metadata-failure", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "window-attempt-metadata-destination", job.ID, "changes-detected", "window-attempt-metadata-scan", time.Now().UTC(), []model.Change{{Key: "window-attempt-metadata-change", Kind: "port", Target: "192.0.2.75", Port: 443}}, false, 0)
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "window-attempt-metadata-owner")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim before window creation = %d deliveries, %v", len(claimed), err)
	}
	item := claimed[0]
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	var linkedWindowID string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id FROM outbox WHERE id=?`, item.ID).Scan(&linkedWindowID); err != nil || linkedWindowID != window.ID {
		t.Fatalf("claim window association = %q, %v; want %q", linkedWindowID, err, window.ID)
	}
	if _, err := s.DB.ExecContext(ctx, `ALTER TABLE change_windows RENAME TO unavailable_change_windows`); err != nil {
		t.Fatal(err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); !errors.Is(err, ErrDeliveryAttemptNotStarted) {
		t.Fatalf("begin provider attempt without linked window metadata = %v; want ErrDeliveryAttemptNotStarted", err)
	}
	var claim, startedAt, sentAt, coalescedAt string
	var attempts, deferrals int
	if err := s.DB.QueryRowContext(ctx, `SELECT claim_token,attempt_started_at,COALESCE(sent_at,''),coalesced_at,attempts,deferrals FROM outbox WHERE id=?`, item.ID).Scan(&claim, &startedAt, &sentAt, &coalescedAt, &attempts, &deferrals); err != nil {
		t.Fatal(err)
	}
	if claim != item.ClaimToken || startedAt != "" || sentAt != "" || coalescedAt != "" || attempts != 0 || deferrals != 0 {
		t.Fatalf("failed dispatch gate changed row claim=%q marker=%q sent=%q coalesced=%q attempts=%d deferrals=%d", claim, startedAt, sentAt, coalescedAt, attempts, deferrals)
	}
}

func TestLateWindowDeliveryEvidenceFailureRollsBackProviderResult(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _, window, item := prepareLateWindowDeliveryResult(t, "window-result-evidence-failure")
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_late_window_result_evidence BEFORE INSERT ON change_window_events WHEN NEW.window_id='`+window.ID+`' BEGIN SELECT RAISE(ABORT,'synthetic evidence write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.System().DeliveryResultClaim(ctx, item.ID, item.ClaimToken, nil); err == nil {
		t.Fatal("late provider success committed after change evidence insertion failed")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID) != 0 {
		t.Fatal("failed evidence insertion persisted a window event")
	}
	assertLateWindowDeliveryUnchanged(t, s, item)
}

func TestLateWindowDeliveryScheduleFailureRollsBackProviderEvidence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _, window, item := prepareLateWindowDeliveryResult(t, "window-result-schedule-failure")
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_late_window_result_schedule BEFORE UPDATE OF next_at ON outbox WHEN OLD.id=`+strconv.FormatInt(item.ID, 10)+` BEGIN SELECT RAISE(ABORT,'synthetic scheduling failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.System().DeliveryResultClaim(ctx, item.ID, item.ClaimToken, nil); err == nil {
		t.Fatal("late provider success committed after window scheduling failed")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID) != 0 {
		t.Fatal("failed reschedule nevertheless persisted window evidence")
	}
	assertLateWindowDeliveryUnchanged(t, s, item)
}

func TestDeliveryResultLostConditionalUpdateDoesNotMarkSuccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "delivery-result-conditional-update", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "delivery-result-conditional-update-destination", job.ID, "changes-detected", "delivery-result-conditional-update-scan", time.Now().UTC(), []model.Change{{Key: "delivery-result-conditional-update-change", Kind: "port", Target: "192.0.2.76", Port: 443}}, false, 0)
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "delivery-result-conditional-update-owner")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim before conditional result = %d deliveries, %v", len(claimed), err)
	}
	item := claimed[0]
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER ignore_delivery_result_success BEFORE UPDATE OF sent_at ON outbox WHEN OLD.id=`+strconv.FormatInt(item.ID, 10)+` BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.System().DeliveryResultClaim(ctx, item.ID, item.ClaimToken, nil); !errors.Is(err, ErrDeliveryClaimLost) {
		t.Fatalf("success result whose conditional update lost = %v; want ErrDeliveryClaimLost", err)
	}
	var sentAt, claim, startedAt string
	var attempts, deferrals int
	if err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(sent_at,''),claim_token,attempt_started_at,attempts,deferrals FROM outbox WHERE id=?`, item.ID).Scan(&sentAt, &claim, &startedAt, &attempts, &deferrals); err != nil {
		t.Fatal(err)
	}
	if sentAt != "" || claim != item.ClaimToken || startedAt == "" || attempts != 0 || deferrals != 0 {
		t.Fatalf("lost conditional success changed row sent=%q claim=%q marker=%q attempts=%d deferrals=%d", sentAt, claim, startedAt, attempts, deferrals)
	}
	var lastSuccess string
	if err := s.DB.QueryRowContext(ctx, `SELECT last_success_at FROM notification_delivery_health WHERE destination_identity=?`, "delivery-result-conditional-update-destination").Scan(&lastSuccess); err != nil || lastSuccess != "" {
		t.Fatalf("lost conditional success changed health timestamp %q, %v", lastSuccess, err)
	}
}

func prepareLateWindowDeliveryResult(t *testing.T, name string) (*Store, *TenantStore, ChangeWindow, Delivery) {
	t.Helper()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, name, "UTC")
	queueWindowTestEvent(t, context.Background(), s, name+"-destination", job.ID, "changes-detected", name+"-scan", time.Now().UTC(), []model.Change{{Key: name + "-change", Kind: "port", Target: "192.0.2.77", Port: 443}}, false, 0)
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, name+"-owner")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim before window creation = %d deliveries, %v", len(claimed), err)
	}
	item := claimed[0]
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	var raw []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT payload_json FROM outbox WHERE id=?`, item.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var event model.Event
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	// Older durable payloads may omit job_id even when the outbox's bounded
	// routing columns still retain it; the final result path restores it before
	// recording the event reference.
	event.JobID = ""
	updated, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET payload_json=? WHERE id=?`, updated, item.ID); err != nil {
		t.Fatal(err)
	}
	end := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=?,end_at=? WHERE id=?`, sqliteTimestamp(end.Add(-time.Hour)), sqliteTimestamp(end), window.ID); err != nil {
		t.Fatal(err)
	}
	return s, ts, window, item
}

func assertLateWindowDeliveryUnchanged(t *testing.T, s *Store, item Delivery) {
	t.Helper()
	ctx := context.Background()
	var sentAt, claim, startedAt, coalescedAt, nextAt string
	var attempts, deferrals int
	if err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(sent_at,''),claim_token,attempt_started_at,coalesced_at,next_at,attempts,deferrals FROM outbox WHERE id=?`, item.ID).Scan(&sentAt, &claim, &startedAt, &coalescedAt, &nextAt, &attempts, &deferrals); err != nil {
		t.Fatal(err)
	}
	if sentAt != "" || claim != item.ClaimToken || startedAt == "" || coalescedAt != "" || attempts != 0 || deferrals != 0 {
		t.Fatalf("late result transaction partially committed sent=%q claim=%q marker=%q coalesced=%q next=%q attempts=%d deferrals=%d", sentAt, claim, startedAt, coalescedAt, nextAt, attempts, deferrals)
	}
}
