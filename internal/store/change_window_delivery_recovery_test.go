package store

import (
	"context"
	"errors"
	"strconv"
	"strings"
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

func TestRecoverExpiredDeliveryClaimsIsBoundedAndMakesRowsRetryable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	startedAt := now.Add(-time.Hour).Format(time.RFC3339Nano)
	expiredAt := now.Add(-time.Minute).Format(time.RFC3339Nano)
	dueAt := now.Add(-time.Second).Format(time.RFC3339Nano)
	const rows = deliveryMaintenanceBatch + 1
	for i := 0; i < rows; i++ {
		_, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,next_at,claim_token,claim_until,tenant_id,event_type,event_job_id,attempt_started_at)
VALUES(?,?,?,?,?,?,?,?,?)`, "expired-recovery-"+strconv.Itoa(i), `{"type":"changes-detected"}`, dueAt, "expired-owner-"+strconv.Itoa(i), expiredAt, DefaultTenantID, "changes-detected", "", startedAt)
		if err != nil {
			t.Fatalf("insert expired delivery %d: %v", i, err)
		}
	}
	if recovered, err := s.System().RecoverExpiredDeliveryClaims(ctx); err != nil || recovered != deliveryMaintenanceBatch {
		t.Fatalf("first bounded recovery = %d rows, %v; want %d", recovered, err, deliveryMaintenanceBatch)
	}
	var pending int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE attempt_started_at<>'' AND claim_token<>''`).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("expired rows after first recovery = %d, %v; want one remaining beyond the batch", pending, err)
	}
	if recovered, err := s.System().RecoverExpiredDeliveryClaims(ctx); err != nil || recovered != 1 {
		t.Fatalf("second bounded recovery = %d rows, %v; want final row", recovered, err)
	}
	var markers int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE attempt_started_at<>'' OR claim_token<>''`).Scan(&markers); err != nil || markers != 0 {
		t.Fatalf("recovered rows retain attempt markers or claims: count %d, err %v", markers, err)
	}
	if deliveries, err := s.System().ClaimDueDeliveries(ctx, rows, "expired-recovery-retry"); err != nil || len(deliveries) != rows {
		t.Fatalf("claim after live recovery = %d rows, %v; want %d retryable rows", len(deliveries), err, rows)
	}
}

func TestRecoverExpiredDeliveryClaimsClearsLastErrorOnlyWhenCoalescing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	startedAt := now.Add(-time.Hour).Format(time.RFC3339Nano)
	expiredAt := now.Add(-time.Minute).Format(time.RFC3339Nano)
	dueAt := now.Add(-time.Second).Format(time.RFC3339Nano)
	for _, item := range []struct {
		destination string
		coalesce    int
	}{
		{destination: "expired-recovery-preserves-error"},
		{destination: "expired-recovery-clears-error", coalesce: 1},
	} {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,next_at,claim_token,claim_until,tenant_id,event_type,attempt_started_at,coalesce_after_attempt,last_error)
VALUES(?,?,?,?,?,?,?,?,?,'provider_timeout')`, item.destination, `{"type":"changes-detected"}`, dueAt, "expired-owner", expiredAt, DefaultTenantID, "changes-detected", startedAt, item.coalesce); err != nil {
			t.Fatalf("insert %s: %v", item.destination, err)
		}
	}
	if recovered, err := s.System().RecoverExpiredDeliveryClaims(ctx); err != nil || recovered != 2 {
		t.Fatalf("recover expired rows = %d, %v; want 2", recovered, err)
	}
	for _, item := range []struct {
		destination  string
		wantError    string
		wantCoalesce bool
	}{
		{destination: "expired-recovery-preserves-error", wantError: "provider_timeout"},
		{destination: "expired-recovery-clears-error", wantCoalesce: true},
	} {
		var claim, started, coalesced, lastError string
		if err := s.DB.QueryRowContext(ctx, `SELECT claim_token,attempt_started_at,coalesced_at,last_error FROM outbox WHERE destination=?`, item.destination).Scan(&claim, &started, &coalesced, &lastError); err != nil {
			t.Fatal(err)
		}
		if claim != "" || started != "" || lastError != item.wantError || (coalesced != "") != item.wantCoalesce {
			t.Errorf("recovered %s = claim %q marker %q coalesced %q last error %q; want claim/marker cleared, coalesced %t, last error %q", item.destination, claim, started, coalesced, lastError, item.wantCoalesce, item.wantError)
		}
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

func TestBeginDeliveryAttemptFailsClosedWhenLinkedWindowIsMissing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, window, item := prepareLinkedWindowDelivery(t, "missing-attempt-window", false)
	before := snapshotWindowDelivery(t, s, item.ID)
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM change_windows WHERE id=?`, window.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); !errors.Is(err, ErrDeliveryAttemptNotStarted) {
		t.Fatalf("begin provider attempt with dangling window link = %v; want ErrDeliveryAttemptNotStarted", err)
	}
	if after := snapshotWindowDelivery(t, s, item.ID); after != before {
		t.Fatalf("failed provider gate changed linked delivery: before %+v, after %+v", before, after)
	}
}

func TestDeliveryResultClaimFailsClosedWhenLinkedWindowIsMissing(t *testing.T) {
	t.Parallel()
	for _, result := range []struct {
		name          string
		err           error
		coalesceAfter int
	}{
		{name: "success"},
		{name: "provider failure", err: errors.New("provider_timeout")},
		{name: "rotation coalesced success", coalesceAfter: 1},
	} {
		t.Run(result.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s, window, item := prepareLinkedWindowDelivery(t, "missing-result-window-"+result.name, true)
			if result.coalesceAfter != 0 {
				if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET coalesce_after_attempt=? WHERE id=?`, result.coalesceAfter, item.ID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.DB.ExecContext(ctx, `UPDATE notification_delivery_health SET last_success_at=?,updated_at=? WHERE destination_identity=?`, "before-success", "before-update", item.Destination); err != nil {
				t.Fatal(err)
			}
			before := snapshotWindowDelivery(t, s, item.ID)
			healthBefore := snapshotDeliveryHealth(t, s, item.Destination)
			if _, err := s.DB.ExecContext(ctx, `DELETE FROM change_windows WHERE id=?`, window.ID); err != nil {
				t.Fatal(err)
			}
			if err := s.System().DeliveryResultClaim(ctx, item.ID, item.ClaimToken, result.err); err == nil {
				t.Fatal("provider result committed with a dangling window link")
			}
			if after := snapshotWindowDelivery(t, s, item.ID); after != before {
				t.Fatalf("failed provider result changed linked delivery: before %+v, after %+v", before, after)
			}
			if healthAfter := snapshotDeliveryHealth(t, s, item.Destination); healthAfter != healthBefore {
				t.Fatalf("failed provider result changed destination health: before %+v, after %+v", healthBefore, healthAfter)
			}
			if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID) != 0 {
				t.Fatal("provider result created evidence for a missing window")
			}
		})
	}
}

func TestDeliveryClaimRecoveryRollsBackWhenLinkedWindowIsMissing(t *testing.T) {
	t.Parallel()
	for _, recovery := range []struct {
		name    string
		expired bool
	}{
		{name: "startup"},
		{name: "expired lease", expired: true},
	} {
		t.Run(recovery.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := openTestStore(t)
			ts := defaultTenant(s)
			items := make([]Delivery, 0, 2)
			windows := make([]ChangeWindow, 0, 2)
			for i := 0; i < 2; i++ {
				job := createWindowTestJob(t, ts, "missing-recovery-window-"+recovery.name+"-"+strconv.Itoa(i), "UTC")
				destination := "missing-recovery-destination-" + recovery.name + "-" + strconv.Itoa(i)
				queueWindowTestEvent(t, ctx, s, destination, job.ID, "changes-detected", "missing-recovery-scan-"+strconv.Itoa(i), time.Now().UTC(), []model.Change{{Key: "missing-recovery-change-" + strconv.Itoa(i), Kind: "port", Target: "192.0.2.76", Port: 443}}, false, 0)
				start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
				window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
				claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "missing-recovery-owner-"+strconv.Itoa(i))
				if err != nil || len(claimed) != 1 {
					t.Fatalf("claim row %d = %d deliveries, %v", i, len(claimed), err)
				}
				if err := s.System().BeginDeliveryAttempt(ctx, claimed[0].ID, claimed[0].ClaimToken); err != nil {
					t.Fatalf("begin row %d = %v", i, err)
				}
				items = append(items, claimed[0])
				windows = append(windows, window)
				if _, err := s.DB.ExecContext(ctx, `UPDATE notification_delivery_health SET last_success_at=?,updated_at=? WHERE destination_identity=?`, "before-success", "before-update", destination); err != nil {
					t.Fatal(err)
				}
			}
			if recovery.expired {
				expiredAt := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
				for _, item := range items {
					if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET claim_until=? WHERE id=?`, expiredAt, item.ID); err != nil {
						t.Fatal(err)
					}
				}
			}
			before := make([]windowDeliverySnapshot, len(items))
			healthBefore := make([]deliveryHealthSnapshot, len(items))
			for i, item := range items {
				before[i] = snapshotWindowDelivery(t, s, item.ID)
				healthBefore[i] = snapshotDeliveryHealth(t, s, item.Destination)
			}
			if result, err := s.DB.ExecContext(ctx, `DELETE FROM change_windows WHERE id=?`, windows[1].ID); err != nil {
				t.Fatal(err)
			} else if deleted, _ := result.RowsAffected(); deleted != 1 {
				t.Fatalf("delete second linked window affected %d rows; want 1", deleted)
			}
			var changed int64
			var err error
			if recovery.expired {
				changed, err = s.System().RecoverExpiredDeliveryClaims(ctx)
			} else {
				changed, err = s.System().ReleaseDeliveryClaims(ctx)
			}
			if err == nil || changed != 0 {
				t.Fatalf("%s recovery with a dangling link = %d rows, %v; want an error and transaction rollback", recovery.name, changed, err)
			}
			for i, item := range items {
				if after := snapshotWindowDelivery(t, s, item.ID); after != before[i] {
					t.Errorf("%s recovery partially changed row %d: before %+v, after %+v", recovery.name, i, before[i], after)
				}
				if healthAfter := snapshotDeliveryHealth(t, s, item.Destination); healthAfter != healthBefore[i] {
					t.Errorf("%s recovery changed row %d destination health: before %+v, after %+v", recovery.name, i, healthBefore[i], healthAfter)
				}
			}
		})
	}
}

type windowDeliverySnapshot struct {
	windowID, claim, claimUntil, startedAt, sentAt, coalescedAt, lastError string
	attempts, deferrals, coalesceAfter                                     int
}

func snapshotWindowDelivery(t *testing.T, s *Store, id int64) windowDeliverySnapshot {
	t.Helper()
	var snapshot windowDeliverySnapshot
	if err := s.DB.QueryRowContext(context.Background(), `SELECT change_window_id,claim_token,claim_until,attempt_started_at,COALESCE(sent_at,''),coalesced_at,last_error,attempts,deferrals,coalesce_after_attempt FROM outbox WHERE id=?`, id).Scan(&snapshot.windowID, &snapshot.claim, &snapshot.claimUntil, &snapshot.startedAt, &snapshot.sentAt, &snapshot.coalescedAt, &snapshot.lastError, &snapshot.attempts, &snapshot.deferrals, &snapshot.coalesceAfter); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

type deliveryHealthSnapshot struct {
	terminalFailures                                                   int
	lastSuccess, lastFailure, lastTerminal, code, fingerprint, updated string
}

func snapshotDeliveryHealth(t *testing.T, s *Store, destination string) deliveryHealthSnapshot {
	t.Helper()
	var snapshot deliveryHealthSnapshot
	if err := s.DB.QueryRowContext(context.Background(), `SELECT terminal_failures,last_success_at,last_failure_at,last_terminal_at,last_error_code,last_error_fingerprint,updated_at FROM notification_delivery_health WHERE destination_identity=?`, destination).Scan(&snapshot.terminalFailures, &snapshot.lastSuccess, &snapshot.lastFailure, &snapshot.lastTerminal, &snapshot.code, &snapshot.fingerprint, &snapshot.updated); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func prepareLinkedWindowDelivery(t *testing.T, label string, started bool) (*Store, ChangeWindow, Delivery) {
	t.Helper()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, label, "UTC")
	destination := "destination-" + label
	queueWindowTestEvent(t, ctx, s, destination, job.ID, "changes-detected", "scan-"+label, time.Now().UTC(), []model.Change{{Key: "change-" + label, Kind: "port", Target: "192.0.2.77", Port: 443}}, false, 0)
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "owner-"+label)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim linked delivery = %d rows, %v", len(claimed), err)
	}
	item := claimed[0]
	if started {
		if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
			t.Fatalf("begin linked delivery = %v", err)
		}
	}
	return s, window, item
}

func TestLateWindowProviderSuccessSurvivesExpiredWindowSideEffects(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		trigger func(*testing.T, *Store, ChangeWindow, Delivery)
	}{
		{
			name: "summary evidence insertion is not part of the provider result",
			trigger: func(t *testing.T, s *Store, window ChangeWindow, _ Delivery) {
				if _, err := s.DB.ExecContext(context.Background(), `CREATE TRIGGER fail_late_window_result_evidence BEFORE INSERT ON change_window_events WHEN NEW.window_id='`+window.ID+`' BEGIN SELECT RAISE(ABORT,'synthetic evidence write failure'); END`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "window rescheduling is not part of the provider result",
			trigger: func(t *testing.T, s *Store, _ ChangeWindow, item Delivery) {
				if _, err := s.DB.ExecContext(context.Background(), `CREATE TRIGGER fail_late_window_result_schedule BEFORE UPDATE OF next_at ON outbox WHEN OLD.id=`+strconv.FormatInt(item.ID, 10)+` BEGIN SELECT RAISE(ABORT,'synthetic scheduling failure'); END`); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, ts, window, item := prepareLateWindowDeliveryResult(t, "window-late-result-"+strings.ReplaceAll(tc.name, " ", "-"))
			tc.trigger(t, s, window, item)
			if err := s.System().DeliveryResultClaim(ctx, item.ID, item.ClaimToken, nil); err != nil {
				t.Fatalf("record provider success after window end: %v", err)
			}
			var sentAt, claim, started, coalesced string
			var attempts int
			if err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(sent_at,''),claim_token,attempt_started_at,coalesced_at,attempts FROM outbox WHERE id=?`, item.ID).Scan(&sentAt, &claim, &started, &coalesced, &attempts); err != nil {
				t.Fatal(err)
			}
			if sentAt == "" || claim != "" || started != "" || coalesced != "" || attempts != 0 {
				t.Fatalf("late provider success sent=%q claim=%q marker=%q coalesced=%q attempts=%d", sentAt, claim, started, coalesced, attempts)
			}
			if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID) != 0 {
				t.Fatal("a delivered post-end alert was retained as suppressed window evidence")
			}
			if _, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return window.EndAt.Add(time.Second) }, nil); err != nil || !changed {
				t.Fatalf("delayed expiry = changed %v, err %v", changed, err)
			}
			var afterSent, afterCoalesced string
			if err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(sent_at,''),coalesced_at FROM outbox WHERE id=?`, item.ID).Scan(&afterSent, &afterCoalesced); err != nil {
				t.Fatal(err)
			}
			if afterSent != sentAt || afterCoalesced != "" {
				t.Fatalf("delayed expiry changed successful provider result: sent=%q→%q coalesced=%q", sentAt, afterSent, afterCoalesced)
			}
			if retries, err := s.System().ClaimDueDeliveries(ctx, 1, "late-success-no-duplicate"); err != nil || len(retries) != 0 {
				t.Fatalf("successful post-end delivery became claimable again: %+v, %v", retries, err)
			}
		})
	}
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
	end := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=?,end_at=? WHERE id=?`, sqliteTimestamp(end.Add(-time.Hour)), sqliteTimestamp(end), window.ID); err != nil {
		t.Fatal(err)
	}
	window.StartAt = end.Add(-time.Hour)
	window.EndAt = end
	return s, ts, window, item
}
