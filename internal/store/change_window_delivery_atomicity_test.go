package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestBeginDeliveryAttemptMarkerWriteFailureLeavesClaimRetryable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-marker-write-failure", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "marker-write-failure", job.ID, "changes-detected", "marker-write-scan", time.Now().UTC(), []model.Change{{Key: "marker-write-change", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "marker-write-owner")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim before marker failure = %d deliveries, %v", len(claimed), err)
	}
	item := claimed[0]
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_window_attempt_marker BEFORE UPDATE OF attempt_started_at ON outbox WHEN NEW.attempt_started_at<>'' BEGIN SELECT RAISE(ABORT,'synthetic invocation marker failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); !errors.Is(err, ErrDeliveryAttemptNotStarted) {
		t.Fatalf("failed invocation marker = %v; want ErrDeliveryAttemptNotStarted", err)
	}
	var claim, startedAt, terminalAt string
	var attempts, deferrals int
	if err := s.DB.QueryRowContext(ctx, `SELECT claim_token,attempt_started_at,terminal_at,attempts,deferrals FROM outbox WHERE id=?`, item.ID).Scan(&claim, &startedAt, &terminalAt, &attempts, &deferrals); err != nil {
		t.Fatal(err)
	}
	if claim != item.ClaimToken || startedAt != "" || terminalAt != "" || attempts != 0 || deferrals != 0 {
		t.Fatalf("failed marker changed row claim=%q marker=%q terminal=%q attempts=%d deferrals=%d", claim, startedAt, terminalAt, attempts, deferrals)
	}
}

func TestReleaseDeliveryClaimsFailureRollsBackMarkerAndLeaseUpdates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-release-write-failure", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "release-write-failure", job.ID, "changes-detected", "release-write-scan", time.Now().UTC(), []model.Change{{Key: "release-write-change", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "release-write-owner")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim before recovery failure = %d deliveries, %v", len(claimed), err)
	}
	item := claimed[0]
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_window_claim_release BEFORE UPDATE OF claim_token ON outbox WHEN OLD.claim_token<>'' AND NEW.claim_token='' BEGIN SELECT RAISE(ABORT,'synthetic lease release failure'); END`); err != nil {
		t.Fatal(err)
	}
	if released, err := s.System().ReleaseDeliveryClaims(ctx); err == nil || released != 0 {
		t.Fatalf("recovery with failed lease update = %d released, %v; want transaction error", released, err)
	}
	var claim, startedAt, coalescedAt string
	if err := s.DB.QueryRowContext(ctx, `SELECT claim_token,attempt_started_at,coalesced_at FROM outbox WHERE id=?`, item.ID).Scan(&claim, &startedAt, &coalescedAt); err != nil {
		t.Fatal(err)
	}
	if claim != item.ClaimToken || startedAt == "" || coalescedAt != "" {
		t.Fatalf("failed recovery partially changed row claim=%q marker=%q coalesced=%q", claim, startedAt, coalescedAt)
	}
}

func TestDeliveryMutationAPIsFailClosedOnCanceledContext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-delivery-canceled-context", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "delivery-canceled-context", job.ID, "changes-detected", "delivery-canceled-context-scan", time.Now().UTC(), []model.Change{{Key: "delivery-canceled-context-change", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "delivery-canceled-context-owner")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim before cancellation = %d deliveries, %v", len(claimed), err)
	}
	item := claimed[0]
	requestCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.System().BeginDeliveryAttempt(requestCtx, item.ID, item.ClaimToken); !errors.Is(err, ErrDeliveryAttemptNotStarted) {
		t.Fatalf("begin attempt with canceled request = %v; want ErrDeliveryAttemptNotStarted", err)
	}
	if released, err := s.System().ReleaseDeliveryClaims(requestCtx); err == nil || released != 0 {
		t.Fatalf("release with canceled request = %d, %v; want error and no release", released, err)
	}
	if err := s.System().DeliveryResultClaim(requestCtx, item.ID, item.ClaimToken, ErrDeliveryProviderTimeout); err == nil {
		t.Fatal("delivery result unexpectedly committed with canceled request")
	}
	if err := s.System().DeferDeliveryWithError(requestCtx, item.ID, item.ClaimToken, ErrDeliveryIndeterminate, time.Minute); err == nil {
		t.Fatal("delivery deferral unexpectedly committed with canceled request")
	}
	var claim, startedAt, terminalAt string
	var attempts, deferrals int
	if err := s.DB.QueryRowContext(ctx, `SELECT claim_token,attempt_started_at,terminal_at,attempts,deferrals FROM outbox WHERE id=?`, item.ID).Scan(&claim, &startedAt, &terminalAt, &attempts, &deferrals); err != nil {
		t.Fatal(err)
	}
	if claim != item.ClaimToken || startedAt != "" || terminalAt != "" || attempts != 0 || deferrals != 0 {
		t.Fatalf("canceled operations changed row claim=%q marker=%q terminal=%q attempts=%d deferrals=%d", claim, startedAt, terminalAt, attempts, deferrals)
	}
}

func TestLateProviderSuccessAndHealthUpdateRollBackTogether(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-late-success-rollback", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "late-success-rollback", job.ID, "changes-detected", "late-success-rollback-scan", time.Now().UTC(), []model.Change{{Key: "late-success-rollback-change", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "late-success-rollback-owner")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim before window = %d deliveries, %v", len(claimed), err)
	}
	item := claimed[0]
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
		t.Fatal(err)
	}
	closedAt := window.EndAt.Add(time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET claim_until=? WHERE id=?`, closedAt.Add(time.Minute).Format(time.RFC3339Nano), item.ID); err != nil {
		t.Fatal(err)
	}
	if summary, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return closedAt }, nil); err != nil || !changed || summary.InFlightEventCount != 1 {
		t.Fatalf("close during provider attempt = %+v, changed %v, err %v", summary, changed, err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_window_delivery_health BEFORE UPDATE ON notification_delivery_health WHEN NEW.destination_identity='late-success-rollback' BEGIN SELECT RAISE(ABORT,'synthetic health update failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.System().DeliveryResultClaim(ctx, item.ID, item.ClaimToken, nil); err == nil {
		t.Fatal("late provider success unexpectedly committed when its health update failed")
	}
	var sentAt, claim, startedAt, coalescedAt string
	var coalesceAfter int
	if err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(sent_at,''),claim_token,attempt_started_at,coalesced_at,coalesce_after_attempt FROM outbox WHERE id=?`, item.ID).Scan(&sentAt, &claim, &startedAt, &coalescedAt, &coalesceAfter); err != nil {
		t.Fatal(err)
	}
	if sentAt != "" || claim != item.ClaimToken || startedAt == "" || coalescedAt != "" || coalesceAfter != 1 {
		t.Fatalf("failed late success was partially recorded sent=%q claim=%q marker=%q coalesced=%q coalesce-after=%d", sentAt, claim, startedAt, coalescedAt, coalesceAfter)
	}
	var lastSuccess string
	if err := s.DB.QueryRowContext(ctx, `SELECT last_success_at FROM notification_delivery_health WHERE destination_identity=?`, "late-success-rollback").Scan(&lastSuccess); err != nil {
		t.Fatal(err)
	}
	if lastSuccess != "" {
		t.Fatalf("failed late success changed destination success timestamp %q", lastSuccess)
	}
}

func TestFinalizeManagedScanOutboxFailureRollsBackChangeWindowEvidence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-finalization-outbox-failure", "UTC")
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_window_scan_outbox BEFORE INSERT ON outbox WHEN NEW.event_type='changes-detected' AND NEW.event_job_id='`+job.ID+`' BEGIN SELECT RAISE(ABORT,'synthetic scan outbox failure'); END`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scan := model.Scan{
		ID: "window-finalization-outbox-failure-scan", JobID: job.ID, Job: job.Job.Name,
		JobRevision: job.Revision, StartedAt: now, FinishedAt: now, Status: "success",
		ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{},
	}
	_, err = s.System().FinalizeManagedScan(ctx, &scan, job.ID, scan.ConfigHash, []string{"finalization-failure-destination"}, func(_ *model.JobState, current *model.Scan) ([]model.Event, error) {
		return []model.Event{{
			Type: "changes-detected", ScanID: current.ID, CreatedAt: current.FinishedAt,
			Changes: []model.Change{{Key: "outbox-failure-change", Kind: "port", Target: "192.0.2.10", Port: 443}},
		}}, nil
	})
	if err == nil {
		t.Fatal("scan finalization unexpectedly committed after its outbox insert failed")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM scans WHERE id=?`, scan.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM job_runtime WHERE job_id=?`, job.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM runtime_incidents WHERE job_id=?`, job.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM events WHERE type='changes-detected' AND scan_id=?`, scan.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE event_job_id=? AND event_type='changes-detected'`, job.ID) != 0 ||
		countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID) != 0 {
		t.Fatal("failed scan finalization left partial scan, incident, notification, or window evidence state")
	}
}

func TestBeginDeliveryAttemptRejectsTenantDisabledAfterClaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-disable-after-claim", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "disable-after-claim", job.ID, "changes-detected", "disable-after-claim-scan", time.Now().UTC(), []model.Change{{Key: "disable-after-claim-change", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "disable-after-claim-owner")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim before tenant disable = %d deliveries, %v", len(claimed), err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE tenants SET state=? WHERE id=?`, TenantStateDisabled, ts.scope.id); err != nil {
		t.Fatal(err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, claimed[0].ID, claimed[0].ClaimToken); !errors.Is(err, ErrDeliveryHeld) {
		t.Fatalf("handoff after tenant disable = %v; want ErrDeliveryHeld", err)
	}
	var claim, marker string
	var attempts, deferrals int
	if err := s.DB.QueryRowContext(ctx, `SELECT claim_token,attempt_started_at,attempts,deferrals FROM outbox WHERE id=?`, claimed[0].ID).Scan(&claim, &marker, &attempts, &deferrals); err != nil {
		t.Fatal(err)
	}
	if claim != "" || marker != "" || attempts != 0 || deferrals != 0 {
		t.Fatalf("disabled-tenant row claim=%q marker=%q attempts=%d deferrals=%d", claim, marker, attempts, deferrals)
	}
}

func TestBeginDeliveryAttemptWindowHoldFailureRollsBackEvidenceAndClaim(t *testing.T) {
	t.Parallel()
	for _, failureStage := range []string{"evidence", "deferral"} {
		t.Run(failureStage, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := openTestStore(t)
			ts := defaultTenant(s)
			job := createWindowTestJob(t, ts, "window-final-gate-"+failureStage, "UTC")
			queueWindowTestEvent(t, context.Background(), s, "final-gate-"+failureStage, job.ID, "changes-detected", "final-gate-"+failureStage, time.Now().UTC(), []model.Change{{Key: "final-gate-" + failureStage, Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
			claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "final-gate-owner-"+failureStage)
			if err != nil || len(claimed) != 1 {
				t.Fatalf("claim before active window = %d deliveries, %v", len(claimed), err)
			}
			window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
			if err != nil {
				t.Fatal(err)
			}
			trigger := `CREATE TRIGGER fail_final_gate_evidence BEFORE INSERT ON change_window_events BEGIN SELECT RAISE(ABORT,'synthetic event evidence failure'); END`
			if failureStage == "deferral" {
				trigger = `CREATE TRIGGER fail_final_gate_deferral BEFORE UPDATE OF next_at ON outbox WHEN OLD.id=` + fmt.Sprint(claimed[0].ID) + ` BEGIN SELECT RAISE(ABORT,'synthetic held-row release failure'); END`
			}
			if _, err := s.DB.ExecContext(ctx, trigger); err != nil {
				t.Fatal(err)
			}
			if err := s.System().BeginDeliveryAttempt(ctx, claimed[0].ID, claimed[0].ClaimToken); !errors.Is(err, ErrDeliveryAttemptNotStarted) {
				t.Fatalf("final gate after %s failure = %v; want ErrDeliveryAttemptNotStarted", failureStage, err)
			}
			var linked, claim, marker, coalesced string
			var attempts, deferrals int
			if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,claim_token,attempt_started_at,coalesced_at,attempts,deferrals FROM outbox WHERE id=?`, claimed[0].ID).Scan(&linked, &claim, &marker, &coalesced, &attempts, &deferrals); err != nil {
				t.Fatal(err)
			}
			if linked != window.ID || claim != claimed[0].ClaimToken || marker != "" || coalesced != "" || attempts != 0 || deferrals != 0 {
				t.Fatalf("failed final gate changed outbox link=%q claim=%q marker=%q coalesced=%q attempts=%d deferrals=%d", linked, claim, marker, coalesced, attempts, deferrals)
			}
			if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID) != 0 {
				t.Fatal("failed final gate left partial event evidence")
			}
		})
	}
}

func TestLateWindowDeliveryOutcomeWriteFailuresPreserveClaimAndBudgets(t *testing.T) {
	t.Parallel()
	for _, failureStage := range []string{"provider-success", "coalesce-after-failure"} {
		t.Run(failureStage, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := openTestStore(t)
			ts, _, item, window, closedAt := prepareWindowAttemptForAtomicity(t, s, "window-outcome-"+failureStage)
			var trigger string
			var outcome error
			if failureStage == "provider-success" {
				trigger = `CREATE TRIGGER fail_late_success_row BEFORE UPDATE OF sent_at ON outbox WHEN OLD.id=` + fmt.Sprint(item.ID) + ` AND NEW.sent_at<>'' BEGIN SELECT RAISE(ABORT,'synthetic sent-state failure'); END`
				outcome = nil
			} else {
				trigger = `CREATE TRIGGER fail_late_coalesce_row BEFORE UPDATE OF coalesced_at ON outbox WHEN OLD.id=` + fmt.Sprint(item.ID) + ` AND NEW.coalesced_at<>'' BEGIN SELECT RAISE(ABORT,'synthetic coalesce failure'); END`
				outcome = ErrDeliveryProviderTimeout
			}
			if _, err := s.DB.ExecContext(ctx, trigger); err != nil {
				t.Fatal(err)
			}
			if err := s.System().DeliveryResultClaim(ctx, item.ID, item.ClaimToken, outcome); err == nil {
				t.Fatal("late provider result unexpectedly committed after its outbox update failed")
			}
			var sentAt, claim, marker, coalesced string
			var attempts, deferrals, coalesceAfter int
			if err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(sent_at,''),claim_token,attempt_started_at,coalesced_at,attempts,deferrals,coalesce_after_attempt FROM outbox WHERE id=?`, item.ID).Scan(&sentAt, &claim, &marker, &coalesced, &attempts, &deferrals, &coalesceAfter); err != nil {
				t.Fatal(err)
			}
			if sentAt != "" || claim != item.ClaimToken || marker == "" || coalesced != "" || attempts != 0 || deferrals != 0 || coalesceAfter != 1 {
				t.Fatalf("failed late result changed outbox sent=%q claim=%q marker=%q coalesced=%q attempts=%d deferrals=%d coalesce-after=%d", sentAt, claim, marker, coalesced, attempts, deferrals, coalesceAfter)
			}
			if summary, err := ts.GetChangeWindow(ctx, item.Event.JobID, window.ID); err != nil || summary.ReviewState != "due" || summary.ClosedAt == nil || !summary.ClosedAt.Equal(closedAt) {
				t.Fatalf("failed late outcome changed durable close summary: %+v, %v", summary, err)
			}
		})
	}
}

func prepareWindowAttemptForAtomicity(t *testing.T, s *Store, name string) (*TenantStore, JobRecord, Delivery, ChangeWindow, time.Time) {
	t.Helper()
	ctx := context.Background()
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, name, "UTC")
	queueWindowTestEvent(t, context.Background(), s, "atomicity-"+name, job.ID, "changes-detected", "atomicity-scan-"+name, time.Now().UTC(), []model.Change{{Key: "atomicity-" + name, Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "atomicity-owner-"+name)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim before atomicity window = %d deliveries, %v", len(claimed), err)
	}
	item := claimed[0]
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
		t.Fatal(err)
	}
	closedAt := window.EndAt.Add(time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET claim_until=? WHERE id=?`, closedAt.Add(time.Minute).Format(time.RFC3339Nano), item.ID); err != nil {
		t.Fatal(err)
	}
	if summary, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return closedAt }, nil); err != nil || !changed || summary.InFlightEventCount != 1 {
		t.Fatalf("close during provider attempt = %+v, changed %v, err %v", summary, changed, err)
	}
	return ts, job, item, window, closedAt
}
