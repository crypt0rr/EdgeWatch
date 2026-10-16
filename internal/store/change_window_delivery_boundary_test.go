package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func openTestStoreWithContext(ctx context.Context, t *testing.T) *Store {
	t.Helper()
	s, err := openWithOptionsContext(ctx, freshTestDatabasePath(t), openOptions{create: true, migrate: true, configureWAL: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestBeginDeliveryAttemptRechecksActiveWindowAfterClaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-pre-send-recheck", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "pre-send-destination", job.ID, "changes-detected", "scan-pre-send", time.Now().UTC(), []model.Change{{Key: "new:pre-send", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	claimed, err := s.System().ClaimDueDeliveries(ctx, 10, "pre-window-claim")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim before window creation = %d deliveries, %v", len(claimed), err)
	}
	item := claimed[0]
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, ""); !errors.Is(err, ErrDeliveryClaimLost) {
		t.Fatalf("empty claim token = %v; want ErrDeliveryClaimLost", err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, "other-owner"); !errors.Is(err, ErrDeliveryClaimLost) {
		t.Fatalf("wrong claim token = %v; want ErrDeliveryClaimLost", err)
	}
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); !errors.Is(err, ErrDeliveryWindowHeld) {
		t.Fatalf("final pre-send gate = %v; want ErrDeliveryWindowHeld", err)
	}
	var linked, startedAt, claim, nextAt string
	var attempts, deferrals int
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,attempt_started_at,claim_token,next_at,attempts,deferrals FROM outbox WHERE id=?`, item.ID).Scan(&linked, &startedAt, &claim, &nextAt, &attempts, &deferrals); err != nil {
		t.Fatal(err)
	}
	if linked != window.ID || startedAt != "" || claim != "" || nextAt != window.EndAt.Format(time.RFC3339Nano) || attempts != 0 || deferrals != 0 {
		t.Fatalf("held row linked=%q started=%q claim=%q next=%q attempts=%d deferrals=%d", linked, startedAt, claim, nextAt, attempts, deferrals)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=? AND event_type='changes-detected'`, window.ID) != 1 {
		t.Fatal("the event held at the final boundary was not retained for the closing review")
	}
	if replay, err := s.System().ClaimDueDeliveries(ctx, 10, "retry-before-close"); err != nil || len(replay) != 0 {
		t.Fatalf("held row was immediately replayed: %#v, %v", replay, err)
	}
}

func TestBeginDeliveryAttemptMarksOrdinaryChangeEventWithoutWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-ordinary-change", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "ordinary-change-destination", job.ID, "changes-detected", "scan-ordinary", time.Now().UTC(), []model.Change{{Key: "new:ordinary", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	claimed, err := s.System().ClaimDueDeliveries(ctx, 10, "ordinary-change-owner")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("ordinary change claim = %d deliveries, %v", len(claimed), err)
	}
	item := claimed[0]
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
		t.Fatalf("ordinary change invocation = %v", err)
	}
	var windowID, marker string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,attempt_started_at FROM outbox WHERE id=?`, item.ID).Scan(&windowID, &marker); err != nil {
		t.Fatal(err)
	}
	if windowID != "" || marker == "" {
		t.Fatalf("ordinary change invocation window=%q marker=%q; want unlinked with a durable start", windowID, marker)
	}
	if err := s.System().DeliveryResultClaim(ctx, item.ID, item.ClaimToken, nil); err != nil {
		t.Fatal(err)
	}
}

func TestActiveWindowDoesNotHoldNonChangeAlert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-health-alert", "UTC")
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	event := model.Event{Type: "health-check", JobID: job.ID, TenantID: DefaultTenantID, ScanID: "health-during-window", Message: "deployment health remains visible", CreatedAt: time.Now().UTC()}
	if err := s.System().QueueEvent(ctx, "window-health-destination", event); err != nil {
		t.Fatal(err)
	}
	var linked string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id FROM outbox WHERE destination=? AND event_job_id=? AND event_type='health-check'`, "window-health-destination", job.ID).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if linked != "" {
		t.Fatalf("non-change health alert was linked to quiet window %q", linked)
	}
	claimed, err := s.System().ClaimDueDeliveries(ctx, 10, "window-health-owner")
	if err != nil || len(claimed) != 1 || claimed[0].Event.Type != "health-check" {
		t.Fatalf("health alert claim during active window = %#v, %v", claimed, err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, claimed[0].ID, claimed[0].ClaimToken); err != nil {
		t.Fatalf("active quiet window held a non-change alert: %v", err)
	}
	var marker string
	if err := s.DB.QueryRowContext(ctx, `SELECT attempt_started_at FROM outbox WHERE id=?`, claimed[0].ID).Scan(&marker); err != nil {
		t.Fatal(err)
	}
	if marker != "" {
		t.Fatalf("non-change alert acquired a change-window invocation marker %q", marker)
	}
	if err := s.System().DeliveryResultClaim(ctx, claimed[0].ID, claimed[0].ClaimToken, nil); err != nil {
		t.Fatalf("record unmuted health alert delivery: %v", err)
	}
	if status, err := ts.GetChangeWindow(ctx, job.ID, window.ID); err != nil || status.SuppressedEventCount != 0 || status.InFlightEventCount != 0 {
		t.Fatalf("non-change alert altered quiet-window evidence: %+v, %v", status, err)
	}
}

func TestReleaseDeliveryClaimsPreservesOrdinaryRetryAndCoalescesClosedWindowAttempt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-release-matrix", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "ordinary-release-destination", job.ID, "changes-detected", "scan-ordinary-release", time.Now().UTC(), []model.Change{{Key: "new:ordinary-release", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	ordinary, err := s.System().ClaimDueDeliveries(ctx, 1, "ordinary-release-owner")
	if err != nil || len(ordinary) != 1 {
		t.Fatalf("ordinary claim = %d deliveries, %v", len(ordinary), err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, ordinary[0].ID, ordinary[0].ClaimToken); err != nil {
		t.Fatal(err)
	}
	if released, err := s.System().ReleaseDeliveryClaims(ctx); err != nil || released != 1 {
		t.Fatalf("release ordinary started alert = %d, %v", released, err)
	}
	var ordinaryMarker, ordinaryCoalesced, ordinaryClaim string
	if err := s.DB.QueryRowContext(ctx, `SELECT attempt_started_at,coalesced_at,claim_token FROM outbox WHERE id=?`, ordinary[0].ID).Scan(&ordinaryMarker, &ordinaryCoalesced, &ordinaryClaim); err != nil {
		t.Fatal(err)
	}
	if ordinaryMarker != "" || ordinaryCoalesced != "" || ordinaryClaim != "" {
		t.Fatalf("ordinary released row marker=%q coalesced=%q claim=%q", ordinaryMarker, ordinaryCoalesced, ordinaryClaim)
	}
	ordinaryReplay, err := s.System().ClaimDueDeliveries(ctx, 1, "ordinary-retry-owner")
	if err != nil || len(ordinaryReplay) != 1 {
		t.Fatalf("ordinary alert was not retryable after recovery: %#v, %v", ordinaryReplay, err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, ordinaryReplay[0].ID, ordinaryReplay[0].ClaimToken); err != nil {
		t.Fatal(err)
	}
	if err := s.System().DeliveryResultClaim(ctx, ordinaryReplay[0].ID, ordinaryReplay[0].ClaimToken, nil); err != nil {
		t.Fatal(err)
	}

	windowJob := createWindowTestJob(t, ts, "window-release-closed", "UTC")
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, windowJob.ID, start, start.Add(time.Hour))
	queueWindowTestEvent(t, context.Background(), s, "closed-release-destination", windowJob.ID, "changes-detected", "scan-closed-release", time.Now().UTC(), []model.Change{{Key: "new:closed-release", Kind: "port", Target: "192.0.2.11", Port: 443}}, false, 0)
	linked, err := s.System().ClaimDueDeliveries(ctx, 1, "closed-window-owner")
	if err != nil || len(linked) != 1 {
		t.Fatalf("window-linked claim = %d deliveries, %v", len(linked), err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, linked[0].ID, linked[0].ClaimToken); err != nil {
		t.Fatal(err)
	}
	closedAt := window.EndAt.Add(time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET claim_until=? WHERE id=?`, closedAt.Add(time.Minute).Format(time.RFC3339Nano), linked[0].ID); err != nil {
		t.Fatal(err)
	}
	if summary, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return closedAt }, nil); err != nil || !changed || summary.InFlightEventCount != 1 {
		t.Fatalf("close with owned attempt = %+v, changed %v, err %v", summary, changed, err)
	}
	if released, err := s.System().ReleaseDeliveryClaims(ctx); err != nil || released != 1 {
		t.Fatalf("release closed-window attempt = %d, %v", released, err)
	}
	var marker, coalesced, claim string
	if err := s.DB.QueryRowContext(ctx, `SELECT attempt_started_at,coalesced_at,claim_token FROM outbox WHERE id=?`, linked[0].ID).Scan(&marker, &coalesced, &claim); err != nil {
		t.Fatal(err)
	}
	if marker != "" || coalesced == "" || claim != "" {
		t.Fatalf("recovered closed-window row marker=%q coalesced=%q claim=%q", marker, coalesced, claim)
	}
	if replay, err := s.System().ClaimDueDeliveries(ctx, 10, "closed-window-replay"); err != nil || len(replay) != 0 {
		t.Fatalf("closed-window alert replayed after recovery: %#v, %v", replay, err)
	}
}

func TestDeliveredInFlightChangeAfterWindowCloseRecordsSuccessOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-late-success", "UTC")
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	queueWindowTestEvent(t, context.Background(), s, "late-success-destination", job.ID, "changes-detected", "scan-late-success", time.Now().UTC(), []model.Change{{Key: "new:late-success", Kind: "port", Target: "192.0.2.12", Port: 443}}, false, 0)
	deliveries, err := s.System().ClaimDueDeliveries(ctx, 1, "late-success-owner")
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("late success claim = %d deliveries, %v", len(deliveries), err)
	}
	item := deliveries[0]
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
		t.Fatal(err)
	}
	closedAt := window.EndAt.Add(time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET claim_until=? WHERE id=?`, closedAt.Add(time.Minute).Format(time.RFC3339Nano), item.ID); err != nil {
		t.Fatal(err)
	}
	if summary, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return closedAt }, nil); err != nil || !changed || summary.InFlightEventCount != 1 {
		t.Fatalf("close in-flight event = %+v, changed %v, err %v", summary, changed, err)
	}
	if err := s.System().DeliveryResultClaim(ctx, item.ID, item.ClaimToken, nil); err != nil {
		t.Fatal(err)
	}
	var sentAt, coalesced, claim, marker string
	var attempts, deferrals int
	if err := s.DB.QueryRowContext(ctx, `SELECT sent_at,coalesced_at,claim_token,attempt_started_at,attempts,deferrals FROM outbox WHERE id=?`, item.ID).Scan(&sentAt, &coalesced, &claim, &marker, &attempts, &deferrals); err != nil {
		t.Fatal(err)
	}
	if sentAt == "" || coalesced != "" || claim != "" || marker != "" || attempts != 0 || deferrals != 0 {
		t.Fatalf("successful late result sent=%q coalesced=%q claim=%q marker=%q attempts=%d deferrals=%d", sentAt, coalesced, claim, marker, attempts, deferrals)
	}
	if health, err := ts.ListDeliveryHealth(ctx); err != nil || health["late-success-destination"].TerminalFailures != 0 || !health["late-success-destination"].LastFailureAt.IsZero() {
		t.Fatalf("successful late result health = %+v, %v", health, err)
	}
}

func TestProviderSuccessAfterWindowEndSurvivesDelayedExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-late-success-before-close", "UTC")
	queueWindowTestEvent(t, ctx, s, "late-success-before-close-destination", job.ID, "changes-detected", "scan-late-success-before-close", time.Now().UTC(), []model.Change{{Key: "new:late-success-before-close", Kind: "port", Target: "192.0.2.13", Port: 443}}, false, 0)
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	deliveries, err := s.System().ClaimDueDeliveries(ctx, 1, "late-success-before-close-owner")
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim before future window = %d deliveries, %v", len(deliveries), err)
	}
	item := deliveries[0]
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
		t.Fatal(err)
	}
	endedAt := time.Now().UTC().Add(-time.Second).Truncate(time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=?,end_at=? WHERE id=?`, sqliteTimestamp(endedAt.Add(-time.Hour)), sqliteTimestamp(endedAt), window.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.System().DeliveryResultClaim(ctx, item.ID, item.ClaimToken, nil); err != nil {
		t.Fatalf("record successful provider result after end_at: %v", err)
	}
	var sentAt, coalesced, claim, marker string
	if err := s.DB.QueryRowContext(ctx, `SELECT sent_at,coalesced_at,claim_token,attempt_started_at FROM outbox WHERE id=?`, item.ID).Scan(&sentAt, &coalesced, &claim, &marker); err != nil {
		t.Fatal(err)
	}
	if sentAt == "" || coalesced != "" || claim != "" || marker != "" {
		t.Fatalf("post-end success before close sent=%q coalesced=%q claim=%q marker=%q", sentAt, coalesced, claim, marker)
	}

	if summary, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return endedAt.Add(time.Second) }, nil); err != nil || !changed {
		t.Fatalf("delayed window expiry = %+v changed=%v err=%v", summary, changed, err)
	}
	var afterSent, afterCoalesced string
	if err := s.DB.QueryRowContext(ctx, `SELECT sent_at,coalesced_at FROM outbox WHERE id=?`, item.ID).Scan(&afterSent, &afterCoalesced); err != nil {
		t.Fatal(err)
	}
	if afterSent != sentAt || afterCoalesced != "" {
		t.Fatalf("delayed expiry changed provider result sent=%q→%q coalesced=%q; want sent result preserved", sentAt, afterSent, afterCoalesced)
	}
}

func TestReleaseDeliveryClaimsUsesExactWindowIntervalForStartedAttempts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		endOffset  time.Duration
		wantMarker bool
	}{
		{name: "active window retains unknown outcome", endOffset: time.Hour, wantMarker: true},
		{name: "expired unclosed window retries", endOffset: -time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := openTestStoreWithContext(ctx, t)
			ts := defaultTenant(s)
			job := createWindowTestJobWithContext(ctx, t, ts, "window-recovery-"+strings.ReplaceAll(tc.name, " ", "-"), "UTC")
			queueWindowTestEvent(t, ctx, s, "window-recovery-"+job.ID, job.ID, "changes-detected", "scan-window-recovery-"+job.ID, time.Now().UTC(), []model.Change{{Key: "new:window-recovery-" + job.ID, Kind: "port", Target: "192.0.2.14", Port: 443}}, false, 0)
			start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
			window := createTestChangeWindowWithContext(ctx, t, ts, job.ID, start, start.Add(time.Hour))
			claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "window-recovery-owner-"+job.ID)
			if err != nil || len(claimed) != 1 {
				t.Fatalf("claim before future window = %+v, %v", claimed, err)
			}
			item := claimed[0]
			if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=?,end_at=? WHERE id=?`, sqliteTimestamp(now.Add(-time.Hour)), sqliteTimestamp(now.Add(tc.endOffset)), window.ID); err != nil {
				t.Fatal(err)
			}
			if released, err := s.System().ReleaseDeliveryClaims(ctx); err != nil || released != 1 {
				t.Fatalf("release started delivery = %d, %v", released, err)
			}
			var marker, coalesced, claim string
			if err := s.DB.QueryRowContext(ctx, `SELECT attempt_started_at,coalesced_at,claim_token FROM outbox WHERE id=?`, item.ID).Scan(&marker, &coalesced, &claim); err != nil {
				t.Fatal(err)
			}
			if (marker != "") != tc.wantMarker || coalesced != "" || claim != "" {
				t.Fatalf("recovered attempt marker=%q coalesced=%q claim=%q; want marker=%t and no coalescing/claim", marker, coalesced, claim, tc.wantMarker)
			}
			retry, err := s.System().ClaimDueDeliveries(ctx, 1, "window-recovery-retry-"+job.ID)
			if tc.wantMarker {
				if err != nil || len(retry) != 0 {
					t.Fatalf("active-window attempt was released for retry: %+v, %v", retry, err)
				}
				return
			}
			if err != nil || len(retry) != 1 || retry[0].ID != item.ID {
				t.Fatalf("expired-window attempt is not retryable: %+v, %v", retry, err)
			}
			if err := s.System().BeginDeliveryAttempt(ctx, retry[0].ID, retry[0].ClaimToken); err != nil {
				t.Fatalf("expired-window retry was held: %v", err)
			}
			if err := s.System().DeliveryResultClaim(ctx, retry[0].ID, retry[0].ClaimToken, nil); err != nil {
				t.Fatalf("complete expired-window retry: %v", err)
			}
		})
	}
}

func TestReleaseDeliveryClaimsCountsMixedWindowAndOrdinaryClaims(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	windowJob := createWindowTestJob(t, ts, "window-release-mixed", "UTC")
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, windowJob.ID, start, start.Add(time.Hour))
	queueWindowTestEvent(t, context.Background(), s, "mixed-window-destination", windowJob.ID, "changes-detected", "scan-mixed-window", time.Now().UTC(), []model.Change{{Key: "new:mixed-window", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	ordinaryJob := createWindowTestJob(t, ts, "window-release-mixed-ordinary", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "mixed-ordinary-destination", ordinaryJob.ID, "changes-recovered", "scan-mixed-ordinary", time.Now().UTC(), []model.Change{{Key: "recovered:mixed-ordinary", Kind: "port", Target: "192.0.2.11", Port: 443}}, false, 0)
	claimed, err := s.System().ClaimDueDeliveries(ctx, 10, "mixed-release-owner")
	if err != nil || len(claimed) != 2 {
		t.Fatalf("mixed claims = %d deliveries, %v", len(claimed), err)
	}
	var windowDelivery, ordinaryDelivery Delivery
	for _, item := range claimed {
		switch item.Event.JobID {
		case windowJob.ID:
			windowDelivery = item
		case ordinaryJob.ID:
			ordinaryDelivery = item
		}
	}
	if windowDelivery.ID == 0 || ordinaryDelivery.ID == 0 {
		t.Fatalf("mixed claims do not identify both rows: %+v", claimed)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, windowDelivery.ID, windowDelivery.ClaimToken); err != nil {
		t.Fatal(err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, ordinaryDelivery.ID, ordinaryDelivery.ClaimToken); err != nil {
		t.Fatal(err)
	}
	closedAt := window.EndAt.Add(time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET claim_until=? WHERE id=?`, closedAt.Add(time.Minute).Format(time.RFC3339Nano), windowDelivery.ID); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return closedAt }, nil); err != nil || !changed {
		t.Fatalf("close mixed linked window: changed %v, err %v", changed, err)
	}
	if released, err := s.System().ReleaseDeliveryClaims(ctx); err != nil || released != 2 {
		t.Fatalf("release mixed active claims = %d, %v; want both linked and ordinary claims", released, err)
	}
	var linkedCoalesced, linkedClaim, ordinaryCoalesced, ordinaryClaim, ordinaryMarker string
	if err := s.DB.QueryRowContext(ctx, `SELECT coalesced_at,claim_token FROM outbox WHERE id=?`, windowDelivery.ID).Scan(&linkedCoalesced, &linkedClaim); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT coalesced_at,claim_token,attempt_started_at FROM outbox WHERE id=?`, ordinaryDelivery.ID).Scan(&ordinaryCoalesced, &ordinaryClaim, &ordinaryMarker); err != nil {
		t.Fatal(err)
	}
	if linkedCoalesced == "" || linkedClaim != "" || ordinaryCoalesced != "" || ordinaryClaim != "" || ordinaryMarker != "" {
		t.Fatalf("released mixed rows: linked coalesced=%q claim=%q ordinary coalesced=%q claim=%q marker=%q", linkedCoalesced, linkedClaim, ordinaryCoalesced, ordinaryClaim, ordinaryMarker)
	}
	if released, err := s.System().ReleaseDeliveryClaims(ctx); err != nil || released != 0 {
		t.Fatalf("idle release = %d, %v; want zero", released, err)
	}
}

func TestRuntimeFinalizationRecordsWindowEvidenceAndCurrentOpenIncidents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-runtime-finalization", "UTC")
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
	if err != nil {
		t.Fatal(err)
	}

	firstEvents := finalizeWindowChangeScan(t, ctx, s, job, "runtime-window-scan", []string{"runtime-window-destination"}, func(state *model.JobState) {
		state.Incidents = make(map[string]model.Incident, changeWindowDetailLimit+5)
		for i := 0; i < changeWindowDetailLimit+5; i++ {
			key := fmt.Sprintf("still-open:%02d", i)
			change := model.Change{Key: key, Kind: "port", Target: "192.0.2.10", Port: 4000 + i}
			state.Incidents[key] = model.Incident{Change: change, ScanID: "runtime-scan", OpenedAt: window.StartAt, LastSeenAt: window.StartAt}
		}
	})
	if len(firstEvents) != 1 || firstEvents[0].JobID != job.ID || firstEvents[0].CreatedAt.IsZero() {
		t.Fatalf("finalized scan events = %+v; want the job ID and assigned event timestamp", firstEvents)
	}
	var associatedWindow string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id FROM outbox WHERE destination=? AND event_job_id=? AND event_type='changes-detected'`, "runtime-window-destination", job.ID).Scan(&associatedWindow); err != nil {
		t.Fatal(err)
	}
	if associatedWindow != window.ID {
		t.Fatalf("finalized scan alert associated with window %q; want %q; event=%+v window=%+v eventRefs=%d", associatedWindow, window.ID, firstEvents, window, countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID))
	}

	closedAt := time.Now().UTC().Add(time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET end_at=? WHERE id=?`, sqliteTimestamp(closedAt.Add(-time.Second)), window.ID); err != nil {
		t.Fatal(err)
	}
	summary, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return closedAt }, nil)
	if err != nil || !changed {
		t.Fatalf("close window after runtime transition: changed %v, err %v", changed, err)
	}
	if summary.NewCount != 1 || summary.StillOpenCount != changeWindowDetailLimit+5 || len(summary.StillOpen) != changeWindowDetailLimit || !summary.StillOpenDetailsTruncated {
		t.Fatalf("closing review = new %d, still open %d, details %d, truncated %v; want exact aggregate and bounded current incidents", summary.NewCount, summary.StillOpenCount, len(summary.StillOpen), summary.StillOpenDetailsTruncated)
	}
	closed, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || closed.ReviewState != "due" || closed.Summary == nil || closed.Summary.StillOpenCount != changeWindowDetailLimit+5 {
		t.Fatalf("durable runtime close review = %+v, err %v", closed, err)
	}
	var coalescedAt, sentAt, claim string
	if err := s.DB.QueryRowContext(ctx, `SELECT coalesced_at,COALESCE(sent_at,''),claim_token FROM outbox WHERE destination=? AND event_job_id=? AND event_type='changes-detected'`, "runtime-window-destination", job.ID).Scan(&coalescedAt, &sentAt, &claim); err != nil {
		t.Fatal(err)
	}
	if coalescedAt == "" || sentAt != "" || claim != "" {
		t.Fatalf("closed-window outbox row coalesced=%q sent=%q claim=%q; want coalesced and not individually delivered", coalescedAt, sentAt, claim)
	}

	postEndEvents := finalizeWindowChangeScan(t, ctx, s, job, "runtime-post-window-scan", []string{"post-window-destination"}, nil)
	if len(postEndEvents) != 1 {
		t.Fatalf("post-end finalization events = %+v; want one change event", postEndEvents)
	}
	var postEndWindow string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id FROM outbox WHERE destination=? AND event_job_id=? AND event_type='changes-detected'`, "post-window-destination", job.ID).Scan(&postEndWindow); err != nil {
		t.Fatal(err)
	}
	if postEndWindow != "" {
		t.Fatalf("new post-end event linked to closed window %q", postEndWindow)
	}
	claimed, err := s.System().ClaimDueDeliveries(ctx, 10, "post-window-claim")
	if err != nil || len(claimed) != 1 || claimed[0].Destination != "post-window-destination" {
		t.Fatalf("post-end claim = %#v, %v; want only the unlinked post-end alert", claimed, err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, claimed[0].ID, claimed[0].ClaimToken); err != nil {
		t.Fatalf("post-end event was not sendable: %v", err)
	}
	if err := s.System().DeliveryResultClaim(ctx, claimed[0].ID, claimed[0].ClaimToken, nil); err != nil {
		t.Fatalf("record post-end provider success: %v", err)
	}
}

func TestRuntimeFinalizationAssociatesPreStartChangeWithFutureWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-future-finalization", "UTC")
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	finalized := finalizeWindowChangeScan(t, ctx, s, job, "runtime-future-window-scan", []string{"future-window-destination"}, nil)
	if len(finalized) != 1 {
		t.Fatalf("future-window finalization events = %+v; want one change event", finalized)
	}
	var linkedWindow string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id FROM outbox WHERE destination=? AND event_job_id=? AND event_type='changes-detected'`, "future-window-destination", job.ID).Scan(&linkedWindow); err != nil {
		t.Fatal(err)
	}
	if linkedWindow != window.ID {
		t.Fatalf("pre-start scan event linked to %q; want future window %q", linkedWindow, window.ID)
	}
	claimed, err := s.System().ClaimDueDeliveries(ctx, 10, "future-window-prestart")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("pre-start future-window claim = %#v, %v; want one sendable row", claimed, err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, claimed[0].ID, claimed[0].ClaimToken); err != nil {
		t.Fatalf("future-window alert should remain sendable before start: %v", err)
	}
	if err := s.System().DeliveryResultClaim(ctx, claimed[0].ID, claimed[0].ClaimToken, nil); err != nil {
		t.Fatalf("record pre-start delivery success: %v", err)
	}
}

func finalizeWindowChangeScan(t *testing.T, ctx context.Context, s *Store, job JobRecord, scanID string, destinations []string, prepare func(*model.JobState)) []model.Event {
	t.Helper()
	now := time.Now().UTC()
	scan := model.Scan{
		ID: scanID, JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision,
		StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{},
	}
	events, err := s.System().FinalizeManagedScan(ctx, &scan, job.ID, scan.ConfigHash, destinations, func(state *model.JobState, current *model.Scan) ([]model.Event, error) {
		if prepare != nil {
			prepare(state)
		}
		return []model.Event{{
			Type: "changes-detected", ScanID: current.ID,
			Changes: []model.Change{{Key: "new:" + current.ID, Kind: "port", Target: "192.0.2.10", Port: 443}},
		}}, nil
	})
	if err != nil {
		t.Fatalf("finalize managed scan %q: %v", scanID, err)
	}
	return events
}
