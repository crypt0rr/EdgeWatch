package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestBeginDeliveryAttemptDoesNotHoldAlertsForExpiredUnclosedWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, mode := range []string{"linked-before-window", "queued-after-window-end"} {
		t.Run(mode, func(t *testing.T) {
			s := openTestStoreWithContext(ctx, t)
			ts := defaultTenant(s)
			job := createWindowTestJobWithContext(ctx, t, ts, "expired-window-gate-"+mode, "UTC")
			now := time.Now().UTC().Truncate(time.Second)
			var early *ChangeWindow
			if mode == "linked-before-window" {
				queueWindowTestEvent(t, ctx, s, "expired-window-gate-"+mode, job.ID, "changes-detected", "expired-window-gate-scan", now, []model.Change{{Key: "expired-window-gate-change", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
			}
			firstEnd := now.Add(time.Hour)
			first, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, firstEnd, true, "first", "actor", "Operator")
			if err != nil {
				t.Fatal(err)
			}
			later := createTestChangeWindowWithContext(ctx, t, ts, job.ID, firstEnd.Add(time.Minute), firstEnd.Add(2*time.Hour))
			if mode == "queued-after-window-end" {
				if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET end_at=? WHERE id=?`, sqliteTimestamp(now.Add(-time.Second)), first.ID); err != nil {
					t.Fatal(err)
				}
				queueWindowTestEvent(t, ctx, s, "expired-window-gate-"+mode, job.ID, "changes-detected", "expired-window-gate-scan", now, []model.Change{{Key: "expired-window-gate-change", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
			} else {
				early = &first
				if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET end_at=? WHERE id=?`, sqliteTimestamp(now.Add(-time.Second)), first.ID); err != nil {
					t.Fatal(err)
				}
			}
			var id int64
			var linked string
			if err := s.DB.QueryRowContext(ctx, `SELECT id,change_window_id FROM outbox WHERE event_job_id=?`, job.ID).Scan(&id, &linked); err != nil {
				t.Fatal(err)
			}
			wantLink := later.ID
			if early != nil {
				wantLink = early.ID
			}
			if linked != wantLink {
				t.Fatalf("initial link = %q; want %q", linked, wantLink)
			}
			claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "expired-window-gate-worker")
			if err != nil || len(claimed) != 1 || claimed[0].ID != id {
				t.Fatalf("claim after end = %+v, %v; want the pending alert", claimed, err)
			}
			if err := s.System().BeginDeliveryAttempt(ctx, id, claimed[0].ClaimToken); err != nil {
				t.Fatalf("expired unclosed window held delivery: %v", err)
			}
			if err := s.System().DeliveryResultClaim(ctx, id, claimed[0].ClaimToken, nil); err != nil {
				t.Fatal(err)
			}
			closed, changed, err := ts.ExpireChangeWindow(ctx, first.ID, func() time.Time { return now }, nil)
			if err != nil || !changed || closed.SuppressedEventCount != 0 {
				t.Fatalf("close expired window after delivery = %+v, changed=%v, err=%v; sent post-end result must not be counted as suppressed", closed, changed, err)
			}
			var sent, coalesced string
			if err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(sent_at,''),coalesced_at FROM outbox WHERE id=?`, id).Scan(&sent, &coalesced); err != nil || sent == "" || coalesced != "" {
				t.Fatalf("post-end alert sent=%q coalesced=%q err=%v", sent, coalesced, err)
			}
		})
	}
}

func TestChangeWindowDeliveryPredicateReleasesAtExactEnd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-exact-end-boundary", "UTC")
	now := time.Now().UTC().Truncate(time.Second)
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, now.Add(time.Hour), true, "exact boundary", "actor", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	queueWindowTestEvent(t, ctx, s, "window-exact-end-boundary", job.ID, "changes-detected", "window-exact-end-scan", now, []model.Change{{Key: "window-exact-end-change", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	var id int64
	if err := s.DB.QueryRowContext(ctx, `SELECT id FROM outbox WHERE event_job_id=? AND event_type='changes-detected'`, job.ID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	endBoundary := now.Add(5 * time.Minute).Truncate(time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET end_at=? WHERE id=?`, sqliteTimestamp(endBoundary), window.ID); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{name: "one nanosecond before end remains held", now: endBoundary.Add(-time.Nanosecond), want: false},
		{name: "exact end is released", now: endBoundary, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var sendable bool
			nowText := sqliteTimestamp(test.now)
			if err := s.DB.QueryRowContext(ctx, `SELECT `+changeWindowDeliverySQL+` FROM outbox AS due WHERE due.id=?`, nowText, nowText, id).Scan(&sendable); err != nil {
				t.Fatal(err)
			}
			if sendable != test.want {
				t.Fatalf("change-window sendable at %s = %v, want %v", nowText, sendable, test.want)
			}
		})
	}
}

func TestExpireChangeWindowWithoutSummaryNotificationReleasesPendingAlertToLaterWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "destination-failure-release", "UTC")
	now := time.Now().UTC().Truncate(time.Second)
	firstEnd := now.Add(5 * time.Minute)
	first, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, firstEnd, true, "first", "actor", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	later := createTestChangeWindow(t, ts, job.ID, firstEnd.Add(10*time.Minute), firstEnd.Add(2*time.Hour))
	queueWindowTestEvent(t, ctx, s, "destination-failure-release", job.ID, "changes-detected", "destination-failure-release-scan", now, []model.Change{{Key: "destination-failure-release-change", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	var id int64
	if err := s.DB.QueryRowContext(ctx, `SELECT id FROM outbox WHERE event_job_id=?`, job.ID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	// Model a delayed expiry heartbeat while keeping a later open window active
	// at the terminal time.
	endedAt := now.Add(-time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET end_at=? WHERE id=?`, sqliteTimestamp(endedAt), first.ID); err != nil {
		t.Fatal(err)
	}
	terminalAt := endedAt.Add(ChangeWindowSummaryDestinationGrace)
	if _, changed, err := ts.ExpireChangeWindowWithoutSummaryNotification(ctx, first.ID, func() time.Time { return terminalAt.Add(-time.Nanosecond) }); err == nil || changed {
		t.Fatalf("terminal destination-failure close before grace = changed %v, err %v; want ErrConflict", changed, err)
	} else if !errors.Is(err, ErrConflict) {
		t.Fatalf("early terminal close error = %v; want ErrConflict", err)
	}
	closedSummary, changed, err := ts.ExpireChangeWindowWithoutSummaryNotification(ctx, first.ID, func() time.Time { return terminalAt.Add(time.Nanosecond) })
	if err != nil || !changed || closedSummary.SummaryNotificationStatus != "not_queued_destinations_unavailable" || closedSummary.SuppressedEventCount != 1 {
		t.Fatalf("terminal destination-failure close = %+v changed=%v err=%v", closedSummary, changed, err)
	}
	closed, err := ts.GetChangeWindow(ctx, job.ID, first.ID)
	if err != nil || closed.Summary == nil || closed.Summary.SummaryNotificationStatus != "not_queued_destinations_unavailable" {
		t.Fatalf("persisted destination-failure outcome = %+v, err %v", closed.Summary, err)
	}
	var linked, coalesced, claim, started string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,coalesced_at,claim_token,attempt_started_at FROM outbox WHERE id=?`, id).Scan(&linked, &coalesced, &claim, &started); err != nil {
		t.Fatal(err)
	}
	if linked != later.ID || coalesced != "" || claim != "" || started != "" {
		t.Fatalf("released alert link=%q coalesced=%q claim=%q started=%q; want later window and retryable state", linked, coalesced, claim, started)
	}
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "destination-failure-release-worker")
	if err != nil || len(claimed) != 1 || claimed[0].ID != id {
		t.Fatalf("claim released alert = %+v, %v", claimed, err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, id, claimed[0].ClaimToken); err != nil {
		t.Fatalf("released post-window alert was not sendable: %v", err)
	}
	if err := s.System().DeliveryResultClaim(ctx, id, claimed[0].ClaimToken, nil); err != nil {
		t.Fatal(err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE event_type='change-window-summary' AND event_job_id=?`, job.ID) != 0 {
		t.Fatal("terminal fallback queued an undeliverable summary notification")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM events WHERE type='change-window-summary' AND job_id=?`, job.ID) != 1 {
		t.Fatal("terminal fallback did not retain one durable review event")
	}
}

func TestExpireChangeWindowWithoutSummaryNotificationPreservesInFlightFailureRetry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "destination-failure-in-flight", "UTC")
	now := time.Now().UTC().Truncate(time.Second)
	firstEnd := now.Add(time.Hour)
	queueWindowTestEvent(t, ctx, s, "destination-failure-in-flight", job.ID, "changes-detected", "destination-failure-in-flight-scan", now, []model.Change{{Key: "destination-failure-in-flight-change", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	first, err := defaultTenant(s).CreateChangeWindow(ctx, job.ID, now.Add(time.Minute), firstEnd, false, "first", "actor", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	later := createTestChangeWindow(t, defaultTenant(s), job.ID, firstEnd.Add(time.Minute), firstEnd.Add(2*time.Hour))
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "destination-failure-in-flight-worker")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim before future window = %+v, %v", claimed, err)
	}
	id := claimed[0].ID
	if err := s.System().BeginDeliveryAttempt(ctx, id, claimed[0].ClaimToken); err != nil {
		t.Fatal(err)
	}
	endedAt := now.Add(-time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET end_at=? WHERE id=?`, sqliteTimestamp(endedAt), first.ID); err != nil {
		t.Fatal(err)
	}
	terminalAt := endedAt.Add(ChangeWindowSummaryDestinationGrace)
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET claim_until=? WHERE id=?`, sqliteTimestamp(terminalAt.Add(time.Minute)), id); err != nil {
		t.Fatal(err)
	}
	summary, changed, err := defaultTenant(s).ExpireChangeWindowWithoutSummaryNotification(ctx, first.ID, func() time.Time { return terminalAt })
	if err != nil || !changed || summary.InFlightEventCount != 1 {
		t.Fatalf("close with live provider attempt = %+v changed=%v err=%v", summary, changed, err)
	}
	var linked, marker, claim string
	var coalesceAfter int
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,attempt_started_at,claim_token,coalesce_after_attempt FROM outbox WHERE id=?`, id).Scan(&linked, &marker, &claim, &coalesceAfter); err != nil {
		t.Fatal(err)
	}
	if linked != later.ID || marker == "" || claim != claimed[0].ClaimToken || coalesceAfter != 0 {
		t.Fatalf("in-flight row after fallback link=%q marker=%q claim=%q coalesce-after=%d", linked, marker, claim, coalesceAfter)
	}
	if err := s.System().DeliveryResultClaim(ctx, id, claim, &DeliveryFailure{Err: ErrDeliveryProvider, Class: DeliveryClassProvider}); err != nil {
		t.Fatalf("record in-flight provider failure after fallback: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE id=?`, sqliteTimestamp(time.Now().UTC().Add(-time.Second)), id); err != nil {
		t.Fatal(err)
	}
	retry, err := s.System().ClaimDueDeliveries(ctx, 1, "destination-failure-in-flight-retry")
	if err != nil || len(retry) != 1 || retry[0].ID != id {
		t.Fatalf("failed in-flight alert retry = %+v, %v", retry, err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, id, retry[0].ClaimToken); err != nil {
		t.Fatalf("failed alert was not retryable after destination fallback: %v", err)
	}
}
