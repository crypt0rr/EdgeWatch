package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

func createWindowTestJob(t *testing.T, ts *TenantStore, name, timezone string) JobRecord {
	t.Helper()
	job := config.NormalizeJob(config.Job{
		Name: name, Schedule: "0 * * * *", Timezone: timezone,
		Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"},
	})
	record, err := ts.CreateJob(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func createTestChangeWindow(t *testing.T, ts *TenantStore, jobID string, start, end time.Time) ChangeWindow {
	t.Helper()
	window, err := ts.CreateChangeWindow(context.Background(), jobID, start, end, false, "maintenance", "test-actor", "Test Operator")
	if err != nil {
		t.Fatal(err)
	}
	return window
}

func queueWindowTestEvent(t *testing.T, ctx context.Context, s *Store, destination, jobID, eventType, scanID string, at time.Time, changes []model.Change, truncated bool, reported int) {
	t.Helper()
	event := model.Event{
		Type: eventType, JobID: jobID, Job: "edge", ScanID: scanID,
		Message: "test change event", CreatedAt: at, Changes: changes,
		ChangesTruncated: truncated, ChangesCount: reported,
	}
	if err := s.System().QueueEvent(ctx, destination, event); err != nil {
		t.Fatal(err)
	}
}

func TestChangeWindowValidationAndZoneOffsets(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-validation", "UTC")
	now := time.Now().UTC()
	start := now.Add(2 * time.Hour).Truncate(time.Second)
	end := start.Add(time.Hour)
	first := createTestChangeWindow(t, ts, job.ID, start, end)

	if _, err := ts.CreateChangeWindow(context.Background(), job.ID, start.Add(30*time.Minute), end.Add(time.Minute), false, "overlap", "actor", "Operator"); !errors.Is(err, ErrConflict) {
		t.Fatalf("overlapping window error = %v, want ErrConflict", err)
	}
	if _, err := ts.CreateChangeWindow(context.Background(), job.ID, end, end.Add(time.Hour), false, "adjacent", "actor", "Operator"); err != nil {
		t.Fatalf("adjacent window rejected: %v", err)
	}
	if _, err := ts.CreateChangeWindow(context.Background(), job.ID, end.Add(2*time.Hour), end.Add(26*time.Hour+time.Nanosecond), false, "too long", "actor", "Operator"); !errors.Is(err, ErrValidation) {
		t.Fatalf("overlong window error = %v, want validation error", err)
	}

	future := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	before := createTestChangeWindow(t, ts, job.ID, future, future.Add(time.Hour))
	cancelled, changed, err := ts.CancelChangeWindow(context.Background(), job.ID, before.ID, "test-actor", "Test Operator", nil, AuditEntry{})
	if err != nil || !changed {
		t.Fatalf("cancel before start = changed %v, err %v", changed, err)
	}
	if cancelled.Status != "cancelled" || cancelled.EndReason != "cancelled-before-start" || cancelled.ReviewState != "none" || cancelled.Summary != nil || cancelled.EffectiveEnd != nil {
		t.Fatalf("cancelled future window = %+v; a pre-start cancel must have no summary or effective end", cancelled)
	}
	var summaries int
	if err := s.DB.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM events WHERE type='change-window-summary' AND job_id=?`, job.ID).Scan(&summaries); err != nil || summaries != 0 {
		t.Fatalf("summary events after pre-start cancel = %d, %v; want none", summaries, err)
	}

	location, err := time.LoadLocation("Europe/Amsterdam")
	if err != nil {
		t.Fatal(err)
	}
	for _, fold := range []string{"2026-10-25T02:30:00+02:00", "2026-10-25T02:30:00+01:00"} {
		instant, err := time.Parse(time.RFC3339Nano, fold)
		if err != nil || !validJobZoneInstant(instant, location) {
			t.Errorf("valid repeated-hour offset %s rejected: %v", fold, err)
		}
	}
	for _, invalid := range []string{"2026-03-29T02:30:00+01:00", "2026-10-25T02:30:00Z"} {
		instant, err := time.Parse(time.RFC3339Nano, invalid)
		if err != nil {
			t.Fatal(err)
		}
		if validJobZoneInstant(instant, location) {
			t.Errorf("invalid local time/offset %s was accepted", invalid)
		}
	}
	if first.ID == "" {
		t.Fatal("first window ID is empty")
	}
}

func TestCreateChangeWindowValidationAndActorLabelBounds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-input-bounds", "UTC")
	now := time.Now().UTC()
	end := now.Add(3 * time.Hour)
	cases := []struct {
		name     string
		jobID    string
		startAt  time.Time
		endAt    time.Time
		startNow bool
		reason   string
		actor    string
	}{
		{name: "unknown job", jobID: "missing-window-job", startNow: true, endAt: end, reason: "maintenance", actor: "operator"},
		{name: "empty reason", jobID: job.ID, startNow: true, endAt: end, reason: " ", actor: "operator"},
		{name: "oversized reason", jobID: job.ID, startNow: true, endAt: end, reason: strings.Repeat("r", changeWindowReasonMaxBytes+1), actor: "operator"},
		{name: "empty actor label", jobID: job.ID, startNow: true, endAt: end, reason: "maintenance", actor: " "},
		{name: "scheduled start in the past", jobID: job.ID, startAt: now.Add(-time.Hour), endAt: end, reason: "maintenance", actor: "operator"},
		{name: "end not after start", jobID: job.ID, startAt: now.Add(time.Hour), endAt: now.Add(30 * time.Minute), reason: "maintenance", actor: "operator"},
		{name: "end not in the future", jobID: job.ID, startNow: true, endAt: now.Add(-time.Minute), reason: "maintenance", actor: "operator"},
		{name: "wrong explicit timezone offset", jobID: job.ID, startNow: true, endAt: end.In(time.FixedZone("wrong", int(time.Hour/time.Second))), reason: "maintenance", actor: "operator"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := ts.CreateChangeWindow(ctx, test.jobID, test.startAt, test.endAt, test.startNow, test.reason, "actor-id", test.actor)
			if test.name == "unknown job" {
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("create error = %v; want ErrNotFound", err)
				}
			} else if !errors.Is(err, ErrValidation) {
				t.Fatalf("create error = %v; want ErrValidation", err)
			}
		})
	}
	longActor := strings.Repeat("名", changeWindowActorMaxRunes+2)
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, end, true, "maintenance", "actor-id", longActor)
	if err != nil {
		t.Fatal(err)
	}
	if got := len([]rune(window.ActorLabel)); got != changeWindowActorMaxRunes {
		t.Fatalf("stored actor label has %d runes; want bounded to %d", got, changeWindowActorMaxRunes)
	}
}

func TestLatestChangeWindowProjectionKeepsOlderDueReviewVisible(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-projection-review", "UTC")
	createDueWindow := func(scanID string) ChangeWindow {
		t.Helper()
		window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "operator", "Operator")
		if err != nil {
			t.Fatal(err)
		}
		queueWindowTestEvent(t, ctx, s, "destination-"+scanID, job.ID, "changes-detected", scanID, time.Now().UTC(), []model.Change{{Key: "new:" + scanID, Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
		closed, changed, err := ts.CancelChangeWindow(ctx, job.ID, window.ID, "operator", "Operator", nil, AuditEntry{})
		if err != nil || !changed || closed.ReviewState != "due" {
			t.Fatalf("close window for projection: changed %v, state %q, err %v", changed, closed.ReviewState, err)
		}
		return closed
	}
	olderDue := createDueWindow("projection-old")
	newerReviewed := createDueWindow("projection-new")
	if _, err := ts.ReviewChangeWindow(ctx, job.ID, newerReviewed.ID, newerReviewed.Revision, "reviewer", "Reviewer", AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	projection, err := ts.LatestChangeWindowSummaries(ctx, false, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	status, ok := projection[job.ID]
	if !ok || status.ID != olderDue.ID || status.ReviewState != "due" || status.KnownChangeCount != 1 || status.Revision != olderDue.Revision {
		t.Fatalf("job projection = %+v, present %v; want older due window %q and its bounded counts", status, ok, olderDue.ID)
	}
	if err := ts.SetJobArchived(ctx, job.ID, true); err != nil {
		t.Fatal(err)
	}
	activeOnly, err := ts.LatestChangeWindowSummaries(ctx, false, time.Now().UTC())
	if err != nil || len(activeOnly) != 0 {
		t.Fatalf("archived job projection without includeArchived = %+v, %v", activeOnly, err)
	}
	archived, err := ts.LatestChangeWindowSummaries(ctx, true, time.Now().UTC())
	if err != nil || archived[job.ID].ID != olderDue.ID {
		t.Fatalf("archived due review projection = %+v, %v", archived, err)
	}
}

func TestMarshalBoundedChangeWindowSummaryTruncatesDetailsWithoutChangingCounts(t *testing.T) {
	t.Parallel()
	large := strings.Repeat("evidence", 700)
	summary := ChangeWindowSummary{NewCount: 40, RecoveredCount: 5, StillOpenCount: 40, SuppressedEventCount: 2}
	for i := 0; i < 40; i++ {
		change := model.Change{Key: fmt.Sprintf("new:%02d", i), Kind: "port", Severity: "high", Target: large}
		summary.KnownChanges = append(summary.KnownChanges, change)
		summary.StillOpen = append(summary.StillOpen, model.Incident{Change: change, ScanID: "scan-" + large, OpenedAt: time.Now().UTC(), LastSeenAt: time.Now().UTC()})
	}
	raw, err := marshalBoundedChangeWindowSummary(&summary)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || len(raw) > changeWindowSummaryMaxBytes {
		t.Fatalf("serialized summary is %d bytes; bound is %d", len(raw), changeWindowSummaryMaxBytes)
	}
	var decoded ChangeWindowSummary
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.KnownChangeDetailsTruncated || !decoded.StillOpenDetailsTruncated || len(decoded.KnownChanges) >= 40 || len(decoded.StillOpen) >= 40 {
		t.Fatalf("summary details were not explicitly truncated: %+v", decoded)
	}
	if decoded.NewCount != 40 || decoded.RecoveredCount != 5 || decoded.StillOpenCount != 40 || decoded.SuppressedEventCount != 2 {
		t.Fatalf("truncation changed aggregate counts: %+v", decoded)
	}
}

func TestChangeWindowTimestampBoundariesUseFixedWidthUTC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-fraction-boundary", "UTC")
	start := time.Now().UTC().Add(5 * time.Second).Truncate(time.Second)
	end := start.Add(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, end)

	var storedStart, storedEnd string
	if err := s.DB.QueryRowContext(ctx, `SELECT start_at,end_at FROM change_windows WHERE id=?`, window.ID).Scan(&storedStart, &storedEnd); err != nil {
		t.Fatal(err)
	}
	if storedStart != sqliteTimestamp(start) || storedEnd != sqliteTimestamp(end) {
		t.Fatalf("stored interval = %q..%q; want fixed-width %q..%q", storedStart, storedEnd, sqliteTimestamp(start), sqliteTimestamp(end))
	}
	tx, err := beginWriteTx(ctx, s.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if id, active, _, err := windowForQueuedChangeTx(ctx, tx, job.ID, DefaultTenantID, start.Add(time.Nanosecond)); err != nil || !active || id != window.ID {
		t.Fatalf("window lookup at start+1ns = %q, active %v, err %v", id, active, err)
	}
	if id, active, _, err := windowForQueuedChangeTx(ctx, tx, job.ID, DefaultTenantID, end.Add(time.Nanosecond)); err != nil || active || id != "" {
		t.Fatalf("window lookup at end+1ns = %q, active %v, err %v", id, active, err)
	}
	due, err := s.System().DueChangeWindows(ctx, end.Add(time.Nanosecond), 10)
	if err != nil || len(due) != 1 || due[0].ID != window.ID {
		t.Fatalf("due windows at end+1ns = %+v, %v; want the exact-second window", due, err)
	}
}

func TestChangeWindowCloseDedupeBoundsSummaryAndCoalescesAlerts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-summary", "UTC")
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "actor", "Test Operator")
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Now().UTC().Truncate(time.Millisecond)
	changes := make([]model.Change, 25)
	for i := range changes {
		changes[i] = model.Change{Key: fmt.Sprintf("new:%02d", i), Kind: "port", Severity: "high", Target: "192.0.2.10", Port: 8000 + i}
	}
	queueWindowTestEvent(t, context.Background(), s, "changes-destination-a", job.ID, "changes-detected", "scan-new", createdAt, changes, false, 0)
	queueWindowTestEvent(t, context.Background(), s, "changes-destination-b", job.ID, "changes-detected", "scan-new", createdAt, changes, false, 0)
	queueWindowTestEvent(t, context.Background(), s, "recovered-destination", job.ID, "changes-recovered", "scan-recovered", createdAt.Add(time.Second), []model.Change{{Key: "recovered:1", Kind: "port", Target: "192.0.2.10", Port: 8443}}, false, 0)
	queueWindowTestEvent(t, context.Background(), s, "reminder-destination", job.ID, "changes-reminder", "scan-reminder", createdAt.Add(2*time.Second), nil, true, 3)
	if err := s.System().QueueEvent(ctx, "health-destination", model.Event{Type: "health-check", TenantID: DefaultTenantID, Message: "unrelated", CreatedAt: createdAt.Add(3 * time.Second)}); err != nil {
		t.Fatal(err)
	}

	closed, changed, err := ts.CancelChangeWindow(ctx, job.ID, window.ID, "actor", "Test Operator", []string{"summary-destination"}, AuditEntry{})
	if err != nil || !changed {
		t.Fatalf("close active window: changed %v, err %v", changed, err)
	}
	summary := closed.Summary
	if summary == nil {
		t.Fatal("closed window has no summary")
	}
	if summary.NewCount != 25 || summary.RecoveredCount != 1 || summary.SuppressedEventCount != 3 || summary.IncompleteEventCount != 1 || summary.IncompleteReportedChangeCount != 3 {
		t.Fatalf("summary counts = %+v", *summary)
	}
	if len(summary.KnownChanges) != changeWindowDetailLimit+1 || !summary.KnownChangeDetailsTruncated {
		t.Fatalf("known change details = %d, truncated %v; want up to 20 per category and explicit truncation", len(summary.KnownChanges), summary.KnownChangeDetailsTruncated)
	}
	if summary.StillOpenCount != 0 || len(summary.StillOpen) != 0 || summary.StillOpenDetailsTruncated {
		t.Fatalf("still-open summary = %+v", summary)
	}
	var raw []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT summary_json FROM change_windows WHERE id=?`, window.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || len(raw) > changeWindowSummaryMaxBytes {
		t.Fatalf("stored summary size = %d; want 1..%d bytes", len(raw), changeWindowSummaryMaxBytes)
	}
	var decoded ChangeWindowSummary
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.KnownChangeDetailsTruncated != summary.KnownChangeDetailsTruncated || decoded.IncompleteReportedChangeCount != 3 {
		t.Fatalf("stored summary flags/count = %+v", decoded)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE change_window_id=? AND coalesced_at<>''`, window.ID) != 4 {
		t.Fatal("the per-destination change-alert rows were not all coalesced")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, window.ID) != 3 {
		t.Fatal("destination copies were counted as separate events")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_refs WHERE window_id=? AND category='new'`, window.ID) != 25 {
		t.Fatal("unique new change references were not preserved")
	}

	deliveries, err := s.System().ClaimDueDeliveries(ctx, 20, "window-test")
	if err != nil {
		t.Fatal(err)
	}
	seenHealth, seenSummary, seenChanged := false, false, false
	for _, delivery := range deliveries {
		switch delivery.Event.Type {
		case "health-check":
			seenHealth = true
		case "change-window-summary":
			seenSummary = true
		case "changes-detected", "changes-reminder", "changes-recovered":
			seenChanged = true
		}
	}
	if !seenHealth || !seenSummary || seenChanged {
		t.Fatalf("claimed after close: health %v, summary %v, stale change %v; deliveries=%+v", seenHealth, seenSummary, seenChanged, deliveries)
	}
	health, err := ts.ListDeliveryHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"changes-destination-a", "changes-destination-b", "recovered-destination", "reminder-destination"} {
		if item := health[id]; item.Pending != 0 {
			t.Errorf("destination %q counts coalesced alerts as pending: %+v", id, item)
		}
	}
	telemetry, err := ts.Telemetry(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if telemetry.OutboxPending != 2 {
		t.Errorf("tenant outbox pending = %d; want only summary and unrelated alert", telemetry.OutboxPending)
	}
	if _, err := ts.ReviewChangeWindow(ctx, job.ID, window.ID, closed.Revision, "reviewer", "Reviewer", AuditEntry{}); err != nil {
		t.Fatalf("review closing summary: %v", err)
	}
}

func TestDelayedWindowExpiryHoldsOnlyLinkedBacklog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-delayed-expiry", "UTC")
	createdAt := time.Now().UTC().Truncate(time.Millisecond)
	queueWindowTestEvent(t, context.Background(), s, "before-window", job.ID, "changes-detected", "scan-before", createdAt, []model.Change{{Key: "old-change", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "actor", "Test Operator")
	if err != nil {
		t.Fatal(err)
	}
	expiredEnd := time.Now().UTC().Add(-time.Second).Truncate(time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET end_at=? WHERE id=?`, sqliteTimestamp(expiredEnd), window.ID); err != nil {
		t.Fatal(err)
	}
	queueWindowTestEvent(t, context.Background(), s, "after-window", job.ID, "changes-detected", "scan-after", time.Now().UTC(), []model.Change{{Key: "new-change", Kind: "port", Target: "192.0.2.10", Port: 444}}, false, 0)
	deliveries, err := s.System().ClaimDueDeliveries(ctx, 20, "window-delayed")
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 || deliveries[0].Event.ScanID != "scan-after" {
		t.Fatalf("before-expiry claim = %+v; want only the post-end event", deliveries)
	}
	if err := s.System().DeliveryResultClaim(ctx, deliveries[0].ID, deliveries[0].ClaimToken, nil); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return time.Now().UTC() }, []string{"summary-destination"}); err != nil || !changed {
		t.Fatalf("delayed expiry: changed %v, err %v", changed, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE event_job_id=? AND event_type='changes-detected' AND change_window_id=? AND coalesced_at<>''`, job.ID, window.ID) != 1 {
		t.Fatal("linked pre-window alert was not coalesced at expiry")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE event_job_id=? AND event_type='changes-detected' AND change_window_id='' AND sent_at IS NOT NULL`, job.ID) != 1 {
		t.Fatal("post-end event was omitted or attached to the old window")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_refs WHERE window_id=? AND category='new'`, window.ID) != 1 {
		t.Fatal("the closing summary omitted the linked pre-window event")
	}
}

func TestEarlierWindowRebindsPendingAlertFromLaterScheduledWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-earlier-rebind", "UTC")
	queueWindowTestEvent(t, ctx, s, "earlier-rebind-destination", job.ID, "changes-detected", "scan-earlier-rebind", time.Now().UTC(), []model.Change{{Key: "earlier-rebind-change", Kind: "port", Target: "192.0.2.14", Port: 443}}, false, 0)
	now := time.Now().UTC()
	later := createTestChangeWindow(t, ts, job.ID, now.Add(2*time.Hour), now.Add(3*time.Hour))
	var outboxID int64
	var linked string
	if err := s.DB.QueryRowContext(ctx, `SELECT id,change_window_id FROM outbox WHERE destination=? AND event_type='changes-detected'`, "earlier-rebind-destination").Scan(&outboxID, &linked); err != nil || linked != later.ID {
		t.Fatalf("initial future-window link = %q, %v; want %q", linked, err, later.ID)
	}
	earlier, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "earlier maintenance", "test-actor", "Test Operator")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id FROM outbox WHERE id=?`, outboxID).Scan(&linked); err != nil || linked != earlier.ID {
		t.Fatalf("pending alert after earlier window creation = %q, %v; want %q", linked, err, earlier.ID)
	}
	claimed, err := s.System().ClaimDueDeliveries(ctx, 10, "earlier-window-rebind")
	if err != nil || len(claimed) != 0 {
		t.Fatalf("claim during earlier active window = %+v, %v; want the alert held", claimed, err)
	}
	closedAt := earlier.EndAt.Add(time.Second)
	summary, changed, err := ts.ExpireChangeWindow(ctx, earlier.ID, func() time.Time { return closedAt }, []string{"earlier-window-summary"})
	if err != nil || !changed || summary.SuppressedEventCount != 1 {
		t.Fatalf("close earlier window = %+v, changed %v, err %v; want its pending alert in the summary", summary, changed, err)
	}
	var coalesced string
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,coalesced_at FROM outbox WHERE id=?`, outboxID).Scan(&linked, &coalesced); err != nil || linked != earlier.ID || coalesced == "" {
		t.Fatalf("closed earlier-window alert = link %q coalesced %q err %v", linked, coalesced, err)
	}
}

func TestEarlierWindowDoesNotRebindStartedLaterWindowAlert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-earlier-rebind-started", "UTC")
	queueWindowTestEvent(t, ctx, s, "earlier-rebind-started-destination", job.ID, "changes-detected", "scan-earlier-rebind-started", time.Now().UTC(), []model.Change{{Key: "earlier-rebind-started-change", Kind: "port", Target: "192.0.2.17", Port: 443}}, false, 0)
	now := time.Now().UTC()
	later := createTestChangeWindow(t, ts, job.ID, now.Add(2*time.Hour), now.Add(3*time.Hour))
	var outboxID int64
	var linked, claim, startedAt string
	if err := s.DB.QueryRowContext(ctx, `SELECT id,change_window_id FROM outbox WHERE destination=? AND event_type='changes-detected'`, "earlier-rebind-started-destination").Scan(&outboxID, &linked); err != nil || linked != later.ID {
		t.Fatalf("initial future-window link = %q, %v; want %q", linked, err, later.ID)
	}
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "earlier-window-rebind-started")
	if err != nil || len(claimed) != 1 || claimed[0].ID != outboxID {
		t.Fatalf("claim before the later window = %+v, %v; want its alert", claimed, err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, outboxID, claimed[0].ClaimToken); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "earlier maintenance", "test-actor", "Test Operator"); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id,claim_token,attempt_started_at FROM outbox WHERE id=?`, outboxID).Scan(&linked, &claim, &startedAt); err != nil {
		t.Fatal(err)
	}
	if linked != later.ID || claim != claimed[0].ClaimToken || startedAt == "" {
		t.Fatalf("in-flight later-window alert changed to link=%q claim=%q marker=%q; want later link and original fenced attempt", linked, claim, startedAt)
	}
}

func TestCancelEarlierWindowRestoresLaterLinkForInFlightReview(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-cancel-earlier-rebind", "UTC")
	queueWindowTestEvent(t, ctx, s, "cancel-earlier-rebind-destination", job.ID, "changes-detected", "scan-cancel-earlier-rebind", time.Now().UTC(), []model.Change{{Key: "cancel-earlier-rebind-change", Kind: "port", Target: "192.0.2.16", Port: 443}}, false, 0)
	now := time.Now().UTC().Truncate(time.Second)
	later := createTestChangeWindow(t, ts, job.ID, now.Add(4*time.Hour), now.Add(5*time.Hour))
	earlier := createTestChangeWindow(t, ts, job.ID, now.Add(2*time.Hour), now.Add(3*time.Hour))
	var outboxID int64
	var linked string
	if err := s.DB.QueryRowContext(ctx, `SELECT id,change_window_id FROM outbox WHERE destination=? AND event_type='changes-detected'`, "cancel-earlier-rebind-destination").Scan(&outboxID, &linked); err != nil || linked != earlier.ID {
		t.Fatalf("initial earlier-window link = %q, %v; want %q", linked, err, earlier.ID)
	}
	if cancelled, changed, err := ts.CancelChangeWindow(ctx, job.ID, earlier.ID, "test-actor", "Test Operator", nil, AuditEntry{}); err != nil || !changed || cancelled.Status != "cancelled" {
		t.Fatalf("cancel earlier scheduled window = %+v, changed %v, err %v", cancelled, changed, err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT change_window_id FROM outbox WHERE id=?`, outboxID).Scan(&linked); err != nil || linked != later.ID {
		t.Fatalf("pending row after earlier-window cancellation = %q, %v; want later window %q restored", linked, err, later.ID)
	}
	claimed, err := s.System().ClaimDueDeliveries(ctx, 1, "cancel-earlier-window-worker")
	if err != nil || len(claimed) != 1 || claimed[0].ID != outboxID {
		t.Fatalf("claim before restored window = %+v, %v; want the linked alert", claimed, err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, outboxID, claimed[0].ClaimToken); err != nil {
		t.Fatalf("begin attempt before restored window: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET claim_until=? WHERE id=?`, later.EndAt.Add(time.Hour).Format(time.RFC3339Nano), outboxID); err != nil {
		t.Fatal(err)
	}
	summary, changed, err := ts.ExpireChangeWindow(ctx, later.ID, func() time.Time { return later.EndAt.Add(time.Second) }, nil)
	if err != nil || !changed || summary.InFlightEventCount != 1 {
		t.Fatalf("close restored later window = %+v, changed %v, err %v; want the started delivery included as in flight", summary, changed, err)
	}
	if err := s.System().DeliveryResultClaim(ctx, outboxID, claimed[0].ClaimToken, ErrDeliveryProviderTimeout); err != nil {
		t.Fatalf("record late failed provider result: %v", err)
	}
	var sentAt, coalesced, claim, started, lastError string
	var attempts, deferrals, coalesceAfter int
	if err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(sent_at,''),coalesced_at,claim_token,attempt_started_at,last_error,attempts,deferrals,coalesce_after_attempt FROM outbox WHERE id=?`, outboxID).Scan(&sentAt, &coalesced, &claim, &started, &lastError, &attempts, &deferrals, &coalesceAfter); err != nil {
		t.Fatal(err)
	}
	if sentAt != "" || coalesced == "" || claim != "" || started != "" || lastError != "" || attempts != 0 || deferrals != 0 || coalesceAfter != 0 {
		t.Fatalf("late result after restored-window close = sent %q coalesced %q claim %q marker %q error %q attempts %d deferrals %d coalesce-after %d", sentAt, coalesced, claim, started, lastError, attempts, deferrals, coalesceAfter)
	}
	var failures int
	var lastFailure string
	if err := s.DB.QueryRowContext(ctx, `SELECT terminal_failures,last_failure_at FROM notification_delivery_health WHERE destination_identity=?`, "cancel-earlier-rebind-destination").Scan(&failures, &lastFailure); err != nil {
		t.Fatal(err)
	}
	if failures != 0 || lastFailure != "" {
		t.Fatalf("coalesced late failure changed destination health: failures %d, last failure %q", failures, lastFailure)
	}
}

func TestStartedBeforeFutureWindowDoesNotCountAsSuppressedAndFailureCoalesces(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-claim-gate", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "claim-destination", job.ID, "changes-detected", "scan-claim", time.Now().UTC(), []model.Change{{Key: "claim-change", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	deliveries, err := s.System().ClaimDueDeliveries(ctx, 10, "window-claim")
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim before future window = %d deliveries, %v", len(deliveries), err)
	}
	delivery := deliveries[0]
	if err := s.System().BeginDeliveryAttempt(ctx, delivery.ID, delivery.ClaimToken); err != nil {
		t.Fatalf("start before window: %v", err)
	}
	// Advance the expiry clock beyond the future window while preserving its
	// actual start boundary. The application-invocation marker predates start,
	// and extend the synthetic lease so it is still live at that boundary.
	closedAt := window.EndAt.Add(time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET claim_until=? WHERE id=?`, closedAt.Add(time.Minute).Format(time.RFC3339Nano), delivery.ID); err != nil {
		t.Fatal(err)
	}
	summary, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return closedAt }, []string{"claim-destination"})
	if err != nil || !changed || summary.SuppressedEventCount != 0 || summary.InFlightEventCount != 1 {
		t.Fatalf("close after pre-window attempt = %+v, changed %v, err %v", summary, changed, err)
	}
	closed, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || closed.ReviewState != "due" || closed.Summary == nil || closed.InFlightEventCount != 1 || closed.UnknownOutcomeEventCount != 0 || closed.Summary.InFlightEventCount != 1 {
		t.Fatalf("window closed after pre-window attempt = %+v, err %v", closed, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=? AND disposition='in_flight'`, window.ID) != 1 {
		t.Fatal("window did not retain its already-in-flight event evidence")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE id=? AND coalesce_after_attempt=1 AND attempt_started_at<>''`, delivery.ID) != 1 {
		t.Fatal("close did not distinguish a started provider handoff from a claim")
	}
	if err := s.System().DeliveryResultClaim(ctx, delivery.ID, delivery.ClaimToken, ErrDeliveryProviderTimeout); err != nil {
		t.Fatalf("record started attempt outcome after close: %v", err)
	}
	var attempts, deferrals int
	var coalesced, claim, started string
	if err := s.DB.QueryRowContext(ctx, `SELECT attempts,deferrals,coalesced_at,claim_token,attempt_started_at FROM outbox WHERE id=?`, delivery.ID).Scan(&attempts, &deferrals, &coalesced, &claim, &started); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || deferrals != 0 || coalesced == "" || claim != "" || started != "" {
		t.Fatalf("post-close failed attempt row = attempts %d, deferrals %d, coalesced %q, claim %q, started %q", attempts, deferrals, coalesced, claim, started)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE event_type IN ('changes-detected','changes-reminder','changes-recovered') AND coalesced_at='' AND sent_at IS NULL AND terminal_at=''`) != 0 {
		t.Fatal("a late in-flight failure remained eligible for individual alert retry")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE event_type='change-window-summary' AND sent_at IS NULL AND terminal_at=''`) != 1 {
		t.Fatal("the durable in-flight review summary was not queued")
	}
}

func TestStartedBeforeFutureWindowRecoveryClearsMarkerAndRetries(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-recovered-inflight", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "recovery-destination", job.ID, "changes-detected", "scan-recovery", time.Now().UTC(), []model.Change{{Key: "recovery-change", Kind: "port", Target: "192.0.2.11", Port: 443}}, false, 0)
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	deliveries, err := s.System().ClaimDueDeliveries(ctx, 10, "pre-window-worker")
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim before window = %d deliveries, %v", len(deliveries), err)
	}
	item := deliveries[0]
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
		t.Fatalf("begin pre-window provider attempt: %v", err)
	}
	if released, err := s.System().ReleaseDeliveryClaims(ctx); err != nil || released != 1 {
		t.Fatalf("recover pre-window attempt = %d released, %v", released, err)
	}
	var claim, startedAt string
	if err := s.DB.QueryRowContext(ctx, `SELECT claim_token,attempt_started_at FROM outbox WHERE id=?`, item.ID).Scan(&claim, &startedAt); err != nil {
		t.Fatal(err)
	}
	if claim != "" || startedAt != "" {
		t.Fatalf("recovered pre-start attempt marker = %q, claim = %q; want cleared marker and released claim", startedAt, claim)
	}
	deliveries, err = s.System().ClaimDueDeliveries(ctx, 10, "pre-start-retry-worker")
	if err != nil || len(deliveries) != 1 || deliveries[0].ID != item.ID {
		t.Fatalf("recovered pre-start attempt was not retryable: %+v, %v", deliveries, err)
	}
	if deliveries[0].ClaimToken == "" || window.ID == "" {
		t.Fatalf("retry claim/window identity = %q/%q", deliveries[0].ClaimToken, window.ID)
	}
}

func TestStartedAttemptInActiveWindowRecoveryPreservesUncertaintyUntilClose(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-active-recovered-inflight", "UTC")
	queueWindowTestEvent(t, ctx, s, "active-recovery-destination", job.ID, "changes-detected", "scan-active-recovery", time.Now().UTC(), []model.Change{{Key: "active-recovery-change", Kind: "port", Target: "192.0.2.13", Port: 443}}, false, 0)
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	deliveries, err := s.System().ClaimDueDeliveries(ctx, 10, "active-pre-window-worker")
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim before active window setup = %d deliveries, %v", len(deliveries), err)
	}
	item := deliveries[0]
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
		t.Fatalf("begin provider attempt: %v", err)
	}
	// Advance only the fixture's start boundary; no code under test receives a
	// synthetic clock, so this puts the row in the genuine active-window path.
	activeStart := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=?,status='active' WHERE id=?`, sqliteTimestamp(activeStart), window.ID); err != nil {
		t.Fatal(err)
	}
	if released, err := s.System().ReleaseDeliveryClaims(ctx); err != nil || released != 1 {
		t.Fatalf("recover active-window attempt = %d released, %v", released, err)
	}
	var claim, startedAt string
	if err := s.DB.QueryRowContext(ctx, `SELECT claim_token,attempt_started_at FROM outbox WHERE id=?`, item.ID).Scan(&claim, &startedAt); err != nil {
		t.Fatal(err)
	}
	if claim != "" || startedAt == "" {
		t.Fatalf("active-window recovery marker = %q, claim = %q; want uncertainty marker retained and claim released", startedAt, claim)
	}
	if deliveries, err := s.System().ClaimDueDeliveries(ctx, 10, "active-replay-worker"); err != nil || len(deliveries) != 0 {
		t.Fatalf("active-window uncertain attempt was replayed: %+v, %v", deliveries, err)
	}
	closedAt := window.EndAt.Add(time.Second)
	summary, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return closedAt }, []string{"active-recovery-destination"})
	if err != nil || !changed || summary.UnknownOutcomeEventCount != 1 || summary.InFlightEventCount != 0 || summary.SuppressedEventCount != 0 {
		t.Fatalf("close after recovered active-window attempt = %+v, changed %v, err %v", summary, changed, err)
	}
	closed, err := ts.GetChangeWindow(ctx, job.ID, window.ID)
	if err != nil || closed.ReviewState != "due" || closed.Summary == nil || closed.Summary.UnknownOutcomeEventCount != 1 || closed.InFlightEventCount != 0 || closed.UnknownOutcomeEventCount != 1 {
		t.Fatalf("recovered active attempt close review = %+v, err %v", closed, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=? AND disposition='unknown_outcome'`, window.ID) != 1 {
		t.Fatal("window did not retain active provider-attempt uncertainty as separate evidence")
	}
	var coalesced, marker, claimAfter string
	if err := s.DB.QueryRowContext(ctx, `SELECT coalesced_at,attempt_started_at,claim_token FROM outbox WHERE id=?`, item.ID).Scan(&coalesced, &marker, &claimAfter); err != nil {
		t.Fatal(err)
	}
	if coalesced == "" || marker != "" || claimAfter != "" {
		t.Fatalf("closed active attempt state = coalesced %q marker %q claim %q", coalesced, marker, claimAfter)
	}
}

func TestLateIndeterminateOutcomeAfterWindowCloseCoalescesWithoutHealthPenalty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-late-indeterminate", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "indeterminate-destination", job.ID, "changes-detected", "scan-indeterminate", time.Now().UTC(), []model.Change{{Key: "indeterminate-change", Kind: "port", Target: "192.0.2.12", Port: 443}}, false, 0)
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	deliveries, err := s.System().ClaimDueDeliveries(ctx, 10, "indeterminate-worker")
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim before window = %d deliveries, %v", len(deliveries), err)
	}
	item := deliveries[0]
	if err := s.System().BeginDeliveryAttempt(ctx, item.ID, item.ClaimToken); err != nil {
		t.Fatal(err)
	}
	closedAt := window.EndAt.Add(time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET claim_until=? WHERE id=?`, closedAt.Add(time.Minute).Format(time.RFC3339Nano), item.ID); err != nil {
		t.Fatal(err)
	}
	if summary, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return closedAt }, []string{"indeterminate-destination"}); err != nil || !changed || summary.InFlightEventCount != 1 {
		t.Fatalf("close with pending provider attempt = %+v, changed %v, err %v", summary, changed, err)
	}
	if err := s.System().DeferDeliveryWithError(ctx, item.ID, item.ClaimToken, ErrDeliveryIndeterminate, 30*time.Minute); err != nil {
		t.Fatalf("record indeterminate late outcome: %v", err)
	}
	var attempts, deferrals int
	var coalesced, claim, started string
	if err := s.DB.QueryRowContext(ctx, `SELECT attempts,deferrals,coalesced_at,claim_token,attempt_started_at FROM outbox WHERE id=?`, item.ID).Scan(&attempts, &deferrals, &coalesced, &claim, &started); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || deferrals != 0 || coalesced == "" || claim != "" || started != "" {
		t.Fatalf("late indeterminate row = attempts %d deferrals %d coalesced %q claim %q marker %q", attempts, deferrals, coalesced, claim, started)
	}
	if failures := countRows(t, s.DB, `SELECT COUNT(*) FROM notification_delivery_health WHERE last_failure_at<>'' OR terminal_failures>0 OR last_error_code<>''`); failures != 0 {
		t.Fatalf("late indeterminate outcome recorded %d destination health failures", failures)
	}
}

func TestExpireChangeWindowSamplesClockAfterWriterAndIsIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-expiry-clock", "UTC")
	window := createTestChangeWindow(t, ts, job.ID, time.Now().UTC().Add(time.Hour), time.Now().UTC().Add(2*time.Hour))
	end := time.Now().UTC().Add(-time.Second).Truncate(time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET end_at=? WHERE id=?`, sqliteTimestamp(end), window.ID); err != nil {
		t.Fatal(err)
	}
	lock, err := beginWriteTx(ctx, s.DB)
	if err != nil {
		t.Fatal(err)
	}
	clockCalled := make(chan time.Time, 1)
	done := make(chan error, 1)
	go func() {
		_, _, expireErr := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time {
			sample := time.Now().UTC()
			clockCalled <- sample
			return sample
		}, nil)
		done <- expireErr
	}()
	select {
	case sample := <-clockCalled:
		t.Fatalf("expiry sampled its clock before acquiring the writer: %s", sample)
	case <-time.After(50 * time.Millisecond):
	}
	if err := lock.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case sample := <-clockCalled:
		if sample.Before(end) {
			t.Fatalf("expiry clock sample %s precedes the stored end %s", sample, end)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expiry never sampled its clock after the writer was released")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return time.Now().UTC() }, nil); err != nil || changed {
		t.Fatalf("idempotent expiry = changed %v, err %v", changed, err)
	}
}

func TestDeliveryResultAfterExactSecondWindowEndKeepsRetryTimestampFormat(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-retry-timestamp", "UTC")
	queueWindowTestEvent(t, context.Background(), s, "retry-destination", job.ID, "changes-detected", "scan-retry", time.Now().UTC(), []model.Change{{Key: "retry-change", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	window := createTestChangeWindow(t, ts, job.ID, start, start.Add(time.Hour))
	deliveries, err := s.System().ClaimDueDeliveries(ctx, 10, "window-retry")
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim before future window = %d deliveries, %v", len(deliveries), err)
	}
	if err := s.System().BeginDeliveryAttempt(ctx, deliveries[0].ID, deliveries[0].ClaimToken); err != nil {
		t.Fatal(err)
	}
	exactEnd := time.Now().UTC().Add(-time.Second).Truncate(time.Second)
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET end_at=? WHERE id=?`, sqliteTimestamp(exactEnd), window.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.System().DeliveryResultClaim(ctx, deliveries[0].ID, deliveries[0].ClaimToken, ErrDeliveryProviderTimeout); err != nil {
		t.Fatal(err)
	}
	var next string
	if err := s.DB.QueryRowContext(ctx, `SELECT next_at FROM outbox WHERE id=?`, deliveries[0].ID).Scan(&next); err != nil {
		t.Fatal(err)
	}
	if next != exactEnd.Format(time.RFC3339Nano) {
		t.Fatalf("held row next_at = %q; want outbox-format %q", next, exactEnd.Format(time.RFC3339Nano))
	}
}

func TestChangeWindowRetentionPreservesDueAndScheduledAndDeletesClosedHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	cutoff := time.Now().UTC().Add(time.Hour)
	old := sqliteTimestamp(cutoff.Add(-48 * time.Hour))

	dueJob := createWindowTestJob(t, ts, "window-retention-due", "UTC")
	due, err := ts.CreateChangeWindow(ctx, dueJob.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "retained review", "actor", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	queueWindowTestEvent(t, context.Background(), s, "retention-due", dueJob.ID, "changes-detected", "scan-retention-due", time.Now().UTC(), []model.Change{{Key: "due-change", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	due, changed, err := ts.CancelChangeWindow(ctx, dueJob.ID, due.ID, "actor", "Operator", nil, AuditEntry{})
	if err != nil || !changed || due.ReviewState != "due" {
		t.Fatalf("close due-review window = %+v, changed %v, err %v", due, changed, err)
	}

	reviewedJob := createWindowTestJob(t, ts, "window-retention-reviewed", "UTC")
	reviewed, err := ts.CreateChangeWindow(ctx, reviewedJob.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "expired review", "actor", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	queueWindowTestEvent(t, context.Background(), s, "retention-reviewed", reviewedJob.ID, "changes-detected", "scan-retention-reviewed", time.Now().UTC(), []model.Change{{Key: "reviewed-change", Kind: "port", Target: "192.0.2.10", Port: 8443}}, false, 0)
	reviewed, changed, err = ts.CancelChangeWindow(ctx, reviewedJob.ID, reviewed.ID, "actor", "Operator", nil, AuditEntry{})
	if err != nil || !changed || reviewed.ReviewState != "due" {
		t.Fatalf("close reviewed-history window = %+v, changed %v, err %v", reviewed, changed, err)
	}
	if reviewed, err = ts.ReviewChangeWindow(ctx, reviewedJob.ID, reviewed.ID, reviewed.Revision, "reviewer", "Reviewer", AuditEntry{}); err != nil || reviewed.ReviewState != "reviewed" {
		t.Fatalf("review history window = %+v, %v", reviewed, err)
	}

	scheduledJob := createWindowTestJob(t, ts, "window-retention-scheduled", "UTC")
	scheduledStart := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	scheduled := createTestChangeWindow(t, ts, scheduledJob.ID, scheduledStart, scheduledStart.Add(time.Hour))

	cancelledJob := createWindowTestJob(t, ts, "window-retention-cancelled", "UTC")
	cancelledStart := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	cancelled := createTestChangeWindow(t, ts, cancelledJob.ID, cancelledStart, cancelledStart.Add(time.Hour))
	if _, changed, err := ts.CancelChangeWindow(ctx, cancelledJob.ID, cancelled.ID, "actor", "Operator", nil, AuditEntry{}); err != nil || !changed {
		t.Fatalf("cancel retained-history candidate: changed %v, err %v", changed, err)
	}

	// Age the closed rows past retention while leaving their durable summaries
	// and evidence untouched. The due review remains protected, and the
	// scheduled window has no close timestamp to qualify for deletion.
	for _, id := range []string{due.ID, reviewed.ID, cancelled.ID} {
		if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET closed_at=? WHERE id=?`, old, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := assertSameOutboxAssociationBeforePrune(t, s, reviewed.ID); err != nil {
		t.Fatal(err)
	}
	stats, err := s.System().PruneWithStats(ctx, cutoff)
	if err != nil {
		t.Fatalf("prune change window history: %v", err)
	}
	if stats.ChangeWindows != 2 || stats.ChangeWindowEvents < 1 || stats.ChangeWindowRefs < 1 {
		t.Fatalf("change window retention stats = %+v; want two closed parents and their bounded child evidence removed", stats)
	}
	for _, check := range []struct {
		id   string
		want int
	}{{due.ID, 1}, {reviewed.ID, 0}, {scheduled.ID, 1}, {cancelled.ID, 0}} {
		if got := countRows(t, s.DB, `SELECT COUNT(*) FROM change_windows WHERE id=?`, check.id); got != check.want {
			t.Errorf("window %s rows = %d, want %d", check.id, got, check.want)
		}
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_refs WHERE window_id=?`, due.ID) != 1 || countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, due.ID) != 1 {
		t.Fatal("retention removed evidence for an unreviewed due window")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE change_window_id=?`, reviewed.ID) != 0 {
		t.Fatal("retention left an outbox pointer to a deleted window")
	}
	if violations := countRows(t, s.DB, `SELECT COUNT(*) FROM pragma_foreign_key_check`); violations != 0 {
		t.Fatalf("foreign-key violations after window retention = %d", violations)
	}
}

func assertSameOutboxAssociationBeforePrune(t *testing.T, s *Store, windowID string) error {
	t.Helper()
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE change_window_id=? AND coalesced_at<>''`, windowID); got == 0 {
		return fmt.Errorf("window %s has no coalesced outbox row to exercise retention cleanup", windowID)
	}
	return nil
}
