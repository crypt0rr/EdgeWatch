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
	return createWindowTestJobWithContext(context.Background(), t, ts, name, timezone)
}

func createWindowTestJobWithContext(ctx context.Context, t *testing.T, ts *TenantStore, name, timezone string) JobRecord {
	t.Helper()
	job := config.NormalizeJob(config.Job{
		Name: name, Schedule: "0 * * * *", Timezone: timezone,
		Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"},
	})
	record, err := ts.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func createTestChangeWindow(t *testing.T, ts *TenantStore, jobID string, start, end time.Time) ChangeWindow {
	return createTestChangeWindowWithContext(context.Background(), t, ts, jobID, start, end)
}

func createTestChangeWindowWithContext(ctx context.Context, t *testing.T, ts *TenantStore, jobID string, start, end time.Time) ChangeWindow {
	t.Helper()
	window, err := ts.CreateChangeWindow(ctx, jobID, start, end, false, "maintenance", "test-actor", "Test Operator")
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

func TestLatestChangeWindowSummariesMatchesPriorWinnerOrdering(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	activeJob := createWindowTestJob(t, ts, "projection-equivalence-active", "UTC")
	expiredJob := createWindowTestJob(t, ts, "projection-equivalence-expired", "UTC")
	scheduledJob := createWindowTestJob(t, ts, "projection-equivalence-scheduled", "UTC")
	dueJob := createWindowTestJob(t, ts, "projection-equivalence-due", "UTC")
	archivedJob := createWindowTestJob(t, ts, "projection-equivalence-archived", "UTC")
	insertSecondTenant(t, s)
	const otherTenantJobID = "projection-equivalence-other-tenant"
	insertSecondTenantJob(t, s, scheduledJob.ID, otherTenantJobID)
	if err := ts.SetJobArchived(ctx, archivedJob.ID, true); err != nil {
		t.Fatal(err)
	}

	insert := func(jobID, id string, start, end time.Time, closedAt, reviewState string) {
		t.Helper()
		status, endReason := "active", ""
		if closedAt != "" {
			status, endReason = "closed", "expired"
		} else if start.After(now) {
			status = "scheduled"
		}
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO change_windows(id,job_id,start_at,end_at,timezone,reason,actor_label,created_at,status,end_reason,closed_at,review_state) VALUES (?,?,?,?,'UTC','projection fixture','Operator',?,?,?,?,?)`, id, jobID, sqliteTimestamp(start), sqliteTimestamp(end), sqliteTimestamp(now), status, endReason, closedAt, reviewState); err != nil {
			t.Fatalf("insert window %s: %v", id, err)
		}
	}
	closed := func(at time.Time) string { return sqliteTimestamp(at) }
	insert(activeJob.ID, "active-winner", now.Add(-time.Minute), now.Add(time.Hour), "", "none")
	insert(activeJob.ID, "expired-loser", now.Add(-3*time.Hour), now.Add(-2*time.Hour), "", "none")
	insert(activeJob.ID, "scheduled-loser", now.Add(time.Hour), now.Add(2*time.Hour), "", "none")
	insert(activeJob.ID, "due-loser", now.Add(-4*time.Hour), now.Add(-3*time.Hour), closed(now.Add(-3*time.Hour)), "due")
	insert(expiredJob.ID, "expired-winner", now.Add(-3*time.Hour), now.Add(-2*time.Hour), "", "none")
	insert(expiredJob.ID, "scheduled-loser-2", now.Add(time.Hour), now.Add(2*time.Hour), "", "none")
	insert(expiredJob.ID, "due-loser-2", now.Add(-4*time.Hour), now.Add(-3*time.Hour), closed(now.Add(-3*time.Hour)), "due")
	insert(scheduledJob.ID, "scheduled-far", now.Add(3*time.Hour), now.Add(4*time.Hour), "", "none")
	insert(scheduledJob.ID, "scheduled-near", now.Add(time.Hour), now.Add(2*time.Hour), "", "none")
	insert(scheduledJob.ID, "due-loser-3", now.Add(-4*time.Hour), now.Add(-3*time.Hour), closed(now.Add(-3*time.Hour)), "due")
	tieStart := now.Add(-6 * time.Hour)
	insert(dueJob.ID, "due-tie-a", tieStart, tieStart.Add(time.Minute), closed(tieStart.Add(time.Minute)), "due")
	insert(dueJob.ID, "due-tie-z", tieStart, tieStart.Add(time.Minute), closed(tieStart.Add(time.Minute)), "due")
	insert(dueJob.ID, "reviewed-newer", now.Add(-time.Hour), now.Add(-time.Minute), closed(now), "reviewed")
	insert(archivedJob.ID, "archived-scheduled", now.Add(time.Hour), now.Add(2*time.Hour), "", "none")
	insert(otherTenantJobID, "other-tenant-window", now.Add(time.Hour), now.Add(2*time.Hour), "", "none")

	// Keep the old scalar-subquery implementation as a test oracle so this
	// fixture proves the ranked query preserves the complete winner ordering.
	legacyWinnerIDs := func(scope TenantScope, includeArchived bool) map[string]string {
		t.Helper()
		rows, err := s.DB.QueryContext(ctx, `SELECT w.job_id,w.id
FROM change_windows AS w JOIN jobs AS j ON j.id=w.job_id AND j.tenant_id=?1
WHERE (?2 OR j.archived=0) AND (w.closed_at='' OR w.review_state='due')
	AND w.id=(SELECT candidate.id FROM change_windows AS candidate
		WHERE candidate.job_id=w.job_id AND (candidate.closed_at='' OR candidate.review_state='due')
		ORDER BY CASE WHEN candidate.closed_at='' AND candidate.start_at<=?3 AND candidate.end_at>?3 THEN 0 WHEN candidate.closed_at='' AND candidate.end_at<=?3 THEN 1 WHEN candidate.closed_at='' THEN 2 ELSE 3 END,
			CASE WHEN candidate.closed_at='' AND candidate.start_at>?3 THEN candidate.start_at END ASC,candidate.start_at DESC,candidate.id DESC LIMIT 1)
ORDER BY w.job_id`, scope.ID(), boolInt(includeArchived), sqliteTimestamp(now))
		if err != nil {
			t.Fatalf("run prior projection query for tenant %s: %v", scope.ID(), err)
		}
		defer rows.Close()
		winners := make(map[string]string)
		for rows.Next() {
			var jobID, windowID string
			if err := rows.Scan(&jobID, &windowID); err != nil {
				t.Fatalf("scan prior projection query: %v", err)
			}
			winners[jobID] = windowID
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("read prior projection query: %v", err)
		}
		return winners
	}

	for _, includeArchived := range []bool{false, true} {
		got, err := ts.LatestChangeWindowSummaries(ctx, includeArchived, now)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{
			activeJob.ID:    "active-winner",
			expiredJob.ID:   "expired-winner",
			scheduledJob.ID: "scheduled-near",
			dueJob.ID:       "due-tie-z",
		}
		if includeArchived {
			want[archivedJob.ID] = "archived-scheduled"
		}
		if len(got) != len(want) {
			t.Fatalf("includeArchived=%v projection has %d jobs, want %d: %+v", includeArchived, len(got), len(want), got)
		}
		for jobID, id := range want {
			if got[jobID].ID != id {
				t.Errorf("includeArchived=%v winner for job %s = %q, want %q", includeArchived, jobID, got[jobID].ID, id)
			}
		}
		legacy := legacyWinnerIDs(ts.scope, includeArchived)
		if len(legacy) != len(got) {
			t.Errorf("includeArchived=%v ranked projection has %d jobs, prior query has %d: ranked=%+v prior=%+v", includeArchived, len(got), len(legacy), got, legacy)
		}
		for jobID, item := range got {
			if legacy[jobID] != item.ID {
				t.Errorf("includeArchived=%v winner for job %s = %q, prior query chose %q", includeArchived, jobID, item.ID, legacy[jobID])
			}
		}
	}
	otherTenant := s.Tenant(TenantScope{id: secondTenantID})
	otherGot, err := otherTenant.LatestChangeWindowSummaries(ctx, false, now)
	if err != nil {
		t.Fatal(err)
	}
	otherLegacy := legacyWinnerIDs(TenantScope{id: secondTenantID}, false)
	if len(otherGot) != 1 || otherGot[otherTenantJobID].ID != "other-tenant-window" || len(otherLegacy) != len(otherGot) || otherLegacy[otherTenantJobID] != otherGot[otherTenantJobID].ID {
		t.Fatalf("other tenant projection = %+v; prior query = %+v", otherGot, otherLegacy)
	}

	plan := queryPlan(t, s.DB, latestChangeWindowSummariesQuery, ts.scope.id, 0, sqliteTimestamp(now))
	if strings.Contains(strings.ToUpper(plan), "CORRELATED SCALAR SUBQUERY") {
		t.Fatalf("latest change-window projection still performs a correlated lookup: %s", plan)
	}
}

func TestLatestChangeWindowSummariesPrioritizeActiveThenExpiredThenNearestScheduled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	now := time.Now().UTC().Truncate(time.Second)
	end := now.Add(time.Hour)

	activeJob := createWindowTestJob(t, ts, "window-rank-active", "UTC")
	active, err := ts.CreateChangeWindow(ctx, activeJob.ID, time.Time{}, end, true, "maintenance", "test-actor", "Test Operator")
	if err != nil {
		t.Fatal(err)
	}
	createTestChangeWindow(t, ts, activeJob.ID, now.Add(2*time.Hour), now.Add(3*time.Hour))
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=?,end_at=? WHERE id=?`, sqliteTimestamp(now), sqliteTimestamp(end), active.ID); err != nil {
		t.Fatal(err)
	}

	expiredJob := createWindowTestJob(t, ts, "window-rank-expired", "UTC")
	expired, err := ts.CreateChangeWindow(ctx, expiredJob.ID, time.Time{}, now.Add(2*time.Hour), true, "maintenance", "test-actor", "Test Operator")
	if err != nil {
		t.Fatal(err)
	}
	createTestChangeWindow(t, ts, expiredJob.ID, now.Add(4*time.Hour), now.Add(5*time.Hour))
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=?,end_at=? WHERE id=?`, sqliteTimestamp(now.Add(-time.Hour)), sqliteTimestamp(now), expired.ID); err != nil {
		t.Fatal(err)
	}

	scheduledJob := createWindowTestJob(t, ts, "window-rank-scheduled", "UTC")
	nearOnly := createTestChangeWindow(t, ts, scheduledJob.ID, now.Add(2*time.Hour), now.Add(3*time.Hour))
	createTestChangeWindow(t, ts, scheduledJob.ID, now.Add(4*time.Hour), now.Add(5*time.Hour))

	dueJob := createWindowTestJob(t, ts, "window-rank-due", "UTC")
	due, err := ts.CreateChangeWindow(ctx, dueJob.ID, time.Time{}, now.Add(2*time.Hour), true, "maintenance", "test-actor", "Test Operator")
	if err != nil {
		t.Fatal(err)
	}
	queueWindowTestEvent(t, ctx, s, "window-rank-due-destination", dueJob.ID, "changes-detected", "window-rank-due-scan", now, []model.Change{{Key: "new:window-rank-due", Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	closedDue, changed, err := ts.CancelChangeWindow(ctx, dueJob.ID, due.ID, "operator", "Operator", nil, AuditEntry{})
	if err != nil || !changed || closedDue.ReviewState != "due" {
		t.Fatalf("close due-review fixture: changed %v, state %q, err %v", changed, closedDue.ReviewState, err)
	}
	dueScheduled := createTestChangeWindow(t, ts, dueJob.ID, now.Add(2*time.Hour), now.Add(3*time.Hour))

	tieJob := createWindowTestJob(t, ts, "window-rank-tie", "UTC")
	firstDue := makeDueWindowForProjectionTest(t, ctx, s, ts, tieJob.ID, "window-rank-tie-first")
	secondDue := makeDueWindowForProjectionTest(t, ctx, s, ts, tieJob.ID, "window-rank-tie-second")
	sharedStart, sharedEnd := sqliteTimestamp(now.Add(-2*time.Hour)), sqliteTimestamp(now.Add(-time.Hour))
	if _, err := s.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=?,end_at=? WHERE id IN (?,?)`, sharedStart, sharedEnd, firstDue.ID, secondDue.ID); err != nil {
		t.Fatal(err)
	}
	wantTie := firstDue.ID
	if secondDue.ID > wantTie {
		wantTie = secondDue.ID
	}

	projection, err := ts.LatestChangeWindowSummaries(ctx, false, now)
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		jobID string
		want  string
	}{
		{activeJob.ID, active.ID},
		{expiredJob.ID, expired.ID},
		{scheduledJob.ID, nearOnly.ID},
		{dueJob.ID, dueScheduled.ID},
		{tieJob.ID, wantTie},
	}
	for _, check := range checks {
		if got := projection[check.jobID].ID; got != check.want {
			t.Errorf("latest window for job %s = %q; want %q", check.jobID, got, check.want)
		}
	}
	if got := projection[activeJob.ID].Status; got != "active" {
		t.Errorf("window starting exactly at now has status %q; want active", got)
	}
	if got := projection[expiredJob.ID].Status; got != "expired" {
		t.Errorf("window ending exactly at now has status %q; want expired", got)
	}
}

func makeDueWindowForProjectionTest(t *testing.T, ctx context.Context, s *Store, ts *TenantStore, jobID, scanID string) ChangeWindow {
	t.Helper()
	window, err := ts.CreateChangeWindow(ctx, jobID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "maintenance", "test-actor", "Test Operator")
	if err != nil {
		t.Fatal(err)
	}
	queueWindowTestEvent(t, ctx, s, "destination-"+scanID, jobID, "changes-detected", scanID, time.Now().UTC(), []model.Change{{Key: "new:" + scanID, Kind: "port", Target: "192.0.2.10", Port: 443}}, false, 0)
	closed, changed, err := ts.CancelChangeWindow(ctx, jobID, window.ID, "operator", "Operator", nil, AuditEntry{})
	if err != nil || !changed || closed.ReviewState != "due" {
		t.Fatalf("close due window %s: changed %v, state %q, err %v", scanID, changed, closed.ReviewState, err)
	}
	return closed
}

func TestListChangeWindowsKeepsActiveExpiredScheduledAndDueBeforeReviewedHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-list-priority", "UTC")
	now := time.Now().UTC().Truncate(time.Second)
	created := sqliteTimestamp(now)

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	insert := func(id string, start, end time.Time, status, closedAt, reviewState string) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, `INSERT INTO change_windows(id,job_id,start_at,end_at,timezone,reason,actor_label,created_at,status,end_reason,closed_at,review_state) VALUES (?,?,? ,?,'UTC','test window','Operator',?,?,'expired',?,?)`, id, job.ID, sqliteTimestamp(start), sqliteTimestamp(end), created, status, closedAt, reviewState); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 105; i++ {
		start := now.Add(-time.Duration(i+3) * time.Hour)
		insert(fmt.Sprintf("reviewed-%03d", i), start, start.Add(time.Hour), "closed", sqliteTimestamp(start.Add(time.Hour)), "reviewed")
	}
	insert("due-review", now.Add(-3*time.Hour), now.Add(-2*time.Hour), "closed", sqliteTimestamp(now.Add(-2*time.Hour)), "due")
	insert("expired-open", now.Add(-time.Hour), now, "active", "", "none")
	insert("active-open", now, now.Add(time.Hour), "active", "", "none")
	insert("scheduled-open", now.Add(2*time.Hour), now.Add(3*time.Hour), "scheduled", "", "none")
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	windows, err := ts.ListChangeWindows(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(windows) != 104 {
		t.Fatalf("visible window count = %d; want active, expired, scheduled, due, and up to 100 reviewed rows", len(windows))
	}
	want := []struct{ id, status, review string }{
		{"active-open", "active", "none"},
		{"expired-open", "expired", "none"},
		{"scheduled-open", "scheduled", "none"},
		{"due-review", "expired", "due"},
	}
	for index, check := range want {
		if windows[index].ID != check.id || windows[index].Status != check.status || windows[index].ReviewState != check.review {
			t.Errorf("window %d = %+v; want id=%s status=%s review=%s", index, windows[index], check.id, check.status, check.review)
		}
	}
	if windows[4].ID != "reviewed-000" || windows[len(windows)-1].ID != "reviewed-099" {
		t.Fatalf("reviewed history bounds = %q..%q; want newest 100 reviewed rows", windows[4].ID, windows[len(windows)-1].ID)
	}
}

func TestListChangeWindowsKeepsDueReviewsVisibleBeyondScheduledRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	job := createWindowTestJob(t, ts, "window-list-due-after-scheduled", "UTC")
	due := makeDueWindowForProjectionTest(t, ctx, s, ts, job.ID, "due-after-scheduled")
	now := time.Now().UTC().Truncate(time.Second)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO change_windows(id,job_id,start_at,end_at,timezone,reason,actor_label,created_at,status,end_reason,closed_at,review_state) VALUES (?,?,?,?,'UTC','scheduled fixture','Operator',?,'scheduled','','','none')`)
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	for index := 0; index < 125; index++ {
		start := now.Add(24*time.Hour + time.Duration(index)*24*time.Hour)
		if _, err := stmt.ExecContext(ctx, fmt.Sprintf("scheduled-visible-%03d", index), job.ID, sqliteTimestamp(start), sqliteTimestamp(start.Add(time.Hour)), sqliteTimestamp(now)); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			t.Fatalf("insert scheduled row %d: %v", index, err)
		}
	}
	if err := stmt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	windows, err := ts.ListChangeWindows(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(windows) != 101 {
		t.Fatalf("window count = %d, want 100 scheduled rows and one due review", len(windows))
	}
	if windows[0].ID != "scheduled-visible-000" || windows[99].ID != "scheduled-visible-099" || windows[100].ID != due.ID || windows[100].ReviewState != "due" {
		t.Fatalf("due review was not retained after 100 scheduled rows: first=%q hundredth=%q last=%+v", windows[0].ID, windows[99].ID, windows[100])
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

func TestDelayedWindowExpiryExcludesAlertsDeliveredAfterWindowEnd(t *testing.T) {
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
	if len(deliveries) != 2 {
		t.Fatalf("before-expiry claim = %+v; want both pending alerts released at the window end", deliveries)
	}
	seen := map[string]bool{}
	for _, delivery := range deliveries {
		seen[delivery.Event.ScanID] = true
		if err := s.System().DeliveryResultClaim(ctx, delivery.ID, delivery.ClaimToken, nil); err != nil {
			t.Fatal(err)
		}
	}
	if !seen["scan-before"] || !seen["scan-after"] {
		t.Fatalf("before-expiry claim scans = %v; want scan-before and scan-after", seen)
	}
	if _, changed, err := ts.ExpireChangeWindow(ctx, window.ID, func() time.Time { return time.Now().UTC() }, []string{"summary-destination"}); err != nil || !changed {
		t.Fatalf("delayed expiry: changed %v, err %v", changed, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE event_job_id=? AND event_type='changes-detected' AND change_window_id=? AND coalesced_at<>''`, job.ID, window.ID) != 0 {
		t.Fatal("delivered post-end alerts were coalesced at delayed expiry")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE event_job_id=? AND event_type='changes-detected' AND sent_at IS NOT NULL`, job.ID) != 2 {
		t.Fatal("both alerts were not individually delivered at delayed expiry")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_refs WHERE window_id=? AND category='new'`, window.ID) != 0 {
		t.Fatal("the closing summary included alerts already delivered after window end")
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

func TestDeliveryFailureAfterWindowEndUsesNormalRetrySchedule(t *testing.T) {
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
	var next, lastError, claim, started, coalesced string
	var attempts int
	if err := s.DB.QueryRowContext(ctx, `SELECT next_at,last_error,claim_token,attempt_started_at,coalesced_at,attempts FROM outbox WHERE id=?`, deliveries[0].ID).Scan(&next, &lastError, &claim, &started, &coalesced, &attempts); err != nil {
		t.Fatal(err)
	}
	nextAt, err := time.Parse(time.RFC3339Nano, next)
	if err != nil || !nextAt.After(time.Now().UTC()) || next == exactEnd.Format(time.RFC3339Nano) || lastError != "provider_timeout" || claim != "" || started != "" || coalesced != "" || attempts != 1 {
		t.Fatalf("post-end provider failure next=%q parseErr=%v error=%q claim=%q marker=%q coalesced=%q attempts=%d; want normal future retry with one recorded attempt", next, err, lastError, claim, started, coalesced, attempts)
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
