package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestMigration73IndexesPrioritizedChangeWindowQueries(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	db := f.store.DB
	for _, index := range []string{
		changeWindowsOpenLatestIndex,
		changeWindowsOpenScheduledIndex,
		changeWindowsDueReviewIndex,
		changeWindowsClosedHistoryIndex,
	} {
		if _, err := db.ExecContext(ctx, `DROP INDEX IF EXISTS `+index); err != nil {
			t.Fatalf("drop schema 73 index %s: %v", index, err)
		}
	}
	if _, err := db.ExecContext(ctx, `PRAGMA user_version=72`); err != nil {
		t.Fatal(err)
	}
	if err := runMigration(ctx, db, 73, []string{
		migration73Statements()[0],
		`CREATE INDEX change_windows_broken ON change_windows(missing_column)`,
	}, false); err == nil {
		t.Fatal("schema 73 migration with an invalid index succeeded")
	}
	if got := countRows(t, db, `PRAGMA user_version`); got != 72 {
		t.Fatalf("failed schema 73 migration advanced to schema %d", got)
	}
	if got := countRows(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, changeWindowsOpenLatestIndex); got != 0 {
		t.Fatalf("failed schema 73 migration left %d new indexes, want none", got)
	}

	tenant := f.store.Tenant(f.a)
	dueJob, err := tenant.CreateJob(ctx, testJob("window-priority-due-heavy"))
	if err != nil {
		t.Fatal(err)
	}
	expiredJob, err := tenant.CreateJob(ctx, testJob("window-priority-expired-heavy"))
	if err != nil {
		t.Fatal(err)
	}
	mixedJob, err := tenant.CreateJob(ctx, testJob("window-priority-mixed"))
	if err != nil {
		t.Fatal(err)
	}
	otherTenantJob, err := f.store.Tenant(f.b).CreateJob(ctx, testJob("window-priority-other-tenant"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	created := sqliteTimestamp(now)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO change_windows(id,job_id,start_at,end_at,timezone,reason,actor_label,created_at,status,end_reason,closed_at,review_state) VALUES (?,?,?,?,'UTC','fixture','Operator',?,?,?, ?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	insert := func(jobID, id string, start, end time.Time, status, endReason, closedAt, reviewState string) {
		t.Helper()
		if _, err := stmt.ExecContext(ctx, id, jobID, sqliteTimestamp(start), sqliteTimestamp(end), created, status, endReason, closedAt, reviewState); err != nil {
			t.Fatalf("insert window %s: %v", id, err)
		}
	}
	insertOpen := func(jobID, id string, start, end time.Time) {
		t.Helper()
		status := "active"
		if start.After(now) {
			status = "scheduled"
		}
		insert(jobID, id, start, end, status, "", "", "none")
	}
	dueIDs, expiredIDs, scheduledIDs := []string{}, []string{}, []string{}
	for i := 0; i < 10_000; i++ {
		start := now.Add(-time.Duration(i+1) * time.Hour)
		id := fmt.Sprintf("due-heavy-%05d", i)
		insert(dueJob.ID, id, start, start.Add(time.Minute), "closed", "expired", sqliteTimestamp(start.Add(time.Minute)), "due")
		dueIDs = append(dueIDs, id)
	}
	// Deliberately seed two overlapping active rows. The write path rejects
	// overlap, but the inventory query must still preserve its general ranking
	// when it encounters legacy or restored rows with more than one active
	// window instead of assuming a single open row.
	activeIDs := []string{"due-active-newer", "due-active-older"}
	insertOpen(dueJob.ID, activeIDs[1], now.Add(-2*time.Hour), now.Add(2*time.Hour))
	insertOpen(dueJob.ID, activeIDs[0], now.Add(-time.Minute), now.Add(time.Hour))
	for i := 0; i < 25; i++ {
		start := now.Add(-30*time.Hour - time.Duration(i)*2*time.Second)
		id := fmt.Sprintf("due-expired-%03d", i)
		insertOpen(dueJob.ID, id, start, start.Add(time.Second))
		expiredIDs = append(expiredIDs, id)
	}
	for i := 0; i < 25; i++ {
		start := now.Add(time.Hour + time.Duration(i)*2*time.Second)
		id := fmt.Sprintf("due-scheduled-%03d", i)
		insertOpen(dueJob.ID, id, start, start.Add(time.Second))
		scheduledIDs = append(scheduledIDs, id)
	}
	for i := 0; i < 150; i++ {
		start := now.Add(-200*time.Hour - time.Duration(i)*time.Hour)
		insert(dueJob.ID, fmt.Sprintf("history-heavy-%03d", i), start, start.Add(time.Minute), "closed", "expired", sqliteTimestamp(start.Add(time.Minute)), "reviewed")
	}

	expiredHeavyIDs := make([]string, 0, 10_000)
	for i := 0; i < 10_000; i++ {
		start := now.Add(-30*24*time.Hour - time.Duration(i)*time.Second)
		id := fmt.Sprintf("expired-heavy-%05d", i)
		insertOpen(expiredJob.ID, id, start, start.Add(time.Second))
		expiredHeavyIDs = append(expiredHeavyIDs, id)
	}
	insertOpen(expiredJob.ID, "expired-heavy-active", now.Add(-time.Minute), now.Add(time.Hour))
	for i := 0; i < 10_000; i++ {
		start := now.Add(2*time.Hour + time.Duration(i)*2*time.Second)
		insertOpen(expiredJob.ID, fmt.Sprintf("expired-scheduled-heavy-%05d", i), start, start.Add(time.Second))
	}
	for i := 0; i < 100; i++ {
		start := now.Add(-300*time.Hour - time.Duration(i)*time.Hour)
		insert(expiredJob.ID, fmt.Sprintf("expired-due-%03d", i), start, start.Add(time.Minute), "closed", "expired", sqliteTimestamp(start.Add(time.Minute)), "due")
		insert(expiredJob.ID, fmt.Sprintf("expired-history-%03d", i), start.Add(-time.Hour), start.Add(-time.Hour+time.Minute), "closed", "expired", sqliteTimestamp(start.Add(-time.Hour+time.Minute)), "reviewed")
	}

	for i, state := range []string{"active", "expired", "scheduled", "due", "reviewed"} {
		start := now.Add(time.Duration(i-3) * time.Hour)
		closed, review := "", "none"
		if state == "due" || state == "reviewed" {
			closed, review = sqliteTimestamp(start.Add(time.Minute)), state
		}
		if state == "scheduled" {
			start = now.Add(time.Duration(i+1) * time.Hour)
		}
		if state == "expired" {
			start = now.Add(-time.Duration(i+1) * time.Hour)
			closed = ""
		}
		if state == "active" {
			start = now.Add(-time.Minute)
		}
		status := state
		endReason := ""
		if closed != "" {
			status, endReason = "closed", "expired"
		}
		if state == "expired" {
			status, endReason = "active", ""
		}
		insert(mixedJob.ID, "mixed-"+state, start, start.Add(time.Hour), status, endReason, closed, review)
	}
	tieStart := now.Add(-5 * time.Hour)
	for _, id := range []string{"mixed-due-tie-a", "mixed-due-tie-z"} {
		insert(mixedJob.ID, id, tieStart, tieStart.Add(time.Minute), "closed", "expired", sqliteTimestamp(tieStart.Add(time.Minute)), "due")
	}
	insert(otherTenantJob.ID, "other-tenant-window", now, now.Add(time.Hour), "active", "", "", "none")
	if err := stmt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	if _, err := db.ExecContext(ctx, `PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatal(err)
	}
	truncateFixtureWAL(t, db)
	if err := applyMigration(ctx, db, 73, migration73Statements()); err != nil {
		t.Fatalf("apply schema 73: %v", err)
	}
	walBytes, err := walSize(f.store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if walBytes > maxSchemaStepWALBytes {
		t.Fatalf("schema 73 WAL is %d bytes, above %d-byte migration budget", walBytes, maxSchemaStepWALBytes)
	}
	var indexBytes int64
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(SUM(pgsize),0) FROM dbstat WHERE name IN (?,?,?,?)`, changeWindowsOpenLatestIndex, changeWindowsOpenScheduledIndex, changeWindowsDueReviewIndex, changeWindowsClosedHistoryIndex).Scan(&indexBytes); err != nil {
		t.Fatalf("measure schema 73 indexes: %v", err)
	}
	if got := countRows(t, db, `PRAGMA user_version`); got != 73 {
		t.Fatalf("schema version = %d, want 73", got)
	}
	for index, want := range map[string]string{
		changeWindowsOpenLatestIndex:    "job_id,start_at DESC,id DESC,end_at",
		changeWindowsOpenScheduledIndex: "job_id,start_at,id DESC",
		changeWindowsDueReviewIndex:     "job_id,start_at DESC,id DESC",
		changeWindowsClosedHistoryIndex: "job_id,start_at DESC,id DESC",
	} {
		if got := indexKeys(t, db, index); got != want {
			t.Errorf("%s keys = %q, want %q", index, got, want)
		}
	}
	plan := queryPlan(t, db, listChangeWindowsQuery, dueJob.ID, f.a.ID(), sqliteTimestamp(now), sqliteTimestamp(now.Add(-changeWindowMaximumDuration)))
	for _, index := range []string{changeWindowsOpenLatestIndex, changeWindowsOpenScheduledIndex, changeWindowsDueReviewIndex, changeWindowsClosedHistoryIndex} {
		if !strings.Contains(plan, index) {
			t.Errorf("prioritized query plan does not use %s: %s", index, plan)
		}
	}
	if got := strings.Count(plan, "USE TEMP B-TREE FOR ORDER BY"); got != 1 {
		t.Errorf("prioritized query uses %d ORDER BY temp sorts, want only the final bounded candidate merge: %s", got, plan)
	}
	t.Logf("schema 73 index plan: %s", plan)
	t.Logf("schema 73 migration WAL: %d bytes; new window indexes: %d bytes; seeded 10,000 each of retained due, expired-unclosed, and scheduled windows plus mixed histories", walBytes, indexBytes)

	assertIDs := func(jobID string, want []string) {
		t.Helper()
		windows, err := tenant.ListChangeWindows(ctx, jobID)
		if err != nil {
			t.Fatalf("list windows for %s: %v", jobID, err)
		}
		if len(windows) != len(want) {
			t.Fatalf("list windows for %s returned %d rows, want %d", jobID, len(windows), len(want))
		}
		for i := range want {
			if windows[i].ID != want[i] {
				t.Errorf("list windows for %s row %d = %q, want %q", jobID, i, windows[i].ID, want[i])
			}
		}
	}
	wantDue := append([]string{}, activeIDs...)
	wantDue = append(wantDue, expiredIDs[:25]...)
	wantDue = append(wantDue, scheduledIDs...)
	wantDue = append(wantDue, dueIDs[:48]...)
	assertIDs(dueJob.ID, wantDue)
	wantExpired := make([]string, 0, 100)
	wantExpired = append(wantExpired, "expired-heavy-active")
	for i := 0; i < 99; i++ {
		wantExpired = append(wantExpired, expiredHeavyIDs[i])
	}
	assertIDs(expiredJob.ID, wantExpired)
	assertIDs(mixedJob.ID, []string{"mixed-active", "mixed-expired", "mixed-scheduled", "mixed-due", "mixed-due-tie-z", "mixed-due-tie-a", "mixed-reviewed"})
	if _, err := f.store.Tenant(f.b).ListChangeWindows(ctx, dueJob.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other tenant listed due-heavy job: %v", err)
	}
}
