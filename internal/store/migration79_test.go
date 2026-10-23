package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

func reconstructSchema78(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, statement := range []string{
		`DROP INDEX ` + scanCyclesCompletedExecutionIndex,
		`PRAGMA user_version=78`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("reconstruct schema 78 with %s: %v", statement, err)
		}
	}
}

func TestMigration79IndexesCompletedCyclesByExecution(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	reconstructSchema78(t, s.DB)
	job, err := defaultTenant(s).CreateJob(ctx, testJob("schema-79"))
	if err != nil {
		t.Fatal(err)
	}
	stamp := sqliteTimestamp(time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC))
	for _, cycle := range []struct{ id, status, finished string }{
		{"schema-79-completed", "completed", stamp},
		{"schema-79-running", "running", ""},
	} {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO scan_cycles(id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,attempt_count,total_units,total_probes,started_at,attempt_started_at,updated_at,expires_at,finished_at)
			VALUES(?,?,?,?,'scope','execution','{}',?,1,1,1,?,?,?,?,?)`, cycle.id, job.ID, job.Job.Name, job.Revision, cycle.status, stamp, stamp, stamp, stamp, cycle.finished); err != nil {
			t.Fatal(err)
		}
	}

	if err := runMigration(ctx, s.DB, 79, []string{migration79Statements()[0], `CREATE INDEX scan_cycles_broken ON scan_cycles(missing_column)`}, false); err == nil {
		t.Fatal("schema 79 migration with an invalid index succeeded")
	}
	if got := countRows(t, s.DB, `PRAGMA user_version`); got != 78 {
		t.Fatalf("failed schema 79 migration advanced to schema %d", got)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, scanCyclesCompletedExecutionIndex); got != 0 {
		t.Fatalf("failed schema 79 migration left %d completed-cycle indexes, want none", got)
	}

	if err := applyMigration(ctx, s.DB, 79, migration79Statements()); err != nil {
		t.Fatalf("apply schema 79: %v", err)
	}
	if got := countRows(t, s.DB, `PRAGMA user_version`); got != 79 {
		t.Fatalf("schema version = %d, want 79", got)
	}
	var definition string
	if err := s.DB.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='index' AND name=?`, scanCyclesCompletedExecutionIndex).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(definition, "(job_id,execution_hash,finished_at DESC,id DESC,attempt_count,started_at,attempt_started_at) WHERE status='completed'") {
		t.Fatalf("completed-cycle index = %s", definition)
	}
	// The index lists the completed cycle that the database held before the
	// migration, and not the running one.
	var ids string
	if err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(group_concat(id),'') FROM scan_cycles INDEXED BY `+scanCyclesCompletedExecutionIndex+` WHERE job_id=? AND execution_hash='execution' AND status='completed'`, job.ID).Scan(&ids); err != nil {
		t.Fatal(err)
	}
	if ids != "schema-79-completed" {
		t.Fatalf("indexed completed cycles = %q, want the completed cycle only", ids)
	}

	if err := reapplyMigration(t, s.DB, 79, migration79Statements()); err != nil {
		t.Fatalf("reapply schema 79: %v", err)
	}
	if err := runMigration(ctx, s.DB, 79, migration79Statements(), false); err == nil || err.Error() != "schema migration 79: the database is at schema 79, not 78; another process is migrating it" {
		t.Errorf("repeated schema 79 migration = %v, want moved-marker refusal", err)
	}
}
