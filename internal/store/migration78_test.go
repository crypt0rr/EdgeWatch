package store

import (
	"context"
	"database/sql"
	"testing"
)

func reconstructSchema77(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, statement := range []string{
		`ALTER TABLE scan_cycles DROP COLUMN attempt_started_at`,
		`PRAGMA user_version=77`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("reconstruct schema 77 with %s: %v", statement, err)
		}
	}
}

func TestMigration78AddsCycleAttemptStart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	reconstructSchema77(t, s.DB)

	if err := runMigration(ctx, s.DB, 78, []string{`CREATE INDEX scan_cycles_broken ON scan_cycles(missing_column)`}, false); err == nil {
		t.Fatal("schema 78 migration with an invalid index succeeded")
	}
	if got := countRows(t, s.DB, `PRAGMA user_version`); got != 77 {
		t.Fatalf("failed schema 78 migration advanced to schema %d", got)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM pragma_table_info('scan_cycles') WHERE name='attempt_started_at'`); got != 0 {
		t.Fatalf("failed schema 78 migration left attempt_started_at column: %d", got)
	}

	if err := applyMigration(ctx, s.DB, 78, migration78Statements()); err != nil {
		t.Fatalf("apply schema 78: %v", err)
	}
	if got := countRows(t, s.DB, `PRAGMA user_version`); got != 78 {
		t.Fatalf("schema version = %d, want 78", got)
	}
	var defaultValue string
	if err := s.DB.QueryRowContext(ctx, `SELECT dflt_value FROM pragma_table_info('scan_cycles') WHERE name='attempt_started_at'`).Scan(&defaultValue); err != nil || defaultValue != `''` {
		t.Fatalf("attempt_started_at default = %q, query error %v; want empty string", defaultValue, err)
	}
	if err := reapplyMigration(t, s.DB, 78, migration78Statements()); err != nil {
		t.Fatalf("reapply schema 78: %v", err)
	}
	if err := runMigration(ctx, s.DB, 78, migration78Statements(), false); err == nil || err.Error() != "schema migration 78: the database is at schema 78, not 77; another process is migrating it" {
		t.Errorf("repeated schema 78 migration = %v, want moved-marker refusal", err)
	}
}
