package store

import (
	"context"
	"database/sql"
	"reflect"
	"strconv"
	"testing"
)

func reconstructSchema76For77(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, column := range []string{
		"scanner_identity_pool_alerted_at",
		"scanner_identity_pool_low",
		"scheduled_backup_alerted_at",
		"scheduled_backup_failing",
	} {
		if _, err := db.Exec(`ALTER TABLE platform_alert_state DROP COLUMN ` + column); err != nil {
			t.Fatalf("remove schema 77 column %s: %v", column, err)
		}
	}
	if _, err := db.Exec(`PRAGMA user_version=76`); err != nil {
		t.Fatal(err)
	}
}

// Schema 77 adds durable state for two operational deployment alerts. A
// failure after its conditional DDL rolls back all four columns and the schema
// marker. Successful apply and reapply run the registered conditional migration.
func TestMigration77AddsOperationalAlertState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	reconstructSchema76For77(t, s.DB)
	if conditionalMigrationStatements[77] == nil {
		t.Fatal("schema 77 conditional migration is not registered")
	}

	conditionalWithFailure := func(ctx context.Context, tx *sql.Tx) ([]string, error) {
		statements, err := migration77ConditionalStatements(ctx, tx)
		if err != nil {
			return nil, err
		}
		return append(statements, `CREATE INDEX migration77_broken ON platform_alert_state(missing_column)`), nil
	}
	if err := applyMigrationWithConditional(ctx, s.DB, 77, migration77Statements(), conditionalWithFailure); err == nil {
		t.Fatal("schema 77 migration with a post-DDL failure succeeded")
	}
	if got := countRows(t, s.DB, `PRAGMA user_version`); got != 76 {
		t.Fatalf("failed schema 77 migration advanced to schema %d", got)
	}
	for _, column := range []string{"scheduled_backup_failing", "scheduled_backup_alerted_at", "scanner_identity_pool_low", "scanner_identity_pool_alerted_at"} {
		var count int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('platform_alert_state') WHERE name=?`, column).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed migration left column %s count=%d, err=%v", column, count, err)
		}
	}

	if err := applyMigration(ctx, s.DB, 77, migration77Statements()); err != nil {
		t.Fatalf("apply schema 77: %v", err)
	}
	if got := countRows(t, s.DB, `PRAGMA user_version`); got != 77 {
		t.Fatalf("schema version = %d, want 77", got)
	}
	want := []string{"0", "", "0", ""}
	var actual []string
	var backupFailing, identityLow int
	var backupAlerted, identityAlerted string
	if err := s.DB.QueryRowContext(ctx, `SELECT scheduled_backup_failing,scheduled_backup_alerted_at,scanner_identity_pool_low,scanner_identity_pool_alerted_at FROM platform_alert_state WHERE id=1`).Scan(&backupFailing, &backupAlerted, &identityLow, &identityAlerted); err != nil {
		t.Fatal(err)
	}
	actual = []string{strconv.Itoa(backupFailing), backupAlerted, strconv.Itoa(identityLow), identityAlerted}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("operational alert state = %q, want %q", actual, want)
	}
	if err := reapplyMigration(t, s.DB, 77, migration77Statements()); err != nil {
		t.Fatalf("reapply schema 77: %v", err)
	}
	var columnCount int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('platform_alert_state') WHERE name IN ('scheduled_backup_failing','scheduled_backup_alerted_at','scanner_identity_pool_low','scanner_identity_pool_alerted_at')`).Scan(&columnCount); err != nil || columnCount != 4 {
		t.Fatalf("schema 77 columns after reapply = %d, err=%v; want four", columnCount, err)
	}
}
