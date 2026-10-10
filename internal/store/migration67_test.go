package store

import (
	"context"
	"strings"
	"testing"
)

// Schema 67 adds the security alert routing of every tenant, empty, the
// platform's alert row with empty routings, and the security alert windows.
// An upgrade sends no tenant a security alert until its administrators
// select a destination. The step refuses to run over schema 67, and its
// statements change nothing when they run again.
func TestMigration67AddsEmptyAlertRouting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	path := s.Path
	insertSecondTenant(t, s)
	for _, statement := range []string{
		`DROP TABLE security_alert_windows`,
		`DROP TABLE platform_alert_state`,
		`ALTER TABLE tenants DROP COLUMN security_destinations_json`,
		`PRAGMA user_version=66`,
	} {
		if _, err := s.DB.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade from schema 66: %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	if version := countRows(t, upgraded.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
	for _, scope := range []TenantScope{DefaultTenantScope(), {id: secondTenantID}} {
		routing, err := upgraded.Tenant(scope).SecurityAlertRouting(ctx)
		if err != nil || routing == nil || len(routing) != 0 {
			t.Errorf("tenant %s's security routing after the upgrade = %v, %v", scope.ID(), routing, err)
		}
	}
	routing, err := upgraded.Platform().PlatformAlertRouting(ctx)
	if err != nil || len(routing.Security) != 0 || len(routing.Health) != 0 {
		t.Errorf("platform alert routing after the upgrade = %+v, %v", routing, err)
	}
	if rows := countRows(t, upgraded.DB, `SELECT COUNT(*) FROM platform_alert_state`); rows != 1 {
		t.Errorf("platform alert rows = %d, want 1", rows)
	}
	if rows := countRows(t, upgraded.DB, `SELECT COUNT(*) FROM security_alert_windows`); rows != 0 {
		t.Errorf("security alert windows = %d, want none", rows)
	}
	// The step re-reads the schema marker in its own transaction, so a
	// second run over the upgraded database is refused and changes nothing.
	if err := runMigration(ctx, upgraded.DB, 67, migration67Statements(), foreignKeysOffMigrations[67]); err == nil || !strings.Contains(err.Error(), "the database is at schema 67, not 66") {
		t.Errorf("repeated schema 67 step = %v, want the moved-marker refusal", err)
	}
	if version := countRows(t, upgraded.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("schema version after the refused step = %d, want %d", version, schemaVersion)
	}
	tx, err := upgraded.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, statement := range migration67Statements() {
		if err := execMigrationStatement(tx, statement); err != nil {
			t.Fatalf("repeated %s: %v", statement, err)
		}
	}
}
