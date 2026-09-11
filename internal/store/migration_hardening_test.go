package store

import (
	"database/sql"
	"strings"
	"testing"
)

func TestMigrationDDLChecksExistingColumnsStructurally(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := execMigrationStatement(tx, "ALTER TABLE sample ADD COLUMN value TEXT NOT NULL"); err != nil {
		t.Fatalf("existing column should be skipped structurally: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := execMigrationStatement(tx, "ALTER TABLE missing ADD COLUMN value TEXT"); err == nil {
		t.Fatal("missing-table migration error was suppressed")
	}
	_ = tx.Rollback()
}

func TestMigrateRefusesNewerSchema(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA user_version = 999"); err != nil {
		t.Fatal(err)
	}
	if err := migrate(db); err == nil {
		t.Fatal("newer schema version was accepted")
	}
}

func TestMigrateRejectsRecoveryFixtureMissingRequiredSourceTable(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(legacySchema); err != nil {
		t.Fatal(err)
	}
	// A schema marker is not a promise that arbitrary newer tables can be
	// reconstructed. This fixture claims the pre-FTS schema but omits the host
	// source table required by migration 22; fail at that exact contract.
	if _, err := db.Exec("PRAGMA user_version = 21"); err != nil {
		t.Fatal(err)
	}
	err = migrate(db)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "scan_hosts") {
		t.Fatalf("missing-source fixture error = %v, want scan_hosts diagnostic", err)
	}
}
