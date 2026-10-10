package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestMigrationDDLChecksExistingColumnsStructurally(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

// Write-capable host commands open the database without migrating. They must
// refuse a schema from a newer release just as the daemon does, before they
// write anything, instead of changing tables they do not understand.
func TestOpenExistingRefusesNewerSchemaWithoutWriting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "edgewatch.db")
	fixture, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.Close(); err != nil {
		t.Fatal(err)
	}
	setUserVersion := func(version int) {
		t.Helper()
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version=%d", version)); err != nil {
			db.Close()
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	setUserVersion(schemaVersion + 1)
	before, err := fileDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("database schema version %d is newer than supported version %d", schemaVersion+1, schemaVersion)
	for name, open := range map[string]func() (*Store, error){
		"OpenExisting":        func() (*Store, error) { return OpenExisting(path) },
		"OpenExistingContext": func() (*Store, error) { return OpenExistingContext(ctx, path) },
	} {
		s, err := open()
		if err == nil {
			// Show that the handle would have written to the newer schema.
			_, auditErr := s.DB.ExecContext(ctx, `INSERT INTO security_audit(action,detail,created_at) VALUES('database.backup','',datetime('now'))`)
			s.Close()
			t.Fatalf("%s opened a schema %d database for writing (audit insert error: %v)", name, schemaVersion+1, auditErr)
		}
		if err.Error() != want {
			t.Fatalf("%s error = %q, want %q", name, err, want)
		}
	}
	after, err := fileDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("refused open changed the database file")
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("refused open left %s: %v", suffix, err)
		}
	}

	// Read-only inspection still opens a newer schema so verify can report it.
	reader, err := OpenReadOnlyExisting(path)
	if err != nil {
		t.Fatalf("read-only open of a newer schema: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	// The current schema still opens for writing.
	setUserVersion(schemaVersion)
	current, err := OpenExisting(path)
	if err != nil {
		t.Fatalf("open current schema: %v", err)
	}
	if err := current.Close(); err != nil {
		t.Fatal(err)
	}
}
