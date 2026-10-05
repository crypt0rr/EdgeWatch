package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
)

func setUserVersion(t *testing.T, path string, version int) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version=%d", version)); err != nil {
		t.Fatal(err)
	}
}

// The openers for the host commands that act on business units or accounts
// refuse a database that the daemon has not migrated yet, before anything
// reads or writes it, and leave no SQLite sidecar behind. The other host
// opens, which backup, restore, verify, and health use, still accept it.
func TestUpgradedOpenersRefuseAnOlderSchema(t *testing.T) {
	t.Parallel()
	path := freshTestDatabasePath(t)
	upgraded := map[string]func(string) (*Store, error){
		"OpenExistingUpgraded":         OpenExistingUpgraded,
		"OpenReadOnlyExistingUpgraded": OpenReadOnlyExistingUpgraded,
	}
	for name, open := range upgraded {
		s, err := open(path)
		if err != nil {
			t.Fatalf("%s on the current schema: %v", name, err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}

	setUserVersion(t, path, schemaVersion-1)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("database schema version %d has not been upgraded to version %d yet", schemaVersion-1, schemaVersion)
	for name, open := range upgraded {
		s, err := open(path)
		if err == nil {
			s.Close()
			t.Fatalf("%s opened a database that is not upgraded yet", name)
		}
		if !errors.Is(err, ErrSchemaUpgradePending) || err.Error() != want {
			t.Fatalf("%s error = %v, want ErrSchemaUpgradePending with %q", name, err, want)
		}
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			if _, statErr := os.Stat(path + suffix); !os.IsNotExist(statErr) {
				t.Fatalf("%s left %s behind (stat err=%v)", name, suffix, statErr)
			}
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("a refused open changed the database")
	}

	for name, open := range map[string]func(string) (*Store, error){
		"OpenExisting":         OpenExisting,
		"OpenReadOnlyExisting": OpenReadOnlyExisting,
	} {
		s, err := open(path)
		if err != nil {
			t.Fatalf("%s on an older schema: %v", name, err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// A newer schema is refused by the write-capable opener as before, and the
// read-only opener leaves it to the command, as OpenReadOnlyExisting does.
func TestUpgradedOpenersOnANewerSchema(t *testing.T) {
	t.Parallel()
	path := freshTestDatabasePath(t)
	setUserVersion(t, path, schemaVersion+1)
	if s, err := OpenExistingUpgraded(path); err == nil || errors.Is(err, ErrSchemaUpgradePending) || err.Error() != newerSchemaError(schemaVersion+1).Error() {
		if s != nil {
			s.Close()
		}
		t.Fatalf("OpenExistingUpgraded on a newer schema = %v, want the newer schema refusal", err)
	}
	s, err := OpenReadOnlyExistingUpgraded(path)
	if err != nil {
		t.Fatalf("OpenReadOnlyExistingUpgraded on a newer schema: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
