// Package storetest gives tests a fresh, fully migrated EdgeWatch database
// without running every migration for each test.
//
// Opening a new database runs every schema migration, table rebuild and
// startup phase, which takes seconds under the race detector. This package
// migrates one template database per test binary and gives each test its own
// copy of it. A copy holds the same schema and rows as a freshly migrated
// database; only the timestamps of the migration differ.
//
// Tests of migrations, fresh installs or setup tokens, and tests that depend
// on the file name or on other files in the database directory, must still
// open a new database themselves.
package storetest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/store"
)

var (
	templateOnce  sync.Once
	templateBytes []byte
	templateErr   error
)

// FreshPath writes a copy of the migrated template database to a new
// temporary directory of t and returns its path. The directory holds no other
// file, so the keys kept beside the database are created for this copy alone.
func FreshPath(t testing.TB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "edgewatch.db")
	raw, err := migratedTemplate()
	if err == nil {
		err = os.WriteFile(path, raw, 0o600)
	}
	if err != nil {
		t.Fatalf("copy the migrated template database: %v", err)
	}
	return path
}

// OpenFresh opens a copy of the migrated template database and closes it when
// the test ends.
func OpenFresh(t testing.TB) *store.Store {
	t.Helper()
	s, err := store.Open(FreshPath(t))
	if err != nil {
		t.Fatalf("open a copy of the migrated template database: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// migratedTemplate returns the contents of a database that store.Open has
// fully migrated. It builds the database once per test binary.
func migratedTemplate() ([]byte, error) {
	templateOnce.Do(func() {
		templateBytes, templateErr = build(os.TempDir(), store.Open)
	})
	return templateBytes, templateErr
}

// build migrates a new database with open in a private directory below
// parent and returns the database file. The directory is removed before build
// returns, so no key file written beside the database can reach a copy.
func build(parent string, open func(string) (*store.Store, error)) ([]byte, error) {
	dir, err := os.MkdirTemp(parent, "edgewatch-storetest-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "edgewatch.db")
	s, err := open(path)
	if err != nil {
		return nil, fmt.Errorf("migrate the template database: %w", err)
	}
	// Move every committed page into the main file, so the file alone is the
	// complete database.
	_, checkpointErr := s.DB.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	if err := errors.Join(checkpointErr, s.Close()); err != nil {
		return nil, fmt.Errorf("close the template database: %w", err)
	}
	return os.ReadFile(path)
}
