package storetest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestOpenFreshMatchesFreshMigration(t *testing.T) {
	fresh, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	copied := OpenFresh(t)

	if got, want := userVersion(t, copied.DB), userVersion(t, fresh.DB); got != want || got == 0 {
		t.Fatalf("user_version = %d, fresh migration has %d", got, want)
	}
	if got, want := schema(t, copied.DB), schema(t, fresh.DB); !slices.Equal(got, want) {
		t.Fatalf("schema differs from a fresh migration:\ncopy:  %q\nfresh: %q", got, want)
	}
	profiles, err := copied.ListScannerProfiles(context.Background(), true)
	if err != nil || len(profiles) == 0 {
		t.Fatalf("ListScannerProfiles() = %d profiles, %v; want the built-in profiles", len(profiles), err)
	}
	for _, name := range []string{"auth.key", "notification.key"} {
		if _, err := os.Stat(filepath.Join(filepath.Dir(copied.FilePath()), name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("copy has %s beside it: %v", name, err)
		}
	}
}

func TestFreshPathWritesPrivateSeparateCopies(t *testing.T) {
	first, second := FreshPath(t), FreshPath(t)
	if filepath.Dir(first) == filepath.Dir(second) {
		t.Fatalf("copies share the directory %s", filepath.Dir(first))
	}
	for _, path := range []string{first, second} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, want 0600", path, info.Mode().Perm())
		}
	}
	s, err := store.Open(first)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.DB.Exec(`CREATE TABLE storetest_probe (id INTEGER)`); err != nil {
		t.Fatal(err)
	}
	other := OpenFresh(t)
	if slices.ContainsFunc(schema(t, other.DB), func(entry string) bool { return strings.Contains(entry, "storetest_probe") }) {
		t.Fatal("a write to one copy reached another copy")
	}
}

func TestFreshPathFailsWhenTheCopyCannotBeWritten(t *testing.T) {
	tb := &fatalTB{dir: filepath.Join(t.TempDir(), "missing")}
	runUntilFatal(tb, func() { FreshPath(tb) })
	if !strings.Contains(tb.fatal, "copy the migrated template database") {
		t.Fatalf("FreshPath() fatal = %q", tb.fatal)
	}
}

func TestOpenFreshFailsWhenTheCopyCannotBeOpened(t *testing.T) {
	// The copy is written through a symbolic link, which store.Open refuses.
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "target.db"), filepath.Join(dir, "edgewatch.db")); err != nil {
		t.Fatal(err)
	}
	tb := &fatalTB{dir: dir}
	runUntilFatal(tb, func() { OpenFresh(tb) })
	if !strings.Contains(tb.fatal, "open a copy of the migrated template database") {
		t.Fatalf("OpenFresh() fatal = %q", tb.fatal)
	}
}

func TestBuildReportsEachFailure(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := build(missing, store.Open); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("build() in a missing directory error = %v", err)
	}

	refused := errors.New("refused")
	failing := func(string) (*store.Store, error) { return nil, refused }
	if _, err := build(t.TempDir(), failing); !errors.Is(err, refused) || !strings.Contains(err.Error(), "migrate the template database") {
		t.Fatalf("build() with a failing migration error = %v", err)
	}

	// A store whose connections are already closed cannot be checkpointed.
	closed := func(string) (*store.Store, error) {
		s, err := store.Open(FreshPath(t))
		if err != nil {
			return nil, err
		}
		return s, s.Close()
	}
	if _, err := build(t.TempDir(), closed); err == nil || !strings.Contains(err.Error(), "close the template database") {
		t.Fatalf("build() with a closed store error = %v", err)
	}
}

// fatalTB records the first fatal failure and stops the goroutine that
// reported it, as testing.T does.
type fatalTB struct {
	testing.TB
	dir   string
	fatal string
}

func (f *fatalTB) Helper()         {}
func (f *fatalTB) TempDir() string { return f.dir }
func (f *fatalTB) Cleanup(func())  { panic("unexpected Cleanup") }
func (f *fatalTB) Fatalf(format string, args ...any) {
	f.fatal = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func runUntilFatal(tb *fatalTB, fn func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	<-done
}

func userVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func schema(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT type,name,tbl_name,COALESCE(sql,'') FROM sqlite_master ORDER BY type,name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var entries []string
	for rows.Next() {
		var kind, name, table, statement string
		if err := rows.Scan(&kind, &name, &table, &statement); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, strings.Join([]string{kind, name, table, statement}, "|"))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return entries
}
