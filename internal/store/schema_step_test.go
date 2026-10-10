package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"modernc.org/sqlite"
)

// reapplyMigration runs one schema step again on a database at a newer
// schema, as the tests of a step's statements do. A step runs only on the
// schema before it, so the marker is set back first.
func reapplyMigration(t testing.TB, db *sql.DB, version int, statements []string) error {
	t.Helper()
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", version-1)); err != nil {
		return err
	}
	return applyMigration(context.Background(), db, version, statements)
}

// A schema step reads the schema marker inside its write transaction and
// refuses to run when the marker has moved on, as when another process has
// migrated the database since this one read its version, or is behind the
// step. Both runners refuse, and nothing changes.
func TestSchemaStepRefusesAMovedSchemaMarker(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name           string
		marker         int
		foreignKeysOff bool
	}{
		{name: "moved past the step", marker: schemaVersion},
		{name: "moved past the step, foreign keys off", marker: schemaVersion, foreignKeysOff: true},
		{name: "behind the step", marker: 57},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			s := openTestStore(t)
			if _, err := s.DB.Exec(fmt.Sprintf("PRAGMA user_version = %d", test.marker)); err != nil {
				t.Fatal(err)
			}
			err := runMigration(context.Background(), s.DB, 60, []string{`CREATE TABLE schema_step_probe (id INTEGER)`}, test.foreignKeysOff)
			want := fmt.Sprintf("schema migration 60: the database is at schema %d, not 59; another process is migrating it", test.marker)
			if err == nil || err.Error() != want {
				t.Fatalf("error = %v, want %q", err, want)
			}
			if got := countRows(t, s.DB, `PRAGMA user_version`); got != test.marker {
				t.Fatalf("user_version = %d, want %d", got, test.marker)
			}
			if got := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE name='schema_step_probe'`); got != 0 {
				t.Fatal("the refused step ran its statements")
			}
		})
	}
}

// migrationStepLog counts the completed schema steps that every logger of a
// test reports.
type migrationStepLog struct {
	mu    sync.Mutex
	steps map[int]int
}

func (l *migrationStepLog) logger() *slog.Logger {
	return slog.New(migrationStepHandler{log: l})
}

type migrationStepHandler struct {
	log *migrationStepLog
}

func (migrationStepHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h migrationStepHandler) Handle(_ context.Context, record slog.Record) error {
	if record.Message != "database migration step completed" {
		return nil
	}
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == "schema" {
			h.log.mu.Lock()
			h.log.steps[int(attr.Value.Int64())]++
			h.log.mu.Unlock()
		}
		return true
	})
	return nil
}

func (h migrationStepHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h migrationStepHandler) WithGroup(string) slog.Handler      { return h }

// assertEachStepOnce checks that the baseline and every later step ran
// exactly once, whichever opener ran it.
func (l *migrationStepLog) assertEachStepOnce(t *testing.T) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	for version := minimumUpgradeSchema; version <= schemaVersion; version++ {
		if l.steps[version] != 1 {
			t.Errorf("schema %d ran %d times, want once: %v", version, l.steps[version], l.steps)
		}
	}
}

// Concurrent daemons on one new database: the migration guard lets one of
// them migrate and refuses the others, which change nothing, so every step
// runs once.
func TestConcurrentOpensMigrateEachStepOnce(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("the migration guard is implemented on Linux")
	}
	path := filepath.Join(t.TempDir(), "edgewatch.db")
	log := &migrationStepLog{steps: map[int]int{}}
	const openers = 4
	errs := make(chan error, openers)
	start := make(chan struct{})
	for range openers {
		go func() {
			<-start
			s, err := OpenWithLogger(path, log.logger())
			if err == nil {
				err = s.Close()
			}
			errs <- err
		}()
	}
	close(start)
	opened := 0
	for range openers {
		switch err := <-errs; {
		case err == nil:
			opened++
		case errors.Is(err, ErrMigrationInProgress):
		default:
			t.Errorf("open error = %v, want success or ErrMigrationInProgress", err)
		}
	}
	if opened == 0 {
		t.Fatal("no open migrated the database")
	}
	log.assertEachStepOnce(t)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := countRows(t, s.DB, `PRAGMA user_version`); got != schemaVersion {
		t.Fatalf("user_version = %d, want %d", got, schemaVersion)
	}
}

// Without the guard, as on a file system that cannot lock the directory, the
// schema marker check of each step still keeps two migrations from running
// a step twice: the one that finds the marker moved fails. A migration that
// waits for the write lock while another one commits transaction after
// transaction can also run out of busy_timeout, which under the race
// detector takes a few seconds; that refusal runs no step either.
func TestConcurrentMigrationsWithoutTheGuardRunEachStepOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "edgewatch.db")
	log := &migrationStepLog{steps: map[int]int{}}
	const migrations = 3
	databases := make([]*sql.DB, migrations)
	for i := range databases {
		connector, err := sqlite.NewConnector(path)
		if err != nil {
			t.Fatal(err)
		}
		databases[i] = sql.OpenDB(sqlitePragmaConnector{Connector: connector})
		databases[i].SetMaxOpenConns(1)
		t.Cleanup(func() { _ = databases[i].Close() })
	}
	if _, err := databases[0].Exec(`PRAGMA journal_mode=WAL`); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, migrations)
	start := make(chan struct{})
	for _, db := range databases {
		go func() {
			<-start
			errs <- migrateContextWithLogger(ctx, db, log.logger())
		}()
	}
	close(start)
	succeeded := 0
	for range migrations {
		switch err := <-errs; {
		case err == nil:
			succeeded++
		case strings.Contains(err.Error(), "another process is migrating it"):
		case isSQLiteWriterBusy(err):
		default:
			t.Errorf("migration error = %v, want success, the moved schema marker, or SQLITE_BUSY", err)
		}
	}
	if succeeded == 0 {
		t.Fatal("no migration completed")
	}
	log.assertEachStepOnce(t)
	if got := countRows(t, databases[0], `PRAGMA user_version`); got != schemaVersion {
		t.Fatalf("user_version = %d, want %d", got, schemaVersion)
	}
}

// The guard refuses a migrating open while another process migrates, or
// restores, a database in the same directory. The refused open writes
// nothing; once the guard is released, the open migrates.
func TestMigrationGuardRefusesAnOpenWhileHeld(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("the migration guard is implemented on Linux")
	}
	ctx := context.Background()
	path := freshTestDatabasePath(t)
	if _, err := setRestoreFixtureVersion(t, path, schemaVersion-1); err != nil {
		t.Fatal(err)
	}
	before, err := fileDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, hold := range map[string]func() (func(), error){
		"migration": func() (func(), error) { return acquireMigrationGuard(filepath.Dir(path)) },
		"restore": func() (func(), error) {
			unlock, _, err := acquireRestoreStagingGuard(ctx, filepath.Dir(path))
			return unlock, err
		},
	} {
		unlock, err := hold()
		if err != nil {
			t.Fatal(err)
		}
		s, err := Open(path)
		unlock()
		if err == nil {
			s.Close()
			t.Fatalf("an open migrated while a %s held the guard", name)
		}
		if !errors.Is(err, ErrMigrationInProgress) || !strings.Contains(err.Error(), filepath.Dir(path)) {
			t.Fatalf("open during a %s = %v, want ErrMigrationInProgress", name, err)
		}
		if after, err := fileDigest(path); err != nil || after != before {
			t.Fatalf("the refused open changed the database (%v)", err)
		}
		for _, sidecar := range []string{"-wal", "-shm"} {
			if _, err := os.Stat(path + sidecar); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the refused open created %s: %v", sidecar, err)
			}
		}
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open after the guard was released: %v", err)
	}
	defer s.Close()
	if got := countRows(t, s.DB, `PRAGMA user_version`); got != schemaVersion {
		t.Fatalf("user_version = %d, want %d", got, schemaVersion)
	}
	// The guard is released when the open returns.
	unlock, err := acquireMigrationGuard(filepath.Dir(path))
	if err != nil {
		t.Fatalf("guard after the open returned: %v", err)
	}
	unlock()
}

// beginWriteTx takes the write lock through startup_state, which every
// database that a migration touches has; without it the transaction is not
// begun.
func TestBeginWriteTxReportsAMissingLockTable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openRebuildTestDB(t)
	if _, err := db.Exec(`DROP TABLE startup_state`); err != nil {
		t.Fatal(err)
	}
	if _, err := beginWriteTx(ctx, db); err == nil || !strings.Contains(err.Error(), "take the database write lock") || !strings.Contains(err.Error(), "startup_state") {
		t.Fatalf("beginWriteTx without startup_state = %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := beginWriteTx(ctx, db); err == nil {
		t.Fatal("beginWriteTx on a closed database succeeded")
	}
	if _, err := checkUpgradableSchemaContext(ctx, db); err == nil {
		t.Fatal("the schema check on a closed database succeeded")
	}
}

// The guard reports a directory that it cannot open, which is not another
// migration, and platforms without the guard return a no-op unlock.
func TestMigrationGuardReportsADirectoryItCannotOpen(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing")
	if runtime.GOOS == "linux" {
		if _, err := acquireMigrationGuard(missing); err == nil || errors.Is(err, ErrMigrationInProgress) || !strings.Contains(err.Error(), "open the database directory") {
			t.Fatalf("guard of a missing directory = %v", err)
		}
	}
	unlock, err := acquireUnsupportedMigrationGuard(missing)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}
