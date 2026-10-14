package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDaemonStartupOpenRetainsGuardUntilLeaseAndClose(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("the daemon migration guard is implemented on Linux")
	}
	ctx := context.Background()
	path := freshTestDatabasePath(t)

	starting, err := OpenDaemonWithLoggerContext(ctx, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer starting.Close()

	if _, err := acquireMigrationGuard(filepath.Dir(path)); !errors.Is(err, ErrMigrationInProgress) {
		t.Fatalf("second daemon guard during startup = %v, want ErrMigrationInProgress", err)
	}
	if _, err := starting.System().AcquireDaemonLease(ctx, "startup-guard-test"); err != nil {
		t.Fatalf("claim daemon lease while holding the startup guard: %v", err)
	}
	starting.ReleaseDaemonStartupGuard()
	starting.ReleaseDaemonStartupGuard()

	unlock, err := acquireMigrationGuard(filepath.Dir(path))
	if err != nil {
		t.Fatalf("guard after the daemon lease committed: %v", err)
	}
	unlock()

	if _, err := OpenDaemonWithLoggerContext(ctx, path, nil); !errors.Is(err, ErrDaemonLeaseBusy) {
		t.Fatalf("second daemon after the first lease committed = %v, want ErrDaemonLeaseBusy", err)
	}
	// The failed in-guard lease check must release its own guard.
	unlock, err = acquireMigrationGuard(filepath.Dir(path))
	if err != nil {
		t.Fatalf("guard after the refused second daemon: %v", err)
	}
	unlock()
}

func TestDaemonStartupOpenRechecksLeaseAfterEarlyPrecheck(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("the daemon migration guard is implemented on Linux")
	}
	ctx := context.Background()
	path := freshTestDatabasePath(t)
	if err := CheckDaemonLeaseBeforeStartup(ctx, path); err != nil {
		t.Fatalf("early lease check before another daemon starts: %v", err)
	}

	owner, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if _, err := owner.System().AcquireDaemonLease(ctx, "interleaved-daemon"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.DB.ExecContext(ctx, `UPDATE startup_state SET state='ready',owner='sentinel',phase='preserve',started_at='sentinel-start',updated_at='sentinel-update',progress=7,total=9,last_error='sentinel-error' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	oldVersion := schemaVersion - 1
	if _, err := owner.DB.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", oldVersion)); err != nil {
		t.Fatal(err)
	}
	var before struct {
		state, owner, phase, startedAt, updatedAt string
		progress, total                           int
		lastError                                 string
	}
	if err := owner.DB.QueryRowContext(ctx, `SELECT state,owner,phase,started_at,updated_at,progress,total,last_error FROM startup_state WHERE id=1`).Scan(&before.state, &before.owner, &before.phase, &before.startedAt, &before.updatedAt, &before.progress, &before.total, &before.lastError); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenDaemonWithLoggerContext(ctx, path, nil); !errors.Is(err, ErrDaemonLeaseBusy) {
		t.Fatalf("guarded daemon open after the early-check race = %v, want ErrDaemonLeaseBusy", err)
	}
	if got := countRows(t, owner.DB, `PRAGMA user_version`); got != oldVersion {
		t.Fatalf("user_version after guarded refusal = %d, want %d", got, oldVersion)
	}
	var after struct {
		state, owner, phase, startedAt, updatedAt string
		progress, total                           int
		lastError                                 string
	}
	if err := owner.DB.QueryRowContext(ctx, `SELECT state,owner,phase,started_at,updated_at,progress,total,last_error FROM startup_state WHERE id=1`).Scan(&after.state, &after.owner, &after.phase, &after.startedAt, &after.updatedAt, &after.progress, &after.total, &after.lastError); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("startup_state after guarded refusal = %#v, want %#v", after, before)
	}
}

func TestDaemonStartupOpenFailsClosedWhenMigrationGuardIsUnsupported(t *testing.T) {
	path := freshTestDatabasePath(t)
	fixture, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	const oldVersion = schemaVersion - 1
	if _, err := fixture.DB.ExecContext(context.Background(), fmt.Sprintf("PRAGMA user_version=%d", oldVersion)); err != nil {
		fixture.Close()
		t.Fatal(err)
	}
	if _, err := fixture.DB.ExecContext(context.Background(), `UPDATE startup_state SET state='ready',owner='sentinel',phase='preserve',started_at='sentinel-start',updated_at='sentinel-update',progress=7,total=9,last_error='sentinel-error' WHERE id=1`); err != nil {
		fixture.Close()
		t.Fatal(err)
	}
	if err := fixture.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	previousGuard := acquireMigrationGuard
	acquireMigrationGuard = func(string) (func(), error) { return nil, errMigrationGuardUnsupported }
	defer func() { acquireMigrationGuard = previousGuard }()

	if _, err := OpenDaemonWithLoggerContext(context.Background(), path, nil); !errors.Is(err, errMigrationGuardUnsupported) {
		t.Fatalf("daemon open without cross-process guard = %v, want unsupported guard error", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("daemon open without a migration guard changed the database")
	}
}

func TestDaemonStartupOpenRejectsInMemorySQLiteButGenericOpenKeepsSupport(t *testing.T) {
	for _, path := range []string{
		":memory:",
		":memory:?cache=shared",
		"file::memory:?cache=shared",
		"file:shared?mode=memory&cache=shared",
	} {
		t.Run(path, func(t *testing.T) {
			if _, err := OpenDaemonWithLoggerContext(context.Background(), path, nil); !errors.Is(err, errDaemonRequiresFileDatabase) {
				t.Fatalf("daemon open for %q = %v, want persistent-file requirement", path, err)
			}
		})
	}

	generic, err := Open(":memory:")
	if err != nil {
		t.Fatalf("generic in-memory open: %v", err)
	}
	defer generic.Close()
	var version int
	if err := generic.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("generic in-memory schema version = %d, want %d", version, schemaVersion)
	}
}

func TestDaemonStartupLeaseProbeErrorCleansItsSidecars(t *testing.T) {
	path := freshTestDatabasePath(t)
	fixture, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.DB.Exec(`DROP TABLE daemon_lease`); err != nil {
		fixture.Close()
		t.Fatal(err)
	}
	if _, err := fixture.DB.Exec(`CREATE TABLE daemon_lease(id INTEGER PRIMARY KEY, owner TEXT NOT NULL)`); err != nil {
		fixture.Close()
		t.Fatal(err)
	}
	if err := fixture.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoDaemonStartupSidecars(t, path)

	if _, err := OpenDaemonWithLoggerContext(context.Background(), path, nil); err == nil {
		t.Fatal("daemon open with a malformed lease table unexpectedly succeeded")
	} else if !strings.Contains(err.Error(), "heartbeat") {
		t.Fatalf("daemon open with malformed lease table error = %v, want lease-column query failure", err)
	}
	assertNoDaemonStartupSidecars(t, path)
}

func assertNoDaemonStartupSidecars(t *testing.T, path string) {
	t.Helper()
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("database sidecar %s after refused daemon open: %v", suffix, err)
		}
	}
}
