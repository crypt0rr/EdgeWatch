package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

type cliStartupState struct {
	state, owner, startedAt string
}

func readCLIStartupState(t *testing.T, database string) cliStartupState {
	t.Helper()
	reader, err := store.OpenReadOnlyExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var state cliStartupState
	if err := reader.DB.QueryRow(`SELECT state,owner,started_at FROM startup_state WHERE id=1`).Scan(&state.state, &state.owner, &state.startedAt); err != nil {
		t.Fatal(err)
	}
	return state
}

// seedDaemonLeaseDatabase creates a database one schema version behind, as a
// running older daemon would leave it, whose daemon lease heartbeat is the
// given age.
func seedDaemonLeaseDatabase(t *testing.T, database string, heartbeatAge time.Duration) int {
	t.Helper()
	ctx := context.Background()
	seed, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := seed.SaveAdmin(ctx, store.Admin{Username: "admin", DisplayName: "Admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		seed.Close()
		t.Fatal(err)
	}
	if _, err := seed.AcquireDaemonLease(ctx, "running-daemon"); err != nil {
		seed.Close()
		t.Fatal(err)
	}
	if _, err := seed.DB.ExecContext(ctx, `UPDATE daemon_lease SET heartbeat=? WHERE id=1`, now.Add(-heartbeatAge).Format(time.RFC3339Nano)); err != nil {
		seed.Close()
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	// The migration runner tolerates the current table shape under an older
	// user_version, as it does for an interrupted upgrade.
	supported := sqliteUserVersion(t, database)
	setSQLiteUserVersion(t, database, supported-1)
	return supported
}

func writeDaemonLeaseConfig(t *testing.T, dir, database string) string {
	t.Helper()
	configPath := filepath.Join(dir, "config.yaml")
	contents := fmt.Sprintf("database: %s\nweb:\n  listen: %s\nupdates:\n  enabled: false\nenrichment:\n  rdap:\n    enabled: false\n", database, occupiedLoopbackAddress(t))
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

// A second daemon started while another daemon's lease is live must exit
// before it migrates the schema or rewrites startup_state. Migrations are
// forward-only, so the running daemon could not restart on the upgraded file.
func TestDaemonRefusesLiveLeaseBeforeMigrating(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	supported := seedDaemonLeaseDatabase(t, database, 0)
	configPath := writeDaemonLeaseConfig(t, dir, database)
	startup := readCLIStartupState(t, database)
	before := snapshotCLIFile(t, database)

	err := run([]string{"daemon", "--config", configPath})
	if !errors.Is(err, store.ErrDaemonLeaseBusy) {
		t.Fatalf("second daemon error = %v, want ErrDaemonLeaseBusy", err)
	}

	after := snapshotCLIFile(t, database)
	if !bytes.Equal(before.data, after.data) || before.mode != after.mode || !before.modTime.Equal(after.modTime) {
		t.Fatal("refused daemon changed the database file")
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(database + suffix); !os.IsNotExist(err) {
			t.Fatalf("refused daemon left %s: %v", suffix, err)
		}
	}
	if got := sqliteUserVersion(t, database); got != supported-1 {
		t.Fatalf("user_version = %d, want %d", got, supported-1)
	}
	if got := readCLIStartupState(t, database); got != startup {
		t.Fatalf("startup_state = %#v, want %#v", got, startup)
	}
}

// A daemon restarting after a crash (stale lease) or starting for the first
// time (no database yet) still migrates and starts. The occupied listener makes
// startup fail only after the database work is done.
func TestDaemonStartsWithoutLiveLease(t *testing.T) {
	t.Run("stale lease", func(t *testing.T) {
		dir := t.TempDir()
		database := filepath.Join(dir, "edgewatch.db")
		supported := seedDaemonLeaseDatabase(t, database, 10*time.Minute)
		err := run([]string{"daemon", "--config", writeDaemonLeaseConfig(t, dir, database)})
		if err == nil || !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("daemon did not get past startup to the listener: %v", err)
		}
		if got := sqliteUserVersion(t, database); got != supported {
			t.Fatalf("user_version = %d, want %d", got, supported)
		}
	})
	// A lease that cannot be read before migrating does not block startup
	// here; App.Daemon still refuses to take it after the migration.
	t.Run("unreadable lease", func(t *testing.T) {
		dir := t.TempDir()
		database := filepath.Join(dir, "edgewatch.db")
		supported := seedDaemonLeaseDatabase(t, database, 0)
		fixture, err := store.OpenExisting(database)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.DB.Exec(`UPDATE daemon_lease SET heartbeat='not-a-time' WHERE id=1`); err != nil {
			fixture.Close()
			t.Fatal(err)
		}
		if err := fixture.Close(); err != nil {
			t.Fatal(err)
		}
		err = run([]string{"daemon", "--config", writeDaemonLeaseConfig(t, dir, database)})
		if err == nil || (!errors.Is(err, store.ErrDaemonLeaseBusy) && !strings.Contains(err.Error(), "address already in use")) {
			t.Fatalf("daemon error = %v, want a lease or listener error after startup", err)
		}
		if got := sqliteUserVersion(t, database); got != supported {
			t.Fatalf("user_version = %d, want %d", got, supported)
		}
	})
	t.Run("first start", func(t *testing.T) {
		dir := t.TempDir()
		database := filepath.Join(dir, "data", "edgewatch.db")
		err := run([]string{"daemon", "--config", writeDaemonLeaseConfig(t, dir, database)})
		if err == nil || !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("daemon did not get past startup to the listener: %v", err)
		}
		if state := readCLIStartupState(t, database); state.state != "ready" {
			t.Fatalf("startup_state = %#v, want ready", state)
		}
	})
}
