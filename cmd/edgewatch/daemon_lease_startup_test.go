package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

type cliStartupState struct {
	state, owner, startedAt string
}

const daemonHotJournalWriterPathEnv = "EDGEWATCH_TEST_DAEMON_HOT_JOURNAL_WRITER_PATH"

const daemonHotJournalProbeTable = "daemon_hot_journal_probe"

// TestDaemonHotJournalWriterProcess is re-executed by the CLI regression so
// SIGKILL leaves a real rollback journal instead of allowing SQLite to roll
// the interrupted transaction back during a normal close.
func TestDaemonHotJournalWriterProcess(t *testing.T) {
	path := os.Getenv(daemonHotJournalWriterPathEnv)
	if path == "" {
		return
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, statement := range []string{
		"PRAGMA busy_timeout=5000",
		"PRAGMA cache_size=8",
		"BEGIN IMMEDIATE",
		`UPDATE ` + daemonHotJournalProbeTable + ` SET detail='UPDATED'||hex(randomblob(1500))`,
	} {
		if _, err := conn.ExecContext(context.Background(), statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	_, _ = fmt.Fprintln(os.Stdout, "EDGEWATCH_DAEMON_HOT_JOURNAL_READY")
	select {}
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
	if _, err := seed.System().AcquireDaemonLease(ctx, "running-daemon"); err != nil {
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
	t.Parallel()
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

func TestCleanDaemonCancellationRequiresTheCommandContext(t *testing.T) {
	active := context.Background()
	if got := cleanDaemonCancellation(active, context.Canceled); !errors.Is(got, context.Canceled) {
		t.Fatalf("cancellation with a live command context = %v, want context.Canceled", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := cleanDaemonCancellation(ctx, fmt.Errorf("startup: %w", context.Canceled)); got != nil {
		t.Fatalf("wrapped cancellation after command cancellation = %v, want nil", got)
	}
	ordinary := errors.New("unrelated startup failure")
	if got := cleanDaemonCancellation(ctx, ordinary); !errors.Is(got, ordinary) {
		t.Fatalf("unrelated error after command cancellation = %v, want the original error", got)
	}
}

// A daemon restarting after a crash (stale lease) or starting for the first
// time (no database yet) still migrates and starts. The occupied listener makes
// startup fail only after the database work is done.
func TestDaemonStartsWithoutLiveLease(t *testing.T) {
	t.Parallel()
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
	// A lease that cannot be read before migration may pass the early
	// diagnostic check, but the daemon-specific open repeats the check while
	// holding the migration guard and fails closed before changing the schema.
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
		startup := readCLIStartupState(t, database)
		configPath := filepath.Join(dir, "config.yaml")
		contents := fmt.Sprintf("database: %s\nweb:\n  listen: 127.0.0.1:0\nupdates:\n  enabled: false\nenrichment:\n  rdap:\n    enabled: false\n", database)
		if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		err = run([]string{"daemon", "--config", configPath})
		if err == nil || errors.Is(err, store.ErrDaemonLeaseBusy) || strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("daemon error = %v, want the unreadable lease error before migration", err)
		}
		if got := sqliteUserVersion(t, database); got != supported-1 {
			t.Fatalf("user_version = %d after fail-closed startup, want %d", got, supported-1)
		}
		if got := readCLIStartupState(t, database); got != startup {
			t.Fatalf("startup_state after unreadable lease = %#v, want %#v", got, startup)
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

func TestDaemonCommandRecoversHotRollbackJournal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	seed, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.DB.Exec(`CREATE TABLE ` + daemonHotJournalProbeTable + ` (id INTEGER PRIMARY KEY, detail TEXT NOT NULL)`); err != nil {
		seed.Close()
		t.Fatal(err)
	}
	for i := 0; i < 400; i++ {
		if _, err := seed.DB.Exec(`INSERT INTO `+daemonHotJournalProbeTable+`(detail) VALUES(?)`, fmt.Sprintf("original-%d", i)); err != nil {
			seed.Close()
			t.Fatal(err)
		}
	}
	supported := sqliteUserVersion(t, database)
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	var journalMode string
	if err := raw.QueryRow(`PRAGMA journal_mode=DELETE`).Scan(&journalMode); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if journalMode != "delete" {
		t.Fatalf("journal_mode = %q, want delete", journalMode)
	}
	setSQLiteUserVersion(t, database, supported-1)

	writerCtx, cancelWriter := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelWriter()
	command := exec.CommandContext(writerCtx, os.Args[0], "-test.run=^TestDaemonHotJournalWriterProcess$", "-test.count=1")
	command.Env = append(os.Environ(), daemonHotJournalWriterPathEnv+"="+database)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	ready := false
	for scanner := bufio.NewScanner(stdout); scanner.Scan(); {
		if scanner.Text() == "EDGEWATCH_DAEMON_HOT_JOURNAL_READY" {
			ready = true
			break
		}
	}
	if !ready {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("hot-journal writer exited before spilling its transaction; stderr: %s", stderr.String())
	}
	if _, err := os.Stat(database + "-journal"); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("writer did not spill a rollback journal: %v", err)
	}
	if err := command.Process.Kill(); err != nil {
		_ = command.Wait()
		t.Fatalf("kill hot-journal writer: %v", err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("hot-journal writer exited successfully after SIGKILL")
	}

	// The occupied listener makes run daemon return only after its database
	// startup, including the guarded lease check and migration, has completed.
	configPath := writeDaemonLeaseConfig(t, dir, database)
	err = run([]string{"daemon", "--config", configPath})
	if err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("daemon error = %v, want startup to reach the occupied listener", err)
	}
	if got := sqliteUserVersion(t, database); got != supported {
		t.Fatalf("user_version after recovered daemon startup = %d, want %d", got, supported)
	}
	if got := countCLIRows(t, database, daemonHotJournalProbeTable); got != 400 {
		t.Fatalf("probe rows after daemon recovered interrupted transaction = %d, want 400", got)
	}
	if got := countCLIRows(t, database, daemonHotJournalProbeTable+` WHERE detail LIKE 'UPDATED%'`); got != 0 {
		t.Fatalf("rows from interrupted transaction after daemon startup = %d, want 0", got)
	}
	if _, err := os.Stat(database + "-journal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback journal after daemon startup: %v", err)
	}
}
