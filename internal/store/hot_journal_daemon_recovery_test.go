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

type daemonRecoveryStartupState struct {
	state, owner, phase, startedAt, updatedAt, lastError string
	progress, total                                      int
}

type daemonRecoveryLease struct {
	owner, heartbeat string
}

func readDaemonRecoveryStartupState(t *testing.T, path string) daemonRecoveryStartupState {
	t.Helper()
	reader, err := OpenReadOnlyExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var state daemonRecoveryStartupState
	err = reader.DB.QueryRow(`SELECT state,owner,phase,started_at,updated_at,progress,total,last_error FROM startup_state WHERE id=1`).Scan(
		&state.state, &state.owner, &state.phase, &state.startedAt, &state.updatedAt, &state.progress, &state.total, &state.lastError,
	)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func readDaemonRecoverySchemaVersion(t *testing.T, path string) int {
	t.Helper()
	reader, err := OpenReadOnlyExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var version int
	if err := reader.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func readDaemonRecoveryLease(t *testing.T, path string) daemonRecoveryLease {
	t.Helper()
	reader, err := OpenReadOnlyExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var lease daemonRecoveryLease
	if err := reader.DB.QueryRow(`SELECT owner,heartbeat FROM daemon_lease WHERE id=1`).Scan(&lease.owner, &lease.heartbeat); err != nil {
		t.Fatal(err)
	}
	return lease
}

func daemonRecoveryFileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func createDaemonHotRollbackJournal(t *testing.T, lease string) string {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "edgewatch.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TABLE `+sqliteSidecarProbeTable+` (id INTEGER PRIMARY KEY, detail TEXT NOT NULL)`); err != nil {
		s.Close()
		t.Fatal(err)
	}
	for i := 0; i < 400; i++ {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO `+sqliteSidecarProbeTable+`(detail) VALUES(?)`, fmt.Sprintf("original-%d", i)); err != nil {
			s.Close()
			t.Fatal(err)
		}
	}
	if lease != "" {
		if _, err := s.System().AcquireDaemonLease(ctx, lease); err != nil {
			s.Close()
			t.Fatal(err)
		}
	}
	switch lease {
	case "malformed":
		if _, err := s.DB.ExecContext(ctx, `UPDATE daemon_lease SET heartbeat='not-a-time' WHERE id=1`); err != nil {
			s.Close()
			t.Fatal(err)
		}
	case "live-daemon":
		if _, err := s.DB.ExecContext(ctx, `UPDATE daemon_lease SET heartbeat='2999-01-01T00:00:00Z' WHERE id=1`); err != nil {
			s.Close()
			t.Fatal(err)
		}
	}
	if lease != "" {
		if _, err := s.DB.ExecContext(ctx, `UPDATE startup_state SET state='ready',owner='hot-journal-sentinel',phase='preserve',started_at='sentinel-start',updated_at='sentinel-update',progress=7,total=9,last_error='sentinel-error' WHERE id=1`); err != nil {
			s.Close()
			t.Fatal(err)
		}
		if _, err := s.DB.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version=%d`, schemaVersion-1)); err != nil {
			s.Close()
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Host opens do not request WAL. Keep this fixture in rollback-journal
	// mode so killing the writer leaves the same hot-journal shape as a
	// restored backup followed by an interrupted host command.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var journalMode string
	if err := raw.QueryRowContext(ctx, `PRAGMA journal_mode=DELETE`).Scan(&journalMode); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if journalMode != "delete" {
		t.Fatalf("journal_mode = %q, want delete", journalMode)
	}

	writer := startSQLiteSidecarHelper(t, "journal-writer", path)
	writer.expect(t, "ready")
	requireSidecars(t, path, "writer spilled its uncommitted rollback transaction", "-journal")
	writer.kill()
	requireSidecars(t, path, "writer was killed with a hot rollback journal", "-journal")
	return path
}

func countHotJournalProbeRows(t *testing.T, path, where string) int {
	t.Helper()
	reader, err := OpenReadOnlyExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var count int
	if err := reader.DB.QueryRow(`SELECT COUNT(*) FROM ` + sqliteSidecarProbeTable + ` WHERE ` + where).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestDaemonOpenRecoversHotRollbackJournalBeforeLeaseCheck(t *testing.T) {
	path := createDaemonHotRollbackJournal(t, "")

	opened, err := OpenDaemonWithLoggerContext(context.Background(), path, nil)
	if err != nil {
		t.Fatalf("daemon open with a hot rollback journal: %v", err)
	}
	defer opened.Close()
	if got := countHotJournalProbeRows(t, path, `detail LIKE 'UPDATED%'`); got != 0 {
		t.Fatalf("rows from the killed transaction after daemon recovery = %d, want 0", got)
	}
	if got := countHotJournalProbeRows(t, path, `detail LIKE 'original-%'`); got != 400 {
		t.Fatalf("original rows after daemon recovery = %d, want 400", got)
	}
	if _, err := os.Stat(path + "-journal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hot journal after successful daemon recovery: %v", err)
	}
}

func TestDaemonOpenRecoversHotJournalThenRefusesLiveLease(t *testing.T) {
	path := createDaemonHotRollbackJournal(t, "live-daemon")
	modeBefore := daemonRecoveryFileMode(t, path)
	wantStartup := daemonRecoveryStartupState{
		state: "ready", owner: "hot-journal-sentinel", phase: "preserve",
		startedAt: "sentinel-start", updatedAt: "sentinel-update", progress: 7, total: 9, lastError: "sentinel-error",
	}
	wantLease := daemonRecoveryLease{owner: "live-daemon", heartbeat: "2999-01-01T00:00:00Z"}

	if _, err := OpenDaemonWithLoggerContext(context.Background(), path, nil); !errors.Is(err, ErrDaemonLeaseBusy) {
		t.Fatalf("daemon open with a hot journal and live lease = %v, want ErrDaemonLeaseBusy", err)
	}
	if got := readDaemonRecoverySchemaVersion(t, path); got != schemaVersion-1 {
		t.Fatalf("schema version after live-lease refusal = %d, want %d", got, schemaVersion-1)
	}
	if after := readDaemonRecoveryStartupState(t, path); after != wantStartup {
		t.Fatalf("startup_state after live-lease refusal = %#v, want %#v", after, wantStartup)
	}
	if after := readDaemonRecoveryLease(t, path); after != wantLease {
		t.Fatalf("lease after live-lease refusal = %#v, want %#v", after, wantLease)
	}
	if got := daemonRecoveryFileMode(t, path); got != modeBefore {
		t.Fatalf("database mode after live-lease refusal = %04o, want %04o", got, modeBefore)
	}
	if got := countHotJournalProbeRows(t, path, `detail LIKE 'UPDATED%'`); got != 0 {
		t.Fatalf("rows from the killed host transaction after lease refusal = %d, want 0", got)
	}
	if got := countHotJournalProbeRows(t, path, `detail LIKE 'original-%'`); got != 400 {
		t.Fatalf("original rows after lease refusal = %d, want 400", got)
	}
	if _, err := os.Stat(path + "-journal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hot journal after lease-aware recovery: %v", err)
	}
}

func TestDaemonOpenRecoversHotJournalThenStillRefusesMalformedLease(t *testing.T) {
	path := createDaemonHotRollbackJournal(t, "malformed")
	modeBefore := daemonRecoveryFileMode(t, path)
	wantStartup := daemonRecoveryStartupState{
		state: "ready", owner: "hot-journal-sentinel", phase: "preserve",
		startedAt: "sentinel-start", updatedAt: "sentinel-update", progress: 7, total: 9, lastError: "sentinel-error",
	}
	wantLease := daemonRecoveryLease{owner: "malformed", heartbeat: "not-a-time"}

	if _, err := OpenDaemonWithLoggerContext(context.Background(), path, nil); err == nil || errors.Is(err, ErrDaemonLeaseBusy) {
		t.Fatalf("daemon open with a hot journal and malformed lease = %v, want malformed lease error", err)
	}
	reader, err := OpenReadOnlyExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var gotVersion int
	if err := reader.DB.QueryRow(`PRAGMA user_version`).Scan(&gotVersion); err != nil {
		t.Fatal(err)
	}
	if gotVersion != schemaVersion-1 {
		t.Fatalf("schema version after malformed lease refusal = %d, want %d", gotVersion, schemaVersion-1)
	}
	if after := readDaemonRecoveryStartupState(t, path); after != wantStartup {
		t.Fatalf("startup_state after malformed lease refusal = %#v, want %#v", after, wantStartup)
	}
	if after := readDaemonRecoveryLease(t, path); after != wantLease {
		t.Fatalf("malformed lease after refusal = %#v, want %#v", after, wantLease)
	}
	if got := daemonRecoveryFileMode(t, path); got != modeBefore {
		t.Fatalf("database mode after malformed-lease refusal = %04o, want %04o", got, modeBefore)
	}
	if got := countHotJournalProbeRows(t, path, `detail LIKE 'UPDATED%'`); got != 0 {
		t.Fatalf("rows from the killed host transaction after malformed lease refusal = %d, want 0", got)
	}
	if _, err := os.Stat(path + "-journal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hot journal after malformed lease recovery: %v", err)
	}
}

func TestDaemonOpenCancellationDoesNotRecoverHotJournal(t *testing.T) {
	path := createDaemonHotRollbackJournal(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := OpenDaemonWithLoggerContext(ctx, path, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon open with canceled context = %v, want context.Canceled", err)
	}
	requireSidecars(t, path, "canceled daemon open did not recover the journal", "-journal")
}
