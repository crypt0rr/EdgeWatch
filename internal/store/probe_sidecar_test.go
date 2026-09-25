package store

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The tests in this file reproduce races between a read-only probe and a
// writer in another OS process. SQLite coordinates processes through file
// locks and the shared WAL index, so a writer in the test process itself
// would not exercise the same code paths. The test binary re-executes itself
// as the writer through TestSQLiteSidecarHelperProcess.
const (
	sqliteSidecarHelperModeEnv     = "EDGEWATCH_TEST_SQLITE_SIDECAR_HELPER"
	sqliteSidecarHelperDatabaseEnv = "EDGEWATCH_TEST_SQLITE_SIDECAR_DATABASE"
	sqliteSidecarProbeTable        = "sidecar_probe_rows"
)

// TestSQLiteSidecarHelperProcess is not a test on its own. It only runs work
// when a parent test starts the test binary with the helper environment.
func TestSQLiteSidecarHelperProcess(t *testing.T) {
	mode := os.Getenv(sqliteSidecarHelperModeEnv)
	if mode == "" {
		return
	}
	if err := runSQLiteSidecarHelper(mode, os.Getenv(sqliteSidecarHelperDatabaseEnv), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stdout, "error: %v\n", err)
	}
}

func runSQLiteSidecarHelper(mode, database string, in io.Reader, out io.Writer) error {
	ctx := context.Background()
	commands := bufio.NewScanner(in)
	switch mode {
	case "wal-writer":
		// Open like a write-capable CLI command and read once, which attaches
		// this process to the WAL and WAL index. The store is deliberately
		// never closed: the parent kills this process to simulate a crash.
		writer, err := OpenExisting(database)
		if err != nil {
			return err
		}
		var rows int
		if err := writer.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+sqliteSidecarProbeTable).Scan(&rows); err != nil {
			return err
		}
		fmt.Fprintln(out, "ready")
		if !commands.Scan() || commands.Text() != "commit" {
			return nil
		}
		if _, err := writer.DB.ExecContext(ctx, `INSERT INTO `+sqliteSidecarProbeTable+`(detail) VALUES('committed')`); err != nil {
			return err
		}
		fmt.Fprintln(out, "committed")
	case "journal-writer":
		// Hold an uncommitted rollback-journal transaction whose pages spill
		// into the database file, as in a large update that crashes midway.
		db, err := sql.Open("sqlite", database)
		if err != nil {
			return err
		}
		conn, err := db.Conn(ctx)
		if err != nil {
			return err
		}
		for _, statement := range []string{
			"PRAGMA busy_timeout=5000",
			"PRAGMA cache_size=8",
			"BEGIN IMMEDIATE",
			`UPDATE ` + sqliteSidecarProbeTable + ` SET detail='UPDATED'||hex(randomblob(1500))`,
		} {
			if _, err := conn.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("%s: %w", statement, err)
			}
		}
		fmt.Fprintln(out, "ready")
	case "exclusive-check":
		// Report whether another process could currently prove that no
		// SQLite connection has the database open.
		fmt.Fprintf(out, "exclusive=%t\n", withExclusiveSQLiteDatabase(database, func() {}))
		return nil
	default:
		return fmt.Errorf("unknown helper mode %q", mode)
	}
	// Keep the connection open until the parent kills the process.
	for commands.Scan() {
	}
	return nil
}

type sqliteSidecarHelper struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  chan string
	stderr *bytes.Buffer
	done   bool
}

func startSQLiteSidecarHelper(t *testing.T, mode, database string) *sqliteSidecarHelper {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSQLiteSidecarHelperProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(), sqliteSidecarHelperModeEnv+"="+mode, sqliteSidecarHelperDatabaseEnv+"="+database)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	helper := &sqliteSidecarHelper{cmd: cmd, stdin: stdin, lines: make(chan string, 16), stderr: &bytes.Buffer{}}
	cmd.Stderr = helper.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(helper.lines)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			helper.lines <- scanner.Text()
		}
	}()
	t.Cleanup(helper.kill)
	return helper
}

// expect waits for a protocol line and returns it. Other output from the test
// framework in the helper process is ignored.
func (h *sqliteSidecarHelper) expect(t *testing.T, prefix string) string {
	t.Helper()
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case line, ok := <-h.lines:
			if !ok {
				h.kill()
				t.Fatalf("helper exited before %q; stderr: %s", prefix, h.stderr.String())
			}
			if strings.HasPrefix(line, "error: ") {
				h.kill()
				t.Fatalf("helper failed: %s; stderr: %s", line, h.stderr.String())
			}
			if strings.HasPrefix(line, prefix) {
				return line
			}
		case <-timeout.C:
			h.kill()
			t.Fatalf("timed out waiting for helper %q; stderr: %s", prefix, h.stderr.String())
		}
	}
}

func (h *sqliteSidecarHelper) send(t *testing.T, command string) {
	t.Helper()
	if _, err := io.WriteString(h.stdin, command+"\n"); err != nil {
		t.Fatal(err)
	}
}

// kill ends the helper with SIGKILL, so SQLite gets no chance to checkpoint,
// roll back, or delete anything on the way out.
func (h *sqliteSidecarHelper) kill() {
	if h.done {
		return
	}
	h.done = true
	_ = h.cmd.Process.Kill()
	_ = h.cmd.Wait()
}

func runSQLiteSidecarCheck(t *testing.T, database string) bool {
	t.Helper()
	helper := startSQLiteSidecarHelper(t, "exclusive-check", database)
	line := helper.expect(t, "exclusive=")
	helper.kill()
	return line == "exclusive=true"
}

func createSidecarProbeFixture(t *testing.T, path string, rows int) {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TABLE ` + sqliteSidecarProbeTable + ` (id INTEGER PRIMARY KEY, detail TEXT NOT NULL)`); err != nil {
		s.Close()
		t.Fatal(err)
	}
	for index := 0; index < rows; index++ {
		if _, err := s.DB.Exec(`INSERT INTO `+sqliteSidecarProbeTable+`(detail) VALUES(?)`, fmt.Sprintf("original-%d", index)); err != nil {
			s.Close()
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("fixture left %s after the last connection closed: %v", suffix, err)
		}
	}
}

func openSidecarProbe(t *testing.T, path string) *Store {
	t.Helper()
	probe, err := OpenReadOnlyExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.DaemonLeaseStatus(context.Background()); err != nil {
		probe.Close()
		t.Fatal(err)
	}
	return probe
}

func requireSidecars(t *testing.T, path, when string, suffixes ...string) {
	t.Helper()
	for _, suffix := range suffixes {
		if _, err := os.Stat(path + suffix); err != nil {
			t.Fatalf("%s: %s is missing: %v", when, suffix, err)
		}
	}
}

func countSidecarProbeRows(t *testing.T, path, where string) int {
	t.Helper()
	reader, err := OpenReadOnlyExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var rows int
	if err := reader.DB.QueryRow(`SELECT COUNT(*) FROM ` + sqliteSidecarProbeTable + ` WHERE ` + where).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func requireSidecarProbeIntegrity(t *testing.T, path string) {
	t.Helper()
	check, err := OpenExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var integrity string
	if err := check.DB.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		t.Fatal(err)
	}
	if integrity != "ok" {
		t.Fatalf("integrity_check = %q", integrity)
	}
}

// A read-only command can be the first process to attach to a WAL database,
// so SQLite creates an empty WAL/SHM pair for it. If a writer attaches before
// the command exits, closing the command must not unlink the files that the
// writer is using: its commits would go to deleted inodes, stay invisible to
// every other process, and vanish when the writer is killed.
func TestReadOnlyProbeCloseKeepsSidecarsOfWriterInAnotherProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edgewatch.db")
	createSidecarProbeFixture(t, path, 0)

	probe := openSidecarProbe(t, path)
	requireSidecars(t, path, "read-only probe on a WAL database", "-wal", "-shm")
	writer := startSQLiteSidecarHelper(t, "wal-writer", path)
	writer.expect(t, "ready")

	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	requireSidecars(t, path, "probe closed while another process had the database open", "-wal", "-shm")

	writer.send(t, "commit")
	writer.expect(t, "committed")
	if rows := countSidecarProbeRows(t, path, "detail='committed'"); rows != 1 {
		t.Fatalf("another process sees %d committed rows, want 1", rows)
	}
	writer.kill()

	if rows := countSidecarProbeRows(t, path, "detail='committed'"); rows != 1 {
		t.Fatalf("after the writer was killed, %d committed rows remain, want 1", rows)
	}
	requireSidecarProbeIntegrity(t, path)
}

// A read-only connection never creates a rollback journal, so any journal
// that exists belongs to another connection. Removing it while that writer
// has spilled uncommitted pages into the database makes a partial transaction
// permanent once the writer dies.
func TestReadOnlyProbeCloseNeverRemovesRollbackJournal(t *testing.T) {
	const rows = 400
	path := filepath.Join(t.TempDir(), "edgewatch.db")
	createSidecarProbeFixture(t, path, rows)
	raw, err := sql.Open("sqlite", path)
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

	probe := openSidecarProbe(t, path)
	writer := startSQLiteSidecarHelper(t, "journal-writer", path)
	writer.expect(t, "ready")
	requireSidecars(t, path, "writer holds an open rollback-journal transaction", "-journal")

	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	requireSidecars(t, path, "probe closed during another process's rollback-journal transaction", "-journal")
	writer.kill()

	// Opening the database again rolls the hot journal back.
	requireSidecarProbeIntegrity(t, path)
	if updated := countSidecarProbeRows(t, path, "detail LIKE 'UPDATED%'"); updated != 0 {
		t.Fatalf("%d of %d rows carry the uncommitted update after the writer died", updated, rows)
	}
	if kept := countSidecarProbeRows(t, path, "detail LIKE 'original-%'"); kept != rows {
		t.Fatalf("%d of %d original rows remain", kept, rows)
	}
}

// Another store in the same process holds SQLite's POSIX locks. Closing the
// probe must neither unlink that store's WAL/SHM pair nor release its locks,
// which closing any extra descriptor for the database file would do.
func TestReadOnlyProbeCloseKeepsSidecarsAndLocksOfSameProcessStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edgewatch.db")
	createSidecarProbeFixture(t, path, 0)

	probe := openSidecarProbe(t, path)
	writer, err := OpenExisting(path)
	if err != nil {
		probe.Close()
		t.Fatal(err)
	}
	defer writer.Close()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	requireSidecars(t, path, "probe closed while a store in the same process was open", "-wal", "-shm")
	if runSQLiteSidecarCheck(t, path) {
		t.Fatal("another process could lock the database exclusively while a store in this process had it open")
	}
	if _, err := writer.DB.Exec(`INSERT INTO ` + sqliteSidecarProbeTable + `(detail) VALUES('committed')`); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if rows := countSidecarProbeRows(t, path, "detail='committed'"); rows != 1 {
		t.Fatalf("%d committed rows after the writer closed, want 1", rows)
	}
}

// Restore probes the destination's daemon lease with a read-only connection.
// When another process has the destination open, that probe's sidecars cannot
// be removed, and replacing the database would put a new file next to the
// other connection's WAL and WAL index. The writer here holds the database
// open without visible sidecars, the state an earlier unlink left behind, so
// the preflight passes and only the lease probe can notice the connection.
func TestRestoreRefusesDestinationOpenedByAnotherConnection(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	destination := filepath.Join(dir, "destination.db")
	createRestoreFixture(t, source, "source")
	createSidecarProbeFixture(t, destination, 1)
	writer := startSQLiteSidecarHelper(t, "wal-writer", destination)
	writer.expect(t, "ready")
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(destination + suffix); err != nil {
			t.Fatal(err)
		}
	}
	before, err := fileDigest(destination)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Restore(context.Background(), source, destination, RestoreOptions{})
	if !errors.Is(err, ErrRestoreSidecars) {
		t.Fatalf("restore error = %v, want ErrRestoreSidecars", err)
	}
	after, err := fileDigest(destination)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("restore replaced a destination that another connection had open")
	}
}
