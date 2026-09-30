package store

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

const walUnavailableWarning = "SQLite WAL is unavailable"

// captureDefaultLog sends the default logger to a buffer until the test ends.
func captureDefaultLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

// writeRollbackJournalBackup backs up a migrated database. VACUUM INTO writes
// the copy in rollback-journal (delete) mode.
func writeRollbackJournalBackup(t *testing.T) string {
	t.Helper()
	s := openTestStore(t)
	path, err := s.Backup(context.Background(), filepath.Join(t.TempDir(), "backup.db"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func journalMode(t *testing.T, s *Store) string {
	t.Helper()
	var mode string
	if err := s.DB.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	return mode
}

// Host commands open a database without asking for WAL, which only the
// daemon switches on. A backup, and a database restored from one, is in
// rollback-journal mode until the daemon's next start, which is not a
// storage problem: the open keeps the writer connection for reads and does
// not warn that WAL is unavailable.
func TestOpeningABackupWithoutWALLogsNoWarning(t *testing.T) {
	ctx := context.Background()
	path := writeRollbackJournalBackup(t)
	logs := captureDefaultLog(t)
	for _, open := range []struct {
		name string
		open func() (*Store, error)
	}{
		{name: "OpenExisting", open: func() (*Store, error) { return OpenExisting(path) }},
		{name: "OpenExistingContext", open: func() (*Store, error) { return OpenExistingContext(ctx, path) }},
	} {
		s, err := open.open()
		if err != nil {
			t.Fatalf("%s: %v", open.name, err)
		}
		if mode := journalMode(t, s); mode != "delete" {
			s.Close()
			t.Fatalf("%s: journal_mode = %q, want the backup's delete mode", open.name, mode)
		}
		if s.ReadDB != nil {
			s.Close()
			t.Fatalf("%s opened a read pool on a database that is not in WAL mode", open.name)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(logs.String(), walUnavailableWarning) {
		t.Fatalf("opening a backup logged a WAL warning: %s", logs.String())
	}
}

// An open that asks for WAL, as the daemon's does, still warns when SQLite
// keeps another journal mode. The unix-dotfile VFS has no shared memory, so
// SQLite cannot switch to WAL on it, as on a filesystem without the shared
// memory that WAL needs.
func TestOpenWarnsWhenRequestedWALIsRefused(t *testing.T) {
	ctx := context.Background()
	path := writeRollbackJournalBackup(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	s, err := openWithOptionsContext(ctx, "file:"+path+"?vfs=unix-dotfile", openOptions{requireExisting: true, configureWAL: true, logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	mode := journalMode(t, s)
	readDB := s.ReadDB
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if mode == "wal" || readDB != nil {
		t.Fatalf("journal_mode = %q with read pool %v, want SQLite to keep the rollback journal", mode, readDB != nil)
	}
	if !strings.Contains(logs.String(), walUnavailableWarning) || !strings.Contains(logs.String(), "journal_mode=delete") {
		t.Fatalf("refused WAL logged %q, want the WAL warning", logs.String())
	}
}
