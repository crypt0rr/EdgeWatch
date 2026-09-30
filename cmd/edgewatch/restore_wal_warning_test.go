package main

import (
	"bytes"
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// A backup made by edgewatch backup is in rollback-journal mode. Restoring
// it, and running a host command on the restored database before the
// daemon's next start, does not warn that WAL is unavailable: none of these
// opens asks for WAL, and the filesystem supports it.
func TestRestoreOfABackupLogsNoWALWarning(t *testing.T) {
	database := storetest.FreshPath(t)
	dir := filepath.Dir(database)
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(dir, "backups", "edgewatch-backup.db")
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := captureCLIOutput(t, func() error {
		return run([]string{"backup", "--config", configPath, "--out", backupPath, "--output", "json"})
	}); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if mode := cliJournalMode(t, backupPath); mode != "delete" {
		t.Fatalf("backup journal_mode = %q, want delete", mode)
	}

	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	for _, args := range [][]string{
		{"restore", "--from", backupPath},
		{"notify", "test"},
	} {
		_, stderr, err := captureCLIOutput(t, func() error {
			return run(append(args, "--config", configPath, "--output", "json"))
		})
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if strings.Contains(stderr, "SQLite WAL is unavailable") {
			t.Fatalf("%v warned that WAL is unavailable: %s", args, stderr)
		}
	}
	if strings.Contains(logs.String(), "SQLite WAL is unavailable") {
		t.Fatalf("restore warned that WAL is unavailable: %s", logs.String())
	}
}

func cliJournalMode(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	return mode
}
