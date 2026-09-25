package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func sqliteUserVersion(t *testing.T, database string) int {
	t.Helper()
	reader, err := store.OpenReadOnlyExisting(database)
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

func setSQLiteUserVersion(t *testing.T, database string, version int) {
	t.Helper()
	db, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version=%d", version)); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func countCLIRows(t *testing.T, database, table string) int {
	t.Helper()
	reader, err := store.OpenReadOnlyExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var rows int
	if err := reader.DB.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

// After a rollback to an older image, the daemon refuses a database that a
// newer release upgraded. The write-capable host commands must refuse it too,
// instead of committing rows into a schema they do not understand.
func TestWriteCommandsRefuseNewerSchema(t *testing.T) {
	for _, tc := range []struct {
		name      string
		withAdmin bool
		args      func(configPath, dir string) []string
	}{
		{name: "admin setup-token", args: func(configPath, _ string) []string {
			return []string{"admin", "setup-token", "--force", "--config", configPath}
		}},
		{name: "admin reset-password", withAdmin: true, args: func(configPath, dir string) []string {
			return []string{"admin", "reset-password", "--config", configPath, "--password-file", filepath.Join(dir, "password")}
		}},
		{name: "admin disable-totp", withAdmin: true, args: func(configPath, _ string) []string {
			return []string{"admin", "disable-totp", "--config", configPath}
		}},
		// Backup writes a security audit row, so it refuses too. A newer
		// database is backed up with the release that upgraded it, or by
		// copying ./data while EdgeWatch is stopped.
		{name: "backup", withAdmin: true, args: func(configPath, dir string) []string {
			return []string{"backup", "--config", configPath, "--out", filepath.Join(dir, "backup.db")}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			database := filepath.Join(dir, "edgewatch.db")
			seed, err := store.Open(database)
			if err != nil {
				t.Fatal(err)
			}
			if tc.withAdmin {
				now := time.Now().UTC()
				if err := seed.SaveAdmin(context.Background(), store.Admin{Username: "admin", DisplayName: "Admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
					seed.Close()
					t.Fatal(err)
				}
			}
			if err := seed.Close(); err != nil {
				t.Fatal(err)
			}
			supported := sqliteUserVersion(t, database)
			setSQLiteUserVersion(t, database, supported+1)
			configPath := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "password"), []byte("replacement administrator password\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			setupTokens := countCLIRows(t, database, "setup_tokens")
			audits := countCLIRows(t, database, "security_audit")
			before := snapshotCLIFile(t, database)

			want := fmt.Sprintf("database schema version %d is newer than supported version %d", supported+1, supported)
			if err := run(tc.args(configPath, dir)); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %v, want %q", err, want)
			}

			assertCLIFileUnchanged(t, database, before)
			if got := countCLIRows(t, database, "setup_tokens"); got != setupTokens {
				t.Fatalf("setup_tokens rows = %d, want %d", got, setupTokens)
			}
			if got := countCLIRows(t, database, "security_audit"); got != audits {
				t.Fatalf("security_audit rows = %d, want %d", got, audits)
			}
			if got := sqliteUserVersion(t, database); got != supported+1 {
				t.Fatalf("user_version = %d, want %d", got, supported+1)
			}
			if _, err := os.Stat(filepath.Join(dir, "backup.db")); !os.IsNotExist(err) {
				t.Fatalf("a backup of the newer schema was written (stat err=%v)", err)
			}
		})
	}
}
