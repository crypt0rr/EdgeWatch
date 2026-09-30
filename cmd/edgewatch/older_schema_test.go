package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// olderSchemaVersion is the schema of the last release before business
// units (v0.19).
const olderSchemaVersion = 50

// writeOlderSchemaDatabase writes a database with the original
// administrator, as a release before business units left it: its schema
// version is 50 and it has no tenants table, which schema 51 adds.
func writeOlderSchemaDatabase(t *testing.T, database string) {
	t.Helper()
	raw, err := os.ReadFile(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(database, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := store.OpenExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.SaveAdmin(context.Background(), store.Admin{Username: "admin", DisplayName: "Admin", PasswordHash: "original-hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range []string{"DROP TABLE tenants", fmt.Sprintf("PRAGMA user_version=%d", olderSchemaVersion)} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

type olderSchemaState struct {
	userVersion  int
	passwordHash string
	audits       int
	setupTokens  int
}

func readOlderSchemaState(t *testing.T, database string) olderSchemaState {
	t.Helper()
	var state olderSchemaState
	state.userVersion = sqliteUserVersion(t, database)
	state.audits = countCLIRows(t, database, "security_audit")
	state.setupTokens = countCLIRows(t, database, "setup_tokens")
	reader, err := store.OpenReadOnlyExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := reader.DB.QueryRow(`SELECT password_hash FROM users WHERE username='admin'`).Scan(&state.passwordHash); err != nil {
		t.Fatal(err)
	}
	return state
}

// The host commands that act on business units or accounts need the current
// schema. On a database that this release has not migrated yet, such as a
// restored backup of an older release before the daemon's first start, they
// stop with a message that names the schema and the daemon, and write
// nothing, instead of reporting an existing account as missing or failing
// with an SQL error.
func TestHostCommandsRefuseADatabaseThatIsNotUpgradedYet(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "older.db")
	writeOlderSchemaDatabase(t, fixture)
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "admin reset-password", args: []string{"admin", "reset-password", "--username", "admin", "--password-file", "PASSWORD"}},
		{name: "admin disable-totp", args: []string{"admin", "disable-totp", "--username", "admin"}},
		{name: "admin setup-token", args: []string{"admin", "setup-token", "--force"}},
		{name: "admin platform-setup-token", args: []string{"admin", "platform-setup-token"}},
		{name: "status", args: []string{"status"}},
		{name: "history", args: []string{"history"}},
		{name: "baseline export", args: []string{"baseline", "export", "--out", "EXPORT"}},
		{name: "notify test", args: []string{"notify", "test"}},
		{name: "scan", args: []string{"scan", "--job", "edge"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			database := filepath.Join(dir, "edgewatch.db")
			raw, err := os.ReadFile(fixture)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(database, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			passwordFile := filepath.Join(dir, "password")
			if err := os.WriteFile(passwordFile, []byte("replacement administrator password\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			exportPath := filepath.Join(dir, "export.json")
			args := make([]string, 0, len(tc.args)+4)
			for _, arg := range tc.args {
				arg = strings.NewReplacer("PASSWORD", passwordFile, "EXPORT", exportPath).Replace(arg)
				args = append(args, arg)
			}
			args = append(args, "--config", configPath, "--output", "json")
			before := readOlderSchemaState(t, database)

			stdout, _, err := captureCLIOutput(t, func() error { return run(args) })
			want := fmt.Sprintf("database schema version %d has not been upgraded to version %d yet", olderSchemaVersion, sqliteUserVersionSupported(t))
			if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "start the daemon") || strings.Contains(err.Error(), "is not configured") {
				t.Fatalf("error = %v, want %q with the advice to start the daemon", err, want)
			}
			if stdout != "" {
				t.Fatalf("refused command printed %q", stdout)
			}
			if after := readOlderSchemaState(t, database); after != before {
				t.Fatalf("refused command changed the database: before %+v, after %+v", before, after)
			}
			if _, statErr := os.Stat(exportPath); !os.IsNotExist(statErr) {
				t.Fatalf("refused command wrote an export (stat err=%v)", statErr)
			}
		})
	}
}

// sqliteUserVersionSupported is the schema version of this release: that of
// a freshly migrated database.
func sqliteUserVersionSupported(t *testing.T) int {
	t.Helper()
	return sqliteUserVersion(t, storetest.FreshPath(t))
}

// Commands on the whole database still work on an older schema: restore
// accepts an older backup and audits the restore, verify inspects it, and
// backup copies it, so the operator can keep the pre-upgrade copy. The
// commands that act on units or accounts wait for the daemon's upgrade.
func TestWholeDatabaseCommandsAcceptAnOlderSchema(t *testing.T) {
	dir := t.TempDir()
	// The staged restore passes the foreign key check only with the tenants
	// table, so this backup keeps the current tables under the older
	// schema version; the store tests cover the audit of a restore on the
	// schema-50 tables.
	source := storetest.FreshPath(t)
	setSQLiteUserVersion(t, source, olderSchemaVersion)
	database := filepath.Join(dir, "data", "edgewatch.db")
	if err := os.MkdirAll(filepath.Dir(database), 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := captureCLIOutput(t, func() error {
		return run([]string{"restore", "--config", configPath, "--from", source, "--output", "json"})
	}); err != nil {
		t.Fatalf("restore of an older backup: %v", err)
	}
	if got := sqliteUserVersion(t, database); got != olderSchemaVersion {
		t.Fatalf("restored user_version = %d, want %d", got, olderSchemaVersion)
	}
	reader, err := store.OpenReadOnlyExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	var restores int
	err = reader.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE action='database.restore'`).Scan(&restores)
	reader.Close()
	if err != nil || restores != 1 {
		t.Fatalf("database.restore audit rows = %d, %v; want 1", restores, err)
	}
	for _, args := range [][]string{
		{"verify"},
		{"backup", "--out", filepath.Join(dir, "data", "backup.db")},
	} {
		if _, _, err := captureCLIOutput(t, func() error {
			return run(append(args, "--config", configPath, "--output", "json"))
		}); err != nil {
			t.Fatalf("%v on an older schema: %v", args, err)
		}
	}
	if err := run([]string{"status", "--config", configPath, "--output", "json"}); !errors.Is(err, store.ErrSchemaUpgradePending) {
		t.Fatalf("status on the restored older schema = %v, want ErrSchemaUpgradePending", err)
	}
	if got := sqliteUserVersion(t, database); got != olderSchemaVersion {
		t.Fatalf("user_version after the host commands = %d, want %d", got, olderSchemaVersion)
	}
}

// Account recovery says that a user is not configured only when the account
// does not exist, and reports any other failure as it is.
func TestAdminRecoveryReportsLookupFailuresAsTheyAre(t *testing.T) {
	database := storetest.FreshPath(t)
	s, err := store.OpenExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.SaveAdmin(context.Background(), store.Admin{Username: "admin", DisplayName: "Admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(database)
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"admin", "disable-totp", "--username", "nobody", "--config", configPath}); err == nil || err.Error() != `user "nobody" is not configured` {
		t.Fatalf("unknown account error = %v", err)
	}
	if err := run([]string{"admin", "disable-totp", "--username", "bad/name", "--config", configPath}); err == nil || strings.Contains(err.Error(), "is not configured") || !strings.Contains(err.Error(), `must not contain`) {
		t.Fatalf("invalid username error = %v, want the username rule", err)
	}
	// A current schema whose tenants table cannot be read fails with the
	// database error, not with a missing account.
	db, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE tenants RENAME TO tenants_unreadable`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"admin", "disable-totp", "--username", "admin", "--config", configPath}); err == nil || strings.Contains(err.Error(), "is not configured") || !strings.Contains(err.Error(), "no such table") {
		t.Fatalf("unreadable unit error = %v, want the database error", err)
	}
}
