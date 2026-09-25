package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func writeAuthKeyFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}
}

// occupiedLoopbackAddress returns a loopback address that is already bound. A
// daemon configured with it completes startup, including the administrator
// compatibility migration, and then fails at listen time instead of serving.
func occupiedLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String()
}

// The daemon migrates the setup administrator's TOTP seed before app.New
// runs. It must use web.auth_key_file for that migration: the default key
// beside the database is either absent (the daemon refused to start) or would
// be created as a stray key that the configured key cannot open.
func TestDaemonCompatibilityMigrationUsesConfiguredAuthKey(t *testing.T) {
	const seedSecret = "JBSWY3DPEHPK3PXP"
	for _, tc := range []struct {
		name      string
		plaintext bool
	}{
		{name: "sealed seed", plaintext: false},
		{name: "plaintext legacy seed", plaintext: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			dataDir := filepath.Join(dir, "data")
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			database := filepath.Join(dataDir, "edgewatch.db")
			keyPath := filepath.Join(dir, "secrets", "auth.key")
			writeAuthKeyFile(t, keyPath)

			seed, err := store.Open(database)
			if err != nil {
				t.Fatal(err)
			}
			seed.SetAuthKeyPath(keyPath)
			now := time.Now().UTC()
			if err := seed.SaveAdmin(ctx, store.Admin{Username: "admin", DisplayName: "Admin", PasswordHash: "hash", TOTPSecret: seedSecret, TOTPEnabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
				seed.Close()
				t.Fatal(err)
			}
			if tc.plaintext {
				// Databases upgraded from v0.3/v0.4 still hold the raw seed.
				if _, err := seed.DB.ExecContext(ctx, `UPDATE users SET totp_secret=? WHERE id=?`, seedSecret, store.LegacyAdminUserID); err != nil {
					seed.Close()
					t.Fatal(err)
				}
				if _, err := seed.DB.ExecContext(ctx, `UPDATE admins SET totp_secret=? WHERE id=1`, seedSecret); err != nil {
					seed.Close()
					t.Fatal(err)
				}
			}
			if err := seed.Close(); err != nil {
				t.Fatal(err)
			}

			listen := occupiedLoopbackAddress(t)
			configPath := filepath.Join(dir, "config.yaml")
			contents := fmt.Sprintf("database: %s\nweb:\n  listen: %s\n  auth_key_file: %s\nupdates:\n  enabled: false\nenrichment:\n  rdap:\n    enabled: false\n", database, listen, keyPath)
			if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}

			err = run([]string{"daemon", "--config", configPath})
			if err == nil || strings.Contains(err.Error(), "migrate administrator compatibility state") || !strings.Contains(err.Error(), "address already in use") {
				t.Fatalf("daemon did not get past startup to the listener: %v", err)
			}
			if _, statErr := os.Stat(filepath.Join(dataDir, "auth.key")); !os.IsNotExist(statErr) {
				t.Fatalf("daemon created a default auth.key beside the database despite web.auth_key_file (stat err=%v)", statErr)
			}

			check, err := store.Open(database)
			if err != nil {
				t.Fatal(err)
			}
			defer check.Close()
			check.SetAuthKeyPath(keyPath)
			admin, err := check.GetAdmin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if admin.TOTPSecretError != nil || admin.TOTPSecret != seedSecret {
				t.Fatalf("configured key cannot open the TOTP seed after startup: secret=%q err=%v", admin.TOTPSecret, admin.TOTPSecretError)
			}
			if !strings.HasPrefix(admin.TOTPSecretStored, "ew") {
				t.Fatalf("TOTP seed is not sealed after startup: stored prefix %.4q", admin.TOTPSecretStored)
			}
		})
	}
}

// An unusable configured key is reported as such before the migration runs,
// instead of surfacing as a TOTP decryption failure.
func TestDaemonValidatesConfiguredAuthKeyBeforeMigration(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	keyPath := filepath.Join(dir, "secrets", "auth.key")
	writeAuthKeyFile(t, keyPath)
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	seed, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	contents := fmt.Sprintf("database: %s\nweb:\n  listen: %s\n  auth_key_file: %s\nupdates:\n  enabled: false\n", database, occupiedLoopbackAddress(t), keyPath)
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"daemon", "--config", configPath}); err == nil || !strings.Contains(err.Error(), "validate authentication key file") {
		t.Fatalf("daemon error = %v, want an authentication key validation error", err)
	}
}

// Host recovery commands also seal TOTP secrets before app.New would run, so
// they must use web.auth_key_file too.
func TestAdminRecoveryUsesConfiguredAuthKey(t *testing.T) {
	const seedSecret = "JBSWY3DPEHPK3PXP"
	ctx := context.Background()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(dataDir, "edgewatch.db")
	keyPath := filepath.Join(dir, "secrets", "auth.key")
	writeAuthKeyFile(t, keyPath)
	seed, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	seed.SetAuthKeyPath(keyPath)
	now := time.Now().UTC()
	if err := seed.SaveAdmin(ctx, store.Admin{Username: "admin", DisplayName: "Admin", PasswordHash: "hash", TOTPSecret: seedSecret, TOTPEnabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		seed.Close()
		t.Fatal(err)
	}
	// A plaintext legacy seed is re-sealed when the password is reset.
	if _, err := seed.DB.ExecContext(ctx, `UPDATE users SET totp_secret=? WHERE id=?`, seedSecret, store.LegacyAdminUserID); err != nil {
		seed.Close()
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("database: %s\nweb:\n  auth_key_file: %s\n", database, keyPath)), 0o600); err != nil {
		t.Fatal(err)
	}
	passwordFile := filepath.Join(dir, "password")
	if err := os.WriteFile(passwordFile, []byte("replacement administrator password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"admin", "reset-password", "--config", configPath, "--password-file", passwordFile}); err != nil {
		t.Fatalf("admin reset-password: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dataDir, "auth.key")); !os.IsNotExist(statErr) {
		t.Fatalf("admin recovery created a default auth.key beside the database (stat err=%v)", statErr)
	}
	check, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	check.SetAuthKeyPath(keyPath)
	admin, err := check.GetAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if admin.TOTPSecretError != nil || admin.TOTPSecret != seedSecret {
		t.Fatalf("configured key cannot open the TOTP seed after password reset: secret=%q err=%v", admin.TOTPSecret, admin.TOTPSecretError)
	}
}
