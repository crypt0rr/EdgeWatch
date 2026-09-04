package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTOTPSecretIsEncryptedAndReloadable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	s, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	secret := "JBSWY3DPEHPK3PXP"
	now := time.Now().UTC()
	if err := s.SaveAdmin(ctx, Admin{Username: "admin", PasswordHash: "hash", TOTPSecret: secret, TOTPEnabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := s.DB.QueryRowContext(ctx, `SELECT totp_secret FROM admins WHERE id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, authCiphertext) || strings.Contains(stored, secret) {
		t.Fatalf("stored TOTP secret was not encrypted: %q", stored)
	}
	info, err := os.Stat(filepath.Join(dir, "auth.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("auth key permissions = %o, want 600", info.Mode().Perm())
	}
	got, err := s.GetAdmin(ctx)
	if err != nil || got.TOTPSecret != secret || got.TOTPSecretError != nil {
		t.Fatalf("decrypted admin = %#v, err=%v", got, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err = s.GetAdmin(ctx)
	if err != nil || got.TOTPSecret != secret || got.TOTPSecretError != nil {
		t.Fatalf("reloaded admin = %#v, err=%v", got, err)
	}
}

func TestDefaultAuthKeyPathRecognizesSQLiteMemoryURIs(t *testing.T) {
	for _, database := range []string{":memory:", "file::memory:?cache=shared", "file:shared?mode=memory&cache=shared"} {
		if path := defaultAuthKeyPath(database); path != "" {
			t.Fatalf("memory database %q unexpectedly selected an auth key path %q", database, path)
		}
	}
}

func TestTOTPSecretKeyLossFailsClosedAndPreservesCiphertext(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	s, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	secret := "JBSWY3DPEHPK3PXP"
	now := time.Now().UTC()
	if err := s.SaveAdmin(ctx, Admin{Username: "admin", PasswordHash: "hash", TOTPSecret: secret, TOTPEnabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "auth.key")); err != nil {
		t.Fatal(err)
	}
	s, err = Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	locked, err := s.GetAdmin(ctx)
	if err != nil || !locked.TOTPEnabled || locked.TOTPSecret != "" || !errors.Is(locked.TOTPSecretError, ErrTOTPSecretLocked) {
		t.Fatalf("key loss did not fail closed: %#v, err=%v", locked, err)
	}
	locked.PasswordHash = "new-hash"
	locked.UpdatedAt = time.Now().UTC()
	if err := s.SaveAdmin(ctx, locked); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := s.DB.QueryRowContext(ctx, `SELECT totp_secret FROM admins WHERE id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "" || !strings.HasPrefix(stored, authCiphertext) {
		t.Fatalf("unrelated admin update overwrote encrypted TOTP secret: %q", stored)
	}
}
