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
	if !strings.HasPrefix(stored, authCiphertextV2) || strings.Contains(stored, secret) {
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
	if stored == "" || !strings.HasPrefix(stored, authCiphertextV2) {
		t.Fatalf("unrelated admin update overwrote encrypted TOTP secret: %q", stored)
	}
}

func TestTOTPSecretLegacyValuesMigrateToOwnerBoundCiphertext(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	secret := "JBSWY3DPEHPK3PXP"
	if err := s.SaveAdmin(ctx, Admin{Username: "admin", PasswordHash: "hash", TOTPSecret: secret, TOTPEnabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	legacy, err := s.sealTOTPSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE admins SET totp_secret=? WHERE id=1`, legacy); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAdmin(ctx)
	if err != nil || got.TOTPSecret != secret {
		t.Fatalf("legacy admin secret = %#v, err=%v", got, err)
	}
	var migrated string
	if err := s.DB.QueryRowContext(ctx, `SELECT totp_secret FROM admins WHERE id=1`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(migrated, authCiphertextV2) {
		t.Fatalf("legacy admin ciphertext was not migrated: %q", migrated)
	}
}

func TestTOTPSecretCiphertextIsBoundToUserIdentity(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	secret := "JBSWY3DPEHPK3PXP"
	first, err := s.CreateUser(ctx, User{Username: "first", Role: RoleViewer, PasswordHash: "hash", TOTPSecret: secret, TOTPEnabled: true, Enabled: true}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateUser(ctx, User{Username: "second", Role: RoleViewer, PasswordHash: "hash", TOTPSecret: secret, TOTPEnabled: true, Enabled: true}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	var firstCipher, secondCipher string
	if err := s.DB.QueryRowContext(ctx, `SELECT totp_secret FROM users WHERE id=?`, first.ID).Scan(&firstCipher); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT totp_secret FROM users WHERE id=?`, second.ID).Scan(&secondCipher); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(firstCipher, authCiphertextV2) || !strings.HasPrefix(secondCipher, authCiphertextV2) {
		t.Fatalf("new user secrets are not v2 ciphertexts: %q %q", firstCipher, secondCipher)
	}
	// A copied ciphertext must not authenticate as another account, even when
	// the local encryption key is shared by every user.
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET totp_secret=? WHERE id=?`, firstCipher, second.ID); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.GetUser(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TOTPSecret != "" || !errors.Is(loaded.TOTPSecretError, ErrTOTPSecretLocked) {
		t.Fatalf("copied user ciphertext was accepted: %#v", loaded)
	}
}
