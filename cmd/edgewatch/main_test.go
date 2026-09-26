package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestAdminRecoverySkipsMonitorInitialization(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	hash, err := auth.PasswordHash("original administrator password")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAdmin(context.Background(), store.Admin{Username: "admin", PasswordHash: hash, CreatedAt: now, UpdatedAt: now}); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "config.yaml")
	config := `database: ` + database + `
web:
  listen: 0.0.0.0:8080
notifications:
  urls: ["not-a-shoutrrr-url"]
  encryption_key_file: ` + filepath.Join(dir, "missing-notification.key") + `
jobs:
  - name: old-job
    schedule: "not a cron schedule"
`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	passwordPath := filepath.Join(dir, "new-password")
	if err := os.WriteFile(passwordPath, []byte("replacement administrator password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"admin", "reset-password", "--config", configPath, "--password-file", passwordPath}); err != nil {
		t.Fatalf("admin recovery was blocked by monitor configuration: %v", err)
	}

	s, err = store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	admin, err := s.GetAdmin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !auth.VerifyPassword(admin.PasswordHash, "replacement administrator password") {
		t.Fatal("replacement password was not persisted")
	}
	if err := s.CreateSession(context.Background(), "session-hash", "csrf", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"admin", "disable-totp", "--config", configPath}); err != nil {
		t.Fatalf("admin TOTP recovery was blocked by monitor configuration: %v", err)
	}
	if _, err := s.GetSession(context.Background(), "session-hash"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("recovery did not invalidate the session: %v", err)
	}
	var audits int
	if err := s.DB.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM security_audit WHERE action IN ('admin.password_reset','admin.totp_disabled')`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 2 {
		t.Fatalf("recovery audit rows = %d, want two", audits)
	}
}

// Since schema 52 the original administrator exists only as a users row. The
// host recovery commands reset its password and disable its TOTP there, keep
// it in the default tenant, and never write the retired admins table.
func TestAdminRecoveryAfterAdminsRetirement(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	manager := auth.NewManager(s)
	token, err := manager.EnsureSetupToken(ctx)
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := manager.Setup(ctx, token, "original administrator password"); err != nil {
		s.Close()
		t.Fatal(err)
	}
	admin, err := s.GetAdmin(ctx)
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	admin.TOTPSecret, admin.TOTPEnabled = "JBSWY3DPEHPK3PXP", true
	if err := s.SaveAdminSecurityWithAudit(ctx, admin, []string{"v2$recovery"}, true, false, store.AuditEntry{}); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\nweb:\n  listen: 0.0.0.0:8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	passwordPath := filepath.Join(dir, "new-password")
	if err := os.WriteFile(passwordPath, []byte("replacement administrator password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"admin", "reset-password", "--config", configPath, "--password-file", passwordPath}); err != nil {
		t.Fatalf("admin reset-password: %v", err)
	}
	if err := run([]string{"admin", "disable-totp", "--config", configPath}); err != nil {
		t.Fatalf("admin disable-totp: %v", err)
	}

	s, err = store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	admin, err = s.GetAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !auth.VerifyPassword(admin.PasswordHash, "replacement administrator password") || admin.TOTPEnabled || admin.TOTPSecretStored != "" {
		t.Fatalf("administrator after recovery = %#v", admin)
	}
	var legacyRows, recoveryCodes, audits int
	var tenant string
	if err := s.DB.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM admins),(SELECT COUNT(*) FROM recovery_codes WHERE user_id=?),(SELECT COUNT(*) FROM security_audit WHERE action IN ('admin.password_reset','admin.totp_disabled') AND actor_username='host-cli'),(SELECT tenant_id FROM users WHERE id=?)`, store.LegacyAdminUserID, store.LegacyAdminUserID).Scan(&legacyRows, &recoveryCodes, &audits, &tenant); err != nil {
		t.Fatal(err)
	}
	if legacyRows != 0 || recoveryCodes != 0 || audits != 2 || tenant != store.DefaultTenantID {
		t.Fatalf("after recovery: admins rows %d, recovery codes %d, audits %d, tenant %q", legacyRows, recoveryCodes, audits, tenant)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "192.0.2.50:9000"
	if raw, user, err := auth.NewManager(s).LoginAs(ctx, request, "admin", "replacement administrator password", "", ""); err != nil || raw == "" || user.ID != store.LegacyAdminUserID {
		t.Fatalf("login with the recovered password = %q %#v, %v", raw, user, err)
	}
}
