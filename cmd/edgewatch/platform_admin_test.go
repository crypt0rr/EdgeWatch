package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// The host issues the platform setup token once the first administrator
// exists. The printed token creates a platform administrator, after which no
// token is issued; an unused token is replaced only with --force. The host CLI
// stays the break-glass path for a platform administrator, whose password
// and TOTP it resets in platform scope.
func TestAdminPlatformSetupToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	database := storetest.FreshPath(t)
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.SaveAdmin(ctx, store.Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"admin", "platform-setup-token", "--config", configPath}); err != nil {
		t.Fatalf("platform setup token: %v", err)
	}
	if got := countCLIRows(t, database, "setup_tokens"); got != 1 {
		t.Fatalf("the platform setup token wrote %d setup token rows, want 1", got)
	}

	s, err = store.OpenExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// An unused token is replaced only when confirmed.
	if _, err := s.DB.ExecContext(ctx, `UPDATE setup_tokens SET issued_at=?`, now.Add(-2*time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := platformSetupToken(ctx, s, false, &out); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("unconfirmed replacement = %v, want a --force hint", err)
	}
	if err := platformSetupToken(ctx, s, true, &out); err != nil {
		t.Fatal(err)
	}
	printed := strings.TrimSpace(out.String())
	const prefix = "EdgeWatch platform setup token (valid for 15 minutes): "
	if !strings.HasPrefix(printed, prefix) || len(printed) == len(prefix) {
		t.Fatalf("printed token = %q", printed)
	}
	manager := auth.NewManager(s)
	const password = "platform administrator password"
	root, err := manager.CompletePlatformSetup(ctx, strings.TrimPrefix(printed, prefix), "root", password)
	if err != nil {
		t.Fatalf("redeem the printed token: %v", err)
	}
	if err := run([]string{"admin", "platform-setup-token", "--force", "--config", configPath}); !errors.Is(err, store.ErrPlatformAdminConfigured) {
		t.Fatalf("token with a platform administrator = %v, want ErrPlatformAdminConfigured", err)
	}

	// Break-glass recovery of the platform administrator.
	root.TOTPEnabled, root.TOTPSecret = true, "JBSWY3DPEHPK3PXP"
	if err := s.Platform().Account(root.ID).SaveUserSecurity(ctx, root, []string{"v2$code"}, true, false, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	passwordPath := filepath.Join(dir, "password")
	if err := os.WriteFile(passwordPath, []byte("replacement platform password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"admin", "reset-password", "--config", configPath, "--username", "root", "--password-file", passwordPath}); err != nil {
		t.Fatalf("reset-password for the platform administrator: %v", err)
	}
	if err := run([]string{"admin", "disable-totp", "--config", configPath, "--username", "root"}); err != nil {
		t.Fatalf("disable-totp for the platform administrator: %v", err)
	}
	recovered, err := s.GetAccount(ctx, root.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !auth.VerifyPassword(recovered.PasswordHash, "replacement platform password") || recovered.TOTPEnabled || recovered.Role != store.RolePlatformAdmin || recovered.TenantID != "" {
		t.Fatalf("platform administrator after recovery = %+v", recovered)
	}
	var audits int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action IN ('user.password_reset','user.totp_disabled') AND tenant_id IS NULL AND actor_kind=? AND actor_username=?`, store.AuditActorHost, hostCLIActor).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("platform recovery audit records = %d, %v; want 2", audits, err)
	}
}
