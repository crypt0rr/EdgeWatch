package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// admin reset-password ends the password-reset links that an administrator
// issued for the account before the reset, for a unit's account and for
// the original administrator, and records each revocation as a host action
// that names the account. Another account's link still works.
func TestHostPasswordResetRevokesTheAccountsLinks(t *testing.T) {
	ctx := context.Background()
	s := storetest.OpenFresh(t)
	now := time.Now().UTC()
	if err := s.SaveAdmin(ctx, store.Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	unit := s.Tenant(store.DefaultTenantScope())
	ids := map[string]string{"admin": store.LegacyAdminUserID}
	for _, account := range []struct{ username, role string }{{"bob", store.RoleAdministrator}, {"alice", store.RoleOperator}, {"carol", store.RoleViewer}} {
		created, err := unit.CreateUser(ctx, store.User{Username: account.username, Role: account.role, PasswordHash: "hash", Enabled: true}, store.AuditEntry{})
		if err != nil {
			t.Fatal(err)
		}
		ids[account.username] = created.ID
	}
	for _, username := range []string{"admin", "alice", "carol"} {
		if err := unit.CreateUserInviteWithAudit(ctx, "link-"+username, ids[username], now, now.Add(30*time.Minute), store.AuditEntry{Action: "user.password_reset_issued", ActorUserID: ids["bob"], ActorUsername: "bob"}); err != nil {
			t.Fatal(err)
		}
	}
	passwordPath := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordPath, []byte("replacement recovery password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	usable := func(hash string) bool {
		t.Helper()
		ok, err := s.ActivationTokenUsable(ctx, hash, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	for _, username := range []string{"alice", "admin"} {
		if err := adminRecovery(ctx, "reset-password", s, passwordPath, username, adminRecoveryOptions{}); err != nil {
			t.Fatalf("reset-password %s: %v", username, err)
		}
		if usable("link-" + username) {
			t.Fatalf("the reset link issued for %s before the host's reset still works", username)
		}
		var kind, actor, detail string
		if err := s.DB.QueryRowContext(ctx, `SELECT actor_kind,actor_username,detail FROM security_audit WHERE action='user.activation_revoked' AND tenant_id=? ORDER BY id DESC LIMIT 1`, store.DefaultTenantID).Scan(&kind, &actor, &detail); err != nil {
			t.Fatalf("revocation record for %s: %v", username, err)
		}
		if kind != store.AuditActorHost || actor != hostCLIActor || !strings.Contains(detail, "revoked for "+username+" ") {
			t.Fatalf("revocation record for %s = %s %s %q", username, kind, actor, detail)
		}
	}
	if !usable("link-carol") {
		t.Fatal("the host's resets revoked another account's link")
	}
}

// A restore marks the backup's outstanding activation links and setup token
// used, so none that was redeemed or replaced after the backup works again.
// The restored database still verifies, and at startup the daemon issues a
// new setup token for the installation that is not set up yet.
func TestRestoreRevokesTheBackupsLinksAndSetupToken(t *testing.T) {
	ctx := context.Background()
	source := storetest.FreshPath(t)
	backup, err := store.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := backup.Platform().PutSetupTokenAt(ctx, "backup-setup-token", now.Add(15*time.Minute), now); err != nil {
		backup.Close()
		t.Fatal(err)
	}
	invitee, err := backup.Tenant(store.DefaultTenantScope()).CreateUser(ctx, store.User{Username: "invitee", Role: store.RoleViewer, PasswordHash: "!pending"}, store.AuditEntry{})
	if err != nil {
		backup.Close()
		t.Fatal(err)
	}
	if err := backup.Tenant(store.DefaultTenantScope()).CreateUserInvite(ctx, "backup-invite", invitee.ID, now, now.Add(30*time.Minute)); err != nil {
		backup.Close()
		t.Fatal(err)
	}
	if err := backup.Close(); err != nil {
		t.Fatal(err)
	}
	database := storetest.FreshPath(t)
	configPath := filepath.Join(filepath.Dir(database), "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := captureCLIOutput(t, func() error {
		return run([]string{"restore", "--config", configPath, "--from", source, "--output", "json"})
	}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, _, err := captureCLIOutput(t, func() error {
		return run([]string{"verify", "--config", configPath, "--output", "json"})
	}); err != nil {
		t.Fatalf("verify the restored database: %v", err)
	}

	if err := store.CheckDaemonLeaseBeforeStartup(ctx, database); err != nil {
		t.Fatalf("startup lease check: %v", err)
	}
	s, err := store.Open(database)
	if err != nil {
		t.Fatalf("open the restored database as the daemon does: %v", err)
	}
	defer s.Close()
	if usable, err := s.ActivationTokenUsable(ctx, "backup-invite", time.Now().UTC()); err != nil || usable {
		t.Fatalf("the backup's activation link usable = %v, %v; want false", usable, err)
	}
	if token, err := s.Platform().GetSetupToken(ctx); err != nil || !token.Used {
		t.Fatalf("the backup's setup token = %+v, %v; want used", token, err)
	}
	// The web server does this when the daemon starts, and logs the token.
	token, err := auth.NewManager(s).EnsureSetupToken(ctx)
	if err != nil || token == "" {
		t.Fatalf("setup token at startup = %q, %v; want a new token", token, err)
	}
	if current, err := s.Platform().GetSetupToken(ctx); err != nil || current.Used {
		t.Fatalf("setup token after startup = %+v, %v; want an unused one", current, err)
	}
}
