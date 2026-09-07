package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSetupTokenAndAdministratorCompatibilityLifecycle(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	if _, err := s.GetSetupToken(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing setup token error = %v", err)
	}
	if err := s.PutSetupTokenAt(ctx, "setup-hash", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	token, err := s.GetSetupToken(ctx)
	if err != nil || token.Used || !token.ExpiresAt.Equal(now.Add(time.Hour)) || !token.IssuedAt.Equal(now) {
		t.Fatalf("setup token = %#v, %v", token, err)
	}
	if err := s.ConsumeSetupToken(ctx, "setup-hash", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	token, err = s.GetSetupToken(ctx)
	if err != nil || !token.Used {
		t.Fatalf("consumed setup token = %#v, %v", token, err)
	}
	if err := s.ConsumeSetupToken(ctx, "setup-hash", now.Add(2*time.Minute)); err == nil {
		t.Fatal("setup token was consumed twice")
	}
	if err := s.PutSetupToken(ctx, "expired-hash", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeSetupToken(ctx, "expired-hash", now); err == nil {
		t.Fatal("expired setup token was accepted")
	}
	if configured, err := s.HasAdministrator(ctx); err != nil || configured {
		t.Fatalf("empty administrator state = %v, %v", configured, err)
	}
	admin := Admin{Username: "admin", DisplayName: "Administrator", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}
	if err := s.SaveAdmin(ctx, admin); err != nil {
		t.Fatal(err)
	}
	if configured, err := s.HasAdministrator(ctx); err != nil || !configured {
		t.Fatalf("configured administrator state = %v, %v", configured, err)
	}
	loaded, err := s.GetAdmin(ctx)
	if err != nil || loaded.Username != "admin" || loaded.DisplayName != "Administrator" {
		t.Fatalf("loaded administrator = %#v, %v", loaded, err)
	}
}

func TestSaveAdminRollsBackLegacyRowWhenUserSyncFails(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_admin_user_sync BEFORE INSERT ON users WHEN NEW.username='rollback-admin' BEGIN SELECT RAISE(ABORT, 'user sync unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	err := s.SaveAdmin(ctx, Admin{Username: "rollback-admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now})
	if err == nil {
		t.Fatal("SaveAdmin unexpectedly succeeded with a failing user sync")
	}
	if _, err := s.GetAdmin(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("legacy admin row survived rollback: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TRIGGER fail_admin_user_sync`); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAdmin(ctx, Admin{Username: "rollback-admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
}

func TestSetupTokenReissueAndCompleteSetup(t *testing.T) {
	ctx := context.Background()
	reissue := openTestStore(t)
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	if err := reissue.ReissueSetupToken(ctx, "first-reissue", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := reissue.ReissueSetupToken(ctx, "too-soon", now.Add(2*time.Hour), now.Add(30*time.Second)); !errors.Is(err, ErrSetupTokenRateLimited) {
		t.Fatalf("early reissue error = %v", err)
	}
	if err := reissue.ReissueSetupToken(ctx, "second-reissue", now.Add(2*time.Hour), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := reissue.SaveAdmin(ctx, Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := reissue.ReissueSetupToken(ctx, "after-admin", now.Add(3*time.Hour), now.Add(2*time.Minute)); err == nil {
		t.Fatal("setup token reissued after administrator creation")
	}

	complete := openTestStore(t)
	if err := complete.PutSetupTokenAt(ctx, "complete-hash", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	admin := Admin{Username: "admin", DisplayName: "", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}
	if err := complete.CompleteSetup(ctx, "complete-hash", admin, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if configured, err := complete.HasAdministrator(ctx); err != nil || !configured {
		t.Fatalf("completed setup state = %v, %v", configured, err)
	}
	if err := complete.CompleteSetup(ctx, "complete-hash", admin, now.Add(2*time.Minute)); err == nil {
		t.Fatal("completed setup token was reusable")
	}
}

func TestSessionAndRecoveryCodeStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := s.SaveAdmin(ctx, Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, "legacy-session", "csrf", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	session, err := s.GetSession(ctx, "legacy-session")
	if err != nil || session.UserID != LegacyAdminUserID || session.CSRFToken != "csrf" {
		t.Fatalf("legacy session = %#v, %v", session, err)
	}
	if err := s.TouchSession(ctx, "legacy-session", now.Add(time.Minute), now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	updated, err := s.GetSession(ctx, "legacy-session")
	if err != nil || !updated.LastSeenAt.Equal(now.Add(time.Minute)) || !updated.ExpiresAt.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("touched session = %#v, %v", updated, err)
	}
	if err := s.DeleteSessionWithAudit(ctx, "legacy-session", "admin.logout", "logout"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "legacy-session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted session = %v", err)
	}

	if err := s.SaveRecoveryCodes(ctx, []string{"legacy-code"}); err != nil {
		t.Fatal(err)
	}
	if count, err := s.RecoveryCodeCount(ctx); err != nil || count != 1 {
		t.Fatalf("recovery count = %d, %v", count, err)
	}
	if ok, err := s.ConsumeRecoveryCode(ctx, "legacy-code", now); err != nil || !ok {
		t.Fatalf("legacy recovery consume = %v, %v", ok, err)
	}
	if ok, err := s.ConsumeRecoveryCode(ctx, "legacy-code", now.Add(time.Second)); err != nil || ok {
		t.Fatalf("reused legacy recovery code = %v, %v", ok, err)
	}
	user, err := s.CreateUser(ctx, User{Username: "operator", DisplayName: "Operator", Role: RoleOperator, PasswordHash: "hash", Enabled: true}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRecoveryCodesForUser(ctx, user.ID, []string{"user-code"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ConsumeRecoveryCodeForUser(ctx, LegacyAdminUserID, "user-code", now); err != nil || ok {
		t.Fatalf("wrong-user recovery consume = %v, %v", ok, err)
	}
	if ok, err := s.ConsumeRecoveryCodeForUser(ctx, user.ID, "user-code", now); err != nil || !ok {
		t.Fatalf("user recovery consume = %v, %v", ok, err)
	}
	if err := s.Audit(ctx, "test.audit", "detail"); err != nil {
		t.Fatal(err)
	}
	if err := s.AuditEntry(ctx, AuditEntry{Action: "test.audit.actor", Detail: "detail", ActorUserID: user.ID, ActorUsername: user.Username}); err != nil {
		t.Fatal(err)
	}
	if err := s.AuditEntry(ctx, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, "expired-session", "csrf", now.Add(-2*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if deleted, err := s.DeleteExpiredSessions(ctx, now); err != nil || deleted != 1 {
		t.Fatalf("expired session deletion = %d, %v", deleted, err)
	}
	if err := s.DeleteAllSessionsWithAudit(ctx, "admin.sessions_revoked", "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, "delete-wrapper", "csrf", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(ctx, "delete-wrapper"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, "delete-all-wrapper", "csrf", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAllSessions(ctx); err != nil {
		t.Fatal(err)
	}
}
