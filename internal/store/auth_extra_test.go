package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSetupTokenAndAdministratorCompatibilityLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	if _, err := s.Platform().GetSetupToken(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing setup token error = %v", err)
	}
	if err := s.Platform().PutSetupTokenAt(ctx, "setup-hash", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	token, err := s.Platform().GetSetupToken(ctx)
	if err != nil || token.Used || !token.ExpiresAt.Equal(now.Add(time.Hour)) || !token.IssuedAt.Equal(now) {
		t.Fatalf("setup token = %#v, %v", token, err)
	}
	if usable, err := s.Platform().SetupTokenUsable(ctx, "setup-hash", now.Add(time.Minute)); err != nil || !usable {
		t.Fatalf("setup token usable = %v, %v", usable, err)
	}
	if err := s.Platform().PutSetupTokenAt(ctx, "expired-hash", now.Add(-time.Minute), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if usable, err := s.Platform().SetupTokenUsable(ctx, "expired-hash", now); err != nil || usable {
		t.Fatalf("expired setup token usable = %v, %v", usable, err)
	}
	if configured, err := s.Platform().HasAdministrator(ctx); err != nil || configured {
		t.Fatalf("empty administrator state = %v, %v", configured, err)
	}
	admin := Admin{Username: "admin", DisplayName: "Administrator", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}
	if err := s.SaveAdmin(ctx, admin); err != nil {
		t.Fatal(err)
	}
	if configured, err := s.Platform().HasAdministrator(ctx); err != nil || !configured {
		t.Fatalf("configured administrator state = %v, %v", configured, err)
	}
	loaded, err := s.GetAdmin(ctx)
	if err != nil || loaded.Username != "admin" || loaded.DisplayName != "Administrator" {
		t.Fatalf("loaded administrator = %#v, %v", loaded, err)
	}
}

func TestTouchSessionIfStaleCoalescesActivity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	created := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	expires := created.Add(30 * 24 * time.Hour)
	if err := createTestSession(ctx, s, LegacyAdminUserID, "activity-session", "csrf", created, expires); err != nil {
		t.Fatal(err)
	}
	refreshed := created.Add(6 * time.Minute)
	touched, err := s.TouchSessionIfStale(ctx, "activity-session", refreshed, expires, created.Add(time.Minute))
	if err != nil || !touched {
		t.Fatalf("stale session touch = %v, %v", touched, err)
	}
	updated, err := s.GetSession(ctx, "activity-session")
	if err != nil || !updated.LastSeenAt.Equal(refreshed) {
		t.Fatalf("refreshed session = %#v, %v", updated, err)
	}
	touched, err = s.TouchSessionIfStale(ctx, "activity-session", refreshed.Add(time.Minute), expires, refreshed.Add(-time.Minute))
	if err != nil || touched {
		t.Fatalf("recent session touch = %v, %v; want false, nil", touched, err)
	}
	touched, err = s.TouchSessionIfStale(ctx, "missing-session", refreshed, expires, refreshed.Add(-time.Minute))
	if err != nil || touched {
		t.Fatalf("missing session touch = %v, %v; want false, nil", touched, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.TouchSessionIfStale(canceled, "activity-session", refreshed.Add(10*time.Minute), expires, refreshed.Add(5*time.Minute)); err == nil {
		t.Fatal("canceled session touch unexpectedly succeeded")
	}
}

func TestSaveAdminFailsWhenUsersRowCannotBeWritten(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_admin_user_write BEFORE INSERT ON users WHEN NEW.username='rollback-admin' BEGIN SELECT RAISE(ABORT, 'user sync unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	err := s.SaveAdmin(ctx, Admin{Username: "rollback-admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now})
	if err == nil {
		t.Fatal("SaveAdmin unexpectedly succeeded with a failing users write")
	}
	if _, err := s.GetAdmin(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("administrator after a failed save: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TRIGGER fail_admin_user_write`); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAdmin(ctx, Admin{Username: "rollback-admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
}

func TestSetupTokenReissueAndCompleteSetup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	reissue := openTestStore(t)
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	if err := reissue.Platform().ReissueSetupToken(ctx, "first-reissue", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := reissue.Platform().ReissueSetupToken(ctx, "too-soon", now.Add(2*time.Hour), now.Add(30*time.Second)); !errors.Is(err, ErrSetupTokenRateLimited) {
		t.Fatalf("early reissue error = %v", err)
	}
	if err := reissue.Platform().ReissueSetupToken(ctx, "second-reissue", now.Add(2*time.Hour), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := reissue.SaveAdmin(ctx, Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := reissue.Platform().ReissueSetupToken(ctx, "after-admin", now.Add(3*time.Hour), now.Add(2*time.Minute)); err == nil {
		t.Fatal("setup token reissued after administrator creation")
	}

	complete := openTestStore(t)
	if err := complete.Platform().PutSetupTokenAt(ctx, "complete-hash", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	admin := Admin{Username: "admin", DisplayName: "", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}
	if err := complete.Platform().CompleteSetup(ctx, "complete-hash", admin, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if configured, err := complete.Platform().HasAdministrator(ctx); err != nil || !configured {
		t.Fatalf("completed setup state = %v, %v", configured, err)
	}
	if err := complete.Platform().CompleteSetup(ctx, "complete-hash", admin, now.Add(2*time.Minute)); err == nil {
		t.Fatal("completed setup token was reusable")
	}
}

func TestSessionAndRecoveryCodeStoreLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := s.SaveAdmin(ctx, Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := createTestSession(ctx, s, LegacyAdminUserID, "legacy-session", "csrf", now, now.Add(time.Hour)); err != nil {
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

	user, err := createTestUser(ctx, defaultTenant(s), User{Username: "operator", DisplayName: "Operator", Role: RoleOperator, PasswordHash: "hash", Enabled: true}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
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
	if err := createTestSession(ctx, s, LegacyAdminUserID, "expired-session", "csrf", now.Add(-2*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if deleted, err := s.DeleteExpiredSessions(ctx, now); err != nil || deleted != 1 {
		t.Fatalf("expired session deletion = %d, %v", deleted, err)
	}
	if err := createTestSession(ctx, s, LegacyAdminUserID, "delete-wrapper", "csrf", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(ctx, "delete-wrapper"); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRevocationRemainsEffectiveWhenAuditInsertFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if err := createTestSession(ctx, s, LegacyAdminUserID, "delete-one", "csrf", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_revocation_audit BEFORE INSERT ON security_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSessionWithAudit(ctx, "delete-one", "session.revoked", "test"); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("single-session audit error = %v", err)
	}
	if _, err := s.GetSession(ctx, "delete-one"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("single session survived audit failure: %v", err)
	}
	user, err := createTestUser(ctx, defaultTenant(s), User{Username: "revoked-user", Role: RoleViewer, PasswordHash: "hash", Enabled: true}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := createTestSession(ctx, s, user.ID, "delete-user", "csrf", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).DeleteUserSessionsWithAudit(ctx, user.ID, AuditEntry{Action: "user.sessions_revoked", Detail: "test"}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("user-session audit error = %v", err)
	}
	if _, err := s.GetSession(ctx, "delete-user"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("user session survived audit failure: %v", err)
	}
}
