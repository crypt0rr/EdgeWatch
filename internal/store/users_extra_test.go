package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestUserStoreProfilesSecurityAndSessions(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	admin, err := s.CreateUser(ctx, User{Username: "admin", DisplayName: "", Role: RoleAdministrator, PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if admin.ID == "" {
		t.Fatal("administrator ID was not generated")
	}
	operator, err := s.CreateUser(ctx, User{Username: "operator", DisplayName: "Operator", Role: RoleOperator, PasswordHash: "hash", Enabled: true}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	users, err := s.ListUsers(ctx)
	if err != nil || len(users) != 2 {
		t.Fatalf("users = %#v, %v", users, err)
	}
	if users[0].Username != "admin" || users[0].DisplayName != "admin" || users[0].Pending {
		t.Fatalf("admin summary = %#v", users[0])
	}
	loaded, err := s.GetUserByUsername(ctx, " OPERATOR ")
	if err != nil || loaded.ID != operator.ID {
		t.Fatalf("case-insensitive user lookup = %#v, %v", loaded, err)
	}
	if loaded.Revision != 1 {
		t.Fatalf("new user revision = %d, want 1", loaded.Revision)
	}
	if _, err := s.GetUser(ctx, "missing-user"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user error = %v", err)
	}
	if err := s.SetUserLastLogin(ctx, operator.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForUserWithAudit(ctx, operator.ID, "operator-session", "csrf", now, now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	operator.PasswordHash = "replacement-hash"
	operator.UpdatedAt = now.Add(time.Minute)
	if err := s.UpdateUser(ctx, operator, false, AuditEntry{Action: "user.updated"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserPassword(ctx, operator.ID, "second-hash", true, AuditEntry{Action: "user.password_changed"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "operator-session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("password change left session active: %v", err)
	}
	operator, err = s.GetUser(ctx, operator.ID)
	if err != nil || operator.PasswordHash != "second-hash" || operator.LastLoginAt.IsZero() {
		t.Fatalf("updated operator = %#v, %v", operator, err)
	}
	if err := s.CreateSessionForUserWithAudit(ctx, operator.ID, "operator-session-2", "csrf", now, now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	operator.DisplayName = "Updated operator"
	operator.UpdatedAt = now.Add(2 * time.Minute)
	if err := s.SaveUserSecurity(ctx, operator, []string{"recovery-a", "recovery-b"}, true, true, AuditEntry{Action: "user.security_updated"}); err != nil {
		t.Fatal(err)
	}
	if count, err := s.RecoveryCodeCount(ctx); err != nil || count != 2 {
		t.Fatalf("recovery count after security update = %d, %v", count, err)
	}
	if _, err := s.GetSession(ctx, "operator-session-2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("security update left session active: %v", err)
	}
	if count, err := s.CountEnabledAdministrators(ctx); err != nil || count != 1 {
		t.Fatalf("enabled administrator count = %d, %v", count, err)
	}
	if err := s.DeleteUserSessionsWithAudit(ctx, operator.ID, AuditEntry{Action: "user.sessions_revoked"}); err != nil {
		t.Fatal(err)
	}
	operator, err = s.GetUser(ctx, operator.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveUserSecurity(ctx, operator, nil, true, false, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if count, err := s.RecoveryCodeCount(ctx); err != nil || count != 0 {
		t.Fatalf("empty recovery replacement count = %d, %v", count, err)
	}
	pending, err := s.CreateUser(ctx, User{Username: "pending", DisplayName: "Pending", Role: RoleViewer, PasswordHash: "!pending", Enabled: false}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUserInvite(ctx, "consume-invite", pending.ID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	consumed, err := s.ConsumeUserInvite(ctx, "consume-invite", now.Add(time.Minute))
	if err != nil || consumed.ID != pending.ID {
		t.Fatalf("consumed invite = %#v, %v", consumed, err)
	}
	if _, err := s.ConsumeUserInvite(ctx, "consume-invite", now.Add(2*time.Minute)); err == nil {
		t.Fatal("consumed invite was reusable")
	}
}

func TestSecuritySaveCanPreserveActingSessionWhileRevokingOthers(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	user, err := s.CreateUser(ctx, User{Username: "totp-user", DisplayName: "TOTP User", Role: RoleViewer, PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForUserWithAudit(ctx, user.ID, "current-session", "csrf", now, now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForUserWithAudit(ctx, user.ID, "other-session", "csrf", now, now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	user.TOTPEnabled = false
	user.UpdatedAt = now.Add(time.Minute)
	if err := s.SaveUserSecurityPreservingSession(ctx, user, []string{"recovery"}, true, true, AuditEntry{}, "current-session"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "current-session"); err != nil {
		t.Fatalf("acting session was revoked: %v", err)
	}
	if _, err := s.GetSession(ctx, "other-session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other session remains after security save: %v", err)
	}
}

func TestSecuritySaveAppliesDisableTransitionsAtomically(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	user, err := s.CreateUser(ctx, User{Username: "disable-transition", DisplayName: "Disable transition", Role: RoleViewer, PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUserInvite(ctx, "disable-invite", user.ID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForUserWithAudit(ctx, user.ID, "disable-session", "csrf", now, now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	user.Enabled = false
	user.UpdatedAt = now.Add(time.Minute)
	// The transition policy must not depend on callers remembering the
	// revokeSessions hint. Security saves and profile updates share the same
	// transactional behavior.
	if err := s.SaveUserSecurity(ctx, user, nil, false, false, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "disable-session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disable transition left session active: %v", err)
	}
	if _, err := s.ActivateUser(ctx, "disable-invite", "replacement-hash", now.Add(2*time.Minute), AuditEntry{}); err == nil {
		t.Fatal("disable transition left activation invite usable")
	}
}

func TestSecuritySaveRoleTransitionRevokesSessionsWithoutHint(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	user, err := s.CreateUser(ctx, User{Username: "role-transition", DisplayName: "Role transition", Role: RoleViewer, PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForUserWithAudit(ctx, user.ID, "role-session", "csrf", now, now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	user.Role = RoleOperator
	user.UpdatedAt = now.Add(time.Minute)
	if err := s.SaveUserSecurity(ctx, user, nil, false, false, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "role-session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("role transition left session active: %v", err)
	}
}

func TestGetAdminUsesAuthoritativeUserCredentials(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if err := s.SaveAdmin(ctx, Admin{Username: "admin", PasswordHash: "legacy-hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET password_hash=?,display_name=?,updated_at=?,revision=revision+1 WHERE id=?`, "authoritative-hash", "Authoritative Admin", now.Add(time.Minute).Format(time.RFC3339Nano), LegacyAdminUserID); err != nil {
		t.Fatal(err)
	}
	admin, err := s.GetAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if admin.PasswordHash != "authoritative-hash" || admin.DisplayName != "Authoritative Admin" {
		t.Fatalf("GetAdmin returned stale compatibility credentials: %#v", admin)
	}
	if admin.Revision < 2 {
		t.Fatalf("authoritative revision was not returned: %d", admin.Revision)
	}
}

func TestGetAdminFallsBackToAuthoritativeUserWhenCompatibilityRowMissing(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if err := s.SaveAdmin(ctx, Admin{Username: "admin", DisplayName: "Administrator", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM admins WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	admin, err := s.GetAdmin(ctx)
	if err != nil {
		t.Fatalf("GetAdmin failed without compatibility row: %v", err)
	}
	if admin.Username != "admin" || admin.PasswordHash != "hash" || admin.Revision == 0 {
		t.Fatalf("unexpected authoritative administrator: %#v", admin)
	}
}

func TestPasswordUpgradeRaceReturnsTypedConflict(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	user, err := s.CreateUser(ctx, User{Username: "race-user", Role: RoleViewer, PasswordHash: "current-hash", Enabled: true, CreatedAt: now, UpdatedAt: now}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	err = s.CreateSessionForUserWithPasswordUpgrade(ctx, user.ID, "stale-hash", "upgraded-hash", "race-session", "csrf", now, now.Add(time.Hour), AuditEntry{})
	if !errors.Is(err, ErrPasswordChangedDuringLogin) {
		t.Fatalf("password upgrade mismatch error = %v", err)
	}
	if _, err := s.GetSession(ctx, "race-session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed upgrade created a session: %v", err)
	}
}
