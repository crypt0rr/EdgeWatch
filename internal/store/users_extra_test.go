package store

import (
	"context"
	"errors"
	"strings"
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

func TestConditionalSessionPrimitivesCoverCredentialGuardsAndLegacyFallback(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	user, err := s.CreateUser(ctx, User{Username: "conditional", DisplayName: "Conditional", Role: RoleViewer, PasswordHash: "current-hash", Enabled: true, CreatedAt: now, UpdatedAt: now}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	audit := AuditEntry{Action: "auth.session_created", Detail: "conditional session", ActorUserID: user.ID, ActorUsername: user.Username}
	if err := s.CreateSessionForUserIfCurrent(ctx, user.ID, "current-hash", user.Revision, false, "conditional-session", "csrf", now, now.Add(time.Hour), audit); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "conditional-session"); err != nil {
		t.Fatalf("conditional session was not created: %v", err)
	}
	if err := s.CreateSessionForUserIfCurrent(ctx, user.ID, "current-hash", user.Revision, false, "conditional-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); err == nil {
		t.Fatal("duplicate conditional session was accepted")
	}
	if err := s.CreateSessionForUserIfCurrent(ctx, user.ID, "wrong-hash", user.Revision, false, "wrong-hash-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); !errors.Is(err, ErrSessionCredentialsChanged) {
		t.Fatalf("stale password guard = %v", err)
	}
	if err := s.CreateSessionForUserIfCurrent(ctx, user.ID, "current-hash", user.Revision+1, false, "wrong-revision-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); !errors.Is(err, ErrSessionCredentialsChanged) {
		t.Fatalf("stale revision guard = %v", err)
	}
	if err := s.CreateSessionForUserIfCurrent(ctx, user.ID, "current-hash", user.Revision, true, "wrong-totp-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); !errors.Is(err, ErrSessionCredentialsChanged) {
		t.Fatalf("stale TOTP guard = %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET revision=? WHERE id=?`, "corrupt", user.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForUserIfCurrent(ctx, user.ID, "current-hash", user.Revision, false, "corrupt-revision-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); err == nil {
		t.Fatal("corrupt revision was accepted")
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET revision=?,enabled=1 WHERE id=?`, user.Revision, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_conditional_audit BEFORE INSERT ON security_audit WHEN NEW.action='auth.audit_failure' BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	auditUser, err := s.CreateUser(ctx, User{Username: "audit-conditional", Role: RoleViewer, PasswordHash: "audit-hash", Enabled: true, CreatedAt: now, UpdatedAt: now}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForUserIfCurrent(ctx, auditUser.ID, "audit-hash", auditUser.Revision, false, "audit-failure-session", "csrf", now, now.Add(time.Hour), AuditEntry{Action: "auth.audit_failure"}); err == nil {
		t.Fatal("audit failure was swallowed")
	}
	if _, err := s.GetSession(ctx, "audit-failure-session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("audit failure left a session: %v", err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT 1 FROM security_audit WHERE action=?`, "auth.session_created").Scan(new(int)); err != nil {
		t.Fatalf("conditional audit row missing: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET enabled=0 WHERE id=?`, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForUserIfCurrent(ctx, user.ID, "current-hash", user.Revision, false, "disabled-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); !errors.Is(err, ErrSessionCredentialsChanged) {
		t.Fatalf("disabled-user guard = %v", err)
	}
	if err := s.CreateSessionForUserIfCurrent(ctx, "missing-user", "hash", 1, false, "missing-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); !errors.Is(err, ErrSessionCredentialsChanged) {
		t.Fatalf("missing-user guard = %v", err)
	}

	if err := s.SaveAdmin(ctx, Admin{Username: "legacy-admin", DisplayName: "Legacy Admin", PasswordHash: "legacy-hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE id=?`, LegacyAdminUserID); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForUserIfCurrent(ctx, LegacyAdminUserID, "legacy-hash", 0, false, "legacy-fallback-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); err != nil {
		t.Fatalf("legacy compatibility session = %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM admins WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForUserIfCurrent(ctx, LegacyAdminUserID, "legacy-hash", 0, false, "missing-legacy-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); !errors.Is(err, ErrSessionCredentialsChanged) {
		t.Fatalf("missing legacy guard = %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TABLE admins`); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForUserIfCurrent(ctx, LegacyAdminUserID, "legacy-hash", 0, false, "missing-admin-table-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); err == nil || !strings.Contains(strings.ToLower(err.Error()), "no such table") {
		t.Fatalf("missing admin table error = %v", err)
	}
}

func TestConditionalPasswordUpgradeCoversRevisionAndCompatibilityPaths(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Date(2026, 9, 17, 13, 0, 0, 0, time.UTC)
	if err := s.CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx, "missing", "old", " ", 1, false, "blank-upgrade", "csrf", now, now.Add(time.Hour), AuditEntry{}); err == nil {
		t.Fatal("blank upgraded hash was accepted")
	}
	user, err := s.CreateUser(ctx, User{Username: "upgrade", DisplayName: "Upgrade", Role: RoleViewer, PasswordHash: "old-hash", Enabled: true, CreatedAt: now, UpdatedAt: now}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	audit := AuditEntry{Action: "auth.password_upgrade", Detail: "upgraded", ActorUserID: user.ID, ActorUsername: user.Username}
	if err := s.CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx, user.ID, "old-hash", "new-hash", user.Revision, false, "upgrade-session", "csrf", now, now.Add(time.Hour), audit); err != nil {
		t.Fatal(err)
	}
	updated, err := s.GetUser(ctx, user.ID)
	if err != nil || updated.PasswordHash != "new-hash" || updated.Revision != user.Revision+1 {
		t.Fatalf("upgraded user = %#v, %v", updated, err)
	}
	if _, err := s.GetSession(ctx, "upgrade-session"); err != nil {
		t.Fatalf("upgrade session missing: %v", err)
	}
	if err := s.CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx, user.ID, "old-hash", "another-hash", user.Revision, false, "stale-upgrade-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); !errors.Is(err, ErrSessionCredentialsChanged) {
		t.Fatalf("stale upgrade guard = %v", err)
	}

	if err := s.SaveAdmin(ctx, Admin{Username: "legacy-admin", DisplayName: "Legacy Admin", PasswordHash: "legacy-old", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	legacy, err := s.GetUser(ctx, LegacyAdminUserID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx, LegacyAdminUserID, "legacy-old", "legacy-new", legacy.Revision, false, "legacy-upgrade-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); err != nil {
		t.Fatalf("legacy authoritative upgrade = %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE id=?`, LegacyAdminUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE admins SET password_hash=? WHERE id=1`, "fallback-old"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx, LegacyAdminUserID, "fallback-old", "fallback-new", 0, false, "legacy-fallback-upgrade-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); err != nil {
		t.Fatalf("legacy fallback upgrade = %v", err)
	}
	if err := s.CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx, LegacyAdminUserID, "not-current", "unused", 0, false, "legacy-stale-upgrade-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); !errors.Is(err, ErrSessionCredentialsChanged) {
		t.Fatalf("legacy stale upgrade guard = %v", err)
	}
}

func TestConditionalPasswordUpgradeFailurePaths(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 17, 14, 0, 0, 0, time.UTC)

	updateFailure := openTestStore(t)
	user, err := updateFailure.CreateUser(ctx, User{Username: "upgrade-failure", Role: RoleViewer, PasswordHash: "old-hash", Enabled: true, CreatedAt: now, UpdatedAt: now}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := updateFailure.DB.ExecContext(ctx, `CREATE TRIGGER fail_password_upgrade BEFORE UPDATE OF password_hash ON users WHEN NEW.password_hash='trigger-fail' BEGIN SELECT RAISE(ABORT, 'upgrade unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := updateFailure.CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx, user.ID, "old-hash", "trigger-fail", user.Revision, false, "trigger-failure-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); err == nil {
		t.Fatal("password-upgrade trigger failure was swallowed")
	}

	legacyFailure := openTestStore(t)
	if err := legacyFailure.SaveAdmin(ctx, Admin{Username: "legacy-admin", DisplayName: "Legacy Admin", PasswordHash: "legacy-old", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	legacy, err := legacyFailure.GetUser(ctx, LegacyAdminUserID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyFailure.DB.ExecContext(ctx, `CREATE TRIGGER fail_admin_sync BEFORE UPDATE OF password_hash ON admins WHEN NEW.password_hash='trigger-fail' BEGIN SELECT RAISE(ABORT, 'legacy sync unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := legacyFailure.CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx, LegacyAdminUserID, "legacy-old", "trigger-fail", legacy.Revision, false, "legacy-sync-failure-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); err == nil {
		t.Fatal("legacy compatibility update failure was swallowed")
	}

	fallbackFailure := openTestStore(t)
	if err := fallbackFailure.SaveAdmin(ctx, Admin{Username: "fallback-admin", DisplayName: "Fallback Admin", PasswordHash: "fallback-old", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := fallbackFailure.DB.ExecContext(ctx, `DELETE FROM users WHERE id=?`, LegacyAdminUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := fallbackFailure.DB.ExecContext(ctx, `CREATE TRIGGER fail_fallback_sync BEFORE UPDATE OF password_hash ON admins WHEN NEW.password_hash='trigger-fail' BEGIN SELECT RAISE(ABORT, 'fallback sync unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := fallbackFailure.CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx, LegacyAdminUserID, "fallback-old", "trigger-fail", 0, false, "fallback-sync-failure-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); err == nil {
		t.Fatal("legacy fallback update failure was swallowed")
	}

	noUsers := openTestStore(t)
	if err := noUsers.SaveAdmin(ctx, Admin{Username: "no-users-admin", DisplayName: "No Users Admin", PasswordHash: "no-users-old", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := noUsers.DB.ExecContext(ctx, `DROP TABLE users`); err != nil {
		t.Fatal(err)
	}
	if err := noUsers.CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx, LegacyAdminUserID, "no-users-old", "no-users-new", 0, false, "no-users-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); err != nil {
		t.Fatalf("pre-users compatibility upgrade = %v", err)
	}
}
