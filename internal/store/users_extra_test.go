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

func TestRevokeUserInvitesIgnoresExpiredLinks(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	user, err := s.CreateUser(ctx, User{Username: "expired-invite", DisplayName: "Expired invite", Role: RoleViewer, PasswordHash: "!pending", Enabled: false}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUserInvite(ctx, "expired-invite-token", user.ID, now.Add(-2*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	affected, err := s.RevokeUserInvitesWithAudit(ctx, user.ID, now, AuditEntry{Action: "user.activation_revoked"})
	if err != nil || affected != 0 {
		t.Fatalf("expired invite revocation = %d, %v", affected, err)
	}
	var audits int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='user.activation_revoked'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 0 {
		t.Fatalf("expired invite produced %d revocation audits", audits)
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

// insertLegacyAdminsRow writes the row of the admins table that schema 52
// retired, as a database changed by hand could still hold it.
func insertLegacyAdminsRow(t *testing.T, s *Store, username, passwordHash string) {
	t.Helper()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO admins(id,username,display_name,password_hash,totp_secret,totp_enabled,created_at,updated_at) VALUES(1,?,?,?,'',0,?,?)`, username, username, passwordHash, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}

// GetAdmin reads the users row only, so a leftover admins row never supplies
// credentials or makes an administrator configured.
func TestGetAdminReadsOnlyTheUsersRow(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if err := s.SaveAdmin(ctx, Admin{Username: "admin", DisplayName: "Administrator", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	insertLegacyAdminsRow(t, s, "admin", "stale-hash")
	admin, err := s.GetAdmin(ctx)
	if err != nil || admin.Username != "admin" || admin.PasswordHash != "hash" || admin.Revision == 0 {
		t.Fatalf("administrator = %#v, %v; want the users row", admin, err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE id=?`, LegacyAdminUserID); err != nil {
		t.Fatal(err)
	}
	if admin, err := s.GetAdmin(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("administrator with only an admins row = %#v, %v; want ErrNotFound", admin, err)
	}
	if configured, err := s.HasAdministrator(ctx); err != nil || configured {
		t.Fatalf("configured with only an admins row = %v, %v; want false", configured, err)
	}
}

func TestGetAdminWorksWithReadOnlyDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "readonly-admin.db")
	writer, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := writer.SaveAdmin(ctx, Admin{Username: "admin", DisplayName: "Administrator", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	if _, err := writer.DB.ExecContext(ctx, `UPDATE users SET totp_secret=?,totp_enabled=1 WHERE id=?`, "legacy-seed", LegacyAdminUserID); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := OpenReadOnlyExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	admin, err := reader.GetAdmin(ctx)
	if err != nil || admin.Username != "admin" || admin.PasswordHash != "hash" || admin.TOTPSecret != "legacy-seed" {
		t.Fatalf("read-only GetAdmin = %#v, %v", admin, err)
	}
	user, err := reader.GetUser(ctx, LegacyAdminUserID)
	if err != nil || user.TOTPSecret != "legacy-seed" {
		t.Fatalf("read-only GetUser = %#v, %v", user, err)
	}
	if _, err := os.Stat(reader.authKeyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only authentication read created a key file: stat err=%v", err)
	}
}

func TestMigrateAdminCompatibilityUpgradesSecretWithoutRecreatingAdminsRow(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if err := s.SaveAdmin(ctx, Admin{Username: "admin", DisplayName: "Old name", PasswordHash: "old-hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET display_name=?,password_hash=?,totp_secret=?,totp_enabled=1 WHERE id=?`, "Current name", "current-hash", "JBSWY3DPEHPK3PXP", LegacyAdminUserID); err != nil {
		t.Fatal(err)
	}
	if err := s.MigrateAdminCompatibility(ctx); err != nil {
		t.Fatalf("migrate administrator compatibility: %v", err)
	}

	var userSecret string
	if err := s.DB.QueryRowContext(ctx, `SELECT totp_secret FROM users WHERE id=?`, LegacyAdminUserID).Scan(&userSecret); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(userSecret, authCiphertextV2) {
		t.Fatalf("administrator secret was not upgraded: %q", userSecret)
	}
	secret, migrate, err := s.openTOTPSecretForOwner(LegacyAdminUserID, userSecret)
	if err != nil || migrate || secret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("upgraded secret = %q, migrate=%v, err=%v", secret, migrate, err)
	}
	// Schema 52 retired the admins row; the startup migration must not write
	// it again.
	var legacyRows int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&legacyRows); err != nil || legacyRows != 0 {
		t.Fatalf("admins rows after the compatibility migration = %d, %v; want 0", legacyRows, err)
	}
}

func TestMigrateAdminCompatibilityRollsBackOnSecretWriteFailure(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if err := s.SaveAdmin(ctx, Admin{Username: "admin", DisplayName: "Old name", PasswordHash: "old-hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET display_name=?,totp_secret=?,totp_enabled=1 WHERE id=?`, "Current name", "JBSWY3DPEHPK3PXP", LegacyAdminUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER reject_totp_migration BEFORE UPDATE OF totp_secret ON users BEGIN SELECT RAISE(ABORT,'migration blocked'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.MigrateAdminCompatibility(ctx); err == nil {
		t.Fatal("TOTP migration write failure was ignored")
	}
	var stored, displayName string
	if err := s.DB.QueryRowContext(ctx, `SELECT totp_secret,display_name FROM users WHERE id=?`, LegacyAdminUserID).Scan(&stored, &displayName); err != nil {
		t.Fatal(err)
	}
	if stored != "JBSWY3DPEHPK3PXP" || displayName != "Current name" {
		t.Fatalf("failed migration partially changed authoritative row: secret=%q name=%q", stored, displayName)
	}
}

// An admins row without a users row is not an administrator any more. The
// startup migration neither restores the users row from it nor rewrites it.
func TestMigrateAdminCompatibilityLeavesLegacyAdminsRowAlone(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	insertLegacyAdminsRow(t, s, "legacy-admin", "legacy-hash")
	if _, err := s.DB.ExecContext(ctx, `UPDATE admins SET totp_secret=?,totp_enabled=1 WHERE id=1`, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	if err := s.MigrateAdminCompatibility(ctx); err != nil {
		t.Fatalf("compatibility migration with only an admins row: %v", err)
	}
	var username, passwordHash, secret string
	if err := s.DB.QueryRowContext(ctx, `SELECT username,password_hash,totp_secret FROM admins WHERE id=1`).Scan(&username, &passwordHash, &secret); err != nil {
		t.Fatal(err)
	}
	if username != "legacy-admin" || passwordHash != "legacy-hash" || secret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("admins row changed: username=%q password=%q secret=%q", username, passwordHash, secret)
	}
	if _, err := s.GetUser(ctx, LegacyAdminUserID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("users row restored from the admins row: %v", err)
	}
}

func TestMigrateAdminCompatibilityAllowsMissingLegacyAdmin(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE id=?`, LegacyAdminUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM admins WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := s.MigrateAdminCompatibility(ctx); err != nil {
		t.Fatalf("missing legacy administrator should be a no-op: %v", err)
	}
}

// The startup migration neither reads nor writes the retired admins table.
func TestMigrateAdminCompatibilityDoesNotUseAdminsTable(t *testing.T) {
	for _, tc := range []struct {
		name       string
		statements []string
	}{
		{name: "table dropped", statements: []string{`DROP TABLE admins`}},
		{name: "writes rejected", statements: []string{
			`CREATE TRIGGER reject_admins_insert BEFORE INSERT ON admins BEGIN SELECT RAISE(ABORT,'admins insert blocked'); END`,
			`CREATE TRIGGER reject_admins_update BEFORE UPDATE ON admins BEGIN SELECT RAISE(ABORT,'admins update blocked'); END`,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := openTestStore(t)
			now := time.Now().UTC()
			if err := s.SaveAdmin(ctx, Admin{Username: "admin", DisplayName: "Old name", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.ExecContext(ctx, `UPDATE users SET display_name=?,totp_secret=?,totp_enabled=1 WHERE id=?`, "Current name", "JBSWY3DPEHPK3PXP", LegacyAdminUserID); err != nil {
				t.Fatal(err)
			}
			for _, statement := range tc.statements {
				if _, err := s.DB.ExecContext(ctx, statement); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.MigrateAdminCompatibility(ctx); err != nil {
				t.Fatalf("compatibility migration: %v", err)
			}
			admin, err := s.GetAdmin(ctx)
			if err != nil || admin.DisplayName != "Current name" || admin.TOTPSecret != "JBSWY3DPEHPK3PXP" || !strings.HasPrefix(admin.TOTPSecretStored, authCiphertextV2) {
				t.Fatalf("administrator after the compatibility migration = %#v, %v", admin, err)
			}
		})
	}
}

func TestMigrateAdminCompatibilityReportsAuthoritativeReadFailure(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `ALTER TABLE users RENAME TO unavailable_users`); err != nil {
		t.Fatal(err)
	}
	if err := s.MigrateAdminCompatibility(ctx); err == nil || !strings.Contains(err.Error(), "read authoritative administrator for compatibility migration") {
		t.Fatalf("authoritative administrator read failure = %v", err)
	}
}

func TestMigrateAdminCompatibilityReturnsBeginError(t *testing.T) {
	s := openTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.MigrateAdminCompatibility(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled migration error = %v, want context canceled", err)
	}
}

func TestMigrateAdminCompatibilityIsANoOpWithoutLegacySecret(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if err := s.SaveAdmin(ctx, Admin{Username: "admin", DisplayName: "Admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.MigrateAdminCompatibility(ctx); err != nil {
		t.Fatalf("compatibility migration without a legacy secret: %v", err)
	}
}

func TestMigrateAdminCompatibilityRejectsUnreadableSecret(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if err := s.SaveAdmin(ctx, Admin{Username: "admin", DisplayName: "Admin", PasswordHash: "hash", TOTPEnabled: true, TOTPSecret: "JBSWY3DPEHPK3PXP", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET totp_secret=? WHERE id=?`, authCiphertextV2+"malformed", LegacyAdminUserID); err != nil {
		t.Fatal(err)
	}
	if err := s.MigrateAdminCompatibility(ctx); err == nil || !strings.Contains(err.Error(), "read administrator TOTP secret for compatibility migration") {
		t.Fatalf("unreadable administrator TOTP secret = %v", err)
	}
}

func TestMigrateAdminCompatibilityReportsSecretSealFailure(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if err := s.SaveAdmin(ctx, Admin{Username: "admin", DisplayName: "Admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET totp_secret=?,totp_enabled=1 WHERE id=?`, "JBSWY3DPEHPK3PXP", LegacyAdminUserID); err != nil {
		t.Fatal(err)
	}
	s.authAutoKey = false
	s.authKeyPath = filepath.Join(t.TempDir(), "missing", "auth.key")
	if err := s.MigrateAdminCompatibility(ctx); err == nil || !strings.Contains(err.Error(), "upgrade administrator TOTP secret") {
		t.Fatalf("administrator secret seal failure = %v", err)
	}
	var stored string
	if err := s.DB.QueryRowContext(ctx, `SELECT totp_secret FROM users WHERE id=?`, LegacyAdminUserID).Scan(&stored); err != nil || stored != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("failed upgrade changed the secret: %q, %v", stored, err)
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

func TestConditionalSessionPrimitivesCoverCredentialGuardsWithoutLegacyFallback(t *testing.T) {
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

	// Schema 52 retired the admins row: without its users row the original
	// administrator cannot start a session, even with matching admins
	// credentials.
	if err := s.SaveAdmin(ctx, Admin{Username: "legacy-admin", DisplayName: "Legacy Admin", PasswordHash: "legacy-hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE id=?`, LegacyAdminUserID); err != nil {
		t.Fatal(err)
	}
	insertLegacyAdminsRow(t, s, "legacy-admin", "legacy-hash")
	if err := s.CreateSessionForUserIfCurrent(ctx, LegacyAdminUserID, "legacy-hash", 0, false, "legacy-fallback-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); !errors.Is(err, ErrSessionCredentialsChanged) {
		t.Fatalf("session from the admins row = %v, want ErrSessionCredentialsChanged", err)
	}
	if _, err := s.GetSession(ctx, "legacy-fallback-session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session from the admins row was created: %v", err)
	}
	// A failed read is reported instead of being treated as a changed
	// credential.
	if _, err := s.DB.ExecContext(ctx, `DROP TABLE users`); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForUserIfCurrent(ctx, LegacyAdminUserID, "legacy-hash", 0, false, "missing-users-table-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); err == nil || errors.Is(err, ErrSessionCredentialsChanged) || !strings.Contains(strings.ToLower(err.Error()), "no such table") {
		t.Fatalf("missing users table error = %v", err)
	}
}

func TestConditionalPasswordUpgradeCoversRevisionWithoutLegacyFallback(t *testing.T) {
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
	// Without its users row, the original administrator's admins row neither
	// signs in nor has its password upgraded.
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE id=?`, LegacyAdminUserID); err != nil {
		t.Fatal(err)
	}
	insertLegacyAdminsRow(t, s, "legacy-admin", "fallback-old")
	if err := s.CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx, LegacyAdminUserID, "fallback-old", "fallback-new", 0, false, "legacy-fallback-upgrade-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); !errors.Is(err, ErrSessionCredentialsChanged) {
		t.Fatalf("upgrade from the admins row = %v, want ErrSessionCredentialsChanged", err)
	}
	var legacyHash string
	if err := s.DB.QueryRowContext(ctx, `SELECT password_hash FROM admins WHERE id=1`).Scan(&legacyHash); err != nil || legacyHash != "fallback-old" {
		t.Fatalf("admins password after a refused upgrade = %q, %v", legacyHash, err)
	}
	if _, err := s.GetSession(ctx, "legacy-fallback-upgrade-session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session from the admins row was created: %v", err)
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

	// The original administrator's upgrade writes only its users row: a
	// rejected admins write cannot fail it.
	legacyUpgrade := openTestStore(t)
	if err := legacyUpgrade.SaveAdmin(ctx, Admin{Username: "legacy-admin", DisplayName: "Legacy Admin", PasswordHash: "legacy-old", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	legacy, err := legacyUpgrade.GetUser(ctx, LegacyAdminUserID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyUpgrade.DB.ExecContext(ctx, `CREATE TRIGGER fail_admin_sync BEFORE UPDATE ON admins BEGIN SELECT RAISE(ABORT, 'legacy sync unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := legacyUpgrade.CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx, LegacyAdminUserID, "legacy-old", "legacy-new", legacy.Revision, false, "legacy-upgrade-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); err != nil {
		t.Fatalf("administrator upgrade = %v", err)
	}
	if upgraded, err := legacyUpgrade.GetUser(ctx, LegacyAdminUserID); err != nil || upgraded.PasswordHash != "legacy-new" {
		t.Fatalf("upgraded administrator = %#v, %v", upgraded, err)
	}

	// A failed read is reported instead of falling back to the admins row.
	noUsers := openTestStore(t)
	if err := noUsers.SaveAdmin(ctx, Admin{Username: "no-users-admin", DisplayName: "No Users Admin", PasswordHash: "no-users-old", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := noUsers.DB.ExecContext(ctx, `DROP TABLE users`); err != nil {
		t.Fatal(err)
	}
	insertLegacyAdminsRow(t, noUsers, "no-users-admin", "no-users-old")
	if err := noUsers.CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx, LegacyAdminUserID, "no-users-old", "no-users-new", 0, false, "no-users-session", "csrf", now, now.Add(time.Hour), AuditEntry{}); err == nil || errors.Is(err, ErrSessionCredentialsChanged) || !strings.Contains(strings.ToLower(err.Error()), "no such table") {
		t.Fatalf("upgrade without a users table = %v", err)
	}
}
