package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestUsersValidateAndInviteLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	seedDefaultAdministrator(t, s)
	audit := AuditEntry{Action: "user.created", Detail: "created", ActorUserID: LegacyAdminUserID, ActorUsername: "admin"}
	user, err := defaultTenant(s).CreateUserWithInvite(ctx, User{Username: " operator ", DisplayName: "Network operator", Role: RoleOperator, PasswordHash: "!pending", Enabled: true}, "invite-hash", now, now.Add(30*time.Minute), audit)
	if err != nil {
		t.Fatal(err)
	}
	if user.Username != "operator" || user.ID == "" {
		t.Fatalf("created user = %#v", user)
	}
	loaded, err := s.GetUserByUsername(ctx, "OPERATOR")
	if err != nil || loaded.ID != user.ID || loaded.Role != RoleOperator || loaded.Enabled {
		t.Fatalf("loaded user = %#v, err=%v", loaded, err)
	}
	if summary := loaded.Summary(); !summary.Pending || summary.Enabled {
		t.Fatalf("pending summary = %#v", summary)
	}
	var actor string
	if err := s.DB.QueryRowContext(ctx, `SELECT actor_username FROM security_audit WHERE action=?`, "user.created").Scan(&actor); err != nil {
		t.Fatal(err)
	}
	if actor != "admin" {
		t.Fatalf("audit actor = %q", actor)
	}

	if _, err := s.ActivateUser(ctx, "invite-hash", "argon2-hash", now.Add(time.Minute), AuditEntry{Action: "user.activated"}); err != nil {
		t.Fatal(err)
	}
	loaded, err = defaultTenant(s).GetUser(ctx, user.ID)
	if err != nil || loaded.PasswordHash != "argon2-hash" || !loaded.Enabled {
		t.Fatalf("activated user = %#v, err=%v", loaded, err)
	}
	if _, err := s.ActivateUser(ctx, "invite-hash", "another-hash", now.Add(2*time.Minute), AuditEntry{Action: "user.activated"}); err == nil {
		t.Fatal("activation token was reusable")
	}
}

func TestRevokeUserInviteAndDisablePreventActivation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	user, err := createTestUser(ctx, defaultTenant(s), User{Username: "revokable", DisplayName: "Revokable", Role: RoleViewer, PasswordHash: "existing-password-hash", Enabled: true}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := createTestLink(ctx, defaultTenant(s), "invite-to-revoke", user.ID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	seedDefaultAdministrator(t, s)
	affected, err := defaultTenant(s).RevokeUserInvitesWithAudit(ctx, user.ID, now.Add(time.Minute), defaultAdministratorAudit("user.activation_revoked"))
	if err != nil || affected != 1 {
		t.Fatalf("revoked invites = %d, err=%v", affected, err)
	}
	if _, err := s.ActivateUser(ctx, "invite-to-revoke", "replacement-hash", now.Add(2*time.Minute), AuditEntry{}); err == nil {
		t.Fatal("revoked activation invite was accepted")
	}

	if err := createTestLink(ctx, defaultTenant(s), "invite-before-disable", user.ID, now.Add(3*time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	loaded, err := defaultTenant(s).GetUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Enabled = false
	loaded.UpdatedAt = now.Add(4 * time.Minute)
	if err := defaultTenant(s).UpdateUser(ctx, loaded, false, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActivateUser(ctx, "invite-before-disable", "replacement-hash", now.Add(5*time.Minute), AuditEntry{}); err == nil {
		t.Fatal("invite issued before disabling an account was accepted")
	}
}

// A pending account keeps its activation link when its display name is
// edited, but a change of its role revokes the link, as for any account:
// the invitee then needs a new link, which works.
func TestUpdatePendingUserKeepsActivationInviteUntilItsRoleChanges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	seedDefaultAdministrator(t, s)
	user, err := defaultTenant(s).CreateUserWithInvite(ctx, User{Username: "pending-edit", DisplayName: "Pending", Role: RoleViewer, PasswordHash: "!pending"}, "pending-edit-invite", now, now.Add(time.Hour), defaultAdministratorAudit(""))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := defaultTenant(s).GetUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	loaded.DisplayName = "Corrected name"
	loaded.UpdatedAt = now.Add(time.Minute)
	if err := defaultTenant(s).UpdateUser(ctx, loaded, false, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if usable, err := s.ActivationTokenUsable(ctx, "pending-edit-invite", now.Add(2*time.Minute)); err != nil || !usable {
		t.Fatalf("editing the pending account's display name revoked its activation link: %v, %v", usable, err)
	}
	loaded, err = defaultTenant(s).GetUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Role = RoleOperator
	loaded.UpdatedAt = now.Add(2 * time.Minute)
	if err := defaultTenant(s).UpdateUserByAdministrator(ctx, loaded, false, defaultAdministratorAudit("user.updated")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActivateUser(ctx, "pending-edit-invite", "activated-hash", now.Add(3*time.Minute), AuditEntry{}); err == nil {
		t.Fatal("the activation link issued before the role change activated the account")
	}
	if err := defaultTenant(s).CreateUserInviteWithAudit(ctx, "pending-edit-renewed", user.ID, now.Add(3*time.Minute), now.Add(time.Hour), defaultAdministratorAudit("user.activation_issued")); err != nil {
		t.Fatal(err)
	}
	if activated, err := s.ActivateUser(ctx, "pending-edit-renewed", "activated-hash", now.Add(4*time.Minute), AuditEntry{}); err != nil || activated.Role != RoleOperator || !activated.Enabled {
		t.Fatalf("new activation link after the role change = %+v, %v", activated, err)
	}
}

func TestUserInviteAuditFailureRollsBackAndOlderInviteIsInvalidated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	user, err := createTestUser(ctx, defaultTenant(s), User{Username: "viewer", DisplayName: "Viewer", Role: RoleViewer, PasswordHash: "!pending", Enabled: true}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := createTestLink(ctx, defaultTenant(s), "old-hash", user.ID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := createTestSession(ctx, s, user.ID, "session-before-reset", "csrf", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActivateUser(ctx, "old-hash", "replacement-hash", now.Add(time.Minute), AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "session-before-reset"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("password reset left prior session active: %v", err)
	}
	// A replacement invite must still be tested independently below; the
	// previous activation consumed the original token as expected.
	if err := createTestLink(ctx, defaultTenant(s), "old-hash-2", user.ID, now.Add(2*time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_user_invite_audit BEFORE INSERT ON security_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	seedDefaultAdministrator(t, s)
	if err := defaultTenant(s).CreateUserInviteWithAudit(ctx, "new-hash", user.ID, now.Add(time.Minute), now.Add(2*time.Hour), defaultAdministratorAudit("user.activation_issued")); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("expected audit failure, got %v", err)
	}
	if _, err := s.ActivateUser(ctx, "old-hash-2", "hash", now.Add(3*time.Minute), AuditEntry{}); err != nil {
		t.Fatalf("old invite should remain usable after rolled-back replacement: %v", err)
	}
	if _, err := defaultTenant(s).GetUser(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
}

func TestUserValidationRejectsPathAndControlCharacters(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	ctx := context.Background()
	for _, username := range []string{"a/b", "a\\b", "a:b", "a\n b"} {
		if _, err := createTestUser(ctx, defaultTenant(s), User{Username: username, Role: RoleViewer, PasswordHash: "hash", Enabled: true}, AuditEntry{}); err == nil {
			t.Fatalf("username %q accepted", username)
		}
	}
	if _, err := createTestUser(ctx, defaultTenant(s), User{Username: "", Role: RoleViewer, PasswordHash: "hash", Enabled: true}, AuditEntry{}); err == nil {
		t.Fatal("empty username accepted")
	}
	if _, err := createTestUser(ctx, defaultTenant(s), User{Username: "viewer", Role: "unknown", PasswordHash: "hash", Enabled: true}, AuditEntry{}); err == nil {
		t.Fatal("unknown role accepted")
	}
}

func TestUpdateUserKeepsLastEnabledAdministrator(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	admin, err := createTestUser(ctx, defaultTenant(s), User{Username: "admin", DisplayName: "Administrator", Role: RoleAdministrator, PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	admin.Role = RoleOperator
	admin.UpdatedAt = now.Add(time.Minute)
	if err := defaultTenant(s).UpdateUser(ctx, admin, true, AuditEntry{}); !errors.Is(err, ErrLastAdministrator) {
		t.Fatalf("last administrator update error = %v", err)
	}
	loaded, err := defaultTenant(s).GetUser(ctx, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Role != RoleAdministrator || !loaded.Enabled {
		t.Fatalf("last administrator changed despite rejection: %#v", loaded)
	}
}

func TestSaveUserSecurityKeepsRoleValidationAndLastAdministratorInvariant(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	admin, err := createTestUser(ctx, defaultTenant(s), User{Username: "admin", DisplayName: "Administrator", Role: RoleAdministrator, PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	admin.Role = RoleOperator
	admin.UpdatedAt = now.Add(time.Minute)
	if err := defaultTenant(s).SaveUserSecurity(ctx, admin, nil, false, false, AuditEntry{}); !errors.Is(err, ErrLastAdministrator) {
		t.Fatalf("last administrator security update error = %v", err)
	}
	loaded, err := defaultTenant(s).GetUser(ctx, admin.ID)
	if err != nil || loaded.Role != RoleAdministrator || !loaded.Enabled {
		t.Fatalf("administrator changed despite security guard: %#v, %v", loaded, err)
	}
	loaded.Role = "invalid"
	if err := defaultTenant(s).SaveUserSecurity(ctx, loaded, nil, false, false, AuditEntry{}); err == nil {
		t.Fatal("invalid role was accepted by SaveUserSecurity")
	}
}

func TestUserMutationsRejectStaleRevision(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	created, err := createTestUser(ctx, defaultTenant(s), User{Username: "concurrent", DisplayName: "Concurrent", Role: RoleViewer, PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := defaultTenant(s).GetUser(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := defaultTenant(s).GetUser(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != 1 || second.Revision != 1 {
		t.Fatalf("initial revisions = %d and %d", first.Revision, second.Revision)
	}
	first.DisplayName = "First writer"
	first.UpdatedAt = now.Add(time.Minute)
	if err := defaultTenant(s).UpdateUser(ctx, first, false, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	second.DisplayName = "Stale writer"
	second.UpdatedAt = now.Add(2 * time.Minute)
	if err := defaultTenant(s).UpdateUser(ctx, second, false, AuditEntry{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale profile update error = %v", err)
	}
	current, err := defaultTenant(s).GetUser(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.DisplayName != "First writer" || current.Revision != 2 {
		t.Fatalf("stale profile update changed user = %#v", current)
	}

	staleSecurity := current
	fresh, err := defaultTenant(s).GetUser(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	fresh.DisplayName = "Fresh writer"
	fresh.UpdatedAt = now.Add(3 * time.Minute)
	if err := defaultTenant(s).UpdateUser(ctx, fresh, false, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).SaveUserSecurity(ctx, staleSecurity, nil, false, false, AuditEntry{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale security update error = %v", err)
	}
	current, err = defaultTenant(s).GetUser(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.DisplayName != "Fresh writer" || current.Revision != 3 {
		t.Fatalf("stale security update changed user = %#v", current)
	}
}
