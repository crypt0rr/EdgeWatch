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
