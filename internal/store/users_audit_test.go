package store

import (
	"context"
	"testing"
)

func TestUpdateUserAuditsEveryPersistedChangeButNotNoOps(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	user, err := s.CreateUser(ctx, User{Username: "renamed-operator", DisplayName: "Before", Role: RoleOperator, PasswordHash: "hash", Enabled: true}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	auditRows := func() int {
		t.Helper()
		var count int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='user.updated'`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	update := func(change func(*User)) {
		t.Helper()
		current, err := s.GetUser(ctx, user.ID)
		if err != nil {
			t.Fatal(err)
		}
		change(&current)
		if err := s.UpdateUser(ctx, current, false, AuditEntry{Action: "user.updated", Detail: "updated", ActorUserID: LegacyAdminUserID, ActorUsername: "admin"}); err != nil {
			t.Fatal(err)
		}
	}

	update(func(u *User) { u.DisplayName = "After" })
	if got := auditRows(); got != 1 {
		t.Fatalf("display-name change audit rows = %d, want 1", got)
	}
	update(func(*User) {})
	if got := auditRows(); got != 1 {
		t.Fatalf("no-op update audit rows = %d, want 1", got)
	}
	update(func(u *User) { u.Username = "operator-renamed" })
	if got := auditRows(); got != 2 {
		t.Fatalf("username change audit rows = %d, want 2", got)
	}
	update(func(u *User) { u.PasswordHash = "new-hash" })
	if got := auditRows(); got != 3 {
		t.Fatalf("password change audit rows = %d, want 3", got)
	}
	// A legacy row with an empty display name is presented as the username;
	// saving that effective value is not a change.
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET display_name='' WHERE id=?`, user.ID); err != nil {
		t.Fatal(err)
	}
	update(func(*User) {})
	if got := auditRows(); got != 3 {
		t.Fatalf("empty stored display name no-op audit rows = %d, want 3", got)
	}
}
