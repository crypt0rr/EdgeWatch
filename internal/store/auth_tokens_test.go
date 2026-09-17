package store

import (
	"context"
	"testing"
	"time"
)

func TestCheapAuthenticationTokenChecks(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

	if ok, err := s.SetupTokenUsable(ctx, "missing", now); err != nil || ok {
		t.Fatalf("missing setup token = %v, %v", ok, err)
	}
	if err := s.PutSetupTokenAt(ctx, "setup-active", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.SetupTokenUsable(ctx, "setup-active", now); err != nil || !ok {
		t.Fatalf("active setup token = %v, %v", ok, err)
	}
	if ok, err := s.SetupTokenUsable(ctx, "setup-active", now.Add(2*time.Hour)); err != nil || ok {
		t.Fatalf("expired setup token = %v, %v", ok, err)
	}
	if err := s.ConsumeSetupToken(ctx, "setup-active", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.SetupTokenUsable(ctx, "setup-active", now.Add(2*time.Minute)); err != nil || ok {
		t.Fatalf("consumed setup token = %v, %v", ok, err)
	}

	pending, err := s.CreateUserWithInvite(ctx, User{Username: "token-pending", DisplayName: "Pending", Role: RoleViewer, PasswordHash: "!pending", Enabled: false}, "invite-active", now, now.Add(time.Hour), AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ActivationTokenUsable(ctx, "invite-active", now); err != nil || !ok {
		t.Fatalf("active activation token = %v, %v", ok, err)
	}
	if ok, err := s.ActivationTokenUsable(ctx, "invite-active", now.Add(2*time.Hour)); err != nil || ok {
		t.Fatalf("expired activation token = %v, %v", ok, err)
	}
	if err := s.CreateUserInvite(ctx, "invite-expired", pending.ID, now.Add(-2*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ActivationTokenUsable(ctx, "invite-expired", now); err != nil || ok {
		t.Fatalf("expired invite = %v, %v", ok, err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET password_hash=?,enabled=0 WHERE id=?`, "configured-hash", pending.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ActivationTokenUsable(ctx, "invite-active", now); err != nil || ok {
		t.Fatalf("disabled configured invite = %v, %v", ok, err)
	}
	if ok, err := s.ActivationTokenUsable(ctx, "missing-invite", now); err != nil || ok {
		t.Fatalf("missing activation token = %v, %v", ok, err)
	}
}

func TestCheapAuthenticationTokenChecksReturnDatabaseErrors(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.SetupTokenUsable(ctx, "missing", time.Now().UTC()); err == nil || ok {
		t.Fatalf("closed setup-token store = %v, %v", ok, err)
	}
	if ok, err := s.ActivationTokenUsable(ctx, "missing", time.Now().UTC()); err == nil || ok {
		t.Fatalf("closed activation-token store = %v, %v", ok, err)
	}
}
