package store

import (
	"context"
	"testing"
	"time"
)

func TestConsumeTOTPStepRejectsReplayAndOlderStep(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	user, err := s.CreateUser(ctx, User{Username: "totp-replay", DisplayName: "TOTP replay", Role: RoleViewer, PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if accepted, err := s.ConsumeTOTPStep(ctx, user.ID, 100, now); err != nil || !accepted {
		t.Fatalf("first TOTP step = %v, %v", accepted, err)
	}
	if accepted, err := s.ConsumeTOTPStep(ctx, user.ID, 100, now.Add(time.Second)); err != nil || accepted {
		t.Fatalf("replayed TOTP step = %v, %v", accepted, err)
	}
	if accepted, err := s.ConsumeTOTPStep(ctx, user.ID, 99, now.Add(2*time.Second)); err != nil || accepted {
		t.Fatalf("older TOTP step = %v, %v", accepted, err)
	}
	if accepted, err := s.ConsumeTOTPStep(ctx, user.ID, 101, now.Add(30*time.Second)); err != nil || !accepted {
		t.Fatalf("next TOTP step = %v, %v", accepted, err)
	}
}
