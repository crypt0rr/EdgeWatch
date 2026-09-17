package store

import (
	"context"
	"errors"
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

func TestConsumeTOTPStepRejectsInvalidAndCancelledRequests(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if accepted, err := s.ConsumeTOTPStep(ctx, "", 1, now); !errors.Is(err, ErrTOTPReplay) || accepted {
		t.Fatalf("empty user id = %v, %v", accepted, err)
	}
	if accepted, err := s.ConsumeTOTPStep(ctx, "user", -1, now); !errors.Is(err, ErrTOTPReplay) || accepted {
		t.Fatalf("negative step = %v, %v", accepted, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if accepted, err := s.ConsumeTOTPStep(cancelled, "user", 1, now); err == nil || accepted {
		t.Fatalf("cancelled request = %v, %v", accepted, err)
	}
}
