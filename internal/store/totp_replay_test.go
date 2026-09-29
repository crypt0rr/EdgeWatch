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
	user, err := defaultTenant(s).CreateUser(ctx, User{Username: "totp-replay", DisplayName: "TOTP replay", Role: RoleViewer, PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}, AuditEntry{})
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
	if accepted, err := s.ConsumeTOTPStep(ctx, "missing-user", 1, now); err == nil || accepted {
		t.Fatalf("unknown user request = %v, %v", accepted, err)
	}
}

// A security save that enrols TOTP records the time step of the code that
// confirmed the new secret, in its own transaction, so ConsumeTOTPStep no
// longer accepts that step while a later one is still accepted. The step
// only raises the guard: a save whose step was accepted already, as when an
// authenticator is replaced in the time step that confirmed the old one,
// still succeeds, and an older step leaves the guard as it is. NoTOTPStep
// records nothing, and neither does a save that fails.
func TestTOTPEnrolmentRecordsTheConfirmingStep(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if err := s.SaveAdmin(ctx, Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	unit, err := defaultTenant(s).CreateUser(ctx, User{Username: "totp-enrolment", Role: RoleViewer, PasswordHash: "hash", Enabled: true}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	const secret = "JBSWY3DPEHPK3PXP"
	for _, account := range []struct {
		name, id string
		// save enrols TOTP with the step; stale saves it at a revision
		// that is no longer current.
		save func(step int64, stale bool) error
	}{
		{"original administrator", LegacyAdminUserID, func(step int64, stale bool) error {
			admin, err := s.GetAdmin(ctx)
			if err != nil {
				return err
			}
			if stale {
				admin.Revision--
			}
			admin.TOTPEnabled, admin.TOTPSecret, admin.UpdatedAt = true, secret, time.Now().UTC()
			return s.SaveAdminSecurityWithAuditPreservingSession(ctx, admin, nil, false, false, AuditEntry{}, "", step)
		}},
		{"unit account", unit.ID, func(step int64, stale bool) error {
			user, err := defaultTenant(s).GetUser(ctx, unit.ID)
			if err != nil {
				return err
			}
			if stale {
				user.Revision--
			}
			user.TOTPEnabled, user.TOTPSecret, user.UpdatedAt = true, secret, time.Now().UTC()
			return defaultTenant(s).SaveUserSecurityPreservingSession(ctx, user, nil, false, false, AuditEntry{}, "", step)
		}},
	} {
		lastStep := func() int64 {
			t.Helper()
			var step int64
			if err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(MAX(last_step),?) FROM totp_replay WHERE user_id=?`, NoTOTPStep, account.id).Scan(&step); err != nil {
				t.Fatal(err)
			}
			return step
		}
		if err := account.save(NoTOTPStep, false); err != nil || lastStep() != NoTOTPStep {
			t.Fatalf("%s: a save without a step = %v, recorded step %d", account.name, err, lastStep())
		}
		if err := account.save(200, true); !errors.Is(err, ErrConflict) || lastStep() != NoTOTPStep {
			t.Fatalf("%s: a stale enrolment = %v, recorded step %d; want ErrConflict and none", account.name, err, lastStep())
		}
		if err := account.save(100, false); err != nil || lastStep() != 100 {
			t.Fatalf("%s: an enrolment at step 100 = %v, recorded step %d", account.name, err, lastStep())
		}
		if accepted, err := s.ConsumeTOTPStep(ctx, account.id, 100, now); err != nil || accepted {
			t.Fatalf("%s: the enrolment's step after the enrolment = %v, %v; want refused", account.name, accepted, err)
		}
		if accepted, err := s.ConsumeTOTPStep(ctx, account.id, 101, now); err != nil || !accepted {
			t.Fatalf("%s: the next step after the enrolment = %v, %v; want accepted", account.name, accepted, err)
		}
		// A replacement confirmed in the step that the old factor's
		// confirmation used, then an older step.
		if err := account.save(101, false); err != nil || lastStep() != 101 {
			t.Fatalf("%s: an enrolment at the accepted step 101 = %v, recorded step %d", account.name, err, lastStep())
		}
		if err := account.save(99, false); err != nil || lastStep() != 101 {
			t.Fatalf("%s: an enrolment at the older step 99 = %v, recorded step %d; want 101 kept", account.name, err, lastStep())
		}
	}
}
