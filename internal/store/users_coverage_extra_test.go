package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestUserStoreValidationAndInviteBoundaries(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()

	for _, test := range []struct {
		name string
		call func() error
	}{
		{"invite hash required", func() error {
			_, err := s.CreateUserWithInvite(ctx, User{Username: "invite", Role: RoleViewer}, "", now, now.Add(time.Hour), AuditEntry{})
			return err
		}},
		{"invite expiry required", func() error {
			_, err := s.CreateUserWithInvite(ctx, User{Username: "invite", Role: RoleViewer}, "hash", now, now, AuditEntry{})
			return err
		}},
		{"invite audit hash required", func() error {
			return s.CreateUserInviteWithAudit(ctx, "", "user", now, now.Add(time.Hour), AuditEntry{})
		}},
		{"invite audit user required", func() error {
			return s.CreateUserInviteWithAudit(ctx, "hash", "", now, now.Add(time.Hour), AuditEntry{})
		}},
		{"invite audit expiry required", func() error {
			return s.CreateUserInviteWithAudit(ctx, "hash", "user", now, now, AuditEntry{})
		}},
		{"invalid activation arguments", func() error {
			_, err := s.ActivateUser(ctx, "", "", now, AuditEntry{})
			return err
		}},
		{"invalid consume token", func() error {
			_, err := s.ConsumeUserInvite(ctx, "missing", now)
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); err == nil {
				t.Fatal("invalid input was accepted")
			}
		})
	}

	if _, err := s.CreateUser(ctx, User{ID: "not-a-uuid", Username: "bad-id", Role: RoleViewer, PasswordHash: "hash"}, AuditEntry{}); err == nil {
		t.Fatal("invalid user UUID was accepted")
	}
	if _, err := s.CreateUser(ctx, User{Username: strings.Repeat("x", 81), Role: RoleViewer, PasswordHash: "hash"}, AuditEntry{}); err == nil {
		t.Fatal("long username was accepted")
	}
	if _, err := s.GetUserByUsername(ctx, "bad/name"); err == nil {
		t.Fatal("invalid lookup username was accepted")
	}

	user, err := s.CreateUser(ctx, User{Username: "blank-display", DisplayName: "Stored", Role: RoleViewer, PasswordHash: "hash", Enabled: true}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET display_name='' WHERE id=?`, user.ID); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.GetUser(ctx, user.ID)
	if err != nil || loaded.DisplayName != loaded.Username {
		t.Fatalf("blank display fallback = %#v, %v", loaded, err)
	}

	validID := uuid.NewString()
	if err := s.UpdateUser(ctx, User{ID: validID, Username: "missing", Role: RoleViewer, PasswordHash: "hash"}, false, AuditEntry{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing update error = %v", err)
	}
	if err := s.SaveUserSecurity(ctx, User{ID: validID, Username: "missing", Role: RoleViewer, PasswordHash: "hash"}, nil, false, false, AuditEntry{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing security update error = %v", err)
	}
	if err := s.UpdateUser(ctx, User{ID: "invalid", Username: "bad", Role: RoleViewer, PasswordHash: "hash"}, false, AuditEntry{}); err == nil {
		t.Fatal("invalid update UUID was accepted")
	}
	if err := s.SaveUserSecurity(ctx, User{ID: "invalid", Username: "bad", Role: RoleViewer, PasswordHash: "hash"}, nil, false, false, AuditEntry{}); err == nil {
		t.Fatal("invalid security UUID was accepted")
	}

	locked, err := s.CreateUser(ctx, User{Username: "locked", Role: RoleViewer, PasswordHash: "hash", Enabled: true}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	locked.TOTPEnabled = true
	locked.TOTPSecret = ""
	locked.TOTPSecretStored = ""
	if err := s.SaveUserSecurity(ctx, locked, nil, false, false, AuditEntry{}); !errors.Is(err, ErrTOTPSecretLocked) {
		t.Fatalf("locked TOTP secret error = %v", err)
	}

	admin1, err := s.CreateUser(ctx, User{Username: "admin-one", Role: RoleAdministrator, PasswordHash: "hash", Enabled: true}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, User{Username: "admin-two", Role: RoleAdministrator, PasswordHash: "hash", Enabled: true}, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	admin1.Role = RoleOperator
	if err := s.UpdateUser(ctx, admin1, false, AuditEntry{}); err != nil {
		t.Fatalf("demotion with another administrator = %v", err)
	}

	expired, err := s.CreateUser(ctx, User{Username: "expired-invite", Role: RoleViewer, PasswordHash: "!pending"}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUserInvite(ctx, "expired-hash", expired.ID, now.Add(-2*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeUserInvite(ctx, "expired-hash", now); err == nil {
		t.Fatal("expired invite was accepted")
	}
}
