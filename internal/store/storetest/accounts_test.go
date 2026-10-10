package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// CreateUser adds a signed-up account to the tenant as the tenant's store
// reads it: the username normalized, the display name defaulted, the
// enabled state and role kept, at revision one. A tenant scope that is not
// valid, an invalid username or role, TOTP, and a username that another
// account holds are refused.
func TestCreateUserAddsTheTenantsAccount(t *testing.T) {
	ctx := context.Background()
	s := OpenFresh(t)
	scope := store.DefaultTenantScope()
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	user, err := CreateUser(ctx, s, scope, store.User{Username: " Fixture-Operator ", Role: store.RoleOperator, PasswordHash: "hash", Enabled: true, CreatedAt: created})
	if err != nil {
		t.Fatal(err)
	}
	if user.ID == "" || user.TenantID != scope.ID() || user.Username != "fixture-operator" || user.DisplayName != "fixture-operator" || user.Role != store.RoleOperator || user.PasswordHash != "hash" || !user.Enabled || user.TOTPEnabled || user.Revision != 1 || !user.CreatedAt.Equal(created) {
		t.Fatalf("created account = %+v", user)
	}
	disabled, err := CreateUser(ctx, s, scope, store.User{ID: "00000000-0000-0000-0000-0000000000d1", Username: "fixture-disabled", DisplayName: "Disabled", Role: store.RoleViewer, PasswordHash: "hash"})
	if err != nil || disabled.ID != "00000000-0000-0000-0000-0000000000d1" || disabled.DisplayName != "Disabled" || disabled.Enabled {
		t.Fatalf("disabled account = %+v, %v", disabled, err)
	}
	for name, refused := range map[string]struct {
		scope store.TenantScope
		user  store.User
	}{
		"without a tenant":    {store.TenantScope{}, store.User{Username: "nobody", Role: store.RoleViewer}},
		"an invalid username": {scope, store.User{Username: "bad/name", Role: store.RoleViewer}},
		"an invalid role":     {scope, store.User{Username: "bad-role", Role: store.RolePlatformAdmin}},
		"with TOTP":           {scope, store.User{Username: "totp", Role: store.RoleViewer, TOTPEnabled: true}},
		"a taken username":    {scope, store.User{Username: "FIXTURE-OPERATOR", Role: store.RoleViewer}},
	} {
		if _, err := CreateUser(ctx, s, refused.scope, refused.user); err == nil {
			t.Errorf("CreateUser %s was accepted", name)
		}
	}
	if _, err := CreateUser(ctx, s, store.TenantScope{}, store.User{Username: "nobody", Role: store.RoleViewer}); !errors.Is(err, store.ErrNoTenantScope) {
		t.Fatalf("CreateUser without a tenant = %v, want ErrNoTenantScope", err)
	}
}

// CreateSession adds a session of the account that authentication reads
// with its CSRF token and times, and a second session with the same hash is
// refused.
func TestCreateSessionAddsTheAccountsSession(t *testing.T) {
	ctx := context.Background()
	s := OpenFresh(t)
	user, err := CreateUser(ctx, s, store.DefaultTenantScope(), store.User{Username: "fixture-session", Role: store.RoleViewer, PasswordHash: "hash", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	if err := CreateSession(ctx, s, user.ID, "session-hash", "csrf", created, created.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	session, err := s.GetSession(ctx, "session-hash")
	if err != nil || session.UserID != user.ID || session.TenantID != store.DefaultTenantID || session.CSRFToken != "csrf" || !session.CreatedAt.Equal(created) || !session.LastSeenAt.Equal(created) || !session.ExpiresAt.Equal(created.Add(time.Hour)) {
		t.Fatalf("session = %+v, %v", session, err)
	}
	if err := CreateSession(ctx, s, user.ID, "session-hash", "csrf", created, created.Add(time.Hour)); err == nil {
		t.Fatal("a second session with the same hash was accepted")
	}
}
