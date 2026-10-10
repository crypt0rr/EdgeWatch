package storetest

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// The account fixtures of other packages' tests. The store writes accounts
// and sessions only through the paths that check them: an administrator
// creates a pending account with its activation link, and a sign-in creates
// a session once the account's credentials are verified. A test that needs
// an account that has signed up, or a session of it, adds the rows directly
// with these.

// CreateUser adds the account to the tenant, with its password hash, role,
// and enabled state, and returns it as the tenant's store reads it. It
// writes the row directly, without the actor check, the activation link,
// and the audit record of the console's account creation. The username is
// normalized and the role checked as the store does, and an empty ID or
// display name gets a new UUID or the username. The account has no TOTP;
// a test enables it afterwards with TenantStore.SaveUserSecurity.
func CreateUser(ctx context.Context, s *store.Store, scope store.TenantScope, u store.User) (store.User, error) {
	if !scope.Valid() {
		return store.User{}, store.ErrNoTenantScope
	}
	if u.TOTPEnabled || u.TOTPSecret != "" {
		return store.User{}, errors.New("storetest: create the account without TOTP and save its TOTP with TenantStore.SaveUserSecurity")
	}
	username, err := store.NormalizeUsername(u.Username)
	if err != nil {
		return store.User{}, err
	}
	if err := store.ValidateUserRole(u.Role); err != nil {
		return store.User{}, err
	}
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if strings.TrimSpace(u.DisplayName) == "" {
		u.DisplayName = username
	}
	created := u.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	stamp := created.UTC().Format(time.RFC3339Nano)
	enabled := 0
	if u.Enabled {
		enabled = 1
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at,revision) VALUES(?,?,?,?,?,?,'',0,?,?,?,'',1)`, u.ID, scope.ID(), username, u.DisplayName, u.Role, u.PasswordHash, enabled, stamp, stamp); err != nil {
		return store.User{}, err
	}
	return s.Tenant(scope).GetUser(ctx, u.ID)
}

// CreateSession adds a session of the account, by the hash of its token,
// with its CSRF token, creation, and absolute expiry. It writes the row
// directly, without the credential checks of Store.CreateSignInSession.
func CreateSession(ctx context.Context, s *store.Store, userID, idHash, csrf string, created, expires time.Time) error {
	stamp := created.UTC().Format(time.RFC3339Nano)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,csrf_token) VALUES(?,?,?,?,?,?)`, idHash, userID, stamp, stamp, expires.UTC().Format(time.RFC3339Nano), csrf)
	return err
}
