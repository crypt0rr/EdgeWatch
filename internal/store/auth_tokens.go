package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SetupTokenUsable reports whether the setup token is valid and unused.
//
// Deprecated: use Store.Platform().SetupTokenUsable.
func (s *Store) SetupTokenUsable(ctx context.Context, tokenHash string, now time.Time) (bool, error) {
	return s.Platform().SetupTokenUsable(ctx, tokenHash, now)
}

// SetupTokenUsable performs the cheap, read-only part of setup validation.
// Callers should use it before scheduling Argon2 work so obviously stale or
// already-consumed tokens cannot be used as a password-hashing oracle.
func (ps *PlatformStore) SetupTokenUsable(ctx context.Context, tokenHash string, now time.Time) (bool, error) {
	var expires string
	var used sql.NullString
	if err := ps.store.reader().QueryRowContext(ctx, `SELECT expires_at,used_at FROM setup_tokens WHERE id=1 AND token_hash=?`, tokenHash).Scan(&expires, &used); errors.Is(err, sql.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return !used.Valid && now.Before(scanTime(expires)), nil
}

// ActivationTokenUsable performs the cheap token and account-state checks
// before the expensive password hash. It intentionally returns only a boolean
// for callers serving unauthenticated activation requests.
//
// It stays global: the token, not a tenant scope, names the account. A
// token of an account whose tenant is not active is not usable, because a
// tenant that is disabled or being deleted stops the redemption of its
// links.
func (s *Store) ActivationTokenUsable(ctx context.Context, tokenHash string, now time.Time) (bool, error) {
	var expires string
	var used sql.NullString
	var passwordHash string
	var enabled int
	var tenantID, tenantState string
	if err := s.reader().QueryRowContext(ctx, `SELECT i.expires_at,i.used_at,u.password_hash,u.enabled,COALESCE(u.tenant_id,''),COALESCE(t.state,'') FROM user_invites i JOIN users u ON u.id=i.user_id LEFT JOIN tenants t ON t.id=u.tenant_id WHERE i.id_hash=?`, tokenHash).Scan(&expires, &used, &passwordHash, &enabled, &tenantID, &tenantState); errors.Is(err, sql.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if used.Valid || !now.Before(scanTime(expires)) {
		return false, nil
	}
	if tenantID != "" && tenantState != TenantStateActive {
		return false, nil
	}
	// A reset link must not re-enable a previously configured account that was
	// disabled. Pending invitees are the sole disabled account allowed through.
	if enabled == 0 && len(passwordHash) > 0 && passwordHash[0] != '!' {
		return false, nil
	}
	return true, nil
}
