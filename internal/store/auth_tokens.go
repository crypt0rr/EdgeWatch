package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SetupTokenUsable performs the cheap, read-only part of setup validation.
// Callers should use it before scheduling Argon2 work so obviously stale or
// already-consumed tokens cannot be used as a password-hashing oracle. Only
// an initial setup token is usable for the first setup, never a platform
// setup token.
func (ps *PlatformStore) SetupTokenUsable(ctx context.Context, tokenHash string, now time.Time) (bool, error) {
	return ps.setupTokenUsable(ctx, tokenHash, SetupTokenPurposeInitial, now)
}

// setupTokenUsable reports whether the setup token with the hash is for the
// purpose, unused, and unexpired.
func (ps *PlatformStore) setupTokenUsable(ctx context.Context, tokenHash, purpose string, now time.Time) (bool, error) {
	var expires string
	var used sql.NullString
	if err := ps.store.reader().QueryRowContext(ctx, `SELECT expires_at,used_at FROM setup_tokens WHERE id=1 AND token_hash=? AND purpose=?`, tokenHash, purpose).Scan(&expires, &used); errors.Is(err, sql.ErrNoRows) {
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
	link, err := s.CheckActivationToken(ctx, tokenHash, now)
	return link.Usable, err
}

// ActivationLink is what CheckActivationToken reports about the activation
// or password-reset link with a token.
type ActivationLink struct {
	// Found reports whether a link has the token, whatever its state.
	Found bool
	// Usable reports whether the link can be redeemed now, as
	// ActivationTokenUsable reports it.
	Usable bool
	// TenantID is the tenant of the link's account, or "" for an account
	// without one, a platform administrator's.
	TenantID string
}

// CheckActivationToken is ActivationTokenUsable that also reports whether a
// link has the token and the tenant of the link's account, also when the
// link cannot be redeemed, so the records of a failed redemption belong
// where the successful redemption's record does. It is one indexed read of
// the token's hash.
func (s *Store) CheckActivationToken(ctx context.Context, tokenHash string, now time.Time) (ActivationLink, error) {
	var expires string
	var used sql.NullString
	var passwordHash string
	var enabled int
	var tenantID, tenantState string
	if err := s.reader().QueryRowContext(ctx, `SELECT i.expires_at,i.used_at,u.password_hash,u.enabled,COALESCE(u.tenant_id,''),COALESCE(t.state,'') FROM user_invites i JOIN users u ON u.id=i.user_id LEFT JOIN tenants t ON t.id=u.tenant_id WHERE i.id_hash=?`, tokenHash).Scan(&expires, &used, &passwordHash, &enabled, &tenantID, &tenantState); errors.Is(err, sql.ErrNoRows) {
		return ActivationLink{}, nil
	} else if err != nil {
		return ActivationLink{}, err
	}
	link := ActivationLink{Found: true, TenantID: tenantID}
	if used.Valid || !now.Before(scanTime(expires)) {
		return link, nil
	}
	if tenantID != "" && tenantState != TenantStateActive {
		return link, nil
	}
	// A reset link must not re-enable a previously configured account that was
	// disabled. Pending invitees are the sole disabled account allowed through.
	if enabled == 0 && len(passwordHash) > 0 && passwordHash[0] != '!' {
		return link, nil
	}
	link.Usable = true
	return link, nil
}
