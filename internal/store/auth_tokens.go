package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SetupTokenUsable performs the cheap, read-only part of setup validation.
// Callers should use it before scheduling Argon2 work so obviously stale or
// already-consumed tokens cannot be used as a password-hashing oracle.
func (s *Store) SetupTokenUsable(ctx context.Context, tokenHash string, now time.Time) (bool, error) {
	var expires string
	var used sql.NullString
	if err := s.reader().QueryRowContext(ctx, `SELECT expires_at,used_at FROM setup_tokens WHERE id=1 AND token_hash=?`, tokenHash).Scan(&expires, &used); errors.Is(err, sql.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return !used.Valid && now.Before(scanTime(expires)), nil
}

// ActivationTokenUsable performs the cheap token and account-state checks
// before the expensive password hash. It intentionally returns only a boolean
// for callers serving unauthenticated activation requests.
func (s *Store) ActivationTokenUsable(ctx context.Context, tokenHash string, now time.Time) (bool, error) {
	var expires string
	var used sql.NullString
	var passwordHash string
	var enabled int
	if err := s.reader().QueryRowContext(ctx, `SELECT i.expires_at,i.used_at,u.password_hash,u.enabled FROM user_invites i JOIN users u ON u.id=i.user_id WHERE i.id_hash=?`, tokenHash).Scan(&expires, &used, &passwordHash, &enabled); errors.Is(err, sql.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if used.Valid || !now.Before(scanTime(expires)) {
		return false, nil
	}
	// A reset link must not re-enable a previously configured account that was
	// disabled. Pending invitees are the sole disabled account allowed through.
	if enabled == 0 && len(passwordHash) > 0 && passwordHash[0] != '!' {
		return false, nil
	}
	return true, nil
}
