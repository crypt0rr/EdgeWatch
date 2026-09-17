package store

import (
	"context"
	"errors"
	"time"
)

// ErrTOTPReplay indicates that a valid time-based code was already accepted
// for this account and time step. It is intentionally safe to expose only as a
// generic authentication failure at the HTTP boundary.
var ErrTOTPReplay = errors.New("TOTP code was already used")

// ConsumeTOTPStep atomically records the accepted TOTP time step. A code may
// be accepted once even when several login requests arrive concurrently.
func (s *Store) ConsumeTOTPStep(ctx context.Context, userID string, step int64, now time.Time) (bool, error) {
	if userID == "" || step < 0 {
		return false, ErrTOTPReplay
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO totp_replay(user_id,last_step,updated_at) VALUES(?,?,?)`, userID, -1, now.UTC().Format(time.RFC3339Nano)); err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE totp_replay SET last_step=?,updated_at=? WHERE user_id=? AND last_step < ?`, step, now.UTC().Format(time.RFC3339Nano), userID, step)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return affected == 1, nil
}
