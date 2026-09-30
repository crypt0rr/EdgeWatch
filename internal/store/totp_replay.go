package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ErrTOTPReplay indicates that a valid time-based code was already accepted
// for this account and time step. It is intentionally safe to expose only as a
// generic authentication failure at the HTTP boundary.
var ErrTOTPReplay = errors.New("TOTP code was already used")

// NoTOTPStep is the TOTP time step of a security save that confirmed no new
// TOTP secret, and the step that the replay guard of an account that has had
// no code accepted holds.
const NoTOTPStep int64 = -1

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
	advanced, err := advanceTOTPStepTx(ctx, tx, userID, step, now)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return advanced, nil
}

// TOTPStepAvailable reports whether a code of step may still be accepted
// for the account: whether step is newer than every step accepted before. It
// records nothing; sign-in records the step with CreateSignInSession, in the
// transaction that creates the session, which checks it again.
func (s *Store) TOTPStepAvailable(ctx context.Context, userID string, step int64) (bool, error) {
	if userID == "" || step < 0 {
		return false, nil
	}
	var last int64
	err := s.reader().QueryRowContext(ctx, `SELECT last_step FROM totp_replay WHERE user_id=?`, userID).Scan(&last)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return step > last, nil
}

// advanceTOTPStepTx raises the account's replay guard to step, and reports
// whether step was newer than every step accepted before, that is, whether
// a code of step may be accepted now. A step that is not newer leaves the
// guard as it is. ConsumeTOTPStep accepts a code only when it advanced the
// guard; a TOTP enrolment records the step of the code that confirmed the
// new secret, whether or not it advanced the guard, so the code is not
// accepted again. The caller has checked in tx that the account is one
// that it may change.
func advanceTOTPStepTx(ctx context.Context, tx *sql.Tx, userID string, step int64, now time.Time) (bool, error) {
	stamp := now.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO totp_replay(user_id,last_step,updated_at) VALUES(?,?,?)`, userID, NoTOTPStep, stamp); err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE totp_replay SET last_step=?,updated_at=? WHERE user_id=? AND last_step < ?`, step, stamp, userID, step)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

// recordEnrolledTOTPStepTx records, in the transaction that saves a new
// TOTP secret, the time step of the code that confirmed it, so that code is
// not accepted again at sign-in or for a TOTP confirmation. NoTOTPStep, or
// any negative step, records nothing. The step only raises the guard: when
// a step as new was accepted already, such as the old factor's in the same
// time step when an authenticator is replaced, the save still succeeds.
func recordEnrolledTOTPStepTx(ctx context.Context, tx *sql.Tx, userID string, step int64, now time.Time) error {
	if step < 0 {
		return nil
	}
	_, err := advanceTOTPStepTx(ctx, tx, userID, step, now)
	return err
}
