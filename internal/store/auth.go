package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrAuditUnavailable indicates that a security-sensitive mutation could not
// record its required audit row. Callers should fail closed (or report the
// operation as degraded) rather than claiming a successful audited action.
var ErrAuditUnavailable = errors.New("security audit unavailable")

// AuditEntry describes a security event that should be committed together
// with the state mutation that caused it. Keeping this small value type in the
// store package lets job, baseline, and notification transactions share the
// same fail-closed audit boundary without exposing database handles to callers.
type AuditEntry struct {
	Action string
	Detail string
}

type Admin struct {
	Username     string
	PasswordHash string
	TOTPSecret   string
	TOTPEnabled  bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	// TOTPSecretStored retains the encrypted database value when the key is
	// unavailable, so unrelated admin updates do not overwrite it.
	TOTPSecretStored string
	TOTPSecretError  error
}

type Session struct {
	IDHash     string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	CSRFToken  string
}

type SetupToken struct {
	ExpiresAt time.Time
	IssuedAt  time.Time
	Used      bool
}

func (s *Store) GetAdmin(ctx context.Context) (Admin, error) {
	var a Admin
	var totp int
	var stored string
	var created, updated string
	err := s.DB.QueryRowContext(ctx, `SELECT username,password_hash,totp_secret,totp_enabled,created_at,updated_at FROM admins WHERE id=1`).
		Scan(&a.Username, &a.PasswordHash, &stored, &totp, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	if err != nil {
		return a, err
	}
	a.TOTPEnabled = totp != 0
	a.CreatedAt, a.UpdatedAt = scanTime(created), scanTime(updated)
	a.TOTPSecretStored = stored
	secret, secretErr := s.openTOTPSecret(stored)
	if secretErr != nil {
		a.TOTPSecretError = secretErr
	} else {
		a.TOTPSecret = secret
		if a.TOTPEnabled && secret != "" && !strings.HasPrefix(stored, authCiphertext) {
			if encrypted, encryptErr := s.sealTOTPSecret(secret); encryptErr == nil {
				_, _ = s.DB.ExecContext(ctx, `UPDATE admins SET totp_secret=?,updated_at=? WHERE id=1 AND totp_secret=?`, encrypted, time.Now().UTC().Format(time.RFC3339Nano), stored)
				a.TOTPSecretStored = encrypted
			}
		}
	}
	return a, nil
}

func (s *Store) SaveAdmin(ctx context.Context, a Admin) error {
	stored, err := s.adminTOTPForSave(a)
	if err != nil {
		return err
	}
	return saveAdminExec(ctx, s.DB, a, stored)
}

type contextExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func saveAdminExec(ctx context.Context, execer contextExecer, a Admin, stored string) error {
	_, err := execer.ExecContext(ctx, `INSERT INTO admins(id,username,password_hash,totp_secret,totp_enabled,created_at,updated_at) VALUES(1,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET username=excluded.username,password_hash=excluded.password_hash,totp_secret=excluded.totp_secret,totp_enabled=excluded.totp_enabled,updated_at=excluded.updated_at`, a.Username, a.PasswordHash, stored, boolInt(a.TOTPEnabled), a.CreatedAt.UTC().Format(time.RFC3339Nano), a.UpdatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

// SaveAdminSecurity commits an administrator mutation and its dependent
// authentication state as one transaction. A nil recoveryCodes slice leaves
// existing recovery codes untouched; a non-nil slice replaces them (including
// an empty slice, which clears them). This prevents a successful credential
// update from being reported when session revocation, recovery-code rotation,
// or the corresponding audit record failed.
func (s *Store) SaveAdminSecurity(ctx context.Context, a Admin, recoveryCodes []string, replaceRecoveryCodes, revokeSessions bool, auditAction, auditDetail string) error {
	stored, err := s.adminTOTPForSave(a)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := saveAdminExec(ctx, tx, a, stored); err != nil {
		return err
	}
	if replaceRecoveryCodes {
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes`); err != nil {
			return err
		}
		for _, hash := range recoveryCodes {
			if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(id_hash) VALUES(?)`, hash); err != nil {
				return err
			}
		}
	}
	if revokeSessions {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
			return err
		}
	}
	if auditAction != "" {
		if err := insertAuditExec(ctx, tx, auditAction, auditDetail, time.Now().UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) adminTOTPForSave(a Admin) (string, error) {
	if !a.TOTPEnabled || a.TOTPSecret == "" {
		if a.TOTPEnabled && a.TOTPSecret == "" && a.TOTPSecretStored != "" {
			return a.TOTPSecretStored, nil
		}
		if a.TOTPEnabled {
			return "", ErrTOTPSecretLocked
		}
		return "", nil
	}
	return s.sealTOTPSecret(a.TOTPSecret)
}

func (s *Store) PutSetupToken(ctx context.Context, hash string, expires time.Time) error {
	return s.PutSetupTokenAt(ctx, hash, expires, time.Now().UTC())
}

// PutSetupTokenAt stores a fresh setup token and records when it was issued.
// The timestamp is persisted so host recovery commands can enforce a rate
// limit across short-lived CLI processes.
func (s *Store) PutSetupTokenAt(ctx context.Context, hash string, expires, issuedAt time.Time) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO setup_tokens(id,token_hash,expires_at,used_at,issued_at) VALUES(1,?,?,NULL,?) ON CONFLICT(id) DO UPDATE SET token_hash=excluded.token_hash,expires_at=excluded.expires_at,used_at=NULL,issued_at=excluded.issued_at`, hash, expires.UTC().Format(time.RFC3339Nano), issuedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) GetSetupToken(ctx context.Context) (SetupToken, error) {
	var expires string
	var issued string
	var used sql.NullString
	err := s.DB.QueryRowContext(ctx, `SELECT expires_at,used_at,issued_at FROM setup_tokens WHERE id=1`).Scan(&expires, &used, &issued)
	if errors.Is(err, sql.ErrNoRows) {
		return SetupToken{}, ErrNotFound
	}
	if err != nil {
		return SetupToken{}, err
	}
	return SetupToken{ExpiresAt: scanTime(expires), IssuedAt: scanTime(issued), Used: used.Valid}, nil
}

var ErrSetupTokenRateLimited = errors.New("setup token was issued too recently; try again later")

// ReissueSetupToken atomically replaces the one-time setup token, but only
// while no administrator exists. It is intended for a host-authorized CLI
// recovery path; the token itself is returned only to that caller and never
// enters an API response or audit detail.
func (s *Store) ReissueSetupToken(ctx context.Context, hash string, expires, now time.Time) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var username string
	if err = tx.QueryRowContext(ctx, `SELECT username FROM admins WHERE id=1`).Scan(&username); err == nil {
		return errors.New("administrator is already configured")
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var issued string
	if err = tx.QueryRowContext(ctx, `SELECT issued_at FROM setup_tokens WHERE id=1`).Scan(&issued); err == nil {
		if previous := scanTime(issued); !previous.IsZero() && now.UTC().Sub(previous) < time.Minute {
			return ErrSetupTokenRateLimited
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO setup_tokens(id,token_hash,expires_at,used_at,issued_at) VALUES(1,?,?,NULL,?) ON CONFLICT(id) DO UPDATE SET token_hash=excluded.token_hash,expires_at=excluded.expires_at,used_at=NULL,issued_at=excluded.issued_at`, hash, expires.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if err = insertAuditExec(ctx, tx, "admin.setup_token_reissued", "setup token reissued from host CLI", now.UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

// CompleteSetup consumes the token and creates the one permitted administrator
// in one transaction, preventing a token race from creating two accounts.
func (s *Store) CompleteSetup(ctx context.Context, tokenHash string, admin Admin, now time.Time) error {
	storedSecret, err := s.adminTOTPForSave(admin)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var expires string
	var used sql.NullString
	if err = tx.QueryRowContext(ctx, `SELECT expires_at,used_at FROM setup_tokens WHERE id=1 AND token_hash=?`, tokenHash).Scan(&expires, &used); errors.Is(err, sql.ErrNoRows) {
		return errors.New("invalid setup token")
	} else if err != nil {
		return err
	}
	if used.Valid || !now.Before(scanTime(expires)) {
		return errors.New("setup token expired or already used")
	}
	var existing string
	if err = tx.QueryRowContext(ctx, `SELECT username FROM admins WHERE id=1`).Scan(&existing); err == nil {
		return errors.New("administrator is already configured")
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO admins(id,username,password_hash,totp_secret,totp_enabled,created_at,updated_at) VALUES(1,?,?,?,?,?,?)`, admin.Username, admin.PasswordHash, storedSecret, boolInt(admin.TOTPEnabled), admin.CreatedAt.UTC().Format(time.RFC3339Nano), admin.UpdatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE setup_tokens SET used_at=? WHERE id=1`, now.UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if err = insertAuditExec(ctx, tx, "admin.setup", "administrator created", now.UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ConsumeSetupToken(ctx context.Context, hash string, now time.Time) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var expires string
	var used sql.NullString
	if err = tx.QueryRowContext(ctx, `SELECT expires_at,used_at FROM setup_tokens WHERE id=1 AND token_hash=?`, hash).Scan(&expires, &used); errors.Is(err, sql.ErrNoRows) {
		return errors.New("invalid setup token")
	} else if err != nil {
		return err
	}
	if used.Valid || !now.Before(scanTime(expires)) {
		return errors.New("setup token expired or already used")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE setup_tokens SET used_at=? WHERE id=1`, now.UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateSession(ctx context.Context, idHash, csrf string, created, expires time.Time) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sessions(id_hash,created_at,last_seen_at,expires_at,csrf_token) VALUES(?,?,?,?,?)`, idHash, created.UTC().Format(time.RFC3339Nano), created.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano), csrf)
	return err
}

// CreateSessionWithAudit creates a login session and its audit record in one
// transaction, so a successful login can never be returned without evidence.
func (s *Store) CreateSessionWithAudit(ctx context.Context, idHash, csrf string, created, expires time.Time, action, detail string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(id_hash,created_at,last_seen_at,expires_at,csrf_token) VALUES(?,?,?,?,?)`, idHash, created.UTC().Format(time.RFC3339Nano), created.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano), csrf); err != nil {
		return err
	}
	if action != "" {
		if err := insertAuditExec(ctx, tx, action, detail, created.UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) GetSession(ctx context.Context, idHash string) (Session, error) {
	var v Session
	var created, lastSeen, expires string
	err := s.DB.QueryRowContext(ctx, `SELECT id_hash,created_at,last_seen_at,expires_at,csrf_token FROM sessions WHERE id_hash=?`, idHash).Scan(&v.IDHash, &created, &lastSeen, &expires, &v.CSRFToken)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, err
	}
	v.CreatedAt, v.LastSeenAt, v.ExpiresAt = scanTime(created), scanTime(lastSeen), scanTime(expires)
	return v, nil
}

func (s *Store) TouchSession(ctx context.Context, idHash string, lastSeen, expires time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE sessions SET last_seen_at=?,expires_at=? WHERE id_hash=?`, lastSeen.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano), idHash)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash=?`, idHash)
	return err
}

func (s *Store) DeleteSessionWithAudit(ctx context.Context, idHash, action, detail string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash=?`, idHash); err != nil {
		return err
	}
	if action != "" {
		if err := insertAuditExec(ctx, tx, action, detail, time.Now().UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DeleteAllSessions(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions`)
	return err
}

func (s *Store) DeleteAllSessionsWithAudit(ctx context.Context, action, detail string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
		return err
	}
	if action != "" {
		if err := insertAuditExec(ctx, tx, action, detail, time.Now().UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteExpiredSessions removes sessions past their absolute expiry. It is
// safe to run during maintenance because the predicate cannot match a newly
// touched active session.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	result, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Store) SaveRecoveryCodes(ctx context.Context, hashes []string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM recovery_codes`); err != nil {
		return err
	}
	for _, hash := range hashes {
		if _, err = tx.ExecContext(ctx, `INSERT INTO recovery_codes(id_hash) VALUES(?)`, hash); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ConsumeRecoveryCode(ctx context.Context, hash string, now time.Time) (bool, error) {
	r, err := s.DB.ExecContext(ctx, `UPDATE recovery_codes SET used_at=? WHERE id_hash=? AND used_at IS NULL`, now.UTC().Format(time.RFC3339Nano), hash)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

func (s *Store) Audit(ctx context.Context, action, detail string) error {
	return insertAuditExec(ctx, s.DB, action, detail, time.Now().UTC())
}

func insertAuditExec(ctx context.Context, execer contextExecer, action, detail string, now time.Time) error {
	if _, err := execer.ExecContext(ctx, `INSERT INTO security_audit(action,detail,created_at) VALUES(?,?,?)`, action, detail, now.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditUnavailable, err)
	}
	return nil
}

func insertAuditEntries(ctx context.Context, execer contextExecer, entries []AuditEntry, now time.Time) error {
	for _, entry := range entries {
		if strings.TrimSpace(entry.Action) == "" {
			continue
		}
		if err := insertAuditExec(ctx, execer, entry.Action, entry.Detail, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) RecoveryCodeCount(ctx context.Context) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE used_at IS NULL`).Scan(&n)
	return n, err
}
