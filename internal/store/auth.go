package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

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
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_audit(action,detail,created_at) VALUES(?,?,?)`, auditAction, auditDetail, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
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
	_, err := s.DB.ExecContext(ctx, `INSERT INTO setup_tokens(id,token_hash,expires_at,used_at) VALUES(1,?,?,NULL) ON CONFLICT(id) DO UPDATE SET token_hash=excluded.token_hash,expires_at=excluded.expires_at,used_at=NULL`, hash, expires.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) GetSetupToken(ctx context.Context) (SetupToken, error) {
	var expires string
	var used sql.NullString
	err := s.DB.QueryRowContext(ctx, `SELECT expires_at,used_at FROM setup_tokens WHERE id=1`).Scan(&expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return SetupToken{}, ErrNotFound
	}
	if err != nil {
		return SetupToken{}, err
	}
	return SetupToken{ExpiresAt: scanTime(expires), Used: used.Valid}, nil
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO security_audit(action,detail,created_at) VALUES(?,?,?)`, "admin.setup", "administrator created", now.UTC().Format(time.RFC3339Nano)); err != nil {
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

func (s *Store) DeleteAllSessions(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions`)
	return err
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
	_, err := s.DB.ExecContext(ctx, `INSERT INTO security_audit(action,detail,created_at) VALUES(?,?,?)`, action, detail, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) RecoveryCodeCount(ctx context.Context) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE used_at IS NULL`).Scan(&n)
	return n, err
}
