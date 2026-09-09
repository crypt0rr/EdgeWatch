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
	Action        string
	Detail        string
	ActorUserID   string
	ActorUsername string
	SourceIP      string
}

type Admin struct {
	// Username is the stable administrator identity used for authentication.
	Username string
	// DisplayName is the label shown in the web console. It is deliberately
	// separate from Username so changing the label never changes sign-in.
	DisplayName  string
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
	IDHash      string
	UserID      string
	Username    string
	DisplayName string
	Role        string
	CreatedAt   time.Time
	LastSeenAt  time.Time
	ExpiresAt   time.Time
	CSRFToken   string
	// SourceIP is populated by the HTTP authentication layer after resolving
	// a trusted proxy chain. It is not persisted in the session row.
	SourceIP string
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
	err := s.DB.QueryRowContext(ctx, `SELECT username,display_name,password_hash,totp_secret,totp_enabled,created_at,updated_at FROM admins WHERE id=1`).
		Scan(&a.Username, &a.DisplayName, &a.PasswordHash, &stored, &totp, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	if err != nil {
		return a, err
	}
	a.DisplayName = adminDisplayName(a)
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

// HasAdministrator reports whether an administrator identity has ever been
// configured. The users table is authoritative for multi-user installations;
// the legacy admins row is retained as a compatibility fallback for databases
// opened by an older binary or a partially completed migration.
func (s *Store) HasAdministrator(ctx context.Context) (bool, error) {
	var present int
	err := s.DB.QueryRowContext(ctx, `SELECT 1 FROM users WHERE role=? LIMIT 1`, RoleAdministrator).Scan(&present)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		// A pre-migration fixture may not have the users table yet. Fall through
		// to the legacy row so host recovery and compatibility callers still work.
		if !strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return false, err
		}
	}
	_, legacyErr := s.GetAdmin(ctx)
	if legacyErr == nil {
		return true, nil
	}
	if errors.Is(legacyErr, ErrNotFound) {
		return false, nil
	}
	return false, legacyErr
}

func (s *Store) SaveAdmin(ctx context.Context, a Admin) error {
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
	return tx.Commit()
}

type contextExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func saveAdminExec(ctx context.Context, execer contextExecer, a Admin, stored string) error {
	_, err := execer.ExecContext(ctx, `INSERT INTO admins(id,username,display_name,password_hash,totp_secret,totp_enabled,created_at,updated_at) VALUES(1,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET username=excluded.username,display_name=excluded.display_name,password_hash=excluded.password_hash,totp_secret=excluded.totp_secret,totp_enabled=excluded.totp_enabled,updated_at=excluded.updated_at`, a.Username, adminDisplayName(a), a.PasswordHash, stored, boolInt(a.TOTPEnabled), a.CreatedAt.UTC().Format(time.RFC3339Nano), a.UpdatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	// Keep the compatibility administrator row and the authoritative users row
	// synchronized while older callers continue using SaveAdmin.
	if _, err = execer.ExecContext(ctx, `INSERT OR IGNORE INTO users(id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, LegacyAdminUserID, a.Username, adminDisplayName(a), RoleAdministrator, a.PasswordHash, stored, boolInt(a.TOTPEnabled), 1, a.CreatedAt.UTC().Format(time.RFC3339Nano), a.UpdatedAt.UTC().Format(time.RFC3339Nano), ""); err != nil {
		return err
	}
	_, err = execer.ExecContext(ctx, `UPDATE users SET username=?,display_name=?,password_hash=?,totp_secret=?,totp_enabled=?,updated_at=? WHERE id=?`, a.Username, adminDisplayName(a), a.PasswordHash, stored, boolInt(a.TOTPEnabled), a.UpdatedAt.UTC().Format(time.RFC3339Nano), LegacyAdminUserID)
	return err
}

func adminDisplayName(a Admin) string {
	if name := strings.TrimSpace(a.DisplayName); name != "" {
		return name
	}
	if username := strings.TrimSpace(a.Username); username != "" {
		return username
	}
	return "admin"
}

// SaveAdminSecurity commits an administrator mutation and its dependent
// authentication state as one transaction. A nil recoveryCodes slice leaves
// existing recovery codes untouched; a non-nil slice replaces them (including
// an empty slice, which clears them). This prevents a successful credential
// update from being reported when session revocation, recovery-code rotation,
// or the corresponding audit record failed.
func (s *Store) SaveAdminSecurity(ctx context.Context, a Admin, recoveryCodes []string, replaceRecoveryCodes, revokeSessions bool, auditAction, auditDetail string) error {
	return s.SaveAdminSecurityWithAudit(ctx, a, recoveryCodes, replaceRecoveryCodes, revokeSessions, AuditEntry{Action: auditAction, Detail: auditDetail})
}

// SaveAdminSecurityWithAudit is the actor-aware form used by the web console.
// The legacy string-argument wrapper above remains for CLI and older callers.
func (s *Store) SaveAdminSecurityWithAudit(ctx context.Context, a Admin, recoveryCodes []string, replaceRecoveryCodes, revokeSessions bool, audit AuditEntry) error {
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
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=?`, LegacyAdminUserID); err != nil {
			return err
		}
		for _, hash := range recoveryCodes {
			if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(id_hash,user_id) VALUES(?,?)`, hash, LegacyAdminUserID); err != nil {
				return err
			}
		}
	}
	if revokeSessions {
		// Password/TOTP changes for the compatibility administrator must not
		// sign out unrelated operator/viewer accounts now that sessions are
		// user-scoped. Older databases have their sessions attributed to the
		// stable legacy administrator ID by migration 12.
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=? OR user_id=''`, LegacyAdminUserID); err != nil {
			return err
		}
	}
	if audit.Action != "" {
		if err := insertAuditEntryExec(ctx, tx, audit, time.Now().UTC()); err != nil {
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
	var userCount int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role=?`, RoleAdministrator).Scan(&userCount); err == nil && userCount > 0 {
		return errors.New("administrator is already configured")
	} else if err != nil && !strings.Contains(strings.ToLower(err.Error()), "no such table") {
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
	var userCount int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role=?`, RoleAdministrator).Scan(&userCount); err == nil && userCount > 0 {
		return errors.New("administrator is already configured")
	} else if err != nil && !strings.Contains(strings.ToLower(err.Error()), "no such table") {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO admins(id,username,display_name,password_hash,totp_secret,totp_enabled,created_at,updated_at) VALUES(1,?,?,?,?,?,?,?)`, admin.Username, adminDisplayName(admin), admin.PasswordHash, storedSecret, boolInt(admin.TOTPEnabled), admin.CreatedAt.UTC().Format(time.RFC3339Nano), admin.UpdatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO users(id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, LegacyAdminUserID, admin.Username, adminDisplayName(admin), RoleAdministrator, admin.PasswordHash, storedSecret, boolInt(admin.TOTPEnabled), 1, admin.CreatedAt.UTC().Format(time.RFC3339Nano), admin.UpdatedAt.UTC().Format(time.RFC3339Nano), ""); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE setup_tokens SET used_at=? WHERE id=1 AND used_at IS NULL`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("setup token expired or already used")
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
	result, err := tx.ExecContext(ctx, `UPDATE setup_tokens SET used_at=? WHERE id=1 AND used_at IS NULL`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("setup token expired or already used")
	}
	return tx.Commit()
}

func (s *Store) CreateSession(ctx context.Context, idHash, csrf string, created, expires time.Time) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,csrf_token) VALUES(?,?,?,?,?,?)`, idHash, LegacyAdminUserID, created.UTC().Format(time.RFC3339Nano), created.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano), csrf)
	return err
}

// CreateSessionWithAudit creates a login session and its audit record in one
// transaction, so a successful login can never be returned without evidence.
func (s *Store) CreateSessionWithAudit(ctx context.Context, idHash, csrf string, created, expires time.Time, action, detail string) error {
	return s.CreateSessionForUserWithAudit(ctx, LegacyAdminUserID, idHash, csrf, created, expires, action, detail)
}

// CreateSessionForUserWithAudit creates a session tied to a concrete user and
// records the login audit atomically.
func (s *Store) CreateSessionForUserWithAudit(ctx context.Context, userID, idHash, csrf string, created, expires time.Time, action, detail string) error {
	return s.CreateSessionForUserWithAuditEntry(ctx, userID, idHash, csrf, created, expires, AuditEntry{Action: action, Detail: detail, ActorUserID: userID})
}

// CreateSessionForUserWithAuditEntry is the actor-aware login primitive. The
// session and its authentication audit record are committed together so a
// successful login cannot be returned without evidence.
func (s *Store) CreateSessionForUserWithAuditEntry(ctx context.Context, userID, idHash, csrf string, created, expires time.Time, audit AuditEntry) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,csrf_token) VALUES(?,?,?,?,?,?)`, idHash, userID, created.UTC().Format(time.RFC3339Nano), created.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano), csrf); err != nil {
		return err
	}
	if audit.Action != "" {
		if err := insertAuditEntryExec(ctx, tx, audit, created.UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) GetSession(ctx context.Context, idHash string) (Session, error) {
	var v Session
	var created, lastSeen, expires string
	err := s.DB.QueryRowContext(ctx, `SELECT id_hash,user_id,created_at,last_seen_at,expires_at,csrf_token FROM sessions WHERE id_hash=?`, idHash).Scan(&v.IDHash, &v.UserID, &created, &lastSeen, &expires, &v.CSRFToken)
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
	return s.DeleteSessionWithAuditEntry(ctx, idHash, AuditEntry{Action: action, Detail: detail})
}

// DeleteSessionWithAuditEntry removes one session and records the actor that
// ended it. The actor fields are additive, so older callers can keep using
// DeleteSessionWithAudit without losing compatibility.
func (s *Store) DeleteSessionWithAuditEntry(ctx context.Context, idHash string, audit AuditEntry) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash=?`, idHash); err != nil {
		return err
	}
	if audit.Action != "" {
		if err := insertAuditEntryExec(ctx, tx, audit, time.Now().UTC()); err != nil {
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
	return s.SaveRecoveryCodesForUser(ctx, LegacyAdminUserID, hashes)
}

func (s *Store) SaveRecoveryCodesForUser(ctx context.Context, userID string, hashes []string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, hash := range hashes {
		if _, err = tx.ExecContext(ctx, `INSERT INTO recovery_codes(id_hash,user_id) VALUES(?,?)`, hash, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ConsumeRecoveryCode(ctx context.Context, hash string, now time.Time) (bool, error) {
	return s.ConsumeRecoveryCodeForUser(ctx, LegacyAdminUserID, hash, now)
}

func (s *Store) ConsumeRecoveryCodeForUser(ctx context.Context, userID, hash string, now time.Time) (bool, error) {
	r, err := s.DB.ExecContext(ctx, `UPDATE recovery_codes SET used_at=? WHERE id_hash=? AND user_id=? AND used_at IS NULL`, now.UTC().Format(time.RFC3339Nano), hash, userID)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

func (s *Store) Audit(ctx context.Context, action, detail string) error {
	return insertAuditExec(ctx, s.DB, action, detail, time.Now().UTC())
}

// AuditEntry records a security event with optional actor attribution. It is
// kept as a small convenience wrapper for mutations that cannot share a
// transaction with their state change (for example, a failed notification
// delivery or a host-initiated recovery action).
func (s *Store) AuditEntry(ctx context.Context, entry AuditEntry) error {
	return insertAuditEntryExec(ctx, s.DB, entry, time.Now().UTC())
}

func insertAuditExec(ctx context.Context, execer contextExecer, action, detail string, now time.Time) error {
	return insertAuditEntryExec(ctx, execer, AuditEntry{Action: action, Detail: detail}, now)
}

func insertAuditEntryExec(ctx context.Context, execer contextExecer, entry AuditEntry, now time.Time) error {
	if strings.TrimSpace(entry.Action) == "" {
		return nil
	}
	if _, err := execer.ExecContext(ctx, `INSERT INTO security_audit(action,detail,actor_user_id,actor_username,source_ip,created_at) VALUES(?,?,?,?,?,?)`, entry.Action, entry.Detail, entry.ActorUserID, entry.ActorUsername, entry.SourceIP, now.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditUnavailable, err)
	}
	return nil
}

func insertAuditEntries(ctx context.Context, execer contextExecer, entries []AuditEntry, now time.Time) error {
	for _, entry := range entries {
		if strings.TrimSpace(entry.Action) == "" {
			continue
		}
		if err := insertAuditEntryExec(ctx, execer, entry, now); err != nil {
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
