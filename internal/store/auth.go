package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrAuditUnavailable indicates that a security-sensitive mutation could not
// record its required audit row. Callers should fail closed (or report the
// operation as degraded) rather than claiming a successful audited action.
var ErrAuditUnavailable = errors.New("security audit unavailable")

// auditPersistenceTimeout bounds standalone audit writes while detaching them
// from a request's cancellation and deadline. Mutations that include an audit
// row in their own transaction continue to use the caller context so they can
// roll back together; this helper is only for post-action, non-transactional
// audit records.
const auditPersistenceTimeout = 5 * time.Second

func auditPersistenceContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), auditPersistenceTimeout)
}

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
	RequestID     string
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
	// Revision mirrors the authoritative users row for the legacy administrator
	// identity. It lets compatibility admin writers participate in the same
	// optimistic-concurrency guard as multi-user updates.
	Revision int64
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

// GetAdmin returns the original administrator, the users row with
// LegacyAdminUserID, without mutating the database. Schema 52 retired the
// legacy admins row, so a missing users row is ErrNotFound. TOTP ciphertext
// upgrades are performed by MigrateAdminCompatibility during daemon startup.
func (s *Store) GetAdmin(ctx context.Context) (Admin, error) {
	var a Admin
	var stored, created, updated string
	var totp int
	err := s.reader().QueryRowContext(ctx, `SELECT username,display_name,password_hash,totp_secret,totp_enabled,created_at,updated_at,revision FROM users WHERE id=?`, LegacyAdminUserID).
		Scan(&a.Username, &a.DisplayName, &a.PasswordHash, &stored, &totp, &created, &updated, &a.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return Admin{}, ErrNotFound
	}
	if err != nil {
		return Admin{}, err
	}
	a.DisplayName = adminDisplayName(a)
	a.TOTPEnabled = totp != 0
	a.CreatedAt, a.UpdatedAt = scanTime(created), scanTime(updated)
	a.TOTPSecretStored = stored
	secret, _, secretErr := s.openTOTPSecretForOwner(LegacyAdminUserID, stored)
	if secretErr != nil {
		a.TOTPSecretError = secretErr
	} else {
		a.TOTPSecret = secret
	}
	return a, nil
}

// HasAdministrator reports whether an administrator account exists. Only
// users counts: schema 52 retired the legacy admins row, and a database
// without a users table is an error rather than an unconfigured one.
func (s *Store) HasAdministrator(ctx context.Context) (bool, error) {
	var present int
	err := s.reader().QueryRowContext(ctx, `SELECT 1 FROM users WHERE role=? LIMIT 1`, RoleAdministrator).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// SaveAdmin writes the original administrator to its users row, and creates
// that row in the default tenant when it is missing.
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
	// Create the users row when it is missing. The update below writes the
	// values in both cases.
	if _, err := execer.ExecContext(ctx, `INSERT OR IGNORE INTO users(id,tenant_id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, LegacyAdminUserID, DefaultTenantID, a.Username, adminDisplayName(a), RoleAdministrator, a.PasswordHash, stored, boolInt(a.TOTPEnabled), 1, a.CreatedAt.UTC().Format(time.RFC3339Nano), a.UpdatedAt.UTC().Format(time.RFC3339Nano), ""); err != nil {
		return err
	}
	expectedRevision := a.Revision
	if expectedRevision > 0 {
		result, updateErr := execer.ExecContext(ctx, `UPDATE users SET username=?,display_name=?,password_hash=?,totp_secret=?,totp_enabled=?,updated_at=?,revision=revision+1 WHERE id=? AND revision=?`, a.Username, adminDisplayName(a), a.PasswordHash, stored, boolInt(a.TOTPEnabled), a.UpdatedAt.UTC().Format(time.RFC3339Nano), LegacyAdminUserID, expectedRevision)
		if updateErr != nil {
			return updateErr
		}
		if affected, affectedErr := result.RowsAffected(); affectedErr != nil || affected != 1 {
			if affectedErr != nil {
				return affectedErr
			}
			return ErrConflict
		}
		return nil
	}
	_, err := execer.ExecContext(ctx, `UPDATE users SET username=?,display_name=?,password_hash=?,totp_secret=?,totp_enabled=?,updated_at=?,revision=revision+1 WHERE id=?`, a.Username, adminDisplayName(a), a.PasswordHash, stored, boolInt(a.TOTPEnabled), a.UpdatedAt.UTC().Format(time.RFC3339Nano), LegacyAdminUserID)
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
	return s.SaveAdminSecurityWithAuditPreservingSession(ctx, a, recoveryCodes, replaceRecoveryCodes, revokeSessions, audit, "")
}

// SaveAdminSecurityWithAuditPreservingSession applies an administrator security
// mutation while revoking every other session for that account. The optional
// preserved hash is used by TOTP enrollment so the browser can keep displaying
// the one-time recovery codes returned by the same request. An empty hash keeps
// the historical behavior and revokes all administrator sessions.
func (s *Store) SaveAdminSecurityWithAuditPreservingSession(ctx context.Context, a Admin, recoveryCodes []string, replaceRecoveryCodes, revokeSessions bool, audit AuditEntry, preserveSessionHash string) error {
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
		if preserveSessionHash = strings.TrimSpace(preserveSessionHash); preserveSessionHash == "" {
			if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=? OR user_id=''`, LegacyAdminUserID); err != nil {
				return err
			}
		} else if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE (user_id=? OR user_id='') AND id_hash<>?`, LegacyAdminUserID, preserveSessionHash); err != nil {
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
	return s.sealTOTPSecretForOwner(LegacyAdminUserID, a.TOTPSecret)
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
	err := s.reader().QueryRowContext(ctx, `SELECT expires_at,used_at,issued_at FROM setup_tokens WHERE id=1`).Scan(&expires, &used, &issued)
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
	if err := requireNoAdministratorTx(ctx, tx); err != nil {
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

// requireNoAdministratorTx fails when an administrator account exists. It is
// the in-transaction form of HasAdministrator for the setup token writers.
func requireNoAdministratorTx(ctx context.Context, tx *sql.Tx) error {
	var administrators int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role=?`, RoleAdministrator).Scan(&administrators); err != nil {
		return err
	}
	if administrators > 0 {
		return errors.New("administrator is already configured")
	}
	return nil
}

// CompleteSetup consumes the token and creates the one permitted administrator
// in the default tenant in one transaction, preventing a token race from
// creating two accounts.
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
	if err := requireNoAdministratorTx(ctx, tx); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, LegacyAdminUserID, DefaultTenantID, admin.Username, adminDisplayName(admin), RoleAdministrator, admin.PasswordHash, storedSecret, boolInt(admin.TOTPEnabled), 1, admin.CreatedAt.UTC().Format(time.RFC3339Nano), admin.UpdatedAt.UTC().Format(time.RFC3339Nano), ""); err != nil {
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
	// Keep the compatibility entry point on the same transactional primitive as
	// user-scoped sessions. It intentionally omits an audit row for callers that
	// predate the audited login API, but it can no longer bypass user attribution
	// or the session schema safeguards.
	return s.CreateSessionForUserWithAuditEntry(ctx, LegacyAdminUserID, idHash, csrf, created, expires, AuditEntry{})
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

// CreateSessionForUserIfCurrent creates a session only when the credential
// material that was verified by the authentication layer is still current.
// The comparison and insert share one transaction so a password, TOTP, or
// enabled-state change cannot race a successful login and leave a stale
// session behind.
func (s *Store) CreateSessionForUserIfCurrent(ctx context.Context, userID, expectedPasswordHash string, expectedRevision int64, expectedTOTPEnabled bool, idHash, csrf string, created, expires time.Time, audit AuditEntry) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var passwordHash string
	var totpEnabled, enabled int
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT password_hash,totp_enabled,enabled,revision FROM users WHERE id=?`, userID).Scan(&passwordHash, &totpEnabled, &enabled, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrSessionCredentialsChanged
	}
	if err != nil {
		return err
	}
	if enabled == 0 || revision != expectedRevision || passwordHash != expectedPasswordHash || (totpEnabled != 0) != expectedTOTPEnabled {
		return ErrSessionCredentialsChanged
	}
	stamp := created.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,csrf_token) VALUES(?,?,?,?,?,?)`, idHash, userID, stamp, stamp, expires.UTC().Format(time.RFC3339Nano), csrf); err != nil {
		return err
	}
	if audit.Action != "" {
		if err := insertAuditEntryExec(ctx, tx, audit, created.UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CreateSessionForUserWithPasswordUpgradeIfCurrent atomically upgrades a
// verified legacy password and creates its session only when every credential
// revision still matches the values read before Argon2id verification.
func (s *Store) CreateSessionForUserWithPasswordUpgradeIfCurrent(ctx context.Context, userID, previousHash, upgradedHash string, expectedRevision int64, expectedTOTPEnabled bool, idHash, csrf string, created, expires time.Time, audit AuditEntry) error {
	if strings.TrimSpace(upgradedHash) == "" {
		return errors.New("upgraded password hash is required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stamp := created.UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=?,last_login_at=?,updated_at=?,revision=revision+1 WHERE id=? AND password_hash=? AND revision=? AND totp_enabled=? AND enabled=1`, upgradedHash, stamp, stamp, userID, previousHash, expectedRevision, boolInt(expectedTOTPEnabled))
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrSessionCredentialsChanged
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,csrf_token) VALUES(?,?,?,?,?,?)`, idHash, userID, stamp, stamp, expires.UTC().Format(time.RFC3339Nano), csrf); err != nil {
		return err
	}
	if audit.Action != "" {
		if err := insertAuditEntryExec(ctx, tx, audit, created.UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CreateSessionForUserWithPasswordUpgrade atomically upgrades a verified
// password hash with the login session and its audit record. The conditional
// update protects against overwriting a password changed concurrently while
// the login was in progress.
func (s *Store) CreateSessionForUserWithPasswordUpgrade(ctx context.Context, userID, previousHash, upgradedHash, idHash, csrf string, created, expires time.Time, audit AuditEntry) error {
	if strings.TrimSpace(upgradedHash) == "" {
		return errors.New("upgraded password hash is required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stamp := created.UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=?,last_login_at=?,updated_at=?,revision=revision+1 WHERE id=? AND password_hash=?`, upgradedHash, stamp, stamp, userID, previousHash)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrPasswordChangedDuringLogin
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,csrf_token) VALUES(?,?,?,?,?,?)`, idHash, userID, stamp, stamp, expires.UTC().Format(time.RFC3339Nano), csrf); err != nil {
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
	err := s.reader().QueryRowContext(ctx, `SELECT id_hash,user_id,created_at,last_seen_at,expires_at,csrf_token FROM sessions WHERE id_hash=?`, idHash).Scan(&v.IDHash, &v.UserID, &created, &lastSeen, &expires, &v.CSRFToken)
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

// TouchSessionIfStale advances a session's idle timestamp only when its
// current timestamp is at or before staleBefore. The predicate makes refreshes
// from multiple tabs coalesce to one writer operation per activity interval.
func (s *Store) TouchSessionIfStale(ctx context.Context, idHash string, lastSeen, expires, staleBefore time.Time) (bool, error) {
	result, err := s.DB.ExecContext(ctx, `UPDATE sessions SET last_seen_at=?,expires_at=? WHERE id_hash=? AND julianday(last_seen_at) <= julianday(?)`, lastSeen.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano), idHash, staleBefore.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows > 0, err
}

func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	return s.DeleteSessionWithAuditEntry(ctx, idHash, AuditEntry{})
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
			// Revocation is security-critical and must not be rolled back just
			// because the audit table is unavailable. Retry the deletion in a
			// detached short-lived context, then report the audit failure so the
			// caller can surface a degraded-but-safe response.
			_ = tx.Rollback()
			if revokeErr := s.deleteSessionWithoutAudit(ctx, idHash); revokeErr != nil {
				return errors.Join(err, revokeErr)
			}
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) deleteSessionWithoutAudit(ctx context.Context, idHash string) error {
	persistCtx, cancel := auditPersistenceContext(ctx)
	defer cancel()
	_, err := s.DB.ExecContext(persistCtx, `DELETE FROM sessions WHERE id_hash=?`, idHash)
	return err
}

func (s *Store) DeleteAllSessions(ctx context.Context) error {
	return s.DeleteAllSessionsWithAudit(ctx, "", "")
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
			_ = tx.Rollback()
			persistCtx, cancel := auditPersistenceContext(ctx)
			_, revokeErr := s.DB.ExecContext(persistCtx, `DELETE FROM sessions`)
			cancel()
			if revokeErr != nil {
				return errors.Join(err, revokeErr)
			}
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

// ConsumeRecoveryCodeTextForUser verifies a presented recovery code against
// the user's unused v2 codes and atomically marks the matching row consumed.
// Unsalted legacy SHA-256 digests are retired by schema migration 38 and are
// never accepted on the authentication path.
func (s *Store) ConsumeRecoveryCodeTextForUser(ctx context.Context, userID, code string, now time.Time) (bool, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return false, nil
	}
	rows, err := s.reader().QueryContext(ctx, `SELECT id_hash FROM recovery_codes WHERE user_id=? AND used_at IS NULL`, userID)
	if err != nil {
		return false, err
	}
	var match string
	for rows.Next() {
		var stored string
		if err := rows.Scan(&stored); err != nil {
			_ = rows.Close()
			return false, err
		}
		if recoveryCodeMatches(stored, code) {
			match = stored
			break
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return false, err
	}
	_ = rows.Close()
	if match == "" {
		return false, nil
	}
	result, err := s.DB.ExecContext(ctx, `UPDATE recovery_codes SET used_at=? WHERE user_id=? AND id_hash=? AND used_at IS NULL`, now.UTC().Format(time.RFC3339Nano), userID, match)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

func recoveryCodeMatches(stored, code string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 3 || parts[0] != "v2" {
		return false
	}
	salt, saltErr := base64.RawStdEncoding.DecodeString(parts[1])
	expected, hashErr := hex.DecodeString(parts[2])
	if saltErr != nil || hashErr != nil || len(salt) < 16 || len(expected) != sha256.Size {
		return false
	}
	h := sha256.New()
	_, _ = h.Write(salt)
	_, _ = h.Write([]byte(code))
	return hmac.Equal(h.Sum(nil), expected)
}

func (s *Store) Audit(ctx context.Context, action, detail string) error {
	persistCtx, cancel := auditPersistenceContext(ctx)
	defer cancel()
	return insertAuditExec(persistCtx, s.DB, action, detail, time.Now().UTC())
}

// AuditEntry records a security event with optional actor attribution. It is
// kept as a small convenience wrapper for mutations that cannot share a
// transaction with their state change (for example, a failed notification
// delivery or a host-initiated recovery action).
func (s *Store) AuditEntry(ctx context.Context, entry AuditEntry) error {
	persistCtx, cancel := auditPersistenceContext(ctx)
	defer cancel()
	return insertAuditEntryExec(persistCtx, s.DB, entry, time.Now().UTC())
}

func insertAuditExec(ctx context.Context, execer contextExecer, action, detail string, now time.Time) error {
	return insertAuditEntryExec(ctx, execer, AuditEntry{Action: action, Detail: detail}, now)
}

func insertAuditEntryExec(ctx context.Context, execer contextExecer, entry AuditEntry, now time.Time) error {
	if strings.TrimSpace(entry.Action) == "" {
		return nil
	}
	requestContext := auditContextFromContext(ctx)
	if strings.TrimSpace(entry.RequestID) == "" {
		entry.RequestID = requestContext.RequestID
	}
	if strings.TrimSpace(entry.SourceIP) == "" {
		entry.SourceIP = requestContext.SourceIP
	}
	createdAt := now.UTC().Format(time.RFC3339Nano)
	// Every record belongs to the default tenant, the only tenant for now.
	_, err := execer.ExecContext(ctx, `INSERT INTO security_audit(action,detail,actor_user_id,actor_username,source_ip,request_id,category,tenant_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, entry.Action, entry.Detail, entry.ActorUserID, entry.ActorUsername, entry.SourceIP, entry.RequestID, auditCategory(entry.Action), DefaultTenantID, createdAt)
	if err != nil {
		// Host commands open the database without migrating it, for example
		// the restored copy of an older backup. Before schema 51 the table
		// has no category or tenant_id column; record the entry without
		// them, and the migration categorizes and attributes it later.
		if legacy, checkErr := auditTableLacksCategory(ctx, execer); checkErr == nil && legacy {
			_, err = execer.ExecContext(ctx, `INSERT INTO security_audit(action,detail,actor_user_id,actor_username,source_ip,request_id,created_at) VALUES(?,?,?,?,?,?,?)`, entry.Action, entry.Detail, entry.ActorUserID, entry.ActorUsername, entry.SourceIP, entry.RequestID, createdAt)
		}
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuditUnavailable, err)
	}
	return nil
}

// auditTableLacksCategory reports whether security_audit exists without the
// category column that schema 51 adds.
func auditTableLacksCategory(ctx context.Context, execer contextExecer) (bool, error) {
	queryer, ok := execer.(interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	})
	if !ok {
		return false, nil
	}
	var columns, categories int
	if err := queryer.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(name='category'),0) FROM pragma_table_info('security_audit')`).Scan(&columns, &categories); err != nil {
		return false, err
	}
	return columns > 0 && categories == 0, nil
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
	err := s.reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE used_at IS NULL`).Scan(&n)
	return n, err
}
