package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// LegacyAdminUserID is the stable identity assigned to the administrator that
// existed before multi-user authentication was introduced. Keeping this value
// stable preserves session and audit attribution across upgrades.
const LegacyAdminUserID = "00000000-0000-0000-0000-000000000001"

const (
	RoleAdministrator = "administrator"
	RoleOperator      = "operator"
	RoleViewer        = "viewer"
	// RoleReadOnly is a compatibility alias for integrations that describe the
	// viewer role by its capability rather than its UI label. It serializes as
	// the canonical "viewer" value and does not add another persisted role.
	RoleReadOnly = RoleViewer
)

var validUserRoles = map[string]bool{
	RoleAdministrator: true,
	RoleOperator:      true,
	RoleViewer:        true,
}

// User is the durable identity used by the web console. TOTPSecret is only
// populated when the local encryption key is available; TOTPSecretStored lets
// unrelated profile edits preserve an encrypted value when it is locked.
type User struct {
	ID               string
	Username         string
	DisplayName      string
	Role             string
	PasswordHash     string
	TOTPSecret       string
	TOTPSecretStored string
	TOTPSecretError  error
	TOTPEnabled      bool
	Enabled          bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
	LastLoginAt      time.Time
}

func (u User) Summary() UserSummary {
	return UserSummary{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Role: u.Role, Enabled: u.Enabled, Pending: strings.HasPrefix(u.PasswordHash, "!pending"), TOTPEnabled: u.TOTPEnabled, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt, LastLoginAt: u.LastLoginAt}
}

type UserSummary struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"`
	Enabled     bool      `json:"enabled"`
	Pending     bool      `json:"pending"`
	TOTPEnabled bool      `json:"totp_enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	LastLoginAt time.Time `json:"last_login_at,omitempty"`
}

func ValidateUserRole(role string) error {
	if !validUserRoles[role] {
		return fmt.Errorf("role must be administrator, operator, or viewer")
	}
	return nil
}

func normalizeUsername(username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", errors.New("username cannot be empty")
	}
	if len(username) > 80 {
		return "", errors.New("username must be at most 80 characters")
	}
	for _, r := range username {
		if unicode.IsControl(r) || r == '/' || r == '\\' || r == ':' {
			return "", errors.New("username contains an invalid character")
		}
	}
	return username, nil
}

func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	var u User
	var totp, enabled int
	var created, updated, lastLogin string
	err := s.DB.QueryRowContext(ctx, `SELECT id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at FROM users WHERE id=?`, id).
		Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.PasswordHash, &u.TOTPSecretStored, &totp, &enabled, &created, &updated, &lastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	if err != nil {
		return u, err
	}
	u.TOTPEnabled = totp != 0
	u.Enabled = enabled != 0
	u.CreatedAt, u.UpdatedAt, u.LastLoginAt = scanTime(created), scanTime(updated), scanTime(lastLogin)
	secret, secretErr := s.openTOTPSecret(u.TOTPSecretStored)
	if secretErr != nil {
		u.TOTPSecretError = secretErr
	} else {
		u.TOTPSecret = secret
		if u.TOTPEnabled && secret != "" && !strings.HasPrefix(u.TOTPSecretStored, authCiphertext) {
			if encrypted, encryptErr := s.sealTOTPSecret(secret); encryptErr == nil {
				_, _ = s.DB.ExecContext(ctx, `UPDATE users SET totp_secret=?,updated_at=? WHERE id=? AND totp_secret=?`, encrypted, time.Now().UTC().Format(time.RFC3339Nano), u.ID, u.TOTPSecretStored)
				u.TOTPSecretStored = encrypted
			}
		}
	}
	if strings.TrimSpace(u.DisplayName) == "" {
		u.DisplayName = u.Username
	}
	return u, nil
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	normalized, err := normalizeUsername(username)
	if err != nil {
		return User{}, err
	}
	var id string
	err = s.DB.QueryRowContext(ctx, `SELECT id FROM users WHERE username=? COLLATE NOCASE`, normalized).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, id)
}

func (s *Store) ListUsers(ctx context.Context) ([]UserSummary, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,username,display_name,role,password_hash,enabled,totp_enabled,created_at,updated_at,last_login_at FROM users ORDER BY username COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []UserSummary
	for rows.Next() {
		var u UserSummary
		var passwordHash string
		var enabled, totp int
		var created, updated, lastLogin string
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &passwordHash, &enabled, &totp, &created, &updated, &lastLogin); err != nil {
			return nil, err
		}
		u.Enabled, u.Pending, u.TOTPEnabled = enabled != 0, strings.HasPrefix(passwordHash, "!pending"), totp != 0
		u.CreatedAt, u.UpdatedAt, u.LastLoginAt = scanTime(created), scanTime(updated), scanTime(lastLogin)
		result = append(result, u)
	}
	return result, rows.Err()
}

func (s *Store) CreateUser(ctx context.Context, u User, audit AuditEntry) (User, error) {
	return s.createUser(ctx, u, nil, audit)
}

type userInviteRecord struct {
	idHash  string
	created time.Time
	expires time.Time
}

// CreateUserWithInvite commits the pending account, one-time activation
// invite, and audit entry together. This avoids leaving an unusable account
// behind when invite persistence or the required audit write fails.
func (s *Store) CreateUserWithInvite(ctx context.Context, u User, idHash string, created, expires time.Time, audit AuditEntry) (User, error) {
	if strings.TrimSpace(idHash) == "" {
		return User{}, errors.New("activation token hash is required")
	}
	if !expires.After(created) {
		return User{}, errors.New("activation token expiry must be after creation")
	}
	return s.createUser(ctx, u, &userInviteRecord{idHash: idHash, created: created, expires: expires}, audit)
}

func (s *Store) createUser(ctx context.Context, u User, invite *userInviteRecord, audit AuditEntry) (User, error) {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if _, err := uuid.Parse(u.ID); err != nil {
		return User{}, errors.New("user id must be a UUID")
	}
	username, err := normalizeUsername(u.Username)
	if err != nil {
		return User{}, err
	}
	if err := ValidateUserRole(u.Role); err != nil {
		return User{}, err
	}
	u.Username = username
	if strings.TrimSpace(u.DisplayName) == "" {
		u.DisplayName = username
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = u.CreatedAt
	}
	if invite != nil {
		// An invited account cannot authenticate until it redeems the one-time
		// token. Keep it disabled as well as password-less so the lifecycle is
		// explicit to both the API and the administration UI.
		u.Enabled = false
	}
	stored, err := s.userTOTPForSave(u)
	if err != nil {
		return User{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO users(id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, u.ID, u.Username, u.DisplayName, u.Role, u.PasswordHash, stored, boolInt(u.TOTPEnabled), boolInt(u.Enabled), u.CreatedAt.UTC().Format(time.RFC3339Nano), u.UpdatedAt.UTC().Format(time.RFC3339Nano), ""); err != nil {
		return User{}, err
	}
	if invite != nil {
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_invites(id_hash,user_id,created_at,expires_at,used_at) VALUES(?,?,?,?,NULL)`, invite.idHash, u.ID, invite.created.UTC().Format(time.RFC3339Nano), invite.expires.UTC().Format(time.RFC3339Nano)); err != nil {
			return User{}, err
		}
	}
	if audit.Action != "" {
		if err := insertAuditEntryExec(ctx, tx, audit, time.Now().UTC()); err != nil {
			return User{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	u.TOTPSecretStored = stored
	return u, nil
}

func (s *Store) UpdateUser(ctx context.Context, u User, revokeSessions bool, audit AuditEntry) error {
	if _, err := uuid.Parse(u.ID); err != nil {
		return errors.New("user id must be a UUID")
	}
	username, err := normalizeUsername(u.Username)
	if err != nil {
		return err
	}
	if err := ValidateUserRole(u.Role); err != nil {
		return err
	}
	u.Username = username
	if strings.TrimSpace(u.DisplayName) == "" {
		u.DisplayName = username
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = time.Now().UTC()
	}
	stored, err := s.userTOTPForSave(u)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentRole string
	var currentEnabled int
	if err := tx.QueryRowContext(ctx, `SELECT role,enabled FROM users WHERE id=?`, u.ID).Scan(&currentRole, &currentEnabled); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	// Keep the last enabled administrator invariant inside the same write
	// transaction as the role/state update. The HTTP layer performs an early
	// check for a friendly response, but this guard also closes the race where
	// two administrators attempt to demote or disable the final account at the
	// same time.
	if currentRole == RoleAdministrator && currentEnabled != 0 && (u.Role != RoleAdministrator || !u.Enabled) {
		var otherAdministrators int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role=? AND enabled=1 AND id<>?`, RoleAdministrator, u.ID).Scan(&otherAdministrators); err != nil {
			return err
		}
		if otherAdministrators == 0 {
			return ErrLastAdministrator
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE users SET username=?,display_name=?,role=?,password_hash=?,totp_secret=?,totp_enabled=?,enabled=?,updated_at=? WHERE id=?`, u.Username, u.DisplayName, u.Role, u.PasswordHash, stored, boolInt(u.TOTPEnabled), boolInt(u.Enabled), u.UpdatedAt.UTC().Format(time.RFC3339Nano), u.ID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrNotFound
	}
	if revokeSessions {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, u.ID); err != nil {
			return err
		}
	}
	// A disabled account must not retain an activation or password-reset link.
	// Otherwise a link issued before the disable could silently re-enable the
	// account when redeemed later. Keep this revocation in the same transaction
	// as the user-state change so there is no race window.
	if !u.Enabled {
		if _, err := tx.ExecContext(ctx, `UPDATE user_invites SET used_at=? WHERE user_id=? AND used_at IS NULL`, u.UpdatedAt.UTC().Format(time.RFC3339Nano), u.ID); err != nil {
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

func (s *Store) SetUserLastLogin(ctx context.Context, id string, at time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET last_login_at=?,updated_at=? WHERE id=?`, at.UTC().Format(time.RFC3339Nano), at.UTC().Format(time.RFC3339Nano), id)
	return err
}

func (s *Store) SetUserPassword(ctx context.Context, id, hash string, revokeSessions bool, audit AuditEntry) error {
	u, err := s.GetUser(ctx, id)
	if err != nil {
		return err
	}
	u.PasswordHash = hash
	u.UpdatedAt = time.Now().UTC()
	return s.UpdateUser(ctx, u, revokeSessions, audit)
}

func (s *Store) SaveUserSecurity(ctx context.Context, u User, recoveryCodes []string, replaceRecoveryCodes, revokeSessions bool, audit AuditEntry) error {
	if _, err := uuid.Parse(u.ID); err != nil {
		return err
	}
	if err := ValidateUserRole(u.Role); err != nil {
		return err
	}
	if strings.TrimSpace(u.DisplayName) == "" {
		u.DisplayName = u.Username
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = time.Now().UTC()
	}
	stored, err := s.userTOTPForSave(u)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentRole string
	var currentEnabled int
	if err := tx.QueryRowContext(ctx, `SELECT role,enabled FROM users WHERE id=?`, u.ID).Scan(&currentRole, &currentEnabled); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	// TOTP and host-recovery writes must enforce the same last-administrator
	// invariant as profile updates. Keeping this check in the transaction
	// closes the race where two security mutations demote or disable the final
	// enabled administrator concurrently.
	if currentRole == RoleAdministrator && currentEnabled != 0 && (u.Role != RoleAdministrator || !u.Enabled) {
		var otherAdministrators int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role=? AND enabled=1 AND id<>?`, RoleAdministrator, u.ID).Scan(&otherAdministrators); err != nil {
			return err
		}
		if otherAdministrators == 0 {
			return ErrLastAdministrator
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE users SET display_name=?,role=?,password_hash=?,totp_secret=?,totp_enabled=?,enabled=?,updated_at=? WHERE id=?`, u.DisplayName, u.Role, u.PasswordHash, stored, boolInt(u.TOTPEnabled), boolInt(u.Enabled), u.UpdatedAt.UTC().Format(time.RFC3339Nano), u.ID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrNotFound
	}
	if replaceRecoveryCodes {
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=?`, u.ID); err != nil {
			return err
		}
		for _, hash := range recoveryCodes {
			if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(id_hash,user_id) VALUES(?,?)`, hash, u.ID); err != nil {
				return err
			}
		}
	}
	if revokeSessions {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, u.ID); err != nil {
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

func (s *Store) userTOTPForSave(u User) (string, error) {
	if !u.TOTPEnabled || u.TOTPSecret == "" {
		if u.TOTPEnabled && u.TOTPSecret == "" && u.TOTPSecretStored != "" {
			return u.TOTPSecretStored, nil
		}
		if u.TOTPEnabled {
			return "", ErrTOTPSecretLocked
		}
		return "", nil
	}
	return s.sealTOTPSecret(u.TOTPSecret)
}

func (s *Store) CountEnabledAdministrators(ctx context.Context) (int, error) {
	var count int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role=? AND enabled=1`, RoleAdministrator).Scan(&count)
	return count, err
}

func (s *Store) DeleteUserSessionsWithAudit(ctx context.Context, userID string, audit AuditEntry) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID); err != nil {
		return err
	}
	if audit.Action != "" {
		if err := insertAuditEntryExec(ctx, tx, audit, time.Now().UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) CreateUserInvite(ctx context.Context, idHash, userID string, created, expires time.Time) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO user_invites(id_hash,user_id,created_at,expires_at,used_at) VALUES(?,?,?,?,NULL)`, idHash, userID, created.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano))
	return err
}

// CreateUserInviteWithAudit stores a replacement activation/password-reset
// token and its audit record atomically. The clear token never reaches this
// method; only its SHA-256 digest is persisted.
func (s *Store) CreateUserInviteWithAudit(ctx context.Context, idHash, userID string, created, expires time.Time, audit AuditEntry) error {
	if strings.TrimSpace(idHash) == "" || strings.TrimSpace(userID) == "" {
		return errors.New("activation token and user are required")
	}
	if !expires.After(created) {
		return errors.New("activation token expiry must be after creation")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Issuing a new activation/password-reset link invalidates any older
	// outstanding link for the same account. This leaves a single recovery
	// path and makes a copied, superseded token unusable.
	if _, err := tx.ExecContext(ctx, `UPDATE user_invites SET used_at=? WHERE user_id=? AND used_at IS NULL`, created.UTC().Format(time.RFC3339Nano), userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_invites(id_hash,user_id,created_at,expires_at,used_at) VALUES(?,?,?,?,NULL)`, idHash, userID, created.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if audit.Action != "" {
		if err := insertAuditEntryExec(ctx, tx, audit, created.UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RevokeUserInvitesWithAudit invalidates every outstanding activation or
// password-reset link for one account. Only the token hash is stored, and the
// operation is audited atomically with the revocation.
func (s *Store) RevokeUserInvitesWithAudit(ctx context.Context, userID string, now time.Time, audit AuditEntry) (int, error) {
	if strings.TrimSpace(userID) == "" {
		return 0, errors.New("user is required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var present int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id=?`, userID).Scan(&present); errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	} else if err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE user_invites SET used_at=? WHERE user_id=? AND used_at IS NULL`, now.UTC().Format(time.RFC3339Nano), userID)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if audit.Action != "" {
		if err := insertAuditEntryExec(ctx, tx, audit, now.UTC()); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(affected), nil
}

// ActivateUser atomically consumes an invite and installs the new Argon2id
// password. A failed audit write rolls the activation back so the token can
// be retried after the audit store is repaired.
func (s *Store) ActivateUser(ctx context.Context, idHash, passwordHash string, now time.Time, audit AuditEntry) (User, error) {
	if strings.TrimSpace(idHash) == "" || strings.TrimSpace(passwordHash) == "" {
		return User{}, errors.New("activation token and password are required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	var userID, expires, currentPasswordHash string
	var currentEnabled int
	var used sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT i.user_id,i.expires_at,i.used_at,u.password_hash,u.enabled FROM user_invites i JOIN users u ON u.id=i.user_id WHERE i.id_hash=?`, idHash).Scan(&userID, &expires, &used, &currentPasswordHash, &currentEnabled); errors.Is(err, sql.ErrNoRows) {
		return User{}, errors.New("invalid activation token")
	} else if err != nil {
		return User{}, err
	}
	if used.Valid || !now.Before(scanTime(expires)) {
		return User{}, errors.New("activation token expired or already used")
	}
	// Pending users start disabled and have the sentinel password, so their
	// first activation remains valid. A previously configured account that an
	// administrator disabled must not be re-enabled by an older reset link;
	// disabling also revokes the link transactionally, but this check is a
	// defence in depth for legacy rows and concurrent callers.
	if currentEnabled == 0 && !strings.HasPrefix(currentPasswordHash, "!pending") {
		return User{}, errors.New("account is disabled")
	}
	result, err := tx.ExecContext(ctx, `UPDATE user_invites SET used_at=? WHERE id_hash=? AND used_at IS NULL`, now.UTC().Format(time.RFC3339Nano), idHash)
	if err != nil {
		return User{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return User{}, errors.New("activation token expired or already used")
	}
	updated := now.UTC().Format(time.RFC3339Nano)
	result, err = tx.ExecContext(ctx, `UPDATE users SET password_hash=?,enabled=1,updated_at=? WHERE id=?`, passwordHash, updated, userID)
	if err != nil {
		return User{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return User{}, ErrNotFound
	}
	// Activation also serves as the administrator-issued password-reset path.
	// Any browser sessions created with the previous password must be revoked
	// before the new credential becomes usable, otherwise a reset would leave
	// already authenticated clients active.
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID); err != nil {
		return User{}, err
	}
	if audit.Action != "" && audit.ActorUserID == "" {
		audit.ActorUserID = userID
	}
	if audit.Action != "" && audit.ActorUsername == "" {
		_ = tx.QueryRowContext(ctx, `SELECT username FROM users WHERE id=?`, userID).Scan(&audit.ActorUsername)
	}
	if audit.Action != "" {
		if err := insertAuditEntryExec(ctx, tx, audit, now.UTC()); err != nil {
			return User{}, err
		}
	}
	var u User
	var totp, enabled int
	var created, updatedAt, lastLogin string
	if err := tx.QueryRowContext(ctx, `SELECT id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at FROM users WHERE id=?`, userID).Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.PasswordHash, &u.TOTPSecretStored, &totp, &enabled, &created, &updatedAt, &lastLogin); err != nil {
		return User{}, err
	}
	u.TOTPEnabled, u.Enabled = totp != 0, enabled != 0
	u.CreatedAt, u.UpdatedAt, u.LastLoginAt = scanTime(created), scanTime(updatedAt), scanTime(lastLogin)
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return u, nil
}

func (s *Store) ConsumeUserInvite(ctx context.Context, idHash string, now time.Time) (User, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	var userID, expires string
	var used sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT user_id,expires_at,used_at FROM user_invites WHERE id_hash=?`, idHash).Scan(&userID, &expires, &used); errors.Is(err, sql.ErrNoRows) {
		return User{}, errors.New("invalid activation token")
	} else if err != nil {
		return User{}, err
	}
	if used.Valid || !now.Before(scanTime(expires)) {
		return User{}, errors.New("activation token expired or already used")
	}
	result, err := tx.ExecContext(ctx, `UPDATE user_invites SET used_at=? WHERE id_hash=? AND used_at IS NULL`, now.UTC().Format(time.RFC3339Nano), idHash)
	if err != nil {
		return User{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return User{}, errors.New("activation token expired or already used")
	}
	var u User
	var totp, enabled int
	var created, updated, lastLogin string
	if err := tx.QueryRowContext(ctx, `SELECT id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at FROM users WHERE id=?`, userID).Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.PasswordHash, &u.TOTPSecretStored, &totp, &enabled, &created, &updated, &lastLogin); err != nil {
		return User{}, err
	}
	u.TOTPEnabled, u.Enabled = totp != 0, enabled != 0
	u.CreatedAt, u.UpdatedAt, u.LastLoginAt = scanTime(created), scanTime(updated), scanTime(lastLogin)
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return u, nil
}
