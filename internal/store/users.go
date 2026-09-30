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

// validUserRoles are the roles of a tenant's account. A platform
// administrator is a separate account with no tenant, and no tenant's
// account management creates or grants that role.
var validUserRoles = map[string]bool{
	RoleAdministrator: true,
	RoleOperator:      true,
	RoleViewer:        true,
}

// ErrUsernameUnavailable reports that an account already has the username.
// Usernames are unique across every tenant, and the error does not say
// which tenant holds the name.
var ErrUsernameUnavailable = errors.New("username is not available")

// User is the durable identity used by the web console. TOTPSecret is only
// populated when the local encryption key is available; TOTPSecretStored lets
// unrelated profile edits preserve an encrypted value when it is locked.
type User struct {
	ID string
	// TenantID is the account's tenant, as users stores it, and empty for a
	// platform administrator. UserSummary leaves it out, so no response
	// names a tenant.
	TenantID         string
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
	Revision         int64
}

func (u User) Summary() UserSummary {
	return UserSummary{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Role: u.Role, Enabled: u.Enabled, Pending: strings.HasPrefix(u.PasswordHash, "!pending"), TOTPEnabled: u.TOTPEnabled, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt, LastLoginAt: u.LastLoginAt, Revision: u.Revision}
}

// UserSummary is an account without its credentials, as the console lists
// it. LastLoginAt is the zero time for an account that never signed in, and
// the JSON then leaves last_login_at out.
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
	LastLoginAt time.Time `json:"last_login_at,omitzero"`
	Revision    int64     `json:"revision"`
}

func ValidateUserRole(role string) error {
	if !validUserRoles[role] {
		return fmt.Errorf("role must be administrator, operator, or viewer")
	}
	return nil
}

// MaxUsernameBytes bounds a username's UTF-8 encoding. The limit counts
// bytes, not characters, so a name with accented or non-Latin characters
// reaches it sooner.
const MaxUsernameBytes = 80

// NormalizeUsername validates a username and returns its stored, lower-case
// form. Handlers call it before a write so a rejected name is reported as a
// field-level validation error instead of a failed store call.
func NormalizeUsername(username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", errors.New("username cannot be empty")
	}
	if len(username) > MaxUsernameBytes {
		return "", fmt.Errorf("username must be at most %d bytes; accented and non-Latin characters use 2 to 4 bytes each", MaxUsernameBytes)
	}
	for _, r := range username {
		if unicode.IsControl(r) || r == '/' || r == '\\' || r == ':' {
			return "", errors.New(`username must not contain control characters, "/", "\", or ":"`)
		}
	}
	// SQLite's NOCASE collation is ASCII-only. Persisting one Unicode-aware
	// lower-case representation keeps activation and login lookups consistent
	// across scripts while preserving the original spelling only in the display
	// name field.
	return strings.ToLower(username), nil
}

// userColumns are the users columns that scanUser reads, in its order.
const userColumns = `id,COALESCE(tenant_id,''),username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at,revision`

// tenantUserSQL is the ID of the tenant's account with the given ID, or
// NULL when the tenant has no such account. It takes two arguments, the
// account ID and the tenant ID. The TenantStore methods name the rows of an
// account's sessions, invites, and recovery codes through it, so a
// statement cannot reach another tenant's account even if the check before
// it were skipped.
const tenantUserSQL = `(SELECT id FROM users WHERE id=? AND tenant_id=?)`

// scanUser reads a row of userColumns without decrypting the TOTP secret.
func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var totp, enabled int
	var created, updated, lastLogin string
	if err := row.Scan(&u.ID, &u.TenantID, &u.Username, &u.DisplayName, &u.Role, &u.PasswordHash, &u.TOTPSecretStored, &totp, &enabled, &created, &updated, &lastLogin, &u.Revision); err != nil {
		return User{}, err
	}
	u.TOTPEnabled, u.Enabled = totp != 0, enabled != 0
	u.CreatedAt, u.UpdatedAt, u.LastLoginAt = scanTime(created), scanTime(updated), scanTime(lastLogin)
	return u, nil
}

// readUser returns the one account that the query of userColumns finds, with
// its decrypted TOTP projection, without upgrading ciphertext or otherwise
// mutating the database. Legacy secret upgrades are handled by the explicit
// startup migration. No account is ErrNotFound.
func (s *Store) readUser(ctx context.Context, query string, args ...any) (User, error) {
	u, err := scanUser(s.reader().QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	secret, _, secretErr := s.openTOTPSecretForOwner(u.ID, u.TOTPSecretStored)
	if secretErr != nil {
		u.TOTPSecretError = secretErr
	} else {
		u.TOTPSecret = secret
	}
	if strings.TrimSpace(u.DisplayName) == "" {
		u.DisplayName = u.Username
	}
	return u, nil
}

// GetUser returns the tenant's account with the given ID and its decrypted
// TOTP projection. Another tenant's account is ErrNotFound, as an unknown
// ID is.
func (ts *TenantStore) GetUser(ctx context.Context, id string) (User, error) {
	if err := ts.ready(); err != nil {
		return User{}, err
	}
	return ts.store.readUser(ctx, `SELECT `+userColumns+` FROM users WHERE id=? AND tenant_id=?`, id, ts.scope.id)
}

// GetAccount returns the account with the given ID, whatever its tenant,
// with the tenant in User.TenantID. It stays global for authentication,
// which knows the account from a verified session, sign-in, or password
// confirmation before any tenant scope exists. Managing accounts goes
// through TenantStore.GetUser, which finds only the tenant's own.
func (s *Store) GetAccount(ctx context.Context, id string) (User, error) {
	return s.readUser(ctx, `SELECT `+userColumns+` FROM users WHERE id=?`, id)
}

// GetUserByUsername returns the account with the username, whatever its
// tenant, with the tenant in User.TenantID. It stays global: sign-in and the
// host CLI name an account before any tenant scope exists, and usernames are
// unique across tenants.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	normalized, err := NormalizeUsername(username)
	if err != nil {
		return User{}, err
	}
	return s.readUser(ctx, `SELECT `+userColumns+` FROM users WHERE username=? COLLATE NOCASE`, normalized)
}

// ListUsers lists the tenant's accounts by username.
func (ts *TenantStore) ListUsers(ctx context.Context) ([]UserSummary, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	rows, err := ts.store.reader().QueryContext(ctx, `SELECT id,username,display_name,role,password_hash,enabled,totp_enabled,created_at,updated_at,last_login_at,revision FROM users WHERE tenant_id=? ORDER BY username COLLATE NOCASE`, ts.scope.id)
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
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &passwordHash, &enabled, &totp, &created, &updated, &lastLogin, &u.Revision); err != nil {
			return nil, err
		}
		u.Enabled, u.Pending, u.TOTPEnabled = enabled != 0, strings.HasPrefix(passwordHash, "!pending"), totp != 0
		u.CreatedAt, u.UpdatedAt, u.LastLoginAt = scanTime(created), scanTime(updated), scanTime(lastLogin)
		result = append(result, u)
	}
	return result, rows.Err()
}

// CreateUser creates an account in the tenant, with its audit record.
func (ts *TenantStore) CreateUser(ctx context.Context, u User, audit AuditEntry) (User, error) {
	if err := ts.ready(); err != nil {
		return User{}, err
	}
	return ts.createUser(ctx, u, nil, audit, nil)
}

type userInviteRecord struct {
	idHash  string
	created time.Time
	expires time.Time
}

// CreateUserWithInvite commits the pending account, one-time activation
// invite, and audit entry together. This avoids leaving an unusable account
// behind when invite persistence or the required audit write fails. The
// actor, audit.ActorUserID, must still be an enabled administrator of the
// tenant, and the tenant must still be active (see
// requireAdministratorActorTx).
func (ts *TenantStore) CreateUserWithInvite(ctx context.Context, u User, idHash string, created, expires time.Time, audit AuditEntry) (User, error) {
	if err := ts.ready(); err != nil {
		return User{}, err
	}
	if strings.TrimSpace(idHash) == "" {
		return User{}, errors.New("activation token hash is required")
	}
	if !expires.After(created) {
		return User{}, errors.New("activation token expiry must be after creation")
	}
	return ts.createUser(ctx, u, &userInviteRecord{idHash: idHash, created: created, expires: expires}, audit, ts.administratorActor(audit.ActorUserID))
}

// userWriteCheck is a policy check that an account write runs first in its
// own transaction, so the policy holds for the state the write changes.
type userWriteCheck func(ctx context.Context, tx *sql.Tx) error

// administratorActor is the write check of an account write that a
// tenant's administrator makes: see requireAdministratorActorTx.
func (ts *TenantStore) administratorActor(actorID string) userWriteCheck {
	return func(ctx context.Context, tx *sql.Tx) error {
		return ts.requireAdministratorActorTx(ctx, tx, actorID)
	}
}

// requireAdministratorActorTx fails unless the actor is an enabled
// administrator of the tenant and the tenant is active. The web console
// authorizes an administrator's account write when the request arrives, and
// the write commits later; checking again in the write's own transaction
// means that a demotion, a disable, or a paused tenant that committed in
// between stops the write, as requirePlatformActorTx and
// requireActiveTenantTx do for the platform's writes. Any other actor,
// including another tenant's administrator, a platform administrator, and
// an empty ID, is ErrAccountNotPermitted; a tenant that is not active is
// ErrTenantNotActive, and a missing or deleted one ErrNoTenantScope.
func (ts *TenantStore) requireAdministratorActorTx(ctx context.Context, tx *sql.Tx, actorID string) error {
	var present int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id=? AND tenant_id=? AND role=? AND enabled=1`, actorID, ts.scope.id, RoleAdministrator).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: the actor is not an enabled administrator of the unit", ErrAccountNotPermitted)
	}
	if err != nil {
		return err
	}
	return requireActiveTenantTx(ctx, tx, ts.scope.id)
}

// createUser creates the account in the store's tenant. Only the roles of a
// tenant's account are accepted, so a platform administrator is never
// created here. Usernames are unique across tenants; a name that any
// account holds is ErrUsernameUnavailable, which does not say where. A
// non-nil check runs first in the transaction, and its error stops the
// write.
func (ts *TenantStore) createUser(ctx context.Context, u User, invite *userInviteRecord, audit AuditEntry, check userWriteCheck) (User, error) {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if _, err := uuid.Parse(u.ID); err != nil {
		return User{}, errors.New("user id must be a UUID")
	}
	username, err := NormalizeUsername(u.Username)
	if err != nil {
		return User{}, err
	}
	if err := ValidateUserRole(u.Role); err != nil {
		return User{}, err
	}
	u.Username = username
	u.TenantID = ts.scope.id
	if strings.TrimSpace(u.DisplayName) == "" {
		u.DisplayName = username
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = u.CreatedAt
	}
	// New users always begin at revision one. Callers never choose this value;
	// it is advanced only by successful guarded mutations.
	u.Revision = 1
	if invite != nil {
		// An invited account cannot authenticate until it redeems the one-time
		// token. Keep it disabled as well as password-less so the lifecycle is
		// explicit to both the API and the administration UI.
		u.Enabled = false
	}
	stored, err := ts.store.userTOTPForSave(u)
	if err != nil {
		return User{}, err
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	if check != nil {
		if err := check(ctx, tx); err != nil {
			return User{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at,revision) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, u.ID, ts.scope.id, u.Username, u.DisplayName, u.Role, u.PasswordHash, stored, boolInt(u.TOTPEnabled), boolInt(u.Enabled), u.CreatedAt.UTC().Format(time.RFC3339Nano), u.UpdatedAt.UTC().Format(time.RFC3339Nano), "", u.Revision); err != nil {
		return User{}, usernameConflict(err)
	}
	if invite != nil {
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_invites(id_hash,user_id,issuer_user_id,created_at,expires_at,used_at) SELECT ?,id,?,?,?,NULL FROM users WHERE id=? AND tenant_id=?`, invite.idHash, audit.ActorUserID, invite.created.UTC().Format(time.RFC3339Nano), invite.expires.UTC().Format(time.RFC3339Nano), u.ID, ts.scope.id); err != nil {
			return User{}, err
		}
	}
	if audit.Action != "" {
		if err := ts.insertAuditEntry(ctx, tx, audit, time.Now().UTC()); err != nil {
			return User{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	u.TOTPSecretStored = stored
	return u, nil
}

// usernameConflict returns ErrUsernameUnavailable for a write that the
// unique username refused, and any other error unchanged. SQLite's own
// message names only the column, but the store's error names neither the
// column nor the account that holds the name.
func usernameConflict(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed: users.username") {
		return ErrUsernameUnavailable
	}
	return err
}

// UpdateUser updates the tenant's account, at its revision when the value
// names one. Another tenant's account is ErrNotFound, as an unknown ID is,
// and nothing is written. It writes an account's changes to itself and the
// host CLI's; a change that one of the tenant's administrators makes to an
// account goes through UpdateUserByAdministrator.
func (ts *TenantStore) UpdateUser(ctx context.Context, u User, revokeSessions bool, audit AuditEntry) error {
	if err := ts.ready(); err != nil {
		return err
	}
	return ts.updateUser(ctx, u, revokeSessions, audit, nil)
}

// UpdateUserByAdministrator is UpdateUser for a change that one of the
// tenant's administrators makes to an account: the actor,
// audit.ActorUserID, must still be an enabled administrator of the tenant,
// and the tenant must still be active (see requireAdministratorActorTx).
func (ts *TenantStore) UpdateUserByAdministrator(ctx context.Context, u User, revokeSessions bool, audit AuditEntry) error {
	if err := ts.ready(); err != nil {
		return err
	}
	return ts.updateUser(ctx, u, revokeSessions, audit, ts.administratorActor(audit.ActorUserID))
}

// updateUser is UpdateUser with a policy check that runs first in the
// transaction; its error stops the write.
func (ts *TenantStore) updateUser(ctx context.Context, u User, revokeSessions bool, audit AuditEntry, check userWriteCheck) error {
	if _, err := uuid.Parse(u.ID); err != nil {
		return errors.New("user id must be a UUID")
	}
	username, err := NormalizeUsername(u.Username)
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
	stored, err := ts.store.userTOTPForSave(u)
	if err != nil {
		return err
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if check != nil {
		if err := check(ctx, tx); err != nil {
			return err
		}
	}
	var currentUsername, currentDisplayName, currentRole, currentPasswordHash string
	var currentEnabled, currentTOTPEnabled int
	var currentRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT username,display_name,role,password_hash,totp_enabled,enabled,revision FROM users WHERE id=? AND tenant_id=?`, u.ID, ts.scope.id).Scan(&currentUsername, &currentDisplayName, &currentRole, &currentPasswordHash, &currentTOTPEnabled, &currentEnabled, &currentRevision); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	// Zero is accepted for compatibility with older in-process callers that
	// construct a User value directly. Web/API callers receive and round-trip
	// the revision, so concurrent read-modify-write requests fail closed.
	expectedRevision := u.Revision
	if expectedRevision > 0 && expectedRevision != currentRevision {
		return ErrConflict
	}
	// Keep the last enabled administrator invariant inside the same write
	// transaction as the role/state update. This is the authoritative guard;
	// callers should validate request shape, then map ErrLastAdministrator.
	if err := ts.ensureLastAdministratorTx(ctx, tx, u.ID, currentRole, currentEnabled != 0, u.Role, u.Enabled); err != nil {
		return err
	}
	if expectedRevision == 0 {
		expectedRevision = currentRevision
	}
	// An empty stored display name is presented as the username, so treat
	// that as the effective current value.
	if strings.TrimSpace(currentDisplayName) == "" {
		currentDisplayName = currentUsername
	}
	// Idempotent updates should not create misleading audit rows, but any
	// change to a persisted account field is audited, including a display-name
	// change. The TOTP secret is compared through its enabled state because a
	// save re-encrypts an unchanged secret.
	if currentUsername == u.Username && currentDisplayName == u.DisplayName && currentRole == u.Role && (currentEnabled != 0) == u.Enabled && currentPasswordHash == u.PasswordHash && (currentTOTPEnabled != 0) == u.TOTPEnabled {
		audit.Action = ""
	}
	result, err := tx.ExecContext(ctx, `UPDATE users SET username=?,display_name=?,role=?,password_hash=?,totp_secret=?,totp_enabled=?,enabled=?,updated_at=?,revision=revision+1 WHERE id=? AND tenant_id=? AND revision=?`, u.Username, u.DisplayName, u.Role, u.PasswordHash, stored, boolInt(u.TOTPEnabled), boolInt(u.Enabled), u.UpdatedAt.UTC().Format(time.RFC3339Nano), u.ID, ts.scope.id, expectedRevision)
	if err != nil {
		return usernameConflict(err)
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrConflict
	}
	// Security transitions are session-invalidating even when a trusted caller
	// forgets to set revokeSessions. Keeping this policy at the transactional
	// store boundary makes API, CLI, and future callers behave consistently;
	// display-name-only edits remain session preserving.
	securityTransition := currentRole != u.Role || (currentEnabled != 0) != u.Enabled
	if revokeSessions || securityTransition {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=`+tenantUserSQL, u.ID, ts.scope.id); err != nil {
			return err
		}
	}
	// A disabled account must not retain an activation or password-reset link.
	// Otherwise a link issued before the disable could silently re-enable the
	// account when redeemed later. Keep this revocation in the same transaction
	// as the user-state change so there is no race window.
	// Revocation is a transition, not a property of the resulting row. Pending
	// invitees are intentionally disabled while their password hash carries a
	// sentinel; editing their display name must not kill the invite.
	if err := ts.revokeUserInvitesOnDisableTx(ctx, tx, u.ID, currentEnabled != 0, currentPasswordHash, u.Enabled, u.UpdatedAt); err != nil {
		return err
	}
	// A new password, or a new role, ends every unused link for the account,
	// whoever issued it: a link issued before the change must not set the
	// password afterwards, and a link that its issuer could issue only for
	// the former role, such as a platform administrator's reset link for a
	// unit administrator, must not outlive that role. This holds for a
	// pending account too, which then needs a new activation link.
	revokedLinks, err := ts.revokeTenantAccountLinksTx(ctx, tx, u.ID, u.Username, accountLinkChange(currentPasswordHash, u.PasswordHash, currentRole, u.Role), u.UpdatedAt, audit)
	if err != nil {
		return err
	}
	// Invitations issued by an administrator must not outlive the issuer's
	// administrative privilege. Revoke them on demotion or disablement, while
	// retaining the issuer identity for audit and recovery diagnostics.
	if currentRole == RoleAdministrator && (u.Role != RoleAdministrator || !u.Enabled) {
		if _, err := tx.ExecContext(ctx, `UPDATE user_invites SET used_at=? WHERE issuer_user_id=`+tenantUserSQL+` AND used_at IS NULL`, u.UpdatedAt.UTC().Format(time.RFC3339Nano), u.ID, ts.scope.id); err != nil {
			return err
		}
	}
	if err := ts.insertAuditEntries(ctx, tx, []AuditEntry{audit, revokedLinks}, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

// SetUserLastLogin records a successful sign-in. It stays global: sign-in
// knows the account before any tenant scope exists.
func (s *Store) SetUserLastLogin(ctx context.Context, id string, at time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET last_login_at=?,updated_at=? WHERE id=?`, at.UTC().Format(time.RFC3339Nano), at.UTC().Format(time.RFC3339Nano), id)
	return err
}

// SetUserPassword sets the password hash of the tenant's account. Another
// tenant's account is ErrNotFound.
func (ts *TenantStore) SetUserPassword(ctx context.Context, id, hash string, revokeSessions bool, audit AuditEntry) error {
	u, err := ts.GetUser(ctx, id)
	if err != nil {
		return err
	}
	u.PasswordHash = hash
	u.UpdatedAt = time.Now().UTC()
	return ts.UpdateUser(ctx, u, revokeSessions, audit)
}

// SaveUserSecurity saves the security state of the tenant's account and
// revokes all of its sessions when asked.
func (ts *TenantStore) SaveUserSecurity(ctx context.Context, u User, recoveryCodes []string, replaceRecoveryCodes, revokeSessions bool, audit AuditEntry) error {
	return ts.SaveUserSecurityPreservingSession(ctx, u, recoveryCodes, replaceRecoveryCodes, revokeSessions, audit, "", NoTOTPStep)
}

// SaveUserSecurityPreservingSession is the actor-aware security mutation used
// by TOTP enrollment. It revokes every other session while optionally keeping
// the browser that is receiving the one-time recovery-code response alive.
// Passing an empty hash preserves the original revoke-all behavior. A TOTP
// enrolment passes the time step of the code that confirmed the new secret
// as totpStep, which is recorded as used in the same transaction, so that
// code is not accepted again; any other save passes NoTOTPStep. Another
// tenant's account is ErrNotFound, and nothing is written.
func (ts *TenantStore) SaveUserSecurityPreservingSession(ctx context.Context, u User, recoveryCodes []string, replaceRecoveryCodes, revokeSessions bool, audit AuditEntry, preserveSessionHash string, totpStep int64) error {
	if err := ts.ready(); err != nil {
		return err
	}
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
	stored, err := ts.store.userTOTPForSave(u)
	if err != nil {
		return err
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentUsername, currentRole, currentPasswordHash string
	var currentEnabled int
	var currentRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT username,role,password_hash,enabled,revision FROM users WHERE id=? AND tenant_id=?`, u.ID, ts.scope.id).Scan(&currentUsername, &currentRole, &currentPasswordHash, &currentEnabled, &currentRevision); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	expectedRevision := u.Revision
	if expectedRevision > 0 && expectedRevision != currentRevision {
		return ErrConflict
	}
	// TOTP and host-recovery writes use the same transactional invariant as
	// profile updates. Keeping one guard prevents the two paths from drifting.
	if err := ts.ensureLastAdministratorTx(ctx, tx, u.ID, currentRole, currentEnabled != 0, u.Role, u.Enabled); err != nil {
		return err
	}
	if expectedRevision == 0 {
		expectedRevision = currentRevision
	}
	result, err := tx.ExecContext(ctx, `UPDATE users SET display_name=?,role=?,password_hash=?,totp_secret=?,totp_enabled=?,enabled=?,updated_at=?,revision=revision+1 WHERE id=? AND tenant_id=? AND revision=?`, u.DisplayName, u.Role, u.PasswordHash, stored, boolInt(u.TOTPEnabled), boolInt(u.Enabled), u.UpdatedAt.UTC().Format(time.RFC3339Nano), u.ID, ts.scope.id, expectedRevision)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrConflict
	}
	// The update above found the account in the tenant.
	if err := recordEnrolledTOTPStepTx(ctx, tx, u.ID, totpStep, u.UpdatedAt); err != nil {
		return err
	}
	if replaceRecoveryCodes {
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=`+tenantUserSQL, u.ID, ts.scope.id); err != nil {
			return err
		}
		for _, hash := range recoveryCodes {
			if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(id_hash,user_id) SELECT ?,id FROM users WHERE id=? AND tenant_id=?`, hash, u.ID, ts.scope.id); err != nil {
				return err
			}
		}
	}
	securityTransition := currentRole != u.Role || (currentEnabled != 0) != u.Enabled
	if revokeSessions || securityTransition {
		if preserveSessionHash = strings.TrimSpace(preserveSessionHash); preserveSessionHash == "" {
			if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=`+tenantUserSQL, u.ID, ts.scope.id); err != nil {
				return err
			}
		} else if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=`+tenantUserSQL+` AND id_hash<>?`, u.ID, ts.scope.id, preserveSessionHash); err != nil {
			return err
		}
	}
	// Disabling an already-configured account must invalidate every outstanding
	// activation or password-reset link in the same transaction. Pending
	// invitees intentionally remain eligible to redeem their first activation
	// link even though their account starts disabled.
	if err := ts.revokeUserInvitesOnDisableTx(ctx, tx, u.ID, currentEnabled != 0, currentPasswordHash, u.Enabled, u.UpdatedAt); err != nil {
		return err
	}
	// A password that the host resets ends the account's unused links, as
	// a password change in updateUser does.
	revokedLinks, err := ts.revokeTenantAccountLinksTx(ctx, tx, u.ID, currentUsername, accountLinkChange(currentPasswordHash, u.PasswordHash, currentRole, u.Role), u.UpdatedAt, audit)
	if err != nil {
		return err
	}
	if err := ts.insertAuditEntries(ctx, tx, []AuditEntry{audit, revokedLinks}, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

// ensureLastAdministratorTx is the single persistence boundary for the
// enabled-administrator invariant. It must be called while the caller owns a
// write transaction so concurrent role/enable changes cannot both observe a
// final administrator and then remove it. The invariant holds for each
// tenant: another tenant's administrators do not count.
func (ts *TenantStore) ensureLastAdministratorTx(ctx context.Context, tx *sql.Tx, userID, currentRole string, currentEnabled bool, nextRole string, nextEnabled bool) error {
	if currentRole != RoleAdministrator || !currentEnabled || (nextRole == RoleAdministrator && nextEnabled) {
		return nil
	}
	var otherAdministrators int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role=? AND enabled=1 AND id<>? AND tenant_id=?`, RoleAdministrator, userID, ts.scope.id).Scan(&otherAdministrators); err != nil {
		return err
	}
	if otherAdministrators == 0 {
		return ErrLastAdministrator
	}
	return nil
}

// revokeUserInvitesOnDisableTx is the single transactional rule for
// invalidating outstanding activation and password-reset links. Pending
// invitees intentionally remain eligible for their first activation while an
// already configured account must lose every outstanding link when disabled.
func (ts *TenantStore) revokeUserInvitesOnDisableTx(ctx context.Context, tx *sql.Tx, userID string, currentEnabled bool, currentPasswordHash string, nextEnabled bool, at time.Time) error {
	if !currentEnabled || nextEnabled || strings.HasPrefix(currentPasswordHash, "!pending") {
		return nil
	}
	_, err := tx.ExecContext(ctx, `UPDATE user_invites SET used_at=? WHERE user_id=`+tenantUserSQL+` AND used_at IS NULL`, at.UTC().Format(time.RFC3339Nano), userID, ts.scope.id)
	return err
}

// Why revokeAccountLinksTx revoked an account's links, as its audit record
// says.
const (
	linksRevokedPasswordChanged = "its password changed"
	linksRevokedRoleChanged     = "its role changed"
)

// revokeAccountLinksTx marks every unused activation and password-reset
// link of one account as used at the time at, whoever issued it, so that
// none of them can set the account's password afterwards. accountSQL names
// the account with its arguments: tenantUserSQL or platformAdminSQL, or a
// plain placeholder for an account the transaction already found. It
// returns the number of revoked links that were still redeemable, unexpired
// at that time; a link that had expired was already unusable, so it needs
// no audit record.
func revokeAccountLinksTx(ctx context.Context, tx *sql.Tx, at time.Time, accountSQL string, accountArgs ...any) (int, error) {
	args := append([]any{at.UTC().Format(time.RFC3339Nano)}, accountArgs...)
	rows, err := tx.QueryContext(ctx, `UPDATE user_invites SET used_at=? WHERE user_id=`+accountSQL+` AND used_at IS NULL RETURNING expires_at`, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	redeemable := 0
	for rows.Next() {
		var expires string
		if err := rows.Scan(&expires); err != nil {
			return 0, err
		}
		if at.Before(scanTime(expires)) {
			redeemable++
		}
	}
	return redeemable, rows.Err()
}

// linksRevokedAudit is the record of the links that revokeAccountLinksTx
// revoked when an account's password or role changed. It has the actor of
// the change's own record, entry, and names the account. The record is
// written only with the change's record: an entry without an action gives
// none.
func linksRevokedAudit(entry AuditEntry, action, username, reason string) AuditEntry {
	if strings.TrimSpace(entry.Action) == "" {
		return AuditEntry{}
	}
	entry.Action, entry.Detail = action, fmt.Sprintf("activation links revoked for %s because %s", username, reason)
	return entry
}

// accountLinkChange is the reason to revoke an account's unused links when
// a write changes its password hash or role, or "" when it changes neither.
func accountLinkChange(currentPasswordHash, nextPasswordHash, currentRole, nextRole string) string {
	switch {
	case currentPasswordHash != nextPasswordHash:
		return linksRevokedPasswordChanged
	case currentRole != nextRole:
		return linksRevokedRoleChanged
	}
	return ""
}

// revokeTenantAccountLinksTx revokes the unused links of the tenant's
// account when a write changes its password or role (see
// accountLinkChange), and returns the audit record of the revocation, which
// has no action when no link was still redeemable.
func (ts *TenantStore) revokeTenantAccountLinksTx(ctx context.Context, tx *sql.Tx, userID, username, reason string, at time.Time, audit AuditEntry) (AuditEntry, error) {
	if reason == "" {
		return AuditEntry{}, nil
	}
	revoked, err := revokeAccountLinksTx(ctx, tx, at, tenantUserSQL, userID, ts.scope.id)
	if err != nil || revoked == 0 {
		return AuditEntry{}, err
	}
	return linksRevokedAudit(audit, "user.activation_revoked", username, reason), nil
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
	return s.sealTOTPSecretForOwner(u.ID, u.TOTPSecret)
}

// CountEnabledAdministrators counts the tenant's enabled administrators.
func (ts *TenantStore) CountEnabledAdministrators(ctx context.Context) (int, error) {
	if err := ts.ready(); err != nil {
		return 0, err
	}
	var count int
	err := ts.store.reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role=? AND enabled=1 AND tenant_id=?`, RoleAdministrator, ts.scope.id).Scan(&count)
	return count, err
}

// requireTenantUserTx returns ErrNotFound unless the tenant has the account.
func (ts *TenantStore) requireTenantUserTx(ctx context.Context, tx *sql.Tx, userID string) error {
	var present int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id=? AND tenant_id=?`, userID, ts.scope.id).Scan(&present); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	return nil
}

// DeleteUserSessionsWithAudit revokes every session of the tenant's account
// with its audit record. Another tenant's account is ErrNotFound, as an
// unknown ID is, and nothing is revoked or recorded. Revocation is
// security-critical, so when only the audit write fails the sessions are
// still revoked and the audit error is returned. It is the write of an
// account that signs itself out everywhere; an administrator's revocation
// of an account's sessions goes through DeleteUserSessionsByAdministrator.
func (ts *TenantStore) DeleteUserSessionsWithAudit(ctx context.Context, userID string, audit AuditEntry) error {
	if err := ts.ready(); err != nil {
		return err
	}
	return ts.deleteUserSessionsWithAudit(ctx, userID, audit, nil)
}

// DeleteUserSessionsByAdministrator is DeleteUserSessionsWithAudit for one
// of the tenant's administrators: the actor, audit.ActorUserID, must still
// be an enabled administrator of the tenant, and the tenant must still be
// active (see requireAdministratorActorTx). A refused revocation revokes
// and records nothing.
func (ts *TenantStore) DeleteUserSessionsByAdministrator(ctx context.Context, userID string, audit AuditEntry) error {
	if err := ts.ready(); err != nil {
		return err
	}
	return ts.deleteUserSessionsWithAudit(ctx, userID, audit, ts.administratorActor(audit.ActorUserID))
}

// deleteUserSessionsWithAudit is DeleteUserSessionsWithAudit with a policy
// check that runs first in the transaction; its error stops the write.
func (ts *TenantStore) deleteUserSessionsWithAudit(ctx context.Context, userID string, audit AuditEntry, check userWriteCheck) error {
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if check != nil {
		if err := check(ctx, tx); err != nil {
			return err
		}
	}
	if err := ts.requireTenantUserTx(ctx, tx, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=`+tenantUserSQL, userID, ts.scope.id); err != nil {
		return err
	}
	if audit.Action != "" {
		if err := ts.insertAuditEntry(ctx, tx, audit, time.Now().UTC()); err != nil {
			_ = tx.Rollback()
			persistCtx, cancel := auditPersistenceContext(ctx)
			_, revokeErr := ts.store.DB.ExecContext(persistCtx, `DELETE FROM sessions WHERE user_id=`+tenantUserSQL, userID, ts.scope.id)
			cancel()
			if revokeErr != nil {
				return errors.Join(err, revokeErr)
			}
			return err
		}
	}
	return tx.Commit()
}

// CreateUserInvite stores an activation or password-reset link, by the hash
// of its token, for the tenant's account. Another tenant's account is
// ErrNotFound, and no link is stored.
func (ts *TenantStore) CreateUserInvite(ctx context.Context, idHash, userID string, created, expires time.Time) error {
	if err := ts.ready(); err != nil {
		return err
	}
	result, err := ts.store.DB.ExecContext(ctx, `INSERT INTO user_invites(id_hash,user_id,issuer_user_id,created_at,expires_at,used_at) SELECT ?,id,'',?,?,NULL FROM users WHERE id=? AND tenant_id=?`, idHash, created.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano), userID, ts.scope.id)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err != nil {
		return err
	} else if affected != 1 {
		return ErrNotFound
	}
	return nil
}

// CreateUserInviteWithAudit stores a replacement activation/password-reset
// token and its audit record atomically. The clear token never reaches this
// method; only its SHA-256 digest is persisted. Another tenant's account is
// ErrNotFound, and its links stay as they are. The actor,
// audit.ActorUserID, must still be an enabled administrator of the tenant,
// and the tenant must still be active (see requireAdministratorActorTx).
func (ts *TenantStore) CreateUserInviteWithAudit(ctx context.Context, idHash, userID string, created, expires time.Time, audit AuditEntry) error {
	if err := ts.ready(); err != nil {
		return err
	}
	return ts.createUserInviteWithAudit(ctx, idHash, userID, created, expires, audit, ts.administratorActor(audit.ActorUserID))
}

// createUserInviteWithAudit is CreateUserInviteWithAudit with a policy check
// that runs first in the transaction; its error stops the write. The
// account must still belong to the tenant.
func (ts *TenantStore) createUserInviteWithAudit(ctx context.Context, idHash, userID string, created, expires time.Time, audit AuditEntry, check userWriteCheck) error {
	if strings.TrimSpace(idHash) == "" || strings.TrimSpace(userID) == "" {
		return errors.New("activation token and user are required")
	}
	if !expires.After(created) {
		return errors.New("activation token expiry must be after creation")
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if check != nil {
		if err := check(ctx, tx); err != nil {
			return err
		}
	}
	if err := ts.requireTenantUserTx(ctx, tx, userID); err != nil {
		return err
	}
	// Issuing a new activation/password-reset link invalidates any older
	// outstanding link for the same account. This leaves a single recovery
	// path and makes a copied, superseded token unusable.
	if _, err := tx.ExecContext(ctx, `UPDATE user_invites SET used_at=? WHERE user_id=`+tenantUserSQL+` AND used_at IS NULL`, created.UTC().Format(time.RFC3339Nano), userID, ts.scope.id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_invites(id_hash,user_id,issuer_user_id,created_at,expires_at,used_at) SELECT ?,id,?,?,?,NULL FROM users WHERE id=? AND tenant_id=?`, idHash, audit.ActorUserID, created.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano), userID, ts.scope.id); err != nil {
		return err
	}
	if audit.Action != "" {
		if err := ts.insertAuditEntry(ctx, tx, audit, created.UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RevokeUserInvitesWithAudit invalidates every outstanding activation or
// password-reset link for one of the tenant's accounts. Only the token hash
// is stored, and the operation is audited atomically with the revocation.
// Another tenant's account is ErrNotFound, and its links stay usable. The
// actor, audit.ActorUserID, must still be an enabled administrator of the
// tenant, and the tenant must still be active (see
// requireAdministratorActorTx).
func (ts *TenantStore) RevokeUserInvitesWithAudit(ctx context.Context, userID string, now time.Time, audit AuditEntry) (int, error) {
	if err := ts.ready(); err != nil {
		return 0, err
	}
	if strings.TrimSpace(userID) == "" {
		return 0, errors.New("user is required")
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := ts.requireAdministratorActorTx(ctx, tx, audit.ActorUserID); err != nil {
		return 0, err
	}
	if err := ts.requireTenantUserTx(ctx, tx, userID); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE user_invites SET used_at=? WHERE user_id=`+tenantUserSQL+` AND used_at IS NULL AND expires_at>?`, now.UTC().Format(time.RFC3339Nano), userID, ts.scope.id, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if affected == 0 {
		// Revoking an already-used or expired token is a safe no-op, not an
		// auditable state transition. Avoid creating misleading audit noise.
		audit.Action = ""
	}
	if audit.Action != "" {
		if err := ts.insertAuditEntry(ctx, tx, audit, now.UTC()); err != nil {
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
//
// It stays global: the token, not a tenant scope, names the account. The
// returned account carries its tenant, and the audit record belongs to it.
// An account whose tenant is not active cannot redeem a link; the token
// stays unused.
func (s *Store) ActivateUser(ctx context.Context, idHash, passwordHash string, now time.Time, audit AuditEntry) (User, error) {
	if strings.TrimSpace(idHash) == "" || strings.TrimSpace(passwordHash) == "" {
		return User{}, errors.New("activation token and password are required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	var userID, expires, currentPasswordHash, tenantID, tenantState string
	var currentEnabled int
	var used sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT i.user_id,i.expires_at,i.used_at,u.password_hash,u.enabled,COALESCE(u.tenant_id,''),COALESCE(t.state,'') FROM user_invites i JOIN users u ON u.id=i.user_id LEFT JOIN tenants t ON t.id=u.tenant_id WHERE i.id_hash=?`, idHash).Scan(&userID, &expires, &used, &currentPasswordHash, &currentEnabled, &tenantID, &tenantState); errors.Is(err, sql.ErrNoRows) {
		return User{}, errors.New("invalid activation token")
	} else if err != nil {
		return User{}, err
	}
	if used.Valid || !now.Before(scanTime(expires)) {
		return User{}, errors.New("activation token expired or already used")
	}
	if tenantID != "" && tenantState != TenantStateActive {
		return User{}, ErrTenantNotActive
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
	result, err = tx.ExecContext(ctx, `UPDATE users SET password_hash=?,enabled=1,updated_at=?,revision=revision+1 WHERE id=?`, passwordHash, updated, userID)
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
	// The new password also ends every other unused link for the account,
	// as any other password change does, so an older link cannot replace
	// the password that this one set.
	revokedLinks, err := revokeAccountLinksTx(ctx, tx, now, "?", userID)
	if err != nil {
		return User{}, err
	}
	u, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id=?`, userID))
	if err != nil {
		return User{}, err
	}
	if audit.Action != "" && audit.ActorUserID == "" {
		audit.ActorUserID = userID
	}
	if audit.Action != "" && audit.ActorUsername == "" {
		audit.ActorUsername = u.Username
	}
	// The records belong to the activated account's tenant, whatever the
	// entry names; a platform administrator's has none, so its records
	// take the actor's, the platform.
	audit.TenantID = tenantID
	records := []AuditEntry{audit}
	if revokedLinks > 0 {
		action := "user.activation_revoked"
		if u.Role == RolePlatformAdmin {
			action = auditPlatformAdminActivationRevoked
		}
		records = append(records, linksRevokedAudit(audit, action, u.Username, linksRevokedPasswordChanged))
	}
	for _, record := range records {
		if err := insertAuditEntryExec(ctx, tx, record, now.UTC()); err != nil {
			return User{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return u, nil
}

// ConsumeUserInvite marks a valid invite used and returns its account, with
// the account's tenant. It stays global, as ActivateUser does, and an
// account whose tenant is not active cannot consume a link.
func (s *Store) ConsumeUserInvite(ctx context.Context, idHash string, now time.Time) (User, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	var userID, expires, tenantID, tenantState string
	var used sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT i.user_id,i.expires_at,i.used_at,COALESCE(u.tenant_id,''),COALESCE(t.state,'') FROM user_invites i JOIN users u ON u.id=i.user_id LEFT JOIN tenants t ON t.id=u.tenant_id WHERE i.id_hash=?`, idHash).Scan(&userID, &expires, &used, &tenantID, &tenantState); errors.Is(err, sql.ErrNoRows) {
		return User{}, errors.New("invalid activation token")
	} else if err != nil {
		return User{}, err
	}
	if used.Valid || !now.Before(scanTime(expires)) {
		return User{}, errors.New("activation token expired or already used")
	}
	if tenantID != "" && tenantState != TenantStateActive {
		return User{}, ErrTenantNotActive
	}
	result, err := tx.ExecContext(ctx, `UPDATE user_invites SET used_at=? WHERE id_hash=? AND used_at IS NULL`, now.UTC().Format(time.RFC3339Nano), idHash)
	if err != nil {
		return User{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return User{}, errors.New("activation token expired or already used")
	}
	u, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id=?`, userID))
	if err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return u, nil
}
