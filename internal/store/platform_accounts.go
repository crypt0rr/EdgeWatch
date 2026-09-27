package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// The account rules of business units. A platform administrator is an
// account without a tenant that manages the tenants and their
// administrators, and never a tenant's data:
//
//   - the first one is created by redeeming a platform setup token, which
//     the host issues, and any other by redeeming the invitation of an
//     enabled platform administrator (InvitePlatformAdmin);
//   - it invites only a tenant's administrators, and a tenant's
//     administrators invite their own operators and viewers;
//   - it resets only a tenant's administrators, never another platform
//     administrator; the host CLI is the break-glass path for those;
//   - the last enabled platform administrator stays enabled.
//
// Its actions on a tenant's accounts are recorded in that tenant's audit
// with the platform actor kind, so the tenant's administrators see them.
// Its other actions, and the attempts to sign in as one, are recorded in
// platform scope, with no tenant.

var (
	// ErrPlatformAdminConfigured reports that an enabled platform
	// administrator exists, so no platform setup token is issued or
	// redeemed.
	ErrPlatformAdminConfigured = errors.New("a platform administrator is already configured")
	// ErrLastPlatformAdmin reports a change that would leave no enabled
	// platform administrator.
	ErrLastPlatformAdmin = errors.New("at least one enabled platform administrator is required")
	// ErrAccountNotPermitted reports an account change that the business
	// unit account rules do not permit, such as a platform administrator
	// inviting an operator.
	ErrAccountNotPermitted = errors.New("the account change is not permitted")
	// ErrSetupIncomplete reports that the installation has no administrator
	// yet. The first setup, with the initial setup token, comes before a
	// platform administrator.
	ErrSetupIncomplete = errors.New("complete the first administrator setup before creating a platform administrator")
	// ErrSetupTokenOutstanding reports that an unused setup token is still
	// valid, so issuing another would replace it without confirmation.
	ErrSetupTokenOutstanding = errors.New("an unused setup token is still valid")
)

// HasMultipleTenants reports whether more than one tenant that has not been
// deleted exists. Once one does, administrators must use TOTP.
func (ps *PlatformStore) HasMultipleTenants(ctx context.Context) (bool, error) {
	var count int
	err := ps.store.reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT 1 FROM tenants WHERE state<>? LIMIT 2)`, TenantStateDeleted).Scan(&count)
	return count > 1, err
}

// AuditEntry records a security event in platform scope, outside a
// transaction: the record has no tenant, whatever the entry names.
// Authentication uses it for an event about a platform administrator's
// account, or about an account that does not exist, so that no tenant's
// audit shows it.
func (ps *PlatformStore) AuditEntry(ctx context.Context, entry AuditEntry) error {
	persistCtx, cancel := auditPersistenceContext(ctx)
	defer cancel()
	return insertPlatformAuditEntry(persistCtx, ps.store.DB, entry, time.Now().UTC())
}

// IssuePlatformSetupToken replaces the setup token with a platform setup
// token, by the hash of its clear value, which only the host CLI sees. It is
// refused while an enabled platform administrator exists, before the first
// administrator setup is complete, within a minute of the previous token,
// and, unless replace confirms it, while an unused token is still valid. The
// record belongs to the platform, with the host as its actor.
func (ps *PlatformStore) IssuePlatformSetupToken(ctx context.Context, hash string, expires, now time.Time, replace bool) error {
	if strings.TrimSpace(hash) == "" {
		return errors.New("setup token hash is required")
	}
	if !expires.After(now) {
		return errors.New("setup token expiry must be after its issue")
	}
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := requireNoPlatformAdminTx(ctx, tx); err != nil {
		return err
	}
	var administrators int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role=?`, RoleAdministrator).Scan(&administrators); err != nil {
		return err
	}
	if administrators == 0 {
		return ErrSetupIncomplete
	}
	var issued, previousExpiry string
	var used sql.NullString
	switch err := tx.QueryRowContext(ctx, `SELECT issued_at,expires_at,used_at FROM setup_tokens WHERE id=1`).Scan(&issued, &previousExpiry, &used); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return err
	default:
		if previous := scanTime(issued); !previous.IsZero() && now.UTC().Sub(previous) < time.Minute {
			return ErrSetupTokenRateLimited
		}
		if !replace && !used.Valid && now.Before(scanTime(previousExpiry)) {
			return ErrSetupTokenOutstanding
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO setup_tokens(id,token_hash,expires_at,used_at,issued_at,purpose) VALUES(1,?,?,NULL,?,?)`, hash, expires.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano), SetupTokenPurposePlatform); err != nil {
		return err
	}
	if err := insertPlatformAuditEntry(ctx, tx, AuditEntry{Action: "platform_admin.setup_token_issued", Detail: "platform setup token issued from host CLI", ActorKind: AuditActorHost}, now.UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

// PlatformSetupTokenUsable reports whether the platform setup token with the
// hash is unused and unexpired. It is the cheap check before hashing a
// password; an initial setup token is never usable here.
func (ps *PlatformStore) PlatformSetupTokenUsable(ctx context.Context, tokenHash string, now time.Time) (bool, error) {
	return ps.setupTokenUsable(ctx, tokenHash, SetupTokenPurposePlatform, now)
}

// CompletePlatformSetup redeems a platform setup token. In one transaction
// it creates the platform administrator, an enabled account without a
// tenant with the chosen username, which is unique across every tenant,
// marks the token used, and records the creation in platform scope. An
// initial setup token, a used or expired token, and an enabled platform
// administrator that already exists are refused, and nothing is written.
func (ps *PlatformStore) CompletePlatformSetup(ctx context.Context, tokenHash, username, passwordHash string, now time.Time) (User, error) {
	normalized, err := NormalizeUsername(username)
	if err != nil {
		return User{}, err
	}
	if strings.TrimSpace(passwordHash) == "" || strings.HasPrefix(passwordHash, "!") {
		return User{}, errors.New("a password hash is required")
	}
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var expires string
	var used sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT expires_at,used_at FROM setup_tokens WHERE id=1 AND token_hash=? AND purpose=?`, tokenHash, SetupTokenPurposePlatform).Scan(&expires, &used); errors.Is(err, sql.ErrNoRows) {
		return User{}, errors.New("invalid setup token")
	} else if err != nil {
		return User{}, err
	}
	if used.Valid || !now.Before(scanTime(expires)) {
		return User{}, errors.New("setup token expired or already used")
	}
	if err := requireNoPlatformAdminTx(ctx, tx); err != nil {
		return User{}, err
	}
	stamp := now.UTC()
	user := User{ID: uuid.NewString(), Username: normalized, DisplayName: normalized, Role: RolePlatformAdmin, PasswordHash: passwordHash, Enabled: true, CreatedAt: stamp, UpdatedAt: stamp, Revision: 1}
	if _, err := tx.ExecContext(ctx, `INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at,revision) VALUES(?,NULL,?,?,?,?,'',0,1,?,?,'',1)`, user.ID, user.Username, user.DisplayName, user.Role, user.PasswordHash, stamp.Format(time.RFC3339Nano), stamp.Format(time.RFC3339Nano)); err != nil {
		return User{}, usernameConflict(err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE setup_tokens SET used_at=? WHERE id=1 AND used_at IS NULL AND purpose=?`, stamp.Format(time.RFC3339Nano), SetupTokenPurposePlatform)
	if err != nil {
		return User{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return User{}, errors.New("setup token expired or already used")
	}
	if err := insertPlatformAuditEntry(ctx, tx, AuditEntry{Action: "platform_admin.setup", Detail: "platform administrator created", ActorUserID: user.ID, ActorUsername: user.Username, ActorKind: AuditActorPlatform}, stamp); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return user, nil
}

// requireNoPlatformAdminTx fails with ErrPlatformAdminConfigured when an
// enabled platform administrator exists.
func requireNoPlatformAdminTx(ctx context.Context, tx *sql.Tx) error {
	var admins int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role=? AND tenant_id IS NULL AND enabled=1`, RolePlatformAdmin).Scan(&admins); err != nil {
		return err
	}
	if admins > 0 {
		return ErrPlatformAdminConfigured
	}
	return nil
}

// requirePlatformActorTx fails with ErrAccountNotPermitted unless the actor
// is an enabled platform administrator.
func requirePlatformActorTx(ctx context.Context, tx *sql.Tx, actorID string) error {
	var present int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id=? AND role=? AND tenant_id IS NULL AND enabled=1`, actorID, RolePlatformAdmin).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: the actor is not an enabled platform administrator", ErrAccountNotPermitted)
	}
	return err
}

// requireActiveTenantTx fails unless the tenant exists and is active: a
// missing or deleted tenant is ErrNoTenantScope, and any other state is
// ErrTenantNotActive.
func requireActiveTenantTx(ctx context.Context, tx *sql.Tx, tenantID string) error {
	var state string
	err := tx.QueryRowContext(ctx, `SELECT state FROM tenants WHERE id=?`, tenantID).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && state == TenantStateDeleted) {
		return fmt.Errorf("%w: tenant %s", ErrNoTenantScope, tenantID)
	}
	if err != nil {
		return err
	}
	if state != TenantStateActive {
		return ErrTenantNotActive
	}
	return nil
}

// unitAccounts returns the store of the tenant whose accounts the platform
// administrator manages. A missing or deleted tenant has none.
func (ps *PlatformStore) unitAccounts(ctx context.Context, tenantID string) (*TenantStore, error) {
	scope, err := ps.store.TenantScopeByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return ps.store.Tenant(scope), nil
}

// InviteUnitAdmin creates a pending administrator account in the tenant,
// with its one-time activation link and audit record, as
// TenantStore.CreateUserWithInvite does. A platform administrator invites
// only a tenant's administrators: any other role is ErrAccountNotPermitted,
// because a tenant's administrators invite its operators and viewers. The
// invitee sets its own password by redeeming the link; any password or TOTP
// in u is ignored. The actor, audit.ActorUserID, must be an enabled
// platform administrator, and the tenant must be active. The record belongs
// to the tenant, with the platform actor kind, so the tenant's
// administrators see it.
func (ps *PlatformStore) InviteUnitAdmin(ctx context.Context, tenantID string, u User, idHash string, created, expires time.Time, audit AuditEntry) (User, error) {
	if u.Role == "" {
		u.Role = RoleAdministrator
	}
	if u.Role != RoleAdministrator {
		return User{}, fmt.Errorf("%w: a platform administrator invites only unit administrators", ErrAccountNotPermitted)
	}
	u.PasswordHash, u.TOTPEnabled, u.TOTPSecret, u.TOTPSecretStored = "!pending", false, "", ""
	if strings.TrimSpace(idHash) == "" {
		return User{}, errors.New("activation token hash is required")
	}
	if !expires.After(created) {
		return User{}, errors.New("activation token expiry must be after creation")
	}
	ts, err := ps.unitAccounts(ctx, tenantID)
	if err != nil {
		return User{}, err
	}
	audit.ActorKind = AuditActorPlatform
	return ts.createUser(ctx, u, &userInviteRecord{idHash: idHash, created: created, expires: expires}, audit, func(ctx context.Context, tx *sql.Tx) error {
		if err := requirePlatformActorTx(ctx, tx, audit.ActorUserID); err != nil {
			return err
		}
		return requireActiveTenantTx(ctx, tx, tenantID)
	})
}

// IssueUnitAdminPasswordReset stores a password-reset link for a tenant's
// administrator, by the hash of its token, and revokes the account's older
// links, as TenantStore.CreateUserInviteWithAudit does. The rule keys on the
// account itself: a platform administrator resets only an administrator of
// a tenant, so another platform administrator or a tenant's operator or
// viewer is ErrAccountNotPermitted, and an account of another tenant than
// tenantID is ErrNotFound. The actor, audit.ActorUserID, must be an enabled
// platform administrator, and the tenant must be active. The record belongs
// to the account's tenant, with the platform actor kind.
func (ps *PlatformStore) IssueUnitAdminPasswordReset(ctx context.Context, tenantID, userID, idHash string, created, expires time.Time, audit AuditEntry) error {
	ts, err := ps.unitAccounts(ctx, tenantID)
	if err != nil {
		return err
	}
	audit.ActorKind = AuditActorPlatform
	return ts.createUserInviteWithAudit(ctx, idHash, userID, created, expires, audit, func(ctx context.Context, tx *sql.Tx) error {
		if err := requirePlatformActorTx(ctx, tx, audit.ActorUserID); err != nil {
			return err
		}
		if err := requireActiveTenantTx(ctx, tx, tenantID); err != nil {
			return err
		}
		var role, accountTenant string
		if err := tx.QueryRowContext(ctx, `SELECT role,COALESCE(tenant_id,'') FROM users WHERE id=?`, userID).Scan(&role, &accountTenant); errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		switch {
		case role == RolePlatformAdmin:
			return fmt.Errorf("%w: a platform administrator cannot reset another platform administrator; use the host CLI", ErrAccountNotPermitted)
		case accountTenant != tenantID:
			return ErrNotFound
		case role != RoleAdministrator:
			return fmt.Errorf("%w: a platform administrator resets only unit administrators", ErrAccountNotPermitted)
		}
		return nil
	})
}

// PlatformAccountStore changes one platform administrator's own account:
// its display name, password, TOTP, recovery codes, and sessions. It is
// bound to that account and reaches no other: another ID, or an account
// that is not a platform administrator, is ErrNotFound. The console's
// self-service routes use it for a signed-in platform administrator, who
// has no tenant scope, and the host CLI uses it to recover a platform
// administrator. A platform administrator's role never changes, and the
// last enabled one cannot be disabled. The records belong to the platform.
type PlatformAccountStore struct {
	store  *Store
	userID string
}

// Account returns the store of the platform administrator's own account.
func (ps *PlatformStore) Account(userID string) *PlatformAccountStore {
	return &PlatformAccountStore{store: ps.store, userID: userID}
}

// bound returns ErrNotFound unless the store is bound to the account id.
func (pa *PlatformAccountStore) bound(id string) error {
	if pa == nil || pa.store == nil || pa.userID == "" || id != pa.userID {
		return ErrNotFound
	}
	return nil
}

// platformAdminSQL is the ID of the platform administrator with the given
// ID, or NULL when no platform administrator has it. It takes two
// arguments, the account ID and RolePlatformAdmin.
const platformAdminSQL = `(SELECT id FROM users WHERE id=? AND role=? AND tenant_id IS NULL)`

// GetUser returns the platform administrator's account with its decrypted
// TOTP projection.
func (pa *PlatformAccountStore) GetUser(ctx context.Context, id string) (User, error) {
	if err := pa.bound(id); err != nil {
		return User{}, err
	}
	return pa.store.readUser(ctx, `SELECT `+userColumns+` FROM users WHERE id=? AND role=? AND tenant_id IS NULL`, id, RolePlatformAdmin)
}

// UpdateUser updates the platform administrator's username, display name,
// password, TOTP, and enabled state, at its revision when the value names
// one. A change that alters nothing records no audit entry.
func (pa *PlatformAccountStore) UpdateUser(ctx context.Context, u User, revokeSessions bool, audit AuditEntry) error {
	return pa.save(ctx, u, nil, false, revokeSessions, audit, "", true)
}

// SaveUserSecurity saves the platform administrator's security state and
// revokes all of its sessions when asked.
func (pa *PlatformAccountStore) SaveUserSecurity(ctx context.Context, u User, recoveryCodes []string, replaceRecoveryCodes, revokeSessions bool, audit AuditEntry) error {
	return pa.save(ctx, u, recoveryCodes, replaceRecoveryCodes, revokeSessions, audit, "", false)
}

// SaveUserSecurityPreservingSession is SaveUserSecurity that keeps the
// session with the given hash, as TOTP enrolment needs.
func (pa *PlatformAccountStore) SaveUserSecurityPreservingSession(ctx context.Context, u User, recoveryCodes []string, replaceRecoveryCodes, revokeSessions bool, audit AuditEntry, preserveSessionHash string) error {
	return pa.save(ctx, u, recoveryCodes, replaceRecoveryCodes, revokeSessions, audit, preserveSessionHash, false)
}

// save writes the platform administrator's account in one transaction with
// its recovery codes, session revocation, and audit record. rename writes
// the username too, and drops the audit entry of a change that alters
// nothing, as TenantStore.UpdateUser does.
func (pa *PlatformAccountStore) save(ctx context.Context, u User, recoveryCodes []string, replaceRecoveryCodes, revokeSessions bool, audit AuditEntry, preserveSessionHash string, rename bool) error {
	if err := pa.bound(u.ID); err != nil {
		return err
	}
	if u.Role != RolePlatformAdmin {
		return fmt.Errorf("%w: a platform administrator's role cannot change", ErrAccountNotPermitted)
	}
	if rename {
		username, err := NormalizeUsername(u.Username)
		if err != nil {
			return err
		}
		u.Username = username
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = time.Now().UTC()
	}
	stored, err := pa.store.userTOTPForSave(u)
	if err != nil {
		return err
	}
	tx, err := pa.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var currentUsername, currentDisplayName, currentPasswordHash string
	var currentTOTPEnabled, currentEnabled int
	var currentRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT username,display_name,password_hash,totp_enabled,enabled,revision FROM users WHERE id=? AND role=? AND tenant_id IS NULL`, u.ID, RolePlatformAdmin).Scan(&currentUsername, &currentDisplayName, &currentPasswordHash, &currentTOTPEnabled, &currentEnabled, &currentRevision); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if u.Revision > 0 && u.Revision != currentRevision {
		return ErrConflict
	}
	if !rename {
		u.Username = currentUsername
	}
	if strings.TrimSpace(u.DisplayName) == "" {
		u.DisplayName = u.Username
	}
	disabling := currentEnabled != 0 && !u.Enabled
	if disabling {
		if err := ensureAnotherPlatformAdminTx(ctx, tx, u.ID); err != nil {
			return err
		}
	}
	if strings.TrimSpace(currentDisplayName) == "" {
		currentDisplayName = currentUsername
	}
	if rename && currentUsername == u.Username && currentDisplayName == u.DisplayName && (currentEnabled != 0) == u.Enabled && currentPasswordHash == u.PasswordHash && (currentTOTPEnabled != 0) == u.TOTPEnabled {
		audit.Action = ""
	}
	result, err := tx.ExecContext(ctx, `UPDATE users SET username=?,display_name=?,password_hash=?,totp_secret=?,totp_enabled=?,enabled=?,updated_at=?,revision=revision+1 WHERE id=? AND role=? AND tenant_id IS NULL AND revision=?`, u.Username, u.DisplayName, u.PasswordHash, stored, boolInt(u.TOTPEnabled), boolInt(u.Enabled), u.UpdatedAt.UTC().Format(time.RFC3339Nano), u.ID, RolePlatformAdmin, currentRevision)
	if err != nil {
		return usernameConflict(err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrConflict
	}
	if replaceRecoveryCodes {
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=`+platformAdminSQL, u.ID, RolePlatformAdmin); err != nil {
			return err
		}
		for _, hash := range recoveryCodes {
			if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(id_hash,user_id) SELECT ?,id FROM users WHERE id=? AND role=? AND tenant_id IS NULL`, hash, u.ID, RolePlatformAdmin); err != nil {
				return err
			}
		}
	}
	// Disabling the account is a security transition, which signs it out
	// even when the caller did not ask, as it does for a tenant's account.
	if revokeSessions || disabling {
		if preserveSessionHash = strings.TrimSpace(preserveSessionHash); preserveSessionHash == "" || disabling {
			if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=`+platformAdminSQL, u.ID, RolePlatformAdmin); err != nil {
				return err
			}
		} else if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=`+platformAdminSQL+` AND id_hash<>?`, u.ID, RolePlatformAdmin, preserveSessionHash); err != nil {
			return err
		}
	}
	if disabling {
		// The links that the account issued must not outlive its
		// privilege, as for a tenant's administrator.
		if _, err := tx.ExecContext(ctx, `UPDATE user_invites SET used_at=? WHERE issuer_user_id=`+platformAdminSQL+` AND used_at IS NULL`, u.UpdatedAt.UTC().Format(time.RFC3339Nano), u.ID, RolePlatformAdmin); err != nil {
			return err
		}
	}
	if audit.Action != "" {
		if err := insertPlatformAuditEntry(ctx, tx, audit, time.Now().UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ensureAnotherPlatformAdminTx fails with ErrLastPlatformAdmin unless an
// enabled platform administrator other than the account exists. It runs in
// the write transaction, so two concurrent changes cannot both disable the
// last two.
func ensureAnotherPlatformAdminTx(ctx context.Context, tx *sql.Tx, userID string) error {
	var others int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role=? AND tenant_id IS NULL AND enabled=1 AND id<>?`, RolePlatformAdmin, userID).Scan(&others); err != nil {
		return err
	}
	if others == 0 {
		return ErrLastPlatformAdmin
	}
	return nil
}

// DeleteUserSessionsWithAudit revokes every session of the platform
// administrator with its audit record. Revocation is security-critical, so
// when only the audit write fails the sessions are still revoked and the
// audit error is returned.
func (pa *PlatformAccountStore) DeleteUserSessionsWithAudit(ctx context.Context, userID string, audit AuditEntry) error {
	if err := pa.bound(userID); err != nil {
		return err
	}
	tx, err := pa.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var present int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id=? AND role=? AND tenant_id IS NULL`, userID, RolePlatformAdmin).Scan(&present); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=`+platformAdminSQL, userID, RolePlatformAdmin); err != nil {
		return err
	}
	if audit.Action != "" {
		if err := insertPlatformAuditEntry(ctx, tx, audit, time.Now().UTC()); err != nil {
			_ = tx.Rollback()
			persistCtx, cancel := auditPersistenceContext(ctx)
			_, revokeErr := pa.store.DB.ExecContext(persistCtx, `DELETE FROM sessions WHERE user_id=`+platformAdminSQL, userID, RolePlatformAdmin)
			cancel()
			if revokeErr != nil {
				return errors.Join(err, revokeErr)
			}
			return err
		}
	}
	return tx.Commit()
}
