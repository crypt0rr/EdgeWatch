package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// The reads and writes of the platform console, for a platform
// administrator:
//
//   - the accounts of a tenant, as summaries without credentials, and the
//     revocation of one account's sessions;
//   - the platform administrators, an invitation for another one, and
//     enabling or disabling one, with the last-platform-administrator guard;
//   - a tenant's capacity, as numbers;
//   - the platform's own notification destinations, the web-managed
//     destinations without a tenant, and the platform's update routing.
//
// A method that changes something takes the acting platform administrator
// in audit.ActorUserID and checks, in its write transaction, that the
// account is an enabled platform administrator. It records the change in
// platform scope, or, for a change to a tenant's account, in that tenant's
// audit with the platform actor kind, so the tenant's administrators see
// it. A tenant's destinations are never read or changed here, and a
// tenant's account never through the platform administrator methods.

// Audit actions of the platform console. The tenant lifecycle and capacity
// methods set their own.
const (
	auditPlatformAdminInvited               = "platform_admin.invited"
	auditPlatformAdminUpdated               = "platform_admin.updated"
	auditPlatformNotificationsCreated       = "platform_notifications.created"
	auditPlatformNotificationsUpdated       = "platform_notifications.updated"
	auditPlatformNotificationsDeleted       = "platform_notifications.deleted"
	auditPlatformNotificationsUpdateRouting = "platform_notifications.update_routing"
)

// platformNotificationRoutingRemovedDetail describes the routing change of a
// platform destination's deletion, by the destination's ID.
const platformNotificationRoutingRemovedDetail = "removed deleted platform notification destination %s from the platform update routing"

// UnitAccounts returns the accounts of the tenant as summaries, ordered by
// username, without credentials. A missing or deleted tenant is
// ErrNoTenantScope, which wraps ErrNotFound.
func (ps *PlatformStore) UnitAccounts(ctx context.Context, tenantID string) ([]UserSummary, error) {
	ts, err := ps.unitAccounts(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	accounts, err := ts.ListUsers(ctx)
	if err == nil && accounts == nil {
		accounts = []UserSummary{}
	}
	return accounts, err
}

// UnitAccount returns one account of the tenant as a summary. An account of
// another tenant and a platform administrator are ErrNotFound, as an
// unknown ID is.
func (ps *PlatformStore) UnitAccount(ctx context.Context, tenantID, userID string) (UserSummary, error) {
	ts, err := ps.unitAccounts(ctx, tenantID)
	if err != nil {
		return UserSummary{}, err
	}
	user, err := ts.GetUser(ctx, userID)
	if err != nil {
		return UserSummary{}, err
	}
	return user.Summary(), nil
}

// RevokeUnitAccountSessions ends every session of one account of the
// tenant, whatever its role, and records it in the tenant's audit with the
// platform actor kind. An account of another tenant, a platform
// administrator, and an unknown ID are ErrNotFound, and nothing changes.
// Revocation is security-critical, so when only the audit write fails the
// sessions are still revoked and the audit error is returned.
func (ps *PlatformStore) RevokeUnitAccountSessions(ctx context.Context, tenantID, userID string, audit AuditEntry) error {
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := requirePlatformActorTx(ctx, tx, audit.ActorUserID); err != nil {
		return err
	}
	var present int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id=? AND tenant_id=?`, userID, tenantID).Scan(&present); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: user %s", ErrNotFound, userID)
	} else if err != nil {
		return err
	}
	const revoke = `DELETE FROM sessions WHERE user_id=` + tenantUserSQL
	if _, err := tx.ExecContext(ctx, revoke, userID, tenantID); err != nil {
		return err
	}
	audit.TenantID, audit.ActorKind = tenantID, AuditActorPlatform
	if err := insertAuditEntryExec(ctx, tx, audit, time.Now().UTC()); err != nil {
		_ = tx.Rollback()
		persistCtx, cancel := auditPersistenceContext(ctx)
		_, revokeErr := ps.store.DB.ExecContext(persistCtx, revoke, userID, tenantID)
		cancel()
		return errors.Join(err, revokeErr)
	}
	return tx.Commit()
}

// TenantCapacity returns the capacity of a tenant that is not deleted. A
// missing or deleted tenant is ErrNoTenantScope.
func (ps *PlatformStore) TenantCapacity(ctx context.Context, tenantID string) (TenantCapacity, error) {
	capacity, err := scanTenantCapacity(ps.store.reader().QueryRowContext(ctx, `SELECT `+tenantCapacityColumns+` FROM tenants WHERE id=? AND state<>?`, tenantID, TenantStateDeleted).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return TenantCapacity{}, fmt.Errorf("%w: tenant %s", ErrNoTenantScope, tenantID)
	}
	return capacity, err
}

// userSummaryColumns are the columns that scanUserSummary reads.
const userSummaryColumns = `id,username,display_name,role,password_hash,enabled,totp_enabled,created_at,updated_at,last_login_at,revision`

// scanUserSummary reads a row of userSummaryColumns. The password hash is
// read only to tell a pending account, and is not returned.
func scanUserSummary(row interface{ Scan(...any) error }) (UserSummary, error) {
	var u UserSummary
	var passwordHash string
	var enabled, totp int
	var created, updated, lastLogin string
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &passwordHash, &enabled, &totp, &created, &updated, &lastLogin, &u.Revision); err != nil {
		return UserSummary{}, err
	}
	u.Enabled, u.Pending, u.TOTPEnabled = enabled != 0, strings.HasPrefix(passwordHash, "!pending"), totp != 0
	u.CreatedAt, u.UpdatedAt, u.LastLoginAt = scanTime(created), scanTime(updated), scanTime(lastLogin)
	if strings.TrimSpace(u.DisplayName) == "" {
		u.DisplayName = u.Username
	}
	return u, nil
}

// PlatformAdmins returns the platform administrators as summaries, ordered
// by username, without credentials.
func (ps *PlatformStore) PlatformAdmins(ctx context.Context) ([]UserSummary, error) {
	rows, err := ps.store.reader().QueryContext(ctx, `SELECT `+userSummaryColumns+` FROM users WHERE role=? AND tenant_id IS NULL ORDER BY username COLLATE NOCASE`, RolePlatformAdmin)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	admins := []UserSummary{}
	for rows.Next() {
		admin, err := scanUserSummary(rows)
		if err != nil {
			return nil, err
		}
		admins = append(admins, admin)
	}
	return admins, rows.Err()
}

// platformAdminSummary reads one platform administrator in tx. Another
// account is ErrNotFound.
func platformAdminSummary(ctx context.Context, tx *sql.Tx, id string) (UserSummary, error) {
	admin, err := scanUserSummary(tx.QueryRowContext(ctx, `SELECT `+userSummaryColumns+` FROM users WHERE id=? AND role=? AND tenant_id IS NULL`, id, RolePlatformAdmin))
	if errors.Is(err, sql.ErrNoRows) {
		return UserSummary{}, fmt.Errorf("%w: platform administrator %s", ErrNotFound, id)
	}
	return admin, err
}

// InvitePlatformAdmin creates another platform administrator: a pending
// account without a tenant, disabled and without a password until the
// invitee redeems its one-time link, which is stored by the hash of its
// token. Besides the platform setup token, which the host issues only while
// no enabled platform administrator exists, this is the only way to create
// a platform administrator. The actor, audit.ActorUserID, must be an
// enabled platform administrator. The username is unique across every
// tenant. The record belongs to the platform.
func (ps *PlatformStore) InvitePlatformAdmin(ctx context.Context, u User, idHash string, created, expires time.Time, audit AuditEntry) (UserSummary, error) {
	username, err := NormalizeUsername(u.Username)
	if err != nil {
		return UserSummary{}, err
	}
	displayName := strings.TrimSpace(u.DisplayName)
	if displayName == "" {
		displayName = username
	}
	if strings.TrimSpace(idHash) == "" {
		return UserSummary{}, errors.New("activation token hash is required")
	}
	if !expires.After(created) {
		return UserSummary{}, errors.New("activation token expiry must be after creation")
	}
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return UserSummary{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := requirePlatformActorTx(ctx, tx, audit.ActorUserID); err != nil {
		return UserSummary{}, err
	}
	id := uuid.NewString()
	stamp := created.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at,revision) VALUES(?,NULL,?,?,?,'!pending','',0,0,?,?,'',1)`, id, username, displayName, RolePlatformAdmin, stamp, stamp); err != nil {
		return UserSummary{}, usernameConflict(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_invites(id_hash,user_id,issuer_user_id,created_at,expires_at,used_at) SELECT ?,id,?,?,?,NULL FROM users WHERE id=? AND role=? AND tenant_id IS NULL`, idHash, audit.ActorUserID, stamp, expires.UTC().Format(time.RFC3339Nano), id, RolePlatformAdmin); err != nil {
		return UserSummary{}, err
	}
	audit.Action, audit.ActorKind = auditPlatformAdminInvited, AuditActorPlatform
	if strings.TrimSpace(audit.Detail) == "" {
		audit.Detail = "platform administrator " + username + " invited"
	}
	if err := insertPlatformAuditEntry(ctx, tx, audit, time.Now().UTC()); err != nil {
		return UserSummary{}, err
	}
	admin, err := platformAdminSummary(ctx, tx, id)
	if err != nil {
		return UserSummary{}, err
	}
	return admin, tx.Commit()
}

// SetPlatformAdminEnabled enables or disables another platform
// administrator, when expectedRevision is 0 or its revision. The actor,
// audit.ActorUserID, must be an enabled platform administrator, and changes
// its own account through PlatformAccountStore instead: its own ID is
// ErrAccountNotPermitted. A pending account, which has not redeemed its
// link, cannot be enabled, and the last enabled platform administrator
// cannot be disabled (ErrLastPlatformAdmin). Disabling ends the account's
// sessions and revokes the links it issued and those issued for it, in the
// same transaction. A change that alters nothing records nothing. A tenant's
// account is ErrNotFound, as an unknown ID is. The record belongs to the
// platform.
func (ps *PlatformStore) SetPlatformAdminEnabled(ctx context.Context, id string, expectedRevision int64, enabled bool, audit AuditEntry) (UserSummary, error) {
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return UserSummary{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := requirePlatformActorTx(ctx, tx, audit.ActorUserID); err != nil {
		return UserSummary{}, err
	}
	current, err := platformAdminSummary(ctx, tx, id)
	if err != nil {
		return UserSummary{}, err
	}
	switch {
	case id == audit.ActorUserID:
		return UserSummary{}, fmt.Errorf("%w: a platform administrator cannot enable or disable its own account", ErrAccountNotPermitted)
	case expectedRevision > 0 && expectedRevision != current.Revision:
		return UserSummary{}, ErrConflict
	case current.Enabled == enabled:
		return current, nil
	case enabled && current.Pending:
		return UserSummary{}, fmt.Errorf("%w: the account must redeem its activation link before it can be enabled", ErrAccountNotPermitted)
	}
	if !enabled {
		if err := ensureAnotherPlatformAdminTx(ctx, tx, id); err != nil {
			return UserSummary{}, err
		}
	}
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	updated, err := execCount(ctx, tx, `UPDATE users SET enabled=?,updated_at=?,revision=revision+1 WHERE id=? AND role=? AND tenant_id IS NULL AND revision=?`, boolInt(enabled), stamp, id, RolePlatformAdmin, current.Revision)
	if err != nil {
		return UserSummary{}, err
	}
	if updated != 1 {
		return UserSummary{}, ErrConflict
	}
	if !enabled {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=`+platformAdminSQL, id, RolePlatformAdmin); err != nil {
			return UserSummary{}, err
		}
		// The links the account issued must not outlive its privilege, and
		// a link issued for it must not enable it again.
		if _, err := tx.ExecContext(ctx, `UPDATE user_invites SET used_at=?1 WHERE used_at IS NULL AND (issuer_user_id IN (SELECT id FROM users WHERE id=?2 AND role=?3 AND tenant_id IS NULL) OR user_id IN (SELECT id FROM users WHERE id=?2 AND role=?3 AND tenant_id IS NULL))`, stamp, id, RolePlatformAdmin); err != nil {
			return UserSummary{}, err
		}
	}
	audit.Action, audit.ActorKind = auditPlatformAdminUpdated, AuditActorPlatform
	if strings.TrimSpace(audit.Detail) == "" {
		audit.Detail = fmt.Sprintf("platform administrator %s updated enabled=%t->%t", current.Username, current.Enabled, enabled)
	}
	if err := insertPlatformAuditEntry(ctx, tx, audit, now); err != nil {
		return UserSummary{}, err
	}
	admin, err := platformAdminSummary(ctx, tx, id)
	if err != nil {
		return UserSummary{}, err
	}
	return admin, tx.Commit()
}

// platformDestinationSQL limits a statement on the outbox to the pending
// deliveries of a platform destination. It takes one argument, the
// destination ID. Each write that uses it has already found the destination
// among the platform's in the same transaction.
const platformDestinationSQL = ` AND tenant_id IS NULL AND EXISTS (SELECT 1 FROM managed_notifications AS owner WHERE owner.id=? AND owner.tenant_id IS NULL)`

// GetPlatformNotification returns one of the platform's destinations. A
// tenant's destination is ErrNotFound, as an unknown ID is.
func (ps *PlatformStore) GetPlatformNotification(ctx context.Context, id string) (ManagedNotification, error) {
	return getPlatformNotification(ctx, ps.store.reader(), id)
}

func getPlatformNotification(ctx context.Context, queryer rowQueryer, id string) (ManagedNotification, error) {
	destination, err := scanManagedNotification(queryer.QueryRowContext(ctx, `SELECT `+managedNotificationColumns+` FROM managed_notifications WHERE id=? AND tenant_id IS NULL`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ManagedNotification{}, fmt.Errorf("%w: notification %s", ErrNotFound, id)
	}
	return destination, err
}

// CreatePlatformNotificationWithAudit creates a platform destination, a
// web-managed destination without a tenant, with its redacted audit record.
// The name is unique among the platform's destinations. The actor,
// audit.ActorUserID, must be an enabled platform administrator.
func (ps *PlatformStore) CreatePlatformNotificationWithAudit(ctx context.Context, id, name, provider string, ciphertext, nonce []byte, enabled bool, audit AuditEntry) (ManagedNotification, error) {
	if name == "" {
		return ManagedNotification{}, errors.New("notification name is required")
	}
	if len(ciphertext) == 0 || len(nonce) == 0 {
		return ManagedNotification{}, errors.New("notification ciphertext is required")
	}
	if id == "" {
		id = uuid.NewString()
	}
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return ManagedNotification{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := requirePlatformActorTx(ctx, tx, audit.ActorUserID); err != nil {
		return ManagedNotification{}, err
	}
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO managed_notifications(id,tenant_id,name,provider,ciphertext,nonce,enabled,revision,credential_revision,created_at,updated_at) VALUES(?,NULL,?,?,?,?,?,1,1,?,?)`, id, name, provider, ciphertext, nonce, boolInt(enabled), stamp, stamp); err != nil {
		return ManagedNotification{}, err
	}
	audit.Action, audit.ActorKind = auditPlatformNotificationsCreated, AuditActorPlatform
	if err := insertPlatformAuditEntry(ctx, tx, audit, now); err != nil {
		return ManagedNotification{}, err
	}
	destination, err := getPlatformNotification(ctx, tx, id)
	if err != nil {
		return ManagedNotification{}, err
	}
	return destination, tx.Commit()
}

// UpdatePlatformNotificationWithAudit updates one of the platform's
// destinations at expectedRevision, as TenantStore.UpdateManagedNotification
// does for a tenant's: a change that keeps the credentials moves the
// pending deliveries to the new revision, and a credential change discards
// them, which is recorded. A tenant's destination is ErrNotFound, and
// nothing changes. The actor, audit.ActorUserID, must be an enabled
// platform administrator.
func (ps *PlatformStore) UpdatePlatformNotificationWithAudit(ctx context.Context, id string, expectedRevision int64, name, provider string, ciphertext, nonce []byte, enabled bool, audit AuditEntry) (ManagedNotification, error) {
	if name == "" {
		return ManagedNotification{}, errors.New("notification name is required")
	}
	if len(ciphertext) == 0 || len(nonce) == 0 {
		return ManagedNotification{}, errors.New("notification ciphertext is required")
	}
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return ManagedNotification{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := requirePlatformActorTx(ctx, tx, audit.ActorUserID); err != nil {
		return ManagedNotification{}, err
	}
	current, err := getPlatformNotification(ctx, tx, id)
	if err != nil {
		return ManagedNotification{}, err
	}
	if current.Revision != expectedRevision {
		return ManagedNotification{}, ErrConflict
	}
	now := time.Now().UTC()
	next := current.Revision + 1
	credentialsChanged := current.Provider != provider || !slices.Equal(current.Ciphertext, ciphertext) || !slices.Equal(current.Nonce, nonce)
	updated, err := execCount(ctx, tx, `UPDATE managed_notifications SET name=?,provider=?,ciphertext=?,nonce=?,enabled=?,revision=?,credential_revision=CASE WHEN ? THEN ? ELSE credential_revision END,updated_at=? WHERE id=? AND revision=? AND tenant_id IS NULL`, name, provider, ciphertext, nonce, boolInt(enabled), next, boolInt(credentialsChanged), next, now.Format(time.RFC3339Nano), id, expectedRevision)
	if err != nil {
		return ManagedNotification{}, err
	}
	if updated != 1 {
		return ManagedNotification{}, ErrConflict
	}
	audit.Action, audit.ActorKind = auditPlatformNotificationsUpdated, AuditActorPlatform
	audits := []AuditEntry{audit}
	if credentialsChanged {
		discarded, err := execCount(ctx, tx, `DELETE FROM outbox WHERE destination LIKE ? AND sent_at IS NULL`+platformDestinationSQL, "managed:"+id+":%", id)
		if err != nil {
			return ManagedNotification{}, err
		}
		if discarded > 0 {
			entry := pendingManagedDeliveryDiscardAudit(audits, id, discarded)
			entry.ActorKind = AuditActorPlatform
			audits = append(audits, entry)
		}
	} else if _, err := tx.ExecContext(ctx, `UPDATE outbox SET destination=? WHERE destination=? AND sent_at IS NULL AND terminal_at=''`+platformDestinationSQL, managedNotificationKey(id, next), managedNotificationKey(id, current.Revision), id); err != nil {
		return ManagedNotification{}, err
	}
	for _, entry := range audits {
		if err := insertPlatformAuditEntry(ctx, tx, entry, now); err != nil {
			return ManagedNotification{}, err
		}
	}
	destination, err := getPlatformNotification(ctx, tx, id)
	if err != nil {
		return ManagedNotification{}, err
	}
	return destination, tx.Commit()
}

// DeletePlatformNotificationWithAudit removes one of the platform's
// destinations at expectedRevision, with its pending deliveries and its
// delivery health, and drops it from the platform's update routing, in one
// transaction with its audit records. A tenant's destination is
// ErrNotFound, and nothing changes. The actor, audit.ActorUserID, must be an
// enabled platform administrator.
func (ps *PlatformStore) DeletePlatformNotificationWithAudit(ctx context.Context, id string, expectedRevision int64, audit AuditEntry) error {
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := requirePlatformActorTx(ctx, tx, audit.ActorUserID); err != nil {
		return err
	}
	current, err := getPlatformNotification(ctx, tx, id)
	if err != nil {
		return err
	}
	if current.Revision != expectedRevision {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM outbox WHERE destination LIKE ? AND sent_at IS NULL`+platformDestinationSQL, "managed:"+id+":%", id); err != nil {
		return err
	}
	// The delivery health goes with the destination, as a unit's does.
	if _, err := tx.ExecContext(ctx, `DELETE FROM notification_delivery_health WHERE destination_identity=? AND EXISTS (SELECT 1 FROM managed_notifications AS owner WHERE owner.id=? AND owner.tenant_id IS NULL)`, "managed:"+id, id); err != nil {
		return err
	}
	deleted, err := execCount(ctx, tx, `DELETE FROM managed_notifications WHERE id=? AND revision=? AND tenant_id IS NULL`, id, expectedRevision)
	if err != nil {
		return err
	}
	if deleted != 1 {
		return ErrConflict
	}
	now := time.Now().UTC()
	audit.Action, audit.ActorKind = auditPlatformNotificationsDeleted, AuditActorPlatform
	audits := []AuditEntry{audit}
	routing, err := readPlatformUpdateDestinationsTx(ctx, tx)
	if err != nil {
		return err
	}
	if kept := slices.DeleteFunc(slices.Clone(routing), func(selector string) bool { return selector == id }); len(kept) != len(routing) {
		if err := writePlatformUpdateDestinationsTx(ctx, tx, kept); err != nil {
			return err
		}
		entry := deletedDestinationRoutingAudit(audits, auditPlatformNotificationsUpdateRouting, fmt.Sprintf(platformNotificationRoutingRemovedDetail, id))
		entry.ActorKind = AuditActorPlatform
		audits = append(audits, entry)
	}
	for _, entry := range audits {
		if err := insertPlatformAuditEntry(ctx, tx, entry, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetPlatformUpdateDestinations replaces the platform's update routing, the
// platform destinations that the platform's copy of an update alert goes
// to. The selectors are stable destination IDs, never URLs. Callers check
// them with the notifier first, for its message; the store checks them
// again in the transaction of the write, after the actor, so the routing
// selects only platform destinations, as
// requirePlatformUpdateDestinationsTx describes, even when a caller skipped
// its check or a destination was deleted since. A tenant's destination, a
// deployment destination, and an unknown ID are refused alike with an
// ErrInvalidDestinationSelection ValidationError, and nothing changes. An
// empty selection silences the platform's copy. The actor,
// audit.ActorUserID, must be an enabled platform administrator. No tenant's
// routing changes.
func (ps *PlatformStore) SetPlatformUpdateDestinations(ctx context.Context, destinations []string, audit AuditEntry) error {
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := requirePlatformActorTx(ctx, tx, audit.ActorUserID); err != nil {
		return err
	}
	destinations = normalizeUpdateDestinations(destinations)
	if err := requirePlatformUpdateDestinationsTx(ctx, tx, destinations); err != nil {
		return err
	}
	if err := writePlatformUpdateDestinationsTx(ctx, tx, destinations); err != nil {
		return err
	}
	audit.Action, audit.ActorKind = auditPlatformNotificationsUpdateRouting, AuditActorPlatform
	if err := insertPlatformAuditEntry(ctx, tx, audit, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

// readPlatformUpdateDestinationsTx returns the platform's update routing.
func readPlatformUpdateDestinationsTx(ctx context.Context, tx *sql.Tx) ([]string, error) {
	var raw string
	err := tx.QueryRowContext(ctx, `SELECT notification_destinations_json FROM application_update_state WHERE id=1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && strings.TrimSpace(raw) == "") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var destinations []string
	if err := json.Unmarshal([]byte(raw), &destinations); err != nil {
		return nil, err
	}
	return normalizeUpdateDestinations(destinations), nil
}

// writePlatformUpdateDestinationsTx replaces the platform's update routing,
// creating the singleton row when it is missing.
func writePlatformUpdateDestinationsTx(ctx context.Context, tx *sql.Tx, destinations []string) error {
	raw, err := json.Marshal(normalizeUpdateDestinations(destinations))
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, insertApplicationUpdateStateRow); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE application_update_state SET notification_destinations_json=? WHERE id=1`, string(raw))
	return err
}
