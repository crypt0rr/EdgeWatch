package store

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"
)

// The side effects of a change to an account's role, enabled state, or
// password. Six writers make such changes: TenantStore.updateUser and
// SaveUserSecurityPreservingSession, PlatformAccountStore.save,
// PlatformStore.SetPlatformAdminEnabled,
// Store.SaveAdminSecurityWithAuditPreservingSession, and Store.ActivateUser.
// Each writes the account and then calls applyAccountTransitionTx in the
// same transaction, so the sessions and links that a change ends, and the
// records of the ended links, do not depend on the writer.

// accountState is the part of an account that decides which of its sessions
// and links stay valid.
type accountState struct {
	role         string
	enabled      bool
	passwordHash string
}

// pending reports whether the account has not redeemed its activation link
// yet. A pending account is disabled until it does.
func (state accountState) pending() bool { return strings.HasPrefix(state.passwordHash, "!pending") }

// issuesLinks reports whether an account with the role issues activation and
// password-reset links: a tenant's administrator, for the tenant's accounts,
// and a platform administrator, for the tenants' administrators and other
// platform administrators.
func issuesLinks(role string) bool { return role == RoleAdministrator || role == RolePlatformAdmin }

// Why applyAccountTransitionTx ended an account's links, as their audit
// record says. linksRevokedIssuerDemoted and linksRevokedIssuerDisabled name
// the issuer.
const (
	linksRevokedPasswordChanged = "its password changed"
	linksRevokedRoleChanged     = "its role changed"
	linksRevokedDisabled        = "it was disabled"
	linksRevokedIssuerDemoted   = "their issuer %s was demoted"
	linksRevokedIssuerDisabled  = "their issuer %s was disabled"
)

// accountTransition is one write's change to an account.
type accountTransition struct {
	// userID and username name the account, and tenantID is its tenant, or
	// "" for a platform administrator.
	userID, username, tenantID string
	// before and after are the account's state before and after the write.
	before, after accountState
	// revokeSessions asks to end the account's sessions when the change
	// itself ends none, as a TOTP change does; preserveSessionHash then
	// keeps the session with that hash, the browser that made the change. A
	// change that ends the sessions ends that one too.
	revokeSessions      bool
	preserveSessionHash string
	// at is the time of the change, at which the links end.
	at time.Time
	// audit is the change's own record. The records of the ended links have
	// its actor, and a change without a record gives none.
	audit AuditEntry
}

// account returns the SQL that names the account by its ID in its tenant or
// in platform scope, tenantUserSQL or platformAdminSQL, with its arguments.
// A statement through it cannot reach an account of another tenant even if
// the writer's own checks were skipped.
func (change accountTransition) account() (string, []any) {
	if change.tenantID == "" {
		return platformAdminSQL, []any{change.userID, RolePlatformAdmin}
	}
	return tenantUserSQL, []any{change.userID, change.tenantID}
}

// applyAccountTransitionTx applies the side effects of the change in tx,
// after the writer wrote the account:
//
//   - a change of the account's role, enabled state, or password ends every
//     session of the account; the writer's own request ends them too, apart
//     from the session it preserves. The original administrator's sessions
//     include those from before accounts existed, which name no account;
//   - a change of the password or the role, and disabling an account that
//     is not pending, end every unused link of the account, whoever issued
//     it, so a link issued before the change cannot set the password
//     afterwards, enable the account again, or outlive the role it was
//     issued for. A pending account's role change ends its activation link
//     too, and the account then needs a new one;
//   - demoting or disabling an administrator or a platform administrator
//     ends every unused link that it issued, which must not outlive its
//     privilege; a tenant's administrator reaches only the links of the
//     tenant's accounts.
//
// It returns the records of the ended links: one for each account that had
// a link that could still have been redeemed, naming the account, with the
// actor of the change's record. The record of a tenant's account belongs to
// that tenant, as user.activation_revoked, and the record of a platform
// administrator to platform scope, as platform_admin.activation_revoked. A
// link that had expired was unusable already, so it gets none. The writer
// writes the records after its own, in the same transaction.
func applyAccountTransitionTx(ctx context.Context, tx *sql.Tx, change accountTransition) ([]AuditEntry, error) {
	accountSQL, accountArgs := change.account()
	before, after := change.before, change.after
	roleChanged, enabledChanged, passwordChanged := before.role != after.role, before.enabled != after.enabled, before.passwordHash != after.passwordHash
	securityChange := roleChanged || enabledChanged || passwordChanged
	if securityChange || change.revokeSessions {
		query, args := `DELETE FROM sessions WHERE user_id=`+accountSQL, accountArgs
		if change.userID == LegacyAdminUserID {
			query = `DELETE FROM sessions WHERE (user_id=` + accountSQL + ` OR user_id='')`
		}
		if preserve := strings.TrimSpace(change.preserveSessionHash); preserve != "" && !securityChange {
			query, args = query+` AND id_hash<>?`, append(slices.Clone(args), preserve)
		}
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return nil, err
		}
	}
	var records []AuditEntry
	var reason string
	switch {
	case passwordChanged:
		reason = linksRevokedPasswordChanged
	case roleChanged:
		reason = linksRevokedRoleChanged
	case before.enabled && !after.enabled && !before.pending():
		reason = linksRevokedDisabled
	}
	if reason != "" {
		ended, err := revokeLinksTx(ctx, tx, change.at, `user_id=`+accountSQL, accountArgs...)
		if err != nil {
			return nil, err
		}
		if len(ended) > 0 {
			records = append(records, change.linksRevoked(change.username, change.tenantID, reason))
		}
	}
	if issuesLinks(before.role) && (roleChanged || !after.enabled) {
		issued, args := `issuer_user_id=`+accountSQL, accountArgs
		if change.tenantID != "" {
			issued, args = issued+` AND user_id IN (SELECT id FROM users WHERE tenant_id=?)`, append(slices.Clone(args), change.tenantID)
		}
		ended, err := revokeLinksTx(ctx, tx, change.at, issued, args...)
		if err != nil {
			return nil, err
		}
		reason := fmt.Sprintf(linksRevokedIssuerDisabled, change.username)
		if roleChanged {
			reason = fmt.Sprintf(linksRevokedIssuerDemoted, change.username)
		}
		for _, userID := range ended {
			var username, tenantID string
			if err := tx.QueryRowContext(ctx, `SELECT username,COALESCE(tenant_id,'') FROM users WHERE id=?`, userID).Scan(&username, &tenantID); err != nil {
				return nil, err
			}
			records = append(records, change.linksRevoked(username, tenantID, reason))
		}
	}
	return records, nil
}

// linksRevoked is the record of the ended links of the account with the
// username in the tenant, "" for a platform administrator. It has the actor
// of the change's record; a change without a record gives one without an
// action, which no writer writes.
func (change accountTransition) linksRevoked(username, tenantID, reason string) AuditEntry {
	entry := change.audit
	if strings.TrimSpace(entry.Action) == "" {
		return AuditEntry{}
	}
	entry.Action, entry.Detail = "user.activation_revoked", fmt.Sprintf("activation links revoked for %s because %s", username, reason)
	entry.TenantID, entry.platform = tenantID, tenantID == ""
	if entry.platform {
		entry.Action = auditPlatformAdminActivationRevoked
	}
	return entry
}

// revokeLinksTx marks every unused activation and password-reset link that
// the condition selects as used at the time at, so none of them can be
// redeemed afterwards. It returns the IDs of the accounts, in order, that
// had a link among them that was still redeemable, unexpired at that time.
func revokeLinksTx(ctx context.Context, tx *sql.Tx, at time.Time, condition string, args ...any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `UPDATE user_invites SET used_at=? WHERE used_at IS NULL AND `+condition+` RETURNING user_id,expires_at`, append([]any{at.UTC().Format(time.RFC3339Nano)}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []string
	for rows.Next() {
		var userID, expires string
		if err := rows.Scan(&userID, &expires); err != nil {
			return nil, err
		}
		if at.Before(scanTime(expires)) && !slices.Contains(accounts, userID) {
			accounts = append(accounts, userID)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	slices.Sort(accounts)
	return accounts, nil
}
