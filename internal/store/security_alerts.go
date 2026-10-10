package store

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// SecurityAlertWindow is how long an alert window lasts. A security alert
// of an owner, a tenant or the platform, opens a window for its kind; the
// alerts of that kind within the window are counted instead of sent, and
// the daemon reports their number once the window ends, which opens the
// next window. An owner therefore gets at most one alert of each kind per
// window, however many events the audit records.
const SecurityAlertWindow = 15 * time.Minute

// securityAlertKindOf returns the security alert kind of an audit record, or
// "" for a record that sends none. The alertable records are a fixed set:
//
//   - the start of a rate-limited episode (auth.rate_limited), which the
//     authentication manager already records once per client, operation,
//     and scope in its own window;
//   - a second-factor lockout (auth.second_factor_locked);
//   - a sign-in with a recovery code (auth.recovery_code_used);
//   - a platform administrator's invitation of a unit administrator, its
//     password-reset link for one, and its end of a unit account's sessions,
//     recorded in the unit's audit with the platform actor kind.
func securityAlertKindOf(entry AuditEntry) string {
	switch entry.Action {
	case "auth.rate_limited":
		return model.SecurityAlertRateLimited
	case "auth.second_factor_locked":
		return model.SecurityAlertSecondFactorLocked
	case "auth.recovery_code_used":
		return model.SecurityAlertRecoveryCodeUsed
	}
	if entry.ActorKind != AuditActorPlatform || entry.platform || entry.TenantID == "" {
		return ""
	}
	switch entry.Action {
	case "user.created":
		return model.SecurityAlertPlatformInvitation
	case "user.password_reset_issued":
		return model.SecurityAlertPlatformPasswordReset
	case "user.sessions_revoked":
		return model.SecurityAlertPlatformSessionsEnded
	}
	return ""
}

// rateLimitOperations names the operations of a rate-limit record by its
// subject, which the authentication manager records as the actor name.
var rateLimitOperations = map[string]string{
	"setup":                 "first setup",
	"platform-setup":        "platform setup",
	"activation":            "activation link",
	"password-confirmation": "password confirmation",
	"totp-confirmation":     "TOTP confirmation",
}

// securityAlertDetail returns what the alert of a record reports. It names
// the account by its username where the record is about a known account,
// and the client address of an authentication event. A record of a
// platform administrator's action names the administrator but not its
// address, which the unit's audit hides too. A rate-limit record of a
// sign-in names its account only in a tenant's scope, where the name is an
// account's of the tenant; in platform scope it may be any name that a
// client sent, so it is left out.
func securityAlertDetail(entry AuditEntry, kind string, platform bool) model.AlertDetail {
	detail := model.AlertDetail{Kind: kind}
	switch kind {
	case model.SecurityAlertRateLimited:
		subject := strings.TrimSpace(entry.ActorUsername)
		if identity, login := strings.CutPrefix(subject, "login:"); login {
			detail.Operation = "sign-in"
			if !platform {
				detail.Account = alertUsername(identity)
			}
		} else if operation, known := rateLimitOperations[subject]; known {
			detail.Operation = operation
		} else {
			detail.Operation = "authentication"
		}
		detail.Source = strings.TrimSpace(entry.SourceIP)
	case model.SecurityAlertSecondFactorLocked, model.SecurityAlertRecoveryCodeUsed:
		detail.Account = alertUsername(entry.ActorUsername)
		detail.Source = strings.TrimSpace(entry.SourceIP)
	default:
		detail.Account = alertUsername(entry.alertAccount)
		detail.Actor = alertUsername(entry.ActorUsername)
	}
	return detail
}

// alertUsername returns the stored form of a username for an alert, or ""
// for a value that cannot be one.
func alertUsername(value string) string {
	normalized, err := NormalizeUsername(value)
	if err != nil {
		return ""
	}
	return normalized
}

// queueSecurityAlertForAuditTx queues the security alert of the audit record
// that tx has just written, when the record's owner routes security alerts
// to destinations. The alert is queued in the record's transaction, so it
// is sent only when the record is committed. A failure to queue it is
// logged and rolled back alone: the record, and the action it records,
// never fail because of their alert.
func queueSecurityAlertForAuditTx(ctx context.Context, tx *sql.Tx, entry AuditEntry, kind string, now time.Time) {
	if _, err := tx.ExecContext(ctx, `SAVEPOINT security_alert`); err != nil {
		slog.Default().Warn("security alert could not be queued", "action", entry.Action, "error", err)
		return
	}
	if err := queueSecurityAlertTx(ctx, tx, entry, kind, now); err != nil {
		_, _ = tx.ExecContext(ctx, `ROLLBACK TO security_alert`)
		slog.Default().Warn("security alert could not be queued", "action", entry.Action, "error", err)
	}
	_, _ = tx.ExecContext(ctx, `RELEASE security_alert`)
}

// queueSecurityAlertTx queues the alert of the audit record that tx has just
// written. Its owner is the record's: the tenant of the record, or the
// platform for a record in platform scope.
func queueSecurityAlertTx(ctx context.Context, tx *sql.Tx, entry AuditEntry, kind string, now time.Time) error {
	var tenant sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT tenant_id FROM security_audit WHERE rowid=last_insert_rowid()`).Scan(&tenant); err != nil {
		return err
	}
	owner := alertOwner{tenantID: tenant.String, platform: !tenant.Valid}
	route, err := securityAlertRouteTx(ctx, tx, owner)
	if err != nil || len(route.keys) == 0 {
		return err
	}
	detail := securityAlertDetail(entry, kind, owner.platform)
	detail.Unit = route.unit
	send, held, since, err := claimSecurityAlertWindowTx(ctx, tx, owner, model.SecurityAlertWindowKind(kind), now)
	if err != nil || !send {
		return err
	}
	if held > 0 {
		detail.Count, detail.Since = held, since
	}
	return queueAlertTx(ctx, tx, owner, detail, route.keys, now)
}

// alertOwner is the owner of an alert: a tenant, or the platform.
type alertOwner struct {
	tenantID string
	platform bool
}

// arg is the owner's tenant as a statement argument: NULL for the platform.
func (owner alertOwner) arg() any {
	if owner.platform {
		return nil
	}
	return owner.tenantID
}

// alertRoute is where an owner's security alerts go: the queue keys of its
// selected destinations and, for a tenant, the tenant's name.
type alertRoute struct {
	keys []string
	unit string
}

// securityAlertRouteTx reads the owner's security alert routing. A tenant
// that is not active gets no alerts: its accounts cannot sign in, and its
// administrators see the records in its audit once it is enabled again.
func securityAlertRouteTx(ctx context.Context, tx *sql.Tx, owner alertOwner) (alertRoute, error) {
	var raw, state, name string
	var err error
	if owner.platform {
		err = tx.QueryRowContext(ctx, `SELECT security_destinations_json FROM platform_alert_state WHERE id=1`).Scan(&raw)
	} else {
		err = tx.QueryRowContext(ctx, `SELECT security_destinations_json,state,name FROM tenants WHERE id=?`, owner.tenantID).Scan(&raw, &state, &name)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return alertRoute{}, nil
	}
	if err != nil {
		return alertRoute{}, err
	}
	if !owner.platform && state != TenantStateActive {
		return alertRoute{}, nil
	}
	ids, err := parseAlertRouting(raw)
	if err != nil || len(ids) == 0 {
		return alertRoute{}, err
	}
	keys, err := alertQueueKeysTx(ctx, tx, owner.tenantID, owner.platform, ids)
	return alertRoute{keys: keys, unit: name}, err
}

// claimSecurityAlertWindowTx decides whether an alert of the owner and
// window kind is sent now. It is when no window of the kind is open, which
// opens one; within an open window the alert is counted instead. When the
// owner's last window ended with alerts that the daemon has not reported
// yet, held is their number and since the start of that window, and the
// alert sent now reports them.
func claimSecurityAlertWindowTx(ctx context.Context, tx *sql.Tx, owner alertOwner, kind string, now time.Time) (send bool, held int, since time.Time, err error) {
	var id int64
	var started string
	err = tx.QueryRowContext(ctx, `SELECT id,started_at,suppressed FROM security_alert_windows WHERE tenant_id IS ? AND kind=?`, owner.arg(), kind).Scan(&id, &started, &held)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, `INSERT INTO security_alert_windows(tenant_id,kind,started_at,suppressed) VALUES(?,?,?,0)`, owner.arg(), kind, sqliteTimestamp(now))
		return err == nil, 0, time.Time{}, err
	}
	if err != nil {
		return false, 0, time.Time{}, err
	}
	startedAt, parseErr := time.Parse(time.RFC3339Nano, started)
	if parseErr == nil && now.Before(startedAt.Add(SecurityAlertWindow)) {
		_, err = tx.ExecContext(ctx, `UPDATE security_alert_windows SET suppressed=suppressed+1 WHERE id=?`, id)
		return false, 0, time.Time{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE security_alert_windows SET started_at=?,suppressed=0 WHERE id=?`, sqliteTimestamp(now), id); err != nil {
		return false, 0, time.Time{}, err
	}
	return true, held, startedAt, nil
}

// queueAlertTx queues one security alert of the owner to the queue keys.
func queueAlertTx(ctx context.Context, tx *sql.Tx, owner alertOwner, detail model.AlertDetail, keys []string, now time.Time) error {
	event := model.Event{Type: model.EventSecurityAlert, Message: "EdgeWatch security alert", Alert: &detail, CreatedAt: now}
	if !owner.platform {
		event.TenantID = owner.tenantID
	}
	return queueEventsTx(ctx, tx, []model.Event{event}, keys)
}

// FlushSecurityAlertWindows reports the alerts that ended windows held back
// and returns how many summaries it queued. A window that ended with alerts
// sends one summary of their number to its owner's current routing, and
// the summary opens the next window; a window that ended without any, or
// whose owner no longer routes security alerts, is removed. The daemon
// runs it with its heartbeat.
func (ss *SystemStore) FlushSecurityAlertWindows(ctx context.Context, now time.Time) (int, error) {
	ended := sqliteTimestamp(now.Add(-SecurityAlertWindow))
	// Count first, without the writer, so the heartbeat that calls this
	// takes the writer only when a window ended.
	var count int
	if err := ss.store.reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM security_alert_windows WHERE started_at<=?`, ended).Scan(&count); err != nil || count == 0 {
		return 0, err
	}
	tx, err := ss.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	windows, err := endedSecurityAlertWindowsTx(ctx, tx, ended)
	if err != nil {
		return 0, err
	}
	queued := 0
	for _, w := range windows {
		route := alertRoute{}
		if w.suppressed > 0 {
			if route, err = securityAlertRouteTx(ctx, tx, w.owner); err != nil {
				return 0, err
			}
		}
		if len(route.keys) == 0 {
			if _, err := tx.ExecContext(ctx, `DELETE FROM security_alert_windows WHERE id=?`, w.id); err != nil {
				return 0, err
			}
			continue
		}
		since, _ := time.Parse(time.RFC3339Nano, w.started)
		detail := model.AlertDetail{Kind: model.SecurityAlertSummary, Subject: w.kind, Unit: route.unit, Count: w.suppressed, Since: since}
		if err := queueAlertTx(ctx, tx, w.owner, detail, route.keys, now); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE security_alert_windows SET started_at=?,suppressed=0 WHERE id=?`, sqliteTimestamp(now), w.id); err != nil {
			return 0, err
		}
		queued++
	}
	return queued, tx.Commit()
}

// securityAlertWindow is one alert window of an owner and kind.
type securityAlertWindow struct {
	id         int64
	owner      alertOwner
	kind       string
	started    string
	suppressed int
}

// endedSecurityAlertWindowsTx reads the windows that started at or before
// ended. The rows are closed before the caller writes to tx.
func endedSecurityAlertWindowsTx(ctx context.Context, tx *sql.Tx, ended string) ([]securityAlertWindow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,tenant_id,kind,started_at,suppressed FROM security_alert_windows WHERE started_at<=? ORDER BY id`, ended)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var windows []securityAlertWindow
	for rows.Next() {
		var w securityAlertWindow
		var tenant sql.NullString
		if err := rows.Scan(&w.id, &tenant, &w.kind, &w.started, &w.suppressed); err != nil {
			return nil, err
		}
		w.owner = alertOwner{tenantID: tenant.String, platform: !tenant.Valid}
		windows = append(windows, w)
	}
	return windows, rows.Err()
}
