package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// auditApplicationHealthAlert is the platform audit record of a
// deployment-health alert. Every alert is recorded, whether or not the
// platform routes deployment alerts to a destination.
const auditApplicationHealthAlert = "application.health_alert"

// DeploymentHealthAlertWindow is the shortest time between two
// deployment-health alerts about one sandbox, and between two rollback
// alerts, so a daemon that restarts in a loop, or whose sandbox comes and
// goes, raises at most one alert of each per window. A change within the
// window is reported once it ends, when it still holds.
const DeploymentHealthAlertWindow = time.Hour

// DeliveryFailureAlertWindow is the shortest time between two alerts about
// deliveries that failed for good. Each reports the failures since the
// previous one.
const DeliveryFailureAlertWindow = 6 * time.Hour

// SandboxHealth is how the scanner and the notification processes start in
// the running daemon, as the confinement states of model.SandboxState*. An
// empty state is not known, such as for a library caller without a sandbox
// policy, and is not compared.
type SandboxHealth struct {
	Scanner      string
	Notification string
}

// sandboxConfinement reports what a confinement state keeps: the process
// identity without root, and the Landlock restriction. A state that was
// never recorded counts as fully confined, so a first observation that is
// already degraded is reported once.
func sandboxConfinement(state string) (identity, landlock bool) {
	switch state {
	case model.SandboxStateIdentityOnly:
		return true, false
	case model.SandboxStateLandlockOnly:
		return false, true
	case model.SandboxStateUnconfined:
		return false, false
	default:
		return true, true
	}
}

// sandboxDegraded reports whether current lost a confinement that previous
// had. A change that loses one and gains the other is a degradation too.
func sandboxDegraded(previous, current string) bool {
	previousIdentity, previousLandlock := sandboxConfinement(previous)
	currentIdentity, currentLandlock := sandboxConfinement(current)
	return (previousIdentity && !currentIdentity) || (previousLandlock && !currentLandlock)
}

// sandboxProfiles names the columns of each sandbox in platform_alert_state.
var sandboxProfiles = []struct{ subject, state, alerted string }{
	{"scanner", "scanner_sandbox", "scanner_sandbox_alerted_at"},
	{"notification", "notification_sandbox", "notification_sandbox_alerted_at"},
}

// RecordSandboxHealth compares the observed sandbox states with the states
// that the last deployment-health alerts reported, and records one alert
// for each sandbox whose state changed: a degradation when it lost
// Landlock or its identity without root, and a recovery otherwise. A state
// that is the same as the recorded one, as after a restart, records
// nothing. A change within DeploymentHealthAlertWindow of the sandbox's
// previous alert waits for the end of the window; the daemon calls this
// again with its heartbeat. The first state observed is recorded without an
// alert when it is fully confined. It returns the number of alerts it
// recorded.
func (ps *PlatformStore) RecordSandboxHealth(ctx context.Context, observed SandboxHealth, now time.Time) (int, error) {
	states := map[string]string{"scanner": observed.Scanner, "notification": observed.Notification}
	if states["scanner"] == "" && states["notification"] == "" {
		return 0, nil
	}
	// Read first, without the writer, so the heartbeat that calls this
	// takes the writer only when a state changed.
	current, err := readSandboxHealth(ctx, ps.store.reader())
	if err != nil {
		return 0, err
	}
	pending := false
	for _, profile := range sandboxProfiles {
		if sandboxChangeDue(states[profile.subject], current[profile.state], current[profile.alerted], now) {
			pending = true
		}
	}
	if !pending {
		return 0, nil
	}
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, ensurePlatformAlertStateRow); err != nil {
		return 0, err
	}
	stored, err := readSandboxHealth(ctx, tx)
	if err != nil {
		return 0, err
	}
	recorded := 0
	for _, profile := range sandboxProfiles {
		observed, previous := states[profile.subject], stored[profile.state]
		if !sandboxChangeDue(observed, previous, stored[profile.alerted], now) {
			continue
		}
		alertedAt := sqliteTimestamp(now)
		if previous == "" && !sandboxDegraded(previous, observed) {
			// The first observation of a confined sandbox is the baseline.
			alertedAt = ""
		} else {
			kind := model.HealthAlertSandboxRecovered
			if sandboxDegraded(previous, observed) {
				kind = model.HealthAlertSandboxDegraded
			}
			detail := model.AlertDetail{Kind: kind, Subject: profile.subject, Previous: previous, Current: observed}
			text := fmt.Sprintf("%s sandbox %s: %s, previously %s", profile.subject, strings.TrimPrefix(kind, "sandbox_"), observed, recordedState(previous))
			if err := recordHealthAlertTx(ctx, tx, detail, text, true, now); err != nil {
				return 0, err
			}
			recorded++
		}
		// The columns are those of sandboxProfiles, never input.
		if _, err := tx.ExecContext(ctx, `UPDATE platform_alert_state SET `+profile.state+`=?,`+profile.alerted+`=? WHERE id=1`, observed, alertedAt); err != nil {
			return 0, err
		}
	}
	return recorded, tx.Commit()
}

// sandboxChangeDue reports whether an observed sandbox state differs from
// the recorded one outside the window of the sandbox's previous alert,
// whose time alerted records.
func sandboxChangeDue(observed, recorded, alerted string, now time.Time) bool {
	if observed == "" || observed == recorded {
		return false
	}
	alertedAt, err := time.Parse(time.RFC3339Nano, alerted)
	return err != nil || !now.Before(alertedAt.Add(DeploymentHealthAlertWindow))
}

// recordedState names a recorded sandbox state for an audit record.
func recordedState(state string) string {
	if state == "" {
		return "not recorded"
	}
	return state
}

// readSandboxHealth reads the recorded sandbox states and the times of
// their last alerts by column. A missing row records nothing.
func readSandboxHealth(ctx context.Context, queryer rowQueryer) (map[string]string, error) {
	values := make([]string, 4)
	err := queryer.QueryRowContext(ctx, `SELECT scanner_sandbox,scanner_sandbox_alerted_at,notification_sandbox,notification_sandbox_alerted_at FROM platform_alert_state WHERE id=1`).Scan(&values[0], &values[1], &values[2], &values[3])
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return map[string]string{
		"scanner_sandbox": values[0], "scanner_sandbox_alerted_at": values[1],
		"notification_sandbox": values[2], "notification_sandbox_alerted_at": values[3],
	}, nil
}

// RecordInstalledVersionRollback persists a running build that is older
// than the installed version, as RecordInstalledVersion does for a
// rollback, and records a deployment-health alert of the rollback in the
// same transaction. The caller compares the versions. A rollback within
// DeploymentHealthAlertWindow of the previous rollback alert is recorded in
// the platform audit but not sent again. It reports whether it queued an
// alert.
func (ps *PlatformStore) RecordInstalledVersionRollback(ctx context.Context, current string, now time.Time) (bool, error) {
	current = strings.TrimSpace(current)
	if current == "" {
		return false, nil
	}
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var previous string
	if err := tx.QueryRowContext(ctx, `SELECT installed_version FROM application_update_state WHERE id=1`).Scan(&previous); err != nil {
		return false, err
	}
	if previous == "" || previous == current {
		_, err := tx.ExecContext(ctx, `UPDATE application_update_state SET installed_version=? WHERE id=1`, current)
		if err != nil {
			return false, err
		}
		return false, tx.Commit()
	}
	// A rollback is not an upgrade notification: clear the announcement, so a
	// later re-install of the previous version is announced again.
	if _, err := tx.ExecContext(ctx, `UPDATE application_update_state SET installed_version=?,announced_upgrade_version='' WHERE id=1`, current); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, ensurePlatformAlertStateRow); err != nil {
		return false, err
	}
	var alerted string
	if err := tx.QueryRowContext(ctx, `SELECT rollback_alerted_at FROM platform_alert_state WHERE id=1`).Scan(&alerted); err != nil {
		return false, err
	}
	send := true
	if alertedAt, err := time.Parse(time.RFC3339Nano, alerted); err == nil && now.Before(alertedAt.Add(DeploymentHealthAlertWindow)) {
		send = false
	}
	detail := model.AlertDetail{Kind: model.HealthAlertVersionRollback, Previous: previous, Current: current}
	if err := recordHealthAlertTx(ctx, tx, detail, fmt.Sprintf("version rollback: %s, previously %s", current, previous), send, now); err != nil {
		return false, err
	}
	if send {
		if _, err := tx.ExecContext(ctx, `UPDATE platform_alert_state SET rollback_alerted_at=? WHERE id=1`, sqliteTimestamp(now)); err != nil {
			return false, err
		}
	}
	return send, tx.Commit()
}

// noteFailedDeliveryTx counts a delivery that failed for good, which tx has
// just marked, for the next deployment-health alert: in the deployment's
// count and, for a platform alert, in the platform's. The failure of a
// deployment-health alert is not counted, so an alert about failed
// deliveries that fails itself raises no further alert. A failure to count
// it is logged and rolled back alone; the delivery's outcome is recorded
// either way.
func noteFailedDeliveryTx(ctx context.Context, tx *sql.Tx, outboxID int64, now time.Time) {
	if _, err := tx.ExecContext(ctx, `SAVEPOINT failed_delivery`); err != nil {
		slog.Default().Warn("failed delivery could not be counted for the deployment alert", "error", err)
		return
	}
	_, err := tx.ExecContext(ctx, `UPDATE platform_alert_state SET
 failed_deliveries=failed_deliveries+1,
 failed_platform_deliveries=failed_platform_deliveries+COALESCE((SELECT CASE WHEN tenant_id IS NULL THEN 1 ELSE 0 END FROM outbox WHERE id=?1),0),
 failed_deliveries_since=CASE WHEN failed_deliveries=0 THEN ?2 ELSE failed_deliveries_since END
WHERE id=1 AND NOT EXISTS (SELECT 1 FROM outbox WHERE id=?1 AND json_valid(CAST(payload_json AS TEXT)) AND json_extract(CAST(payload_json AS TEXT),'$.type')=?3)`, outboxID, sqliteTimestamp(now), model.EventHealthAlert)
	if err != nil {
		_, _ = tx.ExecContext(ctx, `ROLLBACK TO failed_delivery`)
		slog.Default().Warn("failed delivery could not be counted for the deployment alert", "error", err)
	}
	_, _ = tx.ExecContext(ctx, `RELEASE failed_delivery`)
}

// RecordDeliveryFailureHealth records one deployment-health alert of the
// deliveries that failed for good since the previous one, with their
// number and the part of them that the platform owns; counts only, never a
// destination, a URL, or a provider's answer. It records nothing while none
// failed, or within DeliveryFailureAlertWindow of the previous alert. It
// reports whether it recorded an alert.
func (ps *PlatformStore) RecordDeliveryFailureHealth(ctx context.Context, now time.Time) (bool, error) {
	due := func(queryer rowQueryer) (failed, platform int, since time.Time, ok bool, err error) {
		var sinceRaw, alertedRaw string
		err = queryer.QueryRowContext(ctx, `SELECT failed_deliveries,failed_platform_deliveries,failed_deliveries_since,failed_deliveries_alerted_at FROM platform_alert_state WHERE id=1`).Scan(&failed, &platform, &sinceRaw, &alertedRaw)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, time.Time{}, false, nil
		}
		if err != nil || failed <= 0 {
			return 0, 0, time.Time{}, false, err
		}
		if alertedAt, parseErr := time.Parse(time.RFC3339Nano, alertedRaw); parseErr == nil && now.Before(alertedAt.Add(DeliveryFailureAlertWindow)) {
			return 0, 0, time.Time{}, false, nil
		}
		since, _ = time.Parse(time.RFC3339Nano, sinceRaw)
		return failed, platform, since, true, nil
	}
	if _, _, _, ok, err := due(ps.store.reader()); err != nil || !ok {
		return false, err
	}
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	failed, platform, since, ok, err := due(tx)
	if err != nil || !ok {
		return false, err
	}
	detail := model.AlertDetail{Kind: model.HealthAlertDeliveryFailures, Count: failed, PlatformCount: platform, Since: since}
	text := fmt.Sprintf("%d alerts failed for good, %d of them to platform destinations", failed, platform)
	if err := recordHealthAlertTx(ctx, tx, detail, text, true, now); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE platform_alert_state SET failed_deliveries=0,failed_platform_deliveries=0,failed_deliveries_since='',failed_deliveries_alerted_at=? WHERE id=1`, sqliteTimestamp(now)); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// recordHealthAlertTx records a deployment-health alert in the platform
// audit, with the daemon as its actor, and, when send is true, queues it to
// the platform destinations of the deployment alert routing. It is the
// platform's alert: no tenant's destination receives it.
func recordHealthAlertTx(ctx context.Context, tx *sql.Tx, detail model.AlertDetail, text string, send bool, now time.Time) error {
	if err := insertPlatformAuditEntry(ctx, tx, AuditEntry{Action: auditApplicationHealthAlert, Detail: text, ActorKind: AuditActorSystem}, now); err != nil {
		return err
	}
	if !send {
		return nil
	}
	var raw string
	if err := tx.QueryRowContext(ctx, `SELECT health_destinations_json FROM platform_alert_state WHERE id=1`).Scan(&raw); errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	ids, err := parseAlertRouting(raw)
	if err != nil || len(ids) == 0 {
		return err
	}
	keys, err := alertQueueKeysTx(ctx, tx, "", true, ids)
	if err != nil {
		return err
	}
	event := model.Event{Type: model.EventHealthAlert, Message: "EdgeWatch deployment alert", Alert: &detail, CreatedAt: now}
	return queueEventsTx(ctx, tx, []model.Event{event}, keys)
}
