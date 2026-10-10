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
)

// The audit actions of the security and deployment alert routing. A
// tenant's security routing is notification configuration, like its update
// routing; the platform's routings are the platform's own.
const (
	auditSecurityRouting                      = "notifications.security_routing"
	auditPlatformNotificationsSecurityRouting = "platform_notifications.security_routing"
	auditPlatformNotificationsHealthRouting   = "platform_notifications.health_routing"
)

// The routings of the platform_alert_state row, by their column.
const (
	platformSecurityRoutingColumn = "security_destinations_json"
	platformHealthRoutingColumn   = "health_destinations_json"
)

// parseAlertRouting decodes a stored alert routing: the sorted, distinct IDs
// of the web-managed destinations it selects. An empty value selects none.
// It is never nil without an error.
func parseAlertRouting(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return []string{}, nil
	}
	var destinations []string
	if err := json.Unmarshal([]byte(raw), &destinations); err != nil {
		return nil, err
	}
	return normalizeUpdateDestinations(destinations), nil
}

// encodeAlertRouting stores an alert routing: the sorted, distinct IDs as a
// JSON array. Encoding a list of strings cannot fail.
func encodeAlertRouting(destinations []string) string {
	raw, _ := json.Marshal(normalizeUpdateDestinations(destinations))
	return string(raw)
}

// SecurityAlertRouting returns the IDs of the tenant's web-managed
// destinations that its security alerts go to. A tenant starts with none,
// so security alerts are off until its administrators select destinations.
// Another tenant's routing is never read.
func (ts *TenantStore) SecurityAlertRouting(ctx context.Context) ([]string, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	var raw string
	err := ts.store.reader().QueryRowContext(ctx, `SELECT security_destinations_json FROM tenants WHERE id=?`, ts.scope.id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("tenant %s: %w", ts.scope.id, ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	return parseAlertRouting(raw)
}

// SetSecurityAlertDestinations replaces the tenant's security alert routing
// and records audit in the same transaction. Each ID must name a
// web-managed destination of the tenant, paused or not: another tenant's
// destination, a platform destination, a deployment destination from
// config.yaml, and an unknown ID are refused alike with an
// ErrInvalidDestinationSelection ValidationError, and nothing changes. An
// empty selection turns the tenant's security alerts off.
func (ts *TenantStore) SetSecurityAlertDestinations(ctx context.Context, destinations []string, audit AuditEntry) error {
	if err := ts.ready(); err != nil {
		return err
	}
	destinations = normalizeUpdateDestinations(destinations)
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, id := range destinations {
		if err := requireManagedDestinationTx(ctx, tx, id, ts.scope.id, false); err != nil {
			return err
		}
	}
	changed, err := execCount(ctx, tx, `UPDATE tenants SET security_destinations_json=? WHERE id=?`, encodeAlertRouting(destinations), ts.scope.id)
	if err != nil {
		return err
	}
	if changed == 0 {
		return fmt.Errorf("tenant %s: %w", ts.scope.id, ErrNotFound)
	}
	audit.Action = auditSecurityRouting
	if err := ts.insertAuditEntry(ctx, tx, audit, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

// requireManagedDestinationTx refuses an ID that does not name a
// web-managed destination of the owner: the tenant, or the platform when
// platform is true. A deployment destination from config.yaml is not a
// managed one, so its file: selector is refused too.
func requireManagedDestinationTx(ctx context.Context, tx *sql.Tx, id, tenantID string, platform bool) error {
	if strings.HasPrefix(id, "file:") {
		return unknownDestinationSelection(id)
	}
	var found int
	var err error
	if platform {
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM managed_notifications WHERE id=? AND tenant_id IS NULL`, id).Scan(&found)
	} else {
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM managed_notifications WHERE id=? AND tenant_id=?`, id, tenantID).Scan(&found)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return unknownDestinationSelection(id)
	}
	return err
}

// removeSecurityAlertDestinationTx drops a deleted destination from the
// tenant's security alert routing and reports whether it was selected.
func removeSecurityAlertDestinationTx(ctx context.Context, tx *sql.Tx, tenantID, id string) (bool, error) {
	var raw string
	if err := tx.QueryRowContext(ctx, `SELECT security_destinations_json FROM tenants WHERE id=?`, tenantID).Scan(&raw); errors.Is(err, sql.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	current, err := parseAlertRouting(raw)
	if err != nil {
		return false, err
	}
	kept := slices.DeleteFunc(slices.Clone(current), func(selector string) bool { return selector == id })
	if len(kept) == len(current) {
		return false, nil
	}
	_, err = tx.ExecContext(ctx, `UPDATE tenants SET security_destinations_json=? WHERE id=?`, encodeAlertRouting(kept), tenantID)
	return err == nil, err
}

// PlatformAlertRouting is the platform's routing of its security alerts and
// of the deployment-health alerts: the IDs of the platform destinations
// each goes to. Both start empty.
type PlatformAlertRouting struct {
	Security []string
	Health   []string
}

// ensurePlatformAlertStateRow is the statement that creates the platform's
// alert row when it is missing.
const ensurePlatformAlertStateRow = `INSERT OR IGNORE INTO platform_alert_state(id) VALUES(1)`

// PlatformAlertRouting returns the platform's security and deployment alert
// routing. No tenant's routing is read.
func (ps *PlatformStore) PlatformAlertRouting(ctx context.Context) (PlatformAlertRouting, error) {
	var security, health string
	err := ps.store.reader().QueryRowContext(ctx, `SELECT security_destinations_json,health_destinations_json FROM platform_alert_state WHERE id=1`).Scan(&security, &health)
	if errors.Is(err, sql.ErrNoRows) {
		return PlatformAlertRouting{Security: []string{}, Health: []string{}}, nil
	}
	if err != nil {
		return PlatformAlertRouting{}, err
	}
	routing := PlatformAlertRouting{}
	if routing.Security, err = parseAlertRouting(security); err != nil {
		return PlatformAlertRouting{}, err
	}
	if routing.Health, err = parseAlertRouting(health); err != nil {
		return PlatformAlertRouting{}, err
	}
	return routing, nil
}

// SetPlatformSecurityAlertDestinations replaces the platform destinations
// that the platform's security alerts go to: those about the platform
// administrators' accounts and about sign-ins with a username that no
// account has. SetPlatformHealthAlertDestinations replaces those that the
// deployment-health alerts go to. Each ID must name a platform destination,
// paused or not; a tenant's destination, a deployment destination, and an
// unknown ID are refused alike with an ErrInvalidDestinationSelection
// ValidationError, and nothing changes. The actor, audit.ActorUserID, must
// be an enabled platform administrator. The change is recorded in platform
// scope, and no tenant's routing changes.
func (ps *PlatformStore) SetPlatformSecurityAlertDestinations(ctx context.Context, destinations []string, audit AuditEntry) error {
	return ps.setPlatformAlertRouting(ctx, platformSecurityRoutingColumn, auditPlatformNotificationsSecurityRouting, destinations, audit)
}

// SetPlatformHealthAlertDestinations is SetPlatformSecurityAlertDestinations
// for the deployment-health alerts.
func (ps *PlatformStore) SetPlatformHealthAlertDestinations(ctx context.Context, destinations []string, audit AuditEntry) error {
	return ps.setPlatformAlertRouting(ctx, platformHealthRoutingColumn, auditPlatformNotificationsHealthRouting, destinations, audit)
}

// setPlatformAlertRouting writes one routing column of the platform's alert
// row, with its audit record.
func (ps *PlatformStore) setPlatformAlertRouting(ctx context.Context, column, action string, destinations []string, audit AuditEntry) error {
	destinations = normalizeUpdateDestinations(destinations)
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := requirePlatformActorTx(ctx, tx, audit.ActorUserID); err != nil {
		return err
	}
	for _, id := range destinations {
		if err := requireManagedDestinationTx(ctx, tx, id, "", true); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, ensurePlatformAlertStateRow); err != nil {
		return err
	}
	// column is one of the two constants above, never input.
	if _, err := tx.ExecContext(ctx, `UPDATE platform_alert_state SET `+column+`=? WHERE id=1`, encodeAlertRouting(destinations)); err != nil {
		return err
	}
	audit.Action, audit.ActorKind = action, AuditActorPlatform
	if err := insertPlatformAuditEntry(ctx, tx, audit, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

// removePlatformAlertDestinationTx drops a deleted platform destination
// from the platform's security and deployment alert routing, and returns
// the audit actions of the routings that selected it.
func removePlatformAlertDestinationTx(ctx context.Context, tx *sql.Tx, id string) ([]string, error) {
	var security, health string
	if err := tx.QueryRowContext(ctx, `SELECT security_destinations_json,health_destinations_json FROM platform_alert_state WHERE id=1`).Scan(&security, &health); errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var changed []string
	for _, routing := range []struct{ column, raw, action string }{
		{platformSecurityRoutingColumn, security, auditPlatformNotificationsSecurityRouting},
		{platformHealthRoutingColumn, health, auditPlatformNotificationsHealthRouting},
	} {
		current, err := parseAlertRouting(routing.raw)
		if err != nil {
			return nil, err
		}
		kept := slices.DeleteFunc(slices.Clone(current), func(selector string) bool { return selector == id })
		if len(kept) == len(current) {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE platform_alert_state SET `+routing.column+`=? WHERE id=1`, encodeAlertRouting(kept)); err != nil {
			return nil, err
		}
		changed = append(changed, routing.action)
	}
	return changed, nil
}

// alertQueueKeysTx resolves the IDs of an alert routing to the queue keys of
// the owner's web-managed destinations: the tenant's, or the platform's when
// platform is true. An ID that names no destination of the owner, such as a
// deleted one, is skipped. queueEventsTx then skips a paused destination
// and checks the owner again.
func alertQueueKeysTx(ctx context.Context, tx *sql.Tx, tenantID string, platform bool, ids []string) ([]string, error) {
	keys := make([]string, 0, len(ids))
	for _, id := range ids {
		var revision int64
		var err error
		if platform {
			err = tx.QueryRowContext(ctx, `SELECT revision FROM managed_notifications WHERE id=? AND tenant_id IS NULL`, id).Scan(&revision)
		} else {
			err = tx.QueryRowContext(ctx, `SELECT revision FROM managed_notifications WHERE id=? AND tenant_id=?`, id, tenantID).Scan(&revision)
		}
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		keys = append(keys, managedNotificationKey(id, revision))
	}
	return keys, nil
}
