package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// DeliveryHealth is the redacted operational state for one notification
// destination. Destination identity is an internal stable selector; callers
// should join it to a named destination before returning it over HTTP.
type DeliveryHealth struct {
	DestinationIdentity  string
	Pending              int
	Retrying             int
	Deferrals            int
	TerminalFailures     int
	LastSuccessAt        time.Time
	LastFailureAt        time.Time
	LastTerminalAt       time.Time
	LastErrorCode        string
	LastErrorFingerprint string
}

// deliveryIdentity collapses revisioned managed selectors so replacing a
// credential keeps the destination's health history. Deployment selectors
// are already URL hashes and are retained as-is.
func deliveryIdentity(selector string) string {
	if strings.HasPrefix(selector, "managed:") {
		parts := strings.Split(selector, ":")
		if len(parts) >= 2 && parts[1] != "" {
			return "managed:" + parts[1]
		}
	}
	return selector
}

// managedIntent is what resolveManagedIntentTx made of a managed selector for
// one owner: the key of the outbox row, or "" and why no row is created.
type managedIntent struct{ key, discardReason string }

// eventOwner names whose destinations an event's alert may go to: the
// platform's for a platform event, the named tenant's for a tenant's event
// without a job, or else those of the tenant of the event's job. Events with
// the same owner resolve a managed selector the same way.
func eventOwner(event model.Event) string {
	switch {
	case platformEvent(event):
		return ""
	case tenantEvent(event):
		return "tenant:" + event.TenantID
	default:
		return "job:" + event.JobID
	}
}

func deliveryErrorCode(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	switch {
	case errors.Is(err, ErrDeliveryDestinationLocked):
		return "destination_locked"
	case errors.Is(err, ErrDeliveryDestinationMissing):
		return "destination_missing"
	case errors.Is(err, ErrDeliveryProviderPanic):
		return "provider_panic"
	case errors.Is(err, ErrDeliveryWorkerPanic):
		return "worker_panic"
	case errors.Is(err, ErrDeliveryPayloadInvalid):
		return "payload_invalid"
	case errors.Is(err, ErrDeliveryIndeterminate):
		return "delivery_indeterminate"
	case errors.Is(err, ErrDeliveryProvider):
		return "delivery_failed"
	}
	return "delivery_failed"
}

func deliveryErrorFingerprint(err error) string {
	if err == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(err.Error()))
	return hex.EncodeToString(sum[:])[:16]
}

func deliverySelectorFingerprint(selector string) string {
	sum := sha256.Sum256([]byte(selector))
	return hex.EncodeToString(sum[:])[:16]
}

func ensureDeliveryHealthTx(ctx context.Context, tx contextExecer, selector string, now time.Time) error {
	identity := deliveryIdentity(selector)
	if identity == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO notification_delivery_health(destination_identity,updated_at) VALUES(?,?)`, identity, now.UTC().Format(time.RFC3339Nano))
	return err
}

func recordDeliverySuccessTx(ctx context.Context, tx contextExecer, selector string, now time.Time) error {
	identity := deliveryIdentity(selector)
	if identity == "" {
		return nil
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	_, err := tx.ExecContext(ctx, `INSERT INTO notification_delivery_health(destination_identity,last_success_at,last_error_code,last_error_fingerprint,updated_at)
VALUES(?,?,?,?,?)
ON CONFLICT(destination_identity) DO UPDATE SET last_success_at=excluded.last_success_at,last_error_code='',last_error_fingerprint='',updated_at=excluded.updated_at`, identity, stamp, "", "", stamp)
	return err
}

func recordDeliveryFailureTx(ctx context.Context, tx contextExecer, selector string, sendErr error, terminal bool, now time.Time) error {
	identity := deliveryIdentity(selector)
	if identity == "" {
		return nil
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	code := deliveryErrorCode(sendErr)
	fingerprint := deliveryErrorFingerprint(sendErr)
	terminalAt := ""
	if terminal {
		terminalAt = stamp
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO notification_delivery_health(destination_identity,terminal_failures,last_failure_at,last_terminal_at,last_error_code,last_error_fingerprint,updated_at)
VALUES(?,CASE WHEN ? THEN 1 ELSE 0 END,?,?,?,?,?)
ON CONFLICT(destination_identity) DO UPDATE SET
 terminal_failures=notification_delivery_health.terminal_failures+CASE WHEN ? THEN 1 ELSE 0 END,
 last_failure_at=excluded.last_failure_at,
 last_terminal_at=CASE WHEN ? THEN excluded.last_terminal_at ELSE notification_delivery_health.last_terminal_at END,
 last_error_code=excluded.last_error_code,
 last_error_fingerprint=excluded.last_error_fingerprint,
 updated_at=excluded.updated_at`, identity, terminal, stamp, terminalAt, code, fingerprint, stamp, terminal, terminal)
	return err
}

// Delivery health belongs to the tenant that owns the destination: a managed
// identity ("managed:<id>") is joined to managed_notifications.tenant_id. The
// default tenant also keeps every identity that is not managed: those of the
// config.yaml destinations, which it owns, as the installation's health did
// before tenants existed. A managed identity that names no current
// destination belongs to no tenant, so a destination that another tenant or
// the platform deleted never moves to the default tenant's totals. Pending
// deliveries of a paused destination are not counted. Each predicate takes
// one argument, the tenant ID.
const (
	deliveryHealthColumns = `h.destination_identity,h.terminal_failures,h.last_success_at,h.last_failure_at,h.last_terminal_at,h.last_error_code,h.last_error_fingerprint`
	tenantHealthSQL       = `h.destination_identity LIKE 'managed:%' AND EXISTS (SELECT 1 FROM managed_notifications AS m WHERE m.id=substr(h.destination_identity,9) AND m.tenant_id=?)`
	defaultHealthSQL      = `(h.destination_identity NOT LIKE 'managed:%' OR EXISTS (SELECT 1 FROM managed_notifications AS m WHERE m.id=substr(h.destination_identity,9) AND m.tenant_id=?))`
	pendingOutboxColumns  = `o.destination,COUNT(*),COALESCE(SUM(CASE WHEN o.attempts > 0 THEN 1 ELSE 0 END),0),COALESCE(SUM(o.deferrals),0)`
	tenantPendingSQL      = `o.destination LIKE 'managed:%' AND EXISTS (SELECT 1 FROM managed_notifications AS m WHERE o.destination LIKE 'managed:' || m.id || ':%' AND m.tenant_id=? AND m.enabled=1)`
	defaultPendingSQL     = `(o.destination NOT LIKE 'managed:%' OR EXISTS (SELECT 1 FROM managed_notifications AS m WHERE o.destination LIKE 'managed:' || m.id || ':%' AND m.tenant_id=? AND m.enabled=1))`
)

// The platform's delivery health is that of its own destinations, the
// managed destinations without a tenant, and of their deliveries, which
// carry no tenant either. The predicates take no argument.
const (
	platformHealthSQL  = `h.destination_identity LIKE 'managed:%' AND EXISTS (SELECT 1 FROM managed_notifications AS m WHERE m.id=substr(h.destination_identity,9) AND m.tenant_id IS NULL)`
	platformPendingSQL = `o.tenant_id IS NULL AND o.destination LIKE 'managed:%' AND EXISTS (SELECT 1 FROM managed_notifications AS m WHERE o.destination LIKE 'managed:' || m.id || ':%' AND m.tenant_id IS NULL AND m.enabled=1)`
)

// ListDeliveryHealth returns the durable outcome metadata of the tenant's
// destinations merged with their current unsent outbox counts. It never
// reads notification payloads or credentials. The health of another
// tenant's destinations or of the platform's is never returned.
func (ts *TenantStore) ListDeliveryHealth(ctx context.Context) (map[string]DeliveryHealth, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	healthQuery := `SELECT ` + deliveryHealthColumns + ` FROM notification_delivery_health AS h WHERE ` + tenantHealthSQL
	outboxQuery := `SELECT ` + pendingOutboxColumns + ` FROM outbox AS o WHERE o.sent_at IS NULL AND o.terminal_at='' AND o.attempts < ? AND ` + tenantPendingSQL + ` GROUP BY o.destination`
	if ts.scope.id == DefaultTenantID {
		healthQuery = `SELECT ` + deliveryHealthColumns + ` FROM notification_delivery_health AS h WHERE ` + defaultHealthSQL
		outboxQuery = `SELECT ` + pendingOutboxColumns + ` FROM outbox AS o WHERE o.sent_at IS NULL AND o.terminal_at='' AND o.attempts < ? AND ` + defaultPendingSQL + ` GROUP BY o.destination`
	}
	return listDeliveryHealth(ctx, ts.store.reader(), healthQuery, []any{ts.scope.id}, outboxQuery, []any{deliveryMaxAttempts, ts.scope.id})
}

// ListDeliveryHealth returns the delivery health of the platform's own
// destinations, as TenantStore.ListDeliveryHealth does for a tenant's: the
// durable outcome metadata merged with the current unsent outbox counts,
// without notification payloads or credentials. The health of a tenant's
// destinations and of the deployment destinations, which belong to the
// default tenant, is never returned.
func (ps *PlatformStore) ListDeliveryHealth(ctx context.Context) (map[string]DeliveryHealth, error) {
	healthQuery := `SELECT ` + deliveryHealthColumns + ` FROM notification_delivery_health AS h WHERE ` + platformHealthSQL
	outboxQuery := `SELECT ` + pendingOutboxColumns + ` FROM outbox AS o WHERE o.sent_at IS NULL AND o.terminal_at='' AND o.attempts < ? AND ` + platformPendingSQL + ` GROUP BY o.destination`
	return listDeliveryHealth(ctx, ps.store.reader(), healthQuery, nil, outboxQuery, []any{deliveryMaxAttempts})
}

// listDeliveryHealth runs one owner's health query, which selects
// deliveryHealthColumns, and outbox query, which selects
// pendingOutboxColumns, and merges their rows by destination identity.
func listDeliveryHealth(ctx context.Context, reader *sql.DB, healthQuery string, healthArgs []any, outboxQuery string, outboxArgs []any) (map[string]DeliveryHealth, error) {
	out := map[string]DeliveryHealth{}
	rows, err := reader.QueryContext(ctx, healthQuery, healthArgs...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var item DeliveryHealth
		var success, failure, terminal string
		if err := rows.Scan(&item.DestinationIdentity, &item.TerminalFailures, &success, &failure, &terminal, &item.LastErrorCode, &item.LastErrorFingerprint); err != nil {
			rows.Close()
			return nil, err
		}
		item.LastSuccessAt = scanTime(success)
		item.LastFailureAt = scanTime(failure)
		item.LastTerminalAt = scanTime(terminal)
		out[item.DestinationIdentity] = item
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	rows, err = reader.QueryContext(ctx, outboxQuery, outboxArgs...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var selector string
		var pending, retrying, deferrals int
		if err := rows.Scan(&selector, &pending, &retrying, &deferrals); err != nil {
			rows.Close()
			return nil, err
		}
		identity := deliveryIdentity(selector)
		item := out[identity]
		item.DestinationIdentity = identity
		item.Pending += pending
		item.Retrying += retrying
		item.Deferrals += deferrals
		out[identity] = item
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	return out, rows.Close()
}
