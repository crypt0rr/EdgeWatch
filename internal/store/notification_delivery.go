package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
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

// deliveryErrorCodes are the codes that deliveryErrorCode returns for a
// failure.
var deliveryErrorCodes = []string{"canceled", "timeout", "destination_locked", "destination_missing", "destination_excluded", "provider_panic", "worker_panic", "payload_invalid", "provider_timeout", "delivery_indeterminate", "delivery_failed"}

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
	case errors.Is(err, ErrDeliveryDestinationExcluded):
		return "destination_excluded"
	case errors.Is(err, ErrDeliveryProviderPanic):
		return "provider_panic"
	case errors.Is(err, ErrDeliveryWorkerPanic):
		return "worker_panic"
	case errors.Is(err, ErrDeliveryPayloadInvalid):
		return "payload_invalid"
	case errors.Is(err, ErrDeliveryProviderTimeout):
		return "provider_timeout"
	case errors.Is(err, ErrDeliveryIndeterminate):
		return "delivery_indeterminate"
	case errors.Is(err, ErrDeliveryProvider):
		return "delivery_failed"
	}
	return "delivery_failed"
}

// The classes of a failed send that the notification child reports, without
// provider text: the provider's name could not be resolved, it could not be
// reached, its certificate or TLS handshake failed, it did not answer in
// time, or it answered with a failure or failed in another way.
const (
	DeliveryClassDNS      = "dns"
	DeliveryClassConnect  = "connect"
	DeliveryClassTLS      = "tls"
	DeliveryClassTimeout  = "timeout"
	DeliveryClassProvider = "provider"
)

var deliveryFailureClasses = []string{DeliveryClassDNS, DeliveryClassConnect, DeliveryClassTLS, DeliveryClassTimeout, DeliveryClassProvider}

// DeliveryFailure is a redacted send failure: one of the delivery error
// sentinels, such as ErrDeliveryProvider, and the class of the failure, one
// of the DeliveryClass names. It never holds provider text, so a provider
// that echoes a destination URL in its error cannot leak it.
type DeliveryFailure struct {
	Err   error
	Class string
}

func (f *DeliveryFailure) Error() string {
	if f.Class == "" {
		return f.Err.Error()
	}
	return f.Err.Error() + " (" + f.Class + ")"
}

func (f *DeliveryFailure) Unwrap() error { return f.Err }

// deliveryErrorClass returns the class of a DeliveryFailure in err, or ""
// when err has none.
func deliveryErrorClass(err error) string {
	var failure *DeliveryFailure
	if errors.As(err, &failure) && slices.Contains(deliveryFailureClasses, failure.Class) {
		return failure.Class
	}
	return ""
}

// deliveryErrorFingerprint identifies the kind of a failure by its error
// code and class only. Both are fixed names, so every destination that fails
// the same way has the same fingerprint, and the fingerprint reveals nothing
// about a destination: no URL, digest of one, or provider text goes into it.
func deliveryErrorFingerprint(err error) string {
	if err == nil {
		return ""
	}
	return errorKindFingerprint(deliveryErrorCode(err), deliveryErrorClass(err))
}

func errorKindFingerprint(code, class string) string {
	sum := sha256.Sum256([]byte("edgewatch delivery error\x00" + code + "\x00" + class))
	return hex.EncodeToString(sum[:])[:16]
}

// errorKindFingerprints holds every fingerprint that deliveryErrorFingerprint
// can return.
var errorKindFingerprints = sync.OnceValue(func() map[string]struct{} {
	fingerprints := map[string]struct{}{}
	for _, code := range deliveryErrorCodes {
		for _, class := range append([]string{""}, deliveryFailureClasses...) {
			fingerprints[errorKindFingerprint(code, class)] = struct{}{}
		}
	}
	return fingerprints
})

// currentErrorFingerprint returns a stored fingerprint when it is one that
// deliveryErrorFingerprint returns, and "" otherwise. Earlier releases stored
// a digest of the error text, which held a digest of the destination URL, so
// such a value is never returned.
func currentErrorFingerprint(stored string) string {
	if _, ok := errorKindFingerprints()[stored]; ok {
		return stored
	}
	return ""
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
		item.LastErrorFingerprint = currentErrorFingerprint(item.LastErrorFingerprint)
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

// TerminalDelivery is an alert that a destination dropped for good after its
// retry or deferral budget ran out. It holds the alert's metadata only:
// never its message, the destination's URL, or provider text.
type TerminalDelivery struct {
	ID int64
	// EventType, Job, and EventAt are the type, job name, and time of the
	// alert's event; Job is empty for an alert without a job.
	EventType  string
	Job        string
	EventAt    time.Time
	TerminalAt time.Time
	Attempts   int
	Deferrals  int
	ErrorCode  string
}

// MaxTerminalDeliveriesPage is the largest page that ListTerminalDeliveries
// returns.
const MaxTerminalDeliveriesPage = 100

// terminalDeliverySQL selects the deliveries, aliased o, of the managed
// destination aliased m that failed for good and were queued for its current
// credentials: an alert queued for credentials that were replaced since is
// never sent with the new ones. A delivery's selector is
// "managed:<id>:<revision>", so its revision starts after the ID.
const terminalDeliverySQL = `o.destination LIKE 'managed:' || m.id || ':%' AND o.sent_at IS NULL AND o.terminal_at<>''
  AND CAST(substr(o.destination, length(m.id)+10) AS INTEGER) >= m.credential_revision`

// ListTerminalDeliveries returns, newest first, up to limit alerts that the
// tenant's destination dropped for good and that RedeliverTerminalDeliveries
// would queue again. A positive before pages to the alerts with smaller IDs.
// A destination of another tenant or of the platform is ErrNotFound, exactly
// as an unknown ID.
func (ts *TenantStore) ListTerminalDeliveries(ctx context.Context, destinationID string, before int64, limit int) ([]TerminalDelivery, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > MaxTerminalDeliveriesPage {
		limit = MaxTerminalDeliveriesPage
	}
	reader := ts.store.reader()
	var exists int
	if err := reader.QueryRowContext(ctx, `SELECT COUNT(*) FROM managed_notifications WHERE id=? AND tenant_id=?`, destinationID, ts.scope.id).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, fmt.Errorf("%w: notification %s", ErrNotFound, destinationID)
	}
	rows, err := reader.QueryContext(ctx, `SELECT o.id,
  CASE WHEN json_valid(CAST(o.payload_json AS TEXT)) THEN COALESCE(json_extract(CAST(o.payload_json AS TEXT),'$.type'),'') ELSE '' END,
  CASE WHEN json_valid(CAST(o.payload_json AS TEXT)) THEN COALESCE(json_extract(CAST(o.payload_json AS TEXT),'$.job'),'') ELSE '' END,
  CASE WHEN json_valid(CAST(o.payload_json AS TEXT)) THEN COALESCE(json_extract(CAST(o.payload_json AS TEXT),'$.created_at'),'') ELSE '' END,
  o.terminal_at,o.attempts,o.deferrals,o.last_error
FROM outbox AS o JOIN managed_notifications AS m ON m.id=? AND m.tenant_id=?
WHERE `+terminalDeliverySQL+` AND o.tenant_id=? AND (?=0 OR o.id<?)
ORDER BY o.id DESC LIMIT ?`, destinationID, ts.scope.id, ts.scope.id, before, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	deliveries := []TerminalDelivery{}
	for rows.Next() {
		var item TerminalDelivery
		var eventAt, terminalAt string
		if err := rows.Scan(&item.ID, &item.EventType, &item.Job, &eventAt, &terminalAt, &item.Attempts, &item.Deferrals, &item.ErrorCode); err != nil {
			return nil, err
		}
		item.EventAt, item.TerminalAt = scanTime(eventAt), scanTime(terminalAt)
		deliveries = append(deliveries, item)
	}
	return deliveries, rows.Err()
}

// RedeliverTerminalDeliveries queues again the alerts that the tenant's
// destination dropped for good, as ListTerminalDeliveries lists them, or
// those of them that ids names, and returns how many it queued. Each is due
// at once with fresh retry and deferral budgets and the destination's
// current selector, so a paused or locked destination holds it as any other
// alert, and its delivery health counts one terminal failure fewer. An alert
// queued for replaced credentials, and one in restore quarantine, which is
// not in the outbox, is never queued. When it queues any, the audit entry is
// recorded in the same transaction, with a detail that has the count. A
// destination of another tenant or of the platform is ErrNotFound, and
// nothing changes.
func (ts *TenantStore) RedeliverTerminalDeliveries(ctx context.Context, destinationID string, ids []int64, audit AuditEntry) (int, error) {
	if err := ts.ready(); err != nil {
		return 0, err
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM managed_notifications WHERE id=? AND tenant_id=?`, destinationID, ts.scope.id).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("%w: notification %s", ErrNotFound, destinationID)
	}
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	query := `UPDATE outbox SET destination=?,attempts=0,deferrals=0,terminal_at='',next_at=?,last_error='',claim_token='',claim_until=''
WHERE id IN (SELECT o.id FROM outbox AS o JOIN managed_notifications AS m ON m.id=? AND m.tenant_id=? WHERE ` + terminalDeliverySQL + ` AND o.tenant_id=?`
	args := []any{managedNotificationKey(destinationID, revision), now.Format(time.RFC3339Nano), destinationID, ts.scope.id, ts.scope.id}
	if ids != nil {
		if len(ids) == 0 {
			return 0, nil
		}
		placeholders := make([]string, len(ids))
		for i, id := range ids {
			placeholders[i] = "?"
			args = append(args, id)
		}
		query += ` AND o.id IN (` + strings.Join(placeholders, ",") + `)`
	}
	result, err := tx.ExecContext(ctx, query+`)`, args...)
	if err != nil {
		return 0, err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return 0, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE notification_delivery_health SET terminal_failures=MAX(0,terminal_failures-?),updated_at=? WHERE destination_identity=?`+ownedDestinationSQL, count, now.Format(time.RFC3339Nano), "managed:"+destinationID, destinationID, ts.scope.id); err != nil {
		return 0, err
	}
	audit.Detail = fmt.Sprintf("redelivered %d failed deliveries for managed notification %s", count, destinationID)
	if err := ts.insertAuditEntries(ctx, tx, []AuditEntry{audit}, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(count), nil
}
