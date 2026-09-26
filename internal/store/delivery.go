package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/google/uuid"
)

func emptyState() model.JobState { s := model.JobState{}; ensureMaps(&s); return s }
func ensureMaps(s *model.JobState) {
	if s.Pending == nil {
		s.Pending = map[string]model.Pending{}
	}
	if s.Incidents == nil {
		s.Incidents = map[string]model.Incident{}
	}
	if s.Suppressed == nil {
		s.Suppressed = map[string]int{}
	}
	if s.SuppressedChanges == nil {
		s.SuppressedChanges = map[string]model.Change{}
	}
	if s.FingerprintCandidates == nil {
		s.FingerprintCandidates = map[string]model.ValueCount{}
	}
}

// UpdateState changes a config.yaml job's state through
// SystemStore.UpdateState, until its callers use Store.System themselves.
func (s *Store) UpdateState(ctx context.Context, job string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	return s.System().UpdateState(ctx, job, fn)
}

// UpdateState applies fn to the stored state of the config.yaml job with the
// given name and records the events it returns, in one transaction. Those
// jobs keep their state in job_states, and their events belong to the
// default tenant.
func (ss *SystemStore) UpdateState(ctx context.Context, job string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	tx, err := ss.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var raw []byte
	state := emptyState()
	err = tx.QueryRowContext(ctx, `SELECT state_json FROM job_states WHERE job=?`, job).Scan(&raw)
	if err == nil {
		if err = json.Unmarshal(raw, &state); err != nil {
			return nil, err
		}
		ensureMaps(&state)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	events, err := fn(&state)
	if err != nil {
		return nil, err
	}
	raw, err = json.Marshal(state)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO job_states(job,state_json,updated_at) VALUES(?,?,?) ON CONFLICT(job) DO UPDATE SET state_json=excluded.state_json,updated_at=excluded.updated_at`, job, raw, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	for i := range events {
		bounded, payload, marshalErr := model.MarshalBoundedEvent(events[i], model.EventPayloadLimit)
		if marshalErr != nil {
			return nil, marshalErr
		}
		events[i] = bounded
		event := events[i]
		tenantSQL, tenantArgs := eventTenantSQL(event)
		if _, err = tx.ExecContext(ctx, `INSERT INTO events(type,job,scan_id,payload_json,created_at,tenant_id) VALUES(?,?,?,?,?,`+tenantSQL+`)`, append([]any{event.Type, event.Job, event.ScanID, payload, sqliteTimestamp(event.CreatedAt)}, tenantArgs...)...); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

// QueueEvent queues a delivery through SystemStore.QueueEvent, until its
// callers use Store.System themselves.
func (s *Store) QueueEvent(ctx context.Context, destination string, event model.Event) error {
	return s.System().QueueEvent(ctx, destination, event)
}

// QueueEvent queues the delivery of an event to one destination. The
// delivery belongs to the tenant of the event's job, or to the platform for
// an event without a job.
func (ss *SystemStore) QueueEvent(ctx context.Context, destination string, event model.Event) error {
	_, b, err := model.MarshalBoundedEvent(event, model.EventPayloadLimit)
	if err != nil {
		return err
	}
	tx, err := ss.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if strings.HasPrefix(destination, "managed:") {
		key, reason, resolveErr := resolveManagedIntentTx(ctx, tx, destination, event)
		if resolveErr != nil {
			return resolveErr
		}
		if key == "" {
			var discarded managedIntentDiscards
			discarded.add(destination, reason, 1)
			if err := discarded.audit(ctx, tx); err != nil {
				return err
			}
			return tx.Commit()
		}
		destination = key
	}
	now := time.Now().UTC()
	// A delivery belongs to the tenant of its event.
	tenantSQL, tenantArgs := eventTenantSQL(event)
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO outbox(destination,payload_json,next_at,tenant_id) VALUES(?,?,?,`+tenantSQL+`)`, append([]any{destination, b, now.Format(time.RFC3339Nano)}, tenantArgs...)...)
	if err != nil {
		return err
	}
	if inserted, _ := result.RowsAffected(); inserted == 1 {
		if err := ensureDeliveryHealthTx(ctx, tx, destination, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type Delivery struct {
	ID          int64
	Destination string
	Event       model.Event
	Attempts    int
	Deferrals   int
	ClaimToken  string
	// TenantID is the tenant whose event the delivery carries, or "" for a
	// platform delivery such as an update alert, so the delivery worker can
	// resolve the destination in the tenant that queued it.
	TenantID string
}

// DueDeliveries claims due deliveries through SystemStore.DueDeliveries,
// until its callers use Store.System themselves.
func (s *Store) DueDeliveries(ctx context.Context, limit int) ([]Delivery, error) {
	return s.System().DueDeliveries(ctx, limit)
}

// DueDeliveries claims up to limit due deliveries for a new owner.
func (ss *SystemStore) DueDeliveries(ctx context.Context, limit int) ([]Delivery, error) {
	return ss.ClaimDueDeliveries(ctx, limit, uuid.NewString())
}

var ErrDeliveryClaimLost = errors.New("notification delivery claim was lost")

// Delivery errors are stable, redacted categories shared by the notifier and
// store. Keeping them in the store package avoids an import cycle while still
// allowing health accounting and retry policy to use errors.Is rather than
// matching provider error text.
var (
	ErrDeliveryDestinationLocked  = errors.New("notification destination is locked")
	ErrDeliveryDestinationMissing = errors.New("notification destination is missing")
	ErrDeliveryProvider           = errors.New("notification provider failed")
	ErrDeliveryProviderPanic      = errors.New("notification provider panicked")
	ErrDeliveryIndeterminate      = errors.New("notification send outcome is indeterminate")
	ErrDeliveryWorkerPanic        = errors.New("notification delivery worker panicked")
)

const (
	deliveryClaimLease       = 30 * time.Minute
	deliveryMaxAttempts      = 8
	deliveryMaxDeferrals     = 8
	deliveryInitialDelay     = 2 * time.Minute
	deliveryMaxDelay         = time.Hour
	deliveryLockedDelay      = time.Hour
	deliveryMaintenanceBatch = 256
)

// heldDeliverySQL holds back the outbox row aliased "due" while its tenant is
// not active. A disabled tenant is paused: its alerts wait in the outbox,
// with their retry and deferral budgets untouched, until the tenant is
// enabled again. A platform delivery, such as an update alert, has no tenant
// and is never held.
const heldDeliverySQL = `(due.tenant_id IS NULL OR EXISTS (SELECT 1 FROM tenants WHERE tenants.id=due.tenant_id AND tenants.state='` + TenantStateActive + `'))`

// ClaimDueDeliveries claims due deliveries through
// SystemStore.ClaimDueDeliveries, until its callers use Store.System
// themselves.
func (s *Store) ClaimDueDeliveries(ctx context.Context, limit int, owner string) ([]Delivery, error) {
	return s.System().ClaimDueDeliveries(ctx, limit, owner)
}

// ClaimDueDeliveries atomically leases due outbox rows to one drain owner.
// Expired claims can be recovered by a later process, while active claims are
// invisible to concurrent drains until the owner records a result. The rows
// of a tenant that is not active are held, as heldDeliverySQL describes.
func (ss *SystemStore) ClaimDueDeliveries(ctx context.Context, limit int, owner string) ([]Delivery, error) {
	return ss.claimDueDeliveries(ctx, limit, owner, nil)
}

// ClaimDueDeliveriesExcluding claims due deliveries through
// SystemStore.ClaimDueDeliveriesExcluding, until its callers use
// Store.System themselves.
func (s *Store) ClaimDueDeliveriesExcluding(ctx context.Context, limit int, owner string, excluded []string) ([]Delivery, error) {
	return s.System().ClaimDueDeliveriesExcluding(ctx, limit, owner, excluded)
}

// ClaimDueDeliveriesExcluding leases due outbox rows while skipping the
// supplied destination identities. The notifier uses this for destinations
// whose credentials are currently unavailable so one locked backlog cannot
// occupy every delivery slot needed by healthy destinations. The rows of a
// tenant that is not active are held, as in ClaimDueDeliveries.
func (ss *SystemStore) ClaimDueDeliveriesExcluding(ctx context.Context, limit int, owner string, excluded []string) ([]Delivery, error) {
	return ss.claimDueDeliveries(ctx, limit, owner, excluded)
}

// AgeLockedDeliveries ages locked deliveries through
// SystemStore.AgeLockedDeliveries, until its callers use Store.System
// themselves.
func (s *Store) AgeLockedDeliveries(ctx context.Context, destinations []string) error {
	return s.System().AgeLockedDeliveries(ctx, destinations)
}

// AgeLockedDeliveries advances the separate deferral budget for outbox rows
// belonging to managed destinations whose encryption key is currently
// unavailable. The notifier excludes those rows from normal claims, so they
// need an explicit, durable aging path or they would remain pending forever.
// Aging is performed only when a row is due and is bounded to one maintenance
// batch. It never consumes a provider-attempt budget; restoring the key before
// the final deferral leaves the row claimable again. The held rows of a
// tenant that is not active do not age, so a paused tenant's alerts are not
// dropped while it is paused.
func (ss *SystemStore) AgeLockedDeliveries(ctx context.Context, destinations []string) error {
	if len(destinations) == 0 {
		return nil
	}
	unique := make([]string, 0, len(destinations))
	seen := make(map[string]struct{}, len(destinations))
	for _, destination := range destinations {
		destination = strings.TrimSpace(destination)
		if destination == "" {
			continue
		}
		if _, ok := seen[destination]; ok {
			continue
		}
		seen[destination] = struct{}{}
		unique = append(unique, destination)
	}
	if len(unique) == 0 {
		return nil
	}
	placeholders := make([]string, len(unique))
	for i := range unique {
		placeholders[i] = "?"
	}
	now := time.Now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	query := `SELECT id,destination,deferrals FROM outbox AS due
WHERE sent_at IS NULL AND terminal_at='' AND next_at<=?
  AND attempts<? AND deferrals<?
  AND (claim_token='' OR claim_until='' OR claim_until<=?)
  AND ` + heldDeliverySQL + `
  AND destination IN (` + strings.Join(placeholders, ",") + `)
ORDER BY id LIMIT ?`
	// The first timestamp is the due cutoff and the last timestamp before the
	// destination list is the claim-expiry cutoff.
	args := []any{nowText, deliveryMaxAttempts, deliveryMaxDeferrals, nowText}
	for _, destination := range unique {
		args = append(args, destination)
	}
	args = append(args, deliveryMaintenanceBatch)
	tx, err := ss.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	type lockedDelivery struct {
		id          int64
		destination string
		deferrals   int
	}
	var pending []lockedDelivery
	for rows.Next() {
		var item lockedDelivery
		if err := rows.Scan(&item.id, &item.destination, &item.deferrals); err != nil {
			return err
		}
		pending = append(pending, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, item := range pending {
		deferrals := item.deferrals + 1
		terminal := deferrals >= deliveryMaxDeferrals
		terminalAt := ""
		if terminal {
			terminalAt = nowText
		}
		result, err := tx.ExecContext(ctx, `UPDATE outbox SET deferrals=?,next_at=?,last_error=?,terminal_at=?,claim_token='',claim_until=''
WHERE id=? AND sent_at IS NULL AND terminal_at='' AND attempts<? AND deferrals=?
  AND (claim_token='' OR claim_until='' OR claim_until<=?)`, deferrals, now.Add(deliveryLockedDelay).Format(time.RFC3339Nano), deliveryErrorCode(ErrDeliveryDestinationLocked), terminalAt, item.id, deliveryMaxAttempts, item.deferrals, nowText)
		if err != nil {
			return err
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			// A concurrent drain may have claimed or completed this row after
			// the bounded selection. Leave that owner in charge.
			continue
		}
		if err := recordDeliveryFailureTx(ctx, tx, item.destination, ErrDeliveryDestinationLocked, terminal, now); err != nil {
			return err
		}
		if terminal {
			if err := insertTerminalDeliveryEventTx(ctx, tx, item.id, item.destination, ErrDeliveryDestinationLocked, "locked destination grace period", now); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// WakeLockedDeliveries wakes locked deliveries through
// SystemStore.WakeLockedDeliveries, until its callers use Store.System
// themselves.
func (s *Store) WakeLockedDeliveries(ctx context.Context, destinations []string) error {
	return s.System().WakeLockedDeliveries(ctx, destinations)
}

// WakeLockedDeliveries makes rows immediately due when a previously locked
// managed destination becomes usable again. Locked aging uses a one-hour
// cadence to avoid touching the same rows on every worker tick; clearing that
// delay on recovery prevents an otherwise healthy destination from waiting
// for the next aging interval before it can drain.
func (ss *SystemStore) WakeLockedDeliveries(ctx context.Context, destinations []string) error {
	if len(destinations) == 0 {
		return nil
	}
	unique := make([]string, 0, len(destinations))
	seen := make(map[string]struct{}, len(destinations))
	for _, destination := range destinations {
		destination = strings.TrimSpace(destination)
		if destination == "" {
			continue
		}
		if _, ok := seen[destination]; ok {
			continue
		}
		seen[destination] = struct{}{}
		unique = append(unique, destination)
	}
	if len(unique) == 0 {
		return nil
	}
	placeholders := make([]string, len(unique))
	args := make([]any, 0, len(unique)+3)
	now := time.Now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	for i, destination := range unique {
		placeholders[i] = "?"
		args = append(args, destination)
	}
	query := `UPDATE outbox SET next_at=?
WHERE sent_at IS NULL AND terminal_at='' AND last_error='destination_locked'
  AND (claim_token='' OR claim_until='' OR claim_until<=?)
  AND destination IN (` + strings.Join(placeholders, ",") + `)`
	args = append([]any{nowText, nowText}, args...)
	_, err := ss.store.DB.ExecContext(ctx, query, args...)
	return err
}

func (ss *SystemStore) claimDueDeliveries(ctx context.Context, limit int, owner string, excluded []string) ([]Delivery, error) {
	if limit < 1 {
		return nil, nil
	}
	if owner == "" {
		owner = uuid.NewString()
	}
	now := time.Now().UTC()
	query := `UPDATE outbox SET claim_token=?,claim_until=? WHERE id IN (SELECT id FROM outbox AS due WHERE sent_at IS NULL AND terminal_at='' AND attempts < ? AND next_at <= ? AND (claim_token='' OR claim_until='' OR claim_until <= ?) AND ` + heldDeliverySQL
	args := []any{owner, now.Add(deliveryClaimLease).Format(time.RFC3339Nano), deliveryMaxAttempts, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)}
	if len(excluded) > 0 {
		placeholders := make([]string, 0, len(excluded))
		for _, destination := range excluded {
			if strings.TrimSpace(destination) == "" {
				continue
			}
			placeholders = append(placeholders, "?")
			args = append(args, destination)
		}
		if len(placeholders) > 0 {
			query += " AND destination NOT IN (" + strings.Join(placeholders, ",") + ")"
		}
	}
	query += ` ORDER BY id LIMIT ?) RETURNING id,destination,payload_json,attempts,deferrals,claim_token,COALESCE(tenant_id,'')`
	args = append(args, limit)
	rows, err := ss.store.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Delivery
	for rows.Next() {
		var d Delivery
		var b []byte
		if err := rows.Scan(&d.ID, &d.Destination, &b, &d.Attempts, &d.Deferrals, &d.ClaimToken, &d.TenantID); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &d.Event); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ReleaseDeliveryClaims clears the outbox leases through
// SystemStore.ReleaseDeliveryClaims, until the daemon uses Store.System
// itself.
func (s *Store) ReleaseDeliveryClaims(ctx context.Context) (int64, error) {
	return s.System().ReleaseDeliveryClaims(ctx)
}

// ReleaseDeliveryClaims clears all active outbox leases. It is used when a
// daemon starts (or shuts down cleanly) so rows claimed by a previous process
// do not remain unavailable for the full claim lease. Delivery attempts and
// next-at timestamps are intentionally preserved; only ownership is reset.
func (ss *SystemStore) ReleaseDeliveryClaims(ctx context.Context) (int64, error) {
	result, err := ss.store.DB.ExecContext(ctx, `UPDATE outbox SET claim_token='',claim_until='' WHERE sent_at IS NULL AND claim_token<>''`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ReleaseDeliveryClaim releases one delivery claim through
// SystemStore.ReleaseDeliveryClaim, until its callers use Store.System
// themselves.
func (s *Store) ReleaseDeliveryClaim(ctx context.Context, id int64, claim string, delay time.Duration) error {
	return s.System().ReleaseDeliveryClaim(ctx, id, claim, delay)
}

// ReleaseDeliveryClaim returns one in-flight delivery to the due queue without
// recording a provider attempt or a destination deferral. It is used when the
// delivery pass is cancelled (for example during a clean daemon shutdown), so
// lifecycle interruptions cannot exhaust the retry budgets reserved for real
// provider failures. A positive delay is useful when the provider outcome is
// indeterminate and an immediate retry could duplicate an accepted request.
func (ss *SystemStore) ReleaseDeliveryClaim(ctx context.Context, id int64, claim string, delay time.Duration) error {
	if claim == "" {
		return ErrDeliveryClaimLost
	}
	if delay < 0 {
		delay = 0
	}
	nextAt := time.Now().UTC()
	if delay > 0 {
		nextAt = nextAt.Add(delay)
	}
	result, err := ss.store.DB.ExecContext(ctx, `UPDATE outbox SET next_at=?,claim_token='',claim_until='' WHERE id=? AND sent_at IS NULL AND terminal_at='' AND claim_token=?`, nextAt.Format(time.RFC3339Nano), id, claim)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrDeliveryClaimLost
	}
	return nil
}

// DeliveryResult records a delivery result through
// SystemStore.DeliveryResult, until its callers use Store.System themselves.
func (s *Store) DeliveryResult(ctx context.Context, id int64, sendErr error) error {
	return s.System().DeliveryResult(ctx, id, sendErr)
}

// DeliveryResult records the result for the current claim. It retains the
// original API used by CLI/tests by looking up the row's active claim token.
func (ss *SystemStore) DeliveryResult(ctx context.Context, id int64, sendErr error) error {
	var claim string
	if err := ss.store.reader().QueryRowContext(ctx, `SELECT claim_token FROM outbox WHERE id=?`, id).Scan(&claim); err != nil {
		return err
	}
	return ss.DeliveryResultClaim(ctx, id, claim, sendErr)
}

// DeliveryResultClaim records a delivery result through
// SystemStore.DeliveryResultClaim, until its callers use Store.System
// themselves.
func (s *Store) DeliveryResultClaim(ctx context.Context, id int64, claim string, sendErr error) error {
	return s.System().DeliveryResultClaim(ctx, id, claim, sendErr)
}

// DeliveryResultClaim records the outcome of the claimed delivery: sent, or
// a failure that is retried later or ends the delivery for good.
func (ss *SystemStore) DeliveryResultClaim(ctx context.Context, id int64, claim string, sendErr error) error {
	if claim == "" {
		return ErrDeliveryClaimLost
	}
	tx, err := ss.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var attempts, deferrals int
	var destination string
	if err := tx.QueryRowContext(ctx, `SELECT attempts,deferrals,destination FROM outbox WHERE id=? AND sent_at IS NULL AND claim_token=?`, id, claim).Scan(&attempts, &deferrals, &destination); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeliveryClaimLost
		}
		return err
	}
	now := time.Now().UTC()
	if sendErr == nil {
		result, err := tx.ExecContext(ctx, `UPDATE outbox SET sent_at=?,last_error='',claim_token='',claim_until='' WHERE id=? AND sent_at IS NULL AND claim_token=?`, now.Format(time.RFC3339Nano), id, claim)
		if err != nil {
			return err
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return ErrDeliveryClaimLost
		}
		if err := recordDeliverySuccessTx(ctx, tx, destination, now); err != nil {
			return err
		}
		return tx.Commit()
	}
	// A transport timeout or cancellation after bytes may have left the
	// provider in an unknown state. Treat it as a durable deferral, not a
	// provider attempt: the request may already have been accepted and retrying
	// against the ordinary attempt budget could both duplicate the notification
	// and exhaust retries while the daemon is repeatedly restarted.
	if errors.Is(sendErr, ErrDeliveryIndeterminate) {
		deferrals++
		terminal := deferrals >= deliveryMaxDeferrals
		terminalAt := ""
		if terminal {
			terminalAt = now.Format(time.RFC3339Nano)
		}
		result, err := tx.ExecContext(ctx, `UPDATE outbox SET deferrals=?,next_at=?,last_error=?,terminal_at=?,claim_token='',claim_until='' WHERE id=? AND sent_at IS NULL AND claim_token=?`, deferrals, now.Add(deliveryInitialDelay).Format(time.RFC3339Nano), deliveryErrorCode(sendErr), terminalAt, id, claim)
		if err != nil {
			return err
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return ErrDeliveryClaimLost
		}
		if err := recordDeliveryFailureTx(ctx, tx, destination, sendErr, terminal, now); err != nil {
			return err
		}
		if terminal {
			if err := insertTerminalDeliveryEventTx(ctx, tx, id, destination, sendErr, "indeterminate deferral limit", now); err != nil {
				return err
			}
		}
		return tx.Commit()
	}
	attempts++
	terminal := attempts >= deliveryMaxAttempts
	delay := deliveryRetryDelay(attempts)
	terminalAt := ""
	if terminal {
		terminalAt = now.Format(time.RFC3339Nano)
	}
	result, err := tx.ExecContext(ctx, `UPDATE outbox SET attempts=?,next_at=?,last_error=?,terminal_at=?,claim_token='',claim_until='' WHERE id=? AND sent_at IS NULL AND claim_token=?`, attempts, now.Add(delay).Format(time.RFC3339Nano), deliveryErrorCode(sendErr), terminalAt, id, claim)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrDeliveryClaimLost
	}
	if err := recordDeliveryFailureTx(ctx, tx, destination, sendErr, terminal, now); err != nil {
		return err
	}
	if terminal {
		if err := insertTerminalDeliveryEventTx(ctx, tx, id, destination, sendErr, "retry limit", now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// insertTerminalDeliveryEventTx records that the outbox row outboxID was
// dropped. The event belongs to the tenant of the dropped delivery.
func insertTerminalDeliveryEventTx(ctx context.Context, tx *sql.Tx, outboxID int64, destination string, sendErr error, reason string, now time.Time) error {
	fingerprint := deliveryErrorFingerprint(sendErr)
	event := model.Event{Type: "notification-delivery-terminal", Message: fmt.Sprintf("Notification delivery dropped after %s (destination fingerprint %s; error code %s; error fingerprint %s)", reason, deliverySelectorFingerprint(destination), deliveryErrorCode(sendErr), fingerprint), CreatedAt: now}
	bounded, payload, err := model.MarshalBoundedEvent(event, model.EventPayloadLimit)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO events(type,job,scan_id,payload_json,created_at,tenant_id) VALUES(?,?,?,?,?,(SELECT tenant_id FROM outbox WHERE id=?))`, bounded.Type, "", "", payload, sqliteTimestamp(now), outboxID)
	return err
}

func deliveryRetryDelay(attempts int) time.Duration {
	if attempts < 1 {
		return deliveryInitialDelay
	}
	shift := attempts - 1
	if shift > 6 {
		shift = 6
	}
	delay := deliveryInitialDelay * time.Duration(1<<shift)
	if delay > deliveryMaxDelay {
		return deliveryMaxDelay
	}
	return delay
}

// DeferDelivery defers a delivery through SystemStore.DeferDelivery, until
// its callers use Store.System themselves.
func (s *Store) DeferDelivery(ctx context.Context, id int64, claim, reason string, delay time.Duration) error {
	return s.System().DeferDelivery(ctx, id, claim, reason, delay)
}

// DeferDelivery releases a claim without consuming an attempt. This is used
// when an encrypted managed destination is temporarily locked or unavailable.
func (ss *SystemStore) DeferDelivery(ctx context.Context, id int64, claim, reason string, delay time.Duration) error {
	return ss.DeferDeliveryWithError(ctx, id, claim, legacyDeliveryError(reason), delay)
}

// legacyDeliveryError preserves the source-compatible string-based defer API
// without making the durable classifier depend on arbitrary provider text.
// New notifier paths pass the typed sentinels directly.
func legacyDeliveryError(reason string) error {
	lower := strings.ToLower(strings.TrimSpace(reason))
	switch {
	case strings.Contains(lower, "locked") || strings.Contains(lower, "key unavailable"):
		return fmt.Errorf("%w: delivery deferred", ErrDeliveryDestinationLocked)
	case strings.Contains(lower, "no longer configured") || strings.Contains(lower, "not configured"):
		return fmt.Errorf("%w: delivery deferred", ErrDeliveryDestinationMissing)
	case strings.Contains(lower, "indeterminate"):
		return ErrDeliveryIndeterminate
	default:
		return errors.New("notification delivery deferred")
	}
}

// DeferDeliveryWithError defers a delivery through
// SystemStore.DeferDeliveryWithError, until its callers use Store.System
// themselves.
func (s *Store) DeferDeliveryWithError(ctx context.Context, id int64, claim string, reason error, delay time.Duration) error {
	return s.System().DeferDeliveryWithError(ctx, id, claim, reason, delay)
}

// DeferDeliveryWithError releases a claim without consuming an ordinary
// provider attempt. Deferrals are nevertheless bounded: after repeated
// deferrals the row becomes terminal, is reflected in destination health, and
// receives one redacted event so a locked or indeterminate destination cannot
// remain silently pending forever.
func (ss *SystemStore) DeferDeliveryWithError(ctx context.Context, id int64, claim string, reason error, delay time.Duration) error {
	if claim == "" {
		return ErrDeliveryClaimLost
	}
	if delay < time.Minute {
		delay = time.Minute
	}
	tx, err := ss.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var attempts, deferrals int
	var destination, terminalAt string
	if err := tx.QueryRowContext(ctx, `SELECT attempts,deferrals,destination,terminal_at FROM outbox WHERE id=? AND sent_at IS NULL AND claim_token=?`, id, claim).Scan(&attempts, &deferrals, &destination, &terminalAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeliveryClaimLost
		}
		return err
	}
	if terminalAt != "" {
		return ErrDeliveryClaimLost
	}
	deferrals++
	now := time.Now().UTC()
	terminal := deferrals >= deliveryMaxDeferrals
	terminalStamp := ""
	if terminal {
		terminalStamp = now.Format(time.RFC3339Nano)
	}
	result, err := tx.ExecContext(ctx, `UPDATE outbox SET deferrals=?,next_at=?,last_error=?,terminal_at=?,claim_token='',claim_until='' WHERE id=? AND sent_at IS NULL AND claim_token=?`, deferrals, now.Add(delay).Format(time.RFC3339Nano), deliveryErrorCode(reason), terminalStamp, id, claim)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrDeliveryClaimLost
	}
	if err := recordDeliveryFailureTx(ctx, tx, destination, reason, terminal, now); err != nil {
		return err
	}
	if terminal {
		if err := insertTerminalDeliveryEventTx(ctx, tx, id, destination, reason, "deferral limit", now); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func truncate(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}

// PruneStats reports rows removed by one retention pass. Security audit rows
// are intentionally absent: they are an accountability record and are kept
// indefinitely unless an operator explicitly removes the database.
