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

// QueueEvent queues the delivery of an event to one destination. The
// delivery belongs to the tenant of the event's job, or to the platform for
// an event without a job.
func (ss *SystemStore) QueueEvent(ctx context.Context, destination string, event model.Event) error {
	tx, err := beginWriteTx(ctx, ss.store.DB)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	if event.CreatedAt.IsZero() {
		event.CreatedAt = now
	}
	if event.JobID != "" {
		var purging int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM job_history_purges WHERE job_id=?)`, event.JobID).Scan(&purging); err != nil {
			return err
		}
		if purging != 0 {
			return fmt.Errorf("%w: job %s", ErrNotFound, event.JobID)
		}
	}
	if strings.HasPrefix(destination, "managed:") {
		key, reason, resolveErr := resolveManagedIntentTx(ctx, tx, destination, event)
		if resolveErr != nil {
			return resolveErr
		}
		if key == "" {
			var discarded managedIntentDiscards
			discarded.add(event, destination, reason, 1)
			if err := discarded.audit(ctx, tx); err != nil {
				return err
			}
			return tx.Commit()
		}
		destination = key
	}
	// A delivery belongs to the tenant of its event.
	tenantSQL, tenantArgs := eventTenantSQL(event)
	windowID := ""
	if changeWindowEventType(event.Type) && event.JobID != "" {
		tenantID, tenantErr := eventTenantIDTx(ctx, tx, event, "")
		if tenantErr != nil {
			return tenantErr
		}
		var active bool
		windowID, active, _, err = windowForQueuedChangeTx(ctx, tx, event.JobID, tenantID, now)
		if err != nil {
			return err
		}
		if active {
			if err := recordChangeWindowEventTx(ctx, tx, windowID, tenantID, event); err != nil {
				return err
			}
		}
	}
	_, b, err := model.MarshalBoundedEvent(event, model.EventPayloadLimit)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO outbox(destination,payload_json,next_at,tenant_id,event_type,event_job_id,change_window_id) VALUES(?,?,?,`+tenantSQL+`,?,?,?)`, append([]any{destination, b, now.Format(time.RFC3339Nano)}, append(tenantArgs, event.Type, event.JobID, windowID)...)...)
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

// DueDeliveries claims up to limit due deliveries for a new owner.
func (ss *SystemStore) DueDeliveries(ctx context.Context, limit int) ([]Delivery, error) {
	return ss.ClaimDueDeliveries(ctx, limit, uuid.NewString())
}

var ErrDeliveryClaimLost = errors.New("notification delivery claim was lost")

// ErrDeliveryHeld reports that a claimed delivery belongs to a tenant that is
// no longer active, so it must wait in the outbox instead of being sent.
var ErrDeliveryHeld = errors.New("notification delivery is held")

// Delivery errors are stable, redacted categories shared by the notifier and
// store. Keeping them in the store package avoids an import cycle while still
// allowing health accounting and retry policy to use errors.Is rather than
// matching provider error text.
var (
	ErrDeliveryDestinationLocked  = errors.New("notification destination is locked")
	ErrDeliveryDestinationMissing = errors.New("notification destination is missing")
	// ErrDeliveryDestinationExcluded reports a unit's destination whose host
	// is an address that the deployment's target policy refuses.
	ErrDeliveryDestinationExcluded = errors.New("notification destination address is not allowed")
	ErrDeliveryProvider            = errors.New("notification provider failed")
	ErrDeliveryProviderPanic       = errors.New("notification provider panicked")
	ErrDeliveryIndeterminate       = errors.New("notification send outcome is indeterminate")
	// ErrDeliveryProviderTimeout reports a provider that did not answer
	// within its timeout. It is indeterminate, because the provider may have
	// accepted the message, but it is the provider's failure, not the
	// daemon's: it is retried as a provider attempt, no sooner than a claim
	// lease later, so a provider outage that shows up as hangs keeps the
	// alert for the whole retry schedule.
	ErrDeliveryProviderTimeout = fmt.Errorf("%w: the provider did not answer in time", ErrDeliveryIndeterminate)
	ErrDeliveryWorkerPanic     = errors.New("notification delivery worker panicked")
	ErrDeliveryPayloadInvalid  = errors.New("notification delivery payload is invalid")
)

const (
	deliveryClaimLease = 30 * time.Minute
	// Fifteen attempts with exponential backoff capped at twelve hours keep a
	// queued alert retryable for a little over three days, covering long
	// overnight and weekend provider outages without retaining it indefinitely.
	deliveryMaxAttempts      = 15
	deliveryMaxDeferrals     = 8
	deliveryInitialDelay     = 2 * time.Minute
	deliveryMaxDelay         = 12 * time.Hour
	deliveryLockedDelay      = time.Hour
	deliveryMaintenanceBatch = 256
)

// heldDeliverySQL holds back the outbox row aliased "due" while its tenant is
// not active. A disabled tenant is paused: its alerts wait in the outbox,
// with their retry and deferral budgets untouched, until the tenant is
// enabled again. A platform delivery, such as an update alert, has no tenant
// and is never held.
const heldDeliverySQL = `(due.tenant_id IS NULL OR EXISTS (SELECT 1 FROM tenants WHERE tenants.id=due.tenant_id AND tenants.state='` + TenantStateActive + `'))
AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=due.tenant_id AND purge.job_id=CASE WHEN json_valid(CAST(due.payload_json AS TEXT)) THEN COALESCE(json_extract(CAST(due.payload_json AS TEXT),'$.job_id'),'') ELSE '' END)`

// changeWindowDeliverySQL keeps a pending change alert out of a claim while
// its associated window has started but the close transaction has not yet
// committed. The caller supplies the time after it acquired the writer.
const changeWindowDeliverySQL = `(due.change_window_id='' OR NOT EXISTS (
 SELECT 1 FROM change_windows AS quiet
 WHERE quiet.id=due.change_window_id AND quiet.closed_at='' AND quiet.start_at<=?
)) AND due.coalesced_at='' AND due.coalesce_after_attempt=0 AND due.attempt_started_at=''`

// ClaimDueDeliveries atomically leases due outbox rows to one drain owner.
// Expired claims can be recovered by a later process, while active claims are
// invisible to concurrent drains until the owner records a result. The rows
// of a tenant that is not active are held, as heldDeliverySQL describes.
func (ss *SystemStore) ClaimDueDeliveries(ctx context.Context, limit int, owner string) ([]Delivery, error) {
	return ss.claimDueDeliveries(ctx, limit, owner, nil)
}

// ClaimDueDeliveriesExcluding leases due outbox rows while skipping the
// supplied destination identities. The notifier uses this for destinations
// whose credentials are currently unavailable so one locked backlog cannot
// occupy every delivery slot needed by healthy destinations. The rows of a
// tenant that is not active are held, as in ClaimDueDeliveries.
func (ss *SystemStore) ClaimDueDeliveriesExcluding(ctx context.Context, limit int, owner string, excluded []string) ([]Delivery, error) {
	return ss.claimDueDeliveries(ctx, limit, owner, excluded)
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
	tx, err := beginWriteTx(ctx, ss.store.DB)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	nowText := sqliteTimestamp(now)
	windowNowText := sqliteTimestamp(now)
	query := `SELECT id,destination,deferrals FROM outbox AS due
WHERE sent_at IS NULL AND terminal_at='' AND next_at<=?
  AND attempts<? AND deferrals<?
  AND (claim_token='' OR claim_until='' OR claim_until<=?)
  AND ` + heldDeliverySQL + `
  AND ` + changeWindowDeliverySQL + `
  AND destination IN (` + strings.Join(placeholders, ",") + `)
ORDER BY id LIMIT ?`
	// The first timestamp is the due cutoff and the last timestamp before the
	// destination list is the claim-expiry cutoff.
	args := []any{nowText, deliveryMaxAttempts, deliveryMaxDeferrals, nowText, windowNowText}
	for _, destination := range unique {
		args = append(args, destination)
	}
	args = append(args, deliveryMaintenanceBatch)
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
		result, err := applyOutboxTransition(ctx, tx, outboxAgeLocked,
			`id=? AND sent_at IS NULL AND terminal_at='' AND attempts<? AND deferrals=? AND (claim_token='' OR claim_until='' OR claim_until<=?)`,
			[]any{item.id, deliveryMaxAttempts, item.deferrals, nowText},
			outboxChange("deferrals", outboxSet, "?", deferrals),
			outboxChange("next_at", outboxSet, "?", now.Add(deliveryLockedDelay).Format(time.RFC3339Nano)),
			outboxChange("last_error", outboxSet, "?", deliveryErrorCode(ErrDeliveryDestinationLocked)),
			outboxChange("terminal_at", outboxSet, "?", terminalAt),
			outboxChange("claim_token", outboxReset, "''"),
			outboxChange("claim_until", outboxReset, "''"),
		)
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
	where := `sent_at IS NULL AND terminal_at='' AND last_error='destination_locked' AND (claim_token='' OR claim_until='' OR claim_until<=?) AND destination IN (` + strings.Join(placeholders, ",") + `)`
	whereArgs := append([]any{nowText}, args...)
	query, queryArgs, err := buildOutboxTransitionStatement(outboxWakeLocked, where, whereArgs,
		outboxChange("next_at", outboxSet, "?", nowText),
	)
	if err != nil {
		return err
	}
	_, err = ss.store.DB.ExecContext(ctx, query, queryArgs...)
	return err
}

func (ss *SystemStore) claimDueDeliveries(ctx context.Context, limit int, owner string, excluded []string) ([]Delivery, error) {
	if limit < 1 {
		return nil, nil
	}
	if owner == "" {
		owner = uuid.NewString()
	}
	tx, err := beginWriteTx(ctx, ss.store.DB)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	// Sample after taking the writer so a concurrent window start/expiry and
	// this claim have one deterministic SQLite transaction order.
	now := time.Now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	windowNowText := sqliteTimestamp(now)
	where := `id IN (SELECT id FROM outbox AS due WHERE sent_at IS NULL AND terminal_at='' AND attempts < ? AND next_at <= ? AND (claim_token='' OR claim_until='' OR claim_until <= ?) AND ` + heldDeliverySQL + ` AND ` + changeWindowDeliverySQL
	whereArgs := []any{deliveryMaxAttempts, nowText, nowText, windowNowText}
	if len(excluded) > 0 {
		placeholders := make([]string, 0, len(excluded))
		for _, destination := range excluded {
			if strings.TrimSpace(destination) == "" {
				continue
			}
			placeholders = append(placeholders, "?")
			whereArgs = append(whereArgs, destination)
		}
		if len(placeholders) > 0 {
			where += " AND destination NOT IN (" + strings.Join(placeholders, ",") + ")"
		}
	}
	where += ` ORDER BY id LIMIT ?)`
	whereArgs = append(whereArgs, limit)
	query, args, err := buildOutboxTransitionStatement(outboxClaimDue, where, whereArgs,
		outboxChange("claim_token", outboxSet, "?", owner),
		outboxChange("claim_until", outboxSet, "?", now.Add(deliveryClaimLease).Format(time.RFC3339Nano)),
	)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, query+` RETURNING id,destination,payload_json,attempts,deferrals,claim_token,COALESCE(tenant_id,'')`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type claimedPayload struct {
		delivery Delivery
		payload  []byte
	}
	var claimed []claimedPayload
	for rows.Next() {
		var item claimedPayload
		if err := rows.Scan(&item.delivery.ID, &item.delivery.Destination, &item.payload, &item.delivery.Attempts, &item.delivery.Deferrals, &item.delivery.ClaimToken, &item.delivery.TenantID); err != nil {
			return nil, err
		}
		claimed = append(claimed, item)
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	if rowsErr != nil {
		return nil, rowsErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	var out []Delivery
	for _, item := range claimed {
		if err := json.Unmarshal(item.payload, &item.delivery.Event); err != nil {
			if markErr := ss.failInvalidDeliveryPayload(ctx, item.delivery.ID, item.delivery.ClaimToken); markErr != nil {
				return nil, fmt.Errorf("mark invalid notification payload terminal: %w", markErr)
			}
			continue
		}
		out = append(out, item.delivery)
	}
	return out, nil
}

// failInvalidDeliveryPayload dead-letters one undecodable row after the claim
// cursor has closed. Other rows in the same claim batch remain available to
// the caller, and a corrupt row does not occupy its lease until expiry.
func (ss *SystemStore) failInvalidDeliveryPayload(ctx context.Context, id int64, claim string) error {
	if claim == "" {
		return ErrDeliveryClaimLost
	}
	tx, err := ss.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var destination string
	if err := tx.QueryRowContext(ctx, `SELECT destination FROM outbox WHERE id=? AND sent_at IS NULL AND terminal_at='' AND claim_token=?`, id, claim).Scan(&destination); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeliveryClaimLost
		}
		return err
	}
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	result, err := applyOutboxTransition(ctx, tx, outboxInvalidPayload,
		`id=? AND sent_at IS NULL AND terminal_at='' AND claim_token=?`, []any{id, claim},
		outboxChange("terminal_at", outboxSet, "?", stamp),
		outboxChange("last_error", outboxSet, "'payload_invalid'"),
		outboxChange("claim_token", outboxReset, "''"),
		outboxChange("claim_until", outboxReset, "''"),
	)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrDeliveryClaimLost
	}
	if err := recordDeliveryFailureTx(ctx, tx, destination, ErrDeliveryPayloadInvalid, true, now); err != nil {
		return err
	}
	if err := insertTerminalDeliveryEventTx(ctx, tx, id, destination, ErrDeliveryPayloadInvalid, "invalid payload", now); err != nil {
		return err
	}
	return tx.Commit()
}

// ReleaseDeliveryClaims clears all active outbox leases. It is used when a
// daemon starts (or shuts down cleanly) so rows claimed by a previous process
// do not remain unavailable for the full claim lease. Attempt markers for a
// future scheduled window are cleared so the alert is retryable before the
// window starts; a started attempt in an active window remains unknown until
// that window closes.
func (ss *SystemStore) ReleaseDeliveryClaims(ctx context.Context) (int64, error) {
	tx, err := beginWriteTx(ctx, ss.store.DB)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	var released int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL AND claim_token<>''`).Scan(&released); err != nil {
		return 0, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,claim_token,change_window_id,event_type,coalesce_after_attempt,COALESCE(tenant_id,'') FROM outbox WHERE sent_at IS NULL AND terminal_at='' AND coalesced_at='' AND attempt_started_at<>'' ORDER BY id`)
	if err != nil {
		return 0, err
	}
	type startedDelivery struct {
		id            int64
		claim         string
		windowID      string
		eventType     string
		coalesceAfter int
		tenantID      string
	}
	var started []startedDelivery
	for rows.Next() {
		var item startedDelivery
		if err := rows.Scan(&item.id, &item.claim, &item.windowID, &item.eventType, &item.coalesceAfter, &item.tenantID); err != nil {
			_ = rows.Close()
			return 0, err
		}
		started = append(started, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for _, item := range started {
		if err := recoverStartedDeliveryTx(ctx, tx, item.id, item.claim, item.windowID, item.eventType, item.coalesceAfter, item.tenantID, now, nowText, outboxRecoverStartup, ""); err != nil {
			return 0, err
		}
	}
	if _, err := applyOutboxTransition(ctx, tx, outboxReleaseStartup,
		`sent_at IS NULL AND claim_token<>''`, nil,
		outboxChange("claim_token", outboxReset, "''"),
		outboxChange("claim_until", outboxReset, "''"),
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return released, nil
}

// RecoverExpiredDeliveryClaims recovers a bounded page of deliveries whose
// provider invocation marker outlived its lease. Change alerts linked to a
// future window may retry after recovery; an active window keeps the marker
// for its close summary. A dangling nonempty window link is an invariant error;
// the transaction rolls back instead of recovering a row without its policy.
func (ss *SystemStore) RecoverExpiredDeliveryClaims(ctx context.Context) (int64, error) {
	tx, err := beginWriteTx(ctx, ss.store.DB)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	expired, err := expiredDeliveryClaimsTx(ctx, tx, nowText)
	if err != nil {
		return 0, err
	}
	for _, item := range expired {
		if err := recoverStartedDeliveryTx(ctx, tx, item.id, item.claim, item.windowID, item.eventType, item.coalesceAfter, item.tenantID, now, nowText, outboxRecoverExpired, `AND claim_until<>'' AND claim_until<=?`); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int64(len(expired)), nil
}

type expiredDeliveryClaim struct {
	id            int64
	claim         string
	windowID      string
	eventType     string
	coalesceAfter int
	tenantID      string
}

func expiredDeliveryClaimsTx(ctx context.Context, tx *sql.Tx, nowText string) ([]expiredDeliveryClaim, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,claim_token,change_window_id,event_type,coalesce_after_attempt,COALESCE(tenant_id,'') FROM outbox WHERE sent_at IS NULL AND terminal_at='' AND coalesced_at='' AND attempt_started_at<>'' AND claim_token<>'' AND claim_until<>'' AND claim_until<=? ORDER BY id LIMIT ?`, nowText, deliveryMaintenanceBatch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var expired []expiredDeliveryClaim
	for rows.Next() {
		var item expiredDeliveryClaim
		if err := rows.Scan(&item.id, &item.claim, &item.windowID, &item.eventType, &item.coalesceAfter, &item.tenantID); err != nil {
			return nil, err
		}
		expired = append(expired, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return expired, nil
}

func recoverStartedDeliveryTx(ctx context.Context, tx *sql.Tx, id int64, claim, windowID, eventType string, coalesceAfter int, tenantID string, now time.Time, nowText string, transition outboxTransitionName, extraFence string) error {
	clearMarker := true
	coalesce := false
	var startRaw, closedAt string
	if windowID != "" {
		err := tx.QueryRowContext(ctx, `SELECT quiet.start_at,quiet.closed_at FROM change_windows AS quiet JOIN jobs AS j ON j.id=quiet.job_id WHERE quiet.id=? AND j.tenant_id=?`, windowID, tenantID).Scan(&startRaw, &closedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("outbox delivery %d references missing linked change window %q: %w", id, windowID, err)
		}
		if err != nil {
			return err
		}
	}
	if changeWindowEventType(eventType) {
		if windowID == "" {
			coalesce = coalesceAfter != 0
		} else {
			switch {
			case closedAt != "":
				coalesce = true
			case now.Before(scanTime(startRaw)):
				// Ordinary pre-start attempts must be retryable before the
				// window. A credential rotation explicitly prevents retrying
				// against the new destination, so retain that uncertain handoff
				// for the scheduled window's review and coalesce it at close.
				clearMarker = coalesceAfter == 0
			default:
				// An active (or overdue but not yet closed) window preserves the
				// provider-outcome uncertainty until its close summary commits.
				clearMarker = false
			}
		}
	}
	changes := []outboxColumnChange{
		outboxChange("claim_token", outboxReset, "''"),
		outboxChange("claim_until", outboxReset, "''"),
		outboxChange("attempt_started_at", outboxConditional, "CASE WHEN ? THEN '' ELSE attempt_started_at END", clearMarker),
		outboxChange("coalesced_at", outboxConditional, "CASE WHEN ? THEN CASE WHEN coalesced_at='' THEN ? ELSE coalesced_at END ELSE coalesced_at END", coalesce, sqliteTimestamp(now)),
		outboxChange("last_error", outboxConditional, "CASE WHEN ? THEN '' ELSE last_error END", coalesce),
	}
	where := `id=? AND claim_token=? AND attempt_started_at<>'' ` + extraFence
	args := []any{id, claim}
	if extraFence != "" {
		args = append(args, nowText)
	}
	result, err := applyOutboxTransition(ctx, tx, transition, where, args, changes...)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrDeliveryClaimLost
	}
	return nil
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
	result, err := applyOutboxTransition(ctx, ss.store.DB, outboxReleaseClaim,
		`id=? AND sent_at IS NULL AND terminal_at='' AND claim_token=?`, []any{id, claim},
		outboxChange("next_at", outboxSet, "?", nextAt.Format(time.RFC3339Nano)),
		outboxChange("claim_token", outboxReset, "''"),
		outboxChange("claim_until", outboxReset, "''"),
		outboxChange("attempt_started_at", outboxReset, "''"),
	)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrDeliveryClaimLost
	}
	return nil
}

// CheckDeliveryClaim reports whether a claimed delivery may still be sent,
// just before a worker sends it. A pass claims a batch at once, and a
// delivery can wait for a worker while the database changes. The error is
// ErrDeliveryClaimLost when the claim is gone: the delivery was discarded by
// a credential change or a deletion, ended, or claimed again. It is
// ErrDeliveryHeld when the delivery's tenant is no longer active, as
// heldDeliverySQL describes; the caller then releases the claim, and the
// delivery waits until the tenant is enabled again.
func (ss *SystemStore) CheckDeliveryClaim(ctx context.Context, id int64, claim string) error {
	if claim == "" {
		return ErrDeliveryClaimLost
	}
	var sendable bool
	err := ss.store.reader().QueryRowContext(ctx, `SELECT `+heldDeliverySQL+` FROM outbox AS due WHERE due.id=? AND due.claim_token=? AND due.sent_at IS NULL AND due.terminal_at=''`, id, claim).Scan(&sendable)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrDeliveryClaimLost
	case err != nil:
		return err
	case !sendable:
		return ErrDeliveryHeld
	}
	return nil
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

// DeliveryResultClaim records the outcome of the claimed delivery: sent, or
// a failure that is retried later or ends the delivery for good.
func (ss *SystemStore) DeliveryResultClaim(ctx context.Context, id int64, claim string, sendErr error) error {
	if claim == "" {
		return ErrDeliveryClaimLost
	}
	tx, err := beginWriteTx(ctx, ss.store.DB)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var attempts, deferrals, coalesceAfter int
	var destination, windowID, eventType, jobID, tenantID string
	var payload []byte
	if err := tx.QueryRowContext(ctx, `SELECT attempts,deferrals,destination,change_window_id,event_type,event_job_id,payload_json,coalesce_after_attempt,COALESCE(tenant_id,'') FROM outbox WHERE id=? AND sent_at IS NULL AND terminal_at='' AND claim_token=?`, id, claim).Scan(&attempts, &deferrals, &destination, &windowID, &eventType, &jobID, &payload, &coalesceAfter, &tenantID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeliveryClaimLost
		}
		return err
	}
	now := time.Now().UTC()
	if windowID != "" {
		var linkedWindowID string
		if err := tx.QueryRowContext(ctx, `SELECT quiet.id FROM change_windows AS quiet JOIN jobs AS j ON j.id=quiet.job_id WHERE quiet.id=? AND j.tenant_id=?`, windowID, tenantID).Scan(&linkedWindowID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("outbox delivery %d references missing linked change window %q: %w", id, windowID, err)
			}
			return err
		}
	}
	if changeWindowEventType(eventType) {
		if coalesceAfter != 0 {
			if sendErr == nil {
				result, err := applyOutboxTransition(ctx, tx, outboxCompleteCoalesced,
					`id=? AND sent_at IS NULL AND claim_token=?`, []any{id, claim},
					outboxChange("sent_at", outboxSet, "?", now.Format(time.RFC3339Nano)),
					outboxChange("last_error", outboxReset, "''"),
					outboxChange("claim_token", outboxReset, "''"),
					outboxChange("claim_until", outboxReset, "''"),
					outboxChange("attempt_started_at", outboxReset, "''"),
					outboxChange("coalesce_after_attempt", outboxReset, "0"),
				)
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
			if _, err := applyOutboxTransition(ctx, tx, outboxCoalesceCompleted,
				`id=? AND sent_at IS NULL AND claim_token=?`, []any{id, claim},
				outboxChange("coalesced_at", outboxSet, "?", sqliteTimestamp(now)),
				outboxChange("last_error", outboxReset, "''"),
				outboxChange("claim_token", outboxReset, "''"),
				outboxChange("claim_until", outboxReset, "''"),
				outboxChange("attempt_started_at", outboxReset, "''"),
				outboxChange("coalesce_after_attempt", outboxReset, "0"),
			); err != nil {
				return err
			}
			return tx.Commit()
		}
		if windowID != "" {
			var endRaw, closedAt string
			err := tx.QueryRowContext(ctx, `SELECT quiet.end_at,quiet.closed_at FROM change_windows AS quiet JOIN jobs AS j ON j.id=quiet.job_id WHERE quiet.id=? AND j.tenant_id=?`, windowID, tenantID).Scan(&endRaw, &closedAt)
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("outbox delivery %d references missing linked change window %q: %w", id, windowID, err)
			}
			if err != nil {
				return err
			}
			if closedAt == "" && !now.Before(scanTime(endRaw)) {
				var event model.Event
				if json.Unmarshal(payload, &event) == nil {
					if event.JobID == "" {
						event.JobID = jobID
					}
					if err := recordChangeWindowEventTx(ctx, tx, windowID, tenantID, event); err != nil {
						return err
					}
				}
				if _, err := applyOutboxTransition(ctx, tx, outboxHoldClosedWindow,
					`id=? AND sent_at IS NULL AND claim_token=?`, []any{id, claim},
					outboxChange("next_at", outboxSet, "?", scanTime(endRaw).Format(time.RFC3339Nano)),
					outboxChange("last_error", outboxReset, "''"),
					outboxChange("claim_token", outboxReset, "''"),
					outboxChange("claim_until", outboxReset, "''"),
					outboxChange("attempt_started_at", outboxReset, "''"),
				); err != nil {
					return err
				}
				return tx.Commit()
			}
		}
	}
	if sendErr == nil {
		result, err := applyOutboxTransition(ctx, tx, outboxCompleteSent,
			`id=? AND sent_at IS NULL AND claim_token=?`, []any{id, claim},
			outboxChange("sent_at", outboxSet, "?", now.Format(time.RFC3339Nano)),
			outboxChange("last_error", outboxReset, "''"),
			outboxChange("claim_token", outboxReset, "''"),
			outboxChange("claim_until", outboxReset, "''"),
			outboxChange("attempt_started_at", outboxReset, "''"),
		)
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
	// A cancellation after bytes may have left the provider in an unknown
	// state. Treat it as a durable deferral, not a provider attempt: the
	// request may already have been accepted and retrying against the
	// ordinary attempt budget could both duplicate the notification and
	// exhaust retries while the daemon is repeatedly restarted. A provider
	// that did not answer in time is the provider's failure and an attempt.
	if errors.Is(sendErr, ErrDeliveryIndeterminate) && !errors.Is(sendErr, ErrDeliveryProviderTimeout) {
		deferrals++
		terminal := deferrals >= deliveryMaxDeferrals
		terminalAt := ""
		if terminal {
			terminalAt = now.Format(time.RFC3339Nano)
		}
		result, err := applyOutboxTransition(ctx, tx, outboxDeferIndeterminate,
			`id=? AND sent_at IS NULL AND claim_token=?`, []any{id, claim},
			outboxChange("deferrals", outboxSet, "?", deferrals),
			outboxChange("next_at", outboxSet, "?", now.Add(deliveryInitialDelay).Format(time.RFC3339Nano)),
			outboxChange("last_error", outboxSet, "?", deliveryErrorCode(sendErr)),
			outboxChange("terminal_at", outboxSet, "?", terminalAt),
			outboxChange("claim_token", outboxReset, "''"),
			outboxChange("claim_until", outboxReset, "''"),
			outboxChange("attempt_started_at", outboxReset, "''"),
		)
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
	if errors.Is(sendErr, ErrDeliveryProviderTimeout) && delay < deliveryClaimLease {
		// The provider may have accepted the message without answering, so
		// it is not sent again sooner than an indeterminate send would be.
		delay = deliveryClaimLease
	}
	terminalAt := ""
	if terminal {
		terminalAt = now.Format(time.RFC3339Nano)
	}
	result, err := applyOutboxTransition(ctx, tx, outboxRecordSendFailure,
		`id=? AND sent_at IS NULL AND claim_token=?`, []any{id, claim},
		outboxChange("attempts", outboxSet, "?", attempts),
		outboxChange("next_at", outboxSet, "?", now.Add(delay).Format(time.RFC3339Nano)),
		outboxChange("last_error", outboxSet, "?", deliveryErrorCode(sendErr)),
		outboxChange("terminal_at", outboxSet, "?", terminalAt),
		outboxChange("claim_token", outboxReset, "''"),
		outboxChange("claim_until", outboxReset, "''"),
		outboxChange("attempt_started_at", outboxReset, "''"),
	)
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
	if err != nil {
		return err
	}
	noteFailedDeliveryTx(ctx, tx, outboxID, now)
	return nil
}

func deliveryRetryDelay(attempts int) time.Duration {
	if attempts < 1 {
		return deliveryInitialDelay
	}
	delay := deliveryInitialDelay
	for retry := 1; retry < attempts && delay < deliveryMaxDelay; retry++ {
		if delay > deliveryMaxDelay/2 {
			return deliveryMaxDelay
		}
		delay *= 2
	}
	return delay
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
	tx, err := beginWriteTx(ctx, ss.store.DB)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var attempts, deferrals, coalesceAfter int
	var destination, terminalAt, eventType string
	if err := tx.QueryRowContext(ctx, `SELECT attempts,deferrals,destination,terminal_at,event_type,coalesce_after_attempt FROM outbox WHERE id=? AND sent_at IS NULL AND claim_token=?`, id, claim).Scan(&attempts, &deferrals, &destination, &terminalAt, &eventType, &coalesceAfter); err != nil {
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
	if changeWindowEventType(eventType) && coalesceAfter != 0 {
		if _, err := applyOutboxTransition(ctx, tx, outboxCoalesceDeferred,
			`id=? AND sent_at IS NULL AND claim_token=?`, []any{id, claim},
			outboxChange("coalesced_at", outboxSet, "?", sqliteTimestamp(now)),
			outboxChange("last_error", outboxReset, "''"),
			outboxChange("claim_token", outboxReset, "''"),
			outboxChange("claim_until", outboxReset, "''"),
			outboxChange("attempt_started_at", outboxReset, "''"),
			outboxChange("coalesce_after_attempt", outboxReset, "0"),
		); err != nil {
			return err
		}
		// Closing a planned window forbids retries and destination-health
		// penalties even when cancellation grace expires without an outcome.
		return tx.Commit()
	}
	terminal := deferrals >= deliveryMaxDeferrals
	terminalStamp := ""
	if terminal {
		terminalStamp = now.Format(time.RFC3339Nano)
	}
	result, err := applyOutboxTransition(ctx, tx, outboxDeferIndeterminate,
		`id=? AND sent_at IS NULL AND claim_token=?`, []any{id, claim},
		outboxChange("deferrals", outboxSet, "?", deferrals),
		outboxChange("next_at", outboxSet, "?", now.Add(delay).Format(time.RFC3339Nano)),
		outboxChange("last_error", outboxSet, "?", deliveryErrorCode(reason)),
		outboxChange("terminal_at", outboxSet, "?", terminalStamp),
		outboxChange("claim_token", outboxReset, "''"),
		outboxChange("claim_until", outboxReset, "''"),
		outboxChange("attempt_started_at", outboxReset, "''"),
	)
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
