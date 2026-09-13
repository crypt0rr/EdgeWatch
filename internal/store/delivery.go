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

func (s *Store) UpdateState(ctx context.Context, job string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
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
		if _, err = tx.ExecContext(ctx, `INSERT INTO events(type,job,scan_id,payload_json,created_at) VALUES(?,?,?,?,?)`, event.Type, event.Job, event.ScanID, payload, event.CreatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

func (s *Store) QueueEvent(ctx context.Context, destination string, event model.Event) error {
	_, b, err := model.MarshalBoundedEvent(event, model.EventPayloadLimit)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if strings.HasPrefix(destination, "managed:") {
		valid, validationErr := managedDestinationCurrentTx(ctx, tx, destination)
		if validationErr != nil {
			return validationErr
		}
		if !valid {
			return tx.Commit()
		}
	}
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO outbox(destination,payload_json,next_at) VALUES(?,?,?)`, destination, b, now.Format(time.RFC3339Nano))
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
}

func (s *Store) DueDeliveries(ctx context.Context, limit int) ([]Delivery, error) {
	return s.ClaimDueDeliveries(ctx, limit, uuid.NewString())
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
	deliveryClaimLease   = 30 * time.Minute
	deliveryMaxAttempts  = 8
	deliveryMaxDeferrals = 8
	deliveryInitialDelay = 2 * time.Minute
	deliveryMaxDelay     = time.Hour
)

// ClaimDueDeliveries atomically leases due outbox rows to one drain owner.
// Expired claims can be recovered by a later process, while active claims are
// invisible to concurrent drains until the owner records a result.
func (s *Store) ClaimDueDeliveries(ctx context.Context, limit int, owner string) ([]Delivery, error) {
	return s.claimDueDeliveries(ctx, limit, owner, nil)
}

// ClaimDueDeliveriesExcluding leases due outbox rows while skipping the
// supplied destination identities. The notifier uses this for destinations
// whose credentials are currently unavailable so one locked backlog cannot
// occupy every delivery slot needed by healthy destinations.
func (s *Store) ClaimDueDeliveriesExcluding(ctx context.Context, limit int, owner string, excluded []string) ([]Delivery, error) {
	return s.claimDueDeliveries(ctx, limit, owner, excluded)
}

func (s *Store) claimDueDeliveries(ctx context.Context, limit int, owner string, excluded []string) ([]Delivery, error) {
	if limit < 1 {
		return nil, nil
	}
	if owner == "" {
		owner = uuid.NewString()
	}
	now := time.Now().UTC()
	query := `UPDATE outbox SET claim_token=?,claim_until=? WHERE id IN (SELECT id FROM outbox WHERE sent_at IS NULL AND terminal_at='' AND attempts < ? AND next_at <= ? AND (claim_token='' OR claim_until='' OR claim_until <= ?)`
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
	query += ` ORDER BY id LIMIT ?) RETURNING id,destination,payload_json,attempts,deferrals,claim_token`
	args = append(args, limit)
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Delivery
	for rows.Next() {
		var d Delivery
		var b []byte
		if err := rows.Scan(&d.ID, &d.Destination, &b, &d.Attempts, &d.Deferrals, &d.ClaimToken); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &d.Event); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ReleaseDeliveryClaims clears all active outbox leases. It is used when a
// daemon starts (or shuts down cleanly) so rows claimed by a previous process
// do not remain unavailable for the full claim lease. Delivery attempts and
// next-at timestamps are intentionally preserved; only ownership is reset.
func (s *Store) ReleaseDeliveryClaims(ctx context.Context) (int64, error) {
	result, err := s.DB.ExecContext(ctx, `UPDATE outbox SET claim_token='',claim_until='' WHERE sent_at IS NULL AND claim_token<>''`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ReleaseDeliveryClaim returns one in-flight delivery to the due queue without
// recording a provider attempt or a destination deferral. It is used when the
// delivery pass is cancelled (for example during a clean daemon shutdown), so
// lifecycle interruptions cannot exhaust the retry budgets reserved for real
// provider failures. A positive delay is useful when the provider outcome is
// indeterminate and an immediate retry could duplicate an accepted request.
func (s *Store) ReleaseDeliveryClaim(ctx context.Context, id int64, claim string, delay time.Duration) error {
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
	result, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=?,claim_token='',claim_until='' WHERE id=? AND sent_at IS NULL AND terminal_at='' AND claim_token=?`, nextAt.Format(time.RFC3339Nano), id, claim)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrDeliveryClaimLost
	}
	return nil
}

// DeliveryResult records the result for the current claim. It retains the
// original API used by CLI/tests by looking up the row's active claim token.
func (s *Store) DeliveryResult(ctx context.Context, id int64, sendErr error) error {
	var claim string
	if err := s.reader().QueryRowContext(ctx, `SELECT claim_token FROM outbox WHERE id=?`, id).Scan(&claim); err != nil {
		return err
	}
	return s.DeliveryResultClaim(ctx, id, claim, sendErr)
}

func (s *Store) DeliveryResultClaim(ctx context.Context, id int64, claim string, sendErr error) error {
	if claim == "" {
		return ErrDeliveryClaimLost
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var attempts int
	var destination string
	if err := tx.QueryRowContext(ctx, `SELECT attempts,destination FROM outbox WHERE id=? AND sent_at IS NULL AND claim_token=?`, id, claim).Scan(&attempts, &destination); err != nil {
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
		if err := insertTerminalDeliveryEventTx(ctx, tx, destination, sendErr, "retry limit", now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func insertTerminalDeliveryEventTx(ctx context.Context, tx *sql.Tx, destination string, sendErr error, reason string, now time.Time) error {
	fingerprint := deliveryErrorFingerprint(sendErr)
	event := model.Event{Type: "notification-delivery-terminal", Message: fmt.Sprintf("Notification delivery dropped after %s (destination fingerprint %s; error code %s; error fingerprint %s)", reason, deliverySelectorFingerprint(destination), deliveryErrorCode(sendErr), fingerprint), CreatedAt: now}
	bounded, payload, err := model.MarshalBoundedEvent(event, model.EventPayloadLimit)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO events(type,job,scan_id,payload_json,created_at) VALUES(?,?,?,?,?)`, bounded.Type, "", "", payload, now.Format(time.RFC3339Nano))
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

// DeferDelivery releases a claim without consuming an attempt. This is used
// when an encrypted managed destination is temporarily locked or unavailable.
func (s *Store) DeferDelivery(ctx context.Context, id int64, claim, reason string, delay time.Duration) error {
	return s.DeferDeliveryWithError(ctx, id, claim, legacyDeliveryError(reason), delay)
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
func (s *Store) DeferDeliveryWithError(ctx context.Context, id int64, claim string, reason error, delay time.Duration) error {
	if claim == "" {
		return ErrDeliveryClaimLost
	}
	if delay < time.Minute {
		delay = time.Minute
	}
	tx, err := s.DB.BeginTx(ctx, nil)
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
		if err := insertTerminalDeliveryEventTx(ctx, tx, destination, reason, "deferral limit", now); err != nil {
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
