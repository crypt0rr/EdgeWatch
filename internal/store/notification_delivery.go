package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// DeliveryHealth is the redacted operational state for one notification
// destination. Destination identity is an internal stable selector; callers
// should join it to a named destination before returning it over HTTP.
type DeliveryHealth struct {
	DestinationIdentity  string
	Pending              int
	Retrying             int
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
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "locked") || strings.Contains(lower, "key unavailable"):
		return "destination_locked"
	case strings.Contains(lower, "no longer configured") || strings.Contains(lower, "not configured"):
		return "destination_missing"
	default:
		return "delivery_failed"
	}
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

// ListDeliveryHealth returns durable outcome metadata merged with the current
// unsent outbox counts. It never reads notification payloads or credentials.
func (s *Store) ListDeliveryHealth(ctx context.Context) (map[string]DeliveryHealth, error) {
	out := map[string]DeliveryHealth{}
	rows, err := s.DB.QueryContext(ctx, `SELECT destination_identity,terminal_failures,last_success_at,last_failure_at,last_terminal_at,last_error_code,last_error_fingerprint FROM notification_delivery_health`)
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

	rows, err = s.DB.QueryContext(ctx, `SELECT destination,COUNT(*),COALESCE(SUM(CASE WHEN attempts > 0 THEN 1 ELSE 0 END),0)
FROM outbox WHERE sent_at IS NULL AND attempts < ? GROUP BY destination`, deliveryMaxAttempts)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var selector string
		var pending, retrying int
		if err := rows.Scan(&selector, &pending, &retrying); err != nil {
			rows.Close()
			return nil, err
		}
		identity := deliveryIdentity(selector)
		item := out[identity]
		item.DestinationIdentity = identity
		item.Pending += pending
		item.Retrying += retrying
		out[identity] = item
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	return out, rows.Close()
}
