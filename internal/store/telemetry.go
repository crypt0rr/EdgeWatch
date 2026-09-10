package store

import (
	"context"
	"math"
	"time"
)

// DeploymentTelemetry is a bounded, point-in-time summary of the data held by
// an EdgeWatch deployment. It contains aggregate counters and SQLite's
// allocated page size only; scan and event payloads are never decoded.
type DeploymentTelemetry struct {
	CollectedAt      time.Time `json:"collected_at"`
	DatabaseBytes    int64     `json:"database_bytes"`
	Jobs             int64     `json:"jobs"`
	Scans            int64     `json:"scans"`
	HostObservations int64     `json:"host_observations"`
	EffectiveHosts   int64     `json:"effective_hosts"`
	Events           int64     `json:"events"`
	ScanCycles       int64     `json:"scan_cycles"`
	OutboxPending    int64     `json:"outbox_pending"`
	OutboxRetrying   int64     `json:"outbox_retrying"`
	OutboxFailed     int64     `json:"outbox_failed"`
}

// DeploymentTelemetry returns inexpensive aggregate counters for the current
// deployment. Callers should cache this value because retained-history counts
// can become expensive on very large installations. No JSON snapshot is read.
func (s *Store) DeploymentTelemetry(ctx context.Context) (DeploymentTelemetry, error) {
	var telemetry DeploymentTelemetry
	reader := s.reader()
	if err := reader.QueryRowContext(ctx, `SELECT
		COALESCE((SELECT COUNT(*) FROM jobs),0),
		COALESCE((SELECT COUNT(*) FROM scans),0),
		COALESCE((SELECT COUNT(*) FROM scan_hosts),0),
		COALESCE((SELECT COUNT(*) FROM latest_scan_hosts),0),
		COALESCE((SELECT COUNT(*) FROM events),0),
		COALESCE((SELECT COUNT(*) FROM scan_cycles),0),
		COALESCE((SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL),0),
		COALESCE((SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL AND attempts > 0 AND attempts < ?),0),
		COALESCE((SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL AND attempts >= ?),0)`, deliveryMaxAttempts, deliveryMaxAttempts).
		Scan(&telemetry.Jobs, &telemetry.Scans, &telemetry.HostObservations, &telemetry.EffectiveHosts, &telemetry.Events, &telemetry.ScanCycles, &telemetry.OutboxPending, &telemetry.OutboxRetrying, &telemetry.OutboxFailed); err != nil {
		return DeploymentTelemetry{}, err
	}
	var pageCount, pageSize int64
	if err := reader.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pageCount); err != nil {
		return DeploymentTelemetry{}, err
	}
	if err := reader.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil {
		return DeploymentTelemetry{}, err
	}
	if pageCount > 0 && pageSize > 0 {
		if pageCount > math.MaxInt64/pageSize {
			telemetry.DatabaseBytes = math.MaxInt64
		} else {
			telemetry.DatabaseBytes = pageCount * pageSize
		}
	}
	telemetry.CollectedAt = time.Now().UTC()
	return telemetry, nil
}
