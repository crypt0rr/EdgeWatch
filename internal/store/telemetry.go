package store

import (
	"context"
	"database/sql"
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
// It is the platform's view: the counters cover every tenant.
func (ss *SystemStore) DeploymentTelemetry(ctx context.Context) (DeploymentTelemetry, error) {
	var telemetry DeploymentTelemetry
	reader := ss.store.reader()
	if err := reader.QueryRowContext(ctx, `SELECT
		COALESCE((SELECT COUNT(*) FROM jobs),0),
		COALESCE((SELECT COUNT(*) FROM scans),0),
		COALESCE((SELECT COUNT(*) FROM scan_hosts),0),
		COALESCE((SELECT COUNT(*) FROM latest_scan_hosts),0),
		COALESCE((SELECT COUNT(*) FROM events),0),
		COALESCE((SELECT COUNT(*) FROM scan_cycles),0),
		COALESCE((SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL),0),
		COALESCE((SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL AND terminal_at='' AND attempts > 0 AND attempts < ?),0),
		COALESCE((SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL AND (attempts >= ? OR terminal_at <> '')),0)`, deliveryMaxAttempts, deliveryMaxAttempts).
		Scan(&telemetry.Jobs, &telemetry.Scans, &telemetry.HostObservations, &telemetry.EffectiveHosts, &telemetry.Events, &telemetry.ScanCycles, &telemetry.OutboxPending, &telemetry.OutboxRetrying, &telemetry.OutboxFailed); err != nil {
		return DeploymentTelemetry{}, err
	}
	size, err := databaseBytes(ctx, reader)
	if err != nil {
		return DeploymentTelemetry{}, err
	}
	telemetry.DatabaseBytes = size
	telemetry.CollectedAt = time.Now().UTC()
	return telemetry, nil
}

// databaseBytes returns the size that SQLite has allocated for the
// database: its page count times its page size, capped at math.MaxInt64.
func databaseBytes(ctx context.Context, reader *sql.DB) (int64, error) {
	var pageCount, pageSize int64
	if err := reader.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pageCount); err != nil {
		return 0, err
	}
	if err := reader.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0, err
	}
	if pageCount <= 0 || pageSize <= 0 {
		return 0, nil
	}
	if pageCount > math.MaxInt64/pageSize {
		return math.MaxInt64, nil
	}
	return pageCount * pageSize, nil
}

// TenantTelemetry is the tenant's own share of DeploymentTelemetry: the same
// aggregate counters over the tenant's rows only. It holds numbers only, in
// the order of DeploymentTelemetry, so the default tenant's value encodes to
// the same JSON keys.
type TenantTelemetry struct {
	CollectedAt time.Time `json:"collected_at"`
	// DatabaseBytes is the size of the deployment's database. The database
	// holds every tenant's data, so only the default tenant reports it, as
	// it reports the platform's events and deliveries while it owns the
	// deployment. For another tenant it is zero and left out of the JSON.
	DatabaseBytes    int64 `json:"database_bytes,omitempty"`
	Jobs             int64 `json:"jobs"`
	Scans            int64 `json:"scans"`
	HostObservations int64 `json:"host_observations"`
	EffectiveHosts   int64 `json:"effective_hosts"`
	Events           int64 `json:"events"`
	ScanCycles       int64 `json:"scan_cycles"`
	OutboxPending    int64 `json:"outbox_pending"`
	OutboxRetrying   int64 `json:"outbox_retrying"`
	OutboxFailed     int64 `json:"outbox_failed"`
}

// Telemetry returns the tenant's aggregate counters, for the tenant's own
// console. Host observations are counted through the tenant's scans and scan
// cycles through its jobs. The default tenant's events and deliveries also
// count the platform's, which it shows in its history, and it alone reports
// the database size, so while there is one tenant the counters equal the
// deployment's. Callers should cache the value, as they cache
// DeploymentTelemetry.
func (ts *TenantStore) Telemetry(ctx context.Context) (TenantTelemetry, error) {
	if err := ts.ready(); err != nil {
		return TenantTelemetry{}, err
	}
	// The events are counted from the tenant index. The default tenant also
	// counts the platform's rows, with a second lookup of the same index,
	// instead of the COALESCE form that the history pages use for ordered
	// reads, which would read every event.
	eventTenant := `tenant_id=?`
	if ts.scope.id == DefaultTenantID {
		eventTenant = `(tenant_id=? OR tenant_id IS NULL)`
	}
	var telemetry TenantTelemetry
	id := ts.scope.id
	if err := ts.store.reader().QueryRowContext(ctx, `SELECT
		COALESCE((SELECT COUNT(*) FROM jobs WHERE tenant_id=?),0),
		COALESCE((SELECT COUNT(*) FROM scans WHERE tenant_id=?),0),
		COALESCE((SELECT COUNT(*) FROM scans AS s JOIN scan_hosts AS h ON h.scan_id=s.id WHERE s.tenant_id=?),0),
		COALESCE((SELECT COUNT(*) FROM latest_scan_hosts WHERE tenant_id=?),0),
		COALESCE((SELECT COUNT(*) FROM events WHERE `+eventTenant+`),0),
		COALESCE((SELECT COUNT(*) FROM scan_cycles AS c JOIN jobs AS j ON j.id=c.job_id AND j.tenant_id=?),0),
		COALESCE((SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL AND `+historyTenantSQL+`),0),
		COALESCE((SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL AND terminal_at='' AND attempts > 0 AND attempts < ? AND `+historyTenantSQL+`),0),
		COALESCE((SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL AND (attempts >= ? OR terminal_at <> '') AND `+historyTenantSQL+`),0)`,
		id, id, id, id, id, id, id, deliveryMaxAttempts, id, deliveryMaxAttempts, id).
		Scan(&telemetry.Jobs, &telemetry.Scans, &telemetry.HostObservations, &telemetry.EffectiveHosts, &telemetry.Events, &telemetry.ScanCycles, &telemetry.OutboxPending, &telemetry.OutboxRetrying, &telemetry.OutboxFailed); err != nil {
		return TenantTelemetry{}, err
	}
	if ts.scope.id == DefaultTenantID {
		size, err := databaseBytes(ctx, ts.store.reader())
		if err != nil {
			return TenantTelemetry{}, err
		}
		telemetry.DatabaseBytes = size
	}
	telemetry.CollectedAt = time.Now().UTC()
	return telemetry, nil
}
