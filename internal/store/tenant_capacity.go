package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
)

// auditActionTenantCapacityChanged records a platform administrator's change
// to a tenant's capacity.
const auditActionTenantCapacityChanged = "tenant.capacity_changed"

// TenantCapacity is a tenant's share of the deployment's scan capacity, as
// the tenants row stores it. Every field is a cap below the deployment's own
// setting, never a reservation, and a nil field inherits the deployment
// setting.
type TenantCapacity struct {
	// MaxConcurrentScans is the most scan slots the tenant's runs may hold
	// at once. The deployment's slots stay shared: free slots go round-robin
	// to the tenants that are waiting, up to each tenant's cap.
	MaxConcurrentScans *int
	// MaxProbeCount is the tenant's Nmap probe budget. The deployment's
	// max_probe_count still applies when it is lower.
	MaxProbeCount *int64
	// MaxNaabuProbeCount is the tenant's Naabu discovery probe budget. The
	// deployment's max_naabu_probe_count still applies when it is lower.
	MaxNaabuProbeCount *int64
	// HighCostCeiling is the most probes per engine that a job with
	// allow_high_cost may send. It never lowers the tenant's budgets, and
	// config.MaxProbeCountLimit applies above it. Nil keeps the behavior
	// from before tenants: a high-cost job may send up to
	// config.MaxProbeCountLimit. HighCostNotGranted means that no ceiling
	// was granted, so allow_high_cost raises neither budget, whatever
	// config.yaml sets. A tenant other than the default one starts with
	// InitialTenantCapacity, which grants no ceiling, so high-cost work
	// stays off until a platform administrator grants a ceiling.
	HighCostCeiling *int64
}

// HighCostNotGranted is the HighCostCeiling of a tenant without a high-cost
// grant: a job with allow_high_cost keeps the tenant's budgets. The row
// stores it as high_cost_granted=0 with a NULL high_cost_ceiling, so no
// number is left that a later config.yaml could turn into a raise.
const HighCostNotGranted int64 = 0

// CapacityLimits are the deployment's scan settings from config.yaml, which
// bound every tenant's capacity. A probe budget here is the resolved one:
// the configured value, or the default when the setting is omitted.
type CapacityLimits struct {
	MaxConcurrentScans int
	MaxProbeCount      int64
	MaxNaabuProbeCount int64
}

// InitialTenantCapacity returns the capacity a new tenant starts with. It
// inherits the deployment's slots and probe budgets, and has no high-cost
// grant, so allow_high_cost raises neither budget, whatever config.yaml sets
// now or later, until a platform administrator grants a ceiling. The
// default tenant keeps a nil ceiling instead, and with it the behavior from
// before tenants.
func InitialTenantCapacity() TenantCapacity {
	ceiling := HighCostNotGranted
	return TenantCapacity{HighCostCeiling: &ceiling}
}

// Validate checks each setting against the deployment's limits. The slot
// cap and the probe budgets must lie between 1 and the deployment's own
// setting; the high-cost ceiling between 1 and config.MaxProbeCountLimit,
// unless it is HighCostNotGranted. A nil setting is always valid. The error
// is a ValidationError that names the setting.
func (capacity TenantCapacity) Validate(limits CapacityLimits) error {
	if value := capacity.MaxConcurrentScans; value != nil && (*value < 1 || *value > limits.MaxConcurrentScans) {
		return NewValidationError(fmt.Errorf("max_concurrent_scans must be between 1 and %d", limits.MaxConcurrentScans))
	}
	for _, check := range []struct {
		name         string
		value        *int64
		lower, limit int64
	}{
		{"max_probe_count", capacity.MaxProbeCount, 1, limits.MaxProbeCount},
		{"max_naabu_probe_count", capacity.MaxNaabuProbeCount, 1, limits.MaxNaabuProbeCount},
		{"high_cost_ceiling", capacity.HighCostCeiling, HighCostNotGranted, config.MaxProbeCountLimit},
	} {
		if check.value != nil && (*check.value < check.lower || *check.value > check.limit) {
			return NewValidationError(fmt.Errorf("%s must be between %d and %d", check.name, check.lower, check.limit))
		}
	}
	return nil
}

// auditDetail describes the capacity for the audit record, numbers only.
func (capacity TenantCapacity) auditDetail() string {
	setting := func(value *int64) string {
		if value == nil {
			return "deployment"
		}
		return strconv.FormatInt(*value, 10)
	}
	var slots *int64
	if capacity.MaxConcurrentScans != nil {
		value := int64(*capacity.MaxConcurrentScans)
		slots = &value
	}
	ceiling := setting(capacity.HighCostCeiling)
	if capacity.highCostNotGranted() {
		ceiling = "not_granted"
	}
	return "max_concurrent_scans=" + setting(slots) +
		" max_probe_count=" + setting(capacity.MaxProbeCount) +
		" max_naabu_probe_count=" + setting(capacity.MaxNaabuProbeCount) +
		" high_cost_ceiling=" + ceiling
}

// highCostNotGranted reports whether the capacity has no high-cost grant.
func (capacity TenantCapacity) highCostNotGranted() bool {
	return capacity.HighCostCeiling != nil && *capacity.HighCostCeiling == HighCostNotGranted
}

// highCostColumns returns the high_cost_ceiling and high_cost_granted
// values that store the capacity's high-cost ceiling.
func (capacity TenantCapacity) highCostColumns() (ceiling any, granted int) {
	if capacity.highCostNotGranted() {
		return nil, 0
	}
	return nullableInt64(capacity.HighCostCeiling), 1
}

// tenantCapacityColumns are the capacity columns in the order that
// scanTenantCapacity reads them.
const tenantCapacityColumns = `max_concurrent_scans,max_probe_count,max_naabu_probe_count,high_cost_ceiling,high_cost_granted`

// scanTenantCapacity reads the capacity columns that follow the given
// leading destinations. A row with high_cost_granted=0 has the ceiling
// HighCostNotGranted.
func scanTenantCapacity(scan func(...any) error, leading ...any) (TenantCapacity, error) {
	var slots, probes, naabuProbes, ceiling sql.NullInt64
	var granted int64
	if err := scan(append(leading, &slots, &probes, &naabuProbes, &ceiling, &granted)...); err != nil {
		return TenantCapacity{}, err
	}
	var capacity TenantCapacity
	if slots.Valid {
		value := int(slots.Int64)
		capacity.MaxConcurrentScans = &value
	}
	for _, column := range []struct {
		value sql.NullInt64
		field **int64
	}{
		{probes, &capacity.MaxProbeCount},
		{naabuProbes, &capacity.MaxNaabuProbeCount},
		{ceiling, &capacity.HighCostCeiling},
	} {
		if column.value.Valid {
			value := column.value.Int64
			*column.field = &value
		}
	}
	if granted == 0 {
		notGranted := HighCostNotGranted
		capacity.HighCostCeiling = &notGranted
	}
	return capacity, nil
}

// SetTenantCapacity replaces the capacity of an active or disabled tenant
// after checking it against the deployment's limits, and records the change
// in the same transaction. The actor, audit.ActorUserID, must be an enabled
// platform administrator, which the transaction checks first, as the other
// platform writes do; any other actor, or none, is ErrAccountNotPermitted.
// The audit record belongs to the tenant, so its administrators see it, and
// names a platform actor, so it outlives the tenant's purge. The entry
// supplies the actor and request; the action, detail, tenant, and actor
// kind are set here. A tenant that is missing, deleted, or being deleted is
// not found, and nothing changes.
func (ps *PlatformStore) SetTenantCapacity(ctx context.Context, tenantID string, capacity TenantCapacity, limits CapacityLimits, audit AuditEntry) error {
	if err := capacity.Validate(limits); err != nil {
		return err
	}
	now := time.Now().UTC()
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := requirePlatformActorTx(ctx, tx, audit.ActorUserID); err != nil {
		return err
	}
	ceiling, granted := capacity.highCostColumns()
	result, err := tx.ExecContext(ctx, `UPDATE tenants SET `+
		`max_concurrent_scans=?,max_probe_count=?,max_naabu_probe_count=?,high_cost_ceiling=?,high_cost_granted=?,revision=revision+1,updated_at=? `+
		`WHERE id=? AND state IN (?,?)`,
		nullableInt(capacity.MaxConcurrentScans), nullableInt64(capacity.MaxProbeCount), nullableInt64(capacity.MaxNaabuProbeCount), ceiling, granted,
		sqliteTimestamp(now), tenantID, TenantStateActive, TenantStateDisabled)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil {
		return err
	} else if changed == 0 {
		return fmt.Errorf("%w: tenant %s", ErrNoTenantScope, tenantID)
	}
	audit.Action, audit.Detail, audit.TenantID, audit.ActorKind = auditActionTenantCapacityChanged, capacity.auditDetail(), tenantID, AuditActorPlatform
	if err := insertAuditEntryExec(ctx, tx, audit, now); err != nil {
		return err
	}
	return tx.Commit()
}

// TenantCapacities returns the capacity of every active tenant, keyed by
// tenant ID, so the scheduler can cap each tenant's scan slots. It holds
// numbers only.
func (ss *SystemStore) TenantCapacities(ctx context.Context) (map[string]TenantCapacity, error) {
	rows, err := ss.store.reader().QueryContext(ctx, `SELECT id,`+tenantCapacityColumns+` FROM tenants WHERE state=?`, TenantStateActive)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	capacities := map[string]TenantCapacity{}
	for rows.Next() {
		var id string
		capacity, err := scanTenantCapacity(rows.Scan, &id)
		if err != nil {
			return nil, err
		}
		capacities[id] = capacity
	}
	return capacities, rows.Err()
}

// Capacity returns the tenant's own capacity, whatever its state short of
// deleted, so a run that a pause is cancelling still finds its budget. A
// deleted tenant has no scope.
func (ts *TenantStore) Capacity(ctx context.Context) (TenantCapacity, error) {
	if err := ts.ready(); err != nil {
		return TenantCapacity{}, err
	}
	capacity, err := scanTenantCapacity(ts.store.reader().QueryRowContext(ctx, `SELECT `+tenantCapacityColumns+` FROM tenants WHERE id=? AND state<>?`, ts.scope.id, TenantStateDeleted).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return TenantCapacity{}, fmt.Errorf("%w: tenant %s", ErrNoTenantScope, ts.scope.id)
	}
	return capacity, err
}

func nullableInt(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullableInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}
