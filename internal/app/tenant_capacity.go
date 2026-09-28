package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// ErrProbeBudgetUnavailable wraps a failure to read a tenant's probe budget.
// The run or request stops, because a budget that cannot be read must not
// fall back to a larger one.
var ErrProbeBudgetUnavailable = errors.New("the probe budget could not be read")

// SetTenantCapacity changes a tenant's scan capacity for a platform
// administrator: its slot cap, its probe budgets, and its high-cost ceiling.
// The store checks each setting against the deployment's and records the
// change as a platform action in the tenant's audit. The new slot cap
// applies to the next grant at once; the budgets apply to the next check,
// because each check reads them.
func (a *App) SetTenantCapacity(ctx context.Context, tenantID string, capacity store.TenantCapacity, audit store.AuditEntry) error {
	if err := a.Store.Platform().SetTenantCapacity(ctx, tenantID, capacity, a.capacityLimits(), audit); err != nil {
		return err
	}
	if err := a.refreshSlotCaps(ctx); err != nil && a.Logger != nil {
		// The change is saved; the next schedule reconciliation applies
		// the slot cap.
		a.Logger.Warn("tenant slot caps could not be refreshed", "error", err)
	}
	return nil
}

// capacityLimits returns the deployment's scan settings, which bound every
// tenant's capacity.
func (a *App) capacityLimits() store.CapacityLimits {
	budget := a.deploymentProbeBudget()
	return store.CapacityLimits{MaxConcurrentScans: a.Config.Scheduler.MaxConcurrent, MaxProbeCount: budget.nmap, MaxNaabuProbeCount: budget.naabu}
}

// refreshSlotCaps reads every active tenant's slot cap and gives the caps to
// the scan slot pool, which grants queued runs that a raised cap now allows.
// The schedule reconciliation calls it, so a change made elsewhere applies
// within its retry interval, and SetTenantCapacity calls it at once.
func (a *App) refreshSlotCaps(ctx context.Context) error {
	if a.slots == nil {
		return nil
	}
	capacities, err := a.Store.System().TenantCapacities(ctx)
	if err != nil {
		return err
	}
	a.slots.SetCaps(tenantSlotCaps(capacities))
	return nil
}

// tenantSlotCaps returns the slot pool's cap source for the tenants'
// max_concurrent_scans, keyed by tenant ID like the pool. It returns nil
// when no tenant has a cap, so an installation that never set one keeps a
// pool with no caps, exactly as before tenants had capacity.
func tenantSlotCaps(capacities map[string]store.TenantCapacity) func(key string) int {
	caps := map[string]int{}
	for id, capacity := range capacities {
		if capacity.MaxConcurrentScans != nil {
			caps[id] = *capacity.MaxConcurrentScans
		}
	}
	if len(caps) == 0 {
		return nil
	}
	return func(key string) int { return caps[key] }
}

// probeBudget is the probe budget of one tenant's jobs.
type probeBudget struct {
	// nmap and naabu are the most probes a run may send with each engine.
	nmap, naabu int64
	// highCost is the most probes per engine that a job with
	// allow_high_cost may send. It raises the budgets, never lowers them.
	highCost int64
}

// deploymentProbeBudget returns the budget that config.yaml sets: its probe
// budgets, or the defaults when they are omitted, and MaxProbeCountLimit for
// high-cost jobs.
func (a *App) deploymentProbeBudget() probeBudget {
	budget := probeBudget{nmap: a.Config.Scheduler.MaxProbeCount, naabu: a.Config.Scheduler.MaxNaabuProbeCount, highCost: config.MaxProbeCountLimit}
	if budget.nmap <= 0 {
		budget.nmap = config.DefaultMaxProbeCount
	}
	if budget.naabu <= 0 {
		budget.naabu = config.DefaultNaabuMaxProbeCount
	}
	return budget
}

// forTenant lowers the budget to the tenant's own settings where they are
// lower. A tenant setting never raises the deployment's, so tightening
// config.yaml wins over a higher tenant value, and the high-cost ceiling
// stays at or below MaxProbeCountLimit.
func (budget probeBudget) forTenant(capacity store.TenantCapacity) probeBudget {
	for _, setting := range []struct {
		value *int64
		limit *int64
	}{
		{capacity.MaxProbeCount, &budget.nmap},
		{capacity.MaxNaabuProbeCount, &budget.naabu},
		{capacity.HighCostCeiling, &budget.highCost},
	} {
		if setting.value != nil && *setting.value < *setting.limit {
			*setting.limit = *setting.value
		}
	}
	return budget
}

// limits returns the most probes job may send with Nmap and with Naabu.
// allow_high_cost raises each budget to the high-cost ceiling when the
// ceiling is higher.
func (budget probeBudget) limits(job config.Job) (nmap, naabu int64) {
	if job.AllowHighCost {
		return max(budget.nmap, budget.highCost), max(budget.naabu, budget.highCost)
	}
	return budget.nmap, budget.naabu
}

// TenantCapacityLimits returns the scan capacity that applies to the jobs of
// the tenant of ts, as the scheduler enforces it: the deployment's scan
// slots and probe budgets, each lowered to the tenant's own setting where
// that is lower. A tenant without settings gets the deployment's. The
// high-cost ceiling is not among them. No limits are returned with an
// error.
func (a *App) TenantCapacityLimits(ctx context.Context, ts *store.TenantStore) (store.CapacityLimits, error) {
	capacity, err := ts.Capacity(ctx)
	if err != nil {
		return store.CapacityLimits{}, err
	}
	budget := a.deploymentProbeBudget().forTenant(capacity)
	limits := store.CapacityLimits{MaxConcurrentScans: a.Config.Scheduler.MaxConcurrent, MaxProbeCount: budget.nmap, MaxNaabuProbeCount: budget.naabu}
	if capacity.MaxConcurrentScans != nil {
		limits.MaxConcurrentScans = slotLimit(limits.MaxConcurrentScans, *capacity.MaxConcurrentScans)
	}
	return limits, nil
}

// tenantProbeBudget reads the probe budget of the tenant of ts: the
// deployment's budget, lowered to the tenant's settings. A failure wraps
// ErrProbeBudgetUnavailable, and no budget is returned with it.
func (a *App) tenantProbeBudget(ctx context.Context, ts *store.TenantStore) (probeBudget, error) {
	capacity, err := ts.Capacity(ctx)
	if err != nil {
		return probeBudget{}, fmt.Errorf("%w: %w", ErrProbeBudgetUnavailable, err)
	}
	return a.deploymentProbeBudget().forTenant(capacity), nil
}
