package app

import (
	"context"
	"errors"
)

// errNoDeploymentScanDemand is returned by DeploymentScanDemand when the
// application has no store or configuration to estimate from.
var errNoDeploymentScanDemand = errors.New("the deployment's scan demand cannot be estimated without a store and configuration")

// DeploymentScanDemand is the estimated scheduled scan work of every active
// business unit together, compared with the slot-hours that the deployment's
// one pool of scan slots, scheduler.max_concurrent_scans, provides in a day.
// Every unit's scans share that pool: a unit's slot cap only limits its
// share and reserves nothing, so units that each fit their own capacity can
// still oversubscribe the pool together.
//
// Each unit contributes its estimate up to the slot-seconds its effective
// slot limit can provide in a day. The value holds sums and counts only,
// never a unit, job, or per-unit figure, so it tells a platform administrator
// nothing about any one unit's data.
type DeploymentScanDemand struct {
	// Units counts the active units whose jobs the estimate sums. Disabled
	// units and units being deleted schedule no scans, so they are left out.
	Units           int `json:"units"`
	EnabledJobs     int `json:"enabled_jobs"`
	HistoryJobs     int `json:"history_jobs"`
	LowerBoundJobs  int `json:"lower_bound_jobs"`
	UnestimatedJobs int `json:"unestimated_jobs"`
	// CadenceUnattainableJobs counts jobs, in every active unit, for which
	// the estimated run duration makes the scheduler skip a cron tick.
	CadenceUnattainableJobs int `json:"cadence_unattainable_jobs"`
	// Slots is the deployment's scheduler.max_concurrent_scans, the size of
	// the shared pool, whatever the units' own caps are.
	Slots                      int     `json:"slots"`
	EstimatedSlotSecondsPerDay float64 `json:"estimated_slot_seconds_per_day"`
	CapacitySlotSecondsPerDay  float64 `json:"capacity_slot_seconds_per_day"`
	UtilizationPercent         float64 `json:"utilization_percent"`
	OverCapacity               bool    `json:"over_capacity"`
}

// DeploymentScanDemand estimates the scheduled demand of every active unit,
// capped by the unit's effective slot limit, and compares the sum with the
// deployment's shared slot pool. It goes through each active unit's enabled
// jobs and their recent scan history, so a caller that serves it repeatedly
// should cache it. Equivalent schedule-duration projections are shared across
// units within this request, and total projection work is bounded; jobs that
// cannot be projected within that bound are counted as unestimated. A unit
// that cannot be read fails the whole estimate rather than leaving its demand
// out of the sum.
func (a *App) DeploymentScanDemand(ctx context.Context) (DeploymentScanDemand, error) {
	var result DeploymentScanDemand
	if a == nil || a.Store == nil || a.Config == nil {
		return result, errNoDeploymentScanDemand
	}
	scopes, err := a.Store.System().ActiveTenantScopes(ctx)
	if err != nil {
		return DeploymentScanDemand{}, err
	}
	// Schedule-duration projections contain no tenant data, so this request
	// local memo can safely share equivalent work across units. The budget
	// bounds distinct dense projections when their exact durations differ.
	simulations := make(map[scanScheduleDurationKey]scanScheduleDurationEstimate)
	budget := &scanScheduleSimulationBudget{limit: deploymentScheduleSimulationNextCallLimit}
	for _, scope := range scopes {
		ts := a.Store.Tenant(scope)
		unit, err := a.scheduledScanDemandWithSimulationCache(ctx, ts, simulations, budget)
		if err != nil {
			return DeploymentScanDemand{}, err
		}
		limits, err := a.TenantCapacityLimits(ctx, ts)
		if err != nil {
			return DeploymentScanDemand{}, err
		}
		result.Units++
		result.EnabledJobs += unit.EnabledJobs
		result.HistoryJobs += unit.HistoryJobs
		result.LowerBoundJobs += unit.LowerBoundJobs
		result.UnestimatedJobs += unit.UnestimatedJobs
		result.CadenceUnattainableJobs += unit.CadenceUnattainableJobs
		unitCapacity := float64(limits.MaxConcurrentScans) * slotSecondsPerDay
		result.EstimatedSlotSecondsPerDay += min(unit.EstimatedSlotSecondsPerDay, unitCapacity)
	}
	result.Slots = max(a.Config.Scheduler.MaxConcurrent, 0)
	result.CapacitySlotSecondsPerDay, result.UtilizationPercent, result.OverCapacity = compareSlotDemand(result.EstimatedSlotSecondsPerDay, result.Slots)
	return result, nil
}
