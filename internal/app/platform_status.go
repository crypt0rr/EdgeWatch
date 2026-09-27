package app

import "github.com/crypt0rr/edgewatch/internal/store"

// SlotUsage reports the use of the deployment's scan slots as counts only:
// the deployment's own and, by business unit ID, each unit's that holds a
// slot or waits for one. The platform console shows it; it names no job or
// scan.
type SlotUsage struct {
	Capacity int
	InUse    int
	Queued   int
	Units    map[string]UnitSlotUsage
}

// UnitSlotUsage is one business unit's slot use. Limit is the most slots the
// unit may hold under the deployment's capacity and the unit's cap.
type UnitSlotUsage struct {
	InUse  int
	Queued int
	Limit  int
}

// SlotUsage returns the current scan slot use.
func (a *App) SlotUsage() SlotUsage {
	usage := SlotUsage{Units: map[string]UnitSlotUsage{}}
	if a == nil || a.slots == nil {
		return usage
	}
	snapshot := a.slots.CapacitySnapshot()
	usage.Capacity, usage.InUse, usage.Queued = snapshot.Capacity, snapshot.InUse, snapshot.Queued
	for key, unit := range snapshot.Keys {
		usage.Units[key] = UnitSlotUsage(unit)
	}
	return usage
}

// DeploymentCapacityLimits returns the deployment's scan settings from
// config.yaml, which bound every business unit's capacity, with the probe
// budgets resolved to their defaults when they are omitted.
func (a *App) DeploymentCapacityLimits() store.CapacityLimits {
	return a.capacityLimits()
}
