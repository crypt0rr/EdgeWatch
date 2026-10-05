package app

import (
	"context"
	"reflect"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// SlotUsage reports the slot pool's counts, by unit, and no more; an
// application without a pool reports none. The deployment limits resolve
// omitted probe budgets to their defaults.
func TestSlotUsageAndDeploymentLimits(t *testing.T) {
	t.Parallel()
	var missing *App
	if usage := missing.SlotUsage(); usage.Capacity != 0 || len(usage.Units) != 0 {
		t.Fatalf("usage without an application = %+v", usage)
	}
	a := &App{Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 2, MaxNaabuProbeCount: 500}}, slots: newSlotPool(2, func(key string) int {
		if key == "capped" {
			return 1
		}
		return 0
	})}
	release, err := a.slots.Acquire(context.Background(), "capped")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	want := SlotUsage{Capacity: 2, InUse: 1, Units: map[string]UnitSlotUsage{"capped": {InUse: 1, Limit: 1}}}
	if got := a.SlotUsage(); !reflect.DeepEqual(got, want) {
		t.Fatalf("slot usage = %+v, want %+v", got, want)
	}
	if got, want := a.DeploymentCapacityLimits(), (store.CapacityLimits{MaxConcurrentScans: 2, MaxProbeCount: config.DefaultMaxProbeCount, MaxNaabuProbeCount: 500}); got != want {
		t.Fatalf("deployment limits = %+v, want %+v", got, want)
	}
}
