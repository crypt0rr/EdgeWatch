package app

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// sixtyPercentSlotJob creates an enabled hourly job in the unit of ts with
// one completed 36-minute scan, so its estimate is 24 × 36 minutes, 14.4
// slot-hours a day: 60% of one slot.
func sixtyPercentSlotJob(t *testing.T, db *store.Store, ts *store.TenantStore, name string) store.JobRecord {
	t.Helper()
	record, err := ts.CreateJobWithEnabled(context.Background(), config.NormalizeJob(config.Job{
		Name: name, Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.1"},
		TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
	}), true)
	if err != nil {
		t.Fatal(err)
	}
	insertCompletedScan(t, db, record, "scan-"+name, time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC), 36*time.Minute)
	return record
}

// demandUnit creates an active unit through the platform store, as the
// platform console does, and returns its store.
func demandUnit(t *testing.T, db *store.Store, name, slug string) (store.TenantRecord, *store.TenantStore) {
	t.Helper()
	ctx := context.Background()
	record, err := db.Platform().CreateTenant(ctx, name, slug, store.AuditEntry{ActorKind: store.AuditActorHost})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := db.TenantScopeByID(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	return record, db.Tenant(scope)
}

// Three active units that each schedule 60% of a one-slot pool see no
// warning in their own view, while together they need 180% of the pool. A
// disabled unit and a unit being deleted keep their enabled jobs but
// schedule no scans, so they add nothing.
func TestDeploymentScanDemandSumsActiveUnitsAgainstTheSharedPool(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	application := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}

	_, second := demandUnit(t, db, "Second", "second")
	_, third := demandUnit(t, db, "Third", "third")
	disabled, disabledStore := demandUnit(t, db, "Paused", "paused")
	deleting, deletingStore := demandUnit(t, db, "Leaving", "leaving")
	active := []*store.TenantStore{defaultTenant(db), second, third}
	for i, ts := range active {
		sixtyPercentSlotJob(t, db, ts, []string{"first-job", "second-job", "third-job"}[i])
	}
	sixtyPercentSlotJob(t, db, disabledStore, "paused-job")
	sixtyPercentSlotJob(t, db, deletingStore, "leaving-job")
	if _, err := db.Platform().DisableTenant(ctx, disabled.ID, disabled.Revision, store.AuditEntry{ActorKind: store.AuditActorHost}); err != nil {
		t.Fatal(err)
	}
	// The state alone, without the archive that a deletion request also
	// makes, leaves the unit out.
	if _, err := db.DB.ExecContext(ctx, `UPDATE tenants SET state=? WHERE id=?`, store.TenantStateDeleting, deleting.ID); err != nil {
		t.Fatal(err)
	}

	for i, ts := range active {
		own, err := application.ScanSlotDemand(ctx, ts)
		if err != nil {
			t.Fatal(err)
		}
		if own.HistoryJobs != 1 || own.OverCapacity || math.Abs(own.UtilizationPercent-60) > 0.01 {
			t.Fatalf("active unit %d's own demand = %+v, want one history job at 60%% within capacity", i, own)
		}
	}
	demand, err := application.DeploymentScanDemand(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := DeploymentScanDemand{
		Units: 3, EnabledJobs: 3, HistoryJobs: 3, Slots: 1,
		EstimatedSlotSecondsPerDay: 3 * 0.6 * slotSecondsPerDay, CapacitySlotSecondsPerDay: slotSecondsPerDay,
		UtilizationPercent: 180, OverCapacity: true,
	}
	if math.Abs(demand.EstimatedSlotSecondsPerDay-want.EstimatedSlotSecondsPerDay) > 0.01 || math.Abs(demand.UtilizationPercent-want.UtilizationPercent) > 0.01 {
		t.Fatalf("deployment demand = %+v, want %+v", demand, want)
	}
	demand.EstimatedSlotSecondsPerDay, demand.UtilizationPercent = want.EstimatedSlotSecondsPerDay, want.UtilizationPercent
	if demand != want {
		t.Fatalf("deployment demand = %+v, want %+v", demand, want)
	}
}

// The deployment's demand is compared with the whole shared pool, whatever
// the units' own caps: a cap only limits a unit's share. Each count is the
// sum of the units' own counts, so the deployment matches the units' views.
func TestDeploymentScanDemandUsesThePoolNotUnitCapsAndSumsTheUnitsCounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	application := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 4}}}

	capped, cappedStore := demandUnit(t, db, "Capped", "capped")
	if _, err := db.DB.ExecContext(ctx, `UPDATE tenants SET max_concurrent_scans=1 WHERE id=?`, capped.ID); err != nil {
		t.Fatal(err)
	}
	sixtyPercentSlotJob(t, db, cappedStore, "capped-job")
	// A job without history or a configured rate is unestimated, a paused
	// job adds nothing, and a job that needs more than a day per day
	// cannot keep its cadence and adds one slot-day.
	if _, err := cappedStore.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
		Name: "unbounded", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.2"}, TCP: &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
	}), true); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(db).CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
		Name: "paused", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.3"}, TCP: &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
	}), false); err != nil {
		t.Fatal(err)
	}
	busy, err := defaultTenant(db).CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
		Name: "busy", Schedule: "*/30 * * * *", Timezone: "UTC", Timeout: config.Duration(2 * time.Hour),
		Targets: []string{"192.0.2.4"}, TCP: &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
	}), true)
	if err != nil {
		t.Fatal(err)
	}
	insertCompletedScan(t, db, busy, "scan-busy", time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC), time.Hour)

	var sum ScanSlotDemand
	for _, ts := range []*store.TenantStore{defaultTenant(db), cappedStore} {
		own, err := application.ScanSlotDemand(ctx, ts)
		if err != nil {
			t.Fatal(err)
		}
		sum.EnabledJobs += own.EnabledJobs
		sum.HistoryJobs += own.HistoryJobs
		sum.LowerBoundJobs += own.LowerBoundJobs
		sum.UnestimatedJobs += own.UnestimatedJobs
		sum.CadenceUnattainableJobs += own.CadenceUnattainableJobs
		sum.EstimatedSlotSecondsPerDay += own.EstimatedSlotSecondsPerDay
	}
	own, err := application.ScanSlotDemand(ctx, cappedStore)
	if err != nil {
		t.Fatal(err)
	}
	if own.Slots != 1 || own.CapacitySlotSecondsPerDay != slotSecondsPerDay {
		t.Fatalf("the capped unit's own demand = %+v, want its one slot", own)
	}

	demand, err := application.DeploymentScanDemand(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if demand.Units != 2 || demand.Slots != 4 || demand.CapacitySlotSecondsPerDay != 4*slotSecondsPerDay {
		t.Fatalf("deployment demand = %+v, want two units against the 4-slot pool", demand)
	}
	if demand.EnabledJobs != 3 || demand.HistoryJobs != 2 || demand.UnestimatedJobs != 1 || demand.CadenceUnattainableJobs != 1 {
		t.Fatalf("deployment counts = %+v, want 3 enabled, 2 with history, 1 unestimated, 1 that cannot keep its cadence", demand)
	}
	if demand.EnabledJobs != sum.EnabledJobs || demand.HistoryJobs != sum.HistoryJobs || demand.LowerBoundJobs != sum.LowerBoundJobs ||
		demand.UnestimatedJobs != sum.UnestimatedJobs || demand.CadenceUnattainableJobs != sum.CadenceUnattainableJobs ||
		math.Abs(demand.EstimatedSlotSecondsPerDay-sum.EstimatedSlotSecondsPerDay) > 0.01 {
		t.Fatalf("deployment demand = %+v, want the sum of the units' own %+v", demand, sum)
	}
	// 0.6 + 1 slot-days of 4.
	if want := 1.6 / 4 * 100; demand.OverCapacity || math.Abs(demand.UtilizationPercent-want) > 0.01 {
		t.Fatalf("deployment utilization = %+v, want %.0f%% within capacity", demand, want)
	}
}

func TestDeploymentScanDemandCapsEachUnitsContributionAtItsEffectiveSlots(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	application := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 4}}}
	unit, ts := demandUnit(t, db, "One-slot unit", "one-slot")
	if _, err := db.DB.ExecContext(ctx, `UPDATE tenants SET max_concurrent_scans=1 WHERE id=?`, unit.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
			Name: fmt.Sprintf("full-day-%d", i), Schedule: "0 * * * *", Timezone: "UTC", Timeout: config.Duration(24 * time.Hour),
			Targets: []string{fmt.Sprintf("192.0.2.%d", i+1)},
			TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
		}), true)
		if err != nil {
			t.Fatal(err)
		}
		insertCompletedScan(t, db, record, fmt.Sprintf("full-day-scan-%d", i), time.Date(2026, time.April, 1, 12, 0, 0, 0, time.UTC), 24*time.Hour)
	}
	unitDemand, err := application.ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if unitDemand.Slots != 1 || unitDemand.EstimatedSlotSecondsPerDay != 2*slotSecondsPerDay || !unitDemand.OverCapacity {
		t.Fatalf("unit demand = %+v; want two slot-days against its one-slot cap", unitDemand)
	}
	demand, err := application.DeploymentScanDemand(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if demand.Slots != 4 || demand.EnabledJobs != 2 || demand.HistoryJobs != 2 || demand.EstimatedSlotSecondsPerDay != slotSecondsPerDay || demand.OverCapacity {
		t.Fatalf("deployment demand = %+v; want this unit capped at one slot-day against the four-slot pool", demand)
	}
}

// Without active units or jobs, the demand is zero against the pool, and an
// application without a store, or a read that fails, gives no estimate.
func TestDeploymentScanDemandWithoutWorkAndOnErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	application := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 2}}}
	demand, err := application.DeploymentScanDemand(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := (DeploymentScanDemand{Units: 1, Slots: 2, CapacitySlotSecondsPerDay: 2 * slotSecondsPerDay}); demand != want {
		t.Fatalf("empty deployment demand = %+v, want %+v", demand, want)
	}

	for _, empty := range []*App{nil, {}, {Store: db}} {
		if _, err := empty.DeploymentScanDemand(ctx); !errors.Is(err, errNoDeploymentScanDemand) {
			t.Fatalf("demand of %+v = %v, want errNoDeploymentScanDemand", empty, err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := application.DeploymentScanDemand(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled demand error = %v, want context.Canceled", err)
	}
}
