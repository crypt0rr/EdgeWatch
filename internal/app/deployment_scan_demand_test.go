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
		// The timeout is longer than the run, so a run ends in time for the
		// tick a day after its start and the job is busy all day.
		record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
			Name: fmt.Sprintf("full-day-%d", i), Schedule: "0 * * * *", Timezone: "UTC", Timeout: config.Duration(48 * time.Hour),
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

// Every two minutes in a timezone with daylight saving, three-minute runs
// skip ticks, and each distinct run needs thousands of work units to
// project. The units' jobs with the same run share one projection, while
// the distinct ones exceed the request's bound, which leaves some of them
// counted as work-limited.
func TestDeploymentScanDemandSharesAndBoundsDenseScheduleSimulationAcrossUnits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	const (
		unitCount = 100
		schedule  = "*/2 * * * *"
		timezone  = "Europe/Amsterdam"
	)
	application := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: unitCount}}}

	pattern, err := schedulePattern(ctx, timezone, schedule)
	if err != nil || !pattern.ok {
		t.Fatalf("dense schedule pattern = %+v, error %v", pattern, err)
	}
	projection := &scanScheduleSimulationBudget{limit: scanScheduleJobWorkLimit}
	sharedRuns, _, err := pattern.runsForDurationWithBudget(ctx, (3 * time.Minute).Seconds(), false, projection)
	if err != nil {
		t.Fatal(err)
	}
	if projection.used*(unitCount+1) <= scanScheduleRequestWorkLimit || projection.used <= scanScheduleJobFirstPassWorkLimit {
		t.Fatalf("one dense projection used %d work units; want %d of them to exceed the request's bound", projection.used, unitCount+1)
	}

	units := make([]*store.TenantStore, 0, unitCount)
	units = append(units, defaultTenant(db))
	for i := 1; i < unitCount; i++ {
		_, ts := demandUnit(t, db, fmt.Sprintf("Dense unit %03d", i), fmt.Sprintf("dense-%03d", i))
		units = append(units, ts)
	}
	finished := time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC)
	for i, ts := range units {
		for _, sample := range []struct {
			name     string
			duration time.Duration
		}{
			{name: fmt.Sprintf("a-shared-%03d", i), duration: 3 * time.Minute},
			{name: fmt.Sprintf("b-distinct-%03d", i), duration: 3*time.Minute + time.Duration(i+1)*time.Second},
		} {
			record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
				Name: sample.name, Schedule: schedule, Timezone: timezone,
				Targets: []string{"192.0.2.1"},
				TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
			}), true)
			if err != nil {
				t.Fatal(err)
			}
			insertCompletedScan(t, db, record, "scan-"+sample.name, finished, sample.duration)
		}
	}

	budget := &scanScheduleSimulationBudget{limit: scanScheduleRequestWorkLimit}
	demand, err := application.deploymentScanDemandWithBudget(ctx, budget)
	if err != nil {
		t.Fatal(err)
	}
	if demand.Units != unitCount || demand.EnabledJobs != 2*unitCount || demand.HistoryJobs < unitCount || demand.WorkLimitedJobs == 0 || demand.UnestimatedJobs != 0 || demand.CadenceUnattainableJobs < unitCount || demand.Slots != unitCount {
		t.Fatalf("deployment demand = %+v; want all units, shared projections, skipped ticks, and work-limited jobs reported", demand)
	}
	if demand.HistoryJobs+demand.WorkLimitedJobs != demand.EnabledJobs {
		t.Fatalf("deployment demand = %+v; want every job either estimated or work-limited", demand)
	}
	if wantMinimum := float64(unitCount) * 3 * 60 * sharedRuns; demand.EstimatedSlotSecondsPerDay < wantMinimum {
		t.Fatalf("deployment demand %.0f slot-seconds/day omits shared projections; want at least %.0f", demand.EstimatedSlotSecondsPerDay, wantMinimum)
	}
	if budget.used != budget.limit || budget.used > scanScheduleRequestWorkLimit {
		t.Fatalf("deployment estimate used %d work units; want the bounded limit %d", budget.used, scanScheduleRequestWorkLimit)
	}
}

// Ten units with three hourly jobs each, each job with its own 10-minute
// mean run, need no simulation: a run that ends before the next tick starts
// at every tick. The deployment estimate is the sum of the units' own
// estimates, and the request does little more work than expanding the one
// schedule.
func TestDeploymentScanDemandEstimatesEveryUnitsOrdinaryHourlyJobs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	const unitCount = 10
	application := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 6}}}
	units := []*store.TenantStore{defaultTenant(db)}
	for i := 1; i < unitCount; i++ {
		_, ts := demandUnit(t, db, fmt.Sprintf("Hourly unit %02d", i), fmt.Sprintf("hourly-%02d", i))
		units = append(units, ts)
	}
	for u, ts := range units {
		for j := range 3 {
			record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
				Name: fmt.Sprintf("hourly-%02d-%d", u, j), Schedule: "0 * * * *", Timezone: "UTC",
				Targets: []string{"192.0.2.1"},
				TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
			}), true)
			if err != nil {
				t.Fatal(err)
			}
			insertCompletedScan(t, db, record, fmt.Sprintf("hourly-scan-%02d-%d", u, j), time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC), 10*time.Minute+time.Duration(3*u+j+1)*time.Second)
		}
	}
	budget := &scanScheduleSimulationBudget{limit: scanScheduleRequestWorkLimit}
	demand, err := application.deploymentScanDemandWithBudget(ctx, budget)
	if err != nil {
		t.Fatal(err)
	}
	expansion := &scanScheduleSimulationBudget{limit: scanScheduleRequestWorkLimit}
	if _, err := schedulePatternWithBudget(ctx, "UTC", "0 * * * *", expansion); err != nil {
		t.Fatal(err)
	}
	if budget.used != expansion.used {
		t.Fatalf("deployment estimate used %d work units; want only the %d of expanding the one schedule", budget.used, expansion.used)
	}
	var want float64
	for _, ts := range units {
		own, err := application.ScanSlotDemand(ctx, ts)
		if err != nil {
			t.Fatal(err)
		}
		if own.HistoryJobs != 3 || own.WorkLimitedJobs != 0 {
			t.Fatalf("unit's own demand = %+v; want its three jobs estimated", own)
		}
		want += min(own.EstimatedSlotSecondsPerDay, own.CapacitySlotSecondsPerDay)
	}
	if demand.HistoryJobs != 3*unitCount || demand.UnestimatedJobs != 0 || demand.WorkLimitedJobs != 0 || demand.CadenceUnattainableJobs != 0 {
		t.Fatalf("deployment demand = %+v; want all 30 hourly jobs estimated", demand)
	}
	if math.Abs(demand.EstimatedSlotSecondsPerDay-want) > 0.01 || demand.UtilizationPercent < 80 {
		t.Fatalf("deployment demand = %+v; want the units' estimates together, %.0f slot-seconds/day, above the 80%% warning", demand, want)
	}
}

// One unit's dense schedules need more work than the request has, but the
// request takes the units' jobs in turn and projects ordinary jobs first,
// so the other unit's slow hourly jobs, which skip ticks and need a
// projection each, are all estimated.
func TestDeploymentScanDemandKeepsOtherUnitsJobsWhenOneUnitsSchedulesAreDense(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	application := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 4}}}
	// The default unit comes first, so its dense jobs would otherwise take
	// the request's work before the other unit's jobs.
	dense := defaultTenant(db)
	const denseJobs = 40
	for i := range denseJobs {
		// The known work of a full Naabu port range at 100 probes a second
		// outlasts each job's own timeout, which ends each run after 181
		// seconds or more, longer than the two-minute gap.
		if _, err := dense.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
			Name: fmt.Sprintf("dense-%02d", i), Schedule: "*/2 * * * *", Timezone: "Europe/Amsterdam",
			Timeout: config.Duration(time.Duration(181+i) * time.Second), Targets: []string{"192.0.2.1"},
			TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{Rate: 100}},
		}), true); err != nil {
			t.Fatal(err)
		}
	}
	_, ordinary := demandUnit(t, db, "Ordinary", "ordinary")
	const ordinaryJobs = 10
	for i := range ordinaryJobs {
		record, err := ordinary.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
			Name: fmt.Sprintf("slow-hourly-%02d", i), Schedule: "0 * * * *", Timezone: "UTC", Timeout: config.Duration(2 * time.Hour),
			Targets: []string{"192.0.2.2"},
			TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
		}), true)
		if err != nil {
			t.Fatal(err)
		}
		insertCompletedScan(t, db, record, fmt.Sprintf("slow-hourly-scan-%02d", i), time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC), 90*time.Minute+time.Duration(i+1)*time.Second)
	}
	own, err := application.ScanSlotDemand(ctx, ordinary)
	if err != nil {
		t.Fatal(err)
	}
	if own.HistoryJobs != ordinaryJobs || own.CadenceUnattainableJobs != ordinaryJobs {
		t.Fatalf("ordinary unit's own demand = %+v; want its %d jobs estimated with skipped ticks", own, ordinaryJobs)
	}

	budget := &scanScheduleSimulationBudget{limit: 100_000}
	demand, err := application.deploymentScanDemandWithBudget(ctx, budget)
	if err != nil {
		t.Fatal(err)
	}
	if demand.HistoryJobs != ordinaryJobs || demand.WorkLimitedJobs == 0 || demand.LowerBoundJobs+demand.WorkLimitedJobs != denseJobs {
		t.Fatalf("deployment demand = %+v; want every ordinary job estimated and the dense unit's excess work-limited", demand)
	}
	if demand.EstimatedSlotSecondsPerDay < min(own.EstimatedSlotSecondsPerDay, own.CapacitySlotSecondsPerDay) {
		t.Fatalf("deployment demand %.0f slot-seconds/day leaves out the ordinary unit's %.0f", demand.EstimatedSlotSecondsPerDay, own.EstimatedSlotSecondsPerDay)
	}
	if budget.used > budget.limit {
		t.Fatalf("deployment estimate used %d work units; want at most %d", budget.used, budget.limit)
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
	defaultBudgetDemand, err := application.deploymentScanDemandWithBudget(ctx, nil)
	if err != nil || defaultBudgetDemand != demand {
		t.Fatalf("deployment demand with a nil budget = %+v, error %v; want %+v", defaultBudgetDemand, err, demand)
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
