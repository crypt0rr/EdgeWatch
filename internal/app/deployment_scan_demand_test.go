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

// Every two minutes in a timezone with daylight saving, runs of three
// minutes or more skip ticks, and each run of a distinct number of minutes
// needs thousands of work units to project. The units' jobs with the same
// run share one projection, while the distinct ones exceed the request's
// bound, which leaves some of them counted as work-limited without spending
// work on projections that the remaining work cannot cover.
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
			{name: fmt.Sprintf("b-distinct-%03d", i), duration: time.Duration(3+i)*time.Minute + time.Duration(i%59+1)*time.Second},
		} {
			// The timeout outlasts every run, so it does not end any.
			record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
				Name: sample.name, Schedule: schedule, Timezone: timezone, Timeout: config.Duration(3 * time.Hour),
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
	if budget.used > budget.limit || budget.remaining() >= pattern.projectionFloor {
		t.Fatalf("deployment estimate used %d work units; want at most the bound %d, and less left than one projection takes, %d", budget.used, scanScheduleRequestWorkLimit, pattern.projectionFloor)
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
		// The known work of a full Naabu port range at 10 probes a second
		// outlasts each job's own timeout, which ends each run after a
		// distinct number of minutes from 3 to 42, longer than the
		// two-minute gap.
		if _, err := dense.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
			Name: fmt.Sprintf("dense-%02d", i), Schedule: "*/2 * * * *", Timezone: "Europe/Amsterdam",
			Timeout: config.Duration(time.Duration(3+i) * time.Minute), Targets: []string{"192.0.2.1"},
			TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{Rate: 10}},
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
		insertCompletedScan(t, db, record, fmt.Sprintf("slow-hourly-scan-%02d", i), time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC), time.Duration(90+i)*time.Minute+time.Duration(i+1)*time.Second)
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

// A new App expands every schedule in its first estimate. One unit's jobs on
// eight dense schedules in a timezone with daylight saving need more work
// to expand than the request has, and come first in turn, but each
// expansion first gets only a small share, so the other unit's jobs on 20
// hourly schedules are all estimated, and the dense expansions get what is
// left afterwards.
func TestDeploymentScanDemandExpandsOrdinarySchedulesBeforeDenseOnes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	application := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 10}}}
	dense := []string{"* * * * *", "*/2 * * * *", "1-59/2 * * * *", "*/3 * * * *", "1-59/3 * * * *", "2-59/3 * * * *", "*/4 * * * *", "1-59/4 * * * *"}
	const bound = 30_000
	var denseWork int
	for _, schedule := range dense {
		expansion := &scanScheduleSimulationBudget{limit: scanScheduleJobWorkLimit}
		if _, err := schedulePatternWithBudget(ctx, "Europe/Amsterdam", schedule, expansion); err != nil {
			t.Fatal(err)
		}
		if expansion.used <= scanScheduleJobFirstPassWorkLimit {
			t.Fatalf("%q expansion used %d work units; want more than a first-pass share", schedule, expansion.used)
		}
		denseWork += expansion.used
	}
	if denseWork <= bound {
		t.Fatalf("dense expansions use %d work units; want more than the bound, %d", denseWork, bound)
	}
	create := func(ts *store.TenantStore, name, schedule string, duration time.Duration) {
		t.Helper()
		record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
			Name: name, Schedule: schedule, Timezone: "Europe/Amsterdam",
			Targets: []string{"192.0.2.1"},
			TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
		}), true)
		if err != nil {
			t.Fatal(err)
		}
		insertCompletedScan(t, db, record, name+"-scan", time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC), duration)
	}
	// The default unit comes first, and its runs fit every gap, so its jobs
	// need only their expansions.
	for i, schedule := range dense {
		create(defaultTenant(db), fmt.Sprintf("dense-%d", i), schedule, 30*time.Second)
	}
	_, ordinary := demandUnit(t, db, "Ordinary", "ordinary")
	const hourlyJobs = 20
	for i := range hourlyJobs {
		create(ordinary, fmt.Sprintf("hourly-%02d", i), fmt.Sprintf("%d * * * *", i), 10*time.Minute)
	}
	demand, err := application.deploymentScanDemandWithBudget(ctx, &scanScheduleSimulationBudget{limit: bound})
	if err != nil {
		t.Fatal(err)
	}
	if demand.EnabledJobs != len(dense)+hourlyJobs || demand.HistoryJobs+demand.WorkLimitedJobs != demand.EnabledJobs || demand.WorkLimitedJobs == 0 || demand.HistoryJobs <= hourlyJobs {
		t.Fatalf("deployment demand = %+v; want every hourly job and some dense ones estimated, and the rest work-limited", demand)
	}
	own, err := application.ScanSlotDemand(ctx, ordinary)
	if err != nil || own.HistoryJobs != hourlyJobs {
		t.Fatalf("ordinary unit's own demand = %+v, error %v; want its %d jobs estimated", own, err, hourlyJobs)
	}
}

// Hourly jobs in a timezone with daylight saving whose runs take 50 to 70
// minutes, each recorded to the millisecond, skip ticks. A tick falls on a
// whole minute, so the runs that end in the same minute block the same
// ticks and share one projection, within a job and across the units' jobs:
// the estimate's work does not grow with the number of such jobs.
func TestDeploymentScanDemandSharesProjectionsOfRunsThatEndInTheSameMinute(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	const unitCount = 4
	application := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 400}}}
	units := []*store.TenantStore{defaultTenant(db)}
	for i := 1; i < unitCount; i++ {
		_, ts := demandUnit(t, db, fmt.Sprintf("Varied unit %02d", i), fmt.Sprintf("varied-%02d", i))
		units = append(units, ts)
	}
	base := time.Date(2026, time.May, 1, 0, 0, 0, 0, time.UTC)
	samples := 0
	addJobs := func(count int) {
		t.Helper()
		for u, ts := range units {
			for range count {
				name := fmt.Sprintf("varied-%02d-%03d", u, samples)
				record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
					Name: name, Schedule: "0 * * * *", Timezone: "Europe/Amsterdam", Timeout: config.Duration(3 * time.Hour),
					Targets: []string{"192.0.2.1"},
					TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
				}), true)
				if err != nil {
					t.Fatal(err)
				}
				for k := range 6 {
					samples++
					duration := 50*time.Minute + time.Duration(4*k)*time.Minute + time.Duration(samples)*time.Millisecond
					insertCompletedScan(t, db, record, fmt.Sprintf("%s-scan-%d", name, k), base.Add(time.Duration(k)*2*time.Hour), duration)
				}
			}
		}
	}
	estimate := func() (DeploymentScanDemand, int) {
		t.Helper()
		forgetProjections(application)
		budget := &scanScheduleSimulationBudget{limit: scanScheduleRequestWorkLimit}
		demand, err := application.deploymentScanDemandWithBudget(ctx, budget)
		if err != nil {
			t.Fatal(err)
		}
		return demand, budget.used
	}
	addJobs(10)
	// The first estimate expands the schedule, which the App remembers.
	if demand, _ := estimate(); demand.HistoryJobs != 10*unitCount {
		t.Fatalf("first deployment demand = %+v; want every job estimated", demand)
	}
	demand, used := estimate()
	pattern, err := schedulePattern(ctx, "Europe/Amsterdam", "0 * * * *")
	if err != nil {
		t.Fatal(err)
	}
	// The runs that end after 63, 67 and 71 minutes skip ticks; the others
	// end within the hour.
	if demand.HistoryJobs != 10*unitCount || demand.WorkLimitedJobs != 0 || demand.CadenceUnattainableJobs != 10*unitCount || used < 3*pattern.projectionFloor || used > 3*scanScheduleJobFirstPassWorkLimit {
		t.Fatalf("deployment demand = %+v after %d work units; want every job estimated with three projections", demand, used)
	}
	addJobs(20)
	more, moreUsed := estimate()
	if more.HistoryJobs != 30*unitCount || more.WorkLimitedJobs != 0 || moreUsed != used {
		t.Fatalf("deployment demand with three times the jobs = %+v after %d work units; want every job estimated with the same %d work units", more, moreUsed, used)
	}
}

// Adding jobs never lowers how many jobs the estimate covers, even when the
// request's bound leaves some out. Each unit has two ordinary hourly jobs,
// each with a run of its own that skips ticks, which are projected within
// their first share, and a growing number of jobs every ten minutes whose
// runs each need a projection of more than that share. Those wait for the
// second pass without spending a share in the first, so new ones cannot
// take the work that the jobs before them need. Each estimate starts
// without the projections that the App remembers from the ones before,
// which could only add to it.
func TestDeploymentScanDemandEstimatesNoFewerJobsAsJobsAreAdded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	const unitCount = 3
	application := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 100}}}
	units := []*store.TenantStore{defaultTenant(db)}
	for i := 1; i < unitCount; i++ {
		_, ts := demandUnit(t, db, fmt.Sprintf("Growing unit %02d", i), fmt.Sprintf("growing-%02d", i))
		units = append(units, ts)
	}
	dense, err := schedulePattern(ctx, "Europe/Amsterdam", "*/10 * * * *")
	if err != nil || dense.projectionFloor <= scanScheduleJobFirstPassWorkLimit {
		t.Fatalf("ten-minute pattern = %+v, error %v; want projections over a first-pass share", dense, err)
	}
	jobs := 0
	add := func(ts *store.TenantStore, schedule string, duration time.Duration) {
		t.Helper()
		jobs++
		name := fmt.Sprintf("growing-%03d", jobs)
		record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
			Name: name, Schedule: schedule, Timezone: "Europe/Amsterdam", Timeout: config.Duration(12 * time.Hour),
			Targets: []string{"192.0.2.1"},
			TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
		}), true)
		if err != nil {
			t.Fatal(err)
		}
		insertCompletedScan(t, db, record, name+"-scan", time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC), duration+time.Second)
	}
	for _, ts := range units {
		for range 2 {
			add(ts, "0 * * * *", time.Duration(60+jobs)*time.Minute)
		}
	}
	const hourlyJobs = 2 * unitCount
	// The bound covers the two schedules' expansions, which the first
	// estimate remembers, the hourly projections and some dense ones.
	const bound = 30_000
	previous := 0
	for step := range 6 {
		for _, ts := range units {
			for range 4 {
				add(ts, "*/10 * * * *", time.Duration(10+jobs)*time.Minute)
			}
		}
		forgetProjections(application)
		demand, err := application.deploymentScanDemandWithBudget(ctx, &scanScheduleSimulationBudget{limit: bound})
		if err != nil {
			t.Fatal(err)
		}
		estimated := demand.HistoryJobs
		if estimated+demand.WorkLimitedJobs != jobs || estimated < previous {
			t.Fatalf("step %d: deployment demand = %+v of %d jobs; want every job estimated or work-limited, and no fewer estimated than %d before", step, demand, jobs, previous)
		}
		previous = estimated
	}
	forgetProjections(application)
	if last, err := application.deploymentScanDemandWithBudget(ctx, &scanScheduleSimulationBudget{limit: bound}); err != nil || last.WorkLimitedJobs == 0 || last.HistoryJobs <= hourlyJobs {
		t.Fatalf("deployment demand = %+v, error %v; want the bound to leave some dense jobs out after estimating some", last, err)
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
