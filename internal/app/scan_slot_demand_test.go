package app

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
	"github.com/robfig/cron/v3"
)

// Each run holds a slot for its recorded duration, up to the timeout, and
// the estimate uses the mean over the runs: a median would ignore how long
// the longest of them take.
func TestScanSlotDemandUsesMeanRunTimeOfCompletedSamples(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	job := config.NormalizeJob(config.Job{
		Name:     "historical",
		Schedule: "0 */6 * * *",
		Timezone: "UTC",
		Timeout:  config.Duration(4 * time.Hour),
		Targets:  []string{"192.0.2.1"},
		TCP:      &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{Rate: 1000}},
	})
	record, err := ts.CreateJobWithEnabled(ctx, job, true)
	if err != nil {
		t.Fatal(err)
	}
	for i, duration := range []time.Duration{time.Hour, 2 * time.Hour, 6 * time.Hour} {
		insertCompletedCycle(t, db, record, fmt.Sprintf("mean-cycle-%d", i), duration)
	}

	demand, err := (&App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}).ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if demand.EnabledJobs != 1 || demand.HistoryJobs != 1 || demand.LowerBoundJobs != 0 || demand.CadenceUnattainableJobs != 0 {
		t.Fatalf("history source counts = %+v; want one history job that keeps its cadence", demand)
	}
	// The six-hour run counts at the four-hour timeout: (1 + 2 + 4) / 3
	// hours a run, four runs a day.
	if got, want := demand.EstimatedSlotSecondsPerDay, 4*7.0/3*3600; math.Abs(got-want) > 0.01 {
		t.Fatalf("slot demand = %.2f seconds/day, want the mean 2h20m × 4 runs = %.2f", got, want)
	}
	if demand.OverCapacity || math.Abs(demand.UtilizationPercent-100*28.0/3/24) > 0.01 {
		t.Fatalf("capacity comparison = %+v, want 38.89%% and within one slot", demand)
	}
}

func TestTenantScanSlotDemandKeepsEveryMinuteProjectionBounded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
		Name: "every-minute", Schedule: "* * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.1"},
		TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
	}), true)
	if err != nil {
		t.Fatal(err)
	}
	insertCompletedScan(t, db, record, "every-minute-sample", time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC), 61*time.Second)

	app := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}
	budget := &scanScheduleSimulationBudget{limit: scanScheduleRequestWorkLimit}
	demand, err := app.scheduledScanDemandWithSimulationCache(ctx, ts, make(map[scanScheduleDurationKey]scanScheduleDurationEstimate), budget)
	if err != nil {
		t.Fatal(err)
	}
	if demand.EnabledJobs != 1 || demand.HistoryJobs != 1 || demand.UnestimatedJobs != 0 || demand.CadenceUnattainableJobs != 1 {
		t.Fatalf("every-minute tenant demand = %+v; want one history estimate with a skipped tick", demand)
	}
	if got, want := demand.EstimatedSlotSecondsPerDay, float64(61*720); math.Abs(got-want) > 0.01 {
		t.Fatalf("every-minute tenant demand = %.2f seconds/day; want %.2f", got, want)
	}
	if budget.used >= 2_000 {
		t.Fatalf("every-minute tenant request used %d work units; want bounded expansion and constant-work projection", budget.used)
	}
	publicDemand, err := app.ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if publicDemand.HistoryJobs != demand.HistoryJobs || publicDemand.CadenceUnattainableJobs != demand.CadenceUnattainableJobs || publicDemand.EstimatedSlotSecondsPerDay != demand.EstimatedSlotSecondsPerDay {
		t.Fatalf("public tenant endpoint = %+v, internal request estimate = %+v", publicDemand, demand)
	}
}

// A unit with 400 daily jobs, each with its own run duration, is estimated
// in full: a run shorter than a day starts at every daily tick, so no job
// needs a projection.
func TestTenantScanSlotDemandEstimatesEveryDailyJob(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	const jobs = 400
	var want float64
	for i := range jobs {
		record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
			Name: fmt.Sprintf("daily-%03d", i), Schedule: "0 3 * * *", Timezone: "UTC",
			Targets: []string{"192.0.2.1"},
			TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
		}), true)
		if err != nil {
			t.Fatal(err)
		}
		duration := time.Minute + time.Duration(i+1)*time.Second
		insertCompletedScan(t, db, record, fmt.Sprintf("daily-scan-%03d", i), time.Date(2026, time.May, 1, 4, 0, 0, 0, time.UTC), duration)
		want += duration.Seconds()
	}
	app := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}
	budget := &scanScheduleSimulationBudget{limit: scanScheduleRequestWorkLimit}
	demand, err := app.scheduledScanDemandWithSimulationCache(ctx, ts, nil, budget)
	if err != nil {
		t.Fatal(err)
	}
	if demand.EnabledJobs != jobs || demand.HistoryJobs != jobs || demand.UnestimatedJobs != 0 || demand.WorkLimitedJobs != 0 || demand.CadenceUnattainableJobs != 0 {
		t.Fatalf("daily tenant demand = %+v; want all %d jobs estimated", demand, jobs)
	}
	if math.Abs(demand.EstimatedSlotSecondsPerDay-want) > 0.01 {
		t.Fatalf("daily tenant demand = %.2f slot-seconds/day, want the jobs' runs together, %.2f", demand.EstimatedSlotSecondsPerDay, want)
	}
	expansion := &scanScheduleSimulationBudget{limit: scanScheduleRequestWorkLimit}
	if _, err := schedulePatternWithBudget(ctx, "UTC", "0 3 * * *", expansion); err != nil {
		t.Fatal(err)
	}
	if budget.used != expansion.used {
		t.Fatalf("daily tenant request used %d work units; want only the %d of expanding the one schedule", budget.used, expansion.used)
	}
}

// The first request of a new App expands every schedule. A unit with 400
// daily jobs at their own times in a timezone with daylight saving has 400
// schedules to expand, and each expansion takes work for the timezone's
// changes and runs of days, not for each day of the sample, so all of them
// fit the request's bound and every job is estimated.
func TestTenantScanSlotDemandEstimatesDistinctDailySchedulesOnTheFirstRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	const jobs = 400
	var want float64
	for i := range jobs {
		record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
			Name: fmt.Sprintf("daily-%03d", i), Schedule: fmt.Sprintf("%d %d * * *", i%60, i/60), Timezone: "Europe/Amsterdam",
			Targets: []string{"192.0.2.1"},
			TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
		}), true)
		if err != nil {
			t.Fatal(err)
		}
		duration := time.Minute + time.Duration(i+1)*time.Second
		insertCompletedScan(t, db, record, fmt.Sprintf("daily-scan-%03d", i), time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC), duration)
		want += duration.Seconds()
	}
	app := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}
	budget := &scanScheduleSimulationBudget{limit: scanScheduleRequestWorkLimit}
	demand, err := app.scheduledScanDemandWithSimulationCache(ctx, ts, nil, budget)
	if err != nil {
		t.Fatal(err)
	}
	if demand.EnabledJobs != jobs || demand.HistoryJobs != jobs || demand.WorkLimitedJobs != 0 || demand.UnestimatedJobs != 0 || demand.CadenceUnattainableJobs != 0 {
		t.Fatalf("first request's demand = %+v after %d work units; want all %d jobs estimated", demand, budget.used, jobs)
	}
	if math.Abs(demand.EstimatedSlotSecondsPerDay-want) > 0.01 {
		t.Fatalf("first request's demand = %.2f slot-seconds/day, want the jobs' runs together, %.2f", demand.EstimatedSlotSecondsPerDay, want)
	}
	if budget.used > scanScheduleRequestWorkLimit/10 {
		t.Fatalf("expanding %d daily schedules used %d work units; want a small part of the request's %d", jobs, budget.used, scanScheduleRequestWorkLimit)
	}
}

// A request expands each schedule once, whether or not the App's cache can
// keep it. With the cache full of schedules that rank before it, so that it
// refuses this one, 50 jobs on one hourly schedule take the work of one
// expansion, and the next request expands it once again.
func TestScanDemandExpandsEachScheduleOncePerRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	const jobs = 50
	for i := range jobs {
		record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
			Name: fmt.Sprintf("hourly-%02d", i), Schedule: "0 * * * *", Timezone: "Europe/Amsterdam",
			Targets: []string{"192.0.2.1"},
			TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
		}), true)
		if err != nil {
			t.Fatal(err)
		}
		insertCompletedScan(t, db, record, fmt.Sprintf("hourly-scan-%02d", i), time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC), 10*time.Minute+time.Duration(i)*time.Second)
	}
	app := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}
	key := scanRunsPerDayKey{timezone: "Europe/Amsterdam", schedule: "0 * * * *"}
	for i := range scanRunsPerDayCacheLimit {
		app.scanSlotDemand.retainRunsPerDay(scanRunsPerDayKey{timezone: "UTC", schedule: fmt.Sprintf("filler-%04d", i)}, scanRunsPerDayValue{})
	}
	expansion := &scanScheduleSimulationBudget{limit: scanScheduleJobWorkLimit}
	if _, err := schedulePatternWithBudget(ctx, key.timezone, key.schedule, expansion); err != nil {
		t.Fatal(err)
	}
	computed := func() (int, bool) {
		app.scanSlotDemand.mu.Lock()
		defer app.scanSlotDemand.mu.Unlock()
		_, retained := app.scanSlotDemand.runsPerDay[key]
		return app.scanSlotDemand.runsPerDayComputed, retained
	}
	for request := 1; request <= 2; request++ {
		budget := &scanScheduleSimulationBudget{limit: scanScheduleRequestWorkLimit}
		demand, err := app.scheduledScanDemandWithSimulationCache(ctx, ts, nil, budget)
		if err != nil {
			t.Fatal(err)
		}
		if demand.HistoryJobs != jobs || demand.WorkLimitedJobs != 0 {
			t.Fatalf("request %d: demand = %+v; want all %d jobs estimated", request, demand, jobs)
		}
		if got, retained := computed(); retained || got != request || budget.used != expansion.used {
			t.Fatalf("request %d: %d expansions in all, retained %t, %d work units; want the refused schedule expanded once in each request, %d work units", request, got, retained, budget.used, expansion.used)
		}
	}
}

// In the first pass an expansion gets a job's first-pass share. A dense
// schedule's expansion that runs over it waits for the second pass, and the
// schedule's other jobs wait without spending another share; in the second
// pass it gets the job's whole limit. Once the first pass has spent its
// half of the request's work, an expansion waits without spending any. An
// expansion that the request's remaining work cannot finish fails for every
// job with the schedule.
func TestScanDemandWorkGivesFirstPassExpansionsAShare(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dense := config.Job{Schedule: "*/2 * * * *", Timezone: "Europe/Amsterdam"}
	whole := &scanScheduleSimulationBudget{limit: scanScheduleJobWorkLimit}
	if _, err := schedulePatternWithBudget(ctx, dense.Timezone, dense.Schedule, whole); err != nil || whole.used <= scanScheduleJobFirstPassWorkLimit {
		t.Fatalf("dense expansion used %d work units, error %v; want more than a first-pass share", whole.used, err)
	}
	app := &App{Config: &config.Config{}}
	work := newScanDemandWork(nil, nil)
	if _, err := work.schedule(ctx, app, dense, true); !errors.Is(err, errScanDemandDeferred) || work.budget.used != scanScheduleJobFirstPassWorkLimit {
		t.Fatalf("first-pass dense expansion = error %v after %d work units; want it deferred after the share, %d", err, work.budget.used, scanScheduleJobFirstPassWorkLimit)
	}
	if _, err := work.schedule(ctx, app, dense, true); !errors.Is(err, errScanDemandDeferred) || work.budget.used != scanScheduleJobFirstPassWorkLimit {
		t.Fatalf("first-pass expansion of a deferred schedule = error %v after %d work units; want it deferred without work", err, work.budget.used)
	}
	value, err := work.schedule(ctx, app, dense, false)
	if err != nil || !value.ok || work.budget.used != scanScheduleJobFirstPassWorkLimit+whole.used {
		t.Fatalf("second-pass dense expansion = %+v, error %v after %d work units; want it expanded with %d more", value.ok, err, work.budget.used, whole.used)
	}
	if again, err := work.schedule(ctx, app, dense, true); err != nil || again.runsPerDay != value.runsPerDay {
		t.Fatalf("expansion of an expanded schedule = %+v, error %v; want the expansion", again.ok, err)
	}

	hourly := config.Job{Schedule: "0 * * * *", Timezone: "Europe/Amsterdam"}
	work = newScanDemandWork(nil, nil)
	work.budget.used = work.firstPassLimit
	if _, err := work.schedule(ctx, &App{Config: &config.Config{}}, hourly, true); !errors.Is(err, errScanDemandDeferred) || work.budget.used != work.firstPassLimit {
		t.Fatalf("first-pass expansion after half of the request = error %v after %d work units; want it deferred without work", err, work.budget.used-work.firstPassLimit)
	}
	if value, err := work.schedule(ctx, &App{Config: &config.Config{}}, hourly, false); err != nil || !value.ok {
		t.Fatalf("second-pass expansion after half of the request = %+v, error %v; want it expanded", value.ok, err)
	}

	for _, firstPass := range []bool{true, false} {
		work = newScanDemandWork(nil, &scanScheduleSimulationBudget{limit: 10})
		if _, err := work.schedule(ctx, &App{Config: &config.Config{}}, hourly, firstPass); !errors.Is(err, errScheduleSimulationBudgetExceeded) || work.budget.used != 10 {
			t.Fatalf("expansion beyond the request's work, first pass %t = error %v after %d work units; want it exceeded", firstPass, err, work.budget.used)
		}
		if _, err := work.schedule(ctx, &App{Config: &config.Config{}}, hourly, false); !errors.Is(err, errScheduleSimulationBudgetExceeded) {
			t.Fatalf("second expansion beyond the request's work, first pass %t = error %v; want it exceeded", firstPass, err)
		}
	}
}

func TestTenantDemandSharesExpansionAndProjectionWorkBudget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
		Name: "budgeted-pattern", Schedule: "*/5 0 * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.1"},
		TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
	}), true)
	if err != nil {
		t.Fatal(err)
	}
	insertCompletedScan(t, db, record, "budgeted-pattern-sample", time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC), 6*time.Minute)

	app := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}
	expansionBudget := &scanScheduleSimulationBudget{limit: 0}
	expansionDemand, err := app.scheduledScanDemandWithSimulationCache(ctx, ts, make(map[scanScheduleDurationKey]scanScheduleDurationEstimate), expansionBudget)
	if err != nil {
		t.Fatal(err)
	}
	if expansionDemand.EnabledJobs != 1 || expansionDemand.WorkLimitedJobs != 1 || expansionDemand.UnestimatedJobs != 0 || expansionDemand.HistoryJobs != 0 {
		t.Fatalf("expansion-over-budget tenant demand = %+v; want the job reported work-limited", expansionDemand)
	}

	// The six-minute runs skip five-minute ticks, so they need a projection
	// on top of the expansion; a limit just above the expansion's work
	// leaves too little for it.
	expansion := &scanScheduleSimulationBudget{limit: scanScheduleRequestWorkLimit}
	if _, err := schedulePatternWithBudget(ctx, "UTC", "*/5 0 * * *", expansion); err != nil {
		t.Fatal(err)
	}
	requestWorkLimit := expansion.used + 3
	budget := &scanScheduleSimulationBudget{limit: requestWorkLimit}
	simulations := make(map[scanScheduleDurationKey]scanScheduleDurationEstimate)
	demand, err := app.scheduledScanDemandWithSimulationCache(ctx, ts, simulations, budget)
	if err != nil {
		t.Fatal(err)
	}
	if demand.EnabledJobs != 1 || demand.HistoryJobs != 0 || demand.WorkLimitedJobs != 1 || demand.UnestimatedJobs != 0 {
		t.Fatalf("over-budget tenant demand = %+v; want the job reported work-limited", demand)
	}
	if budget.used != requestWorkLimit {
		t.Fatalf("tenant demand used %d work units; want the shared expansion/projection limit %d", budget.used, requestWorkLimit)
	}
	if len(simulations) != 0 {
		t.Fatalf("tenant demand cached %d partial duration projections after budget exhaustion", len(simulations))
	}
}

func TestScheduleExpansionAndDurationProjectionShareBudget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	budget := &scanScheduleSimulationBudget{limit: scanScheduleRequestWorkLimit}
	pattern, err := schedulePatternWithBudget(ctx, "UTC", "*/5 0 * * *", budget)
	if err != nil || !pattern.ok {
		t.Fatalf("budgeted schedule expansion = %+v, error %v", pattern, err)
	}
	expansionWork := budget.used
	if expansionWork <= 0 {
		t.Fatalf("schedule expansion used %d work units; want some", expansionWork)
	}
	budget.limit = expansionWork + 3
	projections := make(map[scanScheduleDurationKey]scanScheduleDurationEstimate)
	if _, _, err := memoizedScheduleRunsForDurationWithBudget(ctx, projections, pattern, (6 * time.Minute).Seconds(), false, budget); !errors.Is(err, errScheduleSimulationBudgetExceeded) {
		t.Fatalf("projection after expansion used %v; want shared budget exhaustion", err)
	}
	if budget.used != budget.limit {
		t.Fatalf("combined expansion and projection used %d work units; want the shared limit %d", budget.used, budget.limit)
	}
	if len(projections) != 0 {
		t.Fatalf("cached %d incomplete projections after shared budget exhaustion", len(projections))
	}
}

// Expanding a schedule takes work for the timezone's transitions, the days
// whose ticks the cron schedule gives, the runs of days on which it ticks
// and the months whose days it restricts, not for each of the sample's
// 1,461 days: at most a little more than the least work of projecting a run
// over those days.
func TestScheduleExpansionWorkGrowsWithTransitionsAndSpansNotDays(t *testing.T) {
	t.Parallel()
	const transitionsAndMonths = 100
	for _, test := range []struct{ timezone, schedule string }{
		{"UTC", "0 3 * * *"},
		{"Europe/Amsterdam", "17 3 * * *"},
		{"Europe/Amsterdam", "0 * * * *"},
		{"Australia/Lord_Howe", "0 0 * * *"},
		{"Africa/Casablanca", "30 1 * * *"},
		{"Europe/Amsterdam", "0 3 * * 1"},
		{"Europe/Amsterdam", "0 3 * * 1-5"},
		{"Europe/Amsterdam", "0 3 1 * *"},
		{"America/New_York", "0 3 * 6-8 *"},
		{"UTC", "0 0 */2 * *"},
		{"Europe/Amsterdam", "*/2 * * * *"},
	} {
		budget := &scanScheduleSimulationBudget{limit: scanScheduleJobWorkLimit}
		pattern, err := schedulePatternWithBudget(context.Background(), test.timezone, test.schedule, budget)
		if err != nil || !pattern.ok {
			t.Fatalf("%s %q: pattern = %+v, error %v", test.timezone, test.schedule, pattern, err)
		}
		if budget.used <= 0 || budget.used > pattern.projectionFloor+transitionsAndMonths {
			t.Errorf("%s %q: expansion used %d work units for %d day spans; want at most %d, a little more than the %d its days take to project", test.timezone, test.schedule, budget.used, len(pattern.days), pattern.projectionFloor+transitionsAndMonths, pattern.projectionFloor)
		}
	}
}

// The expansion's days are the cron scheduler's: each tick follows the one
// before it, so on an ordinary day the ticks are the schedule's times of
// day, the days whose ticks the cron schedule gives have some, and no other
// day has any. The scheduler's search for the tick after a daylight-saving
// change can drift past the first ticks of the following days, as with
// midnight in Lord Howe after its half-hour change, which skips the next
// day, or 2:00 to 2:59 in Chatham, whose change at 2:45 leaves only 15 of
// the next day's 60 ticks.
func TestScheduleExpansionMatchesTheCronSchedulersDays(t *testing.T) {
	t.Parallel()
	type check struct{ timezone, schedule string }
	var checks []check
	for _, timezone := range []string{"UTC", "Europe/Amsterdam", "America/Santiago", "America/Havana", "Asia/Beirut", "Africa/Casablanca", "Australia/Lord_Howe", "Pacific/Chatham", "Antarctica/Troll", "America/St_Johns"} {
		for _, schedule := range []string{"0 0 * * *", "30 2 * * *", "0 0 * * 0,2", "45 1 1-7 * 0", "0 23 * * *"} {
			checks = append(checks, check{timezone, schedule})
		}
	}
	checks = append(checks, check{"Pacific/Chatham", "* 2 * * *"}, check{"Australia/Lord_Howe", "15 */3 * * *"}, check{"Europe/Amsterdam", "*/20 0-3 * * 0,6"})
	for _, test := range checks {
		t.Run(test.timezone+" "+test.schedule, func(t *testing.T) {
			t.Parallel()
			pattern, err := schedulePattern(context.Background(), test.timezone, test.schedule)
			if err != nil || !pattern.ok {
				t.Fatalf("pattern = %+v, error %v", pattern, err)
			}
			location := mustLoadLocation(t, test.timezone)
			parsed, err := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow).Parse(test.schedule)
			if err != nil {
				t.Fatal(err)
			}
			parsed.(*cron.SpecSchedule).Location = location
			start := time.Date(scanScheduleSampleStartYear, time.January, 1, 0, 0, 0, 0, location)
			end := time.Date(scanScheduleSampleEndYear, time.January, 1, 0, 0, 0, 0, location)
			// The cron ticks by the offset of their day's start from the
			// sample's start, in seconds.
			ticks := make(map[int64][]time.Time)
			var count int
			var shortest time.Duration
			var last time.Time
			for next := parsed.Next(start.Add(-time.Nanosecond)); !next.IsZero() && next.Before(end); next = parsed.Next(next) {
				if count > 0 && (shortest == 0 || next.Sub(last) < shortest) {
					shortest = next.Sub(last)
				}
				count, last = count+1, next
				year, month, day := next.In(location).Date()
				dayStart := start
				if year != scanScheduleSampleStartYear || month != time.January || day != 1 {
					var ok bool
					if dayStart, ok = scheduleDateStart(time.Date(year, month, day, 12, 0, 0, 0, time.UTC), location); !ok {
						t.Fatalf("no start for the day of tick %s", next)
					}
				}
				key := int64(dayStart.Sub(start) / time.Second)
				ticks[key] = append(ticks[key], next)
			}
			if want := float64(count) / (end.Sub(start).Hours() / 24); math.Abs(pattern.runsPerDay-want) > 1e-9 {
				t.Fatalf("expansion = %.8f runs/day; cron ticks = %.8f", pattern.runsPerDay, want)
			}
			if pattern.minimumGap != shortest {
				t.Fatalf("expansion's shortest gap = %s; cron's = %s", pattern.minimumGap, shortest)
			}
			offsets := scheduleDayOffsets(pattern.identity.second, pattern.identity.minute, pattern.identity.hour)
			covered := make(map[int64]bool)
			for _, span := range pattern.days {
				if span.days == 0 {
					covered[int64(span.start)] = true
					if len(ticks[int64(span.start)]) == 0 {
						t.Fatalf("day %s, whose ticks the cron schedule gives, has no cron ticks", start.Add(time.Duration(span.start)*time.Second))
					}
					continue
				}
				for day := range int64(span.days) {
					key := int64(span.start) + day*int64(scheduleDay/time.Second)
					covered[key] = true
					dayStart := start.Add(time.Duration(key) * time.Second)
					got := ticks[key]
					if len(got) != len(offsets) {
						t.Fatalf("ordinary day %s has %d cron ticks; want its %d times of day", dayStart, len(got), len(offsets))
					}
					for i, tick := range got {
						if !tick.Equal(dayStart.Add(offsets[i])) {
							t.Fatalf("ordinary day %s ticks at %s; want %s", dayStart, tick, dayStart.Add(offsets[i]))
						}
					}
				}
			}
			for key, dayTicks := range ticks {
				if !covered[key] {
					t.Fatalf("day %s has %d cron ticks but no expanded span", start.Add(time.Duration(key)*time.Second), len(dayTicks))
				}
			}
		})
	}
}

// A run that ends before the schedule's shortest gap between ticks starts
// at every tick, so its projection needs no work and no memo entry, whether
// the schedule ticks more than 20,000 times in the sample or not.
func TestScheduleProjectionOfRunsWithinTheShortestGapTakesNoWork(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, test := range []struct {
		timezone, schedule string
		gap                time.Duration
	}{
		{timezone: "UTC", schedule: "0 * * * *", gap: time.Hour},
		{timezone: "Europe/Amsterdam", schedule: "0 * * * *", gap: time.Hour},
		{timezone: "UTC", schedule: "*/15 * * * *", gap: 15 * time.Minute},
		{timezone: "UTC", schedule: "0 */2 * * *", gap: 2 * time.Hour},
		{timezone: "UTC", schedule: "0 3 * * *", gap: 24 * time.Hour},
		{timezone: "UTC", schedule: "50,55 23 * * *", gap: 5 * time.Minute},
		{timezone: "UTC", schedule: "55 23 * * *", gap: 24 * time.Hour},
		{timezone: "UTC", schedule: "0,30 0 * * *", gap: 30 * time.Minute},
		{timezone: "UTC", schedule: "0 23,0 * * *", gap: time.Hour},
		// 03:00 comes 23 hours after the previous one on the spring day.
		{timezone: "Europe/Amsterdam", schedule: "0 3 * * *", gap: 23 * time.Hour},
		// 02:30 happens twice when the clocks go back.
		{timezone: "Europe/Amsterdam", schedule: "30 2 * * *", gap: time.Hour},
		{timezone: "UTC", schedule: "0 0 * * 1,3", gap: 48 * time.Hour},
	} {
		t.Run(test.timezone+" "+test.schedule, func(t *testing.T) {
			t.Parallel()
			pattern, err := schedulePattern(ctx, test.timezone, test.schedule)
			if err != nil || !pattern.ok {
				t.Fatalf("schedule pattern = %+v, error %v", pattern, err)
			}
			if pattern.minimumGap != test.gap {
				t.Fatalf("shortest gap between ticks = %s, want %s", pattern.minimumGap, test.gap)
			}
			budget := &scanScheduleSimulationBudget{limit: scanScheduleRequestWorkLimit}
			memo := make(map[scanScheduleDurationKey]scanScheduleDurationEstimate)
			for _, run := range []struct {
				seconds       float64
				endsAtTimeout bool
			}{{seconds: test.gap.Seconds() - 1}, {seconds: test.gap.Seconds()}, {seconds: test.gap.Seconds() - 1, endsAtTimeout: true}} {
				runs, skipped, err := memoizedScheduleRunsForDurationWithBudget(ctx, memo, pattern, run.seconds, run.endsAtTimeout, budget)
				if err != nil || skipped || runs != pattern.runsPerDay {
					t.Fatalf("%v-second run = %.4f runs/day, skipped %t, error %v; want every tick, %.4f", run.seconds, runs, skipped, err, pattern.runsPerDay)
				}
			}
			if budget.used != 0 || len(memo) != 0 {
				t.Fatalf("runs within the shortest gap used %d work units and %d memo entries; want none", budget.used, len(memo))
			}
			// A run that its timeout ends at the gap holds the job at the
			// next tick, so it needs a projection.
			if _, skipped, err := memoizedScheduleRunsForDurationWithBudget(ctx, memo, pattern, test.gap.Seconds(), true, budget); err != nil || !skipped {
				t.Fatalf("timeout-ended run of the shortest gap = skipped %t, error %v; want a skipped tick", skipped, err)
			}
		})
	}
}

func TestScanSlotDemandUsesCompletedSingleUnitNmapScanWithoutCycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	job := config.NormalizeJob(config.Job{
		Name:     "single-unit-nmap",
		Schedule: "*/30 * * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.1"},
		TCP:      &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
	})
	record, err := ts.CreateJobWithEnabled(ctx, job, true)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	finished := started.Add(25 * time.Minute)
	if err := db.System().SaveScan(ctx, model.Scan{
		ID: "single-unit-nmap-scan", JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision,
		StartedAt: started, FinishedAt: finished, Status: "success", ScannerEngine: config.EngineNmap,
		ConfigHash: record.Job.SecurityHash(),
	}); err != nil {
		t.Fatal(err)
	}
	var cycles int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_cycles WHERE job_id=?`, record.ID).Scan(&cycles); err != nil {
		t.Fatal(err)
	}
	if cycles != 0 {
		t.Fatalf("single-unit Nmap scan created %d cycle rows, want none", cycles)
	}

	demand, err := (&App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}).ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if demand.HistoryJobs != 1 || demand.LowerBoundJobs != 0 {
		t.Fatalf("history source counts = history %d, lower bound %d; want 1 and 0", demand.HistoryJobs, demand.LowerBoundJobs)
	}
	if got, want := demand.EstimatedSlotSecondsPerDay, float64(20*time.Hour/time.Second); math.Abs(got-want) > 0.01 {
		t.Fatalf("slot demand = %.2f seconds/day, want 25m × 48 runs = %.2f", got, want)
	}
	if demand.UtilizationPercent < 80 || demand.OverCapacity {
		t.Fatalf("capacity comparison = %+v; want an 80%% warning without exceeding one slot", demand)
	}
}

func TestScanSlotDemandUsesTimeoutWhenRecentCurrentKeyRunsTimedOut(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	job := config.NormalizeJob(config.Job{
		Name: "always-times-out", Schedule: "0 * * * *", Timezone: "UTC", Timeout: config.Duration(50 * time.Minute),
		Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
	})
	record, err := ts.CreateJobWithEnabled(ctx, job, true)
	if err != nil {
		t.Fatal(err)
	}
	key := store.NewScanDurationKey(record)
	base := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < scanSlotDemandHistoryLimit; i++ {
		finished := base.Add(time.Duration(i) * time.Hour)
		if err := db.System().SaveScan(ctx, model.Scan{
			ID: fmt.Sprintf("timed-out-demand-%02d", i), JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision,
			StartedAt: finished.Add(-job.Timeout.Value()), FinishedAt: finished, Status: "timed_out", ConfigHash: key.ConfigHash,
			ScannerProfileID: key.ScannerProfileID, ScannerProfileRevision: key.ScannerProfileRevision,
		}); err != nil {
			t.Fatal(err)
		}
	}
	app := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}
	demand, err := app.ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if demand.HistoryJobs != 1 || demand.LowerBoundJobs != 0 || demand.UnestimatedJobs != 0 {
		t.Fatalf("timeout history source counts = %+v; want a history-based timeout estimate", demand)
	}
	if want := float64(20 * time.Hour / time.Second); math.Abs(demand.EstimatedSlotSecondsPerDay-want) > 0.01 {
		t.Fatalf("all-timeout demand = %.2f seconds/day, want 50m × 24 = %.2f", demand.EstimatedSlotSecondsPerDay, want)
	}
	if demand.CadenceUnattainableJobs != 0 {
		t.Fatalf("50-minute runs on an hourly schedule skipped ticks: %+v", demand)
	}

	// A later successful run joins the timed-out ones: the newest 11 runs are
	// one of 15 minutes and ten that ran for the timeout, so each run holds
	// a slot for their mean.
	insertCompletedScan(t, db, record, "successful-demand-after-timeouts", base.Add(12*time.Hour), 15*time.Minute)
	demand, err = app.ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if want := (15 + 10*50) / 11.0 * 60 * 24; demand.HistoryJobs != 1 || math.Abs(demand.EstimatedSlotSecondsPerDay-want) > 0.01 {
		t.Fatalf("demand after a newer successful scan = %+v; want the mean of 15m and ten 50m runs × 24 = %.2f", demand, want)
	}
}

// insertTimedOutScans saves count scans of the record without a cycle that
// ran for its timeout, an hour apart, the newest finishing at newest.
func insertTimedOutScans(t *testing.T, db *store.Store, record store.JobRecord, prefix string, count int, newest time.Time) {
	t.Helper()
	key := store.NewScanDurationKey(record)
	for i := range count {
		finished := newest.Add(-time.Duration(i) * time.Hour)
		if err := db.System().SaveScan(context.Background(), model.Scan{
			ID: fmt.Sprintf("%s-%02d", prefix, i), JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision,
			StartedAt: finished.Add(-record.Job.Timeout.Value()), FinishedAt: finished, Status: "timed_out", ConfigHash: key.ConfigHash,
			ScannerProfileID: key.ScannerProfileID, ScannerProfileRevision: key.ScannerProfileRevision,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// A run that its timeout ends is finalized after the timeout while it still
// holds the job, so the scheduler skips a tick at exactly the timeout. An
// hourly job whose runs time out after an hour therefore runs every other
// hour, while one whose runs time out after 50 minutes keeps its cadence.
func TestScanSlotDemandSkipsTheTickAtWhichATimeoutEndsARun(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		timeout    time.Duration
		wantDemand float64
		wantSkips  int
	}{
		{timeout: time.Hour, wantDemand: 12 * 3600, wantSkips: 1},
		{timeout: 50 * time.Minute, wantDemand: 24 * 50 * 60, wantSkips: 0},
	} {
		t.Run(test.timeout.String(), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			db := storetest.OpenFresh(t)
			ts := defaultTenant(db)
			record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
				Name: "times-out", Schedule: "0 * * * *", Timezone: "UTC", Timeout: config.Duration(test.timeout),
				Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
			}), true)
			if err != nil {
				t.Fatal(err)
			}
			insertTimedOutScans(t, db, record, "timed-out", scanSlotDemandHistoryLimit, time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC))
			demand, err := (&App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}).ScanSlotDemand(ctx, ts)
			if err != nil {
				t.Fatal(err)
			}
			if demand.HistoryJobs != 1 || demand.CadenceUnattainableJobs != test.wantSkips || math.Abs(demand.EstimatedSlotSecondsPerDay-test.wantDemand) > 0.01 {
				t.Fatalf("demand = %+v; want %.0f slot-seconds/day and %d jobs with skipped ticks", demand, test.wantDemand, test.wantSkips)
			}
		})
	}
}

// Jobs that often time out are not nearly free: each timed-out run counts
// at its timeout in the mean over the newest runs.
func TestScanSlotDemandCountsTimedOutRunsAmongMixedHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
		Name: "mostly-times-out", Schedule: "0 * * * *", Timezone: "UTC", Timeout: config.Duration(50 * time.Minute),
		Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
	}), true)
	if err != nil {
		t.Fatal(err)
	}
	newest := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	insertTimedOutScans(t, db, record, "mostly-timed-out", 10, newest.Add(-time.Hour))
	insertCompletedScan(t, db, record, "newest-success", newest, 5*time.Minute)
	demand, err := (&App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}).ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if want := (5 + 10*50) / 11.0 * 60 * 24; demand.HistoryJobs != 1 || demand.CadenceUnattainableJobs != 0 || math.Abs(demand.EstimatedSlotSecondsPerDay-want) > 0.01 {
		t.Fatalf("demand = %+v; want the mean of ten 50m runs and one 5m run × 24 = %.2f", demand, want)
	}
	if demand.EstimatedSlotSecondsPerDay <= 15*3600 {
		t.Fatalf("demand = %.0f slot-seconds/day; want more than 15 slot-hours", demand.EstimatedSlotSecondsPerDay)
	}
}

// A resumable cycle's runs are its attempts: a cycle of a 30-minute attempt
// that its timeout ends and a 5-minute final attempt holds a slot for 17.5
// minutes a run, and neither attempt skips an hourly tick.
func TestScanSlotDemandSpreadsACycleOverItsAttempts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
		Name: "two-attempt-cycles", Schedule: "0 * * * *", Timezone: "UTC", Timeout: config.Duration(30 * time.Minute),
		Targets: []string{"192.0.2.1"},
		TCP:     &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{Rate: 1000}},
	}), true)
	if err != nil {
		t.Fatal(err)
	}
	for i := range scanSlotDemandHistoryLimit {
		insertCycleAttempts(t, db, record, fmt.Sprintf("two-attempt-cycle-%02d", i), time.Date(2026, time.February, 1, 2*i, 0, 0, 0, time.UTC), []time.Duration{30 * time.Minute, 5 * time.Minute}, time.Hour)
	}
	demand, err := (&App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}).ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if want := 24 * 17.5 * 60; demand.HistoryJobs != 1 || demand.CadenceUnattainableJobs != 0 || math.Abs(demand.EstimatedSlotSecondsPerDay-want) > 0.01 {
		t.Fatalf("demand = %+v; want 17.5 minutes a run × 24 = %.0f slot-seconds/day", demand, want)
	}
}

// A resumable job whose first cycle has not completed has only that cycle's
// recorded attempts as runs; when they all timed out, each run lasts its
// timeout, which also ends it.
func TestScanSlotDemandUsesTimeoutForUnfinishedCycleWhoseAttemptsTimedOut(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
		Name: "unfinished-cycle", Schedule: "*/30 * * * *", Timezone: "UTC", Timeout: config.Duration(30 * time.Minute),
		Targets: []string{"192.0.2.1"},
		TCP:     &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{Rate: 1000}},
	}), true)
	if err != nil {
		t.Fatal(err)
	}
	key := store.NewScanDurationKey(record)
	finished := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	stamp := func(value time.Time) string { return value.Format(time.RFC3339Nano) }
	if _, err := db.DB.ExecContext(ctx, `INSERT INTO scan_cycles(id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,attempt_count,total_units,total_probes,started_at,updated_at,expires_at)
		VALUES(?,?,?,?,?,?,?,'paused',3,1,1,?,?,?)`, "unfinished-cycle", record.ID, record.Job.Name, record.Revision, key.ConfigHash, key.ExecutionHash, []byte(`{}`),
		stamp(finished.Add(-3*time.Hour)), stamp(finished), stamp(finished.Add(24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= 3; n++ {
		attemptFinished := finished.Add(-time.Duration(3-n) * time.Hour)
		if err := db.System().SaveScan(ctx, model.Scan{
			ID: fmt.Sprintf("unfinished-cycle-attempt-%d", n), JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision,
			StartedAt: attemptFinished.Add(-30 * time.Minute), FinishedAt: attemptFinished, Status: "timed_out", ConfigHash: key.ConfigHash,
			CycleID: "unfinished-cycle", CycleAttempt: n, CycleStatus: "paused", Resumable: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	demand, err := (&App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}).ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	// Each 30-minute run holds the job past the next half-hourly tick, so the
	// job starts every hour.
	if demand.HistoryJobs != 1 || demand.LowerBoundJobs != 0 || demand.CadenceUnattainableJobs != 1 || math.Abs(demand.EstimatedSlotSecondsPerDay-24*1800) > 0.01 {
		t.Fatalf("demand = %+v; want the 30m timeout × 24 starts and skipped ticks", demand)
	}
}

// A scan without a cycle keeps its samples when its job's timeout changes,
// and a timed-out scan needed at least its old timeout, so after a raise
// each timed-out run counts at the new timeout rather than at the time the
// old one allowed.
func TestScanSlotDemandCountsTimedOutRunsAtTheCurrentTimeout(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
		Name: "raised-timeout", Schedule: "0 */4 * * *", Timezone: "UTC", Timeout: config.Duration(30 * time.Minute),
		Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
	}), true)
	if err != nil {
		t.Fatal(err)
	}
	newest := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	insertTimedOutScans(t, db, record, "timed-out-before-raise", 6, newest.Add(-6*time.Hour))
	app := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}
	demand, err := app.ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if want := 6 * 1800.0; demand.HistoryJobs != 1 || math.Abs(demand.EstimatedSlotSecondsPerDay-want) > 0.01 {
		t.Fatalf("demand before the raise = %+v; want six 30-minute runs a day, %.0f", demand, want)
	}

	job := record.Job
	job.Timeout = config.Duration(2 * time.Hour)
	updated, _, err := ts.UpdateJob(ctx, record.ID, record.Revision, job, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if store.NewScanDurationKey(updated).ConfigHash != store.NewScanDurationKey(record).ConfigHash {
		t.Fatal("a timeout edit changed the scope hash; the samples would not be kept")
	}
	demand, err = app.ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if want := 6 * 7200.0; demand.HistoryJobs != 1 || math.Abs(demand.EstimatedSlotSecondsPerDay-want) > 0.01 {
		t.Fatalf("demand after raising the timeout = %+v; want six runs of the new two-hour timeout a day, %.0f", demand, want)
	}

	// Among successful runs, each timed-out one counts at the new timeout.
	for i := range 5 {
		insertCompletedScan(t, db, updated, fmt.Sprintf("success-after-raise-%d", i), newest.Add(time.Duration(i+1)*time.Hour), 10*time.Minute)
	}
	demand, err = app.ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if want := 6 * (6*7200 + 5*600) / 11.0; demand.HistoryJobs != 1 || math.Abs(demand.EstimatedSlotSecondsPerDay-want) > 0.01 {
		t.Fatalf("demand after newer successes = %+v; want the mean of six 2-hour and five 10-minute runs × 6 = %.2f", demand, want)
	}
}

// insertCycleInProgress records the record's paused cycle in progress with
// the given recorded attempts, which the timeout ended, an hour apart from
// started.
func insertCycleInProgress(t *testing.T, db *store.Store, record store.JobRecord, id string, started time.Time, attempts int) {
	t.Helper()
	key := store.NewScanDurationKey(record)
	stamp := func(value time.Time) string { return value.Format(time.RFC3339Nano) }
	last := started.Add(time.Duration(attempts) * time.Hour)
	if _, err := db.DB.Exec(`INSERT INTO scan_cycles(id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,attempt_count,total_units,total_probes,started_at,updated_at,expires_at)
		VALUES(?,?,?,?,?,?,?,'paused',?,1,1,?,?,?)`, id, record.ID, record.Job.Name, record.Revision, key.ConfigHash, key.ExecutionHash, []byte(`{}`),
		attempts, stamp(started), stamp(last), stamp(last.Add(48*time.Hour))); err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= attempts; n++ {
		attemptStarted := started.Add(time.Duration(n-1) * time.Hour)
		if err := db.System().SaveScan(context.Background(), model.Scan{
			ID: fmt.Sprintf("%s-attempt-%02d", id, n), JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision,
			StartedAt: attemptStarted, FinishedAt: attemptStarted.Add(record.Job.Timeout.Value()), Status: "timed_out", ConfigHash: key.ConfigHash,
			CycleID: id, CycleAttempt: n, CycleStatus: "paused", Resumable: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// The recorded attempts of a resumable job's cycle in progress are its
// newest runs. When its newest runs all timed out, every run counts at its
// timeout, whatever its older completed cycles took; otherwise the attempts
// of the cycle in progress join the mean over its runs.
func TestScanSlotDemandCountsTheAttemptsOfTheCycleInProgress(t *testing.T) {
	t.Parallel()
	create := func(t *testing.T, db *store.Store, name string) store.JobRecord {
		t.Helper()
		record, err := defaultTenant(db).CreateJobWithEnabled(context.Background(), config.NormalizeJob(config.Job{
			Name: name, Schedule: "0 * * * *", Timezone: "UTC", Timeout: config.Duration(30 * time.Minute),
			Targets: []string{"192.0.2.1"},
			TCP:     &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{Rate: 1000}},
		}), true)
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	demand := func(t *testing.T, db *store.Store) ScanSlotDemand {
		t.Helper()
		demand, err := (&App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}).ScanSlotDemand(context.Background(), defaultTenant(db))
		if err != nil {
			t.Fatal(err)
		}
		return demand
	}
	t.Run("newest runs all timed out", func(t *testing.T) {
		t.Parallel()
		db := storetest.OpenFresh(t)
		record := create(t, db, "stuck-cycle")
		// An older cycle of a timed-out attempt and a 5-minute final one,
		// then a cycle in progress whose 11 attempts all timed out.
		insertCycleAttempts(t, db, record, "older-cycle", time.Date(2026, time.February, 1, 1, 5, 0, 0, time.UTC), []time.Duration{30 * time.Minute, 5 * time.Minute}, time.Hour)
		insertCycleInProgress(t, db, record, "stuck-in-progress", time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC), scanSlotDemandHistoryLimit)
		if got := demand(t, db); got.HistoryJobs != 1 || math.Abs(got.EstimatedSlotSecondsPerDay-24*1800) > 0.01 {
			t.Fatalf("demand = %+v; want every hourly run at the 30-minute timeout, 43200 slot-seconds/day", got)
		}
	})
	t.Run("some newest runs timed out", func(t *testing.T) {
		t.Parallel()
		db := storetest.OpenFresh(t)
		record := create(t, db, "slowing-cycle")
		for i := range 10 {
			insertCycleAttempts(t, db, record, fmt.Sprintf("completed-cycle-%02d", i), time.Date(2026, time.February, 1, i, 10, 0, 0, time.UTC), []time.Duration{10 * time.Minute}, time.Hour)
		}
		insertCycleInProgress(t, db, record, "slowing-in-progress", time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC), 2)
		// Ten 10-minute runs and two 30-minute ones.
		if got, want := demand(t, db), 24*(10*600+2*1800)/12.0; got.HistoryJobs != 1 || got.CadenceUnattainableJobs != 0 || math.Abs(got.EstimatedSlotSecondsPerDay-want) > 0.01 {
			t.Fatalf("demand = %+v; want the mean of ten 10-minute runs and the cycle in progress's two 30-minute ones × 24 = %.0f", got, want)
		}
	})
}

func TestScanSlotDemandIgnoresEarlierScanSettingsSamplesAfterScopeAndRateEdit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	job := config.NormalizeJob(config.Job{
		Name:     "revision-demand",
		Schedule: "*/30 * * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.1"},
		TCP:      &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{Rate: 1000}},
	})
	record, err := ts.CreateJobWithEnabled(ctx, job, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < scanSlotDemandHistoryLimit; i++ {
		insertCompletedCycle(t, db, record, fmt.Sprintf("old-revision-demand-%02d", i), time.Second)
	}
	app := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}
	before, err := app.ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if before.HistoryJobs != 1 || before.LowerBoundJobs != 0 || before.OverCapacity {
		t.Fatalf("demand before revision edit = %+v; want short history to be used", before)
	}

	changedJob := record.Job
	changedJob.Targets = []string{"192.0.2.0/24"}
	changedJob.TCP = &config.Protocol{
		Engine: config.EngineNaabuNmap,
		Ports:  "1-65535",
		Naabu:  &config.NaabuOptions{Rate: 100},
	}
	updated, _, err := ts.UpdateJob(ctx, record.ID, record.Revision, changedJob, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision == record.Revision {
		t.Fatalf("material scope/rate edit kept revision %d", record.Revision)
	}

	after, err := app.ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	lowerBound, hasBound, _ := scanRateLowerBound(updated.Job, config.DefaultMaxJobHosts)
	runsPerDay, ok := scanJobRunsPerDay(updated.Job, app.Config.Timezone)
	if !hasBound || !ok {
		t.Fatalf("updated job lower bound/schedule = %.2f seconds, known %v, schedule valid %v", lowerBound, hasBound, ok)
	}
	// The /24 at 100 probes per second takes about 46 hours a run. Its
	// one-hour timeout ends each run sooner, but the run still holds the job
	// at the tick an hour after its start, so the job starts every 90
	// minutes, 16 times a day, and cannot keep its half-hourly cadence.
	if lowerBound <= updated.Job.Timeout.Value().Seconds() || runsPerDay != 48 {
		t.Fatalf("updated job lower bound = %.2f seconds a run at %.0f runs/day, want more than its timeout", lowerBound, runsPerDay)
	}
	if after.HistoryJobs != 0 || after.LowerBoundJobs != 1 || math.Abs(after.EstimatedSlotSecondsPerDay-16*3600) > 0.01 || after.CadenceUnattainableJobs != 1 {
		t.Fatalf("demand after scope/rate edit = %+v; want 16 one-hour runs of the current lower bound and its job counted as unable to keep its cadence", after)
	}
	if math.Abs(after.UtilizationPercent-200.0/3) > 0.01 || after.OverCapacity {
		t.Fatalf("capacity warning after scope/rate edit = %+v; want two thirds of its one slot", after)
	}
}

func TestScanSlotDemandSumsRateLowerBoundsAgainstCapacity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	// Each run's lower bound, about 4.66 hours, fits its six-hour timeout,
	// so the timeout does not shorten it.
	job := config.NormalizeJob(config.Job{
		Name:     "full-tcp-00",
		Schedule: "0 */6 * * *",
		Timezone: "UTC",
		Timeout:  config.Duration(6 * time.Hour),
		Targets:  []string{"192.0.2.0/24"},
		TCP:      &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{Rate: 1000}},
	})
	for i := 0; i < 16; i++ {
		job.Name = fmt.Sprintf("full-tcp-%02d", i)
		if _, err := ts.CreateJobWithEnabled(ctx, job, true); err != nil {
			t.Fatal(err)
		}
	}

	demand, err := (&App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}).ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	gotHours := demand.EstimatedSlotSecondsPerDay / 3600
	if demand.EnabledJobs != 16 || demand.LowerBoundJobs != 16 || !demand.OverCapacity || math.Abs(gotHours-298.257) > 0.02 {
		t.Fatalf("16-job demand = %+v (%.3f slot-hours/day), want about 298.26 against 24 and over capacity", demand, gotHours)
	}
	if demand.UnestimatedJobs != 16 {
		t.Fatalf("lower-bound jobs with unbounded Nmap enrichment = %d, want 16", demand.UnestimatedJobs)
	}
}

func TestScanSlotDemandDoesNotWarnForScopesRejectedByHostLimits(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name                string
		jobMaxExpandedHosts int
		deploymentMaxHosts  int
	}{
		{name: "default job limit", deploymentMaxHosts: config.DefaultMaxJobHosts},
		{name: "deployment limit", jobMaxExpandedHosts: 65_536, deploymentMaxHosts: 256},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			db := storetest.OpenFresh(t)
			ts := defaultTenant(db)
			job := config.NormalizeJob(config.Job{
				Name:             "over-limit",
				Schedule:         "0 0 * * *",
				Timezone:         "UTC",
				Targets:          []string{"10.0.0.0/16"},
				MaxExpandedHosts: test.jobMaxExpandedHosts,
				TCP:              &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{Rate: 1000}},
			})
			if test.name == "default job limit" && job.MaxExpandedHosts != 256 {
				t.Fatalf("default max_expanded_hosts = %d, want 256", job.MaxExpandedHosts)
			}
			if _, err := ts.CreateJobWithEnabled(ctx, job, true); err != nil {
				t.Fatal(err)
			}
			deploymentMaxHosts := test.deploymentMaxHosts
			app := &App{Store: db, Config: &config.Config{
				Scheduler: config.Scheduler{MaxConcurrent: 1},
				Scanner:   config.ScannerConfig{MaxJobHosts: &deploymentMaxHosts},
			}}

			demand, err := app.ScanSlotDemand(ctx, ts)
			if err != nil {
				t.Fatal(err)
			}
			if demand.EstimatedSlotSecondsPerDay != 0 || demand.LowerBoundJobs != 0 || demand.OverCapacity {
				t.Fatalf("over-limit scope produced slot demand %+v; scanner rejects it before sending probes", demand)
			}
		})
	}
}

func TestScanSlotDemandUsesCompletedCycleTimeAfterRecoveryBeforeFinalization(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	job := config.NormalizeJob(config.Job{
		Name: "recovered-first-cycle", Schedule: "*/30 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.1"},
		TCP:     &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{Rate: 1000}},
	})
	record, err := ts.CreateJobWithEnabled(ctx, job, true)
	if err != nil {
		t.Fatal(err)
	}
	changedJob := record.Job
	changedJob.TCP = &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{Rate: 500}}
	current, _, err := ts.UpdateJob(ctx, record.ID, record.Revision, changedJob, true, false, true)
	if err != nil {
		t.Fatal(err)
	}

	plan := scanner.WorkPlan{
		Job:   current.Job,
		Units: []scanner.WorkUnit{{Sequence: 0, Engine: config.EngineNaabuNmap, Phase: "discovery", Protocol: "tcp", Family: 4, Addresses: []string{"192.0.2.1"}, Ports: "1-65535", PortCount: 65535, Probes: 65535}},
	}
	cycle, err := db.System().CreateScanCycle(ctx, store.ScanCycleRecord{
		JobID: current.ID, Job: current.Job.Name, JobRevision: current.Revision,
		ConfigHash: current.Job.SecurityHash(), ExecutionHash: current.Job.ExecutionHash(), Plan: plan,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.System().StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	unit, err := db.System().NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.System().ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := db.System().CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, model.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	// Model a long-running first attempt, then the crash window after the
	// completed-cycle commit and before finalization persists a scan row.
	attemptStarted := time.Now().UTC().Add(-2 * time.Hour)
	stamp := func(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
	if _, err := db.DB.ExecContext(ctx, `UPDATE scan_cycles SET attempt_started_at=? WHERE id=?`, stamp(attemptStarted), cycle.ID); err != nil {
		t.Fatal(err)
	}
	cycle, err = db.System().CompleteScanCycle(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	recoveryStarted := cycle.FinishedAt.Add(time.Minute)
	scan := model.Scan{
		ID: "recovered-cycle-scan", JobID: current.ID, Job: current.Job.Name,
		JobRevision: current.Revision, ConfigHash: current.Job.SecurityHash(), StartedAt: recoveryStarted,
	}
	handled, _, err := (&App{Store: db}).recoverCompletedCycle(ctx, &scan, nil, cycle)
	if err != nil || !handled {
		t.Fatalf("recover completed cycle = handled %t, error %v", handled, err)
	}
	if !scan.StartedAt.Equal(attemptStarted) || !scan.FinishedAt.Equal(cycle.FinishedAt) {
		t.Fatalf("recovered scan interval = %s to %s; want scanner attempt %s to cycle finish %s", scan.StartedAt, scan.FinishedAt, attemptStarted, cycle.FinishedAt)
	}
	setScanFinishedAt(&scan, recoveryStarted.Add(time.Second))
	if !scan.FinishedAt.Equal(cycle.FinishedAt) {
		t.Fatalf("finalization replaced completed-cycle finish with recovery time %s", scan.FinishedAt)
	}
	if err := db.System().SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}

	app := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}
	demand, err := app.ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	// The two-hour attempt outlasts the one-hour timeout, which ends each
	// run while it holds the job at the tick an hour after its start, so the
	// half-hourly job starts every 90 minutes, 16 times a day.
	if attempt := cycle.FinishedAt.Sub(attemptStarted); attempt <= current.Job.Timeout.Value() {
		t.Fatalf("recovered attempt = %s, want more than the %s timeout", attempt, current.Job.Timeout.Value())
	}
	if demand.HistoryJobs != 1 || demand.LowerBoundJobs != 0 || math.Abs(demand.EstimatedSlotSecondsPerDay-16*3600) > 0.01 || demand.CadenceUnattainableJobs != 1 {
		t.Fatalf("recovered cycle demand = %+v; want the completed attempt duration %s counted as 16 one-hour runs", demand, cycle.FinishedAt.Sub(attemptStarted))
	}
	if math.Abs(demand.UtilizationPercent-200.0/3) > 0.01 || demand.OverCapacity {
		t.Fatalf("recovered cycle demand = %+v; want two thirds of a slot from the completed attempt", demand)
	}
}

func TestScanJobRunsPerDayUsesSixHourlySchedule(t *testing.T) {
	t.Parallel()
	job := config.Job{Schedule: "0 */6 * * *", Timezone: "UTC"}
	if got, ok := scanJobRunsPerDay(job, ""); !ok || math.Abs(got-4) > 0.001 {
		t.Fatalf("six-hourly schedule = %.4f runs/day, valid %v; want 4", got, ok)
	}
}

func TestScanSlotDemandReturnsTenantAndStorageErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if _, err := (*App)(nil).ScanSlotDemand(ctx, nil); !errors.Is(err, store.ErrNoTenantScope) {
		t.Fatalf("nil app error = %v, want ErrNoTenantScope", err)
	}
	if _, err := (&App{}).ScanSlotDemand(ctx, nil); !errors.Is(err, store.ErrNoTenantScope) {
		t.Fatalf("nil tenant store error = %v, want ErrNoTenantScope", err)
	}
	db := storetest.OpenFresh(t)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err := (&App{Store: db}).ScanSlotDemand(canceled, defaultTenant(db))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled list-jobs error = %v, want context.Canceled", err)
	}
}

// Every recorded attempt is a run at its duration up to the timeout, which
// ends it, and an attempt that timed out is a run of the current timeout
// whatever it recorded; a cycle's unrecorded attempts are runs without slot
// time.
func TestHistoryDemandRunsCountEachAttemptUpToTheTimeout(t *testing.T) {
	t.Parallel()
	attempts := func(durations ...time.Duration) []store.ScanDurationAttempt {
		out := make([]store.ScanDurationAttempt, len(durations))
		for i, duration := range durations {
			out[i] = store.ScanDurationAttempt{Duration: duration}
		}
		return out
	}
	samples := []store.ScanDurationSample{
		{Attempts: attempts(10 * time.Minute), Runs: 1},
		{Attempts: attempts(90*time.Minute, 30*time.Minute), Runs: 3},
		{Attempts: attempts(time.Hour), Runs: 1},
		{Attempts: attempts(10 * time.Minute), Runs: 1},
		// A timeout of 30 minutes, since raised to the hour, ended it.
		{Attempts: []store.ScanDurationAttempt{{Duration: 30 * time.Minute, TimedOut: true}}, Runs: 1},
	}
	runs := historyDemandRuns(samples, time.Hour.Seconds())
	want := []scanDemandRun{
		{seconds: 0, weight: 1},
		{seconds: 600, weight: 2},
		{seconds: 1800, weight: 1},
		{seconds: 3600, endsAtTimeout: true, weight: 3},
	}
	if !reflect.DeepEqual(runs, want) {
		t.Fatalf("history runs = %+v, want %+v", runs, want)
	}
	// Without a timeout, a timed-out attempt is a run of what it recorded.
	if runs := historyDemandRuns(samples[4:], 0); !reflect.DeepEqual(runs, []scanDemandRun{{seconds: 1800, weight: 1}}) {
		t.Fatalf("history runs without a timeout = %+v, want one 30-minute run", runs)
	}
}

// A job's runs start as often as their mean time from one start to the next
// allows, and each holds a slot for their mean slot time.
func TestProjectScanDemandRunsCombinesRunsByTheirTimeBetweenStarts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pattern, err := schedulePattern(ctx, "UTC", "0 * * * *")
	if err != nil || !pattern.ok {
		t.Fatalf("hourly pattern = %+v, error %v", pattern, err)
	}
	work := newScanDemandWork(nil, nil)
	project := func(run scanDemandRun) (float64, bool, error) {
		return work.project(ctx, pattern, run, work.budget, false)
	}
	// A cycle of an attempt that its one-hour timeout ends, which skips the
	// next tick, and a 10-minute final attempt starts twice in three hours.
	demand, skipped, err := projectScanDemandRuns([]scanDemandRun{
		{seconds: 3600, endsAtTimeout: true, weight: 1},
		{seconds: 600, weight: 1},
	}, project)
	if err != nil {
		t.Fatal(err)
	}
	if want := 16 * 35 * 60.0; !skipped || math.Abs(demand-want) > 0.01 {
		t.Fatalf("mixed demand = %.2f, skipped %t; want 16 starts a day × 35 minutes = %.0f and a skipped tick", demand, skipped, want)
	}
	if demand, skipped, err := projectScanDemandRuns(nil, project); err != nil || demand != 0 || skipped {
		t.Fatalf("demand without runs = %.2f, skipped %t, error %v; want none", demand, skipped, err)
	}
	if demand, skipped, err := projectScanDemandRuns([]scanDemandRun{{weight: 2}}, project); err != nil || demand != 0 || skipped {
		t.Fatalf("demand of runs without slot time = %.2f, skipped %t, error %v; want none", demand, skipped, err)
	}

}

// A first-pass projection gets at most its job's share of work. One whose
// schedule's known work exceeds that share waits for the second pass without
// spending any. One that runs out of the share waits too, and the other
// jobs' projections of the same run or schedule wait without spending it
// again. A projection that needs more than a job's whole limit fails for
// every job, and once half of the request's work is spent the first pass
// gives no projection a share.
func TestScanDemandWorkSparesTheFirstPassShareAndTheRequestBound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	share := func(work *scanDemandWork, limit int) *scanScheduleSimulationBudget {
		return &scanScheduleSimulationBudget{limit: limit, parent: work.budget}
	}
	dense, err := schedulePattern(ctx, "Europe/Amsterdam", "*/2 * * * *")
	if err != nil || !dense.ok || dense.projectionFloor <= scanScheduleJobFirstPassWorkLimit {
		t.Fatalf("dense pattern = %+v, error %v; want known work over a first-pass share", dense, err)
	}
	work := newScanDemandWork(nil, nil)
	slow := scanDemandRun{seconds: 180, weight: 1}
	if _, _, err := work.project(ctx, dense, slow, share(work, scanScheduleJobFirstPassWorkLimit), true); !errors.Is(err, errScanDemandDeferred) || work.budget.used != 0 {
		t.Fatalf("first-pass dense projection = error %v after %d work units; want it deferred without work", err, work.budget.used)
	}
	runs, skipped, err := work.project(ctx, dense, slow, share(work, scanScheduleJobWorkLimit), false)
	if err != nil || !skipped || math.Abs(runs-360) > 0.01 {
		t.Fatalf("second-pass dense projection = %.4f runs/day, skipped %t, error %v; want 360 and skipped", runs, skipped, err)
	}
	if work.budget.used < dense.projectionFloor {
		t.Fatalf("dense projection used %d work units, less than its known work %d", work.budget.used, dense.projectionFloor)
	}

	// An hourly schedule with daylight saving: its 61-minute runs need a
	// little more than its known work.
	hourly, err := schedulePattern(ctx, "Europe/Amsterdam", "0 * * * *")
	if err != nil || !hourly.ok {
		t.Fatalf("hourly pattern = %+v, error %v", hourly, err)
	}
	tight := hourly.projectionFloor + 1
	work = newScanDemandWork(nil, nil)
	first := scanDemandRun{seconds: 61 * 60, weight: 1}
	if _, _, err := work.project(ctx, hourly, first, share(work, tight), true); !errors.Is(err, errScanDemandDeferred) || work.budget.used != tight {
		t.Fatalf("first-pass projection over its share = error %v after %d work units; want it deferred after the share, %d", err, work.budget.used, tight)
	}
	// The same run of a few seconds more, and another run on the schedule,
	// wait without spending another share.
	for _, run := range []scanDemandRun{{seconds: 61*60 - 30, weight: 1}, {seconds: 71 * 60, weight: 1}} {
		if _, _, err := work.project(ctx, hourly, run, share(work, tight), true); !errors.Is(err, errScanDemandDeferred) || work.budget.used != tight {
			t.Fatalf("first-pass projection of %.0f seconds after a deferred one = error %v after %d work units; want it deferred without work", run.seconds, err, work.budget.used)
		}
	}
	if runs, _, err := work.project(ctx, hourly, first, share(work, scanScheduleJobWorkLimit), false); err != nil || math.Abs(runs-12) > 0.01 {
		t.Fatalf("second-pass hourly projection = %.4f runs/day, error %v; want 12", runs, err)
	}

	// A projection that needs more than a job's whole limit fails for the
	// next job without spending it again.
	work = newScanDemandWork(nil, nil)
	if _, _, err := work.project(ctx, hourly, first, share(work, tight), false); !errors.Is(err, errScheduleSimulationBudgetExceeded) || work.budget.used != tight {
		t.Fatalf("second-pass projection over its limit = error %v after %d work units; want it exceeded after the limit", err, work.budget.used)
	}
	if _, _, err := work.project(ctx, hourly, first, share(work, scanScheduleJobWorkLimit), false); !errors.Is(err, errScheduleSimulationBudgetExceeded) || work.budget.used != tight {
		t.Fatalf("second projection of a run over the limit = error %v after %d work units; want it exceeded without work", err, work.budget.used)
	}
	// A projection that the request's remaining work cannot cover fails at
	// once in either pass.
	work = newScanDemandWork(nil, &scanScheduleSimulationBudget{limit: hourly.projectionFloor - 1})
	for _, firstPass := range []bool{true, false} {
		if _, _, err := work.project(ctx, hourly, first, share(work, scanScheduleJobWorkLimit), firstPass); !errors.Is(err, errScheduleSimulationBudgetExceeded) || work.budget.used != 0 {
			t.Fatalf("projection beyond the request's work, first pass %t = error %v after %d work units; want it exceeded without work", firstPass, err, work.budget.used)
		}
	}

	// Once half of the request's work is spent, the first pass gives no
	// share, and the second pass projects the job.
	work = newScanDemandWork(nil, &scanScheduleSimulationBudget{limit: 4 * hourly.projectionFloor})
	work.budget.used = work.firstPassLimit
	if _, _, err := work.project(ctx, hourly, first, share(work, scanScheduleJobFirstPassWorkLimit), true); !errors.Is(err, errScanDemandDeferred) || work.budget.used != work.firstPassLimit {
		t.Fatalf("first-pass projection after half of the request = error %v after %d work units; want it deferred without work", err, work.budget.used-work.firstPassLimit)
	}
	if runs, _, err := work.project(ctx, hourly, first, share(work, scanScheduleJobWorkLimit), false); err != nil || math.Abs(runs-12) > 0.01 {
		t.Fatalf("second-pass projection after half of the request = %.4f runs/day, error %v; want 12", runs, err)
	}
}

func TestScanJobRunsPerDayHandlesFallbackInvalidAndDenseSchedules(t *testing.T) {
	t.Parallel()
	t.Run("timezone fallbacks", func(t *testing.T) {
		job := config.Job{Schedule: "0 */6 * * *", Timezone: "  "}
		if got, ok := scanJobRunsPerDay(job, " "); !ok || math.Abs(got-4) > 0.001 {
			t.Fatalf("UTC fallback schedule = %.4f runs/day, valid %v; want 4", got, ok)
		}
		if got, ok := scanJobRunsPerDay(config.Job{Schedule: job.Schedule}, "America/New_York"); !ok || math.Abs(got-4) > 0.001 {
			t.Fatalf("default timezone schedule = %.4f runs/day, valid %v; want 4", got, ok)
		}
	})
	t.Run("invalid timezone and cron", func(t *testing.T) {
		if _, ok := scanJobRunsPerDay(config.Job{Schedule: "0 * * * *", Timezone: "Mars/Olympus"}, "UTC"); ok {
			t.Fatal("invalid job timezone was accepted")
		}
		if _, ok := scanJobRunsPerDay(config.Job{Schedule: "not cron", Timezone: "UTC"}, ""); ok {
			t.Fatal("invalid cron schedule was accepted")
		}
	})
	t.Run("dense schedule", func(t *testing.T) {
		got, ok := scanJobRunsPerDay(config.Job{Schedule: "* * * * *"}, "")
		if !ok || got < 1440 || got > 1441 {
			t.Fatalf("dense schedule = %.4f runs/day, valid %v; want about 1440", got, ok)
		}
	})
}

func TestScanJobRunsPerDayCountsDenseCalendarScheduleAcrossFourYearCycle(t *testing.T) {
	t.Parallel()
	pattern, err := schedulePattern(context.Background(), "UTC", "* * 1-15 * *")
	if err != nil || !pattern.ok {
		t.Fatalf("dense calendar schedule pattern = %+v, error %v; want a valid four-year estimate", pattern, err)
	}
	// The schedule runs every minute for the first 15 days of each month:
	// 720 active days × 1,440 ticks divided by the 1,461-day sample.
	if got, want := pattern.runsPerDay, float64(720*24*60)/1461; math.Abs(got-want) > 0.001 {
		t.Fatalf("dense calendar schedule = %.4f runs/day; want the four-year average %.4f", got, want)
	}
	// The pattern keeps one span of days for each month's first 15 days, not
	// its million ticks.
	if len(pattern.days) != 48 {
		t.Fatalf("dense calendar schedule retained %d day spans; want one for each of the 48 months", len(pattern.days))
	}
	runs, skipped, err := pattern.runsForDuration(context.Background(), (15 * time.Minute).Seconds(), false)
	if err != nil {
		t.Fatal(err)
	}
	if want := float64(720*24*4) / 1461; math.Abs(runs-want) > 0.001 || !skipped {
		t.Fatalf("dense calendar schedule with 15m runs = %.4f starts/day, skipped %t; want %.4f and skipped", runs, skipped, want)
	}
}

func TestLeapDayScheduleUsesFourYearLongRunAverage(t *testing.T) {
	t.Parallel()
	for _, timezone := range []string{"UTC", "America/New_York", "Australia/Lord_Howe"} {
		t.Run(timezone, func(t *testing.T) {
			t.Parallel()
			pattern, err := schedulePattern(context.Background(), timezone, "0 0 29 2 *")
			if err != nil || !pattern.ok {
				t.Fatalf("leap-day schedule = %+v, error %v", pattern, err)
			}
			want := 1 / (pattern.windowSeconds / float64(24*time.Hour/time.Second))
			if math.Abs(pattern.runsPerDay-want) > 1e-9 {
				t.Fatalf("leap-day schedule = %.8f runs/day; want the four-year average %.8f", pattern.runsPerDay, want)
			}
		})
	}
}

func TestDenseScheduleDemandMemoizesByNormalizedScheduleAndDuration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	first, err := schedulePattern(ctx, "UTC", "* * 1-15 * *")
	if err != nil || !first.ok {
		t.Fatalf("first dense schedule = %+v, error %v", first, err)
	}
	second, err := schedulePattern(ctx, "UTC", "0-59 0-23 1-15 * *")
	if err != nil || !second.ok {
		t.Fatalf("equivalent dense schedule = %+v, error %v", second, err)
	}
	if first.identity != second.identity {
		t.Fatalf("equivalent cron expressions have different identities: %+v != %+v", first.identity, second.identity)
	}
	cache := make(map[scanScheduleDurationKey]scanScheduleDurationEstimate)
	budget := &scanScheduleSimulationBudget{limit: scanScheduleRequestWorkLimit}

	const jobs = 100
	var gotRuns float64
	var gotSkipped bool
	for i := 0; i < jobs; i++ {
		pattern := first
		if i%2 != 0 {
			pattern = second
		}
		gotRuns, gotSkipped, err = memoizedScheduleRunsForDurationWithBudget(ctx, cache, pattern, 15*60, false, budget)
		if err != nil {
			t.Fatal(err)
		}
	}
	if math.Abs(gotRuns-float64(720*24*4)/1461) > 0.001 || !gotSkipped {
		t.Fatalf("100 dense jobs with 15m runs = %.4f starts/day, skipped %t; want %.4f and skipped", gotRuns, gotSkipped, float64(720*24*4)/1461)
	}
	if len(cache) != 1 {
		t.Fatalf("memoized %d schedule-duration pairs, want one normalized pair", len(cache))
	}
	if budget.used == 0 || budget.used > scanScheduleRequestWorkLimit {
		t.Fatalf("100 equivalent dense jobs used %d request work units; want a positive count at most %d", budget.used, scanScheduleRequestWorkLimit)
	}
	workAfterFirstProjection := budget.used
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := memoizedScheduleRunsForDurationWithBudget(canceled, cache, first, 15*60, false, budget); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled cached schedule estimate error = %v; want context.Canceled", err)
	}
	if budget.used != workAfterFirstProjection {
		t.Fatalf("canceled cached estimate used %d more request work units", budget.used-workAfterFirstProjection)
	}
}

func TestScheduleSimulationBudgetPreservesCancellationWhenExhausted(t *testing.T) {
	t.Parallel()
	pattern, err := schedulePattern(context.Background(), "UTC", "*/5 0 * * *")
	if err != nil || !pattern.ok {
		t.Fatalf("dense schedule pattern = %+v, error %v", pattern, err)
	}
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Let memo lookup and run projection begin, then cancel after the empty
	// budget refuses its first Schedule.Next call.
	ctx := &cancelAfterContextChecks{Context: base, cancel: cancel, remaining: 2}
	budget := &scanScheduleSimulationBudget{limit: 0}
	if _, _, err := memoizedScheduleRunsForDurationWithBudget(ctx, make(map[scanScheduleDurationKey]scanScheduleDurationEstimate), pattern, 6*60, false, budget); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation at exhausted schedule budget = %v; want context.Canceled", err)
	}
}

func TestScanJobScheduleTreatsNeverFiringCronAsUnestimatedPromptly(t *testing.T) {
	t.Parallel()
	app := &App{Config: &config.Config{}}
	job := config.Job{Schedule: "0 3 30 2 *", Timezone: "UTC"}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	type result struct {
		value scanRunsPerDayValue
		err   error
	}
	done := make(chan result, 1)
	started := time.Now()
	go func() {
		value, err := app.scanJobSchedule(ctx, job)
		done <- result{value: value, err: err}
	}()
	select {
	case got := <-done:
		if got.err != nil || got.value.ok {
			t.Fatalf("never-firing schedule returned %+v, error %v; want unestimated without an error", got.value, got.err)
		}
		if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
			t.Fatalf("never-firing schedule took %s to classify; want prompt completion", elapsed)
		}
	case <-ctx.Done():
		t.Fatalf("never-firing schedule did not return promptly: %v", ctx.Err())
	}

	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := app.scanJobSchedule(canceled, job); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled never-firing schedule error = %v; want context.Canceled", err)
	}
}

type cancelAfterContextChecks struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (ctx *cancelAfterContextChecks) Err() error {
	if ctx.remaining == 0 {
		ctx.cancel()
	} else {
		ctx.remaining--
	}
	return ctx.Context.Err()
}

func TestScanJobSchedulePropagatesCancellationDuringExpansion(t *testing.T) {
	t.Parallel()
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Checks one through five reach the first sample day; cancel at the next
	// day boundary while countScheduleRunsInWindow is still active.
	ctx := &cancelAfterContextChecks{Context: base, cancel: cancel, remaining: 5}
	app := &App{Config: &config.Config{}}

	if _, err := app.scanJobSchedule(ctx, config.Job{Schedule: "0 0 1 1 *", Timezone: "UTC"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation during schedule expansion error = %v; want context.Canceled", err)
	}
	if got := len(app.scanSlotDemand.runsPerDay); got != 0 {
		t.Fatalf("canceled schedule expansion cached %d entries; want none", got)
	}
}

func TestScheduleSimulationStopsOnZeroNextAndPreservesCancellation(t *testing.T) {
	t.Parallel()
	schedule, err := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow).Parse("0 3 30 2 *")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	for _, endsAtTimeout := range []bool{false, true} {
		if _, err := simulateSchedulePrefix(ctx, schedule, start, time.Minute, endsAtTimeout); !errors.Is(err, errInvalidScanSchedulePattern) {
			t.Fatalf("prefix simulation for a never-firing schedule error = %v; want invalid schedule", err)
		}
	}
	// An irregular day of a schedule that never fires again simply has no
	// ticks.
	if starts, skipped, _, _, err := simulateScheduleSpan(ctx, schedule, start.Add(-time.Nanosecond), start, end, time.Time{}, time.Minute, false); err != nil || starts != 0 || skipped {
		t.Fatalf("span simulation for a never-firing schedule = %d starts, skipped %t, error %v; want none", starts, skipped, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	hourly, err := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow).Parse("0 * * * *")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := simulateSchedulePrefix(canceled, hourly, start, time.Hour, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled prefix simulation error = %v; want context.Canceled", err)
	}
	if _, _, _, _, err := simulateScheduleSpan(canceled, hourly, start.Add(-time.Nanosecond), start, end, time.Time{}, time.Minute, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled span simulation error = %v; want context.Canceled", err)
	}
	walk := scheduleDayWalk{offsets: []time.Duration{0, time.Hour}, run: 90 * time.Minute, days: make(map[int]scheduleDayResult)}
	if _, _, _, err := walk.ordinaryDays(canceled, start, 3, time.Time{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ordinary-day walk error = %v; want context.Canceled", err)
	}
}

func TestScanJobScheduleTreatsInvalidSettingsAsUnestimated(t *testing.T) {
	t.Parallel()
	app := &App{Config: &config.Config{}}
	for _, job := range []config.Job{
		{Schedule: "0 * * * *", Timezone: "Mars/Olympus"},
		{Schedule: "not cron", Timezone: "UTC"},
	} {
		value, err := app.scanJobSchedule(context.Background(), job)
		if err != nil || value.ok {
			t.Fatalf("invalid job schedule returned %+v, error %v; want an unestimated value without a fatal error", value, err)
		}
	}
}

func TestScanSlotDemandDoesNotCountManualOnlyJobsAsUnestimated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	job := config.NormalizeJob(config.Job{
		Name:     "manual-only",
		Schedule: "0 */6 * * *",
		Targets:  []string{"192.0.2.1"},
		TCP:      &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{Rate: 1000}},
	})
	if _, err := ts.CreateJobWithEnabled(ctx, job, false); err != nil {
		t.Fatal(err)
	}

	demand, err := (&App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}).ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if demand.EnabledJobs != 0 || demand.EstimatedSlotSecondsPerDay != 0 || demand.UnestimatedJobs != 0 {
		t.Fatalf("manual-only job demand = %+v; want no enabled, scheduled, or unestimated demand", demand)
	}
}

func TestScanRateLowerBoundUsesOnlyGuaranteedNmapProbeWork(t *testing.T) {
	t.Parallel()
	job := config.Job{
		Targets: []string{"192.0.2.1"},
		TCP: &config.Protocol{
			Engine:           config.EngineNmap,
			Ports:            "443",
			ServiceDetection: true,
			NmapArgs:         []string{"--max-rate", "100"},
		},
	}
	seconds, hasBound, incomplete := scanRateLowerBound(job, config.DefaultMaxJobHosts)
	if !hasBound || !incomplete || math.Abs(seconds-0.01) > 0.000001 {
		t.Fatalf("Nmap lower bound = %.6fs, known %v, incomplete %v; want 0.01s for one guaranteed probe at 100/s and service detection marked unestimated", seconds, hasBound, incomplete)
	}
}

func TestScanRateLowerBoundHandlesMissingAndUDPScannerRates(t *testing.T) {
	t.Parallel()
	if seconds, hasBound, incomplete := scanRateLowerBound(config.Job{}, config.DefaultMaxJobHosts); seconds != 0 || hasBound || incomplete {
		t.Fatalf("empty scan lower bound = %.2f, known %v, incomplete %v; want no bound and complete", seconds, hasBound, incomplete)
	}
	withoutRate := config.Job{Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Engine: config.EngineNmap, Ports: "443"}}
	if seconds, hasBound, incomplete := scanRateLowerBound(withoutRate, config.DefaultMaxJobHosts); seconds != 0 || hasBound || !incomplete {
		t.Fatalf("unlimited Nmap lower bound = %.2f, known %v, incomplete %v; want no bound and incomplete", seconds, hasBound, incomplete)
	}
	udp := config.Job{Targets: []string{"192.0.2.1"}, UDP: &config.Protocol{
		Ports: "53", ServiceDetection: true, NmapArgs: []string{"--max-rate=50"},
	}}
	if seconds, hasBound, incomplete := scanRateLowerBound(udp, config.DefaultMaxJobHosts); !hasBound || !incomplete || math.Abs(seconds-0.02) > 0.000001 {
		t.Fatalf("UDP Nmap lower bound = %.6f, known %v, incomplete %v; want 0.02s with service-detection work unestimated", seconds, hasBound, incomplete)
	}
}

func TestNmapMaxRateAcceptsBothFormsAndIgnoresInvalidValues(t *testing.T) {
	if got := nmapMaxRate([]string{"--max-rate=100", "--max-rate", "50", "--max-rate=0", "--max-rate", "bad"}); got != 50 {
		t.Fatalf("last valid max-rate = %d, want 50", got)
	}
	if got := nmapMaxRate([]string{"--max-rate"}); got != 0 {
		t.Fatalf("missing max-rate value = %d, want 0", got)
	}
}

func insertCompletedCycle(t *testing.T, db *store.Store, record store.JobRecord, id string, duration time.Duration) {
	t.Helper()
	finished := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	started := finished.Add(-duration)
	key := store.NewScanDurationKey(record)
	_, err := db.DB.Exec(`INSERT INTO scan_cycles(id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,total_units,total_probes,started_at,updated_at,expires_at,finished_at)
		VALUES(?,?,?,?,?,?,?,'completed',0,0,?,?,?,?)`,
		id, record.ID, record.Job.Name, record.Revision, key.ConfigHash, key.ExecutionHash, []byte("{}"),
		started.Format(time.RFC3339Nano), finished.Format(time.RFC3339Nano), finished.Format(time.RFC3339Nano), finished.Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.System().SaveScan(context.Background(), model.Scan{
		ID: "scan-" + id, JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision,
		StartedAt: started, FinishedAt: finished, Status: "success", ConfigHash: key.ConfigHash,
		CycleID: id, CycleAttempt: 1, CycleStatus: "completed", Resumable: true,
	}); err != nil {
		t.Fatal(err)
	}
}

// insertCompletedScan saves a successful scan of the record without a cycle,
// with the config hash and TCP scanner profile that a run of it records.
func insertCompletedScan(t *testing.T, db *store.Store, record store.JobRecord, id string, finished time.Time, duration time.Duration) {
	t.Helper()
	key := store.NewScanDurationKey(record)
	if err := db.System().SaveScan(context.Background(), model.Scan{
		ID: id, JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision,
		StartedAt: finished.Add(-duration), FinishedAt: finished, Status: "success", ScannerEngine: config.EngineNmap,
		ScannerProfileID: key.ScannerProfileID, ScannerProfileRevision: key.ScannerProfileRevision, ConfigHash: key.ConfigHash,
	}); err != nil {
		t.Fatal(err)
	}
}

// demandSampleKinds are the two kinds of duration sample: a completed cycle,
// and a completed scan without a cycle.
var demandSampleKinds = []string{"cycle", "scan"}

// createDemandJobWithSamples creates an enabled hourly job and records three
// completed samples of the kind given, of 10, 20 and 30 minutes, so its
// estimate is the 20-minute mean times its runs per day.
func createDemandJobWithSamples(t *testing.T, db *store.Store, kind string) store.JobRecord {
	t.Helper()
	ctx := context.Background()
	record, err := defaultTenant(db).CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
		Name: "kept-samples-" + kind, Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.1"},
		TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
	}), true)
	if err != nil {
		t.Fatal(err)
	}
	for i, duration := range []time.Duration{10 * time.Minute, 20 * time.Minute, 30 * time.Minute} {
		id := fmt.Sprintf("%s-sample-%d", kind, i)
		if kind == "cycle" {
			insertCompletedCycle(t, db, record, id, duration)
		} else {
			insertCompletedScan(t, db, record, id, time.Date(2026, time.January, 1, i, 0, 0, 0, time.UTC), duration)
		}
	}
	return record
}

// A pause and resume, a rename, a schedule edit and a notification edit
// change the job's revision but not how its scans run, so its completed
// samples keep determining the estimate.
func TestScanSlotDemandKeepsSamplesAcrossEditsThatDoNotChangeScans(t *testing.T) {
	t.Parallel()
	for _, kind := range demandSampleKinds {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			db := storetest.OpenFresh(t)
			ts := defaultTenant(db)
			record := createDemandJobWithSamples(t, db, kind)
			app := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}
			check := func(step string, runsPerDay float64) {
				t.Helper()
				demand, err := app.ScanSlotDemand(ctx, ts)
				if err != nil {
					t.Fatal(err)
				}
				want := (20 * time.Minute).Seconds() * runsPerDay
				if demand.HistoryJobs != 1 || demand.LowerBoundJobs != 0 || demand.UnestimatedJobs != 0 || math.Abs(demand.EstimatedSlotSecondsPerDay-want) > 0.01 {
					t.Fatalf("demand after %s = %+v; want the 20m mean of the kept samples × %.0f runs = %.0f seconds/day", step, demand, runsPerDay, want)
				}
			}
			check("creation", 24)

			edit := func(step string, change func(*config.Job)) {
				t.Helper()
				current, err := ts.GetJob(ctx, record.ID)
				if err != nil {
					t.Fatal(err)
				}
				job := current.Job
				change(&job)
				updated, _, err := ts.UpdateJob(ctx, record.ID, current.Revision, job, current.Enabled, current.Archived, false)
				if err != nil {
					t.Fatalf("%s: %v", step, err)
				}
				if updated.Revision == current.Revision {
					t.Fatalf("%s kept revision %d", step, current.Revision)
				}
			}
			if err := ts.SetJobEnabled(ctx, record.ID, false); err != nil {
				t.Fatal(err)
			}
			if demand, err := app.ScanSlotDemand(ctx, ts); err != nil || demand.EnabledJobs != 0 || demand.EstimatedSlotSecondsPerDay != 0 {
				t.Fatalf("paused job demand = %+v, %v; want none", demand, err)
			}
			if err := ts.SetJobEnabled(ctx, record.ID, true); err != nil {
				t.Fatal(err)
			}
			check("pause and resume", 24)
			edit("rename", func(job *config.Job) { job.Name = "renamed-" + kind })
			check("rename", 24)
			edit("notification edit", func(job *config.Job) { job.NotificationDestinations = []string{} })
			check("notification edit", 24)
			edit("schedule edit", func(job *config.Job) { job.Schedule = "*/30 * * * *" })
			check("schedule edit", 48)
		})
	}
}

// A target, port or protocol edit changes what a scan does, so the job's
// earlier samples no longer determine the estimate.
func TestScanSlotDemandDropsSamplesAfterScanScopeEdits(t *testing.T) {
	t.Parallel()
	edits := map[string]func(*config.Job){
		"targets":   func(job *config.Job) { job.Targets = []string{"192.0.2.2"} },
		"ports":     func(job *config.Job) { job.TCP.Ports = "443,8443" },
		"protocols": func(job *config.Job) { job.UDP = &config.Protocol{Ports: "53"} },
	}
	for _, kind := range demandSampleKinds {
		for name, change := range edits {
			t.Run(kind+"/"+name, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				db := storetest.OpenFresh(t)
				ts := defaultTenant(db)
				record := createDemandJobWithSamples(t, db, kind)
				app := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}
				if demand, err := app.ScanSlotDemand(ctx, ts); err != nil || demand.HistoryJobs != 1 {
					t.Fatalf("demand before the edit = %+v, %v; want its samples", demand, err)
				}
				job := record.Job
				tcp := *job.TCP
				job.TCP = &tcp
				change(&job)
				if _, _, err := ts.UpdateJob(ctx, record.ID, record.Revision, job, true, false, true); err != nil {
					t.Fatal(err)
				}
				demand, err := app.ScanSlotDemand(ctx, ts)
				if err != nil {
					t.Fatal(err)
				}
				if demand.HistoryJobs != 0 || demand.EnabledJobs != 1 {
					t.Fatalf("demand after the %s edit = %+v; want the earlier samples dropped", name, demand)
				}
			})
		}
	}
}

// The scheduler skips hourly ticks while a 90-minute run is active. The
// estimate counts the 12 runs that can start, then adds the separate daily
// job's two-hour run.
func TestScanSlotDemandModelsSkippedTicks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	slow, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
		Name: "ninety-minutes-hourly", Schedule: "0 * * * *", Timezone: "UTC", Timeout: config.Duration(2 * time.Hour),
		Targets: []string{"192.0.2.1"},
		TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
	}), true)
	if err != nil {
		t.Fatal(err)
	}
	insertCompletedCycle(t, db, slow, "ninety-minute-cycle", 90*time.Minute)
	daily, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
		Name: "two-hours-daily", Schedule: "0 3 * * *", Timezone: "UTC", Timeout: config.Duration(3 * time.Hour),
		Targets: []string{"192.0.2.2"},
		TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
	}), true)
	if err != nil {
		t.Fatal(err)
	}
	insertCompletedCycle(t, db, daily, "two-hour-cycle", 2*time.Hour)

	for slots, want := range map[int]struct {
		utilization float64
		over        bool
	}{1: {utilization: 2000.0 / 24, over: false}, 2: {utilization: 2000.0 / 48, over: false}} {
		demand, err := (&App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: slots}}}).ScanSlotDemand(ctx, ts)
		if err != nil {
			t.Fatal(err)
		}
		// The scheduler starts the hourly job every two hours: 12 × 90m =
		// 18 slot-hours, plus the daily job's two hours.
		if got := demand.EstimatedSlotSecondsPerDay / 3600; demand.HistoryJobs != 2 || demand.CadenceUnattainableJobs != 1 || math.Abs(got-20) > 0.001 {
			t.Fatalf("%d slots: demand = %+v (%.3f slot-hours/day); want 18 for the skipped hourly job plus 2, and one job with skipped ticks", slots, demand, got)
		}
		if math.Abs(demand.UtilizationPercent-want.utilization) > 0.001 || demand.OverCapacity != want.over {
			t.Fatalf("%d slots: capacity comparison = %+v; want %.2f%% and over capacity %t", slots, demand, want.utilization, want.over)
		}
	}
}

func TestScanSlotDemandUsesSkippedTickCountForDenseWindowSchedule(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
		Name: "dense-window", Schedule: "*/10 8-17 * * *", Timezone: "UTC", Timeout: config.Duration(time.Hour),
		Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
	}), true)
	if err != nil {
		t.Fatal(err)
	}
	insertCompletedCycle(t, db, record, "dense-window-cycle", 15*time.Minute)
	demand, err := (&App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}).ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if demand.CadenceUnattainableJobs != 1 {
		t.Fatalf("cadence jobs = %d, want one job whose 15-minute run skips 10-minute ticks", demand.CadenceUnattainableJobs)
	}
	if want := float64(27_000); math.Abs(demand.EstimatedSlotSecondsPerDay-want) > 0.01 {
		t.Fatalf("dense-window demand = %.2f seconds/day, want 30 × 15m = %.2f", demand.EstimatedSlotSecondsPerDay, want)
	}
}

// The job's timeout ends each run, so a run counts at most the timeout: a
// resumable cycle whose attempts add up to more continues in later runs
// rather than making the scheduler skip any, and a scope whose known work
// takes longer stops at the timeout. None of these jobs is counted as unable
// to keep its cadence.
func TestScanSlotDemandCountsEachRunAtMostItsTimeout(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	create := func(name, schedule string, timeout time.Duration, targets []string, tcp *config.Protocol) store.JobRecord {
		t.Helper()
		record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
			Name: name, Schedule: schedule, Timezone: "UTC", Timeout: config.Duration(timeout), Targets: targets, TCP: tcp,
		}), true)
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	fullTCP := func() *config.Protocol {
		return &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{Rate: 1000}}
	}
	// A daily job with a two-hour timeout whose cycle took 15 attempts,
	// 30 hours of scanning in all, and an hourly job with a 30-minute timeout
	// whose cycle took three.
	daily := create("fifteen-attempts-daily", "0 3 * * *", 2*time.Hour, []string{"192.0.2.1"}, fullTCP())
	insertMultiAttemptCycle(t, db, daily, "fifteen-attempt-cycle", 15, 2*time.Hour, 24*time.Hour)
	hourly := create("three-attempts-hourly", "0 * * * *", 30*time.Minute, []string{"192.0.2.2"}, fullTCP())
	insertMultiAttemptCycle(t, db, hourly, "three-attempt-cycle", 3, 30*time.Minute, time.Hour)
	// A daily /24 without history whose known work, about 4.66 hours a run,
	// outlasts its one-hour timeout.
	create("full-tcp-daily", "0 4 * * *", time.Hour, []string{"198.51.100.0/24"}, fullTCP())

	demand, err := (&App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}).ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	// 2 hours once a day, 30 minutes 24 times a day, and 1 hour once a day.
	if got := demand.EstimatedSlotSecondsPerDay / 3600; demand.HistoryJobs != 2 || demand.LowerBoundJobs != 1 || math.Abs(got-15) > 0.001 {
		t.Fatalf("demand = %+v (%.3f slot-hours/day); want each run counted at its timeout, 15 slot-hours/day", demand, got)
	}
	if demand.CadenceUnattainableJobs != 0 || demand.OverCapacity || math.Abs(demand.UtilizationPercent-62.5) > 0.001 {
		t.Fatalf("demand = %+v; want no job counted as unable to keep its cadence and 62.5%% of one slot", demand)
	}
}

// insertMultiAttemptCycle records a completed cycle of the record that took
// the number of attempts given, each of the attempt duration and each
// starting one interval after the one before, with a saved scan for every
// attempt before the final one, which the cycle row records.
func insertMultiAttemptCycle(t *testing.T, db *store.Store, record store.JobRecord, id string, attempts int, attempt, interval time.Duration) {
	t.Helper()
	durations := make([]time.Duration, attempts)
	for i := range durations {
		durations[i] = attempt
	}
	insertCycleAttempts(t, db, record, id, time.Date(2026, time.February, 1, 12, 0, 0, 0, time.UTC), durations, interval)
	samples, err := defaultTenant(db).ListCompletedScanCycleDurations(context.Background(), []store.ScanDurationKey{store.NewScanDurationKey(record)}, scanSlotDemandHistoryLimit)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Duration(attempts) * attempt; len(samples[record.ID]) != 1 || samples[record.ID][0].Duration() != want || samples[record.ID][0].Runs != attempts {
		t.Fatalf("%d-attempt cycle samples = %+v, want one of %s over %d runs", attempts, samples[record.ID], want, attempts)
	}
}

// insertCycleAttempts records a completed cycle of the record that finished
// at finished after attempts of the durations given, each starting one
// interval after the one before, with a saved timed-out scan for every
// attempt before the final one, which the cycle row records, and the final
// attempt's successful scan, as a run that completes its cycle saves.
func insertCycleAttempts(t *testing.T, db *store.Store, record store.JobRecord, id string, finished time.Time, attempts []time.Duration, interval time.Duration) {
	t.Helper()
	key := store.NewScanDurationKey(record)
	finalStart := finished.Add(-attempts[len(attempts)-1])
	firstStart := finalStart.Add(-time.Duration(len(attempts)-1) * interval)
	stamp := func(value time.Time) string { return value.Format(time.RFC3339Nano) }
	if _, err := db.DB.Exec(`INSERT INTO scan_cycles(id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,attempt_count,total_units,total_probes,started_at,attempt_started_at,updated_at,expires_at,finished_at)
		VALUES(?,?,?,?,?,?,?,'completed',?,1,1,?,?,?,?,?)`,
		id, record.ID, record.Job.Name, record.Revision, key.ConfigHash, key.ExecutionHash, []byte("{}"), len(attempts),
		stamp(firstStart), stamp(finalStart), stamp(finished), stamp(finished), stamp(finished)); err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= len(attempts); n++ {
		started := firstStart.Add(time.Duration(n-1) * interval)
		status, cycleStatus := "timed_out", "paused"
		if n == len(attempts) {
			status, cycleStatus = "success", "completed"
		}
		if err := db.System().SaveScan(context.Background(), model.Scan{
			ID: fmt.Sprintf("%s-attempt-%02d", id, n), JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision,
			StartedAt: started, FinishedAt: started.Add(attempts[n-1]), Status: status, ConfigHash: key.ConfigHash,
			CycleID: id, CycleAttempt: n, CycleStatus: cycleStatus, Resumable: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// Runs per day depend only on a schedule and its timezone, so the App
// computes them once for each pair across requests, and the results equal
// a fresh computation.
func TestScanSlotDemandComputesRunsPerDayOncePerSchedule(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	create := func(name, schedule, timezone string) {
		t.Helper()
		// Each job's known Naabu work bounds its runs, so its schedule is
		// expanded.
		if _, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
			Name: name, Schedule: schedule, Timezone: timezone, Targets: []string{"192.0.2.1"},
			TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{Rate: 1000}},
		}), true); err != nil {
			t.Fatal(err)
		}
	}
	// The first two share a schedule and timezone, the third has its own.
	create("amsterdam-a", "0 * * * *", "Europe/Amsterdam")
	create("amsterdam-b", "0 * * * *", "Europe/Amsterdam")
	create("new-york", "0 * * * *", "America/New_York")
	app := &App{Store: db, Config: &config.Config{Timezone: "Europe/Amsterdam", Scheduler: config.Scheduler{MaxConcurrent: 1}}}
	computed := func() int {
		app.scanSlotDemand.mu.Lock()
		defer app.scanSlotDemand.mu.Unlock()
		return app.scanSlotDemand.runsPerDayComputed
	}
	first, err := app.ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if got := computed(); got != 2 {
		t.Fatalf("runs per day computed %d times for two schedule and timezone pairs", got)
	}
	for range 3 {
		again, err := app.ScanSlotDemand(ctx, ts)
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatalf("repeated demand = %+v, want %+v", again, first)
		}
	}
	if got := computed(); got != 2 {
		t.Fatalf("runs per day computed %d times after repeated requests, want still 2", got)
	}
	create("six-hourly", "0 */6 * * *", "Europe/Amsterdam")
	if _, err := app.ScanSlotDemand(ctx, ts); err != nil {
		t.Fatal(err)
	}
	if got := computed(); got != 3 {
		t.Fatalf("runs per day computed %d times after a new schedule, want 3", got)
	}
	// A job without history or a scanner rate has no run to project, so it
	// is not estimated and its schedule is not expanded.
	if _, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
		Name: "unbounded", Schedule: "*/5 * * * *", Timezone: "Europe/Amsterdam", Targets: []string{"192.0.2.1"},
		TCP: &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
	}), true); err != nil {
		t.Fatal(err)
	}
	unbounded, err := app.ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	// The four Naabu jobs' enrichment is unbounded too.
	if got := computed(); got != 3 || unbounded.EnabledJobs != 5 || unbounded.LowerBoundJobs != 4 || unbounded.UnestimatedJobs != 5 || unbounded.WorkLimitedJobs != 0 {
		t.Fatalf("demand with a job without a run = %+v after %d schedule computations; want it unestimated and 3 computations", unbounded, got)
	}
	// Without any work to spend, it is still unestimated, not work-limited.
	limited, err := app.scheduledScanDemandWithSimulationCache(ctx, ts, nil, &scanScheduleSimulationBudget{limit: 0})
	if err != nil || limited.UnestimatedJobs != 5 || limited.WorkLimitedJobs != 0 {
		t.Fatalf("demand without work = %+v, error %v; want the four jobs with unbounded Nmap enrichment and the unbounded job unestimated, none work-limited", limited, err)
	}
	for _, job := range []config.Job{
		{Schedule: "0 * * * *"}, {Schedule: "0 * * * *", Timezone: " Europe/Amsterdam "}, {Schedule: "0 * * * *", Timezone: "America/New_York"},
		{Schedule: "0 */6 * * *", Timezone: "Europe/Amsterdam"}, {Schedule: "not cron"},
	} {
		cachedRuns, cachedOK := app.scanJobRunsPerDay(job)
		freshRuns, freshOK := scanJobRunsPerDay(job, app.Config.Timezone)
		if cachedRuns != freshRuns || cachedOK != freshOK {
			t.Fatalf("cached runs per day of %+v = %v, %t; want %v, %t", job, cachedRuns, cachedOK, freshRuns, freshOK)
		}
	}
}

// A full runs-per-day cache retains no more than its configured bound.
func TestScanJobRunsPerDayCacheIsBounded(t *testing.T) {
	t.Parallel()
	app := &App{Config: &config.Config{}}
	for i := range scanRunsPerDayCacheLimit + 1 {
		// Yearly schedules compute in one step each.
		if _, ok := app.scanJobRunsPerDay(config.Job{Schedule: fmt.Sprintf("%d %d 1 1 *", i%60, i/60)}); !ok {
			t.Fatalf("yearly schedule %d was rejected", i)
		}
	}
	app.scanSlotDemand.mu.Lock()
	defer app.scanSlotDemand.mu.Unlock()
	if got := len(app.scanSlotDemand.runsPerDay); got != scanRunsPerDayCacheLimit {
		t.Fatalf("runs-per-day cache holds %d schedules after it filled, want its %d-entry bound", got, scanRunsPerDayCacheLimit)
	}
}

func TestScanJobRunsPerDayCacheHasWeightedBoundForDenseSchedules(t *testing.T) {
	t.Parallel()
	// A schedule of every other day keeps a span for about every other day
	// of the 1,461-day sample. Reuse one computed backing array to model the
	// retained weight of many distinct such keys without making the test
	// itself retain the whole cache.
	value, err := schedulePattern(context.Background(), "UTC", "0 0 */2 * *")
	if err != nil || !value.ok || len(value.days) < 700 {
		t.Fatalf("every-other-day schedule pattern has %d day spans, ok %t, err %v; want more than 700", len(value.days), value.ok, err)
	}
	const schedules = scanRunsPerDayCacheLimit
	keyForWeight := scanRunsPerDayKey{timezone: "UTC", schedule: "dense-key-0000"}
	entryWeight := scanRunsPerDayCacheEntryWeight(keyForWeight, value)
	wantEntries := scanRunsPerDayCacheByteLimit / entryWeight
	if wantEntries >= schedules {
		t.Fatalf("test schedule entry weight %d only retains %d entries under %d bytes", entryWeight, wantEntries, scanRunsPerDayCacheByteLimit)
	}
	cache := scanSlotDemandCache{}
	for i := 0; i < schedules; i++ {
		key := scanRunsPerDayKey{timezone: "UTC", schedule: fmt.Sprintf("dense-key-%04d", i)}
		entry := value
		entry.rank = uint64(i)
		cache.retainRunsPerDay(key, entry)
	}
	firstKey := scanRunsPerDayKey{timezone: "UTC", schedule: fmt.Sprintf("dense-key-%04d", 0)}
	cache.retainRunsPerDay(firstKey, value)
	if len(cache.runsPerDay) != wantEntries || cache.runsPerDayBytes != wantEntries*entryWeight || cache.runsPerDayBytes > scanRunsPerDayCacheByteLimit {
		t.Fatalf("dense cache retained %d entries weighing %d bytes; want %d entries and at most %d bytes", len(cache.runsPerDay), cache.runsPerDayBytes, wantEntries, scanRunsPerDayCacheByteLimit)
	}
	for i := 0; i < schedules; i++ {
		key := scanRunsPerDayKey{timezone: "UTC", schedule: fmt.Sprintf("dense-key-%04d", i)}
		_, retained := cache.runsPerDay[key]
		if retained != (i < wantEntries) {
			t.Fatalf("dense schedule rank %d retained = %t; want %t under weighted eviction", i, retained, i < wantEntries)
		}
	}
}

func TestScanRunsPerDayCacheRetainsNoTimezoneObjects(t *testing.T) {
	t.Parallel()
	app := &App{Config: &config.Config{}}
	for _, timezone := range []string{"Africa/Casablanca", "Australia/Lord_Howe", "Europe/Amsterdam", "Pacific/Apia"} {
		if _, err := app.scanJobSchedule(context.Background(), config.Job{Schedule: "30 1 * * *", Timezone: timezone}); err != nil {
			t.Fatalf("cache schedule in %s: %v", timezone, err)
		}
	}

	// A timezone-bearing time.Time, Location, cron.Schedule, pointer, or
	// interface in this value would retain implementation-specific zone data
	// outside the byte-weighted cache accounting.
	var inspect func(reflect.Type) error
	inspect = func(typ reflect.Type) error {
		if typ == reflect.TypeOf(time.Time{}) || typ == reflect.TypeOf((*time.Location)(nil)) || typ.Kind() == reflect.Interface || typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Map {
			return fmt.Errorf("cache value field retains pointer-bearing type %s", typ)
		}
		switch typ.Kind() {
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				if err := inspect(typ.Field(i).Type); err != nil {
					return fmt.Errorf("%s.%s: %w", typ, typ.Field(i).Name, err)
				}
			}
		case reflect.Slice, reflect.Array:
			return inspect(typ.Elem())
		}
		return nil
	}
	if err := inspect(reflect.TypeOf(scanRunsPerDayValue{})); err != nil {
		t.Fatal(err)
	}

	app.scanSlotDemand.mu.Lock()
	defer app.scanSlotDemand.mu.Unlock()
	var weight int
	for key, value := range app.scanSlotDemand.runsPerDay {
		weight += scanRunsPerDayCacheEntryWeight(key, value)
	}
	if weight != app.scanSlotDemand.runsPerDayBytes || weight > scanRunsPerDayCacheByteLimit {
		t.Fatalf("transition-zone cache weights %d bytes, recorded %d; want consistent accounting within %d", weight, app.scanSlotDemand.runsPerDayBytes, scanRunsPerDayCacheByteLimit)
	}
}

func TestScanJobRunsPerDayCacheSkipsOversizedEntry(t *testing.T) {
	t.Parallel()
	cache := scanSlotDemandCache{}
	key := scanRunsPerDayKey{timezone: "UTC", schedule: string(make([]byte, scanRunsPerDayCacheByteLimit))}
	cache.retainRunsPerDay(key, scanRunsPerDayValue{})
	if len(cache.runsPerDay) != 0 || cache.runsPerDayBytes != 0 {
		t.Fatalf("oversized schedule entry retained %d keys weighing %d bytes", len(cache.runsPerDay), cache.runsPerDayBytes)
	}
}

// A fixed traversal larger than the cache used to reset it on every pass.
// The retained subset now stays hot, so the third pass recomputes only the
// keys that cannot fit, rather than all 1,100 schedules.
func TestScanJobRunsPerDayCacheKeepsStableKeysAboveCapacity(t *testing.T) {
	t.Parallel()
	const schedules = scanRunsPerDayCacheLimit + 76
	app := &App{Config: &config.Config{}}
	computed := func() int {
		app.scanSlotDemand.mu.Lock()
		defer app.scanSlotDemand.mu.Unlock()
		return app.scanSlotDemand.runsPerDayComputed
	}
	previous := 0
	for pass := 1; pass <= 3; pass++ {
		for i := 0; i < schedules; i++ {
			job := config.Job{Schedule: fmt.Sprintf("%d %d 1 1 *", i%60, i/60)}
			if _, ok := app.scanJobRunsPerDay(job); !ok {
				t.Fatalf("pass %d schedule %d was rejected", pass, i)
			}
		}
		current := computed()
		growth := current - previous
		if pass > 1 && growth > schedules/8 {
			t.Fatalf("pass %d recomputed %d of %d schedules; want well under a full pass", pass, growth, schedules)
		}
		previous = current
	}
	if got := len(app.scanSlotDemand.runsPerDay); got != scanRunsPerDayCacheLimit {
		t.Fatalf("runs-per-day cache holds %d schedules after repeated passes, want %d", got, scanRunsPerDayCacheLimit)
	}
}

func TestScanJobRunsPerDayCacheEvictionRecomputesTheEvictedKey(t *testing.T) {
	t.Parallel()
	app := &App{Config: &config.Config{}}
	for i := 0; i < scanRunsPerDayCacheLimit; i++ {
		key := scanRunsPerDayKey{timezone: "UTC", schedule: fmt.Sprintf("%d %d 1 1 *", i%60, i/60)}
		if _, ok := app.scanJobRunsPerDay(config.Job{Schedule: key.schedule}); !ok {
			t.Fatalf("initial schedule %d was rejected", i)
		}
	}
	app.scanSlotDemand.mu.Lock()
	var largest scanRunsPerDayKey
	var largestRank uint64
	for key, value := range app.scanSlotDemand.runsPerDay {
		if value.rank > largestRank {
			largest, largestRank = key, value.rank
		}
	}
	app.scanSlotDemand.mu.Unlock()
	candidate := ""
	for i := scanRunsPerDayCacheLimit; i < 1440; i++ {
		schedule := fmt.Sprintf("%d %d 1 1 *", i%60, i/60)
		if scanCacheRank("UTC", schedule) < largestRank {
			candidate = schedule
			break
		}
	}
	if candidate == "" {
		t.Fatal("could not find a deterministic replacement schedule")
	}
	if _, ok := app.scanJobRunsPerDay(config.Job{Schedule: candidate}); !ok {
		t.Fatalf("replacement schedule %q was rejected", candidate)
	}
	app.scanSlotDemand.mu.Lock()
	_, replacementRetained := app.scanSlotDemand.runsPerDay[scanRunsPerDayKey{timezone: "UTC", schedule: candidate}]
	_, evictedRetained := app.scanSlotDemand.runsPerDay[largest]
	gotEntries := len(app.scanSlotDemand.runsPerDay)
	computedBefore := app.scanSlotDemand.runsPerDayComputed
	app.scanSlotDemand.mu.Unlock()
	if !replacementRetained || evictedRetained || gotEntries != scanRunsPerDayCacheLimit {
		t.Fatalf("cache after replacement holds %d entries, replacement present %t, old maximum present %t", gotEntries, replacementRetained, evictedRetained)
	}
	gotRuns, gotOK := app.scanJobRunsPerDay(config.Job{Schedule: largest.schedule})
	wantRuns, wantOK := scheduleRunsPerDay("UTC", largest.schedule)
	if gotRuns != wantRuns || gotOK != wantOK {
		t.Fatalf("evicted schedule recomputed as %v, %t; want %v, %t", gotRuns, gotOK, wantRuns, wantOK)
	}
	app.scanSlotDemand.mu.Lock()
	computedAfter := app.scanSlotDemand.runsPerDayComputed
	app.scanSlotDemand.mu.Unlock()
	if computedAfter != computedBefore+1 {
		t.Fatalf("schedule computations after cache eviction = %d, want %d", computedAfter, computedBefore+1)
	}
}

func TestScheduleDemandSkipsTicksLikeTheCronScheduler(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name          string
		timezone      string
		schedule      string
		runDuration   time.Duration
		endsAtTimeout bool
		wantRuns      float64
		wantSkipped   bool
	}{
		{name: "ten minute window with fifteen minute run", timezone: "UTC", schedule: "*/10 8-17 * * *", runDuration: 15 * time.Minute, wantRuns: 30, wantSkipped: true},
		{name: "two hourly ticks with ten minute run", timezone: "UTC", schedule: "0,5 * * * *", runDuration: 10 * time.Minute, wantRuns: 24, wantSkipped: true},
		{name: "completion exactly at next tick", timezone: "UTC", schedule: "*/15 * * * *", runDuration: 15 * time.Minute, wantRuns: 96},
		// A run that its timeout ends is finalized after the next tick.
		{name: "timeout exactly at next tick", timezone: "UTC", schedule: "*/15 * * * *", runDuration: 15 * time.Minute, endsAtTimeout: true, wantRuns: 48, wantSkipped: true},
		{name: "hourly timeout exactly at next tick", timezone: "UTC", schedule: "0 * * * *", runDuration: time.Hour, endsAtTimeout: true, wantRuns: 12, wantSkipped: true},
		{name: "every-minute timeout exactly at next tick", timezone: "UTC", schedule: "* * * * *", runDuration: time.Minute, endsAtTimeout: true, wantRuns: 720, wantSkipped: true},
		{name: "timeout before next tick", timezone: "UTC", schedule: "0 * * * *", runDuration: 50 * time.Minute, endsAtTimeout: true, wantRuns: 24},
		{name: "hourly across daylight saving", timezone: "Europe/Amsterdam", schedule: "0 * * * *", runDuration: 61 * time.Minute, wantRuns: 12, wantSkipped: true},
		{name: "dense schedule with long run", timezone: "UTC", schedule: "* * * * *", runDuration: 15 * 24 * time.Hour, wantRuns: 1.0 / 15, wantSkipped: true},
		{name: "daily run longer than a day", timezone: "UTC", schedule: "0 3 * * *", runDuration: 25 * time.Hour, wantRuns: 0.5, wantSkipped: true},
		{name: "weekday window with long run", timezone: "UTC", schedule: "*/20 9-10 * * 1-5", runDuration: 30 * time.Minute, wantRuns: 3 * 1461.0 * 5 / 7 / 1461, wantSkipped: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			pattern, err := schedulePattern(context.Background(), test.timezone, test.schedule)
			if err != nil || !pattern.ok {
				t.Fatalf("schedule pattern = %+v, error %v", pattern, err)
			}
			runs, skipped, err := pattern.runsForDuration(context.Background(), test.runDuration.Seconds(), test.endsAtTimeout)
			if err != nil {
				t.Fatal(err)
			}
			if math.Abs(runs-test.wantRuns) > 0.01 || skipped != test.wantSkipped {
				t.Fatalf("runs/day = %.4f, skipped %t; want %.4f and skipped %t", runs, skipped, test.wantRuns, test.wantSkipped)
			}
		})
	}
}

// simulateScheduleTicks is the reference projection over the window from
// start to end: it follows every cron tick from two run durations before
// start, as the scheduler finds each tick from the one before it, and skips
// the ticks at which an earlier run still holds the job.
func simulateScheduleTicks(ctx context.Context, schedule cron.Schedule, start, end time.Time, runDuration time.Duration, endsAtTimeout bool) (float64, bool, error) {
	var busyUntil time.Time
	var starts float64
	skipped := false
	for next := schedule.Next(start.Add(-2 * runDuration).Add(-time.Nanosecond)); ; next = schedule.Next(next) {
		if err := ctx.Err(); err != nil {
			return 0, false, err
		}
		if next.IsZero() {
			return 0, false, errInvalidScanSchedulePattern
		}
		if !next.Before(end) {
			break
		}
		if scheduleTickBusy(next, busyUntil, endsAtTimeout) {
			if !next.Before(start) {
				skipped = true
			}
			continue
		}
		if !next.Before(start) {
			starts++
		}
		busyUntil = next.Add(runDuration)
	}
	return starts / (end.Sub(start).Hours() / 24), skipped, nil
}

// The day walk reproduces a tick-by-tick simulation of the whole sample,
// including irregular days: daylight-saving changes, half-hour shifts,
// midnights that daylight saving skips, and Ramadan offset changes, and the
// days after them into which the cron search for the next tick drifts. It
// takes at least the schedule's known work.
func TestCompactSchedulePatternsPreserveTransitionHeavyTimezoneProjection(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		timezone     string
		schedule     string
		runDurations []time.Duration
	}{
		{name: "half-hour daylight transition", timezone: "Australia/Lord_Howe", schedule: "0,30 * * * *", runDurations: []time.Duration{30 * time.Minute, 45 * time.Minute, 2 * time.Hour}},
		{name: "Ramadan timezone changes", timezone: "Africa/Casablanca", schedule: "30 1 * * *", runDurations: []time.Duration{2 * time.Hour, 24 * time.Hour, 49 * time.Hour}},
		{name: "European daylight transition", timezone: "Europe/Amsterdam", schedule: "0 * * * *", runDurations: []time.Duration{time.Hour, 61 * time.Minute, 150 * time.Minute, 26 * time.Hour}},
		{name: "repeated hour at the clock change", timezone: "Europe/Amsterdam", schedule: "30 2 * * *", runDurations: []time.Duration{time.Hour, 23 * time.Hour, 24 * time.Hour}},
		{name: "skipped midnight", timezone: "America/Santiago", schedule: "0 0,12 * * *", runDurations: []time.Duration{11 * time.Hour, 12 * time.Hour, 13 * time.Hour}},
		{name: "skipped midnight with weekdays", timezone: "America/Havana", schedule: "*/20 0-1 * * 0,6", runDurations: []time.Duration{20 * time.Minute, 50 * time.Minute}},
		{name: "midnight change with every other day", timezone: "Asia/Beirut", schedule: "0 3 */2 * *", runDurations: []time.Duration{24 * time.Hour, 48 * time.Hour, 50 * time.Hour}},
		{name: "month window", timezone: "America/New_York", schedule: "*/30 1-3 1-7 * *", runDurations: []time.Duration{30 * time.Minute, 40 * time.Minute, 3 * time.Hour}},
		{name: "leap day", timezone: "UTC", schedule: "0 0 29 2 *", runDurations: []time.Duration{time.Hour, 400 * 24 * time.Hour}},
		// The search after the half-hour change finds no tick on the next
		// day, 2024-10-07.
		{name: "midnight after a half-hour change", timezone: "Australia/Lord_Howe", schedule: "0 0 * * *", runDurations: []time.Duration{23 * time.Hour, 24 * time.Hour, 25 * time.Hour, 47 * time.Hour}},
		{name: "weekdays after a half-hour change", timezone: "Australia/Lord_Howe", schedule: "0 0 * * 0,2", runDurations: []time.Duration{24 * time.Hour, 48 * time.Hour, 72 * time.Hour}},
		// The change at 2:45 leaves the next day 15 ticks, from 2:45.
		{name: "hour after a change at 2:45", timezone: "Pacific/Chatham", schedule: "* 2 * * *", runDurations: []time.Duration{time.Minute, 90 * time.Second, 15 * time.Minute, 2 * time.Hour}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			pattern, err := schedulePattern(context.Background(), test.timezone, test.schedule)
			if err != nil || !pattern.ok {
				t.Fatalf("compact schedule pattern = %+v, error %v", pattern, err)
			}
			location, err := time.LoadLocation(test.timezone)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow).Parse(test.schedule)
			if err != nil {
				t.Fatal(err)
			}
			parsed.(*cron.SpecSchedule).Location = location
			start := time.Date(scanScheduleSampleStartYear, time.January, 1, 0, 0, 0, 0, location)
			end := time.Date(scanScheduleSampleEndYear, time.January, 1, 0, 0, 0, 0, location)
			var ticks float64
			for next := parsed.Next(start.Add(-time.Nanosecond)); next.Before(end); next = parsed.Next(next) {
				ticks++
			}
			if want := ticks / (end.Sub(start).Hours() / 24); math.Abs(pattern.runsPerDay-want) > 1e-9 {
				t.Fatalf("compact rate = %.8f runs/day; cron ticks = %.8f", pattern.runsPerDay, want)
			}
			for _, runDuration := range test.runDurations {
				for _, endsAtTimeout := range []bool{false, true} {
					budget := &scanScheduleSimulationBudget{limit: scanScheduleJobWorkLimit}
					gotRuns, gotSkipped, err := pattern.runsForDurationWithBudget(context.Background(), runDuration.Seconds(), endsAtTimeout, budget)
					if err != nil {
						t.Fatal(err)
					}
					wantRuns, wantSkipped, err := simulateScheduleTicks(context.Background(), parsed, start, end, runDuration, endsAtTimeout)
					if err != nil {
						t.Fatal(err)
					}
					if math.Abs(gotRuns-wantRuns) > 1e-9 || gotSkipped != wantSkipped {
						t.Fatalf("%s run, ends at timeout %t: compact projection = %.8f, skipped %t; timezone-aware cron projection = %.8f, skipped %t", runDuration, endsAtTimeout, gotRuns, gotSkipped, wantRuns, wantSkipped)
					}
					// The schedule's known work is a lower bound, so a
					// projection that cannot have it is never begun.
					if !pattern.runFitsEveryGap(runDuration.Seconds(), endsAtTimeout) && budget.used < pattern.projectionWorkFloor(runDuration.Seconds()) {
						t.Fatalf("%s run, ends at timeout %t: projection used %d work units, less than the schedule's known work %d", runDuration, endsAtTimeout, budget.used, pattern.projectionFloor)
					}
				}
			}
		})
	}
}

// A tick falls on a whole minute, so a run blocks the same ticks as the
// run of whole minutes that projectedRun gives it, and the memoized
// projection of a run matches a tick-by-tick simulation of the exact run.
// Runs that block the same ticks share one memo entry. A timezone with an
// offset of seconds keeps the exact run.
func TestProjectedRunBlocksTheSameTicksAsTheExactRun(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		timezone, schedule string
		runs               []time.Duration
	}{
		{timezone: "Europe/Amsterdam", schedule: "0 * * * *", runs: []time.Duration{59*time.Minute + 30*time.Second, time.Hour, time.Hour + time.Millisecond, 61*time.Minute + 59*time.Second}},
		{timezone: "Australia/Lord_Howe", schedule: "0,30 * * * *", runs: []time.Duration{29*time.Minute + 59*time.Second, 30 * time.Minute, 45*time.Minute + 500*time.Millisecond}},
		{timezone: "America/Santiago", schedule: "0 0,12 * * *", runs: []time.Duration{12*time.Hour - time.Second, 12 * time.Hour, 13*time.Hour + time.Second}},
		{timezone: "UTC", schedule: "*/7 8-17 * * 1-5", runs: []time.Duration{6*time.Minute + time.Second, 7 * time.Minute, 20*time.Minute + 30*time.Second}},
	} {
		t.Run(test.timezone+" "+test.schedule, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			pattern, err := schedulePattern(ctx, test.timezone, test.schedule)
			if err != nil || !pattern.ok || !pattern.minuteTicks {
				t.Fatalf("schedule pattern = %+v, error %v; want ticks on whole minutes", pattern, err)
			}
			location := mustLoadLocation(t, test.timezone)
			parsed, err := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow).Parse(test.schedule)
			if err != nil {
				t.Fatal(err)
			}
			parsed.(*cron.SpecSchedule).Location = location
			start := time.Date(scanScheduleSampleStartYear, time.January, 1, 0, 0, 0, 0, location)
			end := time.Date(scanScheduleSampleEndYear, time.January, 1, 0, 0, 0, 0, location)
			memo := make(map[scanScheduleDurationKey]scanScheduleDurationEstimate)
			for _, run := range test.runs {
				for _, endsAtTimeout := range []bool{false, true} {
					got, gotSkipped, err := memoizedScheduleRunsForDurationWithBudget(ctx, memo, pattern, run.Seconds(), endsAtTimeout, nil)
					if err != nil {
						t.Fatal(err)
					}
					want, wantSkipped, err := simulateScheduleTicks(ctx, parsed, start, end, run, endsAtTimeout)
					if err != nil {
						t.Fatal(err)
					}
					if math.Abs(got-want) > 1e-9 || gotSkipped != wantSkipped {
						t.Fatalf("%s run, ends at timeout %t: projection = %.8f runs/day, skipped %t; cron = %.8f, skipped %t", run, endsAtTimeout, got, gotSkipped, want, wantSkipped)
					}
				}
			}
		})
	}

	pattern, err := schedulePattern(context.Background(), "Europe/Amsterdam", "0 * * * *")
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range []struct {
		seconds       float64
		endsAtTimeout bool
		want          float64
	}{
		{seconds: 3600.001, want: 3660}, {seconds: 3659.999, want: 3660}, {seconds: 3660, want: 3660},
		{seconds: 3600, endsAtTimeout: true, want: 3660}, {seconds: 3659.999, endsAtTimeout: true, want: 3660},
		{seconds: 3660, endsAtTimeout: true, want: 3720},
	} {
		if seconds, endsAtTimeout := pattern.projectedRun(run.seconds, run.endsAtTimeout); seconds != run.want || endsAtTimeout {
			t.Fatalf("projected run of %.3f seconds, ends at timeout %t = %.3f, %t; want %.0f seconds that end before the tick", run.seconds, run.endsAtTimeout, seconds, endsAtTimeout, run.want)
		}
	}
	memo := make(map[scanScheduleDurationKey]scanScheduleDurationEstimate)
	for _, seconds := range []float64{3600.001, 3620.5, 3659.999, 3660} {
		if _, _, err := memoizedScheduleRunsForDurationWithBudget(context.Background(), memo, pattern, seconds, false, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := memoizedScheduleRunsForDurationWithBudget(context.Background(), memo, pattern, 3600, true, nil); err != nil {
		t.Fatal(err)
	}
	if len(memo) != 1 {
		t.Fatalf("runs that block the same ticks left %d memo entries, want one", len(memo))
	}

	odd := time.FixedZone("odd", 3600+30)
	start := time.Date(scanScheduleSampleStartYear, time.January, 1, 0, 0, 0, 0, odd)
	if scheduleTicksOnWholeMinutes(1, odd, start, start.AddDate(4, 0, 0)) || scheduleTicksOnWholeMinutes(3, time.UTC, start, start.AddDate(4, 0, 0)) {
		t.Fatal("ticks with an offset of seconds, or a schedule with seconds, counted as falling on whole minutes")
	}
	exact := pattern
	exact.minuteTicks = false
	if seconds, endsAtTimeout := exact.projectedRun(3600.5, true); seconds != 3600.5 || !endsAtTimeout {
		t.Fatalf("projected run without whole-minute ticks = %.1f, %t; want the exact run", seconds, endsAtTimeout)
	}
}

func TestEveryMinuteProjectionShortcutMatchesCronAcrossDST(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		timezone string
		start    time.Time
		end      time.Time
	}{
		{name: "half-hour transition", timezone: "Australia/Lord_Howe", start: time.Date(2024, time.October, 6, 0, 0, 0, 0, mustLoadLocation(t, "Australia/Lord_Howe")), end: time.Date(2024, time.October, 8, 0, 0, 0, 0, mustLoadLocation(t, "Australia/Lord_Howe"))},
		{name: "European spring transition", timezone: "Europe/Amsterdam", start: time.Date(2024, time.March, 31, 0, 0, 0, 0, mustLoadLocation(t, "Europe/Amsterdam")), end: time.Date(2024, time.April, 2, 0, 0, 0, 0, mustLoadLocation(t, "Europe/Amsterdam"))},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			location, err := time.LoadLocation(test.timezone)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow).Parse("* * * * *")
			if err != nil {
				t.Fatal(err)
			}
			parsed.(*cron.SpecSchedule).Location = location
			for _, runDuration := range []time.Duration{time.Minute, 61 * time.Second, 90 * time.Second, 2 * time.Minute} {
				for _, endsAtTimeout := range []bool{false, true} {
					got, gotSkipped, err := simulateEveryMinuteScheduleWindow(context.Background(), test.start, test.end, runDuration, endsAtTimeout)
					if err != nil {
						t.Fatal(err)
					}
					want, wantSkipped, err := simulateScheduleTicks(context.Background(), parsed, test.start, test.end, runDuration, endsAtTimeout)
					if err != nil {
						t.Fatal(err)
					}
					if math.Abs(got-want) > 1e-9 || gotSkipped != wantSkipped {
						t.Fatalf("%s run, ends at timeout %t: shortcut = %.8f starts/day, skipped %t; cron = %.8f, skipped %t", runDuration, endsAtTimeout, got, gotSkipped, want, wantSkipped)
					}
				}
			}
		})
	}
}

func TestScheduleProjectionHandlesCancellationAndInvalidCompactState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pattern, err := schedulePattern(ctx, "UTC", "* * * * *")
	if err != nil || !pattern.ok {
		t.Fatalf("every-minute pattern = %+v, error %v", pattern, err)
	}
	_, start, end, err := pattern.runtimeSchedule()
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := pattern.walkScheduleDays(canceled, &cron.SpecSchedule{}, start, 61*time.Second, false, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled compact projection error = %v; want context.Canceled", err)
	}
	if _, _, err := simulateEveryMinuteSchedule(canceled, pattern, 61*time.Second, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled every-minute projection error = %v; want context.Canceled", err)
	}
	if _, _, err := simulateEveryMinuteSchedule(ctx, pattern, 0, false); err != nil {
		t.Fatalf("zero-duration every-minute projection error = %v; want nil", err)
	}
	if _, _, err := simulateEveryMinuteScheduleWindow(canceled, start, end, 61*time.Second, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled every-minute window error = %v; want context.Canceled", err)
	}
	if _, _, err := simulateEveryMinuteScheduleWindow(ctx, start, start, time.Minute, false); err != nil {
		t.Fatalf("empty every-minute window error = %v; want nil", err)
	}

	badTimezone := pattern
	badTimezone.identity.timezone = "Mars/Olympus"
	if _, _, err := simulateEveryMinuteSchedule(ctx, badTimezone, 61*time.Second, false); !errors.Is(err, errInvalidScanSchedulePattern) {
		t.Fatalf("invalid compact timezone error = %v; want invalid schedule", err)
	}
	if _, _, _, err := badTimezone.runtimeSchedule(); !errors.Is(err, errInvalidScanSchedulePattern) {
		t.Fatalf("invalid runtime timezone error = %v; want invalid schedule", err)
	}
	badWindow := pattern
	badWindow.windowSeconds++
	if _, _, err := simulateEveryMinuteSchedule(ctx, badWindow, 61*time.Second, false); !errors.Is(err, errInvalidScanSchedulePattern) {
		t.Fatalf("inconsistent compact window error = %v; want invalid schedule", err)
	}
	daily, err := schedulePattern(ctx, "UTC", "0 0 * * *")
	if err != nil || !daily.ok {
		t.Fatalf("daily pattern = %+v, error %v", daily, err)
	}
	daily.identity.timezone = "Mars/Olympus"
	if _, _, err := memoizedScheduleRunsForDurationWithBudget(ctx, make(map[scanScheduleDurationKey]scanScheduleDurationEstimate), daily, 25*60*60, false, nil); !errors.Is(err, errInvalidScanSchedulePattern) {
		t.Fatalf("invalid memoized runtime timezone error = %v; want invalid schedule", err)
	}
}

func mustLoadLocation(t *testing.T, timezone string) *time.Location {
	t.Helper()
	location, err := time.LoadLocation(timezone)
	if err != nil {
		t.Fatal(err)
	}
	return location
}

func TestScanJobRunsPerDayHonorsCancellationAndConcurrentCalls(t *testing.T) {
	t.Parallel()
	app := &App{Config: &config.Config{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := app.scanJobSchedule(ctx, config.Job{Schedule: "0 0 1 1 *"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled schedule estimate error = %v, want context.Canceled", err)
	}

	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runs, ok := app.scanJobRunsPerDay(config.Job{Schedule: "0 0 1 1 *"})
			if !ok || math.Abs(runs-4.0/1461.0) > 0.001 {
				errs <- fmt.Errorf("concurrent cached schedule = %.6f, valid %t", runs, ok)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	app.scanSlotDemand.mu.Lock()
	runScheduleEntries := len(app.scanSlotDemand.runsPerDay)
	if runScheduleEntries != 1 {
		app.scanSlotDemand.mu.Unlock()
		t.Fatalf("concurrent cache holds %d schedule entries, want one", runScheduleEntries)
	}
	app.scanSlotDemand.mu.Unlock()

	oldRecord := store.JobRecord{
		ID: "concurrent-duration-key", Revision: 1, UpdatedAt: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		Job: config.NormalizeJob(config.Job{Name: "old-revision", Targets: []string{"192.0.2.1"}}),
	}
	newRecord := oldRecord
	newRecord.Revision = 2
	newRecord.UpdatedAt = oldRecord.UpdatedAt.Add(time.Minute)
	newRecord.Job.Name = "new-revision"
	newRecord.Job.Targets = []string{"192.0.2.2"}
	var keyWG sync.WaitGroup
	keyErrs := make(chan error, workers)
	for i := range workers {
		record := oldRecord
		if i%2 == 1 {
			record = newRecord
		}
		keyWG.Add(1)
		go func() {
			defer keyWG.Done()
			got := app.scanDurationKey(record)
			if want := store.NewScanDurationKey(record); got != want {
				keyErrs <- fmt.Errorf("revision %d cached duration key = %+v, want %+v", record.Revision, got, want)
			}
		}()
	}
	keyWG.Wait()
	close(keyErrs)
	for err := range keyErrs {
		t.Error(err)
	}
	if got, want := app.scanDurationKey(newRecord), store.NewScanDurationKey(newRecord); got != want {
		t.Fatalf("latest duration key = %+v, want %+v", got, want)
	}
	app.scanSlotDemand.mu.Lock()
	cachedKey := app.scanSlotDemand.keys[newRecord.ID]
	app.scanSlotDemand.mu.Unlock()
	if cachedKey.revision != newRecord.Revision || cachedKey.key != store.NewScanDurationKey(newRecord) {
		t.Fatalf("concurrent cache retained revision %d key %+v, want revision %d key %+v", cachedKey.revision, cachedKey.key, newRecord.Revision, store.NewScanDurationKey(newRecord))
	}
}

func TestScanDurationKeyCacheIsBounded(t *testing.T) {
	t.Parallel()
	app := &App{}
	for i := 0; i <= scanDurationKeyCacheLimit; i++ {
		record := store.JobRecord{
			ID: fmt.Sprintf("bounded-duration-key-%05d", i), Revision: 1,
			Job: config.NormalizeJob(config.Job{Name: fmt.Sprintf("bounded-%05d", i)}),
		}
		app.scanDurationKey(record)
	}
	app.scanSlotDemand.mu.Lock()
	defer app.scanSlotDemand.mu.Unlock()
	if got := len(app.scanSlotDemand.keys); got != scanDurationKeyCacheLimit {
		t.Fatalf("duration-key cache holds %d entries, want its %d-entry bound", got, scanDurationKeyCacheLimit)
	}
}

func TestScanDurationKeyCacheAdmissionWorkIsBoundedAndDeterministic(t *testing.T) {
	t.Parallel()
	const jobCount = 25_000
	records := make([]store.JobRecord, jobCount)
	ranked := make([]scanDurationKeyRank, jobCount)
	for i := range records {
		id := fmt.Sprintf("bounded-admission-%05d", i)
		records[i] = store.JobRecord{
			ID: id, Revision: 1,
			Job: config.NormalizeJob(config.Job{Name: fmt.Sprintf("job-%05d", i)}),
		}
		ranked[i] = scanDurationKeyRank{id: id, rank: scanCacheRank(id)}
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].rank != ranked[j].rank {
			return ranked[i].rank < ranked[j].rank
		}
		return ranked[i].id < ranked[j].id
	})
	wantIDs := make(map[string]struct{}, scanDurationKeyCacheLimit)
	for _, entry := range ranked[:scanDurationKeyCacheLimit] {
		wantIDs[entry.id] = struct{}{}
	}

	maxComparisonsPerAdmission := uint64(3*bits.Len(uint(scanDurationKeyCacheLimit)) + 2)
	maxComparisons := uint64(jobCount) * maxComparisonsPerAdmission
	for _, reverse := range []bool{false, true} {
		app := &App{}
		for i := range records {
			index := i
			if reverse {
				index = len(records) - i - 1
			}
			app.scanDurationKey(records[index])
		}

		app.scanSlotDemand.mu.Lock()
		gotIDs := make(map[string]struct{}, len(app.scanSlotDemand.keys))
		for id, value := range app.scanSlotDemand.keys {
			gotIDs[id] = struct{}{}
			if value.rank != scanCacheRank(id) {
				app.scanSlotDemand.mu.Unlock()
				t.Fatalf("cached duration key %q has rank %d, want %d", id, value.rank, scanCacheRank(id))
			}
		}
		heapEntries := len(app.scanSlotDemand.keyRanks)
		comparisons := app.scanSlotDemand.keyAdmissionWork
		app.scanSlotDemand.mu.Unlock()

		if len(gotIDs) != scanDurationKeyCacheLimit || heapEntries != scanDurationKeyCacheLimit {
			t.Fatalf("reverse insertion %t retained %d keys and %d heap entries, want %d each", reverse, len(gotIDs), heapEntries, scanDurationKeyCacheLimit)
		}
		if !reflect.DeepEqual(gotIDs, wantIDs) {
			t.Fatalf("reverse insertion %t retained a request-order-dependent subset", reverse)
		}
		if comparisons == 0 || comparisons > maxComparisons {
			t.Fatalf("reverse insertion %t used %d rank comparisons for %d jobs; want 1..%d bounded comparisons", reverse, comparisons, jobCount, maxComparisons)
		}
	}
}

// A timeout edit changes a cycle's execution hash, so it drops completed
// cycle samples. A scan without a cycle records only its scope hash and TCP
// scanner profile revision, so the same edit keeps such a scan's samples.
func TestScanSlotDemandTimeoutEditDropsOnlyCycleSamples(t *testing.T) {
	t.Parallel()
	for kind, wantHistory := range map[string]int{"cycle": 0, "scan": 1} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			db := storetest.OpenFresh(t)
			ts := defaultTenant(db)
			record := createDemandJobWithSamples(t, db, kind)
			job := record.Job
			job.Timeout = config.Duration(2 * time.Hour)
			if _, _, err := ts.UpdateJob(ctx, record.ID, record.Revision, job, true, false, false); err != nil {
				t.Fatal(err)
			}
			demand, err := (&App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}).ScanSlotDemand(ctx, ts)
			if err != nil {
				t.Fatal(err)
			}
			if demand.HistoryJobs != wantHistory {
				t.Fatalf("demand after a timeout edit = %+v; want %d history jobs", demand, wantHistory)
			}
		})
	}
}
