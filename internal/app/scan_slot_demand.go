package app

import (
	"context"
	"errors"
	"hash/fnv"
	"math"
	"math/bits"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/robfig/cron/v3"
)

const (
	scanSlotDemandHistoryLimit = 11
	// slotSecondsPerDay is the work one scan slot does in a day. A job runs
	// at most once at a time, so it is also the most that one job can add
	// to the demand.
	slotSecondsPerDay = 24 * 60 * 60
	// scanRunsPerDayCacheLimit bounds the remembered schedules, and
	// scanDurationKeyCacheLimit bounds the remembered job revisions. Full
	// caches retain a deterministic subset instead of discarding every entry.
	scanRunsPerDayCacheLimit     = 1024
	scanRunsPerDayCacheByteLimit = 8 * 1024 * 1024
	// scanRunsPerDayCacheEntrySize conservatively covers fixed map buckets,
	// value/string headers, and allocator overhead for a retained entry.
	scanRunsPerDayCacheEntrySize = 4096
	scanDurationKeyCacheLimit    = 16384
	// scanProjectionCacheLimit bounds each of the two generations of
	// remembered schedule-duration projections.
	scanProjectionCacheLimit = 4096
	// scanScheduleRequestWorkLimit bounds the schedule work of one tenant or
	// deployment demand request, across pattern expansion and duration
	// projection, so that a request finishes well within the estimate's
	// deadline however dense its schedules are.
	scanScheduleRequestWorkLimit = 540_000
	// scanScheduleJobWorkLimit bounds the work of expanding one job's
	// schedule and, separately, of projecting its runs on that schedule. A
	// request takes its units' jobs in turn, and each job's expansion and
	// projections first get only scanScheduleJobFirstPassWorkLimit each,
	// and only until half of the request's work is spent; the jobs that need
	// more, or that came later, get the rest of their limit after every
	// other job. A projection that a schedule's known work shows to need
	// more than the share waits without spending it, and an expansion or
	// projection that runs over the share spends it once for its schedule,
	// so dense schedules cannot spend the request's work before ordinary
	// jobs are estimated.
	scanScheduleJobWorkLimit          = 50_000
	scanScheduleJobFirstPassWorkLimit = 1_000
	scanScheduleSampleStartYear       = 2024
	scanScheduleSampleEndYear         = 2028
)

var (
	errInvalidScanSchedulePattern       = errors.New("invalid scan schedule pattern")
	errScheduleSimulationBudgetExceeded = errors.New("scan schedule work budget exceeded")
)

// ScanSlotDemand is a tenant's estimated scheduled scan work compared with
// the slot-hours its effective scan-slot limit can provide in a day.
type ScanSlotDemand struct {
	EnabledJobs     int `json:"enabled_jobs"`
	HistoryJobs     int `json:"history_jobs"`
	LowerBoundJobs  int `json:"lower_bound_jobs"`
	UnestimatedJobs int `json:"unestimated_jobs"`
	// WorkLimitedJobs counts jobs left out of the estimate because simulating
	// their schedules would exceed the estimate's work limit.
	WorkLimitedJobs int `json:"work_limited_jobs"`
	// CadenceUnattainableJobs counts jobs for which the estimated run duration
	// makes the scheduler skip at least one scheduled tick.
	CadenceUnattainableJobs    int     `json:"cadence_unattainable_jobs"`
	Slots                      int     `json:"slots"`
	EstimatedSlotSecondsPerDay float64 `json:"estimated_slot_seconds_per_day"`
	CapacitySlotSecondsPerDay  float64 `json:"capacity_slot_seconds_per_day"`
	UtilizationPercent         float64 `json:"utilization_percent"`
	OverCapacity               bool    `json:"over_capacity"`
}

// ScanSlotDemand estimates the unit's scheduled demand from enabled jobs and
// compares it with the unit's effective slot capacity. A job's runs are the
// attempts of its most recent scan samples that ran with its current scan
// settings: each completed scan without a cycle, whether it succeeded, was
// incomplete or timed out, each attempt of a completed resumable cycle, and
// each recorded attempt of the job's cycle in progress. Each run holds a
// slot for its recorded duration, at most the job's timeout, and a run that
// timed out holds it for the job's current timeout; the estimate uses the
// mean over those runs. A job whose newest runs with its current settings
// all timed out runs for its timeout; jobs without samples use only work
// bounded by an explicitly configured scanner rate. The estimate simulates
// the schedule ticks a job can start after each prior run ends. A run that
// its timeout ends holds the job until after the tick at its timeout, so
// that tick is skipped. A job adds at most one slot-day, because it runs at
// most once at a time. A job whose resumable cycle stalled adds nothing
// until someone retries the cycle or its resume window ends, because
// scheduled runs skip it until then, and a stalled cycle's attempts are not
// runs.
//
// The effective capacity is a limit, not a reservation: every unit's scans
// share the deployment's one pool of slots, so DeploymentScanDemand compares
// the units' estimates together with that pool.
func (a *App) ScanSlotDemand(ctx context.Context, ts *store.TenantStore) (ScanSlotDemand, error) {
	if a == nil || ts == nil {
		return ScanSlotDemand{}, store.ErrNoTenantScope
	}
	result, err := a.scheduledScanDemand(ctx, ts)
	if err != nil {
		return result, err
	}
	limits, err := a.TenantCapacityLimits(ctx, ts)
	if err != nil {
		return result, err
	}
	result.Slots = limits.MaxConcurrentScans
	result.CapacitySlotSecondsPerDay, result.UtilizationPercent, result.OverCapacity = compareSlotDemand(result.EstimatedSlotSecondsPerDay, limits.MaxConcurrentScans)
	return result, nil
}

// scheduledScanDemand estimates the scheduled demand of the enabled jobs of
// the unit of ts, as ScanSlotDemand describes, and counts the jobs by the
// source of their estimate. It leaves the capacity fields zero.
func (a *App) scheduledScanDemand(ctx context.Context, ts *store.TenantStore) (ScanSlotDemand, error) {
	return a.scheduledScanDemandWithSimulationCache(ctx, ts, nil, nil)
}

// scheduledScanDemandWithSimulationCache estimates the unit of ts with the
// request's projection memo and work budget; nil values start new ones.
// Both belong to the current request, so no tenant data is shared.
func (a *App) scheduledScanDemandWithSimulationCache(ctx context.Context, ts *store.TenantStore, simulations map[scanScheduleDurationKey]scanScheduleDurationEstimate, budget *scanScheduleSimulationBudget) (ScanSlotDemand, error) {
	var result ScanSlotDemand
	work := newScanDemandWork(simulations, budget)
	work.cache = &a.scanSlotDemand
	if err := a.collectScheduledScanDemand(ctx, ts, &result, work); err != nil {
		return result, err
	}
	err := a.projectScheduledScanDemand(ctx, work)
	return result, err
}

// scanDemandWork is the schedule work of one tenant or deployment demand
// request: the jobs it still has to project, the schedule expansions and
// schedule-duration projections it has computed, which contain no tenant
// data, and its work budget.
type scanDemandWork struct {
	simulations map[scanScheduleDurationKey]scanScheduleDurationEstimate
	// cache is the App's cache, which remembers projections across
	// requests, or nil.
	cache *scanSlotDemandCache
	// schedules holds every expansion of the request by timezone and
	// schedule text, whether or not the App's cache keeps it, and those
	// that failed or wait for the second pass, so that each schedule is
	// expanded at most once in each pass.
	schedules map[scanRunsPerDayKey]scanDemandSchedule
	budget    *scanScheduleSimulationBudget
	jobs      []scanDemandJob
	// units counts the units whose jobs the request has collected.
	units int
	// firstPassLimit is the request's work after which the first pass gives
	// no projection a share, so that the jobs that wait for the second pass
	// keep at least the rest.
	firstPassLimit int
	// deferred holds the projections, and deferredSchedules the schedules,
	// of which one projection needed more than a job's first-pass share on
	// its own. The first pass leaves other jobs' projections of them for the
	// second pass without spending that share again.
	deferred          map[scanScheduleDurationKey]bool
	deferredSchedules map[scanScheduleIdentity]bool
	// exceeded holds the projections that needed more than a job's whole
	// work limit on their own, which fail for every other job at once.
	exceeded map[scanScheduleDurationKey]bool
}

func newScanDemandWork(simulations map[scanScheduleDurationKey]scanScheduleDurationEstimate, budget *scanScheduleSimulationBudget) *scanDemandWork {
	if simulations == nil {
		simulations = make(map[scanScheduleDurationKey]scanScheduleDurationEstimate)
	}
	if budget == nil {
		budget = &scanScheduleSimulationBudget{limit: scanScheduleRequestWorkLimit}
	}
	return &scanDemandWork{
		simulations: simulations, budget: budget,
		schedules:         make(map[scanRunsPerDayKey]scanDemandSchedule),
		firstPassLimit:    budget.used + max(budget.limit-budget.used, 0)/2,
		deferred:          make(map[scanScheduleDurationKey]bool),
		deferredSchedules: make(map[scanScheduleIdentity]bool),
		exceeded:          make(map[scanScheduleDurationKey]bool),
	}
}

// errScanDemandDeferred reports that a job's expansion or projection waits
// for the second pass.
var errScanDemandDeferred = errors.New("scan demand projection deferred to the second pass")

// scanDemandSchedule is the outcome of a request's expansion of a schedule:
// its pattern; or err, errScheduleSimulationBudgetExceeded when it needed
// more than a job's whole limit or the request's remaining work; or
// deferred when it needed more than a job's first-pass share.
type scanDemandSchedule struct {
	value    scanRunsPerDayValue
	err      error
	deferred bool
}

// schedule returns the expansion of the job's schedule: from the request's
// memo, from the App's cache, which takes no work, or by expanding it. In
// the first pass an expansion gets only the job's first-pass share, and none
// once the first pass has spent its half of the request's work; one that
// does not fit waits for the second pass, with errScanDemandDeferred, and
// the schedule's other jobs wait without spending another share. In the
// second pass it gets the job's whole limit. An expansion that needs more
// than that limit, or than the request's remaining work, fails for every
// job with the schedule without spending more.
func (work *scanDemandWork) schedule(ctx context.Context, a *App, job config.Job, firstPass bool) (scanRunsPerDayValue, error) {
	key := a.scanRunsPerDayKey(job)
	if memo, found := work.schedules[key]; found {
		if !memo.deferred {
			return memo.value, memo.err
		}
		if firstPass {
			return scanRunsPerDayValue{}, errScanDemandDeferred
		}
	}
	limit := scanScheduleJobWorkLimit
	if firstPass {
		limit = scanScheduleJobFirstPassWorkLimit
		if work.budget.used >= work.firstPassLimit {
			limit = 0
		}
	}
	value, err := a.scanJobScheduleWithBudget(ctx, job, &scanScheduleSimulationBudget{limit: limit, parent: work.budget})
	if errors.Is(err, errScheduleSimulationBudgetExceeded) && firstPass && !work.budget.exhausted() {
		work.schedules[key] = scanDemandSchedule{deferred: true}
		return scanRunsPerDayValue{}, errScanDemandDeferred
	}
	if err != nil && !errors.Is(err, errScheduleSimulationBudgetExceeded) {
		return scanRunsPerDayValue{}, err
	}
	work.schedules[key] = scanDemandSchedule{value: value, err: err}
	return value, err
}

// scanDemandJob is an enabled scheduled job whose demand a request adds to
// its unit's estimate once it has projected the job's schedule.
type scanDemandJob struct {
	unit *ScanSlotDemand
	// unitIndex is the position of the job's unit in the request, and
	// position the job's position among the unit's jobs.
	unitIndex, position int
	job                 config.Job
	// runs are the kinds of run the job's estimate expects. They are empty
	// for a job whose run duration cannot be estimated at all.
	runs []scanDemandRun
	// history, lowerBound and unestimated name the sources of the estimate,
	// which the unit counts once the projection succeeds.
	history, lowerBound, unestimated bool
}

// scanDemandRun is one kind of run of a job: how long it holds a scan slot
// and whether the job's timeout ends it.
type scanDemandRun struct {
	// seconds is the slot time of the run, at most the job's timeout.
	seconds float64
	// endsAtTimeout is set when the timeout ends the run. The run's claim on
	// the job lasts until the run is finalized after the timeout, so the
	// scheduler skips a tick at exactly the timeout.
	endsAtTimeout bool
	// weight is how many of the job's runs are of this kind.
	weight float64
}

// newScanDemandRun returns a run whose work takes seconds, which the job's
// timeout ends when it takes at least the timeout. A timeout of zero ends
// nothing.
func newScanDemandRun(seconds, timeout, weight float64) scanDemandRun {
	run := scanDemandRun{seconds: max(seconds, 0), weight: weight}
	if timeout > 0 && run.seconds >= timeout {
		run.seconds, run.endsAtTimeout = timeout, true
	}
	return run
}

// historyDemandRuns returns the runs of a job's samples, each attempt at its
// recorded duration up to the job's timeout. An attempt that its timeout
// ended needed at least that timeout, so it runs for the job's current
// timeout, which ends it: a scan without a cycle keeps its samples across a
// timeout edit, and a raised timeout lets such a run take longer. A completed
// cycle whose attempt count exceeds its recorded attempts adds the missing
// attempts as runs without slot time, so the cycle's runs average its
// recorded time over its attempt count.
func historyDemandRuns(samples []store.ScanDurationSample, timeout float64) []scanDemandRun {
	type kind struct {
		seconds       float64
		endsAtTimeout bool
	}
	weights := make(map[kind]float64)
	add := func(run scanDemandRun) {
		weights[kind{seconds: run.seconds, endsAtTimeout: run.endsAtTimeout}] += run.weight
	}
	for _, sample := range samples {
		for _, attempt := range sample.Attempts {
			seconds := attempt.Duration.Seconds()
			if attempt.TimedOut && timeout > 0 {
				seconds = timeout
			}
			add(newScanDemandRun(seconds, timeout, 1))
		}
		if missing := sample.Runs - len(sample.Attempts); missing > 0 {
			add(scanDemandRun{weight: float64(missing)})
		}
	}
	runs := make([]scanDemandRun, 0, len(weights))
	for key, weight := range weights {
		runs = append(runs, scanDemandRun{seconds: key.seconds, endsAtTimeout: key.endsAtTimeout, weight: weight})
	}
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].seconds != runs[j].seconds {
			return runs[i].seconds < runs[j].seconds
		}
		return !runs[i].endsAtTimeout && runs[j].endsAtTimeout
	})
	return runs
}

// collectScheduledScanDemand counts the enabled jobs of the unit of ts into
// unit, reads the recent run durations of the scheduled ones, and queues
// them on work for projection.
func (a *App) collectScheduledScanDemand(ctx context.Context, ts *store.TenantStore, unit *ScanSlotDemand, work *scanDemandWork) error {
	jobs, err := ts.ListJobs(ctx, false)
	if err != nil {
		return err
	}
	var scheduled []store.JobRecord
	var keys []store.ScanDurationKey
	for _, record := range jobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !record.Enabled || record.Archived {
			continue
		}
		unit.EnabledJobs++
		if strings.TrimSpace(record.Job.Schedule) == "" {
			continue
		}
		scheduled = append(scheduled, record)
		keys = append(keys, a.scanDurationKey(record))
	}
	if len(scheduled) == 0 {
		return nil
	}
	history, err := ts.ListCompletedScanCycleDurations(ctx, keys, scanSlotDemandHistoryLimit)
	if err != nil {
		return err
	}
	timedOutOnly, err := ts.LatestScanRunsTimedOut(ctx, keys, scanSlotDemandHistoryLimit)
	if err != nil {
		return err
	}
	stalled, err := ts.ListStalledScanCycles(ctx)
	if err != nil {
		return err
	}
	now := a.nowUTC()
	unitIndex := work.units
	work.units++
	for position, record := range scheduled {
		// Scheduled runs skip a job whose resumable cycle stalled, as
		// prepareRun does, until someone retries the cycle or its resume
		// window ends, so until then the job adds no demand.
		if until, found := stalled[record.ID]; found && (until.IsZero() || now.Before(until)) {
			continue
		}
		job := scanDemandJob{unit: unit, unitIndex: unitIndex, position: position, job: record.Job}
		timeout := record.Job.Timeout.Value().Seconds()
		// A job whose newest runs with its current settings all timed out
		// times out now, whatever its older samples took.
		if timedOutOnly[record.ID] {
			job.runs, job.history = []scanDemandRun{newScanDemandRun(timeout, timeout, 1)}, true
		} else if samples := history[record.ID]; len(samples) > 0 {
			job.runs, job.history = historyDemandRuns(samples, timeout), true
		} else {
			lowerBound, hasBound, incomplete := scanRateLowerBound(record.Job, a.Config.Scanner.MaxJobHostsValue())
			if hasBound {
				job.runs, job.lowerBound = []scanDemandRun{newScanDemandRun(lowerBound, timeout, 1)}, true
			}
			job.unestimated = !hasBound || incomplete
		}
		work.jobs = append(work.jobs, job)
	}
	return nil
}

// projectScheduledScanDemand expands the schedule of every queued job,
// projects its runs on it, and adds its demand to its unit. It takes the
// units' jobs in turn, each unit's first job, then each unit's second, and
// so on. In the first pass each job's expansion and projections get only a
// small share of its work limit, and none at all once half of the request's
// work is spent. A job whose expansion or projection needs more than its
// share, by the schedule's known work or by trying it, or that the first
// pass gave no share, waits for the second pass, which gives the waiting
// jobs, in the same order, their whole limit from what is left. Ordinary
// jobs are therefore estimated before dense schedules take more, and those
// cannot spend the request's work for the second pass in the first. A job
// that its own limit or the request's remaining work cannot finish counts
// as work-limited and adds nothing.
func (a *App) projectScheduledScanDemand(ctx context.Context, work *scanDemandWork) error {
	order := make([]int, len(work.jobs))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		left, right := &work.jobs[order[i]], &work.jobs[order[j]]
		if left.position != right.position {
			return left.position < right.position
		}
		return left.unitIndex < right.unitIndex
	})
	var deferred []int
	for _, i := range order {
		retry, err := a.projectScanDemandJob(ctx, work, &work.jobs[i], true)
		if err != nil {
			return err
		}
		if retry {
			deferred = append(deferred, i)
		}
	}
	for _, i := range deferred {
		if _, err := a.projectScanDemandJob(ctx, work, &work.jobs[i], false); err != nil {
			return err
		}
	}
	return nil
}

// projectScanDemandJob expands the job's schedule and projects its runs on
// it, and adds the job to its unit's estimate and counts. Each step gets its
// own work limit, of which it gets only the first-pass share in the first
// pass. It reports retry when the expansion or the projection waits for the
// second pass, and leaves the job uncounted until then. A job without any
// run to project is unestimated, whatever its schedule, so its schedule is
// not expanded.
func (a *App) projectScanDemandJob(ctx context.Context, work *scanDemandWork, job *scanDemandJob, firstPass bool) (retry bool, err error) {
	if len(job.runs) == 0 {
		job.unit.UnestimatedJobs++
		return false, nil
	}
	schedule, err := work.schedule(ctx, a, job.job, firstPass)
	if errors.Is(err, errScanDemandDeferred) {
		return true, nil
	}
	if errors.Is(err, errScheduleSimulationBudgetExceeded) {
		job.unit.WorkLimitedJobs++
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !schedule.ok {
		job.unit.UnestimatedJobs++
		return false, nil
	}
	if schedule.runsPerDay <= 0 {
		return false, nil
	}
	limit := scanScheduleJobWorkLimit
	if firstPass {
		limit = scanScheduleJobFirstPassWorkLimit
	}
	projection := &scanScheduleSimulationBudget{limit: limit, parent: work.budget}
	demand, skipped, err := projectScanDemandRuns(job.runs, func(run scanDemandRun) (float64, bool, error) {
		return work.project(ctx, schedule, run, projection, firstPass)
	})
	if errors.Is(err, errScanDemandDeferred) {
		return true, nil
	}
	if errors.Is(err, errScheduleSimulationBudgetExceeded) {
		job.unit.WorkLimitedJobs++
		return false, nil
	}
	if errors.Is(err, errInvalidScanSchedulePattern) {
		job.unit.UnestimatedJobs++
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if job.history {
		job.unit.HistoryJobs++
	}
	if job.lowerBound {
		job.unit.LowerBoundJobs++
	}
	if job.unestimated {
		job.unit.UnestimatedJobs++
	}
	if skipped {
		job.unit.CadenceUnattainableJobs++
	}
	job.unit.EstimatedSlotSecondsPerDay += min(demand, slotSecondsPerDay)
	return false, nil
}

// project returns the runs per day that the schedule starts for runs of one
// kind, and whether they skip a tick, from the request's memo when another
// job has the same schedule and projected run. budget is the job's own
// share or limit. A projection that the remaining work cannot cover even by
// the schedule's known work fails without spending any. In the first pass, a
// projection waits for the second, with errScanDemandDeferred, when it needs
// more than the job's share, when one of its key or of its schedule already
// did, or when the first pass has spent its half of the request's work.
func (work *scanDemandWork) project(ctx context.Context, schedule scanRunsPerDayValue, run scanDemandRun, budget *scanScheduleSimulationBudget, firstPass bool) (float64, bool, error) {
	if !schedule.ok || schedule.runsPerDay <= 0 {
		return 0, false, nil
	}
	seconds, endsAtTimeout := schedule.projectedRun(run.seconds, run.endsAtTimeout)
	if schedule.runFitsEveryGap(seconds, endsAtTimeout) {
		return schedule.runsPerDay, false, nil
	}
	key := schedule.durationKey(seconds, endsAtTimeout)
	if estimate, ok := work.simulations[key]; ok {
		return estimate.runsPerDay, estimate.skipped, nil
	}
	if estimate, ok := work.cache.projection(key); ok {
		work.simulations[key] = estimate
		return estimate.runsPerDay, estimate.skipped, nil
	}
	floor := schedule.projectionWorkFloor(seconds)
	if work.exceeded[key] || work.budget.remaining() < floor {
		return 0, false, errScheduleSimulationBudgetExceeded
	}
	alone := budget.used == 0
	if budget.remaining() < floor {
		if firstPass {
			return 0, false, errScanDemandDeferred
		}
		if alone {
			work.exceeded[key] = true
		}
		return 0, false, errScheduleSimulationBudgetExceeded
	}
	if firstPass && (work.deferred[key] || work.deferredSchedules[key.schedule] || work.budget.used >= work.firstPassLimit) {
		return 0, false, errScanDemandDeferred
	}
	runsPerDay, skipped, err := memoizedScheduleRunsForDurationWithBudget(ctx, work.simulations, schedule, seconds, endsAtTimeout, budget)
	if err == nil {
		work.cache.retainProjection(key, scanScheduleDurationEstimate{runsPerDay: runsPerDay, skipped: skipped})
	}
	if !errors.Is(err, errScheduleSimulationBudgetExceeded) || work.budget.exhausted() {
		return runsPerDay, skipped, err
	}
	// The job's own share or limit ran out.
	if firstPass {
		if alone {
			work.deferred[key], work.deferredSchedules[key.schedule] = true, true
		}
		return 0, false, errScanDemandDeferred
	}
	if alone {
		work.exceeded[key] = true
	}
	return runsPerDay, skipped, err
}

// projectScanDemandRuns returns a job's slot-seconds per day for its runs,
// and whether a run makes the scheduler skip a tick, with project giving
// the runs per day of each kind of run. A run of each kind starts at the
// ticks its own projection allows, so the job starts runs as often as the
// mean time from one start to the next allows, and each start holds a slot
// for the mean slot time of the runs.
func projectScanDemandRuns(runs []scanDemandRun, project func(scanDemandRun) (float64, bool, error)) (demand float64, skipped bool, err error) {
	var weight, slotSeconds, daysPerStart float64
	for _, run := range runs {
		if run.weight <= 0 {
			continue
		}
		runsPerDay, runSkipped, err := project(run)
		if err != nil {
			return 0, false, err
		}
		skipped = skipped || runSkipped
		weight += run.weight
		slotSeconds += run.weight * run.seconds
		if runsPerDay <= 0 {
			daysPerStart = math.Inf(1)
		} else {
			daysPerStart += run.weight / runsPerDay
		}
	}
	if weight <= 0 || slotSeconds <= 0 || math.IsInf(daysPerStart, 1) || daysPerStart <= 0 {
		return 0, skipped, nil
	}
	return slotSeconds / daysPerStart, skipped, nil
}

// compareSlotDemand compares an estimated demand in slot-seconds per day
// with what the slots provide in a day, and returns that capacity, the
// demand as a percentage of it, and whether the demand exceeds it. Without
// slots the percentage is 0 and any demand exceeds the capacity.
func compareSlotDemand(estimated float64, slots int) (capacity, utilization float64, over bool) {
	capacity = float64(max(slots, 0)) * slotSecondsPerDay
	if capacity > 0 {
		utilization = estimated / capacity * 100
	}
	return capacity, utilization, estimated > capacity
}

// scanRunsPerDayKey is a schedule's text in the timezone it runs in.
type scanRunsPerDayKey struct {
	timezone, schedule string
}

// scanScheduleIdentity contains the parsed cron fields, so schedules with
// different whitespace or equivalent field syntax share duration estimates.
type scanScheduleIdentity struct {
	timezone                     string
	second, minute, hour         uint64
	dayOfMonth, month, dayOfWeek uint64
}

type scanScheduleDurationKey struct {
	schedule      scanScheduleIdentity
	runSeconds    uint64
	endsAtTimeout bool
}

type scanScheduleDurationEstimate struct {
	runsPerDay float64
	skipped    bool
}

// scanScheduleSimulationBudget bounds schedule work. It counts
// Schedule.Next calls, the timezone transitions, day spans and months that
// an expansion examines, and the runs and day spans that a projection
// simulates. A job's budget has the request's budget as its parent, and
// work counts against both. Work that exceeds a budget leaves its job
// unestimated instead of returning a partial result.
type scanScheduleSimulationBudget struct {
	limit  int
	used   int
	parent *scanScheduleSimulationBudget
}

func (budget *scanScheduleSimulationBudget) take() bool {
	if budget.used >= budget.limit {
		return false
	}
	if budget.parent != nil && !budget.parent.take() {
		return false
	}
	budget.used++
	return true
}

// exhausted reports whether the budget has no work left.
func (budget *scanScheduleSimulationBudget) exhausted() bool {
	return budget.used >= budget.limit
}

// remaining returns how much work the budget, and every budget it counts
// against, has left.
func (budget *scanScheduleSimulationBudget) remaining() int {
	left := max(budget.limit-budget.used, 0)
	if budget.parent != nil {
		left = min(left, budget.parent.remaining())
	}
	return left
}

type budgetedCronSchedule struct {
	schedule  cron.Schedule
	budget    *scanScheduleSimulationBudget
	exhausted *bool
}

func (schedule budgetedCronSchedule) Next(after time.Time) time.Time {
	if !schedule.budget.take() {
		*schedule.exhausted = true
		return time.Time{}
	}
	return schedule.schedule.Next(after)
}

func takeScheduleWork(ctx context.Context, budget *scanScheduleSimulationBudget) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if budget != nil && !budget.take() {
		return errScheduleSimulationBudgetExceeded
	}
	return nil
}

type scanRunsPerDayValue struct {
	runsPerDay    float64
	ok            bool
	startYear     int
	endYear       int
	windowSeconds float64
	// minimumGap is the shortest time from one tick of the sample to the
	// next, or zero when the sample has fewer than two ticks. A run that
	// ends within it never makes the scheduler skip a tick.
	minimumGap time.Duration
	// minuteTicks is set when every tick of the sample falls a whole number
	// of minutes after every other, so that the ticks a run blocks depend
	// only on the first whole minute after its start at which it no longer
	// holds the job; see projectedRun.
	minuteTicks bool
	// projectionFloor is the least work that walkScheduleDays takes for a
	// run on the schedule; see scheduleWindow.
	projectionFloor int
	identity        scanScheduleIdentity
	// days are the sample's days on which the schedule ticks, in order.
	days []scheduleDaySpan
	rank uint64
}

// scheduleDaySpan is a run of consecutive sample days on which a schedule
// ticks. An ordinary day lasts 24 hours from midnight without a change of
// its timezone's offset, so its ticks are the schedule's times of day; the
// cron schedule itself gives the ticks of any other, irregular, day, and of
// a day into which the scheduler's search for the tick after an irregular
// day drifts, skipping some of its first ticks.
type scheduleDaySpan struct {
	// start is the offset of the span's first day from the sample start, in
	// seconds.
	start uint32
	// days is the number of ordinary days in the span, or zero for a single
	// day whose ticks the cron schedule gives, which lasts length seconds.
	days   uint32
	length uint32
}

// cachedScanDurationKey is the duration key of one revision of a job.
type cachedScanDurationKey struct {
	revision int64
	updated  time.Time
	key      store.ScanDurationKey
	rank     uint64
}

type scanDurationKeyRank struct {
	id   string
	rank uint64
}

// scanSlotDemandCache remembers, for every business unit of the process,
// the parts of the scan-slot demand estimate that a request would otherwise
// compute again for each job: each schedule's bounded occurrence pattern,
// which depends only on its text and timezone, each job revision's
// duration key, whose hashes a revision fixes, and the schedule-duration
// projections that requests used most recently, which depend only on the
// schedule and the run. Its zero value is ready to use.
type scanSlotDemandCache struct {
	mu              sync.Mutex
	runsPerDay      map[scanRunsPerDayKey]scanRunsPerDayValue
	runsPerDayBytes int
	keys            map[string]cachedScanDurationKey
	keyRanks        []scanDurationKeyRank
	// projections and earlierProjections are the current and the previous
	// generation of remembered projections. A projection that a request
	// uses joins the current generation, and when the current generation
	// is full it becomes the previous one, so the projections that no
	// request used during two generations are forgotten.
	projections, earlierProjections map[scanScheduleDurationKey]scanScheduleDurationEstimate
	// keyAdmissionWork counts rank comparisons so tests can detect an
	// accidental return to per-admission map scans.
	keyAdmissionWork uint64
	// runsPerDayComputed counts the schedules computed, for tests.
	runsPerDayComputed int
}

// projection returns a remembered projection. A nil cache remembers none.
// Only a request's successful projections are remembered, each computed
// within a job's work limit, so a projection that needs more than that
// limit is never remembered and still leaves its jobs work-limited.
func (cache *scanSlotDemandCache) projection(key scanScheduleDurationKey) (scanScheduleDurationEstimate, bool) {
	if cache == nil {
		return scanScheduleDurationEstimate{}, false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if estimate, ok := cache.projections[key]; ok {
		return estimate, true
	}
	estimate, ok := cache.earlierProjections[key]
	if ok {
		cache.addProjection(key, estimate)
	}
	return estimate, ok
}

// retainProjection remembers a projection that a request computed.
func (cache *scanSlotDemandCache) retainProjection(key scanScheduleDurationKey, estimate scanScheduleDurationEstimate) {
	if cache == nil {
		return
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.addProjection(key, estimate)
}

// addProjection adds a projection to the current generation, which first
// becomes the previous one when it is full. The caller holds cache.mu.
func (cache *scanSlotDemandCache) addProjection(key scanScheduleDurationKey, estimate scanScheduleDurationEstimate) {
	if len(cache.projections) >= scanProjectionCacheLimit {
		cache.earlierProjections, cache.projections = cache.projections, nil
	}
	if cache.projections == nil {
		cache.projections = make(map[scanScheduleDurationKey]scanScheduleDurationEstimate)
	}
	cache.projections[key] = estimate
}

// scanJobRunsPerDay returns the job's average scheduled runs per day, which
// the App remembers across requests by the timezone and schedule text. A
// job without its own timezone uses the deployment's, as its schedule does.
func (a *App) scanJobRunsPerDay(job config.Job) (float64, bool) {
	value, err := a.scanJobSchedule(context.Background(), job)
	return value.runsPerDay, value.ok && err == nil
}

func (a *App) scanJobSchedule(ctx context.Context, job config.Job) (scanRunsPerDayValue, error) {
	return a.scanJobScheduleWithBudget(ctx, job, nil)
}

// scanRunsPerDayKey returns the timezone and text of the job's schedule.
func (a *App) scanRunsPerDayKey(job config.Job) scanRunsPerDayKey {
	return scanRunsPerDayKey{timezone: scheduleTimezone(job, a.Config.Timezone), schedule: job.Schedule}
}

// scanJobScheduleWithBudget returns the job's schedule pattern from the
// App's cache, which takes no work, or expands it with budget and offers it
// to the cache.
func (a *App) scanJobScheduleWithBudget(ctx context.Context, job config.Job, budget *scanScheduleSimulationBudget) (scanRunsPerDayValue, error) {
	key := a.scanRunsPerDayKey(job)
	cache := &a.scanSlotDemand
	if err := ctx.Err(); err != nil {
		return scanRunsPerDayValue{}, err
	}
	cache.mu.Lock()
	value, found := cache.runsPerDay[key]
	cache.mu.Unlock()
	if found {
		return value, nil
	}
	// Schedule expansion runs without the lock. Two requests may compute the
	// same new key, but one slow schedule cannot block cache hits for others.
	value, err := schedulePatternWithBudget(ctx, key.timezone, key.schedule, budget)
	if errors.Is(err, errInvalidScanSchedulePattern) {
		// Invalid persisted settings make the estimate unavailable for this job,
		// but should not fail the whole tenant's demand estimate.
		err = nil
	}
	if err != nil {
		return scanRunsPerDayValue{}, err
	}
	value.rank = scanCacheRank(key.timezone, key.schedule)
	cache.mu.Lock()
	if cache.runsPerDay == nil {
		cache.runsPerDay = make(map[scanRunsPerDayKey]scanRunsPerDayValue)
	}
	cache.retainRunsPerDay(key, value)
	cache.runsPerDayComputed++
	cache.mu.Unlock()
	return value, nil
}

// retainRunsPerDay keeps the lowest-ranked schedule entries that fit both
// the count and byte budgets. Weight uses the retained slice capacity, not
// its length, because that is the memory the cache keeps alive.
func (cache *scanSlotDemandCache) retainRunsPerDay(key scanRunsPerDayKey, value scanRunsPerDayValue) {
	if cache.runsPerDay == nil {
		cache.runsPerDay = make(map[scanRunsPerDayKey]scanRunsPerDayValue)
	}
	if previous, exists := cache.runsPerDay[key]; exists {
		cache.runsPerDayBytes -= scanRunsPerDayCacheEntryWeight(key, previous)
		delete(cache.runsPerDay, key)
	}
	weight := scanRunsPerDayCacheEntryWeight(key, value)
	if weight > scanRunsPerDayCacheByteLimit {
		return
	}
	cache.runsPerDay[key] = value
	cache.runsPerDayBytes += weight
	for len(cache.runsPerDay) > scanRunsPerDayCacheLimit || cache.runsPerDayBytes > scanRunsPerDayCacheByteLimit {
		var largest scanRunsPerDayKey
		var largestValue scanRunsPerDayValue
		var largestTie string
		first := true
		for candidate, current := range cache.runsPerDay {
			tie := candidate.timezone + "\x00" + candidate.schedule
			if first || current.rank > largestValue.rank || current.rank == largestValue.rank && tie > largestTie {
				largest, largestValue, largestTie, first = candidate, current, tie, false
			}
		}
		delete(cache.runsPerDay, largest)
		cache.runsPerDayBytes -= scanRunsPerDayCacheEntryWeight(largest, largestValue)
	}
}

func scanRunsPerDayCacheEntryWeight(key scanRunsPerDayKey, value scanRunsPerDayValue) int {
	daysStorage := conservativeScanDemandCacheStorage(cap(value.days) * int(unsafe.Sizeof(scheduleDaySpan{})))
	timezoneStorage := conservativeScanDemandCacheStorage(len(key.timezone))
	scheduleStorage := conservativeScanDemandCacheStorage(len(key.schedule))
	identityTimezoneStorage := conservativeScanDemandCacheStorage(len(value.identity.timezone))
	return scanRunsPerDayCacheEntrySize + daysStorage + timezoneStorage + scheduleStorage + identityTimezoneStorage
}

// conservativeScanDemandCacheStorage adds room for allocator rounding on
// larger backing arrays and strings, on top of the fixed per-entry allowance.
func conservativeScanDemandCacheStorage(size int) int {
	switch {
	case size > 32*1024:
		return size + 16*1024
	case size > 8*1024:
		return size + 4*1024
	default:
		return size
	}
}

// scanDurationKey returns the duration key of the job's revision, which the
// App remembers by job ID, revision and update time: every edit of a job's
// definition gives it a new revision.
func (a *App) scanDurationKey(record store.JobRecord) store.ScanDurationKey {
	cache := &a.scanSlotDemand
	cache.mu.Lock()
	cached, found := cache.keys[record.ID]
	cache.mu.Unlock()
	if found && cached.revision == record.Revision && cached.updated.Equal(record.UpdatedAt) {
		return cached.key
	}
	cached = cachedScanDurationKey{revision: record.Revision, updated: record.UpdatedAt, key: store.NewScanDurationKey(record), rank: scanCacheRank(record.ID)}
	cache.mu.Lock()
	if cache.keys == nil {
		cache.keys = make(map[string]cachedScanDurationKey)
	}
	current, exists := cache.keys[record.ID]
	if !exists || cached.revision > current.revision || cached.revision == current.revision && !cached.updated.Before(current.updated) {
		cache.retainScanDurationKey(record.ID, cached)
	}
	cache.mu.Unlock()
	return cached.key
}

// retainScanDurationKey keeps the entries with the lowest stable ranks.
// Its max-heap identifies the worst retained rank in logarithmic work, so the
// deterministic subset does not depend on request order without scanning the
// full cache for each new job. Replaced or rejected values are recomputed on
// demand.
func (cache *scanSlotDemandCache) retainScanDurationKey(id string, value cachedScanDurationKey) {
	if cache.keys == nil {
		cache.keys = make(map[string]cachedScanDurationKey)
	}
	if _, exists := cache.keys[id]; exists {
		cache.keys[id] = value
		return
	}
	candidate := scanDurationKeyRank{id: id, rank: value.rank}
	if len(cache.keys) >= scanDurationKeyCacheLimit {
		if cache.compareScanDurationKeyRanks(candidate, cache.keyRanks[0]) >= 0 {
			return
		}
		largest := cache.popLargestScanDurationKeyRank()
		delete(cache.keys, largest.id)
	}
	cache.keys[id] = value
	cache.pushScanDurationKeyRank(candidate)
}

// compareScanDurationKeyRanks orders entries by rank and then ID. All
// admission comparisons pass through this method so the complexity regression
// test measures the work used to maintain the deterministic subset.
func (cache *scanSlotDemandCache) compareScanDurationKeyRanks(a, b scanDurationKeyRank) int {
	cache.keyAdmissionWork++
	if a.rank < b.rank {
		return -1
	}
	if a.rank > b.rank {
		return 1
	}
	if a.id < b.id {
		return -1
	}
	if a.id > b.id {
		return 1
	}
	return 0
}

// pushScanDurationKeyRank inserts an entry into the max-heap of retained
// duration keys.
func (cache *scanSlotDemandCache) pushScanDurationKeyRank(value scanDurationKeyRank) {
	cache.keyRanks = append(cache.keyRanks, value)
	child := len(cache.keyRanks) - 1
	for child > 0 {
		parent := (child - 1) / 2
		if cache.compareScanDurationKeyRanks(cache.keyRanks[parent], cache.keyRanks[child]) >= 0 {
			break
		}
		cache.keyRanks[parent], cache.keyRanks[child] = cache.keyRanks[child], cache.keyRanks[parent]
		child = parent
	}
}

// popLargestScanDurationKeyRank removes the heap root, the highest-ranked
// retained key.
func (cache *scanSlotDemandCache) popLargestScanDurationKeyRank() scanDurationKeyRank {
	largest := cache.keyRanks[0]
	lastIndex := len(cache.keyRanks) - 1
	last := cache.keyRanks[lastIndex]
	cache.keyRanks[lastIndex] = scanDurationKeyRank{}
	cache.keyRanks = cache.keyRanks[:lastIndex]
	if lastIndex == 0 {
		return largest
	}
	cache.keyRanks[0] = last
	parent := 0
	for {
		left := parent*2 + 1
		if left >= len(cache.keyRanks) {
			break
		}
		largestChild := left
		right := left + 1
		if right < len(cache.keyRanks) && cache.compareScanDurationKeyRanks(cache.keyRanks[left], cache.keyRanks[right]) < 0 {
			largestChild = right
		}
		if cache.compareScanDurationKeyRanks(cache.keyRanks[parent], cache.keyRanks[largestChild]) >= 0 {
			break
		}
		cache.keyRanks[parent], cache.keyRanks[largestChild] = cache.keyRanks[largestChild], cache.keyRanks[parent]
		parent = largestChild
	}
	return largest
}

func scanCacheRank(values ...string) uint64 {
	h := fnv.New64a()
	for _, value := range values {
		_, _ = h.Write([]byte(value))
		_, _ = h.Write([]byte{0})
	}
	return h.Sum64()
}

// scheduleTimezone returns the IANA name of the timezone a job's schedule
// runs in: the job's own, else the deployment's, else UTC.
func scheduleTimezone(job config.Job, defaultTimezone string) string {
	timezone := strings.TrimSpace(job.Timezone)
	if timezone == "" {
		timezone = strings.TrimSpace(defaultTimezone)
	}
	if timezone == "" {
		timezone = "UTC"
	}
	return timezone
}

// scanJobRunsPerDay averages a valid five-field schedule over a representative
// four-year calendar cycle in the job's timezone; see scheduleRunsPerDay.
func scanJobRunsPerDay(job config.Job, defaultTimezone string) (float64, bool) {
	return scheduleRunsPerDay(scheduleTimezone(job, defaultTimezone), job.Schedule)
}

// scheduleRunsPerDay averages a valid five-field schedule over a representative
// four-year cycle; see schedulePattern.
func scheduleRunsPerDay(timezone, scheduleText string) (float64, bool) {
	value, err := schedulePattern(context.Background(), timezone, scheduleText)
	return value.runsPerDay, value.ok && err == nil
}

// schedulePattern averages a valid five-field schedule over a representative
// four-year calendar cycle in its timezone. It also records the days of the
// cycle on which the schedule ticks and the shortest gap between two ticks,
// so that projecting the scheduler's skip-while-active rule costs work for
// each distinct kind of day rather than for each tick.
func schedulePattern(ctx context.Context, timezone, scheduleText string) (scanRunsPerDayValue, error) {
	return schedulePatternWithBudget(ctx, timezone, scheduleText, nil)
}

// schedulePatternWithBudget charges the same request-local budget used by
// duration projections. A failed or canceled expansion is never returned
// as a partial pattern, so callers cannot cache or estimate it.
func schedulePatternWithBudget(ctx context.Context, timezone, scheduleText string, budget *scanScheduleSimulationBudget) (scanRunsPerDayValue, error) {
	var value scanRunsPerDayValue
	if budget == nil {
		budget = &scanScheduleSimulationBudget{limit: scanScheduleRequestWorkLimit}
	}
	if err := ctx.Err(); err != nil {
		return value, err
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return value, errInvalidScanSchedulePattern
	}
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(scheduleText)
	if err != nil {
		return value, errInvalidScanSchedulePattern
	}
	value.startYear = scanScheduleSampleStartYear
	value.endYear = scanScheduleSampleEndYear
	start := time.Date(value.startYear, time.January, 1, 0, 0, 0, 0, location)
	end := time.Date(value.endYear, time.January, 1, 0, 0, 0, 0, location)
	value.windowSeconds = end.Sub(start).Seconds()
	spec, ok := schedule.(*cron.SpecSchedule)
	if !ok {
		return scanRunsPerDayValue{}, errInvalidScanSchedulePattern
	}
	spec.Location = location
	value.identity = scanScheduleIdentity{
		timezone: location.String(), second: spec.Second &^ cronStarBit,
		minute: spec.Minute &^ cronStarBit, hour: spec.Hour &^ cronStarBit,
		dayOfMonth: spec.Dom, month: spec.Month &^ cronStarBit, dayOfWeek: spec.Dow,
	}
	var budgetExhausted bool
	schedule = budgetedCronSchedule{schedule: schedule, budget: budget, exhausted: &budgetExhausted}
	first := schedule.Next(start.Add(-time.Nanosecond))
	if err := scheduleBudgetError(ctx, budgetExhausted); err != nil {
		return scanRunsPerDayValue{}, err
	}
	if first.IsZero() {
		return scanRunsPerDayValue{}, errInvalidScanSchedulePattern
	}
	window, err := scanScheduleWindow(ctx, schedule, spec, start, end, budget)
	if err := scheduleBudgetError(ctx, budgetExhausted); err != nil {
		return scanRunsPerDayValue{}, err
	}
	if err != nil {
		return scanRunsPerDayValue{}, err
	}
	if window.runs == 0 {
		value.ok = true
		return value, nil
	}
	if value.windowSeconds <= 0 {
		return scanRunsPerDayValue{}, nil
	}
	value.minimumGap = window.minimumGap
	value.minuteTicks = scheduleTicksOnWholeMinutes(value.identity.second, location, start, end)
	value.projectionFloor = window.projectionFloor
	// The cache weighs a value by its slice capacity, so keep no spare room.
	value.days = append([]scheduleDaySpan(nil), window.days...)
	value.runsPerDay = float64(window.runs) / (value.windowSeconds / scheduleDay.Seconds())
	value.ok = true
	return value, nil
}

// scheduleTicksOnWholeMinutes reports whether every tick from start until
// end of a schedule whose cron second field is second falls a whole number
// of minutes after every other: each tick starts a local minute, and every
// UTC offset that location has in that time is a whole number of minutes.
func scheduleTicksOnWholeMinutes(second uint64, location *time.Location, start, end time.Time) bool {
	if second != 1 {
		return false
	}
	for at := start; at.Before(end); {
		if _, offset := at.Zone(); offset%60 != 0 {
			return false
		}
		_, next := at.ZoneBounds()
		if !next.After(at) {
			return true
		}
		at = next
	}
	return true
}

func scheduleBudgetError(ctx context.Context, exhausted bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if exhausted {
		return errScheduleSimulationBudgetExceeded
	}
	return nil
}

const (
	cronStarBit = uint64(1) << 63
	// scheduleDay is the length of an ordinary local day.
	scheduleDay = 24 * time.Hour
)

// scheduleWindow is what expanding a schedule over the sample finds: how
// often it ticks, the shortest time between two of its ticks, and the days
// on which it ticks.
type scheduleWindow struct {
	runs       int
	minimumGap time.Duration
	days       []scheduleDaySpan
	// projectionFloor is the least work that walkScheduleDays takes to
	// project a run over these days: a Schedule.Next call for the warm
	// start, two units for each span of ordinary days, and, for each day
	// whose ticks the cron schedule gives, one unit and a Schedule.Next call
	// for each of its ticks and for the one after it.
	projectionFloor int
}

// scanScheduleWindow expands the schedule over the sample's local days. An
// ordinary day's ticks are the cron fields' times of day after its start.
// The handful of irregular days, whose local duration differs from 24 hours
// or whose offset changes, lie next to the timezone's transitions, so it
// finds them from those, and on each it follows the cron schedule from the
// previous tick, as the scheduler does. The cron search for the tick after
// such a day can drift past the first ticks of the days after it, so until
// that search arrives at the next ordinary day's first tick it follows the
// cron schedule over the day the search reaches too. It takes the ordinary
// days between those a month at a time, or all at once when the schedule
// ticks on every day, so its work grows with the timezone's transitions, the
// runs of days on which the schedule ticks, and the months it examines day
// by day, not with the sample's days. This keeps dense schedules bounded
// without dropping their month, day-of-month, weekday, or daylight-saving
// behavior, and finds the real shortest gap between ticks, including across
// midnight and on the daylight-saving days.
func scanScheduleWindow(ctx context.Context, schedule cron.Schedule, spec *cron.SpecSchedule, start, end time.Time, budget *scanScheduleSimulationBudget) (scheduleWindow, error) {
	offsets := scheduleDayOffsets(spec.Second&^cronStarBit, spec.Minute&^cronStarBit, spec.Hour&^cronStarBit)
	if len(offsets) == 0 {
		return scheduleWindow{}, errInvalidScanSchedulePattern
	}
	expansion := scheduleExpansion{
		ctx: ctx, schedule: schedule, spec: spec, start: start, end: end, budget: budget,
		offsets: offsets, lastTick: start.Add(-time.Nanosecond),
	}
	if err := expansion.expand(); err != nil {
		return scheduleWindow{}, err
	}
	return expansion.window, nil
}

// scheduleExpansion is the state of one scanScheduleWindow expansion. It
// numbers the sample's local dates from the first, and a day is the time
// from the start of its date to the start of the next.
type scheduleExpansion struct {
	ctx        context.Context
	schedule   cron.Schedule
	spec       *cron.SpecSchedule
	start, end time.Time
	budget     *scanScheduleSimulationBudget
	// offsets are an ordinary day's ticks; ordinaryGap is the shortest time
	// between two of them, or zero when it has one, and acrossMidnight the
	// time from its last tick to the next day's first.
	offsets                     []time.Duration
	ordinaryGap, acrossMidnight time.Duration
	// firstDate is the sample's first date, at noon UTC, and dates the
	// number of its dates.
	firstDate time.Time
	dates     int
	// irregular holds the numbers of the sample's irregular days, in order.
	irregular []int
	window    scheduleWindow
	// lastTick is the latest tick so far; the scheduler finds each tick
	// from the one before it.
	lastTick time.Time
	ticked   bool
}

func (e *scheduleExpansion) expand() error {
	e.window.projectionFloor = 1
	for i := 1; i < len(e.offsets); i++ {
		if gap := e.offsets[i] - e.offsets[i-1]; e.ordinaryGap == 0 || gap < e.ordinaryGap {
			e.ordinaryGap = gap
		}
	}
	e.acrossMidnight = scheduleDay - (e.offsets[len(e.offsets)-1] - e.offsets[0])
	year, month, day := e.start.Date()
	e.firstDate = time.Date(year, month, day, 12, 0, 0, 0, time.UTC)
	year, month, day = e.end.Date()
	e.dates = int(time.Date(year, month, day, 12, 0, 0, 0, time.UTC).Sub(e.firstDate) / scheduleDay)
	if err := e.findIrregularDays(); err != nil {
		return err
	}
	follow := false
	for day := 0; day < e.dates; {
		if follow || e.isIrregular(day) {
			next, followNext, err := e.cronDay(day)
			if err != nil {
				return err
			}
			day, follow = next, followNext
			continue
		}
		stretchEnd := e.dates
		if i := sort.SearchInts(e.irregular, day); i < len(e.irregular) {
			stretchEnd = e.irregular[i]
		}
		if err := e.ordinaryDays(day, stretchEnd); err != nil {
			return err
		}
		day = stretchEnd
	}
	return nil
}

// findIrregularDays finds the sample's irregular days. A day can only be
// irregular when one of the timezone's transitions falls in it or at one of
// its ends, so it checks the days around each transition, and the sample's
// first and last days, whose ends the sample sets.
func (e *scheduleExpansion) findIrregularDays() error {
	checked := make(map[int]bool)
	check := func(day int) error {
		if day < 0 || day >= e.dates || checked[day] {
			return nil
		}
		checked[day] = true
		dayStart, dayEnd, err := e.dayBounds(day)
		if err != nil {
			return err
		}
		if !ordinaryScheduleDay(dayStart, dayEnd) {
			e.irregular = append(e.irregular, day)
		}
		return nil
	}
	if err := check(0); err != nil {
		return err
	}
	if err := check(e.dates - 1); err != nil {
		return err
	}
	for at := e.start; at.Before(e.end); {
		if err := takeScheduleWork(e.ctx, e.budget); err != nil {
			return err
		}
		_, transition := at.ZoneBounds()
		if transition.IsZero() || !transition.After(at) || !transition.Before(e.end) {
			break
		}
		for _, instant := range []time.Time{transition.Add(-time.Nanosecond), transition} {
			day := e.dayOf(instant)
			for candidate := day - 1; candidate <= day+1; candidate++ {
				if err := check(candidate); err != nil {
					return err
				}
			}
		}
		at = transition
	}
	sort.Ints(e.irregular)
	return nil
}

func (e *scheduleExpansion) isIrregular(day int) bool {
	i := sort.SearchInts(e.irregular, day)
	return i < len(e.irregular) && e.irregular[i] == day
}

// dayOf returns the number of the day whose date the instant has.
func (e *scheduleExpansion) dayOf(instant time.Time) int {
	year, month, day := instant.In(e.start.Location()).Date()
	return int(time.Date(year, month, day, 12, 0, 0, 0, time.UTC).Sub(e.firstDate) / scheduleDay)
}

// dayStart returns the start of the day: the sample's start for the first,
// the sample's end after the last, and otherwise its date's midnight or,
// when daylight saving skips that midnight, its date's first instant.
func (e *scheduleExpansion) dayStart(day int) (time.Time, error) {
	if day <= 0 {
		return e.start, nil
	}
	if day >= e.dates {
		return e.end, nil
	}
	start, ok := scheduleDateStart(e.firstDate.AddDate(0, 0, day), e.start.Location())
	if !ok || !start.After(e.start) || !start.Before(e.end) {
		return time.Time{}, errInvalidScanSchedulePattern
	}
	return start, nil
}

func (e *scheduleExpansion) dayBounds(day int) (time.Time, time.Time, error) {
	dayStart, err := e.dayStart(day)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	dayEnd, err := e.dayStart(day + 1)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !dayEnd.After(dayStart) {
		return time.Time{}, time.Time{}, errInvalidScanSchedulePattern
	}
	return dayStart, dayEnd, nil
}

// cronDay follows the cron schedule over the day from the previous tick. It
// returns the next day to expand, and whether the scheduler's search from
// this day's last tick drifted into that day, so that it is followed with
// the cron schedule too: the ordinary days after this one tick at their
// times of day once that search arrives at the first tick of the next of
// them on which the schedule ticks, and until then they have no ticks.
func (e *scheduleExpansion) cronDay(day int) (int, bool, error) {
	if err := takeScheduleWork(e.ctx, e.budget); err != nil {
		return 0, false, err
	}
	dayStart, dayEnd, err := e.dayBounds(day)
	if err != nil {
		return 0, false, err
	}
	ticks, err := scheduleDayTicks(e.ctx, e.schedule, e.lastTick, dayStart, dayEnd)
	if err != nil {
		return 0, false, err
	}
	if ticks.count > 0 {
		offset, offsetOK := scheduleSpanSeconds(dayStart.Sub(e.start))
		length, lengthOK := scheduleSpanSeconds(dayEnd.Sub(dayStart))
		if !offsetOK || !lengthOK {
			return 0, false, errInvalidScanSchedulePattern
		}
		e.noteTicks(ticks.first, ticks.last, ticks.minimumGap)
		e.window.runs += ticks.count
		e.window.projectionFloor += ticks.count + 2
		e.window.days = append(e.window.days, scheduleDaySpan{start: offset, length: length})
	}
	following := day + 1
	expected := e.nextTickingDay(following)
	if expected >= e.dates || e.isIrregular(expected) {
		return following, false, nil
	}
	expectedStart, err := e.dayStart(expected)
	if err != nil {
		return 0, false, err
	}
	if ticks.next.Equal(expectedStart.Add(e.offsets[0])) {
		return following, false, nil
	}
	if ticks.next.IsZero() || !ticks.next.Before(e.end) {
		return e.dates, false, nil
	}
	drifted := max(e.dayOf(ticks.next), following)
	return drifted, !e.isIrregular(drifted), nil
}

// nextTickingDay returns the first day from day on that is irregular or an
// ordinary day on which the schedule ticks, or the number of dates when
// there is none.
func (e *scheduleExpansion) nextTickingDay(day int) int {
	limit := e.dates
	if i := sort.SearchInts(e.irregular, day); i < len(e.irregular) {
		limit = e.irregular[i]
	}
	for day < limit {
		date := e.firstDate.AddDate(0, 0, day)
		monthEnd := min(day+scheduleDaysLeftInMonth(date), limit)
		if e.monthMatches(date.Month()) {
			for d := day; d < monthEnd; d++ {
				if e.dateMatches(date.Day()+d-day, (int(date.Weekday())+d-day)%7) {
					return d
				}
			}
		}
		day = monthEnd
	}
	return limit
}

// ordinaryDays expands the ordinary days from day from until day to. They
// keep one UTC offset, so each starts a whole number of 24 hours after the
// first. It adds them all at once when the schedule ticks on every day, and
// otherwise takes them a month at a time, examining day by day only the
// days of the months whose days the schedule restricts.
func (e *scheduleExpansion) ordinaryDays(from, to int) error {
	first, err := e.dayStart(from)
	if err != nil {
		return err
	}
	everyDate := e.matchesEveryDate()
	if everyDate && e.spec.Month&scheduleAllMonths == scheduleAllMonths {
		return e.addOrdinaryDays(first, 0, to-from)
	}
	for day := from; day < to; {
		date := e.firstDate.AddDate(0, 0, day)
		monthEnd := min(day+scheduleDaysLeftInMonth(date), to)
		switch {
		case !e.monthMatches(date.Month()):
		case everyDate:
			if err := e.addOrdinaryDays(first, day-from, monthEnd-day); err != nil {
				return err
			}
		default:
			if err := takeScheduleWork(e.ctx, e.budget); err != nil {
				return err
			}
			for d := day; d < monthEnd; d++ {
				if !e.dateMatches(date.Day()+d-day, (int(date.Weekday())+d-day)%7) {
					continue
				}
				if err := e.addOrdinaryDays(first, d-from, 1); err != nil {
					return err
				}
			}
		}
		day = monthEnd
	}
	return nil
}

// addOrdinaryDays adds the days ordinary days that start index days after
// first, extending the previous span of ordinary days when they follow it.
// A new span takes a unit of work.
func (e *scheduleExpansion) addOrdinaryDays(first time.Time, index, days int) error {
	if days <= 0 {
		return nil
	}
	spanStart := first.Add(time.Duration(index) * scheduleDay)
	offset, ok := scheduleSpanSeconds(spanStart.Sub(e.start))
	if !ok {
		return errInvalidScanSchedulePattern
	}
	gap := e.ordinaryGap
	if days > 1 && (gap == 0 || e.acrossMidnight < gap) {
		gap = e.acrossMidnight
	}
	e.noteTicks(spanStart.Add(e.offsets[0]), spanStart.Add(time.Duration(days-1)*scheduleDay+e.offsets[len(e.offsets)-1]), gap)
	e.window.runs += days * len(e.offsets)
	if n := len(e.window.days); n > 0 && e.window.days[n-1].days > 0 &&
		uint64(e.window.days[n-1].start)+uint64(e.window.days[n-1].days)*uint64(scheduleDay/time.Second) == uint64(offset) {
		e.window.days[n-1].days += uint32(days)
		return nil
	}
	if err := takeScheduleWork(e.ctx, e.budget); err != nil {
		return err
	}
	e.window.projectionFloor += 2
	e.window.days = append(e.window.days, scheduleDaySpan{start: offset, days: uint32(days)})
	return nil
}

// noteTicks records ticks from first to last whose shortest gap is gap,
// after the ticks before them.
func (e *scheduleExpansion) noteTicks(first, last time.Time, gap time.Duration) {
	if e.ticked {
		e.noteGap(first.Sub(e.lastTick))
	}
	e.noteGap(gap)
	e.lastTick, e.ticked = last, true
}

func (e *scheduleExpansion) noteGap(gap time.Duration) {
	if gap > 0 && (e.window.minimumGap == 0 || gap < e.window.minimumGap) {
		e.window.minimumGap = gap
	}
}

func (e *scheduleExpansion) monthMatches(month time.Month) bool {
	return 1<<uint(month)&e.spec.Month != 0
}

// dateMatches reports whether the schedule ticks on a date with the day of
// the month and weekday given, in a month that it ticks in, as the cron
// schedule decides it.
func (e *scheduleExpansion) dateMatches(dayOfMonth, weekday int) bool {
	domMatches := 1<<uint(dayOfMonth)&e.spec.Dom != 0
	dowMatches := 1<<uint(weekday)&e.spec.Dow != 0
	if e.spec.Dom&cronStarBit != 0 || e.spec.Dow&cronStarBit != 0 {
		return domMatches && dowMatches
	}
	return domMatches || dowMatches
}

// matchesEveryDate reports whether the schedule ticks on every date of the
// months it ticks in.
func (e *scheduleExpansion) matchesEveryDate() bool {
	everyDayOfMonth := e.spec.Dom&scheduleAllDaysOfMonth == scheduleAllDaysOfMonth
	everyWeekday := e.spec.Dow&scheduleAllWeekdays == scheduleAllWeekdays
	if e.spec.Dom&cronStarBit != 0 || e.spec.Dow&cronStarBit != 0 {
		return everyDayOfMonth && everyWeekday
	}
	return everyDayOfMonth || everyWeekday
}

const (
	scheduleAllMonths      = uint64(1<<13 - 1<<1)
	scheduleAllDaysOfMonth = uint64(1<<32 - 1<<1)
	scheduleAllWeekdays    = uint64(1<<7 - 1)
)

// scheduleDaysLeftInMonth returns the days from date to the end of its
// month, both included.
func scheduleDaysLeftInMonth(date time.Time) int {
	return time.Date(date.Year(), date.Month()+1, 0, 12, 0, 0, 0, time.UTC).Day() - date.Day() + 1
}

// scheduleDateStart returns the start of the date that date, a time in
// UTC, has in location: its midnight or, when daylight saving skips that
// midnight, its first instant.
func scheduleDateStart(date time.Time, location *time.Location) (time.Time, bool) {
	year, month, day := date.Date()
	start := time.Date(year, month, day, 0, 0, 0, 0, location)
	if gotYear, gotMonth, gotDay := start.Date(); gotYear != year || gotMonth != month || gotDay != day {
		// Go placed the missing midnight before the gap, on the previous
		// date; the day starts where the gap ends.
		_, start = start.ZoneBounds()
		if gotYear, gotMonth, gotDay := start.Date(); gotYear != year || gotMonth != month || gotDay != day {
			return time.Time{}, false
		}
	}
	return start, true
}

// scheduleDayOffsets returns the times of day of the cron second, minute and
// hour fields, in order, as offsets from midnight.
func scheduleDayOffsets(second, minute, hour uint64) []time.Duration {
	offsets := make([]time.Duration, 0, bits.OnesCount64(second)*bits.OnesCount64(minute)*bits.OnesCount64(hour))
	for h := range 24 {
		if hour&(1<<uint(h)) == 0 {
			continue
		}
		for m := range 60 {
			if minute&(1<<uint(m)) == 0 {
				continue
			}
			for s := range 60 {
				if second&(1<<uint(s)) != 0 {
					offsets = append(offsets, time.Duration(h)*time.Hour+time.Duration(m)*time.Minute+time.Duration(s)*time.Second)
				}
			}
		}
	}
	return offsets
}

// ordinaryScheduleDay reports whether the local day from dayStart to dayEnd
// lasts 24 hours from midnight and keeps one UTC offset, so that its ticks
// are the schedule's times of day after its start.
func ordinaryScheduleDay(dayStart, dayEnd time.Time) bool {
	if dayEnd.Sub(dayStart) != scheduleDay || dayStart.Hour() != 0 || dayStart.Minute() != 0 || dayStart.Second() != 0 || dayStart.Nanosecond() != 0 {
		return false
	}
	_, zoneEnd := dayStart.ZoneBounds()
	return zoneEnd.IsZero() || !zoneEnd.Before(dayEnd)
}

// scheduleSpanSeconds returns a non-negative whole-second offset within
// the sample as the seconds that a scheduleDaySpan stores.
func scheduleSpanSeconds(offset time.Duration) (uint32, bool) {
	if offset < 0 || offset%time.Second != 0 || offset/time.Second > math.MaxUint32 {
		return 0, false
	}
	return uint32(offset / time.Second), true
}

// scheduleDayTickSummary summarizes the cron schedule's ticks on one day,
// and the first tick after them, next, which is zero when there is none.
type scheduleDayTickSummary struct {
	count       int
	first, last time.Time
	minimumGap  time.Duration
	next        time.Time
}

// scheduleDayTicks follows the cron schedule from the tick after, as the
// scheduler finds each tick from the one before it, and summarizes its
// ticks from start until end.
func scheduleDayTicks(ctx context.Context, schedule cron.Schedule, after, start, end time.Time) (scheduleDayTickSummary, error) {
	var ticks scheduleDayTickSummary
	next := schedule.Next(after)
	for ; !next.IsZero() && next.Before(end); next = schedule.Next(next) {
		if err := ctx.Err(); err != nil {
			return scheduleDayTickSummary{}, err
		}
		if next.Before(start) {
			continue
		}
		if ticks.count == 0 {
			ticks.first = next
		} else if gap := next.Sub(ticks.last); ticks.minimumGap == 0 || gap < ticks.minimumGap {
			ticks.minimumGap = gap
		}
		ticks.last = next
		ticks.count++
	}
	ticks.next = next
	return ticks, ctx.Err()
}

// runsForDuration returns the scheduled runs per day that can start when
// each run holds the job for runSeconds, and whether the scheduler skips a
// tick. A run that its timeout ends, endsAtTimeout, still holds the job at a
// tick at exactly its end, because the run is finalized after the timeout.
func (value scanRunsPerDayValue) runsForDuration(ctx context.Context, runSeconds float64, endsAtTimeout bool) (runsPerDay float64, skipped bool, err error) {
	return value.runsForDurationWithBudget(ctx, runSeconds, endsAtTimeout, nil)
}

func (value scanRunsPerDayValue) runsForDurationWithBudget(ctx context.Context, runSeconds float64, endsAtTimeout bool, budget *scanScheduleSimulationBudget) (runsPerDay float64, skipped bool, err error) {
	if !value.ok || value.runsPerDay <= 0 {
		return 0, false, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	if value.runFitsEveryGap(runSeconds, endsAtTimeout) {
		return value.runsPerDay, false, nil
	}
	runDuration := scheduleRunDuration(runSeconds)
	if value.everyMinuteProjection(runSeconds) {
		return simulateEveryMinuteSchedule(ctx, value, runDuration, endsAtTimeout)
	}
	schedule, start, _, err := value.runtimeSchedule()
	if err != nil {
		return 0, false, err
	}
	var budgetExhausted bool
	if budget != nil {
		schedule = budgetedCronSchedule{schedule: schedule, budget: budget, exhausted: &budgetExhausted}
	}
	runsPerDay, skipped, err = value.walkScheduleDays(ctx, schedule, start, runDuration, endsAtTimeout, budget)
	if budgetExhausted {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, false, ctxErr
		}
		return 0, false, errScheduleSimulationBudgetExceeded
	}
	return runsPerDay, skipped, err
}

// runFitsEveryGap reports whether a run of runSeconds always ends before the
// next tick, so every tick starts a run. A run without slot time blocks no
// tick.
func (value scanRunsPerDayValue) runFitsEveryGap(runSeconds float64, endsAtTimeout bool) bool {
	if runSeconds <= 0 {
		return true
	}
	if value.minimumGap <= 0 {
		return false
	}
	gap := value.minimumGap.Seconds()
	return runSeconds < gap || !endsAtTimeout && runSeconds == gap
}

// everyMinuteProjection reports whether runs of runSeconds on the schedule
// are projected by the every-minute formula, which takes no work.
func (value scanRunsPerDayValue) everyMinuteProjection(runSeconds float64) bool {
	return allMinuteSchedule(value.identity) && runSeconds <= value.windowSeconds
}

// projectionWorkFloor returns the least work that projecting runs of
// runSeconds that skip ticks on the schedule takes.
func (value scanRunsPerDayValue) projectionWorkFloor(runSeconds float64) int {
	if value.everyMinuteProjection(runSeconds) {
		return 0
	}
	return value.projectionFloor
}

// projectedRun returns the run that a projection on the schedule uses for a
// run of runSeconds, which its timeout ends when endsAtTimeout is set. When
// every tick falls a whole number of minutes after every other, a run that
// starts at a tick blocks exactly the ticks before the first whole minute
// after its start at which it no longer holds the job: the minute in which
// it ends, or the next one when it ends on a minute and its timeout ends it,
// because it is still being finalized then. That run of whole minutes, which
// ends before a tick at its end, blocks the same ticks, so runs that differ
// by fractions of a minute share one projection. Only the warm start before
// the sample, which begins two runs before it, can begin up to two minutes
// earlier than for the exact run.
func (value scanRunsPerDayValue) projectedRun(runSeconds float64, endsAtTimeout bool) (float64, bool) {
	if !value.minuteTicks || runSeconds <= 0 || math.IsInf(runSeconds, 0) || math.IsNaN(runSeconds) {
		return runSeconds, endsAtTimeout
	}
	minutes := math.Ceil(runSeconds / 60)
	if endsAtTimeout {
		minutes = math.Floor(runSeconds/60) + 1
	}
	return minutes * 60, false
}

// durationKey is the memo key of runs of runSeconds on the schedule.
func (value scanRunsPerDayValue) durationKey(runSeconds float64, endsAtTimeout bool) scanScheduleDurationKey {
	return scanScheduleDurationKey{schedule: value.identity, runSeconds: math.Float64bits(runSeconds), endsAtTimeout: endsAtTimeout}
}

// scheduleRunDuration converts a run's seconds to a duration, bounded so
// that simulating the time before the sample cannot overflow.
func scheduleRunDuration(runSeconds float64) time.Duration {
	const longest = float64(math.MaxInt64 / 8)
	return time.Duration(min(runSeconds*float64(time.Second), longest))
}

// runtimeSchedule reconstructs timezone-bearing values only for the duration
// of one projection. The shared cache retains only the IANA key and numeric
// calendar fields, never time.Location or cron.SpecSchedule pointers.
func (value scanRunsPerDayValue) runtimeSchedule() (cron.Schedule, time.Time, time.Time, error) {
	location, err := time.LoadLocation(value.identity.timezone)
	if err != nil {
		return nil, time.Time{}, time.Time{}, errInvalidScanSchedulePattern
	}
	schedule := &cron.SpecSchedule{
		Second: value.identity.second, Minute: value.identity.minute,
		Hour: value.identity.hour, Dom: value.identity.dayOfMonth,
		Month: value.identity.month, Dow: value.identity.dayOfWeek,
		Location: location,
	}
	start := time.Date(value.startYear, time.January, 1, 0, 0, 0, 0, location)
	end := time.Date(value.endYear, time.January, 1, 0, 0, 0, 0, location)
	return schedule, start, end, nil
}

// walkScheduleDays projects runs of runDuration over the sample's days, as
// a tick-by-tick simulation of the whole sample would. A run of ordinary
// days repeats one day's ticks, so it simulates such a day once for each
// first tick at which the job is free, and once those states repeat it adds
// whole repetitions without simulating them. On the days whose ticks the
// cron schedule gives, it follows the cron schedule from the previous tick,
// as the scheduler does.
func (value scanRunsPerDayValue) walkScheduleDays(ctx context.Context, schedule cron.Schedule, start time.Time, runDuration time.Duration, endsAtTimeout bool, budget *scanScheduleSimulationBudget) (float64, bool, error) {
	busyUntil, err := simulateSchedulePrefix(ctx, schedule, start, runDuration, endsAtTimeout)
	if err != nil {
		return 0, false, err
	}
	walk := scheduleDayWalk{
		offsets: scheduleDayOffsets(value.identity.second, value.identity.minute, value.identity.hour),
		run:     runDuration, endsAtTimeout: endsAtTimeout, budget: budget,
		days: make(map[int]scheduleDayResult),
	}
	if len(walk.offsets) == 0 {
		return 0, false, errInvalidScanSchedulePattern
	}
	var starts int64
	skipped := false
	lastTick := start.Add(-time.Nanosecond)
	for _, span := range value.days {
		if err := takeScheduleWork(ctx, budget); err != nil {
			return 0, false, err
		}
		spanStart := start.Add(time.Duration(span.start) * time.Second)
		var spanStarts int64
		var spanSkipped bool
		if span.days == 0 {
			spanStarts, spanSkipped, busyUntil, lastTick, err = simulateScheduleSpan(ctx, schedule, lastTick, spanStart, spanStart.Add(time.Duration(span.length)*time.Second), busyUntil, runDuration, endsAtTimeout)
		} else {
			spanStarts, spanSkipped, busyUntil, err = walk.ordinaryDays(ctx, spanStart, int(span.days), busyUntil)
			lastTick = spanStart.Add(time.Duration(span.days-1)*scheduleDay + walk.offsets[len(walk.offsets)-1])
		}
		if err != nil {
			return 0, false, err
		}
		starts += spanStarts
		skipped = skipped || spanSkipped
	}
	windowDays := value.windowSeconds / scheduleDay.Seconds()
	if windowDays <= 0 {
		return 0, false, nil
	}
	return float64(starts) / windowDays, skipped, nil
}

// scheduleDayWalk projects runs over ordinary days, which all have the same
// ticks at offsets from their start.
type scheduleDayWalk struct {
	offsets       []time.Duration
	run           time.Duration
	endsAtTimeout bool
	budget        *scanScheduleSimulationBudget
	// days holds the simulated days by the index of the first tick at
	// which the job is free. That index decides the whole day, and the
	// next day's first free tick too while a run lasts less than a day.
	days map[int]scheduleDayResult
}

// scheduleDayResult is one simulated ordinary day: the runs it starts,
// whether it skips a tick, and the offset of its last start.
type scheduleDayResult struct {
	starts  int64
	skipped bool
	last    time.Duration
}

// firstFree returns the index of the first tick, from index from on, that
// can start a run while an earlier run holds the job until busy after the
// day's start.
func (walk *scheduleDayWalk) firstFree(busy time.Duration, from int) int {
	return from + sort.Search(len(walk.offsets)-from, func(i int) bool {
		offset := walk.offsets[from+i]
		if walk.endsAtTimeout {
			return offset > busy
		}
		return offset >= busy
	})
}

// day simulates an ordinary day whose first free tick is first.
func (walk *scheduleDayWalk) day(ctx context.Context, first int) (scheduleDayResult, error) {
	if result, ok := walk.days[first]; ok {
		return result, nil
	}
	result := scheduleDayResult{skipped: first > 0}
	for i := first; i < len(walk.offsets); {
		if err := takeScheduleWork(ctx, walk.budget); err != nil {
			return scheduleDayResult{}, err
		}
		result.starts++
		result.last = walk.offsets[i]
		next := walk.firstFree(walk.offsets[i]+walk.run, i+1)
		if next > i+1 {
			result.skipped = true
		}
		i = next
	}
	walk.days[first] = result
	return result, nil
}

// ordinaryDays projects runs over days consecutive ordinary days from
// dayStart while an earlier run holds the job until busyUntil, and returns
// the runs started, whether a tick is skipped, and until when the last run
// holds the job.
func (walk *scheduleDayWalk) ordinaryDays(ctx context.Context, dayStart time.Time, days int, busyUntil time.Time) (int64, bool, time.Time, error) {
	type visit struct {
		day    int
		starts int64
	}
	var starts int64
	skipped := false
	seen := make(map[int]visit)
	repeating := false
	for day := 0; day < days; {
		if err := takeScheduleWork(ctx, walk.budget); err != nil {
			return 0, false, busyUntil, err
		}
		start := dayStart.Add(time.Duration(day) * scheduleDay)
		busy := busyUntil.Sub(start)
		if busy >= scheduleDay {
			// The earlier run holds the job all day, so it skips each tick
			// of the days it covers.
			day += min(days-day, int(busy/scheduleDay))
			skipped = true
			continue
		}
		first := walk.firstFree(busy, 0)
		if !repeating {
			if earlier, ok := seen[first]; ok {
				// The days since the earlier visit repeat from here on, so
				// add their whole repetitions at once.
				period := day - earlier.day
				repetitions := (days - day) / period
				starts += int64(repetitions) * (starts - earlier.starts)
				day += repetitions * period
				busyUntil = dayStart.Add(time.Duration(day) * scheduleDay).Add(busy)
				repeating = true
				continue
			}
			seen[first] = visit{day: day, starts: starts}
		}
		result, err := walk.day(ctx, first)
		if err != nil {
			return 0, false, busyUntil, err
		}
		starts += result.starts
		skipped = skipped || result.skipped
		if result.starts > 0 {
			busyUntil = start.Add(result.last + walk.run)
		}
		day++
	}
	return starts, skipped, busyUntil, nil
}

// scheduleTickBusy reports whether a run that holds the job until busyUntil
// makes the scheduler skip tick. The scheduler skips a tick while the job's
// run is active; a run that its timeout ends is still being finalized at a
// tick at exactly its end.
func scheduleTickBusy(tick, busyUntil time.Time, endsAtTimeout bool) bool {
	if endsAtTimeout {
		return !tick.After(busyUntil)
	}
	return tick.Before(busyUntil)
}

// nextFreeScheduleTick returns the first tick at which a run that holds the
// job until busyUntil no longer blocks a start.
func nextFreeScheduleTick(schedule cron.Schedule, busyUntil time.Time, endsAtTimeout bool) time.Time {
	if endsAtTimeout {
		return schedule.Next(busyUntil)
	}
	return schedule.Next(busyUntil.Add(-time.Nanosecond))
}

// simulateScheduleSpan simulates the cron ticks from start until end, which
// it follows from the tick after, as the scheduler does, while an earlier
// run holds the job until busyUntil. It returns the runs started, whether a
// tick is skipped, until when the last run holds the job, and the last tick.
func simulateScheduleSpan(ctx context.Context, schedule cron.Schedule, after, start, end, busyUntil time.Time, runDuration time.Duration, endsAtTimeout bool) (int64, bool, time.Time, time.Time, error) {
	var starts int64
	skipped := false
	lastTick := after
	for next := schedule.Next(after); !next.IsZero() && next.Before(end); next = schedule.Next(next) {
		if err := ctx.Err(); err != nil {
			return 0, false, busyUntil, lastTick, err
		}
		if next.Before(start) {
			continue
		}
		lastTick = next
		if scheduleTickBusy(next, busyUntil, endsAtTimeout) {
			skipped = true
			continue
		}
		starts++
		busyUntil = next.Add(runDuration)
	}
	return starts, skipped, busyUntil, lastTick, ctx.Err()
}

// simulateSchedulePrefix returns until when the runs that start before
// start hold the job. It simulates from two run durations before start, so
// that the sample begins as the schedule's steady state does.
func simulateSchedulePrefix(ctx context.Context, schedule cron.Schedule, start time.Time, runDuration time.Duration, endsAtTimeout bool) (time.Time, error) {
	var busyUntil time.Time
	if err := ctx.Err(); err != nil {
		return busyUntil, err
	}
	for next := schedule.Next(start.Add(-2 * runDuration).Add(-time.Nanosecond)); ; {
		if err := ctx.Err(); err != nil {
			return busyUntil, err
		}
		if next.IsZero() {
			return busyUntil, errInvalidScanSchedulePattern
		}
		if !next.Before(start) {
			return busyUntil, nil
		}
		if scheduleTickBusy(next, busyUntil, endsAtTimeout) {
			next = nextFreeScheduleTick(schedule, busyUntil, endsAtTimeout)
			continue
		}
		busyUntil = next.Add(runDuration)
		next = schedule.Next(next)
	}
}

func allMinuteSchedule(identity scanScheduleIdentity) bool {
	return bits.OnesCount64(identity.second) == 1 && identity.second&1 != 0 &&
		bits.OnesCount64(identity.minute) == 60 && bits.OnesCount64(identity.hour) == 24 &&
		bits.OnesCount64(identity.month) == 12 && identity.dayOfMonth&cronStarBit != 0 && identity.dayOfWeek&cronStarBit != 0
}

// simulateEveryMinuteSchedule uses the exact repeated-tick cadence instead
// of simulating every minute over a four-year sample. It reproduces the same
// two-run warm start used by simulateSchedulePrefix, including the phase of
// the first run relative to the sample boundary.
func simulateEveryMinuteSchedule(ctx context.Context, value scanRunsPerDayValue, runDuration time.Duration, endsAtTimeout bool) (float64, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	if runDuration <= 0 {
		return 0, false, nil
	}
	location, err := time.LoadLocation(value.identity.timezone)
	if err != nil {
		return 0, false, errInvalidScanSchedulePattern
	}
	start := time.Date(value.startYear, time.January, 1, 0, 0, 0, 0, location)
	end := time.Date(value.endYear, time.January, 1, 0, 0, 0, 0, location)
	if end.Sub(start).Seconds() != value.windowSeconds {
		return 0, false, errInvalidScanSchedulePattern
	}
	return simulateEveryMinuteScheduleWindow(ctx, start, end, runDuration, endsAtTimeout)
}

func simulateEveryMinuteScheduleWindow(ctx context.Context, start, end time.Time, runDuration time.Duration, endsAtTimeout bool) (float64, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	windowSeconds := end.Sub(start).Seconds()
	if windowSeconds <= 0 || runDuration <= 0 || runDuration.Seconds() > windowSeconds {
		return 0, false, nil
	}
	warmStart := start.Add(-2 * runDuration)
	// The sample start is itself a cron tick. Truncating against Unix minute
	// boundaries would misalign schedules in zones whose UTC offset has seconds.
	first := start.Add((warmStart.Sub(start) / time.Minute) * time.Minute)
	// A run starts at the first minute at which the previous one no longer
	// holds the job: at its end, or after it when its timeout ends it.
	stepMinutes := int64(runDuration / time.Minute)
	if runDuration%time.Minute != 0 || endsAtTimeout {
		stepMinutes++
	}
	step := time.Duration(stepMinutes) * time.Minute
	if first.Before(start) {
		delta := start.Sub(first)
		jumps := delta / step
		if delta%step != 0 {
			jumps++
		}
		first = first.Add(jumps * step)
	}
	starts := float64((end.Sub(first)-1)/step + 1)
	windowDays := windowSeconds / scheduleDay.Seconds()
	skipped := stepMinutes > 1 && starts < windowSeconds/float64(time.Minute/time.Second)
	return starts / windowDays, skipped, nil
}

// memoizedScheduleRunsForDurationWithBudget projects runs of runSeconds on
// the schedule once per request and remembers the result for the other jobs
// with the same schedule and projected run; see projectedRun. A run that
// ends before the schedule's shortest gap between ticks starts at every
// tick, which needs neither a projection nor work.
func memoizedScheduleRunsForDurationWithBudget(ctx context.Context, cache map[scanScheduleDurationKey]scanScheduleDurationEstimate, value scanRunsPerDayValue, runSeconds float64, endsAtTimeout bool, budget *scanScheduleSimulationBudget) (float64, bool, error) {
	if !value.ok || value.runsPerDay <= 0 {
		return 0, false, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	runSeconds, endsAtTimeout = value.projectedRun(runSeconds, endsAtTimeout)
	if value.runFitsEveryGap(runSeconds, endsAtTimeout) {
		return value.runsPerDay, false, nil
	}
	key := value.durationKey(runSeconds, endsAtTimeout)
	if estimate, ok := cache[key]; ok {
		return estimate.runsPerDay, estimate.skipped, nil
	}
	runsPerDay, skipped, err := value.runsForDurationWithBudget(ctx, runSeconds, endsAtTimeout, budget)
	if err == nil {
		cache[key] = scanScheduleDurationEstimate{runsPerDay: runsPerDay, skipped: skipped}
	}
	return runsPerDay, skipped, err
}

// scanRateLowerBound returns seconds per run that are provably bounded by
// configured maximum rates. A scope over either host ceiling cannot run: the
// scanner rejects the whole job before sending probes. DNS targets also have
// no provable expansion here, so they cannot establish that a scope fits.
// The estimate deliberately excludes response-dependent waits, retries,
// Naabu-discovered Nmap enrichment, and Nmap work without an explicit
// --max-rate ceiling.
func scanRateLowerBound(job config.Job, deploymentMaxHosts int) (seconds float64, hasBound, incomplete bool) {
	job = config.NormalizeJob(job)
	if deploymentMaxHosts < 1 {
		deploymentMaxHosts = config.DefaultMaxJobHosts
	}
	hosts, err := config.EstimateJobWork(config.Job{Targets: job.Targets})
	if err != nil || hosts.UnknownDNS > 0 || hosts.Hosts > int64(min(job.MaxExpandedHosts, deploymentMaxHosts)) {
		return 0, false, false
	}
	if job.TCP != nil && job.TCP.Engine == config.EngineNaabuNmap {
		estimate, err := config.EstimateJobWork(job)
		if err == nil && estimate.NaabuProbes > 0 && job.TCP.Naabu != nil && job.TCP.Naabu.Rate > 0 {
			seconds += float64(estimate.NaabuProbes) / float64(job.TCP.Naabu.Rate)
			hasBound = true
		}
		// Nmap enrichment only scans ports found by discovery, so its work is
		// unknown before a run and does not belong in this lower bound.
		incomplete = true
	} else if job.TCP != nil {
		tcpOnly := job
		tcpProtocol := *job.TCP
		tcpProtocol.ServiceDetection = false
		tcpOnly.TCP = &tcpProtocol
		tcpOnly.UDP = nil
		incomplete = job.TCP.ServiceDetection || job.TCP.NSEProfile != "" || len(job.TCP.NSEArgs) > 0
		if estimate, err := config.EstimateJobWork(tcpOnly); err == nil && estimate.NmapProbes > 0 {
			if rate := nmapMaxRate(job.TCP.NmapArgs); rate > 0 {
				seconds += float64(estimate.NmapProbes) / float64(rate)
				hasBound = true
			} else {
				incomplete = true
			}
		}
	}
	if job.UDP != nil {
		udpOnly := job
		udpProtocol := *job.UDP
		udpProtocol.ServiceDetection = false
		udpOnly.UDP = &udpProtocol
		udpOnly.TCP = nil
		incomplete = incomplete || job.UDP.ServiceDetection || job.UDP.NSEProfile != "" || len(job.UDP.NSEArgs) > 0
		if estimate, err := config.EstimateJobWork(udpOnly); err == nil && estimate.NmapProbes > 0 {
			if rate := nmapMaxRate(job.UDP.NmapArgs); rate > 0 {
				seconds += float64(estimate.NmapProbes) / float64(rate)
				hasBound = true
			} else {
				incomplete = true
			}
		}
	}
	if math.IsInf(seconds, 0) || math.IsNaN(seconds) {
		return 0, false, incomplete
	}
	return seconds, hasBound, incomplete
}

func nmapMaxRate(args []string) int64 {
	var rate int64
	for i := 0; i < len(args); i++ {
		value := ""
		if args[i] == "--max-rate" && i+1 < len(args) {
			i++
			value = args[i]
		} else if strings.HasPrefix(args[i], "--max-rate=") {
			value = strings.TrimPrefix(args[i], "--max-rate=")
		}
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err == nil && parsed > 0 {
			rate = parsed
		}
	}
	return rate
}
