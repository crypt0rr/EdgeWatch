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
	scanDurationKeyCacheLimit    = 16384
	scanScheduleObservationLimit = 20_000
	// deploymentScheduleSimulationNextCallLimit bounds expensive cron
	// projections across all active units in one platform demand request.
	deploymentScheduleSimulationNextCallLimit = 540_000
)

var (
	errInvalidScanSchedulePattern       = errors.New("invalid scan schedule pattern")
	errScheduleSimulationBudgetExceeded = errors.New("deployment schedule simulation budget exceeded")
)

// ScanSlotDemand is a tenant's estimated scheduled scan work compared with
// the slot-hours its effective scan-slot limit can provide in a day.
type ScanSlotDemand struct {
	EnabledJobs     int `json:"enabled_jobs"`
	HistoryJobs     int `json:"history_jobs"`
	LowerBoundJobs  int `json:"lower_bound_jobs"`
	UnestimatedJobs int `json:"unestimated_jobs"`
	// CadenceUnattainableJobs counts jobs for which the estimated run duration
	// makes the scheduler skip at least one scheduled tick.
	CadenceUnattainableJobs    int     `json:"cadence_unattainable_jobs"`
	Slots                      int     `json:"slots"`
	EstimatedSlotSecondsPerDay float64 `json:"estimated_slot_seconds_per_day"`
	CapacitySlotSecondsPerDay  float64 `json:"capacity_slot_seconds_per_day"`
	UtilizationPercent         float64 `json:"utilization_percent"`
	OverCapacity               bool    `json:"over_capacity"`
}

// scheduledDemandJob is an enabled job whose schedule runs it.
type scheduledDemandJob struct {
	record   store.JobRecord
	schedule scanRunsPerDayValue
}

// ScanSlotDemand estimates the unit's scheduled demand from enabled jobs and
// compares it with the unit's effective slot capacity. The most recent
// completed scan-history samples that ran with a job's current scan settings
// are the expected duration. If the newest runs with that key all timed out,
// the job's timeout is the expected duration. Jobs without that history use
// only work bounded by an explicitly configured scanner rate. The estimate
// simulates the schedule ticks a job can start after each prior run ends. Each
// run counts at most the job's timeout, which ends it, and a job adds at most
// one slot-day, because it runs at most once at a time.
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
	return a.scheduledScanDemandWithSimulationCache(ctx, ts, make(map[scanScheduleDurationKey]scanScheduleDurationEstimate), nil)
}

// scheduledScanDemandWithSimulationCache lets one deployment request share
// pure schedule-duration projections across its unit-scoped store reads. Its
// cache and work budget belong to that request, so no tenant data is shared.
func (a *App) scheduledScanDemandWithSimulationCache(ctx context.Context, ts *store.TenantStore, simulations map[scanScheduleDurationKey]scanScheduleDurationEstimate, budget *scanScheduleSimulationBudget) (ScanSlotDemand, error) {
	var result ScanSlotDemand
	jobs, err := ts.ListJobs(ctx, false)
	if err != nil {
		return result, err
	}
	var scheduled []scheduledDemandJob
	var keys []store.ScanDurationKey
	for _, record := range jobs {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if !record.Enabled || record.Archived {
			continue
		}
		result.EnabledJobs++
		if strings.TrimSpace(record.Job.Schedule) == "" {
			continue
		}
		schedule, err := a.scanJobSchedule(ctx, record.Job)
		if err != nil {
			return result, err
		}
		if !schedule.ok {
			result.UnestimatedJobs++
			continue
		}
		if schedule.runsPerDay <= 0 {
			continue
		}
		scheduled = append(scheduled, scheduledDemandJob{record: record, schedule: schedule})
		keys = append(keys, a.scanDurationKey(record))
	}
	history, err := ts.ListCompletedScanCycleDurations(ctx, keys, scanSlotDemandHistoryLimit)
	if err != nil {
		return result, err
	}
	timedOutOnly, err := ts.LatestScanRunsTimedOut(ctx, keys, scanSlotDemandHistoryLimit)
	if err != nil {
		return result, err
	}
	for _, job := range scheduled {
		var perRun float64
		historyJob := false
		lowerBoundJob := false
		unestimatedJob := false
		if timedOutOnly[job.record.ID] {
			perRun = job.record.Job.Timeout.Value().Seconds()
			historyJob = true
		} else if samples := history[job.record.ID]; len(samples) > 0 {
			perRun = medianCycleDuration(samples).Seconds()
			historyJob = true
		} else {
			lowerBound, hasBound, incomplete := scanRateLowerBound(job.record.Job, a.Config.Scanner.MaxJobHostsValue())
			if hasBound {
				perRun = lowerBound
				lowerBoundJob = true
			} else {
				unestimatedJob = true
			}
			if incomplete && hasBound {
				unestimatedJob = true
			}
		}
		runSeconds := runSlotSeconds(job.record.Job, perRun)
		runsPerDay, skipped, err := memoizedScheduleRunsForDurationWithBudget(ctx, simulations, job.schedule, runSeconds, budget)
		if err != nil {
			if errors.Is(err, errInvalidScanSchedulePattern) || errors.Is(err, errScheduleSimulationBudgetExceeded) {
				result.UnestimatedJobs++
				continue
			}
			return result, err
		}
		if historyJob {
			result.HistoryJobs++
		}
		if lowerBoundJob {
			result.LowerBoundJobs++
		}
		if unestimatedJob {
			result.UnestimatedJobs++
		}
		demand := runSeconds * runsPerDay
		if skipped {
			result.CadenceUnattainableJobs++
		}
		if demand > slotSecondsPerDay {
			demand = slotSecondsPerDay
		}
		result.EstimatedSlotSecondsPerDay += demand
	}
	return result, nil
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

// runSlotSeconds returns how long one run of the job holds a scan slot when
// its work takes perRun seconds. The job's timeout ends a run, so a run
// holds its slot for at most that long: a resumable cycle that needs more
// continues in the job's later runs, and a scan without a cycle stops. A
// cycle's duration sample sums all of its attempts, so without this bound a
// cycle that spans several runs would count each run as the whole cycle.
func runSlotSeconds(job config.Job, perRun float64) float64 {
	if timeout := job.Timeout.Value().Seconds(); timeout > 0 && perRun > timeout {
		return timeout
	}
	return perRun
}

func medianCycleDuration(samples []time.Duration) time.Duration {
	ordered := append([]time.Duration(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	middle := len(ordered) / 2
	if len(ordered)%2 == 1 {
		return ordered[middle]
	}
	return ordered[middle-1] + (ordered[middle]-ordered[middle-1])/2
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
	schedule   scanScheduleIdentity
	runSeconds uint64
}

type scanScheduleDurationEstimate struct {
	runsPerDay float64
	skipped    bool
}

// scanScheduleSimulationBudget bounds calls to cron.Schedule.Next during one
// deployment projection. A projection that cannot finish within the budget
// is left unestimated instead of returning a partial or undercounted result.
type scanScheduleSimulationBudget struct {
	limit int
	used  int
}

type budgetedCronSchedule struct {
	schedule  cron.Schedule
	budget    *scanScheduleSimulationBudget
	exhausted *bool
}

func (schedule budgetedCronSchedule) Next(after time.Time) time.Time {
	if schedule.budget.used >= schedule.budget.limit {
		*schedule.exhausted = true
		return time.Time{}
	}
	schedule.budget.used++
	return schedule.schedule.Next(after)
}

type scanRunsPerDayValue struct {
	runsPerDay           float64
	ok                   bool
	observationsComplete bool
	start                time.Time
	end                  time.Time
	windowSeconds        float64
	minimumGap           time.Duration
	schedule             cron.Schedule
	identity             scanScheduleIdentity
	occurrences          []uint32
	rank                 uint64
}

// cachedScanDurationKey is the duration key of one revision of a job.
type cachedScanDurationKey struct {
	revision int64
	updated  time.Time
	key      store.ScanDurationKey
	rank     uint64
}

// scanSlotDemandCache remembers, for every business unit of the process,
// the parts of the scan-slot demand estimate that a request would otherwise
// compute again for each job: each schedule's bounded occurrence pattern,
// which depends only on its text and timezone, and each job revision's
// duration key, whose hashes a revision fixes. Its zero value is ready to
// use.
type scanSlotDemandCache struct {
	mu         sync.Mutex
	runsPerDay map[scanRunsPerDayKey]scanRunsPerDayValue
	keys       map[string]cachedScanDurationKey
	// runsPerDayComputed counts the schedules computed, for tests.
	runsPerDayComputed int
}

// scanJobRunsPerDay returns the job's average scheduled runs per day, which
// the App remembers across requests by the timezone and schedule text. A
// job without its own timezone uses the deployment's, as its schedule does.
func (a *App) scanJobRunsPerDay(job config.Job) (float64, bool) {
	value, err := a.scanJobSchedule(context.Background(), job)
	return value.runsPerDay, value.ok && err == nil
}

func (a *App) scanJobSchedule(ctx context.Context, job config.Job) (scanRunsPerDayValue, error) {
	key := scanRunsPerDayKey{timezone: scheduleTimezone(job, a.Config.Timezone), schedule: job.Schedule}
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
	value, err := schedulePattern(ctx, key.timezone, key.schedule)
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
	retainBoundedCache(cache.runsPerDay, key, value, scanRunsPerDayCacheLimit,
		func(v scanRunsPerDayValue) uint64 { return v.rank },
		func(k scanRunsPerDayKey) string { return k.timezone + "\x00" + k.schedule },
		value.rank, key.timezone+"\x00"+key.schedule)
	cache.runsPerDayComputed++
	cache.mu.Unlock()
	return value, nil
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
		retainBoundedCache(cache.keys, record.ID, cached, scanDurationKeyCacheLimit,
			func(v cachedScanDurationKey) uint64 { return v.rank },
			func(k string) string { return k },
			cached.rank, record.ID)
	}
	cache.mu.Unlock()
	return cached.key
}

// retainBoundedCache keeps the entries with the lowest stable ranks. Unlike
// recency eviction, the chosen set does not depend on request order, so a
// repeated traversal of more keys than fit still gets cache hits for its
// retained keys. Replaced or rejected values are always recomputed on demand.
func retainBoundedCache[K comparable, V any](entries map[K]V, key K, value V, limit int, rankOf func(V) uint64, tieOf func(K) string, rank uint64, tie string) {
	if _, exists := entries[key]; exists {
		entries[key] = value
		return
	}
	if len(entries) < limit {
		entries[key] = value
		return
	}
	var largest K
	var largestRank uint64
	var largestTie string
	first := true
	for candidate, current := range entries {
		currentRank, currentTie := rankOf(current), tieOf(candidate)
		if first || currentRank > largestRank || currentRank == largestRank && currentTie > largestTie {
			largest, largestRank, largestTie, first = candidate, currentRank, currentTie, false
		}
	}
	if rank > largestRank || rank == largestRank && tie >= largestTie {
		return
	}
	delete(entries, largest)
	entries[key] = value
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

// scanJobRunsPerDay averages a valid five-field schedule over one calendar
// year in the job's timezone; see scheduleRunsPerDay.
func scanJobRunsPerDay(job config.Job, defaultTimezone string) (float64, bool) {
	return scheduleRunsPerDay(scheduleTimezone(job, defaultTimezone), job.Schedule)
}

// scheduleRunsPerDay averages a valid five-field schedule over one calendar
// year. Dense schedules use calendar-field counts instead of expanding every
// tick; see schedulePattern.
func scheduleRunsPerDay(timezone, scheduleText string) (float64, bool) {
	value, err := schedulePattern(context.Background(), timezone, scheduleText)
	return value.runsPerDay, value.ok && err == nil
}

// schedulePattern averages a valid five-field schedule over one calendar
// year and retains its tick offsets for simulating the scheduler's
// skip-while-active rule when the year fits within the observation limit.
// Denser schedules use their calendar fields to count the full year without
// storing or expanding every minute.
func schedulePattern(ctx context.Context, timezone, scheduleText string) (scanRunsPerDayValue, error) {
	var value scanRunsPerDayValue
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
	value.start = time.Date(2024, time.January, 1, 0, 0, 0, 0, location)
	value.end = time.Date(2025, time.January, 1, 0, 0, 0, 0, location)
	value.schedule = schedule
	value.windowSeconds = value.end.Sub(value.start).Seconds()
	value.occurrences = make([]uint32, 0, min(scanScheduleObservationLimit, 128))
	if err := ctx.Err(); err != nil {
		return scanRunsPerDayValue{}, err
	}
	first := schedule.Next(value.start.Add(-time.Nanosecond))
	if err := ctx.Err(); err != nil {
		return scanRunsPerDayValue{}, err
	}
	if first.IsZero() {
		return scanRunsPerDayValue{}, errInvalidScanSchedulePattern
	}
	spec, ok := schedule.(*cron.SpecSchedule)
	if !ok {
		return scanRunsPerDayValue{}, errInvalidScanSchedulePattern
	}
	value.identity = scanScheduleIdentity{
		timezone: location.String(), second: spec.Second &^ cronStarBit,
		minute: spec.Minute &^ cronStarBit, hour: spec.Hour &^ cronStarBit,
		dayOfMonth: spec.Dom, month: spec.Month &^ cronStarBit, dayOfWeek: spec.Dow,
	}
	runs, err := countScheduleRunsInYear(ctx, schedule, spec, value.start, value.end)
	if err != nil {
		return scanRunsPerDayValue{}, err
	}
	value.observationsComplete = runs <= scanScheduleObservationLimit
	if runs == 0 {
		value.ok = true
		return value, nil
	}
	if !value.observationsComplete {
		// Five-field schedules fire on minute boundaries. This conservative
		// gap lets one-minute runs use the exact annual count; longer runs
		// simulate their starts across the full year below.
		value.minimumGap = time.Minute
	} else {
		var previous time.Time
		for next := first; next.Before(value.end); next = schedule.Next(next) {
			if err := ctx.Err(); err != nil {
				return scanRunsPerDayValue{}, err
			}
			if next.IsZero() {
				return scanRunsPerDayValue{}, errInvalidScanSchedulePattern
			}
			value.occurrences = append(value.occurrences, uint32(next.Sub(value.start)/time.Second))
			if !previous.IsZero() {
				gap := next.Sub(previous)
				if value.minimumGap == 0 || gap < value.minimumGap {
					value.minimumGap = gap
				}
			}
			previous = next
		}
		if len(value.occurrences) != runs {
			return scanRunsPerDayValue{}, errInvalidScanSchedulePattern
		}
	}
	if value.windowSeconds <= 0 {
		return scanRunsPerDayValue{}, nil
	}
	value.runsPerDay = float64(runs) / (value.windowSeconds / float64(24*time.Hour/time.Second))
	value.ok = true
	return value, nil
}

const cronStarBit = uint64(1) << 63

// countScheduleRunsInYear counts ordinary local days from the cron field
// bitsets, then uses cron.Next on the handful of days whose local duration
// differs from 24 hours. This keeps dense schedules bounded without dropping
// their month, day-of-month, weekday, or daylight-saving behavior.
func countScheduleRunsInYear(ctx context.Context, schedule cron.Schedule, spec *cron.SpecSchedule, start, end time.Time) (int, error) {
	ticksPerOrdinaryDay := bits.OnesCount64(spec.Second&^cronStarBit) * bits.OnesCount64(spec.Minute&^cronStarBit) * bits.OnesCount64(spec.Hour&^cronStarBit)
	var runs int
	for dayStart := start; dayStart.Before(end); {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		year, month, day := dayStart.Date()
		dayEnd := time.Date(year, month, day+1, 0, 0, 0, 0, start.Location())
		if !dayEnd.After(dayStart) {
			return 0, errInvalidScanSchedulePattern
		}
		if dayEnd.After(end) {
			dayEnd = end
		}
		if scheduleMatchesDay(spec, dayStart) {
			if dayEnd.Sub(dayStart) != 24*time.Hour || dayStart.Hour() != 0 || dayStart.Minute() != 0 || dayStart.Second() != 0 {
				count, err := countScheduleTicks(ctx, schedule, dayStart, dayEnd)
				if err != nil {
					return 0, err
				}
				runs += count
			} else {
				runs += ticksPerOrdinaryDay
			}
		}
		dayStart = dayEnd
	}
	return runs, nil
}

func scheduleMatchesDay(schedule *cron.SpecSchedule, day time.Time) bool {
	if 1<<uint(day.Month())&schedule.Month == 0 {
		return false
	}
	domMatches := 1<<uint(day.Day())&schedule.Dom != 0
	dowMatches := 1<<uint(day.Weekday())&schedule.Dow != 0
	if schedule.Dom&cronStarBit != 0 || schedule.Dow&cronStarBit != 0 {
		return domMatches && dowMatches
	}
	return domMatches || dowMatches
}

func countScheduleTicks(ctx context.Context, schedule cron.Schedule, start, end time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var count int
	for next := schedule.Next(start.Add(-time.Nanosecond)); ; next = schedule.Next(next) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if next.IsZero() {
			return 0, errInvalidScanSchedulePattern
		}
		if !next.Before(end) {
			return count, nil
		}
		count++
	}
}

func (value scanRunsPerDayValue) runsForDuration(ctx context.Context, runSeconds float64) (runsPerDay float64, skipped bool, err error) {
	if !value.ok || value.runsPerDay <= 0 || runSeconds <= 0 {
		return 0, false, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	if value.minimumGap > 0 && runSeconds <= value.minimumGap.Seconds() {
		return value.runsPerDay, false, nil
	}
	runDuration := time.Duration(runSeconds * float64(time.Second))
	if runSeconds > value.windowSeconds || !value.observationsComplete {
		// A truncated set of offsets cannot represent inactive calendar
		// periods or daylight-saving changes. Model starts over the same full
		// year used for the rate; skipping ahead over active runs bounds work.
		return simulateSchedule(ctx, value.schedule, value.start, value.end, runDuration)
	}
	busyUntil, err := simulateSchedulePrefix(ctx, value.schedule, value.start, runDuration)
	if err != nil {
		return 0, false, err
	}
	var starts float64
	for i, offset := range value.occurrences {
		if i&255 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, false, err
			}
		}
		tick := value.start.Add(time.Duration(offset) * time.Second)
		if tick.Before(busyUntil) {
			skipped = true
			continue
		}
		starts++
		busyUntil = tick.Add(runDuration)
	}
	windowDays := value.windowSeconds / float64(24*time.Hour/time.Second)
	if windowDays <= 0 {
		return 0, false, nil
	}
	return starts / windowDays, skipped, nil
}

func memoizedScheduleRunsForDuration(ctx context.Context, cache map[scanScheduleDurationKey]scanScheduleDurationEstimate, value scanRunsPerDayValue, runSeconds float64) (float64, bool, error) {
	return memoizedScheduleRunsForDurationWithBudget(ctx, cache, value, runSeconds, nil)
}

func memoizedScheduleRunsForDurationWithBudget(ctx context.Context, cache map[scanScheduleDurationKey]scanScheduleDurationEstimate, value scanRunsPerDayValue, runSeconds float64, budget *scanScheduleSimulationBudget) (float64, bool, error) {
	if !value.ok || value.runsPerDay <= 0 || runSeconds <= 0 {
		return value.runsForDuration(ctx, runSeconds)
	}
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	key := scanScheduleDurationKey{schedule: value.identity, runSeconds: math.Float64bits(runSeconds)}
	if estimate, ok := cache[key]; ok {
		return estimate.runsPerDay, estimate.skipped, nil
	}
	var budgetExhausted bool
	if budget != nil {
		value.schedule = budgetedCronSchedule{schedule: value.schedule, budget: budget, exhausted: &budgetExhausted}
	}
	runsPerDay, skipped, err := value.runsForDuration(ctx, runSeconds)
	if budgetExhausted {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, false, ctxErr
		}
		return 0, false, errScheduleSimulationBudgetExceeded
	}
	if err == nil {
		cache[key] = scanScheduleDurationEstimate{runsPerDay: runsPerDay, skipped: skipped}
	}
	return runsPerDay, skipped, err
}

func simulateSchedulePrefix(ctx context.Context, schedule cron.Schedule, start time.Time, runDuration time.Duration) (time.Time, error) {
	warmStart := start.Add(-2 * runDuration)
	busyUntil := warmStart
	for next := schedule.Next(warmStart.Add(-time.Nanosecond)); ; {
		if err := ctx.Err(); err != nil {
			return busyUntil, err
		}
		if next.IsZero() {
			return busyUntil, errInvalidScanSchedulePattern
		}
		if !next.Before(start) {
			return busyUntil, nil
		}
		if next.Before(busyUntil) {
			next = schedule.Next(busyUntil.Add(-time.Nanosecond))
			continue
		}
		busyUntil = next.Add(runDuration)
		next = schedule.Next(next)
	}
}

func simulateSchedule(ctx context.Context, schedule cron.Schedule, start, end time.Time, runDuration time.Duration) (float64, bool, error) {
	warmStart := start.Add(-2 * runDuration)
	busyUntil := warmStart
	var starts float64
	skipped := false
	for next := schedule.Next(warmStart.Add(-time.Nanosecond)); ; {
		if err := ctx.Err(); err != nil {
			return 0, false, err
		}
		if next.IsZero() {
			return 0, false, errInvalidScanSchedulePattern
		}
		if !next.Before(end) {
			break
		}
		if next.Before(busyUntil) {
			if !next.Before(start) {
				skipped = true
			}
			next = schedule.Next(busyUntil.Add(-time.Nanosecond))
			continue
		}
		if !next.Before(start) {
			starts++
		}
		busyUntil = next.Add(runDuration)
		next = schedule.Next(next)
	}
	windowDays := end.Sub(start).Seconds() / float64(24*time.Hour/time.Second)
	if windowDays <= 0 {
		return 0, false, nil
	}
	return starts / windowDays, skipped, nil
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
