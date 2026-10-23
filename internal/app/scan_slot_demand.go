package app

import (
	"context"
	"math"
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
	// scanDurationKeyCacheLimit the remembered job revisions. A full cache
	// starts over, which costs one computation per schedule or job in use.
	scanRunsPerDayCacheLimit  = 1024
	scanDurationKeyCacheLimit = 16384
)

// ScanSlotDemand is a tenant's estimated scheduled scan work compared with
// the slot-hours its effective scan-slot limit can provide in a day.
type ScanSlotDemand struct {
	EnabledJobs     int `json:"enabled_jobs"`
	HistoryJobs     int `json:"history_jobs"`
	LowerBoundJobs  int `json:"lower_bound_jobs"`
	UnestimatedJobs int `json:"unestimated_jobs"`
	// CadenceUnattainableJobs counts the jobs whose own estimated demand is
	// more than one slot-day. Each run counts at most the job's timeout,
	// which ends it, so such a job's runs take longer than its schedule
	// leaves between them, and the scheduler skips some of them. Each adds
	// one slot-day to the estimate.
	CadenceUnattainableJobs    int     `json:"cadence_unattainable_jobs"`
	Slots                      int     `json:"slots"`
	EstimatedSlotSecondsPerDay float64 `json:"estimated_slot_seconds_per_day"`
	CapacitySlotSecondsPerDay  float64 `json:"capacity_slot_seconds_per_day"`
	UtilizationPercent         float64 `json:"utilization_percent"`
	OverCapacity               bool    `json:"over_capacity"`
}

// scheduledDemandJob is an enabled job whose schedule runs it.
type scheduledDemandJob struct {
	record     store.JobRecord
	runsPerDay float64
}

// ScanSlotDemand estimates the unit's scheduled demand from enabled jobs and
// compares it with the unit's effective slot capacity. The most recent
// completed scan-history samples that ran with a job's current scan settings
// are the expected duration; jobs without that history use only work bounded
// by an explicitly configured scanner rate. Each run counts at most the job's
// timeout, which ends it, and a job adds at most one slot-day, because it
// runs at most once at a time.
func (a *App) ScanSlotDemand(ctx context.Context, ts *store.TenantStore) (ScanSlotDemand, error) {
	var result ScanSlotDemand
	if a == nil || ts == nil {
		return result, store.ErrNoTenantScope
	}
	jobs, err := ts.ListJobs(ctx, false)
	if err != nil {
		return result, err
	}
	var scheduled []scheduledDemandJob
	var keys []store.ScanDurationKey
	for _, record := range jobs {
		if !record.Enabled || record.Archived {
			continue
		}
		result.EnabledJobs++
		if strings.TrimSpace(record.Job.Schedule) == "" {
			continue
		}
		runsPerDay, ok := a.scanJobRunsPerDay(record.Job)
		if !ok {
			result.UnestimatedJobs++
			continue
		}
		if runsPerDay <= 0 {
			continue
		}
		scheduled = append(scheduled, scheduledDemandJob{record: record, runsPerDay: runsPerDay})
		keys = append(keys, a.scanDurationKey(record))
	}
	history, err := ts.ListCompletedScanCycleDurations(ctx, keys, scanSlotDemandHistoryLimit)
	if err != nil {
		return result, err
	}
	limits, err := a.TenantCapacityLimits(ctx, ts)
	if err != nil {
		return result, err
	}
	result.Slots = limits.MaxConcurrentScans
	result.CapacitySlotSecondsPerDay = float64(max(limits.MaxConcurrentScans, 0)) * slotSecondsPerDay
	for _, job := range scheduled {
		var perRun float64
		if samples := history[job.record.ID]; len(samples) > 0 {
			perRun = medianCycleDuration(samples).Seconds()
			result.HistoryJobs++
		} else {
			lowerBound, hasBound, incomplete := scanRateLowerBound(job.record.Job, a.Config.Scanner.MaxJobHostsValue())
			if hasBound {
				perRun = lowerBound
				result.LowerBoundJobs++
			} else {
				result.UnestimatedJobs++
			}
			if incomplete && hasBound {
				result.UnestimatedJobs++
			}
		}
		demand := runSlotSeconds(job.record.Job, perRun) * job.runsPerDay
		if demand > slotSecondsPerDay {
			result.CadenceUnattainableJobs++
			demand = slotSecondsPerDay
		}
		result.EstimatedSlotSecondsPerDay += demand
	}
	if result.CapacitySlotSecondsPerDay > 0 {
		result.UtilizationPercent = result.EstimatedSlotSecondsPerDay / result.CapacitySlotSecondsPerDay * 100
	}
	result.OverCapacity = result.EstimatedSlotSecondsPerDay > result.CapacitySlotSecondsPerDay
	return result, nil
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

type scanRunsPerDayValue struct {
	runsPerDay float64
	ok         bool
}

// cachedScanDurationKey is the duration key of one revision of a job.
type cachedScanDurationKey struct {
	revision int64
	updated  time.Time
	key      store.ScanDurationKey
}

// scanSlotDemandCache remembers, for every business unit of the process,
// the parts of the scan-slot demand estimate that a request would otherwise
// compute again for each job: each schedule's runs per day, which depend
// only on its text and timezone, and each job revision's duration key,
// whose hashes a revision fixes. Each map starts over when it is full. Its
// zero value is ready to use.
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
	key := scanRunsPerDayKey{timezone: scheduleTimezone(job, a.Config.Timezone), schedule: job.Schedule}
	cache := &a.scanSlotDemand
	cache.mu.Lock()
	value, found := cache.runsPerDay[key]
	cache.mu.Unlock()
	if found {
		return value.runsPerDay, value.ok
	}
	// The computation can take tens of milliseconds for a dense schedule,
	// so it runs without the lock; two requests may both compute a new
	// schedule, with the same result.
	value.runsPerDay, value.ok = scheduleRunsPerDay(key.timezone, key.schedule)
	cache.mu.Lock()
	if cache.runsPerDay == nil || len(cache.runsPerDay) >= scanRunsPerDayCacheLimit {
		cache.runsPerDay = make(map[scanRunsPerDayKey]scanRunsPerDayValue)
	}
	cache.runsPerDay[key] = value
	cache.runsPerDayComputed++
	cache.mu.Unlock()
	return value.runsPerDay, value.ok
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
	cached = cachedScanDurationKey{revision: record.Revision, updated: record.UpdatedAt, key: store.NewScanDurationKey(record)}
	cache.mu.Lock()
	if cache.keys == nil || len(cache.keys) >= scanDurationKeyCacheLimit {
		cache.keys = make(map[string]cachedScanDurationKey)
	}
	cache.keys[record.ID] = cached
	cache.mu.Unlock()
	return cached.key
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
// year. For dense schedules it stops after two weeks of observations, which
// captures the daily and weekly pattern without iterating hundreds of
// thousands of one-minute runs.
func scheduleRunsPerDay(timezone, scheduleText string) (float64, bool) {
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return 0, false
	}
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(scheduleText)
	if err != nil {
		return 0, false
	}
	start := time.Date(2024, time.January, 1, 0, 0, 0, 0, location)
	end := time.Date(2025, time.January, 1, 0, 0, 0, 0, location)
	const observationLimit = 20_000
	var runs int
	var observedThrough time.Time
	for next := schedule.Next(start.Add(-time.Nanosecond)); next.Before(end); next = schedule.Next(next) {
		runs++
		observedThrough = next
		if runs >= observationLimit {
			break
		}
	}
	if runs == 0 {
		return 0, true
	}
	windowDays := end.Sub(start).Hours() / 24
	if runs >= observationLimit && observedThrough.After(start) {
		windowDays = observedThrough.Sub(start).Hours() / 24
	}
	if windowDays <= 0 {
		return 0, false
	}
	return float64(runs) / windowDays, true
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
