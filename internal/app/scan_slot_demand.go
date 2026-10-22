package app

import (
	"context"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/robfig/cron/v3"
)

const scanSlotDemandHistoryLimit = 11

// ScanSlotDemand is a tenant's estimated scheduled scan work compared with
// the slot-hours its effective scan-slot limit can provide in a day.
type ScanSlotDemand struct {
	EnabledJobs                int     `json:"enabled_jobs"`
	HistoryJobs                int     `json:"history_jobs"`
	LowerBoundJobs             int     `json:"lower_bound_jobs"`
	UnestimatedJobs            int     `json:"unestimated_jobs"`
	Slots                      int     `json:"slots"`
	EstimatedSlotSecondsPerDay float64 `json:"estimated_slot_seconds_per_day"`
	CapacitySlotSecondsPerDay  float64 `json:"capacity_slot_seconds_per_day"`
	UtilizationPercent         float64 `json:"utilization_percent"`
	OverCapacity               bool    `json:"over_capacity"`
}

// ScanSlotDemand estimates the unit's scheduled demand from enabled jobs and
// compares it with the unit's effective slot capacity. The most recent
// completed scan-history samples are the expected duration; jobs without that
// history use only work bounded by an explicitly configured scanner rate.
func (a *App) ScanSlotDemand(ctx context.Context, ts *store.TenantStore) (ScanSlotDemand, error) {
	var result ScanSlotDemand
	if a == nil || ts == nil {
		return result, store.ErrNoTenantScope
	}
	jobs, err := ts.ListJobs(ctx, false)
	if err != nil {
		return result, err
	}
	history, err := ts.ListCompletedScanCycleDurations(ctx, scanSlotDemandHistoryLimit)
	if err != nil {
		return result, err
	}
	limits, err := a.TenantCapacityLimits(ctx, ts)
	if err != nil {
		return result, err
	}
	result.Slots = limits.MaxConcurrentScans
	result.CapacitySlotSecondsPerDay = float64(max(limits.MaxConcurrentScans, 0)) * 24 * 60 * 60
	for _, record := range jobs {
		if !record.Enabled || record.Archived {
			continue
		}
		result.EnabledJobs++
		if strings.TrimSpace(record.Job.Schedule) == "" {
			continue
		}
		runsPerDay, ok := scanJobRunsPerDay(record.Job, a.Config.Timezone)
		if !ok {
			result.UnestimatedJobs++
			continue
		}
		if runsPerDay <= 0 {
			continue
		}

		if samples := history[record.ID]; len(samples) > 0 {
			duration := medianCycleDuration(samples)
			result.EstimatedSlotSecondsPerDay += duration.Seconds() * runsPerDay
			result.HistoryJobs++
			continue
		}

		lowerBound, hasBound, incomplete := scanRateLowerBound(record.Job)
		if hasBound {
			result.EstimatedSlotSecondsPerDay += lowerBound * runsPerDay
			result.LowerBoundJobs++
		} else {
			result.UnestimatedJobs++
		}
		if incomplete && hasBound {
			result.UnestimatedJobs++
		}
	}
	if result.CapacitySlotSecondsPerDay > 0 {
		result.UtilizationPercent = result.EstimatedSlotSecondsPerDay / result.CapacitySlotSecondsPerDay * 100
	}
	result.OverCapacity = result.EstimatedSlotSecondsPerDay > result.CapacitySlotSecondsPerDay
	return result, nil
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

// scanJobRunsPerDay averages a valid five-field schedule over one calendar
// year. For dense schedules it stops after two weeks of observations, which
// captures the daily and weekly pattern without iterating hundreds of
// thousands of one-minute runs.
func scanJobRunsPerDay(job config.Job, defaultTimezone string) (float64, bool) {
	timezone := strings.TrimSpace(job.Timezone)
	if timezone == "" {
		timezone = strings.TrimSpace(defaultTimezone)
	}
	if timezone == "" {
		timezone = "UTC"
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return 0, false
	}
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(job.Schedule)
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
// configured maximum rates. It deliberately excludes response-dependent
// waits, retries, Naabu-discovered Nmap enrichment, and Nmap work without an
// explicit --max-rate ceiling.
func scanRateLowerBound(job config.Job) (seconds float64, hasBound, incomplete bool) {
	job = config.NormalizeJob(job)
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
