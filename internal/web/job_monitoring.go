package web

import (
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/robfig/cron/v3"
)

// jobScanStatusView is the jobs-list-safe projection of one scan. Scan IDs are
// included only for sessions that can open scan details; errors and scan data
// are never part of this view.
type jobScanStatusView struct {
	ScanID     string     `json:"scan_id,omitempty"`
	Status     string     `json:"status"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

// jobMonitoringSummaryView describes the available monitoring state of one
// job without making a general healthy/unhealthy assertion.
type jobMonitoringSummaryView struct {
	Availability         string             `json:"availability"`
	HistoryAvailable     bool               `json:"history_available"`
	Activity             *string            `json:"activity"`
	ScheduleState        string             `json:"schedule_state"`
	NextRunAt            *time.Time         `json:"next_run_at"`
	Timezone             string             `json:"timezone"`
	LatestAttempt        *jobScanStatusView `json:"latest_attempt"`
	LatestSuccessfulScan *jobScanStatusView `json:"latest_successful_scan"`
	AttentionReason      string             `json:"attention_reason"`
}

func jobMonitoringSummary(
	record store.JobRecord,
	execution store.JobExecutionSummary,
	budgetSkipAlertKey string,
	historyAvailable bool,
	appActivity string,
	appActivityAvailable bool,
	cycleStatus string,
	cycleAvailable bool,
	canReadScans bool,
	now time.Time,
) jobMonitoringSummaryView {
	view := jobMonitoringSummaryView{
		Availability:     "unavailable",
		HistoryAvailable: historyAvailable,
		ScheduleState:    "scheduled",
		Timezone:         record.Job.Timezone,
		AttentionReason:  "none",
	}
	activity := ""
	if !historyAvailable {
		view.Availability = "unavailable"
	} else {
		view.LatestAttempt = jobScanStatus(execution.LatestAttempt, canReadScans)
		view.LatestSuccessfulScan = jobScanStatus(execution.LatestSuccessfulScan, canReadScans)
	}

	switch {
	case appActivityAvailable && appActivity == "queued":
		activity = "queued"
	case appActivityAvailable && appActivity == "running":
		activity = "running"
	case appActivityAvailable && cycleAvailable && cycleStatus == "stalled":
		activity = "stalled"
	case appActivityAvailable && cycleAvailable && (cycleStatus == "paused" || cycleStatus == "running"):
		// A durable running cycle without a live queued/running process is
		// recoverable work. Keep that distinct from a live running scan.
		activity = "resumable"
	case appActivityAvailable && cycleAvailable:
		activity = "none"
	}
	if activity != "" {
		view.Activity = &activity
	}
	if historyAvailable && appActivityAvailable && cycleAvailable && view.Activity != nil {
		view.Availability = "available"
	}

	switch {
	case record.Archived:
		view.ScheduleState = "archived"
	case !record.Enabled:
		view.ScheduleState = "paused"
	case strings.TrimSpace(record.Job.Schedule) == "":
		view.ScheduleState = "manual"
	default:
		parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		spec := "CRON_TZ=" + record.Job.Timezone + " " + strings.TrimSpace(record.Job.Schedule)
		parsed, err := parser.Parse(spec)
		if err != nil {
			view.ScheduleState = "unavailable"
		} else if next := parsed.Next(now.UTC()); next.IsZero() {
			view.ScheduleState = "unavailable"
		} else {
			next = next.UTC()
			view.NextRunAt = &next
		}
	}

	switch {
	case cycleAvailable && cycleStatus == "stalled":
		view.AttentionReason = "stalled_cycle"
	case view.Activity != nil && (*view.Activity == "queued" || *view.Activity == "running"):
		// Only current queued/running work supersedes an older result. An
		// unavailable activity lookup cannot erase a known outcome.
	case budgetSkipAlertKey != "":
		// This persisted marker records the last scheduled budget skip; it does
		// not predict whether changed DNS answers or budgets block the next run.
		view.AttentionReason = "probe_budget_skipped"
	case historyAvailable && execution.LatestAttempt != nil:
		switch execution.LatestAttempt.Status {
		case "failed", "timed_out":
			view.AttentionReason = "failed"
		case "incomplete":
			view.AttentionReason = "incomplete"
		}
	}
	return view
}

func jobScanStatus(summary *store.JobScanStatusSummary, canReadScans bool) *jobScanStatusView {
	if summary == nil {
		return nil
	}
	view := &jobScanStatusView{
		Status:     summary.Status,
		StartedAt:  nullableTime(summary.StartedAt),
		FinishedAt: nullableTime(summary.FinishedAt),
	}
	if canReadScans {
		view.ScanID = summary.ID
	}
	return view
}

func nullableTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	value = value.UTC()
	return &value
}
