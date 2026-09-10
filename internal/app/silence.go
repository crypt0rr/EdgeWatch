package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/robfig/cron/v3"
)

const (
	jobSilenceMinimumInterval = time.Minute
	jobSilenceLookback        = 5 * 365 * 24 * time.Hour
	jobSilenceHorizon         = 2 * 365 * 24 * time.Hour
	jobSilenceMaxOccurrences  = 4096
)

// nowUTC is kept behind a small injectable clock so the daemon watchdog can
// be tested by advancing time without sleeping. Production callers use the
// wall clock; tests may set clock to a deterministic function.
func (a *App) nowUTC() time.Time {
	if a.clock != nil {
		return a.clock().UTC()
	}
	return time.Now().UTC()
}

// checkJobSilence runs from the daemon heartbeat. It only evaluates enabled,
// non-archived managed jobs and leaves the normal scan/change engine untouched.
// A store transaction decides whether a job is overdue, active, or already
// alerted in the current window, then persists the event and outbox together.
func (a *App) checkJobSilence(ctx context.Context, now time.Time) {
	if a.Store == nil {
		return
	}
	jobs, err := a.Store.ListJobs(ctx, false)
	if err != nil {
		a.silenceLogger().Warn("job silence watchdog could not list jobs", "error", err)
		return
	}
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	for _, record := range jobs {
		if !record.Enabled || record.Archived {
			continue
		}
		threshold, err := jobSilenceThreshold(parser, record.Job, now)
		if err != nil {
			// Schedule reconciliation already reports invalid persisted schedules;
			// avoid repeating that warning every heartbeat.
			a.silenceLogger().Debug("job silence watchdog skipped job", "job", record.Job.Name, "error", err)
			continue
		}
		due, err := a.Store.JobSilenceDue(ctx, record.ID, record.CreatedAt, now, threshold)
		if err != nil {
			a.silenceLogger().Warn("job silence watchdog failed", "job", record.Job.Name, "error", err)
			continue
		}
		if !due {
			continue
		}
		var destinations []string
		if a.Notifier != nil {
			destinations, err = a.Notifier.QueueDestinationsForJob(ctx, record.Job)
			if err != nil {
				a.silenceLogger().Warn("job silence notification destinations unavailable", "job", record.Job.Name, "error", err)
				// Retain the event even if destinations are temporarily unavailable;
				// the next window can retry after configuration is repaired.
				destinations = nil
			}
		}
		event, created, err := a.Store.RecordJobSilenceAlert(ctx, record.ID, record.Job.Name, record.CreatedAt, now, threshold, destinations)
		if err != nil {
			a.silenceLogger().Warn("job silence watchdog failed", "job", record.Job.Name, "error", err)
			continue
		}
		if created {
			a.emitEvents([]model.Event{event})
			a.wakeDelivery()
		}
	}
}

func (a *App) silenceLogger() *slog.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return slog.Default()
}

func jobSilenceThreshold(parser cron.Parser, job config.Job, now time.Time) (time.Duration, error) {
	timezone := job.Timezone
	if timezone == "" {
		timezone = "UTC"
	}
	parsed, err := parser.Parse(fmt.Sprintf("CRON_TZ=%s %s", timezone, job.Schedule))
	if err != nil {
		return 0, err
	}
	if parsed.Next(now.UTC()).IsZero() {
		return 0, fmt.Errorf("schedule never fires")
	}
	maxGap, typicalGap, ok := maxScheduleGap(parsed, now.UTC())
	if !ok || maxGap <= 0 {
		return 0, fmt.Errorf("schedule interval unavailable")
	}
	// Keep one representative interval of grace after the largest expected
	// calendar gap. This catches weekend/month-end/year-boundary gaps while
	// staying bounded for schedules that fire every minute.
	if typicalGap <= 0 {
		typicalGap = maxGap
	}
	if maxGap > time.Duration(1<<63-1)-typicalGap {
		return 0, fmt.Errorf("schedule interval overflows watchdog window")
	}
	threshold := maxGap + typicalGap
	if threshold <= 0 {
		return 0, fmt.Errorf("schedule interval overflows watchdog window")
	}
	return threshold, nil
}

// maxScheduleGap samples a bounded occurrence window and returns both the
// largest calendar gap and the smallest positive gap. The occurrence cap
// keeps minute-level schedules cheap while the two-year horizon catches
// weekend, month-end, and annual schedules.
func maxScheduleGap(schedule cron.Schedule, now time.Time) (maxGap, typicalGap time.Duration, ok bool) {
	if schedule == nil || now.IsZero() {
		return 0, 0, false
	}
	start := now.Add(-jobSilenceHorizon)
	previous := schedule.Next(start)
	if previous.IsZero() {
		return 0, 0, false
	}
	end := now.Add(jobSilenceHorizon)
	for occurrence := 0; occurrence < jobSilenceMaxOccurrences && !previous.After(end); occurrence++ {
		next := schedule.Next(previous)
		if next.IsZero() {
			break
		}
		gap := next.Sub(previous)
		if gap >= jobSilenceMinimumInterval {
			if gap > maxGap {
				maxGap = gap
			}
			if typicalGap == 0 || gap < typicalGap {
				typicalGap = gap
			}
		}
		previous = next
	}
	return maxGap, typicalGap, maxGap > 0
}

// cronInterval derives the interval between the two most recent occurrences
// without scanning every minute in a long schedule. An exponentially widening
// lookback finds a window containing an occurrence, then cron.Next walks only
// that bounded window to obtain the preceding pair.
func cronInterval(schedule cron.Schedule, now time.Time) (time.Duration, bool) {
	_, _, interval, ok := cronWindow(schedule, now)
	return interval, ok
}

// cronWindow returns the last schedule occurrence, the next occurrence, and
// the interval immediately preceding the last one. Using the upcoming
// occurrence as well as the previous pair is important for calendars with
// uneven gaps (for example a weekday schedule across a weekend): a fixed
// weekday interval would otherwise report a healthy weekend gap as silent.
func cronWindow(schedule cron.Schedule, now time.Time) (last, next time.Time, interval time.Duration, ok bool) {
	if now.IsZero() {
		return time.Time{}, time.Time{}, 0, false
	}
	for delta := jobSilenceMinimumInterval; delta <= jobSilenceLookback; {
		probe := now.Add(-delta)
		var previous, last time.Time
		var upcoming time.Time
		for attempts := 0; attempts < 4096; attempts++ {
			occurrence := schedule.Next(probe)
			if occurrence.IsZero() {
				break
			}
			if !occurrence.Before(now) {
				upcoming = occurrence
				break
			}
			previous, last = last, occurrence
			probe = occurrence
		}
		if !previous.IsZero() && !last.IsZero() {
			interval = last.Sub(previous)
			if interval < jobSilenceMinimumInterval {
				interval = jobSilenceMinimumInterval
			}
			if upcoming.IsZero() {
				upcoming = schedule.Next(now)
			}
			return last, upcoming, interval, true
		}
		if delta >= jobSilenceLookback {
			break
		}
		if delta > jobSilenceLookback/2 {
			delta = jobSilenceLookback
		} else {
			delta *= 2
		}
	}
	return time.Time{}, time.Time{}, 0, false
}
