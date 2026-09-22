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
	jobSilenceHeartbeatBudget = 5 * time.Second
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
		reference, err := a.Store.JobSilenceReference(ctx, record.ID, record.CreatedAt, now)
		if err != nil {
			a.silenceLogger().Warn("job silence watchdog could not determine reference", "job", record.Job.Name, "error", err)
			continue
		}
		if reference.IsZero() {
			// A malformed legacy row without creation or scan timestamps has no
			// safe anchor for a calendar window. Wait for the next lifecycle or
			// successful-scan write to provide one.
			a.silenceLogger().Debug("job silence watchdog skipped job without reference", "job", record.Job.Name)
			continue
		}
		threshold, err := jobSilenceThreshold(parser, record.Job, reference)
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
				// Do not advance the durable watchdog state when destinations
				// cannot be resolved. Recording the event would also advance its
				// exponential backoff without creating an outbox row, delaying
				// delivery long after the notifier is repaired. The next heartbeat
				// retries the same overdue window.
				continue
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

// checkJobSilenceBounded keeps the daemon heartbeat responsive when a large
// installation or a temporarily busy SQLite writer makes the watchdog query
// slow. A missed maintenance pass is safe; the next heartbeat retries it.
func (a *App) checkJobSilenceBounded(ctx context.Context, now time.Time) {
	budget := jobSilenceHeartbeatBudget
	if a.heartbeatInterval > 0 && a.heartbeatInterval/2 < budget {
		budget = a.heartbeatInterval / 2
	}
	if budget <= 0 {
		budget = time.Second
	}
	maintenanceCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	a.checkJobSilence(maintenanceCtx, now)
}

func (a *App) silenceLogger() *slog.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return slog.Default()
}

// jobSilenceThreshold returns the duration from reference until the next
// expected firing plus one representative interval. The caller supplies the
// same reference used by the store (creation, eligibility, or last success),
// so irregular calendars are evaluated against the missed window that is
// actually in progress rather than a historical maximum-gap sample.
func jobSilenceThreshold(parser cron.Parser, job config.Job, reference time.Time) (time.Duration, error) {
	timezone := job.Timezone
	if timezone == "" {
		timezone = "UTC"
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return 0, fmt.Errorf("invalid timezone: %w", err)
	}
	parsed, err := parser.Parse(fmt.Sprintf("CRON_TZ=%s %s", timezone, job.Schedule))
	if err != nil {
		return 0, err
	}
	localReference := reference.In(location)
	if parsed.Next(localReference).IsZero() {
		return 0, fmt.Errorf("schedule never fires")
	}
	deadline, interval, ok := cronSilenceDeadline(parsed, localReference)
	if !ok || interval <= 0 || deadline.IsZero() {
		return 0, fmt.Errorf("schedule interval unavailable")
	}
	if !deadline.After(localReference) {
		return 0, fmt.Errorf("schedule interval overflows watchdog window")
	}
	threshold := deadline.Sub(localReference)
	if threshold <= 0 {
		return 0, fmt.Errorf("schedule interval overflows watchdog window")
	}
	return threshold, nil
}

// cronInterval derives the interval between the two most recent occurrences
// without scanning every minute in a long schedule. An exponentially widening
// lookback finds a window containing an occurrence, then cron.Next walks only
// that bounded window to obtain the preceding pair.
func cronInterval(schedule cron.Schedule, now time.Time) (time.Duration, bool) {
	_, _, interval, ok := cronWindow(schedule, now)
	return interval, ok
}

// cronSilenceDeadline returns the next schedule occurrence after reference
// and one representative interval after it. cronWindow supplies the local
// preceding interval, while the direct Next call makes an occurrence exactly
// at reference count as the already-observed run rather than the missed one.
func cronSilenceDeadline(schedule cron.Schedule, reference time.Time) (deadline time.Time, interval time.Duration, ok bool) {
	if schedule == nil || reference.IsZero() {
		return time.Time{}, 0, false
	}
	next := schedule.Next(reference)
	if next.IsZero() || !next.After(reference) {
		return time.Time{}, 0, false
	}
	_, _, preceding, hasWindow := cronWindow(schedule, reference)
	interval = preceding
	if !hasWindow || interval < jobSilenceMinimumInterval {
		following := schedule.Next(next)
		if following.IsZero() || !following.After(next) {
			return time.Time{}, 0, false
		}
		interval = wallClockDuration(next, following)
	}
	if interval < jobSilenceMinimumInterval {
		return time.Time{}, 0, false
	}
	following := schedule.Next(next)
	deadline = following
	if following.IsZero() || !following.After(next) || wallClockDuration(next, following) != interval {
		deadline = addWallDuration(next, interval)
	}
	if deadline.IsZero() || !deadline.After(reference) || deadline.Sub(reference) <= 0 {
		return time.Time{}, 0, false
	}
	return deadline, interval, true
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
			interval = wallClockDuration(previous, last)
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

// wallClockDuration measures a cron gap using the displayed calendar fields
// instead of elapsed UTC time. A daily 09:00 schedule still has a 24-hour
// interval when a daylight-saving transition makes the elapsed duration 23 or
// 25 hours. This keeps the representative grace aligned with the user's local
// schedule while the final deadline retains the real elapsed time.
func wallClockDuration(from, to time.Time) time.Duration {
	if from.IsZero() || to.IsZero() || !to.After(from) {
		return 0
	}
	fromCivil := time.Date(from.Year(), from.Month(), from.Day(), from.Hour(), from.Minute(), from.Second(), from.Nanosecond(), time.UTC)
	toCivil := time.Date(to.Year(), to.Month(), to.Day(), to.Hour(), to.Minute(), to.Second(), to.Nanosecond(), time.UTC)
	return toCivil.Sub(fromCivil)
}

// addWallDuration advances a schedule occurrence in its local calendar. It
// avoids time.Time.Add's fixed-duration behavior, which can shift a 09:00
// deadline to 08:00 or 10:00 across daylight-saving transitions.
func addWallDuration(value time.Time, duration time.Duration) time.Time {
	if value.IsZero() || duration <= 0 {
		return time.Time{}
	}
	civil := time.Date(value.Year(), value.Month(), value.Day(), value.Hour(), value.Minute(), value.Second(), value.Nanosecond(), time.UTC).Add(duration)
	return time.Date(civil.Year(), civil.Month(), civil.Day(), civil.Hour(), civil.Minute(), civil.Second(), civil.Nanosecond(), value.Location())
}
