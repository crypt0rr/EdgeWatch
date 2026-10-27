package app

import (
	"context"
	"errors"
	"fmt"
	"math"
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

func TestScanSlotDemandUsesMedianCompletedCycleDuration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	// The timeout is longer than the median, so the median, not the
	// timeout, is each run's duration.
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
	for i, duration := range []time.Duration{time.Hour, 2 * time.Hour, 100 * time.Hour} {
		insertCompletedCycle(t, db, record, fmt.Sprintf("median-cycle-%d", i), duration)
	}

	demand, err := (&App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 1}}}).ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if demand.EnabledJobs != 1 || demand.HistoryJobs != 1 || demand.LowerBoundJobs != 0 {
		t.Fatalf("history source counts = enabled %d, history %d, lower bound %d; want 1, 1, 0", demand.EnabledJobs, demand.HistoryJobs, demand.LowerBoundJobs)
	}
	if got, want := demand.EstimatedSlotSecondsPerDay, float64(8*time.Hour/time.Second); math.Abs(got-want) > 0.01 {
		t.Fatalf("slot demand = %.2f seconds/day, want median 2h × 4 runs = %.2f", got, want)
	}
	if demand.OverCapacity || math.Abs(demand.UtilizationPercent-100.0/3.0) > 0.01 {
		t.Fatalf("capacity comparison = %+v, want 33.33%% and within one slot", demand)
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

	// A later successful run means the newest current-key runs are mixed, so
	// the completed sample remains the duration estimate instead of treating
	// the job as an all-timeout workload.
	insertCompletedScan(t, db, record, "successful-demand-after-timeouts", base.Add(12*time.Hour), 15*time.Minute)
	demand, err = app.ScanSlotDemand(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	if demand.HistoryJobs != 1 || math.Abs(demand.EstimatedSlotSecondsPerDay-float64(6*time.Hour/time.Second)) > 0.01 {
		t.Fatalf("demand after a newer successful scan = %+v; want its 15m sample × 24", demand)
	}
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
	// one-hour timeout ends each run sooner, but an hour every half hour is
	// still more than one slot-day, so the job adds one slot-day and cannot
	// keep its half-hourly cadence.
	if uncapped := runSlotSeconds(updated.Job, lowerBound) * runsPerDay; uncapped <= slotSecondsPerDay {
		t.Fatalf("updated job lower bound = %.2f seconds/day, want more than one slot-day", uncapped)
	}
	if after.HistoryJobs != 0 || after.LowerBoundJobs != 1 || after.EstimatedSlotSecondsPerDay != slotSecondsPerDay || after.CadenceUnattainableJobs != 1 {
		t.Fatalf("demand after scope/rate edit = %+v; want the current lower bound capped at one slot-day and its job counted as unable to keep its cadence", after)
	}
	if after.UtilizationPercent != 100 || after.OverCapacity {
		t.Fatalf("capacity warning after scope/rate edit = %+v; want the one job to fill its one slot without exceeding it", after)
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
	// Even at its one-hour timeout, the two-hour attempt of a half-hourly
	// job is 48 slot-hours a day, more than the one slot-day that one job
	// can use.
	if uncapped := runSlotSeconds(current.Job, cycle.FinishedAt.Sub(attemptStarted).Seconds()) * 48; uncapped <= slotSecondsPerDay {
		t.Fatalf("recovered attempt = %s, want more than one slot-day at 48 runs", cycle.FinishedAt.Sub(attemptStarted))
	}
	if demand.HistoryJobs != 1 || demand.LowerBoundJobs != 0 || demand.EstimatedSlotSecondsPerDay != slotSecondsPerDay || demand.CadenceUnattainableJobs != 1 {
		t.Fatalf("recovered cycle demand = %+v; want the completed attempt duration %s capped at one slot-day", demand, cycle.FinishedAt.Sub(attemptStarted))
	}
	if demand.UtilizationPercent != 100 || demand.OverCapacity {
		t.Fatalf("recovered cycle demand = %+v; want a full slot from the completed attempt", demand)
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

func TestMedianCycleDurationAveragesEvenSamples(t *testing.T) {
	got := medianCycleDuration([]time.Duration{5 * time.Second, time.Second, 3 * time.Second, 9 * time.Second})
	if want := 4 * time.Second; got != want {
		t.Fatalf("even-sample median = %s, want %s", got, want)
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
	t.Run("dense schedule observation limit", func(t *testing.T) {
		got, ok := scanJobRunsPerDay(config.Job{Schedule: "* * * * *"}, "")
		if !ok || got < 1440 || got > 1441 {
			t.Fatalf("dense schedule = %.4f runs/day, valid %v; want about 1440", got, ok)
		}
	})
}

func TestScanJobRunsPerDayCountsDenseCalendarScheduleAcrossYear(t *testing.T) {
	t.Parallel()
	pattern, err := schedulePattern(context.Background(), "UTC", "* * 1-15 * *")
	if err != nil || !pattern.ok {
		t.Fatalf("dense calendar schedule pattern = %+v, error %v; want a valid yearly estimate", pattern, err)
	}
	// The schedule runs every minute for the first 15 days of each month:
	// 180 active days × 1,440 ticks divided by the 366-day 2024 calendar.
	if got, want := pattern.runsPerDay, float64(180*24*60)/366; math.Abs(got-want) > 0.001 {
		t.Fatalf("dense calendar schedule = %.4f runs/day; want the full-year average %.4f", got, want)
	}
	if pattern.observationsComplete || len(pattern.occurrences) != 0 {
		t.Fatalf("dense calendar schedule retained %d of %d observations; want bounded offsets marked incomplete", len(pattern.occurrences), scanScheduleObservationLimit)
	}
	runs, skipped, err := pattern.runsForDuration(context.Background(), (15 * time.Minute).Seconds())
	if err != nil {
		t.Fatal(err)
	}
	if want := float64(180*24*4) / 366; math.Abs(runs-want) > 0.001 || !skipped {
		t.Fatalf("dense calendar schedule with 15m runs = %.4f starts/day, skipped %t; want %.4f and skipped", runs, skipped, want)
	}
}

type countingMinuteSchedule struct {
	NextCalls int
}

func (schedule *countingMinuteSchedule) Next(after time.Time) time.Time {
	schedule.NextCalls++
	return after.Truncate(time.Minute).Add(time.Minute)
}

func TestDenseScheduleDemandMemoizesByNormalizedScheduleAndDuration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	first, err := schedulePattern(ctx, "UTC", "* * * * *")
	if err != nil || !first.ok {
		t.Fatalf("first dense schedule = %+v, error %v", first, err)
	}
	second, err := schedulePattern(ctx, "UTC", "0-59 * * * *")
	if err != nil || !second.ok {
		t.Fatalf("equivalent dense schedule = %+v, error %v", second, err)
	}
	if first.identity != second.identity {
		t.Fatalf("equivalent cron expressions have different identities: %+v != %+v", first.identity, second.identity)
	}
	firstTicks, secondTicks := &countingMinuteSchedule{}, &countingMinuteSchedule{}
	first.schedule, second.schedule = firstTicks, secondTicks
	cache := make(map[scanScheduleDurationKey]scanScheduleDurationEstimate)

	const jobs = 100
	var gotRuns float64
	var gotSkipped bool
	for i := 0; i < jobs; i++ {
		pattern := first
		if i%2 != 0 {
			pattern = second
		}
		gotRuns, gotSkipped, err = memoizedScheduleRunsForDuration(ctx, cache, pattern, 61)
		if err != nil {
			t.Fatal(err)
		}
	}
	if math.Abs(gotRuns-720) > 0.001 || !gotSkipped {
		t.Fatalf("100 dense jobs with 61s runs = %.4f starts/day, skipped %t; want 720 and skipped", gotRuns, gotSkipped)
	}
	if len(cache) != 1 {
		t.Fatalf("memoized %d schedule-duration pairs, want one normalized pair", len(cache))
	}
	if calls := firstTicks.NextCalls + secondTicks.NextCalls; calls > 540_000 {
		t.Fatalf("100 equivalent dense jobs called Schedule.Next %d times; want at most 540000", calls)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	callsBeforeCanceledRequest := firstTicks.NextCalls + secondTicks.NextCalls
	if _, _, err := memoizedScheduleRunsForDuration(canceled, cache, first, 61); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled cached schedule estimate error = %v; want context.Canceled", err)
	}
	if calls := firstTicks.NextCalls + secondTicks.NextCalls; calls != callsBeforeCanceledRequest {
		t.Fatalf("canceled cached estimate made %d more Schedule.Next calls", calls-callsBeforeCanceledRequest)
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
	// Checks one through five reach the first annual day; cancel at the next
	// day boundary while countScheduleRunsInYear is still active.
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
	if _, _, err := simulateSchedule(ctx, schedule, start, end, time.Minute); !errors.Is(err, errInvalidScanSchedulePattern) {
		t.Fatalf("simulation for a never-firing schedule error = %v; want invalid schedule", err)
	}
	if _, err := simulateSchedulePrefix(ctx, schedule, start, time.Minute); !errors.Is(err, errInvalidScanSchedulePattern) {
		t.Fatalf("prefix simulation for a never-firing schedule error = %v; want invalid schedule", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := simulateSchedule(canceled, schedule, start, end, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled schedule simulation error = %v; want context.Canceled", err)
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
// estimate is the 20-minute median times its runs per day.
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
					t.Fatalf("demand after %s = %+v; want the 20m median of the kept samples × %.0f runs = %.0f seconds/day", step, demand, runsPerDay, want)
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
	key := store.NewScanDurationKey(record)
	finished := time.Date(2026, time.February, 1, 12, 0, 0, 0, time.UTC)
	finalStart := finished.Add(-attempt)
	firstStart := finalStart.Add(-time.Duration(attempts-1) * interval)
	stamp := func(value time.Time) string { return value.Format(time.RFC3339Nano) }
	if _, err := db.DB.Exec(`INSERT INTO scan_cycles(id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,attempt_count,total_units,total_probes,started_at,attempt_started_at,updated_at,expires_at,finished_at)
		VALUES(?,?,?,?,?,?,?,'completed',?,1,1,?,?,?,?,?)`,
		id, record.ID, record.Job.Name, record.Revision, key.ConfigHash, key.ExecutionHash, []byte("{}"), attempts,
		stamp(firstStart), stamp(finalStart), stamp(finished), stamp(finished), stamp(finished)); err != nil {
		t.Fatal(err)
	}
	for n := 1; n < attempts; n++ {
		started := firstStart.Add(time.Duration(n-1) * interval)
		if err := db.System().SaveScan(context.Background(), model.Scan{
			ID: fmt.Sprintf("%s-attempt-%02d", id, n), JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision,
			StartedAt: started, FinishedAt: started.Add(attempt), Status: "timed_out", ConfigHash: key.ConfigHash,
			CycleID: id, CycleAttempt: n, CycleStatus: "paused", Resumable: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	samples, err := defaultTenant(db).ListCompletedScanCycleDurations(context.Background(), []store.ScanDurationKey{key}, scanSlotDemandHistoryLimit)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Duration(attempts) * attempt; len(samples[record.ID]) != 1 || samples[record.ID][0] != want {
		t.Fatalf("%d-attempt cycle samples = %v, want one of %s", attempts, samples[record.ID], want)
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
		if _, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(config.Job{
			Name: name, Schedule: schedule, Timezone: timezone, Targets: []string{"192.0.2.1"},
			TCP: &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
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
		name        string
		timezone    string
		schedule    string
		runDuration time.Duration
		wantRuns    float64
		wantSkipped bool
	}{
		{name: "ten minute window with fifteen minute run", timezone: "UTC", schedule: "*/10 8-17 * * *", runDuration: 15 * time.Minute, wantRuns: 30, wantSkipped: true},
		{name: "two hourly ticks with ten minute run", timezone: "UTC", schedule: "0,5 * * * *", runDuration: 10 * time.Minute, wantRuns: 24, wantSkipped: true},
		{name: "completion exactly at next tick", timezone: "UTC", schedule: "*/15 * * * *", runDuration: 15 * time.Minute, wantRuns: 96},
		{name: "hourly across daylight saving", timezone: "Europe/Amsterdam", schedule: "0 * * * *", runDuration: 61 * time.Minute, wantRuns: 12, wantSkipped: true},
		{name: "dense schedule with long run", timezone: "UTC", schedule: "* * * * *", runDuration: 15 * 24 * time.Hour, wantRuns: 1.0 / 15, wantSkipped: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			pattern, err := schedulePattern(context.Background(), test.timezone, test.schedule)
			if err != nil || !pattern.ok {
				t.Fatalf("schedule pattern = %+v, error %v", pattern, err)
			}
			runs, skipped, err := pattern.runsForDuration(context.Background(), test.runDuration.Seconds())
			if err != nil {
				t.Fatal(err)
			}
			if math.Abs(runs-test.wantRuns) > 0.01 || skipped != test.wantSkipped {
				t.Fatalf("runs/day = %.4f, skipped %t; want %.4f and skipped %t", runs, skipped, test.wantRuns, test.wantSkipped)
			}
		})
	}
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
			if !ok || math.Abs(runs-1.0/366.0) > 0.001 {
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
