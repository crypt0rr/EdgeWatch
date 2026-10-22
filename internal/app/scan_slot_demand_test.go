package app

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestScanSlotDemandUsesMedianCompletedCycleDuration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	job := config.NormalizeJob(config.Job{
		Name:     "historical",
		Schedule: "0 */6 * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.1"},
		TCP:      &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{Rate: 1000}},
	})
	record, err := ts.CreateJobWithEnabled(ctx, job, true)
	if err != nil {
		t.Fatal(err)
	}
	for i, duration := range []time.Duration{time.Hour, 2 * time.Hour, 100 * time.Hour} {
		insertCompletedCycle(t, db, record.ID, record.Job.Name, record.Revision, fmt.Sprintf("median-cycle-%d", i), duration)
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

func TestScanSlotDemandSumsRateLowerBoundsAgainstCapacity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := storetest.OpenFresh(t)
	ts := defaultTenant(db)
	job := config.NormalizeJob(config.Job{
		Name:     "full-tcp-00",
		Schedule: "0 */6 * * *",
		Timezone: "UTC",
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

func TestScanJobRunsPerDayUsesSixHourlySchedule(t *testing.T) {
	t.Parallel()
	job := config.Job{Schedule: "0 */6 * * *", Timezone: "UTC"}
	if got, ok := scanJobRunsPerDay(job, ""); !ok || math.Abs(got-4) > 0.001 {
		t.Fatalf("six-hourly schedule = %.4f runs/day, valid %v; want 4", got, ok)
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
	seconds, hasBound, incomplete := scanRateLowerBound(job)
	if !hasBound || !incomplete || math.Abs(seconds-0.01) > 0.000001 {
		t.Fatalf("Nmap lower bound = %.6fs, known %v, incomplete %v; want 0.01s for one guaranteed probe at 100/s and service detection marked unestimated", seconds, hasBound, incomplete)
	}
}

func insertCompletedCycle(t *testing.T, db *store.Store, jobID, name string, revision int64, id string, duration time.Duration) {
	t.Helper()
	finished := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	started := finished.Add(-duration)
	_, err := db.DB.Exec(`INSERT INTO scan_cycles(id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,total_units,total_probes,started_at,updated_at,expires_at,finished_at)
		VALUES(?,?,?,?,?,?,?,'completed',0,0,?,?,?,?)`,
		id, jobID, name, revision, "hash", "execution-hash", []byte("{}"),
		started.Format(time.RFC3339Nano), finished.Format(time.RFC3339Nano), finished.Format(time.RFC3339Nano), finished.Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
}
