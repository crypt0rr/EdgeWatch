package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/scanner"
)

func TestMigration44PreservesPausedCycleBaselineEpoch(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "baseline-epoch.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	job, err := store.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name:     "epoch-migration",
		Schedule: "0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.1"},
		TCP:      &config.Protocol{Ports: "1", Mode: "connect"},
	}))
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	// Model a job with an established baseline. The cycle below was created
	// before migration 44 and still carries the pre-epoch default of zero.
	if _, err := store.DB.ExecContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,candidate_attempts,incomplete_candidate_attempts,pending_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, job.ID, 1, "baseline-scan", "baseline-hash", 1, 1, 0, 0, 0, 0, sqliteTimestamp(time.Now())); err != nil {
		store.Close()
		t.Fatal(err)
	}
	var beforeEpoch int64
	if err := store.DB.QueryRowContext(ctx, `SELECT baseline_epoch FROM job_runtime_meta WHERE job_id=?`, job.ID).Scan(&beforeEpoch); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if beforeEpoch != 0 {
		store.Close()
		t.Fatalf("fixture runtime epoch = %d, want zero", beforeEpoch)
	}
	cycle, err := store.CreateScanCycle(ctx, ScanCycleRecord{
		JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision,
		ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(),
		Plan:      scanner.WorkPlan{Job: job.Job, Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Family: 4, Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1}}, TotalUnits: 1, TotalProbes: 1},
		StartedAt: time.Now().UTC(),
	})
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	if cycle.BaselineEpoch != 0 || cycle.Status != "paused" {
		store.Close()
		t.Fatalf("pre-migration cycle = %#v, want paused epoch zero", cycle)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen as a legacy schema-43 database. The current table shape remains in
	// place in this fixture, just as it does for an interrupted upgrade, while
	// the migration runner executes the epoch backfill statement.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `PRAGMA user_version=43`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	var runtimeEpoch int64
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT baseline_epoch FROM job_runtime_meta WHERE job_id=?`, job.ID).Scan(&runtimeEpoch); err != nil {
		t.Fatal(err)
	}
	if runtimeEpoch != 1 {
		t.Fatalf("migrated runtime epoch = %d, want one", runtimeEpoch)
	}
	got, err := upgraded.GetScanCycle(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.BaselineEpoch != 1 || got.Status != "paused" || got.CompletedUnits != 0 {
		t.Fatalf("migrated cycle = %#v, want paused epoch one with progress retained", got)
	}
	if _, err := upgraded.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatalf("migrated cycle could not resume: %v", err)
	}
	resumed, err := upgraded.GetScanCycle(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Status != "running" || resumed.BaselineEpoch != 1 {
		t.Fatalf("resumed migrated cycle = %#v", resumed)
	}
}
