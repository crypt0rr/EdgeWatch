package store

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
)

func TestMigrationBackfillsRefreshStartupHeartbeat(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	// Use enough rows to cross a bounded batch for both resumable migrations.
	const rowCount = 257
	legacyTimestamp := "2026-09-20T12:34:56Z"
	for i := 0; i < rowCount; i++ {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO scans(id,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json) VALUES(?,?,?,?,?,?,?,?,?)`,
			fmt.Sprintf("migration-progress-scan-%03d", i), "migration-progress", legacyTimestamp, legacyTimestamp, "success", "", "", "hash", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}

	job, err := s.CreateJob(ctx, testJob("migration-progress-cycle"))
	if err != nil {
		t.Fatal(err)
	}
	plan := scanner.WorkPlan{
		CreatedAt:   time.Now().UTC(),
		Job:         job.Job,
		Scopes:      []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1"}},
		Units:       []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Family: 4, Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1}},
		TotalUnits:  1,
		TotalProbes: 1,
	}
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{
		JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision,
		ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan,
	})
	if err != nil {
		t.Fatal(err)
	}
	rawUnit, err := json.Marshal(plan.Units[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycle_units SET identity='' WHERE cycle_id=?`, cycle.ID); err != nil {
		t.Fatal(err)
	}
	for sequence := 1; sequence < rowCount; sequence++ {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO scan_cycle_units(cycle_id,sequence,work_unit_json,identity,phase,probes,status,attempts,snapshot_json,started_at,finished_at,last_error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
			cycle.ID, sequence, rawUnit, "", "tcp", 1, "pending", 0, []byte(`{}`), "", "", ""); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := s.DB.ExecContext(ctx, `UPDATE timestamp_normalization_state SET complete=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycle_identity_backfill SET complete=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	const oldHeartbeat = "2000-01-01T00:00:00.000000000Z"
	if _, err := s.DB.ExecContext(ctx, `UPDATE startup_state SET state='migrating',updated_at=?,last_error='' WHERE id=1`, oldHeartbeat); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TABLE migration_progress_observations(phase TEXT NOT NULL,updated_at TEXT NOT NULL,progress INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER migration_progress_capture AFTER UPDATE OF phase,updated_at,progress ON startup_state WHEN NEW.state='migrating' BEGIN INSERT INTO migration_progress_observations(phase,updated_at,progress) VALUES(NEW.phase,NEW.updated_at,NEW.progress); END`); err != nil {
		t.Fatal(err)
	}

	if err := migrate(s.DB); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		name  string
		phase string
	}{
		{name: "timestamp normalization", phase: "timestamp-normalization:%"},
		{name: "cycle identities", phase: "scan-cycle-identities"},
		{name: "legacy hosts", phase: "legacy-host-index"},
	} {
		var updates, progressed int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(MAX(progress),0) FROM migration_progress_observations WHERE phase LIKE ? AND updated_at<>?`, check.phase, oldHeartbeat).Scan(&updates, &progressed); err != nil {
			t.Fatalf("%s heartbeat query: %v", check.name, err)
		}
		if updates == 0 || progressed == 0 {
			t.Fatalf("%s heartbeat updates=%d progressed=%d, want at least one post-commit update", check.name, updates, progressed)
		}
	}
}
