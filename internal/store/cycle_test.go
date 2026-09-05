package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
)

func cycleFixture(t *testing.T) (context.Context, *Store, JobRecord, scanner.WorkPlan) {
	t.Helper()
	ctx := context.Background()
	s := openTestStore(t)
	job, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "cycle", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1", Mode: "syn"}}))
	if err != nil {
		t.Fatal(err)
	}
	plan := scanner.WorkPlan{CreatedAt: time.Now().UTC(), Job: job.Job, Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1"}}, Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Family: 4, Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1}}, TotalUnits: 1, TotalProbes: 1}
	return ctx, s, job, plan
}

func TestScanCycleCheckpointsAndCompletes(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	cycle, err = s.StartScanCycleAttempt(ctx, cycle.ID)
	if err != nil || cycle.Status != "running" || cycle.AttemptCount != 1 {
		t.Fatalf("start cycle = %#v, %v", cycle, err)
	}
	unit, err := s.NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, model.Snapshot{Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp"}}}); err != nil {
		t.Fatal(err)
	}
	cycle, err = s.CompleteScanCycle(ctx, cycle.ID)
	if err != nil || cycle.Status != "completed" || cycle.CompletedUnits != 1 || cycle.CompletedProbes != 1 {
		t.Fatalf("completed cycle = %#v, %v", cycle, err)
	}
	if _, err := s.NextScanCycleUnit(ctx, cycle.ID); !errors.Is(err, ErrNoPendingUnit) {
		t.Fatalf("expected no pending unit, got %v", err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("completed cycle restart error = %v", err)
	}
}

func TestScanCycleCompletionRequiresAllUnits(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteScanCycle(ctx, cycle.ID); !errors.Is(err, ErrCycleIncomplete) {
		t.Fatalf("incomplete cycle completion error = %v", err)
	}
}

func TestScanCyclePauseAndExpiryClearCheckpoints(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), Plan: plan, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PauseScanCycle(ctx, cycle.ID, true, "timeout"); err != nil {
		t.Fatal(err)
	}
	if expired, err := s.ExpireScanCycles(ctx, time.Now().UTC().Add(2*time.Hour)); err != nil || expired != 1 {
		t.Fatalf("expiry = %d, %v", expired, err)
	}
	var raw string
	if err := s.DB.QueryRowContext(ctx, `SELECT status FROM scan_cycles WHERE id=?`, cycle.ID).Scan(&raw); err != nil || raw != "expired" {
		t.Fatalf("cycle status = %q, %v", raw, err)
	}
}

func TestScanCycleStartExpiresAtomically(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{
		JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision,
		ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(),
		Plan: plan, ExpiresAt: time.Now().UTC().Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("expired cycle start error = %v", err)
	}
	var status string
	if err := s.DB.QueryRowContext(ctx, `SELECT status FROM scan_cycles WHERE id=?`, cycle.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "expired" {
		t.Fatalf("expired cycle status = %q", status)
	}
	var snapshot string
	if err := s.DB.QueryRowContext(ctx, `SELECT snapshot_json FROM scan_cycle_units WHERE cycle_id=? AND sequence=0`, cycle.ID).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot != "{}" {
		t.Fatalf("expired checkpoint was retained: %q", snapshot)
	}
}

func TestExpiredScanCycleRejectsLateCheckpoint(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	unit, err := s.NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	if expired, err := s.ExpireScanCycles(ctx, time.Now().UTC().Add(2*time.Hour)); err != nil || expired != 1 {
		t.Fatalf("expiry = %d, %v", expired, err)
	}
	if err := s.CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, model.Snapshot{}); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("late checkpoint error = %v", err)
	}
	if _, err := s.CompleteScanCycle(ctx, cycle.ID); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("expired cycle completion error = %v", err)
	}
}

func TestScanCycleUnitCompletionRequiresClaim(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteScanCycleUnit(ctx, cycle.ID, 0, model.Snapshot{}); err == nil {
		t.Fatal("unclaimed unit was completed")
	}
	if _, err := s.GetLatestScanCycle(ctx, job.ID); err != nil {
		t.Fatalf("latest cycle lookup failed: %v", err)
	}
}
