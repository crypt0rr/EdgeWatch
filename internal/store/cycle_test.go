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

func TestListActiveScanCycleSummariesFiltersArchiveAndOmitsPlan(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	active, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	active, err = s.StartScanCycleAttempt(ctx, active.ID)
	if err != nil {
		t.Fatal(err)
	}

	archivedJob, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "archived-cycle", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.2"}, TCP: &config.Protocol{Ports: "1", Mode: "syn"}}))
	if err != nil {
		t.Fatal(err)
	}
	archivedPlan := plan
	archivedPlan.Job = archivedJob.Job
	archivedPlan.Scopes = []model.Scope{{Target: "192.0.2.2", Protocol: "tcp", Ports: "1"}}
	archivedPlan.Units = []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Family: 4, Addresses: []string{"192.0.2.2"}, Ports: "1", PortCount: 1, Probes: 1}}
	archivedCycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: archivedJob.ID, Job: archivedJob.Job.Name, JobRevision: archivedJob.Revision, ConfigHash: archivedJob.Job.SecurityHash(), ExecutionHash: archivedJob.Job.ExecutionHash(), Plan: archivedPlan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE jobs SET archived=1 WHERE id=?`, archivedJob.ID); err != nil {
		t.Fatal(err)
	}

	assertCycle := func(got ScanCycleSummary, want ScanCycleRecord) {
		t.Helper()
		if got.ID != want.ID || got.JobID != want.JobID || got.JobRevision != want.JobRevision || got.Status != want.Status || got.AttemptCount != want.AttemptCount || got.NoProgressAttempts != want.NoProgressAttempts || got.TotalUnits != want.TotalUnits || got.CompletedUnits != want.CompletedUnits || got.TotalProbes != want.TotalProbes || got.CompletedProbes != want.CompletedProbes || !got.StartedAt.Equal(want.StartedAt) || !got.UpdatedAt.Equal(want.UpdatedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) || !got.FinishedAt.Equal(want.FinishedAt) || got.LastError != want.LastError {
			t.Fatalf("cycle summary = %#v, want fields from %#v", got, want)
		}
	}

	visible, err := s.ListActiveScanCycleSummaries(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(visible) != 1 {
		t.Fatalf("visible cycle summaries = %#v, want only the unarchived job", visible)
	}
	assertCycle(visible[job.ID], active)
	if _, ok := visible[archivedJob.ID]; ok {
		t.Fatal("archived job cycle appeared when archived jobs were excluded")
	}

	all, err := s.ListActiveScanCycleSummaries(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("all cycle summaries = %#v, want both active cycles", all)
	}
	assertCycle(all[job.ID], active)
	assertCycle(all[archivedJob.ID], archivedCycle)
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
	var checkpoint []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT snapshot_json FROM scan_cycle_units WHERE cycle_id=? AND sequence=0`, cycle.ID).Scan(&checkpoint); err != nil {
		t.Fatal(err)
	}
	if string(checkpoint) == "{}" {
		t.Fatal("completed cycle checkpoint was reclaimed before scan promotion")
	}
	if err := s.SaveScan(ctx, model.Scan{
		ID: "cycle-promoted", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name,
		StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), Status: "success",
		ConfigHash: job.Job.SecurityHash(), CycleID: cycle.ID, CycleStatus: "completed", Snapshot: model.Snapshot{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT snapshot_json FROM scan_cycle_units WHERE cycle_id=? AND sequence=0`, cycle.ID).Scan(&checkpoint); err != nil {
		t.Fatal(err)
	}
	if string(checkpoint) != "{}" {
		t.Fatalf("promoted cycle checkpoint = %q, want reclaimed payload", checkpoint)
	}
	var status string
	if err := s.DB.QueryRowContext(ctx, `SELECT status FROM scan_cycle_units WHERE cycle_id=? AND sequence=0`, cycle.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "completed" {
		t.Fatalf("promoted cycle unit status = %q, want completed", status)
	}
}

func TestRetentionDoesNotClearCycleCheckpointForAttemptOnly(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	defer s.Close()
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
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
	fragment := model.Snapshot{Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}}}}}
	if err := s.CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, fragment); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteScanCycle(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.SaveScan(ctx, model.Scan{ID: "timeout-attempt", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: now, FinishedAt: now, Status: "timed_out", CycleID: cycle.ID, CycleStatus: "completed", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{}}); err != nil {
		t.Fatal(err)
	}
	if err := s.clearCompletedCyclePayloads(ctx); err != nil {
		t.Fatal(err)
	}
	var checkpoint []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT snapshot_json FROM scan_cycle_units WHERE cycle_id=? AND sequence=?`, cycle.ID, unit.Sequence).Scan(&checkpoint); err != nil {
		t.Fatal(err)
	}
	if string(checkpoint) == "{}" {
		t.Fatal("attempt-only scan caused checkpoint reclamation")
	}
	if err := s.SaveScan(ctx, model.Scan{ID: "promoted-final", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", CycleID: cycle.ID, CycleStatus: "completed", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{}}); err != nil {
		t.Fatal(err)
	}
	if err := s.clearCompletedCyclePayloads(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT snapshot_json FROM scan_cycle_units WHERE cycle_id=? AND sequence=?`, cycle.ID, unit.Sequence).Scan(&checkpoint); err != nil {
		t.Fatal(err)
	}
	if string(checkpoint) != "{}" {
		t.Fatalf("promoted checkpoint = %q, want reclaimed sentinel", checkpoint)
	}
}

func TestLoadScanCycleFragmentsRejectsReclaimedCheckpoint(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	defer s.Close()
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycle_units SET status='completed',snapshot_json='{}' WHERE cycle_id=? AND sequence=0`, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LoadScanCycleFragments(ctx, cycle.ID); !errors.Is(err, ErrMissingCheckpoint) {
		t.Fatalf("reclaimed checkpoint error = %v, want ErrMissingCheckpoint", err)
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
