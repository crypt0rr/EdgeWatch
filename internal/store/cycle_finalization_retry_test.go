package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func completedUnpromotedCycle(t *testing.T) (context.Context, *Store, JobRecord, ScanCycleRecord) {
	t.Helper()
	ctx, s, job, plan := cycleFixture(t)
	cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{
		JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision,
		ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().ClaimScanCycleUnit(ctx, cycle.ID, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.System().CompleteScanCycleUnit(ctx, cycle.ID, 0, model.Snapshot{Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}}}}}); err != nil {
		t.Fatal(err)
	}
	cycle, err = s.System().CompleteScanCycle(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, s, job, cycle
}

func saveCycleAttempt(t *testing.T, ctx context.Context, s *Store, job JobRecord, cycle ScanCycleRecord, id, status, cycleStatus, message string, resumable bool) {
	t.Helper()
	stamp := time.Now().UTC()
	if err := s.System().SaveScan(ctx, model.Scan{
		ID: id, JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name,
		StartedAt: stamp.Add(-time.Second), FinishedAt: stamp, Status: status,
		Error: message, CycleID: cycle.ID, CycleStatus: cycleStatus,
		Resumable: resumable, ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDiscardCompletedCycleAfterFinalizationFailuresUsesBoundedExactMarker(t *testing.T) {
	t.Parallel()
	ctx, s, job, cycle := completedUnpromotedCycle(t)
	tenant := defaultTenant(s)

	for _, row := range []struct {
		id, status, cycleStatus, message string
		resumable                        bool
	}{
		{"unrelated-failed", "failed", "completed", "scanner failed", true},
		{"canceled", "canceled", "completed", model.ScanFinalizationFailureMessage, true},
		{"not-resumable", "failed", "completed", model.ScanFinalizationFailureMessage, false},
		{"other-cycle-state", "failed", "paused", model.ScanFinalizationFailureMessage, true},
	} {
		saveCycleAttempt(t, ctx, s, job, cycle, row.id, row.status, row.cycleStatus, row.message, row.resumable)
	}
	saveCycleAttempt(t, ctx, s, job, cycle, "finalize-one", "failed", "completed", model.ScanFinalizationFailureMessage, true)

	plan := queryPlan(t, s.DB, scanCycleFinalizationFailureCountQuery, cycle.ID, tenant.scope.id, model.ScanFinalizationFailureMessage, 2)
	if !strings.Contains(plan, scansCycleOutcomeIndex) {
		t.Fatalf("finalization count plan = %q, want %s", plan, scansCycleOutcomeIndex)
	}
	if discarded, err := tenant.DiscardCompletedScanCycleAfterFinalizationFailures(ctx, cycle.ID, cycle.BaselineEpoch, 2); err != nil || discarded {
		t.Fatalf("one exact failure discarded cycle: discarded=%t err=%v", discarded, err)
	}
	if got, err := tenant.GetScanCycle(ctx, cycle.ID); err != nil || got.Status != "completed" {
		t.Fatalf("cycle after one exact failure = %+v, %v", got, err)
	}

	saveCycleAttempt(t, ctx, s, job, cycle, "finalize-two", "failed", "completed", model.ScanFinalizationFailureMessage, true)
	saveCycleAttempt(t, ctx, s, job, cycle, "finalize-three", "failed", "completed", model.ScanFinalizationFailureMessage, true)
	discarded, err := tenant.DiscardCompletedScanCycleAfterFinalizationFailures(ctx, cycle.ID, cycle.BaselineEpoch, 2)
	if err != nil || !discarded {
		t.Fatalf("cycle at threshold = discarded %t, err %v; want discard", discarded, err)
	}
	got, err := tenant.GetScanCycle(ctx, cycle.ID)
	if err != nil || got.Status != "discarded" || got.CompletedUnits != 0 || got.TotalUnits != 0 {
		t.Fatalf("cycle after finalization threshold = %+v, %v", got, err)
	}
	if units, err := tenant.ListScanCycleUnitSummaries(ctx, cycle.ID); err != nil || len(units) != 0 {
		t.Fatalf("discarded cycle units = %v, %v; want none", units, err)
	}
	var attempts int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE cycle_id=?`, cycle.ID).Scan(&attempts); err != nil || attempts != 7 {
		t.Fatalf("discarded cycle scan history = %d, %v; want all 7 rows retained", attempts, err)
	}
	if discarded, err := tenant.DiscardCompletedScanCycleAfterFinalizationFailures(ctx, cycle.ID, cycle.BaselineEpoch, 2); err != nil || discarded {
		t.Fatalf("already discarded cycle decision = %t, %v; want no-op", discarded, err)
	}
}

func TestDiscardCompletedCycleAfterFinalizationFailuresRechecksEpochAndPromotion(t *testing.T) {
	t.Parallel()
	ctx, s, job, unpromoted := completedUnpromotedCycle(t)
	tenant := defaultTenant(s)
	for _, id := range []string{"stale-one", "stale-two"} {
		saveCycleAttempt(t, ctx, s, job, unpromoted, id, "failed", "completed", model.ScanFinalizationFailureMessage, true)
	}
	if discarded, err := tenant.DiscardCompletedScanCycleAfterFinalizationFailures(ctx, unpromoted.ID, unpromoted.BaselineEpoch+1, 2); err != nil || discarded {
		t.Fatalf("different epoch discarded cycle: %t, %v", discarded, err)
	}
	if cycle, err := tenant.GetScanCycle(ctx, unpromoted.ID); err != nil || cycle.Status != "completed" {
		t.Fatalf("cycle after epoch mismatch = %+v, %v", cycle, err)
	}

	ctx2, s2, job2, promoted := completedUnpromotedCycle(t)
	for _, id := range []string{"promoted-one", "promoted-two"} {
		saveCycleAttempt(t, ctx2, s2, job2, promoted, id, "failed", "completed", model.ScanFinalizationFailureMessage, true)
	}
	saveCycleAttempt(t, ctx2, s2, job2, promoted, "promoted-result", "success", "completed", "", true)
	if discarded, err := defaultTenant(s2).DiscardCompletedScanCycleAfterFinalizationFailures(ctx2, promoted.ID, promoted.BaselineEpoch, 2); err != nil || discarded {
		t.Fatalf("promoted cycle discarded: %t, %v", discarded, err)
	}
	if cycle, err := defaultTenant(s2).GetScanCycle(ctx2, promoted.ID); err != nil || cycle.Status != "completed" {
		t.Fatalf("promoted cycle after retry decision = %+v, %v", cycle, err)
	}
	if discarded, err := tenant.DiscardCompletedScanCycleAfterFinalizationFailures(ctx, "missing-cycle", 0, 2); !errors.Is(err, ErrNoScanCycle) || discarded {
		t.Fatalf("missing cycle decision = %t, %v; want ErrNoScanCycle", discarded, err)
	}
	if _, err := tenant.DiscardCompletedScanCycleAfterFinalizationFailures(ctx, unpromoted.ID, unpromoted.BaselineEpoch, 0); err == nil {
		t.Fatal("zero failure threshold was accepted")
	}
}

func TestDiscardCompletedCycleAfterFinalizationFailuresRollsBackOnUnitCleanupError(t *testing.T) {
	t.Parallel()
	ctx, s, job, cycle := completedUnpromotedCycle(t)
	for _, id := range []string{"rollback-one", "rollback-two"} {
		saveCycleAttempt(t, ctx, s, job, cycle, id, "failed", "completed", model.ScanFinalizationFailureMessage, true)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER reject_cycle_unit_delete BEFORE DELETE ON scan_cycle_units BEGIN SELECT RAISE(ABORT, 'injected cleanup failure'); END`); err != nil {
		t.Fatal(err)
	}
	if discarded, err := defaultTenant(s).DiscardCompletedScanCycleAfterFinalizationFailures(ctx, cycle.ID, cycle.BaselineEpoch, 2); err == nil || discarded {
		t.Fatalf("cleanup failure decision = %t, %v; want rollback", discarded, err)
	}
	if got, err := defaultTenant(s).GetScanCycle(ctx, cycle.ID); err != nil || got.Status != "completed" || got.CompletedUnits != 1 {
		t.Fatalf("cycle after rolled-back discard = %+v, %v", got, err)
	}
	if units, err := defaultTenant(s).ListScanCycleUnitSummaries(ctx, cycle.ID); err != nil || len(units) != 1 {
		t.Fatalf("units after rolled-back discard = %v, %v", units, err)
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TRIGGER reject_cycle_unit_delete`); err != nil {
		t.Fatal(err)
	}
	if discarded, err := defaultTenant(s).DiscardCompletedScanCycleAfterFinalizationFailures(ctx, cycle.ID, cycle.BaselineEpoch, 2); err != nil || !discarded {
		t.Fatalf("retry after cleanup recovery = %t, %v; want discard", discarded, err)
	}
}

func TestDiscardCompletedCycleLeavesUnitsWhenUpdateIsIgnored(t *testing.T) {
	t.Parallel()
	ctx, s, job, cycle := completedUnpromotedCycle(t)
	for _, id := range []string{"ignored-discard-one", "ignored-discard-two"} {
		saveCycleAttempt(t, ctx, s, job, cycle, id, "failed", "completed", model.ScanFinalizationFailureMessage, true)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER ignore_cycle_discard BEFORE UPDATE OF status ON scan_cycles WHEN NEW.status='discarded' BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}

	discarded, err := defaultTenant(s).DiscardCompletedScanCycleAfterFinalizationFailures(ctx, cycle.ID, cycle.BaselineEpoch, 2)
	if !errors.Is(err, ErrCycleNotResumable) || discarded {
		t.Fatalf("ignored discard update = %t, %v; want ErrCycleNotResumable", discarded, err)
	}
	if got, err := defaultTenant(s).GetScanCycle(ctx, cycle.ID); err != nil || got.Status != "completed" || got.CompletedUnits != 1 {
		t.Fatalf("cycle after ignored discard = %+v, %v; want completed cycle with progress", got, err)
	}
	if units, err := defaultTenant(s).ListScanCycleUnitSummaries(ctx, cycle.ID); err != nil || len(units) != 1 {
		t.Fatalf("units after ignored discard = %v, %v; want saved unit retained", units, err)
	}
}

func TestDiscardCompletedCyclePreservesProgressWhenFailureIndexIsUnavailable(t *testing.T) {
	t.Parallel()
	ctx, s, job, cycle := completedUnpromotedCycle(t)
	for _, id := range []string{"missing-index-one", "missing-index-two"} {
		saveCycleAttempt(t, ctx, s, job, cycle, id, "failed", "completed", model.ScanFinalizationFailureMessage, true)
	}
	if _, err := s.DB.ExecContext(ctx, `DROP INDEX `+scansCycleOutcomeIndex); err != nil {
		t.Fatal(err)
	}

	discarded, err := defaultTenant(s).DiscardCompletedScanCycleAfterFinalizationFailures(ctx, cycle.ID, cycle.BaselineEpoch, 2)
	if err == nil || discarded {
		t.Fatalf("decision with unavailable required index = %t, %v; want query failure", discarded, err)
	}
	if got, err := defaultTenant(s).GetScanCycle(ctx, cycle.ID); err != nil || got.Status != "completed" || got.CompletedUnits != 1 {
		t.Fatalf("cycle after marker-query failure = %+v, %v; want completed cycle with progress", got, err)
	}
	if units, err := defaultTenant(s).ListScanCycleUnitSummaries(ctx, cycle.ID); err != nil || len(units) != 1 {
		t.Fatalf("units after marker-query failure = %v, %v; want saved unit retained", units, err)
	}
}

func TestConcurrentFinalizationFailureDecisionsDiscardOnce(t *testing.T) {
	t.Parallel()
	ctx, s, job, cycle := completedUnpromotedCycle(t)
	for _, id := range []string{"concurrent-one", "concurrent-two"} {
		saveCycleAttempt(t, ctx, s, job, cycle, id, "failed", "completed", model.ScanFinalizationFailureMessage, true)
	}

	const workers = 8
	start := make(chan struct{})
	type result struct {
		discarded bool
		err       error
	}
	results := make(chan result, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			discarded, err := defaultTenant(s).DiscardCompletedScanCycleAfterFinalizationFailures(ctx, cycle.ID, cycle.BaselineEpoch, 2)
			results <- result{discarded: discarded, err: err}
		}()
	}
	close(start)
	group.Wait()
	close(results)
	decisions := 0
	for result := range results {
		if result.err != nil {
			t.Errorf("concurrent retry decision: %v", result.err)
		}
		if result.discarded {
			decisions++
		}
	}
	if decisions != 1 {
		t.Fatalf("concurrent discard decisions = %d, want exactly one", decisions)
	}
	if got, err := defaultTenant(s).GetScanCycle(ctx, cycle.ID); err != nil || got.Status != "discarded" {
		t.Fatalf("cycle after concurrent decisions = %+v, %v", got, err)
	}
}

func TestRetentionKeepsFinalizationFailuresWithRecoverableCycle(t *testing.T) {
	t.Parallel()
	ctx, s, job, cycle := completedUnpromotedCycle(t)
	now := time.Now().UTC()
	old := sqliteTimestamp(now.Add(-48 * time.Hour))
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET updated_at=?,finished_at=? WHERE id=?`, old, old, cycle.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"retained-finalize-one", "retained-finalize-two"} {
		saveCycleAttempt(t, ctx, s, job, cycle, id, "failed", "completed", model.ScanFinalizationFailureMessage, true)
	}

	if _, err := s.System().PruneWithStats(ctx, now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, err := defaultTenant(s).GetScanCycle(ctx, cycle.ID); err != nil || got.Status != "completed" {
		t.Fatalf("retention removed cycle while its failure history is retained: %+v, %v", got, err)
	}
	var failures int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE cycle_id=? AND error=?`, cycle.ID, model.ScanFinalizationFailureMessage).Scan(&failures); err != nil || failures != 2 {
		t.Fatalf("retention kept %d finalization markers, %v; want 2", failures, err)
	}

	if _, err := s.System().PruneWithStats(ctx, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).GetScanCycle(ctx, cycle.ID); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("retention did not reclaim the expired cycle and its old marker history: %v", err)
	}
}
