package store

import (
	"testing"
)

func TestScanCycleFailureBudgetIgnoresClaimsAndResetsSplitChildren(t *testing.T) {
	ctx, s, job, plan := cycleFixture(t)
	defer s.Close()

	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{
		JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision,
		ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan,
	})
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
	claimed, err := s.ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Attempts != 1 || claimed.Failures != 0 {
		t.Fatalf("first claim = attempts %d failures %d, want 1/0", claimed.Attempts, claimed.Failures)
	}

	// A restart reclaims an in-flight unit, but no scanner execution failed.
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	unit, err = s.NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = s.ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Attempts != 2 || claimed.Failures != 0 {
		t.Fatalf("reclaimed unit = attempts %d failures %d, want 2/0", claimed.Attempts, claimed.Failures)
	}

	if err := s.RetryScanCycleUnitAfterFailure(ctx, cycle.ID, claimed.Sequence, "transient scanner failure"); err != nil {
		t.Fatal(err)
	}
	claimed, err = s.ClaimScanCycleUnit(ctx, cycle.ID, claimed.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Attempts != 3 || claimed.Failures != 1 {
		t.Fatalf("failed execution = attempts %d failures %d, want 3/1", claimed.Attempts, claimed.Failures)
	}

	// Timeout/cancellation returns the unit to pending without recording a
	// failed execution, so a later claim retains the one real failure.
	if err := s.RetryScanCycleUnit(ctx, cycle.ID, claimed.Sequence, "scan timed out"); err != nil {
		t.Fatal(err)
	}
	claimed, err = s.ClaimScanCycleUnit(ctx, cycle.ID, claimed.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Attempts != 4 || claimed.Failures != 1 {
		t.Fatalf("timeout recovery = attempts %d failures %d, want 4/1", claimed.Attempts, claimed.Failures)
	}

	first := plan.Units[0]
	first.Sequence = 0
	second := first
	second.Sequence = 1
	second.Ports = "2"
	second.PortCount = 1
	if err := s.SplitScanCycleUnit(ctx, cycle.ID, claimed.Sequence, first, second, "split after timeout"); err != nil {
		t.Fatal(err)
	}
	summaries, err := s.ListScanCycleUnitSummaries(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 2 {
		t.Fatalf("split summaries = %d, want 2", len(summaries))
	}
	for _, summary := range summaries {
		if summary.Failures != 0 {
			t.Fatalf("split child sequence %d inherited %d failures", summary.Sequence, summary.Failures)
		}
	}
}

func TestScanCycleFailureColumnExistsAfterSchemaMigration(t *testing.T) {
	ctx, s, _, _ := cycleFixture(t)
	defer s.Close()

	var columns int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('scan_cycle_units') WHERE name='failures'`).Scan(&columns); err != nil {
		t.Fatalf("scan cycle failure column unavailable: %v", err)
	}
	if columns != 1 {
		t.Fatalf("scan cycle failure column count = %d, want 1", columns)
	}
}
