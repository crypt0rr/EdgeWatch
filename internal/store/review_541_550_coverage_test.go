package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestRecoverableCycleSelectionAndDeadlineGuards(t *testing.T) {
	t.Parallel()
	ctx, s, job, plan := cycleFixture(t)
	defer s.Close()

	cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if recovered, err := defaultTenant(s).GetRecoverableScanCycle(ctx, job.ID); err != nil || recovered.ID != cycle.ID {
		t.Fatalf("active recoverable cycle = %#v, %v", recovered, err)
	}
	unit, err := s.System().NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := s.System().CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, model.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().CompleteScanCycle(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if recovered, err := defaultTenant(s).GetRecoverableScanCycle(ctx, job.ID); err != nil || recovered.ID != cycle.ID {
		t.Fatalf("unpromoted completed cycle = %#v, %v", recovered, err)
	}

	now := time.Now().UTC()
	if err := s.System().SaveScan(ctx, model.Scan{ID: "recovery-promoted", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", CycleID: cycle.ID, CycleStatus: "completed", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).GetRecoverableScanCycle(ctx, job.ID); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("promoted cycle remained recoverable: %v", err)
	}

	deadline, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().StartScanCycleAttempt(ctx, deadline.ID); err != nil {
		t.Fatal(err)
	}
	unit, err = s.System().NextScanCycleUnit(ctx, deadline.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET expires_at=? WHERE id=?`, now.Add(-time.Minute).Format(time.RFC3339Nano), deadline.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().ClaimScanCycleUnit(ctx, deadline.ID, unit.Sequence); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("expired claim error = %v", err)
	}
	if expired, err := defaultTenant(s).GetScanCycle(ctx, deadline.ID); err != nil || expired.Status != "expired" {
		t.Fatalf("expired cycle = %#v, %v", expired, err)
	}
}

func TestDiscardCompletedCycleRequiresUnpromotedState(t *testing.T) {
	t.Parallel()
	ctx, s, job, plan := cycleFixture(t)
	defer s.Close()
	// Exercise deployments where WAL is unavailable: reads then share the
	// single writer pool, so a store query from inside the discard transaction
	// would wait for the connection held by that transaction.
	readDB := s.ReadDB
	s.ReadDB = nil
	if readDB != nil {
		defer readDB.Close()
	}
	// Bound each discard separately so the deadline measures only the discard
	// transaction. A shared deadline created before the setup below could expire
	// during the cycle and scan writes on a slow runner, turning the regression
	// check into a spurious "context deadline exceeded".
	discard := func(id string) error {
		t.Helper()
		discardCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		defer cancel()
		return defaultTenant(s).DiscardScanCycle(discardCtx, id)
	}
	complete := func(id string) ScanCycleRecord {
		t.Helper()
		cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{ID: id, JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.System().StartScanCycleAttempt(ctx, cycle.ID); err != nil {
			t.Fatal(err)
		}
		unit, err := s.System().NextScanCycleUnit(ctx, cycle.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.System().ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
			t.Fatal(err)
		}
		if err := s.System().CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, model.Snapshot{}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.System().CompleteScanCycle(ctx, cycle.ID); err != nil {
			t.Fatal(err)
		}
		return cycle
	}
	unpromoted := complete("discard-unpromoted")
	if err := discard(unpromoted.ID); err != nil {
		t.Fatalf("discard unpromoted completed cycle = %v", err)
	}
	promoted := complete("discard-promoted")
	now := time.Now().UTC()
	if err := s.System().SaveScan(ctx, model.Scan{ID: "discard-promoted-scan", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", CycleID: promoted.ID, CycleStatus: "completed", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{}}); err != nil {
		t.Fatal(err)
	}
	if err := discard(promoted.ID); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("discard promoted completed cycle = %v", err)
	}
}

func TestDiscardCompletedCycleReturnsScanLookupError(t *testing.T) {
	t.Parallel()
	ctx, s, job, plan := cycleFixture(t)
	defer s.Close()
	readDB := s.ReadDB
	s.ReadDB = nil
	if readDB != nil {
		defer readDB.Close()
	}

	cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{ID: "discard-scan-lookup-error", JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	unit, err := s.System().NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := s.System().CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, model.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().CompleteScanCycle(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `ALTER TABLE scans RENAME TO scans_unavailable_for_discard_test`); err != nil {
		t.Fatal(err)
	}
	discardCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	if err := defaultTenant(s).DiscardScanCycle(discardCtx, cycle.ID); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("discard with failed scan lookup = %v, want database lookup error", err)
	}
}

func TestIndeterminateDeliveryTerminalDeferralsAreDurable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	if err := s.System().QueueEvent(ctx, "indeterminate-terminal", model.Event{Type: "indeterminate", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < deliveryMaxDeferrals; i++ {
		if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE destination=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), "indeterminate-terminal"); err != nil {
			t.Fatal(err)
		}
		due, err := s.System().ClaimDueDeliveries(ctx, 1, "indeterminate-terminal-owner")
		if err != nil || len(due) != 1 {
			t.Fatalf("deferral %d claim = %#v, %v", i, due, err)
		}
		if err := s.System().DeliveryResultClaim(ctx, due[0].ID, due[0].ClaimToken, ErrDeliveryIndeterminate); err != nil {
			t.Fatal(err)
		}
	}
	var attempts, deferrals int
	var terminalAt string
	if err := s.DB.QueryRowContext(ctx, `SELECT attempts,deferrals,terminal_at FROM outbox WHERE destination=?`, "indeterminate-terminal").Scan(&attempts, &deferrals, &terminalAt); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || deferrals != deliveryMaxDeferrals || terminalAt == "" {
		t.Fatalf("terminal indeterminate budgets = attempts %d deferrals %d terminal_at %q", attempts, deferrals, terminalAt)
	}
	if due, err := s.System().ClaimDueDeliveries(ctx, 1, "after-indeterminate-terminal"); err != nil || len(due) != 0 {
		t.Fatalf("terminal indeterminate delivery remained claimable: %#v, %v", due, err)
	}
}

// A claim that finds the resume window closed expires the cycle, although
// the claiming scan holds its job's lease, which keeps ExpireScanCycles
// from expiring it. The cycle is not left running for the next trigger or
// the daily housekeeping to expire and report again.
func TestClaimPastTheDeadlineExpiresTheCycleOfTheLeaseHolder(t *testing.T) {
	t.Parallel()
	ctx, s, job, plan := cycleFixture(t)
	cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.System().AcquireJobLease(ctx, job.ID, "daemon/claim/scan", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	unit, err := s.System().NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET expires_at=? WHERE id=?`, sqliteTimestamp(time.Now().Add(-time.Minute)), cycle.ID); err != nil {
		t.Fatal(err)
	}
	if expired, err := s.System().ExpireScanCycles(ctx, time.Now()); err != nil || expired != 0 {
		t.Fatalf("housekeeping expired %d cycles, %v; want the leased cycle left to its scan", expired, err)
	}
	if _, err := s.System().ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("claim past the deadline = %v, want %v", err, ErrCycleNotResumable)
	}
	if expired, err := defaultTenant(s).GetScanCycle(ctx, cycle.ID); err != nil || expired.Status != "expired" {
		t.Fatalf("cycle status after the refused claim = %q, %v; want expired", expired.Status, err)
	}
}
