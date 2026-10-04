package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func managedFinalizationScan(record JobRecord, id string) model.Scan {
	now := time.Now().UTC()
	return model.Scan{
		ID: id, JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name,
		StartedAt: now, FinishedAt: now, Status: "success",
		ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{},
	}
}

func TestFinalizeManagedScanWithOptionsUsesDefaultBudgetsAndMissingLeaseFallback(t *testing.T) {
	ctx := t.Context()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("managed-options-defaults"))
	if err != nil {
		t.Fatal(err)
	}
	scan := managedFinalizationScan(record, "managed-options-defaults-scan")

	// An owner without a lease exercises the safe job-row write-lock fallback.
	// A missing writer-wait budget defaults independently while the explicit
	// work budget keeps the test bounded.
	_, err = s.System().FinalizeManagedScanWithOptions(ctx, &scan, record.ID, scan.ConfigHash, nil, ManagedScanFinalizationOptions{
		WorkTimeout: time.Second,
		LeaseOwner:  "lease-not-created",
	}, func(*model.JobState, *model.Scan, IncidentReminderSettings) ([]model.Event, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("finalize with default writer wait and missing lease: %v", err)
	}
	if _, err := defaultTenant(s).GetScan(ctx, scan.ID); err != nil {
		t.Fatalf("scan was not committed: %v", err)
	}

	// The inverse setting defaults the transaction-work budget while retaining
	// an explicit writer-wait bound and exercises the ordinary job-row lock.
	scan = managedFinalizationScan(record, "managed-options-default-work")
	_, err = s.System().FinalizeManagedScanWithOptions(ctx, &scan, record.ID, scan.ConfigHash, nil, ManagedScanFinalizationOptions{
		WriterWaitTimeout: time.Second,
	}, func(*model.JobState, *model.Scan, IncidentReminderSettings) ([]model.Event, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("finalize with default transaction-work budget: %v", err)
	}
}

func TestFinalizeManagedScanWithOptionsRetriesExternalSQLiteWriterAndReleasesLease(t *testing.T) {
	ctx := t.Context()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("managed-options-retry"))
	if err != nil {
		t.Fatal(err)
	}
	const owner = "managed-options-owner"
	if err := s.System().AcquireJobLeaseForRevision(ctx, record.ID, owner, record.Revision, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	blocker, err := OpenExistingContext(ctx, s.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blocker.Close() })
	blockerTx, err := blocker.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blockerTx.ExecContext(ctx, `UPDATE jobs SET revision=revision WHERE id=?`, record.ID); err != nil {
		_ = blockerTx.Rollback()
		t.Fatal(err)
	}

	const holdFor = 5500 * time.Millisecond
	unlockDone := make(chan error, 1)
	go func() {
		timer := time.NewTimer(holdFor)
		defer timer.Stop()
		<-timer.C
		unlockDone <- blockerTx.Commit()
	}()
	scan := managedFinalizationScan(record, "managed-options-retry-scan")
	_, err = s.System().FinalizeManagedScanWithOptions(ctx, &scan, record.ID, scan.ConfigHash, nil, ManagedScanFinalizationOptions{
		WriterWaitTimeout: 8 * time.Second,
		WorkTimeout:       time.Second,
		LeaseOwner:        owner,
		LeaseUntil:        time.Now().UTC().Add(10 * time.Minute),
	}, func(*model.JobState, *model.Scan, IncidentReminderSettings) ([]model.Event, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("finalize after SQLite writer becomes available: %v", err)
	}
	if err := <-unlockDone; err != nil {
		t.Fatalf("release blocking transaction: %v", err)
	}
	if active, err := defaultTenant(s).JobActive(ctx, record.ID); err != nil || active {
		t.Fatalf("managed lease after finalization: active=%t err=%v", active, err)
	}
	if stored, err := defaultTenant(s).GetScan(ctx, scan.ID); err != nil || stored.Status != "success" {
		t.Fatalf("scan after writer retry: %#v err=%v", stored, err)
	}
}

func TestFinalizeManagedScanWithOptionsEnforcesWorkBudgetAfterWriterGrant(t *testing.T) {
	ctx := t.Context()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("managed-options-work-budget"))
	if err != nil {
		t.Fatal(err)
	}
	scan := managedFinalizationScan(record, "managed-options-work-budget-scan")
	_, err = s.System().FinalizeManagedScanWithOptions(ctx, &scan, record.ID, scan.ConfigHash, nil, ManagedScanFinalizationOptions{
		WriterWaitTimeout: time.Second,
		WorkTimeout:       20 * time.Millisecond,
	}, func(*model.JobState, *model.Scan, IncidentReminderSettings) ([]model.Event, error) {
		time.Sleep(40 * time.Millisecond)
		return nil, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("finalizer error = %v, want the bounded work context to expire", err)
	}
	if _, err := defaultTenant(s).GetScan(ctx, scan.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("scan persisted after finalizer failure: %v", err)
	}
}

func TestFinalizeManagedScanWithOptionsReturnsWriterWaitAndWorkErrors(t *testing.T) {
	ctx := t.Context()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("managed-options-errors"))
	if err != nil {
		t.Fatal(err)
	}

	called := false
	missing := managedFinalizationScan(record, "managed-options-missing-job")
	_, err = s.System().FinalizeManagedScanWithOptions(ctx, &missing, "missing-job", missing.ConfigHash, nil, ManagedScanFinalizationOptions{
		WriterWaitTimeout: time.Second,
		WorkTimeout:       time.Second,
	}, func(*model.JobState, *model.Scan, IncidentReminderSettings) ([]model.Event, error) {
		called = true
		return nil, nil
	})
	if !errors.Is(err, ErrNotFound) || called {
		t.Fatalf("missing-job finalization = err %v, callback called %t", err, called)
	}

	// Validation is handled before accessing the database.
	if _, err := s.System().FinalizeManagedScanWithOptions(ctx, nil, record.ID, "", nil, ManagedScanFinalizationOptions{}, func(*model.JobState, *model.Scan, IncidentReminderSettings) ([]model.Event, error) { return nil, nil }); err == nil {
		t.Fatal("nil scan was accepted")
	}
	if _, err := s.System().FinalizeManagedScanWithOptions(ctx, &missing, "", "", nil, ManagedScanFinalizationOptions{}, func(*model.JobState, *model.Scan, IncidentReminderSettings) ([]model.Event, error) { return nil, nil }); err == nil {
		t.Fatal("empty job ID was accepted")
	}
	if _, err := s.System().FinalizeManagedScanWithOptions(ctx, &missing, record.ID, "", nil, ManagedScanFinalizationOptions{}, nil); err == nil {
		t.Fatal("nil finalizer was accepted")
	}

	// A closed database makes connection acquisition fail before a transaction
	// can start, and must be returned without running the callback.
	scan := managedFinalizationScan(record, "managed-options-closed-db")
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	called = false
	_, err = s.System().FinalizeManagedScanWithOptions(ctx, &scan, record.ID, scan.ConfigHash, nil, ManagedScanFinalizationOptions{
		WriterWaitTimeout: time.Second,
		WorkTimeout:       time.Second,
	}, func(*model.JobState, *model.Scan, IncidentReminderSettings) ([]model.Event, error) {
		called = true
		return nil, nil
	})
	if err == nil || called {
		t.Fatalf("closed database finalization = err %v, callback called %t", err, called)
	}
}

func TestManagedFinalizationRetryHelpers(t *testing.T) {
	if isSQLiteWriterBusy(errors.New("not a SQLite error")) {
		t.Fatal("ordinary error was treated as SQLite writer contention")
	}
	if got := nextWriterRetryDelay(125 * time.Millisecond); got != 250*time.Millisecond {
		t.Fatalf("retry delay cap = %s, want 250ms", got)
	}
	if got := nextWriterRetryDelay(250 * time.Millisecond); got != 250*time.Millisecond {
		t.Fatalf("retry delay remains capped = %s, want 250ms", got)
	}
	if got := nextWriterRetryDelay(25 * time.Millisecond); got != 50*time.Millisecond {
		t.Fatalf("retry delay growth = %s, want 50ms", got)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := waitForWriterRetry(canceled, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("retry interrupted by cancellation = %v", err)
	}
	if err := waitForWriterRetry(t.Context(), 0); err != nil {
		t.Fatalf("zero-delay retry = %v", err)
	}

	s := openTestStore(t)
	_, err := s.DB.ExecContext(t.Context(), "THIS IS NOT SQL")
	if err == nil || isSQLiteWriterBusy(err) {
		t.Fatalf("non-contention SQLite error classification = %v", err)
	}
}
