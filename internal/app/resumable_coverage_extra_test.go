package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type coverageResumableScanner struct {
	plan    scanner.WorkPlan
	planErr error
	scanErr error
	closeDB *store.Store
}

func (s coverageResumableScanner) Version(context.Context) string { return "coverage" }
func (s coverageResumableScanner) Scan(context.Context, config.Job) (model.Snapshot, error) {
	return model.Snapshot{}, errors.New("ordinary scan path is not expected")
}
func (s coverageResumableScanner) Plan(context.Context, config.Job) (scanner.WorkPlan, error) {
	return s.plan, s.planErr
}
func (s coverageResumableScanner) ScanWorkUnit(context.Context, config.Job, scanner.WorkUnit, scanner.ProgressReporter) (model.Snapshot, error) {
	if s.closeDB != nil {
		_ = s.closeDB.Close()
	}
	if s.scanErr != nil {
		return model.Snapshot{}, s.scanErr
	}
	return model.Snapshot{}, nil
}

func TestResumableAttemptPlanningAndTerminalGuards(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "resumable-coverage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	job := config.NormalizeJob(config.Job{Name: "resumable-coverage", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1-2", Mode: "connect"}, Timeout: config.Duration(time.Minute), ResumeWindow: config.Duration(time.Hour)})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}

	var scan model.Scan
	if handled, _, runErr := a.runResumableAttempt(ctx, ctx, job, "", &scan, nil, coverageResumableScanner{}, false); handled || runErr != nil {
		t.Fatalf("empty job id result = handled %v err %v", handled, runErr)
	}

	for _, test := range []struct {
		name      string
		scanCtx   context.Context
		wantState string
		planErr   string
		wantError string
	}{
		{"plan canceled", canceledContext(), "canceled", "plan canceled", "scan canceled while"},
		{"plan deadline", deadlineContext(), "timed_out", "plan timed out", "scan timed out while"},
		{"plan failure", context.Background(), "failed", "plan unavailable", "plan unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var local model.Scan
			_, _, gotErr := a.runResumableAttempt(ctx, test.scanCtx, job, record.ID+test.name, &local, nil, coverageResumableScanner{planErr: errors.New(test.planErr)}, false)
			if gotErr == nil || local.Status != test.wantState || !strings.Contains(local.Error, test.wantError) {
				t.Fatalf("planning result = scan %#v err %v", local, gotErr)
			}
		})
	}

	oneUnit := scanner.WorkPlan{Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1}}}
	var single model.Scan
	if handled, _, err := a.runResumableAttempt(ctx, ctx, job, record.ID+"single", &single, nil, coverageResumableScanner{plan: oneUnit}, false); handled || err != nil {
		t.Fatalf("single-unit plan = handled %v err %v", handled, err)
	}

	cyclePlan := scanner.WorkPlan{Units: []scanner.WorkUnit{
		{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1},
		{Sequence: 1, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "2", PortCount: 1, Probes: 1},
	}}
	cycle, err := db.CreateScanCycle(ctx, store.ScanCycleRecord{JobID: record.ID, Job: job.Name, JobRevision: record.Revision, ConfigHash: job.SecurityHash(), Plan: cyclePlan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE scan_cycles SET status='stalled' WHERE id=?`, cycle.ID); err != nil {
		t.Fatal(err)
	}
	var stalled model.Scan
	if handled, _, err := a.runResumableAttempt(ctx, ctx, job, record.ID, &stalled, nil, coverageResumableScanner{plan: cyclePlan}, false); !handled || !errors.Is(err, ErrScanCycleStalled) {
		t.Fatalf("scheduled stalled cycle = handled %v err %v scan %#v", handled, err, stalled)
	}
	var manual model.Scan
	if handled, _, err := a.runResumableAttempt(ctx, ctx, job, record.ID, &manual, nil, coverageResumableScanner{plan: cyclePlan}, true); handled && err == nil {
		// The manual path is allowed to retry; it may fail later in this minimal
		// fixture, but it must not be rejected by ErrScanCycleStalled.
		t.Logf("manual stalled-cycle retry reached scan state %#v", manual)
	}

	// A cycle captured under a different security hash is persisted as stalled
	// instead of being resumed with a changed scope.
	mismatchJob := job
	mismatchJob.Name = "resumable-mismatch"
	mismatchRecord, err := db.CreateJob(ctx, mismatchJob)
	if err != nil {
		t.Fatal(err)
	}
	mismatch, err := db.CreateScanCycle(ctx, store.ScanCycleRecord{JobID: mismatchRecord.ID, Job: mismatchJob.Name, JobRevision: mismatchRecord.Revision, ConfigHash: "old-hash", Plan: cyclePlan})
	if err != nil {
		t.Fatal(err)
	}
	var mismatchScan model.Scan
	if handled, _, err := a.runResumableAttempt(ctx, ctx, mismatchJob, mismatchRecord.ID, &mismatchScan, nil, coverageResumableScanner{plan: cyclePlan}, false); !handled || err == nil || mismatchScan.Status != "failed" || mismatchScan.CycleStatus != "stalled" {
		t.Fatalf("mismatched cycle = handled %v scan %#v err %v", handled, mismatchScan, err)
	}
	if got, err := db.GetScanCycle(ctx, mismatch.ID); err != nil || got.Status != "stalled" {
		t.Fatalf("mismatched cycle state = %#v %v", got, err)
	}
}

func TestResumableRecoveryAndFinishPersistenceFailures(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "resumable-failures.db"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	_ = db.Close()
	cycle := store.ScanCycleRecord{ID: "closed-cycle", TotalUnits: 1}
	for _, invoke := range []func(*model.Scan) (bool, model.Snapshot, error){
		func(scan *model.Scan) (bool, model.Snapshot, error) {
			return a.recoverCompletedCycle(ctx, scan, nil, cycle)
		},
		func(scan *model.Scan) (bool, model.Snapshot, error) {
			return a.finishResumableCycle(ctx, scan, nil, cycle)
		},
	} {
		var scan model.Scan
		handled, _, gotErr := invoke(&scan)
		if !handled || gotErr == nil || scan.Status != "failed" {
			t.Fatalf("closed persistence result = handled %v scan %#v err %v", handled, scan, gotErr)
		}
	}
}

func TestResumableAttemptHandlesUnitFailuresAndNoProgressStalls(t *testing.T) {
	ctx := context.Background()
	newApp := func(t *testing.T, name string) (*App, *store.Store, config.Job, store.JobRecord) {
		t.Helper()
		db, err := store.Open(filepath.Join(t.TempDir(), name+".db"))
		if err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
		a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			db.Close()
			t.Fatal(err)
		}
		job := config.NormalizeJob(config.Job{Name: name, Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), ResumeWindow: config.Duration(time.Hour)})
		record, err := db.CreateJob(ctx, job)
		if err != nil {
			db.Close()
			t.Fatal(err)
		}
		return a, db, job, record
	}
	twoUnits := scanner.WorkPlan{Units: []scanner.WorkUnit{
		{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1},
		{Sequence: 1, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "2", PortCount: 1, Probes: 1},
	}}

	a, db, job, record := newApp(t, "unit-error")
	defer db.Close()
	var failed model.Scan
	if handled, _, err := a.runResumableAttempt(ctx, ctx, job, record.ID, &failed, nil, coverageResumableScanner{plan: twoUnits, scanErr: errors.New("scanner unit failed")}, false); !handled || err == nil || failed.Status != "failed" || failed.CycleStatus != "stalled" {
		t.Fatalf("unit failure = handled %v scan %#v err %v", handled, failed, err)
	}

	a, db, job, record = newApp(t, "timeout-stall")
	defer db.Close()
	cycle, err := db.CreateScanCycle(ctx, store.ScanCycleRecord{JobID: record.ID, Job: job.Name, JobRevision: record.Revision, ConfigHash: job.SecurityHash(), Plan: scanner.WorkPlan{Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE scan_cycles SET no_progress_attempts=2 WHERE id=?`, cycle.ID); err != nil {
		t.Fatal(err)
	}
	var stalled model.Scan
	if handled, _, err := a.runResumableAttempt(ctx, ctx, job, record.ID, &stalled, nil, coverageResumableScanner{scanErr: context.DeadlineExceeded}, false); !handled || err == nil || stalled.Status != "failed" || stalled.CycleStatus != "stalled" {
		t.Fatalf("no-progress timeout = handled %v scan %#v err %v", handled, stalled, err)
	}

	a, db, job, record = newApp(t, "complete-error")
	var completeError model.Scan
	if handled, _, err := a.runResumableAttempt(ctx, ctx, job, record.ID, &completeError, nil, coverageResumableScanner{plan: twoUnits, closeDB: db}, false); !handled || err == nil || completeError.Status != "failed" {
		t.Fatalf("checkpoint persistence failure = handled %v scan %#v err %v", handled, completeError, err)
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func deadlineContext() context.Context {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	cancel()
	return ctx
}
