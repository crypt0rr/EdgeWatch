package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
)

func TestRuntimeMetadataFallbackAndSummaryBranches(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("runtime-coverage"))
	if err != nil {
		t.Fatal(err)
	}

	// A row written by a pre-metadata installation must still expose the
	// compact marker. A null legacy marker is conservatively treated as
	// modified so accepted overlays are never hidden by the compatibility path.
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM job_runtime_meta WHERE job_id=?`, record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?) ON CONFLICT(job_id) DO UPDATE SET state_json=excluded.state_json,updated_at=excluded.updated_at`, record.ID, []byte(`{"baseline_scan_id":"legacy-scan","baseline_config_hash":"legacy-hash","baseline_modified":null,"baseline":{"units":[]}}`), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	info, err := s.RuntimeBaselineInfo(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if info.BaselineScanID != "legacy-scan" || info.BaselineConfigHash != "legacy-hash" || !info.BaselineModified {
		t.Fatalf("legacy metadata = %#v", info)
	}
	if modified, err := s.RuntimeBaselineModified(ctx, record.ID); err != nil || !modified {
		t.Fatalf("legacy modified marker = %t, %v", modified, err)
	}

	// The summary query handles an absent job without loading a snapshot and
	// counts a JSON baseline when the indexed projection has no rows.
	missing, err := s.RuntimeStateSummary(ctx, "missing-runtime-job")
	if err != nil || missing != (RuntimeStateSummary{}) {
		t.Fatalf("missing runtime summary = %#v, %v", missing, err)
	}
	if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Hosts: []model.HostObservation{{Address: "192.0.2.10"}}}
		state.BaselineScanID = ""
		state.BaselineConfigHash = ""
		state.BaselineModified = false
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	summary, err := s.RuntimeStateSummary(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.HasBaseline || summary.BaselineHostCount != 1 {
		t.Fatalf("runtime summary = %#v", summary)
	}

	// A malformed compatibility row is surfaced to callers rather than being
	// silently interpreted as an empty baseline.
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM job_runtime_meta WHERE job_id=?`, record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_runtime SET state_json=? WHERE job_id=?`, []byte(`{"baseline_scan_id":`), record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RuntimeBaselineInfo(ctx, record.ID); err == nil {
		t.Fatal("malformed legacy runtime state was accepted")
	}
}

func TestRuntimeBaselineEpochAdvancesOnlyForBaselineChanges(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	record, err := s.CreateJob(ctx, testJob("runtime-epoch"))
	if err != nil {
		t.Fatal(err)
	}
	if epoch, err := s.RuntimeBaselineEpoch(ctx, record.ID); err != nil || epoch != 0 {
		t.Fatalf("initial baseline epoch = %d, %v", epoch, err)
	}
	if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Units: []model.Unit{{Target: "192.0.2.20", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}}}}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if epoch, err := s.RuntimeBaselineEpoch(ctx, record.ID); err != nil || epoch != 1 {
		t.Fatalf("changed baseline epoch = %d, %v", epoch, err)
	}
	if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.CandidateCount++
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if epoch, err := s.RuntimeBaselineEpoch(ctx, record.ID); err != nil || epoch != 1 {
		t.Fatalf("candidate-only baseline epoch = %d, %v", epoch, err)
	}
	if _, err := s.ResetRuntime(ctx, record.ID, record.Job.Name); err != nil {
		t.Fatal(err)
	}
	if epoch, err := s.RuntimeBaselineEpoch(ctx, record.ID); err != nil || epoch != 2 {
		t.Fatalf("reset baseline epoch = %d, %v", epoch, err)
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TABLE job_runtime_meta`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RuntimeBaselineEpoch(ctx, record.ID); err == nil {
		t.Fatal("missing runtime metadata table did not return an error")
	}
}

func TestFinalizeManagedScanRejectsStaleCycleAfterSavingHistory(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	record, err := s.CreateJob(ctx, testJob("stale-finalize"))
	if err != nil {
		t.Fatal(err)
	}
	plan := scanner.WorkPlan{Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.30"}, Ports: "1", PortCount: 1, Probes: 1}}}
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision, ConfigHash: record.Job.SecurityHash(), BaselineEpoch: 0, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET status='discarded' WHERE id=?`, cycle.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scan := model.Scan{ID: "stale-finalize-scan", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", CycleID: cycle.ID, CycleStatus: "completed", ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{}}
	if _, err := s.FinalizeManagedScan(ctx, &scan, record.ID, scan.ConfigHash, nil, func(*model.JobState, *model.Scan) ([]model.Event, error) {
		t.Fatal("stale cycle finalizer callback should not run")
		return nil, nil
	}); !errors.Is(err, ErrCycleNotResumable) {
		t.Fatalf("stale cycle finalization error = %v", err)
	}
	stored, err := s.GetScan(ctx, scan.ID)
	if err != nil || stored.Status != "success" {
		t.Fatalf("stale scan history = %#v, %v", stored, err)
	}
}

func TestFinalizeManagedScanValidationAndRollback(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("finalize-validation"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scan := model.Scan{ID: "validation-scan", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{}}

	for name, call := range map[string]func() error{
		"nil scan": func() error {
			_, err := s.FinalizeManagedScan(ctx, nil, record.ID, scan.ConfigHash, nil, func(*model.JobState, *model.Scan) ([]model.Event, error) { return nil, nil })
			return err
		},
		"missing job id": func() error {
			_, err := s.FinalizeManagedScan(ctx, &scan, "", scan.ConfigHash, nil, func(*model.JobState, *model.Scan) ([]model.Event, error) { return nil, nil })
			return err
		},
		"nil finalizer": func() error {
			_, err := s.FinalizeManagedScan(ctx, &scan, record.ID, scan.ConfigHash, nil, nil)
			return err
		},
		"missing job": func() error {
			_, err := s.FinalizeManagedScan(ctx, &scan, "missing", scan.ConfigHash, nil, func(*model.JobState, *model.Scan) ([]model.Event, error) { return nil, nil })
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("validation unexpectedly succeeded")
			}
		})
	}

	callbackErr := errors.New("finalizer rejected snapshot")
	if _, err := s.FinalizeManagedScan(ctx, &scan, record.ID, scan.ConfigHash, nil, func(*model.JobState, *model.Scan) ([]model.Event, error) {
		return nil, callbackErr
	}); !errors.Is(err, callbackErr) {
		t.Fatalf("callback error = %v", err)
	}
	if _, err := s.GetScan(ctx, scan.ID); err == nil {
		t.Fatal("scan persisted after callback failure")
	}

	// A successful finalization persists events and an outbox row atomically.
	if _, err := s.FinalizeManagedScan(ctx, &scan, record.ID, scan.ConfigHash, []string{"file:coverage-destination"}, func(state *model.JobState, current *model.Scan) ([]model.Event, error) {
		state.CandidateCount = 1
		return []model.Event{{Type: "coverage-finalized", ScanID: current.ID, CreatedAt: now}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetScan(ctx, scan.ID); err != nil {
		t.Fatal(err)
	}
	var outbox int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination=?`, "file:coverage-destination").Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if outbox != 1 {
		t.Fatalf("outbox rows = %d, want 1", outbox)
	}
	if history, err := s.ListJobEvents(ctx, record.ID, 10); err != nil || len(history) != 1 || history[0].Type != "coverage-finalized" {
		t.Fatalf("finalization events = %#v, %v", history, err)
	}

	// An invalid security hash retains the scan as immutable history but does
	// not call the finalizer or mutate runtime state.
	stale := scan
	stale.ID = fmt.Sprintf("%s-stale", scan.ID)
	stale.ConfigHash = "old-scope"
	called := false
	if _, err := s.FinalizeManagedScan(ctx, &stale, record.ID, stale.ConfigHash, nil, func(*model.JobState, *model.Scan) ([]model.Event, error) {
		called = true
		return nil, nil
	}); !errors.Is(err, ErrJobRevisionChanged) {
		t.Fatalf("stale finalization error = %v", err)
	}
	if called {
		t.Fatal("stale finalizer callback was invoked")
	}
	if _, err := s.GetScan(ctx, stale.ID); err != nil {
		t.Fatalf("stale scan was not retained: %v", err)
	}
}
