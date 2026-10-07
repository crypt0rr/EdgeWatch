package engine

import (
	"context"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// Finalizing a managed scan records what the comparison did: the samples
// that a job learns its baseline from, the sample that completes it, a
// comparison with an existing baseline, and a scan that did not complete.
// The recorded outcome does not change when the baseline does.
func TestFinalizeManagedScanRecordsComparisonOutcome(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	record, err := defaultTenant(db).CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "comparison-outcome", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
		TCP: &config.Protocol{Ports: "80,443", Mode: "connect"}, Timing: "balanced", Timeout: config.Duration(time.Minute),
		Baseline: config.Baseline{Samples: 2}, Change: config.Change{Confirmations: 1},
	}))
	if err != nil {
		t.Fatal(err)
	}
	e := Engine{Store: db}
	finished := time.Now().UTC().Add(-time.Hour)
	finalize := func(id, status string, snap model.Snapshot) model.Scan {
		t.Helper()
		finished = finished.Add(time.Minute)
		current := scan(id, snap)
		current.Status, current.StartedAt, current.FinishedAt = status, finished, finished
		if status == "failed" {
			current.Error = "scanner stopped"
		}
		current.JobID, current.JobRevision, current.Job = record.ID, record.Revision, record.Job.Name
		current.ConfigHash = record.Job.SecurityHash()
		if _, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &current, nil); err != nil {
			t.Fatalf("finalize %s: %v", id, err)
		}
		stored, err := defaultTenant(db).GetScan(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Comparison != current.Comparison {
			t.Fatalf("stored %s comparison = %q, finalized %q", id, stored.Comparison, current.Comparison)
		}
		return stored
	}
	expect := func(id, comparison, baselineScanID string, changes int) {
		t.Helper()
		stored, err := defaultTenant(db).GetScan(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Comparison != comparison || stored.BaselineScanID != baselineScanID || len(stored.Changes) != changes {
			t.Fatalf("scan %s = comparison %q, baseline %q, %d changes; want %q, %q, %d", id, stored.Comparison, stored.BaselineScanID, len(stored.Changes), comparison, baselineScanID, changes)
		}
	}

	finalize("sample-1", "success", snapshot("open"))
	expect("sample-1", model.ScanComparisonBaselineSample, "", 0)
	finalize("sample-2", "success", snapshot("open"))
	expect("sample-2", model.ScanComparisonBaselineEstablished, "sample-2", 0)
	expect("sample-1", model.ScanComparisonBaselineSample, "", 0)

	opened := snapshot("open")
	opened.Units[0].Ports = append(opened.Units[0].Ports, model.PortState{Port: 80, State: "open"})
	opened.Normalize()
	finalize("compared", "success", opened)
	expect("compared", model.ScanComparisonCompared, "sample-2", 1)
	if stored := finalize("failed", "failed", model.Snapshot{}); stored.Comparison != model.ScanComparisonNotCompared {
		t.Fatalf("failed scan comparison = %q", stored.Comparison)
	}

	if _, err := defaultTenant(db).ResetRuntime(ctx, record.ID, record.Job.Name); err != nil {
		t.Fatal(err)
	}
	incomplete := snapshot("open")
	incomplete.TargetFailures = []model.TargetCoverageFailure{{Target: "192.0.2.1", Reason: "coverage did not complete"}}
	if stored := finalize("incomplete-sample", "success", incomplete); stored.Status != "incomplete" {
		t.Fatalf("incomplete sample status = %q", stored.Status)
	}
	expect("incomplete-sample", model.ScanComparisonBaselineSample, "", 0)
	finalize("relearn-1", "success", opened)
	expect("relearn-1", model.ScanComparisonBaselineSample, "", 0)

	// The reset changed none of the earlier outcomes.
	expect("sample-1", model.ScanComparisonBaselineSample, "", 0)
	expect("sample-2", model.ScanComparisonBaselineEstablished, "sample-2", 0)
	expect("compared", model.ScanComparisonCompared, "sample-2", 1)
}
