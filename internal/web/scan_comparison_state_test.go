package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/engine"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// scanComparisonResponse is the part of the scan detail and scan changes
// responses that describes the comparison.
type scanComparisonResponse struct {
	State          string         `json:"comparison_state"`
	Source         string         `json:"comparison_source"`
	BaselineScanID string         `json:"baseline_scan_id"`
	Changes        []model.Change `json:"changes"`
}

// A job that learns its baseline from two samples reports each scan's
// comparison as it was when the scan finished (#1224). The first sample is a
// baseline sample, not a failed scan, and stays one after the baseline is
// established, an incident is accepted, and the baseline is reset; the
// second sample established the baseline; a later scan was compared at scan
// time; and a failed scan was not compared. Only a scan recorded before the
// outcome was stored is still compared with the current baseline. The scan
// detail and its changes report the same comparison.
func TestJobScanComparisonStateIsRecordedAtScanTime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	ts := defaultTenantStore(server)
	job := config.NormalizeJob(config.Job{
		Name: "comparison-state", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "80,443", Mode: "connect"},
		Timing: "balanced", Timeout: config.Duration(time.Minute),
		Baseline: config.Baseline{Samples: 2}, Change: config.Change{Confirmations: 1},
	})
	record, err := defaultTenant(db).CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	snapshotWith := func(ports ...int) model.Snapshot {
		unit := model.Unit{Target: "192.0.2.10", Protocol: "tcp", Addresses: []string{"192.0.2.10"}}
		for _, port := range ports {
			unit.Ports = append(unit.Ports, model.PortState{Port: port, State: "open", Evidence: []string{"192.0.2.10"}})
		}
		snapshot := model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.10", Protocol: "tcp", Ports: "80,443"}}, Units: []model.Unit{unit}}
		snapshot.Normalize()
		return snapshot
	}
	finished := time.Now().UTC().Add(-time.Hour)
	newScan := func(id, status string, snapshot model.Snapshot) model.Scan {
		finished = finished.Add(time.Minute)
		scan := model.Scan{ID: id, JobID: record.ID, JobRevision: record.Revision, Job: job.Name, StartedAt: finished, FinishedAt: finished, Status: status, ConfigHash: record.Job.SecurityHash(), Snapshot: snapshot}
		if status == "failed" {
			scan.Error = "scanner stopped"
		}
		return scan
	}
	finalizer := &engine.Engine{Store: db}
	finalize := func(id, status string, snapshot model.Snapshot) []model.Event {
		t.Helper()
		scan := newScan(id, status, snapshot)
		events, err := finalizer.FinalizeManagedScan(ctx, record.ID, record.Job, &scan, nil)
		if err != nil {
			t.Fatalf("finalize %s: %v", id, err)
		}
		return events
	}
	get := func(path string) scanComparisonResponse {
		t.Helper()
		response := httptest.NewRecorder()
		server.jobRoute(response, scanHandlerRequest(http.MethodGet, "/scan?limit=50", ""), admin, ts, record.ID+"/scans/"+path)
		if response.Code != http.StatusOK {
			t.Fatalf("%s = %d: %s", path, response.Code, response.Body.String())
		}
		var decoded scanComparisonResponse
		if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	expect := func(when, id, state, source, baselineScanID string, changes int) {
		t.Helper()
		for _, path := range []string{id, id + "/changes"} {
			got := get(path)
			if got.State != state || got.Source != source || got.BaselineScanID != baselineScanID || len(got.Changes) != changes {
				t.Fatalf("%s: %s = state %q, source %q, baseline %q, %d changes %v; want %q, %q, %q, %d", when, path, got.State, got.Source, got.BaselineScanID, len(got.Changes), got.Changes, state, source, baselineScanID, changes)
			}
		}
	}

	finalize("sample-1", "success", snapshotWith(80))
	expect("while learning", "sample-1", model.ScanComparisonBaselineSample, "none", "", 0)

	if events := finalize("sample-2", "success", snapshotWith(80)); len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("completing sample events = %#v", events)
	}
	expect("after the baseline is established", "sample-2", model.ScanComparisonBaselineEstablished, "none", "sample-2", 0)
	expect("after the baseline is established", "sample-1", model.ScanComparisonBaselineSample, "none", "", 0)

	finalize("opened", "success", snapshotWith(80, 443))
	expect("after a change", "opened", model.ScanComparisonCompared, "scan_time", "sample-2", 1)
	key := get("opened").Changes[0].Key
	if _, err := defaultTenant(db).AcceptIncidentWithAudit(ctx, record.ID, job.Name, key, store.AuditEntry{}); err != nil {
		t.Fatalf("accept %s: %v", key, err)
	}
	expect("after accepting the incident", "sample-1", model.ScanComparisonBaselineSample, "none", "", 0)
	expect("after accepting the incident", "opened", model.ScanComparisonCompared, "scan_time", "sample-2", 1)

	// A row recorded before the outcome was stored, with no scan-time
	// comparison, is still compared with the current baseline.
	legacy := newScan("legacy", "success", snapshotWith(80))
	if err := db.System().SaveScan(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	expect("for a legacy row", "legacy", model.ScanComparisonCompared, "current_baseline_legacy", "", 1)

	finalize("failed", "failed", model.Snapshot{})
	expect("for a failed scan", "failed", model.ScanComparisonNotCompared, "none", "", 0)

	if _, err := defaultTenant(db).ResetRuntime(ctx, record.ID, job.Name); err != nil {
		t.Fatal(err)
	}
	expect("after a baseline reset", "sample-1", model.ScanComparisonBaselineSample, "none", "", 0)
	expect("after a baseline reset", "sample-2", model.ScanComparisonBaselineEstablished, "none", "sample-2", 0)
	expect("after a baseline reset", "opened", model.ScanComparisonCompared, "scan_time", "sample-2", 1)
	expect("for a legacy row without a baseline", "legacy", model.ScanComparisonNotCompared, "none", "", 0)
	finalize("relearn-1", "success", snapshotWith(80, 443))
	expect("while relearning", "relearn-1", model.ScanComparisonBaselineSample, "none", "", 0)
}

// The recorded outcome decides the reported comparison of a successful or
// incomplete scan. A scan that did not complete is never compared, and a
// value this release does not know is reported as not compared instead of
// falling back to the current baseline.
func TestResolveScanComparison(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		summary model.ScanSummary
		want    scanComparisonView
	}{
		{name: "compared", summary: model.ScanSummary{Status: "success", Comparison: model.ScanComparisonCompared}, want: scanComparisonView{state: "compared", source: "scan_time", scanTime: true}},
		{name: "incomplete compared", summary: model.ScanSummary{Status: "incomplete", Comparison: model.ScanComparisonCompared, BaselineScanID: "baseline"}, want: scanComparisonView{state: "compared", source: "scan_time", scanTime: true}},
		{name: "baseline sample", summary: model.ScanSummary{Status: "success", Comparison: model.ScanComparisonBaselineSample}, want: scanComparisonView{state: "baseline_sample", source: "none"}},
		{name: "incomplete baseline sample", summary: model.ScanSummary{Status: "incomplete", Comparison: model.ScanComparisonBaselineSample}, want: scanComparisonView{state: "baseline_sample", source: "none"}},
		{name: "baseline established", summary: model.ScanSummary{Status: "success", Comparison: model.ScanComparisonBaselineEstablished, BaselineScanID: "scan"}, want: scanComparisonView{state: "baseline_established", source: "none"}},
		{name: "kept without a comparison", summary: model.ScanSummary{Status: "success", Comparison: model.ScanComparisonNotCompared}, want: scanComparisonView{state: "not_compared", source: "none"}},
		{name: "failed", summary: model.ScanSummary{Status: "failed", Comparison: model.ScanComparisonCompared, BaselineScanID: "baseline"}, want: scanComparisonView{state: "not_compared", source: "none"}},
		{name: "legacy canceled", summary: model.ScanSummary{Status: "canceled"}, want: scanComparisonView{state: "not_compared", source: "none"}},
		{name: "legacy with a scan-time comparison", summary: model.ScanSummary{Status: "success", BaselineConfigHash: "hash"}, want: scanComparisonView{state: "compared", source: "scan_time", scanTime: true}},
		{name: "legacy without a scan-time comparison", summary: model.ScanSummary{Status: "success"}, want: scanComparisonView{state: "not_compared", source: "none", legacy: true}},
		{name: "unknown outcome", summary: model.ScanSummary{Status: "success", Comparison: "future_outcome"}, want: scanComparisonView{state: "not_compared", source: "none"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := resolveScanComparison(test.summary); got != test.want {
				t.Fatalf("resolveScanComparison(%+v) = %+v, want %+v", test.summary, got, test.want)
			}
		})
	}
}
