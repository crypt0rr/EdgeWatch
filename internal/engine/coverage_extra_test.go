package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestProcessFailureAndOutcomeMessageVariants(t *testing.T) {
	cases := []struct {
		name         string
		status       string
		resumable    bool
		cycleStatus  string
		wantEvent    string
		wantMessage  string
		wantFailures int
	}{
		{name: "paused", status: "failed", resumable: true, cycleStatus: "paused", wantEvent: "scan-paused", wantMessage: "Scan failed: nmap stopped", wantFailures: 0},
		{name: "paused canceled", status: "canceled", resumable: true, cycleStatus: "paused", wantEvent: "scan-canceled", wantMessage: "Scan canceled: detail", wantFailures: 0},
		{name: "canceled", status: "canceled", wantEvent: "scan-canceled", wantMessage: "Scan canceled: detail", wantFailures: 0},
		{name: "empty status", wantEvent: "scan-failure", wantMessage: "Scan failed: detail", wantFailures: 1},
		{name: "timed out", status: "timeout", wantEvent: "scan-failure", wantMessage: "Scan timed out: detail", wantFailures: 1},
		{name: "custom status", status: "provider_error", wantEvent: "scan-failure", wantMessage: "Scan provider error: detail", wantFailures: 1},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			state := model.JobState{}
			scan := model.Scan{Status: test.status, Resumable: test.resumable, CycleStatus: test.cycleStatus, Error: "detail"}
			if test.name == "paused" {
				scan.Error = "nmap stopped"
			}
			events, err := processFailure(&state, "job", scan)
			if err != nil || len(events) != 1 {
				t.Fatalf("events = %#v, err = %v", events, err)
			}
			if events[0].Type != test.wantEvent || events[0].Message != test.wantMessage {
				t.Fatalf("event = %#v, want type=%q message=%q", events[0], test.wantEvent, test.wantMessage)
			}
			if state.ConsecutiveFailures != test.wantFailures {
				t.Fatalf("failure count = %d, want %d", state.ConsecutiveFailures, test.wantFailures)
			}
		})
	}

	for status, want := range map[string]string{
		"":             "Scan failed: reason",
		"timed_out":    "Scan timed out: reason",
		"timed-out":    "Scan timed out: reason",
		"failed_state": "Scan failed state: reason",
	} {
		if got := scanOutcomeMessage(model.Scan{Status: status, Error: "reason"}); got != want {
			t.Errorf("scanOutcomeMessage(%q) = %q, want %q", status, got, want)
		}
	}
}

func TestDiffItemsAndScopeChangesIncludeServicesAndDNS(t *testing.T) {
	old := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "80,443", ServiceDetection: true}},
		Units:  []model.Unit{{Target: "edge.example", Protocol: "tcp", Ports: []model.PortState{{Port: 80, State: "open", Service: "http"}, {Port: 443, State: "open", Service: "https"}}}},
		DNS:    map[string][]string{"edge.example": {"192.0.2.1"}, "removed.example": {"192.0.2.2"}},
	}
	next := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "80,443", ServiceDetection: true}},
		Units:  []model.Unit{{Target: "edge.example", Protocol: "tcp", Ports: []model.PortState{{Port: 80, State: "open", Service: "http-alt"}, {Port: 443, State: "open|filtered", Service: "https"}}}},
		DNS:    map[string][]string{"edge.example": {"192.0.2.9"}},
	}
	if got := len(items(old)); got != 6 {
		t.Fatalf("old item count = %d, want 6", got)
	}
	changes := Diff(old, next, false)
	if len(changes) != 5 {
		t.Fatalf("changes = %#v, want five service/port/DNS changes", changes)
	}
	var sawService, sawDNSAdded, sawDNSRemoved, sawWarning bool
	for _, change := range changes {
		switch {
		case change.Kind == "service":
			sawService = true
		case change.Kind == "dns-added":
			sawDNSAdded = true
		case change.Kind == "dns-removed":
			sawDNSRemoved = true
		case change.Kind == "port" && change.Port == 443:
			sawWarning = change.Severity == "warning"
		}
	}
	if !sawService || !sawDNSAdded || !sawDNSRemoved || !sawWarning {
		t.Fatalf("changes did not preserve evidence kinds/severity: %#v", changes)
	}
	intersection := Diff(old, next, true)
	if len(intersection) == 0 {
		t.Fatal("intersection-only diff unexpectedly removed the retained scope")
	}
}

func TestCandidateAndFingerprintHelpersCoverStallsAndScopeMerges(t *testing.T) {
	state := model.JobState{FingerprintCandidates: map[string]model.ValueCount{"service|stale": {Value: "old", Count: 2}}}
	updateFingerprintCandidates(&state, model.Snapshot{Units: []model.Unit{{Target: "edge", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}}}}})
	if _, ok := state.FingerprintCandidates["service|stale"]; ok {
		t.Fatal("stale fingerprint candidate was retained")
	}

	for i := 1; i <= 6; i++ {
		snapshot := model.Snapshot{Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "1-10"}}, Units: []model.Unit{{Target: "edge", Protocol: "tcp", Ports: []model.PortState{{Port: i, State: "open"}}}}}
		events := advanceCandidate(&state, model.Scan{ID: fmt.Sprintf("scan-%d", i), Job: "job", ConfigHash: "hash", Snapshot: snapshot, FinishedAt: time.Now().UTC()}, 2, false)
		if i < 6 && len(events) != 0 {
			t.Fatalf("scan %d produced early events %#v", i, events)
		}
		if i == 6 {
			if len(events) != 1 || events[0].Type != "baseline-stalled" {
				t.Fatalf("stall event = %#v", events)
			}
		}
	}

	old := model.Snapshot{Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "1-2", ServiceDetection: true}}, Units: []model.Unit{{Target: "edge", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open", Service: "old"}}}}}
	state = model.JobState{Baseline: &old, FingerprintCandidates: map[string]model.ValueCount{}}
	candidate := model.Snapshot{Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "1-2", ServiceDetection: true}}, Units: []model.Unit{{Target: "edge", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open", Service: "new"}, {Port: 2, State: "open", Service: "added"}}}}}
	for i := 0; i < 2; i++ {
		events := advanceCandidate(&state, model.Scan{ID: fmt.Sprintf("merge-%d", i), Job: "job", ConfigHash: "hash", Snapshot: candidate, FinishedAt: time.Now().UTC()}, 2, true)
		if i == 0 && len(events) != 0 {
			t.Fatalf("early merge event = %#v", events)
		}
		if i == 1 && (len(events) != 1 || events[0].Type != "baseline-updated") {
			t.Fatalf("merge event = %#v", events)
		}
	}

	base := model.Snapshot{Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "443-444", ServiceDetection: true}}, Units: []model.Unit{{Target: "edge", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open", Service: "https"}, {Port: 444, State: "closed"}}}}}
	state = model.JobState{Baseline: &base, FingerprintCandidates: map[string]model.ValueCount{"service|missing": {Value: "stale", Count: 1}}}
	current := model.Snapshot{Units: []model.Unit{{Target: "edge", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open", Service: "https"}, {Port: 444, State: "open", Service: "new-service"}}}}}
	learnMissingFingerprints(&state, current, 2)
	if _, ok := state.FingerprintCandidates["service|missing"]; ok {
		t.Fatal("unseen fingerprint candidate was retained")
	}
	learnMissingFingerprints(&state, current, 2)
	if got := baselineService(*state.Baseline, "edge", "tcp", 444); got != "new-service" {
		t.Fatalf("learned baseline service = %q", got)
	}
	if baselineService(*state.Baseline, "missing", "tcp", 1) != "" {
		t.Fatal("baseline service lookup crossed target boundary")
	}
	setBaselineService(state.Baseline, "missing", "tcp", 1, "ignored")
}

func TestApplyChangesHandlesSuppressionRecoveryAndPendingCleanup(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	change := model.Change{Key: "port|edge|tcp|443", Kind: "port", Target: "edge", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}
	state := model.JobState{
		Incidents:         map[string]model.Incident{change.Key: {Change: change, ScanID: "old", OpenedAt: now.Add(-time.Hour), LastSeenAt: now.Add(-time.Minute)}},
		Pending:           map[string]model.Pending{"pending": {Change: change, Count: 1}},
		Suppressed:        map[string]int{change.Key: 1},
		SuppressedChanges: map[string]model.Change{change.Key: change},
	}
	if events := applyChanges(&state, "job", "suppressed", []model.Change{change}, 1, now); len(events) != 0 {
		t.Fatalf("suppressed events = %#v", events)
	}
	if state.Suppressed[change.Key] != 0 || len(state.Incidents) != 0 {
		t.Fatalf("suppression state after first scan = %#v", state)
	}
	events := applyChanges(&state, "job", "reopen", []model.Change{change}, 1, now.Add(time.Minute))
	if len(events) != 1 || events[0].Type != "changes-detected" || len(state.Incidents) != 1 {
		t.Fatalf("reopen events/state = %#v %#v", events, state)
	}
	delete(state.Incidents, change.Key)
	events = applyChanges(&state, "job", "recovered", nil, 1, now.Add(2*time.Minute))
	if len(events) != 0 {
		t.Fatalf("recovery after manually removed incident = %#v", events)
	}
	state.Incidents[change.Key] = model.Incident{Change: change, ScanID: "old", OpenedAt: now, LastSeenAt: now}
	events = applyChanges(&state, "job", "recovered", nil, 1, now.Add(3*time.Minute))
	if len(events) != 1 || events[0].Type != "changes-recovered" {
		t.Fatalf("recovery events = %#v", events)
	}
	if len(state.Pending) != 0 {
		t.Fatalf("stale pending changes = %#v", state.Pending)
	}
	if !strings.Contains(FormatEvent(events[0]), "recovered") {
		t.Fatal("recovery event did not render a recovery message")
	}
}

func TestEngineFinalizeManagedScanCoversExistingBaselineRecoveryAndFailure(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	record, err := db.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "finalize-coverage", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
		TCP: &config.Protocol{Ports: "443", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced",
		Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	}))
	if err != nil {
		t.Fatal(err)
	}
	e := Engine{Store: db}
	base := scan("finalize-base", snapshot(""))
	base.JobID, base.JobRevision, base.Job = record.ID, record.Revision, record.Job.Name
	base.ConfigHash = record.Job.SecurityHash()
	if _, err := e.SuccessForJob(ctx, record.ID, record.Job, base); err != nil {
		t.Fatal(err)
	}
	existing := base
	existing.ID = "finalize-existing"
	existing.Resumable = true
	existing.CycleAttempt = 2
	existing.Snapshot = snapshot("open")
	events, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &existing, nil)
	if err != nil || len(events) != 2 {
		t.Fatalf("existing baseline finalization = %#v, %v", events, err)
	}
	if events[1].Type != "scan-recovered" {
		t.Fatalf("recovery event = %#v", events)
	}
	failure := existing
	failure.ID = "finalize-failure"
	failure.Status = "failed"
	failure.Resumable = false
	failure.Error = "scanner stopped"
	events, err = e.FinalizeManagedScan(ctx, record.ID, record.Job, &failure, nil)
	if err != nil || len(events) != 1 || events[0].Type != "scan-failure" {
		t.Fatalf("failure finalization = %#v, %v", events, err)
	}
}

func TestEngineScopeEdgeBranches(t *testing.T) {
	state := model.JobState{}
	snap := model.Snapshot{Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "1"}}}
	if events := advanceCandidate(&state, model.Scan{ID: "zero", Snapshot: snap}, 0, false); len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("zero-sample baseline event = %#v", events)
	}

	old := model.Snapshot{Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "80"}}, Units: []model.Unit{{Target: "edge", Protocol: "tcp", Ports: []model.PortState{{Port: 80, State: "open"}}}}}
	newSnapshot := model.Snapshot{Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "80"}}, Units: []model.Unit{{Target: "edge", Protocol: "tcp", Ports: []model.PortState{{Port: 80, State: "open|filtered"}, {Port: 81, State: "open"}}}}}
	changes := Diff(old, newSnapshot, false)
	if len(changes) != 2 {
		t.Fatalf("scope edge changes = %#v", changes)
	}
	for _, change := range changes {
		if change.Port == 81 && change.Old != "not-open" {
			t.Fatalf("new port old value = %q", change.Old)
		}
	}
	missingPort := model.Snapshot{Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "80"}}}
	changes = Diff(old, missingPort, false)
	if len(changes) != 1 || changes[0].New != "not-open" || changes[0].Severity != "info" {
		t.Fatalf("missing port change = %#v", changes)
	}

	merged := mergeForScopeChange(old, model.Snapshot{
		Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "80"}, {Target: "new", Protocol: "tcp", Ports: "22"}},
		Units:  []model.Unit{{Target: "new", Protocol: "tcp", Ports: []model.PortState{{Port: 22, State: "open"}}}},
	})
	if len(merged.Units) != 1 || merged.Units[0].Target != "new" {
		t.Fatalf("new-unit scope merge = %#v", merged.Units)
	}

	change := model.Change{Key: "port|edge|tcp|1", Kind: "port", Target: "edge", Protocol: "tcp", Port: 1, Old: "not-open", New: "open", Severity: "critical"}
	state = model.JobState{Incidents: map[string]model.Incident{change.Key: {Change: change, LastSeenAt: time.Unix(1, 0)}}, Pending: map[string]model.Pending{change.Key: {Change: change, Count: 1}}}
	if events := applyChanges(&state, "job", "same", []model.Change{change}, 1, time.Unix(2, 0)); len(events) != 0 || state.Incidents[change.Key].LastSeenAt != time.Unix(2, 0) || len(state.Pending) != 0 {
		t.Fatalf("same incident transition = %#v, state=%#v", events, state)
	}
}

func TestEngineProcessSuccessRebuildsCandidateAfterScopeHashChange(t *testing.T) {
	old := model.Snapshot{Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "443"}}, Units: []model.Unit{{Target: "edge", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "closed"}}}}}
	state := model.JobState{Baseline: &old, BaselineConfigHash: "old", FingerprintCandidates: map[string]model.ValueCount{}, Incidents: map[string]model.Incident{}, Pending: map[string]model.Pending{}, Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{}}
	job := config.Job{Name: "scope-change", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	scan := model.Scan{ID: "scope-scan", Job: "scope-change", ConfigHash: "new", Snapshot: model.Snapshot{Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "443"}}, Units: []model.Unit{{Target: "edge", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}}}}, FinishedAt: time.Now().UTC()}
	events, err := processSuccess(&state, job, scan)
	if err != nil || len(events) != 2 {
		t.Fatalf("scope-change events = %#v, err = %v", events, err)
	}
	if events[0].Type != "changes-detected" || events[1].Type != "baseline-updated" {
		t.Fatalf("scope-change event order = %#v", events)
	}
}

func TestEngineFingerprintAndApplyChangeEdgeBranches(t *testing.T) {
	learnMissingFingerprints(&model.JobState{}, model.Snapshot{}, 1)

	oldChange := model.Change{Key: "port|edge|tcp|80", Kind: "port", Target: "edge", Protocol: "tcp", Port: 80, Old: "open", New: "not-open", Severity: "info"}
	oldChange2 := oldChange
	oldChange2.Key, oldChange2.Port = "port|edge|tcp|81", 81
	newChange := model.Change{Key: "port|edge|tcp|443", Kind: "port", Target: "edge", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}
	newChange2 := newChange
	newChange2.Key, newChange2.Port = "port|edge|tcp|444", 444
	state := model.JobState{Incidents: map[string]model.Incident{oldChange.Key: {Change: oldChange}, oldChange2.Key: {Change: oldChange2}}, Pending: map[string]model.Pending{}}
	events := applyChanges(&state, "job", "mixed", []model.Change{newChange, newChange2}, 1, time.Unix(10, 0))
	if len(events) != 2 || events[0].Type != "changes-detected" || events[1].Type != "changes-recovered" {
		t.Fatalf("mixed transition events = %#v", events)
	}

	expired := model.Change{Key: "port|edge|tcp|8080", Kind: "port", Target: "edge", Protocol: "tcp", Port: 8080, Old: "not-open", New: "open", Severity: "critical"}
	changed := expired
	changed.New = "closed"
	state = model.JobState{Suppressed: map[string]int{expired.Key: 0}, SuppressedChanges: map[string]model.Change{expired.Key: expired}, Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{}}
	if events := applyChanges(&state, "job", "mismatch", []model.Change{changed}, 2, time.Unix(11, 0)); len(events) != 0 || state.Pending[changed.Key].Count != 1 {
		t.Fatalf("expired suppression mismatch = %#v, state=%#v", events, state)
	}
}
