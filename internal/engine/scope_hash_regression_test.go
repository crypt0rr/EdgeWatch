package engine

import (
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestScopeHashChangeKeepsExistingServiceUntilReplacementIsStable(t *testing.T) {
	baseline := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "80", ServiceDetection: true}},
		Units:  []model.Unit{{Target: "edge", Protocol: "tcp", Ports: []model.PortState{{Port: 80, State: "open", Service: "nginx"}}}},
	}
	baseline.Normalize()
	state := model.JobState{
		Baseline:              &baseline,
		BaselineConfigHash:    "legacy-scope",
		FingerprintCandidates: map[string]model.ValueCount{},
		Incidents:             map[string]model.Incident{},
		Pending:               map[string]model.Pending{},
		Suppressed:            map[string]int{},
		SuppressedChanges:     map[string]model.Change{},
	}
	job := config.Job{Name: "scope-change", Baseline: config.Baseline{Samples: 2}, Change: config.Change{Confirmations: 1}}
	candidate := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "80,443", ServiceDetection: true}},
		Units:  []model.Unit{{Target: "edge", Protocol: "tcp", Ports: []model.PortState{{Port: 80, State: "open", Service: "apache"}}}},
	}
	candidate.Normalize()
	first := model.Scan{ID: "scope-first", Job: job.Name, ConfigHash: "current-scope", Snapshot: candidate, FinishedAt: time.Unix(1, 0).UTC()}
	if _, err := processSuccess(&state, job, first); err != nil {
		t.Fatal(err)
	}
	if got := state.Baseline.Units[0].Ports[0].Service; got != "nginx" {
		t.Fatalf("baseline service after first candidate = %q, want existing fingerprint nginx", got)
	}

	// The port state still converges, but Nmap omits a service fingerprint on
	// this sample. Since the fingerprint is intentionally excluded from the
	// convergence hash, this completes the new-scope candidate while its
	// replacement fingerprint has not met the two-sample threshold.
	candidate.Units[0].Ports[0].Service = ""
	second := model.Scan{ID: "scope-second", Job: job.Name, ConfigHash: "current-scope", Snapshot: candidate, FinishedAt: time.Unix(2, 0).UTC()}
	if events, err := processSuccess(&state, job, second); err != nil {
		t.Fatal(err)
	} else if len(events) == 0 || events[len(events)-1].Type != "baseline-updated" {
		t.Fatalf("scope-change events = %#v, want baseline update", events)
	}
	if got := state.Baseline.Units[0].Ports[0].Service; got != "nginx" {
		t.Fatalf("baseline service after unstable replacement = %q, want preserved nginx", got)
	}
}

func TestScopeHashChangeAcceptsStableServiceReplacement(t *testing.T) {
	baseline := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "80", ServiceDetection: true}},
		Units:  []model.Unit{{Target: "edge", Protocol: "tcp", Ports: []model.PortState{{Port: 80, State: "open", Service: "nginx"}}}},
	}
	baseline.Normalize()
	state := model.JobState{
		Baseline:              &baseline,
		BaselineConfigHash:    "legacy-scope",
		FingerprintCandidates: map[string]model.ValueCount{},
		Incidents:             map[string]model.Incident{},
		Pending:               map[string]model.Pending{},
		Suppressed:            map[string]int{},
		SuppressedChanges:     map[string]model.Change{},
	}
	job := config.Job{Name: "scope-change", Baseline: config.Baseline{Samples: 2}, Change: config.Change{Confirmations: 1}}
	candidate := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "80,443", ServiceDetection: true}},
		Units:  []model.Unit{{Target: "edge", Protocol: "tcp", Ports: []model.PortState{{Port: 80, State: "open", Service: "apache"}}}},
	}
	candidate.Normalize()
	for i, scanID := range []string{"stable-service-1", "stable-service-2"} {
		scan := model.Scan{ID: scanID, Job: job.Name, ConfigHash: "current-scope", Snapshot: candidate, FinishedAt: time.Unix(int64(i+1), 0).UTC()}
		if _, err := processSuccess(&state, job, scan); err != nil {
			t.Fatal(err)
		}
	}
	if got := state.Baseline.Units[0].Ports[0].Service; got != "apache" {
		t.Fatalf("baseline service after stable replacement = %q, want apache", got)
	}
}

func TestScopeHashChangeLearnsFirstFingerprintWithoutIncidentOrRecovery(t *testing.T) {
	baseline := model.Snapshot{
		Scopes: []model.Scope{{Target: "192.0.2.41", Protocol: "tcp", Ports: "22", ServiceDetection: true}},
		Units:  []model.Unit{{Target: "192.0.2.41", Protocol: "tcp", Ports: []model.PortState{{Port: 22, State: "open"}}}},
	}
	baseline.Normalize()
	state := model.JobState{
		Baseline:              &baseline,
		BaselineConfigHash:    "previous-scope-hash",
		FingerprintCandidates: map[string]model.ValueCount{},
		Incidents:             map[string]model.Incident{},
		Pending:               map[string]model.Pending{},
		Suppressed:            map[string]int{},
		SuppressedChanges:     map[string]model.Change{},
	}
	job := config.Job{Name: "scope-fingerprint", Baseline: config.Baseline{Samples: 2}, Change: config.Change{Confirmations: 1}}
	current := model.Snapshot{
		Scopes: []model.Scope{{Target: "192.0.2.41", Protocol: "tcp", Ports: "22", ServiceDetection: true}},
		Units:  []model.Unit{{Target: "192.0.2.41", Protocol: "tcp", Ports: []model.PortState{{Port: 22, State: "open", Service: "ssh | OpenSSH | 9.6"}}}},
	}
	current.Normalize()

	for i, id := range []string{"scope-fingerprint-1", "scope-fingerprint-2"} {
		scan := model.Scan{ID: id, Job: job.Name, ConfigHash: "current-scope-hash", Snapshot: current, FinishedAt: time.Unix(int64(i+1), 0).UTC()}
		events, err := processSuccess(&state, job, scan)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			if event.Type == "changes-detected" || event.Type == "changes-recovered" {
				t.Fatalf("scan %d reported a learnable first fingerprint: %#v", i+1, events)
			}
		}
		if i == 1 && (len(events) != 1 || events[0].Type != "baseline-updated") {
			t.Fatalf("second stable scan events = %#v, want baseline-updated only", events)
		}
	}

	events, err := processSuccess(&state, job, model.Scan{ID: "scope-fingerprint-after-migration", Job: job.Name, ConfigHash: "current-scope-hash", Snapshot: current, FinishedAt: time.Unix(3, 0).UTC()})
	if err != nil || len(events) != 0 {
		t.Fatalf("post-migration scan announced an already-learned fingerprint: %#v, %v", events, err)
	}
	if got := baselineService(*state.Baseline, "192.0.2.41", "tcp", 22); got != "ssh | OpenSSH | 9.6" {
		t.Fatalf("baseline service after migration = %q, want stable fingerprint", got)
	}
	if len(state.Incidents) != 0 || len(state.Pending) != 0 {
		t.Fatalf("fingerprint learning left incident state: incidents=%#v pending=%#v", state.Incidents, state.Pending)
	}
}

func TestScopeHashChangeRetiresOutOfScopeIncidentWithoutRecovery(t *testing.T) {
	baseline := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "25,80"}},
		Units:  []model.Unit{{Target: "edge", Protocol: "tcp", Ports: []model.PortState{{Port: 25, State: "open"}, {Port: 80, State: "open"}}}},
	}
	baseline.Normalize()
	key := "port|edge|tcp|80"
	pendingKey := "port|edge|tcp|25"
	suppressedKey := "service|edge|tcp|25"
	incident := model.Change{Key: key, Kind: "port", Target: "edge", Protocol: "tcp", Port: 80, Old: "open", New: "not-open", Severity: "info"}
	state := model.JobState{
		Baseline:              &baseline,
		BaselineConfigHash:    "legacy-scope",
		FingerprintCandidates: map[string]model.ValueCount{},
		Incidents:             map[string]model.Incident{key: {Change: incident, LastSeenAt: time.Unix(1, 0).UTC()}},
		Pending:               map[string]model.Pending{pendingKey: {Change: model.Change{Key: pendingKey, Kind: "port", Target: "edge", Protocol: "tcp", Port: 25}, Count: 1}},
		Suppressed:            map[string]int{suppressedKey: 1},
		SuppressedChanges:     map[string]model.Change{suppressedKey: {Key: suppressedKey, Kind: "service", Target: "edge", Protocol: "tcp", Port: 25}},
	}
	job := config.Job{Name: "scope-change", Baseline: config.Baseline{Samples: 2}, Change: config.Change{Confirmations: 1}}
	current := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge", Protocol: "tcp", Ports: "443"}},
		Units:  []model.Unit{{Target: "edge", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}}},
	}
	current.Normalize()
	scan := model.Scan{ID: "scope-scan", Job: job.Name, ConfigHash: "current-scope", Snapshot: current, FinishedAt: time.Unix(2, 0).UTC()}
	events, err := processSuccess(&state, job, scan)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Type == "changes-recovered" {
			t.Fatalf("out-of-scope incident produced a false recovery: %#v", events)
		}
	}
	if _, ok := state.Incidents[key]; ok {
		t.Fatalf("out-of-scope incident was not retired: %#v", state.Incidents[key])
	}
	if _, ok := state.Pending[pendingKey]; ok {
		t.Fatalf("out-of-scope pending change was not retired: %#v", state.Pending[pendingKey])
	}
	if _, ok := state.SuppressedChanges[suppressedKey]; ok {
		t.Fatalf("out-of-scope suppressed change was not retired: %#v", state.SuppressedChanges[suppressedKey])
	}
	if _, ok := state.Suppressed[suppressedKey]; ok {
		t.Fatalf("out-of-scope suppression counter was not retired: %#v", state.Suppressed[suppressedKey])
	}
}
