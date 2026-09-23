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

func snapshot(state string) model.Snapshot {
	s := model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}}}
	if state != "" {
		s.Units = []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: state}}}}
	}
	s.Normalize()
	return s
}

func snapshotWithOpenPorts(ports ...int) model.Snapshot {
	s := model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}}}
	unit := model.Unit{Target: "192.0.2.1", Protocol: "tcp"}
	for _, port := range ports {
		unit.Ports = append(unit.Ports, model.PortState{Port: port, State: "open"})
	}
	s.Units = []model.Unit{unit}
	s.Normalize()
	return s
}
func scan(id string, s model.Snapshot) model.Scan {
	return model.Scan{ID: id, Job: "test", Status: "success", ConfigHash: "hash", Snapshot: s, FinishedAt: time.Now().UTC()}
}

func TestBaselineChangeAndRecoveryConfirmations(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "test", Baseline: config.Baseline{Samples: 2}, Change: config.Change{Confirmations: 2}}
	if events, err := e.Success(ctx, job, scan("1", snapshot(""))); err != nil || len(events) != 0 {
		t.Fatalf("first baseline: %v %v", events, err)
	}
	if events, err := e.Success(ctx, job, scan("2", snapshot(""))); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline completion: %v %v", events, err)
	}
	if events, _ := e.Success(ctx, job, scan("3", snapshot("open"))); len(events) != 0 {
		t.Fatalf("early change event %v", events)
	}
	events, _ := e.Success(ctx, job, scan("4", snapshot("open")))
	if len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("change event %v", events)
	}
	if events, _ := e.Success(ctx, job, scan("5", snapshot(""))); len(events) != 0 {
		t.Fatalf("early recovery %v", events)
	}
	events, _ = e.Success(ctx, job, scan("6", snapshot("")))
	if len(events) != 1 || events[0].Type != "changes-recovered" {
		t.Fatalf("recovery %v", events)
	}
}

func TestTotalLossScanRequiresConfirmationBeforeOpeningIncidents(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "total-loss", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	ports := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	if events, err := e.Success(ctx, job, scan("baseline", snapshotWithOpenPorts(ports...))); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline setup: %#v, %v", events, err)
	}

	firstEmpty := scan("empty-1", snapshot(""))
	events, err := e.Success(ctx, job, firstEmpty)
	if err != nil || len(events) != 1 || events[0].Type != "scan-anomaly" {
		t.Fatalf("first total-loss scan: %#v, %v", events, err)
	}
	if !strings.Contains(FormatEvent(events[0]), "awaiting confirmation") {
		t.Fatalf("anomaly notification: %q", FormatEvent(events[0]))
	}
	state, err := db.State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 0 || state.TotalLossCandidateCount != 1 || state.Baseline == nil || len(state.Baseline.Units[0].Ports) != len(ports) {
		t.Fatalf("first total-loss state: %#v", state)
	}

	// A second identical complete result confirms the loss and hands control
	// back to the normal diff engine. The finding is never suppressed forever;
	// it is merely protected from a single anomalous pass.
	events, err = e.Success(ctx, job, scan("empty-2", snapshot("")))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("confirmed total-loss scan: %#v, %v", events, err)
	}
	state, err = db.State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != len(ports) || state.TotalLossCandidateCount != 0 || state.TotalLossCandidateHash != "" {
		t.Fatalf("confirmed total-loss state: %#v", state)
	}
}

func TestGradualPortReductionBypassesTotalLossGuard(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "gradual-loss", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	if _, err := e.Success(ctx, job, scan("baseline", snapshotWithOpenPorts(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12))); err != nil {
		t.Fatal(err)
	}
	events, err := e.Success(ctx, job, scan("reduction", snapshotWithOpenPorts(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("gradual reduction: %#v, %v", events, err)
	}
	state, err := db.State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 2 {
		t.Fatalf("gradual reduction incidents: %d (%#v)", len(state.Incidents), state.Incidents)
	}
}

func TestSuppressedIncidentReopensAfterOneSuccessfulScan(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "suppressed", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 2}}
	if _, err := e.Success(ctx, job, scan("baseline", snapshot(""))); err != nil {
		t.Fatal(err)
	}
	if events, err := e.Success(ctx, job, scan("candidate-1", snapshot("open"))); err != nil || len(events) != 0 {
		t.Fatalf("first changed scan: %#v, %v", events, err)
	}
	if events, err := e.Success(ctx, job, scan("incident", snapshot("open"))); err != nil || len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("incident scan: %#v, %v", events, err)
	}
	key := "port|192.0.2.1|tcp|443"
	if _, err := db.UpdateState(ctx, job.Name, func(state *model.JobState) ([]model.Event, error) {
		incident, ok := state.Incidents[key]
		if !ok {
			return nil, fmt.Errorf("incident %s not found", key)
		}
		state.Suppressed[key] = 1
		state.SuppressedChanges[key] = incident.Change
		delete(state.Incidents, key)
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if events, err := e.Success(ctx, job, scan("suppressed-scan", snapshot("open"))); err != nil || len(events) != 0 {
		t.Fatalf("suppressed scan: %#v, %v", events, err)
	}
	state, err := db.State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 0 || state.Suppressed[key] != 0 {
		t.Fatalf("suppression window after scan = %#v", state)
	}
	events, err := e.Success(ctx, job, scan("reopened", snapshot("open")))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("reopened scan: %#v, %v", events, err)
	}
	state, err = db.State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 1 || state.Suppressed[key] != 0 {
		t.Fatalf("reopened state = %#v", state)
	}
}

func TestUDPUncertaintyIsWarning(t *testing.T) {
	changes := Diff(snapshot(""), model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}}, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 53, State: "open|filtered"}}}}}, false)
	if len(changes) != 1 || changes[0].Severity != "warning" {
		t.Fatalf("changes %#v", changes)
	}
}

func TestFormatEventUsesOutcomeIndicators(t *testing.T) {
	recovered := FormatEvent(model.Event{Type: "changes-recovered", Message: "one change recovered", Job: "test"})
	if !strings.HasPrefix(recovered, "🟢 EdgeWatch: ") {
		t.Fatalf("recovery notification = %q", recovered)
	}
	cycleRecovered := FormatEvent(model.Event{Type: "scan-recovered", Message: "scan cycle recovered", Job: "test"})
	if !strings.HasPrefix(cycleRecovered, "🟢 EdgeWatch: ") {
		t.Fatalf("resumable recovery notification = %q", cycleRecovered)
	}

	critical := FormatEvent(model.Event{Type: "changes-detected", Message: "one change", Job: "test", Changes: []model.Change{{Severity: "critical"}}})
	if !strings.HasPrefix(critical, "🔴 EdgeWatch: ") {
		t.Fatalf("critical notification = %q", critical)
	}

	warning := FormatEvent(model.Event{Type: "changes-detected", Message: "one change", Job: "test", Changes: []model.Change{{Severity: "warning"}}})
	if strings.HasPrefix(warning, "🔴 ") || strings.HasPrefix(warning, "🟢 ") {
		t.Fatalf("warning notification has an outcome indicator = %q", warning)
	}
	anomaly := FormatEvent(model.Event{Type: "scan-anomaly", Message: "awaiting confirmation", Job: "test"})
	if !strings.HasPrefix(anomaly, "⚠️ EdgeWatch: ") {
		t.Fatalf("anomaly notification = %q", anomaly)
	}
	incomplete := FormatEvent(model.Event{Type: "scan-incomplete", Message: "Scan incomplete: scan coverage did not complete for 192.0.2.9", Job: "test"})
	if !strings.HasPrefix(incomplete, "⚠️ EdgeWatch: ") || !strings.Contains(incomplete, "192.0.2.9") {
		t.Fatalf("incomplete notification = %q", incomplete)
	}
}

func TestFormatEventUsesApplicationUpdateMessages(t *testing.T) {
	available := FormatEvent(model.Event{Type: "application-update-available", CurrentVersion: "v1.1.0", LatestVersion: "v1.2.0", ReleaseURL: "https://github.com/crypt0rr/EdgeWatch/releases/tag/v1.2.0"})
	if !strings.Contains(available, "⬆️ EdgeWatch update available") || !strings.Contains(available, "Current version: v1.1.0") || !strings.Contains(available, "New version: v1.2.0") || strings.Contains(available, "Job:") {
		t.Fatalf("available update notification = %q", available)
	}
	updated := FormatEvent(model.Event{Type: "application-updated", PreviousVersion: "v1.1.0", CurrentVersion: "v1.2.0", ReleaseURL: "https://github.com/crypt0rr/EdgeWatch/releases/tag/v1.2.0"})
	if !strings.Contains(updated, "🟢 EdgeWatch updated") || !strings.Contains(updated, "Previous version: v1.1.0") || strings.Contains(updated, "Job:") {
		t.Fatalf("updated notification = %q", updated)
	}
}

func TestFormatEventSanitizesScanDerivedText(t *testing.T) {
	event := model.Event{
		Type:    "changes-detected",
		Message: "banner <@everyone>\u202Ehidden\u202C\u2028next",
		Job:     "edge_[prod]",
		Changes: []model.Change{{Severity: "critical", Kind: "service", Target: "host<1>", Protocol: "tcp", Port: 443, Old: "old", New: "[x](javascript:alert(1))"}},
	}
	got := FormatEvent(event)
	for _, unsafe := range []string{"<@everyone>", "@everyone", "[x](javascript:alert(1))", "\nnext", "\u202E", "\u202C"} {
		if strings.Contains(got, unsafe) {
			t.Fatalf("notification retained unsafe text %q: %q", unsafe, got)
		}
	}
	if !strings.Contains(got, "‹＠everyone›") || !strings.Contains(got, "［x］（javascript:alert（1））") || !strings.Contains(got, "old ->") {
		t.Fatalf("notification did not preserve a readable neutralized form: %q", got)
	}
	long := FormatEvent(model.Event{Message: strings.Repeat("x", maxNotificationFieldRunes+20)})
	if len([]rune(long)) > len("EdgeWatch: ")+maxNotificationFieldRunes {
		t.Fatalf("notification field was not bounded: %d runes", len([]rune(long)))
	}
}

func TestIncompleteFailuresDoNotChangeBaseline(t *testing.T) {
	ctx := context.Background()
	db, _ := store.Open(filepath.Join(t.TempDir(), "db"))
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "test", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	e.Success(ctx, job, scan("1", snapshot("open")))
	failed := scan("2", snapshot(""))
	failed.Status = "failed"
	failed.Error = "timeout"
	for i := 0; i < 3; i++ {
		e.Failure(ctx, "test", failed)
	}
	state, _ := db.State(ctx, "test")
	if state.Baseline == nil || len(state.Baseline.Units) == 0 {
		t.Fatal("failure modified baseline")
	}
	if len(state.Incidents) != 0 {
		t.Fatal("failure created incident")
	}
}

func TestUnreachableHostObservationDoesNotChangeBaseline(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "partial", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	baseline := model.Snapshot{
		Scopes: []model.Scope{
			{Target: "192.0.2.1", Protocol: "tcp", Ports: "443"},
			{Target: "192.0.2.2", Protocol: "tcp", Ports: "443"},
		},
		Units: []model.Unit{
			{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}},
			{Target: "192.0.2.2", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}},
		},
	}
	if events, err := e.Success(ctx, job, scan("baseline", baseline)); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline setup: %#v, %v", events, err)
	}
	partial := model.Snapshot{
		Scopes: baseline.Scopes,
		Units:  []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}, {Port: 80, State: "open"}}}},
		Hosts:  []model.HostObservation{{Address: "192.0.2.2", Status: "unreachable", StatusReason: "nmap-omitted"}},
	}
	if events, err := e.Success(ctx, job, scan("partial", partial)); err != nil || len(events) != 2 || events[0].Type != "changes-detected" || events[1].Type != "scan-incomplete" {
		t.Fatalf("partial scan did not compare reachable evidence and report incomplete coverage: %#v, %v", events, err)
	}
	state, err := db.State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline == nil || len(state.Baseline.Units) != 2 || len(state.Incidents) != 1 {
		t.Fatalf("partial scan changed baseline or incidents: %#v", state)
	}
	if _, ok := state.Incidents["port|192.0.2.2|tcp|443"]; ok {
		t.Fatal("unreachable host removal created an incident before it was observed")
	}
	complete := model.Snapshot{
		Scopes: baseline.Scopes,
		Units: []model.Unit{
			{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}, {Port: 80, State: "open"}}},
			{Target: "192.0.2.2", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "closed"}}},
		},
	}
	events, err := e.Success(ctx, job, scan("complete", complete))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" || len(events[0].Changes) != 1 || events[0].Changes[0].Target != "192.0.2.2" {
		t.Fatalf("complete scan did not report deferred unreachable-host removal: %#v, %v", events, err)
	}
}

func TestUnknownNoResponseEvidenceCannotLearnOrRemoveBaselinePorts(t *testing.T) {
	job := config.Job{Name: "no-response", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	current := model.Snapshot{
		Scopes: []model.Scope{{Target: "192.0.2.30", Protocol: "tcp", Ports: "443"}},
		Units:  []model.Unit{{Target: "192.0.2.30", Protocol: "tcp", Addresses: []string{"192.0.2.30"}}},
		Hosts: []model.HostObservation{{
			Address: "192.0.2.30", Status: "unknown", StatusReason: "no-response",
			Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unknown", StatusReason: "no-response", ScannedPorts: "1-65535"}},
		}},
	}

	learningState := model.JobState{}
	learningScan := scan("no-response-learning", current)
	if !MarkIncompleteScan(&learningScan) {
		t.Fatal("unknown/no-response scan was not marked incomplete")
	}
	events, changes, err := processSuccessWithChanges(&learningState, job, learningScan)
	if err != nil || len(changes) != 0 || learningState.Baseline != nil || learningState.CandidateAttempts != 0 || learningState.IncompleteCandidateAttempts != 1 {
		t.Fatalf("incomplete no-response scan advanced baseline learning: events=%#v changes=%#v state=%#v err=%v", events, changes, learningState, err)
	}

	baseline := model.Snapshot{
		Scopes: []model.Scope{{Target: "192.0.2.30", Protocol: "tcp", Ports: "443"}},
		Units:  []model.Unit{{Target: "192.0.2.30", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}}},
	}
	state := model.JobState{Baseline: &baseline, BaselineConfigHash: "hash", Incidents: map[string]model.Incident{}, Pending: map[string]model.Pending{}}
	removalScan := scan("no-response-removal", current)
	removalScan.ConfigHash = "hash"
	if !MarkIncompleteScan(&removalScan) {
		t.Fatal("unknown/no-response removal scan was not marked incomplete")
	}
	events, changes, err = processSuccessWithChanges(&state, job, removalScan)
	if err != nil || len(changes) != 0 || len(events) != 1 || events[0].Type != "scan-incomplete" {
		t.Fatalf("incomplete no-response scan confirmed removals: events=%#v changes=%#v err=%v", events, changes, err)
	}
	if state.Baseline == nil || len(state.Baseline.Units) != 1 || len(state.Baseline.Units[0].Ports) != 1 || len(state.Incidents) != 0 {
		t.Fatalf("incomplete no-response scan changed expected state: %#v", state)
	}
}

func TestCompletedNaabuNoDiscoveryCanEstablishBaseline(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "completed-empty-naabu", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	address := "192.0.2.31"
	current := model.Snapshot{
		Scopes: []model.Scope{{Target: address, Protocol: "tcp", Ports: "1-65535"}},
		Units:  []model.Unit{{Target: address, Protocol: "tcp", Addresses: []string{address}}},
		Hosts: []model.HostObservation{{
			Address: address, Status: "unknown", StatusReason: "scan-complete",
			Protocols: []model.ProtocolObservation{{
				Protocol: "tcp", Status: "unknown", StatusReason: "scan-complete",
				ScannedPorts: "1-65535", ScannedPortCount: 65535,
			}},
		}},
	}
	completed := scan("completed-empty-naabu", current)
	if MarkIncompleteScan(&completed) {
		t.Fatal("completed full-range Naabu discovery was marked incomplete")
	}
	events, err := e.Success(ctx, job, completed)
	if err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("completed empty Naabu scan did not establish baseline: events=%#v err=%v", events, err)
	}
	state, err := db.State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline == nil || len(state.Baseline.Units) != 1 || len(state.Baseline.Units[0].Ports) != 0 {
		t.Fatalf("completed empty Naabu scan baseline = %#v", state.Baseline)
	}
}

func TestIncompleteProtocolDoesNotSuppressCompleteProtocolChanges(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "protocol-partial.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "protocol-partial", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	baseline := model.Snapshot{
		Scopes: []model.Scope{
			{Target: "192.0.2.20", Protocol: "tcp", Ports: "80,443"},
			{Target: "192.0.2.20", Protocol: "udp", Ports: "53"},
		},
		Units: []model.Unit{
			{Target: "192.0.2.20", Protocol: "tcp", Addresses: []string{"192.0.2.20"}, Ports: []model.PortState{{Port: 80, State: "open"}, {Port: 443, State: "open"}}},
			{Target: "192.0.2.20", Protocol: "udp", Addresses: []string{"192.0.2.20"}, Ports: []model.PortState{{Port: 53, State: "open"}}},
		},
	}
	if events, err := e.Success(ctx, job, scan("protocol-baseline", baseline)); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline setup: %#v, %v", events, err)
	}

	partial := model.Snapshot{
		Scopes: baseline.Scopes,
		Units: []model.Unit{{
			Target: "192.0.2.20", Protocol: "tcp", Addresses: []string{"192.0.2.20"},
			Ports: []model.PortState{{Port: 80, State: "open"}},
		}},
		Hosts: []model.HostObservation{{
			Address: "192.0.2.20", Status: "up", StatusReason: "syn-ack",
			Protocols: []model.ProtocolObservation{
				{Protocol: "tcp", Status: "up", StatusReason: "syn-ack", ScannedPorts: "80,443"},
				{Protocol: "udp", Status: "unreachable", StatusReason: "nmap-host-timeout", ScannedPorts: "53"},
			},
		}},
	}
	partialScan := scan("protocol-partial", partial)
	if !MarkIncompleteScan(&partialScan) || partialScan.Status != "incomplete" {
		t.Fatalf("partial scan was not marked incomplete: %#v", partialScan)
	}
	events, err := e.Success(ctx, job, partialScan)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Type != "changes-detected" || events[1].Type != "scan-incomplete" {
		t.Fatalf("partial scan events = %#v", events)
	}
	if len(events[0].Changes) != 1 || events[0].Changes[0].Key != "port|192.0.2.20|tcp|443" {
		t.Fatalf("partial scan changes = %#v, want only complete TCP removal", events[0].Changes)
	}
	state, err := db.State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Incidents["port|192.0.2.20|tcp|443"]; !ok {
		t.Fatalf("complete TCP change did not open incident: %#v", state.Incidents)
	}
	if _, ok := state.Incidents["port|192.0.2.20|udp|53"]; ok {
		t.Fatal("incomplete UDP removal created an incident")
	}
	if state.Baseline == nil || len(state.Baseline.Units) != 2 || len(state.Baseline.Units[0].Ports) != 2 || len(state.Baseline.Units[1].Ports) != 1 {
		t.Fatalf("incomplete protocol evidence changed the baseline: %#v", state.Baseline)
	}
}

func TestIncompleteDNSScanKeepsHealthySiblingAdditions(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "dns-partial.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "dns-siblings", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	baseline := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "80,443", ServiceDetection: true}},
		DNS:    map[string][]string{"edge.example": {"192.0.2.1", "192.0.2.2"}},
		Units: []model.Unit{{
			Target: "edge.example", Protocol: "tcp", Addresses: []string{"192.0.2.1", "192.0.2.2"},
			Ports: []model.PortState{{Port: 443, State: "open", Evidence: []string{"192.0.2.1", "192.0.2.2"}}},
		}},
	}
	baseline.Normalize()
	if events, err := e.Success(ctx, job, scan("dns-baseline", baseline)); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline setup: %#v, %v", events, err)
	}

	partial := model.Snapshot{
		Scopes: baseline.Scopes,
		DNS:    baseline.DNS,
		Units: []model.Unit{{
			Target: "edge.example", Protocol: "tcp", Addresses: []string{"192.0.2.1", "192.0.2.2"},
			Ports: []model.PortState{{Port: 80, State: "open", Service: "http", Evidence: []string{"192.0.2.1"}}},
		}},
		Hosts: []model.HostObservation{{Address: "192.0.2.2", Status: "down", StatusReason: "no-response"}},
	}
	partial.Normalize()
	events, err := e.Success(ctx, job, scan("dns-partial", partial))
	if err != nil || len(events) != 2 || events[0].Type != "changes-detected" || events[1].Type != "scan-incomplete" {
		t.Fatalf("partial DNS scan events: %#v, err=%v", events, err)
	}
	if len(events[0].Changes) != 1 || events[0].Changes[0].Key != "port|edge.example|tcp|80" {
		t.Fatalf("partial DNS changes = %#v, want only healthy port addition", events[0].Changes)
	}
	state, err := db.State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Incidents["port|edge.example|tcp|80"]; !ok {
		t.Fatalf("healthy sibling addition did not open an incident: %#v", state.Incidents)
	}
	if _, ok := state.Incidents["port|edge.example|tcp|443"]; ok {
		t.Fatal("removal protected by incomplete DNS sibling was reported")
	}
	if _, ok := state.Incidents["service|edge.example|tcp|80"]; ok {
		t.Fatal("service change with merged/incomplete evidence was reported")
	}
	if state.Baseline == nil || state.Baseline.Units[0].Ports[0].Port != 443 {
		t.Fatalf("partial DNS scan advanced baseline: %#v", state.Baseline)
	}
}

func TestIncompleteDNSScanPreservesPendingHealthyAdditionUntilCompleteConfirmation(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "dns-pending.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "dns-pending", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 2}}

	baseline := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "80,443"}},
		DNS:    map[string][]string{"edge.example": {"192.0.2.1", "192.0.2.2"}},
		Units: []model.Unit{{
			Target: "edge.example", Protocol: "tcp", Addresses: []string{"192.0.2.1", "192.0.2.2"},
			Ports: []model.PortState{{Port: 443, State: "open", Evidence: []string{"192.0.2.1", "192.0.2.2"}}},
		}},
	}
	baseline.Normalize()
	if events, err := e.Success(ctx, job, scan("dns-pending-baseline", baseline)); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline setup: %#v, %v", events, err)
	}

	// The first complete scan observes a new port only on the healthy address.
	// With two confirmations it must remain pending rather than opening an
	// incident immediately.
	first := baseline
	first.Units = []model.Unit{{
		Target: "edge.example", Protocol: "tcp", Addresses: []string{"192.0.2.1", "192.0.2.2"},
		Ports: []model.PortState{
			{Port: 80, State: "open", Evidence: []string{"192.0.2.1"}},
			{Port: 443, State: "open", Evidence: []string{"192.0.2.1", "192.0.2.2"}},
		},
	}}
	first.Normalize()
	if events, err := e.Success(ctx, job, scan("dns-pending-first", first)); err != nil {
		t.Fatalf("first complete scan: %v", err)
	} else if len(events) != 0 {
		t.Fatalf("first confirmation emitted events before the threshold: %#v", events)
	}
	state, err := db.State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := state.Pending["port|edge.example|tcp|80"]
	if !ok || pending.Count != 1 {
		t.Fatalf("pending healthy addition = %#v, want one confirmation", state.Pending)
	}

	// The sibling address is now incomplete and the pending port is absent from
	// the partial evidence. The pending addition must survive this scan, while
	// the baseline port remains protected from a false removal.
	partial := model.Snapshot{
		Scopes: baseline.Scopes,
		DNS:    baseline.DNS,
		Units: []model.Unit{{
			Target: "edge.example", Protocol: "tcp", Addresses: []string{"192.0.2.1", "192.0.2.2"},
			Ports: []model.PortState{{Port: 443, State: "open", Evidence: []string{"192.0.2.1"}}},
		}},
		Hosts: []model.HostObservation{{Address: "192.0.2.2", Status: "down", StatusReason: "no-response"}},
	}
	partial.Normalize()
	if events, err := e.Success(ctx, job, scan("dns-pending-partial", partial)); err != nil || len(events) != 1 || events[0].Type != "scan-incomplete" {
		t.Fatalf("partial DNS scan: %#v, %v", events, err)
	}
	state, err = db.State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if pending, ok = state.Pending["port|edge.example|tcp|80"]; !ok || pending.Count != 1 {
		t.Fatalf("partial scan changed pending addition = %#v, want one confirmation", state.Pending)
	}
	if _, ok := state.Incidents["port|edge.example|tcp|443"]; ok {
		t.Fatal("partial sibling loss opened a removal incident")
	}

	// A later complete observation of the same healthy addition supplies the
	// second confirmation and opens exactly one incident.
	final := first
	final.Units = append([]model.Unit(nil), first.Units...)
	final.Normalize()
	events, err := e.Success(ctx, job, scan("dns-pending-final", final))
	if err != nil {
		t.Fatalf("final complete scan: %v", err)
	}
	if len(events) != 1 || events[0].Type != "changes-detected" || len(events[0].Changes) != 1 || events[0].Changes[0].Key != "port|edge.example|tcp|80" {
		t.Fatalf("final confirmation events = %#v, want one port change", events)
	}
	state, err = db.State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Pending["port|edge.example|tcp|80"]; ok {
		t.Fatal("confirmed addition remained pending")
	}
	if _, ok := state.Incidents["port|edge.example|tcp|80"]; !ok {
		t.Fatal("confirmed healthy addition did not open an incident")
	}
}

func TestEveryUnsuccessfulScanEmitsAnOutcomeEvent(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "outcomes", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}

	failed := scan("failed", snapshot(""))
	failed.Status = "failed"
	failed.Error = "nmap failed: permission denied"
	events, err := e.Failure(ctx, job.Name, failed)
	if err != nil || len(events) != 1 || events[0].Type != "scan-failure" {
		t.Fatalf("failed scan event = %#v, err=%v", events, err)
	}
	if events[0].Message != "Scan failed: nmap failed: permission denied" {
		t.Fatalf("failed scan message = %q", events[0].Message)
	}

	canceled := scan("canceled", snapshot(""))
	canceled.Status = "canceled"
	canceled.Error = "scan canceled"
	events, err = e.Failure(ctx, job.Name, canceled)
	if err != nil || len(events) != 1 || events[0].Type != "scan-canceled" {
		t.Fatalf("canceled scan event = %#v, err=%v", events, err)
	}
	if events[0].Message != "Scan canceled: scan canceled" {
		t.Fatalf("canceled scan message = %q", events[0].Message)
	}

	timedOut := scan("timed-out", snapshot(""))
	timedOut.Status = "timed_out"
	timedOut.Error = "scan exceeded its timeout"
	events, err = e.Failure(ctx, job.Name, timedOut)
	if err != nil || len(events) != 1 || events[0].Type != "scan-failure" {
		t.Fatalf("timed-out scan event = %#v, err=%v", events, err)
	}
	if events[0].Message != "Scan timed out: scan exceeded its timeout" {
		t.Fatalf("timed-out scan message = %q", events[0].Message)
	}

	state, err := db.State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if state.ConsecutiveFailures != 2 {
		t.Fatalf("unexpected failure count after canceled and timed-out scans: %d", state.ConsecutiveFailures)
	}
}

func TestFinalizeManagedScanRecordsInitialBaselineScanMetadata(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	record, err := db.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "managed", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
		TCP: &config.Protocol{Ports: "443", Mode: "connect"}, Timing: "balanced", Timeout: config.Duration(time.Minute),
		Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	}))
	if err != nil {
		t.Fatal(err)
	}
	e := Engine{Store: db}
	current := scan("managed-baseline", snapshot("open"))
	current.Snapshot.Hosts = []model.HostObservation{{Address: "192.0.2.1", Status: "up"}}
	current.Snapshot.Normalize()
	current.JobID, current.JobRevision, current.Job = record.ID, record.Revision, record.Job.Name
	current.ConfigHash = record.Job.SecurityHash()
	if _, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &current, nil); err != nil {
		t.Fatal(err)
	}
	stored, err := db.GetScan(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.BaselineScanID != current.ID || stored.BaselineConfigHash != current.ConfigHash {
		t.Fatalf("initial baseline metadata = %#v, want scan=%s hash=%s", stored, current.ID, current.ConfigHash)
	}
	if exists, err := db.BaselineHostProjectionExists(ctx, record.ID); err != nil || !exists {
		t.Fatalf("automatic baseline did not maintain host projection: exists=%v err=%v", exists, err)
	}
}

func TestFinalizeManagedScanMarksIncompleteAndKeepsReachableChanges(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	job := config.NormalizeJob(config.Job{
		Name: "partial-managed", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1", "192.0.2.2"},
		TCP: &config.Protocol{Ports: "80,443", Mode: "connect"}, Timing: "balanced", Timeout: config.Duration(time.Minute),
		Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	baseSnapshot := model.Snapshot{
		Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "80,443"}, {Target: "192.0.2.2", Protocol: "tcp", Ports: "80,443"}},
		Units: []model.Unit{
			{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}},
			{Target: "192.0.2.2", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}},
		},
	}
	e := Engine{Store: db}
	baseline := scan("partial-managed-baseline", baseSnapshot)
	baseline.JobID, baseline.JobRevision, baseline.Job, baseline.ConfigHash = record.ID, record.Revision, record.Job.Name, record.Job.SecurityHash()
	if _, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &baseline, nil); err != nil {
		t.Fatal(err)
	}
	current := scan("partial-managed-current", model.Snapshot{
		Scopes: baseSnapshot.Scopes,
		Units:  []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}, {Port: 80, State: "open"}}}},
		Hosts:  []model.HostObservation{{Address: "192.0.2.2", Status: "down", StatusReason: "no-response"}},
	})
	current.JobID, current.JobRevision, current.Job, current.ConfigHash = record.ID, record.Revision, record.Job.Name, record.Job.SecurityHash()
	events, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &current, nil)
	if err != nil || len(events) != 2 || events[0].Type != "changes-detected" || events[1].Type != "scan-incomplete" {
		t.Fatalf("partial managed finalization = %#v, err=%v", events, err)
	}
	stored, err := db.GetScan(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "incomplete" || !strings.Contains(stored.Error, "192.0.2.2") {
		t.Fatalf("stored partial status = %#v", stored)
	}
	if len(stored.Changes) != 1 || stored.Changes[0].Target != "192.0.2.1" || stored.Changes[0].Port != 80 {
		t.Fatalf("stored reachable changes = %#v", stored.Changes)
	}
	state, err := db.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline == nil || len(state.Baseline.Units) != 2 || state.Baseline.Units[0].Ports[0].State != "open" {
		t.Fatalf("partial scan advanced baseline: %#v", state.Baseline)
	}
}

func TestFinalizeManagedScanPersistsTheChangeSetAppliedByEngine(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	record, err := db.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "fingerprint-consistency", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
		TCP: &config.Protocol{Ports: "443", Mode: "connect", ServiceDetection: true}, Timing: "balanced", Timeout: config.Duration(time.Minute),
		Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	}))
	if err != nil {
		t.Fatal(err)
	}
	withService := func(service string) model.Snapshot {
		var hostService *model.ServiceObservation
		if service != "" {
			hostService = &model.ServiceObservation{Product: service, Method: "probed"}
		}
		snapshot := model.Snapshot{
			Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "443", ServiceDetection: true}},
			Units:  []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open", Service: service}}}},
			Hosts: []model.HostObservation{{
				Address: "192.0.2.1", Status: "up",
				Protocols: []model.ProtocolObservation{{
					Protocol: "tcp", ScannedPorts: "443", ScannedPortCount: 1, ServiceDetection: true,
					Ports: []model.PortObservation{{Port: 443, State: "open", Service: hostService}},
				}},
			}},
		}
		snapshot.Normalize()
		return snapshot
	}
	e := Engine{Store: db}
	baseline := model.Scan{ID: "fingerprint-baseline", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: withService("")}
	if _, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &baseline, nil); err != nil {
		t.Fatal(err)
	}
	current := model.Scan{ID: "fingerprint-learned", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: withService("nginx")}
	events, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &current, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("fingerprint learning emitted a change event: %#v", events)
	}
	stored, err := db.GetScan(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Changes) != 0 {
		t.Fatalf("persisted changes = %#v, want the same empty set acted on by the engine", stored.Changes)
	}
	exists, err := db.BaselineHostProjectionExists(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("engine baseline mutation did not maintain the baseline host projection")
	}
	projected, err := db.GetBaselineHost(ctx, record.ID, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if projected.Host.Address != "192.0.2.1" {
		t.Fatalf("baseline projection host = %#v", projected.Host)
	}
}

func TestFingerprintStabilizesWithoutBlockingPortBaseline(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "test", Baseline: config.Baseline{Samples: 2}, Change: config.Change{Confirmations: 1}}
	withService := func(service string) model.Snapshot {
		return model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "443", ServiceDetection: true}}, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open", Service: service}}}}}
	}
	if events, _ := e.Success(ctx, job, scan("1", withService("service A"))); len(events) != 0 {
		t.Fatalf("unexpected event %#v", events)
	}
	events, err := e.Success(ctx, job, scan("2", withService("service B")))
	if err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("fingerprint blocked baseline: %#v %v", events, err)
	}
	state, _ := db.State(ctx, "test")
	if got := baselineService(*state.Baseline, "192.0.2.1", "tcp", 443); got != "" {
		t.Fatalf("unstable service entered baseline: %q", got)
	}
	if events, _ = e.Success(ctx, job, scan("3", withService("service B"))); len(events) != 0 {
		t.Fatalf("fingerprint learning generated alert: %#v", events)
	}
	state, _ = db.State(ctx, "test")
	if got := baselineService(*state.Baseline, "192.0.2.1", "tcp", 443); got != "service B" {
		t.Fatalf("stable service not learned: %q", got)
	}
}
