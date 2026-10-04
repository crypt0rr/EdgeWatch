package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

func dnsComparisonSnapshot(address, portState, service, hostState string) model.Snapshot {
	unit := model.Unit{Target: "edge.example", Protocol: "tcp", Addresses: []string{address}}
	if portState != "" {
		unit.Ports = []model.PortState{{Port: 443, State: portState, Service: service, Evidence: []string{address}}}
	}
	snapshot := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "443", ServiceDetection: true}},
		DNS:    map[string][]string{"edge.example": {address}},
		Units:  []model.Unit{unit},
	}
	if hostState != "" {
		snapshot.HostStates = []model.HostState{{Address: address, State: hostState}}
	}
	snapshot.Normalize()
	return snapshot
}

func TestAggregateDNSComparisonIgnoresAnswerRotationButKeepsPortAndServiceChanges(t *testing.T) {
	baseline := dnsComparisonSnapshot("192.0.2.1", "open", "https | nginx", "up")
	rotated := dnsComparisonSnapshot("192.0.2.2", "open", "https | nginx", "up")
	job := config.Job{DNSComparisonMode: config.DNSComparisonAggregate}

	if baseline.Hash() == rotated.Hash() {
		t.Fatal("historical snapshot hash unexpectedly ignored DNS and effective-host changes")
	}
	if got := snapshotHashForDNSMode(baseline, config.DNSComparisonAddressSensitive); got != baseline.Hash() {
		t.Fatal("address-sensitive mode no longer uses the historical snapshot hash")
	}
	if got, want := snapshotHashForDNSMode(rotated, job.DNSComparisonMode), snapshotHashForDNSMode(baseline, job.DNSComparisonMode); got != want {
		t.Fatalf("aggregate hash changed after DNS answer rotation: %s != %s", got, want)
	}
	if changes := diffForJob(baseline, rotated, false, job); len(changes) != 0 {
		t.Fatalf("DNS answer and host-state rotation emitted aggregate changes: %#v", changes)
	}
	if changes := Diff(baseline, rotated, false); len(changes) == 0 {
		t.Fatal("default address-sensitive diff stopped reporting answer rotation")
	}

	closed := dnsComparisonSnapshot("192.0.2.2", "", "", "up")
	changes := diffForJob(baseline, closed, false, job)
	if !hasChange(changes, "port|edge.example|tcp|443", "not-open") {
		t.Fatalf("aggregate mode suppressed a logical port closure: %#v", changes)
	}

	serviceChanged := dnsComparisonSnapshot("192.0.2.2", "open", "https | caddy", "up")
	changes = diffForJob(baseline, serviceChanged, false, job)
	if !hasChange(changes, "service|edge.example|tcp|443", "https | caddy") {
		t.Fatalf("aggregate mode suppressed a logical service change: %#v", changes)
	}
}

func TestAggregateDNSComparisonDoesNotHideDirectAddressReachability(t *testing.T) {
	const address = "192.0.2.1"
	baseline := dnsComparisonSnapshot(address, "open", "https | nginx", "up")
	current := dnsComparisonSnapshot(address, "open", "https | nginx", "down")
	for _, snapshot := range []*model.Snapshot{&baseline, &current} {
		snapshot.Scopes = append(snapshot.Scopes, model.Scope{Target: address, Protocol: "tcp", Ports: "443", ServiceDetection: true})
		snapshot.Normalize()
	}

	changes := diffForJob(baseline, current, false, config.Job{DNSComparisonMode: config.DNSComparisonAggregate})
	if !hasChange(changes, "host|192.0.2.1", "down") {
		t.Fatalf("aggregate mode hid reachability for an explicitly monitored address: %#v", changes)
	}
}

func TestAggregateDNSHostDownConfirmsLogicalPortLoss(t *testing.T) {
	const target = "edge.example"
	addresses := []string{"192.0.2.1", "192.0.2.2"}
	job := config.Job{Name: "aggregate-down", DNSComparisonMode: config.DNSComparisonAggregate, Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	baseline := model.Snapshot{
		Scopes: []model.Scope{{Target: target, Protocol: "tcp", Ports: "443"}},
		DNS:    map[string][]string{target: addresses},
		Units: []model.Unit{{Target: target, Protocol: "tcp", Addresses: addresses, Ports: []model.PortState{{
			Port: 443, State: "open", Evidence: addresses,
		}}}},
		HostStates: []model.HostState{{Address: addresses[0], State: "up"}, {Address: addresses[1], State: "up"}},
	}
	state := model.JobState{Baseline: &baseline, BaselineScanID: "baseline", BaselineConfigHash: "hash", Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{}, Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{}, FingerprintCandidates: map[string]model.ValueCount{}}
	down := model.Snapshot{
		Scopes: []model.Scope{{Target: target, Protocol: "tcp", Ports: "443"}},
		DNS:    map[string][]string{target: addresses},
		Hosts: []model.HostObservation{
			{Address: addresses[0], Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"}}},
			{Address: addresses[1], Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"}}},
		},
	}
	for i, want := range []string{"scan-anomaly", "changes-detected"} {
		events, changes, err := processSuccessWithChanges(&state, job, scan(fmt.Sprintf("down-%d", i+1), down))
		if err != nil || len(events) != 1 || events[0].Type != want {
			t.Fatalf("aggregate explicit-down scan %d: events=%#v changes=%#v err=%v, want %s", i+1, events, changes, err, want)
		}
		if i == 0 && len(changes) != 0 {
			t.Fatalf("first total-loss candidate reported changes: %#v", changes)
		}
		if i == 1 && (len(changes) != 1 || changes[0].Key != "port|"+target+"|tcp|443" || changes[0].New != "not-open") {
			t.Fatalf("confirmed aggregate port loss changes = %#v", changes)
		}
	}

	// If just the address that supplied a port is down and another configured
	// DNS backend remains up, the logical port still closes after confirmation;
	// the backend's individual host transition stays hidden in aggregate mode.
	baseline = model.Snapshot{
		Scopes:     []model.Scope{{Target: target, Protocol: "tcp", Ports: "443"}},
		DNS:        map[string][]string{target: addresses},
		Units:      []model.Unit{{Target: target, Protocol: "tcp", Addresses: addresses, Ports: []model.PortState{{Port: 443, State: "open", Evidence: []string{addresses[0]}}}}},
		HostStates: []model.HostState{{Address: addresses[0], State: "up"}, {Address: addresses[1], State: "up"}},
	}
	state = model.JobState{Baseline: &baseline, BaselineScanID: "baseline", BaselineConfigHash: "hash", Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{}, Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{}, FingerprintCandidates: map[string]model.ValueCount{}}
	partialDown := model.Snapshot{
		Scopes: []model.Scope{{Target: target, Protocol: "tcp", Ports: "443"}},
		DNS:    map[string][]string{target: addresses},
		Hosts: []model.HostObservation{
			{Address: addresses[0], Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"}}},
			{Address: addresses[1], Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}},
		},
	}
	if events, _, err := processSuccessWithChanges(&state, job, scan("backend-down-1", partialDown)); err != nil || len(events) != 1 || events[0].Type != "scan-anomaly" {
		t.Fatalf("first single-backend loss = %#v, %v", events, err)
	}
	events, changes, err := processSuccessWithChanges(&state, job, scan("backend-down-2", partialDown))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" || len(changes) != 1 || changes[0].Key != "port|"+target+"|tcp|443" {
		t.Fatalf("confirmed single-backend logical port loss = events %#v changes %#v err %v", events, changes, err)
	}

	// Aggregate mode must not reinterpret explicitly configured IP targets as
	// logical DNS-only reachability.
	directBaseline := dnsComparisonSnapshot(addresses[0], "open", "https | edge", "up")
	directCurrent := dnsComparisonSnapshot(addresses[0], "", "", "down")
	for _, snapshot := range []*model.Snapshot{&directBaseline, &directCurrent} {
		snapshot.Scopes = append(snapshot.Scopes, model.Scope{Target: addresses[0], Protocol: "tcp", Ports: "443"})
		snapshot.Normalize()
	}
	if changes := diffForJob(directBaseline, directCurrent, false, job); !hasChange(changes, "host|"+addresses[0], "down") || hasChange(changes, "port|edge.example|tcp|443", "not-open") {
		t.Fatalf("aggregate mode changed direct-address host-down semantics: %#v", changes)
	}
}

func TestAggregateDNSComparisonAllowsBaselineConvergenceAcrossRotatingAnswers(t *testing.T) {
	first := dnsComparisonSnapshot("192.0.2.1", "open", "https | nginx", "up")
	second := dnsComparisonSnapshot("192.0.2.2", "open", "https | nginx", "up")
	state := model.JobState{FingerprintCandidates: map[string]model.ValueCount{}}

	if events := advanceCandidateWithDNSMode(&state, scan("dns-first", first), 2, false, config.DNSComparisonAggregate); len(events) != 0 {
		t.Fatalf("first baseline sample emitted events: %#v", events)
	}
	if state.CandidateCount != 1 || state.Baseline != nil {
		t.Fatalf("first sample state = candidate %d, baseline %#v", state.CandidateCount, state.Baseline)
	}
	events := advanceCandidateWithDNSMode(&state, scan("dns-second", second), 2, false, config.DNSComparisonAggregate)
	if len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("rotating DNS baseline did not converge: %#v", events)
	}
	if state.Baseline == nil || len(state.Baseline.Units) != 1 || len(state.Baseline.Units[0].Ports) != 1 {
		t.Fatalf("aggregate baseline lost the logical port surface: %#v", state.Baseline)
	}
	if got := state.Baseline.DNS["edge.example"]; len(got) != 1 || got[0] != "192.0.2.2" {
		t.Fatalf("converged baseline retained an earlier DNS answer instead of the latest evidence: %#v", got)
	}

	defaultState := model.JobState{FingerprintCandidates: map[string]model.ValueCount{}}
	advanceCandidate(&defaultState, scan("default-first", first), 2, false)
	advanceCandidate(&defaultState, scan("default-second", second), 2, false)
	if defaultState.CandidateCount != 1 || defaultState.Baseline != nil {
		t.Fatalf("default mode unexpectedly converged across DNS answer rotation: candidate=%d baseline=%#v", defaultState.CandidateCount, defaultState.Baseline)
	}
}

func TestAggregateDNSComparisonIsUsedBySuccessfulScanProcessing(t *testing.T) {
	job := config.NormalizeJob(config.Job{
		Name: "dns-aggregate", Targets: []string{"edge.example"},
		DNSComparisonMode: config.DNSComparisonAggregate,
		TCP:               &config.Protocol{Ports: "443", Mode: "connect"},
		Baseline:          config.Baseline{Samples: 2},
		Change:            config.Change{Confirmations: 1},
	})
	baseline := dnsComparisonSnapshot("192.0.2.1", "open", "https | nginx", "up")
	state := model.JobState{
		Baseline: &baseline, BaselineScanID: "baseline",
		BaselineConfigHash: job.SecurityHash(),
		Pending:            map[string]model.Pending{}, Incidents: map[string]model.Incident{},
		Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{},
		FingerprintCandidates: map[string]model.ValueCount{},
	}
	rotated := dnsComparisonSnapshot("192.0.2.2", "open", "https | nginx", "up")
	scan := model.Scan{
		ID: "rotated-answer", Job: job.Name, Status: "success", ConfigHash: job.SecurityHash(),
		FinishedAt: time.Now().UTC(), Snapshot: rotated,
	}
	events, changes, err := processSuccessWithChanges(&state, job, scan)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 || len(changes) != 0 {
		t.Fatalf("rotating DNS answer produced comparison output: events=%#v changes=%#v", events, changes)
	}
}

func hasChange(changes []model.Change, key, newValue string) bool {
	for _, change := range changes {
		if change.Key == key && change.New == newValue {
			return true
		}
	}
	return false
}
