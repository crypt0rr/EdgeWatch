package engine

import (
	"slices"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

func hostDownIncident(address string) model.Incident {
	key := "host|" + address
	return model.Incident{Change: model.Change{Key: key, Kind: "host", Target: address, Old: "up", New: "down", Severity: "warning"}, ScanID: "seed"}
}

// A host-state incident recovers only when a scan observes the host up
// again. An address that left a DNS name's answer was not scanned, so its
// incident is retired without a recovery while the DNS change reports the
// transition; an incomplete scan keeps it for a later complete scan.
func TestHostIncidentOfAddressThatLeftTheAnswerDoesNotRecover(t *testing.T) {
	job := dualStackJob(config.DNSComparisonAddressSensitive)
	key := "host|" + dualStackV6
	moved := func() model.Snapshot {
		snapshot := dualStackSnapshot(map[int][]string{443: {dualStackV4}})
		snapshot.DNS[dualStackTarget] = []string{dualStackV4}
		snapshot.Units[0].Addresses = []string{dualStackV4}
		snapshot.Hosts = snapshot.Hosts[:1]
		return snapshot
	}

	t.Run("complete scan", func(t *testing.T) {
		state := dualStackState(dualStackSnapshot(map[int][]string{443: {dualStackV4, dualStackV6}}), job)
		state.Incidents[key] = hostDownIncident(dualStackV6)
		state.Suppressed["host|"+dualStackV4] = 1
		events, changes, err := processSuccessWithChanges(&state, job, dualStackScan("left-answer", job, moved()))
		if err != nil || !slices.Equal(changeKeys(changes), []string{"dns|edge.example|" + dualStackV6}) {
			t.Fatalf("changes = %#v, %v", changes, err)
		}
		if recovered := recoveredChangeKeys(events); len(recovered) != 0 {
			t.Fatalf("an address outside the answer recovered %v: %#v", recovered, events)
		}
		if _, ok := state.Incidents[key]; ok {
			t.Fatalf("host incident of an address outside the answer stayed open: %#v", state.Incidents)
		}
		// The address that is still in the answer was observed.
		if state.Suppressed["host|"+dualStackV4] != 0 {
			t.Fatalf("suppression of an observed host = %#v", state.Suppressed)
		}
	})

	t.Run("incomplete scan", func(t *testing.T) {
		const other = "198.51.100.7"
		state := dualStackState(dualStackSnapshot(map[int][]string{443: {dualStackV4, dualStackV6}}), job)
		state.Incidents[key] = hostDownIncident(dualStackV6)
		current := moved()
		current.Scopes = append(current.Scopes, model.Scope{Target: other, Protocol: "tcp", Ports: "22,443"})
		current.Hosts = append(current.Hosts, model.HostObservation{Address: other, Status: "down", StatusReason: "no-response"})
		current.Normalize()
		result := dualStackScan("left-answer-incomplete", job, current)
		if !MarkIncompleteScan(&result) {
			t.Fatal("scan with an unreachable target was not incomplete")
		}
		events, _, err := processSuccessWithChanges(&state, job, result)
		if err != nil || len(recoveredChangeKeys(events)) != 0 {
			t.Fatalf("incomplete scan = %#v, %v", events, err)
		}
		if incident, ok := state.Incidents[key]; !ok || incident.RecoveryCount != 0 {
			t.Fatalf("incomplete scan changed the host incident: %#v", state.Incidents)
		}
	})
}

// A complete scan without host discovery for an address in its scope has no
// state for it, so the host incident of that address is kept, and a
// suppression stored without its change is not used up.
func TestHostIncidentWithoutObservedStateIsKept(t *testing.T) {
	const address = "192.0.2.61"
	job := config.Job{Name: "host-without-state", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	scopes := []model.Scope{{Target: address, Protocol: "tcp", Ports: "22"}, {Target: "192.0.2.62", Protocol: "tcp", Ports: "22"}}
	baseline := model.Snapshot{Scopes: scopes, HostStates: []model.HostState{{Address: address, State: "up"}}}
	state := model.JobState{
		Baseline: &baseline, BaselineScanID: "baseline", BaselineConfigHash: "hash",
		Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{"host|" + address: hostDownIncident(address)},
		Suppressed: map[string]int{"host|192.0.2.62": 1}, SuppressedChanges: map[string]model.Change{},
		FingerprintCandidates: map[string]model.ValueCount{},
	}
	current := model.Snapshot{
		Scopes: scopes,
		Hosts: []model.HostObservation{
			{Address: address, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up"}}},
			{Address: "192.0.2.62", Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up"}}},
		},
	}
	events, _, err := processSuccessWithChanges(&state, job, scan("no-host-state", current))
	if err != nil || len(events) != 0 {
		t.Fatalf("scan without host states = %#v, %v", events, err)
	}
	if incident, ok := state.Incidents["host|"+address]; !ok || incident.RecoveryCount != 0 {
		t.Fatalf("host incident without an observed state = %#v", state.Incidents)
	}
	if state.Suppressed["host|192.0.2.62"] != 1 {
		t.Fatalf("suppression of a host without an observed state = %#v", state.Suppressed)
	}
}

// While the total-loss guard compares host transitions only, a host
// incident that the scan has no state for is kept as well.
func TestTotalLossGuardKeepsUnobservedHostIncident(t *testing.T) {
	const live, gone = "192.0.2.71", "192.0.2.72"
	job := config.Job{Name: "guard-unobserved-host", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	scopes := []model.Scope{{Target: live, Protocol: "tcp", Ports: "22,443"}, {Target: gone, Protocol: "tcp", Ports: "22,443"}, {Target: "192.0.2.73", Protocol: "tcp", Ports: "22"}}
	baseline := model.Snapshot{
		Scopes:     scopes,
		Units:      []model.Unit{{Target: live, Protocol: "tcp", Addresses: []string{live}, Ports: []model.PortState{{Port: 443, State: "open"}}}},
		HostStates: []model.HostState{{Address: live, State: "up"}, {Address: gone, State: "up"}, {Address: "192.0.2.73", State: "up"}},
	}
	state := model.JobState{
		Baseline: &baseline, BaselineScanID: "baseline", BaselineConfigHash: "hash",
		Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{"host|192.0.2.73": hostDownIncident("192.0.2.73")},
		Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{},
		FingerprintCandidates: map[string]model.ValueCount{},
	}
	current := model.Snapshot{
		Scopes: scopes,
		Hosts: []model.HostObservation{
			{Address: live, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}},
			{Address: gone, Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"}}},
		},
	}
	events, changes, err := processSuccessWithChanges(&state, job, scan("guarded", current))
	if err != nil || !slices.Equal(changeKeys(changes), []string{"host|" + gone}) || len(recoveredChangeKeys(events)) != 0 {
		t.Fatalf("guarded scan = events %#v changes %#v err %v", events, changes, err)
	}
	if incident, ok := state.Incidents["host|192.0.2.73"]; !ok || incident.RecoveryCount != 0 {
		t.Fatalf("guarded scan changed an unobserved host incident: %#v", state.Incidents)
	}
}
