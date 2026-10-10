package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

const (
	liveHost = "192.0.2.31"
	downHost = "192.0.2.32"
)

var downHostScopes = []model.Scope{
	{Target: liveHost, Protocol: "tcp", Ports: "22,443,8080,9090", ServiceDetection: true},
	{Target: downHost, Protocol: "tcp", Ports: "22,443,8080,9090", ServiceDetection: true},
}

// downHostSnapshot is a complete Nmap result for two IP targets. The live
// host always exposes 443. downPorts are the ports of the second host, or
// nil when its host discovery completed down.
func downHostSnapshot(downPorts []model.PortState) model.Snapshot {
	snapshot := model.Snapshot{
		Scopes: downHostScopes,
		Units:  []model.Unit{{Target: liveHost, Protocol: "tcp", Addresses: []string{liveHost}, Ports: []model.PortState{{Port: 443, State: "open", Evidence: []string{liveHost}}}}},
		Hosts: []model.HostObservation{
			{Address: liveHost, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}},
		},
	}
	if downPorts == nil {
		snapshot.Hosts = append(snapshot.Hosts, model.HostObservation{Address: downHost, Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"}}})
	} else {
		ports := make([]model.PortState, 0, len(downPorts))
		for _, port := range downPorts {
			port.Evidence = []string{downHost}
			ports = append(ports, port)
		}
		snapshot.Units = append(snapshot.Units, model.Unit{Target: downHost, Protocol: "tcp", Addresses: []string{downHost}, Ports: ports})
		snapshot.Hosts = append(snapshot.Hosts, model.HostObservation{Address: downHost, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up"}}})
	}
	snapshot.Normalize()
	return snapshot
}

// downHostState returns a runtime state whose baseline expects 22 on the
// second host, with the given incidents open since openedAt.
func downHostState(openedAt time.Time, incidents ...model.Change) model.JobState {
	baseline := downHostSnapshot([]model.PortState{{Port: 22, State: "open", Service: "ssh | OpenSSH"}})
	completeHostDiscoveryStates(&baseline)
	state := model.JobState{
		Baseline: &baseline, BaselineScanID: "baseline", BaselineConfigHash: "hash",
		Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{},
		Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{},
		FingerprintCandidates: map[string]model.ValueCount{},
	}
	for _, change := range incidents {
		state.Incidents[change.Key] = model.Incident{Change: change, ScanID: "seed", OpenedAt: openedAt, LastSeenAt: openedAt}
	}
	return state
}

func recoveredChangeKeys(events []model.Event) []string {
	var keys []string
	for _, event := range events {
		if event.Type == "changes-recovered" {
			keys = append(keys, changeKeys(event.Changes)...)
		}
	}
	return keys
}

func detectedChangeKeys(events []model.Event) []string {
	var keys []string
	for _, event := range events {
		if event.Type == "changes-detected" {
			keys = append(keys, changeKeys(event.Changes)...)
		}
	}
	return keys
}

// A host that goes down shows none of its ports. Its open port incidents
// must neither recover while it is down nor reopen as new incidents when it
// returns unchanged: the scan never observed the ports change.
func TestPortIncidentOnDownHostDoesNotRecover(t *testing.T) {
	opened := model.Change{Key: "port|" + downHost + "|tcp|8080", Kind: "port", Target: downHost, Protocol: "tcp", Port: 8080, Old: "not-open", New: "open", Severity: "critical"}
	closed := model.Change{Key: "port|" + downHost + "|tcp|22", Kind: "port", Target: downHost, Protocol: "tcp", Port: 22, Old: "open", New: "not-open", Severity: "info"}
	for _, test := range []struct {
		name     string
		incident model.Change
		// returned is the second host's surface when it is up again, which
		// still differs from the baseline in the same way.
		returned []model.PortState
	}{
		{name: "unexpected open port", incident: opened, returned: []model.PortState{{Port: 22, State: "open", Service: "ssh | OpenSSH"}, {Port: 8080, State: "open"}}},
		{name: "closed baseline port", incident: closed, returned: []model.PortState{}},
	} {
		for _, confirmations := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s confirmations %d", test.name, confirmations), func(t *testing.T) {
				job := config.Job{Name: "down-host-recovery", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: confirmations}}
				openedAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
				state := downHostState(openedAt, test.incident)
				for i := 1; i <= confirmations+1; i++ {
					events, _, err := processSuccessWithChanges(&state, job, scan(fmt.Sprintf("down-%d", i), downHostSnapshot(nil)))
					if err != nil {
						t.Fatal(err)
					}
					if keys := recoveredChangeKeys(events); len(keys) != 0 {
						t.Fatalf("down scan %d recovered %v while the host was down: %#v", i, keys, events)
					}
					incident, ok := state.Incidents[test.incident.Key]
					if !ok || incident.RecoveryCount != 0 || !incident.OpenedAt.Equal(openedAt) {
						t.Fatalf("down scan %d changed the incident: %#v", i, state.Incidents)
					}
				}
				if _, ok := state.Incidents["host|"+downHost]; !ok {
					t.Fatalf("the host state change was not reported: %#v", state.Incidents)
				}

				events, _, err := processSuccessWithChanges(&state, job, scan("returned", downHostSnapshot(test.returned)))
				if err != nil {
					t.Fatal(err)
				}
				for _, key := range append(recoveredChangeKeys(events), detectedChangeKeys(events)...) {
					if strings.HasPrefix(key, "port|") {
						t.Fatalf("returned host with the same surface reported %s: %#v", key, events)
					}
				}
				incident, ok := state.Incidents[test.incident.Key]
				if !ok || !incident.OpenedAt.Equal(openedAt) || incident.ScanID != "seed" || incident.RecoveryCount != 0 {
					t.Fatalf("incident after the host returned = %#v, want the original incident", state.Incidents)
				}
			})
		}
	}
}

// The port of a host that is down is not observed in any way: a pending
// confirmation keeps its count, a suppression is not used up, and a service
// finding is not retired as if its port had closed.
func TestDownHostKeepsPendingSuppressedAndServiceFindings(t *testing.T) {
	pendingKey := "port|" + downHost + "|tcp|8080"
	suppressedKey := "port|" + downHost + "|tcp|9090"
	legacySuppressedKey := "port|" + downHost + "|tcp|443"
	serviceKey := "service|" + downHost + "|tcp|22"
	serviceChange := model.Change{Key: serviceKey, Kind: "service", Target: downHost, Protocol: "tcp", Port: 22, Old: "ssh | OpenSSH", New: "ssh | Dropbear", Severity: "warning"}
	liveSuppressedKey := "port|" + liveHost + "|tcp|9090"
	seed := func() model.JobState {
		state := downHostState(time.Unix(1, 0), serviceChange)
		state.Pending[pendingKey] = model.Pending{Change: model.Change{Key: pendingKey, Kind: "port", Target: downHost, Protocol: "tcp", Port: 8080, Old: "not-open", New: "open"}, Count: 1}
		state.Suppressed[suppressedKey] = 1
		state.SuppressedChanges[suppressedKey] = model.Change{Key: suppressedKey, Kind: "port", Target: downHost, Protocol: "tcp", Port: 9090, Old: "not-open", New: "open"}
		// A suppression without its change, as older releases stored it.
		state.Suppressed[legacySuppressedKey] = 1
		state.Suppressed[liveSuppressedKey] = 1
		state.SuppressedChanges[liveSuppressedKey] = model.Change{Key: liveSuppressedKey, Kind: "port", Target: liveHost, Protocol: "tcp", Port: 9090, Old: "not-open", New: "open"}
		return state
	}
	job := config.Job{Name: "down-host-findings", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 2}}
	assertKept := func(t *testing.T, state model.JobState) {
		t.Helper()
		if pending, ok := state.Pending[pendingKey]; !ok || pending.Count != 1 {
			t.Fatalf("pending confirmation on the down host = %#v", state.Pending)
		}
		if state.Suppressed[suppressedKey] != 1 || state.Suppressed[legacySuppressedKey] != 1 {
			t.Fatalf("suppressions on the down host = %#v", state.Suppressed)
		}
		if _, ok := state.SuppressedChanges[suppressedKey]; !ok {
			t.Fatalf("suppressed change on the down host = %#v", state.SuppressedChanges)
		}
		if incident, ok := state.Incidents[serviceKey]; !ok || incident.RecoveryCount != 0 {
			t.Fatalf("service incident on the down host = %#v", state.Incidents)
		}
		// The live host was observed, so its suppression is used up.
		if state.Suppressed[liveSuppressedKey] != 0 {
			t.Fatalf("suppression on the live host = %#v", state.Suppressed)
		}
	}

	t.Run("complete scan", func(t *testing.T) {
		state := seed()
		events, _, err := processSuccessWithChanges(&state, job, scan("down", downHostSnapshot(nil)))
		if err != nil || len(recoveredChangeKeys(events)) != 0 {
			t.Fatalf("down scan = %#v, %v", events, err)
		}
		assertKept(t, state)
	})

	t.Run("incomplete scan", func(t *testing.T) {
		state := seed()
		const timedOut = "192.0.2.33"
		incomplete := downHostSnapshot(nil)
		incomplete.Scopes = append(incomplete.Scopes, model.Scope{Target: timedOut, Protocol: "tcp", Ports: "22"})
		incomplete.Hosts = append(incomplete.Hosts, model.HostObservation{Address: timedOut, Status: "unreachable", StatusReason: "nmap-host-timeout", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "nmap-host-timeout"}}})
		incomplete.Normalize()
		result := scan("down-and-incomplete", incomplete)
		if !MarkIncompleteScan(&result) {
			t.Fatal("scan with a timed-out host was not incomplete")
		}
		events, _, err := processSuccessWithChanges(&state, job, result)
		if err != nil || len(recoveredChangeKeys(events)) != 0 {
			t.Fatalf("incomplete down scan = %#v, %v", events, err)
		}
		assertKept(t, state)
	})

	t.Run("host returns", func(t *testing.T) {
		state := seed()
		if _, _, err := processSuccessWithChanges(&state, job, scan("down", downHostSnapshot(nil))); err != nil {
			t.Fatal(err)
		}
		// Back up with the changed fingerprint and 8080 open: the pending
		// change is confirmed and the service incident continues.
		events, _, err := processSuccessWithChanges(&state, job, scan("returned", downHostSnapshot([]model.PortState{{Port: 22, State: "open", Service: "ssh | Dropbear"}, {Port: 8080, State: "open"}})))
		if err != nil {
			t.Fatal(err)
		}
		if detected := detectedChangeKeys(events); len(detected) != 1 || detected[0] != pendingKey {
			t.Fatalf("returned host confirmed %v, want only %s: %#v", detected, pendingKey, events)
		}
		if incident, ok := state.Incidents[serviceKey]; !ok || !incident.OpenedAt.Equal(time.Unix(1, 0)) {
			t.Fatalf("service incident after the host returned = %#v", state.Incidents)
		}
		// Once the scan observes the second host again, its suppressions
		// count down.
		if state.Suppressed[suppressedKey] != 0 || state.Suppressed[legacySuppressedKey] != 0 {
			t.Fatalf("suppressions after the host returned = %#v", state.Suppressed)
		}
	})
}

// A DNS name's port that opened unexpectedly may be on any of its
// addresses, so while one of them is down its incident cannot recover. In
// aggregate mode the name's addresses are not monitored individually, and
// the port is compared across the addresses that are up.
func TestDNSPortIncidentWaitsForDownAddress(t *testing.T) {
	key := "port|" + dualStackTarget + "|tcp|22"
	for _, test := range []struct {
		mode    string
		recover bool
	}{
		{mode: config.DNSComparisonAddressSensitive},
		{mode: config.DNSComparisonAggregate, recover: true},
	} {
		t.Run(test.mode, func(t *testing.T) {
			job := dualStackJob(test.mode)
			state := dualStackState(dualStackSnapshot(map[int][]string{443: {dualStackV4, dualStackV6}}), job)
			state.Incidents[key] = model.Incident{Change: model.Change{Key: key, Kind: "port", Target: dualStackTarget, Protocol: "tcp", Port: 22, Old: "not-open", New: "open", Severity: "critical"}, ScanID: "seed"}
			current := dualStackSnapshot(map[int][]string{443: {dualStackV4}})
			current.Hosts[1] = model.HostObservation{Address: dualStackV6, SourceTargets: []string{dualStackTarget}, Status: "unreachable", StatusReason: "no-response", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"}}}
			events, _, err := processSuccessWithChanges(&state, job, dualStackScan("ipv6-down", job, current))
			if err != nil {
				t.Fatal(err)
			}
			recovered := strings.Join(recoveredChangeKeys(events), ",") == key
			if _, open := state.Incidents[key]; recovered != test.recover || open == test.recover {
				t.Fatalf("incident with one address down: events %#v incidents %#v, want recovered=%t", events, state.Incidents, test.recover)
			}
		})
	}
}

func TestPortChangeFromKey(t *testing.T) {
	for key, want := range map[string]model.Change{
		"port|192.0.2.1|tcp|22":          {Key: "port|192.0.2.1|tcp|22", Kind: "port", Target: "192.0.2.1", Protocol: "tcp", Port: 22},
		"service|2001:db8::1|udp|53":     {Key: "service|2001:db8::1|udp|53", Kind: "service", Target: "2001:db8::1", Protocol: "udp", Port: 53},
		"port|edge.example|tcp|notaport": {},
		"host|192.0.2.1":                 {},
		"port|tcp|22":                    {},
	} {
		got, ok := portChangeFromKey(key)
		if ok != (want.Key != "") || got != want {
			t.Errorf("portChangeFromKey(%q) = %#v, %t; want %#v", key, got, ok, want)
		}
	}
}
