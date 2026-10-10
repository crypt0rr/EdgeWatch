package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

// How a scan saw a tracked finding.
const (
	// seenObserved: the scan observed the finding back in its baseline
	// state, so it recovers, resets its pending change and uses up its
	// suppression.
	seenObserved = "observed"
	// seenReported: the scan reported the finding's change again.
	seenReported = "reported"
	// seenUnobserved: the scan did not observe the finding, which keeps its
	// state.
	seenUnobserved = "unobserved"
	// seenRetired: the scan shows that the finding cannot be compared any
	// more, so it leaves the state without a recovery.
	seenRetired = "retired"
)

const (
	sweepFingerprint = "https | nginx"
	sweepChanged     = "https | apache"
	sweepLive        = "192.0.2.80"
	sweepWatched     = "192.0.2.81"
)

type sweepFinding struct {
	kind   string
	change model.Change
}

// sweepHost describes the scanned state of one address: "up", "down" when
// host discovery completed down, "timeout" when its coverage did not
// complete, or "scanned" when its ports were scanned without host
// discovery.
type sweepHost struct{ address, state string }

func sweepHostObservations(hosts []sweepHost, exposure map[int][]string, sourceTarget string) []model.HostObservation {
	var observations []model.HostObservation
	for _, host := range hosts {
		observation := model.HostObservation{Address: host.address}
		if sourceTarget != "" {
			observation.SourceTargets = []string{sourceTarget}
		}
		switch host.state {
		case "up":
			observation.Status = "up"
			var ports []model.PortObservation
			for port, addresses := range exposure {
				for _, address := range addresses {
					if address == host.address {
						ports = append(ports, model.PortObservation{Port: port, State: "open"})
					}
				}
			}
			observation.Protocols = []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up", Ports: ports}}
		case "scanned":
			observation.Status = "up"
			observation.Protocols = []model.ProtocolObservation{{Protocol: "tcp", Status: "up"}}
		case "down":
			observation.Status, observation.StatusReason = "unreachable", "no-response"
			observation.Protocols = []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "no-response", DiscoveryState: "down"}}
		case "timeout":
			observation.Status, observation.StatusReason = "unreachable", "nmap-host-timeout"
			observation.Protocols = []model.ProtocolObservation{{Protocol: "tcp", Status: "unreachable", StatusReason: "nmap-host-timeout"}}
		}
		observations = append(observations, observation)
	}
	return observations
}

func sweepPorts(exposure map[int][]string) []model.PortState {
	var ports []model.PortState
	for port, addresses := range exposure {
		if len(addresses) > 0 {
			ports = append(ports, model.PortState{Port: port, State: "open", Service: sweepFingerprint, Evidence: append([]string(nil), addresses...)})
		}
	}
	return ports
}

// sweepDNSSnapshot is a complete Nmap result for edge.example. answer is
// its DNS answer, and exposure the addresses that expose each port.
func sweepDNSSnapshot(answer []string, exposure map[int][]string, hosts ...sweepHost) model.Snapshot {
	snapshot := model.Snapshot{
		Scopes: []model.Scope{{Target: dualStackTarget, Protocol: "tcp", Ports: "22,443,8443", ServiceDetection: true}},
		DNS:    map[string][]string{dualStackTarget: answer},
		Units:  []model.Unit{{Target: dualStackTarget, Protocol: "tcp", Addresses: answer, Ports: sweepPorts(exposure)}},
		Hosts:  sweepHostObservations(hosts, exposure, dualStackTarget),
	}
	snapshot.Normalize()
	return snapshot
}

// sweepIPSnapshot is a complete Nmap result for two IP targets; exposure
// maps each port to the addresses that expose it.
func sweepIPSnapshot(exposure map[int][]string, hosts ...sweepHost) model.Snapshot {
	snapshot := model.Snapshot{}
	for _, address := range []string{sweepLive, sweepWatched} {
		snapshot.Scopes = append(snapshot.Scopes, model.Scope{Target: address, Protocol: "tcp", Ports: "22,443,8443", ServiceDetection: true})
		ports := map[int][]string{}
		for port, addresses := range exposure {
			for _, exposed := range addresses {
				if exposed == address {
					ports[port] = []string{address}
				}
			}
		}
		if len(ports) > 0 {
			snapshot.Units = append(snapshot.Units, model.Unit{Target: address, Protocol: "tcp", Addresses: []string{address}, Ports: sweepPorts(ports)})
		}
	}
	snapshot.Hosts = sweepHostObservations(hosts, exposure, "")
	snapshot.Normalize()
	return snapshot
}

// TestRecoveryRequiresPositiveObservation sweeps the kinds of tracked
// findings against the ways a scan can see the address they depend on. A
// finding recovers, loses its pending change or uses up its suppression only
// when the scan observed it in its baseline state; one that the scan did not
// observe keeps its state or, where the scan shows it cannot be compared
// any more, is retired without a recovery.
func TestRecoveryRequiresPositiveObservation(t *testing.T) {
	dnsBaseline := sweepDNSSnapshot([]string{dualStackV4, dualStackV6}, map[int][]string{443: {dualStackV4, dualStackV6}, 8443: {dualStackV6}}, sweepHost{dualStackV4, "up"}, sweepHost{dualStackV6, "up"})
	dnsFindings := []sweepFinding{
		{kind: "port opened", change: model.Change{Key: "port|" + dualStackTarget + "|tcp|22", Kind: "port", Target: dualStackTarget, Protocol: "tcp", Port: 22, Old: "not-open", New: "open", Severity: "critical"}},
		{kind: "port closed", change: model.Change{Key: "port|" + dualStackTarget + "|tcp|8443", Kind: "port", Target: dualStackTarget, Protocol: "tcp", Port: 8443, Old: "open", New: "not-open", Severity: "info"}},
		{kind: "service", change: model.Change{Key: "service|" + dualStackTarget + "|tcp|8443", Kind: "service", Target: dualStackTarget, Protocol: "tcp", Port: 8443, Old: sweepFingerprint, New: sweepChanged, Severity: "warning"}},
		{kind: "port-address", change: model.Change{Key: portAddressChangeKey(443, dualStackV6), Kind: "port-address", Target: dualStackTarget, Protocol: "tcp", Port: 443, Address: dualStackV6, Old: "open", New: "not-open", Severity: "info"}},
		{kind: "host", change: model.Change{Key: "host|" + dualStackV6, Kind: "host", Target: dualStackV6, Old: "up", New: "down", Severity: "warning"}},
		{kind: "dns", change: model.Change{Key: "dns|" + dualStackTarget + "|" + dualStackV6, Kind: "dns-removed", Target: dualStackTarget, Old: dualStackV6, Severity: "warning"}},
	}
	ipBaseline := sweepIPSnapshot(map[int][]string{443: {sweepLive}, 8443: {sweepWatched}}, sweepHost{sweepLive, "up"}, sweepHost{sweepWatched, "up"})
	ipFindings := []sweepFinding{
		{kind: "port opened", change: model.Change{Key: "port|" + sweepWatched + "|tcp|22", Kind: "port", Target: sweepWatched, Protocol: "tcp", Port: 22, Old: "not-open", New: "open", Severity: "critical"}},
		{kind: "port closed", change: model.Change{Key: "port|" + sweepWatched + "|tcp|8443", Kind: "port", Target: sweepWatched, Protocol: "tcp", Port: 8443, Old: "open", New: "not-open", Severity: "info"}},
		{kind: "service", change: model.Change{Key: "service|" + sweepWatched + "|tcp|8443", Kind: "service", Target: sweepWatched, Protocol: "tcp", Port: 8443, Old: sweepFingerprint, New: sweepChanged, Severity: "warning"}},
		{kind: "host", change: model.Change{Key: "host|" + sweepWatched, Kind: "host", Target: sweepWatched, Old: "up", New: "down", Severity: "warning"}},
	}
	for _, fixture := range []struct {
		name     string
		job      config.Job
		baseline model.Snapshot
		findings []sweepFinding
		states   []struct {
			name    string
			current model.Snapshot
			seen    map[string]string
		}
	}{
		{
			name: "DNS name", job: dualStackJob(config.DNSComparisonAddressSensitive), baseline: dnsBaseline, findings: dnsFindings,
			states: []struct {
				name    string
				current model.Snapshot
				seen    map[string]string
			}{
				{name: "up", current: dnsBaseline, seen: map[string]string{
					"port opened": seenObserved, "port closed": seenObserved, "service": seenObserved, "port-address": seenObserved, "host": seenObserved, "dns": seenObserved,
				}},
				{name: "down", current: sweepDNSSnapshot([]string{dualStackV4, dualStackV6}, map[int][]string{443: {dualStackV4}}, sweepHost{dualStackV4, "up"}, sweepHost{dualStackV6, "down"}), seen: map[string]string{
					// The DNS answer was resolved, so it was observed.
					"port opened": seenUnobserved, "port closed": seenUnobserved, "service": seenUnobserved, "port-address": seenRetired, "host": seenReported, "dns": seenObserved,
				}},
				{name: "incomplete", current: sweepDNSSnapshot([]string{dualStackV4, dualStackV6}, map[int][]string{443: {dualStackV4}}, sweepHost{dualStackV4, "up"}, sweepHost{dualStackV6, "timeout"}), seen: map[string]string{
					"port opened": seenUnobserved, "port closed": seenUnobserved, "service": seenUnobserved, "port-address": seenUnobserved, "host": seenUnobserved, "dns": seenUnobserved,
				}},
				{name: "left the answer", current: sweepDNSSnapshot([]string{dualStackV4}, map[int][]string{443: {dualStackV4}}, sweepHost{dualStackV4, "up"}), seen: map[string]string{
					// The name now resolves to the live address alone, which
					// does not expose 22: the name's port was observed.
					"port opened": seenObserved, "port closed": seenReported, "service": seenRetired, "port-address": seenRetired, "host": seenRetired, "dns": seenReported,
				}},
			},
		},
		{
			name: "IP target", job: config.Job{Name: "sweep-ip", Baseline: config.Baseline{Samples: 1}}, baseline: ipBaseline, findings: ipFindings,
			states: []struct {
				name    string
				current model.Snapshot
				seen    map[string]string
			}{
				{name: "up", current: ipBaseline, seen: map[string]string{
					"port opened": seenObserved, "port closed": seenObserved, "service": seenObserved, "host": seenObserved,
				}},
				{name: "down", current: sweepIPSnapshot(map[int][]string{443: {sweepLive}}, sweepHost{sweepLive, "up"}, sweepHost{sweepWatched, "down"}), seen: map[string]string{
					"port opened": seenUnobserved, "port closed": seenUnobserved, "service": seenUnobserved, "host": seenReported,
				}},
				{name: "incomplete", current: sweepIPSnapshot(map[int][]string{443: {sweepLive}}, sweepHost{sweepLive, "up"}, sweepHost{sweepWatched, "timeout"}), seen: map[string]string{
					"port opened": seenUnobserved, "port closed": seenUnobserved, "service": seenUnobserved, "host": seenUnobserved,
				}},
				// Without host discovery the scan has no state for the host,
				// but it observed the host's ports.
				{name: "no host discovery", current: sweepIPSnapshot(map[int][]string{443: {sweepLive}}, sweepHost{sweepLive, "up"}, sweepHost{sweepWatched, "scanned"}), seen: map[string]string{
					"port opened": seenObserved, "port closed": seenReported, "service": seenRetired, "host": seenUnobserved,
				}},
				// No port is positive: the total-loss guard compares host
				// states only, and none changed.
				{name: "total-loss guard", current: sweepIPSnapshot(nil, sweepHost{sweepLive, "up"}, sweepHost{sweepWatched, "up"}), seen: map[string]string{
					"port opened": seenUnobserved, "port closed": seenUnobserved, "service": seenUnobserved, "host": seenUnobserved,
				}},
			},
		},
	} {
		for _, observed := range fixture.states {
			for _, finding := range fixture.findings {
				want := observed.seen[finding.kind]
				for _, form := range []string{"incident", "pending", "suppression"} {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", fixture.name, observed.name, finding.kind, form), func(t *testing.T) {
						got := sweepOutcome(t, fixture.job, fixture.baseline, observed.current, finding.change, form)
						if got != want {
							t.Fatalf("finding was %s, want %s", got, want)
						}
					})
				}
			}
		}
	}
}

// sweepOutcome tracks change in one form, runs one scan of current, and
// classifies what the scan did with it.
func sweepOutcome(t *testing.T, job config.Job, baseline, current model.Snapshot, change model.Change, form string) string {
	t.Helper()
	state := model.JobState{
		Baseline: &baseline, BaselineScanID: "baseline", BaselineConfigHash: job.SecurityHash(),
		Pending: map[string]model.Pending{}, Incidents: map[string]model.Incident{},
		Suppressed: map[string]int{}, SuppressedChanges: map[string]model.Change{},
		FingerprintCandidates: map[string]model.ValueCount{},
	}
	baselineCopy := cloneSnapshot(baseline)
	completeHostDiscoveryStates(&baselineCopy)
	state.Baseline = &baselineCopy
	seeded := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	// One confirmation recovers an incident in one scan; two confirmations
	// keep a pending change pending until a scan reports it again.
	job.Change.Confirmations = 1
	switch form {
	case "incident":
		state.Incidents[change.Key] = model.Incident{Change: change, ScanID: "seed", OpenedAt: seeded, LastSeenAt: seeded}
	case "pending":
		job.Change.Confirmations = 2
		state.Pending[change.Key] = model.Pending{Change: change, Count: 1}
	case "suppression":
		state.Suppressed[change.Key] = 1
		state.SuppressedChanges[change.Key] = change
	}
	result := model.Scan{ID: "sweep", Job: job.Name, Status: "success", ConfigHash: job.SecurityHash(), Snapshot: cloneSnapshot(current), FinishedAt: seeded.Add(time.Hour)}
	MarkIncompleteScan(&result)
	events, changes, err := processSuccessWithChanges(&state, job, result)
	if err != nil {
		t.Fatal(err)
	}
	recovered := false
	for _, key := range recoveredChangeKeys(events) {
		recovered = recovered || key == change.Key
	}
	reported := false
	for _, current := range changes {
		reported = reported || current.Key == change.Key
	}
	switch form {
	case "incident":
		incident, open := state.Incidents[change.Key]
		switch {
		case recovered && !open:
			return seenObserved
		case reported && open && incident.LastSeenAt.Equal(result.FinishedAt) && incident.OpenedAt.Equal(seeded):
			return seenReported
		case !recovered && open && incident.RecoveryCount == 0 && incident.LastSeenAt.Equal(seeded):
			return seenUnobserved
		case !recovered && !open && !reported:
			return seenRetired
		}
		t.Fatalf("unclassified incident outcome: recovered=%t open=%t reported=%t incident=%#v events=%#v", recovered, open, reported, incident, events)
	case "pending":
		if recovered {
			t.Fatalf("a pending change was recovered: %#v", events)
		}
		pending, waiting := state.Pending[change.Key]
		_, opened := state.Incidents[change.Key]
		switch {
		case reported && opened:
			return seenReported
		case waiting && pending.Count == 1:
			return seenUnobserved
		case !waiting && !opened && !reported:
			// A pending change that the scan observed is reset; one that
			// it retired is dropped: both leave the state without an event.
			if sweepRetires(t, job, baseline, current, change) {
				return seenRetired
			}
			return seenObserved
		}
		t.Fatalf("unclassified pending outcome: pending=%#v opened=%t reported=%t", state.Pending, opened, reported)
	case "suppression":
		if recovered {
			t.Fatalf("a suppressed change was recovered: %#v", events)
		}
		remaining, suppressed := state.Suppressed[change.Key]
		switch {
		case suppressed && remaining == 0 && reported:
			return seenReported
		case suppressed && remaining == 0:
			return seenObserved
		case suppressed && remaining == 1:
			return seenUnobserved
		case !suppressed:
			return seenRetired
		}
		t.Fatalf("unclassified suppression outcome: %#v", state.Suppressed)
	}
	return ""
}

// sweepRetires tells a retired pending change from a reset one: an incident
// of the same change is retired, without a recovery, by the same scan.
func sweepRetires(t *testing.T, job config.Job, baseline, current model.Snapshot, change model.Change) bool {
	t.Helper()
	return sweepOutcome(t, job, baseline, current, change, "incident") == seenRetired
}
