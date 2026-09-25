package scanner

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestPlanCountsEveryResolvedDNSAddressForProbeTotals(t *testing.T) {
	addresses := make([]net.IP, 0, 40)
	for i := 1; i <= 40; i++ {
		addresses = append(addresses, net.ParseIP(fmt.Sprintf("192.0.2.%d", i)))
	}
	n := New("nmap")
	n.Resolver = fakeResolver{ips: addresses}
	job := config.NormalizeJob(config.Job{
		Name: "dns-budget", Targets: []string{"edge.example"}, MaxExpandedHosts: 64,
		TCP: &config.Protocol{Ports: "1-65535", Mode: "connect"},
	})
	plan, err := n.Plan(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	want := int64(40 * 65535)
	if plan.TotalProbes != want {
		t.Fatalf("resolved plan probes = %d, want %d", plan.TotalProbes, want)
	}
	preflight, err := config.EstimateJobWork(job)
	if err != nil {
		t.Fatal(err)
	}
	if preflight.Probes >= plan.TotalProbes {
		t.Fatalf("preflight estimate %d unexpectedly accounts for all resolved DNS work %d", preflight.Probes, plan.TotalProbes)
	}
}

func TestPlanPinsDNSAndChunksBroadPorts(t *testing.T) {
	n := New("nmap")
	n.Resolver = fakeResolver{ips: []net.IP{net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.1")}}
	job := config.NormalizeJob(config.Job{Name: "broad", Targets: []string{"Example.COM"}, MaxExpandedHosts: 2, TCP: &config.Protocol{Ports: "1-65535", Mode: "syn"}})
	plan, err := n.Plan(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) < 2 || plan.TotalUnits != len(plan.Units) {
		t.Fatalf("plan did not chunk full range: units=%d total=%d", len(plan.Units), plan.TotalUnits)
	}
	if got := plan.DNS["example.com"]; len(got) != 2 || got[0] != "192.0.2.1" {
		t.Fatalf("DNS expansion was not pinned deterministically: %#v", got)
	}
	for _, unit := range plan.Units {
		if unit.PortCount > maxWorkUnitPorts || unit.Probes > maxWorkUnitProbes {
			t.Fatalf("work unit exceeds checkpoint bound: %#v", unit)
		}
	}
}

func TestSplitWorkUnitAddressesThenPorts(t *testing.T) {
	unit := WorkUnit{Protocol: "tcp", Addresses: []string{"192.0.2.1", "192.0.2.2"}, Ports: "1-65535", PortCount: 65535, Probes: 131070, Targets: []ResolvedTarget{{Name: "example", Addresses: []string{"192.0.2.1", "192.0.2.2"}}}}
	first, second, ok := SplitWorkUnit(unit)
	if !ok || len(first.Addresses) != 1 || len(second.Addresses) != 1 {
		t.Fatalf("expected address split: %#v %#v %v", first, second, ok)
	}
	unit.Addresses = []string{"192.0.2.1"}
	first, second, ok = SplitWorkUnit(unit)
	if !ok || first.PortCount+second.PortCount != unit.PortCount || first.PortCount < minRetryPortChunk || second.PortCount < minRetryPortChunk {
		t.Fatalf("expected bounded port split: %#v %#v %v", first, second, ok)
	}
	// A range just above the retry bound must still be split. Refusing a
	// 257-port unit would make a timed-out target retry forever until the
	// no-progress guard stalls the cycle, even though two smaller invocations
	// are available.
	unit.Ports = "1-257"
	unit.PortCount = 257
	unit.Probes = 257
	first, second, ok = SplitWorkUnit(unit)
	if !ok || first.PortCount > minRetryPortChunk || second.PortCount > minRetryPortChunk || first.PortCount+second.PortCount != 257 {
		t.Fatalf("expected 257-port unit to split down to retry bound: %#v %#v %v", first, second, ok)
	}
}

func TestMergeWorkSnapshotsDeduplicatesChunkAddresses(t *testing.T) {
	plan := WorkPlan{Scopes: []model.Scope{{Target: "host", Protocol: "tcp", Ports: "1-2"}}, DNS: map[string][]string{}}
	plan.Units = []WorkUnit{{Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1}, {Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "2", PortCount: 1}}
	result := MergeWorkSnapshots(plan, []model.Snapshot{{Units: []model.Unit{{Target: "host", Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: []model.PortState{{Port: 1, State: "open", Evidence: []string{"192.0.2.1"}}}}}}, {Units: []model.Unit{{Target: "host", Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: []model.PortState{{Port: 2, State: "open", Evidence: []string{"192.0.2.1"}}}}}}})
	if len(result.Units) != 1 || len(result.Units[0].Addresses) != 1 || len(result.Units[0].Ports) != 2 {
		t.Fatalf("merged snapshot was not normalized: %#v", result)
	}
}

func TestMergeWorkSnapshotsDeduplicatesChunkedHostProtocols(t *testing.T) {
	plan := WorkPlan{
		Scopes: []model.Scope{{Target: "host", Protocol: "tcp", Ports: "1-8192"}},
		DNS:    map[string][]string{},
	}
	fragments := []model.Snapshot{
		{Hosts: []model.HostObservation{{
			Address: "198.51.100.1",
			Protocols: []model.ProtocolObservation{{
				Protocol: "tcp", ScannedPorts: "1-4096", ScannedPortCount: 4096,
				Ports: []model.PortObservation{{Port: 22, State: "open"}},
			}},
		}}},
		{Hosts: []model.HostObservation{{
			Address: "198.51.100.1",
			Protocols: []model.ProtocolObservation{{
				Protocol: "tcp", ScannedPorts: "4097-8192", ScannedPortCount: 4096,
				Ports: []model.PortObservation{{Port: 443, State: "open|filtered"}},
			}},
		}}},
	}
	result := MergeWorkSnapshots(plan, fragments)
	if len(result.Hosts) != 1 || len(result.Hosts[0].Protocols) != 1 {
		t.Fatalf("merged host protocols = %#v", result.Hosts)
	}
	protocol := result.Hosts[0].Protocols[0]
	if protocol.ScannedPorts != "1-8192" || protocol.ScannedPortCount != 8192 || len(protocol.Ports) != 2 {
		t.Fatalf("merged protocol scope/evidence = %#v", protocol)
	}
}

// fullRangeOpenFragments returns the checkpoints produced by a full-range
// scan of one host with every TCP port open: sixteen 4096-port chunks.
func fullRangeOpenFragments(address string) []model.Snapshot {
	var fragments []model.Snapshot
	for start := 1; start <= 65535; start += maxWorkUnitPorts {
		end := min(start+maxWorkUnitPorts-1, 65535)
		unit := model.Unit{Target: address, Protocol: "tcp", Addresses: []string{address}}
		for port := start; port <= end; port++ {
			unit.Ports = append(unit.Ports, model.PortState{Port: port, State: "open", Evidence: []string{address}})
		}
		fragments = append(fragments, model.Snapshot{Units: []model.Unit{unit}})
	}
	return fragments
}

func TestMergeWorkSnapshotsFoldsRepeatedPortsDeterministically(t *testing.T) {
	plan := WorkPlan{Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "22"}}, DNS: map[string][]string{"edge.example": {"192.0.2.1", "192.0.2.2"}}}
	fragment := func(address, state, service string) model.Snapshot {
		return model.Snapshot{Units: []model.Unit{{Target: "edge.example", Protocol: "tcp", Addresses: []string{address}, Ports: []model.PortState{{Port: 22, State: state, Service: service, Evidence: []string{address}}}}}}
	}
	result := MergeWorkSnapshots(plan, []model.Snapshot{
		fragment("192.0.2.2", "open|filtered", ""),
		fragment("192.0.2.1", "open", "ssh"),
		fragment("192.0.2.2", "open|filtered", "other"),
	})
	if len(result.Units) != 1 || len(result.Units[0].Ports) != 1 {
		t.Fatalf("repeated port was not folded into one record: %#v", result.Units)
	}
	port := result.Units[0].Ports[0]
	if port.State != "open" || port.Service != "ssh" || len(port.Evidence) != 2 || port.Evidence[0] != "192.0.2.1" || port.Evidence[1] != "192.0.2.2" {
		t.Fatalf("folded port = %#v, want open ssh with both addresses as evidence", port)
	}
}

// A host with every port open arrives as sixteen 4096-port checkpoints. The
// merge runs while a cycle is finalized, so it must stay linear in the number
// of port records instead of rescanning the merged ports for each addition.
func TestMergeWorkSnapshotsFullRangeAllOpenHostIsLinear(t *testing.T) {
	plan := WorkPlan{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}}, DNS: map[string][]string{}}
	fragments := fullRangeOpenFragments("192.0.2.1")
	started := time.Now()
	result := MergeWorkSnapshots(plan, fragments)
	elapsed := time.Since(started)
	if len(result.Units) != 1 || len(result.Units[0].Ports) != 65535 {
		t.Fatalf("merged full-range host has %d units, want one with 65535 ports", len(result.Units))
	}
	for index, port := range result.Units[0].Ports {
		if port.Port != index+1 || port.State != "open" || len(port.Evidence) != 1 || port.Evidence[0] != "192.0.2.1" {
			t.Fatalf("merged port %d = %#v", index, port)
		}
	}
	// The quadratic merge needed seconds for this input even without the race
	// detector; the indexed merge needs tens of milliseconds. The bound leaves
	// ample headroom for slow, instrumented CI runners.
	if elapsed > 2*time.Second {
		t.Fatalf("merging 65535 ports in %d fragments took %s", len(fragments), elapsed)
	}
}

func BenchmarkMergeWorkSnapshotsFullRangeAllOpenHost(b *testing.B) {
	plan := WorkPlan{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}}, DNS: map[string][]string{}}
	fragments := fullRangeOpenFragments("192.0.2.1")
	b.ResetTimer()
	for b.Loop() {
		MergeWorkSnapshots(plan, fragments)
	}
}

func TestPlanNaabuUsesPinnedFullRangeAddressBatches(t *testing.T) {
	n := New("nmap")
	n.Resolver = fakeResolver{ips: []net.IP{net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.1")}}
	job := config.NormalizeJob(config.Job{
		Name: "naabu", Targets: []string{"edge.example"}, MaxExpandedHosts: 2,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Mode: "syn", Naabu: &config.NaabuOptions{AddressBatchSize: 1}},
	})
	plan, err := n.Plan(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 2 || plan.TotalUnits != 2 {
		t.Fatalf("unexpected Naabu unit count: %#v", plan.Units)
	}
	for _, unit := range plan.Units {
		if unit.Engine != config.EngineNaabuNmap || unit.Phase != "discovery" || unit.Ports != "1-65535" || unit.PortCount != 65535 || len(unit.Addresses) != 1 {
			t.Fatalf("Naabu unit lost full-range scope: %#v", unit)
		}
	}
}

func TestPlanNaabuSeparatesAddressFamilies(t *testing.T) {
	n := New("nmap")
	n.Resolver = fakeResolver{ips: []net.IP{net.ParseIP("2001:db8::2"), net.ParseIP("192.0.2.2"), net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.1")}}
	job := config.NormalizeJob(config.Job{
		Name: "naabu-families", Targets: []string{"edge.example"}, MaxExpandedHosts: 4,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{AddressBatchSize: 4}},
	})
	plan, err := n.Plan(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 2 {
		t.Fatalf("expected one discovery unit per address family, got %#v", plan.Units)
	}
	for _, unit := range plan.Units {
		if len(unit.Addresses) != 2 {
			t.Fatalf("family unit addresses = %#v", unit)
		}
		for _, address := range unit.Addresses {
			if unit.Family == 4 && net.ParseIP(address).To4() == nil {
				t.Fatalf("IPv6 address in IPv4 unit: %#v", unit)
			}
			if unit.Family == 6 && net.ParseIP(address).To4() != nil {
				t.Fatalf("IPv4 address in IPv6 unit: %#v", unit)
			}
		}
	}
}

func TestPlanUsesSingleAddressBatchesForSingularProfilePlaceholder(t *testing.T) {
	n := New("nmap")
	n.Resolver = fakeResolver{ips: []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}}
	job := config.NormalizeJob(config.Job{
		Name: "singular-profile", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"profile.example"}, MaxExpandedHosts: 2,
		TCP: &config.Protocol{Ports: "1-2", Mode: "connect", NmapArgs: []string{config.PlaceholderAddress, config.PlaceholderPorts, config.PlaceholderStructuredOutput}},
	})
	plan, err := n.Plan(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 2 {
		t.Fatalf("planned units = %d, want one per address: %#v", len(plan.Units), plan.Units)
	}
	for _, unit := range plan.Units {
		if len(unit.Addresses) != 1 || unit.Probes != 2 {
			t.Fatalf("singular profile unit = %#v", unit)
		}
	}
	if plan.TotalProbes != 4 || plan.TotalUnits != 2 {
		t.Fatalf("plan totals = probes %d units %d, want 4/2", plan.TotalProbes, plan.TotalUnits)
	}
}

func TestSplitNaabuUnitNeverSplitsFullPortScope(t *testing.T) {
	unit := WorkUnit{Engine: config.EngineNaabuNmap, Phase: "discovery", Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1-65535", PortCount: 65535, Probes: 65535}
	if first, second, ok := SplitWorkUnit(unit); ok || first.Sequence != 0 || second.Sequence != 0 {
		t.Fatalf("single-address Naabu unit was split: %#v %#v %v", first, second, ok)
	}
	unit.Addresses = []string{"192.0.2.1", "192.0.2.2"}
	first, second, ok := SplitWorkUnit(unit)
	if !ok || len(first.Addresses) != 1 || len(second.Addresses) != 1 || first.Engine != config.EngineNaabuNmap || second.Engine != config.EngineNaabuNmap {
		t.Fatalf("multi-address Naabu unit did not split by address: %#v %#v %v", first, second, ok)
	}
}
