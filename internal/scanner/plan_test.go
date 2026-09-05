package scanner

import (
	"context"
	"net"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

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
