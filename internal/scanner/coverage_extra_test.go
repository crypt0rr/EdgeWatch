package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestScannerObservationMergeCoversDuplicateEvidence(t *testing.T) {
	service := &model.ServiceObservation{Name: "", Product: "", Version: "", ExtraInfo: "", Method: "", Confidence: 0, Tunnel: "", OSType: "", DeviceType: "", CPEs: []string{"cpe:/a:test"}}
	host := model.HostObservation{
		SourceTargets: []string{" z-target ", "", "z-target", "a-target"},
		DNSNames:      []string{"dns.example", "dns.example"},
		LinkAddresses: []model.LinkAddress{{Address: "aa", Type: "mac"}, {Address: "aa", Type: "mac", Vendor: "vendor"}},
		Hostnames:     []model.Hostname{{Name: "host", Type: "ptr"}, {Name: "host", Type: "ptr"}},
		Protocols: []model.ProtocolObservation{
			{Protocol: "tcp", Ports: []model.PortObservation{{Port: 22, State: "closed"}}, StateSummaries: []model.StateSummary{{State: "closed", Count: 1, Reasons: []model.StateReason{{Reason: "reset", Count: 1}}}}},
			{Protocol: "tcp", ScanType: "tcp syn", ScannedPorts: "1-2", ScannedPortCount: 2, ServiceDetection: true, Ports: []model.PortObservation{
				{Port: 22, State: "open", Reason: "syn-ack", ReasonTTL: 64, Service: service},
				{Port: 443, State: "open", Service: &model.ServiceObservation{Name: "https", Product: "nginx", Version: "1", ExtraInfo: "TLS", Method: "probe", Confidence: 9, Tunnel: "ssl", OSType: "linux", DeviceType: "server", CPEs: []string{"cpe:/a:nginx", "cpe:/a:nginx"}}},
			}, StateSummaries: []model.StateSummary{{State: "closed", Count: 2, Reasons: []model.StateReason{{Reason: "reset", Count: 2}, {Reason: "timeout", Count: 1}}}, {State: "open", Count: 1}}},
			{Protocol: "udp", Ports: []model.PortObservation{{Port: 53, State: "open|filtered"}}},
		},
	}
	dedupeHostObservation(&host)
	if len(host.SourceTargets) != 2 || len(host.DNSNames) != 1 || len(host.LinkAddresses) != 1 || len(host.Hostnames) != 1 || len(host.Protocols) != 2 {
		t.Fatalf("deduped observation = %#v", host)
	}
	if host.Protocols[0].Protocol != "tcp" || len(host.Protocols[0].Ports) != 2 || !host.Protocols[0].ServiceDetection || host.Protocols[0].ScanType != "tcp syn" {
		t.Fatalf("merged TCP observation = %#v", host.Protocols[0])
	}
	if host.Protocols[0].Ports[0].Service == nil || len(host.Protocols[0].Ports[0].Service.CPEs) != 1 {
		t.Fatalf("merged TCP service = %#v", host.Protocols[0].Ports[0])
	}
	if len(host.Protocols[0].StateSummaries) != 2 || len(host.Protocols[0].StateSummaries[0].Reasons) != 2 {
		t.Fatalf("merged state summaries = %#v", host.Protocols[0].StateSummaries)
	}

	var hosts []model.HostObservation
	mergeHostObservations(&hosts, map[string]model.HostObservation{"198.51.100.1": {Address: "198.51.100.1", AddressFamily: "IPv4", Status: "up"}})
	mergeHostObservations(&hosts, map[string]model.HostObservation{"198.51.100.1": {Address: "", AddressFamily: "", Status: "", StatusReason: "arp", ReasonTTL: 64, LatencyMS: 1}, "2001:db8::1": {Address: "2001:db8::1"}})
	if len(hosts) != 2 || hosts[0].Address != "198.51.100.1" || hosts[0].StatusReason != "" {
		t.Fatalf("merged hosts = %#v", hosts)
	}
	merged := map[string]model.HostObservation{}
	mergeHostObservationMap(merged, "198.51.100.2", model.HostObservation{Address: "198.51.100.2"})
	mergeHostObservationMap(merged, "198.51.100.2", model.HostObservation{Address: "198.51.100.2", Status: "up", AddressFamily: "IPv4"})
	if len(merged) != 1 {
		t.Fatal("host map merge lost observation")
	}
}

func TestScannerPlanAndArgumentBoundaryHelpers(t *testing.T) {
	if got := New(""); got.Path != "nmap" || got.Resolver == nil {
		t.Fatalf("default scanner = %#v", got)
	}
	if _, ok := protocolForJob(config.Job{}, "tcp"); ok {
		t.Fatal("disabled TCP unexpectedly enabled")
	}
	for _, ports := range [][]int{nil, {}, {1}, {1, 2, 4, 5, 7}} {
		_ = formatPorts(ports)
	}
	if formatPorts([]int{1, 2, 4, 5, 7}) != "1-2,4-5,7" {
		t.Fatal("port formatting is not deterministic")
	}
	for _, test := range []struct {
		unit             WorkUnit
		addresses, ports int
		want             int64
	}{
		{WorkUnit{}, 0, 1, 0},
		{WorkUnit{}, 1, 0, 0},
		{WorkUnit{Addresses: []string{"a"}, Ports: "bad", Probes: 1}, 1, 1, 1},
		{WorkUnit{Addresses: []string{"a", "b"}, PortCount: 2, Probes: 1}, 1, 1, 1},
		{WorkUnit{Addresses: []string{"a", "b"}, PortCount: 2, Probes: 8}, 1, 1, 2},
	} {
		if got := scaleWorkUnitProbes(test.unit, test.addresses, test.ports); got != test.want {
			t.Errorf("scaleWorkUnitProbes(%#v,%d,%d) = %d, want %d", test.unit, test.addresses, test.ports, got, test.want)
		}
	}
	for _, unit := range []WorkUnit{{Addresses: []string{"a"}, Ports: "bad", PortCount: 1}, {Addresses: []string{"a"}, Ports: "1-256", PortCount: 256}, {Addresses: []string{"a"}, Ports: "1", PortCount: 1}} {
		if _, _, ok := SplitWorkUnit(unit); ok {
			t.Errorf("unsplittable unit was split: %#v", unit)
		}
	}
	if args := nmapArgs(6, "udp", config.Protocol{Ports: "53", ServiceDetection: true}, "conservative", true, []string{"2001:db8::1"}); !containsAll(args, []string{"-6", "-sU", "-sV", "--version-light", "-Pn", "--reason"}) {
		t.Fatalf("UDP argument set = %#v", args)
	}
	if args := nmapArgs(4, "tcp", config.Protocol{Ports: "22", Mode: "connect"}, "fast", false, []string{"192.0.2.1"}); !containsAll(args, []string{"-sT", "-T4"}) || contains(args, "-Pn") {
		t.Fatalf("TCP connect argument set = %#v", args)
	}
	if !contains([]string{"a", "b"}, "b") {
		t.Fatal("argument helper failed")
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsAll(values []string, targets []string) bool {
	for _, target := range targets {
		if !contains(values, target) {
			return false
		}
	}
	return true
}

func TestScannerVersionAndAggregateEdgeCases(t *testing.T) {
	n := New("missing-nmap-binary")
	if got := n.Version(context.Background()); got != "unknown" {
		t.Fatalf("missing scanner version = %q", got)
	}
	if _, err := n.ScanWorkUnit(context.Background(), config.Job{UDP: &config.Protocol{Ports: "53"}}, WorkUnit{Protocol: "tcp"}, nil); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("missing protocol scan error = %v", err)
	}
	target := resolvedTarget{Name: "dns", Addresses: []string{"192.0.2.1", "192.0.2.2"}}
	got := aggregate(target, map[string]model.Unit{"192.0.2.1": {Ports: []model.PortState{{Port: 53, State: "open|filtered", Service: "domain"}}}, "192.0.2.2": {Ports: []model.PortState{{Port: 53, State: "open", Service: "dns"}, {Port: 22, State: "closed"}}}}, "udp")
	if len(got.Ports) != 2 || got.Ports[1].State != "open" || !strings.Contains(got.Ports[1].Service, "dns") {
		t.Fatalf("aggregate edge case = %#v", got)
	}
}
