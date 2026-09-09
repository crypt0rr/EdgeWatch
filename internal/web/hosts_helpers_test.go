package web

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestHostParsingAndPaginationHelpers(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/?limit=7&offset=14", nil)
	limit, offset, err := parseHostPagination(request)
	if err != nil || limit != 7 || offset != 14 {
		t.Fatalf("pagination = %d,%d,%v", limit, offset, err)
	}
	request = httptest.NewRequest(http.MethodGet, "/?offset=99999999999", nil)
	_, offset, err = parseHostPagination(request)
	if err != nil || offset != maxPaginationOffset {
		t.Fatalf("large host offset was not capped: %d,%v", offset, err)
	}
	for _, raw := range []string{"limit=0", "limit=101", "limit=bad", "offset=-1", "offset=bad"} {
		request := httptest.NewRequest(http.MethodGet, "/?"+raw, nil)
		if _, _, err := parseHostPagination(request); err == nil {
			t.Errorf("invalid pagination %q was accepted", raw)
		}
	}
	if address, err := normalizedHostAddress("2001%3Adb8%3A%3A1"); err != nil || address != "2001:db8::1" {
		t.Fatalf("escaped address = %q, %v", address, err)
	}
	for _, raw := range []string{"not-an-ip", "%zz"} {
		if _, err := normalizedHostAddress(raw); err == nil {
			t.Errorf("invalid address %q was accepted", raw)
		}
	}
	for _, test := range []struct {
		raw   string
		set   bool
		value bool
	}{
		{"", false, false}, {"true", true, true}, {"false", true, false},
	} {
		value, err := parseHasOpen(test.raw)
		if err != nil || (value != nil) != test.set || (value != nil && *value != test.value) {
			t.Errorf("has_open_ports %q = %v,%v", test.raw, value, err)
		}
	}
	if _, err := parseHasOpen("maybe"); err == nil {
		t.Fatal("invalid has_open_ports was accepted")
	}
	if protocol, err := parseHostProtocol(" TCP "); err != nil || protocol != "tcp" {
		t.Fatalf("protocol = %q, %v", protocol, err)
	}
	if _, err := parseHostProtocol("icmp"); err == nil {
		t.Fatal("invalid protocol was accepted")
	}
}

func TestLegacyHostDerivationMergesEvidenceAndScopes(t *testing.T) {
	snapshot := model.Snapshot{
		Scopes: []model.Scope{{Target: "DNS.Example", Protocol: "tcp", Ports: "22,80", ServiceDetection: true}},
		Units: []model.Unit{
			{Target: "DNS.Example", Protocol: "tcp", Addresses: []string{"198.51.100.1", "198.51.100.2"}, Ports: []model.PortState{
				{Port: 22, State: "open", Service: "ssh", Evidence: []string{"198.51.100.1"}},
				{Port: 80, State: "closed"},
			}},
			{Target: "DNS.Example", Protocol: "tcp", Addresses: []string{"198.51.100.1"}, Ports: []model.PortState{{Port: 443, State: "open", Service: "http"}}},
		},
	}
	hosts := deriveLegacyHosts(snapshot)
	if len(hosts) != 2 || hosts[0].Address != "198.51.100.1" {
		t.Fatalf("derived hosts = %#v", hosts)
	}
	first := hosts[0]
	if !reflect.DeepEqual(first.SourceTargets, []string{"DNS.Example"}) || !reflect.DeepEqual(first.DNSNames, []string{"DNS.Example"}) {
		t.Fatalf("target relationships = %#v %#v", first.SourceTargets, first.DNSNames)
	}
	if len(first.Protocols) != 1 || first.Protocols[0].ScannedPorts != "22,80" || first.Protocols[0].ScannedPortCount != 2 || !first.Protocols[0].ServiceDetection {
		t.Fatalf("derived scope = %#v", first.Protocols)
	}
	if len(first.Protocols[0].Ports) != 3 || first.Protocols[0].Ports[0].Service == nil || first.Protocols[0].Ports[0].Service.Method != "legacy" {
		t.Fatalf("derived positive evidence = %#v", first.Protocols[0].Ports)
	}
	second := hosts[1]
	if len(second.Protocols) != 1 || len(second.Protocols[0].Ports) != 1 || second.Protocols[0].Ports[0].Port != 80 {
		t.Fatalf("address-specific evidence = %#v", second)
	}
	if legacyService("") != nil || legacyService("ssh").Method != "legacy" {
		t.Fatal("legacy service conversion failed")
	}
}

func TestHostDeduplicationMergesServicesAndSummaries(t *testing.T) {
	host := model.HostObservation{
		Address:       "198.51.100.3",
		SourceTargets: []string{"target", "target"},
		DNSNames:      []string{"dns.example", "dns.example"},
		LinkAddresses: []model.LinkAddress{{Address: "aa", Type: "mac"}, {Address: "aa", Type: "mac", Vendor: "Acme"}},
		Hostnames:     []model.Hostname{{Name: "host", Type: "PTR"}, {Name: "host", Type: "PTR"}},
		Protocols: []model.ProtocolObservation{
			{Protocol: "tcp", ScannedPorts: "1", Ports: []model.PortObservation{{Port: 443, State: "closed", Reason: "reset"}}, StateSummaries: []model.StateSummary{{State: "closed", Count: 1, Reasons: []model.StateReason{{Reason: "reset", Count: 1}}}}},
			{Protocol: "tcp", ScannedPorts: "2", ScannedPortCount: 2, ServiceDetection: true, Ports: []model.PortObservation{{Port: 443, State: "open", Reason: "syn-ack", Service: &model.ServiceObservation{Name: "https", Product: "nginx", CPEs: []string{"cpe:/a:nginx"}}}, {Port: 22, State: "open"}}, StateSummaries: []model.StateSummary{{State: "closed", Count: 2, Reasons: []model.StateReason{{Reason: "reset", Count: 1}, {Reason: "timeout", Count: 1}}}, {State: "open", Count: 1}}},
		},
	}
	dedupeHost(&host)
	if len(host.SourceTargets) != 1 || len(host.DNSNames) != 1 || len(host.LinkAddresses) != 1 || len(host.Hostnames) != 1 || len(host.Protocols) != 1 {
		t.Fatalf("deduped host = %#v", host)
	}
	protocol := host.Protocols[0]
	if !protocol.ServiceDetection || protocol.ScannedPortCount != 2 || len(protocol.Ports) != 2 {
		t.Fatalf("merged protocol = %#v", protocol)
	}
	var port443 model.PortObservation
	for _, port := range protocol.Ports {
		if port.Port == 443 {
			port443 = port
		}
	}
	if port443.State != "open" || port443.Service == nil || port443.Service.Product != "nginx" || len(port443.Service.CPEs) != 1 {
		t.Fatalf("merged service = %#v", port443)
	}
	if len(protocol.StateSummaries) != 2 || protocol.StateSummaries[0].Count == 0 {
		t.Fatalf("merged state summaries = %#v", protocol.StateSummaries)
	}

	destination := model.PortObservation{Port: 1, State: "open", Service: &model.ServiceObservation{}}
	mergeServiceObservation(&destination, model.PortObservation{Port: 1, Service: &model.ServiceObservation{Name: "svc", Product: "prod", Version: "1", ExtraInfo: "extra", Method: "probe", Confidence: 90, Tunnel: "ssl", OSType: "linux", DeviceType: "server", CPEs: []string{"cpe:/a:test"}}})
	if destination.Service.Name != "svc" || destination.Service.Confidence != 90 || len(destination.Service.CPEs) != 1 {
		t.Fatalf("service fields were not merged = %#v", destination.Service)
	}
}

func TestHostFilteringAndSnapshotFallback(t *testing.T) {
	hosts := []model.HostObservation{
		{
			Address:       "198.51.100.10",
			SourceTargets: []string{"router"},
			Hostnames:     []model.Hostname{{Name: "router.example"}},
			Protocols:     []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 443, State: "open"}}}},
		},
		{
			Address:       "2001:db8::10",
			SourceTargets: []string{"dns.example"},
			Protocols:     []model.ProtocolObservation{{Protocol: "udp", Ports: []model.PortObservation{{Port: 53, State: "open|filtered"}}}},
		},
	}
	open := true
	if !hostMatches(hosts[0], summaryForHost(hosts[0], false), "ROUTER", "tcp", &open) {
		t.Fatal("host query/protocol filter did not match")
	}
	if hostMatches(hosts[0], summaryForHost(hosts[0], false), "missing", "", nil) {
		t.Fatal("missing host query matched")
	}
	filtered, total := filterHosts(hosts, "detailed", "example", "udp", &open, 0, 10)
	if total != 1 || len(filtered) != 1 || filtered[0].Address != "2001:db8::10" {
		t.Fatalf("filtered hosts = %#v total=%d", filtered, total)
	}
	filtered, total = filterHosts(hosts, "detailed", "", "", nil, 20, 10)
	if total != 2 || len(filtered) != 0 {
		t.Fatalf("out-of-range host page = %#v total=%d", filtered, total)
	}

	detailed, quality, ok := hostFromSnapshot(model.Snapshot{Hosts: hosts}, "2001:db8::10")
	if !ok || quality != "detailed" || detailed.Address != "2001:db8::10" {
		t.Fatalf("detailed snapshot lookup = %#v,%s,%v", detailed, quality, ok)
	}
	legacy, quality, ok := hostFromSnapshot(model.Snapshot{Units: []model.Unit{{Target: "198.51.100.10", Protocol: "tcp", Addresses: []string{"198.51.100.10"}, Ports: []model.PortState{{Port: 443, State: "open"}}}}, Scopes: []model.Scope{{Target: "198.51.100.10", Protocol: "tcp", Ports: "443"}}}, "198.51.100.10")
	if !ok || quality != "legacy" || legacy.Address != "198.51.100.10" || len(legacy.Protocols) != 1 {
		t.Fatalf("legacy snapshot lookup = %#v,%s,%v", legacy, quality, ok)
	}
	if _, _, ok := hostFromSnapshot(model.Snapshot{Hosts: hosts}, "198.51.100.99"); ok {
		t.Fatal("unknown snapshot host matched")
	}
	if !strings.Contains(summaryForHost(hosts[0], true).Address, "198.51.100.10") {
		t.Fatal("summary did not preserve address")
	}
}
