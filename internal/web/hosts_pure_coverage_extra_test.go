package web

import (
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestHostNormalizationAndMergeBranches(t *testing.T) {
	for value, want := range map[string]int{
		"confirmed":   3,
		"discovered":  2,
		"unconfirmed": 1,
		"":            0,
		"other":       0,
	} {
		if got := verificationRank(value); got != want {
			t.Errorf("verification rank %q = %d, want %d", value, got, want)
		}
	}

	service := &model.ServiceObservation{}
	portDestination := model.PortObservation{Port: 443, State: "closed", Service: service}
	incoming := model.PortObservation{Port: 443, State: "open", Reason: "syn-ack", ReasonTTL: 64, Verification: "confirmed", Service: &model.ServiceObservation{
		Name: "https", Product: "nginx", Version: "1.25", ExtraInfo: "TLS", Method: "probed", Confidence: 9,
		Tunnel: "ssl", OSType: "Linux", DeviceType: "server", CPEs: []string{"cpe:/a:nginx:nginx"},
	}}
	mergeServiceObservation(&portDestination, incoming)
	if portDestination.Service.Name != "https" || portDestination.Service.Product != "nginx" || portDestination.Service.Version != "1.25" || portDestination.Service.Confidence != 9 || len(portDestination.Service.CPEs) != 1 {
		t.Fatalf("service merge = %#v", portDestination.Service)
	}
	mergeServiceObservation(&portDestination, model.PortObservation{Port: 443})
	mergeServiceObservation(&model.PortObservation{Port: 1}, incoming)

	protocol := model.ProtocolObservation{
		Protocol: "tcp",
		Ports: []model.PortObservation{
			{Port: 443, State: "closed"},
			incoming,
			{Port: 443, State: "open", Verification: "discovered", Service: &model.ServiceObservation{Name: "https", CPEs: []string{"cpe:/a:nginx:nginx"}}},
		},
		DiscoveredPorts:  []model.PortObservation{{Port: 443, Verification: "discovered"}, {Port: 443, Verification: "confirmed", Reason: "verified", ReasonTTL: 32}},
		UnconfirmedPorts: []model.PortObservation{{Port: 8080}, {Port: 8080, Verification: "unconfirmed", Reason: "timeout"}},
	}
	dedupeProtocolPorts(&protocol)
	if len(protocol.Ports) != 1 || protocol.Ports[0].State != "open" || protocol.Ports[0].Verification != "confirmed" || protocol.Ports[0].Reason != "syn-ack" {
		t.Fatalf("deduped ports = %#v", protocol)
	}
	if len(protocol.DiscoveredPorts) != 1 || len(protocol.UnconfirmedPorts) != 1 || protocol.UnconfirmedPorts[0].Reason != "timeout" {
		t.Fatalf("deduped evidence = %#v", protocol)
	}

	protocolDestination := model.ProtocolObservation{Protocol: "tcp", Ports: []model.PortObservation{{Port: 443, State: "open", Service: incoming.Service}}, StateSummaries: []model.StateSummary{{State: "open", Count: 1, Reasons: []model.StateReason{{Reason: "ok", Count: 1}}}}}
	mergeProtocolObservation(&protocolDestination, model.ProtocolObservation{
		Protocol: "tcp", ScanType: "connect", ScannedPorts: "1-2", ScannedPortCount: 2, ServiceDetection: true,
		DiscoveryEngine: "naabu", NSEProfile: "safe", NSEArgs: map[string]string{"x": "y"}, NSEOutput: []string{"line"}, CommandFingerprint: "fp",
		Ports: []model.PortObservation{{Port: 2}}, StateSummaries: []model.StateSummary{{State: "open", Count: 2, Reasons: []model.StateReason{{Reason: "ok", Count: 2}, {Reason: "new", Count: 1}}}, {State: "closed", Count: 4}},
	})
	if protocolDestination.ScanType != "connect" || protocolDestination.ScannedPorts != "1-2" || protocolDestination.ScannedPortCount != 2 || !protocolDestination.ServiceDetection || protocolDestination.DiscoveryEngine != "naabu" || protocolDestination.NSEProfile != "safe" || protocolDestination.NSEArgs["x"] != "y" || len(protocolDestination.NSEOutput) != 1 || protocolDestination.CommandFingerprint != "fp" {
		t.Fatalf("protocol merge metadata = %#v", protocolDestination)
	}
	if len(protocolDestination.StateSummaries) != 2 || protocolDestination.StateSummaries[0].Count != 3 || len(protocolDestination.StateSummaries[0].Reasons) != 2 || protocolDestination.StateSummaries[1].State != "closed" {
		t.Fatalf("protocol merge summaries = %#v", protocolDestination.StateSummaries)
	}

	host := model.HostObservation{
		Address: " 192.0.2.1 ", SourceTargets: []string{"target", "target", ""}, DNSNames: []string{"dns", "dns"},
		LinkAddresses: []model.LinkAddress{{Address: "aa", Type: "mac"}, {Address: "aa", Type: "mac"}},
		Hostnames:     []model.Hostname{{Name: "host", Type: "ptr"}, {Name: "host", Type: "ptr"}},
		Protocols:     []model.ProtocolObservation{protocolDestination, {Protocol: "tcp", Ports: []model.PortObservation{{Port: 3}}}, {Protocol: "udp", Ports: []model.PortObservation{{Port: 53}}}},
	}
	dedupeHost(&host)
	if host.Address != "192.0.2.1" || len(host.SourceTargets) != 1 || len(host.DNSNames) != 1 || len(host.LinkAddresses) != 1 || len(host.Hostnames) != 1 || len(host.Protocols) != 2 {
		t.Fatalf("deduped host = %#v", host)
	}

	if got := summaryForHost(host, false); !got.HasOpenPorts || got.OpenPorts != 1 || len(got.Protocols) != 2 {
		t.Fatalf("host summary = %#v", got)
	}
	if got := summaryForHost(model.HostObservation{Address: "192.0.2.2", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 1, State: "open|filtered"}}}}}, true); !got.Legacy || !got.HasOpenPorts || got.OpenFilteredPorts != 1 {
		t.Fatalf("open-filtered summary = %#v", got)
	}
}

func TestHostFiltersAndScopeFallbackBranches(t *testing.T) {
	for _, raw := range []string{"", "true", "false"} {
		_, err := parseHasOpen(raw)
		if err != nil {
			t.Fatalf("parse has-open %q: %v", raw, err)
		}
	}
	if _, err := parseHasOpen("maybe"); err == nil {
		t.Fatal("invalid has-open value accepted")
	}
	for _, raw := range []string{"", " TCP ", "udp"} {
		if _, err := parseHostProtocol(raw); err != nil {
			t.Fatalf("parse protocol %q: %v", raw, err)
		}
	}
	if _, err := parseHostProtocol("icmp"); err == nil {
		t.Fatal("invalid protocol accepted")
	}

	for _, query := range []string{"?limit=1&offset=2", "?limit=100&offset=999999999"} {
		r := httptest.NewRequest("GET", "/api/v1/hosts"+query, nil)
		limit, offset, err := parseHostPagination(r)
		if err != nil || limit < 1 || offset < 0 {
			t.Fatalf("pagination %q = %d,%d,%v", query, limit, offset, err)
		}
	}
	for _, query := range []string{"?limit=0", "?limit=101", "?limit=x", "?offset=-1", "?offset=x"} {
		if _, _, err := parseHostPagination(httptest.NewRequest("GET", "/api/v1/hosts"+query, nil)); err == nil {
			t.Fatalf("invalid pagination %q accepted", query)
		}
	}
	if got, err := normalizedHostAddress("2001%3Adb8%3A%3A1"); err != nil || got != "2001:db8::1" {
		t.Fatalf("escaped address = %q,%v", got, err)
	}
	if _, err := normalizedHostAddress("%zz"); err == nil {
		t.Fatal("malformed escaped address accepted")
	}
	if _, err := normalizedHostAddress("example.test"); err == nil {
		t.Fatal("hostname accepted as effective address")
	}

	service := &model.ServiceObservation{Name: "ssh", Product: "OpenSSH", Version: "9", ExtraInfo: "Ubuntu", OSType: "Linux", DeviceType: "server", CPEs: []string{"cpe:/a:openbsd:openssh"}}
	host := model.HostObservation{
		Address:       "192.0.2.3",
		SourceTargets: []string{"target"},
		DNSNames:      []string{"dns.example"},
		Hostnames:     []model.Hostname{{Name: "host.example"}},
		Protocols: []model.ProtocolObservation{{
			Protocol: "tcp",
			Ports:    []model.PortObservation{{Port: 22, State: "open", Service: service}},
		}},
	}
	summary := summaryForHost(host, false)
	for _, query := range []string{"ssh", "openssh", "9", "ubuntu", "linux", "server", "cpe:/a:openbsd", "22"} {
		if !hostMatches(host, summary, query, "", nil) {
			t.Errorf("service query %q did not match", query)
		}
	}
	open := true
	if !hostMatches(host, summary, "", "TCP", &open) || hostMatches(host, summary, "", "udp", nil) || hostMatches(host, summary, "", "tcp", func() *bool { value := false; return &value }()) {
		t.Fatal("protocol/open filtering failed")
	}
	if hostMatches(host, summary, "missing", "", nil) || hostMatches(host, summary, "", "icmp", nil) {
		t.Fatal("unexpected host match")
	}
	items, total := filterHosts([]model.HostObservation{host}, "legacy", "", "tcp", &open, 10, 10)
	if total != 1 || len(items) != 0 {
		t.Fatalf("out-of-range filtered page = %#v,%d", items, total)
	}
	if _, total := filterHosts([]model.HostObservation{host}, "legacy", "", "tcp", nil, 0, 1); total != 1 {
		t.Fatal("filter total was not reported")
	}

	var hosts = []model.HostObservation{{Address: "192.0.2.4", Protocols: []model.ProtocolObservation{{Protocol: "tcp"}}}}
	restoreHostScopes(hosts, []model.Scope{{Protocol: "", Ports: "ignored"}, {Protocol: "tcp", Ports: "1-2", ServiceDetection: true}, {Protocol: "tcp", Ports: "3"}})
	if hosts[0].Protocols[0].ScannedPorts != "1-2" || hosts[0].Protocols[0].ScannedPortCount != 2 || !hosts[0].Protocols[0].ServiceDetection {
		t.Fatalf("restored scopes = %#v", hosts)
	}
	if !reflect.DeepEqual(scopesForJob(config.Job{}), []model.Scope{}) {
		t.Fatal("empty job produced scopes")
	}
}
