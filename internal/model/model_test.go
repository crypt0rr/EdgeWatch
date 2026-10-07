package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMarshalBoundedEventKeepsPayloadWithinLimit(t *testing.T) {
	event := Event{
		Type:      "baseline-change",
		Job:       "production",
		Message:   "a change was detected",
		CreatedAt: nowForModelTest(),
		Changes: []Change{
			{Kind: "port", Target: "host-a", Protocol: "tcp", Port: 443, Old: "closed", New: "open"},
		},
	}
	unchanged, payload, err := MarshalBoundedEvent(event, EventPayloadLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) >= EventPayloadLimit || unchanged.ChangesTruncated {
		t.Fatalf("small event was unexpectedly changed: %#v (%d bytes)", unchanged, len(payload))
	}

	large := event
	large.Changes = make([]Change, 2000)
	for i := range large.Changes {
		large.Changes[i] = Change{Kind: "port", Target: strings.Repeat("target", 12), Protocol: "tcp", Port: i + 1, Old: "closed", New: "open"}
	}
	bounded, payload, err := MarshalBoundedEvent(large, 1200)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > 1200 || !bounded.ChangesTruncated || bounded.Changes != nil || bounded.ChangesCount != len(large.Changes) {
		t.Fatalf("large event was not bounded: %d bytes, %#v", len(payload), bounded)
	}
	var decoded Event
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("bounded event is not valid JSON: %v", err)
	}

	message := Event{Type: "failure", Job: "job", Message: strings.Repeat("é", 5000)}
	bounded, payload, err = MarshalBoundedEvent(message, 320)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > 320 || !json.Valid(payload) || !strings.HasPrefix(bounded.Message, "é") {
		t.Fatalf("oversized UTF-8 message was not safely trimmed: %d bytes, %#v", len(payload), bounded)
	}
	if _, _, err := MarshalBoundedEvent(Event{Type: "x", Job: "x", Message: "too large"}, 1); err == nil {
		t.Fatal("tiny payload limit unexpectedly succeeded")
	}
}

func TestMarshalBoundedEventDefaultLimitAndMessageTruncation(t *testing.T) {
	changes := make([]Change, 100)
	changes[0].Severity = " Critical "
	event := Event{Type: "change", Job: "job", Changes: changes}
	bounded, payload, err := MarshalBoundedEvent(event, 512)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > 512 || !bounded.ChangesTruncated || bounded.ChangesCount != len(changes) || !bounded.HasCriticalChanges || bounded.Message == "" {
		t.Fatalf("default bounded event = %d bytes %#v", len(payload), bounded)
	}
	if _, payload, err := MarshalBoundedEvent(Event{Type: "small", Job: "job"}, 0); err != nil || len(payload) > EventPayloadLimit {
		t.Fatalf("default event limit failed: %d bytes, %v", len(payload), err)
	}
}

func TestSnapshotNormalizeSortsAndCanonicalizesEvidence(t *testing.T) {
	snapshot := Snapshot{
		Units: []Unit{
			{Target: "z.example", Protocol: "udp", Addresses: []string{"2", "1"}, Ports: []PortState{{Port: 53, Evidence: []string{"z", "a"}}, {Port: 1}}},
			{Target: "a.example", Protocol: "tcp", Addresses: []string{"10", "01"}, Ports: []PortState{{Port: 443}}},
		},
		Scopes: []Scope{{Target: "z", Protocol: "udp"}, {Target: "a", Protocol: "tcp"}},
		DNS:    map[string][]string{"z": {"2", "1"}},
		Hosts: []HostObservation{{
			Address:       " 2001:0db8::1 ",
			SourceTargets: []string{"z", "a"},
			DNSNames:      []string{"z", "a"},
			LinkAddresses: []LinkAddress{{Type: "z", Address: "2"}, {Type: "a", Address: "1"}},
			Hostnames:     []Hostname{{Name: "z", Type: "ptr"}, {Name: "a", Type: "ptr"}},
			Protocols: []ProtocolObservation{{
				Protocol:       "tcp",
				DiscoveryState: " DOWN ",
				Ports:          []PortObservation{{Port: 443, Service: &ServiceObservation{CPEs: []string{"c2", "c1"}}}, {Port: 22}},
				StateSummaries: []StateSummary{{State: "open", Reasons: []StateReason{{Reason: "z"}, {Reason: "a"}}}, {State: "closed"}},
			}},
		}},
	}
	snapshot.Normalize()
	if snapshot.Units[0].Target != "a.example" || snapshot.Units[0].Addresses[0] != "01" || snapshot.Units[0].Ports[0].Port != 443 {
		t.Fatalf("units were not normalized: %#v", snapshot.Units)
	}
	if snapshot.Units[1].Ports[1].Evidence[0] != "a" {
		t.Fatalf("port evidence was not normalized: %#v", snapshot.Units[1].Ports)
	}
	if snapshot.Scopes[0].Target != "a" || snapshot.DNS["z"][0] != "1" {
		t.Fatalf("scopes/DNS were not normalized: %#v %#v", snapshot.Scopes, snapshot.DNS)
	}
	host := snapshot.Hosts[0]
	if host.Address != "2001:db8::1" || host.SourceTargets[0] != "a" || host.DNSNames[0] != "a" || host.LinkAddresses[0].Type != "a" || host.Hostnames[0].Name != "a" {
		t.Fatalf("host identity was not normalized: %#v", host)
	}
	if host.Protocols[0].Ports[0].Port != 22 || host.Protocols[0].Ports[1].Service.CPEs[0] != "c1" || host.Protocols[0].StateSummaries[1].Reasons[0].Reason != "a" {
		t.Fatalf("host evidence was not normalized: %#v", host.Protocols[0])
	}
	if host.Protocols[0].DiscoveryState != "down" {
		t.Fatalf("discovery state was not normalized: %#v", host.Protocols[0])
	}
}

func TestSnapshotNormalizeSortsEqualLinkAndHostnameKeysAndNonIPAddresses(t *testing.T) {
	snapshot := Snapshot{Hosts: []HostObservation{
		{Address: "  logical.example ", LinkAddresses: []LinkAddress{{Type: "mac", Address: "z"}, {Type: "mac", Address: "a"}, {Type: "ip", Address: "z"}}, Hostnames: []Hostname{{Name: "same", Type: "z"}, {Name: "same", Type: "a"}, {Name: "other", Type: "z"}}, Protocols: []ProtocolObservation{{Protocol: "udp"}, {Protocol: "tcp"}}},
		{Address: "192.0.2.1"},
	}}
	snapshot.Normalize()
	if snapshot.Hosts[0].Address != "192.0.2.1" || snapshot.Hosts[1].Address != "logical.example" {
		t.Fatalf("hosts were not sorted/canonicalized: %#v", snapshot.Hosts)
	}
	host := snapshot.Hosts[1]
	if host.LinkAddresses[0].Type != "ip" || host.LinkAddresses[1].Address != "a" || host.LinkAddresses[2].Address != "z" {
		t.Fatalf("link addresses were not deterministically ordered: %#v", host.LinkAddresses)
	}
	if host.Hostnames[0].Name != "other" || host.Hostnames[1].Type != "a" || host.Hostnames[2].Type != "z" {
		t.Fatalf("hostnames were not deterministically ordered: %#v", host.Hostnames)
	}
}

func TestSnapshotHashExcludesDescriptiveHostEvidence(t *testing.T) {
	base := Snapshot{Units: []Unit{{Target: "host", Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: []PortState{{Port: 443, State: "open", Service: "https"}}}}}
	withEvidence := base
	withEvidence.Hosts = []HostObservation{{Address: "192.0.2.1", Status: "up", LatencyMS: 4.2, LinkAddresses: []LinkAddress{{Address: "aa:bb", Vendor: "vendor"}}, Protocols: []ProtocolObservation{{Protocol: "tcp", Ports: []PortObservation{{Port: 443, State: "open", Reason: "syn-ack", Service: &ServiceObservation{Product: "product", Version: "1.0"}}}}}}}
	if base.Hash() != withEvidence.Hash() {
		t.Fatal("host metadata changed the snapshot hash")
	}
	withDiscoveryMetadata := withEvidence
	withDiscoveryMetadata.Hosts = []HostObservation{{Address: "192.0.2.1", Status: "unreachable", StatusReason: "no-response", Protocols: []ProtocolObservation{{Protocol: "tcp", DiscoveryState: "down"}}}}
	if base.Hash() != withDiscoveryMetadata.Hash() {
		t.Fatal("discovery metadata changed the snapshot hash")
	}
	withResolutionFailure := base
	withResolutionFailure.TargetFailures = []TargetCoverageFailure{{Target: " Example.COM ", Reason: " LOOKUP-FAILED "}}
	if base.Hash() != withResolutionFailure.Hash() {
		t.Fatal("incomplete target-resolution metadata changed the snapshot hash")
	}
	withExpectedDown := base
	withExpectedDown.HostStates = []HostState{{Address: "192.0.2.1", State: "down"}}
	if base.Hash() == withExpectedDown.Hash() {
		t.Fatal("monitored host state did not change the snapshot hash")
	}
	changed := Snapshot{Units: []Unit{{Target: "host", Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: []PortState{{Port: 443, State: "closed", Service: "https"}}}}}
	if base.Hash() == changed.Hash() {
		t.Fatal("meaningful port state did not change the snapshot hash")
	}
}

func TestSnapshotNormalizeSortsAndDeduplicatesTargetFailures(t *testing.T) {
	snapshot := Snapshot{TargetFailures: []TargetCoverageFailure{
		{Target: " Z.example ", Reason: " LOOKUP-FAILED "},
		{Target: "a.example", Reason: "no-addresses"},
		{Target: "z.EXAMPLE", Reason: "lookup-failed"},
	}}
	snapshot.Normalize()
	want := []TargetCoverageFailure{
		{Target: "a.example", Reason: "no-addresses"},
		{Target: "z.example", Reason: "lookup-failed"},
	}
	if len(snapshot.TargetFailures) != len(want) {
		t.Fatalf("normalized target failures = %#v, want %#v", snapshot.TargetFailures, want)
	}
	for i := range want {
		if snapshot.TargetFailures[i] != want[i] {
			t.Fatalf("normalized target failures = %#v, want %#v", snapshot.TargetFailures, want)
		}
	}
}

func TestSnapshotNormalizeCanonicalizesAndSortsHostStates(t *testing.T) {
	snapshot := Snapshot{HostStates: []HostState{
		{Address: "2001:0db8::2", State: " DOWN "},
		{Address: "192.0.2.2", State: "up"},
		{Address: "2001:db8::1", State: "up"},
	}}
	snapshot.Normalize()
	want := []HostState{
		{Address: "192.0.2.2", State: "up"},
		{Address: "2001:db8::1", State: "up"},
		{Address: "2001:db8::2", State: "down"},
	}
	if len(snapshot.HostStates) != len(want) {
		t.Fatalf("normalized host states = %#v", snapshot.HostStates)
	}
	for i := range want {
		if snapshot.HostStates[i] != want[i] {
			t.Fatalf("normalized host states = %#v, want %#v", snapshot.HostStates, want)
		}
	}
}

func TestEventDeliveredSkipsOnlyScanInterruptions(t *testing.T) {
	for _, eventType := range []string{"scan-canceled", "scan-failure", "changes-detected", "job-silent"} {
		if !EventDelivered(eventType) {
			t.Errorf("EventDelivered(%q) = false", eventType)
		}
	}
	if EventDelivered(EventScanInterrupted) {
		t.Error("a scan interruption would be delivered")
	}
}

func TestFingerprintAndChangeSummary(t *testing.T) {
	cpes := []string{"cpe:/b", "cpe:/a"}
	if got := Fingerprint(" ssh ", " OpenSSH", " 9", " Linux ", cpes); got != "ssh | OpenSSH | 9 | Linux | cpe:/a | cpe:/b" {
		t.Fatalf("fingerprint = %q", got)
	}
	if cpes[0] != "cpe:/b" || cpes[1] != "cpe:/a" {
		t.Fatalf("Fingerprint reordered the caller's CPEs to %v", cpes)
	}
	if got := ChangeSummary(Change{Kind: "dns-added", Target: "router", New: "192.0.2.1"}); got != "router dns-added: 192.0.2.1" {
		t.Fatalf("DNS summary = %q", got)
	}
	if got := ChangeSummary(Change{Kind: "service", Target: "router", Protocol: "tcp", Port: 443, Old: "old", New: "new"}); got != "router tcp/443 service: old -> new" {
		t.Fatalf("service summary = %q", got)
	}
	if got := ChangeSummary(Change{Target: "router", Protocol: "udp", Port: 53}); got != "router udp/53:  -> " {
		t.Fatalf("default summary = %q", got)
	}
	if got := ChangeSummary(Change{Kind: "dns-removed", Target: "router"}); got != "router dns-removed: unknown" {
		t.Fatalf("empty DNS summary = %q", got)
	}
	if got := ChangeSummary(Change{Kind: "host", Target: "192.0.2.1", Old: "up", New: "down"}); got != "192.0.2.1 host state: up -> down" {
		t.Fatalf("host summary = %q", got)
	}
}
