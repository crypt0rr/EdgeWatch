package store

import (
	"errors"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestApplyAcceptedServiceAndDNSChanges(t *testing.T) {
	snapshot := model.Snapshot{
		Units: []model.Unit{{Target: "edge.example", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open", Service: "old"}}}},
		DNS:   map[string][]string{"edge.example": {"192.0.2.1"}},
	}
	service := model.Change{Kind: "service", Target: "edge.example", Protocol: "tcp", Port: 443, New: "new"}
	if err := applyAcceptedChange(&snapshot, service); err != nil || snapshot.Units[0].Ports[0].Service != "new" {
		t.Fatalf("service acceptance = %#v, %v", snapshot, err)
	}
	service.New = "not-open"
	if err := applyAcceptedChange(&snapshot, service); err != nil || snapshot.Units[0].Ports[0].Service != "" {
		t.Fatalf("service removal = %#v, %v", snapshot, err)
	}

	added := model.Change{Kind: "dns-added", Target: "edge.example", New: "192.0.2.2"}
	if err := applyAcceptedChange(&snapshot, added); err != nil || len(snapshot.DNS["edge.example"]) != 2 {
		t.Fatalf("DNS addition = %#v, %v", snapshot.DNS, err)
	}
	if err := applyAcceptedChange(&snapshot, added); err != nil || len(snapshot.DNS["edge.example"]) != 2 {
		t.Fatalf("duplicate DNS addition = %#v, %v", snapshot.DNS, err)
	}
	removed := model.Change{Kind: "dns-removed", Target: "edge.example", Old: "192.0.2.2"}
	if err := applyAcceptedChange(&snapshot, removed); err != nil || len(snapshot.DNS["edge.example"]) != 1 {
		t.Fatalf("DNS removal = %#v, %v", snapshot.DNS, err)
	}
	if err := applyAcceptedChange(&snapshot, model.Change{Kind: "dns-removed", Target: "edge.example", Old: "192.0.2.1"}); err != nil || len(snapshot.DNS) != 0 {
		t.Fatalf("last DNS removal = %#v, %v", snapshot.DNS, err)
	}

	for _, change := range []model.Change{
		{Kind: "service", Target: "missing", Protocol: "tcp", Port: 1, New: "x"},
		{Kind: "bogus", Target: "edge.example"},
	} {
		if err := applyAcceptedChange(&snapshot, change); !errors.Is(err, ErrUnsupportedIncidentChange) {
			t.Fatalf("invalid change %#v error = %v", change, err)
		}
	}
}

func TestAcceptHostDownUpdatesExpectedDNSHostAndRetainsSiblingEvidence(t *testing.T) {
	const downAddress = "192.0.2.10"
	const liveAddress = "192.0.2.11"
	snapshot := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "25,443", ServiceDetection: true}},
		DNS:    map[string][]string{"edge.example": {downAddress, liveAddress}},
		Units: []model.Unit{{
			Target: "edge.example", Protocol: "tcp", Addresses: []string{downAddress, liveAddress},
			Ports: []model.PortState{
				{Port: 25, State: "open", Service: "smtp", Evidence: []string{downAddress}},
				{Port: 443, State: "open", Service: "https | Down || https | Live", Evidence: []string{downAddress, liveAddress}},
			},
		}},
		HostStates: []model.HostState{{Address: downAddress, State: "up"}, {Address: liveAddress, State: "up"}},
		Hosts: []model.HostObservation{
			{Address: downAddress, Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 443, State: "open", Service: &model.ServiceObservation{Name: "https", Product: "Down"}}}}}},
			{Address: liveAddress, Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 443, State: "open", Service: &model.ServiceObservation{Name: "https", Product: "Live"}}}}}},
		},
	}
	change := model.Change{Key: "host|" + downAddress, Kind: "host", Target: downAddress, Old: "up", New: "down"}
	if err := applyAcceptedChange(&snapshot, change); err != nil {
		t.Fatalf("accept host down: %v", err)
	}
	if len(snapshot.HostStates) != 2 || snapshot.HostStates[0] != (model.HostState{Address: downAddress, State: "down"}) {
		t.Fatalf("accepted host states = %#v", snapshot.HostStates)
	}
	if len(snapshot.Units) != 1 || len(snapshot.Units[0].Ports) != 1 {
		t.Fatalf("accepted baseline ports = %#v", snapshot.Units)
	}
	port := snapshot.Units[0].Ports[0]
	if port.Port != 443 || port.Service != model.Fingerprint("https", "Live", "", "", nil) || len(port.Evidence) != 1 || port.Evidence[0] != liveAddress {
		t.Fatalf("accepted sibling port evidence = %#v", port)
	}
	if snapshot.Hosts[0].Status != "unreachable" || len(snapshot.Hosts[0].Protocols[0].Ports) != 0 {
		t.Fatalf("accepted host detail still contains positive evidence: %#v", snapshot.Hosts[0])
	}
}

func TestAcceptHostDownPreservesLegacyAggregateServiceWithoutSiblingFingerprintEvidence(t *testing.T) {
	const downAddress = "192.0.2.20"
	const liveAddress = "192.0.2.21"
	snapshot := model.Snapshot{
		Scopes:     []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "443", ServiceDetection: true}},
		DNS:        map[string][]string{"edge.example": {downAddress, liveAddress}},
		HostStates: []model.HostState{{Address: downAddress, State: "up"}, {Address: liveAddress, State: "up"}},
		Units: []model.Unit{{Target: "edge.example", Protocol: "tcp", Addresses: []string{downAddress, liveAddress}, Ports: []model.PortState{{
			Port: 443, State: "open", Service: "https", Evidence: []string{downAddress, liveAddress},
		}}}},
	}
	change := model.Change{Key: "host|" + downAddress, Kind: "host", Target: downAddress, Old: "up", New: "down"}
	if err := applyAcceptedChange(&snapshot, change); err != nil {
		t.Fatalf("accept host down: %v", err)
	}
	if len(snapshot.Units) != 1 || len(snapshot.Units[0].Ports) != 1 || snapshot.Units[0].Ports[0].Service != "https" {
		t.Fatalf("legacy aggregate service was lost while accepting one DNS host: %#v", snapshot.Units)
	}
}

func TestAcceptServiceRemovalAfterPortRemoval(t *testing.T) {
	snapshot := &model.Snapshot{
		Units: []model.Unit{{
			Target:   "192.0.2.10",
			Protocol: "tcp",
			Ports:    []model.PortState{{Port: 25, State: "open", Service: "smtp"}},
		}},
	}

	// A single scan can report both the port disappearing and its service
	// fingerprint disappearing. Accepting the port first removes the port from
	// the baseline, so accepting the related service change must be idempotent.
	if err := acceptPortChange(snapshot, model.Change{
		Kind: "port", Target: "192.0.2.10", Protocol: "tcp", Port: 25, New: "not-open",
	}); err != nil {
		t.Fatalf("port removal = %v", err)
	}
	if err := acceptServiceChange(snapshot, model.Change{
		Kind: "service", Target: "192.0.2.10", Protocol: "tcp", Port: 25, New: "not-open",
	}); err != nil {
		t.Fatalf("service removal after port removal = %v", err)
	}
}
