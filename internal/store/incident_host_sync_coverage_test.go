package store

import (
	"testing"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestAcceptedChangesSynchronizeDetailedHostObservations(t *testing.T) {
	snapshot := &model.Snapshot{
		Units: []model.Unit{{
			Target:    "router.example",
			Protocol:  "tcp",
			Addresses: []string{"192.0.2.10"},
			Ports:     []model.PortState{{Port: 80, State: "open", Service: "http"}},
		}},
		Hosts: []model.HostObservation{
			{Address: "192.0.2.10", Protocols: []model.ProtocolObservation{{
				Protocol: "tcp",
				Ports:    []model.PortObservation{{Port: 80, State: "open", Service: &model.ServiceObservation{Product: "http"}}},
			}}},
			{Address: "192.0.2.11", SourceTargets: []string{"router.example"}, Protocols: []model.ProtocolObservation{{
				Protocol: "tcp",
				Ports:    []model.PortObservation{{Port: 80, State: "open"}},
			}}},
			{Address: "192.0.2.12", DNSNames: []string{"router.example"}, Protocols: []model.ProtocolObservation{{
				Protocol: "tcp",
				Ports:    []model.PortObservation{{Port: 80, State: "open"}},
			}}},
			{Address: "192.0.2.13", Protocols: []model.ProtocolObservation{{
				Protocol: "udp",
				Ports:    []model.PortObservation{{Port: 53, State: "open"}},
			}}},
		},
	}

	if !acceptedHostMatches(snapshot, snapshot.Hosts[0], " 192.0.2.10 ") {
		t.Fatal("canonical host address did not match")
	}
	if !acceptedHostMatches(snapshot, snapshot.Hosts[1], "router.example") || !acceptedHostMatches(snapshot, snapshot.Hosts[2], "router.example") {
		t.Fatal("configured target relationships did not match")
	}
	if acceptedHostMatches(snapshot, snapshot.Hosts[3], "router.example") || acceptedHostMatches(snapshot, snapshot.Hosts[0], "other.example") {
		t.Fatal("unrelated host matched accepted target")
	}

	// A removal updates all matching detailed hosts while leaving unrelated UDP
	// evidence untouched.
	syncAcceptedPortHosts(snapshot, model.Change{Target: "router.example", Protocol: "tcp", Port: 80, New: "not-open"})
	for _, host := range snapshot.Hosts[:3] {
		if len(host.Protocols[0].Ports) != 0 {
			t.Fatalf("removed port remained on %#v", host)
		}
	}
	if len(snapshot.Hosts[3].Protocols[0].Ports) != 1 {
		t.Fatal("unrelated UDP evidence was changed")
	}

	// An accepted opening is idempotent for existing observations and appends
	// the port when it was not present yet.
	syncAcceptedPortHosts(snapshot, model.Change{Target: "router.example", Protocol: "tcp", Port: 443, New: "open"})
	syncAcceptedPortHosts(snapshot, model.Change{Target: "router.example", Protocol: "tcp", Port: 443, New: "open"})
	for _, host := range snapshot.Hosts[:3] {
		if len(host.Protocols[0].Ports) != 1 || host.Protocols[0].Ports[0].Port != 443 || host.Protocols[0].Ports[0].State != "open" {
			t.Fatalf("accepted port synchronization = %#v", host.Protocols[0].Ports)
		}
	}

	syncAcceptedServiceHosts(snapshot, model.Change{Target: "router.example", Protocol: "tcp", Port: 443, New: "nginx"})
	for _, host := range snapshot.Hosts[:3] {
		service := host.Protocols[0].Ports[0].Service
		if service == nil || service.Product != "nginx" || service.Method != "accepted" {
			t.Fatalf("accepted service synchronization = %#v", service)
		}
	}
	syncAcceptedServiceHosts(snapshot, model.Change{Target: "router.example", Protocol: "tcp", Port: 443, New: "not-open"})
	for _, host := range snapshot.Hosts[:3] {
		if host.Protocols[0].Ports[0].Service != nil {
			t.Fatalf("service removal remained = %#v", host.Protocols[0].Ports[0].Service)
		}
	}
}
