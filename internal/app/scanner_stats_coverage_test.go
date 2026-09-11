package app

import (
	"testing"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestScannerDiscoveryStatsCountsUniqueTCPEvidence(t *testing.T) {
	snapshot := model.Snapshot{Hosts: []model.HostObservation{
		{Address: "192.0.2.1", Protocols: []model.ProtocolObservation{
			{Protocol: "udp", DiscoveredPorts: []model.PortObservation{{Port: 53}}, Ports: []model.PortObservation{{Port: 53, State: "open"}}},
			{Protocol: "tcp", DiscoveredPorts: []model.PortObservation{{Port: 22}, {Port: 22}, {Port: 443}}, Ports: []model.PortObservation{{Port: 22, State: "open"}, {Port: 443, State: "open|filtered"}, {Port: 80, State: "closed"}}},
		}},
		{Address: "192.0.2.1", Protocols: []model.ProtocolObservation{{Protocol: "tcp", DiscoveredPorts: []model.PortObservation{{Port: 22}}, Ports: []model.PortObservation{{Port: 22, State: "open"}}}}},
	}}
	discovered, confirmed := scannerDiscoveryStats(snapshot)
	if discovered != 2 || confirmed != 2 {
		t.Fatalf("discovery stats = %d discovered, %d confirmed; want 2/2", discovered, confirmed)
	}
}
