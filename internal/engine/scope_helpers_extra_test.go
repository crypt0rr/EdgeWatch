package engine

import (
	"testing"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestScopeHelpersAndScopeChangeMerge(t *testing.T) {
	old := model.Snapshot{
		Scopes: []model.Scope{
			{Target: "edge.example", Protocol: "tcp", Ports: "80,443", ServiceDetection: true},
			{Target: "edge.example", Protocol: "udp", Ports: "53"},
		},
		DNS:   map[string][]string{"edge.example": {"192.0.2.1"}, "old.example": {"192.0.2.2"}},
		Units: []model.Unit{{Target: "edge.example", Protocol: "tcp", Ports: []model.PortState{{Port: 80, State: "open", Service: "http"}, {Port: 443, State: "open", Service: "https"}}}},
	}
	candidate := model.Snapshot{
		Scopes: []model.Scope{
			{Target: "edge.example", Protocol: "tcp", Ports: "443", ServiceDetection: false},
			{Target: "new.example", Protocol: "tcp", Ports: "22"},
		},
		DNS:   map[string][]string{"edge.example": {"192.0.2.9"}, "new.example": {"192.0.2.3"}},
		Units: []model.Unit{{Target: "edge.example", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "closed"}, {Port: 22, State: "open", Service: "ssh"}}}},
	}

	if !hasTarget(old, "edge.example") || hasTarget(old, "missing.example") {
		t.Fatal("hasTarget returned an unexpected result")
	}
	if !inBothScopes(old, old, item{Kind: "dns", Target: "edge.example"}) {
		t.Fatal("DNS target should be present in both scopes")
	}
	if inBothScopes(old, candidate, item{Kind: "dns", Target: "old.example"}) {
		t.Fatal("removed DNS target was considered in scope")
	}
	if !inBothScopes(old, candidate, item{Kind: "port", Target: "edge.example", Protocol: "tcp", Port: 443}) {
		t.Fatal("retained TCP port should be in scope")
	}
	if inBothScopes(old, candidate, item{Kind: "service", Target: "edge.example", Protocol: "tcp", Port: 443}) {
		t.Fatal("service should not be in scope when detection is disabled")
	}

	merged := mergeForScopeChange(old, candidate)
	units := unitMap(merged)
	unit := units["edge.example\x00tcp"]
	if len(unit.Ports) != 2 {
		t.Fatalf("merged ports = %#v, want candidate and retained old ports", unit.Ports)
	}
	for _, port := range unit.Ports {
		if port.Port == 443 && port.Service != "" {
			t.Fatalf("service fingerprint should be cleared after disabling detection: %#v", port)
		}
	}
	if got := merged.DNS["edge.example"]; len(got) != 1 || got[0] != "192.0.2.1" {
		t.Fatalf("retained DNS addresses = %#v", got)
	}
	if _, ok := merged.DNS["old.example"]; ok {
		t.Fatal("removed DNS target was retained")
	}
	if len(unitMap(merged)) != 1 {
		t.Fatalf("unit map = %#v", unitMap(merged))
	}
}
