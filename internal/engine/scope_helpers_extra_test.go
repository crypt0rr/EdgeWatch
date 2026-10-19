package engine

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
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
	if len(unit.Ports) != 1 || unit.Ports[0].Port != 443 {
		t.Fatalf("merged ports = %#v, want only ports in the new scope", unit.Ports)
	}
	for _, port := range unit.Ports {
		if port.Port == 443 && port.Service != "" {
			t.Fatalf("service fingerprint should be cleared after disabling detection: %#v", port)
		}
	}
	if got := merged.DNS["edge.example"]; len(got) != 1 || got[0] != "192.0.2.9" {
		t.Fatalf("candidate DNS addresses = %#v", got)
	}
	if _, ok := merged.DNS["old.example"]; ok {
		t.Fatal("removed DNS target was retained")
	}
	if got := candidate.DNS["edge.example"]; len(got) != 1 || got[0] != "192.0.2.9" {
		t.Fatalf("candidate DNS was mutated: %#v", got)
	}
	if len(candidate.Units) != 1 || len(candidate.Units[0].Ports) != 2 {
		t.Fatalf("candidate units were mutated: %#v", candidate.Units)
	}
	if len(unitMap(merged)) != 1 {
		t.Fatalf("unit map = %#v", unitMap(merged))
	}
}

func TestScopeChangeIndexedMergeMatchesLinearReference(t *testing.T) {
	rng := rand.New(rand.NewSource(81423))
	for iteration := 0; iteration < 200; iteration++ {
		old := randomScopeMergeSnapshot(rng)
		candidate := randomScopeMergeSnapshot(rng)
		got := mergeForScopeChange(old, candidate)
		want := mergeForScopeChangeLinear(old, candidate)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("indexed merge differs from linear reference at iteration %d:\n got %#v\nwant %#v", iteration, got, want)
		}
	}
}

func randomScopeMergeSnapshot(rng *rand.Rand) model.Snapshot {
	protocols := []string{"tcp", "udp"}
	snapshot := model.Snapshot{DNS: map[string][]string{}}
	for targetIndex := 0; targetIndex < 8; targetIndex++ {
		target := fmt.Sprintf("edge-%d.example", targetIndex)
		for protocolIndex, protocol := range protocols {
			if rng.Intn(3) != 0 {
				continue
			}
			start := rng.Intn(24) + 1
			end := start + rng.Intn(8)
			snapshot.Scopes = append(snapshot.Scopes, model.Scope{Target: target, Protocol: protocol, Ports: fmt.Sprintf("%d-%d", start, end), ServiceDetection: rng.Intn(2) == 0})
			if rng.Intn(4) == 0 {
				// Overlapping ranges exercise the scope groups and their OR
				// semantics, including different service-detection flags.
				snapshot.Scopes = append(snapshot.Scopes, model.Scope{Target: target, Protocol: protocol, Ports: fmt.Sprintf("%d-%d", max(1, start-2), min(32, end+2)), ServiceDetection: rng.Intn(2) == 0})
			}
			ports := make([]model.PortState, 0, 5)
			for portIndex := 0; portIndex < 5; portIndex++ {
				port := rng.Intn(32) + 1
				service := ""
				if rng.Intn(2) == 0 {
					service = fmt.Sprintf("service-%d-%d", iterationPort(targetIndex, protocolIndex), port)
				}
				ports = append(ports, model.PortState{Port: port, State: []string{"open", "closed", "filtered"}[rng.Intn(3)], Service: service})
			}
			snapshot.Units = append(snapshot.Units, model.Unit{Target: target, Protocol: protocol, Ports: ports})
		}
		if rng.Intn(2) == 0 {
			snapshot.DNS[target] = []string{fmt.Sprintf("192.0.2.%d", targetIndex+1)}
		}
	}
	return snapshot
}

func iterationPort(targetIndex, protocolIndex int) int { return targetIndex*2 + protocolIndex }

func mergeForScopeChangeLinear(old, candidate model.Snapshot) model.Snapshot {
	result := cloneSnapshot(candidate)
	oldUnits := unitMap(old)
	candidateUnits := unitMap(candidate)
	for key, cu := range candidateUnits {
		parts := strings.Split(key, "\x00")
		target, protocol := parts[0], parts[1]
		ou, oldExists := oldUnits[key]
		ports := map[int]model.PortState{}
		for _, port := range cu.Ports {
			if scopeAllows(candidate, target, protocol, port.Port, false) {
				if !scopeAllows(candidate, target, protocol, port.Port, true) {
					port.Service = ""
				}
				ports[port.Port] = port
			}
		}
		if oldExists {
			for _, port := range ou.Ports {
				if !scopeAllows(candidate, target, protocol, port.Port, false) {
					continue
				}
				if !scopeAllows(candidate, target, protocol, port.Port, true) {
					port.Service = ""
				}
				if current, exists := ports[port.Port]; exists {
					if current.Service == "" && port.Service != "" && scopeAllows(candidate, target, protocol, port.Port, true) {
						current.Service = port.Service
						ports[port.Port] = current
					}
				} else {
					ports[port.Port] = port
				}
			}
		}
		cu.Ports = nil
		for _, port := range ports {
			cu.Ports = append(cu.Ports, port)
		}
		candidateUnits[key] = cu
	}
	for key, oldUnit := range oldUnits {
		if _, exists := candidateUnits[key]; exists {
			continue
		}
		parts := strings.Split(key, "\x00")
		target, protocol := parts[0], parts[1]
		if !hasTarget(candidate, target) || !scopeAllowsProtocol(candidate, target, protocol) {
			continue
		}
		mergedUnit := oldUnit
		mergedUnit.Ports = nil
		for _, port := range oldUnit.Ports {
			if !scopeAllows(candidate, target, protocol, port.Port, false) {
				continue
			}
			if !scopeAllows(candidate, target, protocol, port.Port, true) {
				port.Service = ""
			}
			mergedUnit.Ports = append(mergedUnit.Ports, port)
		}
		if addresses := result.DNS[target]; len(addresses) > 0 {
			mergedUnit.Addresses = append([]string(nil), addresses...)
		}
		candidateUnits[key] = mergedUnit
	}
	result.Units = nil
	for _, unit := range candidateUnits {
		result.Units = append(result.Units, unit)
	}
	result.Normalize()
	return result
}
