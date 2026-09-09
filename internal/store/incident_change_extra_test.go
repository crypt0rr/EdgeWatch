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
