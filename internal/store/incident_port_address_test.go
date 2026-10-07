package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/model"
)

const (
	portAddressV4 = "192.0.2.10"
	portAddressV6 = "2001:db8::10"
)

// portAddressBaseline exposes 22 on the IPv4 address and 443 on both
// addresses of a dual-stack DNS target, with a different fingerprint on each.
func portAddressBaseline() model.Snapshot {
	nginx := &model.ServiceObservation{Name: "https", Product: "nginx", Version: "1.25", Method: "probed"}
	caddy := &model.ServiceObservation{Name: "https", Product: "Caddy", Version: "2.8", Method: "probed"}
	snapshot := model.Snapshot{
		Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "22,443", ServiceDetection: true}},
		DNS:    map[string][]string{"edge.example": {portAddressV4, portAddressV6}},
		Units: []model.Unit{{Target: "edge.example", Protocol: "tcp", Addresses: []string{portAddressV4, portAddressV6}, Ports: []model.PortState{
			{Port: 22, State: "open", Evidence: []string{portAddressV4}},
			{Port: 443, State: "open", Service: portAddressFingerprint(caddy) + " || " + portAddressFingerprint(nginx), Evidence: []string{portAddressV4, portAddressV6}},
		}}},
		Hosts: []model.HostObservation{
			{Address: portAddressV4, SourceTargets: []string{"edge.example"}, DNSNames: []string{"edge.example"}, Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 22, State: "open"}, {Port: 443, State: "open", Service: nginx}}}}},
			{Address: portAddressV6, SourceTargets: []string{"edge.example"}, DNSNames: []string{"edge.example"}, Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 443, State: "open", Service: caddy}}}}},
		},
		HostStates: []model.HostState{{Address: portAddressV4, State: "up"}, {Address: portAddressV6, State: "up"}},
	}
	snapshot.Normalize()
	return snapshot
}

func portAddressFingerprint(service *model.ServiceObservation) string {
	fingerprint, _ := acceptedServiceForEvidence(&model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.1", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 1, Service: service}}}}}}}, "tcp", 1, []string{"198.51.100.1"})
	return fingerprint
}

func portAddressChange(port int, address, oldValue, newValue string) model.Change {
	return model.Change{Key: fmt.Sprintf("port-address|edge.example|tcp|%d|%s", port, address), Kind: "port-address", Target: "edge.example", Protocol: "tcp", Port: port, Address: address, Old: oldValue, New: newValue}
}

func hostPorts(snapshot model.Snapshot, address string) []int {
	var ports []int
	for _, host := range snapshot.Hosts {
		if host.Address != address {
			continue
		}
		for _, protocol := range host.Protocols {
			for _, port := range protocol.Ports {
				ports = append(ports, port.Port)
			}
		}
	}
	return ports
}

func TestAcceptPortAddressChangeUpdatesEvidenceServiceAndHostView(t *testing.T) {
	t.Parallel()
	snapshot := portAddressBaseline()
	nginx := portAddressFingerprint(&model.ServiceObservation{Name: "https", Product: "nginx", Version: "1.25", Method: "probed"})

	opened := portAddressChange(22, "2001:DB8::10", "not-open", "open")
	for range 2 {
		if err := applyAcceptedChange(&snapshot, opened); err != nil {
			t.Fatalf("accept opened port address: %v", err)
		}
	}
	if got := snapshot.Units[0].Ports[0]; !slices.Equal(got.Evidence, []string{portAddressV4, portAddressV6}) || got.Service != "" {
		t.Fatalf("opened port address baseline = %#v", got)
	}
	if got := hostPorts(snapshot, portAddressV6); !slices.Equal(got, []int{22, 443}) {
		t.Fatalf("expected IPv6 host ports = %v", got)
	}

	closed := portAddressChange(443, portAddressV6, "open", "not-open")
	if err := applyAcceptedChange(&snapshot, closed); err != nil {
		t.Fatalf("accept closed port address: %v", err)
	}
	if got := snapshot.Units[0].Ports[1]; !slices.Equal(got.Evidence, []string{portAddressV4}) || got.Service != nginx {
		t.Fatalf("closed port address baseline = %#v, want service %q", got, nginx)
	}
	if got := hostPorts(snapshot, portAddressV6); !slices.Equal(got, []int{22}) {
		t.Fatalf("expected IPv6 host ports after closure = %v", got)
	}
	if got := hostPorts(snapshot, portAddressV4); !slices.Equal(got, []int{22, 443}) {
		t.Fatalf("closure on IPv6 changed the IPv4 host view: %v", got)
	}

	// An address on a host the baseline has no evidence for gets one.
	bare := portAddressBaseline()
	bare.Hosts = nil
	if err := applyAcceptedChange(&bare, opened); err != nil || !slices.Equal(hostPorts(bare, portAddressV6), []int{22}) {
		t.Fatalf("opened port address without host evidence = %#v, %v", bare.Hosts, err)
	}

	// A port without address evidence has no per-address expectation, and a
	// port that has left the baseline is not exposed anywhere.
	unknown := portAddressBaseline()
	unknown.Units[0].Ports[0].Evidence = nil
	if err := applyAcceptedChange(&unknown, opened); err != nil || len(unknown.Units[0].Ports[0].Evidence) != 0 {
		t.Fatalf("port without evidence = %#v, %v", unknown.Units[0].Ports[0], err)
	}
	gone := portAddressChange(80, portAddressV6, "open", "not-open")
	if err := applyAcceptedChange(&snapshot, gone); err != nil {
		t.Fatalf("closure of a port outside the baseline = %v", err)
	}

	for _, invalid := range []model.Change{
		portAddressChange(80, portAddressV6, "not-open", "open"),
		portAddressChange(22, "", "not-open", "open"),
		portAddressChange(22, "edge.example", "not-open", "open"),
		portAddressChange(22, portAddressV6, "not-open", "closed"),
		{Kind: "port-address", Target: "edge.example", Protocol: "tcp", Address: portAddressV6, New: "open"},
	} {
		if err := applyAcceptedChange(&snapshot, invalid); !errors.Is(err, ErrUnsupportedIncidentChange) {
			t.Fatalf("invalid change %#v error = %v", invalid, err)
		}
	}
}

func TestAcceptPortAddressClosureResolvesMatchingServiceIncident(t *testing.T) {
	t.Parallel()
	nginx := portAddressFingerprint(&model.ServiceObservation{Name: "https", Product: "nginx", Version: "1.25", Method: "probed"})
	for _, test := range []struct {
		name       string
		reported   string
		wantPaired bool
	}{
		{name: "matching service", reported: nginx, wantPaired: true},
		{name: "different service", reported: "https | other | 1 |", wantPaired: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := openTestStore(t)
			record, err := defaultTenant(s).CreateJob(ctx, testJob("accept-port-address"))
			if err != nil {
				t.Fatal(err)
			}
			closed := portAddressChange(443, portAddressV6, "open", "not-open")
			closed.Severity = "info"
			baseline := portAddressBaseline()
			serviceKey := "service|edge.example|tcp|443"
			service := model.Change{Key: serviceKey, Kind: "service", Severity: "warning", Target: "edge.example", Protocol: "tcp", Port: 443, Old: baseline.Units[0].Ports[1].Service, New: test.reported}
			if _, err := s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
				state.Baseline = &baseline
				state.Incidents[closed.Key] = model.Incident{Change: closed, ScanID: "scan-2"}
				state.Incidents[serviceKey] = model.Incident{Change: service, ScanID: "scan-2"}
				return nil, nil
			}); err != nil {
				t.Fatal(err)
			}
			events, err := defaultTenant(s).AcceptIncidentWithExpectedOutboxAndAudit(ctx, record.ID, record.Job.Name, closed.Key, &IncidentExpectation{Change: closed}, nil, AuditEntry{Action: "incident.accepted", Detail: closed.Key})
			if err != nil {
				t.Fatal(err)
			}
			wantChanges := []model.Change{closed}
			if test.wantPaired {
				wantChanges = append(wantChanges, service)
			}
			if len(events) != 1 || !slices.Equal(events[0].Changes, wantChanges) {
				t.Fatalf("accept events = %#v, want changes %#v", events, wantChanges)
			}
			state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
			if err != nil {
				t.Fatal(err)
			}
			if _, open := state.Incidents[serviceKey]; open == test.wantPaired {
				t.Fatalf("service incident open = %t after accepting the closure, want %t", open, !test.wantPaired)
			}
			if got := state.Baseline.Units[0].Ports[1]; got.Service != nginx || !slices.Equal(got.Evidence, []string{portAddressV4}) || !state.BaselineModified {
				t.Fatalf("accepted baseline port = %#v modified=%t", got, state.BaselineModified)
			}
		})
	}
}
