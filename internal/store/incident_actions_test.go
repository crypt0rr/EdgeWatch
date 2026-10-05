package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestAcceptIncidentUpdatesBaselineAndRecordsAudit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("accept-incident"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	key := "port|127.0.0.1|tcp|443"
	_, err = s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Scopes: []model.Scope{{Target: "127.0.0.1", Protocol: "tcp", Ports: "1-65535"}}}
		state.Incidents[key] = model.Incident{Change: model.Change{Key: key, Kind: "port", Target: "127.0.0.1", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}, ScanID: "scan-2", OpenedAt: now, LastSeenAt: now}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := defaultTenant(s).AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, key, AuditEntry{Action: "incident.accepted", Detail: record.ID + ":" + key})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "incident-accepted" {
		t.Fatalf("accept events = %#v", events)
	}
	state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 0 || len(state.Baseline.Units) != 1 || len(state.Baseline.Units[0].Ports) != 1 || state.Baseline.Units[0].Ports[0].Port != 443 {
		t.Fatalf("accepted state = %#v", state)
	}
	var audits int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action=?`, "incident.accepted").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("audit rows = %d, want 1", audits)
	}
	if _, err := defaultTenant(s).AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, key, AuditEntry{Action: "incident.accepted", Detail: "stale"}); !errors.Is(err, ErrIncidentNotFound) {
		t.Fatalf("stale acceptance error = %v", err)
	}
}

func TestAcceptHostDownIncidentUpdatesExpectedBaselineState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("accept-host-down"))
	if err != nil {
		t.Fatal(err)
	}
	address := "192.0.2.44"
	key := "host|" + address
	change := model.Change{Key: key, Kind: "host", Target: address, Old: "up", New: "down", Severity: "warning"}
	_, err = s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{
			Scopes:     []model.Scope{{Target: address, Protocol: "tcp", Ports: "443"}},
			Units:      []model.Unit{{Target: address, Protocol: "tcp", Addresses: []string{address}, Ports: []model.PortState{{Port: 443, State: "open"}}}},
			Hosts:      []model.HostObservation{{Address: address, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up", Ports: []model.PortObservation{{Port: 443, State: "open"}}}}}},
			HostStates: []model.HostState{{Address: address, State: "up"}},
		}
		state.Incidents[key] = model.Incident{Change: change, ScanID: "scan-down", OpenedAt: time.Now().UTC(), LastSeenAt: time.Now().UTC()}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if events, err := defaultTenant(s).AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, key, AuditEntry{Action: "incident.accepted", Detail: record.ID + ":" + key}); err != nil {
		t.Fatalf("accept host-down incident: events=%#v err=%v", events, err)
	}
	state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 0 || state.Baseline == nil || len(state.Baseline.HostStates) != 1 || state.Baseline.HostStates[0] != (model.HostState{Address: address, State: "down"}) {
		t.Fatalf("accepted host-state baseline = %#v", state)
	}
	if len(state.Baseline.Units) != 1 || len(state.Baseline.Units[0].Ports) != 0 {
		t.Fatalf("accepted down host retained baseline ports: %#v", state.Baseline.Units)
	}
	if len(state.Baseline.Hosts) != 1 || state.Baseline.Hosts[0].Status != "unreachable" || state.Baseline.Hosts[0].Protocols[0].DiscoveryState != "down" {
		t.Fatalf("accepted down host evidence = %#v", state.Baseline.Hosts)
	}
}

func TestIncidentActionsQueueNotificationOutboxAtomically(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("incident-outbox"))
	if err != nil {
		t.Fatal(err)
	}
	key := "port|127.0.0.1|tcp|443"
	_, err = s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Scopes: []model.Scope{{Target: "127.0.0.1", Protocol: "tcp", Ports: "443"}}}
		state.Incidents[key] = model.Incident{Change: model.Change{Key: key, Kind: "port", Target: "127.0.0.1", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}, ScanID: "scan-1"}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).AcceptIncidentWithOutboxAndAudit(ctx, record.ID, record.Job.Name, key, []string{"destination"}, AuditEntry{Action: "incident.accepted", Detail: "incident-outbox"}); err != nil {
		t.Fatal(err)
	}
	var events, deliveries int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE type=?`, "incident-accepted").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination=?`, "destination").Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if events != 1 || deliveries != 1 {
		t.Fatalf("incident notification persistence = events %d, deliveries %d", events, deliveries)
	}
}

func TestAcceptIncidentDiscardsPausedScanCycle(t *testing.T) {
	t.Parallel()
	ctx, s, record, plan := cycleFixture(t)
	acceptKey := "port|192.0.2.1|tcp|1"
	suppressKey := "port|192.0.2.1|tcp|2"
	if _, err := s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-2"}}}
		state.Incidents[acceptKey] = model.Incident{Change: model.Change{Key: acceptKey, Kind: "port", Target: "192.0.2.1", Protocol: "tcp", Port: 1, Old: "not-open", New: "open", Severity: "critical"}, ScanID: "scan-1"}
		state.Incidents[suppressKey] = model.Incident{Change: model.Change{Key: suppressKey, Kind: "port", Target: "192.0.2.1", Protocol: "tcp", Port: 2, Old: "not-open", New: "open", Severity: "critical"}, ScanID: "scan-1"}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	epoch, err := defaultTenant(s).RuntimeBaselineEpoch(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision, ConfigHash: record.Job.SecurityHash(), ExecutionHash: record.Job.ExecutionHash(), BaselineEpoch: epoch, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().PauseScanCycle(ctx, cycle.ID, false, "scan timed out"); err != nil {
		t.Fatal(err)
	}

	// Suppression leaves the comparison baseline untouched, so paused
	// progress stays valid.
	if _, err := defaultTenant(s).SuppressIncidentWithAudit(ctx, record.ID, record.Job.Name, suppressKey, AuditEntry{Action: "incident.suppressed", Detail: suppressKey}); err != nil {
		t.Fatal(err)
	}
	if got, err := defaultTenant(s).GetScanCycle(ctx, cycle.ID); err != nil || got.Status != "paused" {
		t.Fatalf("cycle after suppression = %#v, %v", got, err)
	}

	if _, err := defaultTenant(s).AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, acceptKey, AuditEntry{Action: "incident.accepted", Detail: acceptKey}); err != nil {
		t.Fatal(err)
	}
	got, err := defaultTenant(s).GetScanCycle(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "discarded" || got.LastError != "incident accepted" || got.FinishedAt.IsZero() {
		t.Fatalf("cycle after accept = status %q last_error %q finished_at %v", got.Status, got.LastError, got.FinishedAt)
	}
	var units int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_cycle_units WHERE cycle_id=?`, cycle.ID).Scan(&units); err != nil {
		t.Fatal(err)
	}
	if units != 0 {
		t.Fatalf("discarded cycle retained %d work units", units)
	}
	if _, err := defaultTenant(s).GetActiveScanCycle(ctx, record.ID); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("active cycle after accept = %v, want ErrNoScanCycle", err)
	}
}

func TestSuppressIncidentStoresOneScanWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("suppress-incident"))
	if err != nil {
		t.Fatal(err)
	}
	key := "port|127.0.0.1|tcp|443"
	incident := model.Incident{Change: model.Change{Key: key, Kind: "port", Target: "127.0.0.1", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}, ScanID: "scan-2"}
	_, err = s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents[key] = incident
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := defaultTenant(s).SuppressIncidentWithAudit(ctx, record.ID, record.Job.Name, key, AuditEntry{Action: "incident.suppressed", Detail: record.ID + ":" + key})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "incident-suppressed" {
		t.Fatalf("suppress events = %#v", events)
	}
	state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 0 || state.Suppressed[key] != 1 {
		t.Fatalf("suppressed state = %#v", state)
	}
	if state.SuppressedChanges[key].Key != key {
		t.Fatalf("suppressed change = %#v", state.SuppressedChanges[key])
	}
}

func TestIncidentActionsRejectStaleExpectedChange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("stale-incident-action"))
	if err != nil {
		t.Fatal(err)
	}
	key := "port|127.0.0.1|tcp|443"
	reviewed := model.Change{Key: key, Kind: "port", Target: "127.0.0.1", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}
	if _, err := s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Scopes: []model.Scope{{Target: "127.0.0.1", Protocol: "tcp", Ports: "443"}}}
		state.Incidents[key] = model.Incident{Change: reviewed, ScanID: "scan-1"}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	// Simulate a newer scan changing the observed value while the original
	// confirmation dialog is still open.
	current := reviewed
	current.New = "not-open"
	if _, err := s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents[key] = model.Incident{Change: current, ScanID: "scan-2"}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	expectation := &IncidentExpectation{Change: reviewed}
	if _, err := defaultTenant(s).AcceptIncidentWithExpectedOutboxAndAudit(ctx, record.ID, record.Job.Name, key, expectation, nil, AuditEntry{}); !errors.Is(err, ErrIncidentConflict) {
		t.Fatalf("stale acceptance error = %v", err)
	}
	state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := state.Incidents[key].Change.New; got != current.New {
		t.Fatalf("stale acceptance mutated incident to %q", got)
	}
	if _, err := defaultTenant(s).SuppressIncidentWithExpectedOutboxAndAudit(ctx, record.ID, record.Job.Name, key, expectation, nil, AuditEntry{}); !errors.Is(err, ErrIncidentConflict) {
		t.Fatalf("stale suppression error = %v", err)
	}
	state, err = defaultTenant(s).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Incidents[key]; !ok {
		t.Fatal("stale suppression removed the current incident")
	}
}

func TestAcceptRelatedPortAndServiceRemovalsInEitherOrder(t *testing.T) {
	t.Parallel()
	for _, first := range []string{"port", "service"} {
		t.Run(first+"-first", func(t *testing.T) {
			ctx := context.Background()
			s := openTestStore(t)
			record, err := defaultTenant(s).CreateJob(ctx, testJob("accept-related-removals-"+first))
			if err != nil {
				t.Fatal(err)
			}
			portKey := "port|192.0.2.10|tcp|25"
			serviceKey := "service|192.0.2.10|tcp|25"
			changePort := model.Change{Key: portKey, Kind: "port", Target: "192.0.2.10", Protocol: "tcp", Port: 25, Old: "open", New: "not-open", Severity: "info"}
			changeService := model.Change{Key: serviceKey, Kind: "service", Target: "192.0.2.10", Protocol: "tcp", Port: 25, Old: "smtp", New: "not-open", Severity: "info"}
			_, err = s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
				state.Baseline = &model.Snapshot{Units: []model.Unit{{Target: "192.0.2.10", Protocol: "tcp", Ports: []model.PortState{{Port: 25, State: "open", Service: "smtp"}}}}}
				state.Incidents[portKey] = model.Incident{Change: changePort, ScanID: "scan-1"}
				state.Incidents[serviceKey] = model.Incident{Change: changeService, ScanID: "scan-1"}
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			firstKey := portKey
			secondKey := serviceKey
			if first == "service" {
				firstKey, secondKey = serviceKey, portKey
			}
			events, err := defaultTenant(s).AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, firstKey, AuditEntry{Action: "incident.accepted", Detail: record.ID + ":" + firstKey})
			if err != nil {
				t.Fatalf("accept %s change = %v", first, err)
			}
			if len(events) != 1 || len(events[0].Changes) != 2 {
				t.Fatalf("grouped acceptance events = %#v", events)
			}
			if _, err := defaultTenant(s).AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, secondKey, AuditEntry{Action: "incident.accepted", Detail: "stale"}); !errors.Is(err, ErrIncidentNotFound) {
				t.Fatalf("stale related acceptance error = %v", err)
			}
			state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(state.Incidents) != 0 || len(state.Baseline.Units) != 1 || len(state.Baseline.Units[0].Ports) != 0 {
				t.Fatalf("related removals state = %#v", state)
			}
		})
	}
}

func TestAcceptIncidentDoesNotFoldUnrelatedScanOrServiceChanges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("accept-related-guard"))
	if err != nil {
		t.Fatal(err)
	}
	portKey := "port|192.0.2.12|tcp|25"
	serviceKey := "service|192.0.2.12|tcp|25"
	_, err = s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Units: []model.Unit{{Target: "192.0.2.12", Protocol: "tcp", Ports: []model.PortState{{Port: 25, State: "open", Service: "smtp"}}}}}
		state.Incidents[portKey] = model.Incident{Change: model.Change{Key: portKey, Kind: "port", Target: "192.0.2.12", Protocol: "tcp", Port: 25, Old: "open", New: "not-open"}, ScanID: "scan-new"}
		state.Incidents[serviceKey] = model.Incident{Change: model.Change{Key: serviceKey, Kind: "service", Target: "192.0.2.12", Protocol: "tcp", Port: 25, Old: "smtp", New: "not-open"}, ScanID: "scan-old"}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := defaultTenant(s).AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, portKey, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || len(events[0].Changes) != 1 {
		t.Fatalf("cross-scan acceptance grouped = %#v", events)
	}
	state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Incidents[serviceKey]; !ok {
		t.Fatal("service incident from another scan was accepted unexpectedly")
	}

}

func TestAcceptServiceChangeOnOpenPortRemainsIndependent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("accept-service-independent"))
	if err != nil {
		t.Fatal(err)
	}
	portKey := "port|192.0.2.13|tcp|25"
	serviceKey := "service|192.0.2.13|tcp|25"
	_, err = s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Units: []model.Unit{{Target: "192.0.2.13", Protocol: "tcp", Ports: []model.PortState{{Port: 25, State: "open", Service: "smtp"}}}}}
		state.Incidents[serviceKey] = model.Incident{Change: model.Change{Key: serviceKey, Kind: "service", Target: "192.0.2.13", Protocol: "tcp", Port: 25, Old: "smtp", New: "postfix"}, ScanID: "scan-1"}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := defaultTenant(s).AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, serviceKey, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || len(events[0].Changes) != 1 {
		t.Fatalf("service acceptance unexpectedly grouped = %#v", events)
	}
	state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Baseline.Units) != 1 || len(state.Baseline.Units[0].Ports) != 1 || state.Baseline.Units[0].Ports[0].Service != "postfix" {
		t.Fatalf("service acceptance changed port expectation = %#v", state.Baseline)
	}
	if _, ok := state.Incidents[portKey]; ok {
		t.Fatal("unexpected port incident was created")
	}
}

func TestAcceptServiceOnNewPortIncludesOpenPortIncident(t *testing.T) {
	t.Parallel()
	for _, portScanID := range []string{"scan-3", "scan-2"} {
		t.Run("port-from-"+portScanID, func(t *testing.T) {
			ctx := context.Background()
			s := openTestStore(t)
			record, err := defaultTenant(s).CreateJob(ctx, testJob("accept-service-new-port-"+portScanID))
			if err != nil {
				t.Fatal(err)
			}
			portKey := "port|192.0.2.14|tcp|8080"
			serviceKey := "service|192.0.2.14|tcp|8080"
			portChange := model.Change{Key: portKey, Kind: "port", Target: "192.0.2.14", Protocol: "tcp", Port: 8080, Old: "not-open", New: "open", Severity: "critical"}
			serviceChange := model.Change{Key: serviceKey, Kind: "service", Target: "192.0.2.14", Protocol: "tcp", Port: 8080, Old: "not-open", New: "http", Severity: "warning"}
			_, err = s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
				state.Baseline = &model.Snapshot{Units: []model.Unit{{Target: "192.0.2.14", Protocol: "tcp", Ports: []model.PortState{{Port: 22, State: "open", Service: "ssh"}}}}}
				state.Incidents[portKey] = model.Incident{Change: portChange, ScanID: portScanID}
				state.Incidents[serviceKey] = model.Incident{Change: serviceChange, ScanID: "scan-3"}
				state.FingerprintCandidates[serviceKey] = model.ValueCount{Value: "http", Count: 1}
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			events, err := defaultTenant(s).AcceptIncidentWithExpectedOutboxAndAudit(ctx, record.ID, record.Job.Name, serviceKey, &IncidentExpectation{Change: serviceChange}, nil, AuditEntry{Action: "incident.accepted", Detail: record.ID + ":" + serviceKey})
			if err != nil {
				t.Fatalf("accept service on a new port: %v", err)
			}
			if len(events) != 1 || len(events[0].Changes) != 2 || events[0].Changes[0] != portChange || events[0].Changes[1] != serviceChange {
				t.Fatalf("service acceptance did not include the port it depends on: %#v", events)
			}
			if _, err := defaultTenant(s).AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, portKey, AuditEntry{}); !errors.Is(err, ErrIncidentNotFound) {
				t.Fatalf("port incident remained after its service was accepted: %v", err)
			}
			state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(state.Incidents) != 0 || len(state.FingerprintCandidates) != 0 || !state.BaselineModified {
				t.Fatalf("accepted runtime state = %#v", state)
			}
			ports := state.Baseline.Units[0].Ports
			if len(ports) != 2 || ports[1].Port != 8080 || ports[1].State != "open" || ports[1].Service != "http" {
				t.Fatalf("accepted baseline ports = %#v", ports)
			}
		})
	}
}

// A port accepted without its reported service keeps that service under
// normal comparison until an administrator decides on it. Accepting a service
// or the port's removal ends that decision, and a state change of a port that
// is already expected does not start one.
func TestAcceptIncidentRecordsServiceDecisionForPortAcceptedAlone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("accept-port-service-decision"))
	if err != nil {
		t.Fatal(err)
	}
	change := func(kind string, port int, old, current string) model.Change {
		return model.Change{Key: fmt.Sprintf("%s|192.0.2.15|tcp|%d", kind, port), Kind: kind, Target: "192.0.2.15", Protocol: "tcp", Port: port, Old: old, New: current}
	}
	newPort := change("port", 8080, "not-open", "open")
	newService := change("service", 8080, "not-open", "http")
	stateChange := change("port", 443, "open|filtered", "open")
	removal := change("port", 25, "open", "not-open")
	_, err = s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Units: []model.Unit{{Target: "192.0.2.15", Protocol: "tcp", Ports: []model.PortState{
			{Port: 25, State: "open"}, {Port: 443, State: "open|filtered"},
		}}}}
		for _, tracked := range []model.Change{newPort, newService, stateChange, removal} {
			state.Incidents[tracked.Key] = model.Incident{Change: tracked, ScanID: "scan-2"}
		}
		// Left behind by an earlier acceptance of port 25 on its own.
		state.ServiceDecisionRequired = map[string]bool{"service|192.0.2.15|tcp|25": true}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	accept := func(key string) model.JobState {
		t.Helper()
		if _, err := defaultTenant(s).AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, key, AuditEntry{Action: "incident.accepted", Detail: record.ID + ":" + key}); err != nil {
			t.Fatalf("accept %s: %v", key, err)
		}
		state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
		if err != nil {
			t.Fatal(err)
		}
		return state
	}
	serviceKey := "service|192.0.2.15|tcp|8080"
	if state := accept(newPort.Key); !state.ServiceDecisionRequired[serviceKey] || len(state.ServiceDecisionRequired) != 2 {
		t.Fatalf("port accepted alone did not keep its service for a decision: %#v", state.ServiceDecisionRequired)
	}
	if state := accept(stateChange.Key); state.ServiceDecisionRequired["service|192.0.2.15|tcp|443"] {
		t.Fatalf("state change of an expected port required a service decision: %#v", state.ServiceDecisionRequired)
	}
	if state := accept(removal.Key); state.ServiceDecisionRequired["service|192.0.2.15|tcp|25"] {
		t.Fatalf("accepted port removal kept its service decision: %#v", state.ServiceDecisionRequired)
	}
	state := accept(newService.Key)
	if len(state.ServiceDecisionRequired) != 0 {
		t.Fatalf("accepted service kept its decision: %#v", state.ServiceDecisionRequired)
	}
	if ports := state.Baseline.Units[0].Ports; len(ports) != 2 || ports[0].Port != 443 || ports[0].State != "open" || ports[1].Port != 8080 || ports[1].Service != "http" {
		t.Fatalf("accepted baseline ports = %#v", ports)
	}

	// A baseline reset starts over, so no earlier decision survives it.
	if _, err := s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.ServiceDecisionRequired = map[string]bool{serviceKey: true}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).ResetRuntime(ctx, record.ID, record.Job.Name); err != nil {
		t.Fatal(err)
	}
	if state, err := defaultTenant(s).RuntimeState(ctx, record.ID); err != nil || len(state.ServiceDecisionRequired) != 0 {
		t.Fatalf("reset kept service decisions: %#v, %v", state.ServiceDecisionRequired, err)
	}
}

func TestAcceptServiceOnMissingPortWithoutPortIncidentIsRejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("accept-service-missing-port"))
	if err != nil {
		t.Fatal(err)
	}
	serviceKey := "service|192.0.2.15|tcp|8080"
	portKey := "port|192.0.2.15|tcp|8080"
	_, err = s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Units: []model.Unit{{Target: "192.0.2.15", Protocol: "tcp", Ports: []model.PortState{{Port: 22, State: "open"}}}}}
		state.Incidents[serviceKey] = model.Incident{Change: model.Change{Key: serviceKey, Kind: "service", Target: "192.0.2.15", Protocol: "tcp", Port: 8080, Old: "not-open", New: "http"}, ScanID: "scan-1"}
		// A removal of the same port is not evidence that the port is open, so
		// it must never be folded into a service appearance.
		state.Incidents[portKey] = model.Incident{Change: model.Change{Key: portKey, Kind: "port", Target: "192.0.2.15", Protocol: "tcp", Port: 8080, Old: "open", New: "not-open"}, ScanID: "scan-1"}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, serviceKey, AuditEntry{}); !errors.Is(err, ErrUnsupportedIncidentChange) {
		t.Fatalf("service acceptance without an open port = %v, want unsupported change", err)
	}
	state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 2 || len(state.Baseline.Units[0].Ports) != 1 {
		t.Fatalf("rejected acceptance changed runtime state = %#v", state)
	}
}
