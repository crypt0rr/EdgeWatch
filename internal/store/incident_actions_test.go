package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestAcceptIncidentUpdatesBaselineAndRecordsAudit(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("accept-incident"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	key := "port|127.0.0.1|tcp|443"
	_, err = s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Scopes: []model.Scope{{Target: "127.0.0.1", Protocol: "tcp", Ports: "1-65535"}}}
		state.Incidents[key] = model.Incident{Change: model.Change{Key: key, Kind: "port", Target: "127.0.0.1", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}, ScanID: "scan-2", OpenedAt: now, LastSeenAt: now}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := s.AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, key, AuditEntry{Action: "incident.accepted", Detail: record.ID + ":" + key})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "incident-accepted" {
		t.Fatalf("accept events = %#v", events)
	}
	state, err := s.RuntimeState(ctx, record.ID)
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
	if _, err := s.AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, key, AuditEntry{Action: "incident.accepted", Detail: "stale"}); !errors.Is(err, ErrIncidentNotFound) {
		t.Fatalf("stale acceptance error = %v", err)
	}
}

func TestIncidentActionsQueueNotificationOutboxAtomically(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("incident-outbox"))
	if err != nil {
		t.Fatal(err)
	}
	key := "port|127.0.0.1|tcp|443"
	_, err = s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Scopes: []model.Scope{{Target: "127.0.0.1", Protocol: "tcp", Ports: "443"}}}
		state.Incidents[key] = model.Incident{Change: model.Change{Key: key, Kind: "port", Target: "127.0.0.1", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}, ScanID: "scan-1"}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptIncidentWithOutboxAndAudit(ctx, record.ID, record.Job.Name, key, []string{"destination"}, AuditEntry{Action: "incident.accepted", Detail: "incident-outbox"}); err != nil {
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
	ctx, s, record, plan := cycleFixture(t)
	acceptKey := "port|192.0.2.1|tcp|1"
	suppressKey := "port|192.0.2.1|tcp|2"
	if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-2"}}}
		state.Incidents[acceptKey] = model.Incident{Change: model.Change{Key: acceptKey, Kind: "port", Target: "192.0.2.1", Protocol: "tcp", Port: 1, Old: "not-open", New: "open", Severity: "critical"}, ScanID: "scan-1"}
		state.Incidents[suppressKey] = model.Incident{Change: model.Change{Key: suppressKey, Kind: "port", Target: "192.0.2.1", Protocol: "tcp", Port: 2, Old: "not-open", New: "open", Severity: "critical"}, ScanID: "scan-1"}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	epoch, err := s.RuntimeBaselineEpoch(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision, ConfigHash: record.Job.SecurityHash(), ExecutionHash: record.Job.ExecutionHash(), BaselineEpoch: epoch, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PauseScanCycle(ctx, cycle.ID, false, "scan timed out"); err != nil {
		t.Fatal(err)
	}

	// Suppression leaves the comparison baseline untouched, so paused
	// progress stays valid.
	if _, err := s.SuppressIncidentWithAudit(ctx, record.ID, record.Job.Name, suppressKey, AuditEntry{Action: "incident.suppressed", Detail: suppressKey}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetScanCycle(ctx, cycle.ID); err != nil || got.Status != "paused" {
		t.Fatalf("cycle after suppression = %#v, %v", got, err)
	}

	if _, err := s.AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, acceptKey, AuditEntry{Action: "incident.accepted", Detail: acceptKey}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetScanCycle(ctx, cycle.ID)
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
	if _, err := s.GetActiveScanCycle(ctx, record.ID); !errors.Is(err, ErrNoScanCycle) {
		t.Fatalf("active cycle after accept = %v, want ErrNoScanCycle", err)
	}
}

func TestSuppressIncidentStoresOneScanWindow(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("suppress-incident"))
	if err != nil {
		t.Fatal(err)
	}
	key := "port|127.0.0.1|tcp|443"
	incident := model.Incident{Change: model.Change{Key: key, Kind: "port", Target: "127.0.0.1", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}, ScanID: "scan-2"}
	_, err = s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents[key] = incident
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := s.SuppressIncidentWithAudit(ctx, record.ID, record.Job.Name, key, AuditEntry{Action: "incident.suppressed", Detail: record.ID + ":" + key})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "incident-suppressed" {
		t.Fatalf("suppress events = %#v", events)
	}
	state, err := s.RuntimeState(ctx, record.ID)
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
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("stale-incident-action"))
	if err != nil {
		t.Fatal(err)
	}
	key := "port|127.0.0.1|tcp|443"
	reviewed := model.Change{Key: key, Kind: "port", Target: "127.0.0.1", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}
	if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
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
	if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents[key] = model.Incident{Change: current, ScanID: "scan-2"}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	expectation := &IncidentExpectation{Change: reviewed}
	if _, err := s.AcceptIncidentWithExpectedOutboxAndAudit(ctx, record.ID, record.Job.Name, key, expectation, nil, AuditEntry{}); !errors.Is(err, ErrIncidentConflict) {
		t.Fatalf("stale acceptance error = %v", err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := state.Incidents[key].Change.New; got != current.New {
		t.Fatalf("stale acceptance mutated incident to %q", got)
	}
	if _, err := s.SuppressIncidentWithExpectedOutboxAndAudit(ctx, record.ID, record.Job.Name, key, expectation, nil, AuditEntry{}); !errors.Is(err, ErrIncidentConflict) {
		t.Fatalf("stale suppression error = %v", err)
	}
	state, err = s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Incidents[key]; !ok {
		t.Fatal("stale suppression removed the current incident")
	}
}

func TestAcceptRelatedPortAndServiceRemovalsInEitherOrder(t *testing.T) {
	for _, first := range []string{"port", "service"} {
		t.Run(first+"-first", func(t *testing.T) {
			ctx := context.Background()
			s := openTestStore(t)
			record, err := s.CreateJob(ctx, testJob("accept-related-removals-"+first))
			if err != nil {
				t.Fatal(err)
			}
			portKey := "port|192.0.2.10|tcp|25"
			serviceKey := "service|192.0.2.10|tcp|25"
			changePort := model.Change{Key: portKey, Kind: "port", Target: "192.0.2.10", Protocol: "tcp", Port: 25, Old: "open", New: "not-open", Severity: "info"}
			changeService := model.Change{Key: serviceKey, Kind: "service", Target: "192.0.2.10", Protocol: "tcp", Port: 25, Old: "smtp", New: "not-open", Severity: "info"}
			_, err = s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
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
			events, err := s.AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, firstKey, AuditEntry{Action: "incident.accepted", Detail: record.ID + ":" + firstKey})
			if err != nil {
				t.Fatalf("accept %s change = %v", first, err)
			}
			if len(events) != 1 || len(events[0].Changes) != 2 {
				t.Fatalf("grouped acceptance events = %#v", events)
			}
			if _, err := s.AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, secondKey, AuditEntry{Action: "incident.accepted", Detail: "stale"}); !errors.Is(err, ErrIncidentNotFound) {
				t.Fatalf("stale related acceptance error = %v", err)
			}
			state, err := s.RuntimeState(ctx, record.ID)
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
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("accept-related-guard"))
	if err != nil {
		t.Fatal(err)
	}
	portKey := "port|192.0.2.12|tcp|25"
	serviceKey := "service|192.0.2.12|tcp|25"
	_, err = s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Units: []model.Unit{{Target: "192.0.2.12", Protocol: "tcp", Ports: []model.PortState{{Port: 25, State: "open", Service: "smtp"}}}}}
		state.Incidents[portKey] = model.Incident{Change: model.Change{Key: portKey, Kind: "port", Target: "192.0.2.12", Protocol: "tcp", Port: 25, Old: "open", New: "not-open"}, ScanID: "scan-new"}
		state.Incidents[serviceKey] = model.Incident{Change: model.Change{Key: serviceKey, Kind: "service", Target: "192.0.2.12", Protocol: "tcp", Port: 25, Old: "smtp", New: "not-open"}, ScanID: "scan-old"}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := s.AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, portKey, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || len(events[0].Changes) != 1 {
		t.Fatalf("cross-scan acceptance grouped = %#v", events)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Incidents[serviceKey]; !ok {
		t.Fatal("service incident from another scan was accepted unexpectedly")
	}

}

func TestAcceptServiceChangeOnOpenPortRemainsIndependent(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("accept-service-independent"))
	if err != nil {
		t.Fatal(err)
	}
	portKey := "port|192.0.2.13|tcp|25"
	serviceKey := "service|192.0.2.13|tcp|25"
	_, err = s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Units: []model.Unit{{Target: "192.0.2.13", Protocol: "tcp", Ports: []model.PortState{{Port: 25, State: "open", Service: "smtp"}}}}}
		state.Incidents[serviceKey] = model.Incident{Change: model.Change{Key: serviceKey, Kind: "service", Target: "192.0.2.13", Protocol: "tcp", Port: 25, Old: "smtp", New: "postfix"}, ScanID: "scan-1"}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := s.AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, serviceKey, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || len(events[0].Changes) != 1 {
		t.Fatalf("service acceptance unexpectedly grouped = %#v", events)
	}
	state, err := s.RuntimeState(ctx, record.ID)
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
	for _, portScanID := range []string{"scan-3", "scan-2"} {
		t.Run("port-from-"+portScanID, func(t *testing.T) {
			ctx := context.Background()
			s := openTestStore(t)
			record, err := s.CreateJob(ctx, testJob("accept-service-new-port-"+portScanID))
			if err != nil {
				t.Fatal(err)
			}
			portKey := "port|192.0.2.14|tcp|8080"
			serviceKey := "service|192.0.2.14|tcp|8080"
			portChange := model.Change{Key: portKey, Kind: "port", Target: "192.0.2.14", Protocol: "tcp", Port: 8080, Old: "not-open", New: "open", Severity: "critical"}
			serviceChange := model.Change{Key: serviceKey, Kind: "service", Target: "192.0.2.14", Protocol: "tcp", Port: 8080, Old: "not-open", New: "http", Severity: "warning"}
			_, err = s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
				state.Baseline = &model.Snapshot{Units: []model.Unit{{Target: "192.0.2.14", Protocol: "tcp", Ports: []model.PortState{{Port: 22, State: "open", Service: "ssh"}}}}}
				state.Incidents[portKey] = model.Incident{Change: portChange, ScanID: portScanID}
				state.Incidents[serviceKey] = model.Incident{Change: serviceChange, ScanID: "scan-3"}
				state.FingerprintCandidates[serviceKey] = model.ValueCount{Value: "http", Count: 1}
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			events, err := s.AcceptIncidentWithExpectedOutboxAndAudit(ctx, record.ID, record.Job.Name, serviceKey, &IncidentExpectation{Change: serviceChange}, nil, AuditEntry{Action: "incident.accepted", Detail: record.ID + ":" + serviceKey})
			if err != nil {
				t.Fatalf("accept service on a new port: %v", err)
			}
			if len(events) != 1 || len(events[0].Changes) != 2 || events[0].Changes[0] != portChange || events[0].Changes[1] != serviceChange {
				t.Fatalf("service acceptance did not include the port it depends on: %#v", events)
			}
			if _, err := s.AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, portKey, AuditEntry{}); !errors.Is(err, ErrIncidentNotFound) {
				t.Fatalf("port incident remained after its service was accepted: %v", err)
			}
			state, err := s.RuntimeState(ctx, record.ID)
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

func TestAcceptServiceOnMissingPortWithoutPortIncidentIsRejected(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("accept-service-missing-port"))
	if err != nil {
		t.Fatal(err)
	}
	serviceKey := "service|192.0.2.15|tcp|8080"
	portKey := "port|192.0.2.15|tcp|8080"
	_, err = s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
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
	if _, err := s.AcceptIncidentWithAudit(ctx, record.ID, record.Job.Name, serviceKey, AuditEntry{}); !errors.Is(err, ErrUnsupportedIncidentChange) {
		t.Fatalf("service acceptance without an open port = %v, want unsupported change", err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 2 || len(state.Baseline.Units[0].Ports) != 1 {
		t.Fatalf("rejected acceptance changed runtime state = %#v", state)
	}
}
