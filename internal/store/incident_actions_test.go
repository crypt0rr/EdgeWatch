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
