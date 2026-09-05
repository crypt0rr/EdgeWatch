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
