package engine

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func snapshot(state string) model.Snapshot {
	s := model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}}}
	if state != "" {
		s.Units = []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: state}}}}
	}
	s.Normalize()
	return s
}
func scan(id string, s model.Snapshot) model.Scan {
	return model.Scan{ID: id, Job: "test", Status: "success", ConfigHash: "hash", Snapshot: s, FinishedAt: time.Now().UTC()}
}

func TestBaselineChangeAndRecoveryConfirmations(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "test", Baseline: config.Baseline{Samples: 2}, Change: config.Change{Confirmations: 2}}
	if events, err := e.Success(ctx, job, scan("1", snapshot(""))); err != nil || len(events) != 0 {
		t.Fatalf("first baseline: %v %v", events, err)
	}
	if events, err := e.Success(ctx, job, scan("2", snapshot(""))); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("baseline completion: %v %v", events, err)
	}
	if events, _ := e.Success(ctx, job, scan("3", snapshot("open"))); len(events) != 0 {
		t.Fatalf("early change event %v", events)
	}
	events, _ := e.Success(ctx, job, scan("4", snapshot("open")))
	if len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("change event %v", events)
	}
	if events, _ := e.Success(ctx, job, scan("5", snapshot(""))); len(events) != 0 {
		t.Fatalf("early recovery %v", events)
	}
	events, _ = e.Success(ctx, job, scan("6", snapshot("")))
	if len(events) != 1 || events[0].Type != "changes-recovered" {
		t.Fatalf("recovery %v", events)
	}
}

func TestUDPUncertaintyIsWarning(t *testing.T) {
	changes := Diff(snapshot(""), model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}}, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 53, State: "open|filtered"}}}}}, false)
	if len(changes) != 1 || changes[0].Severity != "warning" {
		t.Fatalf("changes %#v", changes)
	}
}

func TestIncompleteFailuresDoNotChangeBaseline(t *testing.T) {
	ctx := context.Background()
	db, _ := store.Open(filepath.Join(t.TempDir(), "db"))
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "test", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}
	e.Success(ctx, job, scan("1", snapshot("open")))
	failed := scan("2", snapshot(""))
	failed.Status = "failed"
	failed.Error = "timeout"
	for i := 0; i < 3; i++ {
		e.Failure(ctx, "test", failed)
	}
	state, _ := db.State(ctx, "test")
	if state.Baseline == nil || len(state.Baseline.Units) == 0 {
		t.Fatal("failure modified baseline")
	}
	if len(state.Incidents) != 0 {
		t.Fatal("failure created incident")
	}
}

func TestFingerprintStabilizesWithoutBlockingPortBaseline(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "test", Baseline: config.Baseline{Samples: 2}, Change: config.Change{Confirmations: 1}}
	withService := func(service string) model.Snapshot {
		return model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "443", ServiceDetection: true}}, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open", Service: service}}}}}
	}
	if events, _ := e.Success(ctx, job, scan("1", withService("service A"))); len(events) != 0 {
		t.Fatalf("unexpected event %#v", events)
	}
	events, err := e.Success(ctx, job, scan("2", withService("service B")))
	if err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("fingerprint blocked baseline: %#v %v", events, err)
	}
	state, _ := db.State(ctx, "test")
	if got := baselineService(*state.Baseline, "192.0.2.1", "tcp", 443); got != "" {
		t.Fatalf("unstable service entered baseline: %q", got)
	}
	if events, _ = e.Success(ctx, job, scan("3", withService("service B"))); len(events) != 0 {
		t.Fatalf("fingerprint learning generated alert: %#v", events)
	}
	state, _ = db.State(ctx, "test")
	if got := baselineService(*state.Baseline, "192.0.2.1", "tcp", 443); got != "service B" {
		t.Fatalf("stable service not learned: %q", got)
	}
}
