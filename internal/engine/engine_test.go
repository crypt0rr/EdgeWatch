package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
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

func TestSuppressedIncidentReopensAfterOneSuccessfulScan(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "suppressed", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 2}}
	if _, err := e.Success(ctx, job, scan("baseline", snapshot(""))); err != nil {
		t.Fatal(err)
	}
	if events, err := e.Success(ctx, job, scan("candidate-1", snapshot("open"))); err != nil || len(events) != 0 {
		t.Fatalf("first changed scan: %#v, %v", events, err)
	}
	if events, err := e.Success(ctx, job, scan("incident", snapshot("open"))); err != nil || len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("incident scan: %#v, %v", events, err)
	}
	key := "port|192.0.2.1|tcp|443"
	if _, err := db.UpdateState(ctx, job.Name, func(state *model.JobState) ([]model.Event, error) {
		incident, ok := state.Incidents[key]
		if !ok {
			return nil, fmt.Errorf("incident %s not found", key)
		}
		state.Suppressed[key] = 1
		state.SuppressedChanges[key] = incident.Change
		delete(state.Incidents, key)
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if events, err := e.Success(ctx, job, scan("suppressed-scan", snapshot("open"))); err != nil || len(events) != 0 {
		t.Fatalf("suppressed scan: %#v, %v", events, err)
	}
	state, err := db.State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 0 || state.Suppressed[key] != 0 {
		t.Fatalf("suppression window after scan = %#v", state)
	}
	events, err := e.Success(ctx, job, scan("reopened", snapshot("open")))
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("reopened scan: %#v, %v", events, err)
	}
	state, err = db.State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Incidents) != 1 || state.Suppressed[key] != 0 {
		t.Fatalf("reopened state = %#v", state)
	}
}

func TestUDPUncertaintyIsWarning(t *testing.T) {
	changes := Diff(snapshot(""), model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-65535"}}, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 53, State: "open|filtered"}}}}}, false)
	if len(changes) != 1 || changes[0].Severity != "warning" {
		t.Fatalf("changes %#v", changes)
	}
}

func TestFormatEventUsesOutcomeIndicators(t *testing.T) {
	recovered := FormatEvent(model.Event{Type: "changes-recovered", Message: "one change recovered", Job: "test"})
	if !strings.HasPrefix(recovered, "🟢 EdgeWatch: ") {
		t.Fatalf("recovery notification = %q", recovered)
	}

	critical := FormatEvent(model.Event{Type: "changes-detected", Message: "one change", Job: "test", Changes: []model.Change{{Severity: "critical"}}})
	if !strings.HasPrefix(critical, "🔴 EdgeWatch: ") {
		t.Fatalf("critical notification = %q", critical)
	}

	warning := FormatEvent(model.Event{Type: "changes-detected", Message: "one change", Job: "test", Changes: []model.Change{{Severity: "warning"}}})
	if strings.HasPrefix(warning, "🔴 ") || strings.HasPrefix(warning, "🟢 ") {
		t.Fatalf("warning notification has an outcome indicator = %q", warning)
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

func TestEveryUnsuccessfulScanEmitsAnOutcomeEvent(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := Engine{Store: db}
	job := config.Job{Name: "outcomes", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}

	failed := scan("failed", snapshot(""))
	failed.Status = "failed"
	failed.Error = "nmap failed: permission denied"
	events, err := e.Failure(ctx, job.Name, failed)
	if err != nil || len(events) != 1 || events[0].Type != "scan-failure" {
		t.Fatalf("failed scan event = %#v, err=%v", events, err)
	}
	if events[0].Message != "Scan failed: nmap failed: permission denied" {
		t.Fatalf("failed scan message = %q", events[0].Message)
	}

	canceled := scan("canceled", snapshot(""))
	canceled.Status = "canceled"
	canceled.Error = "scan canceled"
	events, err = e.Failure(ctx, job.Name, canceled)
	if err != nil || len(events) != 1 || events[0].Type != "scan-canceled" {
		t.Fatalf("canceled scan event = %#v, err=%v", events, err)
	}
	if events[0].Message != "Scan canceled: scan canceled" {
		t.Fatalf("canceled scan message = %q", events[0].Message)
	}

	timedOut := scan("timed-out", snapshot(""))
	timedOut.Status = "timed_out"
	timedOut.Error = "scan exceeded its timeout"
	events, err = e.Failure(ctx, job.Name, timedOut)
	if err != nil || len(events) != 1 || events[0].Type != "scan-failure" {
		t.Fatalf("timed-out scan event = %#v, err=%v", events, err)
	}
	if events[0].Message != "Scan timed out: scan exceeded its timeout" {
		t.Fatalf("timed-out scan message = %q", events[0].Message)
	}

	state, err := db.State(ctx, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if state.ConsecutiveFailures != 2 {
		t.Fatalf("unexpected failure count after canceled and timed-out scans: %d", state.ConsecutiveFailures)
	}
}

func TestFinalizeManagedScanRecordsInitialBaselineScanMetadata(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	record, err := db.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "managed", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
		TCP: &config.Protocol{Ports: "443", Mode: "connect"}, Timing: "balanced", Timeout: config.Duration(time.Minute),
		Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	}))
	if err != nil {
		t.Fatal(err)
	}
	e := Engine{Store: db}
	current := scan("managed-baseline", snapshot("open"))
	current.JobID, current.JobRevision, current.Job = record.ID, record.Revision, record.Job.Name
	current.ConfigHash = record.Job.SecurityHash()
	if _, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, &current, nil); err != nil {
		t.Fatal(err)
	}
	stored, err := db.GetScan(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.BaselineScanID != current.ID || stored.BaselineConfigHash != current.ConfigHash {
		t.Fatalf("initial baseline metadata = %#v, want scan=%s hash=%s", stored, current.ID, current.ConfigHash)
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
