package engine

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestManagedEngineWrappersUseJobIdentityAndQueueDestinations(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	job := config.NormalizeJob(config.Job{Name: "managed-wrapper", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"}, Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateManagedNotification(ctx, "destination", "Test destination", "generic", []byte{1}, []byte{2}, true); err != nil {
		t.Fatal(err)
	}
	e := Engine{Store: db}
	baseline := model.Scan{ID: "managed-baseline", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, Status: "success", ConfigHash: record.Job.SecurityHash(), FinishedAt: time.Now().UTC(), Snapshot: snapshot("")}
	if events, err := e.SuccessForJob(ctx, record.ID, record.Job, baseline); err != nil || len(events) != 1 || events[0].Type != "baseline-complete" {
		t.Fatalf("managed baseline = %#v, %v", events, err)
	}
	changed := baseline
	changed.ID = "managed-change"
	changed.Snapshot = snapshot("open")
	events, err := e.SuccessForJobWithDestinations(ctx, record.ID, record.Job, changed, []string{"managed:destination:1"})
	if err != nil || len(events) != 1 || events[0].Type != "changes-detected" {
		t.Fatalf("managed change = %#v, %v", events, err)
	}
	var outboxCount int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination=?`, "managed:destination:1").Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 1 {
		t.Fatalf("managed outbox rows = %d, want 1", outboxCount)
	}
	failure := changed
	failure.ID = "managed-failure"
	failure.Status = "timed_out"
	failure.Error = "scan exceeded timeout"
	events, err = e.FailureForJobWithDestinations(ctx, record.ID, record.Job.Name, failure, []string{"managed:destination:1"})
	if err != nil || len(events) != 1 || events[0].Type != "scan-failure" {
		t.Fatalf("managed failure = %#v, %v", events, err)
	}
	canceled := failure
	canceled.ID = "managed-canceled"
	canceled.Status = "canceled"
	events, err = e.FailureForJob(ctx, record.ID, record.Job.Name, canceled)
	if err != nil || len(events) != 1 || events[0].Type != "scan-canceled" {
		t.Fatalf("managed cancellation = %#v, %v", events, err)
	}
	if _, err := e.FinalizeManagedScan(ctx, record.ID, record.Job, nil, nil); err == nil {
		t.Fatal("nil managed scan was accepted")
	}
	if got := ScopeDescription(model.Scope{Target: "192.0.2.1", Protocol: "tcp", Ports: "443", ServiceDetection: true}); got != "192.0.2.1 tcp/443 service=true" {
		t.Fatalf("scope description = %q", got)
	}
	if _, err := e.SuccessForJob(ctx, "missing-job", record.Job, baseline); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing managed job error = %v", err)
	}
}
