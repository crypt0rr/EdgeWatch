package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestAppUtilityMethodsAndLifecycleBinding(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	job := config.NormalizeJob(config.Job{Name: "configured", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}})
	cfg := &config.Config{Version: 1, Database: s.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}, Jobs: []config.Job{job}}
	a, err := New(cfg, s, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := a.Job("configured"); err != nil || got.Name != job.Name {
		t.Fatalf("configured job = %#v, %v", got, err)
	}
	if _, err := a.Job("missing"); err == nil || !strings.Contains(err.Error(), "unknown job") {
		t.Fatalf("missing job error = %v", err)
	}

	budgetErr := &ScanWorkBudgetError{Estimate: config.WorkEstimate{Probes: 42}, Budget: 10}
	if !errors.Is(budgetErr, ErrScanWorkBudget) || !strings.Contains(budgetErr.Error(), "42 probes exceeds budget 10") {
		t.Fatalf("budget error = %v", budgetErr)
	}
	if encoded := JSON(map[string]string{"status": "ok"}); !strings.Contains(encoded, `"status": "ok"`) {
		t.Fatalf("JSON utility = %q", encoded)
	}

	var received []model.Event
	a.SetEventHandler(func(event model.Event) { received = append(received, event) })
	a.emitEvents([]model.Event{{Type: "one"}, {Type: "two"}})
	if len(received) != 2 || received[1].Type != "two" {
		t.Fatalf("event handler received = %#v", received)
	}
	a.SetEventHandler(nil)
	a.emitEvents([]model.Event{{Type: "ignored"}})
	if len(received) != 2 {
		t.Fatalf("nil event handler changed received events = %#v", received)
	}

	a.RefreshSchedules()
	select {
	case <-a.scheduleWake:
	default:
		t.Fatal("schedule refresh was not signaled")
	}
	a.WakeDelivery()
	select {
	case <-a.deliveryWake:
	default:
		t.Fatal("delivery wake was not signaled")
	}

	first, owner := a.BeginRun(ctx)
	if !owner || first == nil {
		t.Fatal("first BeginRun did not create a lifecycle binding")
	}
	second, owner := a.BeginRun(ctx)
	if owner || second != first {
		t.Fatal("second BeginRun replaced an active lifecycle binding")
	}
	a.StopRun()
	if err := a.StartManagedRun("missing", nil); !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("managed run after shutdown error = %v", err)
	}
}

func TestAppRunJobAndScheduledWrappers(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	job := config.NormalizeJob(config.Job{Name: "scheduled-wrapper", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Second)})
	cfg := &config.Config{Version: 1, Database: s.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, s, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Scanner = schedulerFake{}
	if scan, _, err := a.RunJob(ctx, job); err != nil || scan.Status != "success" {
		t.Fatalf("unmanaged RunJob = %#v, %v", scan, err)
	}
	if _, err := s.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	bound, owner := a.BeginRun(ctx)
	if !owner {
		t.Fatal("scheduled wrapper did not own the lifecycle")
	}
	a.startScheduled(bound, job)
	a.StopRun()
	bound, owner = a.BeginRun(ctx)
	if !owner {
		t.Fatal("managed scheduled wrapper did not own the lifecycle")
	}
	jobs, err := s.ListJobs(ctx, false)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("scheduled wrapper jobs = %#v, %v", jobs, err)
	}
	a.startManagedScheduled(bound, jobs[0].ID)
	a.StopRun()
	if a.startTracked(func() {}) {
		t.Fatal("startTracked accepted work after StopRun")
	}
}

func TestResumableProgressAndFailureMetadataHelpers(t *testing.T) {
	cycle := store.ScanCycleRecord{ID: "cycle", AttemptCount: 2, Status: "running", CompletedProbes: 3, TotalProbes: 10, CompletedUnits: 1, TotalUnits: 4, NoProgressAttempts: 1}
	run := &activeRun{}
	setActiveCycle(run, cycle, "starting", 2)
	setActiveCycleProgress(run, cycle, scanner.Progress{CompletedProbes: 2}, scanner.WorkUnit{Ports: "100-101", Addresses: []string{"192.0.2.1"}})
	active := run.snapshot()
	if active.CycleID != cycle.ID || active.CurrentUnitPorts != "100-101" || active.CurrentUnitAddresses != 1 || active.CompletedProbes != 5 || active.TotalProbes != 10 {
		t.Fatalf("active cycle progress = %#v", active)
	}
	setActiveCycle(nil, cycle, "ignored", 0)
	setActiveCycleProgress(nil, cycle, scanner.Progress{}, scanner.WorkUnit{})

	db, err := store.Open(filepath.Join(t.TempDir(), "cycle.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	jobRecord, err := db.CreateJob(context.Background(), config.NormalizeJob(config.Job{Name: "cycle-job", Schedule: "0 * * * *", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}}))
	if err != nil {
		t.Fatal(err)
	}
	plan := scanner.WorkPlan{Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1}}}
	created, err := db.CreateScanCycle(context.Background(), store.ScanCycleRecord{ID: "expired", JobID: jobRecord.ID, Job: jobRecord.Job.Name, Plan: plan, ExpiresAt: time.Now().UTC().Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExpireScanCycles(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	scan := model.Scan{}
	applyCycleFailureState(context.Background(), db, &scan, created.ID, "fallback")
	if scan.Status != "timed_out" || scan.CycleStatus != "expired" {
		t.Fatalf("expired cycle metadata = %#v", scan)
	}
	missing := model.Scan{}
	applyCycleFailureState(context.Background(), db, &missing, "missing", "fallback")
	if missing.Status != "failed" || missing.Error != "fallback" {
		t.Fatalf("missing cycle metadata = %#v", missing)
	}
}
