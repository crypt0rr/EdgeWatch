package app

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestCheckScanCycleProbeBudgetCoversSplitAndHardLimits(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	jobValue := config.NormalizeJob(config.Job{
		Name: "budget-cycle", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Mode: "connect", Ports: "1-65535", Naabu: &config.NaabuOptions{ScanType: "connect"}},
	})
	record, err := s.CreateJob(ctx, jobValue)
	if err != nil {
		t.Fatal(err)
	}
	plan := scanner.WorkPlan{
		Job: record.Job,
		Units: []scanner.WorkUnit{
			{Sequence: 0, Engine: config.EngineNaabuNmap, Phase: "discovery", Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1-65535", Probes: 2},
			{Sequence: 1, Engine: config.EngineNmap, Phase: "enrichment", Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "22", Probes: 3},
		},
	}
	cycle, err := s.CreateScanCycle(ctx, store.ScanCycleRecord{JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}

	a := &App{Store: s, Config: &config.Config{Scheduler: config.Scheduler{MaxProbeCount: 2, MaxNaabuProbeCount: 1}}}
	if err := a.CheckScanCycleProbeBudget(ctx, cycle, record.Job); err == nil || !errors.Is(err, ErrScanWorkBudget) {
		t.Fatalf("Naabu budget result = %v", err)
	}
	a.Config.Scheduler.MaxNaabuProbeCount = 10
	if err := a.CheckScanCycleProbeBudget(ctx, cycle, record.Job); err == nil || !errors.Is(err, ErrScanWorkBudget) {
		t.Fatalf("Nmap budget result = %v", err)
	}
	record.Job.AllowHighCost = true
	if err := a.CheckScanCycleProbeBudget(ctx, cycle, record.Job); err != nil {
		t.Fatalf("high-cost cycle result = %v", err)
	}
	if err := a.CheckScanCycleProbeBudget(ctx, cycle, config.Job{TCP: &config.Protocol{Engine: config.EngineNmap}}); err != nil {
		t.Fatalf("Nmap-only cycle result = %v", err)
	}
	// SQLite's aggregate query intentionally treats an unknown cycle as an
	// empty total. A closed store, however, must still surface the read error.
	closedStore, err := store.Open(filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := closedStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := (&App{Store: closedStore, Config: a.Config}).CheckScanCycleProbeBudget(ctx, store.ScanCycleRecord{ID: "missing"}, record.Job); err == nil {
		t.Fatal("closed store error was swallowed")
	}

	hardJob := jobValue
	hardJob.Name = "hard-limit"
	hardRecord, err := s.CreateJob(ctx, hardJob)
	if err != nil {
		t.Fatal(err)
	}
	hardPlan := scanner.WorkPlan{Job: hardRecord.Job, Units: []scanner.WorkUnit{{Sequence: 0, Engine: config.EngineNaabuNmap, Phase: "discovery", Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1-65535", Probes: config.MaxProbeCountLimit + 1}}}
	hardCycle, err := s.CreateScanCycle(ctx, store.ScanCycleRecord{JobID: hardRecord.ID, Job: hardRecord.Job.Name, JobRevision: hardRecord.Revision, StartedAt: time.Now().UTC(), Plan: hardPlan})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.CheckScanCycleProbeBudget(ctx, hardCycle, hardRecord.Job); err == nil || !errors.Is(err, ErrScanWorkBudget) {
		t.Fatalf("hard ceiling result = %v", err)
	}
}
