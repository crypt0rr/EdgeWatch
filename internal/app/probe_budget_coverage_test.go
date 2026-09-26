package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

type budgetedProgressTestScanner struct {
	called bool
}

func (s *budgetedProgressTestScanner) Version(context.Context) string { return "budgeted-test" }

func (s *budgetedProgressTestScanner) Scan(ctx context.Context, job config.Job) (model.Snapshot, error) {
	return s.ScanWithProgress(ctx, job, nil)
}

func (s *budgetedProgressTestScanner) ScanWithProgress(context.Context, config.Job, scanner.ProgressReporter) (model.Snapshot, error) {
	return model.Snapshot{}, nil
}

func (s *budgetedProgressTestScanner) ScanWithProgressBudget(_ context.Context, _ config.Job, report scanner.ProgressReporter, check func(int64, int64) error) (model.Snapshot, error) {
	s.called = true
	if report != nil {
		report(scanner.Progress{Phase: "budgeted"})
	}
	if err := check(65535, 1); err != nil {
		return model.Snapshot{}, err
	}
	return model.Snapshot{}, nil
}

func TestRunJobUsesBudgetedScannerForDirectNaabuPipeline(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{
		Version: 1, Database: db.Path, Retention: config.Duration(time.Hour),
		Scheduler: config.Scheduler{MaxConcurrent: 1, MaxProbeCount: 10, MaxNaabuProbeCount: config.DefaultNaabuMaxProbeCount},
		Web:       config.Web{Listen: "127.0.0.1:8080"},
	}
	a, err := New(cfg, db, "missing-nmap", nil)
	if err != nil {
		t.Fatal(err)
	}
	fake := &budgetedProgressTestScanner{}
	a.Scanner = fake
	job := config.NormalizeJob(config.Job{
		Name: "direct-naabu-budget", Targets: []string{"192.0.2.1"}, Timeout: config.Duration(time.Minute),
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{ScanType: "connect"}},
	})
	scan, _, err := a.RunJob(ctx, job)
	if err != nil || scan.Status != "success" {
		t.Fatalf("direct budgeted scan = %#v, err=%v", scan, err)
	}
	if !fake.called {
		t.Fatal("direct Naabu run did not use the budgeted scanner hook")
	}
}

func TestCheckScanCycleProbeBudgetCoversSplitAndHardLimits(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(storetest.FreshPath(t))
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
	if err := a.CheckScanCycleProbeBudget(ctx, cycle, config.Job{TCP: &config.Protocol{Engine: config.EngineNmap}}); err == nil || !errors.Is(err, ErrScanWorkBudget) {
		t.Fatalf("Nmap-only cycle result = %v, want budget error", err)
	}
	// SQLite's aggregate query intentionally treats an unknown cycle as an
	// empty total. A closed store, however, must still surface the read error.
	closedStore, err := store.Open(storetest.FreshPath(t))
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

func TestResolvedPlanProbeTotalsPreferConcreteUnits(t *testing.T) {
	plan := scanner.WorkPlan{
		TotalProbes: 8, // lower than the concrete unit sum; never undercount.
		Units: []scanner.WorkUnit{
			{Phase: "discovery", Probes: 6},
			{Phase: "enrichment", Probes: 4},
		},
	}
	discovery, nmapProbes := resolvedPlanProbeTotals(plan)
	if discovery != 6 || nmapProbes != 4 {
		t.Fatalf("concrete plan totals = discovery %d nmap %d, want 6/4", discovery, nmapProbes)
	}

	plan.TotalProbes = 20 // an unexplained declared remainder is conservative Nmap work.
	discovery, nmapProbes = resolvedPlanProbeTotals(plan)
	if discovery != 6 || nmapProbes != 14 {
		t.Fatalf("declared plan totals = discovery %d nmap %d, want 6/14", discovery, nmapProbes)
	}

	discovery, nmapProbes = resolvedPlanProbeTotals(scanner.WorkPlan{TotalProbes: 9})
	if discovery != 0 || nmapProbes != 9 {
		t.Fatalf("unitless plan totals = discovery %d nmap %d, want 0/9", discovery, nmapProbes)
	}
}

func TestResolvedPlanBudgetRejectsExpandedWorkBeforeCycleCreation(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cfg := &config.Config{
		Version:   1,
		Database:  db.Path,
		Retention: config.Duration(time.Hour),
		Scheduler: config.Scheduler{MaxConcurrent: 1, MaxProbeCount: 5, MaxNaabuProbeCount: 5},
		Web:       config.Web{Listen: "127.0.0.1:8080"},
	}
	a, err := New(cfg, db, "missing-nmap", nil)
	if err != nil {
		t.Fatal(err)
	}
	job := config.NormalizeJob(config.Job{
		Name: "expanded-budget", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"edge.example"},
		TCP: &config.Protocol{Ports: "1-6", Mode: "connect"}, Timeout: config.Duration(time.Minute), ResumeWindow: config.Duration(time.Hour),
	})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	// This models a resolved DNS plan: six concrete probes are represented by
	// one Nmap unit even though the preflight logical-target estimate is one.
	plan := scanner.WorkPlan{Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.1", "192.0.2.2"}, Ports: "1-3", Probes: 6}}}
	var scan model.Scan
	handled, _, runErr := a.runResumableAttempt(ctx, ctx, job, record.ID, &scan, nil, coverageResumableScanner{plan: plan}, false)
	if !handled || !errors.Is(runErr, ErrScanWorkBudget) || scan.Status != "failed" {
		t.Fatalf("resolved budget result = handled %v scan %#v err %v", handled, scan, runErr)
	}
	if _, err := db.GetActiveScanCycle(ctx, record.ID); !errors.Is(err, store.ErrNoScanCycle) {
		t.Fatalf("over-budget plan created a cycle: %v", err)
	}
}

// growingResolver answers the first lookup with one address and every later
// lookup with twenty, modelling a DNS answer that grows between the plan and
// the scan.
type growingResolver struct {
	mu    sync.Mutex
	calls int
}

func (r *growingResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.calls == 1 {
		return []net.IP{net.ParseIP("192.0.2.1")}, nil
	}
	addresses := make([]net.IP, 0, 20)
	for host := 1; host <= 20; host++ {
		addresses = append(addresses, net.ParseIP(fmt.Sprintf("192.0.2.%d", host)))
	}
	return addresses, nil
}

// A plan with one unit runs on the direct scanner path, which resolves DNS
// again, and file-managed jobs always do. The work that path executes must be
// the work that was checked against scheduler.max_probe_count: a grown DNS
// answer is rejected before Nmap starts.
func TestDirectScanRechecksProbeBudgetAfterResolvingAgain(t *testing.T) {
	for _, managed := range []bool{true, false} {
		t.Run(fmt.Sprintf("managed=%t", managed), func(t *testing.T) {
			ctx := context.Background()
			db, err := store.Open(storetest.FreshPath(t))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			cfg := &config.Config{
				Version: 1, Database: db.Path, Retention: config.Duration(time.Hour),
				Scheduler: config.Scheduler{MaxConcurrent: 1, MaxProbeCount: 10, MaxNaabuProbeCount: config.DefaultNaabuMaxProbeCount},
				Web:       config.Web{Listen: "127.0.0.1:8080"},
			}
			a, err := New(cfg, db, "missing-nmap", nil)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			marker := filepath.Join(dir, "nmap-ran")
			nmapPath := filepath.Join(dir, "nmap")
			if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > "+marker+"\nexit 1\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			resolver := &growingResolver{}
			direct := scanner.New(nmapPath)
			direct.Resolver = resolver
			a.Scanner = direct
			job := config.NormalizeJob(config.Job{
				Name: "growing-dns", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"edge.example"}, MaxExpandedHosts: 32,
				TCP: &config.Protocol{Engine: config.EngineNmap, Ports: "1-5", Mode: "connect"}, Timeout: config.Duration(time.Minute), ResumeWindow: config.Duration(time.Hour),
			})
			var scan model.Scan
			var runErr error
			if managed {
				record, err := db.CreateJob(ctx, job)
				if err != nil {
					t.Fatal(err)
				}
				scan, _, runErr = a.RunJobRecord(ctx, record)
			} else {
				scan, _, runErr = a.RunJob(ctx, job)
			}
			if !errors.Is(runErr, ErrScanWorkBudget) {
				t.Fatalf("run = %v, want %v", runErr, ErrScanWorkBudget)
			}
			if scan.Status != "failed" || !strings.Contains(scan.Error, ErrScanWorkBudget.Error()) {
				t.Fatalf("scan after DNS growth = %q (%q), want a probe-budget failure", scan.Status, scan.Error)
			}
			if args, err := os.ReadFile(marker); !os.IsNotExist(err) {
				t.Fatalf("Nmap ran with unchecked work: %q (%v)", args, err)
			}
			if resolver.calls != 2 {
				t.Fatalf("resolver calls = %d, want the plan and the scan", resolver.calls)
			}
		})
	}
}
