package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestScanPersistenceTimeoutScalesWithResultSize(t *testing.T) {
	for _, test := range []struct {
		hosts int
		want  time.Duration
	}{
		{hosts: 0, want: 10 * time.Second},
		{hosts: 100, want: 12*time.Second + 500*time.Millisecond},
		{hosts: 400, want: 20 * time.Second},
		{hosts: 100000, want: 5 * time.Minute},
		{hosts: -1, want: 10 * time.Second},
	} {
		if got := scanPersistenceTimeout(test.hosts); got != test.want {
			t.Fatalf("scanPersistenceTimeout(%d) = %s, want %s", test.hosts, got, test.want)
		}
	}
}

func TestProgressPercentAndActiveRunUpdates(t *testing.T) {
	for _, test := range []struct {
		name string
		in   scanner.Progress
		want int
	}{
		{name: "empty", want: 0},
		{name: "invocations fallback", in: scanner.Progress{TotalInvocations: 4, CompletedInvocations: 2}, want: 50},
		{name: "negative", in: scanner.Progress{TotalProbes: 4, CompletedProbes: -1}, want: 0},
		{name: "clamped", in: scanner.Progress{TotalProbes: 4, CompletedProbes: 8}, want: 100},
		{name: "probes", in: scanner.Progress{TotalProbes: 4, CompletedProbes: 3}, want: 75},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := progressPercent(test.in); got != test.want {
				t.Fatalf("progressPercent(%#v) = %d, want %d", test.in, got, test.want)
			}
		})
	}

	a := &App{}
	run := &activeRun{scan: model.ActiveScan{StartedAt: time.Now().UTC().Add(-time.Second)}}
	a.running.Store("scan", run)
	a.updateActiveProgress("missing", scanner.Progress{TotalProbes: 10})
	a.updateActiveProgress("scan", scanner.Progress{
		TotalProbes: 100, CompletedProbes: 25, TotalInvocations: 4, CompletedInvocations: 1,
		Protocol: "tcp", CurrentInvocation: 2, TotalBatches: 4, ProcessProgressPercent: 25,
		ElapsedSeconds: 5, LastOutput: "working", ProcessAlive: true, Phase: "scanning",
	})
	got := run.snapshot()
	if got.TotalProbes != 100 || got.CompletedProbes != 25 || got.TotalInvocations != 4 || got.CompletedInvocations != 1 || got.Protocol != "tcp" || got.CurrentInvocation != 2 || got.TotalBatches != 4 || got.ProcessProgressPercent != 25 || got.LastOutput != "working" || !got.ProcessAlive || got.Phase != "scanning" {
		t.Fatalf("active progress = %#v", got)
	}
	a.updateActiveProgress("scan", scanner.Progress{CompletedProbes: 30, CompletedInvocations: 2, ProcessAlive: false})
	a.updateActivePhase("missing", "ignored")
	a.updateActivePhase("scan", "finalizing")
	got = run.snapshot()
	if got.CompletedProbes != 30 || got.CompletedInvocations != 2 || got.ProcessAlive || got.Phase != "finalizing" {
		t.Fatalf("active phase update = %#v", got)
	}
	if (&activeRun{}).snapshot().ElapsedSeconds != 0 {
		t.Fatal("zero-start active run reported elapsed time")
	}
}

func TestActiveProgressDoesNotRegressWhenPhasesExpandWork(t *testing.T) {
	a := &App{}
	run := &activeRun{scan: model.ActiveScan{StartedAt: time.Now().UTC()}}
	a.running.Store("phased", run)
	a.updateActiveProgress("phased", scanner.Progress{TotalProbes: 100, CompletedProbes: 100, TotalInvocations: 1, CompletedInvocations: 1, Phase: "tcp discovery"})
	a.updateActiveProgress("phased", scanner.Progress{TotalProbes: 300, CompletedProbes: 110, TotalInvocations: 3, CompletedInvocations: 1, Phase: "nmap enrichment"})
	got := run.snapshot()
	if got.CompletedProbes != 110 || got.TotalProbes != 300 || got.ProgressPercent != 100 {
		t.Fatalf("phase expansion regressed progress: %#v", got)
	}
	if got.CompletedInvocations != 1 || got.TotalInvocations != 3 {
		t.Fatalf("invocation progress regressed: %#v", got)
	}
	// A stale callback from a previous process must not lower the durable
	// counters or percentage either.
	a.updateActiveProgress("phased", scanner.Progress{TotalProbes: 50, CompletedProbes: 2, TotalInvocations: 1, CompletedInvocations: 0, Phase: "udp scanning"})
	got = run.snapshot()
	if got.CompletedProbes != 110 || got.TotalProbes != 300 || got.ProgressPercent != 100 {
		t.Fatalf("stale progress regressed state: %#v", got)
	}
}

func TestCheckScanWorkBudgetAndBeginRunFallback(t *testing.T) {
	a := &App{Config: &config.Config{Scheduler: config.Scheduler{MaxProbeCount: 1}}}
	job := config.Job{Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1-2", Mode: "connect"}}
	if _, err := a.CheckScanWorkBudget(job); !errors.Is(err, ErrScanWorkBudget) {
		t.Fatalf("budget error = %v", err)
	}
	job.AllowHighCost = true
	if _, err := a.CheckScanWorkBudget(job); err != nil {
		t.Fatalf("high-cost override error = %v", err)
	}
	if _, err := a.CheckScanWorkBudget(config.Job{TCP: &config.Protocol{Ports: "invalid"}}); err == nil {
		t.Fatal("invalid estimate was accepted")
	}

	oldCtx, oldCancel := context.WithCancel(context.Background())
	a.runCtx, a.runCancel, a.runAccepting, a.runStarted = oldCtx, oldCancel, true, false
	newCtx, owner := a.BeginRun(context.Background())
	if !owner || newCtx == oldCtx || newCtx == nil {
		t.Fatal("BeginRun did not replace the fallback lifecycle context")
	}
	a.StopRun()
}

func TestNaabuUsesDedicatedBudgetAndHardCeiling(t *testing.T) {
	a := &App{Config: &config.Config{Scheduler: config.Scheduler{
		MaxProbeCount:      config.DefaultMaxProbeCount,
		MaxNaabuProbeCount: config.DefaultNaabuMaxProbeCount,
	}}}
	job := config.NormalizeJob(config.Job{
		Targets: []string{"192.0.2.0/24"},
		TCP:     &config.Protocol{Engine: config.EngineNaabuNmap, Mode: "connect", Ports: "1-65535"},
	})
	estimate, err := a.CheckScanWorkBudget(job)
	if err != nil {
		t.Fatalf("default Naabu /24 budget rejected: %v (estimate %#v)", err, estimate)
	}
	if estimate.Probes != 256*65535 {
		t.Fatalf("Naabu estimate = %d, want %d", estimate.Probes, 256*65535)
	}
	if estimate.NaabuProbes != 256*65535 || estimate.NmapProbes != 0 {
		t.Fatalf("Naabu probe categories = %#v", estimate)
	}

	oversized := job
	oversized.Targets = []string{"192.0.0.0/16"}
	if _, err := a.CheckScanWorkBudget(oversized); !errors.Is(err, ErrScanWorkBudget) {
		t.Fatalf("oversized Naabu job error = %v, want probe budget error", err)
	}
	oversized.AllowHighCost = true
	if _, err := a.CheckScanWorkBudget(oversized); !errors.Is(err, ErrScanWorkBudget) {
		t.Fatalf("hard ceiling override error = %v, want probe budget error", err)
	}
}

func TestNaabuAndUDPUseSeparateProbeBudgets(t *testing.T) {
	a := &App{Config: &config.Config{Scheduler: config.Scheduler{
		MaxProbeCount:      5,
		MaxNaabuProbeCount: config.DefaultNaabuMaxProbeCount,
	}}}
	job := config.NormalizeJob(config.Job{
		Targets: []string{"192.0.2.1"},
		TCP:     &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{ScanType: "connect"}},
		UDP:     &config.Protocol{Ports: "1-6"},
	})
	estimate, err := a.CheckScanWorkBudget(job)
	if !errors.Is(err, ErrScanWorkBudget) {
		t.Fatalf("Naabu+UDP budget error = %v (estimate %#v)", err, estimate)
	}
	if estimate.NaabuProbes != 65535 || estimate.NmapProbes != 6 || estimate.Probes != 65541 {
		t.Fatalf("separate probe categories = %#v", estimate)
	}
}

func TestStartManagedRunReportsLookupAndArchivedErrors(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "managed-run.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var calls sync.WaitGroup
	calls.Add(1)
	var lookupErr error
	if err := a.StartManagedRun("missing", func(_ model.Scan, _ []model.Event, err error) { lookupErr = err; calls.Done() }); err != nil {
		t.Fatal(err)
	}
	calls.Wait()
	if lookupErr == nil || !errors.Is(lookupErr, store.ErrNotFound) {
		t.Fatalf("missing managed run error = %v", lookupErr)
	}
	a.StopRun()

	job := config.NormalizeJob(config.Job{Name: "archived-run", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetJobArchived(ctx, record.ID, true); err != nil {
		t.Fatal(err)
	}
	calls.Add(1)
	var archivedErr error
	if err := a.StartManagedRun(record.ID, func(_ model.Scan, _ []model.Event, err error) { archivedErr = err; calls.Done() }); err != nil {
		t.Fatal(err)
	}
	calls.Wait()
	if archivedErr == nil || archivedErr.Error() != "archived jobs cannot run" {
		t.Fatalf("archived managed run error = %v", archivedErr)
	}
	a.StopRun()
}
