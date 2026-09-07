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
