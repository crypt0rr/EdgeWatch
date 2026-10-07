package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func interruptionTestApp(t *testing.T) (*App, *store.Store) {
	t.Helper()
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	cfg := &config.Config{
		Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour),
		Scheduler:     config.Scheduler{MaxConcurrent: 1},
		Web:           config.Web{Listen: "127.0.0.1:8080"},
		Notifications: config.Notifications{URLs: []string{"generic://localhost/edgewatch?disabletls=yes&template=json"}},
	}
	a, err := New(cfg, s, "missing", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return a, s
}

func outboxCount(t *testing.T, s *store.Store) int {
	t.Helper()
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM outbox`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestShutdownInterruptedScanIsRecordedWithoutNotification(t *testing.T) {
	t.Parallel()
	a, s := interruptionTestApp(t)
	record, err := defaultTenant(s).CreateJob(context.Background(), config.NormalizeJob(config.Job{
		Name: "interrupted", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"},
		TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timing: "balanced", Timeout: config.Duration(time.Minute),
	}))
	if err != nil {
		t.Fatal(err)
	}
	blocking := &blockingScanner{started: make(chan struct{}), release: make(chan struct{})}
	a.Scanner = blocking
	runCtx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	var scan model.Scan
	var events []model.Event
	var runErr error
	go func() {
		scan, events, runErr = a.RunJobRecord(runCtx, record)
		close(done)
	}()
	select {
	case <-blocking.started:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not start")
	}
	// The daemon stopping cancels the run context, not this scan.
	stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("interrupted scan did not finish")
	}
	if !errors.Is(runErr, context.Canceled) || scan.Status != "canceled" || scan.Error != ScanInterruptedMessage {
		t.Fatalf("interrupted scan = status %q error %q err %v", scan.Status, scan.Error, runErr)
	}
	if len(events) != 1 || events[0].Type != model.EventScanInterrupted || events[0].Message != "Scan interrupted because EdgeWatch stopped" {
		t.Fatalf("interrupted scan events = %#v", events)
	}
	if count := outboxCount(t, s); count != 0 {
		t.Fatalf("an interrupted scan queued %d notifications", count)
	}
	var raw []byte
	if err := s.DB.QueryRow(`SELECT payload_json FROM events ORDER BY id DESC LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var stored model.Event
	if err := json.Unmarshal(raw, &stored); err != nil || stored.Type != model.EventScanInterrupted {
		t.Fatalf("activity history = %s (%v), want the interruption", raw, err)
	}
}

func TestShutdownInterruptedResumableScanKeepsProgressWithoutNotification(t *testing.T) {
	t.Parallel()
	a, s := interruptionTestApp(t)
	probe := &resumableTestScanner{}
	a.Scanner = probe
	record, err := defaultTenant(s).CreateJob(context.Background(), config.NormalizeJob(config.Job{
		Name: "broad", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
		TCP: &config.Protocol{Ports: "1-2", Mode: "syn"}, Timeout: config.Duration(time.Minute), ResumeWindow: config.Duration(time.Hour),
	}))
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	var scan model.Scan
	var events []model.Event
	go func() {
		scan, events, _ = a.RunJobRecord(runCtx, record)
		close(done)
	}()
	// The second unit blocks until its context ends; stop once it runs.
	deadline := time.Now().Add(5 * time.Second)
	for {
		probe.mu.Lock()
		started := probe.calls[1] > 0
		probe.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("second work unit did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("interrupted resumable scan did not finish")
	}
	if scan.Status != "canceled" || scan.Error != ScanInterruptedMessage+"; progress was saved" || scan.CycleStatus != "paused" {
		t.Fatalf("interrupted resumable scan = status %q error %q cycle %q", scan.Status, scan.Error, scan.CycleStatus)
	}
	if len(events) != 1 || events[0].Type != model.EventScanInterrupted {
		t.Fatalf("interrupted resumable scan events = %#v", events)
	}
	if count := outboxCount(t, s); count != 0 {
		t.Fatalf("an interrupted resumable scan queued %d notifications", count)
	}
}

func TestCancelRequestOutlivesProgressAndEndsAtFinalization(t *testing.T) {
	t.Parallel()
	a := &App{}
	scope := store.DefaultTenantScope()
	canceled := false
	run := &activeRun{scan: model.ActiveScan{ID: "scan", Phase: "scanning"}, cancel: func() { canceled = true }}
	a.registerRun(scope.ID(), "scan", run)
	if err := a.CancelScan(scope, "scan"); err != nil || !canceled {
		t.Fatalf("CancelScan = %v, canceled %v", err, canceled)
	}
	// Nmap and Naabu report one last progress update when their process is
	// stopped. The phase follows it; the cancellation request stays visible.
	a.updateActiveProgress("scan", scanner.Progress{Phase: "scanning"})
	if got := run.snapshot(); !got.CancelRequested || got.Phase != "scanning" {
		t.Fatalf("after progress = cancel_requested %v phase %q", got.CancelRequested, got.Phase)
	}
	a.beginActiveFinalization("scan")
	if got := run.snapshot(); !got.CancelRequested || got.Phase != "finalizing" {
		t.Fatalf("after finalization began = cancel_requested %v phase %q", got.CancelRequested, got.Phase)
	}
	if err := a.CancelScan(scope, "scan"); !errors.Is(err, ErrScanFinalizing) {
		t.Fatalf("CancelScan during finalization = %v, want ErrScanFinalizing", err)
	}
}

func TestInterruptedByShutdownNeedsAStoppedRunAndNoCancelRequest(t *testing.T) {
	t.Parallel()
	live := context.Background()
	stopped := canceledContext()
	if (&activeRun{}).interruptedByShutdown(live, stopped) {
		t.Fatal("a scan canceled while the run context is live was read as a shutdown")
	}
	if !(&activeRun{}).interruptedByShutdown(stopped, stopped) {
		t.Fatal("a scan stopped with its run context was not read as a shutdown")
	}
	if (&activeRun{scan: model.ActiveScan{CancelRequested: true}}).interruptedByShutdown(stopped, stopped) {
		t.Fatal("a requested cancellation during shutdown was read as a shutdown")
	}
	var missing *activeRun
	if !missing.interruptedByShutdown(stopped, stopped) {
		t.Fatal("a scan without an active run was not read as a shutdown")
	}
	timedOut, cancel := context.WithTimeout(live, 0)
	defer cancel()
	<-timedOut.Done()
	if (&activeRun{}).interruptedByShutdown(stopped, timedOut) {
		t.Fatal("a timed-out scan was read as a shutdown")
	}
}
