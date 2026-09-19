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
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/robfig/cron/v3"
)

func TestAppRiskHelpersAndSchedulerBranches(t *testing.T) {
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.FixedZone("test", 3600))
	a := &App{clock: func() time.Time { return now }}
	if got := a.nowUTC(); !got.Equal(now.UTC()) {
		t.Fatalf("injected clock = %v, want %v", got, now.UTC())
	}
	if got := (&App{}).nowUTC(); got.IsZero() {
		t.Fatal("default clock returned zero")
	}
	if (&App{}).silenceLogger() == nil {
		t.Fatal("nil logger did not use slog default")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if (&App{Logger: logger}).silenceLogger() != logger {
		t.Fatal("configured logger was not retained")
	}
	// The recovery helper is deliberately tested through a deferred call: it
	// must swallow a panic while allowing the surrounding goroutine to return.
	func() {
		defer a.recoverBackgroundPanic("coverage")
		panic("expected test panic")
	}()
	func() { defer a.recoverBackgroundPanic("no-panic") }()

	cronParser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	if _, err := jobSilenceThreshold(cronParser, config.Job{Timezone: "Mars/Olympus", Schedule: "0 * * * *"}, now); err == nil {
		t.Fatal("invalid timezone accepted")
	}
	if _, err := jobSilenceThreshold(cronParser, config.Job{Timezone: "UTC", Schedule: "not cron"}, now); err == nil {
		t.Fatal("invalid schedule accepted")
	}
	if _, _, ok := cronSilenceDeadline(nil, now); ok {
		t.Fatal("nil schedule produced a deadline")
	}
	parsed, err := cronParser.Parse("0 * * * *")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := cronSilenceDeadline(parsed, time.Time{}); ok {
		t.Fatal("zero reference produced a deadline")
	}
	if got, ok := cronInterval(parsed, time.Time{}); ok || got != 0 {
		t.Fatal("zero reference produced an interval")
	}
	if got := wallClockDuration(time.Time{}, now); got != 0 {
		t.Fatal("zero wall-clock endpoint produced duration")
	}
	if got := wallClockDuration(now, now); got != 0 {
		t.Fatal("equal wall-clock endpoints produced duration")
	}
	if got := addWallDuration(time.Time{}, time.Hour); !got.IsZero() {
		t.Fatal("zero wall-clock value advanced")
	}
	if got := addWallDuration(now, 0); !got.IsZero() {
		t.Fatal("zero wall-clock duration advanced")
	}

	cronLogger := cronSlogLogger{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	cronLogger.Info("info")
	cronLogger.Error(errors.New("error"), "error")
	cronSlogLogger{}.Info("discarded")
	cronSlogLogger{}.Error(errors.New("discarded"), "discarded")
}

func TestAppStartTrackedAndManagedSchedulerSkips(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "scheduler.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Scanner = schedulerFake{}
	bound, owner := a.BeginRun(ctx)
	if !owner {
		t.Fatal("failed to bind scheduler context")
	}
	a.startManagedScheduled(bound, "missing")
	disabled := config.NormalizeJob(config.Job{Name: "disabled", Schedule: "0 * * * *", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}})
	disabledRecord, err := db.CreateJobWithEnabled(ctx, disabled, false)
	if err != nil {
		t.Fatal(err)
	}
	a.startManagedScheduled(bound, disabledRecord.ID)
	archived := disabled
	archived.Name = "archived"
	archivedRecord, err := db.CreateJob(ctx, archived)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetJobArchived(ctx, archivedRecord.ID, true); err != nil {
		t.Fatal(err)
	}
	a.startManagedScheduled(bound, archivedRecord.ID)
	a.StopRun()

	job := config.NormalizeJob(config.Job{Name: "wrapper", Schedule: "0 * * * *", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Second)})
	if _, _, err := a.runJobRecord(ctx, store.JobRecord{ID: "archived", Job: job, Archived: true}, false); err == nil || !strings.Contains(err.Error(), "archived") {
		t.Fatal("archived record was accepted")
	}

	if got := (&App{}).updateDestinations(ctx); got != nil {
		t.Fatal("nil notifier returned destinations")
	}
	var events []model.Event
	a.SetEventHandler(func(event model.Event) { events = append(events, event) })
	a.emitUpdateStatus()
	if len(events) != 1 || events[0].Type != "application.update_status" {
		t.Fatalf("update status event = %#v", events)
	}
}
