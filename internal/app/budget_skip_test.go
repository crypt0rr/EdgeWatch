package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestScheduledBudgetSkipIsRecordedOnceUntilAScanRuns(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{
		Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour),
		Scheduler:     config.Scheduler{MaxConcurrent: 1, MaxProbeCount: 100},
		Web:           config.Web{Listen: "127.0.0.1:8080"},
		Notifications: config.Notifications{URLs: []string{"generic://localhost/edgewatch?disabletls=yes&template=json"}},
	}
	a, err := New(cfg, s, "missing", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Scanner = schedulerFake{}
	record, err := defaultTenant(s).CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "over-budget", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
		TCP: &config.Protocol{Ports: "1-1000", Mode: "connect", Engine: config.EngineNmap}, Timing: "balanced", Timeout: config.Duration(time.Minute),
	}))
	if err != nil {
		t.Fatal(err)
	}
	live := make(chan model.Event, 32)
	a.SetEventHandler(func(event model.Event) { live <- event })
	scheduled := func() {
		t.Helper()
		a.BeginRun(ctx)
		a.startManagedScheduled(ctx, store.DefaultTenantScope(), record.ID)
		a.StopRun()
	}
	budgetEvents := func() (events []model.Event, outbox int) {
		t.Helper()
		rows, err := s.DB.QueryContext(ctx, `SELECT payload_json FROM events ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var event model.Event
			if err := json.Unmarshal(raw, &event); err != nil {
				t.Fatal(err)
			}
			if event.Type == model.EventScanBudgetExceeded {
				events = append(events, event)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE CAST(payload_json AS TEXT) LIKE '%scan-budget-exceeded%'`).Scan(&outbox); err != nil {
			t.Fatal(err)
		}
		return events, outbox
	}

	scheduled()
	events, outbox := budgetEvents()
	if len(events) != 1 || outbox != 1 || events[0].JobID != record.ID {
		t.Fatalf("first skip = %+v (outbox %d), want one delivered event", events, outbox)
	}
	if want := "Scheduled scan skipped: about 1000 probes exceed the probe budget of 100. An administrator must approve high-cost scans for this job, or its scope must be reduced."; events[0].Message != want {
		t.Fatalf("skip message = %q, want %q", events[0].Message, want)
	}
	var sawLive bool
	for len(live) > 0 {
		if event := <-live; event.Type == model.EventScanBudgetExceeded {
			sawLive = true
		}
	}
	if !sawLive {
		t.Fatal("the budget skip was not published as a live update")
	}

	// The same scope and budget are not reported again.
	scheduled()
	if events, outbox := budgetEvents(); len(events) != 1 || outbox != 1 {
		t.Fatalf("repeated skip = %d events, %d deliveries, want 1 and 1", len(events), outbox)
	}

	// Once a scan runs, a later skip is reported again.
	a.Config.Scheduler.MaxProbeCount = 0
	if _, _, err := a.RunJobRecord(ctx, record); err != nil {
		t.Fatal(err)
	}
	a.Config.Scheduler.MaxProbeCount = 100
	scheduled()
	if events, outbox := budgetEvents(); len(events) != 2 || outbox != 2 {
		t.Fatalf("skip after a scan ran = %d events, %d deliveries, want 2 and 2", len(events), outbox)
	}
}
