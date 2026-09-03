package app

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/robfig/cron/v3"
)

type schedulerFake struct{}

func (schedulerFake) Version(context.Context) string { return "fake" }
func (schedulerFake) Scan(context.Context, config.Job) (model.Snapshot, error) {
	return model.Snapshot{}, nil
}

func TestManagedSchedulerReconcilesCreateUpdateAndArchive(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := &config.Config{Version: 1, Database: "test", Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := New(cfg, s, "missing", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Scanner = schedulerFake{}
	c := cron.New(cron.WithParser(cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)))
	a.cron = c
	job := config.NormalizeJob(config.Job{Name: "hourly", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced"})
	record, err := s.CreateJob(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.reconcileSchedules(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(a.entries) != 1 {
		t.Fatalf("entries after create: %d", len(a.entries))
	}
	updated := record.Job
	updated.Schedule = "15 * * * *"
	if _, _, err := s.UpdateJob(context.Background(), record.ID, record.Revision, updated, true, false, false); err != nil {
		t.Fatal(err)
	}
	if err := a.reconcileSchedules(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(a.entries) != 1 {
		t.Fatalf("entries after update: %d", len(a.entries))
	}
	if err := s.SetJobArchived(context.Background(), record.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := a.reconcileSchedules(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(a.entries) != 0 {
		t.Fatalf("entries after archive: %d", len(a.entries))
	}
}
