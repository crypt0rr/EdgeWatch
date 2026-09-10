package app

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/robfig/cron/v3"
)

func TestJobSilenceWatchdogAlertsOncePerScheduleWindow(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	job := config.NormalizeJob(config.Job{
		Name:     "silent-job",
		Schedule: "0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.1"},
		TCP:      &config.Protocol{Ports: "443", Mode: "connect"},
	})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.January, 1, 4, 30, 0, 0, time.UTC)
	created := now.Add(-3 * time.Hour)
	if _, err := db.DB.ExecContext(ctx, `UPDATE jobs SET created_at=? WHERE id=?`, created.Format(time.RFC3339Nano), record.ID); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), clock: func() time.Time { return now }}

	a.checkJobSilence(ctx, now)
	a.checkJobSilence(ctx, now.Add(30*time.Minute))

	page, err := db.ListJobEventsPage(ctx, record.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("silence events = %#v (total %d), want one", page.Items, page.Total)
	}
	if got := page.Items[0]; got.Type != "job-silent" || got.JobID != record.ID || got.Job != job.Name {
		t.Fatalf("silence event = %#v", got)
	}
}

func TestJobSilenceWatchdogSkipsActiveJob(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	job := config.NormalizeJob(config.Job{
		Name:     "active-job",
		Schedule: "0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.2"},
		TCP:      &config.Protocol{Ports: "443", Mode: "connect"},
	})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.January, 1, 4, 30, 0, 0, time.UTC)
	created := now.Add(-3 * time.Hour)
	if _, err := db.DB.ExecContext(ctx, `UPDATE jobs SET created_at=? WHERE id=?`, created.Format(time.RFC3339Nano), record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `INSERT INTO job_leases(job,owner,expires_at) VALUES(?,?,?)`, record.ID, "test", now.Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a.checkJobSilence(ctx, now)
	page, err := db.ListJobEventsPage(ctx, record.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 0 {
		t.Fatalf("active job generated silence event: %#v", page.Items)
	}
}

func TestCronIntervalHandlesSlowSchedules(t *testing.T) {
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	parsed, err := parser.Parse("CRON_TZ=UTC 0 3 * * 0")
	if err != nil {
		t.Fatal(err)
	}
	interval, ok := cronInterval(parsed, time.Date(2026, time.January, 8, 12, 0, 0, 0, time.UTC))
	if !ok || interval != 7*24*time.Hour {
		t.Fatalf("weekly interval = %s, %v", interval, ok)
	}
}
