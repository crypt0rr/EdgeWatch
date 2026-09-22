package app

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/notify"
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
	if _, err := db.DB.ExecContext(ctx, `UPDATE job_silence_state SET eligible_at=? WHERE job_id=?`, created.Format(time.RFC3339Nano), record.ID); err != nil {
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

func TestJobSilenceWatchdogRetriesWhenDestinationsCannotBeResolved(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	job := config.NormalizeJob(config.Job{
		Name:     "temporarily-unroutable",
		Schedule: "0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.3"},
		TCP:      &config.Protocol{Ports: "443", Mode: "connect"},
	})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	notifier, err := notify.New(db, []string{"generic://127.0.0.1:9/edgewatch?disabletls=yes&template=json"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.January, 1, 4, 30, 0, 0, time.UTC)
	created := now.Add(-3 * time.Hour)
	if _, err := db.DB.ExecContext(ctx, `UPDATE jobs SET created_at=? WHERE id=?`, created.Format(time.RFC3339Nano), record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE job_silence_state SET eligible_at=? WHERE job_id=?`, created.Format(time.RFC3339Nano), record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `ALTER TABLE managed_notifications RENAME TO managed_notifications_unavailable`); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: db, Notifier: notifier, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), clock: func() time.Time { return now }}
	a.checkJobSilence(ctx, now)
	var eventCount, outboxCount, backoff int
	var nextAlert string
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE type='job-silent' AND job_id=?`, record.ID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox`).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRowContext(ctx, `SELECT backoff_level,next_alert_at FROM job_silence_state WHERE job_id=?`, record.ID).Scan(&backoff, &nextAlert); err != nil {
		t.Fatal(err)
	}
	if eventCount != 0 || outboxCount != 0 || backoff != 0 || nextAlert != "" {
		t.Fatalf("unroutable silence alert changed durable state: events=%d outbox=%d backoff=%d next=%q", eventCount, outboxCount, backoff, nextAlert)
	}
	if _, err := db.DB.ExecContext(ctx, `ALTER TABLE managed_notifications_unavailable RENAME TO managed_notifications`); err != nil {
		t.Fatal(err)
	}
	a.checkJobSilence(ctx, now)
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE type='job-silent' AND job_id=?`, record.ID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox`).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 || outboxCount != 1 {
		t.Fatalf("repaired silence alert did not queue delivery: events=%d outbox=%d", eventCount, outboxCount)
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

func TestCheckJobSilenceBoundedUsesHeartbeatBudget(t *testing.T) {
	now := time.Date(2026, time.January, 1, 4, 30, 0, 0, time.UTC)
	a := &App{}

	// A normal heartbeat shortens the maintenance context to half the
	// heartbeat interval, keeping a slow watchdog query from delaying the next
	// daemon tick.
	a.heartbeatInterval = 2 * time.Second
	a.checkJobSilenceBounded(context.Background(), now)

	// A sub-second heartbeat would otherwise produce a zero duration. The
	// bounded path must still provide a usable timeout rather than passing a
	// context that is already expired.
	a.heartbeatInterval = time.Nanosecond
	a.checkJobSilenceBounded(context.Background(), now)

	// With no configured heartbeat, retain the five-second maintenance budget.
	a.heartbeatInterval = 0
	a.checkJobSilenceBounded(context.Background(), now)
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

func TestJobSilenceThresholdUsesNextExpectedFiring(t *testing.T) {
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	tests := []struct {
		name      string
		schedule  string
		reference time.Time
		want      time.Duration
	}{
		{
			name:      "weekday weekend gap",
			schedule:  "0 9 * * 1-5",
			reference: time.Date(2026, time.January, 2, 9, 0, 0, 0, time.UTC), // Friday
			want:      4 * 24 * time.Hour,
		},
		{
			name:      "selected weekdays",
			schedule:  "0 3 * * 1,2",
			reference: time.Date(2026, time.January, 6, 3, 0, 0, 0, time.UTC), // Tuesday
			want:      12 * 24 * time.Hour,
		},
		{
			name:      "month days",
			schedule:  "0 9 1-5 * *",
			reference: time.Date(2026, time.January, 5, 9, 0, 0, 0, time.UTC),
			want:      28 * 24 * time.Hour,
		},
		{
			name:      "hourly",
			schedule:  "0 * * * *",
			reference: time.Date(2026, time.January, 1, 4, 0, 0, 0, time.UTC),
			want:      2 * time.Hour,
		},
		{
			name:      "weekly",
			schedule:  "0 3 * * 0",
			reference: time.Date(2026, time.January, 4, 3, 0, 0, 0, time.UTC), // Sunday
			want:      14 * 24 * time.Hour,
		},
		{
			name:      "five minute",
			schedule:  "*/5 * * * *",
			reference: time.Date(2026, time.January, 1, 4, 0, 0, 0, time.UTC),
			want:      10 * time.Minute,
		},
		{
			name:      "restricted days every ten minutes",
			schedule:  "*/10 * 1-20 * *",
			reference: time.Date(2026, time.January, 20, 23, 50, 0, 0, time.UTC),
			want:      11*24*time.Hour + 20*time.Minute,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := jobSilenceThreshold(parser, config.Job{Schedule: test.schedule, Timezone: "UTC"}, test.reference)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("threshold = %s, want %s", got, test.want)
			}
		})
	}
}

func TestJobSilenceThresholdPreservesDSTWallClock(t *testing.T) {
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	location, err := time.LoadLocation("Europe/Amsterdam")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		reference time.Time
		want      time.Duration
	}{
		{
			name:      "spring forward",
			reference: time.Date(2026, time.March, 27, 9, 0, 0, 0, location),
			want:      47 * time.Hour,
		},
		{
			name:      "fall back",
			reference: time.Date(2026, time.October, 23, 9, 0, 0, 0, location),
			want:      49 * time.Hour,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := jobSilenceThreshold(parser, config.Job{Schedule: "0 9 * * *", Timezone: "Europe/Amsterdam"}, test.reference)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("threshold = %s, want %s", got, test.want)
			}
		})
	}
}

func TestJobSilenceWatchdogUsesReferenceSpecificDeadline(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	job := config.NormalizeJob(config.Job{
		Name:     "weekday-window",
		Schedule: "0 9 * * 1-5",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.3"},
		TCP:      &config.Protocol{Ports: "443", Mode: "connect"},
	})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	reference := time.Date(2026, time.January, 2, 9, 0, 0, 0, time.UTC) // Friday
	if _, err := db.DB.ExecContext(ctx, `UPDATE jobs SET created_at=? WHERE id=?`, reference.Add(-24*time.Hour).Format(time.RFC3339Nano), record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE job_silence_state SET eligible_at=? WHERE job_id=?`, reference.Format(time.RFC3339Nano), record.ID); err != nil {
		t.Fatal(err)
	}
	stamp := reference.Format(time.RFC3339Nano)
	if _, err := db.DB.ExecContext(ctx, `INSERT INTO scans(id,job_id,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json) VALUES(?,?,?,?,?,?,?,?,?,?)`, "weekday-scan", record.ID, record.Job.Name, stamp, stamp, "success", "", "Nmap", job.SecurityHash(), []byte(`{"units":[]}`)); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a.checkJobSilence(ctx, time.Date(2026, time.January, 5, 10, 0, 0, 0, time.UTC)) // Monday, before Tuesday deadline
	page, err := db.ListJobEventsPage(ctx, record.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 0 {
		t.Fatalf("weekday job alerted during the grace window: %#v", page.Items)
	}
	a.checkJobSilence(ctx, time.Date(2026, time.January, 6, 9, 0, 0, 0, time.UTC)) // Tuesday deadline
	page, err = db.ListJobEventsPage(ctx, record.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || page.Items[0].Type != "job-silent" {
		t.Fatalf("weekday job did not alert at its reference-specific deadline: %#v", page.Items)
	}
}

func TestJobSilenceWatchdogHonorsFutureEligibility(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	job := config.NormalizeJob(config.Job{
		Name:     "resume-grace",
		Schedule: "0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.4"},
		TCP:      &config.Protocol{Ports: "443", Mode: "connect"},
	})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.January, 1, 4, 0, 0, 0, time.UTC)
	created := now.Add(-24 * time.Hour)
	if _, err := db.DB.ExecContext(ctx, `UPDATE jobs SET created_at=? WHERE id=?`, created.Format(time.RFC3339Nano), record.ID); err != nil {
		t.Fatal(err)
	}
	eligible := now.Add(30 * time.Minute)
	if _, err := db.DB.ExecContext(ctx, `UPDATE job_silence_state SET eligible_at=?,last_success_at=? WHERE job_id=?`, eligible.Format(time.RFC3339Nano), created.Format(time.RFC3339Nano), record.ID); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// The watchdog may run before the lifecycle grace begins. It must not use
	// the older creation marker and start a silence window prematurely.
	a.checkJobSilence(ctx, now)
	page, err := db.ListJobEventsPage(ctx, record.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 0 {
		t.Fatalf("resume grace generated an early silence event: %#v", page.Items)
	}

	// The first missed firing after eligibility is still within the
	// representative schedule window (04:30 eligibility, 05:00 firing,
	// 06:00 deadline).
	a.checkJobSilence(ctx, now.Add(90*time.Minute))
	page, err = db.ListJobEventsPage(ctx, record.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 0 {
		t.Fatalf("resume grace generated an early post-resume event: %#v", page.Items)
	}

	a.checkJobSilence(ctx, now.Add(2*time.Hour))
	page, err = db.ListJobEventsPage(ctx, record.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || page.Items[0].Type != "job-silent" {
		t.Fatalf("resume grace did not alert at the expected deadline: %#v", page.Items)
	}
}
