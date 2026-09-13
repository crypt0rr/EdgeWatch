package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
)

func TestRecordJobSilenceAlertPersistsEventAndOutboxAtomically(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	job, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name:     "silent",
		Schedule: "0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.10"},
		TCP:      &config.Protocol{Ports: "443", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.January, 1, 4, 30, 0, 0, time.UTC)
	created := now.Add(-3 * time.Hour)
	event, createdEvent, err := s.RecordJobSilenceAlert(ctx, job.ID, job.Job.Name, created, now, 2*time.Hour, []string{"destination"})
	if err != nil {
		t.Fatal(err)
	}
	if !createdEvent || event.Type != "job-silent" || event.JobID != job.ID {
		t.Fatalf("event = %#v, created = %v", event, createdEvent)
	}
	var eventCount, outboxCount int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE type='job-silent' AND job_id=?`, job.ID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination=?`, "destination").Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 || outboxCount != 1 {
		t.Fatalf("persisted event/outbox = %d/%d, want 1/1", eventCount, outboxCount)
	}
	if _, again, err := s.RecordJobSilenceAlert(ctx, job.ID, job.Job.Name, created, now.Add(30*time.Minute), 2*time.Hour, []string{"destination"}); err != nil {
		t.Fatal(err)
	} else if again {
		t.Fatal("silence alert repeated inside its deduplication window")
	}
}

func TestRecordJobSilenceAlertSkipsRecentSuccess(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	job, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name:     "recent",
		Schedule: "0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.11"},
		TCP:      &config.Protocol{Ports: "443", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.January, 1, 4, 30, 0, 0, time.UTC)
	finished := now.Add(-time.Hour)
	stamp := finished.Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO scans(id,job_id,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json) VALUES(?,?,?,?,?,?,?,?,?,?)`, "recent-scan", job.ID, job.Job.Name, stamp, stamp, "success", "", "Nmap", job.Job.SecurityHash(), []byte(`{"units":[]}`)); err != nil {
		t.Fatal(err)
	}
	if _, created, err := s.RecordJobSilenceAlert(ctx, job.ID, job.Job.Name, now.Add(-24*time.Hour), now, 2*time.Hour, nil); err != nil {
		t.Fatal(err)
	} else if created {
		t.Fatal("recent successful scan generated silence alert")
	}
}

func TestJobSilenceReferenceUsesNewestEligibleEvidence(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	job, err := s.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name:     "reference",
		Schedule: "0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.12"},
		TCP:      &config.Protocol{Ports: "443", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	created := now.Add(-24 * time.Hour)
	if _, err := s.DB.ExecContext(ctx, `UPDATE jobs SET created_at=? WHERE id=?`, created.Format(time.RFC3339Nano), job.ID); err != nil {
		t.Fatal(err)
	}
	eligible := now.Add(-6 * time.Hour)
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_silence_state SET eligible_at=? WHERE job_id=?`, eligible.Format(time.RFC3339Nano), job.ID); err != nil {
		t.Fatal(err)
	}
	finished := now.Add(-2 * time.Hour)
	stamp := finished.Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO scans(id,job_id,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json) VALUES(?,?,?,?,?,?,?,?,?,?)`, "reference-scan", job.ID, job.Job.Name, stamp, stamp, "success", "", "Nmap", job.Job.SecurityHash(), []byte(`{"units":[]}`)); err != nil {
		t.Fatal(err)
	}
	lastSuccess := now.Add(-time.Hour)
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_silence_state SET last_success_at=? WHERE job_id=?`, lastSuccess.Format(time.RFC3339Nano), job.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.JobSilenceReference(ctx, job.ID, created, now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(lastSuccess) {
		t.Fatalf("reference = %s, want newest successful marker %s", got, lastSuccess)
	}
}
