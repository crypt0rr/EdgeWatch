package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
)

func TestRecordJobSilenceAlertPersistsEventAndOutboxAtomically(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(freshTestDatabasePath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	job, err := defaultTenant(s).CreateJob(ctx, config.NormalizeJob(config.Job{
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
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_silence_state SET eligible_at=? WHERE job_id=?`, created.Format(time.RFC3339Nano), job.ID); err != nil {
		t.Fatal(err)
	}
	event, createdEvent, err := s.System().RecordJobSilenceAlert(ctx, job.ID, job.Job.Name, created, now, 2*time.Hour, []string{"destination"})
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
	if _, again, err := s.System().RecordJobSilenceAlert(ctx, job.ID, job.Job.Name, created, now.Add(30*time.Minute), 2*time.Hour, []string{"destination"}); err != nil {
		t.Fatal(err)
	} else if again {
		t.Fatal("silence alert repeated inside its deduplication window")
	}
}

func TestRecordJobSilenceAlertSkipsRecentSuccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(freshTestDatabasePath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	job, err := defaultTenant(s).CreateJob(ctx, config.NormalizeJob(config.Job{
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
	if _, created, err := s.System().RecordJobSilenceAlert(ctx, job.ID, job.Job.Name, now.Add(-24*time.Hour), now, 2*time.Hour, nil); err != nil {
		t.Fatal(err)
	} else if created {
		t.Fatal("recent successful scan generated silence alert")
	}
}

func TestJobSilenceWatchdogCountsRecentResumableProgressAsActivity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	job, err := defaultTenant(s).CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "resumable-progress", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.14"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	reference := job.CreatedAt.UTC()
	now := reference.Add(3 * time.Hour)
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_silence_state SET eligible_at=? WHERE job_id=?`, reference.Format(time.RFC3339Nano), job.ID); err != nil {
		t.Fatal(err)
	}
	plan := scanner.WorkPlan{Units: []scanner.WorkUnit{
		{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.14"}, Ports: "22", PortCount: 1, Probes: 1},
		{Sequence: 1, Protocol: "tcp", Addresses: []string{"192.0.2.14"}, Ports: "443", PortCount: 1, Probes: 1},
	}}
	cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{
		JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(),
		ExecutionHash: job.Job.ExecutionHash(), Plan: plan, StartedAt: reference, UpdatedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	unit, err := s.System().NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := s.System().CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, model.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycle_units SET finished_at=? WHERE cycle_id=? AND status='completed'`, now.Add(-time.Minute).Format(time.RFC3339Nano), cycle.ID); err != nil {
		t.Fatal(err)
	}
	threshold := 2 * time.Hour
	if due, err := s.System().JobSilenceDue(ctx, job.ID, reference, now, threshold); err != nil || due {
		t.Fatalf("recent progress silence decision = due %v, err %v; want not due", due, err)
	}
	if _, created, err := s.System().RecordJobSilenceAlert(ctx, job.ID, job.Job.Name, reference, now, threshold, nil); err != nil || created {
		t.Fatalf("recent progress alert = created %v, err %v; want no alert", created, err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET expires_at='' WHERE id=?`, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if due, err := s.System().JobSilenceDue(ctx, job.ID, reference, now, threshold); err != nil || due {
		t.Fatalf("recent legacy progress without expiry = due %v, err %v; want not due", due, err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET status='paused',config_hash='stale-scope' WHERE id=?`, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if due, err := s.System().JobSilenceDue(ctx, job.ID, reference, now, threshold); err != nil || !due {
		t.Fatalf("recent stale-scope progress silence decision = due %v, err %v; want due", due, err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET status='running',config_hash=?,expires_at=? WHERE id=?`, job.Job.SecurityHash(), sqliteTimestamp(now.Add(24*time.Hour)), cycle.ID); err != nil {
		t.Fatal(err)
	}

	// A stalled cycle and an in-window cycle whose last completed checkpoint
	// is old enough to exceed the watchdog window no longer suppress silence.
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET status='stalled' WHERE id=?`, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if due, err := s.System().JobSilenceDue(ctx, job.ID, reference, now, threshold); err != nil || !due {
		t.Fatalf("stalled cycle silence decision = due %v, err %v; want due", due, err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET status='paused' WHERE id=?`, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycle_units SET finished_at=? WHERE cycle_id=? AND status='completed'`, now.Add(-threshold-time.Minute).Format(time.RFC3339Nano), cycle.ID); err != nil {
		t.Fatal(err)
	}
	if due, err := s.System().JobSilenceDue(ctx, job.ID, reference, now, threshold); err != nil || !due {
		t.Fatalf("stale progress silence decision = due %v, err %v; want due", due, err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET updated_at=?,expires_at=? WHERE id=?`, now.Add(-time.Minute).Format(time.RFC3339Nano), now.Add(-time.Minute).Format(time.RFC3339Nano), cycle.ID); err != nil {
		t.Fatal(err)
	}
	if due, err := s.System().JobSilenceDue(ctx, job.ID, reference, now, threshold); err != nil || !due {
		t.Fatalf("expired progress silence decision = due %v, err %v; want due", due, err)
	}
}

func TestJobSilenceWatchdogCountsCompatibleLegacyScopeProgressAsActivity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	job := config.NormalizeJob(config.Job{
		Name: "legacy-scope-progress", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.16"}, TCP: &config.Protocol{Ports: "443,22", Mode: "connect"},
	})
	record, err := tenant.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	legacyDefinition := record.Job
	legacyTCP := *legacyDefinition.TCP
	legacyTCP.Ports = "443,22"
	legacyDefinition.TCP = &legacyTCP
	definition, err := json.Marshal(legacyDefinition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE jobs SET definition_json=? WHERE id=?`, definition, record.ID); err != nil {
		t.Fatal(err)
	}
	record, err = tenant.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	legacyHash := record.Job.LegacySecurityHash()
	if legacyHash == "" || legacyHash == record.Job.SecurityHash() {
		t.Fatalf("stored job hashes = current %q, legacy %q; want distinct compatibility hashes", record.Job.SecurityHash(), legacyHash)
	}

	reference := record.CreatedAt.UTC()
	now := reference.Add(3 * time.Hour)
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_silence_state SET eligible_at=? WHERE job_id=?`, sqliteTimestamp(reference), record.ID); err != nil {
		t.Fatal(err)
	}
	plan := scanner.WorkPlan{Job: record.Job, Units: []scanner.WorkUnit{
		{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.16"}, Ports: "22", PortCount: 1, Probes: 1},
		{Sequence: 1, Protocol: "tcp", Addresses: []string{"192.0.2.16"}, Ports: "443", PortCount: 1, Probes: 1},
	}}
	cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{
		JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision, ConfigHash: legacyHash,
		ExecutionHash: record.Job.ExecutionHash(), Plan: plan, StartedAt: reference, ExpiresAt: now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	unit, err := s.System().NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := s.System().CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, model.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycle_units SET finished_at=? WHERE cycle_id=? AND status='completed'`, sqliteTimestamp(now.Add(-time.Minute)), cycle.ID); err != nil {
		t.Fatal(err)
	}
	if due, err := s.System().JobSilenceDue(ctx, record.ID, reference, now, 2*time.Hour); err != nil || due {
		t.Fatalf("compatible legacy-scope progress silence decision = due %v, err %v; want not due", due, err)
	}
}

func TestJobSilenceWatchdogDoesNotCountNoProgressPauseAsRecentProgress(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	job, err := defaultTenant(s).CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "stale-resumable-progress", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.15"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	reference := now.Add(-3 * time.Hour)
	threshold := 2 * time.Hour
	if _, err := s.DB.ExecContext(ctx, `UPDATE jobs SET created_at=? WHERE id=?`, sqliteTimestamp(reference), job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_silence_state SET eligible_at=? WHERE job_id=?`, sqliteTimestamp(reference), job.ID); err != nil {
		t.Fatal(err)
	}
	plan := scanner.WorkPlan{Units: []scanner.WorkUnit{
		{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.15"}, Ports: "22", PortCount: 1, Probes: 1},
		{Sequence: 1, Protocol: "tcp", Addresses: []string{"192.0.2.15"}, Ports: "443", PortCount: 1, Probes: 1},
	}}
	cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{
		JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(),
		ExecutionHash: job.Job.ExecutionHash(), Plan: plan, StartedAt: reference, ExpiresAt: now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	unit, err := s.System().NextScanCycleUnit(ctx, cycle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().ClaimScanCycleUnit(ctx, cycle.ID, unit.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := s.System().CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, model.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().PauseScanCycle(ctx, cycle.ID, false, "first unit completed"); err != nil {
		t.Fatal(err)
	}
	checkpointAt := now.Add(-threshold - time.Minute)
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycle_units SET finished_at=? WHERE cycle_id=? AND status='completed'`, sqliteTimestamp(checkpointAt), cycle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().StartScanCycleAttempt(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	paused, err := s.System().PauseScanCycle(ctx, cycle.ID, true, "timed out before the next checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	if paused.Status != "paused" || paused.NoProgressAttempts != 1 {
		t.Fatalf("no-progress pause = status %q, attempts %d; want paused with one no-progress attempt", paused.Status, paused.NoProgressAttempts)
	}
	if !paused.UpdatedAt.After(checkpointAt) {
		t.Fatalf("no-progress pause updated_at = %s; want a fresh lifecycle timestamp after %s", paused.UpdatedAt, checkpointAt)
	}
	summaries, err := defaultTenant(s).ListActiveScanCycleSummaries(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := summaries[job.ID].LastProgressAt; !got.Equal(checkpointAt) {
		t.Fatalf("last progress time = %s; want checkpoint time %s despite fresh updated_at %s", got, checkpointAt, paused.UpdatedAt)
	}
	if due, err := s.System().JobSilenceDue(ctx, job.ID, reference, now, threshold); err != nil || !due {
		t.Fatalf("silence after a stale checkpoint and no-progress pause = due %v, err %v; want due", due, err)
	}
}

func TestJobSilenceReferenceUsesNewestEligibleEvidence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	job, err := defaultTenant(s).CreateJob(ctx, config.NormalizeJob(config.Job{
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
	got, err := s.System().JobSilenceReference(ctx, job.ID, created, now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(lastSuccess) {
		t.Fatalf("reference = %s, want newest successful marker %s", got, lastSuccess)
	}
}

func TestJobSilenceReferenceHonorsFutureEligibility(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	job, err := defaultTenant(s).CreateJob(ctx, config.NormalizeJob(config.Job{
		Name:     "future-eligibility",
		Schedule: "0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.13"},
		TCP:      &config.Protocol{Ports: "443", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.January, 1, 4, 0, 0, 0, time.UTC)
	created := now.Add(-24 * time.Hour)
	if _, err := s.DB.ExecContext(ctx, `UPDATE jobs SET created_at=? WHERE id=?`, created.Format(time.RFC3339Nano), job.ID); err != nil {
		t.Fatal(err)
	}
	eligible := now.Add(30 * time.Minute)
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_silence_state SET eligible_at=?,last_success_at=? WHERE job_id=?`, eligible.Format(time.RFC3339Nano), created.Format(time.RFC3339Nano), job.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.System().JobSilenceReference(ctx, job.ID, created, now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(eligible) {
		t.Fatalf("reference = %s, want future eligibility marker %s", got, eligible)
	}
}
