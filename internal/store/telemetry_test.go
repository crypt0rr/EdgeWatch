package store

import (
	"testing"
	"time"
)

func TestDeploymentTelemetryReportsBoundedCounts(t *testing.T) {
	t.Parallel()
	ctx, s, job, _ := cycleFixture(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO scans(id,job_id,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json) VALUES(?,?,?,?,?,?,?,?,?,?)`, "telemetry-scan", job.ID, job.Job.Name, now, now, "success", "", "Nmap 7.99", job.Job.SecurityHash(), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO scan_hosts(scan_id,address,job,host_json) VALUES(?,?,?,?)`, "telemetry-scan", "192.0.2.1", job.Job.Name, []byte(`{"address":"192.0.2.1"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO latest_scan_hosts(tenant_id,address,scan_id,job_id,job,finished_at,host_json) VALUES(?,?,?,?,?,?,?)`, DefaultTenantID, "192.0.2.1", "telemetry-scan", job.ID, job.Job.Name, now, []byte(`{"address":"192.0.2.1"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO events(type,job,payload_json,created_at) VALUES(?,?,?,?)`, "telemetry-event", job.Job.Name, []byte(`{}`), now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,attempts,next_at) VALUES(?,?,?,?)`, "pending", []byte(`{}`), 0, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,attempts,next_at) VALUES(?,?,?,?)`, "retrying", []byte(`{"retry":true}`), 1, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,attempts,next_at) VALUES(?,?,?,?)`, "failed", []byte(`{"failed":true}`), deliveryMaxAttempts, now); err != nil {
		t.Fatal(err)
	}
	telemetry, err := s.System().DeploymentTelemetry(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if telemetry.Jobs != 1 || telemetry.Scans != 1 || telemetry.HostObservations != 1 || telemetry.EffectiveHosts != 1 || telemetry.Events != 1 {
		t.Fatalf("unexpected telemetry counts: %#v", telemetry)
	}
	if telemetry.OutboxPending != 3 || telemetry.OutboxRetrying != 1 || telemetry.OutboxFailed != 1 {
		t.Fatalf("unexpected outbox telemetry: %#v", telemetry)
	}
	if telemetry.DatabaseBytes <= 0 || telemetry.CollectedAt.IsZero() {
		t.Fatalf("database size/timestamp missing: %#v", telemetry)
	}
}

func TestStalledScanCycleCountIsDeploymentAggregate(t *testing.T) {
	t.Parallel()
	ctx, s, job, plan := cycleFixture(t)
	cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().MarkScanCycleStalled(ctx, cycle.ID, "retry budget exhausted"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.System().StalledScanCycleCount(ctx); err != nil || got != 1 {
		t.Fatalf("stalled cycles = %d, %v; want one", got, err)
	}
	if err := s.Tenant(DefaultTenantScope()).SetJobArchived(ctx, job.ID, true); err != nil {
		t.Fatal(err)
	}
	if got, err := s.System().StalledScanCycleCount(ctx); err != nil || got != 0 {
		t.Fatalf("stalled cycles after archiving the job = %d, %v; want zero", got, err)
	}
}
