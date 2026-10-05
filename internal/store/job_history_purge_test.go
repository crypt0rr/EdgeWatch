package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestJobHistoryPurgeBatchesYieldsWriterAndResumesAfterRestart(t *testing.T) {
	ctx := context.Background()
	database := freshTestDatabasePath(t)
	s, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	tenant := defaultTenant(s)
	deleted, err := tenant.CreateJob(ctx, testJob("large-history-delete"))
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	other, err := tenant.CreateJob(ctx, testJob("concurrent-writer"))
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	const hostCount = jobHistoryPurgeBatchSize + 10
	hosts := make([]model.HostObservation, hostCount)
	for i := range hosts {
		hosts[i] = model.HostObservation{Address: fmt.Sprintf("10.20.%d.%d", (i+1)/256, (i+1)%256)}
	}
	finished := time.Now().UTC().Add(-time.Minute)
	for _, scan := range []model.Scan{
		{ID: "older-host-scan", JobID: other.ID, Job: other.Job.Name, StartedAt: finished, FinishedAt: finished, Status: "success", Snapshot: model.Snapshot{Hosts: hosts}},
		{ID: "newer-deleted-host-scan", JobID: deleted.ID, Job: deleted.Job.Name, StartedAt: finished.Add(time.Second), FinishedAt: finished.Add(time.Second), Status: "success", Snapshot: model.Snapshot{Hosts: hosts}},
	} {
		if err := s.System().SaveScan(ctx, scan); err != nil {
			s.Close()
			t.Fatal(err)
		}
	}
	if err := tenant.SetJobArchived(ctx, deleted.ID, true); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := tenant.DeleteJobWithAudit(ctx, deleted.ID, AuditEntry{Action: "job.deleted", Detail: deleted.ID}); err != nil {
		s.Close()
		t.Fatal(err)
	}

	stopAfterBatch := errors.New("stop after first committed scan-host batch")
	writerMadeProgress := false
	rows, err := s.System().purgeDeletedJobHistories(ctx, jobHistoryPurgeOptions{
		batchSize: jobHistoryPurgeBatchSize,
		afterBatch: func(ctx context.Context, _, _, phase string) error {
			if phase != jobPurgePhaseScanHosts || writerMadeProgress {
				return nil
			}
			// This write is made after the scan-host batch committed. It must not
			// wait for the remainder of the job's retained evidence to be erased.
			if err := tenant.SetJobArchived(ctx, other.ID, true); err != nil {
				return fmt.Errorf("unrelated writer could not make progress: %w", err)
			}
			writerMadeProgress = true
			return stopAfterBatch
		},
	})
	if !errors.Is(err, stopAfterBatch) || !writerMadeProgress || rows < jobHistoryPurgeBatchSize {
		t.Fatalf("interrupted purge = %d rows, %v, writer progressed %v; want committed first batch and interruption", rows, err, writerMadeProgress)
	}
	if _, err := tenant.GetJob(ctx, deleted.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("job visible while history purge is pending = %v; want hidden", err)
	}
	page, err := tenant.ListLatestScanHostsPage(ctx, "", "", nil, hostCount+10, 0)
	if err != nil || page.Total != 0 {
		t.Fatalf("latest host inventory during partial purge = %d rows, %v; want hidden", page.Total, err)
	}
	var scanRows int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_hosts WHERE scan_id='newer-deleted-host-scan'`).Scan(&scanRows); err != nil || scanRows != hostCount-jobHistoryPurgeBatchSize {
		t.Fatalf("remaining scan hosts = %d, %v; want %d after first bounded batch", scanRows, err, hostCount-jobHistoryPurgeBatchSize)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// A daemon restart loads the durable phase and safely continues without
	// restarting an already committed batch.
	restarted, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if purged, err := restarted.System().PurgeDeletedJobHistories(ctx); err != nil || purged == 0 {
		t.Fatalf("resume purge after restart = %d rows, %v", purged, err)
	}
	var jobRows int
	if err := restarted.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE id=?`, deleted.ID).Scan(&jobRows); err != nil || jobRows != 0 {
		t.Fatalf("job row after resumed purge = %d, %v; want deleted", jobRows, err)
	}
	page, err = restarted.Tenant(DefaultTenantScope()).ListLatestScanHostsPage(ctx, "", "", nil, hostCount+10, 0)
	if err != nil || page.Total != hostCount {
		t.Fatalf("latest host inventory after purge = %d rows, %v; want %d", page.Total, err, hostCount)
	}
	for _, host := range page.Items {
		if host.JobID != other.ID || host.ScanID != "older-host-scan" {
			t.Fatalf("repaired host %s belongs to %s/%s, want retained older scan %s", host.Host.Address, host.JobID, host.ScanID, other.ID)
		}
	}
	if err := restarted.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_history_purges WHERE phase<>?`, jobPurgePhaseComplete).Scan(&jobRows); err != nil || jobRows != 0 {
		t.Fatalf("pending purge markers after completion = %d, %v; want 0", jobRows, err)
	}
	if err := restarted.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_history_purges WHERE tenant_id=? AND job_id=? AND phase=?`, tenant.scope.id, deleted.ID, jobPurgePhaseComplete).Scan(&jobRows); err != nil || jobRows != 1 {
		t.Fatalf("completed deletion tombstone = %d, %v; want retained", jobRows, err)
	}
}

func TestLatestHostProjectionRebuildExcludesPendingJobPurges(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	survivor, err := tenant.CreateJob(ctx, testJob("surviving-latest-host"))
	if err != nil {
		t.Fatal(err)
	}
	purging, err := tenant.CreateJob(ctx, testJob("purging-latest-host"))
	if err != nil {
		t.Fatal(err)
	}
	address := "192.0.2.200"
	base := time.Now().UTC().Add(-time.Hour)
	for _, scan := range []model.Scan{
		{ID: "surviving-host-history", JobID: survivor.ID, Job: survivor.Job.Name, StartedAt: base, FinishedAt: base, Status: "success", Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: address}}}},
		{ID: "purging-host-history", JobID: purging.ID, Job: purging.Job.Name, StartedAt: base.Add(time.Minute), FinishedAt: base.Add(time.Minute), Status: "success", Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: address}}}},
	} {
		if err := s.System().SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	stamp := sqliteTimestamp(time.Now().UTC())
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_history_purges(tenant_id,job_id,phase,created_at,updated_at) VALUES(?,?,?,?,?)`, tenant.scope.id, purging.ID, jobPurgePhaseComplete, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM latest_scan_hosts WHERE tenant_id=? AND address=?`, tenant.scope.id, address); err != nil {
		t.Fatal(err)
	}
	rebuildTx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rebuildLatestScanHostsTx(ctx, rebuildTx); err != nil {
		_ = rebuildTx.Rollback()
		t.Fatal(err)
	}
	if err := rebuildTx.Commit(); err != nil {
		t.Fatal(err)
	}
	var jobID, scanID string
	if err := s.DB.QueryRowContext(ctx, `SELECT job_id,scan_id FROM latest_scan_hosts WHERE tenant_id=? AND address=?`, tenant.scope.id, address).Scan(&jobID, &scanID); err != nil {
		t.Fatal(err)
	}
	if jobID != survivor.ID || scanID != "surviving-host-history" {
		t.Fatalf("latest host after rebuild = %s/%s; want surviving scan %s", jobID, scanID, survivor.ID)
	}
	deleteSQL, insertSQL, args := latestScanHostRepairQueries([]latestScanHostKey{{tenantID: tenant.scope.id, address: address}})
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, deleteSQL, args...); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, insertSQL, args...); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT job_id,scan_id FROM latest_scan_hosts WHERE tenant_id=? AND address=?`, tenant.scope.id, address).Scan(&jobID, &scanID); err != nil {
		t.Fatal(err)
	}
	if jobID != survivor.ID || scanID != "surviving-host-history" {
		t.Fatalf("latest host after key repair = %s/%s; want surviving scan %s", jobID, scanID, survivor.ID)
	}
}

func TestJobHistoryPurgeDoesNotAttributeMalformedDeliveryPayloads(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	job, err := tenant.CreateJob(ctx, testJob("malformed-delivery-history"))
	if err != nil {
		t.Fatal(err)
	}
	stamp := sqliteTimestamp(time.Now().UTC())
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,next_at,tenant_id) VALUES('unattributed',x'ff',?,?)`, stamp, tenant.scope.id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO restore_quarantined_deliveries(restore_epoch,destination,payload_json,quarantined_at,tenant_id) VALUES('unattributed','unattributed',x'ff',?,?)`, stamp, tenant.scope.id); err != nil {
		t.Fatal(err)
	}
	if err := tenant.SetJobArchived(ctx, job.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := tenant.DeleteJobWithAudit(ctx, job.ID, AuditEntry{Action: "job.deleted", Detail: job.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().PurgeDeletedJobHistories(ctx); err != nil {
		t.Fatalf("purge malformed delivery payloads: %v", err)
	}
	for name, statement := range map[string]string{
		"outbox":      `SELECT COUNT(*) FROM outbox WHERE destination='unattributed'`,
		"quarantined": `SELECT COUNT(*) FROM restore_quarantined_deliveries WHERE restore_epoch='unattributed'`,
	} {
		var count int
		if err := s.DB.QueryRowContext(ctx, statement).Scan(&count); err != nil || count != 1 {
			t.Errorf("unattributed %s rows after deletion = %d, %v; want preserved", name, count, err)
		}
	}
}
