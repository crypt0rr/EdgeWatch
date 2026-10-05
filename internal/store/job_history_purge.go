package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// jobHistoryPurgeBatchSize bounds the writer lock held while a permanent job
// deletion erases history, scan evidence, baselines, and child runtime rows.
const jobHistoryPurgeBatchSize = 500

const (
	jobPurgePhaseCycleCheckpoints = "scan_cycle_discovery_checkpoints"
	jobPurgePhaseCycleUnits       = "scan_cycle_units"
	jobPurgePhaseCycles           = "scan_cycles"
	jobPurgePhasePublicHosts      = "public_dashboard_hosts"
	jobPurgePhaseBaselineHosts    = "baseline_hosts"
	jobPurgePhaseIncidents        = "runtime_incidents"
	jobPurgePhaseRuntime          = "job_runtime"
	jobPurgePhaseRuntimeMeta      = "job_runtime_meta"
	jobPurgePhaseSilence          = "job_silence_state"
	jobPurgePhaseRevisions        = "job_revisions"
	jobPurgePhaseScanBackfill     = "legacy_scan_host_backfill"
	jobPurgePhaseScanHosts        = "scan_hosts"
	jobPurgePhaseScans            = "scans"
	jobPurgePhaseEvents           = "events"
	jobPurgePhaseOutbox           = "outbox"
	jobPurgePhaseQuarantine       = "restore_quarantined_deliveries"
	jobPurgePhaseLeases           = "job_leases"
	jobPurgePhaseLatestHosts      = "latest_scan_hosts"
	jobPurgePhaseRepairHosts      = "repair_latest_scan_hosts"
	jobPurgePhaseDeleteJob        = "delete_job"
	jobPurgePhaseComplete         = "complete"
)

type jobHistoryPurgeOptions struct {
	batchSize int
	// afterBatch runs after each committed transaction. Tests use it to pause
	// between batches and prove unrelated writers can make progress.
	afterBatch func(ctx context.Context, tenantID, jobID, phase string) error
}

type jobHistoryPurgeRecord struct {
	tenantID string
	jobID    string
	phase    string
}

type jobHistoryPurgeStep struct {
	phase  string
	table  string
	rowids string
}

// The job row stays as a small tombstone until its child rows are erased. Its
// marker hides it from application reads and prevents new work; the final
// phase removes the tombstone after every potentially large child relation is
// already empty.
var jobHistoryPurgeSteps = []jobHistoryPurgeStep{
	{jobPurgePhaseCycleCheckpoints, "scan_cycle_discovery_checkpoints", `SELECT rowid FROM scan_cycle_discovery_checkpoints WHERE cycle_id IN (SELECT id FROM scan_cycles WHERE job_id=?2) ORDER BY rowid`},
	{jobPurgePhaseCycleUnits, "scan_cycle_units", `SELECT rowid FROM scan_cycle_units WHERE cycle_id IN (SELECT id FROM scan_cycles WHERE job_id=?2) ORDER BY rowid`},
	{jobPurgePhaseCycles, "scan_cycles", `SELECT rowid FROM scan_cycles WHERE job_id=?2 ORDER BY rowid`},
	{jobPurgePhasePublicHosts, "public_dashboard_hosts", `SELECT rowid FROM public_dashboard_hosts WHERE job_id=?2 ORDER BY rowid`},
	{jobPurgePhaseBaselineHosts, "baseline_hosts", `SELECT rowid FROM baseline_hosts WHERE job_id=?2 ORDER BY rowid`},
	{jobPurgePhaseIncidents, "runtime_incidents", `SELECT rowid FROM runtime_incidents WHERE job_id=?2 ORDER BY rowid`},
	{jobPurgePhaseRuntime, "job_runtime", `SELECT rowid FROM job_runtime WHERE job_id=?2 ORDER BY rowid`},
	{jobPurgePhaseRuntimeMeta, "job_runtime_meta", `SELECT rowid FROM job_runtime_meta WHERE job_id=?2 ORDER BY rowid`},
	{jobPurgePhaseSilence, "job_silence_state", `SELECT rowid FROM job_silence_state WHERE job_id=?2 ORDER BY rowid`},
	{jobPurgePhaseRevisions, "job_revisions", `SELECT rowid FROM job_revisions WHERE job_id=?2 ORDER BY rowid`},
	{jobPurgePhaseScanBackfill, "legacy_scan_host_backfill", `SELECT rowid FROM legacy_scan_host_backfill WHERE scan_id IN (SELECT id FROM scans WHERE tenant_id=?1 AND job_id=?2) ORDER BY rowid`},
	{jobPurgePhaseScanHosts, "scan_hosts", `SELECT h.rowid FROM scan_hosts AS h JOIN scans AS s ON s.id=h.scan_id WHERE s.tenant_id=?1 AND s.job_id=?2 ORDER BY h.rowid`},
	{jobPurgePhaseScans, "scans", `SELECT rowid FROM scans WHERE tenant_id=?1 AND job_id=?2 ORDER BY rowid`},
	{jobPurgePhaseEvents, "events", `SELECT rowid FROM events WHERE tenant_id=?1 AND job_id=?2 ORDER BY rowid`},
	{jobPurgePhaseOutbox, "outbox", `SELECT rowid FROM outbox WHERE tenant_id=?1 AND json_valid(CAST(payload_json AS TEXT)) AND json_extract(CAST(payload_json AS TEXT),'$.job_id')=?2 ORDER BY rowid`},
	{jobPurgePhaseQuarantine, "restore_quarantined_deliveries", `SELECT rowid FROM restore_quarantined_deliveries WHERE tenant_id=?1 AND json_valid(CAST(payload_json AS TEXT)) AND json_extract(CAST(payload_json AS TEXT),'$.job_id')=?2 ORDER BY rowid`},
	{jobPurgePhaseLeases, "job_leases", `SELECT rowid FROM job_leases WHERE job=?2 ORDER BY rowid`},
}

func startJobHistoryPurgeTx(ctx context.Context, tx *sql.Tx, tenantID, jobID string, now time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO job_history_purges(tenant_id,job_id,phase,created_at,updated_at) VALUES(?,?,?,?,?)`, tenantID, jobID, jobPurgePhaseCycleCheckpoints, sqliteTimestamp(now), sqliteTimestamp(now))
	return err
}

// PurgeDeletedJobHistories completes pending permanent job deletions. Each
// child-table batch and its checkpoint is committed separately, so large
// retained histories do not monopolize SQLite's single writer and a restart
// resumes at the last committed phase.
func (ss *SystemStore) PurgeDeletedJobHistories(ctx context.Context) (int64, error) {
	return ss.purgeDeletedJobHistories(ctx, jobHistoryPurgeOptions{batchSize: jobHistoryPurgeBatchSize})
}

func (ss *SystemStore) purgeDeletedJobHistories(ctx context.Context, options jobHistoryPurgeOptions) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if options.batchSize < 1 {
		options.batchSize = jobHistoryPurgeBatchSize
	}
	var purged int64
	for {
		record, err := nextJobHistoryPurge(ctx, ss.store.reader())
		if err != nil {
			return purged, err
		}
		if record == nil {
			return purged, nil
		}
		rows, err := ss.purgeJobHistory(ctx, *record, options)
		purged += rows
		if err != nil {
			return purged, fmt.Errorf("purge deleted job history: %w", err)
		}
	}
}

func nextJobHistoryPurge(ctx context.Context, db *sql.DB) (*jobHistoryPurgeRecord, error) {
	var record jobHistoryPurgeRecord
	err := db.QueryRowContext(ctx, `SELECT p.tenant_id,p.job_id,p.phase
FROM job_history_purges p JOIN tenants t ON t.id=p.tenant_id
WHERE t.state IN (?,?) AND p.phase<>'complete' ORDER BY p.created_at,p.tenant_id,p.job_id LIMIT 1`, TenantStateActive, TenantStateDisabled).Scan(&record.tenantID, &record.jobID, &record.phase)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func (ss *SystemStore) purgeJobHistory(ctx context.Context, record jobHistoryPurgeRecord, options jobHistoryPurgeOptions) (int64, error) {
	var erasedTotal int64
	for {
		if err := ctx.Err(); err != nil {
			return erasedTotal, err
		}
		if record.phase == jobPurgePhaseLatestHosts {
			erased, nextPhase, err := ss.purgeJobLatestHostsBatch(ctx, record, options.batchSize)
			if err != nil {
				return erasedTotal, err
			}
			erasedTotal += erased
			record.phase = nextPhase
			if options.afterBatch != nil {
				if err := options.afterBatch(ctx, record.tenantID, record.jobID, jobPurgePhaseLatestHosts); err != nil {
					return erasedTotal, err
				}
			}
			continue
		}
		if record.phase == jobPurgePhaseRepairHosts {
			erased, nextPhase, err := ss.repairJobLatestHostsBatch(ctx, record, options.batchSize)
			if err != nil {
				return erasedTotal, err
			}
			erasedTotal += erased
			record.phase = nextPhase
			if options.afterBatch != nil {
				if err := options.afterBatch(ctx, record.tenantID, record.jobID, jobPurgePhaseRepairHosts); err != nil {
					return erasedTotal, err
				}
			}
			continue
		}
		if record.phase == jobPurgePhaseDeleteJob {
			if err := ss.finishJobHistoryPurge(ctx, record); err != nil {
				return erasedTotal, err
			}
			return erasedTotal + 1, nil
		}
		stepIndex := jobHistoryPurgeStepIndex(record.phase)
		if stepIndex < 0 {
			return erasedTotal, fmt.Errorf("unknown job history purge phase %q", record.phase)
		}
		step := jobHistoryPurgeSteps[stepIndex]
		batch, nextPhase, err := ss.purgeJobTableBatch(ctx, record, step, options.batchSize)
		if err != nil {
			return erasedTotal, err
		}
		erasedTotal += batch
		record.phase = nextPhase
		if options.afterBatch != nil {
			if err := options.afterBatch(ctx, record.tenantID, record.jobID, step.phase); err != nil {
				return erasedTotal, err
			}
		}
	}
}

func jobHistoryPurgeStepIndex(phase string) int {
	for i, step := range jobHistoryPurgeSteps {
		if step.phase == phase {
			return i
		}
	}
	return -1
}

func (ss *SystemStore) purgeJobTableBatch(ctx context.Context, record jobHistoryPurgeRecord, step jobHistoryPurgeStep, batchSize int) (int64, string, error) {
	tx, err := ss.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, record.phase, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `DELETE FROM `+step.table+` WHERE rowid IN (`+step.rowids+` LIMIT ?3)`, record.tenantID, record.jobID, batchSize)
	if err != nil {
		return 0, record.phase, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, record.phase, err
	}
	next := step.phase
	if count < int64(batchSize) {
		if jobHistoryPurgeStepIndex(step.phase)+1 < len(jobHistoryPurgeSteps) {
			next = jobHistoryPurgeSteps[jobHistoryPurgeStepIndex(step.phase)+1].phase
		} else {
			next = jobPurgePhaseLatestHosts
		}
	}
	if err := updateJobHistoryPurgePhase(ctx, tx, record, next); err != nil {
		return 0, record.phase, err
	}
	if err := tx.Commit(); err != nil {
		return 0, record.phase, err
	}
	return count, next, nil
}

func (ss *SystemStore) purgeJobLatestHostsBatch(ctx context.Context, record jobHistoryPurgeRecord, batchSize int) (int64, string, error) {
	tx, err := ss.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, record.phase, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO job_history_purge_host_keys(tenant_id,job_id,address)
SELECT tenant_id,job_id,address FROM latest_scan_hosts WHERE tenant_id=? AND job_id=? ORDER BY address LIMIT ?`, record.tenantID, record.jobID, batchSize); err != nil {
		return 0, record.phase, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM latest_scan_hosts WHERE rowid IN (
SELECT rowid FROM latest_scan_hosts WHERE tenant_id=? AND job_id=? ORDER BY address LIMIT ?)`, record.tenantID, record.jobID, batchSize)
	if err != nil {
		return 0, record.phase, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, record.phase, err
	}
	next := jobPurgePhaseLatestHosts
	if count < int64(batchSize) {
		next = jobPurgePhaseRepairHosts
	}
	if err := updateJobHistoryPurgePhase(ctx, tx, record, next); err != nil {
		return 0, record.phase, err
	}
	if err := tx.Commit(); err != nil {
		return 0, record.phase, err
	}
	return count, next, nil
}

func (ss *SystemStore) repairJobLatestHostsBatch(ctx context.Context, record jobHistoryPurgeRecord, batchSize int) (int64, string, error) {
	tx, err := ss.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, record.phase, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT tenant_id,address FROM job_history_purge_host_keys WHERE tenant_id=? AND job_id=? ORDER BY address LIMIT ?`, record.tenantID, record.jobID, batchSize)
	if err != nil {
		return 0, record.phase, err
	}
	keys := make([]latestScanHostKey, 0, batchSize)
	addresses := make([]string, 0, batchSize)
	for rows.Next() {
		var key latestScanHostKey
		if err := rows.Scan(&key.tenantID, &key.address); err != nil {
			_ = rows.Close()
			return 0, record.phase, err
		}
		keys = append(keys, key)
		addresses = append(addresses, key.address)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, record.phase, err
	}
	if err := rows.Close(); err != nil {
		return 0, record.phase, err
	}
	if len(keys) > 0 {
		deleteSQL, insertSQL, args := latestScanHostRepairQueries(keys)
		if _, err := tx.ExecContext(ctx, deleteSQL, args...); err != nil {
			return 0, record.phase, err
		}
		if _, err := tx.ExecContext(ctx, insertSQL, args...); err != nil {
			return 0, record.phase, err
		}
		for _, address := range addresses {
			if _, err := tx.ExecContext(ctx, `DELETE FROM job_history_purge_host_keys WHERE tenant_id=? AND job_id=? AND address=?`, record.tenantID, record.jobID, address); err != nil {
				return 0, record.phase, err
			}
		}
	}
	next := jobPurgePhaseRepairHosts
	if len(keys) < batchSize {
		next = jobPurgePhaseDeleteJob
	}
	if err := updateJobHistoryPurgePhase(ctx, tx, record, next); err != nil {
		return 0, record.phase, err
	}
	if err := tx.Commit(); err != nil {
		return 0, record.phase, err
	}
	return int64(len(keys)), next, nil
}

func updateJobHistoryPurgePhase(ctx context.Context, tx *sql.Tx, record jobHistoryPurgeRecord, phase string) error {
	result, err := tx.ExecContext(ctx, `UPDATE job_history_purges SET phase=?,updated_at=? WHERE tenant_id=? AND job_id=? AND phase=?`, phase, sqliteTimestamp(time.Now().UTC()), record.tenantID, record.jobID, record.phase)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return fmt.Errorf("%w: job history purge phase changed for job %s", ErrConflict, record.jobID)
	}
	return nil
}

func (ss *SystemStore) finishJobHistoryPurge(ctx context.Context, record jobHistoryPurgeRecord) error {
	tx, err := ss.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `DELETE FROM jobs WHERE id=? AND tenant_id=? AND EXISTS (
		SELECT 1 FROM job_history_purges WHERE tenant_id=? AND job_id=? AND phase=?)`, record.jobID, record.tenantID, record.tenantID, record.jobID, jobPurgePhaseDeleteJob)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return fmt.Errorf("%w: job history purge is no longer finalizable for job %s", ErrConflict, record.jobID)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM job_history_purge_host_keys WHERE tenant_id=? AND job_id=?`, record.tenantID, record.jobID); err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `UPDATE job_history_purges SET phase=?,updated_at=? WHERE tenant_id=? AND job_id=? AND phase=?`, jobPurgePhaseComplete, sqliteTimestamp(time.Now().UTC()), record.tenantID, record.jobID, jobPurgePhaseDeleteJob)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return fmt.Errorf("%w: job history purge tombstone changed for job %s", ErrConflict, record.jobID)
	}
	return tx.Commit()
}
