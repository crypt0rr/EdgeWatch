package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

type PruneStats struct {
	Scans        int64
	Events       int64
	SentOutbox   int64
	FailedOutbox int64
	Revisions    int64
	Cycles       int64
	RDAPCache    int64
}

// retentionBatchSize bounds both lock duration and rollback cost. Retention
// is maintenance work and may be resumed safely after cancellation or a
// process restart; one very large transaction must not monopolize SQLite's
// writer connection for the lifetime of the deployment.
const retentionBatchSize = 500

func (p PruneStats) Total() int64 {
	return p.Scans + p.Events + p.SentOutbox + p.FailedOutbox + p.Revisions + p.Cycles + p.RDAPCache
}

// Prune removes rows outside the configured retention window while preserving
// every active baseline scan and the current revision of each job. Delivery
// rows that are still pending (or have retry attempts remaining) are never
// removed; only sent rows and terminal failures are eligible. Each bounded
// batch is committed independently, making the operation resumable and
// allowing cancellation between batches without holding the writer lock for
// the whole retained history.
func (s *Store) PruneWithStats(ctx context.Context, before time.Time) (PruneStats, error) {
	var stats PruneStats
	cutoff := before.UTC().Format(time.RFC3339Nano)
	// NOT EXISTS avoids SQL's NULL semantics: most state rows do not yet have a
	// baseline_scan_id, and a NOT IN subquery containing NULL would protect every
	// old scan from pruning.
	deletedScans, err := s.deleteRetentionBatches(ctx, `DELETE FROM scans AS scan WHERE scan.id IN (SELECT candidate.id FROM scans AS candidate WHERE candidate.finished_at < ?
		AND NOT EXISTS (SELECT 1 FROM job_states AS legacy WHERE json_extract(legacy.state_json,'$.baseline_scan_id') = candidate.id)
		AND NOT EXISTS (SELECT 1 FROM job_runtime AS managed WHERE json_extract(managed.state_json,'$.baseline_scan_id') = candidate.id)
		AND NOT EXISTS (SELECT 1 FROM job_runtime AS active, json_each(active.state_json,'$.incidents') AS incident WHERE json_extract(incident.value,'$.scan_id') = candidate.id) ORDER BY candidate.finished_at,candidate.id LIMIT ?)`, cutoff)
	if err != nil {
		return stats, err
	}
	stats.Scans = deletedScans
	if deletedScans > 0 {
		// A projection row is a copy rather than a foreign-key child of its
		// source scan. Repair only addresses whose current row became dangling;
		// rebuilding the complete retained history would hold the writer for the
		// size of the deployment and make every retention pass increasingly
		// expensive. Each repair transaction is bounded by retentionBatchSize.
		if err := s.repairLatestScanHosts(ctx); err != nil {
			return stats, err
		}
	}

	stats.Events, err = s.deleteRetentionBatches(ctx, `DELETE FROM events WHERE rowid IN (SELECT rowid FROM events WHERE created_at < ? ORDER BY created_at,rowid LIMIT ?)`, cutoff)
	if err != nil {
		return stats, err
	}
	stats.SentOutbox, err = s.deleteRetentionBatches(ctx, `DELETE FROM outbox WHERE rowid IN (SELECT rowid FROM outbox WHERE sent_at IS NOT NULL AND sent_at < ? ORDER BY sent_at,rowid LIMIT ?)`, cutoff)
	if err != nil {
		return stats, err
	}
	stats.FailedOutbox, err = s.deleteRetentionBatches(ctx, `DELETE FROM outbox WHERE rowid IN (SELECT rowid FROM outbox WHERE sent_at IS NULL AND (attempts >= ? OR terminal_at <> '') AND next_at < ? ORDER BY next_at,rowid LIMIT ?)`, deliveryMaxAttempts, cutoff)
	if err != nil {
		return stats, err
	}

	// Older releases kept completed cycle payloads until the cycle itself was
	// pruned. Once a merged scan already references a completed cycle, those
	// per-unit snapshots are no longer needed for crash recovery; reclaim them
	// during the regular retention pass while preserving unit metadata.
	if err := s.clearCompletedCyclePayloads(ctx); err != nil {
		return stats, err
	}

	// Keep the newest revision for every job regardless of age. Older revisions
	// contain immutable historical definitions and may be discarded after their
	// retention window because scans retain their own snapshots.
	stats.Revisions, err = s.deleteRetentionBatches(ctx, `DELETE FROM job_revisions WHERE rowid IN (SELECT revision.rowid FROM job_revisions AS revision
			WHERE created_at < ?
			AND revision < COALESCE((SELECT MAX(current.revision) FROM jobs AS current WHERE current.id = revision.job_id), revision)
			AND NOT EXISTS (SELECT 1 FROM scans WHERE scans.job_id = revision.job_id AND scans.job_revision = revision.revision) ORDER BY revision.created_at,revision.rowid LIMIT ?)`, cutoff)
	if err != nil {
		return stats, err
	}

	// Cycle metadata is part of the resumable execution history. Keep active
	// cycles indefinitely (their finished_at is empty) and keep terminal cycles
	// while a retained scan still points at them. Once both the cycle and any
	// referencing scan fall outside retention, the unit checkpoints can be
	// removed through the foreign-key cascade without leaving unbounded plan
	// metadata behind.
	stats.Cycles, err = s.deleteRetentionBatches(ctx, `DELETE FROM scan_cycles AS cycle WHERE cycle.rowid IN (SELECT candidate.rowid FROM scan_cycles AS candidate
		WHERE candidate.finished_at <> '' AND candidate.finished_at < ?
		AND candidate.status IN ('completed','discarded','expired')
		AND NOT EXISTS (SELECT 1 FROM scans WHERE scans.cycle_id = candidate.id) ORDER BY candidate.finished_at,candidate.rowid LIMIT ?)`, cutoff)
	if err != nil {
		return stats, err
	}

	// RDAP registration data is a short-lived enrichment cache rather than
	// retained scan history. Remove rows once their seven-day stale window has
	// elapsed, even when the deployment retains scans for much longer.
	rdapCutoff := time.Now().UTC().Format(time.RFC3339Nano)
	stats.RDAPCache, err = s.deleteRetentionBatches(ctx, `DELETE FROM rdap_cache WHERE rowid IN (SELECT rowid FROM rdap_cache WHERE stale_until < ? ORDER BY stale_until,rowid LIMIT ?)`, rdapCutoff)
	if err != nil {
		return stats, err
	}
	return stats, nil
}

// deleteRetentionBatches repeatedly executes one bounded DELETE transaction.
// The caller supplies only static SQL; the helper appends the batch limit to
// each statement and therefore never interpolates data values into SQL.
func (s *Store) deleteRetentionBatches(ctx context.Context, statement string, args ...any) (int64, error) {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			return total, err
		}
		batchArgs := append(append([]any(nil), args...), retentionBatchSize)
		result, execErr := tx.ExecContext(ctx, statement, batchArgs...)
		if execErr != nil {
			_ = tx.Rollback()
			// Do not echo SQL text into logs or API errors: retention statements
			// contain implementation details and may include deployment-specific
			// expressions. Keep the wrapped database error useful without leaking
			// the query itself.
			return total, fmt.Errorf("retention batch: %w", execErr)
		}
		count, countErr := result.RowsAffected()
		if countErr != nil {
			_ = tx.Rollback()
			return total, countErr
		}
		if err := tx.Commit(); err != nil {
			return total, err
		}
		total += count
		if count == 0 {
			return total, nil
		}
	}
}

func (s *Store) rebuildLatestScanHosts(ctx context.Context) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := rebuildLatestScanHostsTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// repairLatestScanHosts restores only projection addresses whose source scan
// was removed by retention. The address list is selected and repaired in one
// bounded transaction at a time, so the writer lock and rollback cost stay
// independent of total retained history. Addresses with no retained
// successful observation are intentionally left absent.
func (s *Store) repairLatestScanHosts(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		addresses, err := danglingLatestScanHostAddresses(ctx, tx)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		if len(addresses) == 0 {
			if err := tx.Commit(); err != nil {
				return err
			}
			return nil
		}

		placeholders := make([]string, len(addresses))
		args := make([]any, len(addresses))
		for i, address := range addresses {
			placeholders[i] = "?"
			args[i] = address
		}
		inClause := strings.Join(placeholders, ",")
		if _, err := tx.ExecContext(ctx, `DELETE FROM latest_scan_hosts WHERE address IN (`+inClause+`)`, args...); err != nil {
			_ = tx.Rollback()
			return err
		}
		// The projection columns intentionally mirror saveScanHostsExec. The
		// window rank preserves the same finished-at/id tie-breaker as the
		// original full rebuild while restricting work to the affected addresses.
		if _, err := tx.ExecContext(ctx, `INSERT INTO latest_scan_hosts(address,scan_id,job_id,job,finished_at,data_quality,address_family,source_targets_json,dns_names_json,host_json,search_text,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports)
SELECT address,scan_id,COALESCE(job_id,''),job,finished_at,data_quality,address_family,source_targets_json,dns_names_json,host_json,search_text,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports
FROM (
 SELECT h.address,h.scan_id,s.job_id,s.job,s.finished_at,h.data_quality,h.address_family,h.source_targets_json,h.dns_names_json,h.host_json,h.search_text,h.open_ports,h.open_filtered_ports,h.tcp_present,h.udp_present,h.tcp_open_ports,h.tcp_open_filtered_ports,h.udp_open_ports,h.udp_open_filtered_ports,
        ROW_NUMBER() OVER (PARTITION BY h.address ORDER BY s.finished_at DESC,s.id DESC) AS rn
 FROM scan_hosts h JOIN scans s ON s.id=h.scan_id
 WHERE s.status='success' AND h.address IN (`+inClause+`)
) ranked WHERE rn=1`, args...); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
}

func danglingLatestScanHostAddresses(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT address FROM latest_scan_hosts AS current WHERE NOT EXISTS (SELECT 1 FROM scans WHERE scans.id=current.scan_id) ORDER BY address LIMIT ?`, retentionBatchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	addresses := make([]string, 0, retentionBatchSize)
	for rows.Next() {
		var address string
		if err := rows.Scan(&address); err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	return addresses, rows.Err()
}

func (s *Store) clearCompletedCyclePayloads(ctx context.Context) error {
	_, err := s.deleteRetentionBatches(ctx, `UPDATE scan_cycle_units SET snapshot_json='{}' WHERE rowid IN (SELECT unit.rowid FROM scan_cycle_units AS unit WHERE unit.snapshot_json <> '{}' AND unit.cycle_id IN (SELECT cycle.id FROM scan_cycles AS cycle WHERE cycle.status='completed' AND EXISTS (SELECT 1 FROM scans WHERE scans.cycle_id=cycle.id)) ORDER BY unit.rowid LIMIT ?)`)
	return err
}

func rebuildLatestScanHostsTx(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM latest_scan_hosts`); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO latest_scan_hosts(address,scan_id,job_id,job,finished_at,data_quality,address_family,source_targets_json,dns_names_json,host_json,search_text,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports)
SELECT address,scan_id,COALESCE(job_id,''),job,finished_at,data_quality,address_family,source_targets_json,dns_names_json,host_json,search_text,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports
FROM (
 SELECT h.address,h.scan_id,s.job_id,s.job,s.finished_at,h.data_quality,h.address_family,h.source_targets_json,h.dns_names_json,h.host_json,h.search_text,h.open_ports,h.open_filtered_ports,h.tcp_present,h.udp_present,h.tcp_open_ports,h.tcp_open_filtered_ports,h.udp_open_ports,h.udp_open_filtered_ports,
        ROW_NUMBER() OVER (PARTITION BY h.address ORDER BY s.finished_at DESC,s.id DESC) AS rn
 FROM scan_hosts h JOIN scans s ON s.id=h.scan_id
 WHERE s.status='success'
) ranked WHERE rn=1`)
	return err
}

// Prune is retained for callers that only need the total row count.
func (s *Store) Prune(ctx context.Context, before time.Time) (int64, error) {
	stats, err := s.PruneWithStats(ctx, before)
	return stats.Total(), err
}

func (s *Store) AcquireLease(ctx context.Context, owner string) error {
	now := time.Now().UTC()
	stale := now.Add(-2 * time.Minute).Format(time.RFC3339Nano)
	r, err := s.DB.ExecContext(ctx, `INSERT INTO daemon_lease(id,owner,heartbeat) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,heartbeat=excluded.heartbeat WHERE daemon_lease.owner=excluded.owner OR daemon_lease.heartbeat < ?`, owner, now.Format(time.RFC3339Nano), stale)
	if err != nil {
		return err
	}
	changed, _ := r.RowsAffected()
	if changed == 0 {
		return errors.New("another EdgeWatch daemon holds the database lease")
	}
	return nil
}
func (s *Store) Heartbeat(ctx context.Context, owner string) error {
	r, err := s.DB.ExecContext(ctx, `UPDATE daemon_lease SET heartbeat=? WHERE id=1 AND owner=?`, time.Now().UTC().Format(time.RFC3339Nano), owner)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return ErrLeaseLost
	}
	return nil
}

// ReclaimExpiredJobLeases removes only leases whose owner can no longer be
// considered live. Every scan writes its opaque run identifier as owner and a
// bounded expiry before it starts work. A daemon restart must not delete an
// unexpired lease: that lease may belong to a scan started by the CLI (or to a
// daemon process that is still draining), and clearing it would allow the same
// job to run concurrently. Clean shutdowns release the exact owner through
// ReleaseJobLease; crash recovery waits for expiry.
func (s *Store) ReclaimExpiredJobLeases(ctx context.Context, now time.Time) (int64, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.DB.ExecContext(ctx, `DELETE FROM job_leases WHERE expires_at<=?`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ReleaseAllJobLeases is retained as a source-compatible wrapper for older
// callers. Its historical delete-all behavior was unsafe across daemon and
// CLI processes; it now performs the same expiry-only reconciliation as the
// daemon startup path.
func (s *Store) ReleaseAllJobLeases(ctx context.Context) (int64, error) {
	return s.ReclaimExpiredJobLeases(ctx, time.Now().UTC())
}
func (s *Store) ReleaseLease(ctx context.Context, owner string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM daemon_lease WHERE id=1 AND owner=?`, owner)
	return err
}
func (s *Store) Healthy(ctx context.Context) error {
	var raw string
	if err := s.reader().QueryRowContext(ctx, `SELECT heartbeat FROM daemon_lease WHERE id=1`).Scan(&raw); err != nil {
		return err
	}
	v, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return err
	}
	if time.Since(v) > 2*time.Minute {
		return fmt.Errorf("daemon heartbeat is stale: %s", v)
	}
	return nil
}

func (s *Store) AcquireJobLease(ctx context.Context, job, owner string, expires time.Time) error {
	if strings.TrimSpace(job) == "" {
		return errors.New("job lease job is required")
	}
	if strings.TrimSpace(owner) == "" {
		return errors.New("job lease owner is required")
	}
	if !expires.After(time.Now().UTC()) {
		return errors.New("job lease expiry must be in the future")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.DB.ExecContext(ctx, `INSERT INTO job_leases(job,owner,expires_at) VALUES(?,?,?) ON CONFLICT(job) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at WHERE job_leases.expires_at < ?`, job, owner, expires.UTC().Format(time.RFC3339Nano), now)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		return fmt.Errorf("%w: %s", ErrJobBusy, job)
	}
	return nil
}

// AcquireJobLeaseForRevision atomically verifies that the queued scan still
// refers to the current managed job revision and acquires its lease. A job
// edit and a scan start therefore cannot cross between the revision check and
// the lease write: either the edit observes the lease, or the scan observes
// the newer revision and is rejected before it can touch runtime state.
func (s *Store) AcquireJobLeaseForRevision(ctx context.Context, job, owner string, revision int64, expires time.Time) error {
	if strings.TrimSpace(job) == "" {
		return errors.New("job lease job is required")
	}
	if strings.TrimSpace(owner) == "" {
		return errors.New("job lease owner is required")
	}
	if !expires.After(time.Now().UTC()) {
		return errors.New("job lease expiry must be in the future")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var current int64
	var archived int
	err = tx.QueryRowContext(ctx, `SELECT revision,archived FROM jobs WHERE id=?`, job).Scan(&current, &archived)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: job %s", ErrNotFound, job)
	}
	if err != nil {
		return err
	}
	if archived != 0 {
		return errors.New("archived jobs cannot run")
	}
	if current != revision {
		return ErrJobRevisionChanged
	}
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `INSERT INTO job_leases(job,owner,expires_at) VALUES(?,?,?) ON CONFLICT(job) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at WHERE job_leases.expires_at < ?`, job, owner, expires.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		return fmt.Errorf("%w: %s", ErrJobBusy, job)
	}
	return tx.Commit()
}

func (s *Store) ReleaseJobLease(ctx context.Context, job, owner string) error {
	if strings.TrimSpace(job) == "" || strings.TrimSpace(owner) == "" {
		return errors.New("job lease job and owner are required")
	}
	_, err := s.DB.ExecContext(ctx, `DELETE FROM job_leases WHERE job=? AND owner=?`, job, owner)
	return err
}

func (s *Store) Approve(ctx context.Context, job string, scan model.Scan) ([]model.Event, error) {
	if scan.Job != job {
		return nil, fmt.Errorf("scan %s belongs to job %s", scan.ID, scan.Job)
	}
	if scan.Status != "success" {
		return nil, fmt.Errorf("scan %s is not successful", scan.ID)
	}
	return s.UpdateState(ctx, job, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &scan.Snapshot
		state.BaselineScanID = scan.ID
		state.BaselineConfigHash = scan.ConfigHash
		state.BaselineModified = false
		state.Candidate = nil
		state.CandidateHash = ""
		state.CandidateCount = 0
		state.CandidateAttempts = 0
		state.Pending = map[string]model.Pending{}
		state.Incidents = map[string]model.Incident{}
		state.Suppressed = map[string]int{}
		state.SuppressedChanges = map[string]model.Change{}
		state.FingerprintCandidates = map[string]model.ValueCount{}
		return []model.Event{{Type: "baseline-approved", Job: job, ScanID: scan.ID, Message: "Baseline manually approved", CreatedAt: time.Now().UTC()}}, nil
	})
}
func (s *Store) ResetBaseline(ctx context.Context, job string) ([]model.Event, error) {
	return s.UpdateState(ctx, job, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = nil
		state.BaselineScanID = ""
		state.BaselineConfigHash = ""
		state.BaselineModified = false
		state.Candidate = nil
		state.CandidateHash = ""
		state.CandidateCount = 0
		state.CandidateAttempts = 0
		state.Pending = map[string]model.Pending{}
		state.Incidents = map[string]model.Incident{}
		state.Suppressed = map[string]int{}
		state.SuppressedChanges = map[string]model.Change{}
		state.FingerprintCandidates = map[string]model.ValueCount{}
		return []model.Event{{Type: "baseline-reset", Job: job, Message: "Baseline collection reset", CreatedAt: time.Now().UTC()}}, nil
	})
}
