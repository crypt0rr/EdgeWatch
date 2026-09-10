package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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

func (p PruneStats) Total() int64 {
	return p.Scans + p.Events + p.SentOutbox + p.FailedOutbox + p.Revisions + p.Cycles + p.RDAPCache
}

// Prune removes rows outside the configured retention window while preserving
// every active baseline scan and the current revision of each job. Delivery
// rows that are still pending (or have retry attempts remaining) are never
// removed; only sent rows and terminal failures are eligible. The operation is
// transactional so a crash cannot leave a partially pruned history set.
func (s *Store) PruneWithStats(ctx context.Context, before time.Time) (PruneStats, error) {
	var stats PruneStats
	cutoff := before.UTC().Format(time.RFC3339Nano)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return stats, err
	}
	defer func() { _ = tx.Rollback() }()

	// NOT EXISTS avoids SQL's NULL semantics: most state rows do not yet have a
	// baseline_scan_id, and a NOT IN subquery containing NULL would protect every
	// old scan from pruning.
	result, err := tx.ExecContext(ctx, `DELETE FROM scans AS scan WHERE scan.finished_at < ?
		AND NOT EXISTS (SELECT 1 FROM job_states AS legacy WHERE json_extract(legacy.state_json,'$.baseline_scan_id') = scan.id)
		AND NOT EXISTS (SELECT 1 FROM job_runtime AS managed WHERE json_extract(managed.state_json,'$.baseline_scan_id') = scan.id)
		AND NOT EXISTS (SELECT 1 FROM job_runtime AS active, json_each(active.state_json,'$.incidents') AS incident WHERE json_extract(incident.value,'$.scan_id') = scan.id)`, cutoff)
	if err != nil {
		return stats, err
	}
	stats.Scans, _ = result.RowsAffected()
	if stats.Scans > 0 {
		// A projection row is a copy rather than a foreign-key child of its
		// source scan. Rebuild it after cascaded scan deletion so an older
		// retained observation becomes visible when the previous latest row
		// expires.
		if err := rebuildLatestScanHostsTx(ctx, tx); err != nil {
			return stats, err
		}
	}

	result, err = tx.ExecContext(ctx, `DELETE FROM events WHERE created_at < ?`, cutoff)
	if err != nil {
		return stats, err
	}
	stats.Events, _ = result.RowsAffected()

	result, err = tx.ExecContext(ctx, `DELETE FROM outbox WHERE sent_at IS NOT NULL AND sent_at < ?`, cutoff)
	if err != nil {
		return stats, err
	}
	stats.SentOutbox, _ = result.RowsAffected()

	result, err = tx.ExecContext(ctx, `DELETE FROM outbox WHERE sent_at IS NULL AND attempts >= ? AND next_at < ?`, deliveryMaxAttempts, cutoff)
	if err != nil {
		return stats, err
	}
	stats.FailedOutbox, _ = result.RowsAffected()

	// Older releases kept completed cycle payloads until the cycle itself was
	// pruned. Once a merged scan already references a completed cycle, those
	// per-unit snapshots are no longer needed for crash recovery; reclaim them
	// during the regular retention pass while preserving unit metadata.
	if _, err = tx.ExecContext(ctx, `UPDATE scan_cycle_units SET snapshot_json='{}' WHERE cycle_id IN (SELECT cycle.id FROM scan_cycles AS cycle WHERE cycle.status='completed' AND EXISTS (SELECT 1 FROM scans WHERE scans.cycle_id=cycle.id)) AND snapshot_json <> '{}'`); err != nil {
		return stats, err
	}

	// Keep the newest revision for every job regardless of age. Older revisions
	// contain immutable historical definitions and may be discarded after their
	// retention window because scans retain their own snapshots.
	result, err = tx.ExecContext(ctx, `DELETE FROM job_revisions
			WHERE created_at < ?
			AND revision < COALESCE((SELECT MAX(current.revision) FROM jobs AS current WHERE current.id = job_revisions.job_id), revision)
			AND NOT EXISTS (SELECT 1 FROM scans WHERE scans.job_id = job_revisions.job_id AND scans.job_revision = job_revisions.revision)`, cutoff)
	if err != nil {
		return stats, err
	}
	stats.Revisions, _ = result.RowsAffected()

	// Cycle metadata is part of the resumable execution history. Keep active
	// cycles indefinitely (their finished_at is empty) and keep terminal cycles
	// while a retained scan still points at them. Once both the cycle and any
	// referencing scan fall outside retention, the unit checkpoints can be
	// removed through the foreign-key cascade without leaving unbounded plan
	// metadata behind.
	result, err = tx.ExecContext(ctx, `DELETE FROM scan_cycles AS cycle
		WHERE cycle.finished_at <> '' AND cycle.finished_at < ?
		AND cycle.status IN ('completed','discarded','expired')
		AND NOT EXISTS (SELECT 1 FROM scans WHERE scans.cycle_id = cycle.id)`, cutoff)
	if err != nil {
		return stats, err
	}
	stats.Cycles, _ = result.RowsAffected()

	// RDAP registration data is a short-lived enrichment cache rather than
	// retained scan history. Remove rows once their seven-day stale window has
	// elapsed, even when the deployment retains scans for much longer.
	rdapCutoff := time.Now().UTC().Format(time.RFC3339Nano)
	result, err = tx.ExecContext(ctx, `DELETE FROM rdap_cache WHERE stale_until < ?`, rdapCutoff)
	if err != nil {
		return stats, err
	}
	stats.RDAPCache, _ = result.RowsAffected()

	if err := tx.Commit(); err != nil {
		return stats, err
	}
	return stats, nil
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

// ReleaseAllJobLeases clears scan leases after the daemon has acquired the
// exclusive daemon lease. A process that crashed cannot run its deferred
// release, so without this reconciliation a job would remain blocked until
// its full scan timeout. The daemon lease makes clearing all rows safe.
func (s *Store) ReleaseAllJobLeases(ctx context.Context) (int64, error) {
	result, err := s.DB.ExecContext(ctx, `DELETE FROM job_leases`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
func (s *Store) ReleaseLease(ctx context.Context, owner string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM daemon_lease WHERE id=1 AND owner=?`, owner)
	return err
}
func (s *Store) Healthy(ctx context.Context) error {
	var raw string
	if err := s.DB.QueryRowContext(ctx, `SELECT heartbeat FROM daemon_lease WHERE id=1`).Scan(&raw); err != nil {
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
