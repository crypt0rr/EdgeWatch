package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Schema 55 finishes the cleanup after the tenants that earlier releases
// deleted. Those releases made a tenant a tombstone once its rows were
// erased, and only then compacted the search indexes and truncated the
// write-ahead log, as far as one bounded attempt got, so the segments of the
// indexes, and the log until a clean shutdown, may still hold the erased
// rows. Nothing selects a tombstone again.
//
// When the database holds a tombstone at the upgrade, the migration records
// the cleanup as pending in the fts_backfill_state checkpoint
// legacyPurgeMaintenanceState, which edgewatch verify lists. The daemon's
// purge worker then runs RunLegacyPurgeMaintenance on each pass, which runs
// the maintenance of the tenant purge (runSearchMaintenance) once more: a
// merge of every segment of each search index, then, in a database without
// incremental auto-vacuum, the overwrite of every free page, resumable
// across passes and restarts within the same bounded budget per pass, then
// a checkpoint that must truncate the log. It marks the row complete once
// all of that has finished; the cleanup does not run again unless a later
// migration records it again (see migration56.go).
//
// The checkpoint row's last_rowid is the position of the phase the cleanup
// reached in legacyPurgeMaintenancePhases, and processed_rows the number of
// phases it has finished. Releases before schema 56 had no free-pages phase,
// so their last position, the checkpoint phase, is now that of the
// free-pages phase, which comes before it.
const (
	// legacyPurgeMaintenanceState is the fts_backfill_state checkpoint of the
	// cleanup.
	legacyPurgeMaintenanceState = "legacy_tenant_purge_maintenance"
	// legacyPurgeMaintenancePhase names the cleanup in edgewatch health.
	legacyPurgeMaintenancePhase = "legacy-tenant-purge"
)

// migration55Statements record the cleanup as pending when a tenant has been
// deleted, and leave a database without one unchanged. A tenant that is being
// deleted and was already compacting the indexes at the upgrade goes back to
// its verify phase: an earlier release may have deleted another tenant after
// that compaction began, and the compaction that finishes its purge now
// starts after every such tenant, so it completes the cleanup too (see
// finishTenantPurge). Both statements can run again without changing a
// cleanup that is pending or complete.
func migration55Statements() []string {
	return []string{
		`INSERT OR IGNORE INTO fts_backfill_state(table_name,last_rowid,processed_rows,initialized,complete,updated_at)
SELECT '` + legacyPurgeMaintenanceState + `',0,0,0,0,strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE EXISTS (SELECT 1 FROM tenants WHERE state='` + TenantStateDeleted + `')`,
		`UPDATE tenants SET purge_phase='` + tenantPurgePhaseVerify + `'
WHERE state='` + TenantStateDeleting + `' AND (purge_phase LIKE '` + tenantPurgePhaseCompact + `%' OR purge_phase='` + tenantPurgePhaseCheckpoint + `')
AND EXISTS (SELECT 1 FROM fts_backfill_state WHERE table_name='` + legacyPurgeMaintenanceState + `' AND complete=0)`,
	}
}

// legacyPurgeMaintenancePhases are the phases of the cleanup in order: the
// cleanup before it has begun, the compaction of each search index, the
// overwrite of free pages, which a database with incremental auto-vacuum
// skips, and the checkpoint.
func legacyPurgeMaintenancePhases() []string {
	phases := []string{""}
	for _, index := range tenantPurgeSearchIndexes {
		phases = append(phases, tenantPurgePhaseCompact+index)
	}
	return append(phases, tenantPurgePhaseFreePages, tenantPurgePhaseCheckpoint)
}

// legacyPurgeMaintenancePhaseAt returns the phase at a position of
// legacyPurgeMaintenancePhases. A position out of range, such as one that a
// later release wrote, starts the cleanup over.
func legacyPurgeMaintenancePhaseAt(position int64) string {
	phases := legacyPurgeMaintenancePhases()
	if position < 0 || position >= int64(len(phases)) {
		return ""
	}
	return phases[position]
}

// LegacyPurgeMaintenanceResult reports one pass of the cleanup after the
// tenants that earlier releases deleted.
type LegacyPurgeMaintenanceResult struct {
	// Pending reports that the cleanup had not finished when the pass
	// began. The other fields are set only then.
	Pending bool
	// Started reports that this pass began the cleanup.
	Started bool
	// Phase is the phase the cleanup reached: a compaction phase, the
	// free-pages phase or the checkpoint phase of the tenant purge, "" before
	// it has begun, or complete.
	Phase string
	// Deferred reports that a tenant is being deleted. Its purge compacts
	// the search indexes, overwrites free pages where it must, and truncates
	// the log once its rows are erased, which completes this cleanup too, so
	// the pass left the cleanup alone.
	Deferred bool
	// Complete reports that the cleanup finished in this pass.
	Complete bool
	// CheckpointBusy reports that a reader, such as a running backup, held
	// an older snapshot of the database, so the pass's checkpoint could not
	// truncate the write-ahead log. The next pass retries it.
	CheckpointBusy bool
}

// RunLegacyPurgeMaintenance runs one pass of the cleanup after the tenants
// that earlier releases deleted, while schema 55 has recorded it as pending
// and no tenant is being deleted. A pass that runs out of its maintenance
// budget, or whose checkpoint a reader keeps busy, leaves the cleanup at its
// phase for the next pass; cancellation and database errors are returned.
func (ss *SystemStore) RunLegacyPurgeMaintenance(ctx context.Context) (LegacyPurgeMaintenanceResult, error) {
	return ss.runLegacyPurgeMaintenance(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize})
}

func (ss *SystemStore) runLegacyPurgeMaintenance(ctx context.Context, options tenantPurgeOptions) (LegacyPurgeMaintenanceResult, error) {
	var result LegacyPurgeMaintenanceResult
	var position int64
	var deleting int
	err := ss.store.reader().QueryRowContext(ctx, `SELECT last_rowid,EXISTS(SELECT 1 FROM tenants WHERE state=? AND is_default=0) FROM fts_backfill_state WHERE table_name=? AND complete=0`, TenantStateDeleting, legacyPurgeMaintenanceState).Scan(&position, &deleting)
	if errors.Is(err, sql.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	result.Pending, result.Phase = true, legacyPurgeMaintenancePhaseAt(position)
	if deleting != 0 {
		result.Deferred = true
		return result, nil
	}
	db := ss.store.DB
	started, err := execCount(ctx, db, `UPDATE fts_backfill_state SET initialized=1,updated_at=? WHERE table_name=? AND complete=0 AND initialized=0`, sqliteTimestamp(time.Now()), legacyPurgeMaintenanceState)
	if err != nil {
		return result, err
	}
	result.Started = started == 1
	finished, busy, err := runSearchMaintenance(ctx, db, recordLegacyPurgeMaintenancePhase, options, &result.Phase)
	result.CheckpointBusy = busy
	if err != nil || !finished {
		return result, err
	}
	completed, err := completeLegacyPurgeMaintenance(ctx, db)
	if err != nil {
		return result, err
	}
	if !completed {
		return result, errLegacyPurgeMaintenanceGone
	}
	result.Phase, result.Complete = tenantPurgePhaseComplete, true
	return result, nil
}

// errLegacyPurgeMaintenanceGone reports that the cleanup was no longer
// pending when a pass recorded its progress.
var errLegacyPurgeMaintenanceGone = fmt.Errorf("%w: the cleanup after deleted tenants is no longer pending", ErrConflict)

// recordLegacyPurgeMaintenancePhase records the phase that the cleanup
// entered, and the phases before it as finished.
func recordLegacyPurgeMaintenancePhase(ctx context.Context, execer contextExecer, phase string) error {
	position := max(slices.Index(legacyPurgeMaintenancePhases(), phase), 0)
	updated, err := execCount(ctx, execer, `UPDATE fts_backfill_state SET last_rowid=?,processed_rows=?,updated_at=? WHERE table_name=? AND complete=0`, position, max(position-1, 0), sqliteTimestamp(time.Now()), legacyPurgeMaintenanceState)
	if err != nil {
		return err
	}
	if updated != 1 {
		return errLegacyPurgeMaintenanceGone
	}
	return nil
}

// completeLegacyPurgeMaintenance marks the cleanup finished when it is
// pending, and reports whether it was.
func completeLegacyPurgeMaintenance(ctx context.Context, execer contextExecer) (bool, error) {
	last := len(legacyPurgeMaintenancePhases()) - 1
	updated, err := execCount(ctx, execer, `UPDATE fts_backfill_state SET last_rowid=?,processed_rows=?,initialized=1,complete=1,updated_at=? WHERE table_name=? AND complete=0`, last, last, sqliteTimestamp(time.Now()), legacyPurgeMaintenanceState)
	return updated == 1, err
}

// MaintenanceStatus is database maintenance that the daemon runs in the
// background while it is ready, as edgewatch health reports it: the phase,
// named like the startup phases, the number of its steps that have finished
// out of its total, and when it last recorded progress.
type MaintenanceStatus struct {
	Phase     string    `json:"phase"`
	Progress  int64     `json:"progress"`
	Total     int64     `json:"total"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// legacyPurgeMaintenanceStatus returns the cleanup after deleted tenants
// while it is pending, or nil. Its phase is legacyPurgeMaintenancePhase,
// followed by the tenant purge phase it reached once it has begun.
func legacyPurgeMaintenanceStatus(ctx context.Context, reader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (*MaintenanceStatus, error) {
	var position, finished int64
	var updatedAt string
	err := reader.QueryRowContext(ctx, `SELECT last_rowid,processed_rows,updated_at FROM fts_backfill_state WHERE table_name=? AND complete=0`, legacyPurgeMaintenanceState).Scan(&position, &finished, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	status := &MaintenanceStatus{Phase: legacyPurgeMaintenancePhase, Progress: finished, Total: int64(len(legacyPurgeMaintenancePhases()) - 1)}
	if phase := legacyPurgeMaintenancePhaseAt(position); phase != "" {
		status.Phase += ":" + phase
	}
	// The time is diagnostic only; one that does not parse is left out.
	status.UpdatedAt, _ = parseStartupTime(updatedAt)
	return status, nil
}
