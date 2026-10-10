package store

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// The purge of a deleted tenant. RequestTenantDeletion moves a tenant to the
// deleting state; the daemon then calls PurgeDeletingTenants, which erases
// the tenant's rows table by table in bounded batches, in the order of
// tenantPurgeSteps, and finally leaves the tenant row as a tombstone in the
// deleted state.
//
//   - Every batch is its own transaction, which also records the step in
//     tenants.purge_phase and adds the rows it erased to tenants.purge_rows,
//     so a purge that is interrupted, by shutdown or an error, resumes at
//     that step on the next pass.
//   - Each batch runs with PRAGMA secure_delete on for its connection, so
//     SQLite overwrites the content of the erased rows instead of leaving it
//     in free pages. The store has one writer connection, and the purge
//     takes it for one batch at a time, so scans, the console and the
//     daemon's heartbeat keep writing while a large tenant is purged.
//   - Once the rows are erased, and before the tombstone, it compacts the
//     search indexes, whose segments still hold the terms of the erased rows,
//     and clears the database's free pages, which may still hold rows that
//     other writers deleted without secure_delete while the tenant existed, or
//     search terms that a retention merge freed between two passes: a database
//     without incremental auto-vacuum, one created before v0.18.31, keeps them
//     in the file, so the purge overwrites every one of them (see
//     overwriteFreePages); a database with it gets them returned to the file
//     system. It then truncates the write-ahead log, which may still hold old
//     copies of the erased pages. These are phases of the purge like its steps:
//     a pass that runs out of its maintenance budget, or whose checkpoint a
//     reader keeps from truncating the log, leaves the tenant in the deleting
//     state, and the next pass continues. Backups taken before the purge still
//     hold the tenant's data. Releases before schema 55 made the tombstone
//     first and could leave this maintenance unfinished, and releases before
//     schema 56 did not overwrite free pages; RunLegacyPurgeMaintenance runs
//     what they left once after the upgrade (see migration55.go and
//     migration56.go).
//   - While a job of the tenant holds a live scan lease, the tenant is left
//     for the next pass.
//   - The tenant's audit records are erased, except those of platform
//     administrators' actions (actor_kind 'platform'), which stay in the
//     platform audit. The purge itself is recorded there too.
//   - The default tenant is never purged.

// tenantPurgeBatchSize bounds the rows one purge transaction erases.
const tenantPurgeBatchSize = 500

// tenantPurgeMaintenanceBudget bounds the index compaction, the overwrite of
// free pages and the incremental vacuum of one purge pass. The next pass
// continues whatever is left; the checkpoint that truncates the write-ahead
// log runs after them in every pass, even one whose budget ran out.
const tenantPurgeMaintenanceBudget = 30 * time.Second

// The purge_phase values that are not a table of tenantPurgeSteps. After the
// last step the purge checks that nothing of the tenant is left (verify).
// It then compacts each search index of tenantPurgeSearchIndexes in turn,
// each in the phase tenantPurgePhaseCompact followed by the index's name. A
// database without incremental auto-vacuum then has its free pages
// overwritten (free-pages); a database with it skips that phase. Last, the
// purge returns free pages to the file system when the database uses
// incremental auto-vacuum, and truncates the write-ahead log (checkpoint).
// The tombstone is the finished purge (complete).
const (
	tenantPurgePhaseVerify     = "verify"
	tenantPurgePhaseCompact    = "compact:"
	tenantPurgePhaseFreePages  = "free-pages"
	tenantPurgePhaseCheckpoint = "checkpoint"
	tenantPurgePhaseComplete   = "complete"
)

// tenantPurgeStep erases the rows of one tenant table. rowids selects the
// rowids of the tenant's rows, with the tenant's ID as ?1. An FTS5 table has
// no rowids query: its rows are erased with the rows they index, by the
// AFTER DELETE trigger named in trigger on its parent in tenancyTables.
type tenantPurgeStep struct {
	table   string
	rowids  string
	trigger string
}

// The parent rows of a tenant, with the tenant's ID as ?1.
const (
	tenantJobsSQL     = `SELECT id FROM jobs WHERE tenant_id=?1`
	tenantScansSQL    = `SELECT id FROM scans WHERE tenant_id=?1`
	tenantUsersSQL    = `SELECT id FROM users WHERE tenant_id=?1`
	tenantProfilesSQL = `SELECT id FROM scanner_profiles WHERE tenant_id=?1`
	tenantCyclesSQL   = `SELECT c.id FROM scan_cycles AS c JOIN jobs AS j ON j.id=c.job_id AND j.tenant_id=?1`
)

// tenantPurgeSteps erases a tenant's rows, children before their parents, so
// no batch has to cascade to a large set of child rows. Every table that
// tenancyTables classifies as direct or via has exactly one step, and a
// test checks the steps and their order against the registry.
var tenantPurgeSteps = []tenantPurgeStep{
	// Resumable scan work.
	{table: "scan_cycle_discovery_checkpoints", rowids: `SELECT rowid FROM scan_cycle_discovery_checkpoints WHERE cycle_id IN (` + tenantCyclesSQL + `)`},
	{table: "scan_cycle_units", rowids: `SELECT rowid FROM scan_cycle_units WHERE cycle_id IN (` + tenantCyclesSQL + `)`},
	{table: "scan_cycles", rowids: `SELECT rowid FROM scan_cycles WHERE job_id IN (` + tenantJobsSQL + `)`},
	// Baselines and runtime state.
	{table: "baseline_host_search", trigger: "baseline_hosts_search_ad"},
	{table: "baseline_hosts", rowids: `SELECT rowid FROM baseline_hosts WHERE job_id IN (` + tenantJobsSQL + `)`},
	{table: "public_dashboard_hosts", rowids: `SELECT rowid FROM public_dashboard_hosts WHERE job_id IN (` + tenantJobsSQL + `)`},
	{table: "runtime_incidents", rowids: `SELECT rowid FROM runtime_incidents WHERE job_id IN (` + tenantJobsSQL + `)`},
	{table: "job_runtime", rowids: `SELECT rowid FROM job_runtime WHERE job_id IN (` + tenantJobsSQL + `)`},
	{table: "job_runtime_meta", rowids: `SELECT rowid FROM job_runtime_meta WHERE job_id IN (` + tenantJobsSQL + `)`},
	{table: "job_silence_state", rowids: `SELECT rowid FROM job_silence_state WHERE job_id IN (` + tenantJobsSQL + `)`},
	{table: "job_revisions", rowids: `SELECT rowid FROM job_revisions WHERE job_id IN (` + tenantJobsSQL + `)`},
	// Scan history and the latest host of each address.
	{table: "latest_host_search", trigger: "latest_scan_hosts_search_ad"},
	{table: "latest_scan_hosts", rowids: `SELECT rowid FROM latest_scan_hosts WHERE tenant_id=?1`},
	{table: "scan_host_search", trigger: "scan_hosts_search_ad"},
	{table: "scan_hosts", rowids: `SELECT h.rowid FROM scan_hosts AS h JOIN scans AS s ON s.id=h.scan_id AND s.tenant_id=?1`},
	{table: "legacy_scan_host_backfill", rowids: `SELECT rowid FROM legacy_scan_host_backfill WHERE scan_id IN (` + tenantScansSQL + `)`},
	{table: "scans", rowids: `SELECT rowid FROM scans WHERE tenant_id=?1`},
	{table: "events", rowids: `SELECT rowid FROM events WHERE tenant_id=?1`},
	{table: "outbox", rowids: `SELECT rowid FROM outbox WHERE tenant_id=?1`},
	{table: "restore_quarantined_deliveries", rowids: `SELECT rowid FROM restore_quarantined_deliveries WHERE tenant_id=?1`},
	{table: "security_alert_windows", rowids: `SELECT rowid FROM security_alert_windows WHERE tenant_id=?1`},
	{table: "job_history_purge_host_keys", rowids: `SELECT rowid FROM job_history_purge_host_keys WHERE tenant_id=?1`},
	{table: "job_history_purges", rowids: `SELECT rowid FROM job_history_purges WHERE tenant_id=?1`},
	{table: "jobs", rowids: `SELECT rowid FROM jobs WHERE tenant_id=?1`},
	{table: "public_dashboards", rowids: `SELECT rowid FROM public_dashboards WHERE tenant_id=?1`},
	// Notification destinations and scanner profiles. The delivery health of
	// a destination deleted before deletes removed its health names no
	// destination, so its owner cannot be told apart; no tenant counts it,
	// and the purge erases every such row with the tenant's own.
	{table: "notification_delivery_health", rowids: `SELECT h.rowid FROM notification_delivery_health AS h WHERE h.destination_identity LIKE 'managed:%' AND (EXISTS (SELECT 1 FROM managed_notifications AS m WHERE m.id=substr(h.destination_identity,9) AND m.tenant_id=?1) OR NOT EXISTS (SELECT 1 FROM managed_notifications AS m WHERE m.id=substr(h.destination_identity,9)))`},
	{table: "managed_notifications", rowids: `SELECT rowid FROM managed_notifications WHERE tenant_id=?1`},
	{table: "scanner_profile_revisions", rowids: `SELECT rowid FROM scanner_profile_revisions WHERE profile_id IN (` + tenantProfilesSQL + `)`},
	{table: "scanner_profiles", rowids: `SELECT rowid FROM scanner_profiles WHERE tenant_id=?1`},
	// Accounts, and the audit records of everything but the platform
	// administrators' actions.
	{table: "sessions", rowids: `SELECT rowid FROM sessions WHERE user_id IN (` + tenantUsersSQL + `)`},
	{table: "recovery_codes", rowids: `SELECT rowid FROM recovery_codes WHERE user_id IN (` + tenantUsersSQL + `)`},
	{table: "totp_replay", rowids: `SELECT rowid FROM totp_replay WHERE user_id IN (` + tenantUsersSQL + `)`},
	{table: "user_invites", rowids: `SELECT rowid FROM user_invites WHERE user_id IN (` + tenantUsersSQL + `)`},
	{table: "security_audit", rowids: `SELECT rowid FROM security_audit WHERE tenant_id=?1 AND actor_kind<>'` + AuditActorPlatform + `'`},
	{table: "users", rowids: `SELECT rowid FROM users WHERE tenant_id=?1`},
}

// TenantPurgeResult reports one pass of the purge of a tenant.
type TenantPurgeResult struct {
	TenantID string
	// Phase is the step the purge reached, as tenants.purge_phase records
	// it.
	Phase string
	// Rows counts the rows this pass erased, and TotalRows those the purge
	// erased since it began. Rows of a search index, which go with the rows
	// they index, are not counted.
	Rows      int64
	TotalRows int64
	// Deferred reports that a job of the tenant holds a live scan lease, so
	// the pass left the tenant for the next one.
	Deferred bool
	// Complete reports that the purge finished and the tenant is now a
	// tombstone.
	Complete bool
	// MaintenancePending reports that the tenant's rows are erased, but the
	// compaction of the search indexes, the overwrite of the free pages or
	// the truncation of the write-ahead log, which may still hold the erased
	// rows, has not finished: the pass ran out of its maintenance budget, or
	// a reader kept the checkpoint from truncating the log. The tenant stays
	// in the deleting state, and the next pass continues from Phase.
	MaintenancePending bool
	// CheckpointBusy reports that a reader, such as a running backup, held
	// an older snapshot of the database, so the pass's checkpoint could not
	// truncate the write-ahead log.
	CheckpointBusy bool
	// LegacyMaintenanceCompleted reports that the purge's compaction and
	// checkpoint also completed the pending cleanup after the tenants that
	// earlier releases deleted (see RunLegacyPurgeMaintenance), which the
	// tombstone's transaction marked finished.
	LegacyMaintenanceCompleted bool
}

// tenantPurgeOptions tune a purge pass for tests.
type tenantPurgeOptions struct {
	batchSize int
	// afterBatch, when set, runs on the purge connection after each
	// committed batch, with the step the batch worked on.
	afterBatch func(ctx context.Context, conn *sql.Conn, phase string) error
	// maintenanceBudget, when set, replaces the context that bounds the
	// maintenance of a pass by tenantPurgeMaintenanceBudget. The maintenance
	// treats the end of that context as a spent budget.
	maintenanceBudget func(ctx context.Context) (context.Context, context.CancelFunc)
	// afterMerge, when set, runs after each merge of a search index that
	// started a merge of every segment or continued one, with the context
	// bounded by the maintenance budget, the index, and the merge's page
	// count, which is negative for a merge of every segment.
	afterMerge func(ctx context.Context, index string, pages int) error
	// afterFreePages, when set, runs after each committed step of the
	// overwrite of free pages, with the context bounded by the maintenance
	// budget and the step (see freePagesStep).
	afterFreePages func(ctx context.Context, step freePagesStep) error
}

// PurgeDeletingTenants runs one purge pass over every tenant that is being
// deleted, oldest request first, and returns a result for each. A tenant
// whose job holds a live scan lease is deferred to the next pass. A tenant
// whose pass fails is resumed by the next pass; the errors are returned
// together, and cancellation stops the pass.
func (ss *SystemStore) PurgeDeletingTenants(ctx context.Context) ([]TenantPurgeResult, error) {
	return ss.purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: tenantPurgeBatchSize})
}

func (ss *SystemStore) purgeDeletingTenants(ctx context.Context, options tenantPurgeOptions) ([]TenantPurgeResult, error) {
	ids, err := ss.deletingTenantIDs(ctx)
	if err != nil {
		return nil, err
	}
	var results []TenantPurgeResult
	var errs []error
	for _, id := range ids {
		result, err := ss.purgeTenant(ctx, id, options)
		results = append(results, result)
		if err != nil {
			errs = append(errs, fmt.Errorf("purge tenant %s: %w", id, err))
			if ctx.Err() != nil {
				break
			}
		}
	}
	return results, errors.Join(errs...)
}

// deletingTenantIDs returns the tenants that are being deleted, apart from
// the default tenant, oldest request first.
func (ss *SystemStore) deletingTenantIDs(ctx context.Context) ([]string, error) {
	rows, err := ss.store.reader().QueryContext(ctx, `SELECT id FROM tenants WHERE state=? AND is_default=0 ORDER BY state_changed_at, id`, TenantStateDeleting)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// purgeTenant runs one pass of the tenant's purge.
func (ss *SystemStore) purgeTenant(ctx context.Context, id string, options tenantPurgeOptions) (TenantPurgeResult, error) {
	result := TenantPurgeResult{TenantID: id}
	db := ss.store.DB
	var name, slug string
	if err := db.QueryRowContext(ctx, `SELECT name,slug,purge_phase,purge_rows FROM tenants WHERE id=? AND state=? AND is_default=0`, id, TenantStateDeleting).Scan(&name, &slug, &result.Phase, &result.TotalRows); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Another pass finished the tenant in the meantime.
			return result, nil
		}
		return result, err
	}
	leased, err := tenantHoldsLiveLease(ctx, db, id)
	if err != nil || leased {
		result.Deferred = leased
		return result, err
	}
	start := 0
	if result.Phase != "" {
		start = len(tenantPurgeSteps)
		for i, step := range tenantPurgeSteps {
			if step.table == result.Phase {
				start = i
				break
			}
		}
	}
	for i := start; i < len(tenantPurgeSteps); i++ {
		if err := purgeTenantStep(ctx, db, id, i, options, &result); err != nil {
			return result, err
		}
	}
	remaining, err := tenantRowsRemaining(ctx, ss.store.reader(), id)
	if err != nil {
		return result, err
	}
	if remaining != "" {
		// A row was written after its step finished. Start over; each step
		// that has nothing left to erase finishes at once.
		first := tenantPurgeSteps[0].table
		if _, err := db.ExecContext(ctx, `UPDATE tenants SET purge_phase=? WHERE id=? AND state=?`, first, id, TenantStateDeleting); err != nil {
			return result, err
		}
		result.Phase = first
		return result, fmt.Errorf("rows of %s remain after the last step; the next pass starts over", remaining)
	}
	finished, err := purgeTenantMaintenance(ctx, db, id, options, &result)
	if err != nil {
		return result, err
	}
	if !finished {
		result.MaintenancePending = true
		return result, nil
	}
	if err := finishTenantPurge(ctx, db, id, name, slug, &result); err != nil {
		return result, err
	}
	return result, nil
}

// purgeTenantStep erases the tenant's rows of step i in batches, each with
// its progress, and records the next step once the table holds none.
func purgeTenantStep(ctx context.Context, db *sql.DB, id string, i int, options tenantPurgeOptions, result *TenantPurgeResult) error {
	step := tenantPurgeSteps[i]
	next := tenantPurgePhaseVerify
	if i+1 < len(tenantPurgeSteps) {
		next = tenantPurgeSteps[i+1].table
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var erased int64
		err := withSecureDelete(ctx, db, func(conn *sql.Conn) error {
			// The transaction is not bound to ctx: a cancelled context would
			// roll it back from another goroutine while the connection's
			// setting is being restored. A batch is bounded, and ctx is
			// checked before the next one.
			tx, err := conn.BeginTx(context.WithoutCancel(ctx), nil)
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback() }()
			if step.rowids != "" {
				if erased, err = execCount(ctx, tx, `DELETE FROM `+step.table+` WHERE rowid IN (`+step.rowids+` LIMIT ?2)`, id, options.batchSize); err != nil {
					return err
				}
			}
			phase := step.table
			if erased < int64(options.batchSize) {
				phase = next
			}
			updated, err := execCount(ctx, tx, `UPDATE tenants SET purge_phase=?,purge_rows=purge_rows+? WHERE id=? AND state=?`, phase, erased, id, TenantStateDeleting)
			if err != nil {
				return err
			}
			if updated != 1 {
				return fmt.Errorf("%w: the tenant is no longer being deleted", ErrConflict)
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			if options.afterBatch != nil {
				return options.afterBatch(ctx, conn, step.table)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("%s: %w", step.table, err)
		}
		result.Rows += erased
		result.TotalRows += erased
		if erased < int64(options.batchSize) {
			result.Phase = next
			return nil
		}
		result.Phase = step.table
	}
}

// withSecureDelete runs fn on the store's writer connection with PRAGMA
// secure_delete on, and turns it back to its previous value before the
// connection returns to the pool. When the setting cannot be restored, the
// connection is discarded instead, so no other writer inherits it.
func withSecureDelete(ctx context.Context, db *sql.DB, fn func(*sql.Conn) error) (err error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	var previous int
	if err := conn.QueryRowContext(ctx, `PRAGMA secure_delete`).Scan(&previous); err != nil {
		_ = conn.Close()
		return err
	}
	defer func() {
		restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		var restored int
		restoreErr := conn.QueryRowContext(restoreCtx, fmt.Sprintf(`PRAGMA secure_delete=%d`, previous)).Scan(&restored)
		if restoreErr == nil && restored != previous {
			restoreErr = fmt.Errorf("PRAGMA secure_delete is %d after restoring %d", restored, previous)
		}
		if restoreErr != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			err = errors.Join(err, fmt.Errorf("restore secure_delete: %w; the connection was closed", restoreErr))
		}
		_ = conn.Close()
	}()
	var enabled int
	if err := conn.QueryRowContext(ctx, `PRAGMA secure_delete=ON`).Scan(&enabled); err != nil {
		return err
	}
	if enabled != 1 {
		return fmt.Errorf("PRAGMA secure_delete is %d after turning it on", enabled)
	}
	return fn(conn)
}

// tenantHoldsLiveLease reports whether a job of the tenant holds a scan
// lease that has not expired. When none does, it removes the expired leases
// of the tenant's jobs, which name jobs the purge erases.
func tenantHoldsLiveLease(ctx context.Context, db *sql.DB, id string) (bool, error) {
	var live int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_leases WHERE expires_at>? AND job IN (SELECT id FROM jobs WHERE tenant_id=?)`, sqliteTimestamp(time.Now()), id).Scan(&live); err != nil {
		return false, err
	}
	if live > 0 {
		return true, nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM job_leases WHERE job IN (SELECT id FROM jobs WHERE tenant_id=?)`, id)
	return false, err
}

// tenantRowsRemaining returns the first table that still holds a row of the
// tenant, or "".
func tenantRowsRemaining(ctx context.Context, db *sql.DB, id string) (string, error) {
	for _, step := range tenantPurgeSteps {
		if step.rowids == "" {
			continue
		}
		var found int
		if err := db.QueryRowContext(ctx, `SELECT EXISTS(`+step.rowids+`)`, id).Scan(&found); err != nil {
			return "", err
		}
		if found != 0 {
			return step.table, nil
		}
	}
	return "", nil
}

// finishTenantPurge makes the tenant a tombstone and records the purge in
// the platform audit, in one transaction. The tombstone keeps the tenant's
// ID, name and slug, so the platform audit records that name it stay
// meaningful, but a new tenant may take the name and the slug. It drops the
// update routing, which named destinations that no longer exist.
//
// The purge's compaction of every search index began after the tenants that
// earlier releases deleted were erased (schema 55 sends a purge that was
// already compacting at the upgrade back to its verify phase), so did its
// overwrite of free pages in a database without incremental auto-vacuum
// (schema 56 sends a purge that was already in its checkpoint phase at the
// upgrade back to that overwrite), and its checkpoint truncated the log, so
// the same transaction also marks the cleanup after those tenants finished
// when it is pending.
func finishTenantPurge(ctx context.Context, db *sql.DB, id, name, slug string, result *TenantPurgeResult) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	stamp := sqliteTimestamp(now)
	updated, err := execCount(ctx, tx, `UPDATE tenants SET state=?,purge_phase=?,update_destinations_json='',revision=revision+1,updated_at=?,state_changed_at=?,state_changed_by=? WHERE id=? AND state=?`, TenantStateDeleted, tenantPurgePhaseComplete, stamp, stamp, AuditActorSystem, id, TenantStateDeleting)
	if err != nil {
		return err
	}
	if updated != 1 {
		return fmt.Errorf("%w: the tenant is no longer being deleted", ErrConflict)
	}
	var kept int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE tenant_id=? AND actor_kind=?`, id, AuditActorPlatform).Scan(&kept); err != nil {
		return err
	}
	entry := AuditEntry{Action: auditTenantPurged, ActorKind: AuditActorSystem, Detail: fmt.Sprintf("business unit %s purged: %s; %d rows erased, %d platform audit records kept", id, tenantLabel(name, slug), result.TotalRows, kept)}
	if err := insertPlatformAuditEntry(ctx, tx, entry, now); err != nil {
		return err
	}
	legacyCompleted, err := completeLegacyPurgeMaintenance(ctx, tx)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	result.Phase, result.Complete, result.LegacyMaintenanceCompleted = tenantPurgePhaseComplete, true, legacyCompleted
	return nil
}

// tenantPurgeSearchIndexes are the FTS5 indexes whose segments may still
// hold terms of the erased rows until they are merged, in the order the
// purge compacts them.
var tenantPurgeSearchIndexes = []string{"scan_host_search", "latest_host_search", "baseline_host_search"}

// purgeTenantMaintenance runs the phases after the tenant's rows are erased,
// from the phase in result, recording each phase it enters in
// tenants.purge_phase, and reports whether they finished, so the tenant may
// become a tombstone. See runSearchMaintenance.
func purgeTenantMaintenance(ctx context.Context, db *sql.DB, id string, options tenantPurgeOptions, result *TenantPurgeResult) (bool, error) {
	record := func(ctx context.Context, execer contextExecer, phase string) error {
		return setTenantPurgePhase(ctx, execer, id, phase)
	}
	finished, busy, err := runSearchMaintenance(ctx, db, record, options, &result.Phase)
	result.CheckpointBusy = busy
	return finished, err
}

// recordMaintenancePhase records a phase that runSearchMaintenance enters:
// in tenants.purge_phase for the purge of a tenant, or in the checkpoint of
// the cleanup after the tenants that earlier releases purged (see
// migration55.go). execer is the transaction that starts the merge of an
// index, or the database.
type recordMaintenancePhase func(ctx context.Context, execer contextExecer, phase string) error

// runSearchMaintenance runs the maintenance after erased rows from *phase,
// which is a compaction phase, the free-pages phase, the checkpoint phase,
// or any other value to start at the first index, and advances *phase as it
// goes. Within the maintenance budget it compacts the search indexes, and
// overwrites the free pages of a database without incremental auto-vacuum
// or returns them to the file system in one with it. It then runs a
// checkpoint that truncates the write-ahead log, even when the budget ran
// out, so the log does not keep old copies of the erased pages longer than
// it must, and reports whether that checkpoint was busy. The maintenance
// has finished only when the compaction, the overwrite and the vacuum have,
// and the checkpoint was not busy. A spent budget and a busy checkpoint
// leave *phase for the next pass; cancellation and database errors are
// returned.
func runSearchMaintenance(ctx context.Context, db *sql.DB, record recordMaintenancePhase, options tenantPurgeOptions, phase *string) (finished, busy bool, err error) {
	budgetCtx, cancel := options.budget(ctx)
	defer cancel()
	compacted, err := compactSearchIndexes(budgetCtx, db, record, options, phase)
	if err != nil && (ctx.Err() != nil || budgetCtx.Err() == nil) {
		return false, false, err
	}
	busy, err = checkpointTruncate(ctx, db)
	if err != nil {
		return false, false, fmt.Errorf("checkpoint: %w", err)
	}
	return compacted && !busy, busy, nil
}

// compactSearchIndexes compacts each search index in turn, from the one that
// *phase names, then overwrites the free pages of a database without
// incremental auto-vacuum (overwriteFreePages), and then returns free pages
// to the file system when the database uses incremental auto-vacuum. It
// records each phase it enters with record, and reports whether it
// finished.
func compactSearchIndexes(ctx context.Context, db *sql.DB, record recordMaintenancePhase, options tenantPurgeOptions, phase *string) (bool, error) {
	first, started := 0, false
	if *phase == tenantPurgePhaseFreePages || *phase == tenantPurgePhaseCheckpoint {
		first = len(tenantPurgeSearchIndexes)
	} else if index, ok := strings.CutPrefix(*phase, tenantPurgePhaseCompact); ok {
		// A phase that names no index, such as one that a later release
		// removed, starts the compaction over.
		if i := slices.Index(tenantPurgeSearchIndexes, index); i >= 0 {
			first, started = i, true
		}
	}
	for _, index := range tenantPurgeSearchIndexes[first:] {
		if !started {
			if err := startSearchIndexCompaction(ctx, db, record, index); err != nil {
				return false, fmt.Errorf("%s merge: %w", index, err)
			}
			*phase = tenantPurgePhaseCompact + index
			if err := options.merged(ctx, index, -ftsMergePageLimit); err != nil {
				return false, err
			}
		}
		started = false
		if err := continueSearchIndexCompaction(ctx, db, index, options); err != nil {
			return false, fmt.Errorf("%s merge: %w", index, err)
		}
	}
	if *phase != tenantPurgePhaseCheckpoint {
		if err := overwriteFreePages(ctx, db, record, options, phase); err != nil {
			return false, err
		}
	}
	if err := incrementalVacuum(ctx, db); err != nil {
		return false, err
	}
	return true, nil
}

// budget returns the context that bounds the maintenance of a pass.
func (options tenantPurgeOptions) budget(ctx context.Context) (context.Context, context.CancelFunc) {
	if options.maintenanceBudget != nil {
		return options.maintenanceBudget(ctx)
	}
	return context.WithTimeout(ctx, tenantPurgeMaintenanceBudget)
}

// merged runs the afterMerge hook, if any.
func (options tenantPurgeOptions) merged(ctx context.Context, index string, pages int) error {
	if options.afterMerge == nil {
		return nil
	}
	return options.afterMerge(ctx, index, pages)
}

// freePagesStepped runs the afterFreePages hook, if any.
func (options tenantPurgeOptions) freePagesStepped(ctx context.Context, step freePagesStep) error {
	if options.afterFreePages == nil {
		return nil
	}
	return options.afterFreePages(ctx, step)
}

// setTenantPurgePhase records the phase of a tenant that is being deleted.
func setTenantPurgePhase(ctx context.Context, execer contextExecer, id, phase string) error {
	updated, err := execCount(ctx, execer, `UPDATE tenants SET purge_phase=? WHERE id=? AND state=?`, phase, id, TenantStateDeleting)
	if err != nil {
		return err
	}
	if updated != 1 {
		return fmt.Errorf("%w: the tenant is no longer being deleted", ErrConflict)
	}
	return nil
}

// startSearchIndexCompaction starts a merge of every segment of the index
// into one and records the index's compaction phase with record, in one
// transaction, so a later pass continues that merge rather than starting
// another. The merge takes as its input every segment, those that hold the
// terms of the erased rows and those that hold the markers of their
// deletion; once it has finished, no segment holds those terms.
func startSearchIndexCompaction(ctx context.Context, db *sql.DB, record recordMaintenancePhase, index string) error {
	return withSecureDelete(ctx, db, func(conn *sql.Conn) error {
		// As in purgeTenantStep, the transaction is not bound to ctx.
		tx, err := conn.BeginTx(context.WithoutCancel(ctx), nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		// A negative page count makes FTS5 merge every segment into one.
		if _, err := tx.ExecContext(ctx, searchIndexMergeSQL(index), -ftsMergePageLimit); err != nil {
			return err
		}
		if err := record(ctx, tx, tenantPurgePhaseCompact+index); err != nil {
			return err
		}
		return tx.Commit()
	})
}

// continueSearchIndexCompaction continues the merge that
// startSearchIndexCompaction started, a bounded number of pages at a time,
// until it has finished.
//
// A merge with a positive page count continues a merge in progress, but
// finds no work when a lower level holds at least as many segments as the
// merge has inputs and fewer than FTS5's usermerge setting, which new rows
// can bring about. A merge with a negative page count then merges every
// segment into one again, the output of the unfinished merge included.
func continueSearchIndexCompaction(ctx context.Context, db *sql.DB, index string, options tenantPurgeOptions) error {
	for {
		pages := ftsMergePageLimit
		merged, err := mergeSearchIndex(ctx, db, index, pages)
		if err != nil {
			return err
		}
		if !merged {
			merging, err := searchIndexMerging(ctx, db, index)
			if err != nil || !merging {
				return err
			}
			pages = -ftsMergePageLimit
			if _, err := mergeSearchIndex(ctx, db, index, pages); err != nil {
				return err
			}
		}
		if err := options.merged(ctx, index, pages); err != nil {
			return err
		}
	}
}

// mergeSearchIndex runs FTS5's merge command on the index with secure_delete
// on, so the pages it frees are overwritten too, and reports whether it
// found work. pages bounds the work; a negative count starts a merge of
// every segment into one, as the optimize command does.
func mergeSearchIndex(ctx context.Context, db *sql.DB, index string, pages int) (bool, error) {
	var merged bool
	err := withSecureDelete(ctx, db, func(conn *sql.Conn) error {
		var before, after int64
		if err := conn.QueryRowContext(ctx, `SELECT total_changes()`).Scan(&before); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, searchIndexMergeSQL(index), pages); err != nil {
			return err
		}
		if err := conn.QueryRowContext(ctx, `SELECT total_changes()`).Scan(&after); err != nil {
			return err
		}
		// A merge that found no work changes fewer than two rows.
		merged = after-before >= 2
		return nil
	})
	return merged, err
}

// searchIndexMergeSQL is FTS5's merge command for the index, with the page
// count as its argument. The index names are constants of this package.
func searchIndexMergeSQL(index string) string {
	return `INSERT INTO ` + index + `(` + index + `,rank) VALUES('merge',?)`
}

// searchIndexMerging reports whether a merge is in progress in the index,
// from the structure record that FTS5 keeps in the row with ID 10 of the
// index's data table.
func searchIndexMerging(ctx context.Context, db *sql.DB, index string) (bool, error) {
	var record []byte
	err := db.QueryRowContext(ctx, `SELECT block FROM `+index+`_data WHERE id=10`).Scan(&record)
	if errors.Is(err, sql.ErrNoRows) {
		// An index without a structure record has no segments.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	merging, err := ftsStructureMerging(record)
	if err != nil {
		return false, fmt.Errorf("read the structure of %s: %w", index, err)
	}
	return merging, nil
}

// ftsStructureV2 marks an FTS5 structure record whose segments carry the
// fields of the V2 format.
var ftsStructureV2 = []byte{0xff, 0x00, 0x00, 0x01}

// ftsMaxSegments is FTS5's bound on the levels and segments of an index.
const ftsMaxSegments = 2000

// ftsStructureMerging reports whether a level of an FTS5 structure record
// has a merge in progress. The record, as fts5StructureDecode in SQLite's
// fts5_index.c reads it, is a 4-byte cookie, the V2 marker when the record
// has that format, and then varints: the number of levels and of segments
// and a write counter, and for each level the number of its segments that
// a merge in progress takes as input, the number of its segments, and for
// each segment its ID and first and last page, followed in the V2 format by
// five more fields. A record that does not read as one is an error, so a
// change of the format stops the purge rather than misleading it.
func ftsStructureMerging(record []byte) (bool, error) {
	if len(record) < 4 {
		return false, errors.New("the FTS5 structure record is too short")
	}
	r := ftsStructureReader{record: record, pos: 4}
	fields := uint64(3)
	if bytes.HasPrefix(record[4:], ftsStructureV2) {
		r.pos += len(ftsStructureV2)
		fields += 5
	}
	levels, segments := r.next(), r.next()
	r.next() // The write counter.
	if levels > ftsMaxSegments || segments > ftsMaxSegments {
		return false, fmt.Errorf("the FTS5 structure record has %d levels and %d segments", levels, segments)
	}
	for level := uint64(0); level < levels && r.err == nil; level++ {
		inputs, count := r.next(), r.next()
		switch {
		case r.err != nil:
		case inputs > count || count > segments:
			return false, fmt.Errorf("level %d of the FTS5 structure record has %d merge inputs of %d segments, of %d left", level, inputs, count, segments)
		case inputs > 0:
			return true, nil
		}
		segments -= count
		for field := uint64(0); field < count*fields && r.err == nil; field++ {
			r.next()
		}
	}
	if r.err == nil && segments != 0 {
		return false, fmt.Errorf("the levels of the FTS5 structure record miss %d segments", segments)
	}
	return false, r.err
}

// ftsStructureReader reads the varints of an FTS5 structure record.
type ftsStructureReader struct {
	record []byte
	pos    int
	err    error
}

// next reads a varint in SQLite's format: up to eight bytes of seven bits,
// most significant first, each but the last with its high bit set, and a
// ninth byte of eight bits. It returns 0 once the record has ended early.
func (r *ftsStructureReader) next() uint64 {
	var value uint64
	for i := 0; r.err == nil; i++ {
		if r.pos >= len(r.record) {
			r.err = errors.New("the FTS5 structure record ends early")
			break
		}
		b := r.record[r.pos]
		r.pos++
		if i == 8 {
			return value<<8 | uint64(b)
		}
		value = value<<7 | uint64(b&0x7f)
		if b < 0x80 {
			return value
		}
	}
	return 0
}

// incrementalVacuum returns the free pages to the file system, with
// secure_delete on, when the database uses incremental auto-vacuum.
func incrementalVacuum(ctx context.Context, db *sql.DB) error {
	var autoVacuum int
	if err := db.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&autoVacuum); err != nil {
		return fmt.Errorf("read auto-vacuum mode: %w", err)
	}
	for vacuum := autoVacuum == 2; vacuum; {
		if err := withSecureDelete(ctx, db, func(conn *sql.Conn) error {
			var free int64
			if err := conn.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&free); err != nil {
				return err
			}
			if vacuum = free > 0; vacuum {
				_, err := conn.ExecContext(ctx, fmt.Sprintf(`PRAGMA incremental_vacuum(%d)`, incrementalVacuumPageLimit))
				return err
			}
			return nil
		}); err != nil {
			return fmt.Errorf("incremental vacuum: %w", err)
		}
	}
	return nil
}

// checkpointTruncate copies the write-ahead log into the database and
// truncates the log to zero bytes. It reports whether the checkpoint was
// busy: while a reader holds an older snapshot, SQLite waits for the
// connection's busy timeout and then reports busy in the first column
// rather than an error, and the log keeps its frames.
func checkpointTruncate(ctx context.Context, db *sql.DB) (bool, error) {
	var busy, logFrames, checkpointed int64
	if err := db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed); err != nil {
		return false, err
	}
	return busy != 0, nil
}
