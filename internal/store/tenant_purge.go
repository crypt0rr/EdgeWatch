package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
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
//   - After the tombstone it compacts the search indexes, returns free pages
//     to the file system when the database uses incremental auto-vacuum,
//     and truncates the write-ahead log, which may still hold old copies of
//     the erased pages. Backups taken before the purge still hold the
//     tenant's data.
//   - While a job of the tenant holds a live scan lease, the tenant is left
//     for the next pass.
//   - The tenant's audit records are erased, except those of platform
//     administrators' actions (actor_kind 'platform'), which stay in the
//     platform audit. The purge itself is recorded there too.
//   - The default tenant is never purged.

// tenantPurgeBatchSize bounds the rows one purge transaction erases.
const tenantPurgeBatchSize = 500

// tenantPurgeMaintenanceBudget bounds the index and file maintenance after a
// purge. Later maintenance continues whatever compaction is left.
const tenantPurgeMaintenanceBudget = 30 * time.Second

// The purge_phase values that are not a table of tenantPurgeSteps: the check
// that nothing of the tenant is left, which runs after the last step, and
// the finished purge of a tombstone.
const (
	tenantPurgePhaseVerify   = "verify"
	tenantPurgePhaseComplete = "complete"
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
	// MaintenanceErr is the error of the index and file maintenance after a
	// complete purge. The purge itself has finished.
	MaintenanceErr error
}

// tenantPurgeOptions tune a purge pass for tests.
type tenantPurgeOptions struct {
	batchSize int
	// afterBatch, when set, runs on the purge connection after each
	// committed batch, with the step the batch worked on.
	afterBatch func(ctx context.Context, conn *sql.Conn, phase string) error
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
	if err := finishTenantPurge(ctx, db, id, name, slug, &result); err != nil {
		return result, err
	}
	result.MaintenanceErr = tenantPurgeMaintenance(ctx, db, tenantPurgeMaintenanceBudget)
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
	if err := tx.Commit(); err != nil {
		return err
	}
	result.Phase, result.Complete = tenantPurgePhaseComplete, true
	return nil
}

// tenantPurgeSearchIndexes are the FTS5 indexes whose segments may still
// hold terms of the erased rows until they are merged.
var tenantPurgeSearchIndexes = []string{"scan_host_search", "latest_host_search", "baseline_host_search"}

// tenantPurgeMaintenance runs after a purge, with secure_delete on, so the
// pages it frees are overwritten too. It merges the segments of each search
// index into one, as FTS5's optimize command does but a bounded number of
// pages at a time, which drops the erased rows' terms. It then returns free
// pages to the file system when the database uses incremental auto-vacuum,
// and truncates the write-ahead log. All of it is bounded by budget,
// normally tenantPurgeMaintenanceBudget; a merge left unfinished continues
// at the next merge of retention's index maintenance.
func tenantPurgeMaintenance(ctx context.Context, db *sql.DB, budget time.Duration) error {
	maintenanceCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	err := runTenantPurgeMaintenance(maintenanceCtx, db)
	if maintenanceCtx.Err() != nil && ctx.Err() == nil {
		// The budget ran out; the rest is left to later maintenance.
		return nil
	}
	return err
}

func runTenantPurgeMaintenance(ctx context.Context, db *sql.DB) error {
	for _, index := range tenantPurgeSearchIndexes {
		// Only the first merge takes a negative page count, which makes FTS5
		// merge every segment into one; the later ones continue that merge.
		pages := -ftsMergePageLimit
		for merged := true; merged; pages = ftsMergePageLimit {
			if err := withSecureDelete(ctx, db, func(conn *sql.Conn) error {
				var before, after int64
				if err := conn.QueryRowContext(ctx, `SELECT total_changes()`).Scan(&before); err != nil {
					return err
				}
				// The index names are constants of this package.
				if _, err := conn.ExecContext(ctx, `INSERT INTO `+index+`(`+index+`,rank) VALUES('merge',?)`, pages); err != nil {
					return err
				}
				if err := conn.QueryRowContext(ctx, `SELECT total_changes()`).Scan(&after); err != nil {
					return err
				}
				// A merge that found no work changes fewer than two rows.
				merged = after-before >= 2
				return nil
			}); err != nil {
				return fmt.Errorf("%s merge: %w", index, err)
			}
		}
	}
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
	if _, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	return nil
}
