package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Schema 54 keys the latest host projection by (tenant_id, address), so the
// same address scanned by two tenants keeps one row per tenant. Its step,
// now part of the baseline, only swapped the tables: it renamed the
// address-keyed projection to latestScanHostsPreTenantTable and created the
// tenant-keyed table, with triggers that refuse other writes until the copy
// completes. The startup phase latestScanHostsTenantPhase then copies the
// rows in bounded batches, keeping each rowid so that latest_host_search,
// which is keyed by that rowid, stays valid without a search rebuild. A
// database that v0.20.0 to v0.35.0 upgraded to schema 54 may still have the
// copy pending; a new database copies no row.
const (
	// latestScanHostsTenantPhase is the startup phase that edgewatch health
	// reports while the rows are copied.
	latestScanHostsTenantPhase = "tenant-latest-hosts"
	// latestScanHostsTenantRekeyState is the fts_backfill_state checkpoint of
	// the copy: last_rowid is the last copied rowid of the old table.
	latestScanHostsTenantRekeyState = "latest_scan_hosts_tenant_rekey"
	// latestScanHostsPreTenantTable holds the address-keyed rows until the
	// copy completes.
	latestScanHostsPreTenantTable = "latest_scan_hosts_pre_tenant"
	// latestScanHostsRekeyBatchSize bounds each copy transaction.
	latestScanHostsRekeyBatchSize = 500

	latestScanHostsTenantInsertTrigger = "latest_scan_hosts_tenant_insert"
	latestScanHostsTenantUpdateTrigger = "latest_scan_hosts_tenant_update"
	latestScanHostsRekeyInsertTrigger  = "latest_scan_hosts_rekey_insert"
	latestScanHostsRekeyUpdateTrigger  = "latest_scan_hosts_rekey_update"
	latestScanHostsRekeyDeleteTrigger  = "latest_scan_hosts_rekey_delete"
)

// latestScanHostsCopyColumns are the columns that the copy takes from the
// address-keyed table unchanged.
const latestScanHostsCopyColumns = "address,scan_id,job_id,job,finished_at,data_quality,address_family,source_targets_json,dns_names_json,host_json,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports,search_text"

// latestScanHostScanTenantSQL is the condition of the guard triggers that
// the row's scan belongs to the row's tenant. It joins the tenant, so SQLite
// finds the scan through scans_identity, which holds the scan's tenant: a
// lookup through the scan's primary key reads the tenant from the scan row,
// past its snapshot, once for every host row that a scan writes. A tenant's
// row outlives its scans, so the join finds every scan. Schema 66 installed
// this form; earlier schemas compared the row's tenant with the scan row's.
const latestScanHostScanTenantSQL = `EXISTS (SELECT 1 FROM tenants JOIN scans ON scans.tenant_id=tenants.id WHERE tenants.id=NEW.tenant_id AND scans.id=NEW.scan_id)`

// latestScanHostsTenantTriggerSQL are the guard triggers of the projection.
// A row must belong to the tenant of its scan, and that tenant must be
// active or disabled, so no row is written for a tenant that is being
// deleted. An upsert that replaces the observation fires the update trigger
// because it sets scan_id. Other updates, such as the search text backfill,
// keep the scan and do not fire it, so a row whose scan retention has
// removed can still be updated until retention repairs it. The triggers read
// scans and tenants, so a rebuild of either table must drop them in
// dropDependents and create them again.
var latestScanHostsTenantTriggerSQL = []string{
	`CREATE TRIGGER IF NOT EXISTS ` + latestScanHostsTenantInsertTrigger + ` BEFORE INSERT ON latest_scan_hosts BEGIN
 SELECT RAISE(ABORT, 'latest_scan_hosts.tenant_id must be the tenant of the row''s scan')
 WHERE NOT ` + latestScanHostScanTenantSQL + `;
 SELECT RAISE(ABORT, 'latest_scan_hosts.tenant_id must name an active or disabled tenant')
 WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE tenants.id=NEW.tenant_id AND tenants.state IN ('active','disabled'));
END`,
	`CREATE TRIGGER IF NOT EXISTS ` + latestScanHostsTenantUpdateTrigger + ` BEFORE UPDATE OF tenant_id, scan_id ON latest_scan_hosts BEGIN
 SELECT RAISE(ABORT, 'latest_scan_hosts.tenant_id must be the tenant of the row''s scan')
 WHERE NOT ` + latestScanHostScanTenantSQL + `;
 SELECT RAISE(ABORT, 'latest_scan_hosts.tenant_id must name an active or disabled tenant')
 WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE tenants.id=NEW.tenant_id AND tenants.state IN ('active','disabled'));
END`,
}

// rekeyLatestScanHostsByTenantContext runs the schema 54 startup phase. It
// copies the address-keyed rows into the tenant-keyed projection in bounded
// batches, then drops the old table and installs the triggers. Each batch
// commits its checkpoint with its rows, so a cancelled or interrupted phase
// resumes from the next rowid. A row takes the tenant of its scan, or the
// default tenant when retention has removed the scan; retention then
// repairs that row as before. progress receives the copied and total row
// counts after each committed batch.
//
// Once the phase has completed it only reads its checkpoint.
func rekeyLatestScanHostsByTenantContext(ctx context.Context, db *sql.DB, progress func(processed, total int64)) error {
	pending, err := latestScanHostsRekeyPending(ctx, db)
	if err != nil {
		return err
	}
	if pending {
		var processed, remaining int64
		if err := db.QueryRowContext(ctx, `SELECT COALESCE((SELECT processed_rows FROM fts_backfill_state WHERE table_name=?1),0),
 (SELECT COUNT(*) FROM `+latestScanHostsPreTenantTable+` WHERE rowid>COALESCE((SELECT last_rowid FROM fts_backfill_state WHERE table_name=?1),0))`, latestScanHostsTenantRekeyState).Scan(&processed, &remaining); err != nil {
			return err
		}
		total := processed + remaining
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			copied, done, err := copyLatestScanHostsRekeyBatchContext(ctx, db)
			if err != nil {
				return err
			}
			if done {
				break
			}
			if progress != nil {
				progress(copied, max(total, copied))
			}
		}
	} else {
		var complete int
		err := db.QueryRowContext(ctx, `SELECT complete FROM fts_backfill_state WHERE table_name=?`, latestScanHostsTenantRekeyState).Scan(&complete)
		if err == nil && complete != 0 {
			return nil
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	return completeLatestScanHostsRekeyContext(ctx, db)
}

// awaitLatestScanHostsTenantRekeyContext finishes an interrupted schema 54
// copy before a startup phase that reads or writes latest_scan_hosts or its
// search triggers. Until the copy completes, the search triggers are missing
// and the projection refuses other writes. Without a pending copy it only
// checks that the old table is gone.
func awaitLatestScanHostsTenantRekeyContext(ctx context.Context, db *sql.DB) error {
	pending, err := latestScanHostsRekeyPending(ctx, db)
	if err != nil || !pending {
		return err
	}
	return rekeyLatestScanHostsByTenantContext(ctx, db, nil)
}

// latestScanHostsRekeyPending reports whether the address-keyed table is
// still there, so the copy has not completed.
func latestScanHostsRekeyPending(ctx context.Context, db *sql.DB) (bool, error) {
	var pending bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)`, latestScanHostsPreTenantTable).Scan(&pending)
	return pending, err
}

// copyLatestScanHostsRekeyBatchContext copies the next bounded rowid range
// and advances the checkpoint in the same transaction. It returns the
// number of rows copied so far, or done when no row is left.
func copyLatestScanHostsRekeyBatchContext(ctx context.Context, db *sql.DB) (copied int64, done bool, err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = tx.Rollback() }()
	// Take the write lock before reading the checkpoint, so a concurrent
	// writer is handled by busy_timeout instead of a failed read-to-write
	// upgrade.
	now := sqliteTimestamp(time.Now())
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO fts_backfill_state(table_name,initialized,updated_at) VALUES(?,1,?)`, latestScanHostsTenantRekeyState, now); err != nil {
		return 0, false, err
	}
	var lastRowID int64
	if err := tx.QueryRowContext(ctx, `SELECT last_rowid,processed_rows FROM fts_backfill_state WHERE table_name=?`, latestScanHostsTenantRekeyState).Scan(&lastRowID, &copied); err != nil {
		return 0, false, err
	}
	var batchRows int64
	var maxRowID sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),MAX(rowid) FROM (SELECT rowid FROM `+latestScanHostsPreTenantTable+` WHERE rowid>? ORDER BY rowid LIMIT ?)`, lastRowID, latestScanHostsRekeyBatchSize).Scan(&batchRows, &maxRowID); err != nil {
		return 0, false, err
	}
	if batchRows == 0 || !maxRowID.Valid {
		return copied, true, tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO latest_scan_hosts(rowid,tenant_id,`+latestScanHostsCopyColumns+`)
SELECT old.rowid,COALESCE((SELECT scans.tenant_id FROM scans WHERE scans.id=old.scan_id),'`+DefaultTenantID+`'),`+latestScanHostsCopyColumns+`
FROM `+latestScanHostsPreTenantTable+` AS old WHERE old.rowid>? AND old.rowid<=? ORDER BY old.rowid`, lastRowID, maxRowID.Int64); err != nil {
		return 0, false, err
	}
	copied += batchRows
	if _, err := tx.ExecContext(ctx, `UPDATE fts_backfill_state SET last_rowid=?,processed_rows=?,updated_at=? WHERE table_name=?`, maxRowID.Int64, copied, now, latestScanHostsTenantRekeyState); err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return copied, false, nil
}

// completeLatestScanHostsRekeyContext drops the copied table, recreates the
// search triggers on the new table and installs its guard triggers, in one
// transaction. The search rows keep matching the rows by rowid, so the
// search checkpoints stay complete. When latest_host_search does not exist,
// as in a new database, whose baseline has none, the search triggers are
// left to the host search phase, which installs them with the projection and
// rebuilds it. Every step can run again.
func completeLatestScanHostsRekeyContext(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := sqliteTimestamp(time.Now())
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO fts_backfill_state(table_name,initialized,updated_at) VALUES(?,1,?)`, latestScanHostsTenantRekeyState, now); err != nil {
		return err
	}
	statements := []string{
		"DROP TRIGGER IF EXISTS " + latestScanHostsRekeyInsertTrigger,
		"DROP TRIGGER IF EXISTS " + latestScanHostsRekeyUpdateTrigger,
		"DROP TRIGGER IF EXISTS " + latestScanHostsRekeyDeleteTrigger,
		"DROP TABLE IF EXISTS " + latestScanHostsPreTenantTable,
	}
	var searchTables int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='latest_host_search'`).Scan(&searchTables); err != nil {
		return err
	}
	if searchTables != 0 {
		statements = append(statements, latestHostSearchTriggerSQL...)
	}
	statements = append(statements, latestScanHostsTenantTriggerSQL...)
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE fts_backfill_state SET initialized=1,complete=1,updated_at=? WHERE table_name=?`, now, latestScanHostsTenantRekeyState); err != nil {
		return err
	}
	return tx.Commit()
}
