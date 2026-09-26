package store

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"
)

// Schema 54 keys the latest host projection by (tenant_id, address), so the
// same address scanned by two tenants keeps one row per tenant. The versioned
// migration only swaps the tables: it renames the address-keyed projection
// to latestScanHostsPreTenantTable and creates the tenant-keyed table. The
// startup phase latestScanHostsTenantPhase then copies the rows in bounded
// batches, keeping each rowid so that latest_host_search, which is keyed by
// that rowid, stays valid without a search rebuild.
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

// latestScanHostsRekeyGuardSQL refuses every write to the new projection
// other than the copy while it runs. The search triggers are not installed
// yet, so another write, such as a scan saved by a host command, would leave
// latest_host_search out of step with the table, and a new row could take
// the rowid of a row that has not been copied yet. The copy passes because
// it inserts each row under the rowid and address that it has in the old
// table.
var latestScanHostsRekeyGuardSQL = []string{
	`CREATE TRIGGER IF NOT EXISTS ` + latestScanHostsRekeyInsertTrigger + ` BEFORE INSERT ON latest_scan_hosts
WHEN NOT EXISTS (SELECT 1 FROM ` + latestScanHostsPreTenantTable + ` AS old WHERE old.rowid=NEW.rowid AND old.address=NEW.address)
BEGIN
 SELECT RAISE(ABORT, 'latest_scan_hosts is being keyed by tenant; start the daemon to finish the schema 54 upgrade');
END`,
	`CREATE TRIGGER IF NOT EXISTS ` + latestScanHostsRekeyUpdateTrigger + ` BEFORE UPDATE ON latest_scan_hosts BEGIN
 SELECT RAISE(ABORT, 'latest_scan_hosts is being keyed by tenant; start the daemon to finish the schema 54 upgrade');
END`,
	`CREATE TRIGGER IF NOT EXISTS ` + latestScanHostsRekeyDeleteTrigger + ` BEFORE DELETE ON latest_scan_hosts BEGIN
 SELECT RAISE(ABORT, 'latest_scan_hosts is being keyed by tenant; start the daemon to finish the schema 54 upgrade');
END`,
}

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
 WHERE NEW.tenant_id IS NOT (SELECT scans.tenant_id FROM scans WHERE scans.id=NEW.scan_id);
 SELECT RAISE(ABORT, 'latest_scan_hosts.tenant_id must name an active or disabled tenant')
 WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE tenants.id=NEW.tenant_id AND tenants.state IN ('active','disabled'));
END`,
	`CREATE TRIGGER IF NOT EXISTS ` + latestScanHostsTenantUpdateTrigger + ` BEFORE UPDATE OF tenant_id, scan_id ON latest_scan_hosts BEGIN
 SELECT RAISE(ABORT, 'latest_scan_hosts.tenant_id must be the tenant of the row''s scan')
 WHERE NEW.tenant_id IS NOT (SELECT scans.tenant_id FROM scans WHERE scans.id=NEW.scan_id);
 SELECT RAISE(ABORT, 'latest_scan_hosts.tenant_id must name an active or disabled tenant')
 WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE tenants.id=NEW.tenant_id AND tenants.state IN ('active','disabled'));
END`,
}

// migration54Statements are the table guards of schema 54. Some recovery
// databases carry the schema marker without every table, so the tables that
// the copy and the guard triggers read are created in their schema 53 shape,
// with the default tenant. The table swap, and the projection of a database
// that has none, are in migration54ConditionalStatements.
func migration54Statements() []string {
	defaultTenant := "'" + DefaultTenantID + "'"
	return []string{
		`CREATE TABLE IF NOT EXISTS tenants (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL COLLATE NOCASE,
 slug TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','disabled','deleting','deleted')),
 is_default INTEGER NOT NULL DEFAULT 0 CHECK(is_default IN (0,1)),
 max_concurrent_scans INTEGER CHECK(max_concurrent_scans IS NULL OR max_concurrent_scans BETWEEN 1 AND 64),
 max_probe_count INTEGER CHECK(max_probe_count IS NULL OR max_probe_count >= 1),
 max_naabu_probe_count INTEGER CHECK(max_naabu_probe_count IS NULL OR max_naabu_probe_count >= 1),
 high_cost_ceiling INTEGER CHECK(high_cost_ceiling IS NULL OR high_cost_ceiling >= 1),
 update_destinations_json TEXT NOT NULL DEFAULT '',
 revision INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 state_changed_at TEXT NOT NULL DEFAULT '',
 state_changed_by TEXT NOT NULL DEFAULT '',
 purge_phase TEXT NOT NULL DEFAULT '',
 purge_rows INTEGER NOT NULL DEFAULT 0
);`,
		"CREATE UNIQUE INDEX IF NOT EXISTS tenants_name_live ON tenants(name) WHERE state <> 'deleted'",
		"CREATE UNIQUE INDEX IF NOT EXISTS tenants_slug_live ON tenants(slug) WHERE state <> 'deleted'",
		"CREATE UNIQUE INDEX IF NOT EXISTS tenants_one_default ON tenants(is_default) WHERE is_default = 1",
		`INSERT INTO tenants(id,name,slug,state,is_default,update_destinations_json,revision,created_at,updated_at)
SELECT ` + defaultTenant + `,'Default','default','active',1,'',1,strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE id=` + defaultTenant + `)`,
		`CREATE TABLE IF NOT EXISTS scans (
 id TEXT PRIMARY KEY, job TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL,
 status TEXT NOT NULL, error TEXT NOT NULL DEFAULT '', nmap_version TEXT NOT NULL DEFAULT '',
 config_hash TEXT NOT NULL, snapshot_json BLOB NOT NULL,
 job_id TEXT, job_revision INTEGER,
 baseline_scan_id TEXT NOT NULL DEFAULT '', baseline_config_hash TEXT NOT NULL DEFAULT '',
 changes_json BLOB NOT NULL DEFAULT '[]', cycle_id TEXT NOT NULL DEFAULT '',
 cycle_attempt INTEGER NOT NULL DEFAULT 0, cycle_status TEXT NOT NULL DEFAULT '',
 resumable INTEGER NOT NULL DEFAULT 0, completed_probes INTEGER NOT NULL DEFAULT 0,
 total_probes INTEGER NOT NULL DEFAULT 0, completed_units INTEGER NOT NULL DEFAULT 0,
 total_units INTEGER NOT NULL DEFAULT 0, no_progress_attempts INTEGER NOT NULL DEFAULT 0,
 scanner_engine TEXT NOT NULL DEFAULT 'nmap', scanner_profile_id TEXT NOT NULL DEFAULT '',
 scanner_profile_revision INTEGER NOT NULL DEFAULT 0, naabu_version TEXT NOT NULL DEFAULT '',
 discovery_ports INTEGER NOT NULL DEFAULT 0, confirmed_ports INTEGER NOT NULL DEFAULT 0,
 discovery_duration_ms INTEGER NOT NULL DEFAULT 0, enrichment_duration_ms INTEGER NOT NULL DEFAULT 0,
 tenant_id TEXT NOT NULL DEFAULT ` + defaultTenant + `
);`,
		`CREATE TABLE IF NOT EXISTS fts_backfill_state (
 table_name TEXT PRIMARY KEY,
 last_rowid INTEGER NOT NULL DEFAULT 0,
 processed_rows INTEGER NOT NULL DEFAULT 0,
 initialized INTEGER NOT NULL DEFAULT 0,
 complete INTEGER NOT NULL DEFAULT 0,
 updated_at TEXT NOT NULL DEFAULT ''
);`,
	}
}

// latestScanHostsTableSQL is the tenant-keyed projection. It has the columns
// of the address-keyed table and a tenant_id, and stays a rowid table so that
// the copied rows keep their rowids.
const latestScanHostsTableSQL = `CREATE TABLE latest_scan_hosts (
 address TEXT NOT NULL,
 scan_id TEXT NOT NULL,
 job_id TEXT NOT NULL DEFAULT '',
 job TEXT NOT NULL DEFAULT '',
 finished_at TEXT NOT NULL,
 data_quality TEXT NOT NULL DEFAULT 'detailed',
 address_family TEXT NOT NULL DEFAULT '',
 source_targets_json BLOB NOT NULL DEFAULT '[]',
 dns_names_json BLOB NOT NULL DEFAULT '[]',
 host_json BLOB NOT NULL,
 open_ports INTEGER NOT NULL DEFAULT 0,
 open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 tcp_present INTEGER NOT NULL DEFAULT 0,
 udp_present INTEGER NOT NULL DEFAULT 0,
 tcp_open_ports INTEGER NOT NULL DEFAULT 0,
 tcp_open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 udp_open_ports INTEGER NOT NULL DEFAULT 0,
 udp_open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 search_text TEXT NOT NULL DEFAULT '',
 tenant_id TEXT NOT NULL,
 PRIMARY KEY(tenant_id, address)
)`

// latestScanHostsIndexSQL are the indexes of the tenant-keyed projection.
// The filter indexes lead with tenant_id, as each host list reads one
// tenant. The scan_id index serves the legacy backfill, which marks the rows
// of one scan.
var latestScanHostsIndexSQL = []string{
	"CREATE INDEX latest_scan_hosts_open ON latest_scan_hosts(tenant_id, open_ports, open_filtered_ports)",
	"CREATE INDEX latest_scan_hosts_protocol_open ON latest_scan_hosts(tenant_id, tcp_present, udp_present, tcp_open_ports, udp_open_ports)",
	"CREATE INDEX latest_scan_hosts_scan ON latest_scan_hosts(scan_id)",
}

// migration54ConditionalStatements swaps the projection tables while
// latest_scan_hosts is still keyed by address. Once it is keyed by tenant
// the swap has happened, so a repeated run of schema 54 changes nothing.
//
// The swap drops the search triggers, which would otherwise follow the
// renamed table, renames the table to latestScanHostsPreTenantTable, and
// drops its indexes, whose names the new table takes over. It then creates
// the tenant-keyed table, the triggers that refuse other writes during the
// copy, and the checkpoint row, which starts the copy at the first rowid.
//
// A recovery database without the projection gets the tenant-keyed table
// directly. Search rows left from its lost rows could collide with the
// rowids of new rows, so the search checkpoint is reset and the host search
// phase rebuilds the search projections.
func migration54ConditionalStatements(tx *sql.Tx) ([]string, error) {
	checkpoint := `INSERT INTO fts_backfill_state(table_name,last_rowid,processed_rows,initialized,complete,updated_at)
VALUES('` + latestScanHostsTenantRekeyState + `',0,0,1,0,strftime('%Y-%m-%dT%H:%M:%fZ','now'))
ON CONFLICT(table_name) DO UPDATE SET last_rowid=0,processed_rows=0,initialized=1,complete=0,updated_at=excluded.updated_at`
	var tables int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='latest_scan_hosts'`).Scan(&tables); err != nil {
		return nil, err
	}
	if tables == 0 {
		return slices.Concat([]string{latestScanHostsTableSQL}, latestScanHostsIndexSQL, []string{
			`UPDATE fts_backfill_state SET last_rowid=0,processed_rows=0,initialized=0,complete=0,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE table_name='latest_scan_hosts'`,
			checkpoint,
		}), nil
	}
	keyed, err := migrationColumnExists(tx, "latest_scan_hosts", "tenant_id")
	if err != nil || keyed {
		return nil, err
	}
	return slices.Concat([]string{
		"DROP TRIGGER IF EXISTS latest_scan_hosts_search_ai",
		"DROP TRIGGER IF EXISTS latest_scan_hosts_search_au",
		"DROP TRIGGER IF EXISTS latest_scan_hosts_search_ad",
		"ALTER TABLE latest_scan_hosts RENAME TO " + latestScanHostsPreTenantTable,
		"DROP INDEX IF EXISTS latest_scan_hosts_open",
		"DROP INDEX IF EXISTS latest_scan_hosts_protocol_open",
		latestScanHostsTableSQL,
	}, latestScanHostsIndexSQL, latestScanHostsRekeyGuardSQL, []string{checkpoint}), nil
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
// as after an upgrade from before schema 25, the search triggers are left to
// the host search phase, which installs them with the projection and
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
