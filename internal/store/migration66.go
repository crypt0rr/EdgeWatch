package store

import "database/sql"

// The scans table stores snapshot_json, a scan's complete result, before the
// columns that later schemas added, among them job_id, tenant_id,
// cycle_status and comparison. SQLite reads a scan's snapshot pages to reach
// any of those columns in the row, so a predicate on them costs as much as
// reading the snapshot. Schema 66 gives the history reads that test those
// columns indexes that hold them, so a count, an offset, a lookup by ID or a
// retention check reads the index and leaves the snapshot alone.
const (
	// scansJobHistoryIndex lists a job's scans newest first, with the
	// tenant and outcome of each.
	scansJobHistoryIndex = "scans_job_id_history"
	// scansTenantHistoryIndex lists a tenant's scans newest first, with the
	// job ID, outcome and job name of each.
	scansTenantHistoryIndex = "scans_tenant_history"
	// scansIdentityIndex finds a scan's tenant, job and outcome by its ID.
	scansIdentityIndex = "scans_identity"
	// scansCycleOutcomeIndex finds the scans recorded for a cycle by their
	// cycle and scan outcome.
	scansCycleOutcomeIndex = "scans_cycle_outcome"

	// legacyScanHostIndexState is the fts_backfill_state checkpoint of the
	// legacy host index backfill. It is complete once no successful scan is
	// left without host rows or a backfill checkpoint.
	legacyScanHostIndexState = "legacy_scan_host_index"
)

// migration66Statements replaces the scan history indexes that leave a
// reader to fetch tenant_id, job_id or cycle_status from the row with
// indexes that hold them, and records the legacy host index backfill as
// pending, so the next startup backfill confirms that nothing is left and
// marks it complete. The indexes replace scans_job_id_time,
// scans_tenant_id_time, scans_cycle_id and scans_job_time, whose leading
// columns they keep, so a scan write updates as many indexes as before.
// Building each index reads every scan row once.
func migration66Statements() []string {
	return []string{
		"DROP INDEX IF EXISTS scans_job_id_time",
		"DROP INDEX IF EXISTS scans_tenant_id_time",
		"DROP INDEX IF EXISTS scans_cycle_id",
		"DROP INDEX IF EXISTS scans_job_time",
		"CREATE INDEX IF NOT EXISTS " + scansJobHistoryIndex + " ON scans(job_id, finished_at DESC, id DESC, tenant_id, status)",
		"CREATE INDEX IF NOT EXISTS " + scansTenantHistoryIndex + " ON scans(tenant_id, finished_at DESC, id DESC, job_id, status, job)",
		"CREATE INDEX IF NOT EXISTS " + scansIdentityIndex + " ON scans(id, tenant_id, job_id, status, finished_at, job)",
		"CREATE INDEX IF NOT EXISTS " + scansCycleOutcomeIndex + " ON scans(cycle_id, cycle_status, status, tenant_id)",
		`INSERT INTO fts_backfill_state(table_name,last_rowid,processed_rows,initialized,complete,updated_at)
VALUES('` + legacyScanHostIndexState + `',0,0,1,0,strftime('%Y-%m-%dT%H:%M:%fZ','now'))
ON CONFLICT(table_name) DO UPDATE SET complete=0,updated_at=excluded.updated_at`,
	}
}

// migration66ConditionalStatements installs the latest-host guard triggers
// of latestScanHostsTenantTriggerSQL in place of the earlier ones, which
// read the tenant from the scan row for every host written. A database that
// is still copying its latest-host projection for schema 54 has no guard
// triggers yet; the copy installs these when it completes, because rows
// whose scan retention removed must pass it first.
func migration66ConditionalStatements(tx *sql.Tx) ([]string, error) {
	var installed int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name IN (?,?)`, latestScanHostsTenantInsertTrigger, latestScanHostsTenantUpdateTrigger).Scan(&installed); err != nil || installed == 0 {
		return nil, err
	}
	return append([]string{
		"DROP TRIGGER IF EXISTS " + latestScanHostsTenantInsertTrigger,
		"DROP TRIGGER IF EXISTS " + latestScanHostsTenantUpdateTrigger,
	}, latestScanHostsTenantTriggerSQL...), nil
}
