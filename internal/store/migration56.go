package store

import (
	"slices"
	"strconv"
)

// Schema 56 extends the cleanup after deleted tenants (see migration55.go)
// to the free pages of a database without incremental auto-vacuum, one
// created before v0.18.31. Releases before it compacted the search indexes
// and truncated the write-ahead log after a tenant's rows were erased, but
// left such a database's free pages as they were, and those may still hold
// rows of the tenant that other writers deleted without secure_delete while
// it existed (see tenant_purge_free_pages.go).
//
// In a database whose auto-vacuum mode is not incremental and that holds a
// tombstone, the migration records the cleanup as pending at its free-pages
// phase, whether the database had no cleanup or one that a release before
// schema 56 completed; the cleanup then overwrites the free pages and
// truncates the log, and does not compact the indexes again. A cleanup that
// is still pending is left as it is: it reaches the free-pages phase in
// turn. A tenant that is being deleted and has already reached its
// checkpoint phase goes back to the free-pages phase, so its tombstone, which
// also completes a pending cleanup, comes after an overwrite. A database
// with incremental auto-vacuum is left unchanged, and so is one without a
// tombstone, apart from a tenant in its checkpoint phase. The first
// statement changes nothing when it runs again.
func migration56Statements() []string {
	const notIncremental = `(SELECT auto_vacuum FROM pragma_auto_vacuum)<>2`
	phases := legacyPurgeMaintenancePhases()
	freePages := slices.Index(phases, tenantPurgePhaseFreePages)
	checkpoint := slices.Index(phases, tenantPurgePhaseCheckpoint)
	return []string{
		`INSERT INTO fts_backfill_state(table_name,last_rowid,processed_rows,initialized,complete,updated_at)
SELECT '` + legacyPurgeMaintenanceState + `',` + strconv.Itoa(freePages) + `,` + strconv.Itoa(freePages-1) + `,0,0,strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE ` + notIncremental + ` AND EXISTS (SELECT 1 FROM tenants WHERE state='` + TenantStateDeleted + `')
ON CONFLICT(table_name) DO UPDATE SET last_rowid=excluded.last_rowid,processed_rows=excluded.processed_rows,initialized=0,complete=0,updated_at=excluded.updated_at
WHERE complete=1 AND last_rowid<` + strconv.Itoa(checkpoint),
		`UPDATE tenants SET purge_phase='` + tenantPurgePhaseFreePages + `'
WHERE state='` + TenantStateDeleting + `' AND purge_phase='` + tenantPurgePhaseCheckpoint + `' AND ` + notIncremental,
	}
}
