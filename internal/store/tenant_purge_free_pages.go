package store

import (
	"context"
	"database/sql"
	"fmt"
)

// The overwrite of free pages, a phase of the maintenance after erased rows
// (tenantPurgePhaseFreePages, see runSearchMaintenance).
//
// SQLite keeps the pages it frees on the database's freelist, with whatever
// they held, until it reuses them, unless secure_delete was on when they
// were freed. The purge's own batches and merges run with it, but the other
// writers do not, so rows of a tenant, or their search terms, that
// retention, an FTS5 merge or an update removed while the tenant existed, or
// that a retention merge freed between two passes of the purge, can still be
// in free pages. A database
// with incremental auto-vacuum returns its free pages to the file system
// (incrementalVacuum). A database created before v0.18.31 has no
// auto-vacuum, which only a VACUUM of the whole file changes, so it keeps
// them in the file, and in raw copies of it.
//
// For such a database, the purge makes SQLite overwrite every free page
// before the tombstone. With secure_delete on, it allocates the free pages
// to a scratch table, freePagesTable, by inserting rows of zeros until the
// freelist is empty; it then deletes those rows, which with secure_delete on
// makes SQLite zero each of their pages as it frees it, and drops the table.
// The checkpoint that follows copies the zeroed pages from the write-ahead
// log into the database file. The pages in use are not changed.
//
// Each step is its own transaction that allocates or frees about
// freePagesStepPages pages at most, so the other writers keep writing
// between steps, and the scratch table
// records how far the overwrite got, so it resumes after a pass that ran out
// of its maintenance budget and after a restart: while the table has no row
// with rowid 0, the overwrite is allocating, and the step that finds the
// freelist empty inserts that row, after which the overwrite deletes the
// other rows. A page that another writer frees while the overwrite is
// allocating is allocated and overwritten too. A page freed later is not: it
// was in use when the freelist was found empty, after the tenant's rows were
// erased and its search terms compacted away, and holds no more of them than
// the pages that stay in use.

// freePagesTable is the scratch table of the overwrite of free pages. No
// migration creates it; the overwrite drops it when it has finished.
const freePagesTable = "tenant_purge_free_pages"

// freePagesStepPages bounds the free pages that one step of the overwrite
// allocates or returns, as incrementalVacuumPageLimit bounds a step of the
// incremental vacuum.
const freePagesStepPages = incrementalVacuumPageLimit

// freePagesStep is a committed step of the overwrite of free pages.
type freePagesStep string

const (
	// freePagesAllocated: a row of zeros took free pages.
	freePagesAllocated freePagesStep = "allocated"
	// freePagesTaken: the freelist was empty, and the row with rowid 0 now
	// records that.
	freePagesTaken freePagesStep = "taken"
	// freePagesReleased: a row of zeros was deleted, and SQLite zeroed its
	// pages as it freed them.
	freePagesReleased freePagesStep = "released"
	// freePagesFinished: the scratch table was dropped, or the freelist was
	// empty before the overwrite began, and the checkpoint phase recorded.
	freePagesFinished freePagesStep = "finished"
)

// overwriteFreePages runs the free-pages phase from *phase. It enters the
// phase and records it, runs the steps of the overwrite until they have
// finished, and advances *phase to the checkpoint phase, which the last step
// records. A database with incremental auto-vacuum records the checkpoint
// phase at once instead, also when it resumes in the free-pages phase,
// unless a scratch table is left from an overwrite that began before the
// database was converted, which the phase then finishes. Cancellation, a
// spent budget and database errors are returned, and leave *phase at the
// free-pages phase.
func overwriteFreePages(ctx context.Context, db *sql.DB, record recordMaintenancePhase, options tenantPurgeOptions, phase *string) error {
	var autoVacuum, scratch int
	if err := db.QueryRowContext(ctx, `SELECT (SELECT auto_vacuum FROM pragma_auto_vacuum),EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)`, freePagesTable).Scan(&autoVacuum, &scratch); err != nil {
		return fmt.Errorf("read auto-vacuum mode: %w", err)
	}
	next := tenantPurgePhaseFreePages
	if autoVacuum == 2 && scratch == 0 {
		next = tenantPurgePhaseCheckpoint
	}
	if *phase != next {
		if err := record(ctx, db, next); err != nil {
			return err
		}
		*phase = next
	}
	for *phase == tenantPurgePhaseFreePages {
		if err := ctx.Err(); err != nil {
			return err
		}
		step, err := overwriteFreePagesStep(ctx, db, record)
		if err != nil {
			return fmt.Errorf("overwrite free pages: %w", err)
		}
		if step == freePagesFinished {
			*phase = tenantPurgePhaseCheckpoint
		}
		if err := options.freePagesStepped(ctx, step); err != nil {
			return err
		}
	}
	return nil
}

// overwriteFreePagesStep runs the next step of the overwrite in one
// transaction with secure_delete on, and reports it. The transaction first
// records the free-pages phase again: that takes the write lock before the
// step reads the freelist, and fails when the tenant is no longer being
// deleted or the cleanup no longer pending.
func overwriteFreePagesStep(ctx context.Context, db *sql.DB, record recordMaintenancePhase) (freePagesStep, error) {
	var step freePagesStep
	err := withSecureDelete(ctx, db, func(conn *sql.Conn) error {
		// As in purgeTenantStep, the transaction is not bound to ctx.
		tx, err := conn.BeginTx(context.WithoutCancel(ctx), nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if err := record(ctx, tx, tenantPurgePhaseFreePages); err != nil {
			return err
		}
		var scratch int
		var free, pageSize int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?),(SELECT freelist_count FROM pragma_freelist_count),(SELECT page_size FROM pragma_page_size)`, freePagesTable).Scan(&scratch, &free, &pageSize); err != nil {
			return err
		}
		// The largest rowid is that of a row of zeros, or 0 when only the
		// row that records the empty freelist is left.
		var taken int
		var last int64
		if scratch != 0 {
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM `+freePagesTable+` WHERE rowid=0),COALESCE(MAX(rowid),0) FROM `+freePagesTable).Scan(&taken, &last); err != nil {
				return err
			}
		}
		switch {
		case taken != 0 && last > 0:
			if _, err := tx.ExecContext(ctx, `DELETE FROM `+freePagesTable+` WHERE rowid=?`, last); err != nil {
				return err
			}
			step = freePagesReleased
		case taken != 0 || (scratch == 0 && free == 0):
			if scratch != 0 {
				if _, err := tx.ExecContext(ctx, `DROP TABLE `+freePagesTable); err != nil {
					return err
				}
			}
			if err := record(ctx, tx, tenantPurgePhaseCheckpoint); err != nil {
				return err
			}
			step = freePagesFinished
		case free == 0:
			if _, err := tx.ExecContext(ctx, `INSERT INTO `+freePagesTable+`(rowid,zeros) VALUES(0,NULL)`); err != nil {
				return err
			}
			step = freePagesTaken
		default:
			if scratch == 0 {
				if _, err := tx.ExecContext(ctx, `CREATE TABLE `+freePagesTable+`(zeros BLOB)`); err != nil {
					return err
				}
			}
			// A little less than a page's worth of zeros for each free page,
			// so the row takes about as many pages as there are free, up to
			// freePagesStepPages.
			if _, err := tx.ExecContext(ctx, `INSERT INTO `+freePagesTable+`(zeros) VALUES(zeroblob(?))`, min(free, freePagesStepPages)*(pageSize-8)); err != nil {
				return err
			}
			step = freePagesAllocated
		}
		return tx.Commit()
	})
	return step, err
}
