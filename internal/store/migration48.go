package store

import (
	"context"
	"database/sql"
	"time"
)

// baselineHostSearchBackfillTable is the fts_backfill_state checkpoint for
// the baseline host search projection.
const baselineHostSearchBackfillTable = "baseline_hosts"

var baselineHostSearchTriggerNames = []string{
	"baseline_hosts_search_ai",
	"baseline_hosts_search_au",
	"baseline_hosts_search_ad",
}

// baselineHostSearchSchemaSQL keys each search row by baseline_hosts.rowid,
// like scan and latest-host search. Trigger maintenance is then a direct rowid
// delete instead of a scan of every job's search rows. The job and address
// columns are unindexed copies of the source row; only content is indexed.
// The job name is not indexed because baseline search matches the current
// name at read time.
var baselineHostSearchSchemaSQL = []string{
	`CREATE VIRTUAL TABLE IF NOT EXISTS baseline_host_search USING fts5(
 job_id UNINDEXED,
 address UNINDEXED,
 content,
 tokenize='trigram'
);`,
	`CREATE TRIGGER IF NOT EXISTS baseline_hosts_search_ai AFTER INSERT ON baseline_hosts BEGIN
 INSERT INTO baseline_host_search(rowid,job_id,address,content) VALUES(NEW.rowid,NEW.job_id,NEW.address,lower(coalesce(NEW.search_text,'')));
END;`,
	`CREATE TRIGGER IF NOT EXISTS baseline_hosts_search_au AFTER UPDATE ON baseline_hosts BEGIN
 DELETE FROM baseline_host_search WHERE rowid=OLD.rowid;
 INSERT INTO baseline_host_search(rowid,job_id,address,content) VALUES(NEW.rowid,NEW.job_id,NEW.address,lower(coalesce(NEW.search_text,'')));
END;`,
	`CREATE TRIGGER IF NOT EXISTS baseline_hosts_search_ad AFTER DELETE ON baseline_hosts BEGIN
 DELETE FROM baseline_host_search WHERE rowid=OLD.rowid;
END;`,
}

// ensureBaselineHostSearchContext installs the rowid-keyed projection when a
// rebuild was requested (migration 48 resets the checkpoint) or when the table
// or a trigger is missing. The projection is dropped and recreated rather than
// cleared: an FTS5 delete is a full index write, and rows keyed by an older
// scheme cannot be matched to baseline_hosts. The bounded batches in
// backfillBaselineHostSearchBatchContext then index the existing hosts.
func ensureBaselineHostSearchContext(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Take the write lock before reading the checkpoint so an active writer is
	// handled by busy_timeout instead of a failed read-to-write upgrade.
	if _, err := tx.ExecContext(ctx, `UPDATE fts_backfill_state SET updated_at=updated_at WHERE table_name=?`, baselineHostSearchBackfillTable); err != nil {
		return err
	}
	var initialized int
	if err := tx.QueryRowContext(ctx, `SELECT initialized FROM fts_backfill_state WHERE table_name=?`, baselineHostSearchBackfillTable).Scan(&initialized); err != nil {
		return err
	}
	var objects int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE (type='table' AND name='baseline_host_search') OR (type='trigger' AND name IN (?,?,?))`,
		baselineHostSearchTriggerNames[0], baselineHostSearchTriggerNames[1], baselineHostSearchTriggerNames[2]).Scan(&objects); err != nil {
		return err
	}
	if initialized != 0 && objects == len(baselineHostSearchTriggerNames)+1 {
		return tx.Commit()
	}
	for _, name := range baselineHostSearchTriggerNames {
		if _, err := tx.ExecContext(ctx, `DROP TRIGGER IF EXISTS `+name); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS baseline_host_search`); err != nil {
		return err
	}
	for _, statement := range baselineHostSearchSchemaSQL {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE fts_backfill_state SET last_rowid=0,processed_rows=0,initialized=1,complete=0,updated_at=? WHERE table_name=?`, time.Now().UTC().Format(time.RFC3339Nano), baselineHostSearchBackfillTable); err != nil {
		return err
	}
	return tx.Commit()
}

// backfillBaselineHostSearchBatchContext indexes the next bounded rowid range
// of baseline_hosts and advances the checkpoint in the same transaction. The
// stored search_text is already the bounded document written by the baseline
// projection, so the batch is a set-based copy. Rows written after the
// triggers were installed are already indexed under their rowid and skipped.
func backfillBaselineHostSearchBatchContext(ctx context.Context, db *sql.DB) (ftsBatchProgress, error) {
	progress := ftsBatchProgress{table: baselineHostSearchBackfillTable}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return progress, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE fts_backfill_state SET updated_at=updated_at WHERE table_name=?`, baselineHostSearchBackfillTable); err != nil {
		return progress, err
	}
	var lastRowID int64
	var processedRows, complete int
	if err := tx.QueryRowContext(ctx, `SELECT last_rowid,processed_rows,complete FROM fts_backfill_state WHERE table_name=?`, baselineHostSearchBackfillTable).Scan(&lastRowID, &processedRows, &complete); err != nil {
		return progress, err
	}
	progress.lastRowID = lastRowID
	progress.processedRows = processedRows
	if complete != 0 {
		progress.complete = true
		return progress, tx.Commit()
	}
	var batchRows int
	var maxRowID sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),MAX(rowid) FROM (SELECT rowid FROM baseline_hosts WHERE rowid>? ORDER BY rowid LIMIT ?)`, lastRowID, ftsBackfillBatchSize).Scan(&batchRows, &maxRowID); err != nil {
		return progress, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if batchRows == 0 || !maxRowID.Valid {
		if _, err := tx.ExecContext(ctx, `UPDATE fts_backfill_state SET complete=1,updated_at=? WHERE table_name=?`, now, baselineHostSearchBackfillTable); err != nil {
			return progress, err
		}
		if err := tx.Commit(); err != nil {
			return progress, err
		}
		progress.complete = true
		return progress, nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO baseline_host_search(rowid,job_id,address,content)
SELECT h.rowid,h.job_id,h.address,lower(coalesce(h.search_text,'')) FROM baseline_hosts h
WHERE h.rowid>? AND h.rowid<=? AND NOT EXISTS (SELECT 1 FROM baseline_host_search hs WHERE hs.rowid=h.rowid)`, lastRowID, maxRowID.Int64); err != nil {
		return progress, err
	}
	processedRows += batchRows
	if _, err := tx.ExecContext(ctx, `UPDATE fts_backfill_state SET last_rowid=?,processed_rows=?,updated_at=? WHERE table_name=?`, maxRowID.Int64, processedRows, now, baselineHostSearchBackfillTable); err != nil {
		return progress, err
	}
	if err := tx.Commit(); err != nil {
		return progress, err
	}
	progress.batchRows = batchRows
	progress.lastRowID = maxRowID.Int64
	progress.processedRows = processedRows
	return progress, nil
}
