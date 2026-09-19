package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const timestampNormalizationBatchSize = 256

type timestampColumn struct {
	table  string
	column string
}

type timestampBatchItem struct {
	rowID int64
	raw   string
}

func readTimestampBatch(ctx context.Context, tx *sql.Tx, query string, cursor int64) ([]timestampBatchItem, error) {
	rows, err := tx.QueryContext(ctx, query, cursor, timestampNormalizationBatchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	batch := make([]timestampBatchItem, 0, timestampNormalizationBatchSize)
	for rows.Next() {
		var item timestampBatchItem
		if err := rows.Scan(&item.rowID, &item.raw); err != nil {
			return nil, err
		}
		batch = append(batch, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return batch, nil
}

// normalizePersistedTimestampsContext converts the historical variable-width
// RFC3339Nano values used by scan and resumable-cycle tables to the fixed-width
// representation used by new writes. It is deliberately resumable: a large
// retained database is processed in short transactions and the completion
// marker prevents this compatibility work from recurring on every startup.
func normalizePersistedTimestampsContext(ctx context.Context, db *sql.DB) error {
	var complete int
	if err := db.QueryRowContext(ctx, `SELECT complete FROM timestamp_normalization_state WHERE id=1`).Scan(&complete); err != nil {
		// Minimal historical fixtures may have the migration table without its
		// seed row (for example, when an older migration was applied manually).
		// Re-seed it here so startup remains resumable and idempotent.
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO timestamp_normalization_state(id,complete,updated_at) VALUES(1,0,?)`, sqliteTimestamp(time.Now())); err != nil {
			return err
		}
		complete = 0
	}
	if complete != 0 {
		return nil
	}
	columns := []timestampColumn{
		{table: "scans", column: "started_at"},
		{table: "scans", column: "finished_at"},
		{table: "scan_cycles", column: "started_at"},
		{table: "scan_cycles", column: "updated_at"},
		{table: "scan_cycles", column: "expires_at"},
		{table: "scan_cycles", column: "finished_at"},
		{table: "scan_cycle_units", column: "started_at"},
		{table: "scan_cycle_units", column: "finished_at"},
	}
	for _, target := range columns {
		// A handful of historical migration fixtures (and databases created by
		// older host-side tools) legitimately contain only a subset of the
		// runtime tables.  The normalizer must remain safe for those databases;
		// later migrations create the tables when they are part of the active
		// schema, while absent tables have nothing to normalize.
		var tablePresent int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, target.table).Scan(&tablePresent); err != nil {
			return err
		}
		if tablePresent == 0 {
			continue
		}
		var cursor int64
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			query := "SELECT rowid," + target.column + " FROM " + target.table + " WHERE rowid>? AND " + target.column + "<>'' ORDER BY rowid LIMIT ?"
			batch, err := readTimestampBatch(ctx, tx, query, cursor)
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			if len(batch) == 0 {
				if err := tx.Commit(); err != nil {
					return err
				}
				break
			}
			for _, value := range batch {
				if normalized, ok := normalizeSQLiteTimestamp(value.raw); ok && normalized != value.raw {
					if _, err := tx.ExecContext(ctx, "UPDATE "+target.table+" SET "+target.column+"=? WHERE rowid=?", normalized, value.rowID); err != nil {
						_ = tx.Rollback()
						return err
					}
				}
				if value.rowID > cursor {
					cursor = value.rowID
				}
			}
			if err := tx.Commit(); err != nil {
				return err
			}
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE timestamp_normalization_state SET complete=1,updated_at=? WHERE id=1`, sqliteTimestamp(time.Now())); err != nil {
		return err
	}
	return tx.Commit()
}
