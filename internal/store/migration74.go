package store

import (
	"context"
	"database/sql"
)

const budgetSkipAlertBackfillBatchSize = 250
const budgetSkipAlertPendingIndex = "job_runtime_meta_budget_skip_pending"

// migration74Statements adds the scalar projection used by job monitoring.
// Existing values are filled in restartable startup batches from job_runtime.
func migration74Statements() []string {
	return nil
}

// migration74ConditionalStatements also supports migration tests that lower
// user_version on a database copied from the current schema. Those fixtures
// can already contain either piece of the additive schema step.
func migration74ConditionalStatements(tx *sql.Tx) ([]string, error) {
	columnExists, err := migrationColumnExists(tx, "job_runtime_meta", "budget_skip_alert_key")
	if err != nil {
		return nil, err
	}
	var indexExists bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND name=?)`, budgetSkipAlertPendingIndex).Scan(&indexExists); err != nil {
		return nil, err
	}
	var statements []string
	if !columnExists {
		statements = append(statements, `ALTER TABLE job_runtime_meta ADD COLUMN budget_skip_alert_key TEXT`)
	}
	if !indexExists {
		statements = append(statements, `CREATE INDEX `+budgetSkipAlertPendingIndex+` ON job_runtime_meta(job_id) WHERE budget_skip_alert_key IS NULL`)
	}
	return statements, nil
}

type budgetSkipAlertProjectionRow struct {
	jobID string
	key   string
}

// backfillBudgetSkipAlertKeyProjection updates at most one bounded batch per
// writer transaction. A NULL key means the row predates this projection; an
// empty key is a completed backfill with no active skip. JSON is validated and
// only a bounded text scalar is copied, so malformed or oversized legacy state
// does not prevent startup or expand the projection.
func backfillBudgetSkipAlertKeyProjection(ctx context.Context, db *sql.DB, progress func(int64)) error {
	return backfillBudgetSkipAlertKeyProjectionWithBatchSize(ctx, db, budgetSkipAlertBackfillBatchSize, progress)
}

func backfillBudgetSkipAlertKeyProjectionWithBatchSize(ctx context.Context, db *sql.DB, batchSize int, progress func(int64)) error {
	if batchSize < 1 {
		batchSize = budgetSkipAlertBackfillBatchSize
	}
	var processed int64
	for {
		tx, err := beginWriteTx(ctx, db)
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT m.job_id,
CASE WHEN json_valid(r.state_json) THEN
 CASE WHEN json_type(r.state_json,'$.budget_skip_alert_key')='text'
   AND length(json_extract(r.state_json,'$.budget_skip_alert_key'))<=128
 THEN json_extract(r.state_json,'$.budget_skip_alert_key') ELSE '' END
ELSE '' END
FROM job_runtime_meta AS m
LEFT JOIN job_runtime AS r ON r.job_id=m.job_id
WHERE m.budget_skip_alert_key IS NULL
ORDER BY m.job_id
LIMIT ?`, batchSize)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		batch := make([]budgetSkipAlertProjectionRow, 0, batchSize)
		for rows.Next() {
			var item budgetSkipAlertProjectionRow
			if err := rows.Scan(&item.jobID, &item.key); err != nil {
				_ = rows.Close()
				_ = tx.Rollback()
				return err
			}
			batch = append(batch, item)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			_ = tx.Rollback()
			return err
		}
		if err := rows.Close(); err != nil {
			_ = tx.Rollback()
			return err
		}
		for _, item := range batch {
			if _, err := tx.ExecContext(ctx, `UPDATE job_runtime_meta SET budget_skip_alert_key=? WHERE job_id=? AND budget_skip_alert_key IS NULL`, item.key, item.jobID); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		processed += int64(len(batch))
		if progress != nil && len(batch) > 0 {
			progress(processed)
		}
		if len(batch) < batchSize {
			return nil
		}
	}
}
