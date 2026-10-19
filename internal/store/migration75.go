package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/crypt0rr/edgewatch/internal/model"
)

const scanEvidenceProjectionPhase = "scan-evidence-projections"
const scanEvidenceProjectionBatchSize = 1

func migration75Statements() []string { return nil }

func migration75ConditionalStatements(ctx context.Context, tx *sql.Tx) ([]string, error) {
	columns := []struct{ name, statement string }{
		{"results_json", `ALTER TABLE scans ADD COLUMN results_json TEXT`},
		{"results_unit_count", `ALTER TABLE scans ADD COLUMN results_unit_count INTEGER`},
		{"coverage_summary_json", `ALTER TABLE scans ADD COLUMN coverage_summary_json TEXT`},
	}
	var statements []string
	for _, column := range columns {
		exists, err := migrationColumnExists(ctx, tx, "scans", column.name)
		if err != nil {
			return nil, err
		}
		if !exists {
			statements = append(statements, column.statement)
		}
	}
	return statements, nil
}

type scanEvidenceProjectionRow struct {
	id       string
	snapshot []byte
}

func backfillScanEvidenceProjections(ctx context.Context, db *sql.DB, progress func(int64)) error {
	var processed int64
	for {
		tx, err := beginWriteTx(ctx, db)
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT id,snapshot_json FROM scans
			WHERE results_json IS NULL OR results_unit_count IS NULL OR coverage_summary_json IS NULL
			ORDER BY id LIMIT ?`, scanEvidenceProjectionBatchSize)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		batch := make([]scanEvidenceProjectionRow, 0, scanEvidenceProjectionBatchSize)
		for rows.Next() {
			var item scanEvidenceProjectionRow
			if err := rows.Scan(&item.id, &item.snapshot); err != nil {
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
		if len(batch) == 0 {
			if err := tx.Commit(); err != nil {
				return err
			}
			return nil
		}
		for _, item := range batch {
			var snapshot model.Snapshot
			if err := json.Unmarshal(item.snapshot, &snapshot); err != nil {
				// Corrupt legacy evidence remains corrupt in immutable history.
				// An empty projection makes it unclassifiable without keeping
				// the Inbox dependent on that malformed document.
				snapshot = model.Snapshot{}
			}
			results, coverage, err := marshalScanEvidenceProjections(snapshot)
			if err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("project scan %s evidence: %w", item.id, err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE scans SET results_json=?,results_unit_count=?,coverage_summary_json=? WHERE id=? AND (results_json IS NULL OR results_unit_count IS NULL OR coverage_summary_json IS NULL)`, results, len(snapshot.Units), coverage, item.id); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		processed += int64(len(batch))
		if progress != nil {
			progress(processed)
		}
	}
}
