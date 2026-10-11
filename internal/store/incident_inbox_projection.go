package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

const incidentInboxBackfillBatchSize = 250

type incidentInboxProjectionRow struct {
	jobID, key, tenantID string
	incident             model.Incident
}

func readIncidentInboxProjectionBatch(ctx context.Context, tx *sql.Tx) ([]incidentInboxProjectionRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT i.job_id,i.key,i.incident_json,j.tenant_id
		FROM runtime_incidents AS i JOIN jobs AS j ON j.id=i.job_id
		WHERE i.occurrence_token='' AND NOT EXISTS (
			SELECT 1 FROM job_history_purges AS purge WHERE purge.job_id=i.job_id AND purge.tenant_id=j.tenant_id
		)
		ORDER BY i.job_id,i.key LIMIT ?`, incidentInboxBackfillBatchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	batch := make([]incidentInboxProjectionRow, 0, incidentInboxBackfillBatchSize)
	for rows.Next() {
		var item incidentInboxProjectionRow
		var raw []byte
		if err := rows.Scan(&item.jobID, &item.key, &raw, &item.tenantID); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &item.incident); err != nil {
			return nil, fmt.Errorf("decode incident projection for job %s key %s: %w", item.jobID, item.key, err)
		}
		batch = append(batch, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return batch, nil
}

// backfillIncidentInboxProjection upgrades the replaceable active-incident
// projection in bounded, restartable transactions. runtime_incidents is a
// cache of job_runtime, so it can be rebuilt safely from its JSON source.
func backfillIncidentInboxProjection(ctx context.Context, db *sql.DB, progress func(int64)) error {
	var processed int64
	for {
		tx, err := beginWriteTx(ctx, db)
		if err != nil {
			return err
		}
		batch, err := readIncidentInboxProjectionBatch(ctx, tx)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		for _, item := range batch {
			token, err := incidentOccurrenceToken(item.tenantID, item.jobID, item.key, item.incident)
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			openedAt := ""
			if !item.incident.OpenedAt.IsZero() {
				openedAt = sqliteTimestamp(item.incident.OpenedAt)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE runtime_incidents
				SET occurrence_token=?,severity=?,kind=?,opened_at_sort=?,last_seen_at_sort=? WHERE job_id=? AND key=? AND occurrence_token=''`,
				token, item.incident.Change.Severity, item.incident.Change.Kind, openedAt, incidentTimeSort(item.incident.LastSeenAt), item.jobID, item.key); err != nil {
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
		if len(batch) < incidentInboxBackfillBatchSize {
			return nil
		}
	}
}

// refreshRuntimeIncidentProjectionTx replaces the active incident projection
// and closes durable reviews whose occurrences left the runtime state. It is
// called in the same writer transaction as job_runtime, making recovery and a
// suppression reopen distinct from review updates.
func refreshRuntimeIncidentProjectionTx(ctx context.Context, tx *sql.Tx, jobID string, state model.JobState) error {
	var tenantID string
	if err := tx.QueryRowContext(ctx, `SELECT tenant_id FROM jobs WHERE id=?`, jobID).Scan(&tenantID); err != nil {
		return err
	}
	now := sqliteTimestamp(time.Now().UTC())
	if _, err := tx.ExecContext(ctx, `UPDATE incident_reviews SET closed_at=? WHERE job_id=? AND closed_at=''`, now, jobID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM runtime_incidents WHERE job_id=?`, jobID); err != nil {
		return err
	}
	keys := make([]string, 0, len(state.Incidents))
	for key := range state.Incidents {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		incident := state.Incidents[key]
		raw, err := json.Marshal(incident)
		if err != nil {
			return err
		}
		token, err := incidentOccurrenceToken(tenantID, jobID, key, incident)
		if err != nil {
			return err
		}
		openedAt := ""
		if !incident.OpenedAt.IsZero() {
			openedAt = sqliteTimestamp(incident.OpenedAt)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO runtime_incidents(job_id,key,incident_json,occurrence_token,severity,kind,opened_at_sort,last_seen_at_sort)
			VALUES(?,?,?,?,?,?,?,?)`, jobID, key, raw, token, incident.Change.Severity, incident.Change.Kind, openedAt, incidentTimeSort(incident.LastSeenAt)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE incident_reviews SET closed_at='' WHERE job_id=? AND occurrence_token=?`, jobID, token); err != nil {
			return err
		}
	}
	return nil
}

func incidentTimeSort(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return sqliteTimestamp(value)
}
