package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func getScanTx(ctx context.Context, tx *sql.Tx, id string) (model.Scan, error) {
	var v model.Scan
	var started, finished string
	var snapshot, changesJSON []byte
	var baselineScanID, baselineConfigHash string
	var jobID sql.NullString
	var revision sql.NullInt64
	var resumable int
	err := tx.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,changes_json,snapshot_json FROM scans WHERE id=?`, id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &baselineScanID, &baselineConfigHash, &changesJSON, &snapshot)
	if err != nil {
		return v, err
	}
	if jobID.Valid {
		v.JobID = jobID.String
	}
	if revision.Valid {
		v.JobRevision = revision.Int64
	}
	v.Resumable = resumable != 0
	v.StartedAt, v.FinishedAt = scanTime(started), scanTime(finished)
	v.BaselineScanID, v.BaselineConfigHash = baselineScanID, baselineConfigHash
	if len(changesJSON) > 0 && string(changesJSON) != "null" {
		if err := json.Unmarshal(changesJSON, &v.Changes); err != nil {
			return v, err
		}
	}
	if err := json.Unmarshal(snapshot, &v.Snapshot); err != nil {
		return v, err
	}
	if err := loadScanMetadata(ctx, tx, id, &v); err != nil {
		return v, err
	}
	return v, nil
}

func (s *Store) ListScans(ctx context.Context, job string, limit int) ([]model.Scan, error) {
	page, err := s.ListScansPage(ctx, job, limit, 0)
	return page.Items, err
}

func (s *Store) ListScansPage(ctx context.Context, job string, limit, offset int) (Page[model.Scan], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[model.Scan]
	readDB := s.reader()
	query := `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,changes_json,snapshot_json FROM scans`
	countQuery := `SELECT COUNT(*) FROM scans`
	args := []any{}
	countArgs := []any{}
	if job != "" {
		query += ` WHERE job=?`
		args = append(args, job)
		countQuery += ` WHERE job=?`
		countArgs = append(countArgs, job)
	}
	if err := readDB.QueryRowContext(ctx, countQuery, countArgs...).Scan(&page.Total); err != nil {
		return page, err
	}
	query += ` ORDER BY finished_at DESC,id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := readDB.QueryContext(ctx, query, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var v model.Scan
		var jobID sql.NullString
		var revision sql.NullInt64
		var started, finished string
		var snapshot, changesJSON []byte
		var baselineScanID, baselineConfigHash string
		var resumable int
		if err := rows.Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &baselineScanID, &baselineConfigHash, &changesJSON, &snapshot); err != nil {
			return page, err
		}
		v.Resumable = resumable != 0
		if jobID.Valid {
			v.JobID = jobID.String
		}
		if revision.Valid {
			v.JobRevision = revision.Int64
		}
		v.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
		v.FinishedAt, _ = time.Parse(time.RFC3339Nano, finished)
		v.BaselineScanID, v.BaselineConfigHash = baselineScanID, baselineConfigHash
		if len(changesJSON) > 0 && string(changesJSON) != "null" {
			if err := json.Unmarshal(changesJSON, &v.Changes); err != nil {
				return page, err
			}
		}
		if err := json.Unmarshal(snapshot, &v.Snapshot); err != nil {
			return page, err
		}
		page.Items = append(page.Items, v)
	}
	return page, rows.Err()
}

// ListScanSummariesPage is the metadata-only counterpart to ListScansPage.
// Filtering remains name-based for compatibility with legacy CLI callers.
func (s *Store) ListScanSummariesPage(ctx context.Context, job string, limit, offset int) (Page[model.ScanSummary], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[model.ScanSummary]
	readDB := s.reader()
	query := `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash FROM scans`
	countQuery := `SELECT COUNT(*) FROM scans`
	args := []any{}
	countArgs := []any{}
	if job != "" {
		query += ` WHERE job=?`
		args = append(args, job)
		countQuery += ` WHERE job=?`
		countArgs = append(countArgs, job)
	}
	if err := readDB.QueryRowContext(ctx, countQuery, countArgs...).Scan(&page.Total); err != nil {
		return page, err
	}
	query += ` ORDER BY finished_at DESC,id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := readDB.QueryContext(ctx, query, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var v model.ScanSummary
		var jobID sql.NullString
		var revision sql.NullInt64
		var started, finished string
		var resumable int
		if err := rows.Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &v.BaselineScanID, &v.BaselineConfigHash); err != nil {
			return page, err
		}
		v.Resumable = resumable != 0
		if jobID.Valid {
			v.JobID = jobID.String
		}
		if revision.Valid {
			v.JobRevision = revision.Int64
		}
		v.StartedAt, v.FinishedAt = scanTime(started), scanTime(finished)
		page.Items = append(page.Items, v)
	}
	return page, rows.Err()
}

func (s *Store) ListEvents(ctx context.Context, job string, limit int) ([]model.Event, error) {
	page, err := s.ListEventsPage(ctx, job, limit, 0)
	return page.Items, err
}

func (s *Store) ListEventsPage(ctx context.Context, job string, limit, offset int) (Page[model.Event], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[model.Event]
	readDB := s.reader()
	query := `SELECT payload_json FROM events`
	countQuery := `SELECT COUNT(*) FROM events`
	args := []any{}
	countArgs := []any{}
	if job != "" {
		query += ` WHERE job=?`
		args = append(args, job)
		countQuery += ` WHERE job=?`
		countArgs = append(countArgs, job)
	}
	if err := readDB.QueryRowContext(ctx, countQuery, countArgs...).Scan(&page.Total); err != nil {
		return page, err
	}
	query += ` ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := readDB.QueryContext(ctx, query, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return page, err
		}
		var event model.Event
		if err := json.Unmarshal(raw, &event); err != nil {
			return page, err
		}
		page.Items = append(page.Items, event)
	}
	return page, rows.Err()
}

// ListJobEvents returns only events written by the immutable managed job ID.
// Name-based ListEvents is retained for legacy CLI history compatibility.
func (s *Store) ListJobEvents(ctx context.Context, jobID string, limit int) ([]model.Event, error) {
	page, err := s.ListJobEventsPage(ctx, jobID, limit, 0)
	return page.Items, err
}

func (s *Store) ListJobEventsPage(ctx context.Context, jobID string, limit, offset int) (Page[model.Event], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[model.Event]
	readDB := s.reader()
	if err := readDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE job_id=?`, jobID).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := readDB.QueryContext(ctx, `SELECT payload_json FROM events WHERE job_id=? ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, jobID, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return page, err
		}
		var event model.Event
		if err := json.Unmarshal(raw, &event); err != nil {
			return page, err
		}
		page.Items = append(page.Items, event)
	}
	return page, rows.Err()
}

func (s *Store) FailedDeliveries(ctx context.Context) (int, error) {
	var count int
	err := s.reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL AND attempts >= ?`, deliveryMaxAttempts).Scan(&count)
	return count, err
}

func (s *Store) State(ctx context.Context, job string) (model.JobState, error) {
	var b []byte
	err := s.reader().QueryRowContext(ctx, `SELECT state_json FROM job_states WHERE job=?`, job).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return emptyState(), nil
	}
	if err != nil {
		return model.JobState{}, err
	}
	var state model.JobState
	if err := json.Unmarshal(b, &state); err != nil {
		return state, err
	}
	ensureMaps(&state)
	return state, nil
}

// JobIncident is the bounded API representation of one active incident. The
// incident itself remains in the runtime JSON for atomic state transitions,
// while list methods below use SQLite's json_each to page without decoding the
// complete incident map into Go memory.
type JobIncident struct {
	JobID    string
	Job      string
	Incident model.Incident
}

func (s *Store) ListJobIncidentsPage(ctx context.Context, jobID string, limit, offset int) (Page[model.Incident], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[model.Incident]
	readDB := s.reader()
	if err := readDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_runtime, json_each(job_runtime.state_json, '$.incidents') WHERE job_runtime.job_id=?`, jobID).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := readDB.QueryContext(ctx, `SELECT json_each.value FROM job_runtime, json_each(job_runtime.state_json, '$.incidents') WHERE job_runtime.job_id=? ORDER BY json_each.key LIMIT ? OFFSET ?`, jobID, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return page, err
		}
		var incident model.Incident
		if err := json.Unmarshal(raw, &incident); err != nil {
			return page, err
		}
		page.Items = append(page.Items, incident)
	}
	return page, rows.Err()
}

func (s *Store) ListIncidentsPage(ctx context.Context, limit, offset int) (Page[JobIncident], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[JobIncident]
	readDB := s.reader()
	if err := readDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_runtime JOIN jobs ON jobs.id=job_runtime.job_id, json_each(job_runtime.state_json, '$.incidents')`).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := readDB.QueryContext(ctx, `SELECT jobs.id,jobs.name,json_each.value FROM job_runtime JOIN jobs ON jobs.id=job_runtime.job_id, json_each(job_runtime.state_json, '$.incidents') ORDER BY jobs.name,json_each.key LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var item JobIncident
		var raw []byte
		if err := rows.Scan(&item.JobID, &item.Job, &raw); err != nil {
			return page, err
		}
		if err := json.Unmarshal(raw, &item.Incident); err != nil {
			return page, err
		}
		page.Items = append(page.Items, item)
	}
	return page, rows.Err()
}
