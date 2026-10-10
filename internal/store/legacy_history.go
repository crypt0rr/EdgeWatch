package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// LegacyScanSnapshot is the bounded metadata projection used by compatibility
// readers for successful scans that predate the scan_hosts index. Keeping the
// raw snapshot separate from model.Scan avoids decoding (and allocating) the
// unrelated change list and scan metadata for every retained history row.
type LegacyScanSnapshot struct {
	ID         string
	JobID      string
	Job        string
	FinishedAt time.Time
	Snapshot   []byte
}

// ListLegacySuccessfulScanSnapshotsPage returns the tenant's successful
// snapshots that do not have a derived host index. Rows are ordered newest
// first so callers can select the latest effective address without reading
// indexed scans. The query remains paginated, but callers may walk every page
// when correctness requires a complete legacy projection. Another tenant's
// scans are not listed, and neither count towards the total. Once the
// legacy host backfill has completed, no such scan is left and the page is
// empty without a search.
func (ts *TenantStore) ListLegacySuccessfulScanSnapshotsPage(ctx context.Context, limit, offset int) (Page[LegacyScanSnapshot], error) {
	if err := ts.ready(); err != nil {
		return Page[LegacyScanSnapshot]{}, err
	}
	limit, offset = normalizePage(limit, offset)
	var page Page[LegacyScanSnapshot]
	reader := ts.store.reader()
	if complete, err := legacyScanHostIndexComplete(ctx, reader); err != nil || complete {
		return page, err
	}
	// A completed backfill checkpoint also excludes snapshots that were
	// malformed or empty. Retrying those on every request would recreate the
	// history-wide decode cost the migration is designed to remove. The
	// page lists the scans that LegacySuccessfulScanExists finds.
	if err := reader.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans s WHERE s.tenant_id=? AND `+legacyHostBackfillCandidateSQL, ts.scope.id).Scan(&page.Total); err != nil {
		return Page[LegacyScanSnapshot]{}, err
	}
	rows, err := reader.QueryContext(ctx, `SELECT s.id,s.job_id,s.job,s.finished_at,s.snapshot_json
FROM scans s
WHERE s.tenant_id=? AND `+legacyHostBackfillCandidateSQL+`
ORDER BY s.finished_at DESC,s.id DESC LIMIT ? OFFSET ?`, ts.scope.id, limit, offset)
	if err != nil {
		return Page[LegacyScanSnapshot]{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var item LegacyScanSnapshot
		var jobID sql.NullString
		var finished string
		if err := rows.Scan(&item.ID, &jobID, &item.Job, &finished, &item.Snapshot); err != nil {
			return Page[LegacyScanSnapshot]{}, err
		}
		if jobID.Valid {
			item.JobID = jobID.String
		}
		item.FinishedAt = scanTime(finished)
		page.Items = append(page.Items, item)
	}
	if err := rows.Err(); err != nil {
		return Page[LegacyScanSnapshot]{}, err
	}
	return page, nil
}

func getScanTx(ctx context.Context, tx *sql.Tx, id string) (model.Scan, error) {
	var v model.Scan
	var started, finished string
	var snapshot, changesJSON []byte
	var baselineScanID, baselineConfigHash string
	var jobID sql.NullString
	var revision sql.NullInt64
	var resumable int
	err := tx.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,comparison,changes_json,snapshot_json FROM scans WHERE id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=scans.tenant_id AND purge.job_id=scans.job_id)`, id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &baselineScanID, &baselineConfigHash, &v.Comparison, &changesJSON, &snapshot)
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
	return v, nil
}

// ListScans returns the tenant's most recent scans with their results, of
// every job or of the job with the given name. Another tenant's job of the
// same name is never matched.
func (ts *TenantStore) ListScans(ctx context.Context, job string, limit int) ([]model.Scan, error) {
	page, err := ts.ListScansPage(ctx, job, limit, 0)
	return page.Items, err
}

// ListScansPage returns a page of the tenant's scans with their results,
// newest first, of every job or of the job with the given name. The name
// filter is tenant-qualified: another tenant's job of the same name, managed
// or from config.yaml, is never matched.
func (ts *TenantStore) ListScansPage(ctx context.Context, job string, limit, offset int) (Page[model.Scan], error) {
	if err := ts.ready(); err != nil {
		return Page[model.Scan]{}, err
	}
	queries := tenantScansPageQueries(ts.scope.id, job, scanSummaryColumnsSQL+`,s.changes_json,s.snapshot_json`, limit, offset)
	var page Page[model.Scan]
	readDB := ts.store.reader()
	if err := readDB.QueryRowContext(ctx, queries.countSQL, queries.countArg...).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := readDB.QueryContext(ctx, queries.pageSQL, queries.pageArg...)
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
		if err := rows.Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &baselineScanID, &baselineConfigHash, &v.Comparison, &changesJSON, &snapshot); err != nil {
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

// tenantScansPageQueries counts the tenant's scans, of every job or of the
// job with the given name, and selects the columns of one page of them,
// newest first. The columns are qualified with the alias s. The tenant, the
// job name and the purge check read scans_tenant_history, which holds the job
// ID and name after its order columns, so the count and the rows that the
// offset skips leave the scan rows, and their snapshots, alone.
func tenantScansPageQueries(tenantID, job, columns string, limit, offset int) scanPageQueries {
	limit, offset = normalizePage(limit, offset)
	from := ` FROM scans s WHERE s.tenant_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=s.tenant_id AND purge.job_id=s.job_id)`
	args := []any{tenantID}
	if job != "" {
		from += ` AND s.job=?`
		args = append(args, job)
	}
	return scanPageQueries{
		countSQL: `SELECT COUNT(*)` + from,
		countArg: args,
		pageSQL:  `SELECT ` + columns + from + ` ORDER BY s.finished_at DESC,s.id DESC LIMIT ? OFFSET ?`,
		pageArg:  append(append([]any(nil), args...), limit, offset),
	}
}

// ListScanSummariesPage is the metadata-only counterpart to ListScansPage.
// Filtering remains name-based for compatibility with legacy CLI callers,
// and stays within the tenant: another tenant's job of the same name is
// never matched.
func (ts *TenantStore) ListScanSummariesPage(ctx context.Context, job string, limit, offset int) (Page[model.ScanSummary], error) {
	if err := ts.ready(); err != nil {
		return Page[model.ScanSummary]{}, err
	}
	queries := tenantScansPageQueries(ts.scope.id, job, scanSummaryColumnsSQL, limit, offset)
	var page Page[model.ScanSummary]
	readDB := ts.store.reader()
	if err := readDB.QueryRowContext(ctx, queries.countSQL, queries.countArg...).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := readDB.QueryContext(ctx, queries.pageSQL, queries.pageArg...)
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
		if err := rows.Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &v.BaselineScanID, &v.BaselineConfigHash, &v.Comparison); err != nil {
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

// historyTenantSQL is the tenant predicate of the event and delivery
// history, the events and outbox tables. It takes one argument, the tenant
// ID. A history row without a tenant belongs to the platform, such as the
// platform's copy of an update alert and its deliveries, and no tenant's
// history holds it, the default tenant's included: each tenant has its own
// copy of an update alert. The platform's rows are read through
// PlatformStore.
const historyTenantSQL = `tenant_id=?`

// eventsFromSQL is the FROM clause that selects the tenant's events, in
// order from the tenant index. It takes one argument, the tenant ID.
const eventsFromSQL = `FROM events WHERE ` + historyTenantSQL + ` AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=events.tenant_id AND purge.job_id=events.job_id)`

// ListEvents returns the tenant's most recent events, of every job or of the
// job with the given name. Another tenant's job of the same name is never
// matched.
func (ts *TenantStore) ListEvents(ctx context.Context, job string, limit int) ([]model.Event, error) {
	page, err := ts.ListEventsPage(ctx, job, limit, 0)
	return page.Items, err
}

// ListEventsPage returns a page of the tenant's events, newest first, of
// every job or of the job with the given name. The name filter is
// tenant-qualified: another tenant's job of the same name, managed or from
// config.yaml, is never matched. The platform's events are not the tenant's,
// as historyTenantSQL describes.
func (ts *TenantStore) ListEventsPage(ctx context.Context, job string, limit, offset int) (Page[model.Event], error) {
	if err := ts.ready(); err != nil {
		return Page[model.Event]{}, err
	}
	limit, offset = normalizePage(limit, offset)
	var page Page[model.Event]
	readDB := ts.store.reader()
	from := eventsFromSQL
	query := `SELECT payload_json ` + from
	countQuery := `SELECT COUNT(*) ` + from
	args := []any{ts.scope.id}
	countArgs := []any{ts.scope.id}
	if job != "" {
		query += ` AND job=?`
		args = append(args, job)
		countQuery += ` AND job=?`
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

// platformHistorySQL is the predicate of the platform's event and delivery
// history: the rows without a tenant.
const platformHistorySQL = `tenant_id IS NULL`

// ListEventsPage returns a page of the platform's events, newest first: its
// copies of the update alerts and the events about their deliveries. The
// events of a tenant, the default tenant's included, are never returned.
func (ps *PlatformStore) ListEventsPage(ctx context.Context, limit, offset int) (Page[model.Event], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[model.Event]
	readDB := ps.store.reader()
	if err := readDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE `+platformHistorySQL).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := readDB.QueryContext(ctx, `SELECT payload_json FROM events WHERE `+platformHistorySQL+` ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, limit, offset)
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

// FailedDeliveries returns the number of the platform's notification
// deliveries that failed for good. A tenant's deliveries are not counted.
func (ps *PlatformStore) FailedDeliveries(ctx context.Context) (int, error) {
	var count int
	err := ps.store.reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL AND (attempts >= ? OR terminal_at <> '') AND `+platformHistorySQL, deliveryMaxAttempts).Scan(&count)
	return count, err
}

// MaxEventID returns the greatest durable event identifier currently stored,
// across every tenant and the platform. The web server uses this as the
// starting point for its in-memory SSE cursor so a process restart cannot
// immediately reuse IDs that a browser already acknowledged. It stays
// global because the live-update IDs are one sequence that every stream
// shares, whatever its tenant: a floor taken from one tenant's events could
// fall below IDs that a browser of another tenant already acknowledged. A
// missing or empty event table naturally returns zero.
func (ss *SystemStore) MaxEventID(ctx context.Context) (uint64, error) {
	var id int64
	if err := ss.store.reader().QueryRowContext(ctx, `SELECT COALESCE(MAX(id),0) FROM events`).Scan(&id); err != nil {
		return 0, err
	}
	if id < 0 {
		return 0, nil
	}
	return uint64(id), nil
}

// ListJobEvents returns only events written by the immutable managed job ID.
// Name-based ListEvents is retained for legacy CLI history compatibility. A
// job of another tenant has no events here.
func (ts *TenantStore) ListJobEvents(ctx context.Context, jobID string, limit int) ([]model.Event, error) {
	page, err := ts.ListJobEventsPage(ctx, jobID, limit, 0)
	return page.Items, err
}

// ListJobEventsPage returns a page of the events of the tenant's managed job
// with the given ID, newest first. A job of another tenant has no events
// here.
func (ts *TenantStore) ListJobEventsPage(ctx context.Context, jobID string, limit, offset int) (Page[model.Event], error) {
	if err := ts.ready(); err != nil {
		return Page[model.Event]{}, err
	}
	limit, offset = normalizePage(limit, offset)
	var page Page[model.Event]
	readDB := ts.store.reader()
	from := eventsFromSQL + ` AND job_id=?`
	if err := readDB.QueryRowContext(ctx, `SELECT COUNT(*) `+from, ts.scope.id, jobID).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := readDB.QueryContext(ctx, `SELECT payload_json `+from+` ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, ts.scope.id, jobID, limit, offset)
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

// FailedDeliveries returns the number of the tenant's notification
// deliveries that failed for good. A delivery belongs to the tenant of its
// event; the platform's deliveries are not the tenant's, as
// historyTenantSQL describes.
func (ts *TenantStore) FailedDeliveries(ctx context.Context) (int, error) {
	if err := ts.ready(); err != nil {
		return 0, err
	}
	var count int
	err := ts.store.reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL AND (attempts >= ? OR terminal_at <> '') AND `+historyTenantSQL, deliveryMaxAttempts, ts.scope.id).Scan(&count)
	return count, err
}

// State returns the stored state of the config.yaml job with the given name,
// or an empty state when it has none. job_states keeps that state by job
// name, and config.yaml jobs belong to the default tenant, so the statement
// reads it only for the default tenant: another tenant gets an empty state
// for a job of the same name.
func (ts *TenantStore) State(ctx context.Context, job string) (model.JobState, error) {
	if err := ts.ready(); err != nil {
		return model.JobState{}, err
	}
	var b []byte
	err := ts.store.reader().QueryRowContext(ctx, `SELECT s.state_json FROM job_states AS s JOIN tenants AS t ON t.id=? AND t.is_default=1 WHERE s.job=?`, ts.scope.id, job).Scan(&b)
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
// incident itself remains in the runtime JSON for atomic state transitions;
// list methods use the maintained runtime_incidents projection so paging does
// not repeatedly parse a complete baseline/candidate state.
type JobIncident struct {
	JobID    string
	Job      string
	Incident model.Incident
}

// ListJobIncidentsPage returns a page of the active incidents of the
// tenant's managed job with the given ID, ordered by key. A job of another
// tenant has no incidents here.
func (ts *TenantStore) ListJobIncidentsPage(ctx context.Context, jobID string, limit, offset int) (Page[model.Incident], error) {
	if err := ts.ready(); err != nil {
		return Page[model.Incident]{}, err
	}
	limit, offset = normalizePage(limit, offset)
	var page Page[model.Incident]
	readDB := ts.store.reader()
	const from = `FROM runtime_incidents AS i JOIN jobs AS j ON j.id=i.job_id AND j.tenant_id=? WHERE i.job_id=?`
	if err := readDB.QueryRowContext(ctx, `SELECT COUNT(*) `+from, ts.scope.id, jobID).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := readDB.QueryContext(ctx, `SELECT i.incident_json `+from+` ORDER BY i.key LIMIT ? OFFSET ?`, ts.scope.id, jobID, limit, offset)
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

// ListIncidentsPage returns a page of the active incidents of the tenant's
// managed jobs, ordered by job name and key.
func (ts *TenantStore) ListIncidentsPage(ctx context.Context, limit, offset int) (Page[JobIncident], error) {
	if err := ts.ready(); err != nil {
		return Page[JobIncident]{}, err
	}
	limit, offset = normalizePage(limit, offset)
	var page Page[JobIncident]
	readDB := ts.store.reader()
	const from = `FROM runtime_incidents JOIN jobs ON jobs.id=runtime_incidents.job_id AND jobs.tenant_id=?`
	if err := readDB.QueryRowContext(ctx, `SELECT COUNT(*) `+from, ts.scope.id).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := readDB.QueryContext(ctx, `SELECT jobs.id,jobs.name,runtime_incidents.incident_json `+from+` ORDER BY jobs.name,runtime_incidents.key LIMIT ? OFFSET ?`, ts.scope.id, limit, offset)
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
