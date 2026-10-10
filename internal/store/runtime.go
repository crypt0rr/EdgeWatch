package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// RuntimeState returns the runtime state of one of the tenant's jobs. A job
// without runtime state, an unknown job, and a job of another tenant all
// read as an empty state.
func (ts *TenantStore) RuntimeState(ctx context.Context, jobID string) (model.JobState, error) {
	if err := ts.ready(); err != nil {
		return model.JobState{}, err
	}
	raw, err := ts.runtimeStateJSON(ctx, jobID)
	if errors.Is(err, sql.ErrNoRows) {
		return emptyState(), nil
	}
	if err != nil {
		return model.JobState{}, err
	}
	var state model.JobState
	if err := json.Unmarshal(raw, &state); err != nil {
		return state, err
	}
	ensureMaps(&state)
	return state, nil
}

// runtimeStateJSON reads the stored runtime JSON of one of the tenant's
// jobs, or sql.ErrNoRows when the tenant has no such job or the job has no
// runtime row.
func (ts *TenantStore) runtimeStateJSON(ctx context.Context, jobID string) ([]byte, error) {
	var raw []byte
	err := ts.store.reader().QueryRowContext(ctx, `SELECT r.state_json FROM job_runtime r JOIN jobs j ON j.id=r.job_id AND j.tenant_id=? WHERE r.job_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id)`, ts.scope.id, jobID).Scan(&raw)
	return raw, err
}

// RuntimeBaselineInfo is the compact baseline marker used by host read
// endpoints. It is persisted separately from the full runtime state so a
// paginated request does not repeatedly parse large baseline/candidate JSON.
type RuntimeBaselineInfo struct {
	BaselineScanID     string
	BaselineConfigHash string
	BaselineModified   bool
	ProjectionVersion  int64
	BaselineEpoch      int64
}

// BaselineExpectation identifies the runtime state an operator saw before a
// baseline mutation. The set flags distinguish an expected empty source scan
// from an omitted field and let older callers keep using the wrapper methods.
type BaselineExpectation struct {
	ScanID      string
	ScanIDSet   bool
	Modified    bool
	ModifiedSet bool
}

func (e BaselineExpectation) matches(state model.JobState) bool {
	if e.ScanIDSet && e.ScanID != state.BaselineScanID {
		return false
	}
	return !e.ModifiedSet || e.Modified == state.BaselineModified
}

// RuntimeBaselineInfo reads the compact baseline metadata of one of the
// tenant's jobs. A missing metadata row is a legacy marker: fall back to the
// runtime JSON once so databases written before the metadata migration
// remain readable. Current rows always carry a metadata_version and never
// take this path. An unknown job and a job of another tenant have no
// metadata and read as zero.
func (ts *TenantStore) RuntimeBaselineInfo(ctx context.Context, jobID string) (RuntimeBaselineInfo, error) {
	if err := ts.ready(); err != nil {
		return RuntimeBaselineInfo{}, err
	}
	var info RuntimeBaselineInfo
	var metadataVersion int
	var scanID, configHash sql.NullString
	var modified, projectionVersion, baselineEpoch sql.NullInt64
	err := ts.store.reader().QueryRowContext(ctx, `SELECT m.metadata_version,m.baseline_scan_id,m.baseline_config_hash,m.baseline_modified,m.projection_version,m.baseline_epoch FROM job_runtime_meta m JOIN jobs j ON j.id=m.job_id AND j.tenant_id=? WHERE m.job_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id)`, ts.scope.id, jobID).Scan(&metadataVersion, &scanID, &configHash, &modified, &projectionVersion, &baselineEpoch)
	if err == nil && metadataVersion > 0 {
		info.BaselineScanID = scanID.String
		info.BaselineConfigHash = configHash.String
		info.BaselineModified = modified.Int64 != 0
		info.ProjectionVersion = projectionVersion.Int64
		info.BaselineEpoch = baselineEpoch.Int64
		return info, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return info, err
	}
	// Legacy rows (or a fixture that writes job_runtime directly) have no
	// compact marker. Preserve the historical missing/null marker semantics
	// while limiting the expensive decode to this compatibility path.
	raw, stateErr := ts.runtimeStateJSON(ctx, jobID)
	if errors.Is(stateErr, sql.ErrNoRows) {
		return info, nil
	}
	if stateErr != nil {
		return info, stateErr
	}
	var fields map[string]json.RawMessage
	if stateErr := json.Unmarshal(raw, &fields); stateErr != nil {
		return info, stateErr
	}
	if value := fields["baseline_scan_id"]; len(value) > 0 {
		_ = json.Unmarshal(value, &info.BaselineScanID)
	}
	if value := fields["baseline_config_hash"]; len(value) > 0 {
		_ = json.Unmarshal(value, &info.BaselineConfigHash)
	}
	marker, present := fields["baseline_modified"]
	if !present || string(marker) == "null" {
		info.BaselineModified = true
	} else {
		var boolean bool
		if json.Unmarshal(marker, &boolean) == nil {
			info.BaselineModified = boolean
		} else {
			var numeric int64
			if json.Unmarshal(marker, &numeric) == nil {
				info.BaselineModified = numeric != 0
			}
		}
	}
	return info, nil
}

// RuntimeBaselineEpoch returns the monotonic epoch used to fence resumable
// cycles of one of the tenant's jobs from a reset or accepted baseline
// mutation. Legacy rows start at zero, and so do an unknown job and a job of
// another tenant.
func (ts *TenantStore) RuntimeBaselineEpoch(ctx context.Context, jobID string) (int64, error) {
	if err := ts.ready(); err != nil {
		return 0, err
	}
	var epoch sql.NullInt64
	err := ts.store.reader().QueryRowContext(ctx, `SELECT m.baseline_epoch FROM job_runtime_meta m JOIN jobs j ON j.id=m.job_id AND j.tenant_id=? WHERE m.job_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id)`, ts.scope.id, jobID).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return epoch.Int64, nil
}

// RuntimeStateSummary is the bounded state projection used by job-list and
// job-detail responses. It deliberately avoids unmarshalling the
// baseline/candidate snapshots merely to render counters and host_count.
// Detailed state remains available through RuntimeState for mutation
// endpoints.
type RuntimeStateSummary struct {
	HasBaseline                 bool
	BaselineScanID              string
	BaselineConfigHash          string
	BaselineModified            bool
	CandidateCount              int
	CandidateAttempts           int
	IncompleteCandidateAttempts int
	IncidentCount               int
	PendingCount                int
	BaselineHostCount           int
}

// RuntimeStateSummary returns the bounded state projection of one of the
// tenant's jobs. An unknown job and a job of another tenant have no state
// and read as a zero summary. A job whose compact metadata is current never
// has its runtime JSON read, unless it has a baseline that neither indexed
// host table counts.
func (ts *TenantStore) RuntimeStateSummary(ctx context.Context, jobID string) (RuntimeStateSummary, error) {
	if err := ts.ready(); err != nil {
		return RuntimeStateSummary{}, err
	}
	var summary RuntimeStateSummary
	var metadataVersion int
	var scanID, configHash sql.NullString
	var projectionVersion sql.NullInt64
	var modified, candidateCount, candidateAttempts, incompleteCandidateAttempts, pendingCount sql.NullInt64
	var metaUpdated, runtimeUpdated string
	reader := ts.store.reader()
	err := reader.QueryRowContext(ctx, `SELECT m.metadata_version,m.projection_version,m.baseline_scan_id,m.baseline_config_hash,m.baseline_modified,m.candidate_count,m.candidate_attempts,m.incomplete_candidate_attempts,m.pending_count,m.updated_at,COALESCE(r.updated_at,'') FROM job_runtime_meta m JOIN jobs j ON j.id=m.job_id AND j.tenant_id=? LEFT JOIN job_runtime r ON r.job_id=m.job_id WHERE m.job_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id)`, ts.scope.id, jobID).
		Scan(&metadataVersion, &projectionVersion, &scanID, &configHash, &modified, &candidateCount, &candidateAttempts, &incompleteCandidateAttempts, &pendingCount, &metaUpdated, &runtimeUpdated)
	if err == nil && metadataVersion > 0 && (runtimeUpdated == "" || metaUpdated >= runtimeUpdated) {
		summary.HasBaseline = projectionVersion.Int64 > 0 || (scanID.Valid && scanID.String != "")
		summary.BaselineScanID, summary.BaselineConfigHash = scanID.String, configHash.String
		summary.BaselineModified = modified.Int64 != 0
		summary.CandidateCount = int(candidateCount.Int64)
		summary.CandidateAttempts = int(candidateAttempts.Int64)
		summary.IncompleteCandidateAttempts = int(incompleteCandidateAttempts.Int64)
		summary.PendingCount = int(pendingCount.Int64)
		if err := reader.QueryRowContext(ctx, `SELECT COUNT(*) FROM runtime_incidents i JOIN jobs j ON j.id=i.job_id AND j.tenant_id=? WHERE i.job_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id)`, ts.scope.id, jobID).Scan(&summary.IncidentCount); err != nil {
			return summary, err
		}
		return ts.completeRuntimeSummary(ctx, jobID, summary)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return summary, err
	}
	return ts.legacyRuntimeStateSummary(ctx, jobID)
}

// legacyRuntimeStateSummary derives the summary of one of the tenant's jobs
// from its runtime JSON. It is the compatibility fallback for databases
// written before migration 40 and fixtures that intentionally write only
// job_runtime; current writes always keep the scalar projection current.
// The JSON stays in SQLite: only its counters and arrays are counted.
func (ts *TenantStore) legacyRuntimeStateSummary(ctx context.Context, jobID string) (RuntimeStateSummary, error) {
	var summary RuntimeStateSummary
	var baselineType, scanID, configHash sql.NullString
	var modified, candidateCount, candidateAttempts, incompleteCandidateAttempts, pendingCount sql.NullInt64
	var incidentCount, hostArrayCount, unitAddressCount sql.NullInt64
	err := ts.store.reader().QueryRowContext(ctx, `SELECT
 json_type(r.state_json,'$.baseline'),
 json_extract(r.state_json,'$.baseline_scan_id'),
 json_extract(r.state_json,'$.baseline_config_hash'),
 COALESCE(json_extract(r.state_json,'$.baseline_modified'),0),
 COALESCE(json_extract(r.state_json,'$.candidate_count'),0),
 COALESCE(json_extract(r.state_json,'$.candidate_attempts'),0),
 COALESCE(json_extract(r.state_json,'$.incomplete_candidate_attempts'),0),
 COALESCE((SELECT COUNT(*) FROM json_each(r.state_json,'$.incidents')),0),
 COALESCE((SELECT COUNT(*) FROM json_each(r.state_json,'$.pending')),0),
 COALESCE(json_array_length(r.state_json,'$.baseline.hosts'),-1),
 COALESCE((SELECT COUNT(DISTINCT addresses.value)
   FROM json_each(r.state_json,'$.baseline.units') AS units
   JOIN json_each(units.value,'$.addresses') AS addresses),0)
		 FROM job_runtime r JOIN jobs j ON j.id=r.job_id AND j.tenant_id=? WHERE r.job_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id)`, ts.scope.id, jobID).Scan(&baselineType, &scanID, &configHash, &modified, &candidateCount, &candidateAttempts, &incompleteCandidateAttempts, &incidentCount, &pendingCount, &hostArrayCount, &unitAddressCount)
	if errors.Is(err, sql.ErrNoRows) {
		return summary, nil
	}
	if err != nil {
		return summary, err
	}
	summary.HasBaseline = baselineType.Valid && baselineType.String != "null" && baselineType.String != ""
	summary.BaselineScanID, summary.BaselineConfigHash = scanID.String, configHash.String
	summary.BaselineModified = modified.Int64 != 0
	summary.CandidateCount = int(candidateCount.Int64)
	summary.CandidateAttempts = int(candidateAttempts.Int64)
	summary.IncompleteCandidateAttempts = int(incompleteCandidateAttempts.Int64)
	summary.IncidentCount = int(incidentCount.Int64)
	summary.PendingCount = int(pendingCount.Int64)
	// A detailed baseline may be represented by an indexed source scan. The
	// count stays in SQLite and never requires decoding its JSON snapshot.
	if summary.BaselineScanID != "" {
		if summary.BaselineHostCount, err = ts.baselineScanHostCount(ctx, jobID, summary.BaselineScanID); err != nil {
			return summary, err
		}
	}
	// Accepted overlays and legacy baselines are copied to baseline_hosts when
	// available. The JSON array fallback is only for old databases that predate
	// migration 29 or contain a legacy snapshot without scan_hosts rows.
	if summary.BaselineModified {
		if countErr := ts.store.reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM baseline_hosts b JOIN jobs j ON j.id=b.job_id AND j.tenant_id=? WHERE b.job_id=?`, ts.scope.id, jobID).Scan(&summary.BaselineHostCount); countErr != nil && !errors.Is(countErr, sql.ErrNoRows) {
			return summary, countErr
		}
	}
	if summary.BaselineHostCount == 0 {
		if hostArrayCount.Valid && hostArrayCount.Int64 >= 0 {
			summary.BaselineHostCount = int(hostArrayCount.Int64)
		} else if unitAddressCount.Valid && unitAddressCount.Int64 >= 0 {
			// Legacy baselines may only contain logical units. Count distinct
			// effective addresses in SQLite rather than decoding the snapshot.
			summary.BaselineHostCount = int(unitAddressCount.Int64)
		}
	}
	return summary, nil
}

// RuntimeStateSummaries returns the job-list baseline projections of the
// tenant's jobs. One statement reads the compact metadata, the indexed
// counts, and the time the runtime row was written; it never reads the
// runtime JSON, so its cost does not grow with the size of a job's baseline
// or candidate. The JSON is read, inside SQLite and one job at a time, only
// for a job whose metadata is older than its runtime row (a database written
// before migration 40, or a fixture), and for a job with a baseline that
// neither indexed host table counts. The tenant predicate is on the jobs;
// every other count is correlated with one of those jobs or its runtime rows,
// including the host count of the job's baseline scan.
func (ts *TenantStore) RuntimeStateSummaries(ctx context.Context, includeArchived bool) (map[string]RuntimeStateSummary, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	const query = `SELECT
 j.id,
 COALESCE(m.metadata_version,0), COALESCE(m.projection_version,0),
 m.baseline_scan_id, m.baseline_config_hash, COALESCE(m.baseline_modified,0),
 COALESCE(m.candidate_count,0), COALESCE(m.candidate_attempts,0),
 COALESCE(m.incomplete_candidate_attempts,0), COALESCE(m.pending_count,0),
 COALESCE(m.updated_at,''), COALESCE(r.updated_at,''),
 CASE WHEN r.job_id IS NULL THEN 0 ELSE 1 END,
 (SELECT COUNT(*) FROM runtime_incidents i WHERE i.job_id=j.id),
 (SELECT COUNT(*) FROM baseline_hosts b WHERE b.job_id=j.id),
 (SELECT COUNT(*) FROM scan_hosts sh WHERE sh.scan_id=NULLIF(m.baseline_scan_id,''))
 FROM jobs j
 LEFT JOIN job_runtime_meta m ON m.job_id=j.id
 LEFT JOIN job_runtime r ON r.job_id=j.id
	 WHERE j.tenant_id=? AND (?=1 OR j.archived=0)
   AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id)`
	rows, err := ts.store.reader().QueryContext(ctx, query, ts.scope.id, boolInt(includeArchived))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]RuntimeStateSummary)
	var legacyJobs, hostCountJobs []string
	for rows.Next() {
		var jobID string
		var metadataVersion, projectionVersion, modified, candidateCount, candidateAttempts, incompleteAttempts, pendingCount int64
		var scanID, configHash sql.NullString
		var metaUpdated, runtimeUpdated string
		var runtimeExists int
		var incidentCount, baselineHostCount, scanHostCount int64
		if err := rows.Scan(
			&jobID, &metadataVersion, &projectionVersion, &scanID, &configHash, &modified,
			&candidateCount, &candidateAttempts, &incompleteAttempts, &pendingCount,
			&metaUpdated, &runtimeUpdated, &runtimeExists, &incidentCount, &baselineHostCount, &scanHostCount,
		); err != nil {
			return nil, err
		}
		if metadataVersion <= 0 || (runtimeUpdated != "" && metaUpdated < runtimeUpdated) {
			// Stale or missing metadata: only the runtime JSON, if there is
			// any, describes the job.
			if runtimeExists != 0 {
				legacyJobs = append(legacyJobs, jobID)
			}
			out[jobID] = RuntimeStateSummary{}
			continue
		}
		summary := RuntimeStateSummary{
			HasBaseline:                 projectionVersion > 0 || (scanID.Valid && scanID.String != ""),
			BaselineScanID:              scanID.String,
			BaselineConfigHash:          configHash.String,
			BaselineModified:            modified != 0,
			CandidateCount:              int(candidateCount),
			CandidateAttempts:           int(candidateAttempts),
			IncompleteCandidateAttempts: int(incompleteAttempts),
			IncidentCount:               int(incidentCount),
			PendingCount:                int(pendingCount),
		}
		switch {
		case baselineHostCount > 0:
			summary.BaselineHostCount = int(baselineHostCount)
		case scanHostCount > 0:
			summary.BaselineHostCount = int(scanHostCount)
		case summary.HasBaseline && runtimeExists != 0:
			hostCountJobs = append(hostCountJobs, jobID)
		}
		out[jobID] = summary
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, jobID := range legacyJobs {
		summary, err := ts.legacyRuntimeStateSummary(ctx, jobID)
		if err != nil {
			return nil, fmt.Errorf("resolve legacy runtime summary for job %s: %w", jobID, err)
		}
		out[jobID] = summary
	}
	for _, jobID := range hostCountJobs {
		count, present, err := ts.legacyRuntimeBaselineHostCount(ctx, jobID)
		if err != nil {
			return nil, err
		}
		if present {
			summary := out[jobID]
			summary.BaselineHostCount = count
			out[jobID] = summary
		}
	}
	return out, nil
}

// completeRuntimeSummary adds the baseline host count to the summary of one
// of the tenant's jobs.
func (ts *TenantStore) completeRuntimeSummary(ctx context.Context, jobID string, summary RuntimeStateSummary) (RuntimeStateSummary, error) {
	var projectedCount int
	if err := ts.store.reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM baseline_hosts b JOIN jobs j ON j.id=b.job_id AND j.tenant_id=? WHERE b.job_id=?`, ts.scope.id, jobID).Scan(&projectedCount); err != nil {
		return summary, err
	}
	if projectedCount > 0 {
		summary.BaselineHostCount = projectedCount
		return summary, nil
	}
	if summary.BaselineScanID != "" {
		var err error
		if summary.BaselineHostCount, err = ts.baselineScanHostCount(ctx, jobID, summary.BaselineScanID); err != nil {
			return summary, err
		}
		if summary.BaselineHostCount > 0 {
			return summary, nil
		}
	}
	// A job without a baseline has no host count. It may be collecting a
	// large candidate snapshot, which must not be parsed for a counter.
	if !summary.HasBaseline {
		return summary, nil
	}
	// Migration 40 can create current runtime metadata for a legacy baseline
	// before the resumable scan-host backfill has populated scan_hosts. Keep the
	// fast path bounded to this job while recovering the host count from the
	// JSON baseline instead of reporting zero until backfill catches up.
	if count, present, err := ts.legacyRuntimeBaselineHostCount(ctx, jobID); err != nil {
		return summary, err
	} else if present {
		summary.BaselineHostCount = count
	}
	return summary, nil
}

// baselineScanHostCount counts the indexed hosts of the baseline scan of one
// of the tenant's jobs; the hosts of a job of another tenant are not
// counted. The scan ID comes from the job's own runtime rows, which only the
// daemon and the tenant's baseline approval write, from a scan of the job.
// The statement is guarded by the job's tenant, as RuntimeStateSummaries is,
// rather than by scans.tenant_id, which is stored after the scan's snapshot.
func (ts *TenantStore) baselineScanHostCount(ctx context.Context, jobID, scanID string) (int, error) {
	var count int
	err := ts.store.reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_hosts h JOIN jobs j ON j.id=? AND j.tenant_id=? WHERE h.scan_id=?`, jobID, ts.scope.id, scanID).Scan(&count)
	return count, err
}

// legacyRuntimeBaselineHostCount returns the host count from the JSON runtime
// state of one of the tenant's jobs when indexed host projections have not
// been populated. It intentionally reads no scan snapshots or rows for other
// jobs. A valid baseline object with no hosts is present=true and therefore
// remains an authoritative zero rather than falling through to a stale unit
// count.
func (ts *TenantStore) legacyRuntimeBaselineHostCount(ctx context.Context, jobID string) (count int, present bool, err error) {
	var baselineType sql.NullString
	var hostArrayCount, unitAddressCount sql.NullInt64
	err = ts.store.reader().QueryRowContext(ctx, `SELECT
CASE WHEN json_valid(r.state_json) THEN json_type(r.state_json,'$.baseline') ELSE '' END,
CASE WHEN json_valid(r.state_json) AND json_type(r.state_json,'$.baseline')='object' THEN json_array_length(r.state_json,'$.baseline.hosts') END,
CASE WHEN json_valid(r.state_json) AND json_type(r.state_json,'$.baseline')='object' THEN COALESCE((SELECT COUNT(DISTINCT addresses.value)
  FROM json_each(r.state_json,'$.baseline.units') AS units
  JOIN json_each(units.value,'$.addresses') AS addresses),0) ELSE 0 END
FROM job_runtime r JOIN jobs j ON j.id=r.job_id AND j.tenant_id=? WHERE r.job_id=?`, ts.scope.id, jobID).Scan(&baselineType, &hostArrayCount, &unitAddressCount)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !baselineType.Valid || baselineType.String != "object" {
		return 0, false, nil
	}
	if hostArrayCount.Valid && hostArrayCount.Int64 >= 0 {
		return int(hostArrayCount.Int64), true, nil
	}
	if unitAddressCount.Valid && unitAddressCount.Int64 >= 0 {
		return int(unitAddressCount.Int64), true, nil
	}
	return 0, true, nil
}

// RuntimeBaselineMeta retains the small compatibility API used by callers
// that need only baseline identifiers of one of the tenant's jobs. Current
// rows are served from the compact metadata projection; legacy rows use the
// bounded fallback.
func (ts *TenantStore) RuntimeBaselineMeta(ctx context.Context, jobID string) (scanID, configHash string, err error) {
	info, err := ts.RuntimeBaselineInfo(ctx, jobID)
	if err != nil {
		return "", "", err
	}
	return info.BaselineScanID, info.BaselineConfigHash, nil
}

// RuntimeBaselineModified reports whether the current comparison baseline of
// one of the tenant's jobs has been changed independently of its immutable
// source scan. Legacy rows without the compact marker are treated
// conservatively as modified when the JSON marker is missing or null so host
// pages cannot render stale indexed evidence.
func (ts *TenantStore) RuntimeBaselineModified(ctx context.Context, jobID string) (bool, error) {
	info, err := ts.RuntimeBaselineInfo(ctx, jobID)
	if err != nil {
		return false, err
	}
	return info.BaselineModified, nil
}

// UpdateRuntime applies a runtime transition and persists its events in one
// transaction. It is the daemon's writer and reaches a job of any tenant.
func (ss *SystemStore) UpdateRuntime(ctx context.Context, jobID string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	return ss.updateRuntime(ctx, jobID, "", nil, fn)
}

// UpdateRuntimeWithOutbox applies a runtime transition and queues its events
// for the destinations in one transaction. It reaches a job of any tenant.
func (ss *SystemStore) UpdateRuntimeWithOutbox(ctx context.Context, jobID string, destinations []string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	return ss.updateRuntime(ctx, jobID, "", destinations, fn)
}

// updateRuntime is the daemon's transactional runtime mutation path. A
// non-empty securityHash must match the job's current scope, checked in the
// same transaction as the write. Scan finalization uses this path, without
// the active-scan exclusion of the operator actions, so it can commit its
// own result while its lease is held.
func (ss *SystemStore) updateRuntime(ctx context.Context, jobID, securityHash string, destinations []string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	tx, err := ss.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if securityHash != "" {
		var raw []byte
		if err := tx.QueryRowContext(ctx, `SELECT definition_json FROM jobs WHERE id=?`, jobID).Scan(&raw); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("%w: job %s", ErrNotFound, jobID)
			}
			return nil, err
		}
		job, err := unmarshalJob(raw)
		if err != nil {
			return nil, err
		}
		if job.SecurityHash() != securityHash {
			return nil, ErrJobRevisionChanged
		}
	}
	events, err := updateRuntimeTxWithOutbox(ctx, tx, jobID, destinations, fn)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

// UpdateRuntimeForScan applies a runtime transition only when the scan was
// produced for the job's current security scope. A scan can legitimately
// finish after a schedule, pause, or archive revision changes because those
// lifecycle edits do not alter the monitored scope. Conversely, a scope edit
// must never allow an in-flight result from the previous scope to seed or
// mutate the new baseline. The security-hash check and state write share one
// transaction so an edit cannot slip between validation and persistence.
func (ss *SystemStore) UpdateRuntimeForScan(ctx context.Context, jobID, securityHash string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	return ss.updateRuntime(ctx, jobID, securityHash, nil, fn)
}

// UpdateRuntimeForScanWithOutbox persists the state transition, event rows,
// and destination-specific outbox rows in one transaction. Destinations are
// captured before the transaction by the notifier and contain only opaque
// destination identifiers, never URLs.
func (ss *SystemStore) UpdateRuntimeForScanWithOutbox(ctx context.Context, jobID, securityHash string, destinations []string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	return ss.updateRuntime(ctx, jobID, securityHash, destinations, fn)
}

// migrateLegacyScopeHashTx updates only the scope marker written by the old
// raw-port-expression hash. It is called only after canonical hashes prove the
// monitored scope is unchanged, so persisted baselines and paused scan cycles
// remain valid across the representation-only upgrade.
func migrateLegacyScopeHashTx(ctx context.Context, tx *sql.Tx, jobID, legacyHash, canonicalHash string) error {
	if legacyHash == "" || canonicalHash == "" || legacyHash == canonicalHash {
		return nil
	}
	state, err := loadRuntimeTx(ctx, tx, jobID)
	if err != nil {
		return err
	}
	if state.Baseline != nil && state.BaselineConfigHash == legacyHash {
		state.BaselineConfigHash = canonicalHash
		raw, marshalErr := json.Marshal(state)
		if marshalErr != nil {
			return marshalErr
		}
		now := time.Now().UTC()
		if _, err := tx.ExecContext(ctx, `UPDATE job_runtime SET state_json=?,updated_at=? WHERE job_id=?`, raw, sqliteTimestamp(now), jobID); err != nil {
			return err
		}
		if err := upsertRuntimeBaselineMetaTx(ctx, tx, jobID, state, 0, now); err != nil {
			return err
		}
	}
	// A cycle's plan remains pinned to the same effective port set. Advancing
	// its config hash keeps interrupted work resumable without changing its
	// checkpoints or baseline epoch.
	_, err = tx.ExecContext(ctx, `UPDATE scan_cycles SET config_hash=? WHERE job_id=? AND config_hash=? AND status NOT IN ('completed','discarded','expired')`, canonicalHash, jobID, legacyHash)
	return err
}

// FinalizeManagedScan persists a managed scan and its runtime transition on the
// same SQLite transaction. The runtime state is read while the transaction's
// database connection is held, so baseline reset/approval cannot slip between
// comparison capture and the state transition. If the job's security scope
// changed while the scanner was running, the scan is retained as immutable
// history, recorded as not compared, but the runtime state is left
// untouched. It is the daemon's writer
// and reaches a job of any tenant; the scan takes the job's tenant.
//
// The job's tenant must still be active. A scan that finishes after its
// tenant was disabled, in the daemon or in a host command, is recorded as the
// pause cancelled it (see recordScanOfPausedTenantTx), fn does not run, and
// the error wraps ErrTenantNotActive. The tenant's state is read in this
// transaction, so a disable either commits first and is seen here, or
// commits after this scan.
func (ss *SystemStore) FinalizeManagedScan(ctx context.Context, scan *model.Scan, jobID, securityHash string, destinations []string, fn func(*model.JobState, *model.Scan) ([]model.Event, error)) ([]model.Event, error) {
	if fn == nil {
		return nil, errors.New("scan finalizer is required")
	}
	return ss.FinalizeManagedScanWithReminderSetting(ctx, scan, jobID, securityHash, destinations, func(state *model.JobState, current *model.Scan, _ bool) ([]model.Event, error) {
		return fn(state, current)
	})
}

// FinalizeManagedScanWithReminderSetting reads the unit's current preference
// inside the same transaction that records the scan and its notification
// outbox, so a settings change and scan completion have a definite order.
func (ss *SystemStore) FinalizeManagedScanWithReminderSetting(ctx context.Context, scan *model.Scan, jobID, securityHash string, destinations []string, fn func(*model.JobState, *model.Scan, bool) ([]model.Event, error)) ([]model.Event, error) {
	if fn == nil {
		return nil, errors.New("scan finalizer is required")
	}
	return ss.FinalizeManagedScanWithReminderSettings(ctx, scan, jobID, securityHash, destinations, func(state *model.JobState, current *model.Scan, settings IncidentReminderSettings) ([]model.Event, error) {
		return fn(state, current, settings.Enabled)
	})
}

// FinalizeManagedScanWithReminderSettings reads the unit's current reminder
// preferences inside the same transaction that records the scan and outbox.
func (ss *SystemStore) FinalizeManagedScanWithReminderSettings(ctx context.Context, scan *model.Scan, jobID, securityHash string, destinations []string, fn func(*model.JobState, *model.Scan, IncidentReminderSettings) ([]model.Event, error)) ([]model.Event, error) {
	return ss.FinalizeManagedScanWithOptions(ctx, scan, jobID, securityHash, destinations, ManagedScanFinalizationOptions{}, fn)
}

// ManagedScanFinalizationOptions separates time spent waiting for SQLite's
// single writer from the bounded work performed after the writer is acquired.
// Lease renewal and release are committed with the scan when LeaseOwner is set.
type ManagedScanFinalizationOptions struct {
	WriterWaitTimeout time.Duration
	WorkTimeout       time.Duration
	LeaseOwner        string
	LeaseUntil        time.Time
}

// FinalizeManagedScanWithOptions finalizes a managed scan using a bounded
// writer wait and an independent transaction-work budget. The wait is not
// charged against WorkTimeout, which starts only after a write lock is held.
func (ss *SystemStore) FinalizeManagedScanWithOptions(ctx context.Context, scan *model.Scan, jobID, securityHash string, destinations []string, options ManagedScanFinalizationOptions, fn func(*model.JobState, *model.Scan, IncidentReminderSettings) ([]model.Event, error)) ([]model.Event, error) {
	if scan == nil {
		return nil, errors.New("scan is required")
	}
	if jobID == "" {
		return nil, errors.New("job ID is required")
	}
	if fn == nil {
		return nil, errors.New("scan finalizer is required")
	}
	tx, workCtx, cleanup, err := ss.beginManagedScanFinalization(ctx, jobID, options)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	defer func() { _ = tx.Rollback() }()
	ctx = workCtx

	var raw []byte
	var tenantState string
	var reminderSettings IncidentReminderSettings
	if err := tx.QueryRowContext(ctx, `SELECT j.definition_json,t.state,t.incident_reminders_enabled,t.incident_reminder_cadence FROM jobs AS j JOIN tenants AS t ON t.id=j.tenant_id WHERE j.id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id)`, jobID).Scan(&raw, &tenantState, &reminderSettings.Enabled, &reminderSettings.Cadence); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: job %s", ErrNotFound, jobID)
		}
		return nil, err
	}
	if tenantState != TenantStateActive {
		if err := recordScanOfPausedTenantTx(ctx, tx, scan, tenantState); err != nil {
			return nil, err
		}
		if err := releaseManagedScanLeaseTx(ctx, tx, jobID, options.LeaseOwner); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: job %s", ErrTenantNotActive, jobID)
	}
	job, err := unmarshalJob(raw)
	if err != nil {
		return nil, err
	}
	if job.SecurityHash() != securityHash {
		// The result belongs to a superseded security scope, so it is kept
		// as history without a comparison.
		scan.Comparison = model.ScanComparisonNotCompared
		if err := saveScanExec(ctx, tx, *scan); err != nil {
			return nil, err
		}
		if err := clearCompletedScanCycleCheckpointsTx(ctx, tx, scan.CycleID); err != nil {
			return nil, err
		}
		if err := releaseManagedScanLeaseTx(ctx, tx, jobID, options.LeaseOwner); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, ErrJobRevisionChanged
	}
	if scan.CycleID != "" {
		var cycleEpoch int64
		var cycleStatus string
		cycleErr := tx.QueryRowContext(ctx, `SELECT baseline_epoch,status FROM scan_cycles WHERE id=?`, scan.CycleID).Scan(&cycleEpoch, &cycleStatus)
		if cycleErr == nil {
			var currentEpoch int64
			if err := tx.QueryRowContext(ctx, `SELECT COALESCE(baseline_epoch,0) FROM job_runtime_meta WHERE job_id=?`, jobID).Scan(&currentEpoch); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
			cycleNotResumable := cycleStatus == "discarded" || cycleStatus == "expired" || cycleEpoch != currentEpoch
			if cycleNotResumable && (scan.Status == "success" || scan.Status == "incomplete") {
				scan.Comparison = model.ScanComparisonNotCompared
				if err := saveScanExec(ctx, tx, *scan); err != nil {
					return nil, err
				}
				if err := clearCompletedScanCycleCheckpointsTx(ctx, tx, scan.CycleID); err != nil {
					return nil, err
				}
				if err := releaseManagedScanLeaseTx(ctx, tx, jobID, options.LeaseOwner); err != nil {
					return nil, err
				}
				if err := tx.Commit(); err != nil {
					return nil, err
				}
				return nil, ErrCycleNotResumable
			}
		} else if !errors.Is(cycleErr, sql.ErrNoRows) {
			return nil, cycleErr
		}
	}

	state, err := loadRuntimeTx(ctx, tx, jobID)
	if err != nil {
		return nil, err
	}
	if state.Baseline != nil && state.BaselineConfigHash != "" &&
		job.LegacySecurityHash() != "" && state.BaselineConfigHash == job.LegacySecurityHash() &&
		securityHash == job.SecurityHash() {
		state.BaselineConfigHash = securityHash
	}
	baselineModifiedBefore := state.BaselineModified
	baselineBefore, err := marshalBaselineForProjection(state.Baseline)
	if err != nil {
		return nil, err
	}
	events, err := fn(&state, scan, reminderSettings)
	if err != nil {
		return nil, err
	}
	if err := saveScanExec(ctx, tx, *scan); err != nil {
		return nil, err
	}
	if _, err := persistRuntimeTxWithOutbox(ctx, tx, jobID, state, events, destinations); err != nil {
		return nil, err
	}
	baselineAfter, err := marshalBaselineForProjection(state.Baseline)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(baselineBefore, baselineAfter) {
		if err := bumpRuntimeBaselineEpochTx(ctx, tx, jobID); err != nil {
			return nil, err
		}
	}
	if err := refreshBaselineHostProjectionTx(ctx, tx, jobID, baselineModifiedBefore, baselineBefore, state); err != nil {
		return nil, err
	}
	if scan.Status == "success" {
		// A successful result clears any silence watchdog backoff in the same
		// transaction as the scan and runtime update. This prevents a delayed
		// heartbeat from emitting a stale silence alert after recovery.
		stamp := sqliteTimestamp(scan.FinishedAt)
		if _, err := tx.ExecContext(ctx, `INSERT INTO job_silence_state(job_id,eligible_at,last_success_at,updated_at) VALUES(?,?,?,?) ON CONFLICT(job_id) DO UPDATE SET backoff_level=0,next_alert_at='',last_success_at=excluded.last_success_at,updated_at=excluded.updated_at`, jobID, stamp, stamp, stamp); err != nil {
			return nil, err
		}
	}
	if err := clearCompletedScanCycleCheckpointsTx(ctx, tx, scan.CycleID); err != nil {
		return nil, err
	}
	if err := releaseManagedScanLeaseTx(ctx, tx, jobID, options.LeaseOwner); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

// beginManagedScanFinalization reserves the single SQLite writer before
// starting the size-based transaction budget. The no-op job update is the
// write-lock acquisition point; when a lease owner is provided it also renews
// the lease before any potentially lengthy serialization work.
func (ss *SystemStore) beginManagedScanFinalization(ctx context.Context, jobID string, options ManagedScanFinalizationOptions) (*sql.Tx, context.Context, func(), error) {
	if options.WriterWaitTimeout <= 0 && options.WorkTimeout <= 0 {
		tx, err := ss.store.DB.BeginTx(ctx, nil)
		if err != nil {
			return nil, nil, nil, err
		}
		return tx, ctx, func() {}, nil
	}
	if options.WriterWaitTimeout <= 0 {
		options.WriterWaitTimeout = 5 * time.Minute
	}
	if options.WorkTimeout <= 0 {
		options.WorkTimeout = 5 * time.Minute
	}
	baseCtx := context.WithoutCancel(ctx)
	waitCtx, cancelWait := context.WithTimeout(baseCtx, options.WriterWaitTimeout)
	txLifetimeCtx, cancelTxLifetime := context.WithTimeout(baseCtx, options.WriterWaitTimeout+options.WorkTimeout+time.Second)
	var retryDelay = 25 * time.Millisecond
	for {
		conn, err := ss.store.DB.Conn(waitCtx)
		if err != nil {
			cancelWait()
			cancelTxLifetime()
			return nil, nil, nil, err
		}
		tx, err := conn.BeginTx(txLifetimeCtx, nil)
		if err != nil {
			_ = conn.Close()
			if isSQLiteWriterBusy(err) && waitCtx.Err() == nil {
				if waitErr := waitForWriterRetry(waitCtx, retryDelay); waitErr == nil {
					retryDelay = nextWriterRetryDelay(retryDelay)
					continue
				}
			}
			cancelWait()
			cancelTxLifetime()
			return nil, nil, nil, err
		}
		// Acquiring the connection does not reserve a SQLite writer in WAL
		// mode. This first write does so before the scan-size work deadline is
		// started. Retrying BUSY here lets another process finish a long write
		// even when its lock duration exceeds SQLite's per-attempt busy timeout.
		if options.LeaseOwner != "" {
			leaseUntil := options.LeaseUntil
			if !leaseUntil.After(time.Now().UTC()) {
				leaseUntil = time.Now().UTC().Add(options.WriterWaitTimeout + options.WorkTimeout + time.Minute)
			}
			var result sql.Result
			result, err = tx.ExecContext(waitCtx, `UPDATE job_leases SET expires_at=? WHERE job=? AND owner=?`, leaseUntil.UTC().Format(time.RFC3339Nano), jobID, options.LeaseOwner)
			if err == nil {
				if changed, rowsErr := result.RowsAffected(); rowsErr != nil {
					err = rowsErr
				} else if changed == 0 {
					_, err = tx.ExecContext(waitCtx, `UPDATE jobs SET id=id WHERE id=?`, jobID)
				}
			}
		} else {
			_, err = tx.ExecContext(waitCtx, `UPDATE jobs SET id=id WHERE id=?`, jobID)
		}
		if err != nil {
			_ = tx.Rollback()
			_ = conn.Close()
			if isSQLiteWriterBusy(err) && waitCtx.Err() == nil {
				if waitErr := waitForWriterRetry(waitCtx, retryDelay); waitErr == nil {
					retryDelay = nextWriterRetryDelay(retryDelay)
					continue
				}
			}
			cancelWait()
			cancelTxLifetime()
			return nil, nil, nil, err
		}
		cancelWait()
		workCtx, cancelWork := context.WithTimeout(baseCtx, options.WorkTimeout)
		cleanup := func() {
			cancelWork()
			cancelTxLifetime()
			_ = conn.Close()
		}
		return tx, workCtx, cleanup, nil
	}
}

func isSQLiteWriterBusy(err error) bool {
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	code := sqliteErr.Code() & 0xff
	return code == sqlite3.SQLITE_BUSY || code == sqlite3.SQLITE_LOCKED
}

func waitForWriterRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func nextWriterRetryDelay(delay time.Duration) time.Duration {
	delay *= 2
	if delay > 250*time.Millisecond {
		return 250 * time.Millisecond
	}
	return delay
}

func releaseManagedScanLeaseTx(ctx context.Context, tx *sql.Tx, jobID, owner string) error {
	if strings.TrimSpace(owner) == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM job_leases WHERE job=? AND owner=?`, jobID, owner)
	return err
}

// ScanCanceledByPauseMessage is the error of a scan whose result arrived
// after its business unit was paused, which records it as canceled.
const ScanCanceledByPauseMessage = "scan canceled: the business unit was paused before the result was saved"

// recordScanOfPausedTenantTx records a scan that finished after its job's
// tenant stopped being active, as a scan that the pause cancelled. It
// changes no runtime state, baseline, incident, silence state, event or
// alert. A result, successful or incomplete, becomes a canceled scan, so it
// is kept as evidence but never becomes the job's latest successful scan or
// a scan to approve as the baseline, and a resumable cycle that it completed
// is discarded, so the first run after the tenant is enabled again does not
// promote it. A scan that failed, timed out or was cancelled keeps its
// outcome, and a cycle that it paused keeps its checkpoints, as a cycle
// paused by the cancel of a running scan does. A tenant that is being
// deleted records nothing: its data is being erased, and the scans trigger
// refuses its rows. scan is updated to the outcome of the pause.
func recordScanOfPausedTenantTx(ctx context.Context, tx *sql.Tx, scan *model.Scan, tenantState string) error {
	discardCycle := false
	scan.Comparison = model.ScanComparisonNotCompared
	if scan.Status == "success" || scan.Status == "incomplete" {
		scan.Status = "canceled"
		scan.Error = ScanCanceledByPauseMessage
		if scan.CycleID != "" && scan.CycleStatus == "completed" {
			scan.CycleStatus = "discarded"
			discardCycle = true
		}
	}
	if tenantState != TenantStateDisabled {
		return nil
	}
	if discardCycle {
		stamp := sqliteTimestamp(time.Now())
		if _, err := tx.ExecContext(ctx, `UPDATE scan_cycles SET status='discarded',updated_at=?,finished_at=?,last_error='discarded because the business unit was paused' WHERE id=? AND status='completed'`, stamp, stamp, scan.CycleID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM scan_cycle_units WHERE cycle_id=? AND EXISTS (SELECT 1 FROM scan_cycles WHERE id=? AND status='discarded')`, scan.CycleID, scan.CycleID); err != nil {
			return err
		}
	}
	return saveScanExec(ctx, tx, *scan)
}

func updateRuntimeTxWithOutbox(ctx context.Context, tx *sql.Tx, jobID string, destinations []string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	events, err := updateRuntimeTx(ctx, tx, jobID, fn)
	if err != nil {
		return nil, err
	}
	if len(destinations) == 0 || len(events) == 0 {
		return events, nil
	}
	if err := queueEventsTx(ctx, tx, events, destinations); err != nil {
		return nil, err
	}
	return events, nil
}

func queueEventsTx(ctx context.Context, tx *sql.Tx, events []model.Event, destinations []string) error {
	if len(destinations) == 0 || len(events) == 0 {
		return nil
	}
	now := sqliteTimestamp(time.Now())
	// A managed destination is resolved once for each owner of the events,
	// because an alert may only go to its own tenant's destinations.
	type intent struct{ destination, owner string }
	resolved := make(map[intent]managedIntent, len(destinations))
	var discarded managedIntentDiscards
	for _, event := range events {
		if !model.EventDelivered(event.Type) {
			continue
		}
		bounded, payload, err := model.MarshalBoundedEvent(event, model.EventPayloadLimit)
		if err != nil {
			return err
		}
		event = bounded
		// A delivery belongs to the tenant of its event.
		tenantSQL, tenantArgs := eventTenantSQL(event)
		for _, destination := range destinations {
			key := destination
			if strings.HasPrefix(destination, "managed:") {
				selector := intent{destination: destination, owner: eventOwner(event)}
				resolution, known := resolved[selector]
				if !known {
					if resolution.key, resolution.discardReason, err = resolveManagedIntentTx(ctx, tx, destination, event); err != nil {
						return err
					}
					resolved[selector] = resolution
				}
				discarded.add(event, destination, resolution.discardReason, 1)
				key = resolution.key
			}
			if key == "" {
				continue
			}
			result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO outbox(destination,payload_json,next_at,tenant_id) VALUES(?,?,?,`+tenantSQL+`)`, append([]any{key, payload, now}, tenantArgs...)...)
			if err != nil {
				return err
			}
			if inserted, _ := result.RowsAffected(); inserted == 1 {
				if err := ensureDeliveryHealthTx(ctx, tx, key, time.Now().UTC()); err != nil {
					return err
				}
			}
		}
	}
	return discarded.audit(ctx, tx)
}

const (
	managedIntentRotated = "credential rotation"
	managedIntentDeleted = "the destination was deleted"
)

// resolveManagedIntentTx resolves a managed destination key that the notifier
// captured before this transaction to the key the outbox row must use. It runs
// in the transaction that inserts the row, which closes the race with a
// concurrent destination edit:
//
//   - a metadata-only edit (such as a rename) advances the revision but keeps
//     the credentials, so the intent moves to the current revision key;
//   - a credential change after the capture, or a deletion, discards the
//     intent and returns the reason so the caller can audit it; an alert is
//     never rerouted to replacement credentials;
//   - a destination paused in the meantime is skipped without an audit, as
//     alerts raised while it is paused are.
//
// An alert goes only to a destination of its event's owner: the alert of a
// job, or of a config.yaml job, to one of the job's tenant; a tenant's copy
// of an update alert to one of that tenant; and the platform's copy to a
// platform destination, which has no tenant. Any other destination is
// handled exactly as a deleted one, so the alert never reaches it.
//
// An empty key means that no row is created.
func resolveManagedIntentTx(ctx context.Context, tx *sql.Tx, destination string, event model.Event) (key, discardReason string, err error) {
	parts := strings.Split(destination, ":")
	if len(parts) != 3 || parts[0] != "managed" || parts[1] == "" {
		return "", "", nil
	}
	captured, ok := parseManagedRevision(parts[2])
	if !ok {
		return "", "", nil
	}
	var enabled int
	var revision, credentialRevision int64
	var row *sql.Row
	switch {
	case platformEvent(event):
		row = tx.QueryRowContext(ctx, `SELECT enabled,revision,credential_revision FROM managed_notifications WHERE id=? AND tenant_id IS NULL`, parts[1])
	case tenantEvent(event):
		row = tx.QueryRowContext(ctx, `SELECT enabled,revision,credential_revision FROM managed_notifications WHERE id=? AND tenant_id=?`, parts[1], event.TenantID)
	default:
		row = tx.QueryRowContext(ctx, `SELECT enabled,revision,credential_revision FROM managed_notifications WHERE id=? AND tenant_id=`+jobTenantSQL, parts[1], event.JobID)
	}
	err = row.Scan(&enabled, &revision, &credentialRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return "", managedIntentDeleted, nil
	}
	if err != nil {
		return "", "", err
	}
	if captured < credentialRevision || captured > revision {
		return "", managedIntentRotated, nil
	}
	if enabled == 0 {
		return "", "", nil
	}
	return managedNotificationKey(parts[1], revision), "", nil
}

// parseManagedRevision reports whether value is a valid managed revision.
func parseManagedRevision(value string) (int64, bool) {
	revision, err := strconv.ParseInt(value, 10, 64)
	return revision, err == nil && revision >= 1
}

// managedIntentDiscards counts discarded managed intents per event owner, as
// eventOwner names it, destination and reason, so one event transaction
// writes one bounded audit entry for each. The owner names the audit that
// records the discard.
type managedIntentDiscards map[[3]string]int

func (d *managedIntentDiscards) add(event model.Event, destination, reason string, count int) {
	if reason == "" || count == 0 {
		return
	}
	if *d == nil {
		*d = managedIntentDiscards{}
	}
	id := strings.Split(destination, ":")[1]
	(*d)[[3]string{eventOwner(event), id, reason}] += count
}

// audit records discarded intents like the pending deliveries discarded by a
// credential change. Only the stable destination ID and a count are recorded.
// The record belongs to the owner of the event: the tenant of the event's
// job, read in the same transaction, since the discard follows that tenant's
// action or scan; the tenant of a tenant's copy of an update alert; or the
// platform, for the platform's copy. The event of a config.yaml job, which
// has no job ID, keeps the default tenant.
func (d managedIntentDiscards) audit(ctx context.Context, tx *sql.Tx) error {
	if len(d) == 0 {
		return nil
	}
	keys := make([][3]string, 0, len(d))
	for key := range d {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		for part := range keys[i] {
			if keys[i][part] != keys[j][part] {
				return keys[i][part] < keys[j][part]
			}
		}
		return false
	})
	tenants := map[string]string{}
	entries := make([]AuditEntry, 0, len(keys))
	for _, key := range keys {
		entry := AuditEntry{
			Action: "notifications.pending_discarded",
			Detail: fmt.Sprintf("discarded %d new deliveries for managed notification %s after %s", d[key], key[1], key[2]),
		}
		owner := key[0]
		if tenantID, ok := strings.CutPrefix(owner, "tenant:"); ok {
			entry.TenantID = tenantID
		} else if jobID, ok := strings.CutPrefix(owner, "job:"); ok {
			tenant, known := tenants[jobID]
			if !known && jobID != "" {
				if err := tx.QueryRowContext(ctx, `SELECT tenant_id FROM jobs WHERE id=?`, jobID).Scan(&tenant); err != nil && !errors.Is(err, sql.ErrNoRows) {
					return err
				}
				tenants[jobID] = tenant
			}
			entry.TenantID = tenant
		} else {
			entry.platform = true
		}
		entries = append(entries, entry)
	}
	return insertAuditEntries(ctx, tx, entries, time.Now().UTC())
}

// updateRuntimeTx applies a runtime state transition and persists its events
// on the caller's transaction. Keeping the state read, event writes, and any
// caller-provided validation in one transaction prevents stale approvals from
// crossing a job-scope change.
func updateRuntimeTx(ctx context.Context, tx *sql.Tx, jobID string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	var purging int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM job_history_purges WHERE job_id=?)`, jobID).Scan(&purging); err != nil {
		return nil, err
	}
	if purging != 0 {
		return nil, fmt.Errorf("%w: job %s", ErrNotFound, jobID)
	}
	var raw []byte
	state := emptyState()
	err := tx.QueryRowContext(ctx, `SELECT state_json FROM job_runtime WHERE job_id=?`, jobID).Scan(&raw)
	if err == nil {
		if err = json.Unmarshal(raw, &state); err != nil {
			return nil, err
		}
		ensureMaps(&state)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	baselineModifiedBefore := state.BaselineModified
	baselineBefore, err := marshalBaselineForProjection(state.Baseline)
	if err != nil {
		return nil, err
	}
	events, err := fn(&state)
	if err != nil {
		return nil, err
	}
	events, err = persistRuntimeTx(ctx, tx, jobID, state, events)
	if err != nil {
		return nil, err
	}
	baselineAfter, err := marshalBaselineForProjection(state.Baseline)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(baselineBefore, baselineAfter) {
		if err := bumpRuntimeBaselineEpochTx(ctx, tx, jobID); err != nil {
			return nil, err
		}
	}
	if err := refreshBaselineHostProjectionTx(ctx, tx, jobID, baselineModifiedBefore, baselineBefore, state); err != nil {
		return nil, err
	}
	return events, nil
}

// marshalBaselineForProjection captures the effective baseline before a
// runtime mutation. BaselineModified can remain true for the lifetime of a
// baseline, so the marker alone is not enough to tell whether a learned
// fingerprint changed the projection. JSON encoding is deterministic for the
// model's maps and gives us a compact comparison without retaining another
// in-memory snapshot copy.
func marshalBaselineForProjection(baseline *model.Snapshot) ([]byte, error) {
	if baseline == nil {
		return nil, nil
	}
	return json.Marshal(baseline)
}

// refreshBaselineHostProjectionTx keeps the indexed baseline overlay a
// derived invariant of the committed runtime state. It refreshes when the
// effective baseline is established or changed, when it first becomes
// modified, when its contents change again (for example, another service
// fingerprint is learned), or when an older installation has the marker but
// no projection yet. Stable modified baselines are left untouched so every
// scan does not rewrite all host rows.
func refreshBaselineHostProjectionTx(ctx context.Context, tx *sql.Tx, jobID string, modifiedBefore bool, baselineBefore []byte, state model.JobState) error {
	if state.Baseline == nil {
		return nil
	}
	baselineAfter, err := marshalBaselineForProjection(state.Baseline)
	if err != nil {
		return err
	}
	baselineChanged := !bytes.Equal(baselineBefore, baselineAfter)
	if !state.BaselineModified && !baselineChanged {
		return nil
	}
	refresh := baselineChanged || !modifiedBefore
	if !refresh {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM baseline_hosts WHERE job_id=?)`, jobID).Scan(&exists); err != nil {
			return err
		}
		refresh = !exists
	}
	if !refresh {
		return nil
	}
	return replaceBaselineHostProjectionTx(ctx, tx, jobID, *state.Baseline)
}

func loadRuntimeTx(ctx context.Context, tx *sql.Tx, jobID string) (model.JobState, error) {
	var raw []byte
	state := emptyState()
	err := tx.QueryRowContext(ctx, `SELECT state_json FROM job_runtime WHERE job_id=?`, jobID).Scan(&raw)
	if err == nil {
		if err = json.Unmarshal(raw, &state); err != nil {
			return state, err
		}
		ensureMaps(&state)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return state, err
	}
	return state, nil
}

func persistRuntimeTx(ctx context.Context, tx *sql.Tx, jobID string, state model.JobState, events []model.Event) ([]model.Event, error) {
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if _, err = tx.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?) ON CONFLICT(job_id) DO UPDATE SET state_json=excluded.state_json,updated_at=excluded.updated_at`, jobID, raw, sqliteTimestamp(now)); err != nil {
		return nil, err
	}
	if err := upsertRuntimeBaselineMetaTx(ctx, tx, jobID, state, 0, now); err != nil {
		return nil, err
	}
	if err := replaceRuntimeIncidentProjectionTx(ctx, tx, jobID, state); err != nil {
		return nil, err
	}
	for i := range events {
		if events[i].JobID == "" {
			events[i].JobID = jobID
		}
		bounded, payload, err := model.MarshalBoundedEvent(events[i], model.EventPayloadLimit)
		if err != nil {
			return nil, err
		}
		events[i] = bounded
		if err = insertEventExec(ctx, tx, events[i], payload, events[i].CreatedAt); err != nil {
			return nil, err
		}
	}
	return events, nil
}

func upsertRuntimeBaselineMetaTx(ctx context.Context, tx *sql.Tx, jobID string, state model.JobState, projectionVersion int64, now time.Time) error {
	if projectionVersion == 0 && state.Baseline != nil {
		projectionVersion = 1
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,candidate_attempts,incomplete_candidate_attempts,pending_count,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(job_id) DO UPDATE SET metadata_version=excluded.metadata_version,baseline_scan_id=excluded.baseline_scan_id,baseline_config_hash=excluded.baseline_config_hash,baseline_modified=excluded.baseline_modified,projection_version=excluded.projection_version,candidate_count=excluded.candidate_count,candidate_attempts=excluded.candidate_attempts,incomplete_candidate_attempts=excluded.incomplete_candidate_attempts,pending_count=excluded.pending_count,updated_at=excluded.updated_at`, jobID, 1, state.BaselineScanID, state.BaselineConfigHash, boolInt(state.BaselineModified), projectionVersion, state.CandidateCount, state.CandidateAttempts, state.IncompleteCandidateAttempts, len(state.Pending), sqliteTimestamp(now))
	return err
}

// runtimeBaselineEpochTx reads the job's baseline epoch on the caller's
// transaction. A job without runtime metadata is at epoch zero.
func runtimeBaselineEpochTx(ctx context.Context, tx *sql.Tx, jobID string) (int64, error) {
	var epoch int64
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(baseline_epoch,0) FROM job_runtime_meta WHERE job_id=?`, jobID).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return epoch, err
}

func bumpRuntimeBaselineEpochTx(ctx context.Context, tx *sql.Tx, jobID string) error {
	result, err := tx.ExecContext(ctx, `UPDATE job_runtime_meta SET baseline_epoch=baseline_epoch+1 WHERE job_id=?`, jobID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return fmt.Errorf("baseline metadata missing for job %s", jobID)
	}
	return nil
}

// discardUnpromotedCyclesTx fences checkpointed work whenever the comparison
// baseline changes. Completed cycles that already have an immutable promoted
// scan remain history; an unpromoted completion is safe to discard because it
// belongs to the old baseline epoch.
func discardUnpromotedCyclesTx(ctx context.Context, tx *sql.Tx, jobID, reason string, now time.Time) error {
	stamp := sqliteTimestamp(now)
	if _, err := tx.ExecContext(ctx, `UPDATE scan_cycles SET status='discarded',updated_at=?,finished_at=?,last_error=? WHERE job_id=? AND status IN ('running','paused','stalled','completed') AND (status<>'completed' OR NOT EXISTS (SELECT 1 FROM scans WHERE scans.cycle_id=scan_cycles.id AND scans.cycle_status='completed' AND scans.status IN ('success','incomplete')))`, stamp, stamp, trimCycleError(reason), jobID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM scan_cycle_units WHERE cycle_id IN (SELECT id FROM scan_cycles WHERE job_id=? AND status='discarded' AND finished_at=?)`, jobID, stamp)
	return err
}

func replaceRuntimeIncidentProjectionTx(ctx context.Context, tx *sql.Tx, jobID string, state model.JobState) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM runtime_incidents WHERE job_id=?`, jobID); err != nil {
		return err
	}
	keys := make([]string, 0, len(state.Incidents))
	for key := range state.Incidents {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		raw, err := json.Marshal(state.Incidents[key])
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO runtime_incidents(job_id,key,incident_json) VALUES(?,?,?)`, jobID, key, raw); err != nil {
			return err
		}
	}
	return nil
}

func persistRuntimeTxWithOutbox(ctx context.Context, tx *sql.Tx, jobID string, state model.JobState, events []model.Event, destinations []string) ([]model.Event, error) {
	events, err := persistRuntimeTx(ctx, tx, jobID, state, events)
	if err != nil {
		return nil, err
	}
	if len(destinations) == 0 || len(events) == 0 {
		return events, nil
	}
	if err := queueEventsTx(ctx, tx, events, destinations); err != nil {
		return nil, err
	}
	return events, nil
}

// ResetRuntime clears the comparison state of one of the tenant's jobs
// without queueing notifications.
func (ts *TenantStore) ResetRuntime(ctx context.Context, jobID, name string) ([]model.Event, error) {
	return ts.ResetRuntimeWithOutbox(ctx, jobID, name, nil)
}

// ResetRuntimeWithOutbox persists the baseline reset event of one of the
// tenant's jobs and its notification intent in the same transaction.
func (ts *TenantStore) ResetRuntimeWithOutbox(ctx context.Context, jobID, name string, destinations []string) ([]model.Event, error) {
	return ts.resetRuntimeWithAudits(ctx, jobID, name, destinations, nil, BaselineExpectation{})
}

// ResetRuntimeWithOutboxAndAudit clears the comparison state of one of the
// tenant's jobs, persists any reset notification intent, and records the
// administrator action atomically.
func (ts *TenantStore) ResetRuntimeWithOutboxAndAudit(ctx context.Context, jobID, name string, destinations []string, audit AuditEntry) ([]model.Event, error) {
	return ts.resetRuntimeWithAudits(ctx, jobID, name, destinations, []AuditEntry{audit}, BaselineExpectation{})
}

// ResetRuntimeWithExpectationAndAudit is the stale-view-safe baseline reset
// entry point used by the web API. The comparison is made inside the same
// writer transaction that clears the state, so two administrators cannot both
// mutate a baseline they loaded before the other action committed.
func (ts *TenantStore) ResetRuntimeWithExpectationAndAudit(ctx context.Context, jobID, name string, destinations []string, audit AuditEntry, expected BaselineExpectation) ([]model.Event, error) {
	return ts.resetRuntimeWithAudits(ctx, jobID, name, destinations, []AuditEntry{audit}, expected)
}

// rejectActiveScanTx refuses an operator action that replaces the complete
// comparison state while the job is scanning, as incident actions are.
func rejectActiveScanTx(ctx context.Context, tx *sql.Tx, jobID string) error {
	active, err := jobActiveTx(ctx, tx, jobID, time.Now().UTC())
	if err != nil {
		return err
	}
	if active {
		return ErrJobScanActive
	}
	return nil
}

// resetRuntimeWithAudits clears the comparison state of one of the tenant's
// jobs in one transaction. The transaction first finds the job with the
// tenant predicate, so a job of another tenant is ErrNotFound, as an unknown
// job is, and nothing is written; the later statements name only that job.
// The job must not be scanning. The baseline host projection and the
// resumable cycles follow the reset before commit, while the writer
// transaction still protects the final state.
func (ts *TenantStore) resetRuntimeWithAudits(ctx context.Context, jobID, name string, destinations []string, audits []AuditEntry, expected BaselineExpectation) ([]model.Event, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := getTenantJobTx(ctx, tx, ts.scope, jobID); err != nil {
		return nil, err
	}
	if err := rejectActiveScanTx(ctx, tx, jobID); err != nil {
		return nil, err
	}
	events, err := updateRuntimeTxWithOutbox(ctx, tx, jobID, destinations, func(state *model.JobState) ([]model.Event, error) {
		if (expected.ScanIDSet || expected.ModifiedSet) && !expected.matches(*state) {
			return nil, ErrConflict
		}
		state.Baseline = nil
		state.BaselineScanID = ""
		state.BaselineConfigHash = ""
		state.BaselineModified = false
		state.Candidate = nil
		state.CandidateHash = ""
		state.CandidateCount = 0
		state.CandidateAttempts = 0
		state.IncompleteCandidateAttempts = 0
		state.Pending = map[string]model.Pending{}
		state.Incidents = map[string]model.Incident{}
		state.Suppressed = map[string]int{}
		state.SuppressedChanges = map[string]model.Change{}
		state.FingerprintCandidates = map[string]model.ValueCount{}
		state.ServiceDecisionRequired = nil
		return []model.Event{{Type: "baseline-reset", Job: name, Message: "Baseline collection reset", CreatedAt: time.Now().UTC()}}, nil
	})
	if err != nil {
		return nil, err
	}
	if err := clearBaselineHostProjectionTx(ctx, tx, jobID); err != nil {
		return nil, err
	}
	if err := discardUnpromotedCyclesTx(ctx, tx, jobID, "baseline reset", time.Now().UTC()); err != nil {
		return nil, err
	}
	if err := ts.insertAuditEntries(ctx, tx, audits, time.Now().UTC()); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

// ApproveRuntime makes a successful scan the baseline of one of the tenant's
// jobs without queueing notifications.
func (ts *TenantStore) ApproveRuntime(ctx context.Context, jobID, name string, scan model.Scan) ([]model.Event, error) {
	return ts.ApproveRuntimeWithOutbox(ctx, jobID, name, scan, nil)
}

// ApproveRuntimeWithOutbox persists a manual baseline approval of one of the
// tenant's jobs and notification intent together, while retaining the
// current-scope validation.
func (ts *TenantStore) ApproveRuntimeWithOutbox(ctx context.Context, jobID, name string, scan model.Scan, destinations []string) ([]model.Event, error) {
	return ts.approveRuntimeWithAudits(ctx, jobID, name, scan, destinations, nil, BaselineExpectation{})
}

// ApproveRuntimeWithOutboxAndAudit applies a manual baseline approval of one
// of the tenant's jobs and its notification intent/audit row in one
// transaction.
func (ts *TenantStore) ApproveRuntimeWithOutboxAndAudit(ctx context.Context, jobID, name string, scan model.Scan, destinations []string, audit AuditEntry) ([]model.Event, error) {
	return ts.approveRuntimeWithAudits(ctx, jobID, name, scan, destinations, []AuditEntry{audit}, BaselineExpectation{})
}

// ApproveRuntimeWithExpectationAndAudit applies a manual baseline approval of
// one of the tenant's jobs only if the caller's baseline marker still matches
// the committed runtime.
func (ts *TenantStore) ApproveRuntimeWithExpectationAndAudit(ctx context.Context, jobID, name string, scan model.Scan, destinations []string, audit AuditEntry, expected BaselineExpectation) ([]model.Event, error) {
	return ts.approveRuntimeWithAudits(ctx, jobID, name, scan, destinations, []AuditEntry{audit}, expected)
}

// approveRuntimeWithAudits makes a successful scan of one of the tenant's
// jobs its baseline in one transaction. The transaction first finds the job
// with the tenant predicate, so a job of another tenant is ErrNotFound, as
// an unknown job is, and nothing is written. The job must not be scanning,
// and the scan must be a successful scan of the job's current scope; a scan
// of another tenant is refused with the error of an unknown scan.
func (ts *TenantStore) approveRuntimeWithAudits(ctx context.Context, jobID, name string, scan model.Scan, destinations []string, audits []AuditEntry, expected BaselineExpectation) ([]model.Event, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	if scan.ID == "" {
		return nil, errors.New("scan ID is required")
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	record, err := getTenantJobTx(ctx, tx, ts.scope, jobID)
	if err != nil {
		return nil, err
	}
	if err := rejectActiveScanTx(ctx, tx, jobID); err != nil {
		return nil, err
	}
	// getScanTx reads a scan of any tenant, and returns sql.ErrNoRows for an
	// unknown one. Check the tenant first, so another tenant's scan gets
	// that same error instead of the scope mismatch below.
	var owned int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM scans WHERE id=? AND tenant_id=?`, scan.ID, ts.scope.id).Scan(&owned); err != nil {
		return nil, err
	}
	stored, err := getScanTx(ctx, tx, scan.ID)
	if err != nil {
		return nil, err
	}
	if stored.Status != "success" {
		return nil, fmt.Errorf("scan %s is not successful", stored.ID)
	}
	if stored.JobID != jobID || stored.ConfigHash != record.Job.SecurityHash() {
		return nil, errors.New("scan does not belong to the current job scope")
	}
	events, err := updateRuntimeTxWithOutbox(ctx, tx, jobID, destinations, func(state *model.JobState) ([]model.Event, error) {
		if (expected.ScanIDSet || expected.ModifiedSet) && !expected.matches(*state) {
			return nil, ErrConflict
		}
		state.Baseline = &stored.Snapshot
		state.BaselineScanID = stored.ID
		state.BaselineConfigHash = stored.ConfigHash
		state.BaselineModified = false
		state.Candidate = nil
		state.CandidateHash = ""
		state.CandidateCount = 0
		state.CandidateAttempts = 0
		state.IncompleteCandidateAttempts = 0
		state.Pending = map[string]model.Pending{}
		state.Incidents = map[string]model.Incident{}
		state.Suppressed = map[string]int{}
		state.SuppressedChanges = map[string]model.Change{}
		state.FingerprintCandidates = map[string]model.ValueCount{}
		state.ServiceDecisionRequired = nil
		return []model.Event{{Type: "baseline-approved", Job: name, ScanID: stored.ID, Message: "Baseline manually approved", CreatedAt: time.Now().UTC()}}, nil
	})
	if err != nil {
		return nil, err
	}
	if err := discardUnpromotedCyclesTx(ctx, tx, jobID, "baseline approved", time.Now().UTC()); err != nil {
		return nil, err
	}
	if err := ts.insertAuditEntries(ctx, tx, audits, time.Now().UTC()); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}
