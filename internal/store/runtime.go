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
)

func (s *Store) RuntimeState(ctx context.Context, jobID string) (model.JobState, error) {
	var raw []byte
	err := s.reader().QueryRowContext(ctx, `SELECT state_json FROM job_runtime WHERE job_id=?`, jobID).Scan(&raw)
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

// RuntimeBaselineInfo reads compact baseline metadata. A missing metadata row
// is a legacy marker: fall back to the runtime JSON once so databases written
// before the metadata migration remain readable. Current rows always carry a
// metadata_version and never take this path.
func (s *Store) RuntimeBaselineInfo(ctx context.Context, jobID string) (RuntimeBaselineInfo, error) {
	var info RuntimeBaselineInfo
	var metadataVersion int
	var scanID, configHash sql.NullString
	var modified, projectionVersion, baselineEpoch sql.NullInt64
	err := s.reader().QueryRowContext(ctx, `SELECT metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,baseline_epoch FROM job_runtime_meta WHERE job_id=?`, jobID).Scan(&metadataVersion, &scanID, &configHash, &modified, &projectionVersion, &baselineEpoch)
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
	var raw []byte
	stateErr := s.reader().QueryRowContext(ctx, `SELECT state_json FROM job_runtime WHERE job_id=?`, jobID).Scan(&raw)
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
// cycles from a reset or accepted baseline mutation. Legacy rows start at zero.
func (s *Store) RuntimeBaselineEpoch(ctx context.Context, jobID string) (int64, error) {
	var epoch sql.NullInt64
	err := s.reader().QueryRowContext(ctx, `SELECT baseline_epoch FROM job_runtime_meta WHERE job_id=?`, jobID).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return epoch.Int64, nil
}

// RuntimeStateSummary is the bounded state projection used by job-list
// responses. It deliberately avoids unmarshalling the baseline/candidate
// snapshots merely to render counters and host_count. Detailed state remains
// available through RuntimeState for mutation and detail endpoints.
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

func (s *Store) RuntimeStateSummary(ctx context.Context, jobID string) (RuntimeStateSummary, error) {
	var summary RuntimeStateSummary
	var metadataVersion int
	var scanID, configHash sql.NullString
	var projectionVersion sql.NullInt64
	var modified, candidateCount, candidateAttempts, incompleteCandidateAttempts, pendingCount sql.NullInt64
	var metaUpdated, runtimeUpdated string
	err := s.reader().QueryRowContext(ctx, `SELECT m.metadata_version,m.projection_version,m.baseline_scan_id,m.baseline_config_hash,m.baseline_modified,m.candidate_count,m.candidate_attempts,m.incomplete_candidate_attempts,m.pending_count,m.updated_at,COALESCE(r.updated_at,'') FROM job_runtime_meta m LEFT JOIN job_runtime r ON r.job_id=m.job_id WHERE m.job_id=?`, jobID).
		Scan(&metadataVersion, &projectionVersion, &scanID, &configHash, &modified, &candidateCount, &candidateAttempts, &incompleteCandidateAttempts, &pendingCount, &metaUpdated, &runtimeUpdated)
	if err == nil && metadataVersion > 0 && (runtimeUpdated == "" || metaUpdated >= runtimeUpdated) {
		summary.HasBaseline = projectionVersion.Int64 > 0 || (scanID.Valid && scanID.String != "")
		summary.BaselineScanID, summary.BaselineConfigHash = scanID.String, configHash.String
		summary.BaselineModified = modified.Int64 != 0
		summary.CandidateCount = int(candidateCount.Int64)
		summary.CandidateAttempts = int(candidateAttempts.Int64)
		summary.IncompleteCandidateAttempts = int(incompleteCandidateAttempts.Int64)
		summary.PendingCount = int(pendingCount.Int64)
		if err := s.reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM runtime_incidents WHERE job_id=?`, jobID).Scan(&summary.IncidentCount); err != nil {
			return summary, err
		}
		return s.completeRuntimeSummary(ctx, jobID, summary)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return summary, err
	}
	// Compatibility fallback for databases written before migration 40 and
	// fixtures that intentionally write only job_runtime. This path is bounded
	// to old rows; current writes always use the scalar projection above.
	var baselineType sql.NullString
	var incidentCount, hostArrayCount, unitAddressCount sql.NullInt64
	err = s.reader().QueryRowContext(ctx, `SELECT
 json_type(state_json,'$.baseline'),
 json_extract(state_json,'$.baseline_scan_id'),
 json_extract(state_json,'$.baseline_config_hash'),
 COALESCE(json_extract(state_json,'$.baseline_modified'),0),
 COALESCE(json_extract(state_json,'$.candidate_count'),0),
 COALESCE(json_extract(state_json,'$.candidate_attempts'),0),
 COALESCE(json_extract(state_json,'$.incomplete_candidate_attempts'),0),
 COALESCE((SELECT COUNT(*) FROM json_each(state_json,'$.incidents')),0),
 COALESCE((SELECT COUNT(*) FROM json_each(state_json,'$.pending')),0),
 COALESCE(json_array_length(state_json,'$.baseline.hosts'),-1),
 COALESCE((SELECT COUNT(DISTINCT addresses.value)
   FROM json_each(state_json,'$.baseline.units') AS units
   JOIN json_each(units.value,'$.addresses') AS addresses),0)
	 FROM job_runtime WHERE job_id=?`, jobID).Scan(&baselineType, &scanID, &configHash, &modified, &candidateCount, &candidateAttempts, &incompleteCandidateAttempts, &incidentCount, &pendingCount, &hostArrayCount, &unitAddressCount)
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
		if err := s.reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_hosts WHERE scan_id=?`, summary.BaselineScanID).Scan(&summary.BaselineHostCount); err != nil {
			return summary, err
		}
	}
	// Accepted overlays and legacy baselines are copied to baseline_hosts when
	// available. The JSON array fallback is only for old databases that predate
	// migration 29 or contain a legacy snapshot without scan_hosts rows.
	if summary.BaselineModified {
		if countErr := s.reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM baseline_hosts WHERE job_id=?`, jobID).Scan(&summary.BaselineHostCount); countErr != nil && !errors.Is(countErr, sql.ErrNoRows) {
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

// RuntimeStateSummaries returns the job-list baseline projections in one
// bounded query. The legacy JSON fallback stays inside SQLite and counts only
// each job's runtime arrays; it never loads scan snapshots or unmarshals the
// runtime JSON into Go.
func (s *Store) RuntimeStateSummaries(ctx context.Context, includeArchived bool) (map[string]RuntimeStateSummary, error) {
	const query = `SELECT
 j.id,
 COALESCE(m.metadata_version,0), COALESCE(m.projection_version,0),
 m.baseline_scan_id, m.baseline_config_hash, COALESCE(m.baseline_modified,0),
 COALESCE(m.candidate_count,0), COALESCE(m.candidate_attempts,0),
 COALESCE(m.incomplete_candidate_attempts,0), COALESCE(m.pending_count,0),
 COALESCE(m.updated_at,''), COALESCE(r.updated_at,''),
 (SELECT COUNT(*) FROM runtime_incidents i WHERE i.job_id=j.id),
 CASE WHEN r.job_id IS NOT NULL AND json_valid(r.state_json) THEN json_type(r.state_json,'$.baseline') END,
 CASE WHEN r.job_id IS NOT NULL AND json_valid(r.state_json) THEN json_extract(r.state_json,'$.baseline_scan_id') END,
 CASE WHEN r.job_id IS NOT NULL AND json_valid(r.state_json) THEN json_extract(r.state_json,'$.baseline_config_hash') END,
 CASE WHEN r.job_id IS NOT NULL AND json_valid(r.state_json) THEN COALESCE(json_extract(r.state_json,'$.baseline_modified'),0) ELSE 0 END,
 CASE WHEN r.job_id IS NOT NULL AND json_valid(r.state_json) THEN COALESCE(json_extract(r.state_json,'$.candidate_count'),0) ELSE 0 END,
 CASE WHEN r.job_id IS NOT NULL AND json_valid(r.state_json) THEN COALESCE(json_extract(r.state_json,'$.candidate_attempts'),0) ELSE 0 END,
 CASE WHEN r.job_id IS NOT NULL AND json_valid(r.state_json) THEN COALESCE(json_extract(r.state_json,'$.incomplete_candidate_attempts'),0) ELSE 0 END,
 CASE WHEN r.job_id IS NOT NULL AND json_valid(r.state_json) THEN COALESCE((SELECT COUNT(*) FROM json_each(r.state_json,'$.incidents')),0) ELSE 0 END,
 CASE WHEN r.job_id IS NOT NULL AND json_valid(r.state_json) THEN COALESCE((SELECT COUNT(*) FROM json_each(r.state_json,'$.pending')),0) ELSE 0 END,
 CASE WHEN r.job_id IS NOT NULL AND json_valid(r.state_json) AND json_type(r.state_json,'$.baseline')='object' THEN json_array_length(r.state_json,'$.baseline.hosts') END,
 CASE WHEN r.job_id IS NOT NULL AND json_valid(r.state_json) AND json_type(r.state_json,'$.baseline')='object' THEN COALESCE((
   SELECT COUNT(DISTINCT addresses.value)
   FROM json_each(r.state_json,'$.baseline.units') AS units
   JOIN json_each(units.value,'$.addresses') AS addresses
 ),0) END,
 (SELECT COUNT(*) FROM baseline_hosts b WHERE b.job_id=j.id),
 (SELECT COUNT(*) FROM scan_hosts sh WHERE sh.scan_id=NULLIF(m.baseline_scan_id,'')),
 (SELECT COUNT(*) FROM scan_hosts sh WHERE sh.scan_id=CASE WHEN r.job_id IS NOT NULL AND json_valid(r.state_json) THEN json_extract(r.state_json,'$.baseline_scan_id') END),
 CASE WHEN r.job_id IS NULL THEN 0 ELSE 1 END,
 CASE WHEN r.job_id IS NULL THEN 1 ELSE json_valid(r.state_json) END
 FROM jobs j
 LEFT JOIN job_runtime_meta m ON m.job_id=j.id
 LEFT JOIN job_runtime r ON r.job_id=j.id
 WHERE ?=1 OR j.archived=0`
	rows, err := s.reader().QueryContext(ctx, query, boolInt(includeArchived))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]RuntimeStateSummary)
	for rows.Next() {
		var jobID string
		var metadataVersion, projectionVersion, modified, candidateCount, candidateAttempts, incompleteAttempts, pendingCount int64
		var scanID, configHash, legacyBaselineType, legacyScanID, legacyConfigHash sql.NullString
		var metaUpdated, runtimeUpdated string
		var incidentCount, legacyModified, legacyCandidateCount, legacyCandidateAttempts, legacyIncompleteAttempts, legacyIncidentCount, legacyPendingCount int64
		var legacyHostArrayCount, legacyUnitAddressCount sql.NullInt64
		var baselineHostCount, metadataScanHostCount, legacyScanHostCount int64
		var runtimeExists, runtimeJSONValid int
		if err := rows.Scan(
			&jobID, &metadataVersion, &projectionVersion, &scanID, &configHash, &modified,
			&candidateCount, &candidateAttempts, &incompleteAttempts, &pendingCount,
			&metaUpdated, &runtimeUpdated, &incidentCount, &legacyBaselineType,
			&legacyScanID, &legacyConfigHash, &legacyModified, &legacyCandidateCount,
			&legacyCandidateAttempts, &legacyIncompleteAttempts, &legacyIncidentCount,
			&legacyPendingCount, &legacyHostArrayCount, &legacyUnitAddressCount,
			&baselineHostCount, &metadataScanHostCount, &legacyScanHostCount, &runtimeExists, &runtimeJSONValid,
		); err != nil {
			return nil, err
		}

		summary := RuntimeStateSummary{}
		currentProjection := metadataVersion > 0 && (runtimeUpdated == "" || metaUpdated >= runtimeUpdated)
		if currentProjection {
			summary.HasBaseline = projectionVersion > 0 || (scanID.Valid && scanID.String != "")
			summary.BaselineScanID, summary.BaselineConfigHash = scanID.String, configHash.String
			summary.BaselineModified = modified != 0
			summary.CandidateCount = int(candidateCount)
			summary.CandidateAttempts = int(candidateAttempts)
			summary.IncompleteCandidateAttempts = int(incompleteAttempts)
			summary.IncidentCount = int(incidentCount)
			summary.PendingCount = int(pendingCount)
			if baselineHostCount > 0 {
				summary.BaselineHostCount = int(baselineHostCount)
			} else if metadataScanHostCount > 0 {
				summary.BaselineHostCount = int(metadataScanHostCount)
			} else if legacyBaselineType.Valid && legacyBaselineType.String == "object" {
				summary.BaselineHostCount = legacyRuntimeHostCount(legacyHostArrayCount, legacyUnitAddressCount)
			}
		} else if runtimeExists != 0 {
			if runtimeJSONValid == 0 {
				return nil, fmt.Errorf("invalid runtime JSON while resolving baseline summary for job %s", jobID)
			}
			summary.HasBaseline = legacyBaselineType.Valid && legacyBaselineType.String != "null" && legacyBaselineType.String != ""
			summary.BaselineScanID, summary.BaselineConfigHash = legacyScanID.String, legacyConfigHash.String
			summary.BaselineModified = legacyModified != 0
			summary.CandidateCount = int(legacyCandidateCount)
			summary.CandidateAttempts = int(legacyCandidateAttempts)
			summary.IncompleteCandidateAttempts = int(legacyIncompleteAttempts)
			summary.IncidentCount = int(legacyIncidentCount)
			summary.PendingCount = int(legacyPendingCount)
			if summary.BaselineScanID != "" {
				summary.BaselineHostCount = int(legacyScanHostCount)
			}
			if summary.BaselineModified {
				summary.BaselineHostCount = int(baselineHostCount)
			}
			if summary.BaselineHostCount == 0 {
				summary.BaselineHostCount = legacyRuntimeHostCount(legacyHostArrayCount, legacyUnitAddressCount)
			}
		}
		out[jobID] = summary
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func legacyRuntimeHostCount(hostArrayCount, unitAddressCount sql.NullInt64) int {
	if hostArrayCount.Valid && hostArrayCount.Int64 >= 0 {
		return int(hostArrayCount.Int64)
	}
	if unitAddressCount.Valid && unitAddressCount.Int64 >= 0 {
		return int(unitAddressCount.Int64)
	}
	return 0
}

func (s *Store) completeRuntimeSummary(ctx context.Context, jobID string, summary RuntimeStateSummary) (RuntimeStateSummary, error) {
	var projectedCount int
	var projected bool
	if err := s.reader().QueryRowContext(ctx, `SELECT COUNT(*),EXISTS(SELECT 1 FROM baseline_hosts WHERE job_id=?) FROM baseline_hosts WHERE job_id=?`, jobID, jobID).Scan(&projectedCount, &projected); err != nil {
		return summary, err
	}
	if projected {
		summary.BaselineHostCount = projectedCount
		return summary, nil
	}
	if summary.BaselineScanID != "" {
		if err := s.reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_hosts WHERE scan_id=?`, summary.BaselineScanID).Scan(&summary.BaselineHostCount); err != nil {
			return summary, err
		}
		if summary.BaselineHostCount > 0 {
			return summary, nil
		}
	}
	// Migration 40 can create current runtime metadata for a legacy baseline
	// before the resumable scan-host backfill has populated scan_hosts. Keep the
	// fast path bounded to this job while recovering the host count from the
	// JSON baseline instead of reporting zero until backfill catches up.
	if count, present, err := s.legacyRuntimeBaselineHostCount(ctx, jobID); err != nil {
		return summary, err
	} else if present {
		summary.BaselineHostCount = count
	}
	return summary, nil
}

// legacyRuntimeBaselineHostCount returns the host count from the current job's
// JSON runtime state when indexed host projections have not been populated.
// It intentionally reads no scan snapshots or rows for other jobs. A valid
// baseline object with no hosts is present=true and therefore remains an
// authoritative zero rather than falling through to a stale unit count.
func (s *Store) legacyRuntimeBaselineHostCount(ctx context.Context, jobID string) (count int, present bool, err error) {
	var baselineType sql.NullString
	var hostArrayCount, unitAddressCount sql.NullInt64
	err = s.reader().QueryRowContext(ctx, `SELECT
CASE WHEN json_valid(state_json) THEN json_type(state_json,'$.baseline') ELSE '' END,
CASE WHEN json_valid(state_json) AND json_type(state_json,'$.baseline')='object' THEN json_array_length(state_json,'$.baseline.hosts') END,
CASE WHEN json_valid(state_json) AND json_type(state_json,'$.baseline')='object' THEN COALESCE((SELECT COUNT(DISTINCT addresses.value)
  FROM json_each(state_json,'$.baseline.units') AS units
  JOIN json_each(units.value,'$.addresses') AS addresses),0) ELSE 0 END
FROM job_runtime WHERE job_id=?`, jobID).Scan(&baselineType, &hostArrayCount, &unitAddressCount)
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
// that need only baseline identifiers. Current rows are served from the
// compact metadata projection; legacy rows use the bounded fallback.
func (s *Store) RuntimeBaselineMeta(ctx context.Context, jobID string) (scanID, configHash string, err error) {
	info, err := s.RuntimeBaselineInfo(ctx, jobID)
	if err != nil {
		return "", "", err
	}
	return info.BaselineScanID, info.BaselineConfigHash, nil
}

// RuntimeBaselineModified reports whether the current comparison baseline has
// been changed independently of its immutable source scan. Legacy rows without
// the compact marker are treated conservatively as modified when the JSON
// marker is missing or null so host pages cannot render stale indexed evidence.
func (s *Store) RuntimeBaselineModified(ctx context.Context, jobID string) (bool, error) {
	info, err := s.RuntimeBaselineInfo(ctx, jobID)
	if err != nil {
		return false, err
	}
	return info.BaselineModified, nil
}

func (s *Store) UpdateRuntime(ctx context.Context, jobID string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	return s.updateRuntime(ctx, jobID, "", nil, fn)
}

func (s *Store) UpdateRuntimeWithOutbox(ctx context.Context, jobID string, destinations []string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	return s.updateRuntime(ctx, jobID, "", destinations, fn)
}

func (s *Store) updateRuntime(ctx context.Context, jobID, securityHash string, destinations []string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	return s.updateRuntimeWithOutboxAndAudits(ctx, jobID, securityHash, destinations, nil, fn)
}

func (s *Store) updateRuntimeWithOutboxAndAudits(ctx context.Context, jobID, securityHash string, destinations []string, audits []AuditEntry, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	return s.updateRuntimeWithOutboxAndAuditsGuarded(ctx, jobID, securityHash, destinations, audits, false, fn)
}

// updateRuntimeWithOutboxAndAuditsGuarded is the common transactional runtime
// mutation path. Some operator actions replace the complete comparison state
// (rather than applying one incident) and therefore need the same active-scan
// exclusion as incident actions. Scan finalization deliberately uses the
// unguarded path so it can commit its own result while its lease is held.
func (s *Store) updateRuntimeWithOutboxAndAuditsGuarded(ctx context.Context, jobID, securityHash string, destinations []string, audits []AuditEntry, rejectActive bool, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	return s.updateRuntimeWithOutboxAndAuditsGuardedPost(ctx, jobID, securityHash, destinations, audits, rejectActive, nil, fn)
}

// updateRuntimeWithOutboxAndAuditsGuardedPost is the same transactional path
// with an optional post-transition hook. The hook runs before commit while the
// final state is still protected by the writer transaction, which lets
// baseline projections stay in lockstep with reset/accept operations.
func (s *Store) updateRuntimeWithOutboxAndAuditsGuardedPost(ctx context.Context, jobID, securityHash string, destinations []string, audits []AuditEntry, rejectActive bool, post func(*sql.Tx, *model.JobState) error, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if rejectActive {
		if _, err := getJobTx(ctx, tx, jobID); err != nil {
			return nil, err
		}
		active, err := jobActiveTx(ctx, tx, jobID, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		if active {
			return nil, ErrJobScanActive
		}
	}
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
	var resultingState *model.JobState
	events, err := updateRuntimeTxWithOutbox(ctx, tx, jobID, destinations, func(state *model.JobState) ([]model.Event, error) {
		events, err := fn(state)
		if err == nil {
			resultingState = state
		}
		return events, err
	})
	if err != nil {
		return nil, err
	}
	if post != nil && resultingState != nil {
		if err := post(tx, resultingState); err != nil {
			return nil, err
		}
	}
	if err = insertAuditEntries(ctx, tx, audits, time.Now().UTC()); err != nil {
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
func (s *Store) UpdateRuntimeForScan(ctx context.Context, jobID, securityHash string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	return s.updateRuntime(ctx, jobID, securityHash, nil, fn)
}

// UpdateRuntimeForScanWithOutbox persists the state transition, event rows,
// and destination-specific outbox rows in one transaction. Destinations are
// captured before the transaction by the notifier and contain only opaque
// destination identifiers, never URLs.
func (s *Store) UpdateRuntimeForScanWithOutbox(ctx context.Context, jobID, securityHash string, destinations []string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	return s.updateRuntime(ctx, jobID, securityHash, destinations, fn)
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
// history but the runtime state is left untouched.
func (s *Store) FinalizeManagedScan(ctx context.Context, scan *model.Scan, jobID, securityHash string, destinations []string, fn func(*model.JobState, *model.Scan) ([]model.Event, error)) ([]model.Event, error) {
	if scan == nil {
		return nil, errors.New("scan is required")
	}
	if jobID == "" {
		return nil, errors.New("job ID is required")
	}
	if fn == nil {
		return nil, errors.New("scan finalizer is required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

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
		if err := saveScanExec(ctx, tx, *scan); err != nil {
			return nil, err
		}
		if err := clearCompletedScanCycleCheckpointsTx(ctx, tx, scan.CycleID); err != nil {
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
				if err := saveScanExec(ctx, tx, *scan); err != nil {
					return nil, err
				}
				if err := clearCompletedScanCycleCheckpointsTx(ctx, tx, scan.CycleID); err != nil {
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
	events, err := fn(&state, scan)
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
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
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
	for _, event := range events {
		bounded, payload, err := model.MarshalBoundedEvent(event, model.EventPayloadLimit)
		if err != nil {
			return err
		}
		event = bounded
		for _, destination := range destinations {
			if strings.HasPrefix(destination, "managed:") {
				valid, validationErr := managedDestinationCurrentTx(ctx, tx, destination)
				if validationErr != nil {
					return validationErr
				}
				// A destination may have been replaced or disabled after the
				// notifier captured its revision. Preserve the state/event
				// transition but do not create an orphaned delivery for a
				// credential that can never send it.
				if !valid {
					continue
				}
			}
			result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO outbox(destination,payload_json,next_at) VALUES(?,?,?)`, destination, payload, now)
			if err != nil {
				return err
			}
			if inserted, _ := result.RowsAffected(); inserted == 1 {
				if err := ensureDeliveryHealthTx(ctx, tx, destination, time.Now().UTC()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// managedDestinationCurrentTx validates an opaque managed destination key at
// the same transaction boundary that inserts an outbox row. This closes the
// race where a destination is replaced or deleted between notifier metadata
// capture and the runtime/event commit.
func managedDestinationCurrentTx(ctx context.Context, tx *sql.Tx, destination string) (bool, error) {
	parts := strings.Split(destination, ":")
	if len(parts) != 3 || parts[0] != "managed" || parts[1] == "" {
		return false, nil
	}
	revision, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || revision < 1 {
		return false, nil
	}
	var enabled int
	err = tx.QueryRowContext(ctx, `SELECT enabled FROM managed_notifications WHERE id=? AND revision=?`, parts[1], revision).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return enabled != 0, nil
}

// updateRuntimeTx applies a runtime state transition and persists its events
// on the caller's transaction. Keeping the state read, event writes, and any
// caller-provided validation in one transaction prevents stale approvals from
// crossing a job-scope change.
func updateRuntimeTx(ctx context.Context, tx *sql.Tx, jobID string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
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
		if _, err = tx.ExecContext(ctx, `INSERT INTO events(type,job,job_id,scan_id,payload_json,created_at) VALUES(?,?,?,?,?,?)`, events[i].Type, events[i].Job, events[i].JobID, events[i].ScanID, payload, sqliteTimestamp(events[i].CreatedAt)); err != nil {
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

func (s *Store) ResetRuntime(ctx context.Context, jobID, name string) ([]model.Event, error) {
	return s.ResetRuntimeWithOutbox(ctx, jobID, name, nil)
}

// ResetRuntimeWithOutbox persists the baseline reset event and its notification
// intent in the same transaction.
func (s *Store) ResetRuntimeWithOutbox(ctx context.Context, jobID, name string, destinations []string) ([]model.Event, error) {
	return s.resetRuntimeWithAudits(ctx, jobID, name, destinations, nil, BaselineExpectation{})
}

// ResetRuntimeWithOutboxAndAudit clears comparison state, persists any reset
// notification intent, and records the administrator action atomically.
func (s *Store) ResetRuntimeWithOutboxAndAudit(ctx context.Context, jobID, name string, destinations []string, audit AuditEntry) ([]model.Event, error) {
	return s.resetRuntimeWithAudits(ctx, jobID, name, destinations, []AuditEntry{audit}, BaselineExpectation{})
}

// ResetRuntimeWithExpectationAndAudit is the stale-view-safe baseline reset
// entry point used by the web API. The comparison is made inside the same
// writer transaction that clears the state, so two administrators cannot both
// mutate a baseline they loaded before the other action committed.
func (s *Store) ResetRuntimeWithExpectationAndAudit(ctx context.Context, jobID, name string, destinations []string, audit AuditEntry, expected BaselineExpectation) ([]model.Event, error) {
	return s.resetRuntimeWithAudits(ctx, jobID, name, destinations, []AuditEntry{audit}, expected)
}

func (s *Store) resetRuntimeWithAudits(ctx context.Context, jobID, name string, destinations []string, audits []AuditEntry, expected BaselineExpectation) ([]model.Event, error) {
	return s.updateRuntimeWithOutboxAndAuditsGuardedPost(ctx, jobID, "", destinations, audits, true, func(tx *sql.Tx, _ *model.JobState) error {
		if err := clearBaselineHostProjectionTx(ctx, tx, jobID); err != nil {
			return err
		}
		return discardUnpromotedCyclesTx(ctx, tx, jobID, "baseline reset", time.Now().UTC())
	}, func(state *model.JobState) ([]model.Event, error) {
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
		return []model.Event{{Type: "baseline-reset", Job: name, Message: "Baseline collection reset", CreatedAt: time.Now().UTC()}}, nil
	})
}

func (s *Store) ApproveRuntime(ctx context.Context, jobID, name string, scan model.Scan) ([]model.Event, error) {
	return s.ApproveRuntimeWithOutbox(ctx, jobID, name, scan, nil)
}

// ApproveRuntimeWithOutbox persists a manual baseline approval and notification
// intent together, while retaining the current-scope validation.
func (s *Store) ApproveRuntimeWithOutbox(ctx context.Context, jobID, name string, scan model.Scan, destinations []string) ([]model.Event, error) {
	return s.approveRuntimeWithAudits(ctx, jobID, name, scan, destinations, nil, BaselineExpectation{})
}

// ApproveRuntimeWithOutboxAndAudit applies a manual baseline approval and its
// notification intent/audit row in one transaction.
func (s *Store) ApproveRuntimeWithOutboxAndAudit(ctx context.Context, jobID, name string, scan model.Scan, destinations []string, audit AuditEntry) ([]model.Event, error) {
	return s.approveRuntimeWithAudits(ctx, jobID, name, scan, destinations, []AuditEntry{audit}, BaselineExpectation{})
}

// ApproveRuntimeWithExpectationAndAudit applies a manual baseline approval
// only if the caller's baseline marker still matches the committed runtime.
func (s *Store) ApproveRuntimeWithExpectationAndAudit(ctx context.Context, jobID, name string, scan model.Scan, destinations []string, audit AuditEntry, expected BaselineExpectation) ([]model.Event, error) {
	return s.approveRuntimeWithAudits(ctx, jobID, name, scan, destinations, []AuditEntry{audit}, expected)
}

func (s *Store) approveRuntimeWithAudits(ctx context.Context, jobID, name string, scan model.Scan, destinations []string, audits []AuditEntry, expected BaselineExpectation) ([]model.Event, error) {
	if scan.ID == "" {
		return nil, errors.New("scan ID is required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	record, err := getJobTx(ctx, tx, jobID)
	if err != nil {
		return nil, err
	}
	active, err := jobActiveTx(ctx, tx, jobID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if active {
		return nil, ErrJobScanActive
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
		return []model.Event{{Type: "baseline-approved", Job: name, ScanID: stored.ID, Message: "Baseline manually approved", CreatedAt: time.Now().UTC()}}, nil
	})
	if err != nil {
		return nil, err
	}
	if err := discardUnpromotedCyclesTx(ctx, tx, jobID, "baseline approved", time.Now().UTC()); err != nil {
		return nil, err
	}
	if err := insertAuditEntries(ctx, tx, audits, time.Now().UTC()); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}
