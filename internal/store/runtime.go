package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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

// RuntimeStateSummary is the bounded state projection used by job-list
// responses. It deliberately avoids unmarshalling the baseline/candidate
// snapshots merely to render counters and host_count. Detailed state remains
// available through RuntimeState for mutation and detail endpoints.
type RuntimeStateSummary struct {
	HasBaseline        bool
	BaselineScanID     string
	BaselineConfigHash string
	BaselineModified   bool
	CandidateCount     int
	CandidateAttempts  int
	IncidentCount      int
	PendingCount       int
	BaselineHostCount  int
}

func (s *Store) RuntimeStateSummary(ctx context.Context, jobID string) (RuntimeStateSummary, error) {
	var summary RuntimeStateSummary
	var baselineType sql.NullString
	var scanID, configHash sql.NullString
	var modified, candidateCount, candidateAttempts, incidentCount, pendingCount, hostArrayCount, unitAddressCount sql.NullInt64
	err := s.reader().QueryRowContext(ctx, `SELECT
 json_type(state_json,'$.baseline'),
 json_extract(state_json,'$.baseline_scan_id'),
 json_extract(state_json,'$.baseline_config_hash'),
 COALESCE(json_extract(state_json,'$.baseline_modified'),0),
 COALESCE(json_extract(state_json,'$.candidate_count'),0),
 COALESCE(json_extract(state_json,'$.candidate_attempts'),0),
 COALESCE((SELECT COUNT(*) FROM json_each(state_json,'$.incidents')),0),
 COALESCE((SELECT COUNT(*) FROM json_each(state_json,'$.pending')),0),
 COALESCE(json_array_length(state_json,'$.baseline.hosts'),-1),
 COALESCE((SELECT COUNT(DISTINCT addresses.value)
   FROM json_each(state_json,'$.baseline.units') AS units
   JOIN json_each(units.value,'$.addresses') AS addresses),0)
 FROM job_runtime WHERE job_id=?`, jobID).Scan(&baselineType, &scanID, &configHash, &modified, &candidateCount, &candidateAttempts, &incidentCount, &pendingCount, &hostArrayCount, &unitAddressCount)
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

// RuntimeBaselineMeta reads only the baseline identifiers from runtime JSON.
// Host pages use this fast path before deciding whether they need the full
// legacy state snapshot.
func (s *Store) RuntimeBaselineMeta(ctx context.Context, jobID string) (scanID, configHash string, err error) {
	var scan, hash sql.NullString
	err = s.reader().QueryRowContext(ctx, `SELECT json_extract(state_json,'$.baseline_scan_id'), json_extract(state_json,'$.baseline_config_hash') FROM job_runtime WHERE job_id=?`, jobID).Scan(&scan, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	return scan.String, hash.String, nil
}

// RuntimeBaselineModified reports whether the current comparison baseline has
// been changed independently of its immutable source scan. Databases written
// before the marker was introduced are treated conservatively as modified so
// host pages cannot silently render stale indexed evidence after an older
// administrator acceptance.
func (s *Store) RuntimeBaselineModified(ctx context.Context, jobID string) (bool, error) {
	var marker sql.NullInt64
	err := s.reader().QueryRowContext(ctx, `SELECT json_extract(state_json,'$.baseline_modified') FROM job_runtime WHERE job_id=?`, jobID).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !marker.Valid {
		return true, nil
	}
	return marker.Int64 != 0, nil
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

	state, err := loadRuntimeTx(ctx, tx, jobID)
	if err != nil {
		return nil, err
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
	if err := refreshBaselineHostProjectionTx(ctx, tx, jobID, baselineModifiedBefore, baselineBefore, state); err != nil {
		return nil, err
	}
	if scan.Status == "success" {
		// A successful result clears any silence watchdog backoff in the same
		// transaction as the scan and runtime update. This prevents a delayed
		// heartbeat from emitting a stale silence alert after recovery.
		stamp := scan.FinishedAt.UTC().Format(time.RFC3339Nano)
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
	now := time.Now().UTC().Format(time.RFC3339Nano)
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?) ON CONFLICT(job_id) DO UPDATE SET state_json=excluded.state_json,updated_at=excluded.updated_at`, jobID, raw, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
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
		if _, err = tx.ExecContext(ctx, `INSERT INTO events(type,job,job_id,scan_id,payload_json,created_at) VALUES(?,?,?,?,?,?)`, events[i].Type, events[i].Job, events[i].JobID, events[i].ScanID, payload, events[i].CreatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
	}
	return events, nil
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
	return s.resetRuntimeWithAudits(ctx, jobID, name, destinations, nil)
}

// ResetRuntimeWithOutboxAndAudit clears comparison state, persists any reset
// notification intent, and records the administrator action atomically.
func (s *Store) ResetRuntimeWithOutboxAndAudit(ctx context.Context, jobID, name string, destinations []string, audit AuditEntry) ([]model.Event, error) {
	return s.resetRuntimeWithAudits(ctx, jobID, name, destinations, []AuditEntry{audit})
}

func (s *Store) resetRuntimeWithAudits(ctx context.Context, jobID, name string, destinations []string, audits []AuditEntry) ([]model.Event, error) {
	return s.updateRuntimeWithOutboxAndAuditsGuardedPost(ctx, jobID, "", destinations, audits, true, func(tx *sql.Tx, _ *model.JobState) error {
		return clearBaselineHostProjectionTx(ctx, tx, jobID)
	}, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = nil
		state.BaselineScanID = ""
		state.BaselineConfigHash = ""
		state.BaselineModified = false
		state.Candidate = nil
		state.CandidateHash = ""
		state.CandidateCount = 0
		state.CandidateAttempts = 0
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
	return s.approveRuntimeWithAudits(ctx, jobID, name, scan, destinations, nil)
}

// ApproveRuntimeWithOutboxAndAudit applies a manual baseline approval and its
// notification intent/audit row in one transaction.
func (s *Store) ApproveRuntimeWithOutboxAndAudit(ctx context.Context, jobID, name string, scan model.Scan, destinations []string, audit AuditEntry) ([]model.Event, error) {
	return s.approveRuntimeWithAudits(ctx, jobID, name, scan, destinations, []AuditEntry{audit})
}

func (s *Store) approveRuntimeWithAudits(ctx context.Context, jobID, name string, scan model.Scan, destinations []string, audits []AuditEntry) ([]model.Event, error) {
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
		state.Baseline = &stored.Snapshot
		state.BaselineScanID = stored.ID
		state.BaselineConfigHash = stored.ConfigHash
		state.BaselineModified = false
		state.Candidate = nil
		state.CandidateHash = ""
		state.CandidateCount = 0
		state.CandidateAttempts = 0
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
	if err := insertAuditEntries(ctx, tx, audits, time.Now().UTC()); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}
