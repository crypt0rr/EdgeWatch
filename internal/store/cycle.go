package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/google/uuid"
)

var (
	ErrNoScanCycle       = errors.New("scan cycle not found")
	ErrNoPendingUnit     = errors.New("scan cycle has no pending work")
	ErrCycleNotResumable = errors.New("scan cycle is not resumable")
	ErrCycleIncomplete   = errors.New("scan cycle is incomplete")
)

// ScanCycleRecord is the durable state for a complete scope scan that may
// require more than one attempt. The plan includes the normalized job and
// pinned DNS expansion so a resumed cycle never silently changes scope.
type ScanCycleRecord struct {
	ID                 string
	JobID              string
	Job                string
	JobRevision        int64
	ConfigHash         string
	ExecutionHash      string
	Plan               scanner.WorkPlan
	Status             string
	AttemptCount       int
	NoProgressAttempts int
	TotalUnits         int
	CompletedUnits     int
	TotalProbes        int64
	CompletedProbes    int64
	StartedAt          time.Time
	UpdatedAt          time.Time
	ExpiresAt          time.Time
	FinishedAt         time.Time
	LastError          string
}

// ScanCycleUnit is one independently persisted Nmap invocation.
type ScanCycleUnit struct {
	CycleID    string
	Sequence   int
	Unit       scanner.WorkUnit
	Status     string
	Attempts   int
	Snapshot   model.Snapshot
	StartedAt  time.Time
	FinishedAt time.Time
	LastError  string
}

// ScanCycleUnitSummary is the safe progress view returned to the web console.
// It omits checkpoint payloads, which can be very large for a full-range job.
type ScanCycleUnitSummary struct {
	CycleID    string
	Sequence   int
	Protocol   string
	Family     int
	Ports      string
	PortCount  int
	Addresses  int
	Probes     int64
	Status     string
	Attempts   int
	StartedAt  time.Time
	FinishedAt time.Time
	LastError  string
}

func (s *Store) CreateScanCycle(ctx context.Context, cycle ScanCycleRecord) (ScanCycleRecord, error) {
	if cycle.JobID == "" || cycle.Job == "" {
		return ScanCycleRecord{}, errors.New("scan cycle job is required")
	}
	if len(cycle.Plan.Units) == 0 {
		return ScanCycleRecord{}, errors.New("scan cycle has no work units")
	}
	if cycle.ID == "" {
		cycle.ID = uuid.NewString()
	}
	now := cycle.StartedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cycle.StartedAt = now
	if cycle.UpdatedAt.IsZero() {
		cycle.UpdatedAt = now
	}
	if cycle.ExpiresAt.IsZero() {
		cycle.ExpiresAt = now.Add(8 * 24 * time.Hour)
	}
	cycle.Status = "paused"
	cycle.TotalUnits = len(cycle.Plan.Units)
	// Treat the persisted unit list as the source of truth for progress. This
	// also keeps alternate scanners safe when they omit the aggregate totals in
	// their plan; a resumed cycle must never advertise zero work for non-empty
	// units or over-count probes after a split.
	var plannedProbes int64
	for _, unit := range cycle.Plan.Units {
		plannedProbes += unit.Probes
	}
	cycle.TotalProbes = plannedProbes
	cycle.Plan.TotalUnits = cycle.TotalUnits
	cycle.Plan.TotalProbes = plannedProbes
	planJSON, err := json.Marshal(cycle.Plan)
	if err != nil {
		return ScanCycleRecord{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ScanCycleRecord{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO scan_cycles(id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,attempt_count,no_progress_attempts,total_units,completed_units,total_probes,completed_probes,started_at,updated_at,expires_at,finished_at,last_error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		cycle.ID, cycle.JobID, cycle.Job, cycle.JobRevision, cycle.ConfigHash, cycle.ExecutionHash, planJSON, cycle.Status, cycle.AttemptCount, cycle.NoProgressAttempts, cycle.TotalUnits, cycle.CompletedUnits, cycle.TotalProbes, cycle.CompletedProbes, cycle.StartedAt.Format(time.RFC3339Nano), cycle.UpdatedAt.Format(time.RFC3339Nano), cycle.ExpiresAt.Format(time.RFC3339Nano), "", cycle.LastError)
	if err != nil {
		return ScanCycleRecord{}, err
	}
	for _, unit := range cycle.Plan.Units {
		raw, marshalErr := json.Marshal(unit)
		if marshalErr != nil {
			return ScanCycleRecord{}, marshalErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO scan_cycle_units(cycle_id,sequence,work_unit_json,status,attempts,snapshot_json,started_at,finished_at,last_error) VALUES(?,?,?,?,?,?,?,?,?)`, cycle.ID, unit.Sequence, raw, "pending", 0, []byte(`{}`), "", "", ""); err != nil {
			return ScanCycleRecord{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return ScanCycleRecord{}, err
	}
	return cycle, nil
}

func (s *Store) GetScanCycle(ctx context.Context, id string) (ScanCycleRecord, error) {
	var cycle ScanCycleRecord
	var planJSON []byte
	var started, updated, expires, finished string
	err := s.DB.QueryRowContext(ctx, `SELECT id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,attempt_count,no_progress_attempts,total_units,completed_units,total_probes,completed_probes,started_at,updated_at,expires_at,finished_at,last_error FROM scan_cycles WHERE id=?`, id).
		Scan(&cycle.ID, &cycle.JobID, &cycle.Job, &cycle.JobRevision, &cycle.ConfigHash, &cycle.ExecutionHash, &planJSON, &cycle.Status, &cycle.AttemptCount, &cycle.NoProgressAttempts, &cycle.TotalUnits, &cycle.CompletedUnits, &cycle.TotalProbes, &cycle.CompletedProbes, &started, &updated, &expires, &finished, &cycle.LastError)
	if errors.Is(err, sql.ErrNoRows) {
		return cycle, fmt.Errorf("%w: %s", ErrNoScanCycle, id)
	}
	if err != nil {
		return cycle, err
	}
	if err = json.Unmarshal(planJSON, &cycle.Plan); err != nil {
		return cycle, err
	}
	cycle.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
	cycle.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	cycle.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	cycle.FinishedAt, _ = time.Parse(time.RFC3339Nano, finished)
	return cycle, nil
}

func (s *Store) GetActiveScanCycle(ctx context.Context, jobID string) (ScanCycleRecord, error) {
	var id string
	err := s.DB.QueryRowContext(ctx, `SELECT id FROM scan_cycles WHERE job_id=? AND status IN ('running','paused','stalled') ORDER BY started_at DESC LIMIT 1`, jobID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ScanCycleRecord{}, ErrNoScanCycle
	}
	if err != nil {
		return ScanCycleRecord{}, err
	}
	return s.GetScanCycle(ctx, id)
}

// GetLatestScanCycle returns the newest cycle for a job regardless of its
// terminal state. It is intentionally separate from GetActiveScanCycle: a
// completed, discarded, or expired cycle must remain visible in history but
// must never block creation of a fresh cycle.
func (s *Store) GetLatestScanCycle(ctx context.Context, jobID string) (ScanCycleRecord, error) {
	var id string
	err := s.DB.QueryRowContext(ctx, `SELECT id FROM scan_cycles WHERE job_id=? ORDER BY started_at DESC,id DESC LIMIT 1`, jobID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ScanCycleRecord{}, ErrNoScanCycle
	}
	if err != nil {
		return ScanCycleRecord{}, err
	}
	return s.GetScanCycle(ctx, id)
}

// ScanCycleExpiryNotified reports whether an expired cycle already produced
// its terminal scan record. Housekeeping can expire a cycle between schedule
// ticks; keeping this check separate lets the next trigger emit exactly one
// failure notification before a subsequent trigger starts a fresh cycle.
func (s *Store) ScanCycleExpiryNotified(ctx context.Context, cycleID string) (bool, error) {
	var count int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE cycle_id=? AND cycle_status='expired' AND status='timed_out'`, cycleID).Scan(&count)
	return count > 0, err
}

// ScanCycleHasScan reports whether a terminal cycle has already been promoted
// into scan history. The cycle is marked completed before the engine's final
// transaction, so a process crash in that small window must be recoverable on
// the next trigger rather than silently starting a brand-new cycle.
func (s *Store) ScanCycleHasScan(ctx context.Context, cycleID string) (bool, error) {
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE cycle_id=?`, cycleID).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *Store) ListScanCycleUnitSummaries(ctx context.Context, cycleID string) ([]ScanCycleUnitSummary, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT cycle_id,sequence,work_unit_json,status,attempts,started_at,finished_at,last_error FROM scan_cycle_units WHERE cycle_id=? ORDER BY sequence`, cycleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanCycleUnitSummary
	for rows.Next() {
		var item ScanCycleUnitSummary
		var raw []byte
		var started, finished string
		if err := rows.Scan(&item.CycleID, &item.Sequence, &raw, &item.Status, &item.Attempts, &started, &finished, &item.LastError); err != nil {
			return nil, err
		}
		var unit scanner.WorkUnit
		if err := json.Unmarshal(raw, &unit); err != nil {
			return nil, err
		}
		item.Protocol, item.Family, item.Ports, item.PortCount, item.Addresses, item.Probes = unit.Protocol, unit.Family, unit.Ports, unit.PortCount, len(unit.Addresses), unit.Probes
		item.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
		item.FinishedAt, _ = time.Parse(time.RFC3339Nano, finished)
		out = append(out, item)
	}
	return out, rows.Err()
}

// StartScanCycleAttempt resets a unit left running by a process crash and
// atomically marks the cycle running for this attempt.
func (s *Store) StartScanCycleAttempt(ctx context.Context, id string) (ScanCycleRecord, error) {
	now := time.Now().UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ScanCycleRecord{}, err
	}
	defer tx.Rollback()
	var status, expires string
	if err = tx.QueryRowContext(ctx, `SELECT status,expires_at FROM scan_cycles WHERE id=?`, id).Scan(&status, &expires); errors.Is(err, sql.ErrNoRows) {
		return ScanCycleRecord{}, fmt.Errorf("%w: %s", ErrNoScanCycle, id)
	} else if err != nil {
		return ScanCycleRecord{}, err
	}
	if status != "paused" && status != "stalled" && status != "running" {
		return ScanCycleRecord{}, ErrCycleNotResumable
	}
	if expiry, parseErr := time.Parse(time.RFC3339Nano, expires); parseErr == nil && !expiry.IsZero() && !now.Before(expiry) {
		stamp := now.Format(time.RFC3339Nano)
		transition, transitionErr := tx.ExecContext(ctx, `UPDATE scan_cycles SET status='expired',updated_at=?,finished_at=?,last_error='scan cycle exceeded its resume window' WHERE id=? AND status IN ('running','paused','stalled')`, stamp, stamp, id)
		if transitionErr != nil {
			return ScanCycleRecord{}, transitionErr
		}
		changed, _ := transition.RowsAffected()
		if changed != 1 {
			// Another writer may have completed, discarded, or expired the cycle
			// after our initial read. Do not clear its checkpoints in that case;
			// the terminal transition (and any cleanup) belongs to that writer.
			return ScanCycleRecord{}, ErrCycleNotResumable
		}
		// Expired cycles remain as lightweight history, but their detailed
		// checkpoints may contain a large portion of a full-range snapshot. Clear
		// those payloads as part of the same transaction so expiry is atomic even
		// when this method (rather than the daemon housekeeping pass) discovers it.
		if _, clearErr := tx.ExecContext(ctx, `UPDATE scan_cycle_units SET snapshot_json='{}',last_error='cycle expired' WHERE cycle_id=? AND EXISTS (SELECT 1 FROM scan_cycles WHERE id=? AND status='expired' AND finished_at=?)`, id, id, stamp); clearErr != nil {
			return ScanCycleRecord{}, clearErr
		}
		// Commit the terminal transition before returning the sentinel. Without
		// this commit the deferred rollback would undo expiry, causing the next
		// trigger to rediscover the same cycle as resumable and emit duplicate
		// timeout failures.
		if err = tx.Commit(); err != nil {
			return ScanCycleRecord{}, err
		}
		return ScanCycleRecord{}, ErrCycleNotResumable
	}
	if _, err = tx.ExecContext(ctx, `UPDATE scan_cycle_units SET status='pending',started_at='',last_error=last_error WHERE cycle_id=? AND status='running'`, id); err != nil {
		return ScanCycleRecord{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE scan_cycles SET status='running',attempt_count=attempt_count+1,updated_at=? WHERE id=? AND status IN ('paused','stalled','running')`, now.Format(time.RFC3339Nano), id); err != nil {
		return ScanCycleRecord{}, err
	}
	if err = tx.Commit(); err != nil {
		return ScanCycleRecord{}, err
	}
	return s.GetScanCycle(ctx, id)
}

func (s *Store) NextScanCycleUnit(ctx context.Context, cycleID string) (ScanCycleUnit, error) {
	var unit ScanCycleUnit
	var raw, snapshot []byte
	var started, finished string
	status, statusErr := s.scanCycleStatus(ctx, cycleID)
	if statusErr != nil {
		return unit, statusErr
	}
	if status != "running" {
		if status == "completed" {
			return unit, ErrNoPendingUnit
		}
		return unit, ErrCycleNotResumable
	}
	err := s.DB.QueryRowContext(ctx, `SELECT cycle_id,sequence,work_unit_json,status,attempts,snapshot_json,started_at,finished_at,last_error FROM scan_cycle_units WHERE cycle_id=? AND status='pending' ORDER BY sequence LIMIT 1`, cycleID).
		Scan(&unit.CycleID, &unit.Sequence, &raw, &unit.Status, &unit.Attempts, &snapshot, &started, &finished, &unit.LastError)
	if errors.Is(err, sql.ErrNoRows) {
		return unit, ErrNoPendingUnit
	}
	if err != nil {
		return unit, err
	}
	if err = json.Unmarshal(raw, &unit.Unit); err != nil {
		return unit, err
	}
	if len(snapshot) > 0 && string(snapshot) != "{}" && string(snapshot) != "null" {
		if err = json.Unmarshal(snapshot, &unit.Snapshot); err != nil {
			return unit, err
		}
	}
	unit.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
	unit.FinishedAt, _ = time.Parse(time.RFC3339Nano, finished)
	return unit, nil
}

func (s *Store) ClaimScanCycleUnit(ctx context.Context, cycleID string, sequence int) (ScanCycleUnit, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.DB.ExecContext(ctx, `UPDATE scan_cycle_units SET status='running',attempts=attempts+1,started_at=?,last_error='' WHERE cycle_id=? AND sequence=? AND status='pending' AND EXISTS (SELECT 1 FROM scan_cycles WHERE id=? AND status='running')`, now, cycleID, sequence, cycleID)
	if err != nil {
		return ScanCycleUnit{}, err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		if status, statusErr := s.scanCycleStatus(ctx, cycleID); statusErr != nil {
			return ScanCycleUnit{}, statusErr
		} else if status != "running" {
			return ScanCycleUnit{}, ErrCycleNotResumable
		}
		return ScanCycleUnit{}, ErrNoPendingUnit
	}
	return s.getScanCycleUnit(ctx, cycleID, sequence)
}

func (s *Store) scanCycleStatus(ctx context.Context, cycleID string) (string, error) {
	var status string
	err := s.DB.QueryRowContext(ctx, `SELECT status FROM scan_cycles WHERE id=?`, cycleID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: %s", ErrNoScanCycle, cycleID)
	}
	return status, err
}

func (s *Store) getScanCycleUnit(ctx context.Context, cycleID string, sequence int) (ScanCycleUnit, error) {
	var unit ScanCycleUnit
	var raw, snapshot []byte
	var started, finished string
	err := s.DB.QueryRowContext(ctx, `SELECT cycle_id,sequence,work_unit_json,status,attempts,snapshot_json,started_at,finished_at,last_error FROM scan_cycle_units WHERE cycle_id=? AND sequence=?`, cycleID, sequence).
		Scan(&unit.CycleID, &unit.Sequence, &raw, &unit.Status, &unit.Attempts, &snapshot, &started, &finished, &unit.LastError)
	if err != nil {
		return unit, err
	}
	if err = json.Unmarshal(raw, &unit.Unit); err != nil {
		return unit, err
	}
	if len(snapshot) > 0 && string(snapshot) != "{}" && string(snapshot) != "null" {
		_ = json.Unmarshal(snapshot, &unit.Snapshot)
	}
	unit.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
	unit.FinishedAt, _ = time.Parse(time.RFC3339Nano, finished)
	return unit, nil
}

func (s *Store) CompleteScanCycleUnit(ctx context.Context, cycleID string, sequence int, snapshot model.Snapshot) error {
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	var unitRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT status,work_unit_json FROM scan_cycle_units WHERE cycle_id=? AND sequence=?`, cycleID, sequence).Scan(&status, &unitRaw); err != nil {
		return err
	}
	if status == "completed" {
		return nil
	}
	if status != "running" {
		return fmt.Errorf("scan cycle unit %d is not running", sequence)
	}
	var cycleStatus string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM scan_cycles WHERE id=?`, cycleID).Scan(&cycleStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrNoScanCycle, cycleID)
		}
		return err
	}
	if cycleStatus != "running" {
		return ErrCycleNotResumable
	}
	var unit scanner.WorkUnit
	if err = json.Unmarshal(unitRaw, &unit); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE scan_cycle_units SET status='completed',snapshot_json=?,finished_at=?,last_error='' WHERE cycle_id=? AND sequence=?`, raw, now.Format(time.RFC3339Nano), cycleID, sequence); err != nil {
		return err
	}
	cycleUpdate, err := tx.ExecContext(ctx, `UPDATE scan_cycles SET completed_units=completed_units+1,completed_probes=completed_probes+?,updated_at=? WHERE id=? AND status='running'`, unit.Probes, now.Format(time.RFC3339Nano), cycleID)
	if err != nil {
		return err
	}
	if count, _ := cycleUpdate.RowsAffected(); count != 1 {
		return ErrCycleNotResumable
	}
	return tx.Commit()
}

func (s *Store) RetryScanCycleUnit(ctx context.Context, cycleID string, sequence int, lastError string) error {
	result, err := s.DB.ExecContext(ctx, `UPDATE scan_cycle_units SET status='pending',last_error=? WHERE cycle_id=? AND sequence=? AND status='running' AND EXISTS (SELECT 1 FROM scan_cycles WHERE id=? AND status='running')`, trimCycleError(lastError), cycleID, sequence, cycleID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 1 {
		return nil
	}
	status, statusErr := s.scanCycleStatus(ctx, cycleID)
	if statusErr != nil {
		return statusErr
	}
	if status != "running" {
		return ErrCycleNotResumable
	}
	return ErrNoPendingUnit
}

func (s *Store) SplitScanCycleUnit(ctx context.Context, cycleID string, sequence int, first, second scanner.WorkUnit, lastError string) error {
	firstRaw, err := json.Marshal(first)
	if err != nil {
		return err
	}
	secondRaw, err := json.Marshal(second)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM scan_cycle_units WHERE cycle_id=? AND sequence=?`, cycleID, sequence).Scan(&status); err != nil {
		return err
	}
	if status == "completed" {
		return nil
	}
	if status != "running" {
		return ErrCycleNotResumable
	}
	var cycleStatus string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM scan_cycles WHERE id=?`, cycleID).Scan(&cycleStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrNoScanCycle, cycleID)
		}
		return err
	}
	if cycleStatus != "running" {
		return ErrCycleNotResumable
	}
	var next int
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),-1)+1 FROM scan_cycle_units WHERE cycle_id=?`, cycleID).Scan(&next); err != nil {
		return err
	}
	second.Sequence = next
	secondRaw, err = json.Marshal(second)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE scan_cycle_units SET work_unit_json=?,status='pending',last_error=? WHERE cycle_id=? AND sequence=?`, firstRaw, trimCycleError(lastError), cycleID, sequence); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO scan_cycle_units(cycle_id,sequence,work_unit_json,status,attempts,snapshot_json,started_at,finished_at,last_error) VALUES(?,?,?,?,?,?,?,?,?)`, cycleID, next, secondRaw, "pending", 0, []byte(`{}`), "", "", ""); err != nil {
		return err
	}
	cycleUpdate, err := tx.ExecContext(ctx, `UPDATE scan_cycles SET total_units=total_units+1,updated_at=?,last_error=? WHERE id=? AND status='running'`, time.Now().UTC().Format(time.RFC3339Nano), trimCycleError(lastError), cycleID)
	if err != nil {
		return err
	}
	if count, _ := cycleUpdate.RowsAffected(); count != 1 {
		return ErrCycleNotResumable
	}
	return tx.Commit()
}

func (s *Store) PauseScanCycle(ctx context.Context, cycleID string, noProgress bool, lastError string) (ScanCycleRecord, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	query := `UPDATE scan_cycles SET status='paused',no_progress_attempts=CASE WHEN ? THEN no_progress_attempts+1 ELSE 0 END,updated_at=?,last_error=? WHERE id=? AND status IN ('running','paused','stalled')`
	if _, err := s.DB.ExecContext(ctx, query, noProgress, now, trimCycleError(lastError), cycleID); err != nil {
		return ScanCycleRecord{}, err
	}
	return s.GetScanCycle(ctx, cycleID)
}

func (s *Store) MarkScanCycleStalled(ctx context.Context, cycleID, lastError string) (ScanCycleRecord, error) {
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET status='stalled',updated_at=?,last_error=? WHERE id=? AND status IN ('running','paused','stalled')`, time.Now().UTC().Format(time.RFC3339Nano), trimCycleError(lastError), cycleID); err != nil {
		return ScanCycleRecord{}, err
	}
	return s.GetScanCycle(ctx, cycleID)
}

func (s *Store) CompleteScanCycle(ctx context.Context, cycleID string) (ScanCycleRecord, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ScanCycleRecord{}, err
	}
	defer tx.Rollback()
	var status string
	var completed, total int
	if err = tx.QueryRowContext(ctx, `SELECT status,completed_units,total_units FROM scan_cycles WHERE id=?`, cycleID).Scan(&status, &completed, &total); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ScanCycleRecord{}, fmt.Errorf("%w: %s", ErrNoScanCycle, cycleID)
		}
		return ScanCycleRecord{}, err
	}
	if status == "completed" {
		_ = tx.Rollback()
		return s.GetScanCycle(ctx, cycleID)
	}
	if status != "running" {
		return ScanCycleRecord{}, ErrCycleNotResumable
	}
	if completed != total {
		return ScanCycleRecord{}, fmt.Errorf("%w: %d of %d units completed", ErrCycleIncomplete, completed, total)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE scan_cycles SET status='completed',updated_at=?,finished_at=?,last_error='' WHERE id=? AND status='running'`, now, now, cycleID); err != nil {
		return ScanCycleRecord{}, err
	}
	if err = tx.Commit(); err != nil {
		return ScanCycleRecord{}, err
	}
	return s.GetScanCycle(ctx, cycleID)
}

func (s *Store) DiscardScanCycle(ctx context.Context, cycleID string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM scan_cycles WHERE id=?`, cycleID).Scan(&status); errors.Is(err, sql.ErrNoRows) {
		return ErrNoScanCycle
	} else if err != nil {
		return err
	}
	if status != "paused" && status != "stalled" {
		return ErrCycleNotResumable
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, `UPDATE scan_cycles SET status='discarded',updated_at=?,finished_at=?,last_error='discarded by administrator' WHERE id=? AND status IN ('paused','stalled')`, stamp, stamp, cycleID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM scan_cycle_units WHERE cycle_id=?`, cycleID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ExpireScanCycles(ctx context.Context, now time.Time) (int64, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	stamp := now.UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE scan_cycles SET status='expired',updated_at=?,finished_at=?,last_error='scan cycle exceeded its resume window' WHERE status IN ('running','paused','stalled') AND expires_at<=?`, stamp, stamp, stamp)
	if err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE scan_cycle_units SET snapshot_json='{}',last_error='cycle expired' WHERE cycle_id IN (SELECT id FROM scan_cycles WHERE status='expired' AND finished_at=?)`, stamp); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	count, _ := result.RowsAffected()
	return count, nil
}

func (s *Store) LoadScanCycleFragments(ctx context.Context, cycleID string) (scanner.WorkPlan, []model.Snapshot, error) {
	cycle, err := s.GetScanCycle(ctx, cycleID)
	if err != nil {
		return scanner.WorkPlan{}, nil, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT snapshot_json FROM scan_cycle_units WHERE cycle_id=? AND status='completed' ORDER BY sequence`, cycleID)
	if err != nil {
		return scanner.WorkPlan{}, nil, err
	}
	defer rows.Close()
	var fragments []model.Snapshot
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return scanner.WorkPlan{}, nil, err
		}
		var snapshot model.Snapshot
		if err = json.Unmarshal(raw, &snapshot); err != nil {
			return scanner.WorkPlan{}, nil, err
		}
		fragments = append(fragments, snapshot)
	}
	return cycle.Plan, fragments, rows.Err()
}

func trimCycleError(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) > 500 {
		return raw[:500] + "…"
	}
	return raw
}
