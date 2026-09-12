package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/google/uuid"
)

// JobRecord is the durable, web-managed representation of a scan job.
type JobRecord struct {
	ID        string
	Job       config.Job
	Enabled   bool
	Archived  bool
	Revision  int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

func marshalJob(job config.Job) ([]byte, error) { return json.Marshal(job) }

func unmarshalJob(raw []byte) (config.Job, error) {
	var job config.Job
	if err := json.Unmarshal(raw, &job); err != nil {
		return job, err
	}
	return config.NormalizeJob(job), nil
}

func scanTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	// Application writes use RFC3339Nano. SQLite defaults and older databases
	// may contain UTC timestamps without an offset, so accept those formats as
	// well while keeping all parsed values explicitly in UTC.
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
	} {
		if value, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
			return value
		}
	}
	return time.Time{}
}

func (s *Store) CreateJob(ctx context.Context, job config.Job) (JobRecord, error) {
	return s.CreateJobWithEnabled(ctx, job, true)
}

// CreateJobWithEnabled creates the initial job definition and lifecycle state
// in one transaction. Keeping a paused job disabled from its first commit
// prevents a crash window where it could be scheduled before the follow-up
// lifecycle update succeeds.
func (s *Store) CreateJobWithEnabled(ctx context.Context, job config.Job, enabled bool) (JobRecord, error) {
	return s.createJobWithAudits(ctx, job, enabled, nil)
}

// CreateJobWithEnabledAndAudit commits a new job and its security audit row in
// one transaction. The plain CreateJobWithEnabled API remains available to
// internal callers that deliberately do not need an audit entry (for example,
// deterministic fixtures).
func (s *Store) CreateJobWithEnabledAndAudit(ctx context.Context, job config.Job, enabled bool, audits ...AuditEntry) (JobRecord, error) {
	return s.createJobWithAudits(ctx, job, enabled, audits)
}

func (s *Store) createJobWithAudits(ctx context.Context, job config.Job, enabled bool, audits []AuditEntry) (JobRecord, error) {
	job = config.NormalizeJob(job)
	if err := s.validateManagedJob(job); err != nil {
		return JobRecord{}, err
	}
	raw, err := marshalJob(job)
	if err != nil {
		return JobRecord{}, err
	}
	now := time.Now().UTC()
	id := uuid.NewString()
	hash := job.SecurityHash()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return JobRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `INSERT INTO jobs(id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES(?,?,?, ?,0,1,?,?)`, id, job.Name, raw, boolInt(enabled), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return JobRecord{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO job_revisions(job_id,revision,definition_json,security_hash,created_at) VALUES(?,?,?,?,?)`, id, 1, raw, hash, now.Format(time.RFC3339Nano)); err != nil {
		return JobRecord{}, err
	}
	if err = upsertJobSilenceStateTx(ctx, tx, id, now); err != nil {
		return JobRecord{}, err
	}
	if err = insertAuditEntries(ctx, tx, audits, now); err != nil {
		return JobRecord{}, err
	}
	if err = tx.Commit(); err != nil {
		return JobRecord{}, err
	}
	return JobRecord{ID: id, Job: job, Enabled: enabled, Revision: 1, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) GetJob(ctx context.Context, id string) (JobRecord, error) {
	var r JobRecord
	var raw []byte
	var created, updated string
	var enabled, archived int
	err := s.reader().QueryRowContext(ctx, `SELECT id,name,definition_json,enabled,archived,revision,created_at,updated_at FROM jobs WHERE id=?`, id).
		Scan(&r.ID, &r.Job.Name, &raw, &enabled, &archived, &r.Revision, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return r, fmt.Errorf("%w: job %s", ErrNotFound, id)
	}
	if err != nil {
		return r, err
	}
	job, err := unmarshalJob(raw)
	if err != nil {
		return r, err
	}
	r.Job = job
	r.Enabled, r.Archived = enabled != 0, archived != 0
	r.CreatedAt, r.UpdatedAt = scanTime(created), scanTime(updated)
	return r, nil
}

// getJobTx is the transaction-safe equivalent of GetJob. Keeping the read in
// the same transaction as a write is important for optimistic concurrency and
// scan lease coordination: database/sql is configured with one connection, so
// a lease cannot slip between the revision check and the update commit.
func getJobTx(ctx context.Context, tx *sql.Tx, id string) (JobRecord, error) {
	var r JobRecord
	var raw []byte
	var created, updated string
	var enabled, archived int
	err := tx.QueryRowContext(ctx, `SELECT id,name,definition_json,enabled,archived,revision,created_at,updated_at FROM jobs WHERE id=?`, id).
		Scan(&r.ID, &r.Job.Name, &raw, &enabled, &archived, &r.Revision, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return r, fmt.Errorf("%w: job %s", ErrNotFound, id)
	}
	if err != nil {
		return r, err
	}
	job, err := unmarshalJob(raw)
	if err != nil {
		return r, err
	}
	r.Job = job
	r.Enabled, r.Archived = enabled != 0, archived != 0
	r.CreatedAt, r.UpdatedAt = scanTime(created), scanTime(updated)
	return r, nil
}

func (s *Store) GetJobByName(ctx context.Context, name string) (JobRecord, error) {
	var id string
	err := s.reader().QueryRowContext(ctx, `SELECT id FROM jobs WHERE name=?`, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return JobRecord{}, fmt.Errorf("%w: job %s", ErrNotFound, name)
	}
	if err != nil {
		return JobRecord{}, err
	}
	return s.GetJob(ctx, id)
}

func (s *Store) ListJobs(ctx context.Context, includeArchived bool) ([]JobRecord, error) {
	query := `SELECT id,name,definition_json,enabled,archived,revision,created_at,updated_at FROM jobs`
	if !includeArchived {
		query += ` WHERE archived=0`
	}
	// Keep archived jobs grouped after active and paused jobs. The web console
	// requests archived records so they can be restored, and ordering only by
	// name otherwise lets an archived job appear between active entries.
	query += ` ORDER BY archived ASC, name, id`
	rows, err := s.reader().QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JobRecord
	for rows.Next() {
		var r JobRecord
		var raw []byte
		var created, updated string
		var enabled, archived int
		if err := rows.Scan(&r.ID, &r.Job.Name, &raw, &enabled, &archived, &r.Revision, &created, &updated); err != nil {
			return nil, err
		}
		job, err := unmarshalJob(raw)
		if err != nil {
			return nil, err
		}
		r.Job = job
		r.Enabled, r.Archived = enabled != 0, archived != 0
		r.CreatedAt, r.UpdatedAt = scanTime(created), scanTime(updated)
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateJob uses optimistic concurrency. The returned bool reports whether
// the security hash changed and therefore requires rebaseline confirmation.
func (s *Store) UpdateJob(ctx context.Context, id string, expectedRevision int64, job config.Job, enabled, archived, confirmRebaseline bool) (JobRecord, bool, error) {
	record, changed, _, err := s.UpdateJobWithEvents(ctx, id, expectedRevision, job, enabled, archived, confirmRebaseline)
	return record, changed, err
}

// UpdateJobWithEvents updates a managed job and, when its security scope
// changes, clears its runtime comparison state in the same transaction. The
// returned events are already persisted atomically with the new revision; the
// web layer can queue notifications and publish them after the commit.
func (s *Store) UpdateJobWithEvents(ctx context.Context, id string, expectedRevision int64, job config.Job, enabled, archived, confirmRebaseline bool) (JobRecord, bool, []model.Event, error) {
	return s.UpdateJobWithEventsWithOutbox(ctx, id, expectedRevision, job, enabled, archived, confirmRebaseline, nil)
}

// UpdateJobWithEventsWithOutbox also persists notification intent for the
// security-scope reset event. Destination revisions are validated while the
// job transaction is open, so a concurrent credential edit cannot leave an
// orphaned delivery.
func (s *Store) UpdateJobWithEventsWithOutbox(ctx context.Context, id string, expectedRevision int64, job config.Job, enabled, archived, confirmRebaseline bool, destinations []string) (JobRecord, bool, []model.Event, error) {
	return s.UpdateJobWithEventsWithOutboxAndAudit(ctx, id, expectedRevision, job, enabled, archived, confirmRebaseline, destinations)
}

// UpdateJobWithEventsWithOutboxAndAudit extends the job revision transaction
// with one or more audit rows. If an audit insert fails, the revision, runtime
// reset, event, and outbox intent all roll back together.
func (s *Store) UpdateJobWithEventsWithOutboxAndAudit(ctx context.Context, id string, expectedRevision int64, job config.Job, enabled, archived, confirmRebaseline bool, destinations []string, audits ...AuditEntry) (JobRecord, bool, []model.Event, error) {
	job = config.NormalizeJob(job)
	if err := s.validateManagedJob(job); err != nil {
		return JobRecord{}, false, nil, err
	}
	// Archived jobs are never schedulable, regardless of what a stale or
	// hand-crafted request places in the enabled field.
	if archived {
		enabled = false
	}
	raw, err := marshalJob(job)
	if err != nil {
		return JobRecord{}, false, nil, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return JobRecord{}, false, nil, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := getJobTx(ctx, tx, id)
	if err != nil {
		return JobRecord{}, false, nil, err
	}
	if expectedRevision != current.Revision {
		return JobRecord{}, false, nil, ErrConflict
	}
	scopeChanged := current.Job.SecurityHash() != job.SecurityHash()
	if scopeChanged {
		active, activeErr := jobActiveTx(ctx, tx, id, time.Now().UTC())
		if activeErr != nil {
			return JobRecord{}, false, nil, activeErr
		}
		if active {
			return JobRecord{}, false, nil, ErrJobScanActive
		}
		if !confirmRebaseline {
			return current, true, nil, ErrRebaselineRequired
		}
	}
	now := time.Now().UTC()
	next := current.Revision + 1
	result, err := tx.ExecContext(ctx, `UPDATE jobs SET name=?,definition_json=?,enabled=?,archived=?,revision=?,updated_at=? WHERE id=? AND revision=?`, job.Name, raw, boolInt(enabled), boolInt(archived), next, now.Format(time.RFC3339Nano), id, expectedRevision)
	if err != nil {
		return JobRecord{}, false, nil, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return JobRecord{}, false, nil, ErrConflict
	}
	if err = appendJobRevisionTx(ctx, tx, id, next, raw, job.SecurityHash(), now); err != nil {
		return JobRecord{}, false, nil, err
	}
	var events []model.Event
	if scopeChanged {
		stateRaw, marshalErr := json.Marshal(emptyState())
		if marshalErr != nil {
			return JobRecord{}, false, nil, marshalErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?) ON CONFLICT(job_id) DO UPDATE SET state_json=excluded.state_json,updated_at=excluded.updated_at`, id, stateRaw, now.Format(time.RFC3339Nano)); err != nil {
			return JobRecord{}, false, nil, err
		}
		// The indexed baseline overlay belongs to the previous security scope.
		// Clear it in the same transaction as the runtime reset so a concurrent
		// host request cannot observe old expected hosts after the new revision
		// has been committed.
		if err = clearBaselineHostProjectionTx(ctx, tx, id); err != nil {
			return JobRecord{}, false, nil, err
		}
		event := model.Event{Type: "baseline-reset", JobID: id, Job: job.Name, Message: "Baseline collection reset", CreatedAt: now}
		boundedEvent, eventRaw, marshalErr := model.MarshalBoundedEvent(event, model.EventPayloadLimit)
		if marshalErr != nil {
			return JobRecord{}, false, nil, marshalErr
		}
		event = boundedEvent
		if _, err = tx.ExecContext(ctx, `INSERT INTO events(type,job,job_id,scan_id,payload_json,created_at) VALUES(?,?,?,?,?,?)`, event.Type, event.Job, event.JobID, event.ScanID, eventRaw, now.Format(time.RFC3339Nano)); err != nil {
			return JobRecord{}, false, nil, err
		}
		events = append(events, event)
		// A paused/stalled resumable cycle belongs to the previous security
		// scope. Discard its checkpoints atomically with the rebaseline reset so
		// a later trigger cannot merge old work into the new baseline.
		if _, err = tx.ExecContext(ctx, `UPDATE scan_cycles SET status='discarded',updated_at=?,finished_at=?,last_error='security scope changed' WHERE job_id=? AND status IN ('running','paused','stalled')`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), id); err != nil {
			return JobRecord{}, false, nil, err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM scan_cycle_units WHERE cycle_id IN (SELECT id FROM scan_cycles WHERE job_id=? AND status='discarded' AND finished_at=?)`, id, now.Format(time.RFC3339Nano)); err != nil {
			return JobRecord{}, false, nil, err
		}
	}
	if err = queueEventsTx(ctx, tx, events, destinations); err != nil {
		return JobRecord{}, false, nil, err
	}
	if err = insertAuditEntries(ctx, tx, audits, now); err != nil {
		return JobRecord{}, false, nil, err
	}
	if current.Enabled != enabled || current.Archived != archived {
		if err = updateJobSilenceLifecycleTx(ctx, tx, id, current.Enabled, current.Archived, enabled, archived, now); err != nil {
			return JobRecord{}, false, nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return JobRecord{}, false, nil, err
	}
	return JobRecord{ID: id, Job: job, Enabled: enabled, Archived: archived, Revision: next, CreatedAt: current.CreatedAt, UpdatedAt: now}, scopeChanged, events, nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (s *Store) SetJobArchived(ctx context.Context, id string, archived bool) error {
	return s.setJobArchived(ctx, id, archived, nil, nil)
}

// SetJobArchivedWithRevision applies an archive or restore transition only
// when the caller still holds the current immutable job revision. Lifecycle
// actions are state mutations too, so stale browser views must not silently
// overwrite a newer edit.
func (s *Store) SetJobArchivedWithRevision(ctx context.Context, id string, archived bool, expectedRevision int64) error {
	return s.setJobArchived(ctx, id, archived, &expectedRevision, nil)
}

// SetJobArchivedWithRevisionAndAudit applies the lifecycle transition and its
// audit row atomically. It is used by the web administrator path so a failed
// audit write cannot leave an unrecorded archive/restore.
func (s *Store) SetJobArchivedWithRevisionAndAudit(ctx context.Context, id string, archived bool, expectedRevision int64, audit AuditEntry) error {
	return s.setJobArchived(ctx, id, archived, &expectedRevision, []AuditEntry{audit})
}

func (s *Store) setJobArchived(ctx context.Context, id string, archived bool, expectedRevision *int64, audits []AuditEntry) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := getJobTx(ctx, tx, id)
	if err != nil {
		return err
	}
	if expectedRevision != nil && current.Revision != *expectedRevision {
		return ErrConflict
	}
	if current.Archived == archived {
		if err := insertAuditEntries(ctx, tx, audits, time.Now().UTC()); err != nil {
			return err
		}
		return tx.Commit()
	}
	now := time.Now().UTC()
	next := current.Revision + 1
	enabled := current.Enabled
	if archived {
		enabled = false
	}
	result, err := tx.ExecContext(ctx, `UPDATE jobs SET archived=?,enabled=?,revision=?,updated_at=? WHERE id=? AND revision=?`, boolInt(archived), boolInt(enabled), next, now.Format(time.RFC3339Nano), id, current.Revision)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrConflict
	}
	raw, err := marshalJob(current.Job)
	if err != nil {
		return err
	}
	if err := appendJobRevisionTx(ctx, tx, id, next, raw, current.Job.SecurityHash(), now); err != nil {
		return err
	}
	if err := updateJobSilenceLifecycleTx(ctx, tx, id, current.Enabled, current.Archived, enabled, archived, now); err != nil {
		return err
	}
	if err := insertAuditEntries(ctx, tx, audits, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetJobEnabled(ctx context.Context, id string, enabled bool) error {
	return s.setJobEnabled(ctx, id, enabled, nil, nil)
}

// SetJobEnabledWithRevision applies a pause or resume transition only when
// the caller still holds the current immutable job revision.
func (s *Store) SetJobEnabledWithRevision(ctx context.Context, id string, enabled bool, expectedRevision int64) error {
	return s.setJobEnabled(ctx, id, enabled, &expectedRevision, nil)
}

// SetJobEnabledWithRevisionAndAudit applies a pause/resume transition and its
// audit row in one transaction.
func (s *Store) SetJobEnabledWithRevisionAndAudit(ctx context.Context, id string, enabled bool, expectedRevision int64, audit AuditEntry) error {
	return s.setJobEnabled(ctx, id, enabled, &expectedRevision, []AuditEntry{audit})
}

func (s *Store) setJobEnabled(ctx context.Context, id string, enabled bool, expectedRevision *int64, audits []AuditEntry) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := getJobTx(ctx, tx, id)
	if err != nil {
		return err
	}
	if expectedRevision != nil && current.Revision != *expectedRevision {
		return ErrConflict
	}
	if current.Archived {
		return fmt.Errorf("%w: job %s", ErrNotFound, id)
	}
	if current.Enabled == enabled {
		if err := insertAuditEntries(ctx, tx, audits, time.Now().UTC()); err != nil {
			return err
		}
		return tx.Commit()
	}
	now := time.Now().UTC()
	next := current.Revision + 1
	result, err := tx.ExecContext(ctx, `UPDATE jobs SET enabled=?,revision=?,updated_at=? WHERE id=? AND revision=? AND archived=0`, boolInt(enabled), next, now.Format(time.RFC3339Nano), id, current.Revision)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrConflict
	}
	raw, err := marshalJob(current.Job)
	if err != nil {
		return err
	}
	if err := appendJobRevisionTx(ctx, tx, id, next, raw, current.Job.SecurityHash(), now); err != nil {
		return err
	}
	if err := updateJobSilenceLifecycleTx(ctx, tx, id, current.Enabled, current.Archived, enabled, current.Archived, now); err != nil {
		return err
	}
	if err := insertAuditEntries(ctx, tx, audits, now); err != nil {
		return err
	}
	return tx.Commit()
}

func upsertJobSilenceStateTx(ctx context.Context, tx *sql.Tx, jobID string, now time.Time) error {
	stamp := now.UTC().Format(time.RFC3339Nano)
	_, err := tx.ExecContext(ctx, `INSERT INTO job_silence_state(job_id,eligible_at,updated_at) VALUES(?,?,?) ON CONFLICT(job_id) DO NOTHING`, jobID, stamp, stamp)
	return err
}

func updateJobSilenceLifecycleTx(ctx context.Context, tx *sql.Tx, jobID string, wasEnabled, wasArchived, enabled, archived bool, now time.Time) error {
	if err := upsertJobSilenceStateTx(ctx, tx, jobID, now); err != nil {
		return err
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	// A newly enabled/restored job gets a fresh eligibility grace period. A
	// pause/archive clears a pending alert, but does not delete history.
	if enabled && !archived && (!wasEnabled || wasArchived) {
		_, err := tx.ExecContext(ctx, `UPDATE job_silence_state SET eligible_at=?,next_alert_at='',backoff_level=0,updated_at=? WHERE job_id=?`, stamp, stamp, jobID)
		return err
	}
	if !enabled || archived {
		_, err := tx.ExecContext(ctx, `UPDATE job_silence_state SET next_alert_at='',updated_at=? WHERE job_id=?`, stamp, jobID)
		return err
	}
	return nil
}

func appendJobRevisionTx(ctx context.Context, tx *sql.Tx, jobID string, revision int64, raw []byte, securityHash string, createdAt time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO job_revisions(job_id,revision,definition_json,security_hash,created_at) VALUES(?,?,?,?,?)`, jobID, revision, raw, securityHash, createdAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) DeleteJob(ctx context.Context, id string) error {
	return s.deleteJobWithAudits(ctx, id, nil)
}

// DeleteJobWithAudit permanently removes an archived job only when the audit
// row can be committed in the same transaction. The audit row intentionally
// survives the job deletion as part of the append-only security history.
func (s *Store) DeleteJobWithAudit(ctx context.Context, id string, audit AuditEntry) error {
	return s.deleteJobWithAudits(ctx, id, []AuditEntry{audit})
}

func (s *Store) deleteJobWithAudits(ctx context.Context, id string, audits []AuditEntry) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	record, err := getJobTx(ctx, tx, id)
	if err != nil {
		return err
	}
	if !record.Archived {
		return errors.New("job must be archived before permanent deletion")
	}
	active, err := jobActiveTx(ctx, tx, id, time.Now().UTC())
	if err != nil {
		return err
	}
	if active {
		return ErrJobScanActive
	}
	var scans int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE job_id=?`, id).Scan(&scans); err != nil {
		return err
	}
	if scans > 0 {
		return errors.New("job has retained scan history; archive it instead")
	}
	var events int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE job_id=?`, id).Scan(&events); err != nil {
		return err
	}
	if events > 0 {
		return errors.New("job has retained event history; archive it instead")
	}
	var cycles int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_cycles WHERE job_id=?`, id).Scan(&cycles); err != nil {
		return err
	}
	if cycles > 0 {
		return errors.New("job has retained scan-cycle history; archive it instead")
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM jobs WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: job %s", ErrNotFound, id)
	}
	if err := insertAuditEntries(ctx, tx, audits, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) JobActive(ctx context.Context, id string) (bool, error) {
	var n int
	err := s.reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM job_leases WHERE job=? AND expires_at>?`, id, time.Now().UTC().Format(time.RFC3339Nano)).Scan(&n)
	return n > 0, err
}

func jobActiveTx(ctx context.Context, tx *sql.Tx, id string, now time.Time) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_leases WHERE job=? AND expires_at>?`, id, now.UTC().Format(time.RFC3339Nano)).Scan(&n)
	return n > 0, err
}
