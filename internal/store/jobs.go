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
	// TenantID is the tenant that owns the job. It is never serialized, so
	// API responses keep their shape.
	TenantID string `json:"-"`
}

func marshalJob(job config.Job) ([]byte, error) { return json.Marshal(job) }

func unmarshalJob(raw []byte) (config.Job, error) {
	var job config.Job
	if err := json.Unmarshal(raw, &job); err != nil {
		return job, err
	}
	return config.NormalizeStoredJob(job), nil
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

// CreateJob creates an enabled job.
//
// Deprecated: bound to DefaultTenantScope. Use TenantStore.CreateJob.
func (s *Store) CreateJob(ctx context.Context, job config.Job) (JobRecord, error) {
	return s.Tenant(DefaultTenantScope()).CreateJob(ctx, job)
}

// CreateJob creates an enabled job in the tenant.
func (ts *TenantStore) CreateJob(ctx context.Context, job config.Job) (JobRecord, error) {
	return ts.CreateJobWithEnabled(ctx, job, true)
}

// CreateJobWithEnabled creates a job with the given lifecycle state.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.CreateJobWithEnabled.
func (s *Store) CreateJobWithEnabled(ctx context.Context, job config.Job, enabled bool) (JobRecord, error) {
	return s.Tenant(DefaultTenantScope()).CreateJobWithEnabled(ctx, job, enabled)
}

// CreateJobWithEnabled creates the initial job definition and lifecycle state
// in one transaction. Keeping a paused job disabled from its first commit
// prevents a crash window where it could be scheduled before the follow-up
// lifecycle update succeeds.
func (ts *TenantStore) CreateJobWithEnabled(ctx context.Context, job config.Job, enabled bool) (JobRecord, error) {
	return ts.createJobWithAudits(ctx, job, enabled, nil)
}

// CreateJobWithEnabledAndAudit creates a job and its audit rows.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.CreateJobWithEnabledAndAudit.
func (s *Store) CreateJobWithEnabledAndAudit(ctx context.Context, job config.Job, enabled bool, audits ...AuditEntry) (JobRecord, error) {
	return s.Tenant(DefaultTenantScope()).CreateJobWithEnabledAndAudit(ctx, job, enabled, audits...)
}

// CreateJobWithEnabledAndAudit commits a new job and its security audit row in
// one transaction. The plain CreateJobWithEnabled API remains available to
// internal callers that deliberately do not need an audit entry (for example,
// deterministic fixtures).
func (ts *TenantStore) CreateJobWithEnabledAndAudit(ctx context.Context, job config.Job, enabled bool, audits ...AuditEntry) (JobRecord, error) {
	return ts.createJobWithAudits(ctx, job, enabled, audits)
}

// createJobWithAudits creates the job in the store's tenant. Job names are
// unique per tenant, so another tenant may already use the name.
func (ts *TenantStore) createJobWithAudits(ctx context.Context, job config.Job, enabled bool, audits []AuditEntry) (JobRecord, error) {
	if err := ts.ready(); err != nil {
		return JobRecord{}, err
	}
	job = config.NormalizeJob(job)
	if err := ts.store.validateManagedJob(job); err != nil {
		return JobRecord{}, err
	}
	raw, err := marshalJob(job)
	if err != nil {
		return JobRecord{}, err
	}
	now := time.Now().UTC()
	id := uuid.NewString()
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return JobRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `INSERT INTO jobs(id,tenant_id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES(?,?,?,?, ?,0,1,?,?)`, id, ts.scope.id, job.Name, raw, boolInt(enabled), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return JobRecord{}, err
	}
	if err = appendJobRevisionTx(ctx, tx, id, 1, raw, job.SecurityHash(), now); err != nil {
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
	return JobRecord{ID: id, TenantID: ts.scope.id, Job: job, Enabled: enabled, Revision: 1, CreatedAt: now, UpdatedAt: now}, nil
}

// GetJob returns the job with the given ID.
//
// Deprecated: bound to DefaultTenantScope. Use TenantStore.GetJob.
func (s *Store) GetJob(ctx context.Context, id string) (JobRecord, error) {
	return s.Tenant(DefaultTenantScope()).GetJob(ctx, id)
}

// GetJob returns the tenant's job with the given ID. A job of another tenant
// is ErrNotFound.
func (ts *TenantStore) GetJob(ctx context.Context, id string) (JobRecord, error) {
	if err := ts.ready(); err != nil {
		return JobRecord{}, err
	}
	return scanJobRecord(ts.store.reader().QueryRowContext(ctx, `SELECT `+jobRecordColumns+` FROM jobs WHERE id=? AND tenant_id=?`, id, ts.scope.id), id)
}

// jobRecordColumns are the jobs columns that scanJobRecord reads, in order.
const jobRecordColumns = `id,tenant_id,name,definition_json,enabled,archived,revision,created_at,updated_at`

// scanJobRecord reads one row of jobRecordColumns. A missing row is
// ErrNotFound for the job id.
func scanJobRecord(row interface{ Scan(...any) error }, id string) (JobRecord, error) {
	var r JobRecord
	var raw []byte
	var created, updated string
	var enabled, archived int
	err := row.Scan(&r.ID, &r.TenantID, &r.Job.Name, &raw, &enabled, &archived, &r.Revision, &created, &updated)
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

// getTenantJobTx is the transaction-safe equivalent of TenantStore.GetJob: a
// job of another tenant is ErrNotFound. Keeping the read in the same
// transaction as a write is important for optimistic concurrency and scan
// lease coordination: database/sql is configured with one connection, so a
// lease cannot slip between the revision check and the update commit. Once
// a write has found the job here, it may change the job's child rows by job
// ID in the same transaction.
func getTenantJobTx(ctx context.Context, tx *sql.Tx, scope TenantScope, id string) (JobRecord, error) {
	return scanJobRecord(tx.QueryRowContext(ctx, `SELECT `+jobRecordColumns+` FROM jobs WHERE id=? AND tenant_id=?`, id, scope.id), id)
}

// getJobTx reads a job of any tenant on the caller's transaction. Only the
// runtime and incident writes that are still Store methods use it, and they
// act on any tenant's job until they move to TenantStore; each then calls
// getTenantJobTx with its scope instead. TenantStore methods never call it.
func getJobTx(ctx context.Context, tx *sql.Tx, id string) (JobRecord, error) {
	return scanJobRecord(tx.QueryRowContext(ctx, `SELECT `+jobRecordColumns+` FROM jobs WHERE id=?`, id), id)
}

// GetJobByName returns the job with the given name.
//
// Deprecated: bound to DefaultTenantScope. Use TenantStore.GetJobByName.
func (s *Store) GetJobByName(ctx context.Context, name string) (JobRecord, error) {
	return s.Tenant(DefaultTenantScope()).GetJobByName(ctx, name)
}

// GetJobByName returns the tenant's job with the given name. Job names are
// unique per tenant, so another tenant's job with the same name is never
// returned.
func (ts *TenantStore) GetJobByName(ctx context.Context, name string) (JobRecord, error) {
	if err := ts.ready(); err != nil {
		return JobRecord{}, err
	}
	var id string
	err := ts.store.reader().QueryRowContext(ctx, `SELECT id FROM jobs WHERE tenant_id=? AND name=?`, ts.scope.id, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return JobRecord{}, fmt.Errorf("%w: job %s", ErrNotFound, name)
	}
	if err != nil {
		return JobRecord{}, err
	}
	return ts.GetJob(ctx, id)
}

// ListJobs returns the jobs, without archived jobs unless includeArchived is
// set.
//
// Deprecated: bound to DefaultTenantScope. Use TenantStore.ListJobs.
func (s *Store) ListJobs(ctx context.Context, includeArchived bool) ([]JobRecord, error) {
	return s.Tenant(DefaultTenantScope()).ListJobs(ctx, includeArchived)
}

// ListJobs returns the tenant's jobs, without archived jobs unless
// includeArchived is set.
func (ts *TenantStore) ListJobs(ctx context.Context, includeArchived bool) ([]JobRecord, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	query := `SELECT ` + jobRecordColumns + ` FROM jobs WHERE tenant_id=?`
	if !includeArchived {
		query += ` AND archived=0`
	}
	// Keep archived jobs grouped after active and paused jobs. The web console
	// requests archived records so they can be restored, and ordering only by
	// name otherwise lets an archived job appear between active entries.
	query += ` ORDER BY archived ASC, name, id`
	rows, err := ts.store.reader().QueryContext(ctx, query, ts.scope.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JobRecord
	for rows.Next() {
		r, err := scanJobRecord(rows, "")
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateJob updates a job.
//
// Deprecated: bound to DefaultTenantScope. Use TenantStore.UpdateJob.
func (s *Store) UpdateJob(ctx context.Context, id string, expectedRevision int64, job config.Job, enabled, archived, confirmRebaseline bool) (JobRecord, bool, error) {
	return s.Tenant(DefaultTenantScope()).UpdateJob(ctx, id, expectedRevision, job, enabled, archived, confirmRebaseline)
}

// UpdateJob uses optimistic concurrency. The returned bool reports whether
// the security hash changed and therefore requires rebaseline confirmation.
func (ts *TenantStore) UpdateJob(ctx context.Context, id string, expectedRevision int64, job config.Job, enabled, archived, confirmRebaseline bool) (JobRecord, bool, error) {
	record, changed, _, err := ts.UpdateJobWithEvents(ctx, id, expectedRevision, job, enabled, archived, confirmRebaseline)
	return record, changed, err
}

// UpdateJobWithEvents updates a job and returns its persisted events.
//
// Deprecated: bound to DefaultTenantScope. Use TenantStore.UpdateJobWithEvents.
func (s *Store) UpdateJobWithEvents(ctx context.Context, id string, expectedRevision int64, job config.Job, enabled, archived, confirmRebaseline bool) (JobRecord, bool, []model.Event, error) {
	return s.Tenant(DefaultTenantScope()).UpdateJobWithEvents(ctx, id, expectedRevision, job, enabled, archived, confirmRebaseline)
}

// UpdateJobWithEvents updates a managed job and, when its security scope
// changes, clears its runtime comparison state in the same transaction. The
// returned events are already persisted atomically with the new revision; the
// web layer can queue notifications and publish them after the commit.
func (ts *TenantStore) UpdateJobWithEvents(ctx context.Context, id string, expectedRevision int64, job config.Job, enabled, archived, confirmRebaseline bool) (JobRecord, bool, []model.Event, error) {
	return ts.UpdateJobWithEventsWithOutbox(ctx, id, expectedRevision, job, enabled, archived, confirmRebaseline, nil)
}

// UpdateJobWithEventsWithOutbox updates a job and queues its events.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.UpdateJobWithEventsWithOutbox.
func (s *Store) UpdateJobWithEventsWithOutbox(ctx context.Context, id string, expectedRevision int64, job config.Job, enabled, archived, confirmRebaseline bool, destinations []string) (JobRecord, bool, []model.Event, error) {
	return s.Tenant(DefaultTenantScope()).UpdateJobWithEventsWithOutbox(ctx, id, expectedRevision, job, enabled, archived, confirmRebaseline, destinations)
}

// UpdateJobWithEventsWithOutbox also persists notification intent for the
// security-scope reset event. Destination revisions are validated while the
// job transaction is open, so a concurrent credential edit cannot leave an
// orphaned delivery.
func (ts *TenantStore) UpdateJobWithEventsWithOutbox(ctx context.Context, id string, expectedRevision int64, job config.Job, enabled, archived, confirmRebaseline bool, destinations []string) (JobRecord, bool, []model.Event, error) {
	return ts.UpdateJobWithEventsWithOutboxAndAudit(ctx, id, expectedRevision, job, enabled, archived, confirmRebaseline, destinations)
}

// UpdateJobWithEventsWithOutboxAndAudit updates a job with its events,
// notification intent, and audit rows.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.UpdateJobWithEventsWithOutboxAndAudit.
func (s *Store) UpdateJobWithEventsWithOutboxAndAudit(ctx context.Context, id string, expectedRevision int64, job config.Job, enabled, archived, confirmRebaseline bool, destinations []string, audits ...AuditEntry) (JobRecord, bool, []model.Event, error) {
	return s.Tenant(DefaultTenantScope()).UpdateJobWithEventsWithOutboxAndAudit(ctx, id, expectedRevision, job, enabled, archived, confirmRebaseline, destinations, audits...)
}

// UpdateJobWithEventsWithOutboxAndAudit extends the job revision transaction
// with one or more audit rows. If an audit insert fails, the revision, runtime
// reset, event, and outbox intent all roll back together. A job of another
// tenant is ErrNotFound.
func (ts *TenantStore) UpdateJobWithEventsWithOutboxAndAudit(ctx context.Context, id string, expectedRevision int64, job config.Job, enabled, archived, confirmRebaseline bool, destinations []string, audits ...AuditEntry) (JobRecord, bool, []model.Event, error) {
	if err := ts.ready(); err != nil {
		return JobRecord{}, false, nil, err
	}
	job = config.NormalizeJob(job)
	if err := ts.store.validateManagedJob(job); err != nil {
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
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return JobRecord{}, false, nil, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := getTenantJobTx(ctx, tx, ts.scope, id)
	if err != nil {
		return JobRecord{}, false, nil, err
	}
	if expectedRevision != current.Revision {
		return JobRecord{}, false, nil, ErrConflict
	}
	scopeChanged := current.Job.SecurityHash() != job.SecurityHash()
	lifecycleChanged := current.Enabled != enabled || current.Archived != archived
	if scopeChanged || lifecycleChanged {
		active, activeErr := jobActiveTx(ctx, tx, id, time.Now().UTC())
		if activeErr != nil {
			return JobRecord{}, false, nil, activeErr
		}
		if active {
			return JobRecord{}, false, nil, ErrJobScanActive
		}
		if scopeChanged && !confirmRebaseline {
			return current, true, nil, ErrRebaselineRequired
		}
	}
	if !scopeChanged && current.Job.LegacySecurityHash() != "" {
		if err := migrateLegacyScopeHashTx(ctx, tx, id, current.Job.LegacySecurityHash(), job.SecurityHash()); err != nil {
			return JobRecord{}, false, nil, err
		}
	}
	now := time.Now().UTC()
	next := current.Revision + 1
	result, err := tx.ExecContext(ctx, `UPDATE jobs SET name=?,definition_json=?,enabled=?,archived=?,revision=?,updated_at=? WHERE id=? AND tenant_id=? AND revision=?`, job.Name, raw, boolInt(enabled), boolInt(archived), next, now.Format(time.RFC3339Nano), id, ts.scope.id, expectedRevision)
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
		reset := emptyState()
		stateRaw, marshalErr := json.Marshal(reset)
		if marshalErr != nil {
			return JobRecord{}, false, nil, marshalErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) SELECT id,?,? FROM jobs WHERE id=? AND tenant_id=? ON CONFLICT(job_id) DO UPDATE SET state_json=excluded.state_json,updated_at=excluded.updated_at`, stateRaw, sqliteTimestamp(now), id, ts.scope.id); err != nil {
			return JobRecord{}, false, nil, err
		}
		if err = upsertRuntimeBaselineMetaTx(ctx, tx, id, reset, 0, now); err != nil {
			return JobRecord{}, false, nil, err
		}
		// Incident pages and counts read this projection. Rebuild it from the
		// reset state so they cannot show the previous scope's incidents.
		if err = replaceRuntimeIncidentProjectionTx(ctx, tx, id, reset); err != nil {
			return JobRecord{}, false, nil, err
		}
		if err = bumpRuntimeBaselineEpochTx(ctx, tx, id); err != nil {
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
		if err = insertEventExec(ctx, tx, event, eventRaw, now); err != nil {
			return JobRecord{}, false, nil, err
		}
		events = append(events, event)
		// A resumable cycle belongs to the previous security scope. Discard its
		// checkpoints atomically with the rebaseline reset so a later trigger
		// cannot merge old work into the new baseline.
		if err = discardUnpromotedCyclesTx(ctx, tx, id, "security scope changed", now); err != nil {
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
	return JobRecord{ID: id, TenantID: current.TenantID, Job: job, Enabled: enabled, Archived: archived, Revision: next, CreatedAt: current.CreatedAt, UpdatedAt: now}, scopeChanged, events, nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// SetJobArchived archives or restores a job.
//
// Deprecated: bound to DefaultTenantScope. Use TenantStore.SetJobArchived.
func (s *Store) SetJobArchived(ctx context.Context, id string, archived bool) error {
	return s.Tenant(DefaultTenantScope()).SetJobArchived(ctx, id, archived)
}

// SetJobArchived archives or restores the tenant's job, whatever its
// revision. A job of another tenant is ErrNotFound.
func (ts *TenantStore) SetJobArchived(ctx context.Context, id string, archived bool) error {
	return ts.setJobArchived(ctx, id, archived, nil, nil)
}

// SetJobArchivedWithRevision archives or restores a job at a revision.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.SetJobArchivedWithRevision.
func (s *Store) SetJobArchivedWithRevision(ctx context.Context, id string, archived bool, expectedRevision int64) error {
	return s.Tenant(DefaultTenantScope()).SetJobArchivedWithRevision(ctx, id, archived, expectedRevision)
}

// SetJobArchivedWithRevision applies an archive or restore transition only
// when the caller still holds the current immutable job revision. Lifecycle
// actions are state mutations too, so stale browser views must not silently
// overwrite a newer edit.
func (ts *TenantStore) SetJobArchivedWithRevision(ctx context.Context, id string, archived bool, expectedRevision int64) error {
	return ts.setJobArchived(ctx, id, archived, &expectedRevision, nil)
}

// SetJobArchivedWithRevisionAndAudit archives or restores a job at a
// revision, with its audit row.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.SetJobArchivedWithRevisionAndAudit.
func (s *Store) SetJobArchivedWithRevisionAndAudit(ctx context.Context, id string, archived bool, expectedRevision int64, audit AuditEntry) error {
	return s.Tenant(DefaultTenantScope()).SetJobArchivedWithRevisionAndAudit(ctx, id, archived, expectedRevision, audit)
}

// SetJobArchivedWithRevisionAndAudit applies the lifecycle transition and its
// audit row atomically. It is used by the web administrator path so a failed
// audit write cannot leave an unrecorded archive/restore.
func (ts *TenantStore) SetJobArchivedWithRevisionAndAudit(ctx context.Context, id string, archived bool, expectedRevision int64, audit AuditEntry) error {
	return ts.setJobArchived(ctx, id, archived, &expectedRevision, []AuditEntry{audit})
}

func (ts *TenantStore) setJobArchived(ctx context.Context, id string, archived bool, expectedRevision *int64, audits []AuditEntry) error {
	if err := ts.ready(); err != nil {
		return err
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := getTenantJobTx(ctx, tx, ts.scope, id)
	if err != nil {
		return err
	}
	if expectedRevision != nil && current.Revision != *expectedRevision {
		return ErrConflict
	}
	// Lifecycle transitions are serialized with scans through the same durable
	// job lease used by the scanner. Rejecting archive/restore while a scan is
	// active prevents a running revision from finalizing after the UI says that
	// the job is no longer active.
	if current.Archived != archived {
		active, activeErr := jobActiveTx(ctx, tx, id, time.Now().UTC())
		if activeErr != nil {
			return activeErr
		}
		if active {
			return ErrJobScanActive
		}
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
	result, err := tx.ExecContext(ctx, `UPDATE jobs SET archived=?,enabled=?,revision=?,updated_at=? WHERE id=? AND tenant_id=? AND revision=?`, boolInt(archived), boolInt(enabled), next, now.Format(time.RFC3339Nano), id, ts.scope.id, current.Revision)
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

// SetJobEnabled pauses or resumes a job.
//
// Deprecated: bound to DefaultTenantScope. Use TenantStore.SetJobEnabled.
func (s *Store) SetJobEnabled(ctx context.Context, id string, enabled bool) error {
	return s.Tenant(DefaultTenantScope()).SetJobEnabled(ctx, id, enabled)
}

// SetJobEnabled pauses or resumes the tenant's job, whatever its revision. A
// job of another tenant is ErrNotFound.
func (ts *TenantStore) SetJobEnabled(ctx context.Context, id string, enabled bool) error {
	return ts.setJobEnabled(ctx, id, enabled, nil, nil)
}

// SetJobEnabledWithRevision pauses or resumes a job at a revision.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.SetJobEnabledWithRevision.
func (s *Store) SetJobEnabledWithRevision(ctx context.Context, id string, enabled bool, expectedRevision int64) error {
	return s.Tenant(DefaultTenantScope()).SetJobEnabledWithRevision(ctx, id, enabled, expectedRevision)
}

// SetJobEnabledWithRevision applies a pause or resume transition only when
// the caller still holds the current immutable job revision.
func (ts *TenantStore) SetJobEnabledWithRevision(ctx context.Context, id string, enabled bool, expectedRevision int64) error {
	return ts.setJobEnabled(ctx, id, enabled, &expectedRevision, nil)
}

// SetJobEnabledWithRevisionAndAudit pauses or resumes a job at a revision,
// with its audit row.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.SetJobEnabledWithRevisionAndAudit.
func (s *Store) SetJobEnabledWithRevisionAndAudit(ctx context.Context, id string, enabled bool, expectedRevision int64, audit AuditEntry) error {
	return s.Tenant(DefaultTenantScope()).SetJobEnabledWithRevisionAndAudit(ctx, id, enabled, expectedRevision, audit)
}

// SetJobEnabledWithRevisionAndAudit applies a pause/resume transition and its
// audit row in one transaction.
func (ts *TenantStore) SetJobEnabledWithRevisionAndAudit(ctx context.Context, id string, enabled bool, expectedRevision int64, audit AuditEntry) error {
	return ts.setJobEnabled(ctx, id, enabled, &expectedRevision, []AuditEntry{audit})
}

func (ts *TenantStore) setJobEnabled(ctx context.Context, id string, enabled bool, expectedRevision *int64, audits []AuditEntry) error {
	if err := ts.ready(); err != nil {
		return err
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := getTenantJobTx(ctx, tx, ts.scope, id)
	if err != nil {
		return err
	}
	if expectedRevision != nil && current.Revision != *expectedRevision {
		return ErrConflict
	}
	if current.Archived {
		return fmt.Errorf("%w: job %s", ErrNotFound, id)
	}
	// Pausing or resuming changes the lifecycle revision. Do not let a running
	// scan finish against a state that has already been presented as paused;
	// the caller can retry once the lease is released.
	if current.Enabled != enabled {
		active, activeErr := jobActiveTx(ctx, tx, id, time.Now().UTC())
		if activeErr != nil {
			return activeErr
		}
		if active {
			return ErrJobScanActive
		}
	}
	if current.Enabled == enabled {
		if err := insertAuditEntries(ctx, tx, audits, time.Now().UTC()); err != nil {
			return err
		}
		return tx.Commit()
	}
	now := time.Now().UTC()
	next := current.Revision + 1
	result, err := tx.ExecContext(ctx, `UPDATE jobs SET enabled=?,revision=?,updated_at=? WHERE id=? AND tenant_id=? AND revision=? AND archived=0`, boolInt(enabled), next, now.Format(time.RFC3339Nano), id, ts.scope.id, current.Revision)
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

// DeleteJob permanently removes an archived job.
//
// Deprecated: bound to DefaultTenantScope. Use TenantStore.DeleteJob.
func (s *Store) DeleteJob(ctx context.Context, id string) error {
	return s.Tenant(DefaultTenantScope()).DeleteJob(ctx, id)
}

// DeleteJob permanently removes the tenant's archived job. A job of another
// tenant is ErrNotFound.
func (ts *TenantStore) DeleteJob(ctx context.Context, id string) error {
	return ts.deleteJobWithAudits(ctx, id, nil)
}

// DeleteJobWithAudit permanently removes an archived job with its audit row.
//
// Deprecated: bound to DefaultTenantScope. Use TenantStore.DeleteJobWithAudit.
func (s *Store) DeleteJobWithAudit(ctx context.Context, id string, audit AuditEntry) error {
	return s.Tenant(DefaultTenantScope()).DeleteJobWithAudit(ctx, id, audit)
}

// DeleteJobWithAudit permanently removes an archived job only when the audit
// row can be committed in the same transaction. The audit row intentionally
// survives the job deletion as part of the append-only security history.
func (ts *TenantStore) DeleteJobWithAudit(ctx context.Context, id string, audit AuditEntry) error {
	return ts.deleteJobWithAudits(ctx, id, []AuditEntry{audit})
}

func (ts *TenantStore) deleteJobWithAudits(ctx context.Context, id string, audits []AuditEntry) error {
	if err := ts.ready(); err != nil {
		return err
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	record, err := getTenantJobTx(ctx, tx, ts.scope, id)
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
	// The history checks join the job instead of filtering on each row's own
	// tenant, so any row that names the job blocks the delete.
	var scans int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans AS s JOIN jobs AS j ON j.id=s.job_id AND j.tenant_id=? WHERE s.job_id=?`, ts.scope.id, id).Scan(&scans); err != nil {
		return err
	}
	if scans > 0 {
		return errors.New("job has retained scan history; archive it instead")
	}
	var events int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM events AS e JOIN jobs AS j ON j.id=e.job_id AND j.tenant_id=? WHERE e.job_id=?`, ts.scope.id, id).Scan(&events); err != nil {
		return err
	}
	if events > 0 {
		return errors.New("job has retained event history; archive it instead")
	}
	var cycles int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_cycles AS c JOIN jobs AS j ON j.id=c.job_id AND j.tenant_id=? WHERE c.job_id=?`, ts.scope.id, id).Scan(&cycles); err != nil {
		return err
	}
	if cycles > 0 {
		return errors.New("job has retained scan-cycle history; archive it instead")
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM jobs WHERE id=? AND tenant_id=?`, id, ts.scope.id)
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

// JobActive reports whether a job holds an unexpired scan lease.
//
// Deprecated: bound to DefaultTenantScope. Use TenantStore.JobActive.
func (s *Store) JobActive(ctx context.Context, id string) (bool, error) {
	return s.Tenant(DefaultTenantScope()).JobActive(ctx, id)
}

// JobActive reports whether the tenant's job holds an unexpired scan lease.
// A job of another tenant is ErrNotFound. A lease key without a jobs row is
// the name of a config.yaml job, and those jobs belong to the default
// tenant, so only the default tenant can see its lease.
func (ts *TenantStore) JobActive(ctx context.Context, id string) (bool, error) {
	if err := ts.ready(); err != nil {
		return false, err
	}
	var owned, active int
	err := ts.store.reader().QueryRowContext(ctx, `SELECT COALESCE((SELECT tenant_id FROM jobs WHERE id=?),'`+DefaultTenantID+`')=?,EXISTS(SELECT 1 FROM job_leases WHERE job=? AND expires_at>?)`, id, ts.scope.id, id, time.Now().UTC().Format(time.RFC3339Nano)).Scan(&owned, &active)
	if err != nil {
		return false, err
	}
	if owned == 0 {
		return false, fmt.Errorf("%w: job %s", ErrNotFound, id)
	}
	return active != 0, nil
}

func jobActiveTx(ctx context.Context, tx *sql.Tx, id string, now time.Time) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_leases WHERE job=? AND expires_at>?`, id, now.UTC().Format(time.RFC3339Nano)).Scan(&n)
	return n > 0, err
}
