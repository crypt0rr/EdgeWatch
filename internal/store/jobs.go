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

// CreateJob creates an enabled job in the tenant.
func (ts *TenantStore) CreateJob(ctx context.Context, job config.Job) (JobRecord, error) {
	return ts.CreateJobWithEnabled(ctx, job, true)
}

// CreateJobWithEnabled creates the initial job definition and lifecycle state
// in one transaction. Keeping a paused job disabled from its first commit
// prevents a crash window where it could be scheduled before the follow-up
// lifecycle update succeeds.
func (ts *TenantStore) CreateJobWithEnabled(ctx context.Context, job config.Job, enabled bool) (JobRecord, error) {
	return ts.createJobWithAudits(ctx, job, enabled, nil)
}

// CreateJobWithEnabledAndAudit commits a new job and its security audit row in
// one transaction. The plain CreateJobWithEnabled API remains available to
// internal callers that deliberately do not need an audit entry (for example,
// deterministic fixtures).
func (ts *TenantStore) CreateJobWithEnabledAndAudit(ctx context.Context, job config.Job, enabled bool, audits ...AuditEntry) (JobRecord, error) {
	return ts.createJobWithAudits(ctx, job, enabled, audits)
}

// ErrScannerProfileNotFound refuses a job that pins a scanner profile the
// tenant cannot use: neither a built-in profile nor one of the tenant's own
// has the ID. It is the validation error that the console returns for an
// unknown profile, so a job write refused here looks the same as one that
// the console refused.
var ErrScannerProfileNotFound = NewValidationError(config.NewFieldValidationError("profile", errors.New("selected scanner profile was not found")))

// ErrUDPScannerProfile refuses a job whose UDP scan pins a scanner profile.
// UDP always uses the Nmap defaults and a scan never applies a UDP profile,
// so the store refuses one, whoever owns it, as the console does.
var ErrUDPScannerProfile = NewValidationError(config.NewFieldValidationError("udp", errors.New("udp scanner profiles are not supported; UDP uses Nmap defaults")))

// ValidateManagedJob applies the deployment's installed target-exclusion
// policy and the standard managed-job validation to a candidate job. It is
// intended for advisory preflight checks; writes validate again in their
// transaction so a preview never reserves or weakens the final decision.
// The validator preserves the distinction between an unconfigured nil policy
// and an explicitly empty policy installed by the deployment.
func (ts *TenantStore) ValidateManagedJob(job config.Job) error {
	if err := ts.ready(); err != nil {
		return err
	}
	return ts.store.validateManagedJob(config.NormalizeJob(job))
}

// checkPinnedScannerProfileTx refuses a job whose TCP scan pins a scanner
// profile that is neither built in nor the tenant's own. The TCP profile is
// the one a scan applies, and the one the console checks. A UDP profile is
// refused whatever it is, since no scan applies one. It reads in the job
// write's transaction, so the check and the write see the same profiles.
func (ts *TenantStore) checkPinnedScannerProfileTx(ctx context.Context, tx *sql.Tx, job config.Job) error {
	if job.UDP != nil && strings.TrimSpace(job.UDP.ProfileID) != "" {
		return ErrUDPScannerProfile
	}
	if job.TCP == nil || strings.TrimSpace(job.TCP.ProfileID) == "" {
		return nil
	}
	var visible int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scanner_profiles WHERE id=? AND (tenant_id IS NULL OR tenant_id=?)`, job.TCP.ProfileID, ts.scope.id).Scan(&visible); err != nil {
		return err
	}
	if visible == 0 {
		return ErrScannerProfileNotFound
	}
	return nil
}

// createJobWithAudits creates the job in the store's tenant. Job names are
// unique per tenant, so another tenant may already use the name. A pinned
// scanner profile must be built in or the tenant's own.
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
	if err = ts.checkPinnedScannerProfileTx(ctx, tx, job); err != nil {
		return JobRecord{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO jobs(id,tenant_id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES(?,?,?,?, ?,0,1,?,?)`, id, ts.scope.id, job.Name, raw, boolInt(enabled), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return JobRecord{}, err
	}
	if err = appendJobRevisionTx(ctx, tx, id, 1, raw, job.SecurityHash(), now); err != nil {
		return JobRecord{}, err
	}
	if err = upsertJobSilenceStateTx(ctx, tx, id, now); err != nil {
		return JobRecord{}, err
	}
	if err = ts.insertAuditEntries(ctx, tx, audits, now); err != nil {
		return JobRecord{}, err
	}
	if err = tx.Commit(); err != nil {
		return JobRecord{}, err
	}
	return JobRecord{ID: id, TenantID: ts.scope.id, Job: job, Enabled: enabled, Revision: 1, CreatedAt: now, UpdatedAt: now}, nil
}

// GetJob returns the tenant's job with the given ID. A job of another tenant
// is ErrNotFound.
func (ts *TenantStore) GetJob(ctx context.Context, id string) (JobRecord, error) {
	if err := ts.ready(); err != nil {
		return JobRecord{}, err
	}
	return scanJobRecord(ts.store.reader().QueryRowContext(ctx, `SELECT `+jobRecordColumns+` FROM jobs WHERE id=? AND tenant_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=jobs.tenant_id AND purge.job_id=jobs.id)`, id, ts.scope.id), id)
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
	return scanJobRecord(tx.QueryRowContext(ctx, `SELECT `+jobRecordColumns+` FROM jobs WHERE id=? AND tenant_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=jobs.tenant_id AND purge.job_id=jobs.id)`, id, scope.id), id)
}

// GetJobByName returns the tenant's job with the given name. Job names are
// unique per tenant, so another tenant's job with the same name is never
// returned.
func (ts *TenantStore) GetJobByName(ctx context.Context, name string) (JobRecord, error) {
	if err := ts.ready(); err != nil {
		return JobRecord{}, err
	}
	var id string
	err := ts.store.reader().QueryRowContext(ctx, `SELECT id FROM jobs WHERE tenant_id=? AND name=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=jobs.tenant_id AND purge.job_id=jobs.id)`, ts.scope.id, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return JobRecord{}, fmt.Errorf("%w: job %s", ErrNotFound, name)
	}
	if err != nil {
		return JobRecord{}, err
	}
	return ts.GetJob(ctx, id)
}

// ListJobs returns the tenant's jobs, without archived jobs unless
// includeArchived is set.
func (ts *TenantStore) ListJobs(ctx context.Context, includeArchived bool) ([]JobRecord, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	query := `SELECT ` + jobRecordColumns + ` FROM jobs WHERE tenant_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=jobs.tenant_id AND purge.job_id=jobs.id)`
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

// UpdateJob uses optimistic concurrency. The returned bool reports whether
// the security hash changed and therefore requires rebaseline confirmation.
func (ts *TenantStore) UpdateJob(ctx context.Context, id string, expectedRevision int64, job config.Job, enabled, archived, confirmRebaseline bool) (JobRecord, bool, error) {
	record, changed, _, err := ts.UpdateJobWithEvents(ctx, id, expectedRevision, job, enabled, archived, confirmRebaseline)
	return record, changed, err
}

// UpdateJobWithEvents updates a managed job and, when its security scope
// changes, clears its runtime comparison state in the same transaction. The
// returned events are already persisted atomically with the new revision; the
// web layer can queue notifications and publish them after the commit.
func (ts *TenantStore) UpdateJobWithEvents(ctx context.Context, id string, expectedRevision int64, job config.Job, enabled, archived, confirmRebaseline bool) (JobRecord, bool, []model.Event, error) {
	return ts.UpdateJobWithEventsWithOutbox(ctx, id, expectedRevision, job, enabled, archived, confirmRebaseline, nil)
}

// UpdateJobWithEventsWithOutbox also persists notification intent for the
// security-scope reset event. Destination revisions are validated while the
// job transaction is open, so a concurrent credential edit cannot leave an
// orphaned delivery.
func (ts *TenantStore) UpdateJobWithEventsWithOutbox(ctx context.Context, id string, expectedRevision int64, job config.Job, enabled, archived, confirmRebaseline bool, destinations []string) (JobRecord, bool, []model.Event, error) {
	return ts.UpdateJobWithEventsWithOutboxAndAudit(ctx, id, expectedRevision, job, enabled, archived, confirmRebaseline, destinations)
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
	// The console refuses an unknown profile before it looks at the
	// revision, and so does the store.
	if err := ts.checkPinnedScannerProfileTx(ctx, tx, job); err != nil {
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
	if current.Job.Name != job.Name {
		// The latest-host projection is the source for inventory labels and
		// search. Keep renamed jobs visible there in the same transaction as
		// the job revision; the projection's update trigger refreshes its FTS
		// entry. Historical scan records retain their original scan-time name.
		if _, err = tx.ExecContext(ctx, `UPDATE latest_scan_hosts SET job=? WHERE tenant_id=? AND job_id=?`, job.Name, ts.scope.id, id); err != nil {
			return JobRecord{}, false, nil, err
		}
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
	if err = ts.insertAuditEntries(ctx, tx, audits, now); err != nil {
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

// SetJobArchived archives or restores the tenant's job, whatever its
// revision. A job of another tenant is ErrNotFound.
func (ts *TenantStore) SetJobArchived(ctx context.Context, id string, archived bool) error {
	return ts.setJobArchived(ctx, id, archived, nil, nil)
}

// SetJobArchivedWithRevision applies an archive or restore transition only
// when the caller still holds the current immutable job revision. Lifecycle
// actions are state mutations too, so stale browser views must not silently
// overwrite a newer edit.
func (ts *TenantStore) SetJobArchivedWithRevision(ctx context.Context, id string, archived bool, expectedRevision int64) error {
	return ts.setJobArchived(ctx, id, archived, &expectedRevision, nil)
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
		if err := ts.insertAuditEntries(ctx, tx, audits, time.Now().UTC()); err != nil {
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
	if err := ts.insertAuditEntries(ctx, tx, audits, now); err != nil {
		return err
	}
	return tx.Commit()
}

// SetJobEnabled pauses or resumes the tenant's job, whatever its revision. A
// job of another tenant is ErrNotFound.
func (ts *TenantStore) SetJobEnabled(ctx context.Context, id string, enabled bool) error {
	return ts.setJobEnabled(ctx, id, enabled, nil, nil)
}

// SetJobEnabledWithRevision applies a pause or resume transition only when
// the caller still holds the current immutable job revision.
func (ts *TenantStore) SetJobEnabledWithRevision(ctx context.Context, id string, enabled bool, expectedRevision int64) error {
	return ts.setJobEnabled(ctx, id, enabled, &expectedRevision, nil)
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
		if err := ts.insertAuditEntries(ctx, tx, audits, time.Now().UTC()); err != nil {
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
	if err := ts.insertAuditEntries(ctx, tx, audits, now); err != nil {
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

// DeleteJob permanently removes the tenant's archived job and its associated
// retained scan, event, and resumable-cycle history. A job of another tenant
// is ErrNotFound.
func (ts *TenantStore) DeleteJob(ctx context.Context, id string) error {
	return ts.deleteJobWithAudits(ctx, id, nil, nil)
}

// DeleteJobWithAudit permanently removes an archived job and its associated
// retained history only when the audit row can be committed in the same
// transaction. The audit row intentionally survives the job deletion as part
// of the append-only security history.
func (ts *TenantStore) DeleteJobWithAudit(ctx context.Context, id string, audit AuditEntry) error {
	return ts.deleteJobWithAudits(ctx, id, nil, []AuditEntry{audit})
}

// DeleteJobWithAuditAtRevision removes a job only if its revision still
// matches the one the administrator confirmed in the UI. This prevents a
// concurrent rename or lifecycle edit from turning an old confirmation into
// approval to delete a different current definition.
func (ts *TenantStore) DeleteJobWithAuditAtRevision(ctx context.Context, id string, expectedRevision int64, audit AuditEntry) error {
	return ts.deleteJobWithAudits(ctx, id, &expectedRevision, []AuditEntry{audit})
}

func (ts *TenantStore) deleteJobWithAudits(ctx context.Context, id string, expectedRevision *int64, audits []AuditEntry) error {
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
	if expectedRevision != nil && record.Revision != *expectedRevision {
		return ErrConflict
	}
	if !record.Archived {
		return ErrJobNotArchived
	}
	active, err := jobActiveTx(ctx, tx, id, time.Now().UTC())
	if err != nil {
		return err
	}
	if active {
		return ErrJobScanActive
	}
	if err := startJobHistoryPurgeTx(ctx, tx, ts.scope.id, id, time.Now().UTC()); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE jobs SET enabled=0,archived=1,updated_at=? WHERE id=? AND tenant_id=?`, sqliteTimestamp(time.Now().UTC()), id, ts.scope.id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: job %s", ErrNotFound, id)
	}
	if err := ts.insertAuditEntries(ctx, tx, audits, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

// JobActive reports whether the tenant's job holds an unexpired scan lease.
// A job of another tenant is ErrNotFound. A lease key without a jobs row is
// the name of a config.yaml job, and those jobs belong to the default
// tenant, so only the default tenant can see its lease.
func (ts *TenantStore) JobActive(ctx context.Context, id string) (bool, error) {
	if err := ts.ready(); err != nil {
		return false, err
	}
	// The statement returns no row unless the tenant owns a visible job, or the
	// ID names no job and the tenant is the default one. A job with a pending
	// permanent-history purge is already logically deleted, even while its small
	// tombstone row remains for the batch worker.
	var active int
	err := ts.store.reader().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM job_leases WHERE job=? AND expires_at>?) WHERE EXISTS(SELECT 1 FROM jobs WHERE id=? AND tenant_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=jobs.tenant_id AND purge.job_id=jobs.id)) OR ?='`+DefaultTenantID+`' AND NOT EXISTS(SELECT 1 FROM jobs WHERE id=?)`, id, time.Now().UTC().Format(time.RFC3339Nano), id, ts.scope.id, ts.scope.id, id).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("%w: job %s", ErrNotFound, id)
	}
	if err != nil {
		return false, err
	}
	return active != 0, nil
}

func jobActiveTx(ctx context.Context, tx *sql.Tx, id string, now time.Time) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_leases WHERE job=? AND expires_at>?`, id, now.UTC().Format(time.RFC3339Nano)).Scan(&n)
	return n > 0, err
}
