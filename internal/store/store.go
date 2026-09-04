package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type Store struct {
	DB   *sql.DB
	Path string
}

var ErrJobBusy = errors.New("job is already running")

const legacySchema = `
CREATE TABLE IF NOT EXISTS scans (
 id TEXT PRIMARY KEY, job TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL,
 status TEXT NOT NULL, error TEXT NOT NULL DEFAULT '', nmap_version TEXT NOT NULL DEFAULT '',
 config_hash TEXT NOT NULL, snapshot_json BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_job_time ON scans(job, finished_at DESC);
CREATE TABLE IF NOT EXISTS job_states (job TEXT PRIMARY KEY, state_json BLOB NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, job TEXT NOT NULL,
 scan_id TEXT NOT NULL DEFAULT '', payload_json BLOB NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_job_time ON events(job, created_at DESC);
CREATE TABLE IF NOT EXISTS outbox (
 id INTEGER PRIMARY KEY AUTOINCREMENT, destination TEXT NOT NULL, payload_json BLOB NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0, next_at TEXT NOT NULL, sent_at TEXT, last_error TEXT NOT NULL DEFAULT '',
 UNIQUE(destination, payload_json)
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox(sent_at, next_at);
CREATE TABLE IF NOT EXISTS daemon_lease (
 id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT NOT NULL, heartbeat TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS job_leases (
 job TEXT PRIMARY KEY, owner TEXT NOT NULL, expires_at TEXT NOT NULL
);
`

// schemaVersion is deliberately independent from the configuration version.
// The former describes on-disk compatibility; the latter describes YAML.
const schemaVersion = 3

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("database path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{DB: db, Path: path}, nil
}

func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > schemaVersion {
		return fmt.Errorf("database schema version %d is newer than supported version %d", version, schemaVersion)
	}
	migrations := map[int][]string{
		// Version 1 is the pre-web daemon schema. Keeping it as a real
		// migration means a brand-new database and an existing legacy database
		// follow the same transactional path instead of relying on a one-shot
		// schema bootstrap outside the migration runner.
		1: {legacySchema},
		2: {
			"ALTER TABLE scans ADD COLUMN job_id TEXT",
			"ALTER TABLE scans ADD COLUMN job_revision INTEGER",
			"ALTER TABLE events ADD COLUMN job_id TEXT",
			`CREATE TABLE IF NOT EXISTS jobs (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL UNIQUE,
 definition_json BLOB NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1,
 archived INTEGER NOT NULL DEFAULT 0,
 revision INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);`,
			"CREATE INDEX IF NOT EXISTS jobs_active ON jobs(archived, enabled, name)",
			"CREATE INDEX IF NOT EXISTS events_job_id_time ON events(job_id, created_at DESC)",
			`CREATE TABLE IF NOT EXISTS job_revisions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 job_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 definition_json BLOB NOT NULL,
 security_hash TEXT NOT NULL,
 created_at TEXT NOT NULL,
 UNIQUE(job_id, revision),
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
);`,
			`CREATE TABLE IF NOT EXISTS job_runtime (
 job_id TEXT PRIMARY KEY,
 state_json BLOB NOT NULL,
 updated_at TEXT NOT NULL,
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
);`,
			`CREATE TABLE IF NOT EXISTS admins (
 id INTEGER PRIMARY KEY CHECK(id=1),
 username TEXT NOT NULL DEFAULT 'admin',
 password_hash TEXT NOT NULL,
 totp_secret TEXT NOT NULL DEFAULT '',
 totp_enabled INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);`,
			`CREATE TABLE IF NOT EXISTS sessions (
 id_hash TEXT PRIMARY KEY,
 created_at TEXT NOT NULL,
 last_seen_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 csrf_token TEXT NOT NULL
);`,
			"CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at)",
			`CREATE TABLE IF NOT EXISTS recovery_codes (
 id_hash TEXT PRIMARY KEY,
 used_at TEXT
);`,
			`CREATE TABLE IF NOT EXISTS security_audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 action TEXT NOT NULL,
 detail TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);`,
			`CREATE TABLE IF NOT EXISTS setup_tokens (
 id INTEGER PRIMARY KEY CHECK(id=1),
 token_hash TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 used_at TEXT
);`,
		},
		3: {
			`CREATE TABLE IF NOT EXISTS managed_notifications (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL UNIQUE,
 provider TEXT NOT NULL,
 ciphertext BLOB NOT NULL,
 nonce BLOB NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1,
 revision INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);`,
			"CREATE INDEX IF NOT EXISTS managed_notifications_enabled ON managed_notifications(enabled, name)",
		},
	}
	for next := version + 1; next <= schemaVersion; next++ {
		statements, ok := migrations[next]
		if !ok {
			return fmt.Errorf("missing migration for schema version %d", next)
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		for _, statement := range statements {
			if _, err := tx.Exec(statement); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
				return err
			}
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", next)); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		version = next
	}
	return nil
}
func (s *Store) Close() error { return s.DB.Close() }

func nullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func nullInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

var (
	ErrNotFound           = errors.New("not found")
	ErrConflict           = errors.New("resource was modified by another request")
	ErrRebaselineRequired = errors.New("security-relevant job changes require rebaseline confirmation")
	ErrJobScanActive      = errors.New("job has an active scan")
	// ErrJobRevisionChanged is returned when a scan was queued with an older
	// immutable job revision. The caller must reload the job before starting it.
	ErrJobRevisionChanged = errors.New("job revision changed before scan started")
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
	v, _ := time.Parse(time.RFC3339Nano, raw)
	return v
}

func (s *Store) CreateJob(ctx context.Context, job config.Job) (JobRecord, error) {
	job = config.NormalizeJob(job)
	if err := config.ValidateJob(job); err != nil {
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
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO jobs(id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES(?,?,?,1,0,1,?,?)`, id, job.Name, raw, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return JobRecord{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO job_revisions(job_id,revision,definition_json,security_hash,created_at) VALUES(?,?,?,?,?)`, id, 1, raw, hash, now.Format(time.RFC3339Nano)); err != nil {
		return JobRecord{}, err
	}
	if err = tx.Commit(); err != nil {
		return JobRecord{}, err
	}
	return JobRecord{ID: id, Job: job, Enabled: true, Revision: 1, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) GetJob(ctx context.Context, id string) (JobRecord, error) {
	var r JobRecord
	var raw []byte
	var created, updated string
	var enabled, archived int
	err := s.DB.QueryRowContext(ctx, `SELECT id,name,definition_json,enabled,archived,revision,created_at,updated_at FROM jobs WHERE id=?`, id).
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
	err := s.DB.QueryRowContext(ctx, `SELECT id FROM jobs WHERE name=?`, name).Scan(&id)
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
	query += ` ORDER BY name`
	rows, err := s.DB.QueryContext(ctx, query)
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
	job = config.NormalizeJob(job)
	if err := config.ValidateJob(job); err != nil {
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
	defer tx.Rollback()
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
		event := model.Event{Type: "baseline-reset", JobID: id, Job: job.Name, Message: "Baseline collection reset", CreatedAt: now}
		eventRaw, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			return JobRecord{}, false, nil, marshalErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO events(type,job,job_id,scan_id,payload_json,created_at) VALUES(?,?,?,?,?,?)`, event.Type, event.Job, event.JobID, event.ScanID, eventRaw, now.Format(time.RFC3339Nano)); err != nil {
			return JobRecord{}, false, nil, err
		}
		events = append(events, event)
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
	return s.setJobArchived(ctx, id, archived, nil)
}

// SetJobArchivedWithRevision applies an archive or restore transition only
// when the caller still holds the current immutable job revision. Lifecycle
// actions are state mutations too, so stale browser views must not silently
// overwrite a newer edit.
func (s *Store) SetJobArchivedWithRevision(ctx context.Context, id string, archived bool, expectedRevision int64) error {
	return s.setJobArchived(ctx, id, archived, &expectedRevision)
}

func (s *Store) setJobArchived(ctx context.Context, id string, archived bool, expectedRevision *int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := getJobTx(ctx, tx, id)
	if err != nil {
		return err
	}
	if expectedRevision != nil && current.Revision != *expectedRevision {
		return ErrConflict
	}
	if current.Archived == archived {
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
	return tx.Commit()
}

func (s *Store) SetJobEnabled(ctx context.Context, id string, enabled bool) error {
	return s.setJobEnabled(ctx, id, enabled, nil)
}

// SetJobEnabledWithRevision applies a pause or resume transition only when
// the caller still holds the current immutable job revision.
func (s *Store) SetJobEnabledWithRevision(ctx context.Context, id string, enabled bool, expectedRevision int64) error {
	return s.setJobEnabled(ctx, id, enabled, &expectedRevision)
}

func (s *Store) setJobEnabled(ctx context.Context, id string, enabled bool, expectedRevision *int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
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
	return tx.Commit()
}

func appendJobRevisionTx(ctx context.Context, tx *sql.Tx, jobID string, revision int64, raw []byte, securityHash string, createdAt time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO job_revisions(job_id,revision,definition_json,security_hash,created_at) VALUES(?,?,?,?,?)`, jobID, revision, raw, securityHash, createdAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) DeleteJob(ctx context.Context, id string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
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
	result, err := tx.ExecContext(ctx, `DELETE FROM jobs WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: job %s", ErrNotFound, id)
	}
	return tx.Commit()
}

func (s *Store) JobActive(ctx context.Context, id string) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_leases WHERE job=? AND expires_at>?`, id, time.Now().UTC().Format(time.RFC3339Nano)).Scan(&n)
	return n > 0, err
}

func jobActiveTx(ctx context.Context, tx *sql.Tx, id string, now time.Time) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_leases WHERE job=? AND expires_at>?`, id, now.UTC().Format(time.RFC3339Nano)).Scan(&n)
	return n > 0, err
}

type Page[T any] struct {
	Items []T
	Total int
}

func normalizePage(limit, offset int) (int, int) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (s *Store) ListJobScans(ctx context.Context, jobID string, limit int) ([]model.Scan, error) {
	page, err := s.ListJobScansPage(ctx, jobID, limit, 0)
	return page.Items, err
}

func (s *Store) ListJobScansPage(ctx context.Context, jobID string, limit, offset int) (Page[model.Scan], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[model.Scan]
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE job_id=?`, jobID).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json FROM scans WHERE job_id=? ORDER BY finished_at DESC,id DESC LIMIT ? OFFSET ?`, jobID, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var v model.Scan
		var jid sql.NullString
		var revision sql.NullInt64
		var started, finished string
		var snapshot []byte
		if err := rows.Scan(&v.ID, &jid, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ConfigHash, &snapshot); err != nil {
			return page, err
		}
		if jid.Valid {
			v.JobID = jid.String
		}
		if revision.Valid {
			v.JobRevision = revision.Int64
		}
		v.StartedAt, v.FinishedAt = scanTime(started), scanTime(finished)
		if err := json.Unmarshal(snapshot, &v.Snapshot); err != nil {
			return page, err
		}
		page.Items = append(page.Items, v)
	}
	return page, rows.Err()
}

func (s *Store) RuntimeState(ctx context.Context, jobID string) (model.JobState, error) {
	var raw []byte
	err := s.DB.QueryRowContext(ctx, `SELECT state_json FROM job_runtime WHERE job_id=?`, jobID).Scan(&raw)
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

func (s *Store) UpdateRuntime(ctx context.Context, jobID string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	events, err := updateRuntimeTx(ctx, tx, jobID, fn)
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
func (s *Store) UpdateRuntimeForScan(ctx context.Context, jobID, securityHash string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
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
	if securityHash == "" || job.SecurityHash() != securityHash {
		return nil, ErrJobRevisionChanged
	}
	events, err := updateRuntimeTx(ctx, tx, jobID, fn)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
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
	events, err := fn(&state)
	if err != nil {
		return nil, err
	}
	raw, err = json.Marshal(state)
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
		payload, _ := json.Marshal(events[i])
		if _, err = tx.ExecContext(ctx, `INSERT INTO events(type,job,job_id,scan_id,payload_json,created_at) VALUES(?,?,?,?,?,?)`, events[i].Type, events[i].Job, events[i].JobID, events[i].ScanID, payload, events[i].CreatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
	}
	return events, nil
}

func (s *Store) ResetRuntime(ctx context.Context, jobID, name string) ([]model.Event, error) {
	return s.UpdateRuntime(ctx, jobID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = nil
		state.BaselineScanID = ""
		state.BaselineConfigHash = ""
		state.Candidate = nil
		state.CandidateHash = ""
		state.CandidateCount = 0
		state.CandidateAttempts = 0
		state.Pending = map[string]model.Pending{}
		state.Incidents = map[string]model.Incident{}
		state.FingerprintCandidates = map[string]model.ValueCount{}
		return []model.Event{{Type: "baseline-reset", Job: name, Message: "Baseline collection reset", CreatedAt: time.Now().UTC()}}, nil
	})
}

func (s *Store) ApproveRuntime(ctx context.Context, jobID, name string, scan model.Scan) ([]model.Event, error) {
	if scan.ID == "" {
		return nil, errors.New("scan ID is required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	record, err := getJobTx(ctx, tx, jobID)
	if err != nil {
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
	events, err := updateRuntimeTx(ctx, tx, jobID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &stored.Snapshot
		state.BaselineScanID = stored.ID
		state.BaselineConfigHash = stored.ConfigHash
		state.Candidate = nil
		state.CandidateHash = ""
		state.CandidateCount = 0
		state.CandidateAttempts = 0
		state.Pending = map[string]model.Pending{}
		state.Incidents = map[string]model.Incident{}
		state.FingerprintCandidates = map[string]model.ValueCount{}
		return []model.Event{{Type: "baseline-approved", Job: name, ScanID: stored.ID, Message: "Baseline manually approved", CreatedAt: time.Now().UTC()}}, nil
	})
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

func (s *Store) SaveScan(ctx context.Context, scan model.Scan) error {
	b, err := json.Marshal(scan.Snapshot)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO scans(id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		scan.ID, nullString(scan.JobID), nullInt64(scan.JobRevision), scan.Job, scan.StartedAt.UTC().Format(time.RFC3339Nano), scan.FinishedAt.UTC().Format(time.RFC3339Nano), scan.Status, scan.Error, scan.NmapVersion, scan.ConfigHash, b)
	return err
}

func (s *Store) GetScan(ctx context.Context, id string) (model.Scan, error) {
	var v model.Scan
	var started, finished string
	var snapshot []byte
	var jobID sql.NullString
	var revision sql.NullInt64
	err := s.DB.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json FROM scans WHERE id=?`, id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ConfigHash, &snapshot)
	if err != nil {
		return v, err
	}
	if jobID.Valid {
		v.JobID = jobID.String
	}
	if revision.Valid {
		v.JobRevision = revision.Int64
	}
	v.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
	v.FinishedAt, _ = time.Parse(time.RFC3339Nano, finished)
	if err := json.Unmarshal(snapshot, &v.Snapshot); err != nil {
		return v, err
	}
	return v, nil
}

func getScanTx(ctx context.Context, tx *sql.Tx, id string) (model.Scan, error) {
	var v model.Scan
	var started, finished string
	var snapshot []byte
	var jobID sql.NullString
	var revision sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json FROM scans WHERE id=?`, id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ConfigHash, &snapshot)
	if err != nil {
		return v, err
	}
	if jobID.Valid {
		v.JobID = jobID.String
	}
	if revision.Valid {
		v.JobRevision = revision.Int64
	}
	v.StartedAt, v.FinishedAt = scanTime(started), scanTime(finished)
	if err := json.Unmarshal(snapshot, &v.Snapshot); err != nil {
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
	query := `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json FROM scans`
	countQuery := `SELECT COUNT(*) FROM scans`
	args := []any{}
	countArgs := []any{}
	if job != "" {
		query += ` WHERE job=?`
		args = append(args, job)
		countQuery += ` WHERE job=?`
		countArgs = append(countArgs, job)
	}
	if err := s.DB.QueryRowContext(ctx, countQuery, countArgs...).Scan(&page.Total); err != nil {
		return page, err
	}
	query += ` ORDER BY finished_at DESC,id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var v model.Scan
		var jobID sql.NullString
		var revision sql.NullInt64
		var started, finished string
		var snapshot []byte
		if err := rows.Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ConfigHash, &snapshot); err != nil {
			return page, err
		}
		if jobID.Valid {
			v.JobID = jobID.String
		}
		if revision.Valid {
			v.JobRevision = revision.Int64
		}
		v.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
		v.FinishedAt, _ = time.Parse(time.RFC3339Nano, finished)
		if err := json.Unmarshal(snapshot, &v.Snapshot); err != nil {
			return page, err
		}
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
	if err := s.DB.QueryRowContext(ctx, countQuery, countArgs...).Scan(&page.Total); err != nil {
		return page, err
	}
	query += ` ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.DB.QueryContext(ctx, query, args...)
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
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE job_id=?`, jobID).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT payload_json FROM events WHERE job_id=? ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, jobID, limit, offset)
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
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL AND attempts >= 3`).Scan(&count)
	return count, err
}

func (s *Store) State(ctx context.Context, job string) (model.JobState, error) {
	var b []byte
	err := s.DB.QueryRowContext(ctx, `SELECT state_json FROM job_states WHERE job=?`, job).Scan(&b)
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

func emptyState() model.JobState { s := model.JobState{}; ensureMaps(&s); return s }
func ensureMaps(s *model.JobState) {
	if s.Pending == nil {
		s.Pending = map[string]model.Pending{}
	}
	if s.Incidents == nil {
		s.Incidents = map[string]model.Incident{}
	}
	if s.FingerprintCandidates == nil {
		s.FingerprintCandidates = map[string]model.ValueCount{}
	}
}

func (s *Store) UpdateState(ctx context.Context, job string, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var raw []byte
	state := emptyState()
	err = tx.QueryRowContext(ctx, `SELECT state_json FROM job_states WHERE job=?`, job).Scan(&raw)
	if err == nil {
		if err = json.Unmarshal(raw, &state); err != nil {
			return nil, err
		}
		ensureMaps(&state)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	events, err := fn(&state)
	if err != nil {
		return nil, err
	}
	raw, err = json.Marshal(state)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO job_states(job,state_json,updated_at) VALUES(?,?,?) ON CONFLICT(job) DO UPDATE SET state_json=excluded.state_json,updated_at=excluded.updated_at`, job, raw, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		payload, _ := json.Marshal(event)
		if _, err = tx.ExecContext(ctx, `INSERT INTO events(type,job,scan_id,payload_json,created_at) VALUES(?,?,?,?,?)`, event.Type, event.Job, event.ScanID, payload, event.CreatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

func (s *Store) QueueEvent(ctx context.Context, destination string, event model.Event) error {
	b, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO outbox(destination,payload_json,next_at) VALUES(?,?,?)`, destination, b, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

type Delivery struct {
	ID          int64
	Destination string
	Event       model.Event
	Attempts    int
}

func (s *Store) DueDeliveries(ctx context.Context, limit int) ([]Delivery, error) {
	now := time.Now().UTC()
	rows, err := s.DB.QueryContext(ctx, `UPDATE outbox SET next_at=? WHERE id IN (SELECT id FROM outbox WHERE sent_at IS NULL AND attempts < 3 AND next_at <= ? ORDER BY id LIMIT ?) RETURNING id,destination,payload_json,attempts`, now.Add(time.Minute).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Delivery
	for rows.Next() {
		var d Delivery
		var b []byte
		if err := rows.Scan(&d.ID, &d.Destination, &b, &d.Attempts); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &d.Event); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func (s *Store) DeliveryResult(ctx context.Context, id int64, sendErr error) error {
	if sendErr == nil {
		_, err := s.DB.ExecContext(ctx, `UPDATE outbox SET sent_at=?,last_error='' WHERE id=?`, time.Now().UTC().Format(time.RFC3339Nano), id)
		return err
	}
	var attempts int
	if err := s.DB.QueryRowContext(ctx, `SELECT attempts FROM outbox WHERE id=?`, id).Scan(&attempts); err != nil {
		return err
	}
	attempts++
	delay := time.Duration(1<<min(attempts, 6)) * time.Minute
	_, err := s.DB.ExecContext(ctx, `UPDATE outbox SET attempts=?,next_at=?,last_error=? WHERE id=?`, attempts, time.Now().UTC().Add(delay).Format(time.RFC3339Nano), truncate(sendErr.Error(), 500), id)
	return err
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func truncate(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}

func (s *Store) Prune(ctx context.Context, before time.Time) (int64, error) {
	// NOT EXISTS avoids SQL's NULL semantics: most state rows do not yet have a
	// baseline_scan_id, and a NOT IN subquery containing NULL would protect every
	// old scan from pruning.
	r, err := s.DB.ExecContext(ctx, `DELETE FROM scans AS scan WHERE scan.finished_at < ?
		AND NOT EXISTS (SELECT 1 FROM job_states AS legacy WHERE json_extract(legacy.state_json,'$.baseline_scan_id') = scan.id)
		AND NOT EXISTS (SELECT 1 FROM job_runtime AS managed WHERE json_extract(managed.state_json,'$.baseline_scan_id') = scan.id)`, before.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

func (s *Store) AcquireLease(ctx context.Context, owner string) error {
	now := time.Now().UTC()
	stale := now.Add(-2 * time.Minute).Format(time.RFC3339Nano)
	r, err := s.DB.ExecContext(ctx, `INSERT INTO daemon_lease(id,owner,heartbeat) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,heartbeat=excluded.heartbeat WHERE daemon_lease.owner=excluded.owner OR daemon_lease.heartbeat < ?`, owner, now.Format(time.RFC3339Nano), stale)
	if err != nil {
		return err
	}
	changed, _ := r.RowsAffected()
	if changed == 0 {
		return errors.New("another EdgeWatch daemon holds the database lease")
	}
	return nil
}
func (s *Store) Heartbeat(ctx context.Context, owner string) error {
	r, err := s.DB.ExecContext(ctx, `UPDATE daemon_lease SET heartbeat=? WHERE id=1 AND owner=?`, time.Now().UTC().Format(time.RFC3339Nano), owner)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return errors.New("daemon lease lost")
	}
	return nil
}
func (s *Store) ReleaseLease(ctx context.Context, owner string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM daemon_lease WHERE id=1 AND owner=?`, owner)
	return err
}
func (s *Store) Healthy(ctx context.Context) error {
	var raw string
	if err := s.DB.QueryRowContext(ctx, `SELECT heartbeat FROM daemon_lease WHERE id=1`).Scan(&raw); err != nil {
		return err
	}
	v, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return err
	}
	if time.Since(v) > 2*time.Minute {
		return fmt.Errorf("daemon heartbeat is stale: %s", v)
	}
	return nil
}

func (s *Store) AcquireJobLease(ctx context.Context, job, owner string, expires time.Time) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.DB.ExecContext(ctx, `INSERT INTO job_leases(job,owner,expires_at) VALUES(?,?,?) ON CONFLICT(job) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at WHERE job_leases.expires_at < ?`, job, owner, expires.UTC().Format(time.RFC3339Nano), now)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		return fmt.Errorf("%w: %s", ErrJobBusy, job)
	}
	return nil
}

// AcquireJobLeaseForRevision atomically verifies that the queued scan still
// refers to the current managed job revision and acquires its lease. A job
// edit and a scan start therefore cannot cross between the revision check and
// the lease write: either the edit observes the lease, or the scan observes
// the newer revision and is rejected before it can touch runtime state.
func (s *Store) AcquireJobLeaseForRevision(ctx context.Context, job, owner string, revision int64, expires time.Time) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current int64
	var archived int
	err = tx.QueryRowContext(ctx, `SELECT revision,archived FROM jobs WHERE id=?`, job).Scan(&current, &archived)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: job %s", ErrNotFound, job)
	}
	if err != nil {
		return err
	}
	if archived != 0 {
		return errors.New("archived jobs cannot run")
	}
	if current != revision {
		return ErrJobRevisionChanged
	}
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `INSERT INTO job_leases(job,owner,expires_at) VALUES(?,?,?) ON CONFLICT(job) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at WHERE job_leases.expires_at < ?`, job, owner, expires.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		return fmt.Errorf("%w: %s", ErrJobBusy, job)
	}
	return tx.Commit()
}

func (s *Store) ReleaseJobLease(ctx context.Context, job, owner string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM job_leases WHERE job=? AND owner=?`, job, owner)
	return err
}

func (s *Store) Approve(ctx context.Context, job string, scan model.Scan) ([]model.Event, error) {
	if scan.Job != job {
		return nil, fmt.Errorf("scan %s belongs to job %s", scan.ID, scan.Job)
	}
	if scan.Status != "success" {
		return nil, fmt.Errorf("scan %s is not successful", scan.ID)
	}
	return s.UpdateState(ctx, job, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &scan.Snapshot
		state.BaselineScanID = scan.ID
		state.BaselineConfigHash = scan.ConfigHash
		state.Candidate = nil
		state.CandidateHash = ""
		state.CandidateCount = 0
		state.CandidateAttempts = 0
		state.Pending = map[string]model.Pending{}
		state.Incidents = map[string]model.Incident{}
		state.FingerprintCandidates = map[string]model.ValueCount{}
		return []model.Event{{Type: "baseline-approved", Job: job, ScanID: scan.ID, Message: "Baseline manually approved", CreatedAt: time.Now().UTC()}}, nil
	})
}
func (s *Store) ResetBaseline(ctx context.Context, job string) ([]model.Event, error) {
	return s.UpdateState(ctx, job, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = nil
		state.BaselineScanID = ""
		state.BaselineConfigHash = ""
		state.Candidate = nil
		state.CandidateHash = ""
		state.CandidateCount = 0
		state.CandidateAttempts = 0
		state.Pending = map[string]model.Pending{}
		state.Incidents = map[string]model.Incident{}
		state.FingerprintCandidates = map[string]model.ValueCount{}
		return []model.Event{{Type: "baseline-reset", Job: job, Message: "Baseline collection reset", CreatedAt: time.Now().UTC()}}, nil
	})
}
