package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	_ "modernc.org/sqlite"
)

type Store struct{ DB *sql.DB }

var ErrJobBusy = errors.New("job is already running")

const schema = `
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
PRAGMA user_version = 1;
`

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
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{DB: db}, nil
}
func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) SaveScan(ctx context.Context, scan model.Scan) error {
	b, err := json.Marshal(scan.Snapshot)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO scans(id,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json) VALUES(?,?,?,?,?,?,?,?,?)`,
		scan.ID, scan.Job, scan.StartedAt.UTC().Format(time.RFC3339Nano), scan.FinishedAt.UTC().Format(time.RFC3339Nano), scan.Status, scan.Error, scan.NmapVersion, scan.ConfigHash, b)
	return err
}

func (s *Store) GetScan(ctx context.Context, id string) (model.Scan, error) {
	var v model.Scan
	var started, finished string
	var snapshot []byte
	err := s.DB.QueryRowContext(ctx, `SELECT id,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json FROM scans WHERE id=?`, id).
		Scan(&v.ID, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ConfigHash, &snapshot)
	if err != nil {
		return v, err
	}
	v.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
	v.FinishedAt, _ = time.Parse(time.RFC3339Nano, finished)
	if err := json.Unmarshal(snapshot, &v.Snapshot); err != nil {
		return v, err
	}
	return v, nil
}

func (s *Store) ListScans(ctx context.Context, job string, limit int) ([]model.Scan, error) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	query := `SELECT id,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json FROM scans`
	args := []any{}
	if job != "" {
		query += ` WHERE job=?`
		args = append(args, job)
	}
	query += ` ORDER BY finished_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Scan
	for rows.Next() {
		var v model.Scan
		var started, finished string
		var snapshot []byte
		if err := rows.Scan(&v.ID, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ConfigHash, &snapshot); err != nil {
			return nil, err
		}
		v.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
		v.FinishedAt, _ = time.Parse(time.RFC3339Nano, finished)
		if err := json.Unmarshal(snapshot, &v.Snapshot); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) ListEvents(ctx context.Context, job string, limit int) ([]model.Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	query := `SELECT payload_json FROM events`
	args := []any{}
	if job != "" {
		query += ` WHERE job=?`
		args = append(args, job)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []model.Event
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var event model.Event
		if err := json.Unmarshal(raw, &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
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
	r, err := s.DB.ExecContext(ctx, `DELETE FROM scans WHERE finished_at < ? AND id NOT IN (SELECT json_extract(state_json,'$.baseline_scan_id') FROM job_states)`, before.UTC().Format(time.RFC3339Nano))
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
