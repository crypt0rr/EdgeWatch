package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// migrationHeartbeatTimeout is deliberately much longer than the normal
// daemon heartbeat. A large FTS rebuild can spend several minutes in one
// bounded transaction, but a wedged process must still become unhealthy after
// a finite period so an orchestrator can recover it.
const migrationHeartbeatTimeout = 15 * time.Minute

const startupStateSchema = `CREATE TABLE IF NOT EXISTS startup_state (
 id INTEGER PRIMARY KEY CHECK(id=1),
 state TEXT NOT NULL DEFAULT 'ready',
 owner TEXT NOT NULL DEFAULT '',
 phase TEXT NOT NULL DEFAULT '',
 started_at TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL DEFAULT '',
 progress INTEGER NOT NULL DEFAULT 0,
 total INTEGER NOT NULL DEFAULT 0,
 last_error TEXT NOT NULL DEFAULT ''
)`

// HealthStatus is the machine-readable state returned by the health command.
// A starting status is healthy for orchestration purposes while migrations are
// actively progressing; the phase and counters make that state diagnosable.
type HealthStatus struct {
	Status    string    `json:"status"`
	Phase     string    `json:"phase,omitempty"`
	Progress  int64     `json:"progress,omitempty"`
	Total     int64     `json:"total,omitempty"`
	StartedAt time.Time `json:"started_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

func migrationOwner() string {
	return fmt.Sprintf("migration/%d", os.Getpid())
}

func boundedMigrationError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

// ensureStartupStateContext creates the small status table before the first
// migration transaction. This is intentionally idempotent and runs before the
// schema version is read so health checks can observe a long upgrade even when
// the database is still on a legacy schema.
func ensureStartupStateContext(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, startupStateSchema); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO startup_state(id,state) VALUES(1,'ready')`)
	return err
}

func markMigrationStarted(ctx context.Context, db *sql.DB, version, total int) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := db.ExecContext(ctx, `INSERT INTO startup_state(id,state,owner,phase,started_at,updated_at,progress,total,last_error)
VALUES(1,'migrating',?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET state=excluded.state,owner=excluded.owner,phase=excluded.phase,
started_at=excluded.started_at,updated_at=excluded.updated_at,progress=excluded.progress,
total=excluded.total,last_error=excluded.last_error`, migrationOwner(), "schema", now, now, version, total, "")
	return err
}

func updateMigrationStatus(ctx context.Context, db *sql.DB, phase string, progress, total int64) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := db.ExecContext(ctx, `UPDATE startup_state SET state='migrating',phase=?,updated_at=?,progress=?,total=?,last_error='' WHERE id=1`, phase, now, progress, total)
	return err
}

func markMigrationReady(ctx context.Context, db *sql.DB) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := db.ExecContext(ctx, `UPDATE startup_state SET state='ready',phase='',updated_at=?,progress=0,total=0,last_error='' WHERE id=1`, now)
	return err
}

func markMigrationFailed(ctx context.Context, db *sql.DB, err error) {
	// Migration failures often arrive with a cancelled context. Use a short,
	// independent context so the next health check can explain the failure
	// instead of reporting an indistinguishable stale daemon heartbeat.
	statusCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = db.ExecContext(statusCtx, `UPDATE startup_state SET state='failed',phase='',updated_at=?,last_error=? WHERE id=1`, now, boundedMigrationError(err))
}

func parseStartupTime(raw string) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, nil
	}
	value, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, err
	}
	return value.UTC(), nil
}

// HealthStatus reads migration progress first, then falls back to the daemon
// lease once startup work has completed. The migration state is considered
// healthy while its heartbeat is recent; stale or failed migration state is a
// hard error so a genuinely wedged process is still recoverable.
func (s *Store) HealthStatus(ctx context.Context) (HealthStatus, error) {
	var status HealthStatus
	if s == nil || s.DB == nil {
		return status, errors.New("database is not open")
	}
	reader := s.reader()
	var tableCount int
	if err := reader.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='startup_state'`).Scan(&tableCount); err != nil {
		return status, err
	}
	if tableCount > 0 {
		var state, phase, startedRaw, updatedRaw, lastError string
		var progress, total int64
		err := reader.QueryRowContext(ctx, `SELECT state,phase,started_at,updated_at,progress,total,last_error FROM startup_state WHERE id=1`).Scan(&state, &phase, &startedRaw, &updatedRaw, &progress, &total, &lastError)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return status, err
		}
		if err == nil {
			startedAt, parseErr := parseStartupTime(startedRaw)
			if parseErr != nil {
				return status, errors.New("startup migration state is malformed")
			}
			updatedAt, parseErr := parseStartupTime(updatedRaw)
			if parseErr != nil {
				return status, errors.New("startup migration heartbeat is malformed")
			}
			status = HealthStatus{Status: state, Phase: phase, Progress: progress, Total: total, StartedAt: startedAt, UpdatedAt: updatedAt}
			switch state {
			case "migrating":
				status.Status = "starting"
				if updatedAt.IsZero() || time.Since(updatedAt) > migrationHeartbeatTimeout {
					return status, fmt.Errorf("database migration heartbeat is stale: %s", updatedAt)
				}
				return status, nil
			case "failed":
				if lastError == "" {
					return status, errors.New("database migration failed")
				}
				return status, fmt.Errorf("database migration failed: %s", lastError)
			case "ready":
				// Continue to daemon lease validation below.
			}
		}
	}

	var raw string
	if err := reader.QueryRowContext(ctx, `SELECT heartbeat FROM daemon_lease WHERE id=1`).Scan(&raw); err != nil {
		return status, err
	}
	heartbeat, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return status, err
	}
	if time.Since(heartbeat) > 2*time.Minute {
		return status, fmt.Errorf("daemon heartbeat is stale: %s", heartbeat)
	}
	status.Status = "ready"
	status.UpdatedAt = heartbeat.UTC()
	return status, nil
}
