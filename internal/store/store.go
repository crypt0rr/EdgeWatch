package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/google/uuid"
	"modernc.org/sqlite"
)

type Store struct {
	DB          *sql.DB
	Path        string
	authKeyPath string
	authAutoKey bool
}

type rowQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

var ErrJobBusy = errors.New("job is already running")
var ErrLeaseLost = errors.New("daemon lease lost")

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
const schemaVersion = 22

// sqlitePragmaConnector applies connection-scoped SQLite settings whenever
// database/sql opens a physical connection. database/sql can discard a
// connection after a cancelled query, so issuing these PRAGMAs once through
// db.Exec is not sufficient: a replacement connection would silently revert
// to SQLite's defaults.
type sqlitePragmaConnector struct {
	driver.Connector
}

func (c sqlitePragmaConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	execer, ok := conn.(driver.ExecerContext)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("SQLite driver does not support connection setup")
	}
	for _, statement := range []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := execer.ExecContext(ctx, statement, nil); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("database path is empty")
	}
	dsn := path
	memoryDatabase := isSQLiteMemoryPath(path)
	artifactPath := path
	if !memoryDatabase {
		var err error
		artifactPath, err = sqliteArtifactPath(path)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(artifactPath), 0o750); err != nil {
			return nil, err
		}
		if err := ensurePrivateSQLiteFile(artifactPath); err != nil {
			return nil, err
		}
		// Refuse unsafe pre-existing sidecars before SQLite can open or update
		// them. SQLite may follow a WAL/SHM symlink during connection setup, so
		// checking only after the first pragma would leave a small write window.
		if err := enforcePrivateSQLiteArtifacts(artifactPath); err != nil {
			return nil, err
		}
	}
	connector, err := sqlite.NewConnector(dsn)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(sqlitePragmaConnector{Connector: connector})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	for _, pragma := range []string{"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, err
		}
		if !memoryDatabase {
			if err := enforcePrivateSQLiteArtifacts(artifactPath); err != nil {
				db.Close()
				return nil, err
			}
		}
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	if !memoryDatabase {
		if err := enforcePrivateSQLiteArtifacts(artifactPath); err != nil {
			db.Close()
			return nil, err
		}
	}
	return &Store{DB: db, Path: dsn, authKeyPath: defaultAuthKeyPath(artifactPath), authAutoKey: true}, nil
}

// sqliteArtifactPath resolves the on-disk filename represented by a SQLite
// file: URI. The database driver receives the original URI (so query options
// such as mode=rwc remain effective), while permission checks must operate on
// the decoded filename rather than a literal string containing '?mode=…'.
func sqliteArtifactPath(path string) (string, error) {
	if !strings.HasPrefix(path, "file:") {
		return path, nil
	}
	withoutScheme := strings.TrimPrefix(path, "file:")
	if index := strings.IndexByte(withoutScheme, '?'); index >= 0 {
		withoutScheme = withoutScheme[:index]
	}
	if withoutScheme == "" || strings.HasPrefix(withoutScheme, ":memory:") {
		return "", errors.New("filesystem SQLite URI must include a database path")
	}
	// A URI authority is only safe for the local host. SQLite treats a URI
	// with another authority as a VFS-specific path that EdgeWatch cannot
	// reliably permission-check.
	if strings.HasPrefix(withoutScheme, "//") {
		u, err := url.Parse("file:" + withoutScheme)
		if err != nil {
			return "", fmt.Errorf("invalid SQLite database URI: %w", err)
		}
		if u.Host != "" && u.Host != "localhost" {
			return "", errors.New("SQLite database URI must refer to the local host")
		}
		withoutScheme = u.Path
	}
	decoded, err := url.PathUnescape(withoutScheme)
	if err != nil {
		return "", fmt.Errorf("invalid SQLite database URI path: %w", err)
	}
	if decoded == "" {
		return "", errors.New("filesystem SQLite URI must include a database path")
	}
	return decoded, nil
}

func isSQLiteMemoryPath(path string) bool {
	if path == ":memory:" || strings.HasPrefix(path, "file::memory:") {
		return true
	}
	if !strings.HasPrefix(path, "file:") {
		return false
	}
	queryIndex := strings.IndexByte(path, '?')
	if queryIndex < 0 {
		return false
	}
	for _, parameter := range strings.Split(path[queryIndex+1:], "&") {
		key, value, ok := strings.Cut(parameter, "=")
		if ok && key == "mode" && value == "memory" {
			return true
		}
	}
	return false
}

// ensurePrivateSQLiteFile creates the database before the SQLite driver sees
// it and repairs an existing file to owner-only permissions. This makes the
// sensitive database deterministic even when the container umask is 022.
func ensurePrivateSQLiteFile(path string) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("database path must not be a symbolic link: %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	closeErr := file.Close()
	if closeErr != nil {
		return closeErr
	}
	return os.Chmod(path, 0o600)
}

// enforcePrivateSQLiteArtifacts repairs permissions on SQLite's database and
// any sidecar files currently present. SQLite creates WAL/SHM lazily, so this
// is called after connection setup and migrations as well as before opening.
func enforcePrivateSQLiteArtifacts(path string) error {
	for _, candidate := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("database artifact must not be a symbolic link: %s", candidate)
		}
		if err := os.Chmod(candidate, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// SetAuthKeyPath selects an operator-managed authentication key. An explicit
// path is never generated automatically; the default key beside the database
// is generated lazily only when TOTP is first enabled.
func (s *Store) SetAuthKeyPath(path string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	s.authKeyPath = strings.TrimSpace(path)
	s.authAutoKey = false
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
		4: {
			"ALTER TABLE outbox ADD COLUMN claim_token TEXT NOT NULL DEFAULT ''",
			"ALTER TABLE outbox ADD COLUMN claim_until TEXT NOT NULL DEFAULT ''",
			"CREATE INDEX IF NOT EXISTS outbox_claim ON outbox(sent_at, next_at, claim_until)",
		},
		5: {
			"CREATE INDEX IF NOT EXISTS events_created_at ON events(created_at)",
			"CREATE INDEX IF NOT EXISTS job_revisions_created_at ON job_revisions(created_at)",
			"CREATE INDEX IF NOT EXISTS outbox_sent_at ON outbox(sent_at)",
		},
		6: {
			"ALTER TABLE scans ADD COLUMN baseline_scan_id TEXT NOT NULL DEFAULT ''",
			"ALTER TABLE scans ADD COLUMN baseline_config_hash TEXT NOT NULL DEFAULT ''",
			"ALTER TABLE scans ADD COLUMN changes_json BLOB NOT NULL DEFAULT '[]'",
		},
		7: {
			`CREATE TABLE IF NOT EXISTS rdap_cache (
 address TEXT PRIMARY KEY,
 payload_json BLOB NOT NULL,
 fetched_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 stale_until TEXT NOT NULL
);`,
			"CREATE INDEX IF NOT EXISTS rdap_cache_expiry ON rdap_cache(expires_at, stale_until)",
		},
		8: {
			`CREATE TABLE IF NOT EXISTS scan_hosts (
 scan_id TEXT NOT NULL,
 address TEXT NOT NULL,
 job TEXT NOT NULL DEFAULT '',
 address_family TEXT NOT NULL DEFAULT '',
 source_targets_json BLOB NOT NULL DEFAULT '[]',
 dns_names_json BLOB NOT NULL DEFAULT '[]',
 host_json BLOB NOT NULL,
 data_quality TEXT NOT NULL DEFAULT 'detailed',
 open_ports INTEGER NOT NULL DEFAULT 0,
 open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 tcp_present INTEGER NOT NULL DEFAULT 0,
 udp_present INTEGER NOT NULL DEFAULT 0,
 tcp_open_ports INTEGER NOT NULL DEFAULT 0,
 tcp_open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 udp_open_ports INTEGER NOT NULL DEFAULT 0,
 udp_open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(scan_id, address),
 FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);`,
			"CREATE INDEX IF NOT EXISTS scan_hosts_address ON scan_hosts(address)",
			"CREATE INDEX IF NOT EXISTS scan_hosts_scan_address ON scan_hosts(scan_id, address)",
			"CREATE INDEX IF NOT EXISTS scan_hosts_job_address ON scan_hosts(job, address)",
			"CREATE INDEX IF NOT EXISTS scan_hosts_open ON scan_hosts(open_ports, open_filtered_ports)",
		},
		9: {
			"ALTER TABLE setup_tokens ADD COLUMN issued_at TEXT NOT NULL DEFAULT ''",
		},
		10: {
			// Some operators (and older recovery fixtures) may have advanced the
			// schema marker after creating only the authentication tables. Ensure
			// the legacy history table exists before adding the cycle metadata so
			// migration remains incremental and restart-safe.
			`CREATE TABLE IF NOT EXISTS scans (
 id TEXT PRIMARY KEY, job TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL,
 status TEXT NOT NULL, error TEXT NOT NULL DEFAULT '', nmap_version TEXT NOT NULL DEFAULT '',
 config_hash TEXT NOT NULL, snapshot_json BLOB NOT NULL,
 job_id TEXT, job_revision INTEGER,
 baseline_scan_id TEXT NOT NULL DEFAULT '', baseline_config_hash TEXT NOT NULL DEFAULT '',
 changes_json BLOB NOT NULL DEFAULT '[]'
);`,
			"CREATE INDEX IF NOT EXISTS scans_job_time ON scans(job, finished_at DESC)",
			"ALTER TABLE scans ADD COLUMN cycle_id TEXT NOT NULL DEFAULT ''",
			"ALTER TABLE scans ADD COLUMN cycle_attempt INTEGER NOT NULL DEFAULT 0",
			"ALTER TABLE scans ADD COLUMN cycle_status TEXT NOT NULL DEFAULT ''",
			"ALTER TABLE scans ADD COLUMN resumable INTEGER NOT NULL DEFAULT 0",
			"ALTER TABLE scans ADD COLUMN completed_probes INTEGER NOT NULL DEFAULT 0",
			"ALTER TABLE scans ADD COLUMN total_probes INTEGER NOT NULL DEFAULT 0",
			"ALTER TABLE scans ADD COLUMN completed_units INTEGER NOT NULL DEFAULT 0",
			"ALTER TABLE scans ADD COLUMN total_units INTEGER NOT NULL DEFAULT 0",
			"ALTER TABLE scans ADD COLUMN no_progress_attempts INTEGER NOT NULL DEFAULT 0",
			`CREATE TABLE IF NOT EXISTS scan_cycles (
 id TEXT PRIMARY KEY,
 job_id TEXT NOT NULL,
 job TEXT NOT NULL,
 job_revision INTEGER NOT NULL,
 config_hash TEXT NOT NULL,
 execution_hash TEXT NOT NULL,
 plan_json BLOB NOT NULL,
 status TEXT NOT NULL,
 attempt_count INTEGER NOT NULL DEFAULT 0,
 no_progress_attempts INTEGER NOT NULL DEFAULT 0,
 total_units INTEGER NOT NULL,
 completed_units INTEGER NOT NULL DEFAULT 0,
 total_probes INTEGER NOT NULL,
 completed_probes INTEGER NOT NULL DEFAULT 0,
 started_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 finished_at TEXT NOT NULL DEFAULT '',
 last_error TEXT NOT NULL DEFAULT '',
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
);`,
			`CREATE UNIQUE INDEX IF NOT EXISTS scan_cycles_active ON scan_cycles(job_id) WHERE status IN ('running','paused','stalled')`,
			`CREATE INDEX IF NOT EXISTS scan_cycles_expiry ON scan_cycles(status,expires_at)`,
			`CREATE TABLE IF NOT EXISTS scan_cycle_units (
 cycle_id TEXT NOT NULL,
 sequence INTEGER NOT NULL,
 work_unit_json BLOB NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 attempts INTEGER NOT NULL DEFAULT 0,
 snapshot_json BLOB NOT NULL DEFAULT '{}',
 started_at TEXT NOT NULL DEFAULT '',
 finished_at TEXT NOT NULL DEFAULT '',
 last_error TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(cycle_id,sequence),
 FOREIGN KEY(cycle_id) REFERENCES scan_cycles(id) ON DELETE CASCADE
);`,
			"CREATE INDEX IF NOT EXISTS scan_cycle_units_pending ON scan_cycle_units(cycle_id,status,sequence)",
		},
		11: {
			// Keep the stable username as the administrator identity while allowing
			// the console label to be changed without affecting authentication.
			// The table guard also keeps partially-created recovery databases
			// upgradeable when they have a schema marker but no admin row yet.
			`CREATE TABLE IF NOT EXISTS admins (
 id INTEGER PRIMARY KEY CHECK(id=1),
 username TEXT NOT NULL DEFAULT 'admin',
 password_hash TEXT NOT NULL,
 totp_secret TEXT NOT NULL DEFAULT '',
 totp_enabled INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);`,
			"ALTER TABLE admins ADD COLUMN display_name TEXT NOT NULL DEFAULT 'admin'",
		},
		12: {
			// Multi-user authentication keeps the legacy admins table readable for
			// compatibility while making users the authoritative identity store.
			// The fixed UUID gives the original administrator a stable identity and
			// lets existing sessions and recovery codes be migrated without asking
			// the operator to sign in again.
			`CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY,
 username TEXT NOT NULL COLLATE NOCASE UNIQUE,
 display_name TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('administrator','operator','viewer')),
 password_hash TEXT NOT NULL,
 totp_secret TEXT NOT NULL DEFAULT '',
 totp_enabled INTEGER NOT NULL DEFAULT 0,
 enabled INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 last_login_at TEXT NOT NULL DEFAULT ''
);`,
			// A few supported recovery fixtures carry a schema marker without the
			// complete authentication tables. Create their legacy shape before the
			// additive user_id columns below so upgrades remain restart-safe.
			`CREATE TABLE IF NOT EXISTS sessions (
 id_hash TEXT PRIMARY KEY,
 created_at TEXT NOT NULL,
 last_seen_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 csrf_token TEXT NOT NULL
);`,
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
			"ALTER TABLE security_audit ADD COLUMN actor_user_id TEXT NOT NULL DEFAULT ''",
			"ALTER TABLE security_audit ADD COLUMN actor_username TEXT NOT NULL DEFAULT ''",
			`ALTER TABLE sessions ADD COLUMN user_id TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE recovery_codes ADD COLUMN user_id TEXT NOT NULL DEFAULT ''`,
			`CREATE TABLE IF NOT EXISTS user_invites (
 id_hash TEXT PRIMARY KEY,
 user_id TEXT NOT NULL,
 created_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 used_at TEXT,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);`,
			"CREATE INDEX IF NOT EXISTS user_invites_expiry ON user_invites(expires_at, used_at)",
			`CREATE TABLE IF NOT EXISTS public_dashboard (
 id INTEGER PRIMARY KEY CHECK(id=1),
 enabled INTEGER NOT NULL DEFAULT 0,
 title TEXT NOT NULL DEFAULT 'EdgeWatch public status',
 introduction TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL
);`,
			`CREATE TABLE IF NOT EXISTS public_dashboard_hosts (
 dashboard_id INTEGER NOT NULL DEFAULT 1,
 job_id TEXT NOT NULL,
 address TEXT NOT NULL,
 created_at TEXT NOT NULL,
 PRIMARY KEY(dashboard_id,job_id,address),
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
);`,
			"CREATE INDEX IF NOT EXISTS public_dashboard_hosts_address ON public_dashboard_hosts(address)",
			`INSERT OR IGNORE INTO users(id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at)
 SELECT '00000000-0000-0000-0000-000000000001',username,COALESCE(display_name,username),'administrator',password_hash,totp_secret,totp_enabled,1,created_at,updated_at,'' FROM admins WHERE id=1`,
			"UPDATE sessions SET user_id='00000000-0000-0000-0000-000000000001' WHERE user_id=''",
			"UPDATE recovery_codes SET user_id='00000000-0000-0000-0000-000000000001' WHERE user_id=''",
			"INSERT OR IGNORE INTO public_dashboard(id,enabled,title,introduction,updated_at) VALUES(1,0,'EdgeWatch public status','',datetime('now'))",
		},
		13: {
			`CREATE TABLE IF NOT EXISTS application_update_state (
 id INTEGER PRIMARY KEY CHECK(id=1),
 installed_version TEXT NOT NULL DEFAULT '',
 latest_version TEXT NOT NULL DEFAULT '',
 release_url TEXT NOT NULL DEFAULT '',
 release_name TEXT NOT NULL DEFAULT '',
 published_at TEXT NOT NULL DEFAULT '',
 etag TEXT NOT NULL DEFAULT '',
 last_checked_at TEXT NOT NULL DEFAULT '',
 last_successful_check_at TEXT NOT NULL DEFAULT '',
 check_status TEXT NOT NULL DEFAULT 'unknown',
 last_error TEXT NOT NULL DEFAULT '',
 announced_available_version TEXT NOT NULL DEFAULT '',
 announced_upgrade_version TEXT NOT NULL DEFAULT ''
);`,
			`INSERT OR IGNORE INTO application_update_state(id,check_status) VALUES(1,'unknown')`,
		},
		14: {
			// Scanner profiles are append-only definitions. Jobs retain the
			// selected revision, so editing a profile never changes an existing
			// scan's effective command implicitly.
			`CREATE TABLE IF NOT EXISTS scans (
 id TEXT PRIMARY KEY, job TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL,
 status TEXT NOT NULL, error TEXT NOT NULL DEFAULT '', nmap_version TEXT NOT NULL DEFAULT '',
 config_hash TEXT NOT NULL, snapshot_json BLOB NOT NULL,
 job_id TEXT, job_revision INTEGER,
 baseline_scan_id TEXT NOT NULL DEFAULT '', baseline_config_hash TEXT NOT NULL DEFAULT '',
 changes_json BLOB NOT NULL DEFAULT '[]', cycle_id TEXT NOT NULL DEFAULT '',
 cycle_attempt INTEGER NOT NULL DEFAULT 0, cycle_status TEXT NOT NULL DEFAULT '',
 resumable INTEGER NOT NULL DEFAULT 0, completed_probes INTEGER NOT NULL DEFAULT 0,
 total_probes INTEGER NOT NULL DEFAULT 0, completed_units INTEGER NOT NULL DEFAULT 0,
 total_units INTEGER NOT NULL DEFAULT 0, no_progress_attempts INTEGER NOT NULL DEFAULT 0
);`,
			`CREATE TABLE IF NOT EXISTS scanner_profiles (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL COLLATE NOCASE,
 description TEXT NOT NULL DEFAULT '',
 definition_json BLOB NOT NULL,
 built_in INTEGER NOT NULL DEFAULT 0,
 archived INTEGER NOT NULL DEFAULT 0,
 revision INTEGER NOT NULL DEFAULT 1,
 created_by TEXT NOT NULL DEFAULT '',
 updated_by TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 UNIQUE(name)
);`,
			`CREATE TABLE IF NOT EXISTS scanner_profile_revisions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 profile_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 definition_json BLOB NOT NULL,
 created_by TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 UNIQUE(profile_id, revision),
 FOREIGN KEY(profile_id) REFERENCES scanner_profiles(id) ON DELETE CASCADE
);`,
			"CREATE INDEX IF NOT EXISTS scanner_profiles_active ON scanner_profiles(archived,name)",
			"CREATE INDEX IF NOT EXISTS scanner_profile_revisions_profile ON scanner_profile_revisions(profile_id,revision DESC)",
			"ALTER TABLE scans ADD COLUMN scanner_engine TEXT NOT NULL DEFAULT 'nmap'",
			"ALTER TABLE scans ADD COLUMN scanner_profile_id TEXT NOT NULL DEFAULT ''",
			"ALTER TABLE scans ADD COLUMN scanner_profile_revision INTEGER NOT NULL DEFAULT 0",
			"ALTER TABLE scans ADD COLUMN naabu_version TEXT NOT NULL DEFAULT ''",
			"ALTER TABLE scans ADD COLUMN discovery_ports INTEGER NOT NULL DEFAULT 0",
			"ALTER TABLE scans ADD COLUMN confirmed_ports INTEGER NOT NULL DEFAULT 0",
			"ALTER TABLE scans ADD COLUMN discovery_duration_ms INTEGER NOT NULL DEFAULT 0",
			"ALTER TABLE scans ADD COLUMN enrichment_duration_ms INTEGER NOT NULL DEFAULT 0",
		},
		15: {
			// Keep an exact, maintained latest-host projection so inventory reads do
			// not rank the complete retained scan history on every request. The
			// projection intentionally has no foreign key to scans: when retention
			// removes a source scan it is rebuilt from the remaining history, which
			// preserves the legacy "latest retained successful observation" semantics.
			// Source observations retain a foreign key so pruning a scan cannot leak
			// its detailed host rows.
			// A few supported recovery fixtures carry a schema marker without the
			// indexed host table; ensure the source table exists before backfilling.
			`CREATE TABLE IF NOT EXISTS scan_hosts (
 scan_id TEXT NOT NULL,
 address TEXT NOT NULL,
 job TEXT NOT NULL DEFAULT '',
 address_family TEXT NOT NULL DEFAULT '',
 source_targets_json BLOB NOT NULL DEFAULT '[]',
 dns_names_json BLOB NOT NULL DEFAULT '[]',
 host_json BLOB NOT NULL,
 data_quality TEXT NOT NULL DEFAULT 'detailed',
 open_ports INTEGER NOT NULL DEFAULT 0,
 open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 tcp_present INTEGER NOT NULL DEFAULT 0,
 udp_present INTEGER NOT NULL DEFAULT 0,
 tcp_open_ports INTEGER NOT NULL DEFAULT 0,
 tcp_open_filtered_ports INTEGER NOT NULL DEFAULT 0,
			udp_open_ports INTEGER NOT NULL DEFAULT 0,
			udp_open_filtered_ports INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY(scan_id, address),
			FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);`,
			`CREATE TABLE IF NOT EXISTS latest_scan_hosts (
 address TEXT PRIMARY KEY,
 scan_id TEXT NOT NULL,
 job_id TEXT NOT NULL DEFAULT '',
 job TEXT NOT NULL DEFAULT '',
 finished_at TEXT NOT NULL,
 data_quality TEXT NOT NULL DEFAULT 'detailed',
 address_family TEXT NOT NULL DEFAULT '',
 source_targets_json BLOB NOT NULL DEFAULT '[]',
 dns_names_json BLOB NOT NULL DEFAULT '[]',
 host_json BLOB NOT NULL,
 open_ports INTEGER NOT NULL DEFAULT 0,
 open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 tcp_present INTEGER NOT NULL DEFAULT 0,
 udp_present INTEGER NOT NULL DEFAULT 0,
 tcp_open_ports INTEGER NOT NULL DEFAULT 0,
 tcp_open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 udp_open_ports INTEGER NOT NULL DEFAULT 0,
 udp_open_filtered_ports INTEGER NOT NULL DEFAULT 0
);`,
			"CREATE INDEX IF NOT EXISTS latest_scan_hosts_open ON latest_scan_hosts(open_ports, open_filtered_ports)",
			"CREATE INDEX IF NOT EXISTS latest_scan_hosts_protocol_open ON latest_scan_hosts(tcp_present, udp_present, tcp_open_ports, udp_open_ports)",
			`INSERT OR IGNORE INTO latest_scan_hosts(address,scan_id,job_id,job,finished_at,data_quality,address_family,source_targets_json,dns_names_json,host_json,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports)
SELECT address,scan_id,COALESCE(job_id,''),job,finished_at,data_quality,address_family,source_targets_json,dns_names_json,host_json,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports
FROM (
 SELECT h.address,h.scan_id,s.job_id,s.job,s.finished_at,h.data_quality,h.address_family,h.source_targets_json,h.dns_names_json,h.host_json,h.open_ports,h.open_filtered_ports,h.tcp_present,h.udp_present,h.tcp_open_ports,h.tcp_open_filtered_ports,h.udp_open_ports,h.udp_open_filtered_ports,
        ROW_NUMBER() OVER (PARTITION BY h.address ORDER BY s.finished_at DESC,s.id DESC) AS rn
 FROM scan_hosts h JOIN scans s ON s.id=h.scan_id
 WHERE s.status='success'
) ranked WHERE rn=1;`,
		},
		16: {
			// A reconciliation marker lets the resumable Naabu pipeline process
			// only newly completed discovery units. The marker and any generated
			// enrichment work are committed together, so a restart either repeats
			// the complete transaction or observes it as finished.
			`CREATE TABLE IF NOT EXISTS scan_cycle_discovery_checkpoints (
 cycle_id TEXT NOT NULL,
 sequence INTEGER NOT NULL,
 processed_at TEXT NOT NULL,
 PRIMARY KEY(cycle_id, sequence),
 FOREIGN KEY(cycle_id) REFERENCES scan_cycles(id) ON DELETE CASCADE
);`,
			"CREATE INDEX IF NOT EXISTS scan_cycle_discovery_checkpoints_cycle ON scan_cycle_discovery_checkpoints(cycle_id,sequence)",
		},
		17: {
			// Record the resolved client address on security audits. The value is
			// only populated when the HTTP layer has explicitly trusted its direct
			// reverse proxy; otherwise it is the peer address observed by Go.
			"ALTER TABLE security_audit ADD COLUMN source_ip TEXT NOT NULL DEFAULT ''",
		},
		18: {
			// Host inventory search must not scan the serialized host payload on
			// every request. These FTS5 projections contain only a normalized,
			// lower-case search document for the fields users can search (address,
			// job, configured targets, DNS names, hostnames, and services). The
			// trigram tokenizer preserves partial IP/name/service searches while
			// keeping the large evidence JSON out of the query predicates.
			`CREATE VIRTUAL TABLE IF NOT EXISTS scan_host_search USING fts5(
 scan_id UNINDEXED,
 address UNINDEXED,
 content,
 tokenize='trigram'
);`,
			`CREATE VIRTUAL TABLE IF NOT EXISTS latest_host_search USING fts5(
 address UNINDEXED,
 content,
 tokenize='trigram'
);`,
			`CREATE TRIGGER IF NOT EXISTS scan_hosts_search_ai AFTER INSERT ON scan_hosts BEGIN
 INSERT INTO scan_host_search(scan_id,address,content)
 VALUES(NEW.scan_id,NEW.address,lower(coalesce(NEW.address,'') || ' ' || coalesce(NEW.job,'') || ' ' || coalesce(NEW.source_targets_json,'') || ' ' || coalesce(NEW.dns_names_json,'') || ' ' || coalesce(NEW.host_json,'')));
END;`,
			`CREATE TRIGGER IF NOT EXISTS scan_hosts_search_au AFTER UPDATE ON scan_hosts BEGIN
 DELETE FROM scan_host_search WHERE rowid IN (SELECT rowid FROM scan_host_search WHERE scan_id=OLD.scan_id AND address=OLD.address);
 INSERT INTO scan_host_search(scan_id,address,content)
 VALUES(NEW.scan_id,NEW.address,lower(coalesce(NEW.address,'') || ' ' || coalesce(NEW.job,'') || ' ' || coalesce(NEW.source_targets_json,'') || ' ' || coalesce(NEW.dns_names_json,'') || ' ' || coalesce(NEW.host_json,'')));
END;`,
			`CREATE TRIGGER IF NOT EXISTS scan_hosts_search_ad AFTER DELETE ON scan_hosts BEGIN
 DELETE FROM scan_host_search WHERE rowid IN (SELECT rowid FROM scan_host_search WHERE scan_id=OLD.scan_id AND address=OLD.address);
END;`,
			`CREATE TRIGGER IF NOT EXISTS latest_scan_hosts_search_ai AFTER INSERT ON latest_scan_hosts BEGIN
 INSERT INTO latest_host_search(address,content)
 VALUES(NEW.address,lower(coalesce(NEW.address,'') || ' ' || coalesce(NEW.job,'') || ' ' || coalesce(NEW.source_targets_json,'') || ' ' || coalesce(NEW.dns_names_json,'') || ' ' || coalesce(NEW.host_json,'')));
END;`,
			`CREATE TRIGGER IF NOT EXISTS latest_scan_hosts_search_au AFTER UPDATE ON latest_scan_hosts BEGIN
 DELETE FROM latest_host_search WHERE rowid IN (SELECT rowid FROM latest_host_search WHERE address=OLD.address);
 INSERT INTO latest_host_search(address,content)
 VALUES(NEW.address,lower(coalesce(NEW.address,'') || ' ' || coalesce(NEW.job,'') || ' ' || coalesce(NEW.source_targets_json,'') || ' ' || coalesce(NEW.dns_names_json,'') || ' ' || coalesce(NEW.host_json,'')));
END;`,
			`CREATE TRIGGER IF NOT EXISTS latest_scan_hosts_search_ad AFTER DELETE ON latest_scan_hosts BEGIN
 DELETE FROM latest_host_search WHERE rowid IN (SELECT rowid FROM latest_host_search WHERE address=OLD.address);
END;`,
		},
		19: {
			// Keep durable delivery outcomes by stable destination identity. The
			// outbox itself uses revisioned managed selectors, so the identity is
			// canonicalized to managed:<id> (or the already-hashed deployment key)
			// by the store before it is written here. URLs and provider responses
			// never enter this table.
			`CREATE TABLE IF NOT EXISTS notification_delivery_health (
 destination_identity TEXT PRIMARY KEY,
 terminal_failures INTEGER NOT NULL DEFAULT 0,
 last_success_at TEXT NOT NULL DEFAULT '',
 last_failure_at TEXT NOT NULL DEFAULT '',
 last_terminal_at TEXT NOT NULL DEFAULT '',
 last_error_code TEXT NOT NULL DEFAULT '',
 last_error_fingerprint TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL
);`,
			"CREATE INDEX IF NOT EXISTS notification_delivery_health_updated ON notification_delivery_health(updated_at)",
		},
		20: {
			// Keep the FTS documents bounded to fields that are intentionally
			// searchable. Earlier migrations accidentally indexed the complete
			// host evidence JSON, making every scan commit pay for trigram tokens
			// over service metadata, state summaries, and command fingerprints.
			"ALTER TABLE scan_hosts ADD COLUMN search_text TEXT NOT NULL DEFAULT ''",
			"ALTER TABLE latest_scan_hosts ADD COLUMN search_text TEXT NOT NULL DEFAULT ''",
			"DROP TRIGGER IF EXISTS scan_hosts_search_ai",
			"DROP TRIGGER IF EXISTS scan_hosts_search_au",
			"DROP TRIGGER IF EXISTS scan_hosts_search_ad",
			"DROP TRIGGER IF EXISTS latest_scan_hosts_search_ai",
			"DROP TRIGGER IF EXISTS latest_scan_hosts_search_au",
			"DROP TRIGGER IF EXISTS latest_scan_hosts_search_ad",
			`CREATE TRIGGER scan_hosts_search_ai AFTER INSERT ON scan_hosts BEGIN
 INSERT INTO scan_host_search(scan_id,address,content)
 VALUES(NEW.scan_id,NEW.address,lower(coalesce(NEW.search_text,'') || ' ' || coalesce(NEW.address,'') || ' ' || coalesce(NEW.job,'') || ' ' || coalesce(NEW.source_targets_json,'') || ' ' || coalesce(NEW.dns_names_json,'')));
END;`,
			`CREATE TRIGGER scan_hosts_search_au AFTER UPDATE ON scan_hosts BEGIN
 DELETE FROM scan_host_search WHERE rowid IN (SELECT rowid FROM scan_host_search WHERE scan_id=OLD.scan_id AND address=OLD.address);
 INSERT INTO scan_host_search(scan_id,address,content)
 VALUES(NEW.scan_id,NEW.address,lower(coalesce(NEW.search_text,'') || ' ' || coalesce(NEW.address,'') || ' ' || coalesce(NEW.job,'') || ' ' || coalesce(NEW.source_targets_json,'') || ' ' || coalesce(NEW.dns_names_json,'')));
END;`,
			`CREATE TRIGGER scan_hosts_search_ad AFTER DELETE ON scan_hosts BEGIN
 DELETE FROM scan_host_search WHERE rowid IN (SELECT rowid FROM scan_host_search WHERE scan_id=OLD.scan_id AND address=OLD.address);
END;`,
			`CREATE TRIGGER latest_scan_hosts_search_ai AFTER INSERT ON latest_scan_hosts BEGIN
 INSERT INTO latest_host_search(address,content)
 VALUES(NEW.address,lower(coalesce(NEW.search_text,'') || ' ' || coalesce(NEW.address,'') || ' ' || coalesce(NEW.job,'') || ' ' || coalesce(NEW.source_targets_json,'') || ' ' || coalesce(NEW.dns_names_json,'')));
END;`,
			`CREATE TRIGGER latest_scan_hosts_search_au AFTER UPDATE ON latest_scan_hosts BEGIN
 DELETE FROM latest_host_search WHERE rowid IN (SELECT rowid FROM latest_host_search WHERE address=OLD.address);
 INSERT INTO latest_host_search(address,content)
 VALUES(NEW.address,lower(coalesce(NEW.search_text,'') || ' ' || coalesce(NEW.address,'') || ' ' || coalesce(NEW.job,'') || ' ' || coalesce(NEW.source_targets_json,'') || ' ' || coalesce(NEW.dns_names_json,'')));
END;`,
			`CREATE TRIGGER latest_scan_hosts_search_ad AFTER DELETE ON latest_scan_hosts BEGIN
 DELETE FROM latest_host_search WHERE rowid IN (SELECT rowid FROM latest_host_search WHERE address=OLD.address);
END;`,
		},
		21: {
			// Managed history queries are keyed by the stable job identity rather
			// than the legacy display name. Keep the ordering columns in the same
			// indexes used by the console and retain a dedicated cycle index for
			// resumable-cycle promotion checks. The revision index also keeps
			// retention's current-revision protection set-based as history grows.
			"CREATE INDEX IF NOT EXISTS scans_job_id_time ON scans(job_id, finished_at DESC, id DESC)",
			"CREATE INDEX IF NOT EXISTS scans_job_id_revision ON scans(job_id, job_revision)",
			"CREATE INDEX IF NOT EXISTS scans_finished_at ON scans(finished_at DESC)",
			"CREATE INDEX IF NOT EXISTS scans_cycle_id ON scans(cycle_id)",
		},
		22: {
			// Large FTS rebuilds are resumable and run in bounded transactions. The
			// state rows are initialized by backfillHostSearchIndexes after the
			// migration commits, so a restart can continue from the last rowid.
			// The additive column guards also make supported recovery fixtures with a
			// schema marker but an older host-table shape safe to upgrade.
			"ALTER TABLE scan_hosts ADD COLUMN search_text TEXT NOT NULL DEFAULT ''",
			"ALTER TABLE latest_scan_hosts ADD COLUMN search_text TEXT NOT NULL DEFAULT ''",
			`CREATE TABLE IF NOT EXISTS fts_backfill_state (
 table_name TEXT PRIMARY KEY,
 last_rowid INTEGER NOT NULL DEFAULT 0,
 initialized INTEGER NOT NULL DEFAULT 0,
 complete INTEGER NOT NULL DEFAULT 0,
 updated_at TEXT NOT NULL
);`,
			"CREATE INDEX IF NOT EXISTS fts_backfill_state_complete ON fts_backfill_state(complete,table_name)",
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
	if err := repairScanHostsForeignKey(db); err != nil {
		return err
	}
	if err := backfillHostSearchIndexes(db); err != nil {
		return err
	}
	return ensureBuiltinScannerProfiles(db)
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
	ErrNotFound                  = errors.New("not found")
	ErrConflict                  = errors.New("resource was modified by another request")
	ErrRebaselineRequired        = errors.New("security-relevant job changes require rebaseline confirmation")
	ErrJobScanActive             = errors.New("job has an active scan")
	ErrLastAdministrator         = errors.New("at least one enabled administrator is required")
	ErrIncidentNotFound          = errors.New("incident not found")
	ErrBaselineNotReady          = errors.New("baseline is not ready")
	ErrUnsupportedIncidentChange = errors.New("unsupported incident change")
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO jobs(id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES(?,?,?, ?,0,1,?,?)`, id, job.Name, raw, boolInt(enabled), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return JobRecord{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO job_revisions(job_id,revision,definition_json,security_hash,created_at) VALUES(?,?,?,?,?)`, id, 1, raw, hash, now.Format(time.RFC3339Nano)); err != nil {
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
	// Keep archived jobs grouped after active and paused jobs. The web console
	// requests archived records so they can be restored, and ordering only by
	// name otherwise lets an archived job appear between active entries.
	query += ` ORDER BY archived ASC, name, id`
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
	defer tx.Rollback()
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
	if err := insertAuditEntries(ctx, tx, audits, now); err != nil {
		return err
	}
	return tx.Commit()
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

// ScanHost is an indexed effective-address observation. The complete host
// evidence remains in Host, while the scan_hosts table stores summary columns
// used to filter and paginate without decoding unrelated scan snapshots.
type ScanHost struct {
	ScanID      string
	DataQuality string
	Host        model.HostObservation
}

// LatestScanHost is an indexed host observation enriched with the scan/job
// metadata needed by the global Hosts view.
type LatestScanHost struct {
	ScanHost
	JobID     string
	Job       string
	ScannedAt time.Time
}

type hostFilter struct {
	where      []string
	args       []any
	searchText string
}

func buildHostFilter(query, protocol string, hasOpen *bool) hostFilter {
	filter := hostFilter{}
	if query = strings.TrimSpace(strings.ToLower(query)); query != "" {
		filter.searchText = query
	}
	if protocol == "tcp" {
		filter.where = append(filter.where, "h.tcp_present=1")
		if hasOpen != nil {
			if *hasOpen {
				filter.where = append(filter.where, "(h.tcp_open_ports > 0 OR h.tcp_open_filtered_ports > 0)")
			} else {
				filter.where = append(filter.where, "h.tcp_open_ports = 0 AND h.tcp_open_filtered_ports = 0")
			}
		}
	} else if protocol == "udp" {
		filter.where = append(filter.where, "h.udp_present=1")
		if hasOpen != nil {
			if *hasOpen {
				filter.where = append(filter.where, "(h.udp_open_ports > 0 OR h.udp_open_filtered_ports > 0)")
			} else {
				filter.where = append(filter.where, "h.udp_open_ports = 0 AND h.udp_open_filtered_ports = 0")
			}
		}
	} else if hasOpen != nil {
		if *hasOpen {
			filter.where = append(filter.where, "(h.open_ports > 0 OR h.open_filtered_ports > 0)")
		} else {
			filter.where = append(filter.where, "h.open_ports = 0 AND h.open_filtered_ports = 0")
		}
	}
	return filter
}

// hostSearchMatchQuery quotes a user-provided value as one FTS phrase. The
// trigram tokenizer then supports partial addresses, names, and service text
// without allowing FTS operators to alter the query semantics.
func hostSearchMatchQuery(query string) string {
	return `"` + strings.ReplaceAll(query, `"`, `""`) + `"`
}

func hostSearchPredicate(filter hostFilter, searchTable string, keyColumns string) (join, predicate string, args []any) {
	if filter.searchText == "" {
		return "", "", nil
	}
	join = " JOIN " + searchTable + " hs ON " + keyColumns
	if len([]rune(filter.searchText)) < 3 {
		return join, "hs.content LIKE ? ESCAPE '\\'", []any{"%" + escapeLikePattern(filter.searchText) + "%"}
	}
	return join, searchTable + " MATCH ?", []any{hostSearchMatchQuery(filter.searchText)}
}

// escapeLikePattern keeps the short-query fallback literal. FTS5 handles
// wildcard characters safely when a value is quoted as a phrase, but the
// one- and two-character path uses LIKE for trigram-tokenizer boundaries.
func escapeLikePattern(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	value = strings.ReplaceAll(value, `_`, `\_`)
	return value
}

func scanHostStats(host model.HostObservation) (open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered int) {
	for _, protocol := range host.Protocols {
		switch protocol.Protocol {
		case "tcp":
			tcpPresent = 1
		case "udp":
			udpPresent = 1
		}
		for _, port := range protocol.Ports {
			switch port.State {
			case "open":
				open++
				if protocol.Protocol == "tcp" {
					tcpOpen++
				} else if protocol.Protocol == "udp" {
					udpOpen++
				}
			case "open|filtered":
				openFiltered++
				if protocol.Protocol == "tcp" {
					tcpOpenFiltered++
				} else if protocol.Protocol == "udp" {
					udpOpenFiltered++
				}
			}
		}
	}
	return
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
	rows, err := s.DB.QueryContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,changes_json,snapshot_json FROM scans WHERE job_id=? ORDER BY finished_at DESC,id DESC LIMIT ? OFFSET ?`, jobID, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var v model.Scan
		var jid sql.NullString
		var revision sql.NullInt64
		var started, finished string
		var snapshot, changesJSON []byte
		var baselineScanID, baselineConfigHash string
		var resumable int
		if err := rows.Scan(&v.ID, &jid, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &baselineScanID, &baselineConfigHash, &changesJSON, &snapshot); err != nil {
			return page, err
		}
		v.Resumable = resumable != 0
		if jid.Valid {
			v.JobID = jid.String
		}
		if revision.Valid {
			v.JobRevision = revision.Int64
		}
		v.StartedAt, v.FinishedAt = scanTime(started), scanTime(finished)
		v.BaselineScanID, v.BaselineConfigHash = baselineScanID, baselineConfigHash
		if len(changesJSON) > 0 && string(changesJSON) != "null" {
			if err := json.Unmarshal(changesJSON, &v.Changes); err != nil {
				return page, err
			}
		}
		if err := json.Unmarshal(snapshot, &v.Snapshot); err != nil {
			return page, err
		}
		page.Items = append(page.Items, v)
	}
	return page, rows.Err()
}

// ListJobScanSummariesPage returns only the metadata needed by a paginated
// history view. Full snapshots are intentionally left to GetScan/results.
func (s *Store) ListJobScanSummariesPage(ctx context.Context, jobID string, limit, offset int) (Page[model.ScanSummary], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[model.ScanSummary]
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE job_id=?`, jobID).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash FROM scans WHERE job_id=? ORDER BY finished_at DESC,id DESC LIMIT ? OFFSET ?`, jobID, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var v model.ScanSummary
		var jid sql.NullString
		var revision sql.NullInt64
		var started, finished string
		var resumable int
		if err := rows.Scan(&v.ID, &jid, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &v.BaselineScanID, &v.BaselineConfigHash); err != nil {
			return page, err
		}
		v.Resumable = resumable != 0
		if jid.Valid {
			v.JobID = jid.String
		}
		if revision.Valid {
			v.JobRevision = revision.Int64
		}
		v.StartedAt, v.FinishedAt = scanTime(started), scanTime(finished)
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

// RuntimeBaselineMeta reads only the baseline identifiers from runtime JSON.
// Host pages use this fast path before deciding whether they need the full
// legacy state snapshot.
func (s *Store) RuntimeBaselineMeta(ctx context.Context, jobID string) (scanID, configHash string, err error) {
	var scan, hash sql.NullString
	err = s.DB.QueryRowContext(ctx, `SELECT json_extract(state_json,'$.baseline_scan_id'), json_extract(state_json,'$.baseline_config_hash') FROM job_runtime WHERE job_id=?`, jobID).Scan(&scan, &hash)
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
	err := s.DB.QueryRowContext(ctx, `SELECT json_extract(state_json,'$.baseline_modified') FROM job_runtime WHERE job_id=?`, jobID).Scan(&marker)
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
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
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
	events, err := updateRuntimeTxWithOutbox(ctx, tx, jobID, destinations, fn)
	if err != nil {
		return nil, err
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
	if job.SecurityHash() != securityHash {
		if err := saveScanExec(ctx, tx, *scan); err != nil {
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
	events, err := fn(&state)
	if err != nil {
		return nil, err
	}
	return persistRuntimeTx(ctx, tx, jobID, state, events)
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
	return s.updateRuntimeWithOutboxAndAuditsGuarded(ctx, jobID, "", destinations, audits, true, func(state *model.JobState) ([]model.Event, error) {
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
	defer tx.Rollback()
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

func (s *Store) SaveScan(ctx context.Context, scan model.Scan) error {
	return saveScanExec(ctx, s.DB, scan)
}

func saveScanExec(ctx context.Context, execer contextExecer, scan model.Scan) error {
	snapshot, err := json.Marshal(scan.Snapshot)
	if err != nil {
		return err
	}
	changes := scan.Changes
	if changes == nil {
		changes = []model.Change{}
	}
	changesJSON, err := json.Marshal(changes)
	if err != nil {
		return err
	}
	_, err = execer.ExecContext(ctx, `INSERT INTO scans(id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,changes_json,snapshot_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		scan.ID, nullString(scan.JobID), nullInt64(scan.JobRevision), scan.Job, scan.StartedAt.UTC().Format(time.RFC3339Nano), scan.FinishedAt.UTC().Format(time.RFC3339Nano), scan.Status, scan.Error, scan.NmapVersion, scan.ScannerEngine, scan.ScannerProfileID, scan.ScannerProfileRevision, scan.NaabuVersion, scan.DiscoveryPorts, scan.ConfirmedPorts, scan.DiscoveryDurationMS, scan.EnrichmentDurationMS, scan.ConfigHash, scan.CycleID, scan.CycleAttempt, scan.CycleStatus, boolInt(scan.Resumable), scan.CompletedProbes, scan.TotalProbes, scan.CompletedUnits, scan.TotalUnits, scan.NoProgressTries, scan.BaselineScanID, scan.BaselineConfigHash, changesJSON, snapshot)
	if err != nil {
		return err
	}
	return saveScanHostsExec(ctx, execer, scan)
}

func loadScanMetadata(ctx context.Context, queryer rowQueryer, id string, scan *model.Scan) error {
	if scan == nil {
		return nil
	}
	return queryer.QueryRowContext(ctx, `SELECT scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms FROM scans WHERE id=?`, id).Scan(&scan.ScannerEngine, &scan.ScannerProfileID, &scan.ScannerProfileRevision, &scan.NaabuVersion, &scan.DiscoveryPorts, &scan.ConfirmedPorts, &scan.DiscoveryDurationMS, &scan.EnrichmentDurationMS)
}

func loadScanSummaryMetadata(ctx context.Context, queryer rowQueryer, id string, scan *model.ScanSummary) error {
	if scan == nil {
		return nil
	}
	return queryer.QueryRowContext(ctx, `SELECT scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms FROM scans WHERE id=?`, id).Scan(&scan.ScannerEngine, &scan.ScannerProfileID, &scan.ScannerProfileRevision, &scan.NaabuVersion, &scan.DiscoveryPorts, &scan.ConfirmedPorts, &scan.DiscoveryDurationMS, &scan.EnrichmentDurationMS)
}

func saveScanHostsExec(ctx context.Context, execer contextExecer, scan model.Scan) error {
	if len(scan.Snapshot.Hosts) == 0 {
		return nil
	}
	// Normalize a copy so the indexed payload has stable ordering without
	// mutating the immutable snapshot that the caller may still hold.
	hosts := append([]model.HostObservation(nil), scan.Snapshot.Hosts...)
	hostSnapshot := model.Snapshot{Hosts: hosts}
	hostSnapshot.Normalize()
	for _, host := range hostSnapshot.Hosts {
		address := strings.TrimSpace(host.Address)
		if net.ParseIP(address) == nil {
			continue
		}
		hostJSON, err := json.Marshal(host)
		if err != nil {
			return err
		}
		sourceTargets, err := json.Marshal(host.SourceTargets)
		if err != nil {
			return err
		}
		dnsNames, err := json.Marshal(host.DNSNames)
		if err != nil {
			return err
		}
		searchText := hostSearchContent(scan.Job, host)
		open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered := scanHostStats(host)
		if _, err := execer.ExecContext(ctx, `INSERT INTO scan_hosts(scan_id,address,job,address_family,source_targets_json,dns_names_json,host_json,search_text,data_quality,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			scan.ID, address, scan.Job, host.AddressFamily, sourceTargets, dnsNames, hostJSON, searchText, "detailed", open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered); err != nil {
			return err
		}
		if scan.Status == "success" {
			if err := upsertLatestScanHostExec(ctx, execer, scan, address, host.AddressFamily, sourceTargets, dnsNames, hostJSON, searchText, open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered); err != nil {
				return err
			}
		}
	}
	return nil
}

const maxHostSearchTextBytes = 64 * 1024

// hostSearchContent is deliberately built from the small set of fields that
// the host inventory promises to search. Keeping the serialized evidence out
// of this document bounds FTS maintenance time as service and Nmap metadata
// grows while preserving address, job, target, DNS, hostname, port, and
// service searches. Values are de-duplicated and the document has a hard byte
// cap so a host with thousands of open services cannot recreate the old
// host_json write amplification through the search projection.
func hostSearchContent(job string, host model.HostObservation) string {
	var builder strings.Builder
	seen := make(map[string]struct{})
	appendValue := func(raw string) bool {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value == "" {
			return true
		}
		if _, exists := seen[value]; exists {
			return true
		}
		if builder.Len()+len(value)+1 > maxHostSearchTextBytes {
			return false
		}
		seen[value] = struct{}{}
		builder.WriteString(value)
		builder.WriteByte(' ')
		return true
	}
	if !appendValue(host.Address) || !appendValue(job) {
		return strings.TrimSpace(builder.String())
	}
	for _, target := range host.SourceTargets {
		if !appendValue(target) {
			return strings.TrimSpace(builder.String())
		}
	}
	for _, name := range host.DNSNames {
		if !appendValue(name) {
			return strings.TrimSpace(builder.String())
		}
	}
	for _, hostname := range host.Hostnames {
		if !appendValue(hostname.Name) {
			return strings.TrimSpace(builder.String())
		}
	}
	for _, protocol := range host.Protocols {
		for _, port := range protocol.Ports {
			if !appendValue(strconv.Itoa(port.Port)) {
				return strings.TrimSpace(builder.String())
			}
			if port.Service == nil {
				continue
			}
			service := port.Service
			for _, value := range []string{service.Name, service.Product, service.Version, service.ExtraInfo, service.OSType, service.DeviceType} {
				if !appendValue(value) {
					return strings.TrimSpace(builder.String())
				}
			}
			for _, cpe := range service.CPEs {
				if !appendValue(cpe) {
					return strings.TrimSpace(builder.String())
				}
			}
		}
	}
	return strings.TrimSpace(builder.String())
}

func backfillHostSearchTextTx(tx *sql.Tx) error {
	type hostRow struct {
		rowID int64
		job   string
		addr  string
		raw   []byte
	}
	load := func(query string) ([]hostRow, error) {
		rows, err := tx.Query(query)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []hostRow
		for rows.Next() {
			var row hostRow
			if err := rows.Scan(&row.rowID, &row.job, &row.addr, &row.raw); err != nil {
				return nil, err
			}
			out = append(out, row)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return out, nil
	}
	backfill := func(table string, rows []hostRow) error {
		for _, row := range rows {
			var host model.HostObservation
			if len(row.raw) > 0 {
				_ = json.Unmarshal(row.raw, &host)
			}
			host.Address = row.addr
			searchText := hostSearchContent(row.job, host)
			if _, err := tx.Exec(`UPDATE `+table+` SET search_text=? WHERE rowid=?`, searchText, row.rowID); err != nil {
				return err
			}
		}
		return nil
	}
	scanRows, err := load(`SELECT rowid,job,address,host_json FROM scan_hosts`)
	if err != nil {
		return err
	}
	if err := backfill("scan_hosts", scanRows); err != nil {
		return err
	}
	latestRows, err := load(`SELECT rowid,job,address,host_json FROM latest_scan_hosts`)
	if err != nil {
		return err
	}
	return backfill("latest_scan_hosts", latestRows)
}

// upsertLatestScanHostExec maintains the exact latest successful observation
// for one effective address. The finished-at/id ordering mirrors the historical
// ranking query, including deterministic ties between scans with equal times.
func upsertLatestScanHostExec(ctx context.Context, execer contextExecer, scan model.Scan, address, addressFamily string, sourceTargets, dnsNames, hostJSON []byte, searchText string, open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered int) error {
	finishedAt := scan.FinishedAt.UTC().Format(time.RFC3339Nano)
	_, err := execer.ExecContext(ctx, `INSERT INTO latest_scan_hosts(address,scan_id,job_id,job,finished_at,data_quality,address_family,source_targets_json,dns_names_json,host_json,search_text,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(address) DO UPDATE SET
 scan_id=excluded.scan_id,
 job_id=excluded.job_id,
 job=excluded.job,
 finished_at=excluded.finished_at,
 data_quality=excluded.data_quality,
 address_family=excluded.address_family,
 source_targets_json=excluded.source_targets_json,
	dns_names_json=excluded.dns_names_json,
	host_json=excluded.host_json,
	search_text=excluded.search_text,
	open_ports=excluded.open_ports,
 open_filtered_ports=excluded.open_filtered_ports,
 tcp_present=excluded.tcp_present,
 udp_present=excluded.udp_present,
 tcp_open_ports=excluded.tcp_open_ports,
 tcp_open_filtered_ports=excluded.tcp_open_filtered_ports,
 udp_open_ports=excluded.udp_open_ports,
 udp_open_filtered_ports=excluded.udp_open_filtered_ports
WHERE excluded.finished_at > latest_scan_hosts.finished_at
   OR (excluded.finished_at = latest_scan_hosts.finished_at AND excluded.scan_id > latest_scan_hosts.scan_id)`,
		address, scan.ID, scan.JobID, scan.Job, finishedAt, "detailed", addressFamily, sourceTargets, dnsNames, hostJSON, searchText, open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered)
	return err
}

func normalizeStoredHostAddress(raw string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "", fmt.Errorf("host address is not a valid IP: %s", raw)
	}
	return ip.String(), nil
}

func decodeScanHost(address, dataQuality string, raw []byte) (ScanHost, error) {
	normalized, err := normalizeStoredHostAddress(address)
	if err != nil {
		return ScanHost{}, err
	}
	var host model.HostObservation
	if err := json.Unmarshal(raw, &host); err != nil {
		return ScanHost{}, err
	}
	host.Address = normalized
	return ScanHost{DataQuality: dataQuality, Host: host}, nil
}

// ListScanHostsPage reads indexed effective hosts for one scan. The SQL
// predicates run before LIMIT/OFFSET, so a page request never needs to load
// unrelated host payloads into Go.
func (s *Store) ListScanHostsPage(ctx context.Context, scanID, query, protocol string, hasOpen *bool, limit, offset int) (Page[ScanHost], error) {
	limit, offset = normalizePage(limit, offset)
	filter := buildHostFilter(query, protocol, hasOpen)
	where := append([]string{"h.scan_id=?"}, filter.where...)
	args := append([]any{scanID}, filter.args...)
	join, predicate, searchArgs := hostSearchPredicate(filter, "scan_host_search", "hs.scan_id=h.scan_id AND hs.address=h.address")
	if predicate != "" {
		where = append(where, predicate)
		args = append(args, searchArgs...)
	}
	var page Page[ScanHost]
	countQuery := `SELECT COUNT(*) FROM scan_hosts h` + join + ` WHERE ` + strings.Join(where, " AND ")
	if err := s.DB.QueryRowContext(ctx, countQuery, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	querySQL := `SELECT h.address,h.data_quality,h.host_json FROM scan_hosts h` + join + ` WHERE ` + strings.Join(where, " AND ") + ` ORDER BY h.address LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.DB.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var address, dataQuality string
		var raw []byte
		if err := rows.Scan(&address, &dataQuality, &raw); err != nil {
			return page, err
		}
		item, err := decodeScanHost(address, dataQuality, raw)
		if err != nil {
			return page, err
		}
		item.ScanID = scanID
		page.Items = append(page.Items, item)
	}
	return page, rows.Err()
}

// ScanHostIndexExists reports whether a scan has the incremental host index.
// It is separate from a filtered page's Total: a valid indexed scan can have
// zero matches for a particular query and must not fall back to decoding its
// complete snapshot.
func (s *Store) ScanHostIndexExists(ctx context.Context, scanID string) (bool, error) {
	var exists bool
	err := s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM scan_hosts WHERE scan_id=?)`, scanID).Scan(&exists)
	return exists, err
}

// SuccessfulScanHostIndexExists is the global equivalent used by the Hosts
// view to distinguish an indexed database (including a zero-match filter)
// from a wholly legacy database.
func (s *Store) SuccessfulScanHostIndexExists(ctx context.Context) (bool, error) {
	var exists bool
	err := s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM scan_hosts h JOIN scans s ON s.id=h.scan_id WHERE s.status='success')`).Scan(&exists)
	return exists, err
}

// GetScanHost returns one indexed effective host, or ErrNotFound when the scan
// predates the host index or the address was not part of that scan.
func (s *Store) GetScanHost(ctx context.Context, scanID, address string) (ScanHost, error) {
	normalized, err := normalizeStoredHostAddress(address)
	if err != nil {
		return ScanHost{}, fmt.Errorf("%w: host %s", ErrNotFound, address)
	}
	var dataQuality string
	var raw []byte
	err = s.DB.QueryRowContext(ctx, `SELECT data_quality,host_json FROM scan_hosts WHERE scan_id=? AND address=?`, scanID, normalized).Scan(&dataQuality, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ScanHost{}, fmt.Errorf("%w: host %s", ErrNotFound, normalized)
	}
	if err != nil {
		return ScanHost{}, err
	}
	item, err := decodeScanHost(normalized, dataQuality, raw)
	if err != nil {
		return ScanHost{}, err
	}
	item.ScanID = scanID
	return item, nil
}

// ListLatestScanHostsPage returns the maintained newest successful observation
// for each effective address across all jobs. The projection is updated in the
// same transaction as a successful scan and rebuilt after retention deletes.
func (s *Store) ListLatestScanHostsPage(ctx context.Context, query, protocol string, hasOpen *bool, limit, offset int) (Page[LatestScanHost], error) {
	limit, offset = normalizePage(limit, offset)
	filter := buildHostFilter(query, protocol, hasOpen)
	where := filter.where
	if len(where) == 0 {
		where = []string{"1=1"}
	}
	args := append([]any(nil), filter.args...)
	join, predicate, searchArgs := hostSearchPredicate(filter, "latest_host_search", "hs.address=h.address")
	if predicate != "" {
		where = append(where, predicate)
		args = append(args, searchArgs...)
	}
	var page Page[LatestScanHost]
	countQuery := `SELECT COUNT(*) FROM latest_scan_hosts h` + join + ` WHERE ` + strings.Join(where, " AND ")
	if err := s.DB.QueryRowContext(ctx, countQuery, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	querySQL := `SELECT h.scan_id,h.address,h.data_quality,h.host_json,h.job_id,h.job,h.finished_at FROM latest_scan_hosts h` + join + ` WHERE ` + strings.Join(where, " AND ") + ` ORDER BY h.address LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.DB.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var scanID, address, dataQuality, job, finished string
		var jobID sql.NullString
		var raw []byte
		if err := rows.Scan(&scanID, &address, &dataQuality, &raw, &jobID, &job, &finished); err != nil {
			return page, err
		}
		item, err := decodeScanHost(address, dataQuality, raw)
		if err != nil {
			return page, err
		}
		parsed := scanTime(finished)
		page.Items = append(page.Items, LatestScanHost{ScanHost: ScanHost{ScanID: scanID, DataQuality: dataQuality, Host: item.Host}, JobID: jobID.String, Job: job, ScannedAt: parsed})
	}
	return page, rows.Err()
}

func (s *Store) GetScan(ctx context.Context, id string) (model.Scan, error) {
	var v model.Scan
	var started, finished string
	var snapshot, changesJSON []byte
	var baselineScanID, baselineConfigHash string
	var jobID sql.NullString
	var revision sql.NullInt64
	var resumable int
	err := s.DB.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,changes_json,snapshot_json FROM scans WHERE id=?`, id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &baselineScanID, &baselineConfigHash, &changesJSON, &snapshot)
	if err != nil {
		return v, err
	}
	if jobID.Valid {
		v.JobID = jobID.String
	}
	if revision.Valid {
		v.JobRevision = revision.Int64
	}
	v.Resumable = resumable != 0
	v.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
	v.FinishedAt, _ = time.Parse(time.RFC3339Nano, finished)
	v.BaselineScanID, v.BaselineConfigHash = baselineScanID, baselineConfigHash
	if len(changesJSON) > 0 && string(changesJSON) != "null" {
		if err := json.Unmarshal(changesJSON, &v.Changes); err != nil {
			return v, err
		}
	}
	if err := json.Unmarshal(snapshot, &v.Snapshot); err != nil {
		return v, err
	}
	if err := loadScanMetadata(ctx, s.DB, id, &v); err != nil {
		return v, err
	}
	return v, nil
}

// GetScanSummary returns scan metadata without reading either the snapshot or
// the serialized change list. History/detail views use this method so a broad
// scan cannot cause a hidden full-result allocation.
func (s *Store) GetScanSummary(ctx context.Context, id string) (model.ScanSummary, error) {
	var v model.ScanSummary
	var started, finished string
	var jobID sql.NullString
	var revision sql.NullInt64
	var resumable int
	err := s.DB.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash FROM scans WHERE id=?`, id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &v.BaselineScanID, &v.BaselineConfigHash)
	if err != nil {
		return v, err
	}
	if jobID.Valid {
		v.JobID = jobID.String
	}
	if revision.Valid {
		v.JobRevision = revision.Int64
	}
	v.Resumable = resumable != 0
	v.StartedAt, v.FinishedAt = scanTime(started), scanTime(finished)
	if err := loadScanSummaryMetadata(ctx, s.DB, id, &v); err != nil {
		return v, err
	}
	return v, nil
}

// GetScanComparison returns scan metadata and the immutable scan-time change
// list without loading snapshot_json. Legacy rows without a scan-time
// comparison can be resolved through GetScan when callers need to recreate
// their historical diff against the then-current baseline behavior.
func (s *Store) GetScanComparison(ctx context.Context, id string) (model.ScanSummary, []model.Change, error) {
	var v model.ScanSummary
	var started, finished string
	var changesJSON []byte
	var jobID sql.NullString
	var revision sql.NullInt64
	var resumable int
	err := s.DB.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,changes_json FROM scans WHERE id=?`, id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &v.BaselineScanID, &v.BaselineConfigHash, &changesJSON)
	if err != nil {
		return v, nil, err
	}
	if jobID.Valid {
		v.JobID = jobID.String
	}
	if revision.Valid {
		v.JobRevision = revision.Int64
	}
	v.Resumable = resumable != 0
	v.StartedAt, v.FinishedAt = scanTime(started), scanTime(finished)
	if err := loadScanSummaryMetadata(ctx, s.DB, id, &v); err != nil {
		return v, nil, err
	}
	var changes []model.Change
	if len(changesJSON) > 0 && string(changesJSON) != "null" {
		if err := json.Unmarshal(changesJSON, &changes); err != nil {
			return v, nil, err
		}
	}
	return v, changes, nil
}

// ListScanChangesPage reads only one page of the immutable scan-time diff.
// Changes are stored as a JSON array for backwards-compatible scan records;
// SQLite's json_each keeps pagination in the database so the web handler does
// not deserialize the entire change list merely to return the first page.
// Legacy rows with a NULL/empty array naturally return an empty page and are
// handled by the caller's explicit compatibility path.
func (s *Store) ListScanChangesPage(ctx context.Context, id string, limit, offset int) (Page[model.Change], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[model.Change]
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans, json_each(scans.changes_json) WHERE scans.id=?`, id).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT json_each.value FROM scans, json_each(scans.changes_json) WHERE scans.id=? ORDER BY json_each.key LIMIT ? OFFSET ?`, id, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return page, err
		}
		var change model.Change
		if err := json.Unmarshal(raw, &change); err != nil {
			return page, err
		}
		page.Items = append(page.Items, change)
	}
	return page, rows.Err()
}

// ListScanResultsPage reads one page of snapshot units directly from the
// persisted JSON document. The explicit results endpoint can therefore show a
// broad scan incrementally without first materializing every host in Go.
func (s *Store) ListScanResultsPage(ctx context.Context, id string, limit, offset int) (Page[model.Unit], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[model.Unit]
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans, json_each(scans.snapshot_json, '$.units') WHERE scans.id=?`, id).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT json_each.value FROM scans, json_each(scans.snapshot_json, '$.units') WHERE scans.id=? ORDER BY json_each.key LIMIT ? OFFSET ?`, id, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return page, err
		}
		var unit model.Unit
		if err := json.Unmarshal(raw, &unit); err != nil {
			return page, err
		}
		page.Items = append(page.Items, unit)
	}
	return page, rows.Err()
}

// RDAPCacheEntry is the normalized, deliberately non-sensitive representation
// kept for on-demand registry enrichment. Raw RDAP documents and contact
// details never enter this table.
type RDAPCacheEntry struct {
	Address    string
	Payload    []byte
	FetchedAt  time.Time
	ExpiresAt  time.Time
	StaleUntil time.Time
}

func normalizeRDAPAddress(raw string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "", errors.New("RDAP cache address must be a valid IP")
	}
	return ip.String(), nil
}

func (s *Store) GetRDAPCache(ctx context.Context, address string) (RDAPCacheEntry, error) {
	normalized, err := normalizeRDAPAddress(address)
	if err != nil {
		return RDAPCacheEntry{}, fmt.Errorf("%w: %s", ErrNotFound, strings.TrimSpace(address))
	}
	var entry RDAPCacheEntry
	var fetched, expires, stale string
	var payload []byte
	err = s.DB.QueryRowContext(ctx, `SELECT address,payload_json,fetched_at,expires_at,stale_until FROM rdap_cache WHERE address=?`, normalized).Scan(&entry.Address, &payload, &fetched, &expires, &stale)
	if errors.Is(err, sql.ErrNoRows) {
		return RDAPCacheEntry{}, fmt.Errorf("%w: RDAP cache %s", ErrNotFound, address)
	}
	if err != nil {
		return RDAPCacheEntry{}, err
	}
	entry.Payload = append([]byte(nil), payload...)
	entry.FetchedAt, entry.ExpiresAt, entry.StaleUntil = scanTime(fetched), scanTime(expires), scanTime(stale)
	return entry, nil
}

func (s *Store) PutRDAPCache(ctx context.Context, entry RDAPCacheEntry) error {
	address, err := normalizeRDAPAddress(entry.Address)
	if err != nil || len(entry.Payload) == 0 {
		return errors.New("RDAP cache entry is incomplete")
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO rdap_cache(address,payload_json,fetched_at,expires_at,stale_until) VALUES(?,?,?,?,?) ON CONFLICT(address) DO UPDATE SET payload_json=excluded.payload_json,fetched_at=excluded.fetched_at,expires_at=excluded.expires_at,stale_until=excluded.stale_until`, address, entry.Payload, entry.FetchedAt.UTC().Format(time.RFC3339Nano), entry.ExpiresAt.UTC().Format(time.RFC3339Nano), entry.StaleUntil.UTC().Format(time.RFC3339Nano))
	return err
}

func getScanTx(ctx context.Context, tx *sql.Tx, id string) (model.Scan, error) {
	var v model.Scan
	var started, finished string
	var snapshot, changesJSON []byte
	var baselineScanID, baselineConfigHash string
	var jobID sql.NullString
	var revision sql.NullInt64
	var resumable int
	err := tx.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,changes_json,snapshot_json FROM scans WHERE id=?`, id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &baselineScanID, &baselineConfigHash, &changesJSON, &snapshot)
	if err != nil {
		return v, err
	}
	if jobID.Valid {
		v.JobID = jobID.String
	}
	if revision.Valid {
		v.JobRevision = revision.Int64
	}
	v.Resumable = resumable != 0
	v.StartedAt, v.FinishedAt = scanTime(started), scanTime(finished)
	v.BaselineScanID, v.BaselineConfigHash = baselineScanID, baselineConfigHash
	if len(changesJSON) > 0 && string(changesJSON) != "null" {
		if err := json.Unmarshal(changesJSON, &v.Changes); err != nil {
			return v, err
		}
	}
	if err := json.Unmarshal(snapshot, &v.Snapshot); err != nil {
		return v, err
	}
	if err := loadScanMetadata(ctx, tx, id, &v); err != nil {
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
	query := `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,changes_json,snapshot_json FROM scans`
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
		var snapshot, changesJSON []byte
		var baselineScanID, baselineConfigHash string
		var resumable int
		if err := rows.Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &baselineScanID, &baselineConfigHash, &changesJSON, &snapshot); err != nil {
			return page, err
		}
		v.Resumable = resumable != 0
		if jobID.Valid {
			v.JobID = jobID.String
		}
		if revision.Valid {
			v.JobRevision = revision.Int64
		}
		v.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
		v.FinishedAt, _ = time.Parse(time.RFC3339Nano, finished)
		v.BaselineScanID, v.BaselineConfigHash = baselineScanID, baselineConfigHash
		if len(changesJSON) > 0 && string(changesJSON) != "null" {
			if err := json.Unmarshal(changesJSON, &v.Changes); err != nil {
				return page, err
			}
		}
		if err := json.Unmarshal(snapshot, &v.Snapshot); err != nil {
			return page, err
		}
		page.Items = append(page.Items, v)
	}
	return page, rows.Err()
}

// ListScanSummariesPage is the metadata-only counterpart to ListScansPage.
// Filtering remains name-based for compatibility with legacy CLI callers.
func (s *Store) ListScanSummariesPage(ctx context.Context, job string, limit, offset int) (Page[model.ScanSummary], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[model.ScanSummary]
	query := `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash FROM scans`
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
		var v model.ScanSummary
		var jobID sql.NullString
		var revision sql.NullInt64
		var started, finished string
		var resumable int
		if err := rows.Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &v.BaselineScanID, &v.BaselineConfigHash); err != nil {
			return page, err
		}
		v.Resumable = resumable != 0
		if jobID.Valid {
			v.JobID = jobID.String
		}
		if revision.Valid {
			v.JobRevision = revision.Int64
		}
		v.StartedAt, v.FinishedAt = scanTime(started), scanTime(finished)
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
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL AND attempts >= ?`, deliveryMaxAttempts).Scan(&count)
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

// JobIncident is the bounded API representation of one active incident. The
// incident itself remains in the runtime JSON for atomic state transitions,
// while list methods below use SQLite's json_each to page without decoding the
// complete incident map into Go memory.
type JobIncident struct {
	JobID    string
	Job      string
	Incident model.Incident
}

func (s *Store) ListJobIncidentsPage(ctx context.Context, jobID string, limit, offset int) (Page[model.Incident], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[model.Incident]
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_runtime, json_each(job_runtime.state_json, '$.incidents') WHERE job_runtime.job_id=?`, jobID).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT json_each.value FROM job_runtime, json_each(job_runtime.state_json, '$.incidents') WHERE job_runtime.job_id=? ORDER BY json_each.key LIMIT ? OFFSET ?`, jobID, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return page, err
		}
		var incident model.Incident
		if err := json.Unmarshal(raw, &incident); err != nil {
			return page, err
		}
		page.Items = append(page.Items, incident)
	}
	return page, rows.Err()
}

func (s *Store) ListIncidentsPage(ctx context.Context, limit, offset int) (Page[JobIncident], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[JobIncident]
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_runtime JOIN jobs ON jobs.id=job_runtime.job_id, json_each(job_runtime.state_json, '$.incidents')`).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT jobs.id,jobs.name,json_each.value FROM job_runtime JOIN jobs ON jobs.id=job_runtime.job_id, json_each(job_runtime.state_json, '$.incidents') ORDER BY jobs.name,json_each.key LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var item JobIncident
		var raw []byte
		if err := rows.Scan(&item.JobID, &item.Job, &raw); err != nil {
			return page, err
		}
		if err := json.Unmarshal(raw, &item.Incident); err != nil {
			return page, err
		}
		page.Items = append(page.Items, item)
	}
	return page, rows.Err()
}

func emptyState() model.JobState { s := model.JobState{}; ensureMaps(&s); return s }
func ensureMaps(s *model.JobState) {
	if s.Pending == nil {
		s.Pending = map[string]model.Pending{}
	}
	if s.Incidents == nil {
		s.Incidents = map[string]model.Incident{}
	}
	if s.Suppressed == nil {
		s.Suppressed = map[string]int{}
	}
	if s.SuppressedChanges == nil {
		s.SuppressedChanges = map[string]model.Change{}
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
	for i := range events {
		bounded, payload, marshalErr := model.MarshalBoundedEvent(events[i], model.EventPayloadLimit)
		if marshalErr != nil {
			return nil, marshalErr
		}
		events[i] = bounded
		event := events[i]
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
	_, b, err := model.MarshalBoundedEvent(event, model.EventPayloadLimit)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if strings.HasPrefix(destination, "managed:") {
		valid, validationErr := managedDestinationCurrentTx(ctx, tx, destination)
		if validationErr != nil {
			return validationErr
		}
		if !valid {
			return tx.Commit()
		}
	}
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO outbox(destination,payload_json,next_at) VALUES(?,?,?)`, destination, b, now.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if inserted, _ := result.RowsAffected(); inserted == 1 {
		if err := ensureDeliveryHealthTx(ctx, tx, destination, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type Delivery struct {
	ID          int64
	Destination string
	Event       model.Event
	Attempts    int
	ClaimToken  string
}

func (s *Store) DueDeliveries(ctx context.Context, limit int) ([]Delivery, error) {
	return s.ClaimDueDeliveries(ctx, limit, uuid.NewString())
}

var ErrDeliveryClaimLost = errors.New("notification delivery claim was lost")

const (
	deliveryClaimLease   = 30 * time.Minute
	deliveryMaxAttempts  = 8
	deliveryInitialDelay = 2 * time.Minute
	deliveryMaxDelay     = time.Hour
)

// ClaimDueDeliveries atomically leases due outbox rows to one drain owner.
// Expired claims can be recovered by a later process, while active claims are
// invisible to concurrent drains until the owner records a result.
func (s *Store) ClaimDueDeliveries(ctx context.Context, limit int, owner string) ([]Delivery, error) {
	return s.claimDueDeliveries(ctx, limit, owner, nil)
}

// ClaimDueDeliveriesExcluding leases due outbox rows while skipping the
// supplied destination identities. The notifier uses this for destinations
// whose credentials are currently unavailable so one locked backlog cannot
// occupy every delivery slot needed by healthy destinations.
func (s *Store) ClaimDueDeliveriesExcluding(ctx context.Context, limit int, owner string, excluded []string) ([]Delivery, error) {
	return s.claimDueDeliveries(ctx, limit, owner, excluded)
}

func (s *Store) claimDueDeliveries(ctx context.Context, limit int, owner string, excluded []string) ([]Delivery, error) {
	if limit < 1 {
		return nil, nil
	}
	if owner == "" {
		owner = uuid.NewString()
	}
	now := time.Now().UTC()
	query := `UPDATE outbox SET claim_token=?,claim_until=? WHERE id IN (SELECT id FROM outbox WHERE sent_at IS NULL AND attempts < ? AND next_at <= ? AND (claim_token='' OR claim_until='' OR claim_until <= ?)`
	args := []any{owner, now.Add(deliveryClaimLease).Format(time.RFC3339Nano), deliveryMaxAttempts, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)}
	if len(excluded) > 0 {
		placeholders := make([]string, 0, len(excluded))
		for _, destination := range excluded {
			if strings.TrimSpace(destination) == "" {
				continue
			}
			placeholders = append(placeholders, "?")
			args = append(args, destination)
		}
		if len(placeholders) > 0 {
			query += " AND destination NOT IN (" + strings.Join(placeholders, ",") + ")"
		}
	}
	query += ` ORDER BY id LIMIT ?) RETURNING id,destination,payload_json,attempts,claim_token`
	args = append(args, limit)
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Delivery
	for rows.Next() {
		var d Delivery
		var b []byte
		if err := rows.Scan(&d.ID, &d.Destination, &b, &d.Attempts, &d.ClaimToken); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &d.Event); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ReleaseDeliveryClaims clears all active outbox leases. It is used when a
// daemon starts (or shuts down cleanly) so rows claimed by a previous process
// do not remain unavailable for the full claim lease. Delivery attempts and
// next-at timestamps are intentionally preserved; only ownership is reset.
func (s *Store) ReleaseDeliveryClaims(ctx context.Context) (int64, error) {
	result, err := s.DB.ExecContext(ctx, `UPDATE outbox SET claim_token='',claim_until='' WHERE sent_at IS NULL AND claim_token<>''`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// DeliveryResult records the result for the current claim. It retains the
// original API used by CLI/tests by looking up the row's active claim token.
func (s *Store) DeliveryResult(ctx context.Context, id int64, sendErr error) error {
	var claim string
	if err := s.DB.QueryRowContext(ctx, `SELECT claim_token FROM outbox WHERE id=?`, id).Scan(&claim); err != nil {
		return err
	}
	return s.DeliveryResultClaim(ctx, id, claim, sendErr)
}

func (s *Store) DeliveryResultClaim(ctx context.Context, id int64, claim string, sendErr error) error {
	if claim == "" {
		return ErrDeliveryClaimLost
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var attempts int
	var destination string
	if err := tx.QueryRowContext(ctx, `SELECT attempts,destination FROM outbox WHERE id=? AND sent_at IS NULL AND claim_token=?`, id, claim).Scan(&attempts, &destination); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeliveryClaimLost
		}
		return err
	}
	now := time.Now().UTC()
	if sendErr == nil {
		result, err := tx.ExecContext(ctx, `UPDATE outbox SET sent_at=?,last_error='',claim_token='',claim_until='' WHERE id=? AND sent_at IS NULL AND claim_token=?`, now.Format(time.RFC3339Nano), id, claim)
		if err != nil {
			return err
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return ErrDeliveryClaimLost
		}
		if err := recordDeliverySuccessTx(ctx, tx, destination, now); err != nil {
			return err
		}
		return tx.Commit()
	}
	attempts++
	terminal := attempts >= deliveryMaxAttempts
	delay := deliveryRetryDelay(attempts)
	result, err := tx.ExecContext(ctx, `UPDATE outbox SET attempts=?,next_at=?,last_error=?,claim_token='',claim_until='' WHERE id=? AND sent_at IS NULL AND claim_token=?`, attempts, now.Add(delay).Format(time.RFC3339Nano), deliveryErrorCode(sendErr), id, claim)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrDeliveryClaimLost
	}
	if err := recordDeliveryFailureTx(ctx, tx, destination, sendErr, terminal, now); err != nil {
		return err
	}
	if terminal {
		fingerprint := deliveryErrorFingerprint(sendErr)
		event := model.Event{Type: "notification-delivery-terminal", Message: fmt.Sprintf("Notification delivery dropped after retry limit (destination fingerprint %s; error code %s; error fingerprint %s)", deliverySelectorFingerprint(destination), deliveryErrorCode(sendErr), fingerprint), CreatedAt: now}
		bounded, payload, marshalErr := model.MarshalBoundedEvent(event, model.EventPayloadLimit)
		if marshalErr != nil {
			return marshalErr
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO events(type,job,scan_id,payload_json,created_at) VALUES(?,?,?,?,?)`, bounded.Type, "", "", payload, now.Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func deliveryRetryDelay(attempts int) time.Duration {
	if attempts < 1 {
		return deliveryInitialDelay
	}
	shift := attempts - 1
	if shift > 6 {
		shift = 6
	}
	delay := deliveryInitialDelay * time.Duration(1<<shift)
	if delay > deliveryMaxDelay {
		return deliveryMaxDelay
	}
	return delay
}

// DeferDelivery releases a claim without consuming an attempt. This is used
// when an encrypted managed destination is temporarily locked or unavailable.
func (s *Store) DeferDelivery(ctx context.Context, id int64, claim, reason string, delay time.Duration) error {
	if claim == "" {
		return ErrDeliveryClaimLost
	}
	if delay < time.Minute {
		delay = time.Minute
	}
	result, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=?,last_error=?,claim_token='',claim_until='' WHERE id=? AND sent_at IS NULL AND claim_token=?`, time.Now().UTC().Add(delay).Format(time.RFC3339Nano), deliveryErrorCode(errors.New(reason)), id, claim)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrDeliveryClaimLost
	}
	return nil
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

// PruneStats reports rows removed by one retention pass. Security audit rows
// are intentionally absent: they are an accountability record and are kept
// indefinitely unless an operator explicitly removes the database.
type PruneStats struct {
	Scans        int64
	Events       int64
	SentOutbox   int64
	FailedOutbox int64
	Revisions    int64
	Cycles       int64
	RDAPCache    int64
}

func (p PruneStats) Total() int64 {
	return p.Scans + p.Events + p.SentOutbox + p.FailedOutbox + p.Revisions + p.Cycles + p.RDAPCache
}

// Prune removes rows outside the configured retention window while preserving
// every active baseline scan and the current revision of each job. Delivery
// rows that are still pending (or have retry attempts remaining) are never
// removed; only sent rows and terminal failures are eligible. The operation is
// transactional so a crash cannot leave a partially pruned history set.
func (s *Store) PruneWithStats(ctx context.Context, before time.Time) (PruneStats, error) {
	var stats PruneStats
	cutoff := before.UTC().Format(time.RFC3339Nano)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return stats, err
	}
	defer tx.Rollback()

	// NOT EXISTS avoids SQL's NULL semantics: most state rows do not yet have a
	// baseline_scan_id, and a NOT IN subquery containing NULL would protect every
	// old scan from pruning.
	result, err := tx.ExecContext(ctx, `DELETE FROM scans AS scan WHERE scan.finished_at < ?
		AND NOT EXISTS (SELECT 1 FROM job_states AS legacy WHERE json_extract(legacy.state_json,'$.baseline_scan_id') = scan.id)
		AND NOT EXISTS (SELECT 1 FROM job_runtime AS managed WHERE json_extract(managed.state_json,'$.baseline_scan_id') = scan.id)
		AND NOT EXISTS (SELECT 1 FROM job_runtime AS active, json_each(active.state_json,'$.incidents') AS incident WHERE json_extract(incident.value,'$.scan_id') = scan.id)`, cutoff)
	if err != nil {
		return stats, err
	}
	stats.Scans, _ = result.RowsAffected()
	if stats.Scans > 0 {
		// A projection row is a copy rather than a foreign-key child of its
		// source scan. Rebuild it after cascaded scan deletion so an older
		// retained observation becomes visible when the previous latest row
		// expires.
		if err := rebuildLatestScanHostsTx(ctx, tx); err != nil {
			return stats, err
		}
	}

	result, err = tx.ExecContext(ctx, `DELETE FROM events WHERE created_at < ?`, cutoff)
	if err != nil {
		return stats, err
	}
	stats.Events, _ = result.RowsAffected()

	result, err = tx.ExecContext(ctx, `DELETE FROM outbox WHERE sent_at IS NOT NULL AND sent_at < ?`, cutoff)
	if err != nil {
		return stats, err
	}
	stats.SentOutbox, _ = result.RowsAffected()

	result, err = tx.ExecContext(ctx, `DELETE FROM outbox WHERE sent_at IS NULL AND attempts >= ? AND next_at < ?`, deliveryMaxAttempts, cutoff)
	if err != nil {
		return stats, err
	}
	stats.FailedOutbox, _ = result.RowsAffected()

	// Keep the newest revision for every job regardless of age. Older revisions
	// contain immutable historical definitions and may be discarded after their
	// retention window because scans retain their own snapshots.
	result, err = tx.ExecContext(ctx, `DELETE FROM job_revisions
			WHERE created_at < ?
			AND revision < COALESCE((SELECT MAX(current.revision) FROM jobs AS current WHERE current.id = job_revisions.job_id), revision)
			AND NOT EXISTS (SELECT 1 FROM scans WHERE scans.job_id = job_revisions.job_id AND scans.job_revision = job_revisions.revision)`, cutoff)
	if err != nil {
		return stats, err
	}
	stats.Revisions, _ = result.RowsAffected()

	// Cycle metadata is part of the resumable execution history. Keep active
	// cycles indefinitely (their finished_at is empty) and keep terminal cycles
	// while a retained scan still points at them. Once both the cycle and any
	// referencing scan fall outside retention, the unit checkpoints can be
	// removed through the foreign-key cascade without leaving unbounded plan
	// metadata behind.
	result, err = tx.ExecContext(ctx, `DELETE FROM scan_cycles AS cycle
		WHERE cycle.finished_at <> '' AND cycle.finished_at < ?
		AND cycle.status IN ('completed','discarded','expired')
		AND NOT EXISTS (SELECT 1 FROM scans WHERE scans.cycle_id = cycle.id)`, cutoff)
	if err != nil {
		return stats, err
	}
	stats.Cycles, _ = result.RowsAffected()

	// RDAP registration data is a short-lived enrichment cache rather than
	// retained scan history. Remove rows once their seven-day stale window has
	// elapsed, even when the deployment retains scans for much longer.
	rdapCutoff := time.Now().UTC().Format(time.RFC3339Nano)
	result, err = tx.ExecContext(ctx, `DELETE FROM rdap_cache WHERE stale_until < ?`, rdapCutoff)
	if err != nil {
		return stats, err
	}
	stats.RDAPCache, _ = result.RowsAffected()

	if err := tx.Commit(); err != nil {
		return stats, err
	}
	return stats, nil
}

func rebuildLatestScanHostsTx(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM latest_scan_hosts`); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO latest_scan_hosts(address,scan_id,job_id,job,finished_at,data_quality,address_family,source_targets_json,dns_names_json,host_json,search_text,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports)
SELECT address,scan_id,COALESCE(job_id,''),job,finished_at,data_quality,address_family,source_targets_json,dns_names_json,host_json,search_text,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports
FROM (
 SELECT h.address,h.scan_id,s.job_id,s.job,s.finished_at,h.data_quality,h.address_family,h.source_targets_json,h.dns_names_json,h.host_json,h.search_text,h.open_ports,h.open_filtered_ports,h.tcp_present,h.udp_present,h.tcp_open_ports,h.tcp_open_filtered_ports,h.udp_open_ports,h.udp_open_filtered_ports,
        ROW_NUMBER() OVER (PARTITION BY h.address ORDER BY s.finished_at DESC,s.id DESC) AS rn
 FROM scan_hosts h JOIN scans s ON s.id=h.scan_id
 WHERE s.status='success'
) ranked WHERE rn=1`)
	return err
}

// Prune is retained for callers that only need the total row count.
func (s *Store) Prune(ctx context.Context, before time.Time) (int64, error) {
	stats, err := s.PruneWithStats(ctx, before)
	return stats.Total(), err
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
		return ErrLeaseLost
	}
	return nil
}

// ReleaseAllJobLeases clears scan leases after the daemon has acquired the
// exclusive daemon lease. A process that crashed cannot run its deferred
// release, so without this reconciliation a job would remain blocked until
// its full scan timeout. The daemon lease makes clearing all rows safe.
func (s *Store) ReleaseAllJobLeases(ctx context.Context) (int64, error) {
	result, err := s.DB.ExecContext(ctx, `DELETE FROM job_leases`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
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
		return []model.Event{{Type: "baseline-approved", Job: job, ScanID: scan.ID, Message: "Baseline manually approved", CreatedAt: time.Now().UTC()}}, nil
	})
}
func (s *Store) ResetBaseline(ctx context.Context, job string) ([]model.Event, error) {
	return s.UpdateState(ctx, job, func(state *model.JobState) ([]model.Event, error) {
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
		return []model.Event{{Type: "baseline-reset", Job: job, Message: "Baseline collection reset", CreatedAt: time.Now().UTC()}}, nil
	})
}
