package store

import (
	"database/sql"
	"fmt"
	"strings"
)

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
const schemaVersion = 26

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
		23: {
			// User mutations are optimistic-concurrency guarded just like jobs,
			// notifications, and scanner profiles. Keep the additive migration
			// restart-safe for recovery fixtures that may have a schema marker but
			// not yet have the users table.
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
 last_login_at TEXT NOT NULL DEFAULT '',
 revision INTEGER NOT NULL DEFAULT 1
);`,
			"ALTER TABLE users ADD COLUMN revision INTEGER NOT NULL DEFAULT 1",
			"UPDATE users SET revision=1 WHERE revision IS NULL OR revision < 1",
		},
		24: {
			// Update notifications may be routed to an explicit subset of the
			// configured destinations. An empty string preserves the legacy
			// behavior (all globally enabled destinations); a JSON array, including
			// [], is an administrator-owned explicit selection.
			"ALTER TABLE application_update_state ADD COLUMN notification_destinations_json TEXT NOT NULL DEFAULT ''",
		},
		25: {
			// FTS rows use the source table's rowid as their stable key. This makes
			// trigger maintenance a direct indexed delete instead of repeatedly
			// searching the entire virtual table by unindexed scan/address columns.
			// Drop the old trigger set and clear the projections; the normal bounded
			// backfill after migrations repopulates them with matching rowids.
			"DROP TRIGGER IF EXISTS scan_hosts_search_ai",
			"DROP TRIGGER IF EXISTS scan_hosts_search_au",
			"DROP TRIGGER IF EXISTS scan_hosts_search_ad",
			"DROP TRIGGER IF EXISTS latest_scan_hosts_search_ai",
			"DROP TRIGGER IF EXISTS latest_scan_hosts_search_au",
			"DROP TRIGGER IF EXISTS latest_scan_hosts_search_ad",
			"DELETE FROM scan_host_search",
			"DELETE FROM latest_host_search",
			"UPDATE fts_backfill_state SET last_rowid=0,initialized=0,complete=0,updated_at=datetime('now')",
		},
		26: {
			// The silence watchdog asks for the newest alert for one managed job
			// on every heartbeat. Keep that bounded independently of the global
			// event history so a large retained deployment does not turn the
			// watchdog into a writer-bound query. Some supported recovery fixtures
			// carry a newer schema marker with only authentication tables, so make
			// the legacy event table available before creating the additive index.
			`CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 type TEXT NOT NULL,
 job TEXT NOT NULL DEFAULT '',
 scan_id TEXT NOT NULL DEFAULT '',
 payload_json BLOB NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL DEFAULT '',
 job_id TEXT NOT NULL DEFAULT ''
);`,
			"ALTER TABLE events ADD COLUMN job_id TEXT NOT NULL DEFAULT ''",
			"CREATE INDEX IF NOT EXISTS events_type_job_time ON events(type,job_id,created_at DESC,id DESC)",
		},
	}
	for next := version + 1; next <= schemaVersion; next++ {
		statements, ok := migrations[next]
		if !ok {
			return fmt.Errorf("missing migration for schema version %d", next)
		}
		if err := applyMigration(db, next, statements); err != nil {
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

// applyMigration scopes the transaction rollback to one migration. Keeping
// this in a helper avoids accumulating deferred rollbacks while a database is
// upgraded through many versions.
func applyMigration(db *sql.DB, version int, statements []string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, statement := range statements {
		if err := execMigrationStatement(tx, statement); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
		return err
	}
	return tx.Commit()
}

// execMigrationStatement handles the only intentionally repeatable DDL in
// the migration set (ALTER TABLE ... ADD COLUMN) by inspecting SQLite's
// schema first. Suppressing arbitrary errors based on driver error text would
// hide real migration failures and is not stable across SQLite versions.
func execMigrationStatement(tx *sql.Tx, statement string) error {
	if table, column, ok := parseAddColumnStatement(statement); ok {
		exists, err := migrationColumnExists(tx, table, column)
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
	}
	_, err := tx.Exec(statement)
	return err
}

func parseAddColumnStatement(statement string) (table, column string, ok bool) {
	fields := strings.Fields(statement)
	if len(fields) < 6 || !strings.EqualFold(fields[0], "ALTER") || !strings.EqualFold(fields[1], "TABLE") || !strings.EqualFold(fields[3], "ADD") || !strings.EqualFold(fields[4], "COLUMN") {
		return "", "", false
	}
	table = strings.Trim(fields[2], "`\"")
	column = strings.Trim(fields[5], "`\"")
	if !validMigrationIdentifier(table) || !validMigrationIdentifier(column) {
		return "", "", false
	}
	return table, column, true
}

func validMigrationIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func migrationColumnExists(tx *sql.Tx, table, column string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM pragma_table_info('" + table + "') WHERE name='" + column + "'"
	if err := tx.QueryRow(query).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}
