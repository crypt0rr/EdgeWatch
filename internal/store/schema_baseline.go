package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
)

// minimumUpgradeSchema is the oldest schema that this release upgrades:
// schema 54, of v0.20.0, the first release with business units. A database
// with an older schema is refused before anything writes to it, and must be
// upgraded by upgradeFloorRelease first. A new database starts from the
// baseline of this schema, in baselineSchemaStatements.
const minimumUpgradeSchema = 54

// upgradeFloorRelease is the last release that upgrades a database from
// every older schema, back to schema 1.
const upgradeFloorRelease = "v0.35.0"

// ErrSchemaBelowUpgradeFloor is the refusal of a database whose schema is
// older than minimumUpgradeSchema.
var ErrSchemaBelowUpgradeFloor = errors.New("database schema is older than the oldest schema this release upgrades")

// schemaBelowUpgradeFloorError names the schema of a database that this
// release does not upgrade. Version 0 is a database with tables but no
// schema marker, such as one of the releases before the web console.
type schemaBelowUpgradeFloorError struct {
	version int
}

func (e schemaBelowUpgradeFloorError) Error() string {
	return fmt.Sprintf("database schema version %d is older than schema %d, the oldest that this release upgrades; upgrade through %s first", e.version, minimumUpgradeSchema, upgradeFloorRelease)
}

func (e schemaBelowUpgradeFloorError) Is(target error) bool {
	return target == ErrSchemaBelowUpgradeFloor
}

// checkUpgradableSchemaContext returns the schema version of a database that
// this release can open and migrate, and refuses any other: a newer schema,
// a schema older than minimumUpgradeSchema, and a database without a schema
// marker that already holds tables. It only reads. startup_state is not
// counted, because the first start of a new database creates it before the
// baseline, which commits in one transaction.
//
// One statement reads the marker and the tables, so both come from the same
// snapshot: read one after the other, a baseline that another process
// commits in between would make a new database look like one with tables
// and no marker.
func checkUpgradableSchemaContext(ctx context.Context, queryer rowQueryer) (int, error) {
	var version, tables int
	if err := queryer.QueryRowContext(ctx, `SELECT (SELECT user_version FROM pragma_user_version),
 (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name<>'startup_state')`).Scan(&version, &tables); err != nil {
		return 0, err
	}
	switch {
	case version > schemaVersion:
		return version, newerSchemaError(version)
	case version >= minimumUpgradeSchema:
		return version, nil
	case version > 0 || tables > 0:
		return version, schemaBelowUpgradeFloorError{version: version}
	}
	return version, nil
}

// applyBaselineSchema creates schema minimumUpgradeSchema in a new database,
// in one transaction, and sets its schema marker. The migrations from
// schema 1 to that schema are retired; upgradeFloorRelease still has them.
// The statements and rows are what those migrations left in a new database,
// which TestBaselineSchemaMatchesMigrationChain checks against
// testdata/schema54-migration-chain.golden. They are frozen: change the
// schema in a new migration instead.
//
// The baseline keeps the state of the schema 54 upgrade that its startup
// phase completes: latest_scan_hosts_pre_tenant, the triggers that guard the
// copy, and its checkpoint. In a new database the copy finds no row, drops
// the table and installs the latest-host triggers.
func applyBaselineSchema(ctx context.Context, db *sql.DB) error {
	tx, err := beginSchemaStep(ctx, db, 0, minimumUpgradeSchema)
	if err != nil {
		return fmt.Errorf("baseline schema %d: %w", minimumUpgradeSchema, err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, statement := range slices.Concat(baselineSchemaStatements, baselineSchemaRows) {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("baseline schema %d: %w", minimumUpgradeSchema, err)
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", minimumUpgradeSchema)); err != nil {
		return err
	}
	return tx.Commit()
}

// baselineSchemaStatements are the tables, indexes and triggers of schema
// 54 in a new database, in the order in which the migrations created them.
// The text is SQLite's, as sqlite_master stores it; columns that a migration
// added with ALTER TABLE follow the original definition. startup_state
// already exists when they run.
var baselineSchemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS startup_state (
 id INTEGER PRIMARY KEY CHECK(id=1),
 state TEXT NOT NULL DEFAULT 'ready',
 owner TEXT NOT NULL DEFAULT '',
 phase TEXT NOT NULL DEFAULT '',
 started_at TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL DEFAULT '',
 progress INTEGER NOT NULL DEFAULT 0,
 total INTEGER NOT NULL DEFAULT 0,
 last_error TEXT NOT NULL DEFAULT ''
)`,
	`CREATE TABLE scans (
 id TEXT PRIMARY KEY, job TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL,
 status TEXT NOT NULL, error TEXT NOT NULL DEFAULT '', nmap_version TEXT NOT NULL DEFAULT '',
 config_hash TEXT NOT NULL, snapshot_json BLOB NOT NULL
, job_id TEXT, job_revision INTEGER, baseline_scan_id TEXT NOT NULL DEFAULT '', baseline_config_hash TEXT NOT NULL DEFAULT '', changes_json BLOB NOT NULL DEFAULT '[]', cycle_id TEXT NOT NULL DEFAULT '', cycle_attempt INTEGER NOT NULL DEFAULT 0, cycle_status TEXT NOT NULL DEFAULT '', resumable INTEGER NOT NULL DEFAULT 0, completed_probes INTEGER NOT NULL DEFAULT 0, total_probes INTEGER NOT NULL DEFAULT 0, completed_units INTEGER NOT NULL DEFAULT 0, total_units INTEGER NOT NULL DEFAULT 0, no_progress_attempts INTEGER NOT NULL DEFAULT 0, scanner_engine TEXT NOT NULL DEFAULT 'nmap', scanner_profile_id TEXT NOT NULL DEFAULT '', scanner_profile_revision INTEGER NOT NULL DEFAULT 0, naabu_version TEXT NOT NULL DEFAULT '', discovery_ports INTEGER NOT NULL DEFAULT 0, confirmed_ports INTEGER NOT NULL DEFAULT 0, discovery_duration_ms INTEGER NOT NULL DEFAULT 0, enrichment_duration_ms INTEGER NOT NULL DEFAULT 0, tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000100')`,
	`CREATE INDEX scans_job_time ON scans(job, finished_at DESC)`,
	`CREATE TABLE job_states (job TEXT PRIMARY KEY, state_json BLOB NOT NULL, updated_at TEXT NOT NULL)`,
	`CREATE TABLE events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, job TEXT NOT NULL,
 scan_id TEXT NOT NULL DEFAULT '', payload_json BLOB NOT NULL, created_at TEXT NOT NULL
, job_id TEXT, tenant_id TEXT DEFAULT '00000000-0000-0000-0000-000000000100')`,
	`CREATE INDEX events_job_time ON events(job, created_at DESC)`,
	`CREATE TABLE outbox (
 id INTEGER PRIMARY KEY AUTOINCREMENT, destination TEXT NOT NULL, payload_json BLOB NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0, next_at TEXT NOT NULL, sent_at TEXT, last_error TEXT NOT NULL DEFAULT '', claim_token TEXT NOT NULL DEFAULT '', claim_until TEXT NOT NULL DEFAULT '', deferrals INTEGER NOT NULL DEFAULT 0, terminal_at TEXT NOT NULL DEFAULT '', tenant_id TEXT DEFAULT '00000000-0000-0000-0000-000000000100',
 UNIQUE(destination, payload_json)
)`,
	`CREATE INDEX outbox_due ON outbox(sent_at, next_at)`,
	`CREATE TABLE daemon_lease (
 id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT NOT NULL, heartbeat TEXT NOT NULL
)`,
	`CREATE TABLE job_leases (
 job TEXT PRIMARY KEY, owner TEXT NOT NULL, expires_at TEXT NOT NULL
)`,
	`CREATE INDEX events_job_id_time ON events(job_id, created_at DESC)`,
	`CREATE TABLE job_revisions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 job_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 definition_json BLOB NOT NULL,
 security_hash TEXT NOT NULL,
 created_at TEXT NOT NULL,
 UNIQUE(job_id, revision),
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
)`,
	`CREATE TABLE job_runtime (
 job_id TEXT PRIMARY KEY,
 state_json BLOB NOT NULL,
 updated_at TEXT NOT NULL,
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
)`,
	`CREATE TABLE admins (
 id INTEGER PRIMARY KEY CHECK(id=1),
 username TEXT NOT NULL DEFAULT 'admin',
 password_hash TEXT NOT NULL,
 totp_secret TEXT NOT NULL DEFAULT '',
 totp_enabled INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
, display_name TEXT NOT NULL DEFAULT 'admin')`,
	`CREATE TABLE sessions (
 id_hash TEXT PRIMARY KEY,
 created_at TEXT NOT NULL,
 last_seen_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 csrf_token TEXT NOT NULL
, user_id TEXT NOT NULL DEFAULT '')`,
	`CREATE INDEX sessions_expiry ON sessions(expires_at)`,
	`CREATE TABLE recovery_codes (
 id_hash TEXT PRIMARY KEY,
 used_at TEXT
, user_id TEXT NOT NULL DEFAULT '')`,
	`CREATE TABLE security_audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 action TEXT NOT NULL,
 detail TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
, actor_user_id TEXT NOT NULL DEFAULT '', actor_username TEXT NOT NULL DEFAULT '', source_ip TEXT NOT NULL DEFAULT '', request_id TEXT NOT NULL DEFAULT '', tenant_id TEXT DEFAULT '00000000-0000-0000-0000-000000000100', actor_kind TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '')`,
	`CREATE TABLE setup_tokens (
 id INTEGER PRIMARY KEY CHECK(id=1),
 token_hash TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 used_at TEXT
, issued_at TEXT NOT NULL DEFAULT '', purpose TEXT NOT NULL DEFAULT 'initial')`,
	`CREATE INDEX outbox_claim ON outbox(sent_at, next_at, claim_until)`,
	`CREATE INDEX events_created_at ON events(created_at)`,
	`CREATE INDEX job_revisions_created_at ON job_revisions(created_at)`,
	`CREATE INDEX outbox_sent_at ON outbox(sent_at)`,
	`CREATE TABLE rdap_cache (
 address TEXT PRIMARY KEY,
 payload_json BLOB NOT NULL,
 fetched_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 stale_until TEXT NOT NULL
)`,
	`CREATE INDEX rdap_cache_expiry ON rdap_cache(expires_at, stale_until)`,
	`CREATE TABLE scan_hosts (
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
 udp_open_filtered_ports INTEGER NOT NULL DEFAULT 0, search_text TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(scan_id, address),
 FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
)`,
	`CREATE INDEX scan_hosts_address ON scan_hosts(address)`,
	`CREATE INDEX scan_hosts_scan_address ON scan_hosts(scan_id, address)`,
	`CREATE INDEX scan_hosts_job_address ON scan_hosts(job, address)`,
	`CREATE INDEX scan_hosts_open ON scan_hosts(open_ports, open_filtered_ports)`,
	`CREATE TABLE scan_cycles (
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
 last_error TEXT NOT NULL DEFAULT '', baseline_epoch INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
)`,
	`CREATE UNIQUE INDEX scan_cycles_active ON scan_cycles(job_id) WHERE status IN ('running','paused','stalled')`,
	`CREATE INDEX scan_cycles_expiry ON scan_cycles(status,expires_at)`,
	`CREATE TABLE scan_cycle_units (
 cycle_id TEXT NOT NULL,
 sequence INTEGER NOT NULL,
 work_unit_json BLOB NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 attempts INTEGER NOT NULL DEFAULT 0,
 snapshot_json BLOB NOT NULL DEFAULT '{}',
 started_at TEXT NOT NULL DEFAULT '',
 finished_at TEXT NOT NULL DEFAULT '',
 last_error TEXT NOT NULL DEFAULT '', identity TEXT NOT NULL DEFAULT '', phase TEXT NOT NULL DEFAULT '', probes INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(cycle_id,sequence),
 FOREIGN KEY(cycle_id) REFERENCES scan_cycles(id) ON DELETE CASCADE
)`,
	`CREATE INDEX scan_cycle_units_pending ON scan_cycle_units(cycle_id,status,sequence)`,
	`CREATE TABLE user_invites (
 id_hash TEXT PRIMARY KEY,
 user_id TEXT NOT NULL,
 created_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 used_at TEXT, issuer_user_id TEXT NOT NULL DEFAULT '',
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
)`,
	`CREATE INDEX user_invites_expiry ON user_invites(expires_at, used_at)`,
	`CREATE TABLE public_dashboard_hosts (
 dashboard_id INTEGER NOT NULL DEFAULT 1,
 job_id TEXT NOT NULL,
 address TEXT NOT NULL,
 created_at TEXT NOT NULL,
 PRIMARY KEY(dashboard_id,job_id,address),
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
)`,
	`CREATE INDEX public_dashboard_hosts_address ON public_dashboard_hosts(address)`,
	`CREATE TABLE application_update_state (
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
, notification_destinations_json TEXT NOT NULL DEFAULT '')`,
	`CREATE TABLE scanner_profile_revisions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 profile_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 definition_json BLOB NOT NULL,
 created_by TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 UNIQUE(profile_id, revision),
 FOREIGN KEY(profile_id) REFERENCES scanner_profiles(id) ON DELETE CASCADE
)`,
	`CREATE INDEX scanner_profile_revisions_profile ON scanner_profile_revisions(profile_id,revision DESC)`,
	`CREATE TABLE "latest_scan_hosts_pre_tenant" (
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
, search_text TEXT NOT NULL DEFAULT '')`,
	`CREATE TABLE scan_cycle_discovery_checkpoints (
 cycle_id TEXT NOT NULL,
 sequence INTEGER NOT NULL,
 processed_at TEXT NOT NULL,
 PRIMARY KEY(cycle_id, sequence),
 FOREIGN KEY(cycle_id) REFERENCES scan_cycles(id) ON DELETE CASCADE
)`,
	`CREATE INDEX scan_cycle_discovery_checkpoints_cycle ON scan_cycle_discovery_checkpoints(cycle_id,sequence)`,
	`CREATE TABLE notification_delivery_health (
 destination_identity TEXT PRIMARY KEY,
 terminal_failures INTEGER NOT NULL DEFAULT 0,
 last_success_at TEXT NOT NULL DEFAULT '',
 last_failure_at TEXT NOT NULL DEFAULT '',
 last_terminal_at TEXT NOT NULL DEFAULT '',
 last_error_code TEXT NOT NULL DEFAULT '',
 last_error_fingerprint TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL
)`,
	`CREATE INDEX notification_delivery_health_updated ON notification_delivery_health(updated_at)`,
	`CREATE INDEX scans_job_id_time ON scans(job_id, finished_at DESC, id DESC)`,
	`CREATE INDEX scans_job_id_revision ON scans(job_id, job_revision)`,
	`CREATE INDEX scans_finished_at ON scans(finished_at DESC)`,
	`CREATE INDEX scans_cycle_id ON scans(cycle_id)`,
	`CREATE TABLE fts_backfill_state (
 table_name TEXT PRIMARY KEY,
 last_rowid INTEGER NOT NULL DEFAULT 0,
	 processed_rows INTEGER NOT NULL DEFAULT 0,
 initialized INTEGER NOT NULL DEFAULT 0,
 complete INTEGER NOT NULL DEFAULT 0,
 updated_at TEXT NOT NULL
)`,
	`CREATE INDEX fts_backfill_state_complete ON fts_backfill_state(complete,table_name)`,
	`CREATE INDEX events_type_job_time ON events(type,job_id,created_at DESC,id DESC)`,
	`CREATE TABLE job_silence_state (
 job_id TEXT PRIMARY KEY,
 eligible_at TEXT NOT NULL,
 backoff_level INTEGER NOT NULL DEFAULT 0,
 next_alert_at TEXT NOT NULL DEFAULT '',
 last_success_at TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL,
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
)`,
	`CREATE INDEX job_silence_state_due ON job_silence_state(next_alert_at,eligible_at)`,
	`CREATE TABLE baseline_hosts (
 job_id TEXT NOT NULL,
 address TEXT NOT NULL,
 address_family TEXT NOT NULL DEFAULT '',
 source_targets_json BLOB NOT NULL DEFAULT '[]',
 dns_names_json BLOB NOT NULL DEFAULT '[]',
 host_json BLOB NOT NULL,
 data_quality TEXT NOT NULL DEFAULT 'detailed',
 search_text TEXT NOT NULL DEFAULT '',
 open_ports INTEGER NOT NULL DEFAULT 0,
 open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 tcp_present INTEGER NOT NULL DEFAULT 0,
 udp_present INTEGER NOT NULL DEFAULT 0,
 tcp_open_ports INTEGER NOT NULL DEFAULT 0,
 tcp_open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 udp_open_ports INTEGER NOT NULL DEFAULT 0,
 udp_open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(job_id,address),
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
)`,
	`CREATE INDEX baseline_hosts_job_address ON baseline_hosts(job_id,address)`,
	`CREATE INDEX baseline_hosts_job_open ON baseline_hosts(job_id,open_ports,open_filtered_ports)`,
	`CREATE INDEX baseline_hosts_job_protocol_open ON baseline_hosts(job_id,tcp_present,udp_present,tcp_open_ports,udp_open_ports)`,
	`CREATE TABLE sse_event_cursor (
 id INTEGER PRIMARY KEY CHECK(id=1),
 next_id INTEGER NOT NULL DEFAULT 0
)`,
	`CREATE INDEX outbox_terminal_due ON outbox(sent_at,terminal_at,next_at)`,
	`CREATE INDEX scan_cycle_units_identity ON scan_cycle_units(cycle_id,identity)`,
	`CREATE INDEX security_audit_request_id ON security_audit(request_id,created_at)`,
	`CREATE TABLE restore_quarantined_deliveries (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 restore_epoch TEXT NOT NULL,
 destination TEXT NOT NULL,
 payload_json BLOB NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 deferrals INTEGER NOT NULL DEFAULT 0,
 next_at TEXT NOT NULL DEFAULT '',
 last_error TEXT NOT NULL DEFAULT '',
 quarantined_at TEXT NOT NULL
, tenant_id TEXT DEFAULT '00000000-0000-0000-0000-000000000100')`,
	`CREATE INDEX restore_quarantined_deliveries_epoch ON restore_quarantined_deliveries(restore_epoch,quarantined_at)`,
	`CREATE TABLE restore_epochs (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 epoch TEXT NOT NULL UNIQUE,
 restored_at TEXT NOT NULL,
 pending_delivery_policy TEXT NOT NULL,
 pending_delivery_count INTEGER NOT NULL DEFAULT 0
)`,
	`CREATE INDEX restore_epochs_restored_at ON restore_epochs(restored_at)`,
	`CREATE INDEX scan_cycle_units_cycle_phase_status ON scan_cycle_units(cycle_id,phase,status,probes,sequence)`,
	`CREATE TABLE job_runtime_meta (
 job_id TEXT PRIMARY KEY,
 metadata_version INTEGER NOT NULL DEFAULT 1,
 baseline_scan_id TEXT NOT NULL DEFAULT '',
 baseline_config_hash TEXT NOT NULL DEFAULT '',
 baseline_modified INTEGER NOT NULL DEFAULT 0,
 projection_version INTEGER NOT NULL DEFAULT 0,
 updated_at TEXT NOT NULL, candidate_count INTEGER NOT NULL DEFAULT 0, candidate_attempts INTEGER NOT NULL DEFAULT 0, incomplete_candidate_attempts INTEGER NOT NULL DEFAULT 0, pending_count INTEGER NOT NULL DEFAULT 0, baseline_epoch INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
)`,
	`CREATE INDEX job_runtime_meta_baseline ON job_runtime_meta(baseline_scan_id,baseline_modified)`,
	`CREATE TABLE legacy_scan_host_backfill (
 scan_id TEXT PRIMARY KEY,
 processed_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'complete', error TEXT NOT NULL DEFAULT '', attempts INTEGER NOT NULL DEFAULT 1,
 FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
)`,
	`CREATE INDEX legacy_scan_host_backfill_processed ON legacy_scan_host_backfill(processed_at)`,
	`CREATE TABLE runtime_incidents (job_id TEXT NOT NULL,key TEXT NOT NULL,incident_json BLOB NOT NULL,PRIMARY KEY(job_id,key),FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE)`,
	`CREATE INDEX runtime_incidents_key ON runtime_incidents(key)`,
	`CREATE TABLE totp_replay (
 user_id TEXT PRIMARY KEY,
 last_step INTEGER NOT NULL DEFAULT -1,
 updated_at TEXT NOT NULL DEFAULT '',
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
)`,
	`CREATE INDEX totp_replay_updated ON totp_replay(updated_at)`,
	`CREATE INDEX user_invites_issuer ON user_invites(issuer_user_id,used_at,expires_at)`,
	`CREATE TABLE deployment_notification_ids (
 legacy_hash TEXT PRIMARY KEY,
 opaque_id TEXT NOT NULL UNIQUE,
 created_at TEXT NOT NULL
, managed_notification_id TEXT NOT NULL DEFAULT '', imported_at TEXT NOT NULL DEFAULT '')`,
	`CREATE INDEX deployment_notification_ids_opaque ON deployment_notification_ids(opaque_id)`,
	`CREATE TABLE scan_cycle_identity_backfill (
 id INTEGER PRIMARY KEY CHECK(id=1),
 complete INTEGER NOT NULL DEFAULT 0,
 updated_at TEXT NOT NULL DEFAULT ''
)`,
	`CREATE INDEX scan_cycle_units_identity_pending ON scan_cycle_units(identity,cycle_id,sequence)`,
	`CREATE TABLE timestamp_normalization_state (
 id INTEGER PRIMARY KEY CHECK(id=1),
 complete INTEGER NOT NULL DEFAULT 0,
 updated_at TEXT NOT NULL DEFAULT ''
)`,
	`CREATE INDEX scan_cycles_job_epoch_status ON scan_cycles(job_id,baseline_epoch,status)`,
	`CREATE INDEX legacy_scan_host_backfill_status ON legacy_scan_host_backfill(status,processed_at)`,
	`CREATE TABLE notification_config_import (
 id INTEGER PRIMARY KEY CHECK(id=1),
 status TEXT NOT NULL DEFAULT '',
 configured_urls INTEGER NOT NULL DEFAULT 0,
 imported_urls INTEGER NOT NULL DEFAULT 0,
 error_code TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL DEFAULT ''
)`,
	`CREATE TABLE tenants (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL COLLATE NOCASE,
 slug TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','disabled','deleting','deleted')),
 is_default INTEGER NOT NULL DEFAULT 0 CHECK(is_default IN (0,1)),
 max_concurrent_scans INTEGER CHECK(max_concurrent_scans IS NULL OR max_concurrent_scans BETWEEN 1 AND 64),
 max_probe_count INTEGER CHECK(max_probe_count IS NULL OR max_probe_count >= 1),
 max_naabu_probe_count INTEGER CHECK(max_naabu_probe_count IS NULL OR max_naabu_probe_count >= 1),
 high_cost_ceiling INTEGER CHECK(high_cost_ceiling IS NULL OR high_cost_ceiling >= 1),
 update_destinations_json TEXT NOT NULL DEFAULT '',
 revision INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 state_changed_at TEXT NOT NULL DEFAULT '',
 state_changed_by TEXT NOT NULL DEFAULT '',
 purge_phase TEXT NOT NULL DEFAULT '',
 purge_rows INTEGER NOT NULL DEFAULT 0
)`,
	`CREATE UNIQUE INDEX tenants_name_live ON tenants(name) WHERE state <> 'deleted'`,
	`CREATE UNIQUE INDEX tenants_slug_live ON tenants(slug) WHERE state <> 'deleted'`,
	`CREATE UNIQUE INDEX tenants_one_default ON tenants(is_default) WHERE is_default = 1`,
	`CREATE TABLE public_dashboards (
 id INTEGER PRIMARY KEY,
 tenant_id TEXT NOT NULL UNIQUE REFERENCES tenants(id),
 enabled INTEGER NOT NULL DEFAULT 0,
 title TEXT NOT NULL DEFAULT 'EdgeWatch public status',
 introduction TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL
)`,
	`CREATE INDEX security_audit_tenant_time ON security_audit(tenant_id,created_at,id)`,
	`CREATE INDEX security_audit_platform_time ON security_audit(created_at,id) WHERE category IN ('account','platform')`,
	`CREATE TABLE "users" (
 id TEXT PRIMARY KEY,
 tenant_id TEXT REFERENCES tenants(id),
 username TEXT NOT NULL COLLATE NOCASE UNIQUE,
 display_name TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('platform_admin','administrator','operator','viewer')),
 password_hash TEXT NOT NULL,
 totp_secret TEXT NOT NULL DEFAULT '',
 totp_enabled INTEGER NOT NULL DEFAULT 0,
 enabled INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 last_login_at TEXT NOT NULL DEFAULT '',
 revision INTEGER NOT NULL DEFAULT 1,
 CHECK((role='platform_admin') = (tenant_id IS NULL))
)`,
	`CREATE INDEX users_tenant ON users(tenant_id, role, enabled)`,
	`CREATE TABLE "jobs" (
 id TEXT PRIMARY KEY,
 tenant_id TEXT NOT NULL REFERENCES tenants(id),
 name TEXT NOT NULL,
 definition_json BLOB NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1,
 archived INTEGER NOT NULL DEFAULT 0,
 revision INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 UNIQUE(tenant_id, name)
)`,
	`CREATE INDEX jobs_active ON jobs(archived, enabled, name)`,
	`CREATE TABLE "scanner_profiles" (
 id TEXT PRIMARY KEY,
 tenant_id TEXT REFERENCES tenants(id),
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
 CHECK((built_in=1) = (tenant_id IS NULL))
)`,
	`CREATE INDEX scanner_profiles_active ON scanner_profiles(archived,name)`,
	`CREATE UNIQUE INDEX scanner_profiles_tenant_name ON scanner_profiles(COALESCE(tenant_id,''), name)`,
	`CREATE TABLE "managed_notifications" (
 id TEXT PRIMARY KEY,
 tenant_id TEXT REFERENCES tenants(id),
 name TEXT NOT NULL,
 provider TEXT NOT NULL,
 ciphertext BLOB NOT NULL,
 nonce BLOB NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1,
 revision INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 credential_revision INTEGER NOT NULL DEFAULT 1,
 UNIQUE(tenant_id, name)
)`,
	`CREATE INDEX managed_notifications_enabled ON managed_notifications(enabled, name)`,
	`CREATE UNIQUE INDEX managed_notifications_platform_name ON managed_notifications(name) WHERE tenant_id IS NULL`,
	`CREATE INDEX scans_tenant_id_time ON scans(tenant_id, finished_at DESC, id DESC)`,
	`CREATE INDEX events_tenant_id_time ON events(tenant_id, created_at DESC, id DESC)`,
	`CREATE TRIGGER scans_tenant_insert BEFORE INSERT ON scans BEGIN
 SELECT RAISE(ABORT, 'scans.tenant_id must be the tenant of the scan''s job, or the default tenant for a scan without a job ID')
 WHERE CASE WHEN COALESCE(NEW.job_id,'')='' THEN NEW.tenant_id IS NOT '00000000-0000-0000-0000-000000000100'
  ELSE NOT EXISTS (SELECT 1 FROM jobs WHERE jobs.id=NEW.job_id AND jobs.tenant_id=NEW.tenant_id) END;
 SELECT RAISE(ABORT, 'scans.tenant_id must name an active or disabled tenant')
 WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE tenants.id=NEW.tenant_id AND tenants.state IN ('active','disabled'));
END`,
	`CREATE TRIGGER scans_tenant_immutable BEFORE UPDATE OF tenant_id ON scans BEGIN
 SELECT RAISE(ABORT, 'scans.tenant_id cannot be changed');
END`,
	`CREATE TRIGGER events_tenant_insert BEFORE INSERT ON events BEGIN
 SELECT RAISE(ABORT, 'events.tenant_id must be the tenant of the event''s job')
 WHERE COALESCE(NEW.job_id,'')<>''
  AND NOT EXISTS (SELECT 1 FROM jobs WHERE jobs.id=NEW.job_id AND jobs.tenant_id=NEW.tenant_id);
 SELECT RAISE(ABORT, 'events.tenant_id must name an active or disabled tenant')
 WHERE NEW.tenant_id IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM tenants WHERE tenants.id=NEW.tenant_id AND tenants.state IN ('active','disabled'));
END`,
	`CREATE TRIGGER events_tenant_immutable BEFORE UPDATE OF tenant_id ON events BEGIN
 SELECT RAISE(ABORT, 'events.tenant_id cannot be changed');
END`,
	`CREATE TRIGGER public_dashboard_hosts_tenant_insert BEFORE INSERT ON public_dashboard_hosts BEGIN
 SELECT RAISE(ABORT, 'a public dashboard host must belong to a job of the dashboard''s tenant')
 WHERE NOT EXISTS (SELECT 1 FROM jobs JOIN public_dashboards ON public_dashboards.tenant_id=jobs.tenant_id
  WHERE jobs.id=NEW.job_id AND public_dashboards.id=NEW.dashboard_id);
END`,
	`CREATE TRIGGER public_dashboard_hosts_tenant_update BEFORE UPDATE OF dashboard_id, job_id ON public_dashboard_hosts BEGIN
 SELECT RAISE(ABORT, 'a public dashboard host must belong to a job of the dashboard''s tenant')
 WHERE NOT EXISTS (SELECT 1 FROM jobs JOIN public_dashboards ON public_dashboards.tenant_id=jobs.tenant_id
  WHERE jobs.id=NEW.job_id AND public_dashboards.id=NEW.dashboard_id);
END`,
	`CREATE TRIGGER public_dashboards_tenant_immutable BEFORE UPDATE OF tenant_id ON public_dashboards BEGIN
 SELECT RAISE(ABORT, 'public_dashboards.tenant_id cannot be changed');
END`,
	`CREATE TRIGGER jobs_tenant_immutable BEFORE UPDATE OF tenant_id ON jobs BEGIN
 SELECT RAISE(ABORT, 'jobs.tenant_id cannot be changed');
END`,
	`CREATE TABLE latest_scan_hosts (
 address TEXT NOT NULL,
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
 udp_open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 search_text TEXT NOT NULL DEFAULT '',
 tenant_id TEXT NOT NULL,
 PRIMARY KEY(tenant_id, address)
)`,
	`CREATE INDEX latest_scan_hosts_open ON latest_scan_hosts(tenant_id, open_ports, open_filtered_ports)`,
	`CREATE INDEX latest_scan_hosts_protocol_open ON latest_scan_hosts(tenant_id, tcp_present, udp_present, tcp_open_ports, udp_open_ports)`,
	`CREATE INDEX latest_scan_hosts_scan ON latest_scan_hosts(scan_id)`,
	`CREATE TRIGGER latest_scan_hosts_rekey_insert BEFORE INSERT ON latest_scan_hosts
WHEN NOT EXISTS (SELECT 1 FROM latest_scan_hosts_pre_tenant AS old WHERE old.rowid=NEW.rowid AND old.address=NEW.address)
BEGIN
 SELECT RAISE(ABORT, 'latest_scan_hosts is being keyed by tenant; start the daemon to finish the schema 54 upgrade');
END`,
	`CREATE TRIGGER latest_scan_hosts_rekey_update BEFORE UPDATE ON latest_scan_hosts BEGIN
 SELECT RAISE(ABORT, 'latest_scan_hosts is being keyed by tenant; start the daemon to finish the schema 54 upgrade');
END`,
	`CREATE TRIGGER latest_scan_hosts_rekey_delete BEFORE DELETE ON latest_scan_hosts BEGIN
 SELECT RAISE(ABORT, 'latest_scan_hosts is being keyed by tenant; start the daemon to finish the schema 54 upgrade');
END`,
}

// baselineSchemaRows are the rows of schema 54 in a new database: the
// default tenant, the singletons and the checkpoints of the startup phases.
// The timestamps use the format of the migration that wrote them. Like the
// statements, they name every value literally, so a later change of a
// constant cannot change them.
var baselineSchemaRows = []string{
	"INSERT OR IGNORE INTO startup_state(id,state) VALUES(1,'ready')",
	"INSERT INTO sqlite_sequence(name,seq) VALUES('security_audit',0)",
	"INSERT INTO tenants(id,name,slug,state,is_default,update_destinations_json,revision,created_at,updated_at) VALUES('00000000-0000-0000-0000-000000000100','Default','default','active',1,'',1,strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
	"INSERT INTO public_dashboards(id,tenant_id,enabled,title,introduction,updated_at) VALUES(1,'00000000-0000-0000-0000-000000000100',0,'EdgeWatch public status','',datetime('now'))",
	"INSERT INTO application_update_state(id,check_status,notification_destinations_json) VALUES(1,'unknown','[]')",
	"INSERT INTO sse_event_cursor(id,next_id) VALUES(1,0)",
	"INSERT INTO scan_cycle_identity_backfill(id,complete,updated_at) VALUES(1,1,datetime('now'))",
	"INSERT INTO timestamp_normalization_state(id,complete,updated_at) VALUES(1,0,datetime('now'))",
	"INSERT INTO fts_backfill_state(table_name,last_rowid,processed_rows,initialized,complete,updated_at) VALUES('baseline_hosts',0,0,0,0,datetime('now'))",
	"INSERT INTO fts_backfill_state(table_name,last_rowid,processed_rows,initialized,complete,updated_at) VALUES('latest_scan_hosts_tenant_rekey',0,0,1,0,strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
}
