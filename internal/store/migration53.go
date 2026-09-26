package store

// The schema 53 guard triggers. The triggers on scans, events and
// public_dashboard_hosts read jobs, tenants or public_dashboards. SQLite
// refuses to rename a table while a trigger refers to a table that does not
// exist, so a rebuild of jobs, tenants or public_dashboards must drop the
// triggers that read it in dropDependents and create them again afterwards.
const (
	scansTenantInsertTrigger                = "scans_tenant_insert"
	scansTenantImmutableTrigger             = "scans_tenant_immutable"
	eventsTenantInsertTrigger               = "events_tenant_insert"
	eventsTenantImmutableTrigger            = "events_tenant_immutable"
	publicDashboardHostsTenantInsertTrigger = "public_dashboard_hosts_tenant_insert"
	publicDashboardHostsTenantUpdateTrigger = "public_dashboard_hosts_tenant_update"
	publicDashboardsTenantImmutableTrigger  = "public_dashboards_tenant_immutable"
	jobsTenantImmutableTrigger              = "jobs_tenant_immutable"
)

// jobsReaderTriggerDrops drops the schema 53 triggers on other tables whose
// SQL reads jobs.
func jobsReaderTriggerDrops() []string {
	return []string{
		"DROP TRIGGER IF EXISTS " + scansTenantInsertTrigger,
		"DROP TRIGGER IF EXISTS " + eventsTenantInsertTrigger,
		"DROP TRIGGER IF EXISTS " + publicDashboardHostsTenantInsertTrigger,
		"DROP TRIGGER IF EXISTS " + publicDashboardHostsTenantUpdateTrigger,
	}
}

// migration53Statements attributes the history and delivery tables to
// tenants. There is exactly one tenant, so every read and write keeps its
// previous result:
//
//   - scans gains a required tenant_id, events, outbox and
//     restore_quarantined_deliveries a nullable one. A NULL tenant marks a
//     platform row, such as an update alert and its deliveries.
//   - Every existing row belongs to the default tenant through the constant
//     column default. ADD COLUMN with a constant default only changes the
//     table definition, so the large scan snapshots and event payloads are
//     neither read nor rewritten. The column has no foreign key: SQLite
//     cannot add a REFERENCES column with a non-NULL default while foreign
//     keys are enforced. The guard triggers check the tenant instead.
//   - New indexes serve the tenant-filtered history lists:
//     scans(tenant_id, finished_at DESC, id DESC) and
//     events(tenant_id, created_at DESC, id DESC). Building them reads each
//     table once, which can take a while on a large history.
//   - Guard triggers turn the fail-open column default into a fail-closed
//     check. A scan must belong to its job's tenant, or to the default
//     tenant when it has no job ID, as a job from config.yaml does. An event
//     of a job must belong to the job's tenant. A new scan, and a new event
//     with a tenant, need an existing tenant that is active or disabled, so
//     a tenant that is being deleted takes no new history. A published
//     host's job must belong to the dashboard's tenant. The tenant of a
//     scan, an event, a job and a public dashboard cannot change.
//
// Every writer names tenant_id and derives it inside its write transaction
// from the owning row, so the column defaults only cover the existing rows.
// The migration itself writes no row, so the triggers, which it creates
// last, see no backfill.
//
// Every statement is safe to run again. The table guards create the
// schema-52 shape of the tables the migration changes or the triggers read,
// and the default tenant, because some recovery databases carry the schema
// marker without every table.
func migration53Statements() []string {
	defaultTenant := "'" + DefaultTenantID + "'"
	return []string{
		`CREATE TABLE IF NOT EXISTS tenants (
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
);`,
		"CREATE UNIQUE INDEX IF NOT EXISTS tenants_name_live ON tenants(name) WHERE state <> 'deleted'",
		"CREATE UNIQUE INDEX IF NOT EXISTS tenants_slug_live ON tenants(slug) WHERE state <> 'deleted'",
		"CREATE UNIQUE INDEX IF NOT EXISTS tenants_one_default ON tenants(is_default) WHERE is_default = 1",
		`INSERT INTO tenants(id,name,slug,state,is_default,update_destinations_json,revision,created_at,updated_at)
SELECT ` + defaultTenant + `,'Default','default','active',1,'',1,strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE id=` + defaultTenant + `)`,
		`CREATE TABLE IF NOT EXISTS jobs (
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
);`,
		"CREATE INDEX IF NOT EXISTS jobs_active ON jobs(archived, enabled, name)",
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
 total_units INTEGER NOT NULL DEFAULT 0, no_progress_attempts INTEGER NOT NULL DEFAULT 0,
 scanner_engine TEXT NOT NULL DEFAULT 'nmap', scanner_profile_id TEXT NOT NULL DEFAULT '',
 scanner_profile_revision INTEGER NOT NULL DEFAULT 0, naabu_version TEXT NOT NULL DEFAULT '',
 discovery_ports INTEGER NOT NULL DEFAULT 0, confirmed_ports INTEGER NOT NULL DEFAULT 0,
 discovery_duration_ms INTEGER NOT NULL DEFAULT 0, enrichment_duration_ms INTEGER NOT NULL DEFAULT 0
);`,
		`CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 type TEXT NOT NULL,
 job TEXT NOT NULL DEFAULT '',
 scan_id TEXT NOT NULL DEFAULT '',
 payload_json BLOB NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL DEFAULT '',
 job_id TEXT NOT NULL DEFAULT ''
);`,
		`CREATE TABLE IF NOT EXISTS outbox (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 destination TEXT NOT NULL,
 payload_json BLOB NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 next_at TEXT NOT NULL,
 sent_at TEXT,
 last_error TEXT NOT NULL DEFAULT '',
 claim_token TEXT NOT NULL DEFAULT '',
 claim_until TEXT NOT NULL DEFAULT '',
 deferrals INTEGER NOT NULL DEFAULT 0,
 terminal_at TEXT NOT NULL DEFAULT '',
 UNIQUE(destination, payload_json)
);`,
		`CREATE TABLE IF NOT EXISTS restore_quarantined_deliveries (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 restore_epoch TEXT NOT NULL,
 destination TEXT NOT NULL,
 payload_json BLOB NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 deferrals INTEGER NOT NULL DEFAULT 0,
 next_at TEXT NOT NULL DEFAULT '',
 last_error TEXT NOT NULL DEFAULT '',
 quarantined_at TEXT NOT NULL
);`,
		`CREATE TABLE IF NOT EXISTS public_dashboards (
 id INTEGER PRIMARY KEY,
 tenant_id TEXT NOT NULL UNIQUE REFERENCES tenants(id),
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

		"ALTER TABLE scans ADD COLUMN tenant_id TEXT NOT NULL DEFAULT " + defaultTenant,
		"ALTER TABLE events ADD COLUMN tenant_id TEXT DEFAULT " + defaultTenant,
		"ALTER TABLE outbox ADD COLUMN tenant_id TEXT DEFAULT " + defaultTenant,
		"ALTER TABLE restore_quarantined_deliveries ADD COLUMN tenant_id TEXT DEFAULT " + defaultTenant,
		// The history lists order as scans_job_id_time and
		// events_type_job_time do.
		"CREATE INDEX IF NOT EXISTS scans_tenant_id_time ON scans(tenant_id, finished_at DESC, id DESC)",
		"CREATE INDEX IF NOT EXISTS events_tenant_id_time ON events(tenant_id, created_at DESC, id DESC)",

		`CREATE TRIGGER IF NOT EXISTS ` + scansTenantInsertTrigger + ` BEFORE INSERT ON scans BEGIN
 SELECT RAISE(ABORT, 'scans.tenant_id must be the tenant of the scan''s job, or the default tenant for a scan without a job ID')
 WHERE CASE WHEN COALESCE(NEW.job_id,'')='' THEN NEW.tenant_id IS NOT ` + defaultTenant + `
  ELSE NOT EXISTS (SELECT 1 FROM jobs WHERE jobs.id=NEW.job_id AND jobs.tenant_id=NEW.tenant_id) END;
 SELECT RAISE(ABORT, 'scans.tenant_id must name an active or disabled tenant')
 WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE tenants.id=NEW.tenant_id AND tenants.state IN ('active','disabled'));
END`,
		`CREATE TRIGGER IF NOT EXISTS ` + scansTenantImmutableTrigger + ` BEFORE UPDATE OF tenant_id ON scans BEGIN
 SELECT RAISE(ABORT, 'scans.tenant_id cannot be changed');
END`,
		`CREATE TRIGGER IF NOT EXISTS ` + eventsTenantInsertTrigger + ` BEFORE INSERT ON events BEGIN
 SELECT RAISE(ABORT, 'events.tenant_id must be the tenant of the event''s job')
 WHERE COALESCE(NEW.job_id,'')<>''
  AND NOT EXISTS (SELECT 1 FROM jobs WHERE jobs.id=NEW.job_id AND jobs.tenant_id=NEW.tenant_id);
 SELECT RAISE(ABORT, 'events.tenant_id must name an active or disabled tenant')
 WHERE NEW.tenant_id IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM tenants WHERE tenants.id=NEW.tenant_id AND tenants.state IN ('active','disabled'));
END`,
		`CREATE TRIGGER IF NOT EXISTS ` + eventsTenantImmutableTrigger + ` BEFORE UPDATE OF tenant_id ON events BEGIN
 SELECT RAISE(ABORT, 'events.tenant_id cannot be changed');
END`,
		`CREATE TRIGGER IF NOT EXISTS ` + publicDashboardHostsTenantInsertTrigger + ` BEFORE INSERT ON public_dashboard_hosts BEGIN
 SELECT RAISE(ABORT, 'a public dashboard host must belong to a job of the dashboard''s tenant')
 WHERE NOT EXISTS (SELECT 1 FROM jobs JOIN public_dashboards ON public_dashboards.tenant_id=jobs.tenant_id
  WHERE jobs.id=NEW.job_id AND public_dashboards.id=NEW.dashboard_id);
END`,
		`CREATE TRIGGER IF NOT EXISTS ` + publicDashboardHostsTenantUpdateTrigger + ` BEFORE UPDATE OF dashboard_id, job_id ON public_dashboard_hosts BEGIN
 SELECT RAISE(ABORT, 'a public dashboard host must belong to a job of the dashboard''s tenant')
 WHERE NOT EXISTS (SELECT 1 FROM jobs JOIN public_dashboards ON public_dashboards.tenant_id=jobs.tenant_id
  WHERE jobs.id=NEW.job_id AND public_dashboards.id=NEW.dashboard_id);
END`,
		// The published hosts and the history rows follow the tenant of
		// their dashboard and job, so those cannot move either.
		`CREATE TRIGGER IF NOT EXISTS ` + publicDashboardsTenantImmutableTrigger + ` BEFORE UPDATE OF tenant_id ON public_dashboards BEGIN
 SELECT RAISE(ABORT, 'public_dashboards.tenant_id cannot be changed');
END`,
		`CREATE TRIGGER IF NOT EXISTS ` + jobsTenantImmutableTrigger + ` BEFORE UPDATE OF tenant_id ON jobs BEGIN
 SELECT RAISE(ABORT, 'jobs.tenant_id cannot be changed');
END`,
	}
}
