package store

// migration51Statements adds the tenants table with the default tenant and
// moves the installation-wide singletons to that tenant. There is exactly one
// tenant, so every read and write keeps its previous result:
//
//   - The update alert routing moves from application_update_state to the
//     default tenant's update_destinations_json. The old column is set to '[]'
//     and from now on holds the routing to platform destinations only.
//   - The public status page moves from the public_dashboard singleton to the
//     default tenant's row in public_dashboards, with the same id, so the
//     public_dashboard_hosts rows keep pointing at it through dashboard_id=1.
//   - Setup tokens record their purpose; every existing token is the initial
//     setup token.
//   - Security audit records gain a tenant, an actor kind, and a category.
//     Existing records belong to the default tenant through the column
//     default, and their category is derived from the action.
//
// Every statement is safe to run again. The copies only insert what is
// missing, and the table guards create the current shape of the tables the
// migration reads, because some recovery databases carry the schema marker
// without every table.
func migration51Statements() []string {
	defaultTenant := "'" + DefaultTenantID + "'"
	return []string{
		// Capacity columns are NULL when the tenant inherits the deployment
		// setting. An empty update_destinations_json means that the tenant's
		// update routing was never configured, so update alerts go to every
		// enabled destination.
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

		// Update alert routing.
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
 announced_upgrade_version TEXT NOT NULL DEFAULT '',
 notification_destinations_json TEXT NOT NULL DEFAULT ''
);`,
		"ALTER TABLE application_update_state ADD COLUMN notification_destinations_json TEXT NOT NULL DEFAULT ''",
		`INSERT INTO tenants(id,name,slug,state,is_default,update_destinations_json,revision,created_at,updated_at)
SELECT ` + defaultTenant + `,'Default','default','active',1,
 COALESCE((SELECT notification_destinations_json FROM application_update_state WHERE id=1),''),
 1,strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE id=` + defaultTenant + `)`,
		"INSERT OR IGNORE INTO application_update_state(id,check_status) VALUES(1,'unknown')",
		"UPDATE application_update_state SET notification_destinations_json='[]' WHERE id=1",

		// Public status page.
		`CREATE TABLE IF NOT EXISTS public_dashboard (
 id INTEGER PRIMARY KEY CHECK(id=1),
 enabled INTEGER NOT NULL DEFAULT 0,
 title TEXT NOT NULL DEFAULT 'EdgeWatch public status',
 introduction TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL
);`,
		`CREATE TABLE IF NOT EXISTS public_dashboards (
 id INTEGER PRIMARY KEY,
 tenant_id TEXT NOT NULL UNIQUE REFERENCES tenants(id),
 enabled INTEGER NOT NULL DEFAULT 0,
 title TEXT NOT NULL DEFAULT 'EdgeWatch public status',
 introduction TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL
);`,
		// The updated_at value is the editor's revision token, so it is
		// copied unchanged.
		`INSERT INTO public_dashboards(id,tenant_id,enabled,title,introduction,updated_at)
SELECT 1,` + defaultTenant + `,enabled,title,introduction,updated_at FROM public_dashboard
WHERE id=1 AND NOT EXISTS (SELECT 1 FROM public_dashboards WHERE tenant_id=` + defaultTenant + `)`,
		"DROP TABLE IF EXISTS public_dashboard",

		// Setup tokens.
		`CREATE TABLE IF NOT EXISTS setup_tokens (
 id INTEGER PRIMARY KEY CHECK(id=1),
 token_hash TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 used_at TEXT,
 issued_at TEXT NOT NULL DEFAULT ''
);`,
		"ALTER TABLE setup_tokens ADD COLUMN purpose TEXT NOT NULL DEFAULT 'initial'",

		// Security audit. A NULL tenant_id means platform scope. actor_kind is
		// empty for the records written before this migration.
		`CREATE TABLE IF NOT EXISTS security_audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 action TEXT NOT NULL,
 detail TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 actor_user_id TEXT NOT NULL DEFAULT '',
 actor_username TEXT NOT NULL DEFAULT '',
 source_ip TEXT NOT NULL DEFAULT '',
 request_id TEXT NOT NULL DEFAULT ''
);`,
		"CREATE INDEX IF NOT EXISTS security_audit_request_id ON security_audit(request_id,created_at)",
		"ALTER TABLE security_audit ADD COLUMN tenant_id TEXT DEFAULT " + defaultTenant,
		"ALTER TABLE security_audit ADD COLUMN actor_kind TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE security_audit ADD COLUMN category TEXT NOT NULL DEFAULT ''",
		auditCategoryBackfillStatement(),
		"CREATE INDEX IF NOT EXISTS security_audit_tenant_time ON security_audit(tenant_id,created_at,id)",
		"CREATE INDEX IF NOT EXISTS security_audit_platform_time ON security_audit(created_at,id) WHERE category IN ('account','platform')",
	}
}
