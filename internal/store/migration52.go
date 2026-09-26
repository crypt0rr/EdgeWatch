package store

// migration52Statements gives the four root tables an owning tenant and
// retires the legacy admins row. Every existing row goes to the default
// tenant, so reads and writes keep their previous results:
//
//   - users gains tenant_id, which only the new platform_admin role leaves
//     NULL. Usernames stay unique across all tenants.
//   - jobs gains a required tenant_id, and job names become unique per
//     tenant instead of globally.
//   - scanner_profiles gains tenant_id, NULL for the built-in profiles and
//     required for custom ones. Custom profile names become unique per
//     tenant, and the built-ins keep a namespace of their own.
//   - managed_notifications gains tenant_id, NULL for a platform destination.
//     Destination names become unique per tenant and among the platform
//     destinations.
//   - The legacy admins row is copied into users one last time, if that row
//     is still missing, and then deleted. users is the only administrator
//     record from now on.
//
// A column can only gain a foreign key and a CHECK through a table rebuild.
// The rebuilds keep each row's rowid, column values, indexes and defaults.
// Other tables reference all four tables with ON DELETE CASCADE, so the
// version runs through applyMigrationForeignKeysOff, see
// foreignKeysOffMigrations. None of the four tables has a view or a trigger
// that references it. The tenant_id columns have no default: every INSERT
// names its tenant.
//
// The table guards create the schema-51 shape of the tables that the
// migration reads, because some recovery databases carry the schema marker
// without every table, and the default tenant, which every copied row
// references.
func migration52Statements() []string {
	defaultTenant := "'" + DefaultTenantID + "'"
	statements := []string{
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
		// Schema 51 creates the default tenant. A recovery database without
		// it gets one with unconfigured update routing, as schema 51 does
		// when application_update_state is missing.
		`INSERT INTO tenants(id,name,slug,state,is_default,update_destinations_json,revision,created_at,updated_at)
SELECT ` + defaultTenant + `,'Default','default','active',1,'',1,strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE id=` + defaultTenant + `)`,
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
		`CREATE TABLE IF NOT EXISTS admins (
 id INTEGER PRIMARY KEY CHECK(id=1),
 username TEXT NOT NULL DEFAULT 'admin',
 password_hash TEXT NOT NULL,
 totp_secret TEXT NOT NULL DEFAULT '',
 totp_enabled INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 display_name TEXT NOT NULL DEFAULT 'admin'
);`,
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
		// The built-in profiles are seeded with their revisions after the
		// migration, so a recreated profiles table needs its revisions too.
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
		"CREATE INDEX IF NOT EXISTS scanner_profile_revisions_profile ON scanner_profile_revisions(profile_id,revision DESC)",
		`CREATE TABLE IF NOT EXISTS managed_notifications (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL UNIQUE,
 provider TEXT NOT NULL,
 ciphertext BLOB NOT NULL,
 nonce BLOB NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1,
 revision INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 credential_revision INTEGER NOT NULL DEFAULT 1
);`,

		// Retire the legacy admins row. Schema 12 copied it into users, so
		// the copy only restores a users row that is missing. A copy that
		// conflicts with another account's username is skipped, and then the
		// admins row stays, unused.
		`INSERT OR IGNORE INTO users(id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at)
SELECT '` + LegacyAdminUserID + `',username,COALESCE(display_name,username),'administrator',password_hash,totp_secret,totp_enabled,1,created_at,updated_at,'' FROM admins WHERE id=1`,
		`DELETE FROM admins WHERE id=1 AND EXISTS (SELECT 1 FROM users WHERE id='` + LegacyAdminUserID + `')`,
	}
	for _, rebuild := range []sqliteTableRebuild{
		{
			table: "users",
			definition: `
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
`,
			columns: []string{"id", "username", "display_name", "role", "password_hash", "totp_secret", "totp_enabled", "enabled", "created_at", "updated_at", "last_login_at", "revision"},
			fill:    []sqliteRebuildFill{{column: "tenant_id", expression: defaultTenant}},
			recreate: []string{
				"CREATE INDEX users_tenant ON users(tenant_id, role, enabled)",
			},
		},
		{
			table: "jobs",
			// Names compare binary, as the global UNIQUE(name) did.
			definition: `
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
`,
			columns: []string{"id", "name", "definition_json", "enabled", "archived", "revision", "created_at", "updated_at"},
			fill:    []sqliteRebuildFill{{column: "tenant_id", expression: defaultTenant}},
			recreate: []string{
				"CREATE INDEX jobs_active ON jobs(archived, enabled, name)",
			},
		},
		{
			table: "scanner_profiles",
			definition: `
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
`,
			columns: []string{"id", "name", "description", "definition_json", "built_in", "archived", "revision", "created_by", "updated_by", "created_at", "updated_at"},
			fill:    []sqliteRebuildFill{{column: "tenant_id", expression: "CASE WHEN built_in=1 THEN NULL ELSE " + defaultTenant + " END"}},
			recreate: []string{
				"CREATE INDEX scanner_profiles_active ON scanner_profiles(archived,name)",
				// The built-ins have no tenant and share the '' namespace. name
				// keeps its NOCASE collation in the index.
				"CREATE UNIQUE INDEX scanner_profiles_tenant_name ON scanner_profiles(COALESCE(tenant_id,''), name)",
			},
		},
		{
			table: "managed_notifications",
			definition: `
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
`,
			columns: []string{"id", "name", "provider", "ciphertext", "nonce", "enabled", "revision", "created_at", "updated_at", "credential_revision"},
			fill:    []sqliteRebuildFill{{column: "tenant_id", expression: defaultTenant}},
			recreate: []string{
				"CREATE INDEX managed_notifications_enabled ON managed_notifications(enabled, name)",
				// UNIQUE treats NULLs as distinct, so it does not cover the
				// platform destinations.
				"CREATE UNIQUE INDEX managed_notifications_platform_name ON managed_notifications(name) WHERE tenant_id IS NULL",
			},
		},
	} {
		statements = append(statements, rebuild.statements()...)
	}
	return statements
}
