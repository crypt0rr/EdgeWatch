package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
)

// schema51RootTables are the tables that schema 52 rebuilds, in their
// schema-51 definitions and with their schema-51 indexes.
var schema51RootTables = []sqliteTableRebuild{
	{
		table: "users",
		definition: `
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
`,
		columns: []string{"id", "username", "display_name", "role", "password_hash", "totp_secret", "totp_enabled", "enabled", "created_at", "updated_at", "last_login_at", "revision"},
	},
	{
		table: "jobs",
		definition: `
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL UNIQUE,
 definition_json BLOB NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1,
 archived INTEGER NOT NULL DEFAULT 0,
 revision INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
`,
		columns:  []string{"id", "name", "definition_json", "enabled", "archived", "revision", "created_at", "updated_at"},
		recreate: []string{"CREATE INDEX jobs_active ON jobs(archived, enabled, name)"},
	},
	{
		table: "scanner_profiles",
		definition: `
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
`,
		columns:  []string{"id", "name", "description", "definition_json", "built_in", "archived", "revision", "created_by", "updated_by", "created_at", "updated_at"},
		recreate: []string{"CREATE INDEX scanner_profiles_active ON scanner_profiles(archived,name)"},
	},
	{
		table: "managed_notifications",
		definition: `
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
`,
		columns:  []string{"id", "name", "provider", "ciphertext", "nonce", "enabled", "revision", "created_at", "updated_at", "credential_revision"},
		recreate: []string{"CREATE INDEX managed_notifications_enabled ON managed_notifications(enabled, name)"},
	},
}

// schema51FixtureStatements turn a current database into the schema-51
// shape. They first undo schema 53, see schema52FixtureStatements. Then the
// root tables lose tenant_id and get their schema-51 constraints and indexes
// back, and the original administrator gets back the admins row that schema
// 52 retired. They run with foreign keys off, as execFixtureStatements does,
// so the rebuilds keep the child rows.
var schema51FixtureStatements = func() []string {
	statements := slices.Concat(schema52FixtureStatements, []string{
		`INSERT INTO admins(id,username,display_name,password_hash,totp_secret,totp_enabled,created_at,updated_at)
SELECT 1,username,display_name,password_hash,totp_secret,totp_enabled,created_at,updated_at FROM users WHERE id='` + LegacyAdminUserID + `'`,
	})
	for _, rebuild := range schema51RootTables {
		statements = append(statements, rebuild.statements()...)
	}
	return append(statements, "PRAGMA user_version=51")
}()

// schema52RootTables are the tables that schema 52 rebuilds.
var schema52RootTables = []string{"users", "jobs", "scanner_profiles", "managed_notifications"}

// schema52ChildTables hold rows that reference a rebuilt table, directly or
// through another child, or that name one of its rows without a foreign key.
var schema52ChildTables = []string{
	"user_invites", "totp_replay", "sessions", "recovery_codes",
	"job_revisions", "job_runtime", "job_runtime_meta", "runtime_incidents", "baseline_hosts", "scan_cycles", "public_dashboard_hosts", "job_silence_state",
	"scan_cycle_units", "scanner_profile_revisions", "notification_delivery_health",
}

type schema51Fixture struct {
	path       string
	operatorID string
	jobIDs     []string
	profileID  string
}

// newSchema51Fixture writes a populated database with the current code and
// rewrites it into the schema-51 shape. It has users with invites, TOTP
// replay rows, recovery codes and a session; jobs with a row in each of the
// eight tables that reference jobs; a custom profile with two revisions next
// to the built-ins; and destinations with delivery health. Some root rows
// have rowids out of their insertion order, so a rebuild that renumbers them
// is caught.
func newSchema51Fixture(t *testing.T) schema51Fixture {
	t.Helper()
	ctx := context.Background()
	fixture := schema51Fixture{path: filepath.Join(t.TempDir(), "schema51.db")}
	s, err := Open(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := s.DB.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	stamp := now.Format(time.RFC3339Nano)

	if err := s.PutSetupTokenAt(ctx, "setup-hash", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteSetup(ctx, "setup-hash", Admin{Username: "admin", DisplayName: "Administrator", PasswordHash: "admin-hash", TOTPSecret: "JBSWY3DPEHPK3PXP", TOTPEnabled: true, CreatedAt: now, UpdatedAt: now}, now); err != nil {
		t.Fatal(err)
	}
	operator, err := s.CreateUser(ctx, User{Username: "operator", Role: RoleOperator, PasswordHash: "operator-hash", Enabled: true, CreatedAt: now}, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	fixture.operatorID = operator.ID
	if _, err := s.CreateUserWithInvite(ctx, User{Username: "viewer", Role: RoleViewer, PasswordHash: "!pending", CreatedAt: now}, "invite-hash", now, now.Add(time.Hour), AuditEntry{ActorUserID: LegacyAdminUserID}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{LegacyAdminUserID, operator.ID} {
		if _, err := s.ConsumeTOTPStep(ctx, id, 42, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SaveRecoveryCodesForUser(ctx, operator.ID, []string{"v2$first", "v2$second"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForUserWithAudit(ctx, operator.ID, "session-hash", "csrf", now, now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}

	for i, name := range []string{"edge-a", "edge-b", "edge-c"} {
		job, err := s.CreateJob(ctx, testJob(name))
		if err != nil {
			t.Fatal(err)
		}
		fixture.jobIDs = append(fixture.jobIDs, job.ID)
		cycleID := "cycle-" + name
		exec(`INSERT INTO job_revisions(job_id,revision,definition_json,security_hash,created_at) SELECT job_id,2,definition_json,security_hash,created_at FROM job_revisions WHERE job_id=? AND revision=1`, job.ID)
		exec(`INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,'{}',?)`, job.ID, stamp)
		exec(`INSERT INTO job_runtime_meta(job_id,baseline_scan_id,updated_at) VALUES(?,?,?)`, job.ID, "scan-"+name, stamp)
		exec(`INSERT INTO runtime_incidents(job_id,key,incident_json) VALUES(?,?,'{}')`, job.ID, "incident-"+name)
		exec(`INSERT INTO baseline_hosts(job_id,address,host_json,search_text) VALUES(?,?,'{}',?)`, job.ID, fmt.Sprintf("192.0.2.%d", 10+i), name)
		exec(`INSERT INTO scan_cycles(id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,total_units,total_probes,started_at,updated_at,expires_at) VALUES(?,?,?,1,'config','execution','{}','paused',1,1,?,?,?)`, cycleID, job.ID, name, stamp, stamp, now.Add(time.Hour).Format(time.RFC3339Nano))
		exec(`INSERT INTO scan_cycle_units(cycle_id,sequence,work_unit_json,identity) VALUES(?,0,'{}',?)`, cycleID, "unit-"+name)
	}
	if err := s.SavePublicDashboard(ctx, PublicDashboard{Enabled: true, Title: "Perimeter"}, []PublicDashboardHost{
		{JobID: fixture.jobIDs[0], Address: "192.0.2.10"},
		{JobID: fixture.jobIDs[1], Address: "192.0.2.11"},
	}, AuditEntry{}); err != nil {
		t.Fatal(err)
	}

	profile, err := s.CreateScannerProfile(ctx, "Edge TCP", "custom", config.ScannerProfile{Engine: config.EngineNmap}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateScannerProfile(ctx, profile.ID, profile.Revision, "Edge TCP", "custom, revised", config.ScannerProfile{Engine: config.EngineNmap, Description: "revised"}, "admin"); err != nil {
		t.Fatal(err)
	}
	fixture.profileID = profile.ID

	for _, name := range []string{"Operations", "Security"} {
		destination, err := s.CreateManagedNotification(ctx, "destination-"+strings.ToLower(name), name, "generic", []byte("sealed-"+name), []byte("nonce-"+name), true)
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO notification_delivery_health(destination_identity,terminal_failures,last_success_at,last_error_code,updated_at) VALUES(?,1,?,'timeout',?)`, "managed:"+destination.ID, stamp, stamp)
	}
	exec(`UPDATE managed_notifications SET revision=3,credential_revision=2 WHERE id='destination-security'`)

	// Move rows out of their insertion order.
	exec(`UPDATE users SET rowid=rowid+50 WHERE id=?`, LegacyAdminUserID)
	exec(`UPDATE jobs SET rowid=rowid+100 WHERE id=?`, fixture.jobIDs[1])
	exec(`UPDATE scanner_profiles SET rowid=rowid+30 WHERE id=?`, profile.ID)
	exec(`UPDATE managed_notifications SET rowid=rowid+20 WHERE id='destination-operations'`)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	execFixtureStatements(t, fixture.path, schema51FixtureStatements)

	raw, err := sql.Open("sqlite", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, table := range schema52RootTables {
		if got := countRows(t, raw, `SELECT COUNT(*) FROM pragma_table_info(?) WHERE name='tenant_id'`, table); got != 0 {
			t.Fatalf("schema 51 fixture %s still has tenant_id", table)
		}
	}
	if got := countRows(t, raw, `SELECT COUNT(*) FROM admins WHERE id=1 AND username='admin'`); got != 1 {
		t.Fatalf("schema 51 fixture admins rows = %d, want 1", got)
	}
	return fixture
}

func countRows(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var count int
	if err := db.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return count
}

// schema52RowSnapshot renders the rows of the rebuilt tables, without
// tenant_id, and of their child tables, each with its rowid.
func schema52RowSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	queries := []string{
		`SELECT rowid,id,username,display_name,role,password_hash,totp_secret,totp_enabled,enabled,created_at,updated_at,last_login_at,revision FROM users ORDER BY rowid`,
		`SELECT rowid,id,name,definition_json,enabled,archived,revision,created_at,updated_at FROM jobs ORDER BY rowid`,
		`SELECT rowid,id,name,description,definition_json,built_in,archived,revision,created_by,updated_by,created_at,updated_at FROM scanner_profiles ORDER BY rowid`,
		`SELECT rowid,id,name,provider,ciphertext,nonce,enabled,revision,created_at,updated_at,credential_revision FROM managed_notifications ORDER BY rowid`,
	}
	for _, table := range schema52ChildTables {
		queries = append(queries, `SELECT rowid,* FROM `+table+` ORDER BY rowid`)
	}
	var out strings.Builder
	for _, query := range queries {
		fmt.Fprintln(&out, query)
		if err := snapshotRows(db, query, &out); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	return out.String()
}

// schemaObjectsSnapshot renders every schema object that is not one of the
// rebuilt tables or their indexes. It also leaves out what schemas 53 and 54
// change next: the definitions of the tables that gain tenant_id, the tenant
// indexes and guard triggers, and latest_scan_hosts with its indexes and
// triggers. migration53_test.go and migration54_test.go check those.
func schemaObjectsSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	schema53Objects := slices.Concat(schema53Tables, schema53Triggers, []string{"scans_tenant_id_time", "events_tenant_id_time"})
	var out strings.Builder
	if err := snapshotRows(db, `SELECT type,name,tbl_name,COALESCE(sql,'') FROM sqlite_master WHERE tbl_name NOT IN ('users','jobs','scanner_profiles','managed_notifications','latest_scan_hosts') AND name NOT IN ('`+strings.Join(schema53Objects, "','")+`') ORDER BY type,name`, &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// tableColumns lists name, type, NOT NULL, default and primary key position
// of each column of table.
func tableColumns(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name,type,"notnull",COALESCE(dflt_value,'<none>'),pk FROM pragma_table_xinfo(?) ORDER BY cid`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var name, kind, dflt string
		var notNull, pk int
		if err := rows.Scan(&name, &kind, &notNull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, fmt.Sprintf("%s %s notnull=%d default=%s pk=%d", name, kind, notNull, dflt, pk))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return columns
}

// tableIndexes lists each index of table with its uniqueness, origin,
// partial flag and key columns with their collations.
func tableIndexes(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT il.name,il."unique",il.origin,il.partial,
 (SELECT group_concat(k,',') FROM (SELECT COALESCE(x.name,'<expr>') || ':' || x.coll AS k FROM pragma_index_xinfo(il.name) x WHERE x.key=1 ORDER BY x.seqno))
FROM pragma_index_list(?) il ORDER BY il.name`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var indexes []string
	for rows.Next() {
		var name, origin, keys string
		var unique, partial int
		if err := rows.Scan(&name, &unique, &origin, &partial, &keys); err != nil {
			t.Fatal(err)
		}
		indexes = append(indexes, fmt.Sprintf("%s unique=%d origin=%s partial=%d %s", name, unique, origin, partial, keys))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return indexes
}

// schema52Indexes are the indexes of the rebuilt tables after the migration.
var schema52Indexes = map[string][]string{
	"users": {
		"sqlite_autoindex_users_1 unique=1 origin=pk partial=0 id:BINARY",
		"sqlite_autoindex_users_2 unique=1 origin=u partial=0 username:NOCASE",
		"users_tenant unique=0 origin=c partial=0 tenant_id:BINARY,role:BINARY,enabled:BINARY",
	},
	"jobs": {
		"jobs_active unique=0 origin=c partial=0 archived:BINARY,enabled:BINARY,name:BINARY",
		"sqlite_autoindex_jobs_1 unique=1 origin=pk partial=0 id:BINARY",
		"sqlite_autoindex_jobs_2 unique=1 origin=u partial=0 tenant_id:BINARY,name:BINARY",
	},
	"scanner_profiles": {
		"scanner_profiles_active unique=0 origin=c partial=0 archived:BINARY,name:NOCASE",
		"scanner_profiles_tenant_name unique=1 origin=c partial=0 <expr>:BINARY,name:NOCASE",
		"sqlite_autoindex_scanner_profiles_1 unique=1 origin=pk partial=0 id:BINARY",
	},
	"managed_notifications": {
		"managed_notifications_enabled unique=0 origin=c partial=0 enabled:BINARY,name:BINARY",
		"managed_notifications_platform_name unique=1 origin=c partial=1 name:BINARY",
		"sqlite_autoindex_managed_notifications_1 unique=1 origin=pk partial=0 id:BINARY",
		"sqlite_autoindex_managed_notifications_2 unique=1 origin=u partial=0 tenant_id:BINARY,name:BINARY",
	},
}

func TestMigration52GivesRootTablesTheDefaultTenant(t *testing.T) {
	ctx := context.Background()
	fixture := newSchema51Fixture(t)
	raw, err := sql.Open("sqlite", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	rowsBefore := schema52RowSnapshot(t, raw)
	objectsBefore := schemaObjectsSnapshot(t, raw)
	columnsBefore := map[string][]string{}
	for _, table := range schema52RootTables {
		columnsBefore[table] = tableColumns(t, raw, table)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(fixture.path)
	if err != nil {
		t.Fatalf("upgrade from schema 51: %v", err)
	}
	defer s.Close()
	if version := countRows(t, s.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}

	// Every row keeps its rowid and values, and no child row is lost.
	if rowsAfter := schema52RowSnapshot(t, s.DB); rowsAfter != rowsBefore {
		t.Fatalf("rows changed:\nbefore:\n%s\nafter:\n%s", rowsBefore, rowsAfter)
	}
	for _, table := range schema52ChildTables {
		if countRows(t, s.DB, `SELECT COUNT(*) FROM `+table) == 0 {
			t.Fatalf("fixture has no %s rows, so the migration does not show that they survive", table)
		}
	}
	// Tables other than the rebuilt ones, their triggers and indexes, and
	// the foreign keys of the child tables are unchanged.
	if objectsAfter := schemaObjectsSnapshot(t, s.DB); objectsAfter != objectsBefore {
		t.Fatalf("schema objects changed:\nbefore:\n%s\nafter:\n%s", objectsBefore, objectsAfter)
	}
	for _, trigger := range []string{"baseline_hosts_search_ai", "baseline_hosts_search_au", "baseline_hosts_search_ad", "scan_hosts_search_ai", "latest_scan_hosts_search_ai"} {
		if countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=?`, trigger) != 1 {
			t.Fatalf("trigger %s is missing", trigger)
		}
	}

	// The rebuilt tables keep every column and gain tenant_id without a
	// default, and have exactly the expected indexes.
	wantTenantColumn := map[string]string{
		"users":                 "tenant_id TEXT notnull=0 default=<none> pk=0",
		"jobs":                  "tenant_id TEXT notnull=1 default=<none> pk=0",
		"scanner_profiles":      "tenant_id TEXT notnull=0 default=<none> pk=0",
		"managed_notifications": "tenant_id TEXT notnull=0 default=<none> pk=0",
	}
	for _, table := range schema52RootTables {
		columns := tableColumns(t, s.DB, table)
		tenantColumn := slices.IndexFunc(columns, func(column string) bool { return strings.HasPrefix(column, "tenant_id ") })
		if tenantColumn < 0 || columns[tenantColumn] != wantTenantColumn[table] {
			t.Fatalf("%s columns = %v, want %q", table, columns, wantTenantColumn[table])
		}
		if kept := slices.Delete(slices.Clone(columns), tenantColumn, tenantColumn+1); !slices.Equal(kept, columnsBefore[table]) {
			t.Fatalf("%s columns without tenant_id = %v, want the schema-51 columns %v", table, kept, columnsBefore[table])
		}
		if indexes := tableIndexes(t, s.DB, table); !slices.Equal(indexes, schema52Indexes[table]) {
			t.Fatalf("%s indexes = %v, want %v", table, indexes, schema52Indexes[table])
		}
	}

	// Every row belongs to the default tenant; the built-in profiles have
	// none.
	for _, check := range []struct {
		query string
		want  int
	}{
		{`SELECT COUNT(*) FROM users WHERE tenant_id IS NOT '` + DefaultTenantID + `'`, 0},
		{`SELECT COUNT(*) FROM jobs WHERE tenant_id IS NOT '` + DefaultTenantID + `'`, 0},
		{`SELECT COUNT(*) FROM managed_notifications WHERE tenant_id IS NOT '` + DefaultTenantID + `'`, 0},
		{`SELECT COUNT(*) FROM scanner_profiles WHERE built_in=0 AND tenant_id IS NOT '` + DefaultTenantID + `'`, 0},
		{`SELECT COUNT(*) FROM scanner_profiles WHERE built_in=1 AND tenant_id IS NULL`, 2},
		{`SELECT COUNT(*) FROM users WHERE (role='platform_admin') <> (tenant_id IS NULL)`, 0},
		{`SELECT COUNT(*) FROM scanner_profiles WHERE (built_in=1) <> (tenant_id IS NULL)`, 0},
		{`SELECT COUNT(*) FROM users`, 3},
		{`SELECT COUNT(*) FROM jobs`, 3},
		{`SELECT COUNT(*) FROM scanner_profile_revisions WHERE profile_id='` + fixture.profileID + `'`, 2},
		{`SELECT COUNT(*) FROM job_revisions`, 6},
		{`SELECT COUNT(*) FROM admins`, 0},
		{`SELECT COUNT(*) FROM tenants`, 1},
		{`SELECT COUNT(*) FROM managed_notifications WHERE id='destination-security' AND revision=3 AND credential_revision=2`, 1},
		{`SELECT COUNT(*) FROM notification_delivery_health WHERE destination_identity IN ('managed:destination-operations','managed:destination-security')`, 2},
	} {
		if got := countRows(t, s.DB, check.query); got != check.want {
			t.Fatalf("%s = %d, want %d", check.query, got, check.want)
		}
	}
	var integrity string
	if err := s.DB.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("integrity_check = %q, %v", integrity, err)
	}
	assertForeignKeysClean(t, s.DB)

	// The store reads the migrated rows as before.
	admin, err := s.GetAdmin(ctx)
	if err != nil || admin.Username != "admin" || admin.PasswordHash != "admin-hash" || !admin.TOTPEnabled || admin.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("administrator after the upgrade = %#v, %v", admin, err)
	}
	if record, err := s.GetJobByName(ctx, "edge-b"); err != nil || record.ID != fixture.jobIDs[1] {
		t.Fatalf("job by name = %#v, %v", record, err)
	}
	dashboard, err := s.GetPublicDashboard(ctx)
	if err != nil || len(dashboard.Hosts) != 2 {
		t.Fatalf("public dashboard = %#v, %v", dashboard, err)
	}

	// The children still reference the rebuilt tables: deleting a parent
	// cascades.
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM jobs WHERE id=?`, fixture.jobIDs[0]); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"job_revisions", "job_runtime", "job_runtime_meta", "runtime_incidents", "baseline_hosts", "scan_cycles", "public_dashboard_hosts", "job_silence_state"} {
		if got := countRows(t, s.DB, `SELECT COUNT(*) FROM `+table+` WHERE job_id=?`, fixture.jobIDs[0]); got != 0 {
			t.Fatalf("%s rows of a deleted job = %d, want the cascade to remove them", table, got)
		}
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM scan_cycle_units WHERE cycle_id='cycle-edge-a'`); got != 0 {
		t.Fatalf("scan_cycle_units of a deleted job = %d", got)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE id=?`, fixture.operatorID); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM totp_replay WHERE user_id=?`, fixture.operatorID); got != 0 {
		t.Fatalf("totp_replay rows of a deleted user = %d", got)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM scanner_profiles WHERE id=?`, fixture.profileID); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM scanner_profile_revisions WHERE profile_id=?`, fixture.profileID); got != 0 {
		t.Fatalf("revisions of a deleted profile = %d", got)
	}
}

// The admins row is copied into users only when the users row is missing,
// and deleted once the users row exists.
func TestMigration52RetiresTheAdminsRow(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra []string
		// retired reports whether the admins row is gone afterwards.
		retired bool
	}{
		{name: "users row present", retired: true},
		{
			// The copy restores the administrator in the default tenant.
			name:    "users row missing",
			extra:   []string{`DELETE FROM users WHERE id='` + LegacyAdminUserID + `'`},
			retired: true,
		},
		{
			// Another account holds the username, so the copy is skipped
			// and the admins row stays, unused.
			name: "username taken",
			extra: []string{
				`DELETE FROM users WHERE id='` + LegacyAdminUserID + `'`,
				`UPDATE users SET username='admin' WHERE username='operator'`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fixture := newSchema51Fixture(t)
			execFixtureStatements(t, fixture.path, tc.extra)
			s, err := Open(fixture.path)
			if err != nil {
				t.Fatalf("upgrade from schema 51: %v", err)
			}
			defer s.Close()
			legacyRows := countRows(t, s.DB, `SELECT COUNT(*) FROM admins`)
			if tc.retired != (legacyRows == 0) {
				t.Fatalf("admins rows = %d, want retired=%v", legacyRows, tc.retired)
			}
			admin, err := s.GetAdmin(ctx)
			if !tc.retired {
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("administrator = %#v, %v; want ErrNotFound", admin, err)
				}
				if owner, err := s.GetUserByUsername(ctx, "admin"); err != nil || owner.ID != fixture.operatorID || owner.Role != RoleOperator {
					t.Fatalf("user named admin = %#v, %v; want the operator", owner, err)
				}
				return
			}
			if err != nil || admin.Username != "admin" || admin.DisplayName != "Administrator" || admin.PasswordHash != "admin-hash" || !admin.TOTPEnabled || admin.TOTPSecret != "JBSWY3DPEHPK3PXP" {
				t.Fatalf("administrator = %#v, %v", admin, err)
			}
			var tenant, role string
			var enabled int
			if err := s.DB.QueryRow(`SELECT tenant_id,role,enabled FROM users WHERE id=?`, LegacyAdminUserID).Scan(&tenant, &role, &enabled); err != nil || tenant != DefaultTenantID || role != RoleAdministrator || enabled != 1 {
				t.Fatalf("administrator row = %q/%q/%d, %v", tenant, role, enabled, err)
			}
			assertForeignKeysClean(t, s.DB)
		})
	}
}

// Some recovery databases carry a schema marker without every table. The
// migration creates the tables it reads, and the store works on the result.
func TestMigration52UpgradesRecoveryDatabasesWithMissingTables(t *testing.T) {
	for _, tc := range []struct {
		name    string
		missing []string
	}{
		{name: "users", missing: []string{"users"}},
		{name: "jobs", missing: []string{"jobs"}},
		// Schema 14 creates the profiles and their revisions together.
		{name: "scanner_profiles", missing: []string{"scanner_profiles", "scanner_profile_revisions"}},
		{name: "managed_notifications", missing: []string{"managed_notifications"}},
		{name: "admins", missing: []string{"admins"}},
		{name: "tenants", missing: []string{"tenants"}},
		{name: "all", missing: []string{"users", "jobs", "scanner_profiles", "scanner_profile_revisions", "managed_notifications", "admins", "tenants"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fixture := newSchema51Fixture(t)
			extra := make([]string, 0, len(tc.missing))
			for _, table := range tc.missing {
				extra = append(extra, "DROP TABLE "+table)
			}
			execFixtureStatements(t, fixture.path, extra)

			s, err := Open(fixture.path)
			if err != nil {
				t.Fatalf("upgrade without %v: %v", tc.missing, err)
			}
			defer s.Close()
			if version := countRows(t, s.DB, `PRAGMA user_version`); version != schemaVersion {
				t.Fatalf("schema version = %d, want %d", version, schemaVersion)
			}
			if got := countRows(t, s.DB, `SELECT COUNT(*) FROM tenants WHERE id=? AND is_default=1`, DefaultTenantID); got != 1 {
				t.Fatalf("default tenant rows = %d", got)
			}
			for _, table := range schema52RootTables {
				if indexes := tableIndexes(t, s.DB, table); !slices.Equal(indexes, schema52Indexes[table]) {
					t.Fatalf("%s indexes = %v, want %v", table, indexes, schema52Indexes[table])
				}
			}
			// Only the users table and the admins row together lose the
			// original administrator.
			_, adminErr := s.GetAdmin(ctx)
			if lost := slices.Contains(tc.missing, "users") && slices.Contains(tc.missing, "admins"); lost != errors.Is(adminErr, ErrNotFound) || (!lost && adminErr != nil) {
				t.Fatalf("administrator after recovery: %v", adminErr)
			}
			if got := countRows(t, s.DB, `SELECT COUNT(*) FROM admins`); got != 0 {
				t.Fatalf("admins rows = %d, want the row retired", got)
			}

			job, err := s.CreateJob(ctx, testJob("recovered"))
			if err != nil {
				t.Fatal(err)
			}
			user, err := s.CreateUser(ctx, User{Username: "recovered", Role: RoleViewer, PasswordHash: "hash", Enabled: true}, AuditEntry{})
			if err != nil {
				t.Fatal(err)
			}
			profile, err := s.CreateScannerProfile(ctx, "Recovered", "", config.ScannerProfile{Engine: config.EngineNmap}, "admin")
			if err != nil {
				t.Fatal(err)
			}
			destination, err := s.CreateManagedNotification(ctx, "destination-recovered", "Recovered", "generic", []byte{1}, []byte{2}, true)
			if err != nil {
				t.Fatal(err)
			}
			for table, id := range map[string]string{"jobs": job.ID, "users": user.ID, "scanner_profiles": profile.ID, "managed_notifications": destination.ID} {
				if got := countRows(t, s.DB, `SELECT COUNT(*) FROM `+table+` WHERE id=? AND tenant_id=?`, id, DefaultTenantID); got != 1 {
					t.Fatalf("new %s row is not in the default tenant", table)
				}
			}
			if got := countRows(t, s.DB, `SELECT COUNT(*) FROM scanner_profiles WHERE built_in=1 AND tenant_id IS NULL`); got != 2 {
				t.Fatalf("built-in profiles = %d, want 2", got)
			}
		})
	}
}

// Running the migration again, after the schema marker was reset, changes
// no row and no schema object.
func TestMigration52IsANoOpWhenRepeated(t *testing.T) {
	fixture := newSchema51Fixture(t)
	s, err := Open(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func(db *sql.DB) string {
		var out strings.Builder
		fmt.Fprintln(&out, schema52RowSnapshot(t, db))
		for _, table := range schema52RootTables {
			if err := snapshotRows(db, `SELECT rowid,id,tenant_id FROM `+table+` ORDER BY rowid`, &out); err != nil {
				t.Fatal(err)
			}
		}
		if err := snapshotRows(db, `SELECT type,name,tbl_name,COALESCE(sql,'') FROM sqlite_master ORDER BY type,name`, &out); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	before := snapshot(s.DB)
	if _, err := s.DB.Exec(`PRAGMA user_version=51`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	repeated, err := Open(fixture.path)
	if err != nil {
		t.Fatalf("repeat migration 52: %v", err)
	}
	defer repeated.Close()
	if after := snapshot(repeated.DB); after != before {
		t.Fatalf("repeating migration 52 changed the database:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	assertForeignKeysClean(t, repeated.DB)
}

// secondTenantID is a tenant that the tests create directly in SQL, because
// no product API creates one yet.
const secondTenantID = "00000000-0000-0000-0000-000000000200"

func insertSecondTenant(t *testing.T, s *Store) {
	t.Helper()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Second','second',?,?)`, secondTenantID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}

// The rebuilt tables enforce tenant ownership and per-tenant names.
func TestSchema52TenantConstraints(t *testing.T) {
	s := openTestStore(t)
	insertSecondTenant(t, s)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	var tenantNone any
	sequence := 0
	nextID := func() string {
		sequence++
		return fmt.Sprintf("00000000-0000-0000-0000-%012d", 1000+sequence)
	}
	user := func(tenant any, username, role string) func() error {
		return func() error {
			_, err := s.DB.Exec(`INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,created_at,updated_at) VALUES(?,?,?,?,?,'hash',?,?)`, nextID(), tenant, username, username, role, stamp, stamp)
			return err
		}
	}
	job := func(tenant any, name string) func() error {
		return func() error {
			_, err := s.DB.Exec(`INSERT INTO jobs(id,tenant_id,name,definition_json,created_at,updated_at) VALUES(?,?,?,'{}',?,?)`, nextID(), tenant, name, stamp, stamp)
			return err
		}
	}
	profile := func(tenant any, name string, builtIn int) func() error {
		return func() error {
			_, err := s.DB.Exec(`INSERT INTO scanner_profiles(id,tenant_id,name,definition_json,built_in,created_at,updated_at) VALUES(?,?,?,'{}',?,?,?)`, nextID(), tenant, name, builtIn, stamp, stamp)
			return err
		}
	}
	destination := func(tenant any, name string) func() error {
		return func() error {
			_, err := s.DB.Exec(`INSERT INTO managed_notifications(id,tenant_id,name,provider,ciphertext,nonce,created_at,updated_at) VALUES(?,?,?,'generic',x'01',x'02',?,?)`, nextID(), tenant, name, stamp, stamp)
			return err
		}
	}
	for _, tc := range []struct {
		name    string
		insert  func() error
		wantErr string
	}{
		{"administrator in the default tenant", user(DefaultTenantID, "alice", RoleAdministrator), ""},
		{"platform admin without a tenant", user(tenantNone, "root", "platform_admin"), ""},
		{"platform admin with a tenant", user(DefaultTenantID, "platform-with-tenant", "platform_admin"), "CHECK constraint failed"},
		{"administrator without a tenant", user(tenantNone, "admin-without-tenant", RoleAdministrator), "CHECK constraint failed"},
		{"viewer without a tenant", user(tenantNone, "viewer-without-tenant", RoleViewer), "CHECK constraint failed"},
		{"unknown role", user(DefaultTenantID, "owner", "owner"), "CHECK constraint failed"},
		{"unknown tenant", user("00000000-0000-0000-0000-000000000999", "stranger", RoleViewer), "FOREIGN KEY constraint failed"},
		{"operator in the second tenant", user(secondTenantID, "bob", RoleOperator), ""},
		{"username taken in another tenant", user(secondTenantID, "ALICE", RoleViewer), "UNIQUE constraint failed: users.username"},

		{"job in the default tenant", job(DefaultTenantID, "edge"), ""},
		{"duplicate job name in a tenant", job(DefaultTenantID, "edge"), "UNIQUE constraint failed: jobs.tenant_id, jobs.name"},
		{"job name that differs in case", job(DefaultTenantID, "EDGE"), ""},
		{"same job name in the second tenant", job(secondTenantID, "edge"), ""},
		{"duplicate job name in the second tenant", job(secondTenantID, "edge"), "UNIQUE constraint failed: jobs.tenant_id, jobs.name"},
		{"job without a tenant", job(tenantNone, "orphan"), "NOT NULL constraint failed: jobs.tenant_id"},

		{"custom profile in the default tenant", profile(DefaultTenantID, "Edge", 0), ""},
		{"duplicate custom profile name in a tenant", profile(DefaultTenantID, "EDGE", 0), "UNIQUE constraint failed: index 'scanner_profiles_tenant_name'"},
		{"same custom profile name in the second tenant", profile(secondTenantID, "edge", 0), ""},
		{"custom profile without a tenant", profile(tenantNone, "Loose", 0), "CHECK constraint failed"},
		{"built-in profile with a tenant", profile(DefaultTenantID, "Owned built-in", 1), "CHECK constraint failed"},
		{"duplicate built-in profile name", profile(tenantNone, "NMAP STANDARD", 1), "UNIQUE constraint failed: index 'scanner_profiles_tenant_name'"},
		{"custom profile named like a built-in", profile(DefaultTenantID, "Nmap standard", 0), ""},

		{"destination in the default tenant", destination(DefaultTenantID, "Ops"), ""},
		{"duplicate destination name in a tenant", destination(DefaultTenantID, "Ops"), "UNIQUE constraint failed: managed_notifications.tenant_id, managed_notifications.name"},
		{"same destination name in the second tenant", destination(secondTenantID, "Ops"), ""},
		{"platform destination", destination(tenantNone, "Ops"), ""},
		{"duplicate platform destination name", destination(tenantNone, "Ops"), "UNIQUE constraint failed: managed_notifications.name"},
		{"platform destination name that differs in case", destination(tenantNone, "OPS"), ""},
		{"destination in an unknown tenant", destination("00000000-0000-0000-0000-000000000999", "Lost"), "FOREIGN KEY constraint failed"},
	} {
		err := tc.insert()
		if tc.wantErr == "" && err != nil {
			t.Errorf("%s: %v, want success", tc.name, err)
		}
		if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.wantErr)
		}
	}
}

// Every store writer of a rebuilt table names the default tenant: none of
// them relies on a column default, which the tenant_id columns do not have.
func TestRootTableWritersNameTheDefaultTenant(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if err := s.PutSetupTokenAt(ctx, "setup-hash", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteSetup(ctx, "setup-hash", Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, User{Username: "operator", Role: RoleOperator, PasswordHash: "hash", Enabled: true}, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUserWithInvite(ctx, User{Username: "invited", Role: RoleViewer, PasswordHash: "!pending"}, "invite-hash", now, now.Add(time.Hour), AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateJob(ctx, testJob("edge")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateScannerProfile(ctx, "Edge TCP", "", config.ScannerProfile{Engine: config.EngineNmap}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateManagedNotification(ctx, "destination-web", "Web", "generic", []byte{1}, []byte{2}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportDeploymentNotifications(ctx, []DeploymentNotificationImport{testImport(testURLDigest("tenant"), "destination-imported")}); err != nil {
		t.Fatal(err)
	}
	saved := openTestStore(t)
	if err := saved.SaveAdmin(ctx, Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}

	for _, written := range []*Store{s, saved} {
		for query, want := range map[string]int{
			`SELECT COUNT(*) FROM users WHERE tenant_id IS NOT '` + DefaultTenantID + `'`:                           0,
			`SELECT COUNT(*) FROM jobs WHERE tenant_id IS NOT '` + DefaultTenantID + `'`:                            0,
			`SELECT COUNT(*) FROM managed_notifications WHERE tenant_id IS NOT '` + DefaultTenantID + `'`:           0,
			`SELECT COUNT(*) FROM scanner_profiles WHERE built_in=0 AND tenant_id IS NOT '` + DefaultTenantID + `'`: 0,
			`SELECT COUNT(*) FROM scanner_profiles WHERE built_in=1 AND tenant_id IS NOT NULL`:                      0,
			`SELECT COUNT(*) FROM admins`: 0,
		} {
			if got := countRows(t, written.DB, query); got != want {
				t.Fatalf("%s = %d, want %d", query, got, want)
			}
		}
	}
	for table, want := range map[string]int{"users": 3, "jobs": 1, "managed_notifications": 2, "scanner_profiles": 3} {
		if got := countRows(t, s.DB, `SELECT COUNT(*) FROM `+table); got != want {
			t.Fatalf("%s rows = %d, want %d", table, got, want)
		}
	}
	if got := countRows(t, saved.DB, `SELECT COUNT(*) FROM users WHERE id=?`, LegacyAdminUserID); got != 1 {
		t.Fatalf("SaveAdmin users rows = %d, want 1", got)
	}
}

// A first setup creates the original administrator in users, in the default
// tenant, and nothing in the retired admins table.
func TestCompleteSetupOnAFreshInstallCreatesOnlyTheUsersRow(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if configured, err := s.HasAdministrator(ctx); err != nil || configured {
		t.Fatalf("fresh install configured = %v, %v", configured, err)
	}
	if err := s.PutSetupTokenAt(ctx, "setup-hash", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteSetup(ctx, "setup-hash", Admin{Username: "admin", PasswordHash: "setup-hash-value", CreatedAt: now, UpdatedAt: now}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var tenant, role, displayName string
	var revision int64
	if err := s.DB.QueryRow(`SELECT tenant_id,role,display_name,revision FROM users WHERE id=? AND username='admin'`, LegacyAdminUserID).Scan(&tenant, &role, &displayName, &revision); err != nil {
		t.Fatal(err)
	}
	if tenant != DefaultTenantID || role != RoleAdministrator || displayName != "admin" || revision != 1 {
		t.Fatalf("administrator = %q/%q/%q revision %d", tenant, role, displayName, revision)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM admins`); got != 0 {
		t.Fatalf("setup wrote %d admins rows", got)
	}
	if configured, err := s.HasAdministrator(ctx); err != nil || !configured {
		t.Fatalf("configured after setup = %v, %v", configured, err)
	}
	if admin, err := s.GetAdmin(ctx); err != nil || admin.PasswordHash != "setup-hash-value" {
		t.Fatalf("administrator = %#v, %v", admin, err)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM security_audit WHERE action='admin.setup'`); got != 1 {
		t.Fatalf("setup audit rows = %d", got)
	}
	// Setup and a reissued token are refused once the administrator exists.
	if err := s.PutSetupTokenAt(ctx, "second-hash", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteSetup(ctx, "second-hash", Admin{Username: "second", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}, now.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "already configured") {
		t.Fatalf("second setup = %v", err)
	}
	if err := s.ReissueSetupToken(ctx, "reissued-hash", now.Add(time.Hour), now.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "already configured") {
		t.Fatalf("reissue after setup = %v", err)
	}
}

// The setup token writers fail closed when the administrator check cannot
// run, instead of treating a missing users table as an unconfigured install.
func TestSetupTokenWritersRequireTheUsersTable(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if err := s.PutSetupTokenAt(ctx, "setup-hash", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DROP TABLE users`); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteSetup(ctx, "setup-hash", Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}, now); err == nil || !strings.Contains(err.Error(), "no such table") {
		t.Fatalf("setup without a users table = %v", err)
	}
	if err := s.ReissueSetupToken(ctx, "reissued-hash", now.Add(time.Hour), now.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "no such table") {
		t.Fatalf("reissue without a users table = %v", err)
	}
	if configured, err := s.HasAdministrator(ctx); err == nil || configured {
		t.Fatalf("HasAdministrator without a users table = %v, %v", configured, err)
	}
	if admin, err := s.GetAdmin(ctx); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAdmin without a users table = %#v, %v; want the read error", admin, err)
	}
}

// Built-in profiles keep their names reserved: a custom profile cannot take
// one, as under the global unique name before schema 52.
func TestCustomScannerProfileCannotUseABuiltinName(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.CreateScannerProfile(ctx, "  nmap STANDARD ", "", config.ScannerProfile{Engine: config.EngineNmap}, "admin"); !errors.Is(err, ErrScannerProfileNameInUse) {
		t.Fatalf("custom profile named like a built-in = %v, want ErrScannerProfileNameInUse", err)
	}
	profile, err := s.CreateScannerProfile(ctx, "Custom", "", config.ScannerProfile{Engine: config.EngineNmap}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateScannerProfile(ctx, profile.ID, profile.Revision, "NAABU FULL TCP → NMAP", "", config.ScannerProfile{Engine: config.EngineNmap}, "admin"); !errors.Is(err, ErrScannerProfileNameInUse) {
		t.Fatalf("rename to a built-in name = %v, want ErrScannerProfileNameInUse", err)
	}
	current, err := s.GetScannerProfile(ctx, profile.ID)
	if err != nil || current.Name != "Custom" || current.Revision != profile.Revision {
		t.Fatalf("profile after a refused rename = %#v, %v", current, err)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM scanner_profiles WHERE built_in=0`); got != 1 {
		t.Fatalf("custom profiles = %d, want 1", got)
	}
}
