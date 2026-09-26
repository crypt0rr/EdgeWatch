package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// schema50FixtureStatements turn a current database into the schema-50 shape:
// the update alert routing and the public status page go back to their
// schema-50 locations, and the tenants table, the public_dashboards table,
// and the columns and indexes that schema 51 adds are removed.
var schema50FixtureStatements = []string{
	"DROP INDEX security_audit_tenant_time",
	"DROP INDEX security_audit_platform_time",
	"ALTER TABLE security_audit DROP COLUMN tenant_id",
	"ALTER TABLE security_audit DROP COLUMN actor_kind",
	"ALTER TABLE security_audit DROP COLUMN category",
	"ALTER TABLE setup_tokens DROP COLUMN purpose",
	`CREATE TABLE public_dashboard (
 id INTEGER PRIMARY KEY CHECK(id=1),
 enabled INTEGER NOT NULL DEFAULT 0,
 title TEXT NOT NULL DEFAULT 'EdgeWatch public status',
 introduction TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL
)`,
	`INSERT INTO public_dashboard(id,enabled,title,introduction,updated_at)
SELECT 1,enabled,title,introduction,updated_at FROM public_dashboards WHERE tenant_id='` + DefaultTenantID + `'`,
	"DROP TABLE public_dashboards",
	`UPDATE application_update_state SET notification_destinations_json=(SELECT update_destinations_json FROM tenants WHERE id='` + DefaultTenantID + `') WHERE id=1`,
	"DROP TABLE tenants",
	"PRAGMA user_version=50",
}

// execFixtureStatements runs statements against the closed database at path
// without migrating it.
func execFixtureStatements(t *testing.T, path string, statements []string) {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, statement := range statements {
		if _, err := raw.Exec(statement); err != nil {
			t.Fatalf("fixture statement %s: %v", statement, err)
		}
	}
}

type schema50Fixture struct {
	path        string
	jobID       string
	routingJSON string
	dashboard   PublicDashboard
	auditRows   int
}

// schema50AuditActions covers each category, an action that is written by
// SQL in migration 38, and an action that no release writes.
var schema50AuditActions = map[string]string{
	"user.login":                         auditCategoryAccount,
	"auth.login_failed":                  auditCategoryAccount,
	"admin.setup_token_reissued":         auditCategoryAccount,
	"database.backup":                    auditCategoryPlatform,
	"notifications.config_imported":      auditCategoryPlatform,
	"job.created":                        auditCategoryData,
	"notifications.update_routing":       auditCategoryData,
	"public_dashboard.updated":           auditCategoryData,
	"auth.legacy_recovery_codes_retired": auditCategoryAccount,
	"legacy.unknown_action":              auditCategoryData,
}

// newSchema50Fixture writes a populated database with the current code and
// rewrites it into the schema-50 shape. routing is the update routing to
// configure; nil leaves it unconfigured.
func newSchema50Fixture(t *testing.T, routing func(destinations []ManagedNotification) []string) schema50Fixture {
	t.Helper()
	ctx := context.Background()
	fixture := schema50Fixture{path: filepath.Join(t.TempDir(), "schema50.db")}
	s, err := Open(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	job, err := s.CreateJob(ctx, testJob("schema50-public"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.jobID = job.ID
	var destinations []ManagedNotification
	for _, name := range []string{"Operations", "Security"} {
		destination, err := s.CreateManagedNotification(ctx, "destination-"+strings.ToLower(name), name, "generic", []byte{1}, []byte{2}, true)
		if err != nil {
			t.Fatal(err)
		}
		destinations = append(destinations, destination)
	}
	if routing != nil {
		if err := s.SetApplicationUpdateDestinations(ctx, routing(destinations), AuditEntry{Action: "notifications.update_routing", ActorUsername: "admin"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SavePublicDashboard(ctx, PublicDashboard{Enabled: true, Title: "Perimeter", Introduction: "Published hosts"}, []PublicDashboardHost{
		{JobID: job.ID, Address: "192.0.2.10"},
		{JobID: job.ID, Address: "192.0.2.11"},
	}, AuditEntry{Action: "public_dashboard.updated", ActorUsername: "admin"}); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"user.login", "auth.login_failed", "admin.setup_token_reissued", "database.backup", "notifications.config_imported", "job.created", "legacy.unknown_action"} {
		if err := s.AuditEntry(ctx, AuditEntry{Action: action, Detail: "fixture", ActorUsername: "admin"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO security_audit(action,detail,created_at) VALUES('auth.legacy_recovery_codes_retired','retired=1',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSetupToken(ctx, "setup-token-hash", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	execFixtureStatements(t, fixture.path, schema50FixtureStatements)

	raw, err := sql.Open("sqlite", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := raw.QueryRow(`SELECT notification_destinations_json FROM application_update_state WHERE id=1`).Scan(&fixture.routingJSON); err != nil {
		t.Fatal(err)
	}
	var enabled int
	var updated string
	if err := raw.QueryRow(`SELECT enabled,title,introduction,updated_at FROM public_dashboard WHERE id=1`).Scan(&enabled, &fixture.dashboard.Title, &fixture.dashboard.Introduction, &updated); err != nil {
		t.Fatal(err)
	}
	fixture.dashboard.Enabled = enabled != 0
	fixture.dashboard.UpdatedAt = scanTime(updated)
	if err := raw.QueryRow(`SELECT COUNT(*) FROM security_audit`).Scan(&fixture.auditRows); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"tenants", "public_dashboards"} {
		var count int
		if err := raw.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name=?`, table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("schema 50 fixture still has %s: %d, %v", table, count, err)
		}
	}
	return fixture
}

func assertForeignKeysClean(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		var table, parent string
		var rowID, key sql.NullInt64
		if err := rows.Scan(&table, &rowID, &parent, &key); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("foreign key violation in %s row %v referencing %s", table, rowID, parent)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

// schema51Snapshot renders everything that migration 51 writes, so a repeated
// run can be shown to change nothing.
func schema51Snapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	var out strings.Builder
	for _, query := range []string{
		`SELECT id,name,slug,state,is_default,update_destinations_json,revision,created_at,updated_at FROM tenants ORDER BY id`,
		`SELECT id,notification_destinations_json FROM application_update_state ORDER BY id`,
		`SELECT id,tenant_id,enabled,title,introduction,updated_at FROM public_dashboards ORDER BY id`,
		`SELECT dashboard_id,job_id,address,created_at FROM public_dashboard_hosts ORDER BY dashboard_id,job_id,address`,
		`SELECT id,token_hash,purpose FROM setup_tokens ORDER BY id`,
		`SELECT id,action,COALESCE(tenant_id,'<null>'),actor_kind,category FROM security_audit ORDER BY id`,
		`SELECT name FROM sqlite_master WHERE name IN ('public_dashboard') ORDER BY name`,
	} {
		if err := snapshotRows(db, query, &out); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		fmt.Fprintln(&out, "--")
	}
	return out.String()
}

// snapshotRows writes one line per row of query to out.
func snapshotRows(db *sql.DB, query string, out *strings.Builder) error {
	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return err
	}
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return err
		}
		fmt.Fprintln(out, values...)
	}
	return rows.Err()
}

func TestMigration51MovesSingletonsToTheDefaultTenant(t *testing.T) {
	for _, tc := range []struct {
		name    string
		routing func([]ManagedNotification) []string
	}{
		{name: "configured update routing", routing: func(destinations []ManagedNotification) []string { return []string{destinations[1].ID} }},
		{name: "silenced update routing", routing: func([]ManagedNotification) []string { return []string{} }},
		{name: "unconfigured update routing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fixture := newSchema50Fixture(t, tc.routing)

			s, err := Open(fixture.path)
			if err != nil {
				t.Fatalf("upgrade from schema 50: %v", err)
			}
			defer s.Close()
			var version int
			if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 51 {
				t.Fatalf("schema version = %d, %v; want 51", version, err)
			}

			// The default tenant exists once, with the fixed ID, and holds the
			// update routing unchanged.
			var tenants int
			if err := s.DB.QueryRow(`SELECT COUNT(*) FROM tenants`).Scan(&tenants); err != nil || tenants != 1 {
				t.Fatalf("tenant count = %d, %v; want 1", tenants, err)
			}
			var name, slug, state, routing, created string
			var isDefault, revision int
			if err := s.DB.QueryRow(`SELECT name,slug,state,is_default,update_destinations_json,revision,created_at FROM tenants WHERE id=?`, DefaultTenantID).Scan(&name, &slug, &state, &isDefault, &routing, &revision, &created); err != nil {
				t.Fatalf("default tenant: %v", err)
			}
			if name != "Default" || slug != "default" || state != "active" || isDefault != 1 || revision != 1 || scanTime(created).IsZero() {
				t.Fatalf("default tenant = %q/%q/%q default=%d revision=%d created=%q", name, slug, state, isDefault, revision, created)
			}
			if routing != fixture.routingJSON {
				t.Fatalf("tenant update routing = %q, want the schema-50 routing %q", routing, fixture.routingJSON)
			}
			var platformRouting string
			if err := s.DB.QueryRow(`SELECT notification_destinations_json FROM application_update_state WHERE id=1`).Scan(&platformRouting); err != nil || platformRouting != "[]" {
				t.Fatalf("platform update routing = %q, %v; want []", platformRouting, err)
			}
			updateState, err := s.GetApplicationUpdateState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if tc.routing == nil {
				if fixture.routingJSON != "" || updateState.UpdateNotificationDestinationsConfigured || updateState.UpdateNotificationDestinations != nil {
					t.Fatalf("unconfigured routing became %#v (fixture %q)", updateState, fixture.routingJSON)
				}
			} else {
				var want []string
				if err := json.Unmarshal([]byte(fixture.routingJSON), &want); err != nil {
					t.Fatal(err)
				}
				if !updateState.UpdateNotificationDestinationsConfigured || !slices.Equal(updateState.UpdateNotificationDestinations, want) {
					t.Fatalf("configured routing = %#v, want %v", updateState, want)
				}
			}

			// The public status page is the default tenant's dashboard 1, and
			// its hosts still point at it.
			var oldTables int
			if err := s.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='public_dashboard'`).Scan(&oldTables); err != nil || oldTables != 0 {
				t.Fatalf("public_dashboard table count = %d, %v; want dropped", oldTables, err)
			}
			var dashboardID int64
			var dashboardTenant string
			if err := s.DB.QueryRow(`SELECT id,tenant_id FROM public_dashboards`).Scan(&dashboardID, &dashboardTenant); err != nil || dashboardID != 1 || dashboardTenant != DefaultTenantID {
				t.Fatalf("public dashboard = %d/%q, %v", dashboardID, dashboardTenant, err)
			}
			dashboard, err := s.GetPublicDashboard(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if dashboard.Enabled != fixture.dashboard.Enabled || dashboard.Title != fixture.dashboard.Title || dashboard.Introduction != fixture.dashboard.Introduction || !dashboard.UpdatedAt.Equal(fixture.dashboard.UpdatedAt) {
				t.Fatalf("public dashboard = %#v, want %#v", dashboard, fixture.dashboard)
			}
			if len(dashboard.Hosts) != 2 || dashboard.Hosts[0].JobID != fixture.jobID || dashboard.Hosts[0].Address != "192.0.2.10" || dashboard.Hosts[1].Address != "192.0.2.11" {
				t.Fatalf("public dashboard hosts = %#v", dashboard.Hosts)
			}
			var orphanHosts int
			if err := s.DB.QueryRow(`SELECT COUNT(*) FROM public_dashboard_hosts WHERE dashboard_id NOT IN (SELECT id FROM public_dashboards)`).Scan(&orphanHosts); err != nil || orphanHosts != 0 {
				t.Fatalf("public dashboard hosts without a dashboard = %d, %v", orphanHosts, err)
			}

			// Audit records keep their IDs, belong to the default tenant, and
			// are categorized by their action.
			var auditRows int
			if err := s.DB.QueryRow(`SELECT COUNT(*) FROM security_audit`).Scan(&auditRows); err != nil || auditRows != fixture.auditRows {
				t.Fatalf("audit rows = %d, %v; want %d", auditRows, err, fixture.auditRows)
			}
			audits, err := readMigratedAudits(s.DB)
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			for _, audit := range audits {
				if !audit.tenant.Valid || audit.tenant.String != DefaultTenantID || audit.actorKind != "" || audit.category != auditCategory(audit.action) {
					t.Fatalf("migrated audit %s = tenant %v, actor kind %q, category %q", audit.action, audit.tenant, audit.actorKind, audit.category)
				}
				if want, ok := schema50AuditActions[audit.action]; ok && audit.category != want {
					t.Fatalf("migrated audit %s category = %q, want %q", audit.action, audit.category, want)
				}
				seen[audit.action] = true
			}
			for action := range schema50AuditActions {
				if action == "notifications.update_routing" && tc.routing == nil {
					continue
				}
				if !seen[action] {
					t.Fatalf("fixture audit %s is missing after the migration", action)
				}
			}
			for _, index := range []string{"security_audit_tenant_time", "security_audit_platform_time", "tenants_name_live", "tenants_slug_live", "tenants_one_default"} {
				var count int
				if err := s.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, index).Scan(&count); err != nil || count != 1 {
					t.Fatalf("index %s count = %d, %v", index, count, err)
				}
			}

			var purpose string
			if err := s.DB.QueryRow(`SELECT purpose FROM setup_tokens WHERE id=1`).Scan(&purpose); err != nil || purpose != "initial" {
				t.Fatalf("setup token purpose = %q, %v; want initial", purpose, err)
			}
			assertForeignKeysClean(t, s.DB)

			// The copied revision token still lets the loaded editor save.
			if err := s.SavePublicDashboardIfCurrent(ctx, dashboard.UpdatedAt, PublicDashboard{Enabled: false, Title: "After upgrade"}, dashboard.Hosts[:1], AuditEntry{Action: "public_dashboard.updated"}); err != nil {
				t.Fatalf("save with the pre-upgrade revision token: %v", err)
			}
			saved, err := s.GetPublicDashboard(ctx)
			if err != nil || saved.Title != "After upgrade" || saved.Enabled || len(saved.Hosts) != 1 {
				t.Fatalf("saved public dashboard = %#v, %v", saved, err)
			}
			var dashboards int
			if err := s.DB.QueryRow(`SELECT COUNT(*) FROM public_dashboards WHERE id=1`).Scan(&dashboards); err != nil || dashboards != 1 {
				t.Fatalf("public dashboards after save = %d, %v", dashboards, err)
			}
		})
	}
}

type migratedAudit struct {
	action, actorKind, category string
	tenant                      sql.NullString
}

func readMigratedAudits(db *sql.DB) ([]migratedAudit, error) {
	rows, err := db.Query(`SELECT action,tenant_id,actor_kind,category FROM security_audit ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var audits []migratedAudit
	for rows.Next() {
		var audit migratedAudit
		if err := rows.Scan(&audit.action, &audit.tenant, &audit.actorKind, &audit.category); err != nil {
			return nil, err
		}
		audits = append(audits, audit)
	}
	return audits, rows.Err()
}

// A second run of the migration, both on an already current database and
// after the schema marker was reset, leaves every relocated value unchanged.
func TestMigration51IsANoOpWhenRepeated(t *testing.T) {
	ctx := context.Background()
	fixture := newSchema50Fixture(t, func(destinations []ManagedNotification) []string { return []string{destinations[0].ID} })
	s, err := Open(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	// Write after the upgrade so the repeat cannot pass by copying the
	// schema-50 values again.
	if err := s.SetApplicationUpdateDestinations(ctx, []string{"file:after-upgrade"}, AuditEntry{Action: "notifications.update_routing"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePublicDashboard(ctx, PublicDashboard{Enabled: true, Title: "After upgrade"}, nil, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	before := schema51Snapshot(t, s.DB)
	if err := migrateContext(ctx, s.DB); err != nil {
		t.Fatalf("migrate a current database: %v", err)
	}
	if after := schema51Snapshot(t, s.DB); after != before {
		t.Fatalf("migrating a current database changed it:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if _, err := s.DB.ExecContext(ctx, `PRAGMA user_version=50`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	repeated, err := Open(fixture.path)
	if err != nil {
		t.Fatalf("repeat migration 51: %v", err)
	}
	defer repeated.Close()
	if after := schema51Snapshot(t, repeated.DB); after != before {
		t.Fatalf("repeating migration 51 changed the database:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	assertForeignKeysClean(t, repeated.DB)
}

// Some recovery databases carry a schema marker without every table. The
// migration creates the tables it reads, and the store works on the result.
func TestMigration51UpgradesRecoveryDatabasesWithMissingTables(t *testing.T) {
	for _, tc := range []struct {
		name    string
		missing []string
	}{
		{name: "application_update_state", missing: []string{"application_update_state"}},
		{name: "public_dashboard", missing: []string{"public_dashboard"}},
		{name: "setup_tokens", missing: []string{"setup_tokens"}},
		{name: "security_audit", missing: []string{"security_audit"}},
		{name: "all", missing: []string{"application_update_state", "public_dashboard", "setup_tokens", "security_audit"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fixture := newSchema50Fixture(t, nil)
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
			var version int
			if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 51 {
				t.Fatalf("schema version = %d, %v", version, err)
			}
			var routing string
			if err := s.DB.QueryRow(`SELECT update_destinations_json FROM tenants WHERE id=? AND is_default=1`, DefaultTenantID).Scan(&routing); err != nil {
				t.Fatalf("default tenant: %v", err)
			}
			state, err := s.GetApplicationUpdateState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if state.UpdateNotificationDestinationsConfigured {
				t.Fatalf("update routing = %#v, want unconfigured", state)
			}
			if err := s.SetApplicationUpdateDestinations(ctx, []string{"file:ops"}, AuditEntry{Action: "notifications.update_routing"}); err != nil {
				t.Fatal(err)
			}
			if slices.Contains(tc.missing, "public_dashboard") {
				if _, err := s.GetPublicDashboard(ctx); !errors.Is(err, ErrNotFound) {
					t.Fatalf("public dashboard of a recovery database = %v, want not found", err)
				}
			}
			if err := s.SavePublicDashboard(ctx, PublicDashboard{Enabled: true, Title: "Recovered"}, []PublicDashboardHost{{JobID: fixture.jobID, Address: "192.0.2.20"}}, AuditEntry{Action: "public_dashboard.updated"}); err != nil {
				t.Fatal(err)
			}
			dashboard, err := s.GetPublicDashboard(ctx)
			if err != nil || dashboard.Title != "Recovered" || len(dashboard.Hosts) != 1 {
				t.Fatalf("recovered public dashboard = %#v, %v", dashboard, err)
			}
			if err := s.PutSetupToken(ctx, "recovered-token", time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			var purpose, category, tenant string
			if err := s.DB.QueryRow(`SELECT purpose FROM setup_tokens WHERE id=1`).Scan(&purpose); err != nil || purpose != "initial" {
				t.Fatalf("setup token purpose = %q, %v", purpose, err)
			}
			if err := s.DB.QueryRow(`SELECT category,tenant_id FROM security_audit WHERE action='public_dashboard.updated' ORDER BY id DESC LIMIT 1`).Scan(&category, &tenant); err != nil || category != auditCategoryData || tenant != DefaultTenantID {
				t.Fatalf("audit after recovery = %q/%q, %v", category, tenant, err)
			}
			assertForeignKeysClean(t, s.DB)
		})
	}
}

// The update routing lives on the default tenant's row. Without that row a
// routing write fails and changes nothing, instead of reporting success for
// a routing that is not stored.
func TestUpdateRoutingWritesRequireTheDefaultTenant(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	destination, err := s.CreateManagedNotification(ctx, "destination-routing", "Routing", "generic", []byte{1}, []byte{2}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetApplicationUpdateDestinations(ctx, []string{destination.ID}, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM public_dashboards; DELETE FROM tenants`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetApplicationUpdateDestinations(ctx, []string{"file:other"}, AuditEntry{Action: "notifications.update_routing"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("routing write without the default tenant = %v, want ErrNotFound", err)
	}
	var audits int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='notifications.update_routing'`).Scan(&audits); err != nil || audits != 0 {
		t.Fatalf("failed routing write left %d audit rows: %v", audits, err)
	}
	if changed, err := s.DeleteManagedNotificationWithAudit(ctx, destination.ID, destination.Revision, AuditEntry{Action: "notifications.deleted"}); err != nil || len(changed) != 0 {
		t.Fatalf("delete without the default tenant = %v, %v", changed, err)
	}
}

// Host commands open the database without migrating it. A command that runs
// on a schema-50 database, such as the audit of a restore of an older backup,
// still records its audit entry, and the migration categorizes it later.
func TestAuditEntryOnSchema50DatabaseIsCategorizedByTheMigration(t *testing.T) {
	ctx := context.Background()
	fixture := newSchema50Fixture(t, nil)
	existing, err := OpenExisting(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := existing.AuditEntry(ctx, AuditEntry{Action: "database.restore", Detail: "host command", ActorUsername: "host-cli"}); err != nil {
		existing.Close()
		t.Fatalf("audit on a schema-50 database: %v", err)
	}
	tx, err := existing.DB.BeginTx(ctx, nil)
	if err != nil {
		existing.Close()
		t.Fatal(err)
	}
	if err := insertRestoreAuditTx(ctx, tx, PendingDeliveriesQuarantine, 0, "epoch-50", time.Now().UTC()); err != nil {
		_ = tx.Rollback()
		existing.Close()
		t.Fatalf("restore audit on a schema-50 database: %v", err)
	}
	if err := tx.Commit(); err != nil {
		existing.Close()
		t.Fatal(err)
	}
	// A failure unrelated to the missing column is still reported.
	if _, err := existing.DB.ExecContext(ctx, `CREATE TRIGGER reject_audit BEFORE INSERT ON security_audit WHEN NEW.action='auth.rate_limited' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		existing.Close()
		t.Fatal(err)
	}
	if err := existing.AuditEntry(ctx, AuditEntry{Action: "auth.rate_limited"}); !errors.Is(err, ErrAuditUnavailable) {
		existing.Close()
		t.Fatalf("rejected audit on a schema-50 database = %v, want ErrAuditUnavailable", err)
	}
	if err := existing.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, action := range []string{"database.restore", "database.restore.pending_deliveries"} {
		var category, tenant string
		if err := s.DB.QueryRow(`SELECT category,tenant_id FROM security_audit WHERE action=?`, action).Scan(&category, &tenant); err != nil {
			t.Fatalf("%s audit: %v", action, err)
		}
		if category != auditCategoryPlatform || tenant != DefaultTenantID {
			t.Fatalf("%s audit = %q/%q, want platform for the default tenant", action, category, tenant)
		}
	}

	// On a current database both writers record the category directly.
	tx, err = s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertRestoreAuditTx(ctx, tx, PendingDeliveriesDiscard, 2, "epoch-51", time.Now().UTC()); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.AuditEntry(ctx, AuditEntry{Action: "user.login", ActorUsername: "admin"}); err != nil {
		t.Fatal(err)
	}
	for action, want := range map[string]string{"database.restore.pending_deliveries": auditCategoryPlatform, "user.login": auditCategoryAccount} {
		var category, actor string
		if err := s.DB.QueryRow(`SELECT category,actor_username FROM security_audit WHERE action=? ORDER BY id DESC LIMIT 1`, action).Scan(&category, &actor); err != nil {
			t.Fatal(err)
		}
		if category != want {
			t.Fatalf("%s audit category = %q, want %q", action, category, want)
		}
	}
}
