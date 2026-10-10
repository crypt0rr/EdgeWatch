package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
)

func countRows(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var count int
	if err := db.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return count
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

// secondTenantID is a tenant that tests seed directly in SQL to keep a stable
// identifier across the shared tenant-isolation fixture.
const secondTenantID = "00000000-0000-0000-0000-000000000200"

func insertSecondTenant(t *testing.T, s *Store) {
	t.Helper()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO tenants(id,name,slug,incident_reminder_cadence,created_at,updated_at) VALUES(?,'Second','second','hourly',?,?)`, secondTenantID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}

// The rebuilt tables enforce tenant ownership and per-tenant names.
func TestSchema52TenantConstraints(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if err := s.Platform().PutSetupTokenAt(ctx, "setup-hash", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := s.Platform().CompleteSetup(ctx, "setup-hash", Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := createTestUser(ctx, defaultTenant(s), User{Username: "operator", Role: RoleOperator, PasswordHash: "hash", Enabled: true}, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).CreateUserWithInvite(ctx, User{Username: "invited", Role: RoleViewer, PasswordHash: "!pending"}, "invite-hash", now, now.Add(time.Hour), AuditEntry{ActorUserID: LegacyAdminUserID}); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).CreateJob(ctx, testJob("edge")); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).CreateScannerProfile(ctx, "Edge TCP", "", config.ScannerProfile{Engine: config.EngineNmap}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).CreateManagedNotification(ctx, "destination-web", "Web", "generic", []byte{1}, []byte{2}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().ImportDeploymentNotifications(ctx, []DeploymentNotificationImport{testImport(testURLDigest("tenant"), "destination-imported")}); err != nil {
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
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if configured, err := s.Platform().HasAdministrator(ctx); err != nil || configured {
		t.Fatalf("fresh install configured = %v, %v", configured, err)
	}
	if err := s.Platform().PutSetupTokenAt(ctx, "setup-hash", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := s.Platform().CompleteSetup(ctx, "setup-hash", Admin{Username: "admin", PasswordHash: "setup-hash-value", CreatedAt: now, UpdatedAt: now}, now.Add(time.Minute)); err != nil {
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
	if configured, err := s.Platform().HasAdministrator(ctx); err != nil || !configured {
		t.Fatalf("configured after setup = %v, %v", configured, err)
	}
	if admin, err := s.GetAdmin(ctx); err != nil || admin.PasswordHash != "setup-hash-value" {
		t.Fatalf("administrator = %#v, %v", admin, err)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM security_audit WHERE action='admin.setup'`); got != 1 {
		t.Fatalf("setup audit rows = %d", got)
	}
	// Setup and a reissued token are refused once the administrator exists.
	if err := s.Platform().PutSetupTokenAt(ctx, "second-hash", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := s.Platform().CompleteSetup(ctx, "second-hash", Admin{Username: "second", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}, now.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "already configured") {
		t.Fatalf("second setup = %v", err)
	}
	if err := s.Platform().ReissueSetupToken(ctx, "reissued-hash", now.Add(time.Hour), now.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "already configured") {
		t.Fatalf("reissue after setup = %v", err)
	}
}

// The setup token writers fail closed when the administrator check cannot
// run, instead of treating a missing users table as an unconfigured install.
func TestSetupTokenWritersRequireTheUsersTable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	if err := s.Platform().PutSetupTokenAt(ctx, "setup-hash", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DROP TABLE users`); err != nil {
		t.Fatal(err)
	}
	if err := s.Platform().CompleteSetup(ctx, "setup-hash", Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}, now); err == nil || !strings.Contains(err.Error(), "no such table") {
		t.Fatalf("setup without a users table = %v", err)
	}
	if err := s.Platform().ReissueSetupToken(ctx, "reissued-hash", now.Add(time.Hour), now.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "no such table") {
		t.Fatalf("reissue without a users table = %v", err)
	}
	if configured, err := s.Platform().HasAdministrator(ctx); err == nil || configured {
		t.Fatalf("HasAdministrator without a users table = %v, %v", configured, err)
	}
	if admin, err := s.GetAdmin(ctx); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAdmin without a users table = %#v, %v; want the read error", admin, err)
	}
}

// Built-in profiles keep their names reserved: a custom profile cannot take
// one, as under the global unique name before schema 52.
func TestCustomScannerProfileCannotUseABuiltinName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := defaultTenant(s).CreateScannerProfile(ctx, "  nmap STANDARD ", "", config.ScannerProfile{Engine: config.EngineNmap}, "admin"); !errors.Is(err, ErrScannerProfileNameInUse) {
		t.Fatalf("custom profile named like a built-in = %v, want ErrScannerProfileNameInUse", err)
	}
	profile, err := defaultTenant(s).CreateScannerProfile(ctx, "Custom", "", config.ScannerProfile{Engine: config.EngineNmap}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).UpdateScannerProfile(ctx, profile.ID, profile.Revision, "NAABU FULL TCP → NMAP", "", config.ScannerProfile{Engine: config.EngineNmap}, "admin"); !errors.Is(err, ErrScannerProfileNameInUse) {
		t.Fatalf("rename to a built-in name = %v, want ErrScannerProfileNameInUse", err)
	}
	current, err := defaultTenant(s).GetScannerProfile(ctx, profile.ID)
	if err != nil || current.Name != "Custom" || current.Revision != profile.Revision {
		t.Fatalf("profile after a refused rename = %#v, %v", current, err)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM scanner_profiles WHERE built_in=0`); got != 1 {
		t.Fatalf("custom profiles = %d, want 1", got)
	}
}
