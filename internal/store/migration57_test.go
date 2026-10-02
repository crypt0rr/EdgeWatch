package store

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

// reopenAtSchema56 marks the store's database as a schema 56 one and opens
// it again, as the first start of this release after an upgrade does.
func reopenAtSchema56(t *testing.T, s *Store) *Store {
	t.Helper()
	if _, err := s.DB.Exec(`PRAGMA user_version=56`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := Open(s.Path)
	if err != nil {
		t.Fatalf("upgrade from schema 56: %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	if version := countRows(t, upgraded.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
	return upgraded
}

// schema56Tenant is a tenant as a schema 56 database holds it, and the
// capacity the upgrade gives it.
type schema56Tenant struct {
	id, state string
	ceiling   any
	// audits are the actions recorded in the tenant's security audit.
	audits []string
	want   TenantCapacity
}

// The upgrade takes the automatic ceiling away from each unit other than
// the default one whose capacity no platform administrator has saved, active
// or disabled, so a high-cost approval raises nothing there. A ceiling that
// a platform administrator saved, a number or the deployment's, stays a
// grant, and so does the default unit's ceiling. Another action in the
// unit's audit, or a capacity change of another unit, is not a grant.
func TestMigration57TakesTheAutomaticCeilingAway(t *testing.T) {
	ctx := context.Background()
	notGranted := TenantCapacity{HighCostCeiling: ptrTo(HighCostNotGranted)}
	tenants := []schema56Tenant{
		{id: "automatic", state: TenantStateActive, ceiling: int64(5_000_000), audits: []string{"users.created", "tenant.renamed"}, want: notGranted},
		{id: "automatic-disabled", state: TenantStateDisabled, ceiling: int64(1_000_000), want: notGranted},
		{id: "granted", state: TenantStateActive, ceiling: int64(7_000_000), audits: []string{auditActionTenantCapacityChanged}, want: TenantCapacity{HighCostCeiling: ptrTo[int64](7_000_000)}},
		{id: "saved", state: TenantStateDisabled, ceiling: int64(5_000_000), audits: []string{auditActionTenantCapacityChanged, auditActionTenantCapacityChanged}, want: TenantCapacity{HighCostCeiling: ptrTo[int64](5_000_000)}},
		{id: "inherited", state: TenantStateActive, ceiling: nil, audits: []string{auditActionTenantCapacityChanged}, want: TenantCapacity{}},
	}
	// A schema 56 database has no high_cost_granted column.
	s := openTestStore(t)
	if _, err := s.DB.Exec(`ALTER TABLE tenants DROP COLUMN high_cost_granted`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`ALTER TABLE tenants DROP COLUMN incident_reminders_enabled`); err != nil {
		t.Fatal(err)
	}
	stamp := sqliteTimestamp(time.Now())
	insertAudit := func(tenant any, action string) {
		t.Helper()
		if _, err := s.DB.Exec(`INSERT INTO security_audit(action,detail,actor_user_id,actor_username,source_ip,request_id,category,created_at,tenant_id,actor_kind) VALUES(?,'','','','','',?,?,?,?)`, action, auditCategory(action), stamp, tenant, AuditActorPlatform); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range tenants {
		if _, err := s.DB.Exec(`INSERT INTO tenants(id,name,slug,state,high_cost_ceiling,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`, tenant.id, "Unit "+tenant.id, "unit-"+tenant.id, tenant.state, tenant.ceiling, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		for _, action := range tenant.audits {
			insertAudit(tenant.id, action)
		}
	}
	// A unit's creation belongs to no unit.
	insertAudit(nil, auditTenantCreated)
	// The default unit keeps a ceiling that nothing in its audit explains.
	if _, err := s.DB.Exec(`UPDATE tenants SET high_cost_ceiling=9000 WHERE id=?`, DefaultTenantID); err != nil {
		t.Fatal(err)
	}
	tenants = append(tenants, schema56Tenant{id: DefaultTenantID, want: TenantCapacity{HighCostCeiling: ptrTo[int64](9_000)}})

	upgraded := reopenAtSchema56(t, s)
	for _, tenant := range tenants {
		got, err := upgraded.Platform().TenantCapacity(ctx, tenant.id)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, tenant.want) {
			t.Errorf("tenant %s after the upgrade = %s, want %s", tenant.id, describeCapacity(got), describeCapacity(tenant.want))
		}
		scope, err := upgraded.TenantScopeByID(ctx, tenant.id)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := upgraded.Tenant(scope).Capacity(ctx); err != nil || !reflect.DeepEqual(got, tenant.want) {
			t.Errorf("tenant %s reads its capacity after the upgrade as %s, %v; want %s", tenant.id, describeCapacity(got), err, describeCapacity(tenant.want))
		}
	}
	if got := countRows(t, upgraded.DB, `SELECT COUNT(*) FROM tenants WHERE high_cost_granted=0 AND high_cost_ceiling IS NOT NULL`); got != 0 {
		t.Fatalf("%d tenants without a grant kept a ceiling", got)
	}
	// Only the platform administrator's grants remain, so a repeated run
	// changes nothing.
	snapshot := func(s *Store) string {
		t.Helper()
		var out strings.Builder
		if err := snapshotRows(s.DB, `SELECT id,high_cost_ceiling,high_cost_granted,revision,updated_at FROM tenants ORDER BY id`, &out); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	before := snapshot(upgraded)
	if after := snapshot(reopenAtSchema56(t, upgraded)); after != before {
		t.Fatalf("repeating migration 57 changed the tenants:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// A fresh install has the column with its check, and its default unit
// inherits the deployment's high-cost behavior as before business units.
func TestMigration57FreshInstallKeepsTheDefaultUnitsBehavior(t *testing.T) {
	s := openTestStore(t)
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM pragma_table_info('tenants') WHERE name='high_cost_granted' AND "notnull"=1 AND dflt_value='1'`); got != 1 {
		t.Fatal("tenants has no high_cost_granted column that defaults to a grant")
	}
	capacity, err := s.Platform().TenantCapacity(context.Background(), DefaultTenantID)
	if err != nil || !reflect.DeepEqual(capacity, TenantCapacity{}) {
		t.Fatalf("the default unit's capacity = %s, %v; want every setting inherited", describeCapacity(capacity), err)
	}
}
