package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
)

// The capacity case joins tenantStoreLeakCases before any test runs, so the
// completeness check and TestTenantStoreIsolation cover it.
func init() {
	for name, leak := range capacityTenantLeakCases {
		if _, exists := tenantStoreLeakCases[name]; exists {
			panic("duplicate tenant leak case " + name)
		}
		tenantStoreLeakCases[name] = leak
	}
}

var capacityTenantLeakCases = map[string]tenantLeakCase{
	// Each tenant reads its own capacity row and never another tenant's,
	// while it is paused too; a deleted tenant has no capacity.
	"Capacity": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		setCapacityColumns(t, f.store, secondTenantID, 1, 10, 20, 30)
		wantB := TenantCapacity{MaxConcurrentScans: ptrTo(1), MaxProbeCount: ptrTo[int64](10), MaxNaabuProbeCount: ptrTo[int64](20), HighCostCeiling: ptrTo[int64](30)}
		for _, state := range []string{TenantStateActive, TenantStateDisabled, TenantStateDeleting} {
			setTenantState(t, f.store, secondTenantID, state)
			if got, err := f.store.Tenant(f.b).Capacity(ctx); err != nil || !reflect.DeepEqual(got, wantB) {
				t.Errorf("%s tenant B's capacity = %s, %v; want %s", state, describeCapacity(got), err, describeCapacity(wantB))
			}
			if got, err := f.store.Tenant(f.a).Capacity(ctx); err != nil || !reflect.DeepEqual(got, TenantCapacity{}) {
				t.Errorf("tenant A's capacity while B is %s = %s, %v; want every setting inherited", state, describeCapacity(got), err)
			}
		}
		setTenantState(t, f.store, secondTenantID, TenantStateDeleted)
		if got, err := f.store.Tenant(f.b).Capacity(ctx); !errors.Is(err, ErrNoTenantScope) || !reflect.DeepEqual(got, TenantCapacity{}) {
			t.Errorf("deleted tenant B's capacity = %s, %v; want ErrNoTenantScope", describeCapacity(got), err)
		}
	}},
}

func ptrTo[T any](value T) *T { return &value }

// describeCapacity prints a capacity's values rather than its pointers.
func describeCapacity(capacity TenantCapacity) string { return capacity.auditDetail() }

// setCapacityColumns writes a tenant's capacity directly in SQL.
func setCapacityColumns(t *testing.T, s *Store, tenant string, slots, probes, naabuProbes, ceiling any) {
	t.Helper()
	if _, err := s.DB.Exec(`UPDATE tenants SET max_concurrent_scans=?,max_probe_count=?,max_naabu_probe_count=?,high_cost_ceiling=? WHERE id=?`, slots, probes, naabuProbes, ceiling, tenant); err != nil {
		t.Fatal(err)
	}
}

// tenantCapacityRow reads a tenant's capacity columns and revision.
func tenantCapacityRow(t *testing.T, s *Store, tenant string) (TenantCapacity, int64) {
	t.Helper()
	var revision int64
	capacity, err := scanTenantCapacity(s.DB.QueryRow(`SELECT revision,`+tenantCapacityColumns+` FROM tenants WHERE id=?`, tenant).Scan, &revision)
	if err != nil {
		t.Fatal(err)
	}
	return capacity, revision
}

func capacityAuditCount(t *testing.T, s *Store) int {
	t.Helper()
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE action=?`, auditActionTenantCapacityChanged).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

var testCapacityLimits = CapacityLimits{MaxConcurrentScans: 4, MaxProbeCount: 1_000, MaxNaabuProbeCount: 2_000}

// The setter accepts each setting from 1 up to the deployment's own value,
// and the ceiling up to MaxProbeCountLimit. Anything else is a validation
// error that names the setting and changes nothing.
func TestSetTenantCapacityValidatesBounds(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	insertTenantUser(t, s, platformRoot, nil, RolePlatformAdmin)
	platform := s.Platform()
	before, revision := tenantCapacityRow(t, s, DefaultTenantID)
	for _, invalid := range []struct {
		capacity TenantCapacity
		setting  string
	}{
		{TenantCapacity{MaxConcurrentScans: ptrTo(0)}, "max_concurrent_scans must be between 1 and 4"},
		{TenantCapacity{MaxConcurrentScans: ptrTo(5)}, "max_concurrent_scans must be between 1 and 4"},
		{TenantCapacity{MaxProbeCount: ptrTo[int64](0)}, "max_probe_count must be between 1 and 1000"},
		{TenantCapacity{MaxProbeCount: ptrTo[int64](1_001)}, "max_probe_count must be between 1 and 1000"},
		{TenantCapacity{MaxNaabuProbeCount: ptrTo[int64](-1)}, "max_naabu_probe_count must be between 1 and 2000"},
		{TenantCapacity{MaxNaabuProbeCount: ptrTo[int64](2_001)}, "max_naabu_probe_count must be between 1 and 2000"},
		{TenantCapacity{HighCostCeiling: ptrTo[int64](-1)}, "high_cost_ceiling must be between 0 and 100000000"},
		{TenantCapacity{HighCostCeiling: ptrTo(config.MaxProbeCountLimit + 1)}, "high_cost_ceiling must be between 0 and 100000000"},
		// A valid setting does not save an invalid one next to it.
		{TenantCapacity{MaxConcurrentScans: ptrTo(1), HighCostCeiling: ptrTo(config.MaxProbeCountLimit + 1)}, "high_cost_ceiling must be between 0 and 100000000"},
	} {
		err := platform.SetTenantCapacity(ctx, DefaultTenantID, invalid.capacity, testCapacityLimits, AuditEntry{})
		if !errors.Is(err, ErrValidation) || err.Error() != invalid.setting {
			t.Errorf("%s: error = %v, want the validation error %q", describeCapacity(invalid.capacity), err, invalid.setting)
		}
	}
	// A deployment without slots admits no slot cap at all.
	if err := platform.SetTenantCapacity(ctx, DefaultTenantID, TenantCapacity{MaxConcurrentScans: ptrTo(1)}, CapacityLimits{}, AuditEntry{}); !errors.Is(err, ErrValidation) {
		t.Errorf("slot cap without deployment limits: %v", err)
	}
	if after, afterRevision := tenantCapacityRow(t, s, DefaultTenantID); !reflect.DeepEqual(after, before) || afterRevision != revision || capacityAuditCount(t, s) != 0 {
		t.Fatalf("refused changes wrote %s, revision %d, %d audit records", describeCapacity(after), afterRevision, capacityAuditCount(t, s))
	}

	for _, valid := range []TenantCapacity{
		{MaxConcurrentScans: ptrTo(1), MaxProbeCount: ptrTo[int64](1), MaxNaabuProbeCount: ptrTo[int64](1), HighCostCeiling: ptrTo[int64](1)},
		{MaxConcurrentScans: ptrTo(4), MaxProbeCount: ptrTo[int64](1_000), MaxNaabuProbeCount: ptrTo[int64](2_000), HighCostCeiling: ptrTo(config.MaxProbeCountLimit)},
		{MaxProbeCount: ptrTo[int64](1_000), HighCostCeiling: ptrTo(HighCostNotGranted)},
		{},
	} {
		if err := platform.SetTenantCapacity(ctx, DefaultTenantID, valid, testCapacityLimits, platformAudit("")); err != nil {
			t.Fatalf("%s: %v", describeCapacity(valid), err)
		}
		if got, _ := tenantCapacityRow(t, s, DefaultTenantID); !reflect.DeepEqual(got, valid) {
			t.Fatalf("stored capacity = %s, want %s", describeCapacity(got), describeCapacity(valid))
		}
	}
}

// A capacity change updates only its tenant's row and records a platform
// action in that tenant's audit, with the actor the caller names.
func TestSetTenantCapacityRecordsAPlatformActionInTheTenantsAudit(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	const admin = "00000000-0000-0000-0000-00000000f001"
	insertTenantUser(t, f.store, admin, nil, RolePlatformAdmin)
	beforeA, revisionA := tenantCapacityRow(t, f.store, DefaultTenantID)
	_, revisionB := tenantCapacityRow(t, f.store, secondTenantID)
	capacity := TenantCapacity{MaxConcurrentScans: ptrTo(2), MaxProbeCount: ptrTo[int64](500), HighCostCeiling: ptrTo[int64](700)}
	// The caller cannot move the record to another tenant, give it another
	// actor kind, or rename the action.
	entry := AuditEntry{Action: "job.created", Detail: "ignored", TenantID: DefaultTenantID, ActorKind: AuditActorUnit, ActorUserID: admin, ActorUsername: "platform-admin", SourceIP: "192.0.2.10", RequestID: "request-1"}
	if err := f.store.Platform().SetTenantCapacity(ctx, secondTenantID, capacity, testCapacityLimits, entry); err != nil {
		t.Fatal(err)
	}
	if got, revision := tenantCapacityRow(t, f.store, secondTenantID); !reflect.DeepEqual(got, capacity) || revision != revisionB+1 {
		t.Fatalf("tenant B's capacity = %s at revision %d, want %s at %d", describeCapacity(got), revision, describeCapacity(capacity), revisionB+1)
	}
	if got, revision := tenantCapacityRow(t, f.store, DefaultTenantID); !reflect.DeepEqual(got, beforeA) || revision != revisionA {
		t.Fatalf("tenant A's capacity changed to %s at revision %d", describeCapacity(got), revision)
	}
	var tenant, actorKind, category, detail, actor, username, source, request string
	if err := f.store.DB.QueryRow(`SELECT COALESCE(tenant_id,''),actor_kind,category,detail,actor_user_id,actor_username,source_ip,request_id FROM security_audit WHERE action=?`, auditActionTenantCapacityChanged).Scan(&tenant, &actorKind, &category, &detail, &actor, &username, &source, &request); err != nil {
		t.Fatal(err)
	}
	if tenant != secondTenantID || actorKind != AuditActorPlatform || category != auditCategoryPlatform {
		t.Errorf("audit record tenant %q, actor kind %q, category %q; want tenant B, platform, platform", tenant, actorKind, category)
	}
	if want := "max_concurrent_scans=2 max_probe_count=500 max_naabu_probe_count=deployment high_cost_ceiling=700"; detail != want {
		t.Errorf("audit detail = %q, want %q", detail, want)
	}
	if actor != admin || username != "platform-admin" || source != "192.0.2.10" || request != "request-1" {
		t.Errorf("audit actor = %q %q %q %q", actor, username, source, request)
	}
	if count := capacityAuditCount(t, f.store); count != 1 {
		t.Fatalf("capacity audit records = %d, want 1", count)
	}
	byAdmin := AuditEntry{ActorUserID: admin, ActorUsername: "platform-admin"}

	// A paused tenant's capacity can change. A tenant that is gone or being
	// deleted is not found, and nothing is written for it.
	setTenantState(t, f.store, secondTenantID, TenantStateDisabled)
	if err := f.store.Platform().SetTenantCapacity(ctx, secondTenantID, TenantCapacity{}, testCapacityLimits, byAdmin); err != nil {
		t.Fatalf("paused tenant: %v", err)
	}
	if got, _ := tenantCapacityRow(t, f.store, secondTenantID); !reflect.DeepEqual(got, TenantCapacity{}) {
		t.Fatalf("paused tenant B's capacity = %s, want every setting inherited", describeCapacity(got))
	}
	for _, state := range []string{TenantStateDeleting, TenantStateDeleted} {
		setTenantState(t, f.store, secondTenantID, state)
		if err := f.store.Platform().SetTenantCapacity(ctx, secondTenantID, capacity, testCapacityLimits, byAdmin); !errors.Is(err, ErrNoTenantScope) || !errors.Is(err, ErrNotFound) {
			t.Errorf("%s tenant: error = %v, want ErrNoTenantScope", state, err)
		}
	}
	if err := f.store.Platform().SetTenantCapacity(ctx, "00000000-0000-0000-0000-00000000dead", capacity, testCapacityLimits, byAdmin); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown tenant: error = %v, want ErrNotFound", err)
	}
	if got, _ := tenantCapacityRow(t, f.store, secondTenantID); !reflect.DeepEqual(got, TenantCapacity{}) {
		t.Fatalf("a refused change wrote %s", describeCapacity(got))
	}
	if count := capacityAuditCount(t, f.store); count != 2 {
		t.Fatalf("capacity audit records = %d, want 2", count)
	}

	// A write that cannot be recorded in the audit is not saved either.
	setTenantState(t, f.store, secondTenantID, TenantStateActive)
	if _, err := f.store.DB.Exec(`CREATE TRIGGER refuse_capacity_audit BEFORE INSERT ON security_audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Platform().SetTenantCapacity(ctx, secondTenantID, capacity, testCapacityLimits, byAdmin); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("change without an audit record: error = %v, want ErrAuditUnavailable", err)
	}
	if got, _ := tenantCapacityRow(t, f.store, secondTenantID); !reflect.DeepEqual(got, TenantCapacity{}) {
		t.Fatalf("an unaudited change was saved: %s", describeCapacity(got))
	}
	_ = f.store.Close()
	if err := f.store.Platform().SetTenantCapacity(ctx, secondTenantID, capacity, testCapacityLimits, byAdmin); err == nil {
		t.Fatal("a closed store saved a capacity")
	}
}

// A capacity change is written only for an enabled platform administrator,
// which the write checks in its own transaction, as the other platform
// writes do: a platform administrator that was disabled after it was
// authorized, a unit's administrator, an unknown account, and a change that
// names no actor are refused with ErrAccountNotPermitted, and no capacity,
// revision, or audit record is written. An enabled platform administrator's
// change is saved.
func TestSetTenantCapacityRequiresAnEnabledPlatformAdministrator(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	insertTenantUser(t, f.store, platformOther, nil, RolePlatformAdmin)
	if _, err := f.store.DB.Exec(`UPDATE users SET enabled=0 WHERE id=?`, platformOther); err != nil {
		t.Fatal(err)
	}
	capacity := TenantCapacity{MaxConcurrentScans: ptrTo(2), HighCostCeiling: ptrTo[int64](700)}
	before, revision := tenantCapacityRow(t, f.store, secondTenantID)
	for _, refused := range []struct {
		name  string
		audit AuditEntry
	}{
		{"a disabled platform administrator", AuditEntry{ActorUserID: platformOther, ActorUsername: platformOther}},
		{"a unit's administrator", accountAudit("")},
		{"an unknown account", AuditEntry{ActorUserID: accountUnknown, ActorUsername: "unknown"}},
		{"no actor", AuditEntry{}},
	} {
		if err := f.store.Platform().SetTenantCapacity(ctx, secondTenantID, capacity, testCapacityLimits, refused.audit); !errors.Is(err, ErrAccountNotPermitted) {
			t.Errorf("change by %s = %v, want ErrAccountNotPermitted", refused.name, err)
		}
	}
	if got, gotRevision := tenantCapacityRow(t, f.store, secondTenantID); !reflect.DeepEqual(got, before) || gotRevision != revision {
		t.Fatalf("refused changes wrote %s at revision %d, want %s at %d", describeCapacity(got), gotRevision, describeCapacity(before), revision)
	}
	if count := capacityAuditCount(t, f.store); count != 0 {
		t.Fatalf("refused changes wrote %d audit records", count)
	}

	if err := f.store.Platform().SetTenantCapacity(ctx, secondTenantID, capacity, testCapacityLimits, platformAudit("")); err != nil {
		t.Fatalf("change by an enabled platform administrator: %v", err)
	}
	if got, gotRevision := tenantCapacityRow(t, f.store, secondTenantID); !reflect.DeepEqual(got, capacity) || gotRevision != revision+1 {
		t.Fatalf("capacity = %s at revision %d, want %s at %d", describeCapacity(got), gotRevision, describeCapacity(capacity), revision+1)
	}
	if count := capacityAuditCount(t, f.store); count != 1 {
		t.Fatalf("capacity audit records = %d, want 1", count)
	}
}

// The scheduler's view holds the capacity of the active tenants only.
func TestTenantCapacitiesListsTheActiveTenants(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	setCapacityColumns(t, f.store, secondTenantID, 1, nil, 20, nil)
	want := map[string]TenantCapacity{
		DefaultTenantID: {},
		secondTenantID:  {MaxConcurrentScans: ptrTo(1), MaxNaabuProbeCount: ptrTo[int64](20)},
	}
	if got, err := f.store.System().TenantCapacities(ctx); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("capacities = %v, %v; want %v", got, err, want)
	}
	for _, state := range []string{TenantStateDisabled, TenantStateDeleting, TenantStateDeleted} {
		setTenantState(t, f.store, secondTenantID, state)
		if got, err := f.store.System().TenantCapacities(ctx); err != nil || !reflect.DeepEqual(got, map[string]TenantCapacity{DefaultTenantID: {}}) {
			t.Errorf("%s tenant B: capacities = %v, %v; want the default tenant's only", state, got, err)
		}
	}
	_ = f.store.Close()
	if _, err := f.store.System().TenantCapacities(ctx); err == nil {
		t.Fatal("capacities read a closed store")
	}
}

// A new tenant has no high-cost grant, which no deployment budget turns
// into a number, so high-cost work raises neither budget until a platform
// administrator grants a ceiling.
func TestInitialTenantCapacityKeepsHighCostOff(t *testing.T) {
	capacity := InitialTenantCapacity()
	want := TenantCapacity{HighCostCeiling: ptrTo(HighCostNotGranted)}
	if !reflect.DeepEqual(capacity, want) {
		t.Errorf("initial capacity = %s, want %s", describeCapacity(capacity), describeCapacity(want))
	}
	if got := describeCapacity(capacity); got != "max_concurrent_scans=deployment max_probe_count=deployment max_naabu_probe_count=deployment high_cost_ceiling=not_granted" {
		t.Errorf("initial capacity audit detail = %q", got)
	}
	for _, limits := range []CapacityLimits{
		{MaxConcurrentScans: 2, MaxProbeCount: 5, MaxNaabuProbeCount: 20},
		{MaxConcurrentScans: 2, MaxProbeCount: 20, MaxNaabuProbeCount: 5},
	} {
		if err := capacity.Validate(limits); err != nil {
			t.Errorf("%+v: the initial capacity is invalid: %v", limits, err)
		}
	}
}

// A tenant without a grant is stored without a ceiling, a granted ceiling
// and the deployment's are stored as before, and each reads back as it was
// set. The row cannot hold a ceiling beside high_cost_granted=0, so no
// number stays behind that a later release could read as a grant.
func TestHighCostGrantIsStoredApartFromTheCeiling(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	insertTenantUser(t, s, platformRoot, nil, RolePlatformAdmin)
	stored := func() (any, int) {
		t.Helper()
		var ceiling any
		var granted int
		if err := s.DB.QueryRow(`SELECT high_cost_ceiling,high_cost_granted FROM tenants WHERE id=?`, DefaultTenantID).Scan(&ceiling, &granted); err != nil {
			t.Fatal(err)
		}
		return ceiling, granted
	}
	for _, check := range []struct {
		ceiling *int64
		column  any
		granted int
	}{
		{ptrTo(HighCostNotGranted), nil, 0},
		{ptrTo[int64](1), int64(1), 1},
		{nil, nil, 1},
		{ptrTo(config.MaxProbeCountLimit), config.MaxProbeCountLimit, 1},
		{ptrTo(HighCostNotGranted), nil, 0},
	} {
		capacity := TenantCapacity{HighCostCeiling: check.ceiling}
		if err := s.Platform().SetTenantCapacity(ctx, DefaultTenantID, capacity, testCapacityLimits, platformAudit("")); err != nil {
			t.Fatalf("%s: %v", describeCapacity(capacity), err)
		}
		if column, granted := stored(); column != check.column || granted != check.granted {
			t.Fatalf("%s is stored as high_cost_ceiling=%v high_cost_granted=%d, want %v and %d", describeCapacity(capacity), column, granted, check.column, check.granted)
		}
		if got, _ := tenantCapacityRow(t, s, DefaultTenantID); !reflect.DeepEqual(got, capacity) {
			t.Fatalf("%s reads back as %s", describeCapacity(capacity), describeCapacity(got))
		}
	}
	if _, err := s.DB.Exec(`UPDATE tenants SET high_cost_ceiling=5000 WHERE id=?`, DefaultTenantID); err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
		t.Fatalf("a ceiling beside high_cost_granted=0: %v, want a check constraint failure", err)
	}
	if _, err := s.DB.Exec(`UPDATE tenants SET high_cost_granted=2 WHERE id=?`, DefaultTenantID); err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
		t.Fatalf("high_cost_granted=2: %v, want a check constraint failure", err)
	}
}
