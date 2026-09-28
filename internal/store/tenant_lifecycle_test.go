package store

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// platformAdminID is a platform administrator that the lifecycle tests add.
const platformAdminID = "00000000-0000-0000-0000-00000000f0a1"

// lifecycleAudit is how a lifecycle record of the platform audit looks to a
// test.
type lifecycleAudit struct {
	tenant, kind, category, actor, detail string
}

// lastPlatformAudit returns the newest audit record with the action.
func lastPlatformAudit(t *testing.T, s *Store, action string) lifecycleAudit {
	t.Helper()
	var record lifecycleAudit
	if err := s.DB.QueryRow(`SELECT COALESCE(tenant_id,'<null>'),actor_kind,category,actor_user_id,detail FROM security_audit WHERE action=? ORDER BY id DESC LIMIT 1`, action).Scan(&record.tenant, &record.kind, &record.category, &record.actor, &record.detail); err != nil {
		t.Fatalf("audit record %s: %v", action, err)
	}
	return record
}

// tenantCycleStatuses returns the status of each scan cycle of the tenant's
// jobs, by cycle ID.
func tenantCycleStatuses(t *testing.T, s *Store, tenant string) map[string]string {
	t.Helper()
	rows, err := s.DB.Query(`SELECT c.id,c.status FROM scan_cycles AS c JOIN jobs AS j ON j.id=c.job_id WHERE j.tenant_id=?`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	statuses := map[string]string{}
	for rows.Next() {
		var id, status string
		if err := rows.Scan(&id, &status); err != nil {
			t.Fatal(err)
		}
		statuses[id] = status
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return statuses
}

// tenantNames returns the name of each tenant in the order of the list.
func tenantNames(records []TenantRecord) []string {
	names := make([]string, 0, len(records))
	for _, record := range records {
		names = append(names, record.Name)
	}
	return names
}

// Creating a tenant validates its name and slug, keeps both unique among
// the tenants that are not deleted, gives it the initial capacity, and
// records the creation in the platform audit. Renaming follows the same
// rules, and the list shows each tenant with counts of its accounts,
// administrators and jobs.
func TestCreateRenameAndListTenants(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	platform := f.store.Platform()
	insertTenantUser(t, f.store, platformAdminID, nil, RolePlatformAdmin)

	third, err := platform.CreateTenant(ctx, "  Third  ", "third", testCapacityLimits, AuditEntry{ActorKind: AuditActorHost})
	if err != nil {
		t.Fatal(err)
	}
	if third.ID == "" || third.Name != "Third" || third.Slug != "third" || third.State != TenantStateActive || third.IsDefault || third.Revision != 1 || third.StateChangedBy != AuditActorHost || third.CreatedAt.IsZero() {
		t.Fatalf("created tenant = %+v", third)
	}
	// The new tenant inherits the deployment's slots and budgets, and its
	// high-cost ceiling is the lower budget, so high-cost work stays off.
	scope, err := f.store.TenantScopeByID(ctx, third.ID)
	if err != nil {
		t.Fatal(err)
	}
	capacity, err := f.store.Tenant(scope).Capacity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(capacity, InitialTenantCapacity(testCapacityLimits)) || capacity.HighCostCeiling == nil || *capacity.HighCostCeiling != testCapacityLimits.MaxProbeCount {
		t.Fatalf("a new tenant's capacity = %+v, want %+v", capacity, InitialTenantCapacity(testCapacityLimits))
	}
	if got := lastPlatformAudit(t, f.store, "tenant.created"); got.tenant != "<null>" || got.kind != AuditActorHost || got.category != auditCategoryPlatform || !strings.Contains(got.detail, third.ID) {
		t.Fatalf("creation audit = %+v", got)
	}
	fourth, err := platform.CreateTenant(ctx, "Fourth", "fourth", testCapacityLimits, AuditEntry{ActorUserID: platformAdminID, ActorUsername: "root"})
	if err != nil {
		t.Fatal(err)
	}
	if got := lastPlatformAudit(t, f.store, "tenant.created"); got.tenant != "<null>" || got.kind != AuditActorPlatform || got.actor != platformAdminID || fourth.StateChangedBy != platformAdminID {
		t.Fatalf("creation by a platform administrator: audit %+v, tenant %+v", got, fourth)
	}

	// Only the platform acts on tenants. An account of a tenant, an unknown
	// account, a platform kind without an account, or a tenant actor kind is
	// refused, and nothing is created.
	for label, audit := range map[string]AuditEntry{
		"unit account":             {ActorUserID: accountAdminA},
		"unit account as platform": {ActorUserID: accountAdminA, ActorKind: AuditActorPlatform},
		"unknown account":          {ActorUserID: accountUnknown},
		"platform kind alone":      {ActorKind: AuditActorPlatform},
		"unit kind":                {ActorKind: AuditActorUnit},
		"host with an account":     {ActorUserID: platformAdminID, ActorKind: AuditActorHost},
	} {
		if _, err := platform.CreateTenant(ctx, "Refused", "refused", testCapacityLimits, audit); !errors.Is(err, ErrAccountNotPermitted) {
			t.Errorf("%s: creation = %v, want %v", label, err, ErrAccountNotPermitted)
		}
	}

	for _, check := range []struct{ label, name, slug string }{
		{"empty name", "   ", "fifth"},
		{"long name", strings.Repeat("n", tenantNameMaxLength+1), "fifth"},
		{"control character", "Fi\tfth", "fifth"},
		{"invalid UTF-8", "Fi\xfffth", "fifth"},
		{"short slug", "Fifth", "f"},
		{"long slug", "Fifth", strings.Repeat("f", 41)},
		{"upper-case slug", "Fifth", "Fifth"},
		{"slug with a space", "Fifth", "fi fth"},
		{"slug with a dot", "Fifth", "fi.fth"},
		{"reserved slug", "Fifth", "api"},
		{"name in use", "second", "fifth"},
		{"slug in use", "Fifth", "second"},
		{"default name", "DEFAULT", "fifth"},
		{"default slug", "Fifth", "default"},
	} {
		if _, err := platform.CreateTenant(ctx, check.name, check.slug, testCapacityLimits, AuditEntry{}); !errors.Is(err, ErrValidation) {
			t.Errorf("%s: creation = %v, want a validation error", check.label, err)
		}
	}
	if _, err := platform.CreateTenant(ctx, "SECOND", "fifth", testCapacityLimits, AuditEntry{}); !errors.Is(err, ErrTenantNameInUse) {
		t.Errorf("a name in use in another case = %v, want %v", err, ErrTenantNameInUse)
	}
	if _, err := platform.CreateTenant(ctx, "Fifth", "second", testCapacityLimits, AuditEntry{}); !errors.Is(err, ErrTenantSlugInUse) {
		t.Errorf("a slug in use = %v, want %v", err, ErrTenantSlugInUse)
	}

	// The list: the default tenant first, then by name, with counts.
	records, err := platform.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := tenantNames(records), []string{"Default", "Fourth", "Second", "Third"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("tenants = %v, want %v", got, want)
	}
	counts := map[string][3]int{}
	for _, record := range records {
		counts[record.ID] = [3]int{record.Accounts, record.Administrators, record.Jobs}
	}
	var wantA [3]int
	if err := f.store.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM users WHERE tenant_id=?1),(SELECT COUNT(*) FROM users WHERE tenant_id=?1 AND role='administrator' AND enabled=1),(SELECT COUNT(*) FROM jobs WHERE tenant_id=?1 AND archived=0)`, DefaultTenantID).Scan(&wantA[0], &wantA[1], &wantA[2]); err != nil {
		t.Fatal(err)
	}
	// Tenant B has an administrator and an operator, and an active and an
	// archived job.
	if counts[DefaultTenantID] != wantA || counts[secondTenantID] != [3]int{2, 1, 1} || counts[third.ID] != [3]int{} {
		t.Fatalf("counts = %v, want A %v and B [2 1 1]", counts, wantA)
	}
	if got, err := platform.GetTenant(ctx, secondTenantID); err != nil || got.Name != "Second" || got.Accounts != 2 || got.Administrators != 1 || got.Jobs != 1 {
		t.Fatalf("tenant B = %+v, %v", got, err)
	}
	if _, err := platform.GetTenant(ctx, accountUnknown); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown tenant = %v", err)
	}

	// Renaming checks the revision, the rules, and the other tenants' names
	// and slugs. A tenant may change the case of its own name.
	if _, err := platform.RenameTenant(ctx, third.ID, third.Revision+1, "Gamma", "gamma", AuditEntry{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("rename with a stale revision = %v", err)
	}
	for label, check := range map[string][2]string{"name in use": {"Second", "gamma"}, "slug in use": {"Gamma", "fourth"}, "invalid slug": {"Gamma", "-"}, "invalid name": {"", "gamma"}} {
		if _, err := platform.RenameTenant(ctx, third.ID, third.Revision, check[0], check[1], AuditEntry{}); !errors.Is(err, ErrValidation) {
			t.Errorf("rename, %s = %v", label, err)
		}
	}
	renamed, err := platform.RenameTenant(ctx, third.ID, third.Revision, "THIRD", "gamma", AuditEntry{ActorUserID: platformAdminID})
	if err != nil {
		t.Fatal(err)
	}
	if renamed.Name != "THIRD" || renamed.Slug != "gamma" || renamed.Revision != third.Revision+1 {
		t.Fatalf("renamed tenant = %+v", renamed)
	}
	if got := lastPlatformAudit(t, f.store, "tenant.renamed"); got.tenant != "<null>" || got.kind != AuditActorPlatform || !strings.Contains(got.detail, `"Third" (third)`) || !strings.Contains(got.detail, `"THIRD" (gamma)`) {
		t.Fatalf("rename audit = %+v", got)
	}
	// Renaming to the current name and slug changes nothing.
	var audits int
	countAudits := func() int {
		t.Helper()
		var n int
		if err := f.store.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE action='tenant.renamed'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	audits = countAudits()
	if same, err := platform.RenameTenant(ctx, third.ID, renamed.Revision, "THIRD", "gamma", AuditEntry{}); err != nil || same.Revision != renamed.Revision || countAudits() != audits {
		t.Fatalf("an unchanged rename = %+v, %v", same, err)
	}
	// The old slug is free again, and so is the name and slug of a deleted
	// tenant.
	if _, err := platform.CreateTenant(ctx, "Delta", "third", testCapacityLimits, AuditEntry{}); err != nil {
		t.Fatalf("reuse a released slug: %v", err)
	}
	setTenantState(t, f.store, fourth.ID, TenantStateDeleted)
	if _, err := platform.CreateTenant(ctx, "Fourth", "fourth", testCapacityLimits, AuditEntry{}); err != nil {
		t.Fatalf("reuse the name and slug of a deleted tenant: %v", err)
	}
	if _, err := platform.RenameTenant(ctx, fourth.ID, fourth.Revision, "Fifth", "fifth", AuditEntry{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rename a deleted tenant = %v, want %v", err, ErrNotFound)
	}
	if tombstone, err := platform.GetTenant(ctx, fourth.ID); err != nil || tombstone.State != TenantStateDeleted {
		t.Fatalf("a deleted tenant's tombstone = %+v, %v", tombstone, err)
	}
	setTenantState(t, f.store, secondTenantID, TenantStateDeleting)
	if _, err := platform.RenameTenant(ctx, secondTenantID, 1, "Beta", "beta", AuditEntry{}); !errors.Is(err, ErrTenantStateChange) {
		t.Fatalf("rename a tenant being deleted = %v, want %v", err, ErrTenantStateChange)
	}
}

// A new tenant starts with update alerts off: its update routing is
// configured and selects nothing, stored exactly as an administrator's
// cleared selection is. The routing of the tenants that already exist is
// left alone: the default tenant's routing that was never configured still
// sends update alerts to every enabled destination, as before business
// units.
func TestCreateTenantStartsWithUpdateAlertsOff(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	storedRouting := func(id string) string {
		t.Helper()
		var routing string
		if err := f.store.DB.QueryRowContext(ctx, `SELECT update_destinations_json FROM tenants WHERE id=?`, id).Scan(&routing); err != nil {
			t.Fatal(err)
		}
		return routing
	}
	if _, err := f.store.DB.ExecContext(ctx, `UPDATE tenants SET update_destinations_json='' WHERE id=?`, DefaultTenantID); err != nil {
		t.Fatal(err)
	}
	before := map[string]string{DefaultTenantID: storedRouting(DefaultTenantID), secondTenantID: storedRouting(secondTenantID)}
	third, err := f.store.Platform().CreateTenant(ctx, "Third", "third", testCapacityLimits, AuditEntry{ActorKind: AuditActorHost})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := f.store.TenantScopeByID(ctx, third.ID)
	if err != nil {
		t.Fatal(err)
	}
	ts := f.store.Tenant(scope)
	routing, err := ts.ApplicationUpdateRouting(ctx)
	if err != nil || !reflect.DeepEqual(routing, ApplicationUpdateRouting{Configured: true, Destinations: []string{}}) {
		t.Fatalf("a new tenant's update routing = %#v, %v; want configured and empty", routing, err)
	}
	created := storedRouting(third.ID)
	if err := ts.SetApplicationUpdateDestinations(ctx, nil, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if cleared := storedRouting(third.ID); cleared != created {
		t.Fatalf("a new tenant's stored update routing = %q, want %q as a cleared selection is stored", created, cleared)
	}
	for id, routing := range before {
		if after := storedRouting(id); after != routing {
			t.Errorf("tenant %s's stored update routing changed from %q to %q when another tenant was created", id, routing, after)
		}
	}
	if routing, err := defaultTenant(f.store).ApplicationUpdateRouting(ctx); err != nil || routing.Configured || routing.Destinations != nil {
		t.Fatalf("the default tenant's update routing = %#v, %v; want it never configured", routing, err)
	}
}

// The platform counts each tenant's stored scans: every scan of the tenant,
// whatever its status, those of archived jobs and, for the default tenant,
// those without a job ID included, and never another tenant's, although the
// two tenants' jobs and scans look alike. A new tenant has none. The count
// reads the tenant's entries of the scans_tenant_id_time index.
func TestTenantRecordsCountStoredScans(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	platform := f.store.Platform()
	storedScans := func() map[string]int64 {
		t.Helper()
		records, err := platform.ListTenants(ctx)
		if err != nil {
			t.Fatal(err)
		}
		counts := map[string]int64{}
		for _, record := range records {
			counts[record.ID] = record.StoredScans
			single, err := platform.GetTenant(ctx, record.ID)
			if err != nil || single.StoredScans != record.StoredScans {
				t.Fatalf("tenant %s alone has %d stored scans, %v; the list says %d", record.ID, single.StoredScans, err, record.StoredScans)
			}
		}
		return counts
	}
	// Tenant A holds the scan of its "edge" job and a legacy scan without a
	// job ID; tenant B only the scan of its "edge" job.
	if got, want := storedScans(), map[string]int64{DefaultTenantID: 2, secondTenantID: 1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("stored scans = %v, want %v", got, want)
	}

	// Tenant B's archived job keeps a failed scan and a successful one.
	finished := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	failed := fixtureScan("scan-archived-b-failed", f.archivedB, "edge-archived", finished, nil)
	failed.Status, failed.Error = "failed", "nmap exited"
	for _, scan := range []model.Scan{failed, fixtureScan("scan-archived-b", f.archivedB, "edge-archived", finished.Add(time.Minute), fixtureHosts(0, 1))} {
		if err := f.store.System().SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	if archived, err := f.store.Tenant(f.b).GetJob(ctx, f.archivedB); err != nil || !archived.Archived {
		t.Fatalf("tenant B's job %s = %+v, %v; want it archived", f.archivedB, archived, err)
	}
	third, err := platform.CreateTenant(ctx, "Third", "third", testCapacityLimits, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if third.StoredScans != 0 {
		t.Fatalf("a new tenant has %d stored scans", third.StoredScans)
	}
	if got, want := storedScans(), map[string]int64{DefaultTenantID: 2, secondTenantID: 3, third.ID: 0}; !reflect.DeepEqual(got, want) {
		t.Fatalf("stored scans with tenant B's archived job's scans = %v, want %v", got, want)
	}

	rows, err := f.store.DB.QueryContext(ctx, `EXPLAIN QUERY PLAN SELECT `+tenantRecordColumns+` FROM tenants AS t WHERE t.state<>?`, TenantStateDeleted)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(plan, "SEARCH s USING COVERING INDEX scans_tenant_id_time (tenant_id=?)") {
		t.Fatalf("the tenant list's plan = %q, want the stored scans counted from scans_tenant_id_time", plan)
	}
}

// Every lifecycle method reports a database that fails, and changes
// nothing.
func TestTenantLifecycleReportsDatabaseErrors(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	_ = s.Close()
	platform := s.Platform()
	for name, call := range map[string]func() error{
		"list": func() error { _, err := platform.ListTenants(ctx); return err },
		"get":  func() error { _, err := platform.GetTenant(ctx, DefaultTenantID); return err },
		"create": func() error {
			_, err := platform.CreateTenant(ctx, "Third", "third", testCapacityLimits, AuditEntry{})
			return err
		},
		"rename": func() error {
			_, err := platform.RenameTenant(ctx, DefaultTenantID, 1, "Default", "home", AuditEntry{})
			return err
		},
		"disable": func() error { _, err := platform.DisableTenant(ctx, DefaultTenantID, 1, AuditEntry{}); return err },
		"enable":  func() error { _, err := platform.EnableTenant(ctx, DefaultTenantID, 1, AuditEntry{}); return err },
		"delete": func() error {
			_, err := platform.RequestTenantDeletion(ctx, DefaultTenantID, "Default", AuditEntry{})
			return err
		},
		"purge": func() error {
			_, err := s.System().purgeTenant(ctx, secondTenantID, tenantPurgeOptions{batchSize: 1})
			return err
		},
	} {
		if err := call(); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("%s on a closed database = %v, want the database error", name, err)
		}
	}
}

// A write that races the name check hits the unique indexes, whose errors
// map to the same errors as the check.
func TestTenantUniqueError(t *testing.T) {
	for message, want := range map[string]error{
		"constraint failed: UNIQUE constraint failed: tenants.name (2067)": ErrTenantNameInUse,
		"constraint failed: UNIQUE constraint failed: tenants.slug (2067)": ErrTenantSlugInUse,
	} {
		if err := tenantUniqueError(errors.New(message)); !errors.Is(err, want) || !errors.Is(err, ErrValidation) {
			t.Errorf("%s: %v", message, err)
		}
	}
	other := errors.New("disk I/O error")
	if err := tenantUniqueError(other); err != other {
		t.Errorf("another error = %v", err)
	}
}

// Disabling a tenant ends its sessions and revokes its invitations in the
// same transaction and refuses its sign-in, leaving tenant A's accounts as
// they are. Enabling it again restarts the silence reference of its jobs,
// so the pause does not count as silence.
func TestDisableAndEnableTenant(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	platform := f.store.Platform()
	insertTenantUser(t, f.store, platformAdminID, nil, RolePlatformAdmin)
	before := tenantAccountDigest(t, f.store, f.a)
	b, err := platform.GetTenant(ctx, secondTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platform.DisableTenant(ctx, secondTenantID, b.Revision+1, AuditEntry{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("disable with a stale revision = %v", err)
	}
	if _, err := platform.EnableTenant(ctx, secondTenantID, b.Revision, AuditEntry{}); !errors.Is(err, ErrTenantStateChange) {
		t.Fatalf("enable an active tenant = %v", err)
	}
	if _, err := platform.DisableTenant(ctx, accountUnknown, 1, AuditEntry{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disable an unknown tenant = %v", err)
	}
	disabled, err := platform.DisableTenant(ctx, secondTenantID, b.Revision, AuditEntry{ActorKind: AuditActorHost})
	if err != nil {
		t.Fatal(err)
	}
	if disabled.State != TenantStateDisabled || disabled.Revision != b.Revision+1 || disabled.StateChangedBy != AuditActorHost || disabled.StateChangedAt.IsZero() {
		t.Fatalf("disabled tenant = %+v", disabled)
	}
	var sessions, invites int
	if err := f.store.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM sessions WHERE user_id IN (?1,?2)),(SELECT COUNT(*) FROM user_invites WHERE user_id IN (?1,?2) AND used_at IS NULL)`, accountAdminB, accountOperatorB).Scan(&sessions, &invites); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || invites != 0 {
		t.Fatalf("tenant B kept %d sessions and %d outstanding invitations", sessions, invites)
	}
	if after := tenantAccountDigest(t, f.store, f.a); after != before {
		t.Fatal("disabling tenant B changed tenant A's accounts, sessions, invitations or audit")
	}
	if got := lastPlatformAudit(t, f.store, "tenant.disabled"); got.tenant != "<null>" || got.kind != AuditActorHost || !strings.Contains(got.detail, "2 sessions ended, 1 invitations revoked") {
		t.Fatalf("disable audit = %+v", got)
	}
	now := time.Now().UTC()
	if err := f.store.CreateSessionForUserWithAuditEntry(ctx, accountAdminB, "session-refused", "csrf", now, now.Add(time.Hour), AuditEntry{Action: "user.login", ActorUserID: accountAdminB}); !errors.Is(err, ErrTenantNotActive) {
		t.Fatalf("sign-in to a disabled tenant = %v, want %v", err, ErrTenantNotActive)
	}
	if _, err := platform.DisableTenant(ctx, secondTenantID, disabled.Revision, AuditEntry{}); !errors.Is(err, ErrTenantStateChange) {
		t.Fatalf("disable a disabled tenant = %v", err)
	}

	// Both tenants' jobs were last eligible, and last alerted, long ago.
	old := now.Add(-30 * 24 * time.Hour).Format(time.RFC3339Nano)
	if _, err := f.store.DB.Exec(`UPDATE job_silence_state SET eligible_at=?,next_alert_at=?,backoff_level=3`, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`UPDATE jobs SET created_at=?`, old); err != nil {
		t.Fatal(err)
	}
	silenceDue := func(jobID string) bool {
		t.Helper()
		due, err := f.store.System().JobSilenceDue(ctx, jobID, now.Add(-30*24*time.Hour), time.Now(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return due
	}
	if silenceDue(f.jobB) || !silenceDue(f.jobA) {
		t.Fatal("a paused tenant's job is due for a silence alert, or the active tenant's is not")
	}
	if _, err := platform.EnableTenant(ctx, secondTenantID, disabled.Revision+1, AuditEntry{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("enable with a stale revision = %v", err)
	}
	enabled, err := platform.EnableTenant(ctx, secondTenantID, disabled.Revision, AuditEntry{ActorUserID: platformAdminID, ActorKind: AuditActorPlatform})
	if err != nil {
		t.Fatal(err)
	}
	if enabled.State != TenantStateActive || enabled.Revision != disabled.Revision+1 {
		t.Fatalf("enabled tenant = %+v", enabled)
	}
	if got := lastPlatformAudit(t, f.store, "tenant.enabled"); got.tenant != "<null>" || got.kind != AuditActorPlatform {
		t.Fatalf("enable audit = %+v", got)
	}
	if silenceDue(f.jobB) || !silenceDue(f.jobA) {
		t.Fatal("tenant B's job is due for a silence alert right after the tenant was enabled")
	}
	var reset, untouched int
	if err := f.store.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM job_silence_state WHERE job_id=?1 AND eligible_at>?4 AND next_alert_at='' AND backoff_level=0),(SELECT COUNT(*) FROM job_silence_state WHERE job_id IN (?2,?3) AND eligible_at=?4 AND backoff_level=3)`, f.jobB, f.archivedB, f.jobA, old).Scan(&reset, &untouched); err != nil {
		t.Fatal(err)
	}
	// B's active job restarts; B's archived job and A's job keep their state.
	if reset != 1 || untouched != 2 {
		t.Fatalf("silence state after enabling: %d reset, %d untouched; want 1 and 2", reset, untouched)
	}
	if err := f.store.CreateSessionForUserWithAuditEntry(ctx, accountAdminB, "session-allowed", "csrf", now, now.Add(time.Hour), AuditEntry{Action: "user.login", ActorUserID: accountAdminB}); err != nil {
		t.Fatalf("sign-in after the tenant was enabled: %v", err)
	}
}

// Only a disabled tenant that is not the default one can be deleted, after
// typing its exact name. The request archives and pauses the tenant's jobs
// and discards its scan cycles that were not promoted, and leaves tenant A
// alone.
func TestRequestTenantDeletion(t *testing.T) {
	ctx := context.Background()
	f := newCycleTenantFixture(t)
	platform := f.store.Platform()
	insertTenantUser(t, f.store, platformAdminID, nil, RolePlatformAdmin)
	jobsA := tenantRows(t, f.store, "jobs", "tenant_id=?1", f.a)
	cyclesA := tenantRows(t, f.store, "scan_cycles", "job_id IN (SELECT id FROM jobs WHERE tenant_id=?1)", f.a)

	a, err := platform.GetTenant(ctx, DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platform.RequestTenantDeletion(ctx, DefaultTenantID, a.Name, AuditEntry{}); !errors.Is(err, ErrDefaultTenantDeletion) {
		t.Fatalf("delete the default tenant = %v", err)
	}
	if _, err := platform.DisableTenant(ctx, DefaultTenantID, a.Revision, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := platform.RequestTenantDeletion(ctx, DefaultTenantID, a.Name, AuditEntry{}); !errors.Is(err, ErrDefaultTenantDeletion) {
		t.Fatalf("delete the disabled default tenant = %v", err)
	}
	if _, err := platform.EnableTenant(ctx, DefaultTenantID, a.Revision+1, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := platform.RequestTenantDeletion(ctx, secondTenantID, "Second", AuditEntry{}); !errors.Is(err, ErrTenantStateChange) {
		t.Fatalf("delete an active tenant = %v", err)
	}
	if _, err := platform.RequestTenantDeletion(ctx, accountUnknown, "Second", AuditEntry{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete an unknown tenant = %v", err)
	}
	b, err := platform.GetTenant(ctx, secondTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platform.DisableTenant(ctx, secondTenantID, b.Revision, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	for _, typed := range []string{"second", "Second ", "", "Default"} {
		if _, err := platform.RequestTenantDeletion(ctx, secondTenantID, typed, AuditEntry{}); !errors.Is(err, ErrTenantNameMismatch) || !errors.Is(err, ErrValidation) {
			t.Errorf("delete with the typed name %q = %v", typed, err)
		}
	}
	deleting, err := platform.RequestTenantDeletion(ctx, secondTenantID, "Second", AuditEntry{ActorUserID: platformAdminID})
	if err != nil {
		t.Fatal(err)
	}
	if deleting.State != TenantStateDeleting || deleting.Jobs != 0 || deleting.PurgePhase != "" || deleting.PurgeRows != 0 {
		t.Fatalf("tenant being deleted = %+v", deleting)
	}
	var liveJobs int
	if err := f.store.DB.QueryRow(`SELECT COUNT(*) FROM jobs WHERE tenant_id=? AND (archived=0 OR enabled=1)`, secondTenantID).Scan(&liveJobs); err != nil || liveJobs != 0 {
		t.Fatalf("tenant B has %d jobs that are not archived and paused: %v", liveJobs, err)
	}
	cycles := cyclesOf(f, f.b)
	statuses := tenantCycleStatuses(t, f.store, secondTenantID)
	want := map[string]string{cycles.promoted: "completed", cycles.expired: "expired", cycles.active: "discarded", cycles.recoverable: "discarded"}
	if !reflect.DeepEqual(statuses, want) {
		t.Fatalf("tenant B's cycles = %v, want %v", statuses, want)
	}
	if got := lastPlatformAudit(t, f.store, "tenant.deletion_requested"); got.tenant != "<null>" || got.kind != AuditActorPlatform || !strings.Contains(got.detail, "1 jobs archived, 2 scan cycles discarded") {
		t.Fatalf("deletion audit = %+v", got)
	}
	if tenantRows(t, f.store, "jobs", "tenant_id=?1", f.a) != jobsA || tenantRows(t, f.store, "scan_cycles", "job_id IN (SELECT id FROM jobs WHERE tenant_id=?1)", f.a) != cyclesA {
		t.Fatal("deleting tenant B changed tenant A's jobs or scan cycles")
	}
	// A tenant being deleted is past every other change.
	if _, err := platform.RequestTenantDeletion(ctx, secondTenantID, "Second", AuditEntry{}); !errors.Is(err, ErrTenantStateChange) {
		t.Fatalf("delete a tenant twice = %v", err)
	}
	if _, err := platform.EnableTenant(ctx, secondTenantID, deleting.Revision, AuditEntry{}); !errors.Is(err, ErrTenantStateChange) {
		t.Fatalf("enable a tenant being deleted = %v", err)
	}
	if records, err := platform.ListTenants(ctx); err != nil || !reflect.DeepEqual(tenantNames(records), []string{"Default", "Second"}) {
		t.Fatalf("tenants while B is being deleted = %v, %v", tenantNames(records), err)
	}
}
