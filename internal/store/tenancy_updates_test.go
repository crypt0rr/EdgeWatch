package store

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// pausedTenantID is a third tenant that the update alert tests add to the
// tenant fixture, disabled.
const pausedTenantID = "00000000-0000-0000-0000-000000000300"

// addPausedTenant adds a disabled third tenant with a destination of its
// own, created while the tenant was active, and returns the destination's
// ID and the tenant's scope.
func addPausedTenant(t *testing.T, s *Store) (string, TenantScope) {
	t.Helper()
	ctx := context.Background()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Paused','paused',?,?)`, pausedTenantID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	scope := TenantScope{id: pausedTenantID}
	destination, err := s.Tenant(scope).CreateManagedNotification(ctx, "", "ops", "generic", []byte("sealed paused ops"), []byte("nonce ops"), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE tenants SET state=? WHERE id=?`, TenantStateDisabled, pausedTenantID); err != nil {
		t.Fatal(err)
	}
	return destination.ID, scope
}

// updateAlertRows returns the owner of each copy of the update alerts of
// the type, and the owner and destination of each of their deliveries,
// sorted. The platform owns the rows without a tenant.
func updateAlertRows(t *testing.T, s *Store, eventType string) (copies, deliveries []string) {
	t.Helper()
	copies = queryStrings(t, s.DB, `SELECT COALESCE(tenant_id,'platform') FROM events WHERE type=? ORDER BY 1`, eventType)
	deliveries = queryStrings(t, s.DB, `SELECT COALESCE(tenant_id,'platform')||' '||destination FROM outbox WHERE json_extract(CAST(payload_json AS TEXT),'$.type')=? ORDER BY 1`, eventType)
	return copies, deliveries
}

// eventTypes returns the type of each event, in order.
func eventTypes(events []model.Event) []string {
	types := make([]string, 0, len(events))
	for _, event := range events {
		types = append(types, event.Type)
	}
	return types
}

// tenantEventTypes returns the types of the tenant's events, newest first.
func tenantEventTypes(ts *TenantStore) ([]string, error) {
	page, err := ts.ListEventsPage(context.Background(), "", 50, 0)
	return eventTypes(page.Items), err
}

// countUpdateAlerts counts the update alerts among the event types.
func countUpdateAlerts(types []string) int {
	count := 0
	for _, eventType := range types {
		if eventType == "application-updated" || eventType == "application-update-available" {
			count++
		}
	}
	return count
}

// One update alert is recorded once for the platform and once for each
// active tenant, and each copy goes only to its owner's destinations. A
// destination of another owner is discarded as a deleted one, and audited
// by the copy's owner; a deployment destination takes only the default
// tenant's copy, which owns it. A paused tenant gets no copy, even when it
// is routed. Each owner's history holds its own copy only: the platform's
// copy and its audit record are in the platform's views, not in the default
// tenant's.
func TestUpdateAlertFansOutToThePlatformAndEachActiveTenant(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	ids := tenantFixtureNotifications
	pausedDestination, paused := addPausedTenant(t, f.store)
	key := func(id string) string { return managedNotificationKey(id, 1) }
	routes := []UpdateAlertRoute{
		{Destinations: []string{key(ids.platform), key(ids.a), "deployment-platform"}},
		{TenantID: DefaultTenantID, Destinations: []string{key(ids.a), key(ids.platform), key(ids.b), "deployment-a"}},
		{TenantID: secondTenantID, Destinations: []string{key(ids.b), key(ids.a), "deployment-b"}},
		{TenantID: pausedTenantID, Destinations: []string{key(pausedDestination)}},
	}
	lastAudit := countRows(t, f.store.DB, `SELECT COALESCE(MAX(id),0) FROM security_audit`)
	if _, err := f.store.Platform().RecordInstalledVersion(ctx, "1.0.0", "", false, nil); err != nil {
		t.Fatal(err)
	}
	upgraded, err := f.store.Platform().RecordInstalledVersion(ctx, "1.1.0", "https://example.invalid/1.1.0", true, routes)
	if err != nil {
		t.Fatal(err)
	}
	available, err := f.store.Platform().RecordReleaseCheck(ctx, "1.1.0", "1.2.0", "https://example.invalid/1.2.0", "EdgeWatch 1.2.0", "", "etag", true, routes)
	if err != nil {
		t.Fatal(err)
	}
	wantCopies := []string{DefaultTenantID, secondTenantID, "platform"}
	wantDeliveries := []string{
		DefaultTenantID + " deployment-a",
		DefaultTenantID + " " + key(ids.a),
		secondTenantID + " " + key(ids.b),
		"platform " + key(ids.platform),
	}
	for eventType, recorded := range map[string][]string{"application-updated": tenantsOf(upgraded), "application-update-available": tenantsOf(available)} {
		if want := []string{"", DefaultTenantID, secondTenantID}; !reflect.DeepEqual(recorded, want) {
			t.Errorf("%s: recorded copies of %v, want the platform's first, then each active tenant's %v", eventType, recorded, want)
		}
		copies, deliveries := updateAlertRows(t, f.store, eventType)
		if !reflect.DeepEqual(copies, wantCopies) {
			t.Errorf("%s: copies owned by %v, want %v", eventType, copies, wantCopies)
		}
		if !reflect.DeepEqual(deliveries, wantDeliveries) {
			t.Errorf("%s: deliveries %v, want %v", eventType, deliveries, wantDeliveries)
		}
	}
	if again, err := f.store.Platform().RecordReleaseCheck(ctx, "1.1.0", "1.2.0", "https://example.invalid/1.2.0", "EdgeWatch 1.2.0", "", "etag", true, routes); err != nil || len(again) != 0 {
		t.Fatalf("a repeated release check recorded %v, %v", again, err)
	}

	// Each owner's history holds its own copies, and the paused tenant's
	// none.
	for label, list := range map[string]func() ([]string, error){
		"tenant A":          func() ([]string, error) { return tenantEventTypes(f.store.Tenant(f.a)) },
		"tenant B":          func() ([]string, error) { return tenantEventTypes(f.store.Tenant(f.b)) },
		"the paused tenant": func() ([]string, error) { return tenantEventTypes(f.store.Tenant(paused)) },
		"the platform": func() ([]string, error) {
			page, err := f.store.Platform().ListEventsPage(ctx, 50, 0)
			return eventTypes(page.Items), err
		},
	} {
		types, err := list()
		if err != nil {
			t.Fatal(err)
		}
		want := 2
		if label == "the paused tenant" {
			want = 0
		}
		if got := countUpdateAlerts(types); got != want {
			t.Errorf("%s lists %d update alerts (%v), want %d", label, got, types, want)
		}
	}

	// A discarded destination is audited by the owner of the copy: the
	// platform's discard in platform scope, which the platform's audit view
	// shows and the default tenant's does not.
	for label, check := range map[string]struct {
		page func() (AuditLogPage, error)
		want []string
	}{
		"the platform's view": {func() (AuditLogPage, error) {
			return f.store.Platform().AuditPage(ctx, PlatformAuditFilter{AuditFilter: AuditFilter{ActionPrefix: "notifications.pending_discarded"}}, 0, 50)
		}, []string{" " + ids.a, " " + ids.a}},
		"tenant A's view": {func() (AuditLogPage, error) {
			return f.store.Tenant(f.a).AuditPage(ctx, AuditFilter{ActionPrefix: "notifications.pending_discarded"}, 0, 50)
		}, sortedIDs(DefaultTenantID+" "+ids.b, DefaultTenantID+" "+ids.b, DefaultTenantID+" "+ids.platform, DefaultTenantID+" "+ids.platform)},
		"tenant B's view": {func() (AuditLogPage, error) {
			return f.store.Tenant(f.b).AuditPage(ctx, AuditFilter{ActionPrefix: "notifications.pending_discarded"}, 0, 50)
		}, []string{secondTenantID + " " + ids.a, secondTenantID + " " + ids.a}},
	} {
		page, err := check.page()
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, entry := range page.Entries {
			if entry.ID <= int64(lastAudit) {
				continue
			}
			for _, id := range []string{ids.a, ids.b, ids.platform, pausedDestination} {
				if strings.Contains(entry.Detail, "managed notification "+id+" after the destination was deleted") {
					got = append(got, entry.TenantID+" "+id)
				}
			}
		}
		sort.Strings(got)
		if !reflect.DeepEqual(got, check.want) {
			t.Errorf("%s: discards %v, want %v", label, got, check.want)
		}
	}
}

// tenantsOf returns the tenant of each event, in order.
func tenantsOf(events []model.Event) []string {
	tenants := make([]string, 0, len(events))
	for _, event := range events {
		tenants = append(tenants, event.TenantID)
	}
	return tenants
}
