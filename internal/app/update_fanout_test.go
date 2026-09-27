package app

import (
	"context"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/updatecheck"
)

// pausedUnitID is a third business unit that the fan-out test adds and
// disables.
const pausedUnitID = "00000000-0000-0000-0000-000000000300"

// platformDestinationID is a platform destination, which no product API
// creates yet. Its credentials are never opened: an update alert is queued
// to a locked destination too, and delivered once the key is available.
const platformDestinationID = "00000000-0000-0000-0000-0000000000f1"

// An update alert is fanned out. The platform's copy follows the platform
// routing to platform destinations only, although the routing also names a
// destination of the default unit. Each active business unit's copy follows
// its own routing to its own destinations: the default unit's configured
// selection, and the other unit's routing that was never configured, which
// takes its every destination. A paused unit gets no copy. Each unit lists
// its own copy, and each copy is published as a live update once, naming
// its owner, so the web console sends each unit only its own copy and the
// platform only the platform's.
func TestUpdateAlertsFanOutToEachBusinessUnit(t *testing.T) {
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	a := f.app
	audit := store.AuditEntry{Action: "notifications.created"}
	own := f.db.Tenant(f.a)
	security, err := a.Notifier.Tenant(own).CreateManagedWithAudit(ctx, "Security", "generic://127.0.0.1:9/security?disabletls=yes&template=json", true, audit)
	if err != nil {
		t.Fatal(err)
	}
	if err := own.SetApplicationUpdateDestinations(ctx, []string{security.ID}, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := f.db.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Paused','paused',?,?)`, pausedUnitID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	pausedScope, err := f.db.TenantScopeByID(ctx, pausedUnitID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Notifier.Tenant(f.db.Tenant(pausedScope)).CreateManagedWithAudit(ctx, "Operations", "generic://127.0.0.1:9/paused?disabletls=yes&template=json", true, audit); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET state='disabled' WHERE id=?`, pausedUnitID); err != nil {
		t.Fatal(err)
	}
	addPlatformUpdateRouting(t, f.db, stamp, platformDestinationID, f.destinationA)
	var mu sync.Mutex
	var live []model.Event
	a.SetEventHandler(func(event model.Event) {
		mu.Lock()
		defer mu.Unlock()
		if event.Type == "application-update-available" {
			live = append(live, event)
		}
	})

	a.Version = "v1.0.0"
	a.ReleaseChecker = &fakeReleaseChecker{result: updatecheck.Result{Release: updatecheck.Release{Version: "v1.1.0"}}}
	a.runUpdateCheck(ctx)

	deliveries := queryColumn(t, f.db, `SELECT COALESCE(tenant_id,'platform')||' '||destination FROM outbox WHERE CAST(payload_json AS TEXT) LIKE '%application-update-available%' ORDER BY 1`)
	want := []string{
		store.DefaultTenantID + " managed:" + security.ID + ":1",
		secondTenantID + " managed:" + f.destinationB + ":1",
		"platform managed:" + platformDestinationID + ":1",
	}
	if !slices.Equal(deliveries, want) {
		t.Fatalf("update alert deliveries = %v, want %v", deliveries, want)
	}
	copies := queryColumn(t, f.db, `SELECT COALESCE(tenant_id,'platform') FROM events WHERE type='application-update-available' ORDER BY 1`)
	if want := []string{store.DefaultTenantID, secondTenantID, "platform"}; !slices.Equal(copies, want) {
		t.Fatalf("update alert copies = %v, want %v", copies, want)
	}
	for _, scope := range []store.TenantScope{f.a, f.b, pausedScope} {
		events, err := f.db.Tenant(scope).ListEvents(ctx, "", 20)
		if err != nil {
			t.Fatal(err)
		}
		want := 1
		if scope == pausedScope {
			want = 0
		}
		if got := len(events); got != want || (want == 1 && events[0].Type != "application-update-available") {
			t.Errorf("unit %s lists %+v, want %d update alert", scope.ID(), events, want)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	var owners []string
	for _, event := range live {
		owners = append(owners, event.TenantID)
	}
	if want := []string{"", store.DefaultTenantID, secondTenantID}; !slices.Equal(owners, want) {
		t.Fatalf("live update owners = %q, want the platform's copy and each active unit's copy once: %q", owners, want)
	}
}

// A business unit that CreateUnit creates starts with update alerts off. Its
// copy of an update alert is recorded, so its console shows the alert, but
// it goes to none of the unit's destinations, while the default unit's
// routing that was never configured still takes each of its enabled
// destinations, and so does the routing of the unit that existed before.
// Once the new unit's administrators select a destination, its copy of the
// next update alert goes there.
func TestNewBusinessUnitGetsNoUpdateAlertsUntilItSelectsDestinations(t *testing.T) {
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	a := f.app
	enableBusinessUnits(a)
	unit, err := a.CreateUnit(ctx, "Charlie", "charlie", store.AuditEntry{ActorKind: store.AuditActorHost})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := f.db.TenantScopeByID(ctx, unit.ID)
	if err != nil {
		t.Fatal(err)
	}
	ts := f.db.Tenant(scope)
	operations, err := a.Notifier.Tenant(ts).CreateManagedWithAudit(ctx, "Operations", "generic://127.0.0.1:9/charlie?disabletls=yes&template=json", true, store.AuditEntry{Action: "notifications.created"})
	if err != nil {
		t.Fatal(err)
	}
	if routing, err := ts.ApplicationUpdateRouting(ctx); err != nil || !reflect.DeepEqual(routing, store.ApplicationUpdateRouting{Configured: true, Destinations: []string{}}) {
		t.Fatalf("the new unit's update routing = %#v, %v; want configured and empty", routing, err)
	}
	deliveries := func(tenantID string) []string {
		t.Helper()
		return queryColumn(t, f.db, `SELECT destination FROM outbox WHERE tenant_id='`+tenantID+`' AND CAST(payload_json AS TEXT) LIKE '%application-update-available%' ORDER BY 1`)
	}

	a.Version = "v1.0.0"
	a.ReleaseChecker = &fakeReleaseChecker{result: updatecheck.Result{Release: updatecheck.Release{Version: "v1.1.0"}}}
	a.runUpdateCheck(ctx)
	if got := deliveries(unit.ID); len(got) != 0 {
		t.Fatalf("the new unit's update alert went to %v, want none of its destinations", got)
	}
	if events, err := ts.ListEvents(ctx, "", 20); err != nil || len(events) != 1 || events[0].Type != "application-update-available" {
		t.Fatalf("the new unit lists %+v, %v; want its copy of the update alert", events, err)
	}
	// The default unit's web-managed destination and the deployment
	// destination from config.yaml.
	if got := deliveries(store.DefaultTenantID); len(got) != 2 {
		t.Fatalf("the default unit's update alert went to %v, want its two enabled destinations", got)
	}
	if got, want := deliveries(secondTenantID), []string{"managed:" + f.destinationB + ":1"}; !slices.Equal(got, want) {
		t.Fatalf("the existing unit's update alert went to %v, want %v", got, want)
	}

	if err := ts.SetApplicationUpdateDestinations(ctx, []string{operations.ID}, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	a.ReleaseChecker = &fakeReleaseChecker{result: updatecheck.Result{Release: updatecheck.Release{Version: "v1.2.0"}}}
	a.runUpdateCheck(ctx)
	if got, want := deliveries(unit.ID), []string{"managed:" + operations.ID + ":1"}; !slices.Equal(got, want) {
		t.Fatalf("the new unit's update alert after it selected a destination went to %v, want %v", got, want)
	}
}

// addPlatformUpdateRouting adds the platform destination and a platform
// update routing that selects the given destinations. No product API sets
// either yet.
func addPlatformUpdateRouting(t *testing.T, db *store.Store, stamp, platform string, selection ...string) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.DB.ExecContext(ctx, `INSERT INTO managed_notifications(id,tenant_id,name,provider,ciphertext,nonce,enabled,revision,credential_revision,created_at,updated_at) VALUES(?,NULL,'Platform','generic',?,?,1,1,1,?,?)`, platform, []byte("sealed"), []byte("nonce"), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Platform().GetApplicationUpdateState(ctx); err != nil {
		t.Fatal(err)
	}
	routing := `["` + platform + `"`
	for _, selector := range selection {
		routing += `,"` + selector + `"`
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE application_update_state SET notification_destinations_json=? WHERE id=1`, routing+`]`); err != nil {
		t.Fatal(err)
	}
}

// queryColumn returns the first column of each row of the query.
func queryColumn(t *testing.T, db *store.Store, query string) []string {
	t.Helper()
	rows, err := db.DB.QueryContext(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return values
}

// Without a notifier, and when a unit's routing or the destinations cannot
// be read, the alert still has the platform's copy and each active unit's,
// only without those destinations.
func TestUpdateAlertRoutesWithoutDestinations(t *testing.T) {
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET update_destinations_json='not json' WHERE id=?`, secondTenantID); err != nil {
		t.Fatal(err)
	}
	addPlatformUpdateRouting(t, f.db, time.Now().UTC().Format(time.RFC3339Nano), platformDestinationID)
	owners := []string{"", store.DefaultTenantID, secondTenantID}
	routes := f.app.updateAlertRoutes(ctx)
	if got := routedOwners(routes); !slices.Equal(got, owners) {
		t.Fatalf("update alert routes of %v, want the platform and each unit", got)
	}
	if got := routes[0].Destinations; !slices.Equal(got, []string{"managed:" + platformDestinationID + ":1"}) {
		t.Fatalf("the platform's destinations = %v", got)
	}
	if got := routes[2].Destinations; got != nil {
		t.Fatalf("the unit with unreadable routing has destinations %v", got)
	}
	// The default unit's routing was never configured: its web-managed
	// destination and the deployment destination from config.yaml.
	if got := routes[1].Destinations; len(got) != 2 {
		t.Fatalf("the default unit's destinations = %v, want its two", got)
	}

	if _, err := f.db.DB.ExecContext(ctx, `ALTER TABLE managed_notifications RENAME TO managed_notifications_unavailable`); err != nil {
		t.Fatal(err)
	}
	routes = f.app.updateAlertRoutes(ctx)
	if got := routedOwners(routes); !slices.Equal(got, owners) || routedDestinations(routes) != nil {
		t.Fatalf("update alert routes with unreadable destinations = %+v", routes)
	}

	f.app.Notifier = nil
	routes = f.app.updateAlertRoutes(ctx)
	if got := routedOwners(routes); !slices.Equal(got, owners) || routedDestinations(routes) != nil {
		t.Fatalf("update alert routes without a notifier = %+v", routes)
	}
}

// routedOwners returns the owner of each route, in order.
func routedOwners(routes []store.UpdateAlertRoute) []string {
	owners := make([]string, 0, len(routes))
	for _, route := range routes {
		owners = append(owners, route.TenantID)
	}
	return owners
}
