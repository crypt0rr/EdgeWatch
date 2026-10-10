package store

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// The notification cases join tenantStoreLeakCases before any test runs, so
// each store slice keeps its leak cases in its own file.
func init() {
	for name, leak := range notificationLeakCases {
		if _, duplicate := tenantStoreLeakCases[name]; duplicate {
			panic("two leak cases for TenantStore." + name)
		}
		tenantStoreLeakCases[name] = leak
	}
}

// tenantFixtureNotifications holds the IDs of the destinations that
// addTenantNotifications gives the tenant fixture. The fixture is built once
// and copied, so they are the same in every copy.
var tenantFixtureNotifications struct {
	a, pausedA, b, platform string
}

const (
	// unknownNotificationID names no destination anywhere.
	unknownNotificationID = "00000000-0000-0000-0000-00000000dead"
	// tenantFixturePlatformNotification is the fixture's platform
	// destination. No product API creates one yet.
	tenantFixturePlatformNotification = "00000000-0000-0000-0000-0000000000f1"
)

// addTenantNotifications gives the tenant fixture its destinations. Both
// tenants and the platform have a destination named "ops"; tenant A also has
// a paused one. Each ciphertext names its owner, so a test can tell whose
// credentials it holds. Each tenant's update routing selects its own "ops".
func addTenantNotifications(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	a, b := DefaultTenantScope(), TenantScope{id: secondTenantID}
	create := func(scope TenantScope, name string, enabled bool) string {
		t.Helper()
		destination, err := s.Tenant(scope).CreateManagedNotification(ctx, "", name, "generic", []byte("sealed "+scope.ID()+" "+name), []byte("nonce "+name), enabled)
		if err != nil {
			t.Fatal(err)
		}
		return destination.ID
	}
	ids := &tenantFixtureNotifications
	ids.a = create(a, "ops", true)
	ids.pausedA = create(a, "paused", false)
	ids.b = create(b, "ops", true)
	ids.platform = tenantFixturePlatformNotification
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO managed_notifications(id,tenant_id,name,provider,ciphertext,nonce,enabled,revision,credential_revision,created_at,updated_at) VALUES(?,NULL,'ops','generic',?,?,1,1,1,?,?)`, ids.platform, []byte("sealed platform ops"), []byte("nonce ops"), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	for scope, own := range map[TenantScope]string{a: ids.a, b: ids.b} {
		if err := s.Tenant(scope).SetApplicationUpdateDestinations(ctx, []string{own}, AuditEntry{}); err != nil {
			t.Fatal(err)
		}
	}
}

// tenantNotificationDigest returns a digest of the tenant's notification
// data: its destinations with their ciphertext, its update routing, the
// deliveries and delivery health of its destinations, and its jobs with
// their routing (tenantJobDigest). A test uses it to show that a write
// through another tenant left the tenant's data unchanged.
func tenantNotificationDigest(t *testing.T, s *Store, tenant TenantScope) string {
	t.Helper()
	return tenantJobDigest(t, s, tenant) + "\n" +
		tenantRows(t, s, "managed_notifications", "tenant_id=?1", tenant) +
		tenantRows(t, s, "tenants", "id=?1", tenant) +
		tenantRows(t, s, "outbox", "EXISTS (SELECT 1 FROM managed_notifications AS m WHERE m.tenant_id=?1 AND outbox.destination LIKE 'managed:' || m.id || ':%')", tenant) +
		tenantRows(t, s, "notification_delivery_health", "destination_identity IN (SELECT 'managed:' || id FROM managed_notifications WHERE tenant_id=?1)", tenant)
}

// notificationIDs returns the IDs of the destinations, sorted.
func notificationIDs(destinations []ManagedNotification) []string {
	ids := make([]string, 0, len(destinations))
	for _, destination := range destinations {
		ids = append(ids, destination.ID)
	}
	sort.Strings(ids)
	return ids
}

// foreignNotificationIDs are the destinations that tenant B must not reach:
// tenant A's, the platform's, and an unknown one.
func foreignNotificationIDs() []string {
	ids := tenantFixtureNotifications
	return []string{ids.a, ids.pausedA, ids.platform, unknownNotificationID}
}

// queueFixtureDeliveries queues one pending delivery to each destination of
// the fixture, each for an event of the destination's owner, as the store
// writes them: tenant A's to "ops" and the paused one, tenant B's to its
// "ops", and a platform update alert to the platform's.
func queueFixtureDeliveries(t *testing.T, f tenantFixture) {
	t.Helper()
	ctx := context.Background()
	ids := tenantFixtureNotifications
	at := time.Date(2026, 9, 21, 9, 0, 0, 0, time.UTC)
	for _, delivery := range []struct {
		destination string
		event       model.Event
	}{
		{ids.a, model.Event{Type: "changes-detected", JobID: f.jobA, Job: "edge", Message: "tenant-a", CreatedAt: at}},
		{ids.pausedA, model.Event{Type: "changes-detected", JobID: f.jobA, Job: "edge", Message: "tenant-a", CreatedAt: at}},
		{ids.b, model.Event{Type: "changes-detected", JobID: f.jobB, Job: "edge", Message: "tenant-b", CreatedAt: at}},
		{ids.platform, model.Event{Type: "application-update-available", Message: "platform", CreatedAt: at}},
	} {
		tx, err := f.store.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := queueEventsTx(ctx, tx, []model.Event{delivery.event}, []string{managedNotificationKey(delivery.destination, 1)}); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
}

// terminateFixtureDeliveries ends every delivery of the fixture for good,
// as its retry budget running out does.
func terminateFixtureDeliveries(t *testing.T, f tenantFixture) {
	t.Helper()
	if _, err := f.store.DB.Exec(`UPDATE outbox SET attempts=15,terminal_at=?,last_error='delivery_failed' WHERE sent_at IS NULL`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

// selectDestinations sets the routing of the tenant's jobs through the
// tenant's own store.
func selectDestinations(t *testing.T, f tenantFixture, scope TenantScope, selection ...string) {
	t.Helper()
	if count, err := f.store.Tenant(scope).MaterializeLegacyNotificationSelections(context.Background(), selection); err != nil || count != 2 {
		t.Fatalf("tenant %s: routing of %d jobs, %v", scope.ID(), count, err)
	}
}

// jobSelection returns the saved routing of a job and its revision.
func jobSelection(t *testing.T, f tenantFixture, scope TenantScope, id string) ([]string, int64) {
	t.Helper()
	record, err := f.store.Tenant(scope).GetJob(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return record.Job.NotificationDestinations, record.Revision
}

// assertNotificationWritesStayInTenant runs a write through tenant B against
// each foreign destination, then against B's own "ops". Each foreign one is
// not found, exactly as an unknown ID, although the write names its current
// revision, and tenant A's data is unchanged, also after B's write to its
// own destination. It returns the error of B's own write.
func assertNotificationWritesStayInTenant(t *testing.T, f tenantFixture, write func(ts *TenantStore, id string) error) error {
	t.Helper()
	before := tenantNotificationDigest(t, f.store, f.a)
	for _, id := range foreignNotificationIDs() {
		err := write(f.store.Tenant(f.b), id)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("tenant B wrote destination %s: %v, want ErrNotFound", id, err)
		}
		if err != nil && strings.Contains(err.Error(), "sealed") {
			t.Errorf("the error names a ciphertext: %v", err)
		}
	}
	if after := tenantNotificationDigest(t, f.store, f.a); after != before {
		t.Fatal("a write through tenant B changed tenant A's notification data")
	}
	var platform string
	if err := f.store.DB.QueryRow(`SELECT name||revision||enabled FROM managed_notifications WHERE id=? AND tenant_id IS NULL`, tenantFixtureNotifications.platform).Scan(&platform); err != nil || platform != "ops11" {
		t.Fatalf("the platform destination changed: %q, %v", platform, err)
	}
	err := write(f.store.Tenant(f.b), tenantFixtureNotifications.b)
	if after := tenantNotificationDigest(t, f.store, f.a); after != before {
		t.Fatal("tenant B's write to its own destination changed tenant A's notification data")
	}
	return err
}

// assertCreatedInTenantB checks a create through tenant B: the destination
// belongs to B, may use a name that tenant A uses, and is invisible to A.
// The legacy selection, when given, freezes only B's jobs.
func assertCreatedInTenantB(t *testing.T, f tenantFixture, create func(ts *TenantStore, name string) (ManagedNotification, error), legacy bool) {
	t.Helper()
	ctx := context.Background()
	ids := tenantFixtureNotifications
	before := tenantNotificationDigest(t, f.store, f.a)
	created, err := create(f.store.Tenant(f.b), "paused")
	if err != nil {
		t.Fatalf("tenant B could not use a name that tenant A uses: %v", err)
	}
	var owner string
	if err := f.store.DB.QueryRowContext(ctx, `SELECT tenant_id FROM managed_notifications WHERE id=?`, created.ID).Scan(&owner); err != nil || owner != secondTenantID || created.TenantID != secondTenantID {
		t.Fatalf("created destination's tenant = %q (%q), %v", owner, created.TenantID, err)
	}
	if _, err := f.store.Tenant(f.a).GetManagedNotification(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("tenant A read tenant B's new destination: %v", err)
	}
	if _, err := create(f.store.Tenant(f.b), "ops"); err == nil || !isUniqueTestError(err) {
		t.Errorf("tenant B created a second destination named like its own: %v", err)
	}
	if after := tenantNotificationDigest(t, f.store, f.a); after != before {
		t.Fatal("a create through tenant B changed tenant A's notification data")
	}
	for _, job := range []string{f.jobB, f.archivedB} {
		selection, revision := jobSelection(t, f, f.b, job)
		if legacy && (!reflect.DeepEqual(selection, []string{ids.b}) || revision != 2) {
			t.Errorf("tenant B's job %s routing = %v at revision %d, want its legacy selection at revision 2", job, selection, revision)
		}
		if !legacy && (selection != nil || revision != 1) {
			t.Errorf("tenant B's job %s routing = %v at revision %d, want unchanged", job, selection, revision)
		}
	}
}

func isUniqueTestError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE")
}

// notificationLeakCases show that tenant B sees and changes only its own
// destinations and routing, although tenant A and the platform have a
// destination with the same name. A foreign destination is not found,
// exactly as an unknown ID.
var notificationLeakCases = map[string]tenantLeakCase{
	"ListManagedNotifications": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		ids := tenantFixtureNotifications
		for scope, want := range map[TenantScope][]string{f.a: sortedIDs(ids.a, ids.pausedA), f.b: {ids.b}} {
			destinations, err := f.store.Tenant(scope).ListManagedNotifications(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got := notificationIDs(destinations); !reflect.DeepEqual(got, want) {
				t.Errorf("tenant %s: destinations = %v, want %v", scope.ID(), got, want)
			}
			for _, destination := range destinations {
				if destination.TenantID != scope.ID() || !strings.Contains(string(destination.Ciphertext), scope.ID()) {
					t.Errorf("tenant %s listed %+v", scope.ID(), destination)
				}
			}
		}
		all, err := f.store.System().ListManagedNotifications(ctx)
		if err != nil {
			t.Fatal(err)
		}
		owners := map[string]string{}
		for _, destination := range all {
			owners[destination.ID] = destination.TenantID
		}
		if want := map[string]string{ids.a: DefaultTenantID, ids.pausedA: DefaultTenantID, ids.b: secondTenantID, ids.platform: ""}; !reflect.DeepEqual(owners, want) {
			t.Errorf("system list owners = %v, want %v", owners, want)
		}
	}},
	"GetManagedNotification": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		ids := tenantFixtureNotifications
		for _, id := range foreignNotificationIDs() {
			destination, err := f.store.Tenant(f.b).GetManagedNotification(ctx, id)
			if !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(destination, ManagedNotification{}) {
				t.Errorf("tenant B read destination %s: %+v, %v", id, destination, err)
			}
		}
		for scope, id := range map[TenantScope]string{f.a: ids.a, f.b: ids.b} {
			destination, err := f.store.Tenant(scope).GetManagedNotification(ctx, id)
			if err != nil || destination.Name != "ops" || destination.TenantID != scope.ID() || string(destination.Ciphertext) != "sealed "+scope.ID()+" ops" {
				t.Errorf("tenant %s's own destination = %+v, %v", scope.ID(), destination, err)
			}
		}
	}},
	"OwnsDeploymentNotifications": {run: func(t *testing.T, f tenantFixture) {
		for scope, want := range map[TenantScope]bool{f.a: true, f.b: false} {
			if owns, err := f.store.Tenant(scope).OwnsDeploymentNotifications(context.Background()); err != nil || owns != want {
				t.Errorf("tenant %s owns the deployment destinations: %v, %v; want %v", scope.ID(), owns, err, want)
			}
		}
	}},
	"CreateManagedNotification": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertCreatedInTenantB(t, f, func(ts *TenantStore, name string) (ManagedNotification, error) {
			return ts.CreateManagedNotification(context.Background(), "", name, "generic", []byte("sealed b"), []byte("nonce"), true)
		}, false)
	}},
	"CreateManagedNotificationWithAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertCreatedInTenantB(t, f, func(ts *TenantStore, name string) (ManagedNotification, error) {
			return ts.CreateManagedNotificationWithAudit(context.Background(), "", name, "generic", []byte("sealed b"), []byte("nonce"), true, AuditEntry{Action: "notifications.created", Detail: "managed notification created"})
		}, false)
	}},
	// The legacy selection freezes only the creating tenant's jobs that still
	// follow every destination, to that tenant's destinations.
	"CreateManagedNotificationWithLegacySelection": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertCreatedInTenantB(t, f, func(ts *TenantStore, name string) (ManagedNotification, error) {
			return ts.CreateManagedNotificationWithLegacySelection(context.Background(), "", name, "generic", []byte("sealed b"), []byte("nonce"), true, []string{tenantFixtureNotifications.b})
		}, true)
	}},
	"CreateManagedNotificationWithLegacySelectionAndAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertCreatedInTenantB(t, f, func(ts *TenantStore, name string) (ManagedNotification, error) {
			return ts.CreateManagedNotificationWithLegacySelectionAndAudit(context.Background(), "", name, "generic", []byte("sealed b"), []byte("nonce"), true, []string{tenantFixtureNotifications.b}, AuditEntry{Action: "notifications.created"})
		}, true)
	}},
	"MaterializeLegacyNotificationSelections": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ids := tenantFixtureNotifications
		before := tenantNotificationDigest(t, f.store, f.a)
		selectDestinations(t, f, f.b, ids.b)
		if after := tenantNotificationDigest(t, f.store, f.a); after != before {
			t.Fatal("freezing tenant B's jobs changed tenant A's jobs")
		}
		for _, job := range []string{f.jobA, f.archivedA} {
			if selection, revision := jobSelection(t, f, f.a, job); selection != nil || revision != 1 {
				t.Errorf("tenant A's job %s routing = %v at revision %d", job, selection, revision)
			}
		}
		for _, job := range []string{f.jobB, f.archivedB} {
			if selection, revision := jobSelection(t, f, f.b, job); !reflect.DeepEqual(selection, []string{ids.b}) || revision != 2 {
				t.Errorf("tenant B's job %s routing = %v at revision %d", job, selection, revision)
			}
		}
		if count, err := f.store.Tenant(f.b).MaterializeLegacyNotificationSelections(context.Background(), []string{ids.b}); err != nil || count != 0 {
			t.Errorf("tenant B froze its jobs twice: %d, %v", count, err)
		}
	}},
	// Tenant B cannot update a foreign destination, even with its current
	// revision: the name, credentials, and pending deliveries stay as they
	// are.
	"UpdateManagedNotification": {writes: true, run: func(t *testing.T, f tenantFixture) {
		queueFixtureDeliveries(t, f)
		err := assertNotificationWritesStayInTenant(t, f, func(ts *TenantStore, id string) error {
			_, err := ts.UpdateManagedNotification(context.Background(), id, 1, "stolen", "generic", []byte("sealed stolen"), []byte("nonce"), true)
			return err
		})
		if err != nil {
			t.Fatalf("tenant B's own update: %v", err)
		}
		assertDeliveriesDiscarded(t, f, tenantFixtureNotifications.b)
	}},
	"UpdateManagedNotificationWithAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		queueFixtureDeliveries(t, f)
		err := assertNotificationWritesStayInTenant(t, f, func(ts *TenantStore, id string) error {
			_, err := ts.UpdateManagedNotificationWithAudit(context.Background(), id, 1, "stolen", "generic", []byte("sealed stolen"), []byte("nonce"), true, AuditEntry{Action: "notifications.updated"})
			return err
		})
		if err != nil {
			t.Fatalf("tenant B's own update: %v", err)
		}
		assertDeliveriesDiscarded(t, f, tenantFixtureNotifications.b)
	}},
	// Tenant B cannot replace a foreign destination's credentials and keep
	// its deliveries: A's deliveries stay where they are. B's own keep its
	// deliveries under the new revision.
	"UpdateManagedNotificationKeepingPendingWithAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		queueFixtureDeliveries(t, f)
		err := assertNotificationWritesStayInTenant(t, f, func(ts *TenantStore, id string) error {
			_, err := ts.UpdateManagedNotificationKeepingPendingWithAudit(context.Background(), id, 1, "stolen", "generic", []byte("sealed stolen"), []byte("nonce"), true, AuditEntry{Action: "notifications.updated"})
			return err
		})
		if err != nil {
			t.Fatalf("tenant B's own update: %v", err)
		}
		var kept int
		if err := f.store.DB.QueryRow(`SELECT COUNT(*) FROM outbox WHERE destination=? AND sent_at IS NULL`, managedNotificationKey(tenantFixtureNotifications.b, 2)).Scan(&kept); err != nil || kept != 1 {
			t.Fatalf("tenant B kept %d deliveries, %v; want its one", kept, err)
		}
	}},
	// Tenant B cannot list or redeliver a foreign destination's terminal
	// deliveries: each is ErrNotFound, as an unknown destination is, and A's
	// deliveries stay terminal.
	"ListTerminalDeliveries": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		queueFixtureDeliveries(t, f)
		terminateFixtureDeliveries(t, f)
		for _, id := range foreignNotificationIDs() {
			if deliveries, err := f.store.Tenant(f.b).ListTerminalDeliveries(ctx, id, 0, 10); !errors.Is(err, ErrNotFound) || deliveries != nil {
				t.Errorf("tenant B listed destination %s's deliveries: %+v, %v", id, deliveries, err)
			}
		}
		for scope, own := range map[TenantScope]string{f.a: tenantFixtureNotifications.a, f.b: tenantFixtureNotifications.b} {
			deliveries, err := f.store.Tenant(scope).ListTerminalDeliveries(ctx, own, 0, 10)
			if err != nil || len(deliveries) != 1 {
				t.Errorf("tenant %s: its own terminal deliveries = %+v, %v", scope.ID(), deliveries, err)
			}
		}
	}},
	"RedeliverTerminalDeliveries": {writes: true, run: func(t *testing.T, f tenantFixture) {
		queueFixtureDeliveries(t, f)
		terminateFixtureDeliveries(t, f)
		count := 0
		err := assertNotificationWritesStayInTenant(t, f, func(ts *TenantStore, id string) error {
			var err error
			count, err = ts.RedeliverTerminalDeliveries(context.Background(), id, nil, AuditEntry{Action: "notifications.redelivered"})
			return err
		})
		if err != nil || count != 1 {
			t.Fatalf("tenant B's own redelivery = %d, %v; want its one", count, err)
		}
	}},
	// Tenant B cannot delete a foreign destination. Deleting its own removes
	// it from B's jobs and B's update routing only, even where tenant A's
	// jobs select a destination of the same name.
	"DeleteManagedNotification": {writes: true, run: func(t *testing.T, f tenantFixture) {
		assertDeleteStaysInTenant(t, f, func(ts *TenantStore, id string) ([]string, error) {
			return nil, ts.DeleteManagedNotification(context.Background(), id, 1)
		})
	}},
	"DeleteManagedNotificationWithAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		changed := assertDeleteStaysInTenant(t, f, func(ts *TenantStore, id string) ([]string, error) {
			return ts.DeleteManagedNotificationWithAudit(context.Background(), id, 1, AuditEntry{Action: "notifications.deleted"})
		})
		if want := sortedIDs(f.jobB, f.archivedB); !reflect.DeepEqual(sortedIDs(changed...), want) {
			t.Errorf("changed jobs = %v, want tenant B's %v", changed, want)
		}
	}},
	// A tenant sees the delivery health of its own destinations only. The
	// default tenant also keeps the health of the deployment destinations,
	// which it owns; neither sees the platform's.
	"ListDeliveryHealth": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		ids := tenantFixtureNotifications
		queueFixtureDeliveries(t, f)
		stamp := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := f.store.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,next_at,tenant_id) VALUES('deployment-id','{}',?,?)`, stamp, DefaultTenantID); err != nil {
			t.Fatal(err)
		}
		for identity, failures := range map[string]int{"managed:" + ids.a: 2, "managed:" + ids.b: 3, "managed:" + ids.platform: 5} {
			if _, err := f.store.DB.ExecContext(ctx, `UPDATE notification_delivery_health SET terminal_failures=? WHERE destination_identity=?`, failures, identity); err != nil {
				t.Fatal(err)
			}
		}
		health := func(scope TenantScope) map[string][2]int {
			t.Helper()
			items, err := f.store.Tenant(scope).ListDeliveryHealth(ctx)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string][2]int{}
			for identity, item := range items {
				got[identity] = [2]int{item.Pending, item.TerminalFailures}
			}
			return got
		}
		if got, want := health(f.b), map[string][2]int{"managed:" + ids.b: {1, 3}}; !reflect.DeepEqual(got, want) {
			t.Errorf("tenant B: delivery health = %v, want %v", got, want)
		}
		got := health(f.a)
		if got["managed:"+ids.a] != [2]int{1, 2} || got["deployment-id"] != [2]int{1, 0} {
			t.Errorf("tenant A: delivery health = %v", got)
		}
		for _, foreign := range []string{"managed:" + ids.b, "managed:" + ids.platform, "managed:" + ids.pausedA} {
			if _, leaked := got[foreign]; leaked {
				t.Errorf("tenant A: delivery health has %s: %v", foreign, got)
			}
		}
	}},
	"ApplicationUpdateRouting": {run: func(t *testing.T, f tenantFixture) {
		ids := tenantFixtureNotifications
		for scope, want := range map[TenantScope]string{f.a: ids.a, f.b: ids.b} {
			routing, err := f.store.Tenant(scope).ApplicationUpdateRouting(context.Background())
			if err != nil || !routing.Configured || !reflect.DeepEqual(routing.Destinations, []string{want}) {
				t.Errorf("tenant %s: update routing = %+v, %v; want its own destination", scope.ID(), routing, err)
			}
		}
	}},
	// Each tenant's update routing is its own: silencing or changing B's
	// leaves A's as it is, and the platform's routing is not touched. B's
	// routing cannot select A's destinations, the platform's, the deployment
	// destinations, which are A's, or an unknown one: each is refused alike,
	// and neither routing changes.
	"SetApplicationUpdateDestinations": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		ids := tenantFixtureNotifications
		before := tenantNotificationDigest(t, f.store, f.a)
		if err := f.store.Tenant(f.b).SetApplicationUpdateDestinations(ctx, []string{}, AuditEntry{Action: "notifications.update_routing"}); err != nil {
			t.Fatal(err)
		}
		if after := tenantNotificationDigest(t, f.store, f.a); after != before {
			t.Fatal("tenant B's routing write changed tenant A's routing")
		}
		if routing, err := f.store.Tenant(f.b).ApplicationUpdateRouting(ctx); err != nil || !routing.Configured || len(routing.Destinations) != 0 || routing.Destinations == nil {
			t.Errorf("tenant B's silenced routing = %+v, %v", routing, err)
		}
		beforeB := tenantNotificationDigest(t, f.store, f.b)
		for _, foreign := range append(foreignNotificationIDs(), "file:deployment") {
			err := f.store.Tenant(f.b).SetApplicationUpdateDestinations(ctx, []string{foreign}, AuditEntry{Action: "notifications.update_routing"})
			assertSelectionRefused(t, err, foreign)
		}
		if tenantNotificationDigest(t, f.store, f.a) != before || tenantNotificationDigest(t, f.store, f.b) != beforeB {
			t.Fatal("a refused routing write through tenant B changed a tenant's routing")
		}
		if err := f.store.Tenant(f.a).SetApplicationUpdateDestinations(ctx, []string{ids.pausedA, ids.a}, AuditEntry{}); err != nil {
			t.Fatal(err)
		}
		if routing, err := f.store.Tenant(f.b).ApplicationUpdateRouting(ctx); err != nil || len(routing.Destinations) != 0 {
			t.Errorf("tenant A's routing write changed tenant B's: %+v, %v", routing, err)
		}
		platform, err := f.store.Platform().GetApplicationUpdateState(ctx)
		if err != nil || !platform.UpdateNotificationDestinationsConfigured || len(platform.UpdateNotificationDestinations) != 0 {
			t.Errorf("platform routing = %+v, %v", platform, err)
		}
	}},
}

// assertDeliveriesDiscarded checks that a credential change discarded the
// pending deliveries of the tenant's destination.
func assertDeliveriesDiscarded(t *testing.T, f tenantFixture, id string) {
	t.Helper()
	var pending int
	if err := f.store.DB.QueryRow(`SELECT COUNT(*) FROM outbox WHERE destination LIKE ? AND sent_at IS NULL`, "managed:"+id+":%").Scan(&pending); err != nil || pending != 0 {
		t.Errorf("tenant B's credential change left %d pending deliveries: %v", pending, err)
	}
}

// assertDeleteStaysInTenant selects destinations for both tenants' jobs and
// update routing, then deletes through tenant B. Each tenant's jobs also
// name the other tenant's destination, as a selection saved before this
// check existed could. Deleting a foreign destination is not found and
// changes nothing; deleting B's own removes it from B's jobs and routing
// only. It returns the jobs that B's own delete changed.
func assertDeleteStaysInTenant(t *testing.T, f tenantFixture, remove func(ts *TenantStore, id string) ([]string, error)) []string {
	t.Helper()
	ids := tenantFixtureNotifications
	queueFixtureDeliveries(t, f)
	selectDestinations(t, f, f.a, ids.a, ids.b)
	selectDestinations(t, f, f.b, ids.a, ids.b)
	var changed []string
	err := assertNotificationWritesStayInTenant(t, f, func(ts *TenantStore, id string) error {
		var err error
		changed, err = remove(ts, id)
		return err
	})
	if err != nil {
		t.Fatalf("tenant B's own delete: %v", err)
	}
	for _, job := range []string{f.jobB, f.archivedB} {
		if selection, revision := jobSelection(t, f, f.b, job); !reflect.DeepEqual(selection, []string{ids.a}) || revision != 3 {
			t.Errorf("tenant B's job %s routing after the delete = %v at revision %d", job, selection, revision)
		}
	}
	routing, err := f.store.Tenant(f.b).ApplicationUpdateRouting(context.Background())
	if err != nil || !routing.Configured || len(routing.Destinations) != 0 {
		t.Errorf("tenant B's update routing after the delete = %+v, %v", routing, err)
	}
	assertDeliveriesDiscarded(t, f, ids.b)
	return changed
}

// An alert goes only to its owner's destinations: queueing tenant B's alert
// to tenant A's or the platform's destination creates no delivery, exactly
// as for a deleted destination. The same holds for each copy of an update
// alert: a tenant's copy reaches only that tenant's destinations, and the
// platform's copy only the platform's.
func TestQueuedAlertsStayWithTheirTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	ids := tenantFixtureNotifications
	at := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	every := []string{managedNotificationKey(ids.a, 1), managedNotificationKey(ids.pausedA, 1), managedNotificationKey(ids.b, 1), managedNotificationKey(ids.platform, 1)}
	queued := func(event model.Event, destinations []string) []string {
		t.Helper()
		tx, err := f.store.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if err := queueEventsTx(ctx, tx, []model.Event{event}, destinations); err != nil {
			t.Fatal(err)
		}
		rows, err := tx.QueryContext(ctx, `SELECT destination||' '||COALESCE(tenant_id,'platform') FROM outbox WHERE CAST(payload_json AS TEXT) LIKE ? ORDER BY destination`, "%"+event.Message+"%")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var got []string
		for rows.Next() {
			var row string
			if err := rows.Scan(&row); err != nil {
				t.Fatal(err)
			}
			got = append(got, row)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return got
	}
	for label, check := range map[string]struct {
		event model.Event
		want  []string
	}{
		"tenant B's job":                       {model.Event{Type: "changes-detected", JobID: f.jobB, Job: "edge", Message: "queued-b", CreatedAt: at}, []string{managedNotificationKey(ids.b, 1) + " " + secondTenantID}},
		"tenant A's job":                       {model.Event{Type: "changes-detected", JobID: f.jobA, Job: "edge", Message: "queued-a", CreatedAt: at}, []string{managedNotificationKey(ids.a, 1) + " " + DefaultTenantID}},
		"a config.yaml job of tenant A":        {model.Event{Type: "scan-failure", Job: "edge", Message: "queued-legacy", CreatedAt: at}, []string{managedNotificationKey(ids.a, 1) + " " + DefaultTenantID}},
		"the platform's update alert":          {model.Event{Type: "application-update-available", Message: "queued-platform", CreatedAt: at}, []string{managedNotificationKey(ids.platform, 1) + " platform"}},
		"tenant A's update alert":              {model.Event{Type: "application-update-available", Message: "queued-update-a", TenantID: DefaultTenantID, CreatedAt: at}, []string{managedNotificationKey(ids.a, 1) + " " + DefaultTenantID}},
		"tenant B's update alert":              {model.Event{Type: "application-update-available", Message: "queued-update-b", TenantID: secondTenantID, CreatedAt: at}, []string{managedNotificationKey(ids.b, 1) + " " + secondTenantID}},
		"tenant A's job alert naming tenant B": {model.Event{Type: "changes-detected", JobID: f.jobA, Job: "edge", Message: "queued-named-b", TenantID: secondTenantID, CreatedAt: at}, []string{managedNotificationKey(ids.a, 1) + " " + DefaultTenantID}},
	} {
		if got := queued(check.event, every); !reflect.DeepEqual(got, check.want) {
			t.Errorf("%s: queued %v, want %v", label, got, check.want)
		}
	}

	// A single queued delivery follows the same rule, and the discarded one
	// is audited with the destination ID only.
	if err := f.store.System().QueueEvent(ctx, managedNotificationKey(ids.a, 1), model.Event{Type: "changes-detected", JobID: f.jobB, Job: "edge", Message: "single-b", CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	var leaked int
	if err := f.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE CAST(payload_json AS TEXT) LIKE '%single-b%'`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("tenant B's alert was queued to tenant A's destination: %d, %v", leaked, err)
	}
	var detail string
	if err := f.store.DB.QueryRowContext(ctx, `SELECT detail FROM security_audit WHERE action='notifications.pending_discarded' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil || !strings.Contains(detail, ids.a) || strings.Contains(detail, "sealed") {
		t.Fatalf("discard audit = %q, %v", detail, err)
	}
}
