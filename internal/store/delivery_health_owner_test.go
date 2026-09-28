package store

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"
)

// healthIdentities returns the destination identities that have a delivery
// health row, sorted.
func healthIdentities(t *testing.T, s *Store) []string {
	t.Helper()
	rows, err := s.DB.Query(`SELECT destination_identity FROM notification_delivery_health ORDER BY destination_identity`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var identities []string
	for rows.Next() {
		var identity string
		if err := rows.Scan(&identity); err != nil {
			t.Fatal(err)
		}
		identities = append(identities, identity)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return identities
}

// Deleting a destination removes its delivery health in the same
// transaction, for a unit's destination and for a platform destination, and
// leaves the health of every other destination.
func TestDeletingADestinationRemovesItsDeliveryHealth(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
	ids := tenantFixtureNotifications
	queueFixtureDeliveries(t, f)
	before := healthIdentities(t, f.store)
	for _, identity := range []string{"managed:" + ids.a, "managed:" + ids.b, "managed:" + ids.platform} {
		if !slices.Contains(before, identity) {
			t.Fatalf("delivery health before the deletes = %v, want %s", before, identity)
		}
	}
	without := func(identities []string, removed ...string) []string {
		return slices.DeleteFunc(slices.Clone(identities), func(identity string) bool { return slices.Contains(removed, identity) })
	}
	if _, err := f.store.Tenant(f.b).DeleteManagedNotificationWithAudit(ctx, ids.b, 1, AuditEntry{Action: "notifications.deleted"}); err != nil {
		t.Fatal(err)
	}
	if got, want := healthIdentities(t, f.store), without(before, "managed:"+ids.b); !reflect.DeepEqual(got, want) {
		t.Fatalf("delivery health after unit B's delete = %v, want %v", got, want)
	}
	if err := f.store.Platform().DeletePlatformNotificationWithAudit(ctx, ids.platform, 1, platformAudit("")); err != nil {
		t.Fatal(err)
	}
	if got, want := healthIdentities(t, f.store), without(before, "managed:"+ids.b, "managed:"+ids.platform); !reflect.DeepEqual(got, want) {
		t.Fatalf("delivery health after the platform's delete = %v, want %v", got, want)
	}
}

// The default tenant keeps the delivery health of the deployment
// destinations, which have no managed identity. A managed identity that
// names no current destination, such as the health left behind by a
// destination deleted before deletes removed it, belongs to no tenant: the
// default tenant counts neither its health nor its deliveries.
func TestDefaultTenantHealthLeavesOutDeletedDestinations(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	deleted := "managed:" + unknownNotificationID
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO notification_delivery_health(destination_identity,terminal_failures,updated_at) VALUES(?,4,?)`, []any{deleted, stamp}},
		{`INSERT INTO notification_delivery_health(destination_identity,terminal_failures,updated_at) VALUES('deployment-id',1,?)`, []any{stamp}},
		{`INSERT INTO outbox(destination,payload_json,next_at,attempts,deferrals,tenant_id) VALUES(?,'{"n":1}',?,1,2,?)`, []any{deleted + ":1", stamp, DefaultTenantID}},
		{`INSERT INTO outbox(destination,payload_json,next_at,tenant_id) VALUES('deployment-id','{"n":2}',?,?)`, []any{stamp, DefaultTenantID}},
	} {
		if _, err := f.store.DB.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("%s: %v", statement.query, err)
		}
	}
	health, err := f.store.Tenant(f.a).ListDeliveryHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, counted := health[deleted]; counted {
		t.Errorf("the default tenant counts the health of a deleted destination: %+v", health[deleted])
	}
	if got := health["deployment-id"]; got.TerminalFailures != 1 || got.Pending != 1 {
		t.Errorf("the default tenant's deployment destination health = %+v, want 1 terminal failure and 1 pending", got)
	}
	other, err := f.store.Tenant(f.b).ListDeliveryHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, counted := other[deleted]; counted {
		t.Errorf("tenant B counts the health of a deleted destination")
	}
}

// A unit's purge leaves none of its delivery health behind: that of its
// current destinations, and that of the destinations it deleted before
// deletes removed their health. Those rows name no destination, so their
// owner cannot be told apart; the purge removes every such row. The health
// of another unit's destinations and of the deployment destinations stays.
func TestTenantPurgeErasesDeliveryHealthOfDeletedDestinations(t *testing.T) {
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	ids := tenantFixtureNotifications
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	deleted := "managed:" + unknownNotificationID
	for _, identity := range []string{deleted, "deployment-id"} {
		if _, err := f.store.DB.ExecContext(ctx, `INSERT INTO notification_delivery_health(destination_identity,terminal_failures,updated_at) VALUES(?,1,?)`, identity, stamp); err != nil {
			t.Fatal(err)
		}
	}
	before := healthIdentities(t, f.store)
	for _, identity := range []string{deleted, "deployment-id", "managed:" + ids.a, "managed:" + ids.b} {
		if !slices.Contains(before, identity) {
			t.Fatalf("delivery health before the purge = %v, want %s", before, identity)
		}
	}
	requestSecondTenantDeletion(t, f)
	results, err := f.store.System().PurgeDeletingTenants(ctx)
	if err != nil || len(results) != 1 || !results[0].Complete {
		t.Fatalf("purge = %+v, %v", results, err)
	}
	after := healthIdentities(t, f.store)
	for _, erased := range []string{deleted, "managed:" + ids.b} {
		if slices.Contains(after, erased) {
			t.Errorf("the purge left the delivery health of %s: %v", erased, after)
		}
	}
	for _, kept := range []string{"deployment-id", "managed:" + ids.a} {
		if !slices.Contains(after, kept) {
			t.Errorf("the purge erased the delivery health of %s: %v", kept, after)
		}
	}
}
