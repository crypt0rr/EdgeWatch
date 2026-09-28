package notify

import (
	"context"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// failTerminally queues one alert of event to the destination and ends its
// delivery with a terminal provider failure.
func failTerminally(t *testing.T, db *store.Store, created DestinationView, event model.Event) {
	t.Helper()
	ctx := context.Background()
	if err := db.System().QueueEvent(ctx, managedKey(created.ID, created.Revision), event); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE outbox SET attempts=7 WHERE destination=?`, managedKey(created.ID, created.Revision)); err != nil {
		t.Fatal(err)
	}
	due, err := db.System().DueDeliveries(ctx, 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("claimed deliveries = %+v, %v", due, err)
	}
	if err := db.System().DeliveryResultClaim(ctx, due[0].ID, due[0].ClaimToken, store.ErrDeliveryProvider); err != nil {
		t.Fatal(err)
	}
}

// The default unit's notification totals cover its own destinations and the
// deployment destinations only. When another unit or the platform deletes a
// destination with terminal failures, the default unit's totals do not
// change, and the destination's delivery health is removed with it.
func TestDeletedDestinationsOfOtherOwnersLeaveTheDefaultTotals(t *testing.T) {
	ctx := context.Background()
	notifier, db, _, other := twoTenantNotifier(t)
	audit := addPlatformAdmin(t, db)
	totals := func() [4]any {
		t.Helper()
		status := defaultStatus(t, notifier)
		return [4]any{status["delivery_pending"], status["delivery_retrying"], status["delivery_deferrals"], status["delivery_terminal_failures"]}
	}
	want := totals()
	if want != [4]any{0, 0, 0, 0} {
		t.Fatalf("default totals before = %v", want)
	}

	unit := notifier.Tenant(other)
	unitDestination, err := unit.CreateManagedWithAudit(ctx, "B hook", "generic://localhost/unit-b?disabletls=yes", true, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	failTerminally(t, db, unitDestination, model.Event{Type: "application-update-available", LatestVersion: "9.9.9", TenantID: otherTenantID, CreatedAt: time.Now().UTC()})
	if status, err := unit.Status(ctx); err != nil || status["delivery_terminal_failures"] != 1 {
		t.Fatalf("unit B totals = %v, %v; want its terminal failure", status, err)
	}
	if _, err := unit.DeleteManagedWithAudit(ctx, unitDestination.ID, unitDestination.Revision, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if got := totals(); got != want {
		t.Fatalf("default totals after unit B deleted its destination = %v, want %v", got, want)
	}

	platform := notifier.Platform(db.Platform())
	platformDestination, err := platform.CreateManagedWithAudit(ctx, "Platform hook", "generic://localhost/platform?disabletls=yes", true, audit)
	if err != nil {
		t.Fatal(err)
	}
	failTerminally(t, db, platformDestination, model.Event{Type: "application-update-available", LatestVersion: "9.9.9", CreatedAt: time.Now().UTC()})
	if err := platform.DeleteManagedWithAudit(ctx, platformDestination.ID, platformDestination.Revision, audit); err != nil {
		t.Fatal(err)
	}
	if got := totals(); got != want {
		t.Fatalf("default totals after the platform deleted its destination = %v, want %v", got, want)
	}
	var rows int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_delivery_health`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("delivery health rows after both deletes = %d, %v; want none", rows, err)
	}
}
