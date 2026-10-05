package notify

import (
	"context"
	"fmt"
	"strings"
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
	for attempt := 0; attempt < 32; attempt++ {
		due, err := db.System().DueDeliveries(ctx, 10)
		if err != nil || len(due) != 1 {
			t.Fatalf("claimed deliveries on attempt %d = %+v, %v", attempt+1, due, err)
		}
		if err := db.System().DeliveryResultClaim(ctx, due[0].ID, due[0].ClaimToken, store.ErrDeliveryProvider); err != nil {
			t.Fatal(err)
		}
		var terminalAt string
		if err := db.DB.QueryRowContext(ctx, `SELECT terminal_at FROM outbox WHERE id=?`, due[0].ID).Scan(&terminalAt); err != nil {
			t.Fatal(err)
		}
		if terminalAt != "" {
			return
		}
		// Make the next scheduled retry immediately due so the helper can
		// exercise the whole durable budget without waiting for its backoff.
		if _, err := db.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE id=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), due[0].ID); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("delivery did not reach a terminal failure within the bounded retry budget")
}

// The default unit's notification totals cover its own destinations and the
// deployment destinations only. When another unit or the platform deletes a
// destination with terminal failures, the default unit's totals do not
// change, and the destination's delivery health is removed with it.
func TestDeletedDestinationsOfOtherOwnersLeaveTheDefaultTotals(t *testing.T) {
	t.Parallel()
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

// The platform's destinations report their delivery health in the platform
// view and their delivery totals in the platform status, as a unit's do. A
// unit's destinations never count in the platform's, and the platform's
// never count in a unit's, the default unit's included. No view carries a
// URL or a provider error.
func TestPlatformDestinationsReportTheirDeliveryHealth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	notifier, db, own, other := twoTenantNotifier(t)
	audit := addPlatformAdmin(t, db)
	platform := notifier.Platform(db.Platform())
	failing, err := platform.CreateManagedWithAudit(ctx, "Platform hook", "generic://localhost/platform-secret?disabletls=yes", true, audit)
	if err != nil {
		t.Fatal(err)
	}
	quiet, err := platform.CreateManagedWithAudit(ctx, "Quiet hook", "generic://localhost/quiet?disabletls=yes", true, audit)
	if err != nil {
		t.Fatal(err)
	}
	// Each of these destinations has an update alert that failed terminally
	// and one that is pending: one of the platform's, and one in each unit,
	// which the platform must not count.
	type owned struct {
		destination DestinationView
		tenant      string
	}
	queued := []owned{{failing, ""}}
	for _, unit := range []struct {
		ts     *store.TenantStore
		tenant string
		url    string
	}{
		{own, store.DefaultTenantID, "generic://localhost/unit-a?disabletls=yes"},
		{other, otherTenantID, "generic://localhost/unit-b?disabletls=yes"},
	} {
		created, err := notifier.Tenant(unit.ts).CreateManagedWithAudit(ctx, "Unit hook", unit.url, true, store.AuditEntry{})
		if err != nil {
			t.Fatal(err)
		}
		queued = append(queued, owned{created, unit.tenant})
	}
	for _, item := range queued {
		failTerminally(t, db, item.destination, model.Event{Type: "application-update-available", LatestVersion: "9.9.8", TenantID: item.tenant, CreatedAt: time.Now().UTC()})
	}
	for _, item := range queued {
		if err := db.System().QueueEvent(ctx, managedKey(item.destination.ID, item.destination.Revision), model.Event{Type: "application-update-available", LatestVersion: "9.9.9", TenantID: item.tenant, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}

	views, status, err := platform.Destinations(ctx)
	if err != nil || len(views) != 2 {
		t.Fatalf("platform destinations = %+v, %v", views, err)
	}
	byID := map[string]DestinationView{}
	for _, view := range views {
		byID[view.ID] = view
		if strings.Contains(fmt.Sprintf("%+v", view), "platform-secret") {
			t.Fatalf("a platform view carries the URL: %+v", view)
		}
	}
	got := byID[failing.ID]
	if got.TerminalFailures != 1 || got.Pending != 1 || got.LastTerminalAt == "" || got.LastFailureAt == "" || got.LastErrorCode != "delivery_failed" {
		t.Fatalf("failing platform destination = %+v; want one terminal failure and one pending alert", got)
	}
	if quietView := byID[quiet.ID]; quietView.TerminalFailures != 0 || quietView.Pending != 0 || quietView.LastFailureAt != "" {
		t.Fatalf("quiet platform destination = %+v; want no delivery health", quietView)
	}
	for key, want := range map[string]int{"delivery_pending": 1, "delivery_retrying": 0, "delivery_deferrals": 0, "delivery_terminal_failures": 1} {
		if status[key] != want {
			t.Errorf("platform status %s = %v, want %d (status %v)", key, status[key], want, status)
		}
	}

	// Each unit counts only its own destination.
	for _, ts := range []*store.TenantStore{own, other} {
		unitStatus, err := notifier.Tenant(ts).Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if unitStatus["delivery_pending"] != 1 || unitStatus["delivery_terminal_failures"] != 1 {
			t.Errorf("unit status = %v; want only its own destination's pending alert and terminal failure", unitStatus)
		}
		unitViews, err := notifier.Tenant(ts).Destinations(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, view := range unitViews {
			if view.ID == failing.ID || view.ID == quiet.ID {
				t.Errorf("a unit lists a platform destination: %+v", view)
			}
		}
	}
}
