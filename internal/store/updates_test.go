package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// defaultUpdateRoutes routes an update alert as a single-tenant installation
// does: the platform's copy has no destinations, and the default tenant's
// copy goes to the given ones.
func defaultUpdateRoutes(destinations ...string) []UpdateAlertRoute {
	return []UpdateAlertRoute{{}, {TenantID: DefaultTenantID, Destinations: destinations}}
}

// Each alert is recorded once, as the platform's copy and the default
// tenant's, and is delivered once.
func TestApplicationUpdateStateAndNotificationDeduplication(t *testing.T) {
	t.Parallel()
	s, err := Open(freshTestDatabasePath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if state, err := s.Platform().GetApplicationUpdateState(ctx); err != nil || state.CheckStatus != "unknown" {
		t.Fatalf("initial update state = %#v, err=%v", state, err)
	}
	if events, err := s.Platform().RecordInstalledVersion(ctx, "v1.0.0", "", false, nil); err != nil || len(events) != 0 {
		t.Fatalf("first version seed events=%#v err=%v", events, err)
	}
	if events, err := s.Platform().RecordReleaseCheck(ctx, "v1.0.0", "v1.1.0", "https://github.com/crypt0rr/EdgeWatch/releases/tag/v1.1.0", "1.1", "2026-09-07T12:00:00Z", `"etag"`, true, defaultUpdateRoutes("file:test")); err != nil || len(events) != 2 {
		t.Fatalf("new release events=%#v err=%v", events, err)
	}
	if events, err := s.Platform().RecordReleaseCheck(ctx, "v1.0.0", "v1.1.0", "https://github.com/crypt0rr/EdgeWatch/releases/tag/v1.1.0", "1.1", "2026-09-07T12:00:00Z", `"etag"`, true, defaultUpdateRoutes("file:test")); err != nil || len(events) != 0 {
		t.Fatalf("duplicate release events=%#v err=%v", events, err)
	}
	var deliveries int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM outbox").Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 {
		t.Fatalf("outbox deliveries=%d, want one available-release notification", deliveries)
	}
	state, err := s.Platform().GetApplicationUpdateState(ctx)
	if err != nil || state.LatestVersion != "v1.1.0" || state.AnnouncedAvailableVersion != "v1.1.0" {
		t.Fatalf("release state=%#v err=%v", state, err)
	}
	if events, err := s.Platform().RecordInstalledVersion(ctx, "v1.1.0", state.ReleaseURL, true, defaultUpdateRoutes("file:test")); err != nil || len(events) != 2 {
		t.Fatalf("upgrade events=%#v err=%v", events, err)
	}
	if events, err := s.Platform().RecordInstalledVersion(ctx, "v1.1.0", state.ReleaseURL, true, defaultUpdateRoutes("file:test")); err != nil || len(events) != 0 {
		t.Fatalf("duplicate upgrade events=%#v err=%v", events, err)
	}
	if events, err := s.Platform().RecordInstalledVersion(ctx, "v1.0.0", state.ReleaseURL, false, nil); err != nil || len(events) != 0 {
		t.Fatalf("rollback events=%#v err=%v", events, err)
	}
	if events, err := s.Platform().RecordInstalledVersion(ctx, "v1.1.0", state.ReleaseURL, true, defaultUpdateRoutes("file:test")); err != nil || len(events) != 2 {
		t.Fatalf("re-upgrade events=%#v err=%v", events, err)
	}
	if err := s.Platform().RecordReleaseCheckFailure(ctx, "temporary upstream failure"); err != nil {
		t.Fatal(err)
	}
	state, err = s.Platform().GetApplicationUpdateState(ctx)
	if err != nil || state.LatestVersion != "v1.1.0" || state.CheckStatus != "failed" || state.LastError != "temporary upstream failure" {
		t.Fatalf("failure state=%#v err=%v", state, err)
	}
}

func TestApplicationUpdateNotificationDestinationsAreExplicitAndNormalized(t *testing.T) {
	t.Parallel()
	s, err := Open(freshTestDatabasePath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	routing, err := defaultTenant(s).ApplicationUpdateRouting(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if routing.Configured || routing.Destinations != nil {
		t.Fatalf("new routing is unexpectedly explicit: %#v", routing)
	}
	var created []string
	for _, name := range []string{"first", "second"} {
		destination, err := defaultTenant(s).CreateManagedNotification(ctx, "", name, "generic", []byte{1}, []byte{2}, true)
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, destination.ID)
	}
	first, second := created[0], created[1]
	if err := defaultTenant(s).SetApplicationUpdateDestinations(ctx, []string{" " + second + " ", first, second, ""}, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	routing, err = defaultTenant(s).ApplicationUpdateRouting(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := sortedCopy([]string{first, second})
	if !routing.Configured || !reflect.DeepEqual(routing.Destinations, want) {
		t.Fatalf("normalized routing = %#v, want %#v (configured=%t)", routing.Destinations, want, routing.Configured)
	}
	if err := defaultTenant(s).SetApplicationUpdateDestinations(ctx, []string{}, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	routing, err = defaultTenant(s).ApplicationUpdateRouting(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !routing.Configured || routing.Destinations == nil || len(routing.Destinations) != 0 {
		t.Fatalf("explicit empty routing = %#v (configured=%t)", routing.Destinations, routing.Configured)
	}
}

// selectionRefusal is the error text of a routing selector that names no
// destination of the routing's owner. It is the notifier's text, so an API
// answer does not depend on which check refused the selector, and it names
// only the selector, so another owner's destination reads as an unknown one.
func selectionRefusal(selector string) string {
	return fmt.Sprintf("invalid notification destination selection: notification destination %q was not found", selector)
}

// assertSelectionRefused checks that a routing write refused the selector as
// a validation error with the text of an unknown destination.
func assertSelectionRefused(t *testing.T, err error, selector string) {
	t.Helper()
	if !errors.Is(err, ErrValidation) || err.Error() != selectionRefusal(selector) {
		t.Errorf("routing to %q = %v, want %q", selector, err, selectionRefusal(selector))
	}
}

// A unit's update routing selects only the unit's own destinations: its
// web-managed ones, paused ones too, and, for the default unit, which owns
// them, the deployment destinations from config.yaml. The store checks this
// in the transaction of the write, whatever its caller checked, so another
// unit's destination, a platform destination, an unknown ID, and a
// destination deleted since the caller's check are refused alike, and the
// stored routing and the audit stay as they were.
func TestTenantUpdateRoutingSelectsOnlyOwnDestinations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	ids := tenantFixtureNotifications
	a, b := f.store.Tenant(f.a), f.store.Tenant(f.b)
	if err := a.SetApplicationUpdateDestinations(ctx, []string{ids.pausedA, "file:deployment", ids.a}, AuditEntry{}); err != nil {
		t.Fatalf("tenant A's own destinations: %v", err)
	}
	if routing, err := a.ApplicationUpdateRouting(ctx); err != nil || !reflect.DeepEqual(routing.Destinations, sortedCopy([]string{ids.a, ids.pausedA, "file:deployment"})) {
		t.Fatalf("tenant A's routing = %+v, %v", routing, err)
	}
	digests := func() [2]string {
		return [2]string{tenantNotificationDigest(t, f.store, f.a), tenantNotificationDigest(t, f.store, f.b)}
	}
	audits := func() int {
		return countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit WHERE action='notifications.update_routing'`)
	}
	before, beforeAudits := digests(), audits()
	for _, refused := range []struct {
		name          string
		ts            *TenantStore
		own, selector string
	}{
		{"tenant B selects tenant A's destination", b, ids.b, ids.a},
		{"tenant B selects tenant A's paused destination", b, ids.b, ids.pausedA},
		{"tenant B selects a platform destination", b, ids.b, ids.platform},
		{"tenant B selects an unknown destination", b, ids.b, unknownNotificationID},
		{"tenant B selects a deployment destination", b, ids.b, "file:deployment"},
		{"tenant A selects tenant B's destination", a, ids.a, ids.b},
		{"tenant A selects a platform destination", a, ids.a, ids.platform},
		{"tenant A selects an unknown destination", a, ids.a, unknownNotificationID},
		{"tenant A selects a deployment selector without an ID", a, ids.a, "file:"},
	} {
		t.Run(refused.name, func(t *testing.T) {
			err := refused.ts.SetApplicationUpdateDestinations(ctx, []string{refused.own, refused.selector}, AuditEntry{Action: "notifications.update_routing"})
			assertSelectionRefused(t, err, refused.selector)
		})
	}
	if digests() != before || audits() != beforeAudits {
		t.Fatal("a refused routing write changed a tenant's notification data or audit")
	}

	// The caller checked the selection before this delete; the write after
	// it must not store the deleted destination.
	if _, err := b.DeleteManagedNotificationWithAudit(ctx, ids.b, 1, AuditEntry{Action: "notifications.deleted"}); err != nil {
		t.Fatal(err)
	}
	assertSelectionRefused(t, b.SetApplicationUpdateDestinations(ctx, []string{ids.b}, AuditEntry{Action: "notifications.update_routing"}), ids.b)
	if routing, err := b.ApplicationUpdateRouting(ctx); err != nil || !routing.Configured || routing.Destinations == nil || len(routing.Destinations) != 0 {
		t.Fatalf("tenant B's routing after the refused write = %+v, %v", routing, err)
	}
}
