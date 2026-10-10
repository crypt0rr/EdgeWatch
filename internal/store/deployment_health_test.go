package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// secondPlatformNotification is a second platform destination of the
// deployment alert fixture.
const secondPlatformNotification = "00000000-0000-0000-0000-0000000000f2"

// newDeploymentAlertFixture returns the security alert fixture, where every
// owner also routes its security alerts, with a second platform destination,
// and the deployment alert routing selecting both platform destinations.
func newDeploymentAlertFixture(t *testing.T) tenantFixture {
	t.Helper()
	ctx := context.Background()
	f := newSecurityAlertFixture(t)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := f.store.DB.Exec(`INSERT INTO managed_notifications(id,tenant_id,name,provider,ciphertext,nonce,enabled,revision,credential_revision,created_at,updated_at) VALUES(?,NULL,'pager','generic',?,?,1,1,1,?,?)`, secondPlatformNotification, []byte("sealed platform pager"), []byte("nonce pager"), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Platform().SetPlatformHealthAlertDestinations(ctx, []string{tenantFixtureNotifications.platform, secondPlatformNotification}, AuditEntry{ActorUserID: platformAdminID}); err != nil {
		t.Fatal(err)
	}
	return f
}

// assertHealthAlerts checks the number of queued deployment-health alerts
// and that each went to a platform destination, never to a tenant's.
func assertHealthAlerts(t *testing.T, s *Store, want int) []queuedAlert {
	t.Helper()
	alerts := queuedAlerts(t, s, model.EventHealthAlert)
	if len(alerts) != want {
		t.Fatalf("deployment alerts = %d, want %d: %+v", len(alerts), want, alerts)
	}
	for _, alert := range alerts {
		if alert.tenant.Valid {
			t.Errorf("deployment alert went to tenant %s's destination %s", alert.tenant.String, alert.destination)
		}
		if alert.destination != managedNotificationKey(tenantFixtureNotifications.platform, 1) && alert.destination != managedNotificationKey(secondPlatformNotification, 1) {
			t.Errorf("deployment alert went to %s", alert.destination)
		}
	}
	return alerts
}

// countHealthAudit returns the number of deployment-health records in the
// platform audit, all of which must be in platform scope with the platform
// category.
func countHealthAudit(t *testing.T, s *Store) int {
	t.Helper()
	var count, misplaced int
	if err := s.DB.QueryRow(`SELECT COUNT(*),COALESCE(SUM(tenant_id IS NOT NULL OR category<>'platform' OR actor_kind<>'system'),0) FROM security_audit WHERE action='application.health_alert'`).Scan(&count, &misplaced); err != nil {
		t.Fatal(err)
	}
	if misplaced != 0 {
		t.Errorf("%d deployment alert records are not platform records of the daemon", misplaced)
	}
	return count
}

// A sandbox that gets worse writes one outbox row per selected platform
// destination; restarting with the same state writes none; a recovery
// within the window of the previous alert waits for its end and then
// writes one; no unit destination receives either.
func TestSandboxDegradationAlertsThePlatformOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newDeploymentAlertFixture(t)
	platform := f.store.Platform()
	start := time.Now().UTC()
	confined := SandboxHealth{Scanner: model.SandboxStateSandboxed, Notification: model.SandboxStateSandboxed}
	if recorded, err := platform.RecordSandboxHealth(ctx, confined, start); err != nil || recorded != 0 {
		t.Fatalf("first confined observation = %d, %v; want the silent baseline", recorded, err)
	}
	if recorded, err := platform.RecordSandboxHealth(ctx, confined, start.Add(time.Minute)); err != nil || recorded != 0 {
		t.Fatalf("restart with the same state = %d, %v", recorded, err)
	}
	degraded := SandboxHealth{Scanner: model.SandboxStateLandlockOnly, Notification: model.SandboxStateSandboxed}
	if recorded, err := platform.RecordSandboxHealth(ctx, degraded, start.Add(2*time.Minute)); err != nil || recorded != 1 {
		t.Fatalf("degradation = %d, %v; want one alert", recorded, err)
	}
	alerts := assertHealthAlerts(t, f.store, 2)
	want := model.AlertDetail{Kind: model.HealthAlertSandboxDegraded, Subject: "scanner", Previous: model.SandboxStateSandboxed, Current: model.SandboxStateLandlockOnly}
	if got := *alerts[0].event.Alert; got != want {
		t.Errorf("alert = %+v, want %+v", got, want)
	}
	for _, restart := range []time.Duration{3 * time.Minute, 2 * time.Hour} {
		if recorded, err := platform.RecordSandboxHealth(ctx, degraded, start.Add(restart)); err != nil || recorded != 0 {
			t.Fatalf("restart with the degraded state = %d, %v", recorded, err)
		}
	}
	assertHealthAlerts(t, f.store, 2)
	// A recovery right after the degradation waits for the window.
	recoveredAt := start.Add(2*time.Minute + DeploymentHealthAlertWindow/2)
	if recorded, err := platform.RecordSandboxHealth(ctx, confined, recoveredAt); err != nil || recorded != 0 {
		t.Fatalf("recovery within the window = %d, %v", recorded, err)
	}
	if recorded, err := platform.RecordSandboxHealth(ctx, confined, start.Add(3*time.Minute+DeploymentHealthAlertWindow)); err != nil || recorded != 1 {
		t.Fatalf("recovery after the window = %d, %v; want one alert", recorded, err)
	}
	alerts = assertHealthAlerts(t, f.store, 4)
	if got := alerts[3].event.Alert; got.Kind != model.HealthAlertSandboxRecovered || got.Previous != model.SandboxStateLandlockOnly || got.Current != model.SandboxStateSandboxed {
		t.Errorf("recovery alert = %+v", got)
	}
	if count := countHealthAudit(t, f.store); count != 2 {
		t.Errorf("deployment alert records = %d, want 2", count)
	}
	if alerts := queuedAlerts(t, f.store, model.EventSecurityAlert); len(alerts) != 0 {
		t.Errorf("security alerts = %+v; the units must not receive deployment alerts", alerts)
	}
}

// A first observation that is already degraded is reported once, and an
// unknown state is not compared.
func TestDegradedFirstSandboxObservationAlerts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newDeploymentAlertFixture(t)
	now := time.Now().UTC()
	if recorded, err := f.store.Platform().RecordSandboxHealth(ctx, SandboxHealth{}, now); err != nil || recorded != 0 {
		t.Fatalf("unknown states = %d, %v", recorded, err)
	}
	if recorded, err := f.store.Platform().RecordSandboxHealth(ctx, SandboxHealth{Notification: model.SandboxStateUnconfined}, now); err != nil || recorded != 1 {
		t.Fatalf("degraded first observation = %d, %v", recorded, err)
	}
	alerts := assertHealthAlerts(t, f.store, 2)
	if got := alerts[0].event.Alert; got.Kind != model.HealthAlertSandboxDegraded || got.Subject != "notification" || got.Previous != "" || got.Current != model.SandboxStateUnconfined {
		t.Errorf("alert = %+v", got)
	}
}

// Without deployment alert routing the alert is still recorded in the
// platform audit, and nothing is queued.
func TestDeploymentAlertWithoutRoutingIsAudited(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	if recorded, err := s.Platform().RecordSandboxHealth(ctx, SandboxHealth{Scanner: model.SandboxStateIdentityOnly}, time.Now().UTC()); err != nil || recorded != 1 {
		t.Fatalf("degradation = %d, %v", recorded, err)
	}
	assertHealthAlerts(t, s, 0)
	if count := countHealthAudit(t, s); count != 1 {
		t.Errorf("deployment alert records = %d, want 1", count)
	}
	page, err := s.Platform().AuditPage(ctx, PlatformAuditFilter{}, 0, 10)
	if err != nil || len(page.Entries) == 0 || page.Entries[0].Action != auditApplicationHealthAlert || page.Entries[0].Category != auditCategoryPlatform {
		t.Fatalf("platform audit = %+v, %v; want the deployment alert first", page.Entries, err)
	}
	unit, err := s.Tenant(DefaultTenantScope()).AuditPage(ctx, AuditFilter{}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range unit.Entries {
		if entry.Action == auditApplicationHealthAlert {
			t.Error("a unit's audit shows a deployment alert")
		}
	}
}

// A version rollback records one deployment alert in the transaction of
// the installed version; a second rollback within the window is recorded
// in the audit but not sent again.
func TestVersionRollbackAlertsThePlatform(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newDeploymentAlertFixture(t)
	platform := f.store.Platform()
	if _, err := platform.RecordInstalledVersion(ctx, "0.36.1", "", false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`UPDATE application_update_state SET installed_version='0.36.1',announced_upgrade_version='0.36.1' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if queued, err := platform.RecordInstalledVersionRollback(ctx, "0.36.0", now); err != nil || !queued {
		t.Fatalf("rollback = %v, %v; want an alert", queued, err)
	}
	alerts := assertHealthAlerts(t, f.store, 2)
	if got := alerts[0].event.Alert; got.Kind != model.HealthAlertVersionRollback || got.Previous != "0.36.1" || got.Current != "0.36.0" {
		t.Errorf("rollback alert = %+v", got)
	}
	state, err := platform.GetApplicationUpdateState(ctx)
	if err != nil || state.InstalledVersion != "0.36.0" || state.AnnouncedUpgradeVersion != "" {
		t.Errorf("update state = %+v, %v", state, err)
	}
	if _, err := f.store.DB.Exec(`UPDATE application_update_state SET installed_version='0.36.1' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if queued, err := platform.RecordInstalledVersionRollback(ctx, "0.36.0", now.Add(time.Minute)); err != nil || queued {
		t.Fatalf("rollback within the window = %v, %v; want none sent", queued, err)
	}
	assertHealthAlerts(t, f.store, 2)
	if count := countHealthAudit(t, f.store); count != 2 {
		t.Errorf("deployment alert records = %d, want both rollbacks", count)
	}
	// The same version, or none recorded before, is no rollback.
	if queued, err := platform.RecordInstalledVersionRollback(ctx, "0.36.0", now.Add(2*DeploymentHealthAlertWindow)); err != nil || queued {
		t.Fatalf("same version = %v, %v", queued, err)
	}
	if queued, err := platform.RecordInstalledVersionRollback(ctx, " ", now); err != nil || queued {
		t.Fatalf("empty version = %v, %v", queued, err)
	}
}

// terminalizeDelivery queues a delivery of the event to the destination for
// the owner and marks it failed for good, as the delivery worker does.
func terminalizeDelivery(t *testing.T, s *Store, destination string, event model.Event) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := queueEventsTx(ctx, tx, []model.Event{event}, []string{destination}); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := tx.QueryRow(`SELECT MAX(id) FROM outbox`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := tx.Exec(`UPDATE outbox SET attempts=?,terminal_at=? WHERE id=?`, deliveryMaxAttempts, now.Format(time.RFC3339Nano), id); err != nil {
		t.Fatal(err)
	}
	if err := insertTerminalDeliveryEventTx(ctx, tx, id, destination, ErrDeliveryProviderTimeout, "the attempt limit", now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// Deliveries that failed for good raise one deployment alert with their
// counts, at most once in DeliveryFailureAlertWindow. A deployment alert
// that fails itself is not counted, so it raises no further alert.
func TestFailedDeliveriesAlertThePlatformWithCounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newDeploymentAlertFixture(t)
	ids := tenantFixtureNotifications
	platform := f.store.Platform()
	now := time.Now().UTC()
	if recorded, err := platform.RecordDeliveryFailureHealth(ctx, now); err != nil || recorded {
		t.Fatalf("no failures = %v, %v", recorded, err)
	}
	terminalizeDelivery(t, f.store, managedNotificationKey(ids.b, 1), model.Event{Type: "changes-detected", TenantID: secondTenantID, Message: "unit B alert", CreatedAt: now})
	terminalizeDelivery(t, f.store, managedNotificationKey(ids.a, 1), model.Event{Type: "changes-detected", TenantID: DefaultTenantID, Message: "unit A alert", CreatedAt: now})
	terminalizeDelivery(t, f.store, managedNotificationKey(ids.platform, 1), model.Event{Type: "application-updated", Message: "platform alert", CreatedAt: now})
	terminalizeDelivery(t, f.store, managedNotificationKey(ids.platform, 1), model.Event{Type: model.EventHealthAlert, Message: "deployment alert", CreatedAt: now})
	if recorded, err := platform.RecordDeliveryFailureHealth(ctx, now); err != nil || !recorded {
		t.Fatalf("failures = %v, %v; want an alert", recorded, err)
	}
	// The failed deployment alert above is in the outbox too.
	alerts := assertHealthAlerts(t, f.store, 3)
	got := alerts[1].event.Alert
	if got.Kind != model.HealthAlertDeliveryFailures || got.Count != 3 || got.PlatformCount != 1 || got.Since.IsZero() {
		t.Errorf("failure alert = %+v; want 3 failures, 1 of them the platform's", got)
	}
	for _, alert := range alerts[1:] {
		for _, leak := range []string{"unit B alert", "unit A alert", ids.a, ids.b} {
			if strings.Contains(alert.payload, leak) {
				t.Errorf("failure alert %s names %q", alert.payload, leak)
			}
		}
	}
	terminalizeDelivery(t, f.store, managedNotificationKey(ids.b, 1), model.Event{Type: "changes-detected", TenantID: secondTenantID, Message: "another unit B alert", CreatedAt: now})
	if recorded, err := platform.RecordDeliveryFailureHealth(ctx, now.Add(time.Hour)); err != nil || recorded {
		t.Fatalf("failure within the window = %v, %v", recorded, err)
	}
	if recorded, err := platform.RecordDeliveryFailureHealth(ctx, now.Add(DeliveryFailureAlertWindow+time.Minute)); err != nil || !recorded {
		t.Fatalf("failure after the window = %v, %v", recorded, err)
	}
	alerts = assertHealthAlerts(t, f.store, 5)
	if got := alerts[3].event.Alert; got.Count != 1 || got.PlatformCount != 0 {
		t.Errorf("second failure alert = %+v", got)
	}
}

// The confinement comparison treats losing either confinement as a
// degradation, including a change that gains the other.
func TestSandboxDegraded(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		previous, current string
		degraded          bool
	}{
		{"", model.SandboxStateSandboxed, false},
		{"", model.SandboxStateIdentityOnly, true},
		{model.SandboxStateSandboxed, model.SandboxStateLandlockOnly, true},
		{model.SandboxStateIdentityOnly, model.SandboxStateLandlockOnly, true},
		{model.SandboxStateUnconfined, model.SandboxStateLandlockOnly, false},
		{model.SandboxStateLandlockOnly, model.SandboxStateSandboxed, false},
	} {
		if got := sandboxDegraded(test.previous, test.current); got != test.degraded {
			t.Errorf("sandboxDegraded(%q, %q) = %v, want %v", test.previous, test.current, got, test.degraded)
		}
	}
}
