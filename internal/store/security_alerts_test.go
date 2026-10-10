package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// The security alert routing cases join tenantStoreLeakCases before any test
// runs, as the other slices' cases do.
func init() {
	for name, leak := range securityAlertLeakCases {
		if _, duplicate := tenantStoreLeakCases[name]; duplicate {
			panic("two leak cases for TenantStore." + name)
		}
		tenantStoreLeakCases[name] = leak
	}
}

var securityAlertLeakCases = map[string]tenantLeakCase{
	// Each tenant reads its own security routing only.
	"SecurityAlertRouting": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		ids := tenantFixtureNotifications
		if err := f.store.Tenant(f.a).SetSecurityAlertDestinations(ctx, []string{ids.a}, AuditEntry{}); err != nil {
			t.Fatal(err)
		}
		if routing, err := f.store.Tenant(f.b).SecurityAlertRouting(ctx); err != nil || len(routing) != 0 || routing == nil {
			t.Errorf("tenant B's security routing = %v, %v; want its own empty routing", routing, err)
		}
		if routing, err := f.store.Tenant(f.a).SecurityAlertRouting(ctx); err != nil || !reflect.DeepEqual(routing, []string{ids.a}) {
			t.Errorf("tenant A's security routing = %v, %v", routing, err)
		}
	}},
	// B's routing selects only B's web-managed destinations: A's, the
	// platform's, a deployment destination, and an unknown one are refused
	// alike, and neither routing changes.
	"SetSecurityAlertDestinations": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		ids := tenantFixtureNotifications
		before := tenantNotificationDigest(t, f.store, f.a)
		if err := f.store.Tenant(f.b).SetSecurityAlertDestinations(ctx, []string{ids.b}, AuditEntry{}); err != nil {
			t.Fatal(err)
		}
		if after := tenantNotificationDigest(t, f.store, f.a); after != before {
			t.Fatal("tenant B's security routing write changed tenant A's notification data")
		}
		beforeB := tenantNotificationDigest(t, f.store, f.b)
		for _, foreign := range append(foreignNotificationIDs(), "file:deployment") {
			err := f.store.Tenant(f.b).SetSecurityAlertDestinations(ctx, []string{foreign}, AuditEntry{})
			assertSelectionRefused(t, err, foreign)
		}
		if tenantNotificationDigest(t, f.store, f.a) != before || tenantNotificationDigest(t, f.store, f.b) != beforeB {
			t.Fatal("a refused security routing write through tenant B changed a tenant's routing")
		}
		if routing, err := f.store.Tenant(f.b).SecurityAlertRouting(ctx); err != nil || !reflect.DeepEqual(routing, []string{ids.b}) {
			t.Errorf("tenant B's security routing = %v, %v", routing, err)
		}
	}},
}

// queuedAlert is one outbox row of an alert.
type queuedAlert struct {
	destination string
	tenant      sql.NullString
	event       model.Event
	payload     string
}

// queuedAlerts returns the outbox rows of the events of the type, in the
// order they were queued.
func queuedAlerts(t *testing.T, s *Store, eventType string) []queuedAlert {
	t.Helper()
	rows, err := s.DB.Query(`SELECT destination,tenant_id,CAST(payload_json AS TEXT) FROM outbox WHERE json_extract(CAST(payload_json AS TEXT),'$.type')=? ORDER BY id`, eventType)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var alerts []queuedAlert
	for rows.Next() {
		var alert queuedAlert
		if err := rows.Scan(&alert.destination, &alert.tenant, &alert.payload); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(alert.payload), &alert.event); err != nil {
			t.Fatal(err)
		}
		alerts = append(alerts, alert)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return alerts
}

// newSecurityAlertFixture returns the tenant fixture with a platform
// administrator, where tenant A, tenant B, and the platform each route
// their security alerts to their own "ops" destination.
func newSecurityAlertFixture(t *testing.T) tenantFixture {
	t.Helper()
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, platformAdminID, nil, RolePlatformAdmin)
	ids := tenantFixtureNotifications
	for scope, own := range map[TenantScope]string{f.a: ids.a, f.b: ids.b} {
		if err := f.store.Tenant(scope).SetSecurityAlertDestinations(ctx, []string{own}, AuditEntry{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.store.Platform().SetPlatformSecurityAlertDestinations(ctx, []string{ids.platform}, AuditEntry{ActorUserID: platformAdminID}); err != nil {
		t.Fatal(err)
	}
	return f
}

// A platform administrator's password-reset link for a unit administrator
// queues exactly one security alert, to that unit's destination, and none
// to the other unit or the platform. The alert names the account and the
// platform administrator, but neither the link's token or its digest, nor
// the administrator's address, which the unit's audit hides, nor a URL.
func TestPlatformPasswordResetQueuesOneAlertToTheUnit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newSecurityAlertFixture(t)
	ids := tenantFixtureNotifications
	now := time.Now().UTC()
	const digest = "reset-token-digest-not-for-alerts"
	audit := AuditEntry{Action: "user.password_reset_issued", Detail: "password reset issued for admin-b by platform administrator", ActorUserID: platformAdminID, ActorUsername: platformAdminID, ActorKind: AuditActorPlatform, SourceIP: "203.0.113.9"}
	if err := f.store.Platform().IssueUnitAdminPasswordReset(ctx, secondTenantID, accountAdminB, digest, now, now.Add(30*time.Minute), audit); err != nil {
		t.Fatal(err)
	}
	alerts := queuedAlerts(t, f.store, model.EventSecurityAlert)
	if len(alerts) != 1 {
		t.Fatalf("security alerts = %+v, want exactly one", alerts)
	}
	alert := alerts[0]
	if alert.destination != managedNotificationKey(ids.b, 1) || alert.tenant.String != secondTenantID {
		t.Errorf("alert went to %s of tenant %v, want tenant B's ops destination", alert.destination, alert.tenant)
	}
	want := model.AlertDetail{Kind: model.SecurityAlertPlatformPasswordReset, Unit: "Second", Account: "admin-b", Actor: platformAdminID}
	if alert.event.Alert == nil || !reflect.DeepEqual(*alert.event.Alert, want) {
		t.Errorf("alert detail = %+v, want %+v", alert.event.Alert, want)
	}
	for _, secret := range []string{digest, "203.0.113.9", "://", "token"} {
		if strings.Contains(alert.payload, secret) {
			t.Errorf("alert payload %s contains %q", alert.payload, secret)
		}
	}
	// The unit's audit still records the action, as before.
	page, err := f.store.Tenant(f.b).AuditPage(ctx, AuditFilter{}, 0, 10)
	if err != nil || len(page.Entries) == 0 || page.Entries[0].Action != "user.password_reset_issued" {
		t.Fatalf("tenant B's audit = %+v, %v", page.Entries, err)
	}
}

// The platform's invitation of a unit administrator and its end of a unit
// account's sessions alert the unit too; the unit's own administrators'
// account actions do not.
func TestPlatformAccountActionsAlertTheUnit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newSecurityAlertFixture(t)
	now := time.Now().UTC()
	if _, err := f.store.Platform().InviteUnitAdmin(ctx, secondTenantID, User{Username: "new-admin-b", DisplayName: "New"}, "invite-digest", now, now.Add(30*time.Minute), AuditEntry{Action: "user.created", ActorUserID: platformAdminID, ActorUsername: platformAdminID}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Platform().RevokeUnitAccountSessions(ctx, secondTenantID, accountOperatorB, AuditEntry{Action: "user.sessions_revoked", ActorUserID: platformAdminID, ActorUsername: platformAdminID}); err != nil {
		t.Fatal(err)
	}
	// A unit administrator's own action on a unit account sends nothing.
	if err := f.store.Tenant(f.b).AuditEntry(ctx, AuditEntry{Action: "user.sessions_revoked", ActorUserID: accountAdminB, ActorUsername: "admin-b"}); err != nil {
		t.Fatal(err)
	}
	alerts := queuedAlerts(t, f.store, model.EventSecurityAlert)
	if len(alerts) != 1 {
		t.Fatalf("security alerts = %+v, want the invitation's only; the end of sessions is in its window", alerts)
	}
	if got := alerts[0].event.Alert; got.Kind != model.SecurityAlertPlatformInvitation || got.Account != "new-admin-b" || alerts[0].tenant.String != secondTenantID {
		t.Errorf("invitation alert = %+v of tenant %v", got, alerts[0].tenant)
	}
	assertAlertWindow(t, f.store, secondTenantID, model.SecurityAlertPlatformAccountActions, 1)
}

// assertAlertWindow checks the held alerts of an owner's open window. An
// empty tenant is the platform's.
func assertAlertWindow(t *testing.T, s *Store, tenant, kind string, suppressed int) {
	t.Helper()
	var owner any = tenant
	if tenant == "" {
		owner = nil
	}
	var got int
	if err := s.DB.QueryRow(`SELECT suppressed FROM security_alert_windows WHERE tenant_id IS ? AND kind=?`, owner, kind).Scan(&got); err != nil || got != suppressed {
		t.Errorf("window %s of %q holds %d alerts (%v), want %d", kind, tenant, got, err, suppressed)
	}
}

// rateLimited records the start of a rate-limited sign-in episode in the
// tenant, as the authentication manager does.
func rateLimited(t *testing.T, s *Store, tenant, source string) {
	t.Helper()
	if err := s.AuditEntry(context.Background(), AuditEntry{Action: "auth.rate_limited", Detail: "authentication event for login:admin-b", ActorUsername: "login:admin-b", SourceIP: source, TenantID: tenant, ActorKind: AuditActorUnit}); err != nil {
		t.Fatal(err)
	}
}

// Repeated rate-limit episodes in one window produce one alert; the
// daemon's flush then reports the held ones in one summary, which opens the
// next window, and a window that ends without any is removed.
func TestRateLimitEpisodesCoalesceIntoOneAlertPerWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newSecurityAlertFixture(t)
	woken := 0
	f.store.SetAlertWake(func() { woken++ })
	for _, source := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		rateLimited(t, f.store, secondTenantID, source)
	}
	if woken != 3 {
		t.Errorf("the alert hook ran %d times, want once per record", woken)
	}
	alerts := queuedAlerts(t, f.store, model.EventSecurityAlert)
	if len(alerts) != 1 {
		t.Fatalf("security alerts = %d, want one", len(alerts))
	}
	want := model.AlertDetail{Kind: model.SecurityAlertRateLimited, Unit: "Second", Operation: "sign-in", Account: "admin-b", Source: "198.51.100.1"}
	if got := *alerts[0].event.Alert; !reflect.DeepEqual(got, want) {
		t.Errorf("alert = %+v, want %+v", got, want)
	}
	assertAlertWindow(t, f.store, secondTenantID, model.SecurityAlertRateLimited, 2)
	// Within the window nothing is reported yet.
	if queued, err := f.store.System().FlushSecurityAlertWindows(ctx, time.Now().UTC()); err != nil || queued != 0 {
		t.Fatalf("flush within the window = %d, %v", queued, err)
	}
	later := time.Now().UTC().Add(SecurityAlertWindow + time.Minute)
	if queued, err := f.store.System().FlushSecurityAlertWindows(ctx, later); err != nil || queued != 1 {
		t.Fatalf("flush after the window = %d, %v; want one summary", queued, err)
	}
	alerts = queuedAlerts(t, f.store, model.EventSecurityAlert)
	if len(alerts) != 2 || alerts[1].tenant.String != secondTenantID {
		t.Fatalf("security alerts after the flush = %+v", alerts)
	}
	if summary := alerts[1].event.Alert; summary.Kind != model.SecurityAlertSummary || summary.Subject != model.SecurityAlertRateLimited || summary.Count != 2 || summary.Since.IsZero() {
		t.Errorf("summary = %+v", summary)
	}
	assertAlertWindow(t, f.store, secondTenantID, model.SecurityAlertRateLimited, 0)
	if queued, err := f.store.System().FlushSecurityAlertWindows(ctx, later.Add(SecurityAlertWindow+time.Minute)); err != nil || queued != 0 {
		t.Fatalf("flush of an empty ended window = %d, %v", queued, err)
	}
	var windows int
	if err := f.store.DB.QueryRow(`SELECT COUNT(*) FROM security_alert_windows`).Scan(&windows); err != nil || windows != 0 {
		t.Errorf("windows left = %d, %v; want the empty window removed", windows, err)
	}
}

// An alert after a window that ended with held alerts, before the daemon's
// flush, reports them itself.
func TestAlertAfterAnEndedWindowReportsTheHeldAlerts(t *testing.T) {
	t.Parallel()
	f := newSecurityAlertFixture(t)
	started := time.Now().UTC().Add(-2 * SecurityAlertWindow)
	if _, err := f.store.DB.Exec(`INSERT INTO security_alert_windows(tenant_id,kind,started_at,suppressed) VALUES(?,?,?,4)`, secondTenantID, model.SecurityAlertRateLimited, sqliteTimestamp(started)); err != nil {
		t.Fatal(err)
	}
	rateLimited(t, f.store, secondTenantID, "198.51.100.7")
	alerts := queuedAlerts(t, f.store, model.EventSecurityAlert)
	if len(alerts) != 1 {
		t.Fatalf("security alerts = %d, want one", len(alerts))
	}
	if got := alerts[0].event.Alert; got.Count != 4 || !got.Since.Equal(started.Truncate(time.Nanosecond)) {
		t.Errorf("alert = %+v, want the 4 held alerts since %s", got, started)
	}
	assertAlertWindow(t, f.store, secondTenantID, model.SecurityAlertRateLimited, 0)
}

// Security alerts are opt-in: a tenant that selected no destination, as
// every tenant starts, gets no alert and no window, and so does a tenant
// that is not active.
func TestSecurityAlertsNeedTheOwnersRouting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	rateLimited(t, f.store, secondTenantID, "198.51.100.1")
	if alerts := queuedAlerts(t, f.store, model.EventSecurityAlert); len(alerts) != 0 {
		t.Fatalf("alerts without routing = %+v", alerts)
	}
	if err := f.store.Tenant(f.b).SetSecurityAlertDestinations(ctx, []string{tenantFixtureNotifications.b}, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.Exec(`UPDATE tenants SET state='disabled' WHERE id=?`, secondTenantID); err != nil {
		t.Fatal(err)
	}
	rateLimited(t, f.store, secondTenantID, "198.51.100.1")
	if alerts := queuedAlerts(t, f.store, model.EventSecurityAlert); len(alerts) != 0 {
		t.Fatalf("alerts of a disabled tenant = %+v", alerts)
	}
	var windows int
	if err := f.store.DB.QueryRow(`SELECT COUNT(*) FROM security_alert_windows`).Scan(&windows); err != nil || windows != 0 {
		t.Errorf("windows = %d, %v; want none", windows, err)
	}
}

// The records in platform scope alert the platform's destinations only: a
// platform administrator's second-factor lockout, its recovery-code
// sign-in, and a rate-limited sign-in with a name that no account has,
// whose name the alert leaves out.
func TestPlatformScopeAlertsGoToThePlatform(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newSecurityAlertFixture(t)
	ids := tenantFixtureNotifications
	for _, entry := range []AuditEntry{
		{Action: "auth.second_factor_locked", ActorUsername: platformAdminID, SourceIP: "192.0.2.5", ActorKind: AuditActorUnit},
		{Action: "auth.recovery_code_used", ActorUsername: platformAdminID, SourceIP: "192.0.2.5", ActorKind: AuditActorUnit},
		{Action: "auth.rate_limited", ActorUsername: "login:<b>attacker</b>", SourceIP: "192.0.2.6", ActorKind: AuditActorUnit},
	} {
		if err := f.store.Platform().AuditEntry(ctx, entry); err != nil {
			t.Fatal(err)
		}
	}
	alerts := queuedAlerts(t, f.store, model.EventSecurityAlert)
	if len(alerts) != 3 {
		t.Fatalf("platform alerts = %d, want one of each kind", len(alerts))
	}
	for _, alert := range alerts {
		if alert.tenant.Valid || alert.destination != managedNotificationKey(ids.platform, 1) {
			t.Errorf("platform alert went to %s of tenant %v", alert.destination, alert.tenant)
		}
	}
	if got := alerts[0].event.Alert; got.Kind != model.SecurityAlertSecondFactorLocked || got.Account != platformAdminID || got.Source != "192.0.2.5" || got.Unit != "" {
		t.Errorf("lockout alert = %+v", got)
	}
	if got := alerts[2].event.Alert; got.Account != "" || got.Operation != "sign-in" || strings.Contains(alerts[2].payload, "attacker") {
		t.Errorf("rate-limit alert = %+v; it must not repeat a name that no account has", got)
	}
}

// An alert that cannot be queued, here because the tenant's stored routing
// is malformed, leaves the audit record and its action in place.
func TestAlertFailureKeepsTheAuditRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	if _, err := f.store.DB.Exec(`UPDATE tenants SET security_destinations_json='not json' WHERE id=?`, secondTenantID); err != nil {
		t.Fatal(err)
	}
	rateLimited(t, f.store, secondTenantID, "198.51.100.1")
	page, err := f.store.Tenant(f.b).AuditPage(ctx, AuditFilter{}, 0, 10)
	if err != nil || len(page.Entries) == 0 || page.Entries[0].Action != "auth.rate_limited" {
		t.Fatalf("tenant B's audit = %+v, %v; want the rate-limit record", page.Entries, err)
	}
	if alerts := queuedAlerts(t, f.store, model.EventSecurityAlert); len(alerts) != 0 {
		t.Errorf("alerts = %+v", alerts)
	}
}

// Deleting a destination removes it from its owner's security routing,
// and from the platform's security and deployment routing for a platform
// destination, each recorded in the owner's audit.
func TestDeletingADestinationRemovesItFromAlertRouting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newSecurityAlertFixture(t)
	ids := tenantFixtureNotifications
	destination, err := f.store.Tenant(f.b).GetManagedNotification(ctx, ids.b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Tenant(f.b).DeleteManagedNotificationWithAudit(ctx, ids.b, destination.Revision, AuditEntry{Action: "notifications.deleted", ActorUserID: accountAdminB}); err != nil {
		t.Fatal(err)
	}
	if routing, err := f.store.Tenant(f.b).SecurityAlertRouting(ctx); err != nil || len(routing) != 0 {
		t.Errorf("tenant B's security routing after the delete = %v, %v", routing, err)
	}
	if routing, err := f.store.Tenant(f.a).SecurityAlertRouting(ctx); err != nil || !reflect.DeepEqual(routing, []string{ids.a}) {
		t.Errorf("tenant A's security routing = %v, %v", routing, err)
	}
	assertAuditActions(t, f.store, secondTenantID, auditSecurityRouting)

	if err := f.store.Platform().SetPlatformHealthAlertDestinations(ctx, []string{ids.platform}, AuditEntry{ActorUserID: platformAdminID}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Platform().DeletePlatformNotificationWithAudit(ctx, ids.platform, 1, AuditEntry{ActorUserID: platformAdminID}); err != nil {
		t.Fatal(err)
	}
	routing, err := f.store.Platform().PlatformAlertRouting(ctx)
	if err != nil || len(routing.Security) != 0 || len(routing.Health) != 0 {
		t.Errorf("platform alert routing after the delete = %+v, %v", routing, err)
	}
	assertAuditActions(t, f.store, "", auditPlatformNotificationsSecurityRouting, auditPlatformNotificationsHealthRouting)
}

// assertAuditActions checks that the owner's audit, a tenant's or the
// platform's for an empty tenant, holds a record of each action whose
// detail says that a deleted destination was removed.
func assertAuditActions(t *testing.T, s *Store, tenant string, actions ...string) {
	t.Helper()
	var owner any = tenant
	if tenant == "" {
		owner = nil
	}
	for _, action := range actions {
		var count int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE tenant_id IS ? AND action=? AND detail LIKE 'removed deleted%'`, owner, action).Scan(&count); err != nil || count != 1 {
			t.Errorf("audit of %q has %d %s records (%v), want one", tenant, count, action, err)
		}
	}
}

// The platform's alert routings select platform destinations only and need
// an enabled platform administrator; a tenant's destination, a deployment
// destination, and an unknown one are refused, and no routing changes.
func TestPlatformAlertRoutingSelectsPlatformDestinations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	insertTenantUser(t, f.store, platformAdminID, nil, RolePlatformAdmin)
	ids := tenantFixtureNotifications
	platform := f.store.Platform()
	if err := platform.SetPlatformHealthAlertDestinations(ctx, []string{ids.platform, ids.platform}, AuditEntry{ActorUserID: platformAdminID}); err != nil {
		t.Fatal(err)
	}
	for _, write := range []func(context.Context, []string, AuditEntry) error{platform.SetPlatformSecurityAlertDestinations, platform.SetPlatformHealthAlertDestinations} {
		for _, foreign := range []string{ids.a, ids.b, "file:deployment", unknownNotificationID} {
			assertSelectionRefused(t, write(ctx, []string{foreign}, AuditEntry{ActorUserID: platformAdminID}), foreign)
		}
		if err := write(ctx, []string{ids.platform}, AuditEntry{ActorUserID: accountAdminA}); err == nil {
			t.Error("a unit administrator changed the platform's alert routing")
		}
	}
	routing, err := platform.PlatformAlertRouting(ctx)
	if err != nil || len(routing.Security) != 0 || !reflect.DeepEqual(routing.Health, []string{ids.platform}) {
		t.Errorf("platform alert routing = %+v, %v", routing, err)
	}
	for _, scope := range []TenantScope{f.a, f.b} {
		if routing, err := f.store.Tenant(scope).SecurityAlertRouting(ctx); err != nil || len(routing) != 0 {
			t.Errorf("tenant %s's security routing = %v, %v", scope.ID(), routing, err)
		}
	}
}

// The platform alert routing of a database without the platform's alert
// row, as a restored older copy may be before the daemon writes it, is
// empty.
func TestPlatformAlertRoutingWithoutItsRow(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	if _, err := s.DB.Exec(`DELETE FROM platform_alert_state`); err != nil {
		t.Fatal(err)
	}
	routing, err := s.Platform().PlatformAlertRouting(context.Background())
	if err != nil || routing.Security == nil || routing.Health == nil || len(routing.Security)+len(routing.Health) != 0 {
		t.Errorf("routing = %+v, %v", routing, err)
	}
}
