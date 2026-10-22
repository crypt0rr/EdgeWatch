package app

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/sandbox"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestSandboxHealthState(t *testing.T) {
	t.Parallel()
	enforced := sandbox.Status{State: sandbox.StateEnforced, ProcessUID: testUIDPointer(sandbox.UID)}
	for _, test := range []struct {
		name   string
		status sandbox.Status
		want   string
	}{
		{"identity and Landlock", withLandlock(enforced), model.SandboxStateSandboxed},
		{"identity only", enforced, model.SandboxStateIdentityOnly},
		{"leased scanner identities", sandbox.Status{State: sandbox.StateEnforced, IdentityPool: &sandbox.ScannerIdentityPoolStatus{State: sandbox.StateEnforced}}, model.SandboxStateIdentityOnly},
		{"Landlock as UID 0", withLandlock(sandbox.Status{State: sandbox.StateUnavailable}), model.SandboxStateLandlockOnly},
		{"unconfined as UID 0", sandbox.Status{State: sandbox.StateUnavailable}, model.SandboxStateUnconfined},
		{"scanner launches refused", sandbox.Status{Mode: sandbox.ModeAuto, State: sandbox.StateUnavailable, IdentityPool: &sandbox.ScannerIdentityPoolStatus{State: sandbox.StateUnavailable}}, model.SandboxStateLaunchesRefused},
		{"off as UID 0", sandbox.Status{State: sandbox.StateDisabled}, model.SandboxStateUnconfined},
		{"daemon that is not root", sandbox.Status{State: sandbox.StateUnavailable, ProcessUID: testUIDPointer(1000)}, model.SandboxStateIdentityOnly},
	} {
		if got := sandboxHealthState(test.status); got != test.want {
			t.Errorf("%s: state = %s, want %s", test.name, got, test.want)
		}
	}
}

func testUIDPointer(uid int) *int { return &uid }

// withLandlock returns the status with Landlock enforced.
func withLandlock(status sandbox.Status) sandbox.Status {
	status.Landlock.State = sandbox.StateEnforced
	return status
}

// routeDeploymentAlerts adds a platform destination and selects it for the
// deployment and the platform's security alerts.
func routeDeploymentAlerts(t *testing.T, db *store.Store) {
	t.Helper()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	addPlatformUpdateRouting(t, db, stamp, platformDestinationID)
	if _, err := db.DB.Exec(`UPDATE platform_alert_state SET health_destinations_json=?,security_destinations_json=? WHERE id=1`, `["`+platformDestinationID+`"]`, `["`+platformDestinationID+`"]`); err != nil {
		t.Fatal(err)
	}
}

// healthAlerts returns the details of the queued deployment-health alerts,
// and fails when one went to a business unit's destination.
func healthAlerts(t *testing.T, db *store.Store) []model.AlertDetail {
	t.Helper()
	rows, err := db.DB.Query(`SELECT COALESCE(tenant_id,''),CAST(payload_json AS TEXT) FROM outbox WHERE json_extract(CAST(payload_json AS TEXT),'$.type')=? ORDER BY id`, model.EventHealthAlert)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var alerts []model.AlertDetail
	for rows.Next() {
		var tenant, payload string
		if err := rows.Scan(&tenant, &payload); err != nil {
			t.Fatal(err)
		}
		if tenant != "" {
			t.Errorf("a deployment alert went to unit %s", tenant)
		}
		var event model.Event
		if err := json.Unmarshal([]byte(payload), &event); err != nil || event.Alert == nil {
			t.Fatalf("payload %s: %v", payload, err)
		}
		alerts = append(alerts, *event.Alert)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return alerts
}

// drainWake reports whether the delivery worker was woken, and clears it.
func drainWake(a *App) bool {
	select {
	case <-a.deliveryWake:
		return true
	default:
		return false
	}
}

// The daemon compares its sandboxes with the states that the last alerts
// reported when it starts and with each heartbeat. A loss of Landlock is
// reported once to the platform's destination and wakes the delivery worker;
// running on with the same state reports nothing more.
func TestCheckDeploymentAlertsReportsASandboxLoss(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	a := f.app
	routeDeploymentAlerts(t, f.db)
	a.sandbox = sandbox.NewEnforced().WithLandlock("/usr/local/bin/edgewatch", 3)
	a.notificationSandbox = sandbox.NewEnforcedFor(sandbox.Notifier).WithLandlock("/usr/local/bin/edgewatch", 3)
	now := time.Now().UTC()
	drainWake(a)
	a.checkDeploymentAlerts(ctx, now)
	if alerts := healthAlerts(t, f.db); len(alerts) != 0 || drainWake(a) {
		t.Fatalf("a confined first start alerted: %+v", alerts)
	}
	if got := a.SandboxHealth(); got.Scanner != model.SandboxStateSandboxed || got.Notification != model.SandboxStateSandboxed {
		t.Fatalf("sandbox health = %+v", got)
	}
	a.sandbox = sandbox.NewEnforced()
	a.checkDeploymentAlerts(ctx, now.Add(time.Minute))
	alerts := healthAlerts(t, f.db)
	want := []model.AlertDetail{{Kind: model.HealthAlertSandboxDegraded, Subject: "scanner", Previous: model.SandboxStateSandboxed, Current: model.SandboxStateIdentityOnly}}
	if !reflect.DeepEqual(alerts, want) || !drainWake(a) {
		t.Fatalf("alerts after the loss = %+v, want %+v and a wake", alerts, want)
	}
	a.checkDeploymentAlerts(ctx, now.Add(2*time.Minute))
	if alerts := healthAlerts(t, f.db); len(alerts) != 1 || drainWake(a) {
		t.Fatalf("alerts after a heartbeat with the same state = %+v", alerts)
	}
	// Without a policy, as for a library caller, nothing is compared.
	var none *App
	if got := none.SandboxHealth(); got != (store.SandboxHealth{}) {
		t.Errorf("nil application's sandbox health = %+v", got)
	}
	(&App{}).checkDeploymentAlerts(ctx, now)
}

func TestCheckDeploymentAlertsReportsBackupAndIdentityCapacity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	a := f.app
	routeDeploymentAlerts(t, f.db)
	a.Config.Scheduler.MaxConcurrent = 4
	a.Config.Backup.Directory = t.TempDir()
	a.sandbox = sandbox.NewEnforced().WithLandlock("/usr/local/bin/edgewatch", 3)
	a.inspectScannerIdentities = func(context.Context) (*sandbox.ScannerIdentityPoolStatus, error) {
		return &sandbox.ScannerIdentityPoolStatus{State: sandbox.StateEnforced, MaxParallel: 64, Active: 60, Free: 3}, nil
	}
	if err := writeBackupStatusFile(BackupStatusPath(f.db.Path), BackupStatus{Directory: a.Config.Backup.Directory, ConsecutiveFailures: 2}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	drainWake(a)
	a.checkDeploymentAlerts(ctx, now)
	want := []model.AlertDetail{
		{Kind: model.HealthAlertScheduledBackupFailed, Subject: "scheduled_backup", Count: 2},
		{Kind: model.HealthAlertScannerIdentitiesLow, Subject: "scanner identity pool", Current: "3 free, 4 required"},
	}
	if alerts := healthAlerts(t, f.db); !reflect.DeepEqual(alerts, want) || !drainWake(a) {
		t.Fatalf("operational deployment alerts = %+v, want %+v and a delivery wake", alerts, want)
	}
	a.checkDeploymentAlerts(ctx, now.Add(time.Minute))
	if alerts := healthAlerts(t, f.db); !reflect.DeepEqual(alerts, want) || drainWake(a) {
		t.Fatalf("repeated operational alerts = %+v, want no repeat", alerts)
	}
}

// A scanner identity inspection without an enforced pool cannot report a
// low-capacity alert or clear a previously observed low-capacity condition.
func TestScannerIdentityCapacityRequiresEnforcedInspection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	a := f.app
	routeDeploymentAlerts(t, f.db)
	a.Config.Scheduler.MaxConcurrent = 4
	a.sandbox = sandbox.NewEnforced()
	pool := &sandbox.ScannerIdentityPoolStatus{State: sandbox.StateUnavailable, Free: 0}
	a.inspectScannerIdentities = func(context.Context) (*sandbox.ScannerIdentityPoolStatus, error) {
		return pool, nil
	}
	now := time.Now().UTC()

	if metrics := a.DeploymentMetrics(ctx, now); metrics.ScannerIdentities != nil {
		t.Fatalf("unavailable scanner identity pool was exported: %+v", metrics.ScannerIdentities)
	}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now); err != nil || recorded != 0 {
		t.Fatalf("unavailable scanner identity observation = %d, %v; want no alert", recorded, err)
	}
	if alerts := healthAlerts(t, f.db); len(alerts) != 0 {
		t.Fatalf("unavailable scanner identity inspection alerted: %+v", alerts)
	}

	pool = &sandbox.ScannerIdentityPoolStatus{State: sandbox.StateEnforced, Free: 3}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now.Add(time.Minute)); err != nil || recorded != 1 {
		t.Fatalf("low enforced capacity = %d, %v; want one alert", recorded, err)
	}
	pool = &sandbox.ScannerIdentityPoolStatus{State: sandbox.StateUnavailable, Free: 0}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now.Add(2*time.Minute)); err != nil || recorded != 0 {
		t.Fatalf("unavailable inspection after low capacity = %d, %v; want no transition", recorded, err)
	}
	var failing int
	if err := f.db.DB.QueryRowContext(ctx, `SELECT scanner_identity_pool_low FROM platform_alert_state WHERE id=1`).Scan(&failing); err != nil || failing != 1 {
		t.Fatalf("low-capacity state after unavailable inspection = %d, %v; want it preserved", failing, err)
	}

	pool = &sandbox.ScannerIdentityPoolStatus{State: sandbox.StateEnforced, Free: 4}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now.Add(3*time.Minute)); err != nil || recorded != 0 {
		t.Fatalf("healthy enforced capacity = %d, %v; want silent recovery", recorded, err)
	}
	if alerts := healthAlerts(t, f.db); len(alerts) != 1 || alerts[0].Kind != model.HealthAlertScannerIdentitiesLow {
		t.Fatalf("scanner identity alerts after recovery = %+v; want only the low-capacity alert", alerts)
	}
}

// The heartbeat's check also reports the security alerts that an ended
// window held back.
func TestCheckDeploymentAlertsFlushesSecurityAlertWindows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	a := f.app
	routeDeploymentAlerts(t, f.db)
	for range 2 {
		if err := f.db.Platform().AuditEntry(ctx, store.AuditEntry{Action: "auth.rate_limited", ActorUsername: "platform-setup", SourceIP: "192.0.2.4", ActorKind: store.AuditActorUnit}); err != nil {
			t.Fatal(err)
		}
	}
	if !drainWake(a) {
		t.Error("the rate-limit record did not wake the delivery worker")
	}
	a.checkDeploymentAlerts(ctx, time.Now().UTC().Add(store.SecurityAlertWindow+time.Minute))
	if !drainWake(a) {
		t.Error("the summary did not wake the delivery worker")
	}
	var alerts, summaries int
	if err := f.db.DB.QueryRow(`SELECT COUNT(*),COALESCE(SUM(json_extract(CAST(payload_json AS TEXT),'$.alert.kind')='summary'),0) FROM outbox WHERE tenant_id IS NULL AND json_extract(CAST(payload_json AS TEXT),'$.type')=?`, model.EventSecurityAlert).Scan(&alerts, &summaries); err != nil {
		t.Fatal(err)
	}
	if alerts != 2 || summaries != 1 {
		t.Errorf("platform security alerts = %d with %d summaries, want the first and one summary", alerts, summaries)
	}
}

// A version rollback that the update check sees records its deployment
// alert with the installed version.
func TestRunUpdateCheckAlertsAVersionRollback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	a := f.app
	routeDeploymentAlerts(t, f.db)
	a.ReleaseChecker = nil
	a.Version = "v2.0.0"
	a.runUpdateCheck(ctx)
	a.Version = "v1.9.0"
	drainWake(a)
	a.runUpdateCheck(ctx)
	alerts := healthAlerts(t, f.db)
	want := []model.AlertDetail{{Kind: model.HealthAlertVersionRollback, Previous: "v2.0.0", Current: "v1.9.0"}}
	if !reflect.DeepEqual(alerts, want) || !drainWake(a) {
		t.Fatalf("alerts = %+v, want %+v and a wake", alerts, want)
	}
	state, err := f.db.Platform().GetApplicationUpdateState(ctx)
	if err != nil || state.InstalledVersion != "v1.9.0" {
		t.Fatalf("installed version = %+v, %v", state, err)
	}
	if _, err := f.db.DB.Exec(`UPDATE application_update_state SET installed_version='v1.9.1' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DB.Exec(`DROP TABLE platform_alert_state`); err != nil {
		t.Fatal(err)
	}
	// A rollback that cannot be recorded is logged and retried by the next
	// check, which still sees the newer installed version.
	a.runUpdateCheck(ctx)
	if state, err := f.db.Platform().GetApplicationUpdateState(ctx); err != nil || state.InstalledVersion != "v1.9.1" {
		t.Fatalf("installed version after a failed record = %+v, %v", state, err)
	}
}

// A check whose state cannot be read logs a warning for each part, wakes
// nothing, and leaves the daemon running; a nil application's wake is a
// no-op.
func TestCheckDeploymentAlertsLogsStorageFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	a := f.app
	a.sandbox = sandbox.NewEnforced()
	for _, statement := range []string{`DROP TABLE platform_alert_state`, `DROP TABLE security_alert_windows`} {
		if _, err := f.db.DB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	drainWake(a)
	a.checkDeploymentAlerts(ctx, time.Now().UTC())
	if drainWake(a) {
		t.Error("a failed check woke the delivery worker")
	}
	var none *App
	none.WakeDelivery()
}
