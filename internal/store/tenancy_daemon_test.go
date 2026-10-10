package store

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// The daemon slice's case joins tenantStoreLeakCases before any test runs,
// so the completeness check and TestTenantStoreIsolation cover it.
func init() {
	for name, leak := range daemonTenantLeakCases {
		if _, exists := tenantStoreLeakCases[name]; exists {
			panic("duplicate tenant leak case " + name)
		}
		tenantStoreLeakCases[name] = leak
	}
}

var daemonTenantLeakCases = map[string]tenantLeakCase{
	"Telemetry": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		a, err := f.store.Tenant(f.a).Telemetry(ctx)
		if err != nil {
			t.Fatal(err)
		}
		b, err := f.store.Tenant(f.b).Telemetry(ctx)
		if err != nil {
			t.Fatal(err)
		}
		deployment, err := f.store.System().DeploymentTelemetry(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if a.CollectedAt.IsZero() || b.CollectedAt.IsZero() {
			t.Fatalf("telemetry without a collection time: %+v, %+v", a, b)
		}
		// Tenant B counts only its own rows: its two jobs, its scan with its
		// three hosts, and its one event with its failed delivery.
		got := b
		got.CollectedAt = time.Time{}
		if want := (TenantTelemetry{Jobs: 2, Scans: 1, HostObservations: 3, EffectiveHosts: 3, Events: 1, OutboxPending: 1, OutboxFailed: 1}); got != want {
			t.Errorf("tenant B's telemetry = %+v, want %+v", got, want)
		}
		// Every row is counted for exactly one owner. The platform's events
		// and deliveries belong to no tenant, the default tenant included,
		// so the two tenants and the platform add up to the deployment.
		var platform TenantTelemetry
		events, err := f.store.Platform().ListEventsPage(ctx, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		failed, err := f.store.Platform().FailedDeliveries(ctx)
		if err != nil {
			t.Fatal(err)
		}
		platform.Events, platform.OutboxFailed = int64(events.Total), int64(failed)
		if err := f.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL AND tenant_id IS NULL`).Scan(&platform.OutboxPending); err != nil {
			t.Fatal(err)
		}
		if platform.Events == 0 || platform.OutboxPending == 0 || platform.OutboxFailed == 0 {
			t.Fatalf("the fixture has no platform history: %+v", platform)
		}
		for _, counter := range []struct {
			name                       string
			a, b, platform, deployment int64
		}{
			{"jobs", a.Jobs, b.Jobs, 0, deployment.Jobs},
			{"scans", a.Scans, b.Scans, 0, deployment.Scans},
			{"host observations", a.HostObservations, b.HostObservations, 0, deployment.HostObservations},
			{"effective hosts", a.EffectiveHosts, b.EffectiveHosts, 0, deployment.EffectiveHosts},
			{"events", a.Events, b.Events, platform.Events, deployment.Events},
			{"scan cycles", a.ScanCycles, b.ScanCycles, 0, deployment.ScanCycles},
			{"pending deliveries", a.OutboxPending, b.OutboxPending, platform.OutboxPending, deployment.OutboxPending},
			{"retrying deliveries", a.OutboxRetrying, b.OutboxRetrying, 0, deployment.OutboxRetrying},
			{"failed deliveries", a.OutboxFailed, b.OutboxFailed, platform.OutboxFailed, deployment.OutboxFailed},
		} {
			if counter.a+counter.b+counter.platform != counter.deployment {
				t.Errorf("%s: tenant A %d + tenant B %d + the platform %d, want the deployment's %d", counter.name, counter.a, counter.b, counter.platform, counter.deployment)
			}
		}
		// The database holds every tenant's data, so only the default
		// tenant reports its size, the deployment's.
		if a.DatabaseBytes <= 0 || a.DatabaseBytes != deployment.DatabaseBytes || b.DatabaseBytes != 0 {
			t.Errorf("database size: tenant A %d, tenant B %d, deployment %d", a.DatabaseBytes, b.DatabaseBytes, deployment.DatabaseBytes)
		}
	}},
}

// The delivery worker holds the deliveries of a disabled tenant: they are
// neither claimed nor aged until the tenant is enabled again. The deliveries
// of the active tenant and of the platform are claimed as before, and each
// claimed delivery names its tenant.
func TestDeliveryClaimsHoldADisabledTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	system := f.store.System()
	now := time.Now().UTC()
	for destination, event := range map[string]model.Event{
		"claim-a":        {Type: "changes-detected", JobID: f.jobA, Job: "edge", Message: "tenant-a", CreatedAt: now},
		"claim-b":        {Type: "changes-detected", JobID: f.jobB, Job: "edge", Message: "tenant-b", CreatedAt: now},
		"claim-platform": {Type: "platform-notice", Message: "platform", CreatedAt: now},
	} {
		if err := system.QueueEvent(ctx, destination, event); err != nil {
			t.Fatal(err)
		}
	}
	claimed := func(deliveries []Delivery, err error) map[string]string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, delivery := range deliveries {
			out[delivery.Destination] = delivery.TenantID
		}
		return out
	}
	heldDeferrals := func() int {
		t.Helper()
		var deferrals int
		if err := f.store.DB.QueryRowContext(ctx, `SELECT deferrals FROM outbox WHERE destination='claim-b'`).Scan(&deferrals); err != nil {
			t.Fatal(err)
		}
		return deferrals
	}

	setTenantState(t, f.store, secondTenantID, TenantStateDisabled)
	if got, want := claimed(system.ClaimDueDeliveriesExcluding(ctx, 10, "owner-1", []string{"claim-a"})), map[string]string{"claim-platform": ""}; !reflect.DeepEqual(got, want) {
		t.Fatalf("claims excluding tenant A's destination = %v, want %v", got, want)
	}
	if got, want := claimed(f.store.System().ClaimDueDeliveries(ctx, 10, "owner-2")), map[string]string{"claim-a": DefaultTenantID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("claims with tenant B disabled = %v, want %v", got, want)
	}
	// A locked destination does not use up the held delivery's deferrals.
	if err := system.AgeLockedDeliveries(ctx, []string{"claim-b"}); err != nil {
		t.Fatal(err)
	}
	if deferrals := heldDeferrals(); deferrals != 0 {
		t.Fatalf("a held delivery aged to %d deferrals", deferrals)
	}
	setTenantState(t, f.store, secondTenantID, TenantStateDeleting)
	if got := claimed(system.ClaimDueDeliveries(ctx, 10, "owner-3")); len(got) != 0 {
		t.Fatalf("claims with tenant B being deleted = %v, want none", got)
	}

	setTenantState(t, f.store, secondTenantID, TenantStateActive)
	if got, want := claimed(system.DueDeliveries(ctx, 10)), map[string]string{"claim-b": secondTenantID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("claims after tenant B was enabled = %v, want %v", got, want)
	}
}

// The silence watchdog does not alert about a disabled tenant's jobs, whose
// scans are paused, and judges them again once the tenant is enabled.
func TestSilenceWatchdogSkipsADisabledTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	system := f.store.System()
	created := time.Now().UTC().Add(-time.Hour)
	now := time.Now().UTC().Add(30 * 24 * time.Hour)
	const threshold = time.Hour
	due := func(jobID string) bool {
		t.Helper()
		due, err := system.JobSilenceDue(ctx, jobID, created, now, threshold)
		if err != nil {
			t.Fatal(err)
		}
		return due
	}
	alerts := func(jobID string) int {
		t.Helper()
		var count int
		if err := f.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE type='job-silent' AND job_id=?`, jobID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if !due(f.jobA) || !due(f.jobB) {
		t.Fatal("the fixture's jobs are not overdue while both tenants are active")
	}

	for _, state := range []string{TenantStateDisabled, TenantStateDeleting} {
		setTenantState(t, f.store, secondTenantID, state)
		if due(f.jobB) {
			t.Errorf("tenant B's job is due while the tenant is %s", state)
		}
		if _, recorded, err := system.RecordJobSilenceAlert(ctx, f.jobB, "edge", created, now, threshold, []string{"silence-destination"}); err != nil || recorded {
			t.Errorf("silence alert for tenant B's job while the tenant is %s: recorded %v, %v", state, recorded, err)
		}
		if !due(f.jobA) {
			t.Errorf("tenant A's job is not due while tenant B is %s", state)
		}
	}
	if count := alerts(f.jobB); count != 0 {
		t.Fatalf("a paused tenant got %d silence alerts", count)
	}
	var queued int
	if err := f.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination='silence-destination'`).Scan(&queued); err != nil || queued != 0 {
		t.Fatalf("a paused tenant's silence alert was queued: %d, %v", queued, err)
	}

	setTenantState(t, f.store, secondTenantID, TenantStateActive)
	if !due(f.jobB) {
		t.Fatal("tenant B's job is not due after the tenant was enabled")
	}
	event, recorded, err := f.store.System().RecordJobSilenceAlert(ctx, f.jobB, "edge", created, now, threshold, nil)
	if err != nil || !recorded || event.JobID != f.jobB {
		t.Fatalf("silence alert after tenant B was enabled = %+v, %v, %v", event, recorded, err)
	}
	var tenant string
	if err := f.store.DB.QueryRowContext(ctx, `SELECT tenant_id FROM events WHERE type='job-silent' AND job_id=?`, f.jobB).Scan(&tenant); err != nil || tenant != secondTenantID {
		t.Fatalf("the silence alert belongs to %q, %v; want tenant B", tenant, err)
	}
}

// retentionRows lists, per table, the rows of a tenant that a retention pass
// may delete or rewrite. The cycle units carry the size of their checkpoint,
// so a cleared checkpoint shows.
func retentionRows(t *testing.T, s *Store, scope TenantScope) map[string][]string {
	t.Helper()
	rows := map[string][]string{}
	for table, query := range map[string]string{
		"scans":             `SELECT id FROM scans WHERE tenant_id=?`,
		"events":            `SELECT id||' '||type FROM events WHERE tenant_id=?`,
		"outbox":            `SELECT id||' '||destination FROM outbox WHERE tenant_id=?`,
		"job_revisions":     `SELECT r.job_id||' '||r.revision FROM job_revisions r JOIN jobs j ON j.id=r.job_id AND j.tenant_id=?`,
		"scan_cycles":       `SELECT c.id FROM scan_cycles c JOIN jobs j ON j.id=c.job_id AND j.tenant_id=?`,
		"scan_cycle_units":  `SELECT u.cycle_id||' '||u.sequence||' '||length(u.snapshot_json) FROM scan_cycle_units u JOIN scan_cycles c ON c.id=u.cycle_id JOIN jobs j ON j.id=c.job_id AND j.tenant_id=?`,
		"latest_scan_hosts": `SELECT address||' '||scan_id FROM latest_scan_hosts WHERE tenant_id=?`,
	} {
		values := queryStrings(t, s.DB, query, scope.ID())
		sort.Strings(values)
		rows[table] = values
	}
	return rows
}

// Retention leaves the history of a tenant that is being deleted to the
// purge, and keeps pruning the history of a disabled tenant, of the active
// tenant and of the platform.
func TestRetentionLeavesATenantBeingDeletedToThePurge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newCycleTenantFixture(t)
	system := f.store.System()
	// Supersede the first revision of each tenant's "edge" job, which no scan
	// uses, so retention may remove it. Each promoted cycle keeps its
	// checkpoint, as older releases left it, so retention may clear it.
	if _, err := f.store.DB.ExecContext(ctx, `UPDATE jobs SET revision=2 WHERE id IN (?,?)`, f.jobA, f.jobB); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.ExecContext(ctx, `UPDATE scan_cycle_units SET snapshot_json='{"hosts":[]}' WHERE cycle_id IN (?,?)`, cyclesOf(f, f.a).promoted, cyclesOf(f, f.b).promoted); err != nil {
		t.Fatal(err)
	}
	checkpoint := func(cycleID string) string {
		t.Helper()
		var snapshot string
		if err := f.store.DB.QueryRowContext(ctx, `SELECT snapshot_json FROM scan_cycle_units WHERE cycle_id=? AND sequence=0`, cycleID).Scan(&snapshot); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	cutoff := time.Now().UTC().Add(time.Hour)

	setTenantState(t, f.store, secondTenantID, TenantStateDeleting)
	beforeA, beforeB := retentionRows(t, f.store, f.a), retentionRows(t, f.store, f.b)
	// The checkpoint of a promoted cycle is cleared for the active tenant
	// only.
	if err := system.clearFinishedCyclePayloads(ctx); err != nil {
		t.Fatal(err)
	}
	if got := checkpoint(cyclesOf(f, f.a).promoted); got != "{}" {
		t.Errorf("tenant A's promoted checkpoint = %q, want it cleared", got)
	}
	if got := checkpoint(cyclesOf(f, f.b).promoted); got == "{}" {
		t.Error("the checkpoint of a tenant being deleted was cleared")
	}
	stats, err := system.PruneWithStats(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Scans == 0 || stats.Events == 0 || stats.FailedOutbox == 0 || stats.Revisions == 0 || stats.Cycles == 0 {
		t.Fatalf("retention stats = %+v, want every kind of history pruned", stats)
	}
	if got := retentionRows(t, f.store, f.b); !reflect.DeepEqual(got, beforeB) {
		t.Errorf("retention changed the rows of a tenant being deleted:\n got %v\nwant %v", got, beforeB)
	}
	afterA := retentionRows(t, f.store, f.a)
	for _, table := range []string{"scans", "events", "outbox", "job_revisions", "scan_cycles", "scan_cycle_units"} {
		if len(afterA[table]) >= len(beforeA[table]) {
			t.Errorf("retention kept every row of tenant A's %s: %v", table, afterA[table])
		}
	}
	var platform int
	if err := f.store.DB.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM events WHERE tenant_id IS NULL)+(SELECT COUNT(*) FROM outbox WHERE tenant_id IS NULL)`).Scan(&platform); err != nil || platform != 0 {
		t.Errorf("retention kept %d platform events and deliveries, %v", platform, err)
	}

	// A disabled tenant's history ages out like the active tenant's did.
	setTenantState(t, f.store, secondTenantID, TenantStateDisabled)
	if _, err := system.PruneWithStats(ctx, cutoff); err != nil {
		t.Fatal(err)
	}
	afterB := retentionRows(t, f.store, f.b)
	for _, table := range []string{"scans", "events", "outbox", "job_revisions", "scan_cycles", "scan_cycle_units"} {
		if len(afterB[table]) >= len(beforeB[table]) {
			t.Errorf("retention kept every row of disabled tenant B's %s: %v", table, afterB[table])
		}
	}
	for _, table := range []string{"events", "outbox"} {
		if len(afterB[table]) != 0 {
			t.Errorf("retention kept disabled tenant B's %s: %v", table, afterB[table])
		}
	}
	if want := []string{cyclesOf(f, f.b).active, cyclesOf(f, f.b).promoted}; !reflect.DeepEqual(afterB["scan_cycles"], want) {
		t.Errorf("disabled tenant B's cycles = %v, want the active cycle and the latest-success history cycle %v", afterB["scan_cycles"], want)
	}
}

// The config.yaml import names each destination within the default tenant,
// which it imports into: another tenant's destination with the same name
// takes no name from it.
func TestImportDeploymentNotificationsNamesWithinTheDefaultTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	insertSecondTenant(t, s)
	stamp := sqliteTimestamp(time.Now())
	for _, destination := range []struct{ id, tenant, name string }{
		{"00000000-0000-0000-0000-000000000b11", secondTenantID, "Deployment destination"},
		{"00000000-0000-0000-0000-000000000b12", secondTenantID, "Taken"},
		{"00000000-0000-0000-0000-000000000a11", DefaultTenantID, "Taken"},
	} {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO managed_notifications(id,tenant_id,name,provider,ciphertext,nonce,created_at,updated_at) VALUES(?,?,?,'generic',x'01',x'02',?,?)`, destination.id, destination.tenant, destination.name, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	taken := testImport(testURLDigest("taken"), "taken")
	taken.Name = "Taken"
	result, err := s.System().ImportDeploymentNotifications(ctx, []DeploymentNotificationImport{testImport(testURLDigest("free"), "free"), taken})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, imported := range result.Imported {
		names = append(names, imported.Name)
	}
	if want := []string{"Deployment destination", "Taken 2"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("imported names = %v, want %v", names, want)
	}
	var tenants int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM managed_notifications WHERE id IN ('free','taken') AND tenant_id=?`, DefaultTenantID).Scan(&tenants); err != nil || tenants != 2 {
		t.Fatalf("imported destinations in the default tenant = %d, %v; want 2", tenants, err)
	}
}

// A scan lease refuses a job whose tenant is paused or being deleted, so
// the daemon starts no scan for it, whether scheduled or manual. The other
// tenant's jobs lease as before, and the job leases again once its tenant
// is active.
func TestJobLeaseRefusesATenantThatIsNotActive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	system := f.store.System()
	expires := time.Now().UTC().Add(time.Hour)
	revision := func(jobID string) int64 {
		t.Helper()
		var revision int64
		if err := f.store.DB.QueryRowContext(ctx, `SELECT revision FROM jobs WHERE id=?`, jobID).Scan(&revision); err != nil {
			t.Fatal(err)
		}
		return revision
	}
	leases := func() int {
		t.Helper()
		var count int
		if err := f.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_leases WHERE job=?`, f.jobB).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	for _, state := range []string{TenantStateDisabled, TenantStateDeleting} {
		setTenantState(t, f.store, secondTenantID, state)
		if err := system.AcquireJobLeaseForRevision(ctx, f.jobB, "owner-b", revision(f.jobB), expires); !errors.Is(err, ErrTenantNotActive) {
			t.Errorf("lease of tenant B's job while the tenant is %s = %v, want %v", state, err, ErrTenantNotActive)
		}
		if count := leases(); count != 0 {
			t.Fatalf("a refused lease left %d rows", count)
		}
		owner := "owner-a-" + state
		if err := system.AcquireJobLeaseForRevision(ctx, f.jobA, owner, revision(f.jobA), expires); err != nil {
			t.Fatalf("lease of tenant A's job while tenant B is %s: %v", state, err)
		}
		if err := system.ReleaseJobLease(ctx, f.jobA, owner); err != nil {
			t.Fatal(err)
		}
	}
	setTenantState(t, f.store, secondTenantID, TenantStateActive)
	if err := system.AcquireJobLeaseForRevision(ctx, f.jobB, "owner-b", revision(f.jobB), expires); err != nil {
		t.Fatalf("lease of tenant B's job after the tenant was enabled: %v", err)
	}
}

// The scheduler and the silence watchdog go through the active tenants
// only: a paused tenant, one being deleted, and a deleted one are left out.
func TestActiveTenantScopesLeaveOutTenantsThatAreNotActive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	active := func() []string {
		t.Helper()
		scopes, err := f.store.System().ActiveTenantScopes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, scope := range scopes {
			ids = append(ids, scope.ID())
		}
		return ids
	}
	if got, want := active(), []string{DefaultTenantID, secondTenantID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("active tenants = %v, want %v", got, want)
	}
	for _, state := range []string{TenantStateDisabled, TenantStateDeleting, TenantStateDeleted} {
		setTenantState(t, f.store, secondTenantID, state)
		if got, want := active(), []string{DefaultTenantID}; !reflect.DeepEqual(got, want) {
			t.Errorf("active tenants with tenant B %s = %v, want %v", state, got, want)
		}
	}
	setTenantState(t, f.store, secondTenantID, TenantStateActive)
	if got, want := active(), []string{DefaultTenantID, secondTenantID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("active tenants after tenant B was enabled = %v, want %v", got, want)
	}
}
