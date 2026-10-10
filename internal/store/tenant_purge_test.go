package store

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// tenantPurgeOracle selects the rowids of a tenant's rows, with the tenant's
// ID as ?1, in every table that holds tenant data. The tests use it to check
// the purge, so it is written apart from tenantPurgeSteps. The FTS5 tables
// share the rowids of the rows they index.
var tenantPurgeOracle = map[string]string{
	"events":                           `SELECT rowid FROM events WHERE tenant_id=?1`,
	"jobs":                             `SELECT rowid FROM jobs WHERE tenant_id=?1`,
	"job_history_purge_host_keys":      `SELECT rowid FROM job_history_purge_host_keys WHERE tenant_id=?1`,
	"job_history_purges":               `SELECT rowid FROM job_history_purges WHERE tenant_id=?1`,
	"latest_scan_hosts":                `SELECT rowid FROM latest_scan_hosts WHERE tenant_id=?1`,
	"managed_notifications":            `SELECT rowid FROM managed_notifications WHERE tenant_id=?1`,
	"outbox":                           `SELECT rowid FROM outbox WHERE tenant_id=?1`,
	"public_dashboards":                `SELECT rowid FROM public_dashboards WHERE tenant_id=?1`,
	"restore_quarantined_deliveries":   `SELECT rowid FROM restore_quarantined_deliveries WHERE tenant_id=?1`,
	"scanner_profiles":                 `SELECT rowid FROM scanner_profiles WHERE tenant_id=?1`,
	"scans":                            `SELECT rowid FROM scans WHERE tenant_id=?1`,
	"security_alert_windows":           `SELECT rowid FROM security_alert_windows WHERE tenant_id=?1`,
	"security_audit":                   `SELECT rowid FROM security_audit WHERE tenant_id=?1`,
	"users":                            `SELECT rowid FROM users WHERE tenant_id=?1`,
	"baseline_hosts":                   `SELECT x.rowid FROM baseline_hosts AS x JOIN jobs AS j ON j.id=x.job_id WHERE j.tenant_id=?1`,
	"job_revisions":                    `SELECT x.rowid FROM job_revisions AS x JOIN jobs AS j ON j.id=x.job_id WHERE j.tenant_id=?1`,
	"job_runtime":                      `SELECT x.rowid FROM job_runtime AS x JOIN jobs AS j ON j.id=x.job_id WHERE j.tenant_id=?1`,
	"job_runtime_meta":                 `SELECT x.rowid FROM job_runtime_meta AS x JOIN jobs AS j ON j.id=x.job_id WHERE j.tenant_id=?1`,
	"job_silence_state":                `SELECT x.rowid FROM job_silence_state AS x JOIN jobs AS j ON j.id=x.job_id WHERE j.tenant_id=?1`,
	"public_dashboard_hosts":           `SELECT x.rowid FROM public_dashboard_hosts AS x JOIN public_dashboards AS d ON d.id=x.dashboard_id WHERE d.tenant_id=?1`,
	"runtime_incidents":                `SELECT x.rowid FROM runtime_incidents AS x JOIN jobs AS j ON j.id=x.job_id WHERE j.tenant_id=?1`,
	"scan_cycles":                      `SELECT x.rowid FROM scan_cycles AS x JOIN jobs AS j ON j.id=x.job_id WHERE j.tenant_id=?1`,
	"legacy_scan_host_backfill":        `SELECT x.rowid FROM legacy_scan_host_backfill AS x JOIN scans AS s ON s.id=x.scan_id WHERE s.tenant_id=?1`,
	"scan_cycle_discovery_checkpoints": `SELECT x.rowid FROM scan_cycle_discovery_checkpoints AS x JOIN scan_cycles AS c ON c.id=x.cycle_id JOIN jobs AS j ON j.id=c.job_id WHERE j.tenant_id=?1`,
	"scan_cycle_units":                 `SELECT x.rowid FROM scan_cycle_units AS x JOIN scan_cycles AS c ON c.id=x.cycle_id JOIN jobs AS j ON j.id=c.job_id WHERE j.tenant_id=?1`,
	"scan_hosts":                       `SELECT x.rowid FROM scan_hosts AS x JOIN scans AS s ON s.id=x.scan_id WHERE s.tenant_id=?1`,
	"recovery_codes":                   `SELECT x.rowid FROM recovery_codes AS x JOIN users AS u ON u.id=x.user_id WHERE u.tenant_id=?1`,
	"sessions":                         `SELECT x.rowid FROM sessions AS x JOIN users AS u ON u.id=x.user_id WHERE u.tenant_id=?1`,
	"totp_replay":                      `SELECT x.rowid FROM totp_replay AS x JOIN users AS u ON u.id=x.user_id WHERE u.tenant_id=?1`,
	"user_invites":                     `SELECT x.rowid FROM user_invites AS x JOIN users AS u ON u.id=x.user_id WHERE u.tenant_id=?1`,
	"notification_delivery_health":     `SELECT x.rowid FROM notification_delivery_health AS x JOIN managed_notifications AS m ON x.destination_identity='managed:' || m.id WHERE m.tenant_id=?1`,
	"scanner_profile_revisions":        `SELECT x.rowid FROM scanner_profile_revisions AS x JOIN scanner_profiles AS p ON p.id=x.profile_id WHERE p.tenant_id=?1`,
	"baseline_host_search":             `SELECT x.rowid FROM baseline_hosts AS x JOIN jobs AS j ON j.id=x.job_id WHERE j.tenant_id=?1`,
	"latest_host_search":               `SELECT rowid FROM latest_scan_hosts WHERE tenant_id=?1`,
	"scan_host_search":                 `SELECT x.rowid FROM scan_hosts AS x JOIN scans AS s ON s.id=x.scan_id WHERE s.tenant_id=?1`,
}

// tenantDataTables returns every table that tenancyTables classifies as
// direct or via, sorted.
func tenantDataTables() []string {
	var tables []string
	for table, tenancy := range tenancyTables {
		if tenancy.tenantData() {
			tables = append(tables, table)
		}
	}
	sort.Strings(tables)
	return tables
}

// Every table that holds tenant data has exactly one purge step, and the
// steps erase children before their parents. A step deletes by the tenant
// predicate, except for an FTS5 table, whose rows its parent's AFTER DELETE
// trigger removes; that trigger must exist and delete from the table.
func TestTenantPurgeCoversTheRegistry(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	position := map[string]int{}
	for i, step := range tenantPurgeSteps {
		if _, duplicate := position[step.table]; duplicate {
			t.Errorf("%s has two purge steps", step.table)
		}
		position[step.table] = i
		tenancy, classified := tenancyTables[step.table]
		switch {
		case !classified || !tenancy.tenantData():
			t.Errorf("the purge step for %s names a table that tenancyTables does not classify as direct or via (%s)", step.table, tenancy)
		case (step.rowids == "") == (step.trigger == ""):
			t.Errorf("the purge step for %s needs either a rowids query or a trigger", step.table)
		case step.rowids != "" && !strings.Contains(step.rowids, "tenant_id=?1"):
			t.Errorf("the purge step for %s does not select by tenant_id=?1: %s", step.table, step.rowids)
		}
		if step.trigger != "" {
			var definition string
			err := s.DB.QueryRow(`SELECT sql FROM sqlite_master WHERE type='trigger' AND name=? AND tbl_name=?`, step.trigger, tenancy.parent).Scan(&definition)
			if err != nil || !strings.Contains(definition, "AFTER DELETE ON "+tenancy.parent) || !strings.Contains(definition, "DELETE FROM "+step.table+" WHERE rowid=OLD.rowid") {
				t.Errorf("the rows of %s are not removed with its parent %s by trigger %s: %q, %v", step.table, tenancy.parent, step.trigger, definition, err)
			}
		}
	}
	for _, table := range tenantDataTables() {
		if _, ok := position[table]; !ok {
			t.Errorf("%s holds tenant data but has no step in tenantPurgeSteps (internal/store/tenant_purge.go); a deleted tenant's rows would stay behind", table)
		}
		if _, ok := tenantPurgeOracle[table]; !ok {
			t.Errorf("%s holds tenant data but has no query in tenantPurgeOracle, so the purge tests do not check it", table)
		}
	}
	for table, i := range position {
		tenancy := tenancyTables[table]
		if tenancy.class != tenancyVia || tenantPurgeSteps[i].trigger != "" {
			continue
		}
		if parent, ok := position[tenancy.parent]; ok && parent < i {
			t.Errorf("%s is purged after its parent %s, so deleting the parent would cascade to it", table, tenancy.parent)
		}
	}
}

// addTenantPurgeRows gives both tenants of the fixture a row in each table
// that the fixture leaves empty, so the purge has something to erase, and to
// keep, in every table: a public status page with a host, a legacy host
// backfill marker, a quarantined delivery, a discovery checkpoint, delivery
// health, a TOTP step, and audit records of a tenant action and of a
// platform administrator's action.
func addTenantPurgeRows(t *testing.T, f tenantFixture) {
	t.Helper()
	ctx := context.Background()
	stamp := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	for _, owner := range []struct {
		scope                           TenantScope
		job, scan, account, destination string
	}{
		{f.a, f.jobA, f.scanA, accountAdminA, tenantFixtureNotifications.a},
		{f.b, f.jobB, f.scanB, accountAdminB, tenantFixtureNotifications.b},
	} {
		tenant := owner.scope.ID()
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO public_dashboards(tenant_id,enabled,title,introduction,updated_at) SELECT ?1,1,'status','',?2 WHERE NOT EXISTS (SELECT 1 FROM public_dashboards WHERE tenant_id=?1)`, []any{tenant, stamp}},
			{`INSERT INTO public_dashboard_hosts(dashboard_id,job_id,address,created_at) SELECT id,?2,'192.0.2.10',?3 FROM public_dashboards WHERE tenant_id=?1`, []any{tenant, owner.job, stamp}},
			{`INSERT INTO legacy_scan_host_backfill(scan_id,processed_at) VALUES(?,?)`, []any{owner.scan, stamp}},
			{`INSERT INTO restore_quarantined_deliveries(restore_epoch,destination,payload_json,quarantined_at,tenant_id) VALUES('epoch',?,'{}',?,?)`, []any{"managed:" + owner.destination + ":1", stamp, tenant}},
			{`INSERT INTO scan_cycle_discovery_checkpoints(cycle_id,sequence,processed_at) VALUES(?,0,?)`, []any{cyclesOf(f, owner.scope).active, stamp}},
			{`INSERT INTO notification_delivery_health(destination_identity,updated_at) VALUES(?,?)`, []any{"managed:" + owner.destination, stamp}},
			{`INSERT INTO totp_replay(user_id,last_step,updated_at) VALUES(?,1,?)`, []any{owner.account, stamp}},
			{`INSERT INTO job_history_purges(tenant_id,job_id,phase,created_at,updated_at) VALUES(?,?,?,?,?)`, []any{tenant, owner.job, jobPurgePhaseCycleCheckpoints, stamp, stamp}},
			{`INSERT INTO job_history_purge_host_keys(tenant_id,job_id,address) VALUES(?,?,?)`, []any{tenant, owner.job, "192.0.2.10"}},
			{`INSERT INTO security_alert_windows(tenant_id,kind,started_at,suppressed) VALUES(?,'rate_limited',?,2)`, []any{tenant, stamp}},
		} {
			if _, err := f.store.DB.ExecContext(ctx, statement.query, statement.args...); err != nil {
				t.Fatalf("%s: %v", statement.query, err)
			}
		}
		ts := f.store.Tenant(owner.scope)
		if err := ts.AuditEntry(ctx, AuditEntry{Action: "job.updated", ActorUserID: owner.account}); err != nil {
			t.Fatal(err)
		}
		if err := ts.AuditEntry(ctx, AuditEntry{Action: "user.password_reset", ActorUserID: platformAdminID, ActorKind: AuditActorPlatform}); err != nil {
			t.Fatal(err)
		}
	}
}

// newTenantPurgeFixture returns the cycle fixture with addTenantPurgeRows,
// in which tenant B has rows in every table that holds tenant data.
func newTenantPurgeFixture(t *testing.T) tenantFixture {
	t.Helper()
	f := newCycleTenantFixture(t)
	insertTenantUser(t, f.store, platformAdminID, nil, RolePlatformAdmin)
	addTenantPurgeRows(t, f)
	return f
}

// requestSecondTenantDeletion disables tenant B and requests its deletion.
func requestSecondTenantDeletion(t *testing.T, f tenantFixture) {
	t.Helper()
	ctx := context.Background()
	b, err := f.store.Platform().GetTenant(ctx, secondTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Platform().DisableTenant(ctx, secondTenantID, b.Revision, AuditEntry{ActorUserID: platformAdminID}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Platform().RequestTenantDeletion(ctx, secondTenantID, b.Name, AuditEntry{ActorUserID: platformAdminID}); err != nil {
		t.Fatal(err)
	}
}

// rowids returns the rowids that query selects, sorted.
func rowids(t *testing.T, s *Store, query string, args ...any) []int64 {
	t.Helper()
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(ids)
	return ids
}

// tenantPurgeSnapshot holds, for every table that holds tenant data, the
// rowids of tenant B's rows and of all rows.
type tenantPurgeSnapshot struct{ b, all map[string][]int64 }

func takeTenantPurgeSnapshot(t *testing.T, s *Store) tenantPurgeSnapshot {
	t.Helper()
	snapshot := tenantPurgeSnapshot{b: map[string][]int64{}, all: map[string][]int64{}}
	for _, table := range tenantDataTables() {
		snapshot.b[table] = rowids(t, s, tenantPurgeOracle[table], secondTenantID)
		snapshot.all[table] = rowids(t, s, `SELECT rowid FROM `+table)
	}
	return snapshot
}

// tenantPurgeErasable counts the rows the purge erases for tenant B: every
// row of B except its platform administrators' audit records, and apart from
// the search indexes, whose rows go with the rows they index.
func tenantPurgeErasable(t *testing.T, s *Store) int64 {
	t.Helper()
	var total int64
	for _, step := range tenantPurgeSteps {
		if step.trigger != "" {
			continue
		}
		total += int64(len(rowids(t, s, tenantPurgeOracle[step.table], secondTenantID)))
	}
	return total - int64(len(rowids(t, s, `SELECT rowid FROM security_audit WHERE tenant_id=? AND actor_kind='platform'`, secondTenantID)))
}

// without returns the ids that are not in removed.
func without(ids, removed []int64) []int64 {
	var kept []int64
	for _, id := range ids {
		if !slices.Contains(removed, id) {
			kept = append(kept, id)
		}
	}
	return kept
}

// The purge erases every row of tenant B in every table that holds tenant
// data, search index rows included, with secure_delete on for each batch.
// Every other row stays, and so do B's platform administrator audit records
// and B's row in tenants, now a deleted tombstone whose name and slug are
// free again. The purge is recorded in the platform audit.
func TestTenantPurgeErasesOnlyTheDeletedTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	before := takeTenantPurgeSnapshot(t, f.store)
	for _, table := range tenantDataTables() {
		if len(before.b[table]) == 0 {
			t.Errorf("tenant B has no row in %s; add one to the fixture so the purge is checked there", table)
		}
		if len(without(before.all[table], before.b[table])) == 0 {
			t.Errorf("only tenant B has rows in %s; add another tenant's row so the purge is shown to keep it", table)
		}
	}
	keptAudit := rowids(t, f.store, `SELECT rowid FROM security_audit WHERE tenant_id=? AND actor_kind='platform'`, secondTenantID)
	if len(keptAudit) == 0 {
		t.Fatal("tenant B has no audit record of a platform administrator's action")
	}
	requestSecondTenantDeletion(t, f)
	erasable := tenantPurgeErasable(t, f.store)

	batches := 0
	results, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: 2, afterBatch: func(ctx context.Context, conn *sql.Conn, phase string) error {
		batches++
		var secure int
		if err := conn.QueryRowContext(ctx, `PRAGMA secure_delete`).Scan(&secure); err != nil {
			return err
		}
		if secure != 1 {
			t.Errorf("secure_delete is %d while the purge erases %s", secure, phase)
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].Complete || results[0].TenantID != secondTenantID || results[0].TotalRows != erasable || results[0].Rows != erasable || results[0].MaintenancePending || results[0].CheckpointBusy {
		t.Fatalf("purge results = %+v, want tenant B complete with %d rows", results, erasable)
	}
	if batches < len(tenantPurgeSteps) {
		t.Fatalf("the purge ran %d batches for %d steps", batches, len(tenantPurgeSteps))
	}
	var secure int
	if err := f.store.DB.QueryRow(`PRAGMA secure_delete`).Scan(&secure); err != nil || secure != 0 {
		t.Fatalf("the writer connection kept secure_delete %d after the purge: %v", secure, err)
	}

	for _, table := range tenantDataTables() {
		after := rowids(t, f.store, `SELECT rowid FROM `+table)
		want := without(before.all[table], before.b[table])
		if table == "security_audit" {
			want = append(want, keptAudit...)
			slices.Sort(want)
			// The lifecycle records of the platform are the only new rows.
			added := without(after, before.all[table])
			var foreign int
			if err := f.store.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE rowid IN (`+strings.Repeat("?,", len(added))+`0) AND (tenant_id IS NOT NULL OR action NOT LIKE 'tenant.%')`, int64sAsAny(added)...).Scan(&foreign); err != nil || foreign != 0 {
				t.Fatalf("the purge added %d audit records that are not platform lifecycle records: %v", foreign, err)
			}
			after = without(after, added)
		}
		if !slices.Equal(after, want) {
			t.Errorf("%s: rowids after the purge = %v, want %v (tenant B's %v erased)", table, after, want, before.b[table])
		}
	}
	for index, parent := range map[string]string{"scan_host_search": "scan_hosts", "latest_host_search": "latest_scan_hosts", "baseline_host_search": "baseline_hosts"} {
		var orphans int
		if err := f.store.DB.QueryRow(`SELECT COUNT(*) FROM ` + index + ` WHERE rowid NOT IN (SELECT rowid FROM ` + parent + `)`).Scan(&orphans); err != nil || orphans != 0 {
			t.Errorf("%s has %d rows without a %s row: %v", index, orphans, parent, err)
		}
		if _, err := f.store.DB.Exec(`INSERT INTO ` + index + `(` + index + `) VALUES('integrity-check')`); err != nil {
			t.Errorf("%s fails its integrity check after the purge: %v", index, err)
		}
	}
	assertForeignKeysClean(t, f.store.DB)

	tombstone, err := f.store.Platform().GetTenant(ctx, secondTenantID)
	if err != nil || tombstone.State != TenantStateDeleted || tombstone.PurgePhase != tenantPurgePhaseComplete || tombstone.PurgeRows != erasable || tombstone.StateChangedBy != AuditActorSystem || tombstone.Accounts+tombstone.Jobs != 0 {
		t.Fatalf("tombstone = %+v, %v", tombstone, err)
	}
	var routing string
	if err := f.store.DB.QueryRow(`SELECT update_destinations_json FROM tenants WHERE id=?`, secondTenantID).Scan(&routing); err != nil || routing != "" {
		t.Fatalf("the tombstone kept update routing %q: %v", routing, err)
	}
	if _, err := f.store.TenantScopeByID(ctx, secondTenantID); !errors.Is(err, ErrNoTenantScope) {
		t.Fatalf("the tombstone lends a scope: %v", err)
	}
	if got := lastPlatformAudit(t, f.store, "tenant.purged"); got.tenant != "<null>" || got.kind != AuditActorSystem || got.category != auditCategoryPlatform || !strings.Contains(got.detail, "platform audit records kept") {
		t.Fatalf("purge audit = %+v", got)
	}
	if records, err := f.store.Platform().ListTenants(ctx); err != nil || len(records) != 1 || records[0].ID != DefaultTenantID {
		t.Fatalf("tenants after the purge = %+v, %v", records, err)
	}
	if _, err := f.store.Platform().CreateTenant(ctx, "Second", "second", AuditEntry{}); err != nil {
		t.Fatalf("reuse the purged tenant's name and slug: %v", err)
	}
	// Nothing is left to purge.
	if results, err := f.store.System().PurgeDeletingTenants(ctx); err != nil || len(results) != 0 {
		t.Fatalf("a second pass = %+v, %v", results, err)
	}
}

func int64sAsAny(values []int64) []any {
	out := make([]any, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

// A purge that is interrupted resumes at the step it reached, and counts
// each erased row once.
func TestTenantPurgeResumesAfterInterruption(t *testing.T) {
	t.Parallel()
	f := newTenantPurgeFixture(t)
	requestSecondTenantDeletion(t, f)
	erasable := tenantPurgeErasable(t, f.store)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	batches := 0
	results, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: 1, afterBatch: func(context.Context, *sql.Conn, string) error {
		if batches++; batches == 40 {
			cancel()
		}
		return nil
	}})
	if !errors.Is(err, context.Canceled) || len(results) != 1 || results[0].Complete {
		t.Fatalf("interrupted purge = %+v, %v", results, err)
	}
	interrupted, err := f.store.Platform().GetTenant(context.Background(), secondTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if interrupted.State != TenantStateDeleting || interrupted.PurgePhase == "" || interrupted.PurgePhase == tenantPurgeSteps[0].table || interrupted.PurgeRows == 0 || interrupted.PurgeRows != results[0].TotalRows || interrupted.PurgeRows >= erasable {
		t.Fatalf("progress after the interruption = %+v (result %+v), want part of %d rows", interrupted, results[0], erasable)
	}

	var resumedAt string
	results, err = f.store.System().purgeDeletingTenants(context.Background(), tenantPurgeOptions{batchSize: 3, afterBatch: func(_ context.Context, _ *sql.Conn, phase string) error {
		if resumedAt == "" {
			resumedAt = phase
		}
		return nil
	}})
	if err != nil || len(results) != 1 || !results[0].Complete {
		t.Fatalf("resumed purge = %+v, %v", results, err)
	}
	if resumedAt != interrupted.PurgePhase {
		t.Fatalf("the purge resumed at %s, want %s where it stopped", resumedAt, interrupted.PurgePhase)
	}
	if results[0].TotalRows != erasable || results[0].Rows != erasable-interrupted.PurgeRows {
		t.Fatalf("resumed purge counted %d rows in total and %d in this pass, want %d and %d", results[0].TotalRows, results[0].Rows, erasable, erasable-interrupted.PurgeRows)
	}
}

// The purge erases a tenant's host rows and backfill checkpoints before its
// scans, so a purge that stops in between leaves scans that look like scans
// of a release before the host index. A start whose legacy host backfill is
// pending, after an upgrade from before schema 66 or a scan saved with units
// only, leaves them to the purge: indexing one would write a latest host of
// a tenant that is being deleted, which the guard triggers refuse, so every
// start would fail and the purge, which only the daemon runs, would never
// finish. Another tenant's legacy scans are still indexed.
func TestLegacyHostBackfillLeavesTheScansOfADeletingTenantToThePurge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	// The fixture's history purge of each tenant's "edge" job keeps that
	// job's scans from the backfill, so these scans of the archived jobs are
	// the ones that show it. Each has host rows until it is rewound or
	// purged.
	finished := time.Date(2026, 9, 20, 14, 0, 0, 0, time.UTC)
	for _, scan := range []model.Scan{
		fixtureScan("scan-legacy-a", f.archivedA, "edge-archived", finished, fixtureHosts(0, 2)),
		fixtureScan("scan-deleting-b-1", f.archivedB, "edge-archived", finished, fixtureHosts(0, 2)),
		fixtureScan("scan-deleting-b-2", f.archivedB, "edge-archived", finished.Add(time.Hour), fixtureHosts(2, 4)),
	} {
		if err := f.store.System().SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	requestSecondTenantDeletion(t, f)
	stop := errors.New("stop in the scans step")
	if _, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: 1, afterBatch: func(_ context.Context, _ *sql.Conn, phase string) error {
		if phase == "scans" {
			return stop
		}
		return nil
	}}); !errors.Is(err, stop) {
		t.Fatalf("purge = %v, want it stopped in the scans step", err)
	}
	if stopped, err := f.store.Platform().GetTenant(ctx, secondTenantID); err != nil || stopped.State != TenantStateDeleting || stopped.PurgePhase != "scans" {
		t.Fatalf("tenant B after the stopped purge = %+v, %v", stopped, err)
	}
	const unindexedOfB = `SELECT COUNT(*) FROM scans s WHERE s.tenant_id=? AND s.status='success'
  AND NOT EXISTS (SELECT 1 FROM scan_hosts h WHERE h.scan_id=s.id)
  AND NOT EXISTS (SELECT 1 FROM legacy_scan_host_backfill b WHERE b.scan_id=s.id)
  AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=s.tenant_id AND purge.job_id=s.job_id)`
	if got := countRows(t, f.store.DB, unindexedOfB, secondTenantID); got == 0 {
		t.Fatal("the stopped purge left no scan of tenant B without host rows or a checkpoint; the test shows nothing")
	}
	rewindToLegacyScans(t, f.store.DB, "scan-legacy-a")
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := Open(f.store.Path)
	if err != nil {
		t.Fatalf("start with a pending legacy host backfill while tenant B's purge is stopped in its scans step: %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if got := legacyScanHostIndexMarker(t, restarted.DB); got != 1 {
		t.Fatalf("legacy host index checkpoint after the start = %d, want complete", got)
	}
	if got := countRows(t, restarted.DB, `SELECT COUNT(*) FROM scan_hosts WHERE scan_id='scan-legacy-a' AND data_quality='legacy'`); got != 2 {
		t.Fatalf("tenant A's legacy scan has %d indexed host rows, want 2", got)
	}
	for _, query := range []string{
		`SELECT COUNT(*) FROM scan_hosts AS h JOIN scans AS s ON s.id=h.scan_id WHERE s.tenant_id=?`,
		`SELECT COUNT(*) FROM latest_scan_hosts WHERE tenant_id=?`,
		`SELECT COUNT(*) FROM legacy_scan_host_backfill AS b JOIN scans AS s ON s.id=b.scan_id WHERE s.tenant_id=?`,
	} {
		if got := countRows(t, restarted.DB, query, secondTenantID); got != 0 {
			t.Fatalf("the start indexed tenant B's scans: %s = %d", query, got)
		}
	}
	// With the marker pending again, neither the backfill nor the Hosts
	// view finds tenant B's scans.
	if _, err := restarted.DB.ExecContext(ctx, pendingLegacyScanHostIndexSQL); err != nil {
		t.Fatal(err)
	}
	if total, err := countLegacyHostBackfillCandidates(ctx, restarted.DB); err != nil || total != 0 {
		t.Fatalf("legacy host backfill candidates = %d, %v; want none", total, err)
	}
	deleting := restarted.Tenant(f.b)
	if exists, err := deleting.LegacySuccessfulScanExists(ctx); err != nil || exists {
		t.Fatalf("tenant B's legacy successful scan = %v, %v; want none", exists, err)
	}
	if page, err := deleting.ListLegacySuccessfulScanSnapshotsPage(ctx, 50, 0); err != nil || page.Total != 0 || len(page.Items) != 0 {
		t.Fatalf("tenant B's legacy snapshots = %+v, %v; want none", page, err)
	}

	results, err := restarted.System().PurgeDeletingTenants(ctx)
	if err != nil || len(results) != 1 || !results[0].Complete || results[0].Phase != tenantPurgePhaseComplete {
		t.Fatalf("purge after the start = %+v, %v; want tenant B complete", results, err)
	}
	if got := countRows(t, restarted.DB, `SELECT COUNT(*) FROM scans WHERE tenant_id=?`, secondTenantID); got != 0 {
		t.Fatalf("tenant B has %d scans left after its purge", got)
	}
}

// A tenant being deleted reports the scans that the purge has not erased
// yet: the count holds until the purge reaches the scans, falls with each
// batch there, and is zero on the tombstone. Tenant A's count is unchanged.
func TestTenantPurgeLowersTheStoredScanCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	a, err := f.store.Platform().GetTenant(ctx, DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	requestSecondTenantDeletion(t, f)
	deleting, err := f.store.Platform().GetTenant(ctx, secondTenantID)
	if err != nil {
		t.Fatal(err)
	}
	stored := deleting.StoredScans
	if deleting.State != TenantStateDeleting || stored < 2 || int(stored) != len(rowids(t, f.store, `SELECT rowid FROM scans WHERE tenant_id=?`, secondTenantID)) {
		t.Fatalf("tenant B being deleted = %+v; want every one of its scans, at least two, still counted", deleting)
	}

	stepOf := func(table string) int {
		return slices.IndexFunc(tenantPurgeSteps, func(step tenantPurgeStep) bool { return step.table == table })
	}
	var falling []int64
	results, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: 1, afterBatch: func(ctx context.Context, conn *sql.Conn, phase string) error {
		// The batch has committed; the purge connection reads the record
		// as the platform console would between two batches.
		record, err := getTenantRecord(ctx, conn, secondTenantID)
		if err != nil {
			return err
		}
		switch step := stepOf(phase); {
		case step < stepOf("scans") && record.StoredScans != stored:
			t.Errorf("after a batch of %s tenant B reports %d stored scans, want all %d", phase, record.StoredScans, stored)
		case phase == "scans":
			falling = append(falling, record.StoredScans)
		case step > stepOf("scans") && record.StoredScans != 0:
			t.Errorf("after a batch of %s tenant B reports %d stored scans, want none", phase, record.StoredScans)
		}
		return nil
	}})
	if err != nil || len(results) != 1 || !results[0].Complete {
		t.Fatalf("purge = %+v, %v", results, err)
	}
	// One scan per batch, then the batch that finds none left.
	want := make([]int64, 0, stored+1)
	for remaining := stored - 1; remaining >= 0; remaining-- {
		want = append(want, remaining)
	}
	want = append(want, 0)
	if !slices.Equal(falling, want) {
		t.Fatalf("stored scans after each batch of the scans step = %v, want %v", falling, want)
	}
	tombstone, err := f.store.Platform().GetTenant(ctx, secondTenantID)
	if err != nil || tombstone.State != TenantStateDeleted || tombstone.StoredScans != 0 {
		t.Fatalf("tombstone = %+v, %v", tombstone, err)
	}
	if after, err := f.store.Platform().GetTenant(ctx, DefaultTenantID); err != nil || after.StoredScans != a.StoredScans || a.StoredScans == 0 {
		t.Fatalf("tenant A's stored scans went from %d to %d: %v", a.StoredScans, after.StoredScans, err)
	}
}

// While a job of the tenant holds a live scan lease the purge leaves the
// tenant alone, and it proceeds once the lease has expired.
func TestTenantPurgeWaitsForLiveLeases(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	requestSecondTenantDeletion(t, f)
	if _, err := f.store.DB.Exec(`INSERT INTO job_leases(job,owner,expires_at) VALUES(?,'daemon/scan',?)`, f.jobB, sqliteTimestamp(time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	results, err := f.store.System().PurgeDeletingTenants(ctx)
	if err != nil || len(results) != 1 || !results[0].Deferred || results[0].Rows != 0 || results[0].Complete {
		t.Fatalf("purge with a live lease = %+v, %v", results, err)
	}
	if jobs := rowids(t, f.store, tenantPurgeOracle["jobs"], secondTenantID); len(jobs) != 2 {
		t.Fatalf("the purge erased jobs while a scan held a lease: %v", jobs)
	}
	if _, err := f.store.DB.Exec(`UPDATE job_leases SET expires_at=? WHERE job=?`, sqliteTimestamp(time.Now().Add(-time.Minute)), f.jobB); err != nil {
		t.Fatal(err)
	}
	results, err = f.store.System().PurgeDeletingTenants(ctx)
	if err != nil || len(results) != 1 || !results[0].Complete {
		t.Fatalf("purge after the lease expired = %+v, %v", results, err)
	}
	if leases := rowids(t, f.store, `SELECT rowid FROM job_leases WHERE job=?`, f.jobB); len(leases) != 0 {
		t.Fatalf("the purge left the expired lease of an erased job: %v", leases)
	}
}

// The default tenant is never purged, even in the deleting state, which no
// product path can give it.
func TestTenantPurgeNeverErasesTheDefaultTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	before := takeTenantPurgeSnapshot(t, f.store)
	setTenantState(t, f.store, DefaultTenantID, TenantStateDeleting)
	results, err := f.store.System().PurgeDeletingTenants(ctx)
	if err != nil || len(results) != 0 {
		t.Fatalf("purge with the default tenant deleting = %+v, %v", results, err)
	}
	if after := takeTenantPurgeSnapshot(t, f.store); !slices.Equal(after.all["jobs"], before.all["jobs"]) || !slices.Equal(after.all["users"], before.all["users"]) {
		t.Fatal("the purge erased the default tenant's rows")
	}
}

// When rows of the tenant remain after the last step, the purge starts over
// on the next pass instead of making a tombstone that hides them. A phase
// that names no step, such as a step that a later release removed, gets the
// same check.
func TestTenantPurgeStartsOverWhenRowsRemain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	requestSecondTenantDeletion(t, f)
	for _, phase := range []string{tenantPurgePhaseVerify, "retired_table"} {
		if _, err := f.store.DB.Exec(`UPDATE tenants SET purge_phase=? WHERE id=?`, phase, secondTenantID); err != nil {
			t.Fatal(err)
		}
		results, err := f.store.System().PurgeDeletingTenants(ctx)
		if err == nil || !strings.Contains(err.Error(), "remain after the last step") || len(results) != 1 || results[0].Complete || results[0].Phase != tenantPurgeSteps[0].table {
			t.Fatalf("purge from phase %s = %+v, %v", phase, results, err)
		}
		if record, err := f.store.Platform().GetTenant(ctx, secondTenantID); err != nil || record.State != TenantStateDeleting || record.PurgePhase != tenantPurgeSteps[0].table {
			t.Fatalf("tenant after the purge from phase %s found rows = %+v, %v", phase, record, err)
		}
	}
	results, err := f.store.System().PurgeDeletingTenants(ctx)
	if err != nil || len(results) != 1 || !results[0].Complete {
		t.Fatalf("the next pass = %+v, %v", results, err)
	}
	if rows := rowids(t, f.store, tenantPurgeOracle["jobs"], secondTenantID); len(rows) != 0 {
		t.Fatalf("tenant B's jobs after the purge: %v", rows)
	}
}

// A purge stops when its tenant leaves the deleting state between batches,
// which no product path does, and a pass over a tenant that is not being
// deleted, such as one another pass just finished, does nothing.
func TestTenantPurgeStopsWhenTheTenantIsNoLongerBeingDeleted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	requestSecondTenantDeletion(t, f)
	results, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: 1, afterBatch: func(ctx context.Context, conn *sql.Conn, _ string) error {
		_, err := conn.ExecContext(ctx, `UPDATE tenants SET state=? WHERE id=?`, TenantStateDisabled, secondTenantID)
		return err
	}})
	if !errors.Is(err, ErrConflict) || len(results) != 1 || results[0].Complete || results[0].TotalRows != 1 {
		t.Fatalf("purge of a tenant that left the deleting state = %+v, %v", results, err)
	}
	result, err := f.store.System().purgeTenant(ctx, secondTenantID, tenantPurgeOptions{batchSize: 1})
	if err != nil || result.Complete || result.Rows != 0 {
		t.Fatalf("purge pass over a disabled tenant = %+v, %v", result, err)
	}
	if jobs := rowids(t, f.store, tenantPurgeOracle["jobs"], secondTenantID); len(jobs) != 2 {
		t.Fatalf("tenant B's jobs = %v, want both kept", jobs)
	}
}
