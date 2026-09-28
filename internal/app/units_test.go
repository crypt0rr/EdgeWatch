package app

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// tenantRecord returns the tenant as the platform sees it.
func tenantRecord(t *testing.T, db *store.Store, id string) store.TenantRecord {
	t.Helper()
	record, err := db.Platform().GetTenant(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// A configuration written for the business units preview still starts, and
// startup warns that experimental.business_units is obsolete, whatever its
// value. Without the setting there is no such warning.
func TestStartupWarnsAboutTheObsoleteBusinessUnitsSetting(t *testing.T) {
	s := storetest.OpenFresh(t)
	for name, value := range map[string]*bool{"omitted": nil, "true": ptrTo(true), "false": ptrTo(false)} {
		cfg := routingTestConfig(s.Path)
		cfg.Experimental.BusinessUnits = value
		var logs bytes.Buffer
		if _, err := New(cfg, s, "missing-nmap", slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		warned := false
		for _, line := range strings.Split(logs.String(), "\n") {
			if strings.Contains(line, "level=WARN") && strings.Contains(line, "experimental.business_units") {
				warned = true
			}
		}
		if warned != (value != nil) {
			t.Fatalf("business_units %s: warned %t; logs:\n%s", name, warned, logs.String())
		}
	}
}

// A new unit is active and starts with the initial capacity of the
// deployment's limits, and it can be renamed.
func TestCreateAndRenameUnit(t *testing.T) {
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	third, err := f.app.CreateUnit(ctx, "Third", "third", store.AuditEntry{ActorKind: store.AuditActorHost})
	if err != nil || third.State != store.TenantStateActive {
		t.Fatalf("create = %+v, %v", third, err)
	}
	// The new unit starts with the initial capacity of the deployment's
	// limits: no high-cost work until a platform administrator allows it.
	scope, err := f.db.TenantScopeByID(ctx, third.ID)
	if err != nil {
		t.Fatal(err)
	}
	if capacity, err := f.db.Tenant(scope).Capacity(ctx); err != nil || !reflect.DeepEqual(capacity, store.InitialTenantCapacity(f.app.capacityLimits())) {
		t.Fatalf("a new unit's capacity = %+v, %v; want %+v", capacity, err, store.InitialTenantCapacity(f.app.capacityLimits()))
	}
	if renamed, err := f.app.RenameUnit(ctx, third.ID, third.Revision, "Gamma", "gamma", store.AuditEntry{ActorKind: store.AuditActorHost}); err != nil || renamed.Slug != "gamma" {
		t.Fatalf("rename = %+v, %v", renamed, err)
	}
}

// Disabling a unit ends its sessions and invitations, fails its run that
// waits for a scan slot, cancels its running scan, which is recorded as
// canceled and leaves the baseline alone, and removes its jobs from the
// schedule. The default unit's queued run takes the freed slot and
// completes, and its accounts and schedule are untouched.
func TestDisableUnitPausesTheUnitsWork(t *testing.T) {
	ctx := context.Background()
	sc := gatedScanner{started: make(chan string, 2), finish: make(chan struct{})}
	f := newTwoTenants(t, sc, lifecycleJob)
	b := f.db.Tenant(f.b)
	second, err := b.CreateJob(ctx, lifecycleJob("edge-2"))
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	for _, account := range []struct{ id, tenant string }{{"00000000-0000-0000-0000-00000000aa01", store.DefaultTenantID}, {"00000000-0000-0000-0000-00000000bb01", secondTenantID}} {
		for _, statement := range []string{
			`INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,created_at,updated_at) VALUES(?1,?2,?1,?1,'operator','hash',?3,?3)`,
			`INSERT INTO sessions(id_hash,user_id,created_at,last_seen_at,expires_at,csrf_token) VALUES('session-' || ?1,?1,?3,?3,?4,'csrf')`,
			`INSERT INTO user_invites(id_hash,user_id,issuer_user_id,created_at,expires_at,used_at) VALUES('invite-' || ?1,?1,'',?3,?4,NULL)`,
		} {
			if _, err := f.db.DB.ExecContext(ctx, statement, account.id, account.tenant, stamp, expires); err != nil {
				t.Fatal(err)
			}
		}
	}
	runCtx, _ := f.app.BeginRun(ctx)
	defer f.app.StopRun()
	f.startSchedules(t, runCtx)
	if !f.scheduled(f.jobA.ID) || !f.scheduled(f.jobB.ID) || !f.scheduled(second.ID) {
		t.Fatalf("scheduled jobs before the pause = %v", f.app.entries)
	}

	type outcome struct {
		scan model.Scan
		err  error
	}
	run := func(record store.JobRecord) chan outcome {
		done := make(chan outcome, 1)
		go func() {
			scan, _, err := f.app.RunJobRecord(ctx, record)
			done <- outcome{scan, err}
		}()
		return done
	}
	runningB := run(f.jobB)
	select {
	case <-sc.started:
	case <-time.After(10 * time.Second):
		t.Fatal("tenant B's scan did not start")
	}
	queuedB := run(second)
	waitForSlotQueue(t, f.app, 1)
	queuedA := run(f.jobA)
	waitForSlotQueue(t, f.app, 2)

	disabled, err := f.app.DisableUnit(ctx, secondTenantID, tenantRecord(t, f.db, secondTenantID).Revision, store.AuditEntry{ActorKind: store.AuditActorHost})
	if err != nil || disabled.State != store.TenantStateDisabled {
		t.Fatalf("disable tenant B = %+v, %v", disabled, err)
	}
	if got := <-queuedB; !errors.Is(got.err, store.ErrTenantNotActive) || got.scan.ID != "" {
		t.Fatalf("tenant B's queued run = %+v, want %v", got, store.ErrTenantNotActive)
	}
	canceled := <-runningB
	if canceled.scan.Status != "canceled" || !errors.Is(canceled.err, context.Canceled) {
		t.Fatalf("tenant B's running scan = %+v", canceled)
	}
	select {
	case <-sc.started:
	case <-time.After(10 * time.Second):
		t.Fatal("tenant A's queued run did not start after tenant B's scan was cancelled")
	}
	sc.finish <- struct{}{}
	if got := <-queuedA; got.err != nil || got.scan.Status != "success" {
		t.Fatalf("tenant A's run = %+v", got)
	}

	scans, err := b.ListJobScans(ctx, f.jobB.ID, 10)
	if err != nil || len(scans) != 1 || scans[0].Status != "canceled" {
		t.Fatalf("tenant B's scans = %+v, %v", scans, err)
	}
	if state, err := b.RuntimeState(ctx, f.jobB.ID); err != nil || state.Baseline != nil || state.CandidateCount != 0 {
		t.Fatalf("the cancelled scan changed tenant B's runtime state: %+v, %v", state, err)
	}
	if state, err := f.db.Tenant(f.a).RuntimeState(ctx, f.jobA.ID); err != nil || state.Baseline == nil {
		t.Fatalf("tenant A's run did not set its baseline: %+v, %v", state, err)
	}
	for tenant, want := range map[string][2]int{store.DefaultTenantID: {1, 1}, secondTenantID: {0, 0}} {
		var sessions, invites int
		if err := f.db.DB.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM sessions WHERE user_id IN (SELECT id FROM users WHERE tenant_id=?1)),(SELECT COUNT(*) FROM user_invites WHERE used_at IS NULL AND user_id IN (SELECT id FROM users WHERE tenant_id=?1))`, tenant).Scan(&sessions, &invites); err != nil {
			t.Fatal(err)
		}
		if got := [2]int{sessions, invites}; got != want {
			t.Errorf("tenant %s: sessions and outstanding invitations = %v, want %v", tenant, got, want)
		}
	}

	// The schedule follows at the daemon's next reconciliation, which the
	// pause requested.
	select {
	case <-f.app.scheduleWake:
	default:
		t.Fatal("disabling a unit did not wake the scheduler")
	}
	if err := f.app.reconcileSchedules(runCtx, false); err != nil {
		t.Fatal(err)
	}
	if !f.scheduled(f.jobA.ID) || f.scheduled(f.jobB.ID) || f.scheduled(second.ID) {
		t.Fatalf("scheduled jobs after the pause = %v, want only tenant A's", f.app.entries)
	}
}

// A run registers after its scan lease. When its unit was paused in between,
// the pause could not see the run, so the run is cancelled as it registers;
// a run of another unit is not.
func TestRegisterRunCancelsARunOfAPausedUnit(t *testing.T) {
	a := &App{}
	a.pauseUnit(secondTenantID)
	paused, cancelPaused := context.WithCancel(context.Background())
	defer cancelPaused()
	other, cancelOther := context.WithCancel(context.Background())
	defer cancelOther()
	pausedRun := &activeRun{cancel: cancelPaused}
	otherRun := &activeRun{cancel: cancelOther}
	a.registerRun(secondTenantID, "scan-b", pausedRun)
	a.registerRun(store.DefaultTenantID, "scan-a", otherRun)
	if paused.Err() == nil || pausedRun.snapshot().Phase != "cancelling" {
		t.Fatal("a run of a paused unit was not cancelled when it registered")
	}
	if other.Err() != nil {
		t.Fatal("a run of another unit was cancelled")
	}
	if got := len(a.ActiveScans(store.DefaultTenantScope())); got != 1 {
		t.Fatalf("the default unit's active scans = %d, want its run", got)
	}
}

// Enabling a unit returns its jobs to the schedule, and the silence
// watchdog judges them from the moment the unit was enabled. The default
// unit's job, silent for as long, alerts; the re-enabled unit's does not.
func TestEnableUnitResumesTheUnitWithoutASilenceAlert(t *testing.T) {
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	old := time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	for _, statement := range []string{`UPDATE jobs SET created_at=?`, `UPDATE job_silence_state SET eligible_at=?`} {
		if _, err := f.db.DB.ExecContext(ctx, statement, old); err != nil {
			t.Fatal(err)
		}
	}
	for _, record := range []*store.JobRecord{&f.jobA, &f.jobB} {
		reloaded, err := f.db.Tenant(store.DefaultTenantScope()).GetJob(ctx, record.ID)
		if err != nil {
			reloaded, err = f.db.Tenant(f.b).GetJob(ctx, record.ID)
		}
		if err != nil {
			t.Fatal(err)
		}
		*record = reloaded
	}
	silenceAlerts := func(jobID string) int {
		t.Helper()
		var n int
		if err := f.db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE type='job-silent' AND job_id=?`, jobID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	runCtx, _ := f.app.BeginRun(ctx)
	defer f.app.StopRun()
	f.startSchedules(t, runCtx)

	disabled, err := f.app.DisableUnit(ctx, secondTenantID, tenantRecord(t, f.db, secondTenantID).Revision, store.AuditEntry{ActorKind: store.AuditActorHost})
	if err != nil {
		t.Fatal(err)
	}
	f.app.checkJobSilence(ctx, time.Now())
	if silenceAlerts(f.jobA.ID) != 1 || silenceAlerts(f.jobB.ID) != 0 {
		t.Fatalf("silence alerts while tenant B is paused: A %d, B %d; want 1 and 0", silenceAlerts(f.jobA.ID), silenceAlerts(f.jobB.ID))
	}
	if err := f.app.reconcileSchedules(runCtx, false); err != nil {
		t.Fatal(err)
	}
	if f.scheduled(f.jobB.ID) {
		t.Fatal("a paused unit's job is scheduled")
	}

	enabled, err := f.app.EnableUnit(ctx, secondTenantID, disabled.Revision, store.AuditEntry{ActorKind: store.AuditActorHost})
	if err != nil || enabled.State != store.TenantStateActive {
		t.Fatalf("enable tenant B = %+v, %v", enabled, err)
	}
	select {
	case <-f.app.scheduleWake:
	default:
		t.Fatal("enabling a unit did not wake the scheduler")
	}
	if err := f.app.reconcileSchedules(runCtx, false); err != nil {
		t.Fatal(err)
	}
	if !f.scheduled(f.jobB.ID) || !f.scheduled(f.jobA.ID) {
		t.Fatalf("scheduled jobs after tenant B was enabled = %v", f.app.entries)
	}
	f.app.checkJobSilence(ctx, time.Now())
	if silenceAlerts(f.jobB.ID) != 0 {
		t.Fatal("tenant B's job raised a silence alert right after the unit was enabled")
	}
	// A run of the enabled unit is not cancelled as it registers.
	f.fireSchedule(t, f.jobB.ID)
	scans, err := f.db.Tenant(f.b).ListJobScans(ctx, f.jobB.ID, 10)
	if err != nil || len(scans) != 1 || scans[0].Status != "success" {
		t.Fatalf("tenant B's scans after it was enabled = %+v, %v", scans, err)
	}
	if _, err := f.app.EnableUnit(ctx, secondTenantID, enabled.Revision, store.AuditEntry{}); !errors.Is(err, store.ErrTenantStateChange) {
		t.Fatalf("enable an active unit = %v", err)
	}
	if _, err := f.app.DisableUnit(ctx, secondTenantID, enabled.Revision+1, store.AuditEntry{}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("disable with a stale revision = %v", err)
	}
}

// A purge pass logs each unit it worked on, by ID and counts, and a pass
// that fails is logged for the next one to resume. Wakes coalesce.
func TestPurgeDeletedUnitsLogsEachPass(t *testing.T) {
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	var logs bytes.Buffer
	f.app.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	disabled, err := f.app.DisableUnit(ctx, secondTenantID, tenantRecord(t, f.db, secondTenantID).Revision, store.AuditEntry{ActorKind: store.AuditActorHost})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.RequestUnitDeletion(ctx, secondTenantID, disabled.Name, store.AuditEntry{ActorKind: store.AuditActorHost}); err != nil {
		t.Fatal(err)
	}
	f.app.wakeUnitPurge()
	f.app.wakeUnitPurge()
	if queued := len(f.app.units.purgeWakeChannel()); queued != 1 {
		t.Fatalf("queued purge wakes = %d, want 1", queued)
	}
	if _, err := f.db.DB.ExecContext(ctx, `INSERT INTO job_leases(job,owner,expires_at) VALUES(?,'scan',?)`, f.jobB.ID, time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	f.app.purgeDeletedUnits(ctx)
	if !strings.Contains(logs.String(), "tenant_id="+secondTenantID) || !strings.Contains(logs.String(), "deferred=true") || tenantRecord(t, f.db, secondTenantID).State != store.TenantStateDeleting {
		t.Fatalf("a pass held back by a live lease logged %q", logs.String())
	}
	if _, err := f.db.DB.ExecContext(ctx, `DELETE FROM job_leases`); err != nil {
		t.Fatal(err)
	}
	f.app.purgeDeletedUnits(ctx)
	if !strings.Contains(logs.String(), "complete=true") || tenantRecord(t, f.db, secondTenantID).State != store.TenantStateDeleted {
		t.Fatalf("a complete pass logged %q", logs.String())
	}

	// A pass over a database that fails is logged, here through the
	// default logger of an application without one.
	closed := storetest.OpenFresh(t)
	_ = closed.Close()
	previous := slog.Default()
	defer slog.SetDefault(previous)
	logs.Reset()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	(&App{Store: closed}).purgeDeletedUnits(ctx)
	if !strings.Contains(logs.String(), "business unit purge stopped") {
		t.Fatalf("a failed pass logged %q", logs.String())
	}
}

// While a reader of the database, such as a running backup, keeps the purge
// from truncating the write-ahead log, a pass logs the unit's maintenance as
// pending and warns about the reader, and the unit stays deleting. The next
// pass without the reader finishes the purge.
func TestPurgeDeletedUnitsWarnsWhileAReaderKeepsTheLog(t *testing.T) {
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	var logs bytes.Buffer
	f.app.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	disabled, err := f.app.DisableUnit(ctx, secondTenantID, tenantRecord(t, f.db, secondTenantID).Revision, store.AuditEntry{ActorKind: store.AuditActorHost})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.RequestUnitDeletion(ctx, secondTenantID, disabled.Name, store.AuditEntry{ActorKind: store.AuditActorHost}); err != nil {
		t.Fatal(err)
	}
	// The checkpoint waits for the busy timeout of the one writer
	// connection before it gives up.
	if _, err := f.db.DB.ExecContext(ctx, `PRAGMA busy_timeout=200`); err != nil {
		t.Fatal(err)
	}
	reader, err := f.db.ReadDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Rollback() }()
	var units int
	if err := reader.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants`).Scan(&units); err != nil {
		t.Fatal(err)
	}

	f.app.purgeDeletedUnits(ctx)
	if !strings.Contains(logs.String(), "maintenance_pending=true") || !strings.Contains(logs.String(), "kept the business unit purge from truncating the write-ahead log") || tenantRecord(t, f.db, secondTenantID).State != store.TenantStateDeleting {
		t.Fatalf("a pass whose checkpoint a reader kept busy logged %q", logs.String())
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	logs.Reset()
	f.app.purgeDeletedUnits(ctx)
	if !strings.Contains(logs.String(), "complete=true") || !strings.Contains(logs.String(), "maintenance_pending=false") || strings.Contains(logs.String(), "write-ahead log") || tenantRecord(t, f.db, secondTenantID).State != store.TenantStateDeleted {
		t.Fatalf("the next pass logged %q", logs.String())
	}
}

// Deleting a disabled unit wakes the daemon's purge worker, which erases the
// unit and leaves a tombstone, while the default unit keeps its job.
func TestRequestUnitDeletionPurgesTheUnit(t *testing.T) {
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	workerCtx, stop := context.WithCancel(ctx)
	done := f.app.startUnitPurgeWorker(workerCtx)
	defer func() {
		stop()
		<-done
	}()
	if _, err := f.app.RequestUnitDeletion(ctx, secondTenantID, "Second", store.AuditEntry{ActorKind: store.AuditActorHost}); !errors.Is(err, store.ErrTenantStateChange) {
		t.Fatalf("delete an active unit = %v", err)
	}
	if _, err := f.app.RequestUnitDeletion(ctx, store.DefaultTenantID, "Default", store.AuditEntry{}); !errors.Is(err, store.ErrDefaultTenantDeletion) {
		t.Fatalf("delete the default unit = %v", err)
	}
	disabled, err := f.app.DisableUnit(ctx, secondTenantID, tenantRecord(t, f.db, secondTenantID).Revision, store.AuditEntry{ActorKind: store.AuditActorHost})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.RequestUnitDeletion(ctx, secondTenantID, "second", store.AuditEntry{ActorKind: store.AuditActorHost}); !errors.Is(err, store.ErrTenantNameMismatch) {
		t.Fatalf("delete with a mistyped name = %v", err)
	}
	deleting, err := f.app.RequestUnitDeletion(ctx, secondTenantID, disabled.Name, store.AuditEntry{ActorKind: store.AuditActorHost})
	if err != nil || deleting.State != store.TenantStateDeleting {
		t.Fatalf("delete tenant B = %+v, %v", deleting, err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for tenantRecord(t, f.db, secondTenantID).State != store.TenantStateDeleted {
		if time.Now().After(deadline) {
			t.Fatalf("the purge worker did not erase tenant B: %+v", tenantRecord(t, f.db, secondTenantID))
		}
		time.Sleep(10 * time.Millisecond)
	}
	var jobsB int
	if err := f.db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE tenant_id=?`, secondTenantID).Scan(&jobsB); err != nil || jobsB != 0 {
		t.Fatalf("tenant B has %d jobs after the purge: %v", jobsB, err)
	}
	if _, err := f.db.Tenant(f.a).GetJob(ctx, f.jobA.ID); err != nil {
		t.Fatalf("the purge erased the default unit's job: %v", err)
	}
}
