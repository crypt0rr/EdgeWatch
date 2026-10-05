package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
	"github.com/robfig/cron/v3"
)

// defaultTenant returns the store of the default tenant, which owns every
// job, destination and scan that a test creates without naming a tenant.
func defaultTenant(s *store.Store) *store.TenantStore {
	return s.Tenant(store.DefaultTenantScope())
}

// secondTenantID is the tenant that the tests below add in SQL, because no
// product API creates a tenant yet.
const secondTenantID = "00000000-0000-0000-0000-000000000200"

// twoTenants is an application whose database has a second tenant, B, next
// to the default tenant, A. Each tenant has an enabled web-managed
// destination with the same name and a job with the same name, and A also
// has the deployment destination from config.yaml. Both jobs keep the legacy
// nil notification selection.
type twoTenants struct {
	app                        *App
	db                         *store.Store
	a, b                       store.TenantScope
	jobA, jobB                 store.JobRecord
	destinationA, destinationB string
}

func newTwoTenants(t *testing.T, sc Scanner, job func(name string) config.Job) twoTenants {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Second','second',?,?)`, secondTenantID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour),
		Scheduler:     config.Scheduler{MaxConcurrent: 1},
		Web:           config.Web{Listen: "127.0.0.1:8080"},
		Notifications: config.Notifications{URLs: []string{"generic://127.0.0.1:9/deployment?disabletls=yes&template=json"}},
	}
	a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Scanner = sc
	b, err := db.TenantScopeByID(ctx, secondTenantID)
	if err != nil {
		t.Fatal(err)
	}
	f := twoTenants{app: a, db: db, a: store.DefaultTenantScope(), b: b}
	// The destinations come first: adding a destination freezes the nil
	// selection of the tenant's existing jobs.
	for _, tenant := range []struct {
		scope       store.TenantScope
		destination *string
		job         *store.JobRecord
	}{{f.a, &f.destinationA, &f.jobA}, {f.b, &f.destinationB, &f.jobB}} {
		ts := db.Tenant(tenant.scope)
		destination, err := a.Notifier.Tenant(ts).CreateManagedWithAudit(ctx, "Operations", "generic://127.0.0.1:9/"+tenant.scope.ID()+"?disabletls=yes&template=json", true, store.AuditEntry{Action: "notifications.created"})
		if err != nil {
			t.Fatal(err)
		}
		*tenant.destination = destination.ID
		if *tenant.job, err = ts.CreateJob(ctx, job("edge")); err != nil {
			t.Fatal(err)
		}
		if tenant.job.Job.NotificationDestinations != nil {
			t.Fatalf("the job's notification selection = %v, want the legacy nil selection", tenant.job.Job.NotificationDestinations)
		}
	}
	return f
}

// startSchedules installs a stopped cron in the application and reconciles
// the schedules, as the daemon does at startup. A job that runs on start is
// started; the test waits for it with a.wg.
func (f twoTenants) startSchedules(t *testing.T, ctx context.Context) {
	t.Helper()
	f.app.scheduleMu.Lock()
	f.app.cron = cron.New(cron.WithParser(cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)))
	f.app.scheduleMu.Unlock()
	if err := f.app.reconcileSchedules(ctx, true); err != nil {
		t.Fatal(err)
	}
}

// fireSchedule runs a job's cron entry as the cron would at its next
// scheduled time and waits for the run to finish.
func (f twoTenants) fireSchedule(t *testing.T, jobID string) {
	t.Helper()
	f.app.scheduleMu.Lock()
	entry, scheduled := f.app.entries[jobID]
	c := f.app.cron
	f.app.scheduleMu.Unlock()
	if !scheduled {
		t.Fatalf("job %s is not scheduled", jobID)
	}
	c.Entry(entry).WrappedJob.Run()
	f.app.wg.Wait()
}

func (f twoTenants) scheduled(jobID string) bool {
	f.app.scheduleMu.Lock()
	defer f.app.scheduleMu.Unlock()
	_, ok := f.app.entries[jobID]
	return ok
}

// twoUnitScanner plans two work units for every job. The first attempt at
// the second unit fails with a transient error, so a job's first run pauses
// its scan cycle and its next run completes the cycle.
type twoUnitScanner struct {
	mu     sync.Mutex
	failed map[string]bool
}

func (s *twoUnitScanner) Version(context.Context) string { return "two-unit" }
func (s *twoUnitScanner) Scan(context.Context, config.Job) (model.Snapshot, error) {
	return model.Snapshot{}, errors.New("ordinary scan path should not be used")
}
func (s *twoUnitScanner) Plan(context.Context, config.Job) (scanner.WorkPlan, error) {
	target := []scanner.ResolvedTarget{{Name: "192.0.2.1", ConfiguredTarget: "192.0.2.1", Addresses: []string{"192.0.2.1"}}}
	return scanner.WorkPlan{CreatedAt: time.Now().UTC(), Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-2"}}, Units: []scanner.WorkUnit{
		{Sequence: 0, Protocol: "tcp", Family: 4, Targets: target, Addresses: []string{"192.0.2.1"}, Ports: "1", PortCount: 1, Probes: 1},
		{Sequence: 1, Protocol: "tcp", Family: 4, Targets: target, Addresses: []string{"192.0.2.1"}, Ports: "2", PortCount: 1, Probes: 1},
	}, TotalUnits: 2, TotalProbes: 2}, nil
}
func (s *twoUnitScanner) ScanWorkUnit(_ context.Context, job config.Job, unit scanner.WorkUnit, _ scanner.ProgressReporter) (model.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed == nil {
		s.failed = map[string]bool{}
	}
	if unit.Sequence == 1 && !s.failed[job.Name] {
		s.failed[job.Name] = true
		return model.Snapshot{}, errors.New("connection reset by peer")
	}
	return model.Snapshot{Units: []model.Unit{{Target: "192.0.2.1", Protocol: unit.Protocol, Addresses: unit.Addresses, Ports: []model.PortState{{Port: unit.PortCount, State: "open"}}}}}, nil
}

func runOnStartJob(name string) config.Job {
	job := lifecycleJob(name)
	runOnStart := true
	job.RunOnStart = &runOnStart
	return job
}

// jobRows lists, per table, the tenant of each row that belongs to a job:
// its scans, scan cycles, events and deliveries.
func jobRows(t *testing.T, db *store.Store, jobID string) map[string][]string {
	t.Helper()
	rows := map[string][]string{}
	for table, query := range map[string]string{
		"scans":    `SELECT tenant_id FROM scans WHERE job_id=? ORDER BY started_at`,
		"cycles":   `SELECT j.tenant_id FROM scan_cycles AS c JOIN jobs AS j ON j.id=c.job_id WHERE c.job_id=? ORDER BY c.started_at`,
		"events":   `SELECT COALESCE(tenant_id,'') || ' ' || type FROM events WHERE job_id=? ORDER BY id`,
		"outbox":   `SELECT COALESCE(tenant_id,'') || ' ' || destination FROM outbox WHERE json_extract(CAST(payload_json AS TEXT),'$.job_id')=? ORDER BY id`,
		"runtimes": `SELECT j.tenant_id FROM job_runtime AS r JOIN jobs AS j ON j.id=r.job_id WHERE r.job_id=?`,
	} {
		if values := queryStrings(t, db, query, jobID); len(values) > 0 {
			rows[table] = values
		}
	}
	return rows
}

// queryStrings returns the single text column of every row that query
// selects.
func queryStrings(t *testing.T, db *store.Store, query string, args ...any) []string {
	t.Helper()
	result, err := db.DB.Query(query, args...)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	defer result.Close()
	var values []string
	for result.Next() {
		var value string
		if err := result.Scan(&value); err != nil {
			t.Fatal(err)
		}
		values = append(values, value)
	}
	if err := result.Err(); err != nil {
		t.Fatal(err)
	}
	return values
}

// The daemon schedules and runs a second tenant's job through that tenant's
// store: its scans, scan cycle, runtime state, events and deliveries all
// belong to the tenant, and an alert of its legacy nil selection goes to the
// tenant's own destination, never to the default tenant's. The default
// tenant's job with the same name is scheduled and alerts as before.
func TestDaemonRunsASecondTenantsJobInThatTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTwoTenants(t, &twoUnitScanner{}, lifecycleJob)
	// Only tenant B's job runs on start.
	b := f.db.Tenant(f.b)
	updated := f.jobB.Job
	runOnStart := true
	updated.RunOnStart = &runOnStart
	jobB, _, err := b.UpdateJob(ctx, f.jobB.ID, f.jobB.Revision, updated, true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, _ := f.app.BeginRun(ctx)
	defer f.app.StopRun()

	// Startup: both tenants' jobs are scheduled, and B's job runs. Its
	// second unit fails, so the run pauses the cycle and alerts.
	f.startSchedules(t, runCtx)
	f.app.wg.Wait()
	if !f.scheduled(f.jobA.ID) || !f.scheduled(jobB.ID) {
		t.Fatalf("scheduled jobs = %v, want tenant A's and tenant B's", f.app.entries)
	}
	cycle, err := b.GetActiveScanCycle(ctx, jobB.ID)
	if err != nil || cycle.Status != "paused" || cycle.CompletedUnits != 1 {
		t.Fatalf("tenant B's cycle after the first run = %+v, %v", cycle, err)
	}
	// The next scheduled run completes the cycle and sets B's baseline.
	f.fireSchedule(t, jobB.ID)
	state, err := b.RuntimeState(ctx, jobB.ID)
	if err != nil || state.Baseline == nil {
		t.Fatalf("tenant B's runtime state = %+v, %v", state, err)
	}
	scans, err := b.ListJobScans(ctx, jobB.ID, 10)
	if err != nil || len(scans) != 2 || scans[0].Status != "success" || scans[1].Status != "failed" {
		t.Fatalf("tenant B's scans = %+v, %v", scans, err)
	}

	own := secondTenantID + " managed:" + f.destinationB + ":1"
	want := map[string][]string{
		"scans":    {secondTenantID, secondTenantID},
		"cycles":   {secondTenantID},
		"events":   {secondTenantID + " scan-paused", secondTenantID + " baseline-complete", secondTenantID + " scan-recovered"},
		"outbox":   {own, own, own},
		"runtimes": {secondTenantID},
	}
	if got := jobRows(t, f.db, jobB.ID); !reflect.DeepEqual(got, want) {
		t.Fatalf("tenant B's job rows = %v, want %v", got, want)
	}
	// Tenant A cannot see B's rows.
	a := f.db.Tenant(f.a)
	if state, err := a.RuntimeState(ctx, jobB.ID); err != nil || state.Baseline != nil {
		t.Fatalf("tenant A reads tenant B's runtime state: %+v, %v", state, err)
	}
	if _, err := a.GetLatestScanCycle(ctx, jobB.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("tenant A reads tenant B's scan cycle: %v", err)
	}

	// Tenant A's job ran nothing so far, and nothing reached its destinations.
	if got := jobRows(t, f.db, f.jobA.ID); len(got) != 0 {
		t.Fatalf("tenant A's job rows before its own run = %v", got)
	}
	// A's own scheduled run alerts A's destinations only: its managed
	// destination and the deployment destination, never B's.
	f.fireSchedule(t, f.jobA.ID)
	rows := jobRows(t, f.db, f.jobA.ID)
	if !slices.Equal(rows["events"], []string{store.DefaultTenantID + " baseline-complete"}) {
		t.Fatalf("tenant A's events = %v", rows["events"])
	}
	destinations := slices.Clone(rows["outbox"])
	sort.Strings(destinations)
	legacy, err := f.app.Notifier.Tenant(a).QueueDestinationsForSelection(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wantA []string
	for _, destination := range legacy {
		wantA = append(wantA, store.DefaultTenantID+" "+destination)
	}
	sort.Strings(wantA)
	if len(wantA) != 2 || !slices.Contains(wantA, store.DefaultTenantID+" managed:"+f.destinationA+":1") || !slices.Equal(destinations, wantA) {
		t.Fatalf("tenant A's deliveries = %v, want %v", destinations, wantA)
	}
	if got := jobRows(t, f.db, jobB.ID); !reflect.DeepEqual(got, want) {
		t.Fatalf("tenant A's run changed tenant B's rows: %v", got)
	}
}

// A paused tenant's jobs are not scheduled, and a manual run is refused at
// the scan lease, so no scan starts. Once the tenant is active again, the
// next reconciliation schedules its jobs and they run.
func TestDaemonPausesADisabledTenantsJobs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, runOnStartJob)
	setState := func(state string) {
		t.Helper()
		if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET state=? WHERE id=?`, state, secondTenantID); err != nil {
			t.Fatal(err)
		}
	}
	scanCount := func(ts *store.TenantStore, jobID string) int {
		t.Helper()
		scans, err := ts.ListJobScans(ctx, jobID, 10)
		if err != nil {
			t.Fatal(err)
		}
		return len(scans)
	}
	a, b := f.db.Tenant(f.a), f.db.Tenant(f.b)
	runCtx, _ := f.app.BeginRun(ctx)
	defer f.app.StopRun()

	setState(store.TenantStateDisabled)
	f.startSchedules(t, runCtx)
	f.app.wg.Wait()
	if f.scheduled(f.jobB.ID) || !f.scheduled(f.jobA.ID) {
		t.Fatalf("scheduled jobs with tenant B paused = %v, want only tenant A's", f.app.entries)
	}
	if scanCount(a, f.jobA.ID) != 1 || scanCount(b, f.jobB.ID) != 0 {
		t.Fatalf("runs on start with tenant B paused: tenant A %d, tenant B %d; want 1 and 0", scanCount(a, f.jobA.ID), scanCount(b, f.jobB.ID))
	}

	// A manual run, from the host CLI or the console, is refused at the lease.
	if scan, _, err := f.app.RunJobRecord(ctx, f.jobB); !errors.Is(err, store.ErrTenantNotActive) || scan.ID != "" {
		t.Fatalf("manual run of a paused tenant's job = %+v, %v; want %v", scan, err, store.ErrTenantNotActive)
	}
	done := make(chan error, 1)
	if err := f.app.StartManagedRun(b, f.jobB.ID, func(_ model.Scan, _ []model.Event, err error) { done <- err }); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, store.ErrTenantNotActive) {
		t.Fatalf("console run of a paused tenant's job = %v, want %v", err, store.ErrTenantNotActive)
	}
	if active, err := b.JobActive(ctx, f.jobB.ID); err != nil || active {
		t.Fatalf("a refused run left a scan lease: %v, %v", active, err)
	}
	if got := scanCount(b, f.jobB.ID); got != 0 {
		t.Fatalf("a paused tenant's job has %d scans", got)
	}

	// A tenant being deleted is not scheduled either.
	setState(store.TenantStateDeleting)
	if err := f.app.reconcileSchedules(runCtx, false); err != nil {
		t.Fatal(err)
	}
	if f.scheduled(f.jobB.ID) {
		t.Fatal("a tenant being deleted has scheduled jobs")
	}

	setState(store.TenantStateActive)
	if err := f.app.reconcileSchedules(runCtx, false); err != nil {
		t.Fatal(err)
	}
	if !f.scheduled(f.jobB.ID) || !f.scheduled(f.jobA.ID) {
		t.Fatalf("scheduled jobs after tenant B was enabled = %v", f.app.entries)
	}
	f.fireSchedule(t, f.jobB.ID)
	if got := scanCount(b, f.jobB.ID); got != 1 {
		t.Fatalf("tenant B's scans after it was enabled = %d, want 1", got)
	}

	// A tenant paused after its jobs were scheduled starts no scan when the
	// schedule fires before the next reconciliation.
	setState(store.TenantStateDisabled)
	f.fireSchedule(t, f.jobB.ID)
	if got := scanCount(b, f.jobB.ID); got != 1 {
		t.Fatalf("tenant B's scans after a scheduled run while paused = %d, want 1", got)
	}
}

// A run takes its scan slot under its job's tenant's ID, so tenants queue
// separately for the deployment's slots.
func TestScanSlotsAreKeyedByTheJobsTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sc := gatedScanner{started: make(chan string, 2), finish: make(chan struct{})}
	f := newTwoTenants(t, sc, lifecycleJob)
	doneB, doneA := make(chan error, 1), make(chan error, 1)
	go func() {
		_, _, err := f.app.RunJobRecord(ctx, f.jobB)
		doneB <- err
	}()
	select {
	case <-sc.started:
	case err := <-doneB:
		t.Fatalf("tenant B's run returned before it scanned: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("tenant B's run did not start")
	}
	go func() {
		_, _, err := f.app.RunJobRecord(ctx, f.jobA)
		doneA <- err
	}()
	waitForSlotQueue(t, f.app, 1)
	want := slotSnapshot{Capacity: 1, InUse: 1, Queued: 1, Keys: map[string]slotUsage{
		secondTenantID:        {InUse: 1, Limit: 1},
		store.DefaultTenantID: {Queued: 1, Limit: 1},
	}}
	if got := f.app.slots.CapacitySnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("slots while tenant B scans = %#v, want %#v", got, want)
	}
	sc.finish <- struct{}{}
	if err := <-doneB; err != nil {
		t.Fatalf("tenant B's run: %v", err)
	}
	select {
	case <-sc.started:
	case <-time.After(10 * time.Second):
		t.Fatal("tenant A's run did not start")
	}
	sc.finish <- struct{}{}
	if err := <-doneA; err != nil {
		t.Fatalf("tenant A's run: %v", err)
	}
}

// A run takes its tenant from the job record, so a record that names no
// tenant, or a deleted one, runs nothing.
func TestRunRefusesAJobRecordWithoutATenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	orphan := f.jobB
	orphan.TenantID = ""
	if scan, _, err := f.app.RunJobRecord(ctx, orphan); !errors.Is(err, store.ErrNoTenantScope) || scan.ID != "" {
		t.Fatalf("run of a record without a tenant = %+v, %v; want %v", scan, err, store.ErrNoTenantScope)
	}
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET state=? WHERE id=?`, store.TenantStateDeleted, secondTenantID); err != nil {
		t.Fatal(err)
	}
	if scan, _, err := f.app.RunJobRecord(ctx, f.jobB); !errors.Is(err, store.ErrNoTenantScope) || scan.ID != "" {
		t.Fatalf("run of a deleted tenant's job = %+v, %v; want %v", scan, err, store.ErrNoTenantScope)
	}
	if got := queryStrings(t, f.db, `SELECT id FROM scans WHERE job_id=?`, f.jobB.ID); len(got) != 0 {
		t.Fatalf("refused runs persisted scans: %v", got)
	}
}
