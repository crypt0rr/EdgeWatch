package app

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func ptrTo[T any](value T) *T { return &value }

// newCapacityTenants is newTwoTenants with the given number of deployment
// scan slots.
func newCapacityTenants(t *testing.T, sc Scanner, slots int) twoTenants {
	t.Helper()
	f := newTwoTenants(t, sc, lifecycleJob)
	f.app.Config.Scheduler.MaxConcurrent = slots
	f.app.slots.SetCapacity(slots, nil)
	return f
}

func (f twoTenants) setCapacity(t *testing.T, scope store.TenantScope, capacity store.TenantCapacity) {
	t.Helper()
	if err := f.app.SetTenantCapacity(context.Background(), scope.ID(), capacity, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
}

// probeJob is a job of one address whose TCP scan sends one Nmap probe per
// port in 1-ports.
func probeJob(name string, ports int, allowHighCost bool) config.Job {
	job := lifecycleJob(name)
	job.TCP.Ports = "1-" + strconv.Itoa(ports)
	job.AllowHighCost = allowHighCost
	return job
}

// namedGateScanner holds each scan until the test finishes its job by name.
type namedGateScanner struct {
	started chan string
	mu      sync.Mutex
	gates   map[string]chan struct{}
}

func newNamedGateScanner() *namedGateScanner {
	return &namedGateScanner{started: make(chan string, 8), gates: map[string]chan struct{}{}}
}

func (s *namedGateScanner) gate(name string) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gates[name] == nil {
		s.gates[name] = make(chan struct{})
	}
	return s.gates[name]
}

func (s *namedGateScanner) Version(context.Context) string { return "named-gate" }

func (s *namedGateScanner) Scan(ctx context.Context, job config.Job) (model.Snapshot, error) {
	s.started <- job.Name
	select {
	case <-s.gate(job.Name):
		return model.Snapshot{}, nil
	case <-ctx.Done():
		return model.Snapshot{}, ctx.Err()
	}
}

func (s *namedGateScanner) awaitStart(t *testing.T, want string) {
	t.Helper()
	select {
	case got := <-s.started:
		if got != want {
			t.Fatalf("started %s, want %s", got, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not start", want)
	}
}

func (s *namedGateScanner) assertNothingStarted(t *testing.T) {
	t.Helper()
	select {
	case got := <-s.started:
		t.Fatalf("%s started while it should wait for a slot", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func startRun(ctx context.Context, a *App, record store.JobRecord) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, _, err := a.RunJobRecord(ctx, record)
		done <- err
	}()
	return done
}

func awaitRun(t *testing.T, label string, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not finish", label)
	}
}

func assertSlots(t *testing.T, a *App, want slotSnapshot) {
	t.Helper()
	if got := a.slots.CapacitySnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("slots = %#v, want %#v", got, want)
	}
}

// With two deployment slots and tenant B capped at one, B's second job waits
// while a slot is free, and tenant A's job takes that slot. Raising B's cap
// grants B's waiting job at once.
func TestTenantSlotCapHoldsBackOnlyThatTenant(t *testing.T) {
	ctx := context.Background()
	sc := newNamedGateScanner()
	f := newCapacityTenants(t, sc, 2)
	create := func(scope store.TenantScope, name string) store.JobRecord {
		t.Helper()
		record, err := f.db.Tenant(scope).CreateJob(ctx, lifecycleJob(name))
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	firstB, secondB, onlyA := create(f.b, "b-first"), create(f.b, "b-second"), create(f.a, "a-only")
	f.setCapacity(t, f.b, store.TenantCapacity{MaxConcurrentScans: ptrTo(1)})

	doneFirstB := startRun(ctx, f.app, firstB)
	sc.awaitStart(t, "b-first")
	doneSecondB := startRun(ctx, f.app, secondB)
	waitForSlotQueue(t, f.app, 1)
	sc.assertNothingStarted(t)
	assertSlots(t, f.app, slotSnapshot{Capacity: 2, InUse: 1, Queued: 1, Keys: map[string]slotUsage{
		secondTenantID: {InUse: 1, Queued: 1, Limit: 1},
	}})

	doneA := startRun(ctx, f.app, onlyA)
	sc.awaitStart(t, "a-only")
	assertSlots(t, f.app, slotSnapshot{Capacity: 2, InUse: 2, Queued: 1, Keys: map[string]slotUsage{
		secondTenantID:        {InUse: 1, Queued: 1, Limit: 1},
		store.DefaultTenantID: {InUse: 1, Limit: 2},
	}})
	close(sc.gate("a-only"))
	awaitRun(t, "tenant A's run", doneA)
	// A's slot is free again, and B is still at its cap.
	sc.assertNothingStarted(t)
	assertSlots(t, f.app, slotSnapshot{Capacity: 2, InUse: 1, Queued: 1, Keys: map[string]slotUsage{
		secondTenantID: {InUse: 1, Queued: 1, Limit: 1},
	}})

	f.setCapacity(t, f.b, store.TenantCapacity{MaxConcurrentScans: ptrTo(2)})
	sc.awaitStart(t, "b-second")
	close(sc.gate("b-first"))
	close(sc.gate("b-second"))
	awaitRun(t, "tenant B's first run", doneFirstB)
	awaitRun(t, "tenant B's second run", doneSecondB)
}

// Tenant caps keep the round-robin grants: a capped tenant is passed over
// only while it is at its cap, and gets the next slot once it is below it
// and its turn has come.
func TestTenantSlotCapsKeepRoundRobinGrants(t *testing.T) {
	const a, b = "tenant-a", "tenant-b"
	ctx := context.Background()
	p := newSlotPool(2, nil)
	p.SetCaps(tenantSlotCaps(map[string]store.TenantCapacity{a: {}, b: {MaxConcurrentScans: ptrTo(1)}}))
	holdFirst, holdSecond := mustAcquireSlot(t, p, "hold"), mustAcquireSlot(t, p, "hold")
	waiters := map[string]<-chan slotResult{}
	queued := map[string]int{}
	for _, label := range []string{"b1", "a1", "b2", "a2", "a3"} {
		key := "tenant-" + label[:1]
		waiters[label] = startSlotAcquire(ctx, p, key)
		queued[key]++
		waitForSlotWaiters(t, p, key, queued[key])
	}
	grant := func(label string) func() {
		t.Helper()
		got := receiveSlot(t, waiters[label])
		if got.err != nil {
			t.Fatalf("%s: %v", label, got.err)
		}
		return got.release
	}
	holdFirst()
	releaseB1 := grant("b1")
	holdSecond()
	releaseA1 := grant("a1")
	// It is B's turn, but B is at its cap, so A's next waiter gets the slot.
	releaseA1()
	releaseA2 := grant("a2")
	assertSlotWaiting(t, waiters["b2"])
	// Below its cap again, B gets the next slot before A, whose grant is
	// more recent.
	releaseB1()
	releaseB2 := grant("b2")
	assertSlotWaiting(t, waiters["a3"])
	releaseA2()
	releaseA3 := grant("a3")
	releaseB2()
	releaseA3()
	assertIdleSlotPool(t, p, 2)
}

// With every capacity setting inherited, which is how an installation
// upgrades and all a unit has until a platform administrator caps it, the
// slots and the budgets are the deployment's, and allow_high_cost reaches
// MaxProbeCountLimit as before tenants had capacity.
func TestInheritedTenantCapacityKeepsTheDeploymentsSlotsAndBudgets(t *testing.T) {
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	capacities, err := f.db.System().TenantCapacities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(capacities) != 2 || tenantSlotCaps(capacities) != nil {
		t.Fatalf("inherited capacities %v give slot caps", capacities)
	}
	f.startSchedules(t, ctx)
	release := mustAcquireSlot(t, f.app.slots, store.DefaultTenantID)
	assertSlots(t, f.app, slotSnapshot{Capacity: 1, InUse: 1, Keys: map[string]slotUsage{store.DefaultTenantID: {InUse: 1, Limit: 1}}})
	release()
	want := probeBudget{nmap: config.DefaultMaxProbeCount, naabu: config.DefaultNaabuMaxProbeCount, highCost: config.MaxProbeCountLimit}
	for _, scope := range []store.TenantScope{f.a, f.b} {
		if got, err := f.app.tenantProbeBudget(ctx, f.db.Tenant(scope)); err != nil || got != want {
			t.Fatalf("tenant %s's budget = %+v, %v; want %+v", scope.ID(), got, err, want)
		}
	}
	// 65,536 addresses on 100 ports exceed the default budget, and stay
	// below MaxProbeCountLimit.
	job := lifecycleJob("wide")
	job.Targets, job.TCP.Ports = []string{"198.18.0.0/16"}, "1-100"
	var workErr *ScanWorkBudgetError
	if _, err := f.app.CheckScanWorkBudget(ctx, f.db.Tenant(f.a), job); !errors.As(err, &workErr) || workErr.Budget != config.DefaultMaxProbeCount {
		t.Fatalf("wide job without high cost: %v", err)
	}
	job.AllowHighCost = true
	if _, err := f.app.CheckScanWorkBudget(ctx, f.db.Tenant(f.a), job); err != nil {
		t.Fatalf("wide high-cost job: %v", err)
	}
}

// resolvedWorkScanner reports resolved work to the budget check before it
// scans, as the production scanner does after resolving DNS.
type resolvedWorkScanner struct{ discovery, nmap int64 }

func (resolvedWorkScanner) Version(context.Context) string { return "resolved-work" }
func (s resolvedWorkScanner) Scan(ctx context.Context, job config.Job) (model.Snapshot, error) {
	return s.ScanWithProgress(ctx, job, nil)
}
func (resolvedWorkScanner) ScanWithProgress(context.Context, config.Job, scanner.ProgressReporter) (model.Snapshot, error) {
	return model.Snapshot{}, nil
}
func (s resolvedWorkScanner) ScanWithProgressBudget(_ context.Context, _ config.Job, _ scanner.ProgressReporter, check func(int64, int64) error) (model.Snapshot, error) {
	return model.Snapshot{}, check(s.discovery, s.nmap)
}

// Tenant B's lower budgets refuse work that tenant A may run, at every check:
// the estimate, the resolved plan, the scanner's own check, and a scan
// cycle's totals.
func TestTenantProbeBudgetRefusesWhatAnotherTenantMayRun(t *testing.T) {
	ctx := context.Background()
	f := newCapacityTenants(t, schedulerFake{}, 1)
	a, b := f.db.Tenant(f.a), f.db.Tenant(f.b)
	f.setCapacity(t, f.b, store.TenantCapacity{MaxProbeCount: ptrTo[int64](1), MaxNaabuProbeCount: ptrTo[int64](1_000)})
	assertBudget := func(t *testing.T, label string, err error, budget int64) {
		t.Helper()
		var workErr *ScanWorkBudgetError
		if !errors.As(err, &workErr) || workErr.Budget != budget {
			t.Fatalf("%s: %v, want a budget error at %d", label, err, budget)
		}
	}

	// The estimate: the job sends two Nmap probes.
	if _, err := f.app.CheckScanWorkBudget(ctx, a, f.jobA.Job); err != nil {
		t.Fatalf("tenant A's estimate: %v", err)
	}
	_, err := f.app.CheckScanWorkBudget(ctx, b, f.jobB.Job)
	assertBudget(t, "tenant B's estimate", err, 1)
	naabu := config.NormalizeJob(config.Job{Name: "naabu", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{ScanType: "connect"}}})
	if _, err := f.app.CheckScanWorkBudget(ctx, a, naabu); err != nil {
		t.Fatalf("tenant A's Naabu estimate: %v", err)
	}
	_, err = f.app.CheckScanWorkBudget(ctx, b, naabu)
	assertBudget(t, "tenant B's Naabu estimate", err, 1_000)
	if scan, _, err := f.app.RunJobRecord(ctx, f.jobA); err != nil || scan.Status != "success" {
		t.Fatalf("tenant A's run = %s, %v", scan.Status, err)
	}
	_, _, err = f.app.RunJobRecord(ctx, f.jobB)
	assertBudget(t, "tenant B's run", err, 1)
	if got := queryStrings(t, f.db, `SELECT id FROM scans WHERE job_id=?`, f.jobB.ID); len(got) != 0 {
		t.Fatalf("a refused run persisted scans %v", got)
	}

	// The resolved plan of a resumable run.
	plan := scanner.WorkPlan{Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.1", "192.0.2.2"}, Ports: "1", Probes: 2}}}
	var scanA, scanB model.Scan
	if handled, _, err := f.app.runResumableAttempt(ctx, ctx, a, f.jobA.Job, f.jobA.ID, &scanA, nil, coverageResumableScanner{plan: plan}, false); handled || err != nil {
		t.Fatalf("tenant A's resolved plan: handled %v, %v", handled, err)
	}
	handled, _, err := f.app.runResumableAttempt(ctx, ctx, b, f.jobB.Job, f.jobB.ID, &scanB, nil, coverageResumableScanner{plan: plan}, false)
	assertBudget(t, "tenant B's resolved plan", err, 1)
	if !handled || scanB.Status != "failed" {
		t.Fatalf("tenant B's resolved plan: handled %v, status %q", handled, scanB.Status)
	}

	// The scanner's own check of resolved work, with an estimate that fits.
	f.setCapacity(t, f.b, store.TenantCapacity{MaxProbeCount: ptrTo[int64](2)})
	f.app.Scanner = resolvedWorkScanner{nmap: 3}
	if scan, _, err := f.app.RunJobRecord(ctx, f.jobA); err != nil || scan.Status != "success" {
		t.Fatalf("tenant A's resolved run = %s, %v", scan.Status, err)
	}
	scan, _, err := f.app.RunJobRecord(ctx, f.jobB)
	assertBudget(t, "tenant B's resolved run", err, 2)
	if scan.Status != "failed" || !strings.Contains(scan.Error, "exceeds budget 2") {
		t.Fatalf("tenant B's resolved run = %s %q", scan.Status, scan.Error)
	}

	// A scan cycle's totals.
	cycleOf := func(ts *store.TenantStore, record store.JobRecord) store.ScanCycleRecord {
		t.Helper()
		units := []scanner.WorkUnit{
			{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1", Probes: 2},
			{Sequence: 1, Protocol: "tcp", Addresses: []string{"192.0.2.2"}, Ports: "1", Probes: 1},
		}
		current, err := ts.GetJob(ctx, record.ID)
		if err != nil {
			t.Fatal(err)
		}
		cycle, err := f.db.System().CreateScanCycle(ctx, store.ScanCycleRecord{JobID: current.ID, Job: current.Job.Name, JobRevision: current.Revision, StartedAt: time.Now().UTC(), Plan: scanner.WorkPlan{Job: current.Job, Units: units}})
		if err != nil {
			t.Fatal(err)
		}
		return cycle
	}
	if err := f.app.CheckScanCycleProbeBudget(ctx, a, cycleOf(a, f.jobA), f.jobA.Job); err != nil {
		t.Fatalf("tenant A's cycle: %v", err)
	}
	assertBudget(t, "tenant B's cycle", f.app.CheckScanCycleProbeBudget(ctx, b, cycleOf(b, f.jobB), f.jobB.Job), 2)
}

// allow_high_cost raises a tenant's budgets to its ceiling and no further; a
// ceiling below the budget raises nothing and lowers nothing; and the
// ceiling never exceeds MaxProbeCountLimit, whatever the row holds.
func TestHighCostIsLimitedByTheTenantsCeiling(t *testing.T) {
	ctx := context.Background()
	f := newCapacityTenants(t, schedulerFake{}, 1)
	f.app.Config.Scheduler.MaxProbeCount = 100
	a, b := f.db.Tenant(f.a), f.db.Tenant(f.b)
	f.setCapacity(t, f.b, store.TenantCapacity{MaxProbeCount: ptrTo[int64](50), HighCostCeiling: ptrTo[int64](1_000)})
	check := func(label string, ts *store.TenantStore, job config.Job, budget int64) {
		t.Helper()
		_, err := f.app.CheckScanWorkBudget(ctx, ts, job)
		var workErr *ScanWorkBudgetError
		switch {
		case budget == 0 && err != nil:
			t.Errorf("%s: %v, want it allowed", label, err)
		case budget != 0 && (!errors.As(err, &workErr) || workErr.Budget != budget):
			t.Errorf("%s: %v, want a budget error at %d", label, err, budget)
		}
	}
	check("tenant A, 500 probes", a, probeJob("job", 500, false), 100)
	check("tenant B, 500 probes", b, probeJob("job", 500, false), 50)
	check("tenant A, 2000 high-cost probes", a, probeJob("job", 2_000, true), 0)
	check("tenant B, 500 high-cost probes", b, probeJob("job", 500, true), 0)
	check("tenant B, 2000 high-cost probes", b, probeJob("job", 2_000, true), 1_000)
	budgetB, err := f.app.tenantProbeBudget(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkResolvedProbeBudget(budgetB, probeJob("job", 1, true), 0, 900); err != nil {
		t.Errorf("tenant B's resolved high-cost work within the ceiling: %v", err)
	}
	if err := checkResolvedProbeBudget(budgetB, probeJob("job", 1, true), 0, 1_500); err == nil || !strings.Contains(err.Error(), "exceeds budget 1000") {
		t.Errorf("tenant B's resolved high-cost work above the ceiling: %v", err)
	}
	// B's Naabu budget is the deployment's, above the ceiling, so the
	// ceiling does not lower it.
	if err := checkResolvedProbeBudget(budgetB, probeJob("job", 1, true), 1_500, 0); err != nil {
		t.Errorf("tenant B's resolved high-cost discovery within its Naabu budget: %v", err)
	}

	f.setCapacity(t, f.b, store.TenantCapacity{MaxProbeCount: ptrTo[int64](50), HighCostCeiling: ptrTo[int64](10)})
	check("tenant B, 40 high-cost probes with a ceiling below its budget", b, probeJob("job", 40, true), 0)
	check("tenant B, 60 high-cost probes with a ceiling below its budget", b, probeJob("job", 60, true), 50)

	f.setCapacity(t, f.b, store.TenantCapacity{HighCostCeiling: ptrTo(config.MaxProbeCountLimit)})
	huge := lifecycleJob("huge")
	huge.Targets, huge.TCP.Ports, huge.AllowHighCost = []string{"198.18.0.0/16"}, "1-65535", true
	check("tenant B, high-cost work above MaxProbeCountLimit", b, huge, config.MaxProbeCountLimit)
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET high_cost_ceiling=? WHERE id=?`, 10*config.MaxProbeCountLimit, secondTenantID); err != nil {
		t.Fatal(err)
	}
	if budget, err := f.app.tenantProbeBudget(ctx, b); err != nil || budget.highCost != config.MaxProbeCountLimit {
		t.Fatalf("tenant B's budget with a ceiling above the limit = %+v, %v", budget, err)
	}
	check("tenant B, high-cost work above MaxProbeCountLimit with a larger ceiling", b, huge, config.MaxProbeCountLimit)
}

// A deployment budget tightened below a tenant's own budget wins.
func TestTighterDeploymentBudgetWinsOverTheTenants(t *testing.T) {
	ctx := context.Background()
	f := newCapacityTenants(t, schedulerFake{}, 1)
	f.app.Config.Scheduler.MaxProbeCount, f.app.Config.Scheduler.MaxNaabuProbeCount = 100, 1_000
	b := f.db.Tenant(f.b)
	f.setCapacity(t, f.b, store.TenantCapacity{MaxProbeCount: ptrTo[int64](100), MaxNaabuProbeCount: ptrTo[int64](1_000), HighCostCeiling: ptrTo[int64](5_000)})
	f.app.Config.Scheduler.MaxProbeCount, f.app.Config.Scheduler.MaxNaabuProbeCount = 10, 500
	want := probeBudget{nmap: 10, naabu: 500, highCost: 5_000}
	if got, err := f.app.tenantProbeBudget(ctx, b); err != nil || got != want {
		t.Fatalf("tenant B's budget = %+v, %v; want %+v", got, err, want)
	}
	var workErr *ScanWorkBudgetError
	if _, err := f.app.CheckScanWorkBudget(ctx, b, probeJob("job", 20, false)); !errors.As(err, &workErr) || workErr.Budget != 10 {
		t.Fatalf("20 probes against the tightened budget: %v", err)
	}
}

// A tenant's capacity limits are what the scheduler enforces for its runs:
// the deployment's slots and probe budgets where the tenant has no setting,
// the tenant's where they are lower, and the deployment's again once
// config.yaml is tightened below them. A
// tenant whose settings cannot be read gets no limits.
func TestTenantCapacityLimitsAreWhatTheSchedulerEnforces(t *testing.T) {
	ctx := context.Background()
	f := newCapacityTenants(t, schedulerFake{}, 4)
	f.app.Config.Scheduler.MaxProbeCount, f.app.Config.Scheduler.MaxNaabuProbeCount = 5_000, 20_000
	a, b := f.db.Tenant(f.a), f.db.Tenant(f.b)
	check := func(label string, ts *store.TenantStore, want store.CapacityLimits) {
		t.Helper()
		if got, err := f.app.TenantCapacityLimits(ctx, ts); err != nil || got != want {
			t.Fatalf("%s = %+v, %v; want %+v", label, got, err, want)
		}
	}
	deployment := store.CapacityLimits{MaxConcurrentScans: 4, MaxProbeCount: 5_000, MaxNaabuProbeCount: 20_000}
	check("tenant A without settings", a, deployment)
	check("tenant B without settings", b, deployment)

	f.setCapacity(t, f.b, store.TenantCapacity{MaxConcurrentScans: ptrTo(2), MaxProbeCount: ptrTo[int64](1_000), MaxNaabuProbeCount: ptrTo[int64](3_000)})
	capped := store.CapacityLimits{MaxConcurrentScans: 2, MaxProbeCount: 1_000, MaxNaabuProbeCount: 3_000}
	check("tenant B with caps", b, capped)
	check("tenant A beside a capped tenant", a, deployment)
	release := mustAcquireSlot(t, f.app.slots, f.b.ID())
	if limit := f.app.slots.CapacitySnapshot().Keys[f.b.ID()].Limit; limit != capped.MaxConcurrentScans {
		t.Fatalf("the slot pool holds tenant B to %d slots, the limits report %d", limit, capped.MaxConcurrentScans)
	}
	release()
	if budget, err := f.app.tenantProbeBudget(ctx, b); err != nil || budget.nmap != capped.MaxProbeCount || budget.naabu != capped.MaxNaabuProbeCount {
		t.Fatalf("tenant B's enforced budget = %+v, %v; the limits report %+v", budget, err, capped)
	}

	f.app.Config.Scheduler.MaxConcurrent, f.app.Config.Scheduler.MaxProbeCount, f.app.Config.Scheduler.MaxNaabuProbeCount = 1, 500, 2_000
	check("tenant B under a tightened deployment", b, store.CapacityLimits{MaxConcurrentScans: 1, MaxProbeCount: 500, MaxNaabuProbeCount: 2_000})

	if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET state=? WHERE id=?`, store.TenantStateDeleted, secondTenantID); err != nil {
		t.Fatal(err)
	}
	if got, err := f.app.TenantCapacityLimits(ctx, b); !errors.Is(err, store.ErrNoTenantScope) || got != (store.CapacityLimits{}) {
		t.Fatalf("limits of a deleted tenant = %+v, %v", got, err)
	}
}

// A tenant's capacity change is checked against the deployment's settings,
// and the stored budget is what the tenant's runs are held to.
func TestSetTenantCapacityIsCheckedAndApplies(t *testing.T) {
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	capacity := store.TenantCapacity{MaxConcurrentScans: ptrTo(1), MaxProbeCount: ptrTo[int64](1)}
	f.setCapacity(t, f.b, capacity)
	if err := f.app.SetTenantCapacity(ctx, secondTenantID, store.TenantCapacity{MaxConcurrentScans: ptrTo(2)}, store.AuditEntry{}); !errors.Is(err, store.ErrValidation) {
		t.Fatalf("a slot cap above the deployment's: %v", err)
	}
	if got, err := f.db.Tenant(f.b).Capacity(ctx); err != nil || !reflect.DeepEqual(got, capacity) {
		t.Fatalf("tenant B's capacity after a refused change = %+v, %v; want %+v", got, err, capacity)
	}
	if budget, err := f.app.tenantProbeBudget(ctx, f.db.Tenant(f.b)); err != nil || budget.nmap != 1 {
		t.Fatalf("tenant B's budget = %+v, %v", budget, err)
	}
}

// The schedule reconciliation reloads the slot caps, so a change that did
// not go through SetTenantCapacity applies too.
func TestScheduleReconciliationReloadsSlotCaps(t *testing.T) {
	ctx := context.Background()
	f := newCapacityTenants(t, schedulerFake{}, 2)
	setSlots := func(slots any) {
		t.Helper()
		if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET max_concurrent_scans=? WHERE id=?`, slots, secondTenantID); err != nil {
			t.Fatal(err)
		}
	}
	limitOfB := func() int { return f.app.slots.CapacitySnapshot().Keys[secondTenantID].Limit }
	setSlots(1)
	release := mustAcquireSlot(t, f.app.slots, secondTenantID)
	defer release()
	if got := limitOfB(); got != 2 {
		t.Fatalf("tenant B's limit before a reconciliation = %d, want 2", got)
	}
	f.startSchedules(t, ctx)
	if got := limitOfB(); got != 1 {
		t.Fatalf("tenant B's limit after a reconciliation = %d, want 1", got)
	}
	setSlots(nil)
	if err := f.app.reconcileSchedules(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := limitOfB(); got != 2 {
		t.Fatalf("tenant B's limit after its cap was cleared = %d, want 2", got)
	}
}

// A budget that cannot be read stops the run or request instead of falling
// back to the deployment's, at every check.
func TestUnreadableProbeBudgetStopsTheRun(t *testing.T) {
	ctx := context.Background()
	f := newCapacityTenants(t, schedulerFake{}, 1)
	b := f.db.Tenant(f.b)
	if _, err := f.db.DB.ExecContext(ctx, `UPDATE tenants SET state=? WHERE id=?`, store.TenantStateDeleted, secondTenantID); err != nil {
		t.Fatal(err)
	}
	unavailable := func(label string, err error) {
		t.Helper()
		if !errors.Is(err, ErrProbeBudgetUnavailable) || !errors.Is(err, store.ErrNoTenantScope) {
			t.Errorf("%s: %v, want ErrProbeBudgetUnavailable", label, err)
		}
	}
	_, err := f.app.CheckScanWorkBudget(ctx, b, f.jobB.Job)
	unavailable("estimate", err)
	_, _, err = f.app.runJob(ctx, f.b, lifecycleJob("unmanaged"), "", 0, false, false)
	unavailable("run", err)
	var scan model.Scan
	plan := scanner.WorkPlan{Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Addresses: []string{"192.0.2.1"}, Ports: "1", Probes: 1}}}
	_, _, err = f.app.runResumableAttempt(ctx, ctx, b, f.jobB.Job, f.jobB.ID, &scan, nil, coverageResumableScanner{plan: plan}, false)
	unavailable("resolved plan", err)
	unavailable("cycle", f.app.CheckScanCycleProbeBudget(ctx, b, store.ScanCycleRecord{ID: "missing"}, f.jobB.Job))
}
