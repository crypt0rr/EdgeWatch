package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
)

// The scan cycle cases join tenantStoreLeakCases from here, so this slice's
// cases stay apart from those of the other slices.
func init() {
	for name, leak := range cycleTenantLeakCases {
		if _, exists := tenantStoreLeakCases[name]; exists {
			panic("duplicate tenant leak case " + name)
		}
		tenantStoreLeakCases[name] = leak
	}
}

// tenantCycles are the scan cycles that addTenantCycles gives a tenant.
type tenantCycles struct {
	// active is the paused cycle of the "edge" job. It started last, so it
	// is also the job's latest cycle, and it has a discovery unit and an
	// enrichment unit whose probes differ per tenant.
	active string
	// promoted is a completed cycle of the "edge" job whose scan was saved.
	promoted string
	// expired is an expired cycle of the "edge" job with its timed-out scan.
	expired string
	// recoverable is a completed cycle of the archived job whose scan was
	// never saved, so a trigger would still promote it.
	recoverable string
	// discovery and nmap are the probes of the active cycle's units.
	discovery, nmap int64
}

// cyclesOf returns the cycles of a tenant of the fixture. Both tenants use
// the same kind of IDs, marked with the tenant.
func cyclesOf(f tenantFixture, scope TenantScope) tenantCycles {
	if scope == f.a {
		return tenantCycles{active: "cycle-active-tenant-a", promoted: "cycle-promoted-tenant-a", expired: "cycle-expired-tenant-a", recoverable: "cycle-recoverable-tenant-a", discovery: 3, nmap: 5}
	}
	return tenantCycles{active: "cycle-active-tenant-b", promoted: "cycle-promoted-tenant-b", expired: "cycle-expired-tenant-b", recoverable: "cycle-recoverable-tenant-b", discovery: 7, nmap: 11}
}

// unknownCycle is a cycle ID that no tenant has.
const unknownCycle = "cycle-unknown"

// cycleUnit returns a one-address unit of the cycle plan.
func cycleUnit(sequence int, phase string, probes int64) scanner.WorkUnit {
	return scanner.WorkUnit{Sequence: sequence, Engine: config.EngineNmap, Phase: phase, Protocol: "tcp", Family: 4, Addresses: []string{"192.0.2.10"}, Ports: "443", PortCount: 1, Probes: probes}
}

// addTenantCycles gives each tenant the cycles of tenantCycles, through the
// daemon's lifecycle writers.
func addTenantCycles(t *testing.T, f tenantFixture) {
	t.Helper()
	ctx := context.Background()
	system := f.store.System()
	at := time.Now().UTC().Add(-time.Hour)
	for _, owner := range []struct {
		scope         TenantScope
		job, archived string
	}{{f.a, f.jobA, f.archivedA}, {f.b, f.jobB, f.archivedB}} {
		cycles := cyclesOf(f, owner.scope)
		create := func(id, jobID string, started, expires time.Time, units ...scanner.WorkUnit) {
			t.Helper()
			record, err := f.store.Tenant(owner.scope).GetJob(ctx, jobID)
			if err != nil {
				t.Fatal(err)
			}
			plan := scanner.WorkPlan{CreatedAt: started, Job: record.Job, Scopes: []model.Scope{{Target: "192.0.2.10", Protocol: "tcp", Ports: "443"}}, Units: units}
			if _, err := system.CreateScanCycle(ctx, ScanCycleRecord{ID: id, JobID: jobID, Job: record.Job.Name, JobRevision: record.Revision, ConfigHash: record.Job.SecurityHash(), Plan: plan, StartedAt: started, ExpiresAt: expires}); err != nil {
				t.Fatal(err)
			}
		}
		complete := func(id string) {
			t.Helper()
			if _, err := system.StartScanCycleAttempt(ctx, id); err != nil {
				t.Fatal(err)
			}
			if _, err := system.ClaimScanCycleUnit(ctx, id, 0); err != nil {
				t.Fatal(err)
			}
			snapshot := model.Snapshot{Hosts: fixtureHosts(0, 1)}
			if err := system.CompleteScanCycleUnit(ctx, id, 0, snapshot); err != nil {
				t.Fatal(err)
			}
			if _, err := system.CompleteScanCycle(ctx, id); err != nil {
				t.Fatal(err)
			}
		}
		saveScan := func(id, cycleID, status, cycleStatus string, finished time.Time) {
			t.Helper()
			scan := model.Scan{ID: id, JobID: owner.job, Job: "edge", StartedAt: finished.Add(-time.Minute), FinishedAt: finished, Status: status, CycleID: cycleID, CycleStatus: cycleStatus, Resumable: true}
			if err := system.SaveScan(ctx, scan); err != nil {
				t.Fatal(err)
			}
		}
		later := at.Add(24 * time.Hour)
		create(cycles.promoted, owner.job, at, later, cycleUnit(0, "discovery", 1))
		complete(cycles.promoted)
		saveScan("scan-"+cycles.promoted, cycles.promoted, "success", "completed", at.Add(time.Minute))
		create(cycles.expired, owner.job, at.Add(2*time.Minute), at.Add(3*time.Minute), cycleUnit(0, "discovery", 1))
		if expired, err := system.ExpireScanCycle(ctx, cycles.expired, time.Now()); err != nil || expired.Status != "expired" {
			t.Fatalf("expire %s = %+v, %v", cycles.expired, expired, err)
		}
		saveScan("scan-"+cycles.expired, cycles.expired, "timed_out", "expired", at.Add(4*time.Minute))
		create(cycles.active, owner.job, at.Add(5*time.Minute), later, cycleUnit(0, "discovery", cycles.discovery), cycleUnit(1, "enrichment", cycles.nmap))
		create(cycles.recoverable, owner.archived, at, later, cycleUnit(0, "discovery", 1))
		complete(cycles.recoverable)
	}
}

// cycleTenantFixtureFile holds the database file of the cycle fixture,
// built once from the tenant fixture. Each case opens its own copy.
var cycleTenantFixtureFile struct {
	once     sync.Once
	contents []byte
}

// newCycleTenantFixture returns a private copy of the tenant fixture with
// the cycles of addTenantCycles.
func newCycleTenantFixture(t *testing.T) tenantFixture {
	t.Helper()
	cycleTenantFixtureFile.once.Do(func() {
		f := newTenantFixture(t)
		addTenantCycles(t, f)
		if err := f.store.Close(); err != nil {
			t.Fatal(err)
		}
		for _, sidecar := range []string{"-wal", "-shm", "-journal"} {
			if _, err := os.Stat(f.store.Path + sidecar); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the cycle fixture left %s behind: %v", sidecar, err)
			}
		}
		contents, err := os.ReadFile(f.store.Path)
		if err != nil {
			t.Fatal(err)
		}
		cycleTenantFixtureFile.contents = contents
	})
	if len(cycleTenantFixtureFile.contents) == 0 {
		t.Fatal("the cycle fixture could not be built")
	}
	path := filepath.Join(t.TempDir(), "cycles.db")
	if err := os.WriteFile(path, cycleTenantFixtureFile.contents, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return tenantFixture{store: s, a: DefaultTenantScope(), b: TenantScope{id: secondTenantID}, tenantFixtureIDs: tenantFixtureFile.ids}
}

// assertNoScanCycle checks that a cycle read failed as for an unknown cycle,
// and returned no cycle.
func assertNoScanCycle(t *testing.T, label string, cycle ScanCycleRecord, err error) {
	t.Helper()
	if !errors.Is(err, ErrNoScanCycle) || !errors.Is(err, ErrNotFound) || cycle.ID != "" || cycle.JobID != "" {
		t.Errorf("%s = %q of job %q, %v; want ErrNoScanCycle", label, cycle.ID, cycle.JobID, err)
	}
}

// checkTenantCycleByJob checks a read of a job's cycle. Tenant B reads
// tenant A's jobs as unknown jobs, and each tenant reads its own job's
// cycle, although both tenants' jobs have the same name. want returns the
// cycle a tenant reads for its "edge" job and for its archived job, or ""
// for none.
func checkTenantCycleByJob(t *testing.T, read func(ts *TenantStore, jobID string) (ScanCycleRecord, error), want func(tenantCycles) (edge, archived string)) {
	t.Helper()
	f := newCycleTenantFixture(t)
	for _, jobID := range []string{f.jobA, f.archivedA, "00000000-0000-0000-0000-00000000dead"} {
		cycle, err := read(f.store.Tenant(f.b), jobID)
		assertNoScanCycle(t, "tenant B, job "+jobID, cycle, err)
	}
	cycle, err := read(f.store.Tenant(f.a), f.jobB)
	assertNoScanCycle(t, "tenant A, tenant B's job", cycle, err)
	for _, owner := range []struct {
		scope         TenantScope
		job, archived string
	}{{f.a, f.jobA, f.archivedA}, {f.b, f.jobB, f.archivedB}} {
		edge, archived := want(cyclesOf(f, owner.scope))
		for jobID, wantID := range map[string]string{owner.job: edge, owner.archived: archived} {
			cycle, err := read(f.store.Tenant(owner.scope), jobID)
			if wantID == "" {
				assertNoScanCycle(t, "tenant "+owner.scope.ID()+", job "+jobID, cycle, err)
				continue
			}
			if err != nil || cycle.ID != wantID || cycle.JobID != jobID {
				t.Errorf("tenant %s, job %s: cycle = %q of job %q, %v; want %s", owner.scope.ID(), jobID, cycle.ID, cycle.JobID, err, wantID)
			}
		}
	}
}

// unitCycles returns the cycle and phase of each unit summary.
func unitCycles(units []ScanCycleUnitSummary) []string {
	var out []string
	for _, unit := range units {
		out = append(out, unit.CycleID+"/"+unit.Phase)
	}
	return out
}

// checkTenantCycleUnits checks a read of a cycle's units. Tenant B reads
// none of tenant A's cycles' units, and each tenant reads its own active
// cycle's two units in order.
func checkTenantCycleUnits(t *testing.T, read func(ts *TenantStore, cycleID string) ([]ScanCycleUnitSummary, int, error)) {
	t.Helper()
	f := newCycleTenantFixture(t)
	a := cyclesOf(f, f.a)
	for _, cycleID := range []string{a.active, a.promoted, a.expired, a.recoverable, unknownCycle} {
		units, total, err := read(f.store.Tenant(f.b), cycleID)
		if err != nil || len(units) != 0 || total != 0 {
			t.Errorf("tenant B read the units of cycle %s: %v (total %d), %v", cycleID, unitCycles(units), total, err)
		}
	}
	for _, scope := range []TenantScope{f.a, f.b} {
		cycle := cyclesOf(f, scope).active
		units, total, err := read(f.store.Tenant(scope), cycle)
		if want := []string{cycle + "/discovery", cycle + "/enrichment"}; err != nil || !reflect.DeepEqual(unitCycles(units), want) || total != 2 {
			t.Errorf("tenant %s: units = %v (total %d), %v; want %v", scope.ID(), unitCycles(units), total, err, want)
		}
	}
}

// checkTenantCycleScanCheck checks a check for a cycle's scan, where only a
// scan of the tenant counts. Tenant B finds no scan for tenant A's cycles,
// and each tenant finds the scan of its own cycle that cycleOf names.
func checkTenantCycleScanCheck(t *testing.T, check func(ts *TenantStore, cycleID string) (bool, error), cycleOf func(tenantCycles) string) {
	t.Helper()
	f := newCycleTenantFixture(t)
	a := cyclesOf(f, f.a)
	for _, cycleID := range []string{a.promoted, a.expired, unknownCycle} {
		if found, err := check(f.store.Tenant(f.b), cycleID); err != nil || found {
			t.Errorf("tenant B found the scan of cycle %s: %v, %v", cycleID, found, err)
		}
	}
	for _, scope := range []TenantScope{f.a, f.b} {
		cycles := cyclesOf(f, scope)
		if found, err := check(f.store.Tenant(scope), cycleOf(cycles)); err != nil || !found {
			t.Errorf("tenant %s: scan of its own cycle %s = %v, %v", scope.ID(), cycleOf(cycles), found, err)
		}
		if found, err := check(f.store.Tenant(scope), cycles.active); err != nil || found {
			t.Errorf("tenant %s: scan of its active cycle = %v, %v", scope.ID(), found, err)
		}
	}
}

// tenantCycleRows renders a tenant's rows: those of tenantJobDigest, which
// include its cycles, and its cycles' units and discovery checkpoints.
func tenantCycleRows(t *testing.T, s *Store, scope TenantScope) string {
	t.Helper()
	const cycles = "cycle_id IN (SELECT c.id FROM scan_cycles c JOIN jobs j ON j.id=c.job_id WHERE j.tenant_id=?1)"
	return tenantJobDigest(t, s, scope) + "\n" + tenantRows(t, s, "scan_cycle_units", cycles, scope) + tenantRows(t, s, "scan_cycle_discovery_checkpoints", cycles, scope)
}

// cycleTenantLeakCases hold the leak cases of the scan cycle reads and the
// cycle discard. Each case opens its own copy of the cycle fixture.
var cycleTenantLeakCases = map[string]tenantLeakCase{
	"GetScanCycle": {run: func(t *testing.T, _ tenantFixture) {
		ctx := context.Background()
		f := newCycleTenantFixture(t)
		a := cyclesOf(f, f.a)
		for _, id := range []string{a.active, a.promoted, a.expired, a.recoverable, unknownCycle} {
			cycle, err := f.store.Tenant(f.b).GetScanCycle(ctx, id)
			assertNoScanCycle(t, "tenant B, cycle "+id, cycle, err)
		}
		cycle, err := f.store.Tenant(f.a).GetScanCycle(ctx, cyclesOf(f, f.b).active)
		assertNoScanCycle(t, "tenant A, tenant B's cycle", cycle, err)
		for scope, job := range map[TenantScope]string{f.a: f.jobA, f.b: f.jobB} {
			cycles := cyclesOf(f, scope)
			cycle, err := f.store.Tenant(scope).GetScanCycle(ctx, cycles.active)
			if err != nil || cycle.ID != cycles.active || cycle.JobID != job || cycle.Status != "paused" || cycle.TotalProbes != cycles.discovery+cycles.nmap || len(cycle.Plan.Units) != 2 {
				t.Errorf("tenant %s: own cycle = %+v, %v", scope.ID(), cycle, err)
			}
		}
	}},
	"GetActiveScanCycle": {run: func(t *testing.T, _ tenantFixture) {
		checkTenantCycleByJob(t, func(ts *TenantStore, jobID string) (ScanCycleRecord, error) {
			return ts.GetActiveScanCycle(context.Background(), jobID)
		}, func(cycles tenantCycles) (string, string) { return cycles.active, "" })
	}},
	"GetLatestScanCycle": {run: func(t *testing.T, _ tenantFixture) {
		checkTenantCycleByJob(t, func(ts *TenantStore, jobID string) (ScanCycleRecord, error) {
			return ts.GetLatestScanCycle(context.Background(), jobID)
		}, func(cycles tenantCycles) (string, string) { return cycles.active, cycles.recoverable })
	}},
	"GetRecoverableScanCycle": {run: func(t *testing.T, _ tenantFixture) {
		checkTenantCycleByJob(t, func(ts *TenantStore, jobID string) (ScanCycleRecord, error) {
			return ts.GetRecoverableScanCycle(context.Background(), jobID)
		}, func(cycles tenantCycles) (string, string) { return cycles.active, cycles.recoverable })
	}},
	"ListActiveScanCycleSummaries": {run: func(t *testing.T, _ tenantFixture) {
		ctx := context.Background()
		f := newCycleTenantFixture(t)
		for _, owner := range []struct {
			scope TenantScope
			job   string
		}{{f.a, f.jobA}, {f.b, f.jobB}} {
			for _, includeArchived := range []bool{false, true} {
				summaries, err := f.store.Tenant(owner.scope).ListActiveScanCycleSummaries(ctx, includeArchived)
				var got []string
				for jobID, summary := range summaries {
					got = append(got, jobID+"="+summary.ID)
				}
				sort.Strings(got)
				if want := []string{owner.job + "=" + cyclesOf(f, owner.scope).active}; err != nil || !reflect.DeepEqual(got, want) {
					t.Errorf("tenant %s, archived %v: active cycles = %v, %v; want %v", owner.scope.ID(), includeArchived, got, err, want)
				}
			}
		}
	}},
	"ListScanCycleUnitSummaries": {run: func(t *testing.T, _ tenantFixture) {
		checkTenantCycleUnits(t, func(ts *TenantStore, cycleID string) ([]ScanCycleUnitSummary, int, error) {
			units, err := ts.ListScanCycleUnitSummaries(context.Background(), cycleID)
			return units, len(units), err
		})
	}},
	"ListScanCycleUnitSummariesPage": {run: func(t *testing.T, _ tenantFixture) {
		checkTenantCycleUnits(t, func(ts *TenantStore, cycleID string) ([]ScanCycleUnitSummary, int, error) {
			page, err := ts.ListScanCycleUnitSummariesPage(context.Background(), cycleID, 10, 0)
			return page.Items, page.Total, err
		})
	}},
	"ScanCycleProbeTotals": {run: func(t *testing.T, _ tenantFixture) {
		ctx := context.Background()
		f := newCycleTenantFixture(t)
		a := cyclesOf(f, f.a)
		for _, id := range []string{a.active, a.promoted, unknownCycle} {
			if discovery, nmap, err := f.store.Tenant(f.b).ScanCycleProbeTotals(ctx, id); err != nil || discovery != 0 || nmap != 0 {
				t.Errorf("tenant B: probes of cycle %s = %d, %d, %v", id, discovery, nmap, err)
			}
		}
		for _, scope := range []TenantScope{f.a, f.b} {
			cycles := cyclesOf(f, scope)
			if discovery, nmap, err := f.store.Tenant(scope).ScanCycleProbeTotals(ctx, cycles.active); err != nil || discovery != cycles.discovery || nmap != cycles.nmap {
				t.Errorf("tenant %s: probes = %d, %d, %v; want %d, %d", scope.ID(), discovery, nmap, err, cycles.discovery, cycles.nmap)
			}
		}
	}},
	"ScanCycleExpiryNotified": {run: func(t *testing.T, _ tenantFixture) {
		checkTenantCycleScanCheck(t, func(ts *TenantStore, cycleID string) (bool, error) {
			return ts.ScanCycleExpiryNotified(context.Background(), cycleID)
		}, func(cycles tenantCycles) string { return cycles.expired })
	}},
	"ScanCycleHasScan": {run: func(t *testing.T, _ tenantFixture) {
		checkTenantCycleScanCheck(t, func(ts *TenantStore, cycleID string) (bool, error) {
			return ts.ScanCycleHasScan(context.Background(), cycleID)
		}, func(cycles tenantCycles) string { return cycles.promoted })
	}},
	"DiscardScanCycle": {run: func(t *testing.T, _ tenantFixture) {
		ctx := context.Background()
		f := newCycleTenantFixture(t)
		a, b := cyclesOf(f, f.a), cyclesOf(f, f.b)
		before := tenantCycleRows(t, f.store, f.a)
		for _, id := range []string{a.active, a.recoverable, a.promoted, a.expired, unknownCycle} {
			if err := f.store.Tenant(f.b).DiscardScanCycle(ctx, id); !errors.Is(err, ErrNoScanCycle) || !errors.Is(err, ErrNotFound) {
				t.Errorf("tenant B discarded tenant A's cycle %s: %v", id, err)
			}
		}
		if after := tenantCycleRows(t, f.store, f.a); after != before {
			t.Fatalf("tenant B's discards changed tenant A:\nbefore\n%s\nafter\n%s", before, after)
		}
		for _, id := range []string{b.active, b.recoverable} {
			if err := f.store.Tenant(f.b).DiscardScanCycle(ctx, id); err != nil {
				t.Fatalf("tenant B's own cycle %s: %v", id, err)
			}
			cycle, err := f.store.Tenant(f.b).GetScanCycle(ctx, id)
			if err != nil || cycle.Status != "discarded" {
				t.Fatalf("tenant B's cycle %s after its discard = %+v, %v", id, cycle, err)
			}
		}
		if err := f.store.Tenant(f.b).DiscardScanCycle(ctx, b.promoted); !errors.Is(err, ErrCycleNotResumable) {
			t.Errorf("tenant B discarded its promoted cycle: %v", err)
		}
		if units, err := f.store.Tenant(f.b).ListScanCycleUnitSummaries(ctx, b.active); err != nil || len(units) != 0 {
			t.Errorf("tenant B's discarded cycle kept units %v, %v", unitCycles(units), err)
		}
		if after := tenantCycleRows(t, f.store, f.a); after != before {
			t.Fatalf("tenant B's discard of its own cycles changed tenant A:\nbefore\n%s\nafter\n%s", before, after)
		}
	}},
}

// The cycle checks outside the leak suite share one copy of the cycle
// fixture, because opening a database is the slow part of these tests. The
// last one writes.
func TestTenantCycles(t *testing.T) {
	t.Parallel()
	f := newCycleTenantFixture(t)
	t.Run("unit reads use the unit index", func(t *testing.T) { assertTenantCycleUnitReadsUseTheIndex(t, f) })
	t.Run("system writers", func(t *testing.T) { assertSystemCycleWritersReachEveryTenant(t, f) })
}

// A tenant's unit reads find the cycle and its job by their keys and read
// the units in order from the primary key, without sorting them.
func assertTenantCycleUnitReadsUseTheIndex(t *testing.T, f tenantFixture) {
	query := `SELECT u.sequence FROM scan_cycle_units u JOIN scan_cycles c ON c.id=u.cycle_id JOIN jobs j ON j.id=c.job_id AND j.tenant_id=? WHERE u.cycle_id=? ORDER BY u.sequence LIMIT ? OFFSET ?`
	plan := queryPlan(t, f.store.DB, query, secondTenantID, cyclesOf(f, f.b).active, 10, 0)
	if !strings.Contains(plan, "sqlite_autoindex_scan_cycle_units_1") || strings.Contains(plan, "TEMP B-TREE") {
		t.Errorf("unit page plan = %q, want the primary key without a sort", plan)
	}
}

// The daemon's lifecycle writers run a cycle of any tenant: they take no
// scope, and the cycle belongs to its job's tenant. Tenant B's active cycle
// runs to completion through them and leaves tenant A's rows unchanged.
func assertSystemCycleWritersReachEveryTenant(t *testing.T, f tenantFixture) {
	ctx := context.Background()
	system := f.store.System()
	b := cyclesOf(f, f.b)
	before := tenantCycleRows(t, f.store, f.a)
	started, err := system.StartScanCycleAttempt(ctx, b.active)
	if err != nil || started.JobID != f.jobB || started.Status != "running" {
		t.Fatalf("start tenant B's cycle = %+v, %v", started, err)
	}
	for sequence := 0; sequence < 2; sequence++ {
		unit, err := system.NextScanCycleUnit(ctx, b.active)
		if err != nil || unit.Sequence != sequence {
			t.Fatalf("next unit = %+v, %v; want %d", unit, err, sequence)
		}
		if _, err := system.ClaimScanCycleUnit(ctx, b.active, sequence); err != nil {
			t.Fatal(err)
		}
		if err := system.CompleteScanCycleUnit(ctx, b.active, sequence, model.Snapshot{Hosts: fixtureHosts(sequence, sequence+1)}); err != nil {
			t.Fatal(err)
		}
	}
	if completed, err := system.CompleteScanCycle(ctx, b.active); err != nil || completed.Status != "completed" {
		t.Fatalf("complete tenant B's cycle = %+v, %v", completed, err)
	}
	if _, fragments, err := system.LoadScanCycleFragments(ctx, b.active); err != nil || len(fragments) != 2 {
		t.Fatalf("fragments of tenant B's cycle = %d, %v", len(fragments), err)
	}
	if after := tenantCycleRows(t, f.store, f.a); after != before {
		t.Fatalf("running tenant B's cycle changed tenant A:\nbefore\n%s\nafter\n%s", before, after)
	}
}
