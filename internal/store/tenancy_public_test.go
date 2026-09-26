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

// The public status cases join tenantStoreLeakCases before any test runs,
// so each store slice keeps its leak cases in its own file.
func init() {
	for name, leak := range publicStatusLeakCases {
		if _, duplicate := tenantStoreLeakCases[name]; duplicate {
			panic("two leak cases for TenantStore." + name)
		}
		tenantStoreLeakCases[name] = leak
	}
}

// unknownPublicJobID names no job in any tenant.
const unknownPublicJobID = "00000000-0000-0000-0000-00000000dead"

// publicStatusRows returns the tenant's public page and its published hosts
// as text, so a test can show that a save through another tenant left them
// unchanged.
func publicStatusRows(t *testing.T, s *Store, scope TenantScope) string {
	t.Helper()
	return tenantRows(t, s, "public_dashboards", "tenant_id=?1", scope) +
		tenantRows(t, s, "public_dashboard_hosts", "dashboard_id IN (SELECT id FROM public_dashboards WHERE tenant_id=?1)", scope)
}

// publicFixtureHosts selects hosts 0 to 2 of the job: the addresses that the
// scans of both tenants' "edge" jobs found.
func publicFixtureHosts(jobID string) []PublicDashboardHost {
	hosts := make([]PublicDashboardHost, 0, 3)
	for _, host := range fixtureHosts(0, 3) {
		hosts = append(hosts, PublicDashboardHost{JobID: jobID, Address: host.Address})
	}
	return hosts
}

// publicSelections returns "job/address" for each selection, sorted.
func publicSelections(hosts []PublicDashboardHost) []string {
	selections := make([]string, 0, len(hosts))
	for _, host := range hosts {
		selections = append(selections, host.JobID+"/"+host.Address)
	}
	sort.Strings(selections)
	return selections
}

// publicResultOwners returns "scan@job/address" for each result, sorted, so
// a list shows which scan and job every published address came from.
func publicResultOwners(results []PublicDashboardHostResult) []string {
	owners := make([]string, 0, len(results))
	for _, result := range results {
		owners = append(owners, result.Host.ScanID+"@"+result.Summary.JobID+"/"+result.Selection.Address)
	}
	sort.Strings(owners)
	return owners
}

// wantPublicOwners returns the owners of hosts 0 to 2 of the scan and job.
func wantPublicOwners(scanID, jobID string) []string {
	owners := make([]string, 0, 3)
	for _, host := range fixtureHosts(0, 3) {
		owners = append(owners, scanID+"@"+jobID+"/"+host.Address)
	}
	sort.Strings(owners)
	return owners
}

// publishTenantPages gives both tenants of the fixture an enabled public page,
// titled after the tenant, that publishes hosts 0 to 2 of their "edge" job:
// the same addresses in both tenants. It is tenant B's first save, which
// creates B's page.
func publishTenantPages(t *testing.T, f tenantFixture) {
	t.Helper()
	ctx := context.Background()
	for scope, job := range map[TenantScope]string{f.a: f.jobA, f.b: f.jobB} {
		title := map[TenantScope]string{f.a: "tenant-a", f.b: "tenant-b"}[scope]
		if err := f.store.Tenant(scope).SavePublicDashboard(ctx, PublicDashboard{Enabled: true, Title: title}, publicFixtureHosts(job), AuditEntry{}); err != nil {
			t.Fatal(err)
		}
	}
}

// assertPublicHostJobRefused checks that the save of each selection is
// refused as a host of an unknown job: the same validation error for tenant
// A's job as for a job that does not exist. Neither tenant's page changes.
func assertPublicHostJobRefused(t *testing.T, f tenantFixture, save func(ts *TenantStore, hosts []PublicDashboardHost) error) {
	t.Helper()
	beforeA, beforeB := publicStatusRows(t, f.store, f.a), publicStatusRows(t, f.store, f.b)
	unknown := save(f.store.Tenant(f.b), []PublicDashboardHost{{JobID: unknownPublicJobID, Address: fixtureHost(0).Address}})
	if !errors.Is(unknown, ErrValidation) || unknown.Error() != errPublicDashboardHostJob.Error() {
		t.Fatalf("host of an unknown job: %v", unknown)
	}
	for label, hosts := range map[string][]PublicDashboardHost{
		"tenant A's host":           publicFixtureHosts(f.jobA)[:1],
		"tenant A's archived job":   {{JobID: f.archivedA, Address: fixtureHost(0).Address}},
		"own hosts and one of A's":  append(publicFixtureHosts(f.jobB), publicFixtureHosts(f.jobA)[2]),
		"A's host after an own one": {publicFixtureHosts(f.jobB)[0], publicFixtureHosts(f.jobA)[0]},
	} {
		if err := save(f.store.Tenant(f.b), hosts); !errors.Is(err, ErrValidation) || err.Error() != unknown.Error() {
			t.Errorf("tenant B published %s: %v, want %v", label, err, unknown)
		}
	}
	if publicStatusRows(t, f.store, f.a) != beforeA || publicStatusRows(t, f.store, f.b) != beforeB {
		t.Fatal("a refused save through tenant B changed a public page")
	}
}

// publicStatusLeakCases show that tenant B reads and writes only its own
// public page, and publishes only the hosts of its own jobs, although both
// tenants publish the same addresses from jobs with the same name.
var publicStatusLeakCases = map[string]tenantLeakCase{
	"GetPublicDashboard": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		if dashboard, err := f.store.Tenant(f.b).GetPublicDashboard(ctx); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(dashboard, PublicDashboard{}) {
			t.Fatalf("tenant B without a page read %+v, %v", dashboard, err)
		}
		if dashboard, err := f.store.Tenant(f.a).GetPublicDashboard(ctx); err != nil || dashboard.Enabled || dashboard.Title != "EdgeWatch public status" || len(dashboard.Hosts) != 0 {
			t.Fatalf("tenant A's page as migrated = %+v, %v", dashboard, err)
		}
		publishTenantPages(t, f)
		for scope, want := range map[TenantScope]struct{ title, job string }{f.a: {"tenant-a", f.jobA}, f.b: {"tenant-b", f.jobB}} {
			dashboard, err := f.store.Tenant(scope).GetPublicDashboard(ctx)
			if err != nil || !dashboard.Enabled || dashboard.Title != want.title || !reflect.DeepEqual(publicSelections(dashboard.Hosts), publicSelections(publicFixtureHosts(want.job))) {
				t.Errorf("tenant %s: page = %+v, %v", scope.ID(), dashboard, err)
			}
		}
		if dashboard, err := f.store.GetPublicDashboard(ctx); err != nil || dashboard.Title != "tenant-a" {
			t.Errorf("deprecated GetPublicDashboard = %+v, %v; want tenant A's page", dashboard, err)
		}
	}},
	"SavePublicDashboard": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		if err := f.store.Tenant(f.a).SavePublicDashboard(ctx, PublicDashboard{Enabled: true, Title: "tenant-a"}, publicFixtureHosts(f.jobA), AuditEntry{}); err != nil {
			t.Fatal(err)
		}
		beforeA := publicStatusRows(t, f.store, f.a)
		assertPublicHostJobRefused(t, f, func(ts *TenantStore, hosts []PublicDashboardHost) error {
			return ts.SavePublicDashboard(ctx, PublicDashboard{Enabled: true, Title: "tenant-b"}, hosts, AuditEntry{})
		})
		if _, err := f.store.Tenant(f.b).GetPublicDashboard(ctx); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a refused first save left tenant B a page: %v", err)
		}
		// B's first save creates its page, and a second one replaces it.
		for _, save := range []struct {
			title string
			hosts []PublicDashboardHost
		}{{"tenant-b", publicFixtureHosts(f.jobB)}, {"tenant-b again", publicFixtureHosts(f.jobB)[1:]}} {
			if err := f.store.Tenant(f.b).SavePublicDashboard(ctx, PublicDashboard{Enabled: true, Title: save.title}, save.hosts, AuditEntry{}); err != nil {
				t.Fatal(err)
			}
			dashboard, err := f.store.Tenant(f.b).GetPublicDashboard(ctx)
			if err != nil || dashboard.Title != save.title || !reflect.DeepEqual(publicSelections(dashboard.Hosts), publicSelections(save.hosts)) {
				t.Fatalf("tenant B's own page = %+v, %v", dashboard, err)
			}
			if publicStatusRows(t, f.store, f.a) != beforeA {
				t.Fatal("tenant B's save changed tenant A's page")
			}
		}
		// The deprecated wrapper writes tenant A's page, not B's.
		beforeB := publicStatusRows(t, f.store, f.b)
		if err := f.store.SavePublicDashboard(ctx, PublicDashboard{Title: "default"}, nil, AuditEntry{}); err != nil {
			t.Fatal(err)
		}
		if dashboard, err := f.store.Tenant(f.a).GetPublicDashboard(ctx); err != nil || dashboard.Title != "default" || publicStatusRows(t, f.store, f.b) != beforeB {
			t.Fatalf("deprecated SavePublicDashboard wrote %+v, %v, or changed tenant B's page", dashboard, err)
		}
	}},
	"SavePublicDashboardIfCurrent": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		save := func(scope TenantScope, token time.Time, title string, hosts []PublicDashboardHost) error {
			return f.store.Tenant(scope).SavePublicDashboardIfCurrent(ctx, token, PublicDashboard{Enabled: true, Title: title}, hosts, AuditEntry{})
		}
		loadedA, err := f.store.Tenant(f.a).GetPublicDashboard(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := save(f.a, loadedA.UpdatedAt, "tenant-a", publicFixtureHosts(f.jobA)); err != nil {
			t.Fatal(err)
		}
		pageA, err := f.store.Tenant(f.a).GetPublicDashboard(ctx)
		if err != nil {
			t.Fatal(err)
		}
		beforeA := publicStatusRows(t, f.store, f.a)
		// Tenant B has no page yet; its editor loads the zero time.
		assertPublicHostJobRefused(t, f, func(ts *TenantStore, hosts []PublicDashboardHost) error {
			return ts.SavePublicDashboardIfCurrent(ctx, time.Time{}, PublicDashboard{Enabled: true, Title: "tenant-b"}, hosts, AuditEntry{})
		})
		// Tenant A's token is no token for B's page.
		if err := save(f.b, pageA.UpdatedAt, "tenant-b", publicFixtureHosts(f.jobB)); !errors.Is(err, ErrConflict) {
			t.Fatalf("tenant B saved with tenant A's token: %v", err)
		}
		if err := save(f.b, time.Time{}, "tenant-b", publicFixtureHosts(f.jobB)); err != nil {
			t.Fatal(err)
		}
		pageB, err := f.store.Tenant(f.b).GetPublicDashboard(ctx)
		if err != nil || pageB.Title != "tenant-b" || !reflect.DeepEqual(publicSelections(pageB.Hosts), publicSelections(publicFixtureHosts(f.jobB))) {
			t.Fatalf("tenant B's page = %+v, %v", pageB, err)
		}
		if publicStatusRows(t, f.store, f.a) != beforeA {
			t.Fatal("tenant B's saves changed tenant A's page")
		}
		// A save of tenant A's page is no conflict for B's editor, and B's
		// save leaves A's page as A saved it.
		if err := save(f.a, pageA.UpdatedAt, "tenant-a again", publicFixtureHosts(f.jobA)[:1]); err != nil {
			t.Fatal(err)
		}
		beforeA = publicStatusRows(t, f.store, f.a)
		if err := save(f.b, pageB.UpdatedAt, "tenant-b again", publicFixtureHosts(f.jobB)[:2]); err != nil {
			t.Fatalf("tenant A's save made tenant B's token stale: %v", err)
		}
		if err := save(f.b, pageB.UpdatedAt, "stale", nil); !errors.Is(err, ErrConflict) {
			t.Fatalf("tenant B's stale token: %v", err)
		}
		if publicStatusRows(t, f.store, f.a) != beforeA {
			t.Fatal("tenant B's saves changed tenant A's page")
		}
	}},
	"PublicScope": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		for scope, want := range map[TenantScope]struct{ own, other, scan string }{f.a: {f.jobA, f.jobB, f.scanA}, f.b: {f.jobB, f.jobA, f.scanB}} {
			public, err := f.store.Tenant(scope).PublicScope()
			if err != nil || public.TenantID() != scope.ID() {
				t.Fatalf("tenant %s: public scope = %q, %v", scope.ID(), public.TenantID(), err)
			}
			results, err := f.store.Public(public).GetLatestSuccessfulJobHosts(ctx, append(publicFixtureHosts(want.own), publicFixtureHosts(want.other)...))
			if err != nil {
				t.Fatal(err)
			}
			if got, wantOwners := publicResultOwners(results), wantPublicOwners(want.scan, want.own); !reflect.DeepEqual(got, wantOwners) {
				t.Errorf("tenant %s: published hosts = %v, want %v", scope.ID(), got, wantOwners)
			}
		}
		if public, err := f.store.Tenant(f.a).PublicScope(); err != nil || public != DefaultPublicScope() {
			t.Errorf("default tenant's public scope = %q, %v", public.TenantID(), err)
		}
	}},
}

// publicStoreCase shows that one PublicStore method reads only the rows of
// its scope's tenant. Each runs on its own copy of a fixture in which both
// tenants publish the same addresses and have legacy scans that found them.
type publicStoreCase func(t *testing.T, f tenantFixture, a, b PublicScope)

// publicStoreCases holds a case for every exported PublicStore method.
var publicStoreCases = map[string]publicStoreCase{
	"GetPublicDashboard": func(t *testing.T, f tenantFixture, a, b PublicScope) {
		ctx := context.Background()
		for scope, want := range map[PublicScope]struct{ title, job string }{a: {"tenant-a", f.jobA}, b: {"tenant-b", f.jobB}} {
			dashboard, err := f.store.Public(scope).GetPublicDashboard(ctx)
			if err != nil || !dashboard.Enabled || dashboard.Title != want.title || !reflect.DeepEqual(publicSelections(dashboard.Hosts), publicSelections(publicFixtureHosts(want.job))) {
				t.Errorf("tenant %s: published page = %+v, %v", scope.TenantID(), dashboard, err)
			}
		}
		// The page is not published once withdrawn or while the tenant is
		// not active, although the scope was resolved before.
		if err := f.store.Tenant(f.b).SavePublicDashboard(ctx, PublicDashboard{Title: "tenant-b"}, publicFixtureHosts(f.jobB), AuditEntry{}); err != nil {
			t.Fatal(err)
		}
		if dashboard, err := f.store.Public(b).GetPublicDashboard(ctx); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(dashboard, PublicDashboard{}) {
			t.Errorf("withdrawn page = %+v, %v", dashboard, err)
		}
		if dashboard, err := f.store.Tenant(f.b).GetPublicDashboard(ctx); err != nil || dashboard.Enabled || len(dashboard.Hosts) != 3 {
			t.Errorf("the editor's view of the withdrawn page = %+v, %v", dashboard, err)
		}
		for _, state := range []string{TenantStateDisabled, TenantStateDeleting, TenantStateDeleted} {
			setTenantState(t, f.store, DefaultTenantID, state)
			if dashboard, err := f.store.Public(a).GetPublicDashboard(ctx); !errors.Is(err, ErrNotFound) || dashboard.Title != "" {
				t.Errorf("page of a %s tenant = %+v, %v", state, dashboard, err)
			}
		}
	},
	"ListJobs": func(t *testing.T, f tenantFixture, a, b PublicScope) {
		ctx := context.Background()
		for _, check := range []struct {
			scope           PublicScope
			includeArchived bool
			want            []string
		}{
			{b, false, []string{f.jobB}},
			{b, true, sortedIDs(f.jobB, f.archivedB)},
			{a, false, []string{f.jobA}},
			{a, true, sortedIDs(f.jobA, f.archivedA)},
		} {
			records, err := f.store.Public(check.scope).ListJobs(ctx, check.includeArchived)
			if err != nil {
				t.Fatal(err)
			}
			if got := jobIDs(records); !reflect.DeepEqual(got, check.want) {
				t.Errorf("tenant %s, archived %v: jobs = %v, want %v", check.scope.TenantID(), check.includeArchived, got, check.want)
			}
		}
	},
	"ListLegacyPublicScans": func(t *testing.T, f tenantFixture, a, b PublicScope) {
		ctx := context.Background()
		for _, check := range []struct {
			scope PublicScope
			job   string
			want  []string
		}{
			{b, f.jobA, nil},
			{b, f.archivedA, nil},
			{b, f.jobB, []string{"legacy-" + f.jobB}},
			{a, f.jobB, nil},
			{a, f.jobA, []string{"legacy-" + f.jobA}},
		} {
			scans, err := f.store.Public(check.scope).ListLegacyPublicScans(ctx, check.job, 0)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, scan := range scans {
				got = append(got, scan.ID)
			}
			if !reflect.DeepEqual(got, check.want) {
				t.Errorf("tenant %s, job %s: legacy scans = %v, want %v", check.scope.TenantID(), check.job, got, check.want)
			}
		}
	},
	// Each tenant's scan found the same addresses. A tenant's scope resolves
	// only its own job's selections, through the maintained projection and
	// through the history fallback alike.
	"GetLatestSuccessfulJobHosts": func(t *testing.T, f tenantFixture, a, b PublicScope) {
		ctx := context.Background()
		all := append(append(publicFixtureHosts(f.jobA), publicFixtureHosts(f.jobB)...), publicFixtureHosts(unknownPublicJobID)...)
		check := func(label string) {
			t.Helper()
			for scope, want := range map[PublicScope][]string{a: wantPublicOwners(f.scanA, f.jobA), b: wantPublicOwners(f.scanB, f.jobB)} {
				results, err := f.store.Public(scope).GetLatestSuccessfulJobHosts(ctx, all)
				if err != nil {
					t.Fatal(err)
				}
				if got := publicResultOwners(results); !reflect.DeepEqual(got, want) {
					t.Errorf("%s: tenant %s: published hosts = %v, want %v", label, scope.TenantID(), got, want)
				}
			}
		}
		check("projection")
		// A newer scan of each tenant's archived job moves the projection of
		// host 0 to that job, so the "edge" job's host 0 is read from history.
		for _, job := range []string{f.archivedA, f.archivedB} {
			if err := f.store.System().SaveScan(ctx, fixtureScan("newer-"+job, job, "edge-archived", time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC), fixtureHosts(0, 1))); err != nil {
				t.Fatal(err)
			}
		}
		check("history")
		for _, selection := range []PublicDashboardHost{{JobID: f.archivedA, Address: fixtureHost(0).Address}, {JobID: f.jobA, Address: fixtureHost(0).Address}} {
			if results, err := f.store.Public(b).GetLatestSuccessfulJobHosts(ctx, []PublicDashboardHost{selection}); err != nil || len(results) != 0 {
				t.Errorf("tenant B resolved tenant A's selection %+v: %v, %v", selection, publicResultOwners(results), err)
			}
		}
	},
	"GetLatestSuccessfulJobHost": func(t *testing.T, f tenantFixture, a, b PublicScope) {
		ctx := context.Background()
		address := fixtureHost(0).Address
		for _, job := range []string{f.jobA, f.archivedA, unknownPublicJobID} {
			if host, summary, err := f.store.Public(b).GetLatestSuccessfulJobHost(ctx, job, address); !errors.Is(err, ErrNotFound) || host.ScanID != "" || summary.ID != "" {
				t.Errorf("tenant B read job %s's host: %s, %v", job, host.ScanID, err)
			}
		}
		for scope, want := range map[PublicScope]struct{ job, scan string }{a: {f.jobA, f.scanA}, b: {f.jobB, f.scanB}} {
			host, summary, err := f.store.Public(scope).GetLatestSuccessfulJobHost(ctx, want.job, address)
			if err != nil || host.ScanID != want.scan || summary.JobID != want.job || host.Host.Address != address {
				t.Errorf("tenant %s: own host = %s from %s, %v", scope.TenantID(), host.ScanID, summary.JobID, err)
			}
		}
	},
}

// newPublicStatusFixture returns a copy of the tenant fixture in which both
// tenants publish hosts 0 to 2 of their "edge" job, and each "edge" job also
// has a legacy scan, without host index rows, that found host 0.
func newPublicStatusFixture(t *testing.T) tenantFixture {
	t.Helper()
	ctx := context.Background()
	f := newTenantFixture(t)
	publishTenantPages(t, f)
	for _, job := range []string{f.jobA, f.jobB} {
		legacy := model.Scan{ID: "legacy-" + job, JobID: job, Job: "edge", StartedAt: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC), FinishedAt: time.Date(2026, 9, 19, 12, 1, 0, 0, time.UTC), Status: "success",
			Snapshot: model.Snapshot{Units: []model.Unit{{Target: fixtureHost(0).Address, Addresses: []string{fixtureHost(0).Address}, Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}}}}}
		if err := f.store.System().SaveScan(ctx, legacy); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// Every exported PublicStore method has a case, and every case names a
// method.
func TestEveryPublicStoreMethodHasACase(t *testing.T) {
	methods := reflect.TypeOf(&PublicStore{})
	for i := 0; i < methods.NumMethod(); i++ {
		if name := methods.Method(i).Name; publicStoreCases[name] == nil {
			t.Errorf("PublicStore.%s has no case; add one to publicStoreCases that shows it reads only its tenant's rows", name)
		}
	}
	for name := range publicStoreCases {
		if _, ok := methods.MethodByName(name); !ok {
			t.Errorf("publicStoreCases has a case for %s, which is not an exported PublicStore method", name)
		}
	}
}

// TestPublicStoreIsolation runs every PublicStore case with tenant A read
// through the default public scope, as the legacy public URLs read it, and
// tenant B through its slug. It then checks that every PublicStore method
// refuses a store without a valid scope, and that the deprecated Store
// wrappers read only the default tenant.
func TestPublicStoreIsolation(t *testing.T) {
	names := make([]string, 0, len(publicStoreCases))
	for name := range publicStoreCases {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			f := newPublicStatusFixture(t)
			b, err := f.store.PublicScopeBySlug(context.Background(), "second")
			if err != nil || b.TenantID() != secondTenantID {
				t.Fatalf("tenant B's public scope = %q, %v", b.TenantID(), err)
			}
			publicStoreCases[name](t, f, DefaultPublicScope(), b)
		})
	}
	f := newPublicStatusFixture(t)
	t.Run("invalid scope", func(t *testing.T) { assertPublicStoreRefusesInvalidScopes(t, f) })
	t.Run("deprecated wrappers", func(t *testing.T) { assertDeprecatedPublicReadsUseTheDefaultTenant(t, f) })
}

// assertPublicStoreRefusesInvalidScopes calls every PublicStore method on a
// store without a valid scope. Each must refuse with ErrNoTenantScope before
// it reads anything, and return only zero values with the error.
func assertPublicStoreRefusesInvalidScopes(t *testing.T, f tenantFixture) {
	t.Helper()
	contextType := reflect.TypeOf((*context.Context)(nil)).Elem()
	var nilStore *PublicStore
	for label, ps := range map[string]*PublicStore{
		"zero scope": f.store.Public(PublicScope{}),
		"nil store":  nilStore,
		"no Store":   {scope: DefaultPublicScope()},
	} {
		receiver := reflect.ValueOf(ps)
		for i := 0; i < receiver.NumMethod(); i++ {
			method := receiver.Type().Method(i)
			fn := receiver.Method(i)
			args := make([]reflect.Value, fn.Type().NumIn())
			for j := range args {
				if in := fn.Type().In(j); in == contextType {
					args[j] = reflect.ValueOf(context.Background())
				} else {
					args[j] = reflect.Zero(in)
				}
			}
			results := fn.Call(args)
			err, _ := results[len(results)-1].Interface().(error)
			if !errors.Is(err, ErrNoTenantScope) || !errors.Is(err, ErrNotFound) {
				t.Errorf("%s: %s returned %v, want ErrNoTenantScope", label, method.Name, err)
			}
			for _, result := range results[:len(results)-1] {
				if !result.IsZero() {
					t.Errorf("%s: %s returned %v with its error", label, method.Name, result.Interface())
				}
			}
		}
	}
}

// assertDeprecatedPublicReadsUseTheDefaultTenant checks that the deprecated
// Store wrappers read only the default tenant, exactly as the default public
// scope does.
func assertDeprecatedPublicReadsUseTheDefaultTenant(t *testing.T, f tenantFixture) {
	t.Helper()
	ctx := context.Background()
	all := append(publicFixtureHosts(f.jobA), publicFixtureHosts(f.jobB)...)
	results, err := f.store.GetLatestSuccessfulJobHosts(ctx, all)
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := f.store.Public(DefaultPublicScope()).GetLatestSuccessfulJobHosts(ctx, all)
	if err != nil || !reflect.DeepEqual(results, scoped) {
		t.Fatalf("GetLatestSuccessfulJobHosts differs from the default public scope: %v", err)
	}
	if got, want := publicResultOwners(results), wantPublicOwners(f.scanA, f.jobA); !reflect.DeepEqual(got, want) {
		t.Errorf("GetLatestSuccessfulJobHosts = %v, want %v", got, want)
	}
	if _, _, err := f.store.GetLatestSuccessfulJobHost(ctx, f.jobB, fixtureHost(0).Address); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetLatestSuccessfulJobHost read tenant B's host: %v", err)
	}
	if host, _, err := f.store.GetLatestSuccessfulJobHost(ctx, f.jobA, fixtureHost(0).Address); err != nil || host.ScanID != f.scanA {
		t.Errorf("GetLatestSuccessfulJobHost = %s, %v; want %s", host.ScanID, err, f.scanA)
	}
	if scans, err := f.store.ListLegacyPublicScans(ctx, f.jobB, 10); err != nil || len(scans) != 0 {
		t.Errorf("ListLegacyPublicScans read tenant B's scans: %d, %v", len(scans), err)
	}
	if scans, err := f.store.ListLegacyPublicScans(ctx, f.jobA, 10); err != nil || len(scans) != 1 || scans[0].ID != "legacy-"+f.jobA {
		t.Errorf("ListLegacyPublicScans = %+v, %v", scans, err)
	}
}

// PublicScopeBySlug resolves only the enabled page of an active tenant, by
// its exact slug. An unknown slug, a withdrawn page, and a tenant that is
// not active all have no public scope, and a failed read is an error, never
// a scope.
func TestPublicScopeBySlug(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	notFound := func(label, slug string) {
		t.Helper()
		if scope, err := f.store.PublicScopeBySlug(ctx, slug); !errors.Is(err, ErrNoTenantScope) || !errors.Is(err, ErrNotFound) || scope != (PublicScope{}) {
			t.Errorf("%s: slug %q = %q, %v; want not found", label, slug, scope.TenantID(), err)
		}
	}
	found := func(slug string, want TenantScope) {
		t.Helper()
		if scope, err := f.store.PublicScopeBySlug(ctx, slug); err != nil || scope.TenantID() != want.ID() {
			t.Errorf("slug %q = %q, %v; want tenant %s", slug, scope.TenantID(), err, want.ID())
		}
	}
	// Tenant A's page is disabled as migrated, and tenant B has none yet.
	notFound("disabled page", "default")
	notFound("no page", "second")
	publishTenantPages(t, f)
	found("default", f.a)
	found("second", f.b)
	if scope, _ := f.store.PublicScopeBySlug(ctx, "default"); scope != DefaultPublicScope() {
		t.Errorf("the default tenant's slug = %q, want the default public scope", scope.TenantID())
	}
	for _, slug := range []string{"", "missing", "Second", " second", "second ", "00000000-0000-0000-0000-000000000200"} {
		notFound("unknown slug", slug)
	}
	if err := f.store.Tenant(f.b).SavePublicDashboard(ctx, PublicDashboard{Title: "tenant-b"}, publicFixtureHosts(f.jobB), AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	notFound("withdrawn page", "second")
	if err := f.store.Tenant(f.b).SavePublicDashboard(ctx, PublicDashboard{Enabled: true, Title: "tenant-b"}, publicFixtureHosts(f.jobB), AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	found("second", f.b)
	for _, state := range []string{TenantStateDisabled, TenantStateDeleting, TenantStateDeleted} {
		setTenantState(t, f.store, secondTenantID, state)
		notFound(state+" tenant", "second")
	}
	found("default", f.a)

	_ = f.store.Close()
	if scope, err := f.store.PublicScopeBySlug(ctx, "default"); err == nil || errors.Is(err, ErrNotFound) || scope != (PublicScope{}) {
		t.Errorf("closed store: slug lookup = %q, %v", scope.TenantID(), err)
	}
}
