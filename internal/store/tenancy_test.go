package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

// tenantFixture is a database with two tenants that look alike: each has an
// active job named "edge" and an archived job named "edge-archived", and
// the scan of each "edge" job found the same addresses. Tenant A is the
// default tenant; tenant B is created directly in SQL, because no product
// API creates a tenant yet.
type tenantFixture struct {
	store *Store
	a, b  TenantScope
	tenantFixtureIDs
}

// tenantFixtureIDs are the row IDs of a tenant fixture, the same in every
// copy.
type tenantFixtureIDs struct {
	jobA, jobB           string
	archivedA, archivedB string
	scanA, scanB         string
}

const (
	tenantFixtureJobB      = "00000000-0000-0000-0000-000000000b01"
	tenantFixtureArchivedB = "00000000-0000-0000-0000-000000000b02"
)

// tenantFixtureFile holds the database file that buildTenantFixture writes.
// A test binary builds it once, and each test opens its own copy, because
// opening a fresh database is the slow part of these tests.
var tenantFixtureFile struct {
	once     sync.Once
	contents []byte
	ids      tenantFixtureIDs
}

// newTenantFixture returns a private copy of the two-tenant fixture.
func newTenantFixture(t *testing.T) tenantFixture {
	t.Helper()
	tenantFixtureFile.once.Do(func() {
		path, ids := buildTenantFixture(t)
		for _, sidecar := range []string{"-wal", "-shm", "-journal"} {
			if _, err := os.Stat(path + sidecar); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the tenant fixture left %s behind: %v", sidecar, err)
			}
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		tenantFixtureFile.contents, tenantFixtureFile.ids = contents, ids
	})
	if len(tenantFixtureFile.contents) == 0 {
		t.Fatal("the tenant fixture could not be built")
	}
	path := filepath.Join(t.TempDir(), "tenants.db")
	if err := os.WriteFile(path, tenantFixtureFile.contents, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return tenantFixture{store: s, a: DefaultTenantScope(), b: TenantScope{id: secondTenantID}, tenantFixtureIDs: tenantFixtureFile.ids}
}

// buildTenantFixture writes the two-tenant fixture and returns the path of
// its database file, closed, with the IDs of its rows. It starts from
// openTestStore, so it gets faster whenever that does.
func buildTenantFixture(t *testing.T) (string, tenantFixtureIDs) {
	t.Helper()
	ctx := context.Background()
	s := openTestStore(t)
	jobA, err := s.CreateJob(ctx, testJob("edge"))
	if err != nil {
		t.Fatal(err)
	}
	archivedA, err := s.CreateJob(ctx, testJob("edge-archived"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE jobs SET archived=1,enabled=0 WHERE id=?`, archivedA.ID); err != nil {
		t.Fatal(err)
	}
	insertSecondTenant(t, s)
	insertSecondTenantJob(t, s, jobA.ID, tenantFixtureJobB)
	insertSecondTenantJob(t, s, archivedA.ID, tenantFixtureArchivedB)
	ids := tenantFixtureIDs{jobA: jobA.ID, jobB: tenantFixtureJobB, archivedA: archivedA.ID, archivedB: tenantFixtureArchivedB, scanA: "scan-tenant-a", scanB: "scan-tenant-b"}
	finished := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	for _, scan := range []struct{ id, job string }{{ids.scanA, ids.jobA}, {ids.scanB, ids.jobB}} {
		if err := s.SaveScan(ctx, fixtureScan(scan.id, scan.job, "edge", finished, fixtureHosts(0, 3))); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return s.Path, ids
}

// jobIDs returns the IDs of the records, sorted.
func jobIDs(records []JobRecord) []string {
	ids := make([]string, 0, len(records))
	for _, record := range records {
		ids = append(ids, record.ID)
	}
	sort.Strings(ids)
	return ids
}

func sortedIDs(ids ...string) []string {
	sort.Strings(ids)
	return ids
}

// tenantLeakCase shows that one TenantStore method keeps tenant B away
// from tenant A's rows.
type tenantLeakCase struct {
	// writes marks a case that changes the fixture. It gets its own copy;
	// the read-only cases share one, because opening a database is the slow
	// part of these tests.
	writes bool
	run    func(t *testing.T, f tenantFixture)
}

// tenantStoreLeakCases holds a leak case for every exported TenantStore
// method. Each case checks that tenant B cannot reach tenant A's rows by ID
// or by name, and that B's lists hold only B's rows, although both tenants
// use the same names and addresses. A case for a write also checks that A's
// rows are unchanged.
var tenantStoreLeakCases = map[string]tenantLeakCase{
	"GetJob": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		for _, id := range []string{f.jobA, f.archivedA} {
			if _, err := f.store.Tenant(f.b).GetJob(ctx, id); !errors.Is(err, ErrNotFound) {
				t.Errorf("tenant B read tenant A's job %s: %v", id, err)
			}
		}
		record, err := f.store.Tenant(f.b).GetJob(ctx, f.jobB)
		if err != nil || record.ID != f.jobB || record.Job.Name != "edge" {
			t.Fatalf("tenant B's own job = %+v, %v", record, err)
		}
		if record, err := f.store.Tenant(f.a).GetJob(ctx, f.jobA); err != nil || record.ID != f.jobA {
			t.Fatalf("tenant A's own job = %+v, %v", record, err)
		}
	}},
	"GetJobByName": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		for scope, want := range map[TenantScope]string{f.a: f.jobA, f.b: f.jobB} {
			record, err := f.store.Tenant(scope).GetJobByName(ctx, "edge")
			if err != nil || record.ID != want {
				t.Errorf("tenant %s: job edge = %s, %v; want %s", scope.ID(), record.ID, err, want)
			}
		}
		if _, err := f.store.Tenant(f.b).GetJobByName(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Errorf("missing job name: %v", err)
		}
	}},
	"ListJobs": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		for _, check := range []struct {
			scope           TenantScope
			includeArchived bool
			want            []string
		}{
			{f.b, false, []string{f.jobB}},
			{f.b, true, sortedIDs(f.jobB, f.archivedB)},
			{f.a, false, []string{f.jobA}},
			{f.a, true, sortedIDs(f.jobA, f.archivedA)},
		} {
			records, err := f.store.Tenant(check.scope).ListJobs(ctx, check.includeArchived)
			if err != nil {
				t.Fatal(err)
			}
			if got := jobIDs(records); !reflect.DeepEqual(got, check.want) {
				t.Errorf("tenant %s, archived %v: jobs = %v, want %v", check.scope.ID(), check.includeArchived, got, check.want)
			}
		}
	}},
}

// Every exported TenantStore method has a leak case, and every leak case
// names a method, so a method cannot move to TenantStore without one.
func TestEveryTenantStoreMethodHasALeakCase(t *testing.T) {
	methods := reflect.TypeOf(&TenantStore{})
	if methods.NumMethod() == 0 {
		t.Fatal("TenantStore has no exported methods")
	}
	for i := 0; i < methods.NumMethod(); i++ {
		if name := methods.Method(i).Name; tenantStoreLeakCases[name].run == nil {
			t.Errorf("TenantStore.%s has no leak case; add one to tenantStoreLeakCases that shows tenant B cannot reach tenant A's rows", name)
		}
	}
	for name := range tenantStoreLeakCases {
		if _, ok := methods.MethodByName(name); !ok {
			t.Errorf("tenantStoreLeakCases has a case for %s, which is not an exported TenantStore method", name)
		}
	}
}

// TestTenantStoreIsolation runs every leak case, then checks that every
// TenantStore method refuses a store without a valid scope and that the
// deprecated Store wrappers read only the default tenant. The read-only
// checks share one copy of the fixture.
func TestTenantStoreIsolation(t *testing.T) {
	shared := newTenantFixture(t)
	names := make([]string, 0, len(tenantStoreLeakCases))
	for name := range tenantStoreLeakCases {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			leak := tenantStoreLeakCases[name]
			f := shared
			if leak.writes {
				f = newTenantFixture(t)
			}
			leak.run(t, f)
		})
	}
	t.Run("invalid scope", func(t *testing.T) { assertTenantStoreRefusesInvalidScopes(t, shared) })
	t.Run("deprecated wrappers", func(t *testing.T) { assertDeprecatedJobReadsUseTheDefaultTenant(t, shared) })
}

// assertTenantStoreRefusesInvalidScopes calls every TenantStore method on a
// store without a valid scope. Each must refuse with ErrNoTenantScope before
// it reads anything, and return only zero values with the error.
func assertTenantStoreRefusesInvalidScopes(t *testing.T, f tenantFixture) {
	t.Helper()
	contextType := reflect.TypeOf((*context.Context)(nil)).Elem()
	var nilStore *TenantStore
	for label, ts := range map[string]*TenantStore{
		"zero scope": f.store.Tenant(TenantScope{}),
		"nil store":  nilStore,
		"no Store":   {scope: f.a},
	} {
		receiver := reflect.ValueOf(ts)
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
			last := results[len(results)-1]
			err, _ := last.Interface().(error)
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

// assertDeprecatedJobReadsUseTheDefaultTenant checks that the deprecated
// Store wrappers read only the default tenant.
func assertDeprecatedJobReadsUseTheDefaultTenant(t *testing.T, f tenantFixture) {
	t.Helper()
	ctx := context.Background()
	if _, err := f.store.GetJob(ctx, f.jobB); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetJob read tenant B's job: %v", err)
	}
	if record, err := f.store.GetJobByName(ctx, "edge"); err != nil || record.ID != f.jobA {
		t.Errorf("GetJobByName = %s, %v; want %s", record.ID, err, f.jobA)
	}
	records, err := f.store.ListJobs(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := jobIDs(records), sortedIDs(f.jobA, f.archivedA); !reflect.DeepEqual(got, want) {
		t.Errorf("ListJobs = %v, want %v", got, want)
	}
}

func TestTenantScopeValues(t *testing.T) {
	if (TenantScope{}).Valid() || (TenantScope{}).ID() != "" {
		t.Fatal("the zero scope must name no tenant")
	}
	if scope := DefaultTenantScope(); !scope.Valid() || scope.ID() != DefaultTenantID {
		t.Fatalf("default scope = %q", scope.ID())
	}
	if DefaultPublicScope().TenantID() != DefaultTenantID || (PublicScope{}).TenantID() != "" {
		t.Fatal("the public scope must name the default tenant, and its zero value none")
	}
}

// insertTenantUser adds an account directly in SQL; a nil tenant makes a
// platform administrator.
func insertTenantUser(t *testing.T, s *Store, id string, tenant any, role string) {
	t.Helper()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,created_at,updated_at) VALUES(?,?,?,?,?,'hash',?,?)`, id, tenant, id, id, role, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}

// TestTenantScopeLookups walks tenant B through its states on one copy of
// the fixture, because opening a database is the slow part of these tests.
//
//   - A session's scope is its account's tenant as users stores it, not the
//     session's role. Platform administrators, unknown accounts, and tenants
//     that are not active have no scope.
//   - The host and system lookup by ID accepts every tenant that is not
//     deleted, whatever its state.
//   - The system and platform stores list every tenant that is not deleted.
//   - A failed read is an error, never a scope.
func TestTenantScopeLookups(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	const (
		userA    = "00000000-0000-0000-0000-00000000a001"
		userB    = "00000000-0000-0000-0000-00000000b001"
		platform = "00000000-0000-0000-0000-00000000f001"
		unknown  = "00000000-0000-0000-0000-00000000dead"
	)
	insertTenantUser(t, f.store, userA, DefaultTenantID, RoleViewer)
	insertTenantUser(t, f.store, userB, secondTenantID, RoleOperator)
	insertTenantUser(t, f.store, platform, nil, RolePlatformAdmin)
	defaultTenant := Tenant{ID: DefaultTenantID, Name: "Default", Slug: "default", State: TenantStateActive, IsDefault: true}
	secondTenant := Tenant{ID: secondTenantID, Name: "Second", Slug: "second", State: TenantStateActive}

	check := func(state string, sessionB, byIDB bool) {
		t.Helper()
		for user, want := range map[string]TenantScope{userA: f.a, userB: f.b} {
			scope, err := f.store.TenantScopeForSession(ctx, Session{UserID: user, Role: RoleAdministrator})
			if user == userB && !sessionB {
				if !errors.Is(err, ErrNoTenantScope) || scope.Valid() {
					t.Errorf("%s tenant B: session scope = %q, %v", state, scope.ID(), err)
				}
				continue
			}
			if err != nil || scope != want {
				t.Errorf("%s: user %s: session scope = %q, %v; want %q", state, user, scope.ID(), err, want.ID())
			}
		}
		scope, err := f.store.TenantScopeByID(ctx, secondTenantID)
		if byIDB != (err == nil && scope == f.b) || (!byIDB && !errors.Is(err, ErrNoTenantScope)) {
			t.Errorf("%s tenant B: scope by ID = %q, %v", state, scope.ID(), err)
		}
		wantScopes, wantTenants := []TenantScope{f.a}, []Tenant{defaultTenant}
		if byIDB {
			secondTenant.State = state
			wantScopes, wantTenants = []TenantScope{f.a, f.b}, []Tenant{defaultTenant, secondTenant}
		}
		if scopes, err := f.store.System().TenantScopes(ctx); err != nil || !reflect.DeepEqual(scopes, wantScopes) {
			t.Errorf("%s: system scopes = %v, %v", state, scopes, err)
		}
		if tenants, err := f.store.Platform().Tenants(ctx); err != nil || !reflect.DeepEqual(tenants, wantTenants) {
			t.Errorf("%s: platform tenants = %+v, %v", state, tenants, err)
		}
	}

	check(TenantStateActive, true, true)
	if scope, err := f.store.TenantScopeByID(ctx, DefaultTenantID); err != nil || scope != f.a {
		t.Errorf("default tenant: scope by ID = %q, %v", scope.ID(), err)
	}
	for label, session := range map[string]Session{
		"platform role in the session": {UserID: userA, Role: RolePlatformAdmin},
		"platform account":             {UserID: platform, Role: RoleAdministrator},
		"unknown account":              {UserID: unknown, Role: RoleAdministrator},
		"no account":                   {Role: RoleAdministrator},
	} {
		if scope, err := f.store.TenantScopeForSession(ctx, session); !errors.Is(err, ErrNoTenantScope) || !errors.Is(err, ErrNotFound) || scope.Valid() {
			t.Errorf("%s: session scope = %q, %v", label, scope.ID(), err)
		}
	}
	for _, id := range []string{"", unknown} {
		if scope, err := f.store.TenantScopeByID(ctx, id); !errors.Is(err, ErrNoTenantScope) || scope.Valid() {
			t.Errorf("tenant %q: scope by ID = %q, %v", id, scope.ID(), err)
		}
	}
	for _, state := range []string{TenantStateDisabled, TenantStateDeleting} {
		setTenantState(t, f.store, secondTenantID, state)
		check(state, false, true)
	}
	setTenantState(t, f.store, secondTenantID, TenantStateDeleted)
	check(TenantStateDeleted, false, false)

	_ = f.store.Close()
	if _, err := f.store.TenantScopeForSession(ctx, Session{UserID: userA}); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("closed store: session scope error = %v", err)
	}
	if _, err := f.store.TenantScopeByID(ctx, DefaultTenantID); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("closed store: scope by ID error = %v", err)
	}
	if _, err := f.store.System().TenantScopes(ctx); err == nil {
		t.Error("system scopes read a closed store")
	}
	if _, err := f.store.Platform().Tenants(ctx); err == nil {
		t.Error("platform tenants read a closed store")
	}
}
