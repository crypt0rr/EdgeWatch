package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
)

// The scanner profile cases join tenantStoreLeakCases before any test runs,
// so each store slice keeps its leak cases in its own file.
func init() {
	for name, leak := range scannerProfileLeakCases {
		if _, duplicate := tenantStoreLeakCases[name]; duplicate {
			panic("two leak cases for TenantStore." + name)
		}
		tenantStoreLeakCases[name] = leak
	}
}

// tenantFixtureProfiles holds the IDs of the custom profiles that
// addTenantProfiles gives the tenant fixture. The fixture is built once and
// copied, so they are the same in every copy.
var tenantFixtureProfiles struct {
	a, archivedA, b, archivedB string
}

// unknownScannerProfileID names no profile in any tenant.
const unknownScannerProfileID = "00000000-0000-0000-0000-00000000dead"

// addTenantProfiles gives each tenant of the fixture two custom profiles
// with the same names: "edge", revised once, and "edge-archived", archived.
// Both are at revision 2, and their descriptions name their tenant. The two
// built-in profiles belong to no tenant and are shared.
func addTenantProfiles(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	create := func(scope TenantScope, marker, name string, archive bool) string {
		t.Helper()
		ts := s.Tenant(scope)
		profile, err := ts.CreateScannerProfile(ctx, name, marker, config.ScannerProfile{Engine: config.EngineNmap, Description: marker}, "fixture")
		if err != nil {
			t.Fatal(err)
		}
		if archive {
			err = ts.SetScannerProfileArchived(ctx, profile.ID, true, profile.Revision, "fixture")
		} else {
			_, err = ts.UpdateScannerProfile(ctx, profile.ID, profile.Revision, name, marker, config.ScannerProfile{Engine: config.EngineNmap, Description: marker + " v2"}, "fixture")
		}
		if err != nil {
			t.Fatal(err)
		}
		return profile.ID
	}
	a, b := DefaultTenantScope(), TenantScope{id: secondTenantID}
	tenantFixtureProfiles.a = create(a, "tenant-a", "edge", false)
	tenantFixtureProfiles.archivedA = create(a, "tenant-a", "edge-archived", true)
	tenantFixtureProfiles.b = create(b, "tenant-b", "edge", false)
	tenantFixtureProfiles.archivedB = create(b, "tenant-b", "edge-archived", true)
}

// withBuiltinProfiles returns the IDs with the built-in profiles' IDs, sorted.
func withBuiltinProfiles(ids ...string) []string {
	return sortedIDs(append([]string{BuiltinNmapProfileID, BuiltinNaabuProfileID}, ids...)...)
}

// scannerProfileIDs returns the IDs of the profiles, sorted.
func scannerProfileIDs(profiles []ScannerProfileRecord) []string {
	ids := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		ids = append(ids, profile.ID)
	}
	sort.Strings(ids)
	return ids
}

// scannerProfileSnapshot returns, as text, every row of the profiles the
// tenant can use, the built-ins and its own, and of their revisions, so a
// test can show that a write through another tenant left them unchanged.
func scannerProfileSnapshot(t *testing.T, s *Store, scope TenantScope) string {
	t.Helper()
	return scannerProfileRows(t, s, `SELECT * FROM scanner_profiles WHERE tenant_id IS NULL OR tenant_id=? ORDER BY rowid`, scope) +
		scannerProfileRows(t, s, `SELECT r.* FROM scanner_profile_revisions AS r JOIN scanner_profiles AS p ON p.id=r.profile_id WHERE p.tenant_id IS NULL OR p.tenant_id=? ORDER BY r.rowid`, scope)
}

// scannerProfileRows returns the rows of the query for the tenant as text.
func scannerProfileRows(t *testing.T, s *Store, query string, scope TenantScope) string {
	t.Helper()
	rows, err := s.DB.Query(query, scope.ID())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	values := make([]any, len(columns))
	pointers := make([]any, len(columns))
	for i := range values {
		pointers[i] = &values[i]
	}
	text := ""
	for rows.Next() {
		if err := rows.Scan(pointers...); err != nil {
			t.Fatal(err)
		}
		text += fmt.Sprintf("%q\n", values)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return text
}

// scannerProfileLeakCases show that tenant B sees and changes only the
// built-in profiles, read-only as before, and its own, although both tenants
// have custom profiles with the same names. Another tenant's profile is not
// found, exactly as an unknown ID.
var scannerProfileLeakCases = map[string]tenantLeakCase{
	"ListScannerProfiles": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		p := tenantFixtureProfiles
		for _, check := range []struct {
			scope           TenantScope
			includeArchived bool
			want            []string
		}{
			{f.b, false, withBuiltinProfiles(p.b)},
			{f.b, true, withBuiltinProfiles(p.b, p.archivedB)},
			{f.a, false, withBuiltinProfiles(p.a)},
			{f.a, true, withBuiltinProfiles(p.a, p.archivedA)},
		} {
			profiles, err := f.store.Tenant(check.scope).ListScannerProfiles(ctx, check.includeArchived)
			if err != nil {
				t.Fatal(err)
			}
			if got := scannerProfileIDs(profiles); !reflect.DeepEqual(got, check.want) {
				t.Errorf("tenant %s, archived %v: profiles = %v, want %v", check.scope.ID(), check.includeArchived, got, check.want)
			}
		}
	}},
	// A profile whose definition cannot be read is reported in Invalid, with
	// its ID and name, only to its own tenant.
	"ListScannerProfilesReport": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		p := tenantFixtureProfiles
		if _, err := f.store.DB.ExecContext(ctx, `UPDATE scanner_profiles SET definition_json=? WHERE id=?`, []byte(`{"engine":`), p.archivedA); err != nil {
			t.Fatal(err)
		}
		for _, check := range []struct {
			scope           TenantScope
			includeArchived bool
			want, invalid   []string
		}{
			{f.b, true, withBuiltinProfiles(p.b, p.archivedB), nil},
			{f.b, false, withBuiltinProfiles(p.b), nil},
			{f.a, true, withBuiltinProfiles(p.a), []string{p.archivedA}},
			{f.a, false, withBuiltinProfiles(p.a), nil},
		} {
			report, err := f.store.Tenant(check.scope).ListScannerProfilesReport(ctx, check.includeArchived)
			if err != nil {
				t.Fatal(err)
			}
			var invalid []string
			for _, profile := range report.Invalid {
				invalid = append(invalid, profile.ID)
			}
			if got := scannerProfileIDs(report.Profiles); !reflect.DeepEqual(got, check.want) || !reflect.DeepEqual(invalid, check.invalid) {
				t.Errorf("tenant %s, archived %v: profiles = %v, invalid = %v; want %v, %v", check.scope.ID(), check.includeArchived, got, invalid, check.want, check.invalid)
			}
		}
	}},
	"GetScannerProfile": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		p := tenantFixtureProfiles
		for _, id := range []string{p.a, p.archivedA, unknownScannerProfileID} {
			if profile, err := f.store.Tenant(f.b).GetScannerProfile(ctx, id); !errors.Is(err, ErrNotFound) || profile.ID != "" {
				t.Errorf("tenant B read profile %s: %+v, %v", id, profile, err)
			}
		}
		for _, id := range []string{BuiltinNmapProfileID, BuiltinNaabuProfileID} {
			if profile, err := f.store.Tenant(f.b).GetScannerProfile(ctx, id); err != nil || !profile.BuiltIn {
				t.Errorf("tenant B's built-in profile %s = %+v, %v", id, profile, err)
			}
		}
		for scope, want := range map[TenantScope]struct{ id, description string }{f.a: {p.a, "tenant-a v2"}, f.b: {p.b, "tenant-b v2"}} {
			profile, err := f.store.Tenant(scope).GetScannerProfile(ctx, want.id)
			if err != nil || profile.Name != "edge" || profile.Revision != 2 || profile.Definition.Description != want.description {
				t.Errorf("tenant %s's own profile = %+v, %v", scope.ID(), profile, err)
			}
		}
	}},
	"CurrentScannerProfileRevisions": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		p := tenantFixtureProfiles
		for scope, own := range map[TenantScope][]string{f.a: {p.a, p.archivedA}, f.b: {p.b, p.archivedB}} {
			revisions, err := f.store.Tenant(scope).CurrentScannerProfileRevisions(ctx)
			if err != nil {
				t.Fatal(err)
			}
			ids := make([]string, 0, len(revisions))
			for id := range revisions {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			if want := withBuiltinProfiles(own...); !reflect.DeepEqual(ids, want) {
				t.Errorf("tenant %s: revisions of %v, want %v", scope.ID(), ids, want)
			}
			for _, id := range own {
				if revisions[id] != 2 {
					t.Errorf("tenant %s: profile %s at revision %d, want 2", scope.ID(), id, revisions[id])
				}
			}
		}
	}},
	"GetScannerProfileRevision": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		p := tenantFixtureProfiles
		for _, id := range []string{p.a, p.archivedA, unknownScannerProfileID} {
			for _, revision := range []int64{1, 2} {
				if found, err := f.store.Tenant(f.b).GetScannerProfileRevision(ctx, id, revision); !errors.Is(err, ErrNotFound) || found.ProfileID != "" {
					t.Errorf("tenant B read revision %d of profile %s: %+v, %v", revision, id, found, err)
				}
			}
		}
		if found, err := f.store.Tenant(f.b).GetScannerProfileRevision(ctx, BuiltinNmapProfileID, 1); err != nil || found.ProfileID != BuiltinNmapProfileID {
			t.Errorf("tenant B's built-in revision = %+v, %v", found, err)
		}
		for scope, want := range map[TenantScope]struct{ id, description string }{f.a: {p.a, "tenant-a"}, f.b: {p.b, "tenant-b"}} {
			found, err := f.store.Tenant(scope).GetScannerProfileRevision(ctx, want.id, 1)
			if err != nil || found.ProfileID != want.id || found.Revision != 1 || found.Definition.Description != want.description {
				t.Errorf("tenant %s's own revision = %+v, %v", scope.ID(), found, err)
			}
		}
	}},
	"ListScannerProfileRevisions": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		p := tenantFixtureProfiles
		for _, id := range []string{p.a, p.archivedA, unknownScannerProfileID} {
			if revisions, err := f.store.Tenant(f.b).ListScannerProfileRevisions(ctx, id); !errors.Is(err, ErrNotFound) || revisions != nil {
				t.Errorf("tenant B listed the revisions of profile %s: %+v, %v", id, revisions, err)
			}
		}
		if revisions, err := f.store.Tenant(f.b).ListScannerProfileRevisions(ctx, BuiltinNaabuProfileID); err != nil || len(revisions) == 0 || revisions[0].ProfileID != BuiltinNaabuProfileID {
			t.Errorf("tenant B's built-in revisions = %+v, %v", revisions, err)
		}
		for scope, want := range map[TenantScope]struct{ id, marker string }{f.a: {p.a, "tenant-a"}, f.b: {p.b, "tenant-b"}} {
			revisions, err := f.store.Tenant(scope).ListScannerProfileRevisions(ctx, want.id)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, revision := range revisions {
				got = append(got, fmt.Sprintf("%s %d %s", revision.ProfileID, revision.Revision, revision.Definition.Description))
			}
			if expected := []string{want.id + " 2 " + want.marker + " v2", want.id + " 1 " + want.marker}; !reflect.DeepEqual(got, expected) {
				t.Errorf("tenant %s's own revisions = %q, want %q", scope.ID(), got, expected)
			}
		}
	}},
	// A profile belongs to the tenant that creates it. Names are unique
	// within a tenant, so tenant B may use a name that tenant A uses, and the
	// built-in names stay reserved in every tenant.
	"CreateScannerProfile": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		nmap := config.ScannerProfile{Engine: config.EngineNmap}
		first, err := f.store.Tenant(f.a).CreateScannerProfile(ctx, "Shared name", "tenant-a", nmap, "admin-a")
		if err != nil {
			t.Fatal(err)
		}
		before := scannerProfileSnapshot(t, f.store, f.a)
		created, err := f.store.Tenant(f.b).CreateScannerProfile(ctx, "SHARED NAME", "tenant-b", nmap, "admin-b")
		if err != nil {
			t.Fatalf("tenant B could not use a name that tenant A uses: %v", err)
		}
		var owner string
		if err := f.store.DB.QueryRowContext(ctx, `SELECT tenant_id FROM scanner_profiles WHERE id=?`, created.ID).Scan(&owner); err != nil || owner != secondTenantID {
			t.Fatalf("created profile's tenant = %q, %v", owner, err)
		}
		if _, err := f.store.Tenant(f.a).GetScannerProfile(ctx, created.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("tenant A read tenant B's new profile: %v", err)
		}
		if profile, err := f.store.Tenant(f.b).GetScannerProfile(ctx, created.ID); err != nil || profile.Name != "SHARED NAME" || profile.BuiltIn {
			t.Errorf("tenant B's new profile = %+v, %v", profile, err)
		}
		if revisions, err := f.store.Tenant(f.b).ListScannerProfileRevisions(ctx, created.ID); err != nil || len(revisions) != 1 || revisions[0].CreatedBy != "admin-b" {
			t.Errorf("tenant B's new profile revisions = %+v, %v", revisions, err)
		}
		if _, err := f.store.Tenant(f.b).CreateScannerProfile(ctx, "Edge", "", nmap, "admin-b"); err == nil || !strings.Contains(err.Error(), "scanner_profiles_tenant_name") {
			t.Errorf("tenant B created a second profile named like its own: %v", err)
		}
		if _, err := f.store.Tenant(f.b).CreateScannerProfile(ctx, " nmap standard ", "", nmap, "admin-b"); !errors.Is(err, ErrScannerProfileNameInUse) {
			t.Errorf("tenant B created a profile named like a built-in: %v", err)
		}
		if after := scannerProfileSnapshot(t, f.store, f.a); after != before {
			t.Fatal("a create through tenant B changed tenant A's profiles")
		}
		if profile, err := f.store.Tenant(f.a).GetScannerProfile(ctx, first.ID); err != nil || profile.Name != "Shared name" {
			t.Errorf("tenant A's profile = %+v, %v", profile, err)
		}
	}},
	// Tenant B cannot update tenant A's profiles, even with their current
	// revision, and a built-in profile stays immutable. B's own profile may
	// take a name that tenant A uses.
	"UpdateScannerProfile": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		p := tenantFixtureProfiles
		nmap := config.ScannerProfile{Engine: config.EngineNmap, Description: "stolen"}
		if _, err := f.store.Tenant(f.a).CreateScannerProfile(ctx, "a-only", "", nmap, "admin-a"); err != nil {
			t.Fatal(err)
		}
		before := scannerProfileSnapshot(t, f.store, f.a)
		for _, id := range []string{p.a, p.archivedA, unknownScannerProfileID} {
			if profile, err := f.store.Tenant(f.b).UpdateScannerProfile(ctx, id, 2, "stolen", "", nmap, "admin-b"); !errors.Is(err, ErrNotFound) || profile.ID != "" {
				t.Errorf("tenant B updated profile %s: %+v, %v", id, profile, err)
			}
		}
		builtin, err := f.store.Tenant(f.b).GetScannerProfile(ctx, BuiltinNmapProfileID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Tenant(f.b).UpdateScannerProfile(ctx, builtin.ID, builtin.Revision, "stolen", "", nmap, "admin-b"); !errors.Is(err, ErrValidation) {
			t.Errorf("tenant B updated a built-in profile: %v", err)
		}
		if after := scannerProfileSnapshot(t, f.store, f.a); after != before {
			t.Fatal("updates through tenant B changed tenant A's or the built-in profiles")
		}
		updated, err := f.store.Tenant(f.b).UpdateScannerProfile(ctx, p.b, 2, "A-ONLY", "renamed", nmap, "admin-b")
		if err != nil || updated.Revision != 3 || updated.Name != "A-ONLY" {
			t.Fatalf("tenant B's own profile update = %+v, %v", updated, err)
		}
		if revision, err := f.store.Tenant(f.b).GetScannerProfileRevision(ctx, p.b, 3); err != nil || revision.CreatedBy != "admin-b" || revision.Definition.Description != "stolen" {
			t.Errorf("tenant B's new revision = %+v, %v", revision, err)
		}
		if after := scannerProfileSnapshot(t, f.store, f.a); after != before {
			t.Fatal("tenant B's update of its own profile changed tenant A's profiles")
		}
	}},
	// Tenant B cannot archive or restore tenant A's profiles, even with their
	// current revision, and a built-in profile stays immutable.
	"SetScannerProfileArchived": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		p := tenantFixtureProfiles
		before := scannerProfileSnapshot(t, f.store, f.a)
		for _, write := range []struct {
			id       string
			archived bool
		}{{p.a, true}, {p.archivedA, false}, {unknownScannerProfileID, true}} {
			if err := f.store.Tenant(f.b).SetScannerProfileArchived(ctx, write.id, write.archived, 2, "admin-b"); !errors.Is(err, ErrNotFound) {
				t.Errorf("tenant B set profile %s archived=%v: %v", write.id, write.archived, err)
			}
		}
		builtin, err := f.store.Tenant(f.b).GetScannerProfile(ctx, BuiltinNaabuProfileID)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.Tenant(f.b).SetScannerProfileArchived(ctx, builtin.ID, true, builtin.Revision, "admin-b"); !errors.Is(err, ErrValidation) {
			t.Errorf("tenant B archived a built-in profile: %v", err)
		}
		if after := scannerProfileSnapshot(t, f.store, f.a); after != before {
			t.Fatal("lifecycle writes through tenant B changed tenant A's or the built-in profiles")
		}
		// The lifecycle revision keeps the profile's current definition.
		for _, write := range []struct {
			id, description string
			archived        bool
		}{{p.b, "tenant-b v2", true}, {p.archivedB, "tenant-b", false}} {
			if err := f.store.Tenant(f.b).SetScannerProfileArchived(ctx, write.id, write.archived, 2, "admin-b"); err != nil {
				t.Fatalf("tenant B's own profile %s: %v", write.id, err)
			}
			profile, err := f.store.Tenant(f.b).GetScannerProfile(ctx, write.id)
			if err != nil || profile.Archived != write.archived || profile.Revision != 3 {
				t.Errorf("tenant B's own profile = %+v, %v", profile, err)
			}
			revision, err := f.store.Tenant(f.b).GetScannerProfileRevision(ctx, write.id, 3)
			if err != nil || revision.CreatedBy != "admin-b" || revision.Definition.Description != write.description {
				t.Errorf("tenant B's lifecycle revision = %+v, %v", revision, err)
			}
		}
		if after := scannerProfileSnapshot(t, f.store, f.a); after != before {
			t.Fatal("tenant B's lifecycle writes to its own profiles changed tenant A's profiles")
		}
	}},
}
