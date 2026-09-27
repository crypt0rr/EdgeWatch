package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// The scan and host reads join tenantStoreLeakCases from here, so this
// slice's cases stay apart from those of the other slices.
func init() {
	for name, leak := range scanTenantLeakCases {
		if _, exists := tenantStoreLeakCases[name]; exists {
			panic("duplicate tenant leak case " + name)
		}
		tenantStoreLeakCases[name] = leak
	}
}

// scanIDs returns the IDs of the scans, sorted.
func scanIDs(scans []model.Scan) []string {
	ids := make([]string, 0, len(scans))
	for _, scan := range scans {
		ids = append(ids, scan.ID)
	}
	sort.Strings(ids)
	return ids
}

// summaryIDs returns the IDs of the summaries, sorted, and fails unless each
// carries the tenant it was read for.
func summaryIDs(t *testing.T, scope TenantScope, summaries []model.ScanSummary) []string {
	t.Helper()
	ids := make([]string, 0, len(summaries))
	for _, summary := range summaries {
		if summary.TenantID != scope.ID() {
			t.Errorf("tenant %s: summary %s has tenant %q", scope.ID(), summary.ID, summary.TenantID)
		}
		ids = append(ids, summary.ID)
	}
	sort.Strings(ids)
	return ids
}

// hostOwners returns "scan/address" for each host, sorted, so a list shows
// which scan every address came from.
func hostOwners[T any](items []T, owner func(T) (scanID, address string)) []string {
	owners := make([]string, 0, len(items))
	for _, item := range items {
		scanID, address := owner(item)
		owners = append(owners, scanID+"/"+address)
	}
	sort.Strings(owners)
	return owners
}

// fixtureHostOwners returns the owners of hosts first..last-1 of a scan.
func fixtureHostOwners(scanID string, first, last int) []string {
	owners := make([]string, 0, last-first)
	for i := first; i < last; i++ {
		owners = append(owners, scanID+"/"+fixtureHost(i).Address)
	}
	sort.Strings(owners)
	return owners
}

// latestHostOwner describes a latest host with its scan and job.
func latestHostOwner(host LatestScanHost) (string, string) {
	return host.ScanID + "@" + host.JobID, host.Host.Address
}

// tenantFixtureScan is the scan of a tenant fixture's "edge" job. Both
// tenants' scans found hosts 0 to 2, and each records two changes and two
// units named after the scan, so a leak of either shows in a list.
func tenantFixtureScan(id, jobID string, finished time.Time) model.Scan {
	scan := fixtureScan(id, jobID, "edge", finished, fixtureHosts(0, 3))
	for i := 0; i < 2; i++ {
		scan.Changes = append(scan.Changes, model.Change{Key: fmt.Sprintf("%s-change-%d", id, i), Kind: "port_opened", Severity: "high", Target: fixtureHost(i).Address, Protocol: "tcp", Port: 443})
		scan.Snapshot.Units = append(scan.Snapshot.Units, model.Unit{Target: fmt.Sprintf("%s-unit-%d", id, i), Protocol: "tcp"})
	}
	return scan
}

// fixtureScanKeys returns the change keys, or with units the unit targets,
// that tenantFixtureScan records for a scan.
func fixtureScanKeys(id string, units bool) []string {
	kind := "change"
	if units {
		kind = "unit"
	}
	return []string{fmt.Sprintf("%s-%s-0", id, kind), fmt.Sprintf("%s-%s-1", id, kind)}
}

// scanTenantLeakCases show that tenant B cannot reach tenant A's scans and
// hosts by scan ID, by job ID, or through the host inventory and its search,
// although both tenants' scans found the same addresses.
var scanTenantLeakCases = map[string]tenantLeakCase{
	"GetScan": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		if scan, err := f.store.Tenant(f.b).GetScan(ctx, f.scanA); !errors.Is(err, ErrNotFound) || scan.ID != "" {
			t.Errorf("tenant B read tenant A's scan: %+v, %v", scan.ID, err)
		}
		if _, err := f.store.Tenant(f.b).GetScan(ctx, "missing-scan"); !errors.Is(err, ErrNotFound) {
			t.Errorf("unknown scan: %v", err)
		}
		for scope, want := range map[TenantScope]string{f.a: f.scanA, f.b: f.scanB} {
			scan, err := f.store.Tenant(scope).GetScan(ctx, want)
			if err != nil || scan.ID != want || len(scan.Snapshot.Hosts) != 3 {
				t.Errorf("tenant %s: own scan = %s with %d hosts, %v", scope.ID(), scan.ID, len(scan.Snapshot.Hosts), err)
			}
		}
	}},
	"GetScanSummary": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		if summary, err := f.store.Tenant(f.b).GetScanSummary(ctx, f.scanA); !errors.Is(err, ErrNotFound) || summary != (model.ScanSummary{}) {
			t.Errorf("tenant B read tenant A's scan summary: %+v, %v", summary, err)
		}
		for scope, want := range map[TenantScope]string{f.a: f.scanA, f.b: f.scanB} {
			summary, err := f.store.Tenant(scope).GetScanSummary(ctx, want)
			if err != nil || summary.ID != want || summary.TenantID != scope.ID() {
				t.Errorf("tenant %s: own scan summary = %+v, %v", scope.ID(), summary, err)
			}
		}
	}},
	"GetScanComparison": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		if summary, changes, err := f.store.Tenant(f.b).GetScanComparison(ctx, f.scanA); !errors.Is(err, ErrNotFound) || summary.ID != "" || changes != nil {
			t.Errorf("tenant B read tenant A's comparison: %s with %d changes, %v", summary.ID, len(changes), err)
		}
		for scope, id := range map[TenantScope]string{f.a: f.scanA, f.b: f.scanB} {
			summary, changes, err := f.store.Tenant(scope).GetScanComparison(ctx, id)
			keys := make([]string, 0, len(changes))
			for _, change := range changes {
				keys = append(keys, change.Key)
			}
			if err != nil || summary.ID != id || summary.TenantID != scope.ID() || !reflect.DeepEqual(keys, fixtureScanKeys(id, false)) {
				t.Errorf("tenant %s: own comparison = %s (%q) with changes %v, %v", scope.ID(), summary.ID, summary.TenantID, keys, err)
			}
		}
	}},
	"GetLatestSuccessfulJobScanSummary": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		if summary, err := f.store.Tenant(f.b).GetLatestSuccessfulJobScanSummary(ctx, f.jobA); err != nil || summary != nil {
			t.Errorf("tenant B read the latest scan of tenant A's job: %+v, %v", summary, err)
		}
		for scope, want := range map[TenantScope][2]string{f.a: {f.jobA, f.scanA}, f.b: {f.jobB, f.scanB}} {
			summary, err := f.store.Tenant(scope).GetLatestSuccessfulJobScanSummary(ctx, want[0])
			if err != nil || summary == nil || summary.ID != want[1] || summary.TenantID != scope.ID() {
				t.Errorf("tenant %s: latest scan of its job = %+v, %v", scope.ID(), summary, err)
			}
		}
	}},
	"ListScanChangesPage": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		if page, err := f.store.Tenant(f.b).ListScanChangesPage(ctx, f.scanA, 50, 0); err != nil || page.Total != 0 || len(page.Items) != 0 {
			t.Errorf("tenant B read tenant A's changes: %+v, %v", page, err)
		}
		for scope, id := range map[TenantScope]string{f.a: f.scanA, f.b: f.scanB} {
			page, err := f.store.Tenant(scope).ListScanChangesPage(ctx, id, 50, 0)
			keys := make([]string, 0, len(page.Items))
			for _, change := range page.Items {
				keys = append(keys, change.Key)
			}
			if want := fixtureScanKeys(id, false); err != nil || page.Total != len(want) || !reflect.DeepEqual(keys, want) {
				t.Errorf("tenant %s: own changes = %v (total %d), %v; want %v", scope.ID(), keys, page.Total, err, want)
			}
		}
	}},
	"ListScanResultsPage": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		if page, err := f.store.Tenant(f.b).ListScanResultsPage(ctx, f.scanA, 50, 0); err != nil || page.Total != 0 || len(page.Items) != 0 {
			t.Errorf("tenant B read tenant A's results: %+v, %v", page, err)
		}
		for scope, id := range map[TenantScope]string{f.a: f.scanA, f.b: f.scanB} {
			page, err := f.store.Tenant(scope).ListScanResultsPage(ctx, id, 50, 0)
			targets := make([]string, 0, len(page.Items))
			for _, unit := range page.Items {
				targets = append(targets, unit.Target)
			}
			if want := fixtureScanKeys(id, true); err != nil || page.Total != len(want) || !reflect.DeepEqual(targets, want) {
				t.Errorf("tenant %s: own results = %v (total %d), %v; want %v", scope.ID(), targets, page.Total, err, want)
			}
		}
	}},
	"ListScanHostsPage": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		scanHostOwner := func(host ScanHost) (string, string) { return host.ScanID, host.Host.Address }
		for _, query := range []string{"", fixtureHost(0).Address, "10"} {
			if page, err := f.store.Tenant(f.b).ListScanHostsPage(ctx, f.scanA, query, "", nil, 50, 0); err != nil || page.Total != 0 || len(page.Items) != 0 {
				t.Errorf("tenant B read tenant A's scan hosts for %q: %+v, %v", query, page, err)
			}
		}
		for scope, scanID := range map[TenantScope]string{f.a: f.scanA, f.b: f.scanB} {
			page, err := f.store.Tenant(scope).ListScanHostsPage(ctx, scanID, "", "", nil, 50, 0)
			if got, want := hostOwners(page.Items, scanHostOwner), fixtureHostOwners(scanID, 0, 3); err != nil || page.Total != 3 || !reflect.DeepEqual(got, want) {
				t.Errorf("tenant %s: own scan hosts = %v (total %d), %v; want %v", scope.ID(), got, page.Total, err, want)
			}
			page, err = f.store.Tenant(scope).ListScanHostsPage(ctx, scanID, fixtureHost(0).Address, "", nil, 50, 0)
			if got, want := hostOwners(page.Items, scanHostOwner), fixtureHostOwners(scanID, 0, 1); err != nil || page.Total != 1 || !reflect.DeepEqual(got, want) {
				t.Errorf("tenant %s: own scan host search = %v (total %d), %v; want %v", scope.ID(), got, page.Total, err, want)
			}
		}
	}},
	"GetScanHost": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		address := fixtureHost(1).Address
		if host, err := f.store.Tenant(f.b).GetScanHost(ctx, f.scanA, address); !errors.Is(err, ErrNotFound) || host.ScanID != "" {
			t.Errorf("tenant B read a host of tenant A's scan: %+v, %v", host, err)
		}
		for scope, scanID := range map[TenantScope]string{f.a: f.scanA, f.b: f.scanB} {
			host, err := f.store.Tenant(scope).GetScanHost(ctx, scanID, address)
			if err != nil || host.ScanID != scanID || host.Host.Address != address {
				t.Errorf("tenant %s: own scan host = %+v, %v", scope.ID(), host, err)
			}
		}
	}},
	"ScanHostIndexExists": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		for _, check := range []struct {
			scope  TenantScope
			scanID string
			want   bool
		}{{f.b, f.scanA, false}, {f.b, f.scanB, true}, {f.a, f.scanA, true}, {f.a, f.scanB, false}} {
			if exists, err := f.store.Tenant(check.scope).ScanHostIndexExists(ctx, check.scanID); err != nil || exists != check.want {
				t.Errorf("tenant %s: host index of %s = %v, %v; want %v", check.scope.ID(), check.scanID, exists, err, check.want)
			}
		}
	}},
	"SuccessfulScanHostIndexExists": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		// Tenant B's only scan did not succeed, so only tenant A's
		// successful scan has a host index.
		if _, err := f.store.DB.ExecContext(ctx, `UPDATE scans SET status='failed' WHERE id=?`, f.scanB); err != nil {
			t.Fatal(err)
		}
		for scope, want := range map[TenantScope]bool{f.a: true, f.b: false} {
			if exists, err := f.store.Tenant(scope).SuccessfulScanHostIndexExists(ctx); err != nil || exists != want {
				t.Errorf("tenant %s: successful host index = %v, %v; want %v", scope.ID(), exists, err, want)
			}
		}
	}},
	"LegacySuccessfulScanExists": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		// A successful scan without host observations has no host index,
		// like a scan from before the index existed. Only tenant A has one.
		legacy := fixtureScan("legacy-tenant-a", f.jobA, "edge", time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC), nil)
		if err := f.store.System().SaveScan(ctx, legacy); err != nil {
			t.Fatal(err)
		}
		for scope, want := range map[TenantScope]bool{f.a: true, f.b: false} {
			if exists, err := f.store.Tenant(scope).LegacySuccessfulScanExists(ctx); err != nil || exists != want {
				t.Errorf("tenant %s: legacy successful scan = %v, %v; want %v", scope.ID(), exists, err, want)
			}
		}
	}},
	// The hosts page reads the snapshots of the scans without a host index
	// through this list, so each tenant lists and counts only its own.
	"ListLegacySuccessfulScanSnapshotsPage": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		finished := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
		own := map[TenantScope]string{f.a: "legacy-tenant-a", f.b: "legacy-tenant-b"}
		for scope, job := range map[TenantScope]string{f.a: f.jobA, f.b: f.jobB} {
			if err := f.store.System().SaveScan(ctx, fixtureScan(own[scope], job, "edge", finished, nil)); err != nil {
				t.Fatal(err)
			}
		}
		for scope, want := range own {
			page, err := f.store.Tenant(scope).ListLegacySuccessfulScanSnapshotsPage(ctx, 50, 0)
			if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != want {
				t.Errorf("tenant %s: legacy snapshots = %+v, %v; want %s", scope.ID(), page, err, want)
			}
		}
		// The other tenant's snapshots do not fill a page past B's own.
		if page, err := f.store.Tenant(f.b).ListLegacySuccessfulScanSnapshotsPage(ctx, 50, 1); err != nil || page.Total != 1 || len(page.Items) != 0 {
			t.Errorf("tenant B's second page of legacy snapshots = %+v, %v", page, err)
		}
	}},
	"ListLatestScanHostsPage": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		own := map[TenantScope]string{f.a: f.scanA + "@" + f.jobA, f.b: f.scanB + "@" + f.jobB}
		// The same addresses are in both tenants' inventories. A search by
		// address, by DNS name, and by a short term, which takes the LIKE
		// path instead of the full-text index, finds only the tenant's own.
		for _, search := range []struct {
			query       string
			first, last int
		}{{"", 0, 3}, {fixtureHost(2).Address, 2, 3}, {"host-0001", 1, 2}, {"10", 0, 3}} {
			for scope, owner := range own {
				page, err := f.store.Tenant(scope).ListLatestScanHostsPage(ctx, search.query, "", nil, 50, 0)
				if got, want := hostOwners(page.Items, latestHostOwner), fixtureHostOwners(owner, search.first, search.last); err != nil || page.Total != len(want) || !reflect.DeepEqual(got, want) {
					t.Errorf("tenant %s: inventory for %q = %v (total %d), %v; want %v", scope.ID(), search.query, got, page.Total, err, want)
				}
			}
		}
	}},
	"ListLatestScanHosts": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		for scope, owner := range map[TenantScope]string{f.a: f.scanA + "@" + f.jobA, f.b: f.scanB + "@" + f.jobB} {
			hosts, err := f.store.Tenant(scope).ListLatestScanHosts(ctx)
			if got, want := hostOwners(hosts, latestHostOwner), fixtureHostOwners(owner, 0, 3); err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("tenant %s: inventory = %v, %v; want %v", scope.ID(), got, err, want)
			}
		}
	}},
	"ListJobScans": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		for _, check := range []struct {
			scope TenantScope
			job   string
			want  []string
		}{{f.b, f.jobA, []string{}}, {f.b, f.jobB, []string{f.scanB}}, {f.a, f.jobA, []string{f.scanA}}, {f.a, f.jobB, []string{}}} {
			scans, err := f.store.Tenant(check.scope).ListJobScans(ctx, check.job, 10)
			if got := scanIDs(scans); err != nil || !reflect.DeepEqual(got, check.want) {
				t.Errorf("tenant %s: scans of job %s = %v, %v; want %v", check.scope.ID(), check.job, got, err, check.want)
			}
		}
	}},
	"ListJobScansPage": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		for _, check := range []struct {
			scope TenantScope
			job   string
			want  []string
		}{{f.b, f.jobA, []string{}}, {f.b, f.jobB, []string{f.scanB}}, {f.a, f.jobA, []string{f.scanA}}} {
			page, err := f.store.Tenant(check.scope).ListJobScansPage(ctx, check.job, 10, 0)
			if got := scanIDs(page.Items); err != nil || page.Total != len(check.want) || !reflect.DeepEqual(got, check.want) {
				t.Errorf("tenant %s: scan page of job %s = %v (total %d), %v; want %v", check.scope.ID(), check.job, got, page.Total, err, check.want)
			}
		}
	}},
	"ListJobScanSummariesPage": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		for _, check := range []struct {
			scope TenantScope
			job   string
			want  []string
		}{{f.b, f.jobA, []string{}}, {f.b, f.jobB, []string{f.scanB}}, {f.a, f.jobA, []string{f.scanA}}} {
			page, err := f.store.Tenant(check.scope).ListJobScanSummariesPage(ctx, check.job, 10, 0)
			if got := summaryIDs(t, check.scope, page.Items); err != nil || page.Total != len(check.want) || !reflect.DeepEqual(got, check.want) {
				t.Errorf("tenant %s: summary page of job %s = %v (total %d), %v; want %v", check.scope.ID(), check.job, got, page.Total, err, check.want)
			}
		}
	}},
}
