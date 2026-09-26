package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
)

// The runtime and baseline cases join tenantStoreLeakCases from here, so
// this slice's cases stay apart from those of the other slices.
func init() {
	for name, leak := range runtimeTenantLeakCases {
		if _, exists := tenantStoreLeakCases[name]; exists {
			panic("duplicate tenant leak case " + name)
		}
		tenantStoreLeakCases[name] = leak
	}
}

// The runtime data that addTenantRuntime adds to the tenant fixture.
const (
	// runtimeLegacyJob is the name of a config.yaml job of the default
	// tenant with a stored state.
	runtimeLegacyJob = "edge-legacy"
	// runtimeUnknownJob is a job ID that no tenant has.
	runtimeUnknownJob = "00000000-0000-0000-0000-00000000dead"
	// runtimeAddress is a baseline host of both tenants' archived jobs.
	runtimeAddress = "10.54.0.1"
)

// runtimeMarker names the tenant in the rows that addTenantRuntime writes,
// so a row that leaks shows in a list.
func runtimeMarker(f tenantFixture, scope TenantScope) string {
	if scope == f.a {
		return "tenant-a"
	}
	return "tenant-b"
}

// runtimeBaselineHosts returns a tenant's baseline hosts: hosts 0 to 2, the
// addresses both tenants' scans found, each with a DNS name that names the
// tenant.
func runtimeBaselineHosts(marker string) []model.HostObservation {
	hosts := fixtureHosts(0, 3)
	for i := range hosts {
		hosts[i].DNSNames = append(hosts[i].DNSNames, marker+".example")
	}
	return hosts
}

// addTenantRuntime gives each tenant's archived job, "edge-archived", the
// same kind of baseline, marked with the tenant: a modified baseline of
// hosts 0 to 2, with its baseline host projection, whose source is the
// tenant's fixture scan, and a candidate count of 1 for A and 2 for B. It
// adds no scan, event, incident or scan cycle, so the other slices' cases
// see the same history as before. The default tenant also gets the stored
// state of a config.yaml job.
func addTenantRuntime(t *testing.T, s *Store, ids tenantFixtureIDs) {
	t.Helper()
	ctx := context.Background()
	hash := testJob("edge-archived").SecurityHash()
	for _, owner := range []struct {
		job, scan, marker string
		candidates        int
	}{{ids.archivedA, ids.scanA, "tenant-a", 1}, {ids.archivedB, ids.scanB, "tenant-b", 2}} {
		if _, err := s.System().UpdateRuntime(ctx, owner.job, func(state *model.JobState) ([]model.Event, error) {
			state.Baseline = &model.Snapshot{Hosts: runtimeBaselineHosts(owner.marker)}
			state.BaselineScanID, state.BaselineConfigHash, state.BaselineModified = owner.scan, hash, true
			state.CandidateCount = owner.candidates
			return nil, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	legacy, err := json.Marshal(model.JobState{BaselineScanID: ids.scanA, Baseline: &model.Snapshot{Hosts: runtimeBaselineHosts("legacy")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_states(job,state_json,updated_at) VALUES(?,?,?)`, runtimeLegacyJob, legacy, sqliteTimestamp(time.Date(2026, 9, 20, 14, 0, 0, 0, time.UTC))); err != nil {
		t.Fatal(err)
	}
}

// runtimeApproveScan is the ID of the successful scan of the current scope
// that prepareRuntimeWrites saves for a tenant's archived job.
func runtimeApproveScan(marker string) string { return "approve-scan-" + marker }

// prepareRuntimeWrites gives each tenant's archived job, on a private copy
// of the fixture, what a baseline write acts on: a successful scan of the
// job's current scope that an approval may use, and a paused scan cycle
// that a reset or an approval discards.
func prepareRuntimeWrites(t *testing.T, f tenantFixture) {
	t.Helper()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 15, 0, 0, 0, time.UTC)
	for _, owner := range []struct {
		scope TenantScope
		job   string
	}{{f.a, f.archivedA}, {f.b, f.archivedB}} {
		marker := runtimeMarker(f, owner.scope)
		record, err := f.store.Tenant(owner.scope).GetJob(ctx, owner.job)
		if err != nil {
			t.Fatal(err)
		}
		hash := record.Job.SecurityHash()
		approve := fixtureScan(runtimeApproveScan(marker), owner.job, "edge-archived", at, runtimeBaselineHosts(marker))
		approve.ConfigHash = hash
		if err := f.store.SaveScan(ctx, approve); err != nil {
			t.Fatal(err)
		}
		plan := scanner.WorkPlan{CreatedAt: at, Job: record.Job, Scopes: []model.Scope{{Target: runtimeAddress, Protocol: "tcp", Ports: "1"}}, Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Family: 4, Addresses: []string{runtimeAddress}, Ports: "1", PortCount: 1, Probes: 1}}, TotalUnits: 1, TotalProbes: 1}
		if _, err := f.store.CreateScanCycle(ctx, ScanCycleRecord{ID: "cycle-" + marker, JobID: owner.job, Job: "edge-archived", JobRevision: record.Revision, ConfigHash: hash, Plan: plan}); err != nil {
			t.Fatal(err)
		}
	}
}

// runtimeWrite is one baseline write by a tenant: a reset or an approval of
// a job. scanID names the scan that an approval makes the baseline; a reset
// ignores it.
type runtimeWrite func(ts *TenantStore, jobID, scanID string) error

// checkTenantRuntimeWriteRefused runs a baseline write from tenant B on
// tenant A's jobs and on an unknown job, without letting it succeed, so the
// case can share the fixture. Each is refused with ErrNotFound, and neither
// tenant's rows nor the audit log change.
func checkTenantRuntimeWriteRefused(t *testing.T, f tenantFixture, write runtimeWrite) {
	t.Helper()
	beforeA, beforeB := tenantJobDigest(t, f.store, f.a), tenantJobDigest(t, f.store, f.b)
	audits := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`)
	for _, jobID := range []string{f.jobA, f.archivedA, runtimeUnknownJob} {
		if err := write(f.store.Tenant(f.b), jobID, f.scanA); !errors.Is(err, ErrNotFound) {
			t.Fatalf("tenant B wrote the baseline of job %s: %v", jobID, err)
		}
	}
	if after := tenantJobDigest(t, f.store, f.a); after != beforeA {
		t.Fatalf("a refused write changed tenant A: digest %s, was %s", after, beforeA)
	}
	if after := tenantJobDigest(t, f.store, f.b); after != beforeB {
		t.Fatalf("a refused write changed tenant B: digest %s, was %s", after, beforeB)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`); got != audits {
		t.Fatalf("a refused write wrote %d audit records", got-audits)
	}
}

// checkApprovalOfAnotherTenantsScan shows, on the shared fixture, that
// tenant B cannot approve tenant A's scan for its own job: it is refused
// with the error of an unknown scan, and nothing changes.
func checkApprovalOfAnotherTenantsScan(t *testing.T, f tenantFixture, write runtimeWrite) {
	t.Helper()
	before := tenantJobDigest(t, f.store, f.a) + tenantJobDigest(t, f.store, f.b)
	unknown := write(f.store.Tenant(f.b), f.archivedB, "missing-scan")
	foreign := write(f.store.Tenant(f.b), f.archivedB, f.scanA)
	if !errors.Is(unknown, sql.ErrNoRows) || !errors.Is(foreign, sql.ErrNoRows) || foreign.Error() != unknown.Error() {
		t.Fatalf("tenant B approved tenant A's scan: %v; an unknown scan: %v", foreign, unknown)
	}
	if after := tenantJobDigest(t, f.store, f.a) + tenantJobDigest(t, f.store, f.b); after != before {
		t.Fatalf("a refused approval changed the baselines: digest %s, was %s", after, before)
	}
}

// checkTenantRuntimeWrite runs a baseline write from tenant B on a private
// copy of the fixture. On tenant A's jobs and on an unknown job it is
// refused with ErrNotFound and changes nothing, not even the audit log. On
// B's own archived job, whose baseline has the same hosts as A's, it
// succeeds, discards only B's scan cycle, records its event in tenant B,
// and leaves A unchanged. check then inspects B's state.
func checkTenantRuntimeWrite(t *testing.T, f tenantFixture, eventType string, write runtimeWrite, check func(t *testing.T, f tenantFixture)) {
	t.Helper()
	ctx := context.Background()
	prepareRuntimeWrites(t, f)
	approveA, approveB := runtimeApproveScan("tenant-a"), runtimeApproveScan("tenant-b")
	beforeA, beforeB := tenantJobDigest(t, f.store, f.a), tenantJobDigest(t, f.store, f.b)
	audits := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`)
	for _, target := range []struct{ job, scan string }{{f.jobA, approveA}, {f.archivedA, approveA}, {runtimeUnknownJob, approveB}} {
		if err := write(f.store.Tenant(f.b), target.job, target.scan); !errors.Is(err, ErrNotFound) {
			t.Fatalf("tenant B wrote the baseline of job %s: %v", target.job, err)
		}
	}
	if after := tenantJobDigest(t, f.store, f.a); after != beforeA {
		t.Fatalf("a refused write changed tenant A: digest %s, was %s", after, beforeA)
	}
	if after := tenantJobDigest(t, f.store, f.b); after != beforeB {
		t.Fatalf("a refused write changed tenant B: digest %s, was %s", after, beforeB)
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`); got != audits {
		t.Fatalf("a refused write wrote %d audit records", got-audits)
	}
	if _, err := f.store.DB.ExecContext(ctx, `DELETE FROM security_audit`); err != nil {
		t.Fatal(err)
	}
	if err := write(f.store.Tenant(f.b), f.archivedB, approveB); err != nil {
		t.Fatalf("tenant B's own job: %v", err)
	}
	if after := tenantJobDigest(t, f.store, f.a); after != beforeA {
		t.Fatalf("tenant B's write changed tenant A: digest %s, was %s", after, beforeA)
	}
	if after := tenantJobDigest(t, f.store, f.b); after == beforeB {
		t.Fatal("tenant B's write changed nothing")
	}
	if got := tenantOf(t, f.store.DB, `SELECT tenant_id FROM events WHERE type=?`, eventType); got != secondTenantID {
		t.Fatalf("the %s event belongs to %s, want tenant B", eventType, got)
	}
	status := queryStrings(t, f.store.DB, `SELECT id||'='||status FROM scan_cycles WHERE id LIKE 'cycle-tenant-%' ORDER BY id`)
	if want := []string{"cycle-tenant-a=paused", "cycle-tenant-b=discarded"}; !reflect.DeepEqual(status, want) {
		t.Fatalf("scan cycles after tenant B's write = %v, want %v", status, want)
	}
	check(t, f)
}

// checkTenantResetOfB checks tenant B's state after its own reset: no
// baseline and no baseline hosts, and the audit record when the write had
// one.
func checkTenantResetOfB(withAudit bool) func(t *testing.T, f tenantFixture) {
	return func(t *testing.T, f tenantFixture) {
		t.Helper()
		ctx := context.Background()
		ts := f.store.Tenant(f.b)
		state, err := ts.RuntimeState(ctx, f.archivedB)
		if err != nil || state.Baseline != nil || state.BaselineScanID != "" {
			t.Fatalf("tenant B's state after its reset = %+v, %v", state, err)
		}
		if exists, err := ts.BaselineHostProjectionExists(ctx, f.archivedB); err != nil || exists {
			t.Fatalf("tenant B's baseline hosts after its reset = %v, %v", exists, err)
		}
		checkRuntimeAudit(t, f, withAudit, "baseline.reset")
	}
}

// checkTenantApprovalOfB checks tenant B's state after it approved its own
// scan: the scan is the baseline, and the baseline hosts are the scan's.
func checkTenantApprovalOfB(withAudit bool) func(t *testing.T, f tenantFixture) {
	return func(t *testing.T, f tenantFixture) {
		t.Helper()
		ctx := context.Background()
		ts := f.store.Tenant(f.b)
		info, err := ts.RuntimeBaselineInfo(ctx, f.archivedB)
		if err != nil || info.BaselineScanID != runtimeApproveScan("tenant-b") || info.BaselineModified {
			t.Fatalf("tenant B's baseline after its approval = %+v, %v", info, err)
		}
		summary, err := ts.RuntimeStateSummary(ctx, f.archivedB)
		if err != nil || !summary.HasBaseline || summary.BaselineHostCount != 3 {
			t.Fatalf("tenant B's summary after its approval = %+v, %v", summary, err)
		}
		checkRuntimeAudit(t, f, withAudit, "baseline.approved")
	}
}

// checkRuntimeAudit checks that a write with an audit entry recorded one,
// and a write without one recorded none.
func checkRuntimeAudit(t *testing.T, f tenantFixture, withAudit bool, action string) {
	t.Helper()
	want := 0
	if withAudit {
		want = 1
	}
	if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit WHERE action=?`, action); got != want {
		t.Fatalf("%s audit records = %d, want %d", action, got, want)
	}
}

// runtimeExpectation is the baseline that a tenant's archived job has in
// the fixture, as an operator who reviewed it would name it.
func runtimeExpectation(f tenantFixture, jobID string) BaselineExpectation {
	scanID := f.scanA
	if jobID == f.archivedB {
		scanID = f.scanB
	}
	return BaselineExpectation{ScanID: scanID, ScanIDSet: true, Modified: true, ModifiedSet: true}
}

// checkTenantRuntimeReads checks a read of one job's runtime data. Tenant B
// reading A's jobs, or an unknown job, gets the zero value, as does A
// reading B's jobs, and each tenant reads its own archived job.
func checkTenantRuntimeReads[T any](t *testing.T, f tenantFixture, read func(ts *TenantStore, jobID string) (T, error), own func(t *testing.T, scope TenantScope, got T)) {
	t.Helper()
	var zero T
	for _, check := range []struct {
		scope TenantScope
		jobID string
	}{{f.b, f.jobA}, {f.b, f.archivedA}, {f.b, runtimeUnknownJob}, {f.a, f.jobB}, {f.a, f.archivedB}} {
		got, err := read(f.store.Tenant(check.scope), check.jobID)
		if err != nil || !reflect.DeepEqual(got, zero) {
			t.Errorf("tenant %s read job %s: %+v, %v", check.scope.ID(), check.jobID, got, err)
		}
	}
	for scope, jobID := range map[TenantScope]string{f.a: f.archivedA, f.b: f.archivedB} {
		got, err := read(f.store.Tenant(scope), jobID)
		if err != nil {
			t.Fatalf("tenant %s: %v", scope.ID(), err)
		}
		own(t, scope, got)
	}
}

// runtimeScanOf returns the fixture scan of a tenant.
func runtimeScanOf(f tenantFixture, scope TenantScope) string {
	if scope == f.a {
		return f.scanA
	}
	return f.scanB
}

// runtimeCandidatesOf returns the candidate count that addTenantRuntime
// gives a tenant's archived job.
func runtimeCandidatesOf(f tenantFixture, scope TenantScope) int {
	if scope == f.a {
		return 1
	}
	return 2
}

// baselineHostMarkers returns "address/tenant" for each host, sorted, from
// the DNS name that names the tenant.
func baselineHostMarkers(hosts []model.HostObservation) []string {
	var markers []string
	for _, host := range hosts {
		marker := "?"
		for _, name := range host.DNSNames {
			if strings.HasPrefix(name, "tenant-") {
				marker = strings.TrimSuffix(name, ".example")
			}
		}
		markers = append(markers, host.Address+"/"+marker)
	}
	sort.Strings(markers)
	return markers
}

// scanHostObservations returns the observations of the hosts.
func scanHostObservations(hosts []ScanHost) []model.HostObservation {
	var observations []model.HostObservation
	for _, host := range hosts {
		observations = append(observations, host.Host)
	}
	return observations
}

// wantBaselineHostMarkers returns the markers of a tenant's three baseline
// hosts.
func wantBaselineHostMarkers(marker string) []string {
	return baselineHostMarkers(runtimeBaselineHosts(marker))
}

// exportJobIDs returns the job ID of each managed entry and "legacy:name"
// for each legacy entry, in export order.
func exportJobIDs(export BaselineExport) []string {
	var ids []string
	for _, entry := range export.Jobs {
		if entry.Legacy {
			ids = append(ids, "legacy:"+entry.Name)
			continue
		}
		ids = append(ids, entry.JobID)
	}
	return ids
}

// runtimeTenantLeakCases show that tenant B cannot read or write tenant A's
// runtime state, baseline, baseline hosts or export, by job ID or by job
// name, although both tenants have jobs named "edge" and "edge-archived"
// whose baselines hold the same addresses. The reads and the refused writes
// share the fixture. The writes that succeed each run on a private copy and
// show that B can still reset and approve its own baseline, which leaves A
// unchanged.
var runtimeTenantLeakCases = map[string]tenantLeakCase{
	"RuntimeState": {run: func(t *testing.T, f tenantFixture) {
		checkTenantRuntimeReads(t, f, func(ts *TenantStore, jobID string) (model.JobState, error) {
			state, err := ts.RuntimeState(context.Background(), jobID)
			if reflect.DeepEqual(state, emptyState()) {
				// An empty state stands for no state, as for an unknown job.
				state = model.JobState{}
			}
			return state, err
		}, func(t *testing.T, scope TenantScope, state model.JobState) {
			if state.BaselineScanID != runtimeScanOf(f, scope) || state.Baseline == nil {
				t.Fatalf("tenant %s: own state = %+v", scope.ID(), state)
			}
			if got, want := baselineHostMarkers(state.Baseline.Hosts), wantBaselineHostMarkers(runtimeMarker(f, scope)); !reflect.DeepEqual(got, want) {
				t.Errorf("tenant %s: own baseline hosts = %v, want %v", scope.ID(), got, want)
			}
		})
	}},
	"RuntimeBaselineInfo": {run: func(t *testing.T, f tenantFixture) {
		checkTenantRuntimeReads(t, f, func(ts *TenantStore, jobID string) (RuntimeBaselineInfo, error) {
			return ts.RuntimeBaselineInfo(context.Background(), jobID)
		}, func(t *testing.T, scope TenantScope, info RuntimeBaselineInfo) {
			if info.BaselineScanID != runtimeScanOf(f, scope) || !info.BaselineModified || info.ProjectionVersion == 0 || info.BaselineEpoch == 0 {
				t.Errorf("tenant %s: own baseline info = %+v", scope.ID(), info)
			}
		})
	}},
	"RuntimeBaselineMeta": {run: func(t *testing.T, f tenantFixture) {
		checkTenantRuntimeReads(t, f, func(ts *TenantStore, jobID string) ([2]string, error) {
			scanID, configHash, err := ts.RuntimeBaselineMeta(context.Background(), jobID)
			return [2]string{scanID, configHash}, err
		}, func(t *testing.T, scope TenantScope, meta [2]string) {
			if meta != [2]string{runtimeScanOf(f, scope), testJob("edge-archived").SecurityHash()} {
				t.Errorf("tenant %s: own baseline meta = %v", scope.ID(), meta)
			}
		})
	}},
	"RuntimeBaselineModified": {run: func(t *testing.T, f tenantFixture) {
		checkTenantRuntimeReads(t, f, func(ts *TenantStore, jobID string) (bool, error) {
			return ts.RuntimeBaselineModified(context.Background(), jobID)
		}, func(t *testing.T, scope TenantScope, modified bool) {
			if !modified {
				t.Errorf("tenant %s: own baseline is not modified", scope.ID())
			}
		})
	}},
	"RuntimeBaselineEpoch": {run: func(t *testing.T, f tenantFixture) {
		checkTenantRuntimeReads(t, f, func(ts *TenantStore, jobID string) (int64, error) {
			return ts.RuntimeBaselineEpoch(context.Background(), jobID)
		}, func(t *testing.T, scope TenantScope, epoch int64) {
			if epoch == 0 {
				t.Errorf("tenant %s: own baseline epoch is zero", scope.ID())
			}
		})
	}},
	"RuntimeStateSummary": {run: func(t *testing.T, f tenantFixture) {
		checkTenantRuntimeReads(t, f, func(ts *TenantStore, jobID string) (RuntimeStateSummary, error) {
			return ts.RuntimeStateSummary(context.Background(), jobID)
		}, func(t *testing.T, scope TenantScope, summary RuntimeStateSummary) {
			want := RuntimeStateSummary{HasBaseline: true, BaselineScanID: runtimeScanOf(f, scope), BaselineConfigHash: testJob("edge-archived").SecurityHash(), BaselineModified: true, CandidateCount: runtimeCandidatesOf(f, scope), BaselineHostCount: 3}
			if summary != want {
				t.Errorf("tenant %s: own summary = %+v, want %+v", scope.ID(), summary, want)
			}
		})
	}},
	"RuntimeStateSummaries": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		for _, check := range []struct {
			scope           TenantScope
			includeArchived bool
			archived        string
			want            []string
		}{
			{f.b, false, "", []string{f.jobB}},
			{f.b, true, f.archivedB, sortedIDs(f.jobB, f.archivedB)},
			{f.a, false, "", []string{f.jobA}},
			{f.a, true, f.archivedA, sortedIDs(f.jobA, f.archivedA)},
		} {
			summaries, err := f.store.Tenant(check.scope).RuntimeStateSummaries(ctx, check.includeArchived)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for jobID := range summaries {
				got = append(got, jobID)
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, check.want) {
				t.Fatalf("tenant %s, archived %v: summaries of %v, want %v", check.scope.ID(), check.includeArchived, got, check.want)
			}
			if check.archived == "" {
				continue
			}
			if own := summaries[check.archived]; own.BaselineScanID != runtimeScanOf(f, check.scope) || own.CandidateCount != runtimeCandidatesOf(f, check.scope) || own.BaselineHostCount != 3 {
				t.Errorf("tenant %s: own summary = %+v", check.scope.ID(), own)
			}
		}
	}},
	"BaselineHostProjectionExists": {run: func(t *testing.T, f tenantFixture) {
		checkTenantRuntimeReads(t, f, func(ts *TenantStore, jobID string) (bool, error) {
			return ts.BaselineHostProjectionExists(context.Background(), jobID)
		}, func(t *testing.T, scope TenantScope, exists bool) {
			if !exists {
				t.Errorf("tenant %s: own baseline host projection is missing", scope.ID())
			}
		})
	}},
	"GetBaselineHost": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		for _, check := range []struct {
			scope TenantScope
			jobID string
		}{{f.b, f.archivedA}, {f.b, f.jobA}, {f.b, runtimeUnknownJob}, {f.a, f.archivedB}} {
			if host, err := f.store.Tenant(check.scope).GetBaselineHost(ctx, check.jobID, runtimeAddress); !errors.Is(err, ErrNotFound) || host.Host.Address != "" {
				t.Errorf("tenant %s read the baseline host of job %s: %+v, %v", check.scope.ID(), check.jobID, host, err)
			}
		}
		for scope, jobID := range map[TenantScope]string{f.a: f.archivedA, f.b: f.archivedB} {
			host, err := f.store.Tenant(scope).GetBaselineHost(ctx, jobID, runtimeAddress)
			if got, want := baselineHostMarkers([]model.HostObservation{host.Host}), []string{runtimeAddress + "/" + runtimeMarker(f, scope)}; err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("tenant %s: own baseline host = %v, %v; want %v", scope.ID(), got, err, want)
			}
		}
		if _, err := f.store.GetBaselineHost(ctx, f.archivedB, runtimeAddress); !errors.Is(err, ErrNotFound) {
			t.Errorf("deprecated GetBaselineHost read tenant B's host: %v", err)
		}
	}},
	"ListBaselineHostsPage": {run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		for _, check := range []struct {
			scope TenantScope
			jobID string
			query string
			want  []string
		}{
			// Another tenant's job, whatever the search, has no hosts.
			{f.b, f.archivedA, "", nil},
			{f.b, f.archivedA, "edge", nil},
			{f.b, f.archivedA, "tenant-a", nil},
			{f.b, runtimeUnknownJob, "", nil},
			{f.a, f.archivedB, "edge", nil},
			// A search, by the shared job name, a shared address, or a short
			// text, finds only the tenant's own hosts.
			{f.b, f.archivedB, "", wantBaselineHostMarkers("tenant-b")},
			{f.b, f.archivedB, "edge", wantBaselineHostMarkers("tenant-b")},
			{f.b, f.archivedB, runtimeAddress, []string{runtimeAddress + "/tenant-b"}},
			{f.b, f.archivedB, "54", wantBaselineHostMarkers("tenant-b")},
			{f.b, f.archivedB, "tenant-a", nil},
			{f.a, f.archivedA, "edge", wantBaselineHostMarkers("tenant-a")},
			{f.a, f.archivedA, "tenant-b", nil},
		} {
			page, err := f.store.Tenant(check.scope).ListBaselineHostsPage(ctx, check.jobID, check.query, "", nil, 10, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := baselineHostMarkers(scanHostObservations(page.Items)); !reflect.DeepEqual(got, check.want) || page.Total != len(check.want) {
				t.Errorf("tenant %s, job %s, search %q: hosts %v (total %d), want %v", check.scope.ID(), check.jobID, check.query, got, page.Total, check.want)
			}
		}
		if page, err := f.store.ListBaselineHostsPage(ctx, f.archivedB, "", "", nil, 10, 0); err != nil || page.Total != 0 {
			t.Errorf("deprecated ListBaselineHostsPage read tenant B's hosts: %+v, %v", page, err)
		}
	}},
	"ExportBaselines": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		// Tenant B's "edge" job names tenant A's scan as its baseline scan.
		// The export must not describe another tenant's scan.
		if _, err := f.store.System().UpdateRuntime(ctx, f.jobB, func(state *model.JobState) ([]model.Event, error) {
			state.BaselineScanID = f.scanA
			return nil, nil
		}); err != nil {
			t.Fatal(err)
		}
		exportB, err := f.store.Tenant(f.b).ExportBaselines(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		if got, want := exportJobIDs(exportB), []string{f.jobB, f.archivedB}; !reflect.DeepEqual(got, want) {
			t.Fatalf("tenant B's export = %v, want %v", got, want)
		}
		if crossed := exportB.Jobs[0]; crossed.BaselineScanID != f.scanA || crossed.SourceScan != nil {
			t.Errorf("tenant B's export described tenant A's scan: %+v", crossed.SourceScan)
		}
		if own := exportB.Jobs[1]; own.Status != "ready" || own.SourceScan == nil || own.SourceScan.ID != f.scanB || own.Baseline == nil || !reflect.DeepEqual(baselineHostMarkers(own.Baseline.Hosts), wantBaselineHostMarkers("tenant-b")) {
			t.Errorf("tenant B's own baseline = %+v", own)
		}
		exportA, err := f.store.Tenant(f.a).ExportBaselines(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		// The default tenant's export also holds the config.yaml job states,
		// whatever other history the fixture has.
		idsA := strings.Join(exportJobIDs(exportA), ",")
		for _, want := range []string{f.jobA, f.archivedA, "legacy:" + runtimeLegacyJob} {
			if !strings.Contains(idsA, want) {
				t.Errorf("tenant A's export %s lacks %s", idsA, want)
			}
		}
		if strings.Contains(idsA, f.jobB) || strings.Contains(idsA, f.archivedB) {
			t.Errorf("tenant A's export %s holds tenant B's jobs", idsA)
		}
		for _, name := range []string{f.jobA, f.archivedA, runtimeLegacyJob, "missing"} {
			if export, err := f.store.Tenant(f.b).ExportBaselines(ctx, name); !errors.Is(err, ErrNotFound) {
				t.Errorf("tenant B exported %s: %v, %v", name, exportJobIDs(export), err)
			}
		}
		for scope, want := range map[TenantScope]string{f.a: f.archivedA, f.b: f.archivedB} {
			if export, err := f.store.Tenant(scope).ExportBaselines(ctx, "edge-archived"); err != nil || !reflect.DeepEqual(exportJobIDs(export), []string{want}) {
				t.Errorf("tenant %s: export of edge-archived = %v, %v; want %s", scope.ID(), exportJobIDs(export), err, want)
			}
		}
		if export, err := f.store.Tenant(f.a).ExportBaselines(ctx, runtimeLegacyJob); err != nil || !reflect.DeepEqual(exportJobIDs(export), []string{"legacy:" + runtimeLegacyJob}) || export.Jobs[0].SourceScan == nil {
			t.Errorf("tenant A's export of its config.yaml job = %+v, %v", export, err)
		}
		if export, err := f.store.ExportBaselines(ctx, f.archivedB); !errors.Is(err, ErrNotFound) {
			t.Errorf("deprecated ExportBaselines exported tenant B's job: %v, %v", exportJobIDs(export), err)
		}
	}},
	"ResetRuntime": {run: func(t *testing.T, f tenantFixture) {
		checkTenantRuntimeWriteRefused(t, f, func(ts *TenantStore, jobID, _ string) error {
			_, err := ts.ResetRuntime(context.Background(), jobID, "edge")
			return err
		})
	}},
	"ResetRuntimeWithOutbox": {writes: true, run: func(t *testing.T, f tenantFixture) {
		checkTenantRuntimeWrite(t, f, "baseline-reset", func(ts *TenantStore, jobID, _ string) error {
			_, err := ts.ResetRuntimeWithOutbox(context.Background(), jobID, "edge-archived", []string{"runtime-destination"})
			return err
		}, func(t *testing.T, f tenantFixture) {
			checkTenantResetOfB(false)(t, f)
			if got := tenantOf(t, f.store.DB, `SELECT tenant_id FROM outbox WHERE destination='runtime-destination'`); got != secondTenantID {
				t.Fatalf("the reset delivery belongs to %s, want tenant B", got)
			}
		})
	}},
	"ResetRuntimeWithOutboxAndAudit": {run: func(t *testing.T, f tenantFixture) {
		checkTenantRuntimeWriteRefused(t, f, func(ts *TenantStore, jobID, _ string) error {
			_, err := ts.ResetRuntimeWithOutboxAndAudit(context.Background(), jobID, "edge", nil, AuditEntry{Action: "baseline.reset", Detail: jobID})
			return err
		})
	}},
	"ResetRuntimeWithExpectationAndAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		// B names the baseline that A's archived job has; that is its current
		// baseline, yet B is refused as for an unknown job.
		checkTenantRuntimeWrite(t, f, "baseline-reset", func(ts *TenantStore, jobID, _ string) error {
			_, err := ts.ResetRuntimeWithExpectationAndAudit(context.Background(), jobID, "edge-archived", nil, AuditEntry{Action: "baseline.reset", Detail: jobID}, runtimeExpectation(f, jobID))
			return err
		}, checkTenantResetOfB(true))
	}},
	"ApproveRuntime": {run: func(t *testing.T, f tenantFixture) {
		approve := func(ts *TenantStore, jobID, scanID string) error {
			_, err := ts.ApproveRuntime(context.Background(), jobID, "edge", model.Scan{ID: scanID})
			return err
		}
		checkTenantRuntimeWriteRefused(t, f, approve)
		checkApprovalOfAnotherTenantsScan(t, f, approve)
	}},
	"ApproveRuntimeWithOutbox": {writes: true, run: func(t *testing.T, f tenantFixture) {
		checkTenantRuntimeWrite(t, f, "baseline-approved", func(ts *TenantStore, jobID, scanID string) error {
			_, err := ts.ApproveRuntimeWithOutbox(context.Background(), jobID, "edge-archived", model.Scan{ID: scanID}, []string{"runtime-destination"})
			return err
		}, func(t *testing.T, f tenantFixture) {
			checkTenantApprovalOfB(false)(t, f)
			if got := tenantOf(t, f.store.DB, `SELECT tenant_id FROM outbox WHERE destination='runtime-destination'`); got != secondTenantID {
				t.Fatalf("the approval delivery belongs to %s, want tenant B", got)
			}
		})
	}},
	"ApproveRuntimeWithOutboxAndAudit": {run: func(t *testing.T, f tenantFixture) {
		approve := func(ts *TenantStore, jobID, scanID string) error {
			_, err := ts.ApproveRuntimeWithOutboxAndAudit(context.Background(), jobID, "edge", model.Scan{ID: scanID}, nil, AuditEntry{Action: "baseline.approved", Detail: jobID})
			return err
		}
		checkTenantRuntimeWriteRefused(t, f, approve)
		checkApprovalOfAnotherTenantsScan(t, f, approve)
	}},
	"ApproveRuntimeWithExpectationAndAudit": {writes: true, run: func(t *testing.T, f tenantFixture) {
		approve := func(ts *TenantStore, jobID, scanID string) error {
			_, err := ts.ApproveRuntimeWithExpectationAndAudit(context.Background(), jobID, "edge-archived", model.Scan{ID: scanID}, nil, AuditEntry{Action: "baseline.approved", Detail: jobID}, runtimeExpectation(f, jobID))
			return err
		}
		checkTenantRuntimeWrite(t, f, "baseline-approved", approve, checkTenantApprovalOfB(true))
	}},
}

// The deprecated Store wrappers of the runtime reads and writes reach only
// the default tenant's jobs, and the daemon's writers reach every tenant's
// jobs.
func TestRuntimeWritersFollowTheirScope(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	if state, err := f.store.RuntimeState(ctx, f.archivedB); err != nil || state.Baseline != nil {
		t.Fatalf("deprecated RuntimeState read tenant B's job: %+v, %v", state, err)
	}
	if summaries, err := f.store.RuntimeStateSummaries(ctx, true); err != nil || len(summaries) != 2 || summaries[f.archivedA].BaselineHostCount != 3 {
		t.Fatalf("deprecated RuntimeStateSummaries = %+v, %v", summaries, err)
	}
	before := tenantJobDigest(t, f.store, f.b)
	if _, err := f.store.ResetRuntimeWithOutboxAndAudit(ctx, f.archivedB, "edge-archived", nil, AuditEntry{Action: "baseline.reset"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deprecated reset of tenant B's job = %v", err)
	}
	if _, err := f.store.ApproveRuntimeWithOutboxAndAudit(ctx, f.jobB, "edge", model.Scan{ID: f.scanB}, nil, AuditEntry{Action: "baseline.approved"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deprecated approval of tenant B's job = %v", err)
	}
	if after := tenantJobDigest(t, f.store, f.b); after != before {
		t.Fatalf("a deprecated write changed tenant B: digest %s, was %s", after, before)
	}
	if _, err := f.store.ResetRuntime(ctx, f.archivedA, "edge-archived"); err != nil {
		t.Fatalf("deprecated reset of tenant A's job = %v", err)
	}
	if state, err := f.store.RuntimeState(ctx, f.archivedA); err != nil || state.Baseline != nil {
		t.Fatalf("tenant A's state after the deprecated reset = %+v, %v", state, err)
	}
	// The daemon's writers reach tenant B's job through the system store and
	// the plain Store forwarders alike.
	if err := f.store.ReplaceBaselineHostProjection(ctx, f.archivedB, model.Snapshot{Hosts: fixtureHosts(0, 5)}); err != nil {
		t.Fatal(err)
	}
	if page, err := f.store.Tenant(f.b).ListBaselineHostsPage(ctx, f.archivedB, "", "", nil, 10, 0); err != nil || page.Total != 5 {
		t.Fatalf("tenant B's baseline hosts after the system replace = %d, %v", page.Total, err)
	}
	if _, err := f.store.UpdateRuntime(ctx, f.archivedB, func(state *model.JobState) ([]model.Event, error) {
		state.CandidateCount = 7
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if summary, err := f.store.Tenant(f.b).RuntimeStateSummary(ctx, f.archivedB); err != nil || summary.CandidateCount != 7 {
		t.Fatalf("tenant B's summary after the system update = %+v, %v", summary, err)
	}
}
