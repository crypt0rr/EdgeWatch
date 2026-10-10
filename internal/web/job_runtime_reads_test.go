package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// stateBaselineJSON is how the job detail derived its baseline summary
// from the fully decoded runtime state before it used the bounded store
// summary. The tests below compare the two.
func stateBaselineJSON(state model.JobState, currentHash string) map[string]any {
	summary := store.RuntimeStateSummary{HasBaseline: state.Baseline != nil, BaselineScanID: state.BaselineScanID, BaselineConfigHash: state.BaselineConfigHash, BaselineModified: state.BaselineModified, CandidateCount: state.CandidateCount, CandidateAttempts: state.CandidateAttempts, IncompleteCandidateAttempts: state.IncompleteCandidateAttempts, IncidentCount: len(state.Incidents), PendingCount: len(state.Pending)}
	if state.Baseline != nil {
		summary.BaselineHostCount = len(state.Baseline.Hosts)
		if summary.BaselineHostCount == 0 && len(state.Baseline.Units) > 0 {
			if page, err := observationsForSnapshot(*state.Baseline); err == nil {
				summary.BaselineHostCount = len(page.Items)
			}
		}
	}
	return baselineJSONFromSummary(summary, currentHash)
}

// runtimeTestJob creates a job for the runtime read tests.
func runtimeTestJob(t *testing.T, db *store.Store, name string) store.JobRecord {
	t.Helper()
	record, err := defaultTenant(db).CreateJob(context.Background(), config.NormalizeJob(config.Job{
		Name:     name,
		Schedule: "0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"198.18.0.0/22"},
		TCP:      &config.Protocol{Ports: "1000-1019", Mode: "connect"},
		Timeout:  config.Duration(time.Minute),
		Timing:   "balanced",
	}))
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// runtimeTestSnapshot returns a snapshot of hosts addresses, each with ports
// open ports, as both a logical unit and a host observation, and a host
// state for every address.
func runtimeTestSnapshot(hosts, ports int) model.Snapshot {
	snapshot := model.Snapshot{
		Scopes:         []model.Scope{{Target: "198.18.0.0/22", Protocol: "tcp", Ports: "1000-1019"}},
		DNS:            map[string][]string{"edge.example": {"198.18.0.1"}},
		TargetFailures: []model.TargetCoverageFailure{{Target: "missing.example", Reason: "no addresses"}},
	}
	for index := 0; index < hosts; index++ {
		address := fmt.Sprintf("198.18.%d.%d", index/250, index%250+1)
		unit := model.Unit{Target: address, Protocol: "tcp", Addresses: []string{address}}
		host := model.HostObservation{Address: address, AddressFamily: "IPv4", Status: "up"}
		protocol := model.ProtocolObservation{Protocol: "tcp", ScannedPorts: "1000-1019", ScannedPortCount: 20}
		for port := 0; port < ports; port++ {
			unit.Ports = append(unit.Ports, model.PortState{Port: 1000 + port, State: "open", Service: "http"})
			protocol.Ports = append(protocol.Ports, model.PortObservation{Port: 1000 + port, State: "open", Service: &model.ServiceObservation{Name: "http", Product: "nginx"}})
		}
		host.Protocols = []model.ProtocolObservation{protocol}
		snapshot.Units = append(snapshot.Units, unit)
		snapshot.Hosts = append(snapshot.Hosts, host)
		snapshot.HostStates = append(snapshot.HostStates, model.HostState{Address: address, State: "up"})
	}
	return snapshot
}

// setIndexedRuntimeBaseline saves a successful scan of snapshot and makes it
// the job's baseline, as the engine does once the baseline converges.
func setIndexedRuntimeBaseline(t *testing.T, db *store.Store, record store.JobRecord, scanID string, snapshot model.Snapshot, change func(*model.JobState)) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.System().SaveScan(ctx, model.Scan{ID: scanID, JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: record.Job.SecurityHash(), Snapshot: snapshot}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		baseline := snapshot
		state.Baseline, state.BaselineScanID, state.BaselineConfigHash = &baseline, scanID, record.Job.SecurityHash()
		state.CandidateCount, state.CandidateAttempts = 2, 3
		if change != nil {
			change(state)
		}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
}

// getJobJSON returns the decoded response of GET /jobs/{id}.
func getJobJSON(t *testing.T, server *Server, session store.Session, id string) map[string]any {
	t.Helper()
	response := httptest.NewRecorder()
	server.jobRoute(response, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+id, nil), session, defaultTenantStore(server), id)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /jobs/%s = %d: %s", id, response.Code, response.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

// limitReadValueLength leaves the store's read pool one connection that
// refuses to load any string or blob longer than limit bytes, so a request
// that reads a large runtime JSON value fails.
func limitReadValueLength(t *testing.T, db *store.Store, limit int) {
	t.Helper()
	db.ReadDB.SetMaxOpenConns(1)
	conn, err := db.ReadDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := sqlite.Limit(conn, sqlite3.SQLITE_LIMIT_LENGTH, limit); err != nil {
		t.Fatal(err)
	}
}

// TestJobDetailBaselineMatchesFullRuntimeState builds GET /jobs/{id} from
// the bounded summary and compares its baseline with the one derived from
// the decoded runtime state, for an indexed baseline, an accepted overlay,
// a legacy baseline of logical units only, a baseline of an older scope, and
// a job that is still collecting its baseline. The job list reports the
// same baseline as the job detail.
func TestJobDetailBaselineMatchesFullRuntimeState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)

	indexed := runtimeTestJob(t, db, "indexed-baseline")
	setIndexedRuntimeBaseline(t, db, indexed, "indexed-scan", runtimeTestSnapshot(4, 2), func(state *model.JobState) {
		state.Pending = map[string]model.Pending{
			"one": {Change: model.Change{Key: "one", Kind: "port", Target: "198.18.0.1", Protocol: "tcp", Port: 1000}, Count: 1},
			"two": {Change: model.Change{Key: "two", Kind: "port", Target: "198.18.0.2", Protocol: "tcp", Port: 1001}, Count: 1},
		}
	})

	modified := runtimeTestJob(t, db, "modified-baseline")
	setIndexedRuntimeBaseline(t, db, modified, "modified-scan", runtimeTestSnapshot(4, 2), func(state *model.JobState) {
		accepted := runtimeTestSnapshot(3, 1)
		state.Baseline, state.BaselineModified = &accepted, true
		state.Incidents = map[string]model.Incident{"port|198.18.0.4": {Change: model.Change{Key: "port|198.18.0.4", Kind: "port", Target: "198.18.0.4"}}}
	})

	updating := runtimeTestJob(t, db, "updating-baseline")
	setIndexedRuntimeBaseline(t, db, updating, "updating-scan", runtimeTestSnapshot(2, 1), func(state *model.JobState) {
		state.BaselineConfigHash = "an-earlier-scope"
	})

	legacy := runtimeTestJob(t, db, "legacy-baseline")
	legacyState, err := json.Marshal(model.JobState{
		Baseline:       &model.Snapshot{Units: []model.Unit{{Target: "edge.example", Protocol: "tcp", Addresses: []string{"198.18.1.1", "198.18.1.2"}}, {Target: "198.18.1.2", Protocol: "udp", Addresses: []string{"198.18.1.2"}}}},
		CandidateCount: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?) ON CONFLICT(job_id) DO UPDATE SET state_json=excluded.state_json,updated_at=excluded.updated_at`, legacy.ID, legacyState, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `DELETE FROM job_runtime_meta WHERE job_id=?`, legacy.ID); err != nil {
		t.Fatal(err)
	}

	collecting := runtimeTestJob(t, db, "collecting-baseline")
	if _, err := db.System().UpdateRuntime(ctx, collecting.ID, func(state *model.JobState) ([]model.Event, error) {
		candidate := runtimeTestSnapshot(3, 1)
		state.Candidate, state.CandidateCount, state.CandidateAttempts, state.IncompleteCandidateAttempts = &candidate, 1, 4, 3
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}

	listResponse := httptest.NewRecorder()
	server.listJobs(listResponse, httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil), defaultTenantStore(server))
	var list struct {
		Jobs []map[string]any `json:"jobs"`
	}
	if err := json.Unmarshal(listResponse.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	listed := map[string]any{}
	for _, job := range list.Jobs {
		listed[job["id"].(string)] = job["baseline"]
	}
	for _, record := range []store.JobRecord{indexed, modified, updating, legacy, collecting} {
		state, err := defaultTenant(db).RuntimeState(ctx, record.ID)
		if err != nil {
			t.Fatal(err)
		}
		want := jsonValue(t, stateBaselineJSON(state, record.Job.SecurityHash()))
		got := getJobJSON(t, server, admin, record.ID)["baseline"]
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: job detail baseline = %v, want %v", record.Job.Name, got, want)
		}
		if !reflect.DeepEqual(listed[record.ID], want) {
			t.Errorf("%s: job list baseline = %v, want %v", record.Job.Name, listed[record.ID], want)
		}
	}
	if got := getJobJSON(t, server, admin, updating.ID)["baseline"].(map[string]any)["status"]; got != "updating" {
		t.Errorf("baseline of an earlier scope has status %v", got)
	}
	if got := getJobJSON(t, server, admin, collecting.ID)["baseline"].(map[string]any)["status"]; got != "stalled" {
		t.Errorf("collecting baseline with three incomplete attempts has status %v", got)
	}
}

// TestJobDetailAllocationsDoNotGrowWithBaselineHosts keeps GET /jobs/{id}
// independent of the size of the job's runtime state. A job with a baseline
// of 1,500 hosts costs the same allocations as one with 10 hosts, and the
// response for it is built while the store cannot load a value as large as
// its runtime JSON. The test is not parallel, so that other tests do not
// count towards the allocations it measures.
func TestJobDetailAllocationsDoNotGrowWithBaselineHosts(t *testing.T) {
	server, db, admin := newUsersTestServer(t)
	// Write the runtime rows as persistRuntimeTx leaves them, with the
	// baseline host projection, without the cost of indexing every host's
	// evidence for search.
	writeRuntime := func(name string, hosts int) store.JobRecord {
		t.Helper()
		record := runtimeTestJob(t, db, name)
		snapshot := runtimeTestSnapshot(hosts, 20)
		raw, err := json.Marshal(model.JobState{Baseline: &snapshot, BaselineScanID: name + "-scan", BaselineConfigHash: record.Job.SecurityHash(), CandidateCount: 2})
		if err != nil {
			t.Fatal(err)
		}
		stamp := time.Now().UTC().Format(time.RFC3339Nano)
		tx, err := db.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?)`, record.ID, raw, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,updated_at) VALUES(?,1,?,?,0,1,2,?)`, record.ID, name+"-scan", record.Job.SecurityHash(), stamp); err != nil {
			t.Fatal(err)
		}
		for _, host := range snapshot.Hosts {
			if _, err := tx.Exec(`INSERT INTO baseline_hosts(job_id,address,host_json) VALUES(?,?,'{}')`, record.ID, host.Address); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return record
	}
	small, large := writeRuntime("small-baseline", 10), writeRuntime("large-baseline", 1500)

	var runtimeBytes int
	if err := db.DB.QueryRow(`SELECT length(state_json) FROM job_runtime WHERE job_id=?`, large.ID).Scan(&runtimeBytes); err != nil {
		t.Fatal(err)
	}
	const limit = 1 << 20
	if runtimeBytes < 2*limit {
		t.Fatalf("large runtime JSON is %d bytes, want several MiB", runtimeBytes)
	}
	limitReadValueLength(t, db, limit)
	for _, check := range []struct {
		record store.JobRecord
		hosts  float64
	}{{small, 10}, {large, 1500}} {
		if got := getJobJSON(t, server, admin, check.record.ID)["baseline"].(map[string]any)["host_count"]; got != check.hosts {
			t.Fatalf("%s: host_count = %v, want %v", check.record.Job.Name, got, check.hosts)
		}
	}
	allocations := func(record store.JobRecord) float64 {
		return testing.AllocsPerRun(10, func() {
			response := httptest.NewRecorder()
			server.jobRoute(response, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID, nil), admin, defaultTenantStore(server), record.ID)
			if response.Code != http.StatusOK {
				t.Fatalf("GET /jobs/%s = %d", record.ID, response.Code)
			}
		})
	}
	smallAllocations, largeAllocations := allocations(small), allocations(large)
	if largeAllocations > smallAllocations+50 {
		t.Fatalf("GET /jobs/{id} allocations: %v for 1500 baseline hosts, %v for 10", largeAllocations, smallAllocations)
	}
}

// TestJobBaselinePageLeavesOutHostStatesAndStaysBounded keeps a page of
// GET /jobs/{id}/baseline the same size whatever the number of addresses
// in the baseline. A page carries its units and the scope metadata, but
// neither the host observations nor the host states of the whole baseline.
func TestJobBaselinePageLeavesOutHostStatesAndStaysBounded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	page := func(record store.JobRecord, query string) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		response := httptest.NewRecorder()
		server.jobRoute(response, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/baseline"+query, nil), admin, defaultTenantStore(server), record.ID+"/baseline")
		if response.Code != http.StatusOK {
			t.Fatalf("GET /jobs/%s/baseline%s = %d: %s", record.ID, query, response.Code, response.Body.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		return response, payload
	}

	sizes := map[int]int{}
	for _, hosts := range []int{10, 300} {
		record := runtimeTestJob(t, db, fmt.Sprintf("baseline-page-%d", hosts))
		snapshot := runtimeTestSnapshot(hosts, 1)
		setIndexedRuntimeBaseline(t, db, record, fmt.Sprintf("baseline-page-scan-%d", hosts), snapshot, nil)
		response, payload := page(record, "?limit=1&offset=1")
		sizes[hosts] = response.Body.Len()
		got, ok := payload["snapshot"].(map[string]any)
		if !ok {
			t.Fatalf("%d hosts: snapshot = %#v", hosts, payload["snapshot"])
		}
		if _, present := got["host_states"]; present {
			t.Errorf("%d hosts: the page carries the baseline's host states", hosts)
		}
		if _, present := got["hosts"]; present {
			t.Errorf("%d hosts: the page carries the baseline's host observations", hosts)
		}
		// Apart from the host states and observations, the page is the
		// snapshot that decoding the whole runtime state gave.
		want := runtimeTestSnapshot(hosts, 1)
		want.Units, want.Hosts, want.HostStates = want.Units[1:2], nil, nil
		if !reflect.DeepEqual(got, jsonValue(t, want)) {
			t.Errorf("%d hosts: snapshot page = %v, want %v", hosts, got, jsonValue(t, want))
		}
		wantPagination := jsonValue(t, paginationJSON(1, 1, hosts))
		if !reflect.DeepEqual(payload["pagination"], wantPagination) {
			t.Errorf("%d hosts: pagination = %v, want %v", hosts, payload["pagination"], wantPagination)
		}
		state, err := defaultTenant(db).RuntimeState(ctx, record.ID)
		if err != nil {
			t.Fatal(err)
		}
		if want := jsonValue(t, stateBaselineJSON(state, record.Job.SecurityHash())); !reflect.DeepEqual(payload["baseline"], want) {
			t.Errorf("%d hosts: baseline = %v, want %v", hosts, payload["baseline"], want)
		}
		if _, beyond := page(record, fmt.Sprintf("?limit=5&offset=%d", hosts)); !reflect.DeepEqual(beyond["snapshot"].(map[string]any)["units"], []any{}) {
			t.Errorf("%d hosts: page beyond the units = %v", hosts, beyond["snapshot"])
		}
	}
	// Only the digits of the totals and of the host count differ.
	if growth := sizes[300] - sizes[10]; growth < 0 || growth > 16 {
		t.Fatalf("baseline page with limit=1 is %d bytes for 300 hosts and %d bytes for 10", sizes[300], sizes[10])
	}

	collecting := runtimeTestJob(t, db, "baseline-page-collecting")
	if _, err := db.System().UpdateRuntime(ctx, collecting.ID, func(state *model.JobState) ([]model.Event, error) {
		candidate := runtimeTestSnapshot(3, 1)
		state.Candidate, state.CandidateCount = &candidate, 1
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, payload := page(collecting, ""); payload["snapshot"] != nil || payload["pagination"].(map[string]any)["total"] != float64(0) {
		t.Fatalf("collecting job baseline page = %v", payload)
	}
}

// TestJobBaselinePageReportsInvalidRuntimeJSON answers a baseline page whose
// runtime JSON cannot be read with a sanitized internal error.
func TestJobBaselinePageReportsInvalidRuntimeJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	record := runtimeTestJob(t, db, "baseline-page-invalid")
	setIndexedRuntimeBaseline(t, db, record, "baseline-page-invalid-scan", runtimeTestSnapshot(2, 1), nil)
	if _, err := db.DB.ExecContext(ctx, `UPDATE job_runtime SET state_json=json_set(state_json,'$.baseline.units','not units') WHERE job_id=?`, record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE job_runtime SET state_json=json_set(state_json,'$.baseline.scopes','not scopes') WHERE job_id=?`, record.ID); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.jobRoute(response, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/baseline", nil), admin, defaultTenantStore(server), record.ID+"/baseline")
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "scopes") {
		t.Fatalf("baseline page with invalid scopes = %d: %s", response.Code, response.Body.String())
	}
}
