package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func scanHandlerRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func breakReadProjection(t *testing.T, db *store.Store, table string) {
	t.Helper()
	if db.ReadDB != nil {
		_ = db.ReadDB.Close()
		db.ReadDB = nil
	}
	if _, err := db.DB.ExecContext(context.Background(), "DROP TABLE "+table); err != nil {
		t.Fatalf("drop %s: %v", table, err)
	}
}

func TestScanAndLifecycleHandlersRedactStoreFailures(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	job := config.NormalizeJob(config.Job{Name: "scan-error-handlers", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	get := func(fn func(http.ResponseWriter, *http.Request)) int {
		rec := httptest.NewRecorder()
		fn(rec, scanHandlerRequest(http.MethodGet, "/api/v1", ""))
		return rec.Code
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for name, fn := range map[string]func(http.ResponseWriter, *http.Request){
		"scans":     server.listScans,
		"incidents": server.listIncidents,
		"events":    func(w http.ResponseWriter, r *http.Request) { server.listEvents(w, r, "") },
	} {
		if code := get(fn); code != http.StatusInternalServerError {
			t.Errorf("%s status = %d", name, code)
		}
	}
	for name, fn := range map[string]func(http.ResponseWriter, *http.Request){
		"archive": func(w http.ResponseWriter, r *http.Request) {
			server.archiveJob(w, scanHandlerRequest(http.MethodPost, "/archive", `{"revision":1}`), admin, record.ID, true)
		},
		"pause": func(w http.ResponseWriter, r *http.Request) {
			server.enableJob(w, scanHandlerRequest(http.MethodPost, "/pause", `{"revision":1}`), admin, record.ID, false)
		},
	} {
		if code := get(fn); code != http.StatusInternalServerError {
			t.Errorf("%s status = %d", name, code)
		}
	}

	// Recreate independent fixtures so each broken projection is reached after
	// the route's ownership check has succeeded.
	server, db, admin = newUsersTestServer(t)
	record, err = db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	breakReadProjection(t, db, "job_runtime")
	if code := get(func(w http.ResponseWriter, r *http.Request) { server.getJob(w, r, record.ID) }); code != http.StatusInternalServerError {
		t.Fatalf("job runtime failure status = %d", code)
	}

	server, db, _ = newUsersTestServer(t)
	record, err = db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	breakReadProjection(t, db, "scans")
	if code := get(func(w http.ResponseWriter, r *http.Request) { server.latestSuccessfulScan(w, r, record.ID) }); code != http.StatusInternalServerError {
		t.Fatalf("latest scan failure status = %d", code)
	}
	if code := get(func(w http.ResponseWriter, r *http.Request) { server.jobScans(w, r, record.ID) }); code != http.StatusInternalServerError {
		t.Fatalf("job scans failure status = %d", code)
	}

	server, db, admin = newUsersTestServer(t)
	record, err = db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	breakReadProjection(t, db, "job_leases")
	if code := get(func(w http.ResponseWriter, r *http.Request) {
		server.runJob(w, scanHandlerRequest(http.MethodPost, "/run", `{}`), admin, record.ID)
	}); code != http.StatusInternalServerError {
		t.Fatalf("manual run failure status = %d", code)
	}

	server, db, _ = newUsersTestServer(t)
	record, err = db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	breakReadProjection(t, db, "scan_cycles")
	if code := get(func(w http.ResponseWriter, r *http.Request) { server.scanCycle(w, r, record.ID) }); code != http.StatusInternalServerError {
		t.Fatalf("scan cycle failure status = %d", code)
	}

	server, db, _ = newUsersTestServer(t)
	record, err = db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	breakReadProjection(t, db, "events")
	if code := get(func(w http.ResponseWriter, r *http.Request) { server.jobEvents(w, r, record.ID) }); code != http.StatusInternalServerError {
		t.Fatalf("job events failure status = %d", code)
	}

	server, db, _ = newUsersTestServer(t)
	record, err = db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	breakReadProjection(t, db, "runtime_incidents")
	if code := get(func(w http.ResponseWriter, r *http.Request) { server.jobIncidents(w, r, record.ID) }); code != http.StatusInternalServerError {
		t.Fatalf("job incidents failure status = %d", code)
	}

	server, db, admin = newUsersTestServer(t)
	breakReadProjection(t, db, "scanner_profiles")
	if code := get(func(w http.ResponseWriter, r *http.Request) { server.scannerProfilesRoute(w, r, admin, "") }); code != http.StatusInternalServerError {
		t.Fatalf("scanner profiles failure status = %d", code)
	}

	server, db, _ = newUsersTestServer(t)
	breakReadProjection(t, db, "jobs")
	if code := get(func(w http.ResponseWriter, r *http.Request) {
		server.scheduleSuggestion(w, httptest.NewRequest(http.MethodGet, "/api/v1/schedule/suggestion?schedule=0+*+*+*+*&timezone=UTC", nil))
	}); code != http.StatusInternalServerError {
		t.Fatalf("schedule suggestion failure status = %d", code)
	}
}

func TestScanHandlersCoverLegacyComparisonAndFailures(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	job := config.NormalizeJob(config.Job{
		Name: "scan-handler-coverage", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "80,443", Mode: "connect"},
		Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	baseline := model.Scan{
		ID: "legacy-handler-baseline", JobID: record.ID, JobRevision: record.Revision, Job: job.Name,
		StartedAt: now.Add(-time.Minute), FinishedAt: now.Add(-time.Minute), Status: "success", ConfigHash: job.SecurityHash(),
		Snapshot: model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.10", Protocol: "tcp", Ports: "80,443"}}, Units: []model.Unit{{Target: "192.0.2.10", Protocol: "tcp", Addresses: []string{"192.0.2.10"}, Ports: []model.PortState{{Port: 80, State: "open"}}}}},
	}
	if err := db.SaveScan(ctx, baseline); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ApproveRuntime(ctx, record.ID, job.Name, baseline); err != nil {
		t.Fatal(err)
	}
	legacy := model.Scan{
		ID: "legacy-handler-current", JobID: record.ID, JobRevision: record.Revision, Job: job.Name,
		StartedAt: now, FinishedAt: now, Status: "success", ConfigHash: job.SecurityHash(),
		Snapshot: model.Snapshot{Units: []model.Unit{{Target: "192.0.2.10", Protocol: "tcp", Addresses: []string{"192.0.2.10"}, Ports: []model.PortState{{Port: 443, State: "open"}}}}},
	}
	if err := db.SaveScan(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	selected := httptest.NewRecorder()
	server.jobScan(selected, scanHandlerRequest(http.MethodGet, "/scan?limit=10&offset=0", ""), record.ID, legacy.ID)
	if selected.Code != http.StatusOK || !strings.Contains(selected.Body.String(), "current_baseline_legacy") {
		t.Fatalf("legacy scan detail = %d: %s", selected.Code, selected.Body.String())
	}
	changes := httptest.NewRecorder()
	server.jobScanChanges(changes, scanHandlerRequest(http.MethodGet, "/changes?limit=1", ""), record.ID, legacy.ID)
	if changes.Code != http.StatusOK || !strings.Contains(changes.Body.String(), "current_baseline_legacy") {
		t.Fatalf("legacy scan changes = %d: %s", changes.Code, changes.Body.String())
	}
	results := httptest.NewRecorder()
	server.jobScanResults(results, scanHandlerRequest(http.MethodGet, "/results?limit=1", ""), record.ID, legacy.ID)
	if results.Code != http.StatusOK || !strings.Contains(results.Body.String(), `"results"`) {
		t.Fatalf("legacy scan results = %d: %s", results.Code, results.Body.String())
	}

	failed := model.Scan{ID: "failed-handler-scan", JobID: record.ID, JobRevision: record.Revision, Job: job.Name, StartedAt: now.Add(time.Minute), FinishedAt: now.Add(time.Minute), Status: "failed", Error: "scanner stopped", ConfigHash: job.SecurityHash(), Snapshot: model.Snapshot{}}
	if err := db.SaveScan(ctx, failed); err != nil {
		t.Fatal(err)
	}
	for name, fn := range map[string]func(*httptest.ResponseRecorder){
		"failed detail": func(w *httptest.ResponseRecorder) {
			server.jobScan(w, scanHandlerRequest(http.MethodGet, "/scan", ""), record.ID, failed.ID)
		},
		"failed changes": func(w *httptest.ResponseRecorder) {
			server.jobScanChanges(w, scanHandlerRequest(http.MethodGet, "/changes", ""), record.ID, failed.ID)
		},
		"empty results": func(w *httptest.ResponseRecorder) {
			server.jobScanResults(w, scanHandlerRequest(http.MethodGet, "/results", ""), record.ID, failed.ID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			fn(response)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", response.Code, response.Body.String())
			}
		})
	}

	for name, fn := range map[string]func(*httptest.ResponseRecorder){
		"missing job detail": func(w *httptest.ResponseRecorder) {
			server.jobScan(w, scanHandlerRequest(http.MethodGet, "/", ""), "missing", legacy.ID)
		},
		"wrong scan detail": func(w *httptest.ResponseRecorder) {
			server.jobScan(w, scanHandlerRequest(http.MethodGet, "/", ""), record.ID, "missing")
		},
		"missing job results": func(w *httptest.ResponseRecorder) {
			server.jobScanResults(w, scanHandlerRequest(http.MethodGet, "/", ""), "missing", legacy.ID)
		},
		"wrong scan changes": func(w *httptest.ResponseRecorder) {
			server.jobScanChanges(w, scanHandlerRequest(http.MethodGet, "/", ""), record.ID, "missing")
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			fn(response)
			if response.Code != http.StatusNotFound {
				t.Fatalf("status = %d: %s", response.Code, response.Body.String())
			}
		})
	}

	// A malformed runtime row exercises the explicit store-failure response
	// rather than allowing the legacy compatibility path to hide corruption.
	if _, err := db.DB.ExecContext(ctx, `UPDATE job_runtime SET state_json=? WHERE job_id=?`, []byte(`{"broken"`), record.ID); err != nil {
		t.Fatal(err)
	}
	corrupt := httptest.NewRecorder()
	server.jobScanChanges(corrupt, scanHandlerRequest(http.MethodGet, "/", ""), record.ID, legacy.ID)
	if corrupt.Code != http.StatusInternalServerError {
		t.Fatalf("corrupt runtime status = %d: %s", corrupt.Code, corrupt.Body.String())
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE job_runtime SET state_json=? WHERE job_id=?`, []byte(`{}`), record.ID); err != nil {
		t.Fatal(err)
	}
	// Restore the valid comparison state after the corruption branch so the
	// incident action checks exercise their baseline guards rather than the
	// unrelated baseline-not-ready response.
	if _, err := db.ApproveRuntime(ctx, record.ID, job.Name, baseline); err != nil {
		t.Fatal(err)
	}

	// The action handlers reject incomplete requests before touching the store.
	for _, fn := range []func(*httptest.ResponseRecorder){
		func(w *httptest.ResponseRecorder) {
			server.acceptIncident(w, scanHandlerRequest(http.MethodPost, "/", `{"key":""}`), admin, record.ID)
		},
		func(w *httptest.ResponseRecorder) {
			server.suppressIncident(w, scanHandlerRequest(http.MethodPost, "/", `{"key":"port|x"}`), admin, record.ID)
		},
		func(w *httptest.ResponseRecorder) {
			server.acceptIncident(w, scanHandlerRequest(http.MethodPost, "/", `{}`), admin, "missing")
		},
	} {
		response := httptest.NewRecorder()
		fn(response)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid incident request status = %d: %s", response.Code, response.Body.String())
		}
	}

	// Restore a valid state, then exercise unsupported and valid incident
	// actions. The expected change is required so an old browser cannot apply a
	// stale action to a newer incident.
	if _, err := db.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents["unsupported"] = model.Incident{Change: model.Change{Key: "unsupported", Kind: "hostname", Target: "192.0.2.10", Old: "a", New: "b"}, ScanID: legacy.ID}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	unsupportedBody := `{"key":"unsupported","expected_change":{"key":"unsupported","kind":"hostname","target":"192.0.2.10","old":"a","new":"b"}}`
	unsupported := httptest.NewRecorder()
	server.acceptIncident(unsupported, scanHandlerRequest(http.MethodPost, "/", unsupportedBody), admin, record.ID)
	if unsupported.Code != http.StatusBadRequest || !strings.Contains(unsupported.Body.String(), "incident_change_invalid") {
		t.Fatalf("unsupported incident = %d: %s", unsupported.Code, unsupported.Body.String())
	}
	unknown := httptest.NewRecorder()
	unknownBody := `{"key":"missing","expected_change":{"key":"missing","kind":"port","target":"192.0.2.10","protocol":"tcp","port":80,"old":"open","new":"closed"}}`
	server.suppressIncident(unknown, scanHandlerRequest(http.MethodPost, "/", unknownBody), admin, record.ID)
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown incident = %d: %s", unknown.Code, unknown.Body.String())
	}

	// Add a supported port incident and suppress it. This verifies the normal
	// transactional route, including audit/event broadcast preparation.
	change := model.Change{Key: "port|192.0.2.10|tcp|80", Kind: "port", Target: "192.0.2.10", Protocol: "tcp", Port: 80, Old: "open", New: "not-open", Severity: "critical"}
	if _, err := db.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents[change.Key] = model.Incident{Change: change, ScanID: legacy.ID, OpenedAt: now, LastSeenAt: now}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	encodedChange, err := json.Marshal(change)
	if err != nil {
		t.Fatal(err)
	}
	suppressed := httptest.NewRecorder()
	server.suppressIncident(suppressed, scanHandlerRequest(http.MethodPost, "/", `{"key":"`+change.Key+`","expected_change":`+string(encodedChange)+`}`), admin, record.ID)
	if suppressed.Code != http.StatusNoContent {
		t.Fatalf("suppress incident = %d: %s", suppressed.Code, suppressed.Body.String())
	}
}

func TestScanRunAndCancellationGuards(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	job := config.NormalizeJob(config.Job{Name: "run-handler-coverage", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	server.App.Scanner = fakeScanner{}
	server.App.BeginRun(ctx)
	accepted := httptest.NewRecorder()
	server.runJob(accepted, scanHandlerRequest(http.MethodPost, "/run", "{}"), admin, record.ID)
	if accepted.Code != http.StatusAccepted || !strings.Contains(accepted.Body.String(), `"mode":"standard"`) {
		t.Fatalf("accepted run = %d: %s", accepted.Code, accepted.Body.String())
	}
	server.App.StopRun()

	for _, raw := range []string{"", "missing"} {
		response := httptest.NewRecorder()
		server.cancelScan(response, httptest.NewRequest(http.MethodPost, "/cancel", nil), admin, raw)
		want := http.StatusNotFound
		if raw == "missing" {
			want = http.StatusConflict
		}
		if response.Code != want {
			t.Fatalf("cancel %q = %d: %s", raw, response.Code, response.Body.String())
		}
	}
}

func TestSecurityScopeChangesReportsAllSecurityInputs(t *testing.T) {
	old := config.NormalizeJob(config.Job{Name: "scope", Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1, AssumeAlive: boolPtr(true), TCP: &config.Protocol{Ports: "22", Mode: "connect", ServiceDetection: false, Engine: config.EngineNmap}, UDP: &config.Protocol{Ports: "53", ServiceDetection: false}})
	next := config.NormalizeJob(config.Job{Name: "scope", Targets: []string{"192.0.2.2"}, MaxExpandedHosts: 2, AssumeAlive: boolPtr(false), TCP: &config.Protocol{Ports: "443", Mode: "syn", ServiceDetection: true, Engine: config.EngineNaabuNmap, NSEProfile: "safe", Naabu: &config.NaabuOptions{ScanType: "syn", Verify: true}}, UDP: &config.Protocol{Ports: "5353", ServiceDetection: true}})
	changes := securityScopeChanges(old, next)
	if len(changes) < 9 {
		t.Fatalf("security changes = %#v", changes)
	}
	if broadScan(config.Job{}) {
		t.Fatal("empty job was considered broad")
	}
	broad := config.Job{TCP: &config.Protocol{Ports: "1-65535"}}
	if !broadScan(broad) {
		t.Fatal("full TCP scope was not considered broad")
	}
}
