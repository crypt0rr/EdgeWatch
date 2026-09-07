package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestHistoryAndIncidentHandlersExposeScopedPages(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := app.New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(a, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	job := config.NormalizeJob(config.Job{Name: "history-handlers", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced"})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	when := time.Now().UTC()
	change := model.Change{Key: "port|127.0.0.1|tcp|1", Kind: "port", Severity: "critical", Target: "127.0.0.1", Protocol: "tcp", Port: 1, Old: "closed", New: "open"}
	scan := model.Scan{ID: "history-handler-scan", JobID: record.ID, JobRevision: record.Revision, Job: job.Name, StartedAt: when, FinishedAt: when, Status: "success", ConfigHash: job.SecurityHash(), BaselineScanID: "baseline-scan", BaselineConfigHash: job.SecurityHash(), Changes: []model.Change{change}, Snapshot: model.Snapshot{Units: []model.Unit{{Target: "127.0.0.1", Protocol: "tcp", Addresses: []string{"127.0.0.1"}, Ports: []model.PortState{{Port: 1, State: "open"}}}}}}
	if err := db.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents[change.Key] = model.Incident{Change: change, ScanID: scan.ID, OpenedAt: when, LastSeenAt: when}
		return []model.Event{{Type: "history-event", Job: job.Name, JobID: record.ID, ScanID: scan.ID, CreatedAt: when}}, nil
	}); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	server.jobScans(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/scans?limit=1", nil), record.ID)
	if recorder.Code != http.StatusOK || !containsJSONField(recorder.Body.Bytes(), "scans") {
		t.Fatalf("job scans = %d: %s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	server.jobScan(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/scans/"+scan.ID, nil), record.ID, scan.ID)
	if recorder.Code != http.StatusOK || !containsJSONField(recorder.Body.Bytes(), "scan_time") || !containsJSONField(recorder.Body.Bytes(), "changes") {
		t.Fatalf("job scan = %d: %s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	server.jobScanResults(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/scans/"+scan.ID+"/results?limit=1", nil), record.ID, scan.ID)
	if recorder.Code != http.StatusOK || !containsJSONField(recorder.Body.Bytes(), "results") {
		t.Fatalf("scan results = %d: %s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	server.jobScanChanges(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/scans/"+scan.ID+"/changes", nil), record.ID, scan.ID)
	if recorder.Code != http.StatusOK || !containsJSONField(recorder.Body.Bytes(), "comparison_source") || !containsJSONField(recorder.Body.Bytes(), "scan_time") {
		t.Fatalf("scan changes = %d: %s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	server.listScans(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/scans?job="+job.Name, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("all scans = %d: %s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	server.getScan(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+scan.ID, nil), scan.ID)
	if recorder.Code != http.StatusOK {
		t.Fatalf("scan detail = %d: %s", recorder.Code, recorder.Body.String())
	}
	var detail map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &detail); err != nil || detail["scan"] == nil {
		t.Fatalf("scan detail payload = %#v, %v", detail, err)
	}

	recorder = httptest.NewRecorder()
	server.listEvents(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/events?job_id="+record.ID, nil), "")
	if recorder.Code != http.StatusOK || !containsJSONField(recorder.Body.Bytes(), "history-event") {
		t.Fatalf("job-id events = %d: %s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	server.listEvents(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/events?job="+job.Name, nil), job.Name)
	if recorder.Code != http.StatusOK {
		t.Fatalf("name events = %d: %s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	server.jobEvents(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/events", nil), record.ID)
	if recorder.Code != http.StatusOK {
		t.Fatalf("job events = %d: %s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	server.listIncidents(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil))
	if recorder.Code != http.StatusOK || !containsJSONField(recorder.Body.Bytes(), "incidents") {
		t.Fatalf("all incidents = %d: %s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	server.jobIncidents(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+record.ID+"/incidents", nil), record.ID)
	if recorder.Code != http.StatusOK || !containsJSONField(recorder.Body.Bytes(), change.Key) {
		t.Fatalf("job incidents = %d: %s", recorder.Code, recorder.Body.String())
	}

	for _, call := range []func(*httptest.ResponseRecorder){
		func(w *httptest.ResponseRecorder) {
			server.jobScans(w, httptest.NewRequest(http.MethodGet, "/", nil), "missing")
		},
		func(w *httptest.ResponseRecorder) {
			server.getScan(w, httptest.NewRequest(http.MethodGet, "/", nil), "missing")
		},
		func(w *httptest.ResponseRecorder) {
			server.jobEvents(w, httptest.NewRequest(http.MethodGet, "/", nil), "missing")
		},
		func(w *httptest.ResponseRecorder) {
			server.jobIncidents(w, httptest.NewRequest(http.MethodGet, "/", nil), "missing")
		},
	} {
		missing := httptest.NewRecorder()
		call(missing)
		if missing.Code != http.StatusNotFound {
			t.Fatalf("missing history resource status = %d: %s", missing.Code, missing.Body.String())
		}
	}
}
