package web

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestJobUpdateRebaselineAndLifecycleErrors(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	job := config.NormalizeJob(config.Job{
		Name: "update-coverage", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"},
		Timeout: config.Duration(time.Minute), Timing: "balanced",
	})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	callUpdate := func(payload jobPayload) *httptest.ResponseRecorder {
		body, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		req := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/"+record.ID, strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.updateJob(rec, req, admin, record.ID)
		return rec
	}

	if rec := callUpdate(jobPayload{}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "revision") {
		t.Fatalf("missing revision update = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := callUpdate(jobPayload{Revision: 1, Timeout: "not-a-duration"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid duration update = %d: %s", rec.Code, rec.Body.String())
	}
	current := fromConfig(record.Job)
	current.Revision = record.Revision
	if rec := callUpdate(current); rec.Code != http.StatusOK {
		t.Fatalf("unchanged update = %d: %s", rec.Code, rec.Body.String())
	}
	record, err = db.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	stale := fromConfig(record.Job)
	stale.Revision = 1
	if rec := callUpdate(stale); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "conflict") {
		t.Fatalf("stale update = %d: %s", rec.Code, rec.Body.String())
	}

	scope := fromConfig(record.Job)
	scope.Revision = record.Revision
	scope.Targets = []string{"192.0.2.2"}
	if rec := callUpdate(scope); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "rebaseline") {
		t.Fatalf("unconfirmed scope update = %d: %s", rec.Code, rec.Body.String())
	}
	scope.ConfirmRebaseline = true
	if rec := callUpdate(scope); rec.Code != http.StatusOK {
		t.Fatalf("confirmed scope update = %d: %s", rec.Code, rec.Body.String())
	}
	record, err = db.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Revision != 3 || record.Job.Targets[0] != "192.0.2.2" {
		t.Fatalf("scope update record = %#v", record)
	}

	activeScope := fromConfig(record.Job)
	activeScope.Revision = record.Revision
	activeScope.Targets = []string{"192.0.2.3"}
	if err := db.AcquireJobLease(ctx, record.ID, "active-update", time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if rec := callUpdate(activeScope); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "active") {
		t.Fatalf("active scope update = %d: %s", rec.Code, rec.Body.String())
	}
	_ = db.ReleaseJobLease(ctx, record.ID, "active-update")

	// Pausing through the general job update endpoint must use the same lease
	// guard as the dedicated lifecycle route. Otherwise a running scan could
	// finalize after the UI says the job is paused.
	if err := db.AcquireJobLease(ctx, record.ID, "active-pause", time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	paused := fromConfig(record.Job)
	paused.Revision = record.Revision
	enabled := false
	paused.Enabled = &enabled
	if rec := callUpdate(paused); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "active") {
		t.Fatalf("active pause update = %d: %s", rec.Code, rec.Body.String())
	}
	_ = db.ReleaseJobLease(ctx, record.ID, "active-pause")

	// Lifecycle endpoints reject missing revisions, stale revisions, and
	// unknown jobs before changing any durable state.
	for _, invoke := range []struct {
		name string
		call func(*httptest.ResponseRecorder)
	}{
		{"archive missing revision", func(w *httptest.ResponseRecorder) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
			request.Header.Set("Content-Type", "application/json")
			server.archiveJob(w, request, admin, record.ID, true)
		}},
		{"restore stale revision", func(w *httptest.ResponseRecorder) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"revision":1}`))
			req.Header.Set("Content-Type", "application/json")
			server.archiveJob(w, req, admin, record.ID, false)
		}},
		{"pause missing revision", func(w *httptest.ResponseRecorder) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
			request.Header.Set("Content-Type", "application/json")
			server.enableJob(w, request, admin, record.ID, false)
		}},
		{"resume unknown job", func(w *httptest.ResponseRecorder) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"revision":1}`))
			req.Header.Set("Content-Type", "application/json")
			server.enableJob(w, req, admin, "missing", true)
		}},
	} {
		t.Run(invoke.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			invoke.call(rec)
			if rec.Code != http.StatusBadRequest && rec.Code != http.StatusConflict && rec.Code != http.StatusNotFound {
				t.Fatalf("lifecycle status = %d: %s", rec.Code, rec.Body.String())
			}
		})
	}

	nonAdmin := admin
	nonAdmin.Role = store.RoleOperator
	delete := httptest.NewRecorder()
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/?permanent=true", strings.NewReader(`{"confirm_name":"update-coverage"}`))
	deleteRequest.Header.Set("Content-Type", "application/json")
	server.permanentDelete(delete, deleteRequest, nonAdmin, record.ID)
	if delete.Code != http.StatusForbidden {
		t.Fatalf("non-admin permanent delete = %d", delete.Code)
	}
}

func TestJobListAndAPIDispatchCoverage(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	job := config.NormalizeJob(config.Job{Name: "dispatch", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}})
	if _, err := db.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	list := httptest.NewRecorder()
	server.listJobs(list, httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "dispatch") {
		t.Fatalf("job list = %d: %s", list.Code, list.Body.String())
	}

	raw := "dispatch-api-session"
	now := time.Now().UTC()
	if err := db.CreateSessionForUserWithAudit(ctx, admin.UserID, digest(raw), "dispatch-csrf", now, now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	callAPI := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "edgewatch_session", Value: raw})
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if method != http.MethodGet {
			req.Header.Set("X-CSRF-Token", "dispatch-csrf")
		}
		rec := httptest.NewRecorder()
		server.api(rec, req)
		return rec
	}
	for _, path := range []string{
		"/api/v1/setup/status", "/api/v1/status", "/api/v1/jobs", "/api/v1/jobs/schedule-suggestion?schedule=0+*+*+*+*&timezone=UTC",
		"/api/v1/scans", "/api/v1/hosts", "/api/v1/scans/active", "/api/v1/incidents", "/api/v1/events", "/api/v1/notifications/options",
		"/api/v1/jobs/missing", "/api/v1/jobs/missing/baseline", "/api/v1/jobs/missing/scans", "/api/v1/jobs/missing/incidents", "/api/v1/jobs/missing/events", "/api/v1/scans/missing/summary",
	} {
		rec := callAPI(http.MethodGet, path, "")
		if rec.Code != http.StatusOK && rec.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d: %s", path, rec.Code, rec.Body.String())
		}
	}
	for _, path := range []string{"/api/v1/jobs/missing/run", "/api/v1/jobs/missing/pause", "/api/v1/jobs/missing/archive", "/api/v1/jobs/missing/restore", "/api/v1/jobs/missing/baseline/reset", "/api/v1/jobs/missing/incidents/accept", "/api/v1/jobs/missing/incidents/suppress"} {
		rec := callAPI(http.MethodPost, path, `{}`)
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusBadRequest && rec.Code != http.StatusConflict {
			t.Errorf("POST %s status = %d: %s", path, rec.Code, rec.Body.String())
		}
	}
	unauthenticated := httptest.NewRecorder()
	server.api(unauthenticated, httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API status = %d", unauthenticated.Code)
	}
	closedServer, closedDB, _ := newUsersTestServer(t)
	_ = closedDB.Close()
	closed := httptest.NewRecorder()
	closedServer.listJobs(closed, httptest.NewRequest(http.MethodGet, "/", nil))
	if closed.Code != http.StatusInternalServerError {
		t.Fatalf("closed list jobs = %d", closed.Code)
	}
}

func TestJobPayloadConfigCopiesProfilesAndDurationFields(t *testing.T) {
	payload := jobPayload{
		Name: " payload ", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"},
		Timeout: "2h", ResumeWindow: "1.5d", NotificationDestinations: &[]string{"dest"},
		TCP: &protocolPayload{Ports: "1-2", Mode: "connect", ServiceDetection: true, ProfileID: "tcp-profile", ProfileRevision: 3, NaabuArgs: []string{"-rate", "100"}, NmapArgs: []string{"-sV"}, EnrichmentArgs: []string{"-sC"}, NSEProfile: "safe", NSEArgs: map[string]string{"a": "b"}},
		UDP: &protocolPayload{Ports: "53", Mode: "udp", ServiceDetection: true},
	}
	job, err := payload.config()
	if err != nil {
		t.Fatal(err)
	}
	if job.Name != "payload" || job.Timeout.Value() != 2*time.Hour || job.ResumeWindow.Value() != 36*time.Hour || job.TCP == nil || job.UDP == nil || job.TCP.ProfileRevision != 3 || len(job.TCP.NSEArgs) != 1 {
		t.Fatalf("payload config = %#v", job)
	}
	for _, raw := range []string{"", "0d", "31d", "NaNd", "0s", "721h"} {
		if _, err := parseDuration(raw); err == nil {
			t.Fatalf("invalid duration %q was accepted", raw)
		}
	}
}

func TestHighCostOverrideRequiresAdministrator(t *testing.T) {
	server, _, admin := newUsersTestServer(t)
	operator := admin
	operator.Role = store.RoleOperator
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(`{"name":"operator-high-cost","schedule":"0 * * * *","timezone":"UTC","targets":["192.0.2.1"],"tcp":{"ports":"1-65535","mode":"connect"},"allow_high_cost":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.createJob(rec, req, operator)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "high_cost_admin_required") {
		t.Fatalf("operator high-cost create = %d: %s", rec.Code, rec.Body.String())
	}

	adminReq := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(`{"name":"admin-high-cost","schedule":"0 * * * *","timezone":"UTC","targets":["192.0.2.1"],"tcp":{"ports":"1","mode":"connect"},"allow_high_cost":true}`))
	adminReq.Header.Set("Content-Type", "application/json")
	adminRec := httptest.NewRecorder()
	server.createJob(adminRec, adminReq, admin)
	if adminRec.Code != http.StatusCreated {
		t.Fatalf("administrator high-cost create = %d: %s", adminRec.Code, adminRec.Body.String())
	}
}

func TestJobResponsesRedactActiveScanCycleStoreFailures(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	job := config.NormalizeJob(config.Job{
		Name: "cycle-error-redaction", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "22", Mode: "connect"},
	})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	server.Log = slog.New(slog.NewTextHandler(&logs, nil))
	breakReadProjection(t, db, "scan_cycles")

	request := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), requestIDContextKey{}, "request-731-test"))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		switch {
		case path == "/api/v1/jobs" && method == http.MethodGet:
			server.listJobs(rec, req)
		case path == "/api/v1/jobs" && method == http.MethodPost:
			server.createJob(rec, req, admin)
		case path == "/api/v1/jobs/"+record.ID && method == http.MethodGet:
			server.getJob(rec, req, record.ID)
		case path == "/api/v1/jobs/"+record.ID && method == http.MethodPut:
			server.updateJob(rec, req, admin, record.ID)
		default:
			t.Fatalf("unexpected request %s %s", method, path)
		}
		return rec
	}

	assertSafeCycleError := func(name string, response *httptest.ResponseRecorder, status int) {
		t.Helper()
		if response.Code != status {
			t.Fatalf("%s status = %d, want %d: %s", name, response.Code, status, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "no such table: scan_cycles") || !strings.Contains(response.Body.String(), `"scan_cycle_error":"cycle_status_unavailable"`) {
			t.Errorf("%s did not return a safe cycle error marker: %s", name, response.Body.String())
		}
	}

	assertSafeCycleError("list", request(http.MethodGet, "/api/v1/jobs", ""), http.StatusOK)
	assertSafeCycleError("detail", request(http.MethodGet, "/api/v1/jobs/"+record.ID, ""), http.StatusOK)

	createBody := `{"name":"created-cycle-error","schedule":"0 * * * *","timezone":"UTC","targets":["192.0.2.11"],"tcp":{"ports":"80","mode":"connect","service_detection":false,"engine":"nmap"}}`
	assertSafeCycleError("create", request(http.MethodPost, "/api/v1/jobs", createBody), http.StatusCreated)

	updatePayload := fromConfig(record.Job)
	updatePayload.Revision = record.Revision
	body, err := json.Marshal(updatePayload)
	if err != nil {
		t.Fatal(err)
	}
	assertSafeCycleError("update", request(http.MethodPut, "/api/v1/jobs/"+record.ID, string(body)), http.StatusOK)

	if !strings.Contains(logs.String(), "request_id=request-731-test") || !strings.Contains(logs.String(), "no such table: scan_cycles") {
		t.Errorf("server log should retain the correlated storage error, got %q", logs.String())
	}
}

func TestBaselineJSONReportsStalledLearning(t *testing.T) {
	result := baselineJSONFromSummary(store.RuntimeStateSummary{IncompleteCandidateAttempts: 3}, "")
	if result["status"] != "stalled" || result["incomplete_attempts"] != 3 {
		t.Fatalf("stalled baseline response = %#v", result)
	}
}
