package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestChangeWindowEvidenceIsPermissionScopedForReadAndMutationResponses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	ts := defaultTenantStore(server)
	job, err := ts.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "change-window-privacy", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	viewerUser, err := storetest.CreateUser(ctx, db, store.DefaultTenantScope(), store.User{
		Username: "change-window-viewer", DisplayName: "Window Viewer", Role: store.RoleViewer, PasswordHash: "unused-hash", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	viewer := store.Session{UserID: viewerUser.ID, Username: viewerUser.Username, Role: store.RoleViewer, CSRFToken: "window-viewer-csrf"}
	admin.CSRFToken = "window-admin-csrf"
	const viewerToken = "change-window-viewer-token"
	const adminToken = "change-window-admin-token"
	now := time.Now().UTC()
	for session, token := range map[store.Session]string{viewer: viewerToken, admin: adminToken} {
		if err := storetest.CreateSession(ctx, db, session.UserID, digest(token), session.CSRFToken, now, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}

	createEvidence := func(label string) store.ChangeWindow {
		t.Helper()
		window, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "approved maintenance", admin.UserID, admin.Username)
		if err != nil {
			t.Fatal(err)
		}
		event := model.Event{
			Type: "changes-detected", JobID: job.ID, Job: job.Job.Name, ScanID: "scan-" + label,
			Message: "change detected", CreatedAt: time.Now().UTC(),
			Changes: []model.Change{{Key: "private-fingerprint-" + label, Kind: "port", Severity: "high", Target: "192.0.2.10", Protocol: "tcp", Port: 443}},
		}
		if err := db.System().QueueEvent(ctx, "window-evidence-"+label, event); err != nil {
			t.Fatal(err)
		}
		return window
	}

	readWindow := createEvidence("read")
	if _, changed, err := ts.CancelChangeWindow(ctx, job.ID, readWindow.ID, admin.UserID, admin.Username, []string{"window-summary-read"}, store.AuditEntry{}); err != nil || !changed {
		t.Fatalf("close read fixture: changed %v, err %v", changed, err)
	}
	requestDetail := func(token, windowID string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+job.ID+"/change-windows/"+windowID, nil)
		addTestSessionCookie(request, token)
		response := httptest.NewRecorder()
		server.api(response, request)
		return response
	}
	viewerDetail := requestDetail(viewerToken, readWindow.ID)
	if viewerDetail.Code != http.StatusOK || strings.Contains(viewerDetail.Body.String(), "private-fingerprint-read") {
		t.Fatalf("jobs.read without incidents.read detail = %d: %s", viewerDetail.Code, viewerDetail.Body.String())
	}
	listRequest := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+job.ID+"/change-windows", nil)
	listResponse := httptest.NewRecorder()
	server.listChangeWindows(listResponse, listRequest, viewer, ts, job)
	if listResponse.Code != http.StatusOK || strings.Contains(listResponse.Body.String(), "private-fingerprint-read") {
		t.Fatalf("metadata-only list response = %d: %s", listResponse.Code, listResponse.Body.String())
	}
	var listPayload struct {
		Windows []store.ChangeWindow `json:"windows"`
	}
	if err := json.Unmarshal(listResponse.Body.Bytes(), &listPayload); err != nil {
		t.Fatal(err)
	}
	if len(listPayload.Windows) != 1 || listPayload.Windows[0].Summary != nil || listPayload.Windows[0].SuppressedEventCount != 1 {
		t.Fatalf("list window metadata = %+v", listPayload.Windows)
	}
	var viewerPayload struct {
		Window store.ChangeWindow `json:"window"`
	}
	if err := json.Unmarshal(viewerDetail.Body.Bytes(), &viewerPayload); err != nil {
		t.Fatal(err)
	}
	if viewerPayload.Window.Summary != nil || viewerPayload.Window.SuppressedEventCount != 1 || viewerPayload.Window.ReviewState != "due" {
		t.Fatalf("jobs.read window projection lost metadata or exposed evidence: %+v", viewerPayload.Window)
	}
	adminDetail := requestDetail(adminToken, readWindow.ID)
	if adminDetail.Code != http.StatusOK || !strings.Contains(adminDetail.Body.String(), "private-fingerprint-read") {
		t.Fatalf("incidents.read detail did not expose authorized evidence: %d: %s", adminDetail.Code, adminDetail.Body.String())
	}

	// Built-in roles that can mutate windows currently also hold incidents.read.
	// Invoke the handlers with a viewer session to exercise their independent
	// response redaction while route-table tests cover mutation authorization.
	cancelWindow := createEvidence("cancel")
	cancelBody := `{"window_id":"` + cancelWindow.ID + `"}`
	cancelRequest := httptest.NewRequest(http.MethodDelete, "/api/v1/jobs/"+job.ID+"/change-windows", strings.NewReader(cancelBody))
	cancelRequest.Header.Set("Content-Type", "application/json")
	cancelResponse := httptest.NewRecorder()
	server.cancelChangeWindow(cancelResponse, cancelRequest, viewer, ts, job)
	if cancelResponse.Code != http.StatusOK || strings.Contains(cancelResponse.Body.String(), "private-fingerprint-cancel") {
		t.Fatalf("jobs.write cancellation response without incidents.read = %d: %s", cancelResponse.Code, cancelResponse.Body.String())
	}
	var canceled struct {
		Window store.ChangeWindow `json:"window"`
	}
	if err := json.Unmarshal(cancelResponse.Body.Bytes(), &canceled); err != nil {
		t.Fatal(err)
	}
	if canceled.Window.Summary != nil || canceled.Window.SuppressedEventCount != 1 {
		t.Fatalf("redacted cancellation lost status/count metadata: %+v", canceled.Window)
	}

	reviewWindow := createEvidence("review")
	closedReview, changed, err := ts.CancelChangeWindow(ctx, job.ID, reviewWindow.ID, admin.UserID, admin.Username, []string{"window-summary-review"}, store.AuditEntry{})
	if err != nil || !changed || closedReview.Summary == nil {
		t.Fatalf("close review fixture: changed %v, err %v", changed, err)
	}
	reviewEncoded, err := json.Marshal(map[string]any{"window_id": reviewWindow.ID, "revision": closedReview.Revision})
	if err != nil {
		t.Fatal(err)
	}
	reviewRequest := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/"+job.ID+"/change-windows/review", strings.NewReader(string(reviewEncoded)))
	reviewRequest.Header.Set("Content-Type", "application/json")
	reviewResponse := httptest.NewRecorder()
	server.reviewChangeWindow(reviewResponse, reviewRequest, viewer, ts, job)
	if reviewResponse.Code != http.StatusOK || strings.Contains(reviewResponse.Body.String(), "private-fingerprint-review") {
		t.Fatalf("incidents.manage review response without incidents.read = %d: %s", reviewResponse.Code, reviewResponse.Body.String())
	}
	var reviewed struct {
		Window store.ChangeWindow `json:"window"`
	}
	if err := json.Unmarshal(reviewResponse.Body.Bytes(), &reviewed); err != nil {
		t.Fatal(err)
	}
	if reviewed.Window.Summary != nil || reviewed.Window.ReviewState != "reviewed" || reviewed.Window.SuppressedEventCount != 1 {
		t.Fatalf("redacted review response lost status/count metadata: %+v", reviewed.Window)
	}
}

func TestCreateChangeWindowValidatesTimeAndCreatesDurableWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, _, admin := newUsersTestServer(t)
	ts := defaultTenantStore(server)
	job, err := ts.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "change-window-create-validation", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().UTC().Add(3 * time.Hour).Format(time.RFC3339Nano)
	wrongZone := time.Now().UTC().Add(4 * time.Hour).In(time.FixedZone("wrong", 60*60)).Format(time.RFC3339Nano)
	cases := []struct {
		name      string
		input     map[string]any
		status    int
		code      string
		fieldName string
	}{
		{name: "missing start mode", input: map[string]any{"end_at": end, "reason": "maintenance"}, status: http.StatusBadRequest, code: "validation_failed", fieldName: "start_now"},
		{name: "invalid scheduled start", input: map[string]any{"start_now": false, "start_at": "not-an-instant", "end_at": end, "reason": "maintenance"}, status: http.StatusBadRequest, code: "validation_failed", fieldName: "start_at"},
		{name: "start now with a start instant", input: map[string]any{"start_now": true, "start_at": end, "end_at": end, "reason": "maintenance"}, status: http.StatusBadRequest, code: "validation_failed", fieldName: "start_at"},
		{name: "invalid end", input: map[string]any{"start_now": true, "start_at": "", "end_at": "not-an-instant", "reason": "maintenance"}, status: http.StatusBadRequest, code: "validation_failed", fieldName: "end_at"},
		{name: "wrong job zone offset", input: map[string]any{"start_now": true, "start_at": "", "end_at": wrongZone, "reason": "maintenance"}, status: http.StatusBadRequest, code: "validation_failed", fieldName: "job"},
		{name: "empty reason", input: map[string]any{"start_now": true, "start_at": "", "end_at": end, "reason": "  "}, status: http.StatusBadRequest, code: "validation_failed", fieldName: "job"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.input)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+job.ID+"/change-windows", strings.NewReader(string(encoded)))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			server.createChangeWindow(response, request, admin, ts, job)
			if response.Code != test.status {
				t.Fatalf("create response = %d: %s; want %d", response.Code, response.Body.String(), test.status)
			}
			var payload struct {
				Error struct {
					Code    string            `json:"code"`
					Message string            `json:"message"`
					Details map[string]string `json:"details"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Error.Code != test.code || payload.Error.Message == "" || payload.Error.Details[test.fieldName] == "" {
				t.Fatalf("validation payload = %+v; want code %q and field %q", payload.Error, test.code, test.fieldName)
			}
		})
	}

	create := func(end string) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(map[string]any{"start_now": true, "start_at": "", "end_at": end, "reason": "scheduled maintenance"})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+job.ID+"/change-windows", strings.NewReader(string(encoded)))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		server.createChangeWindow(response, request, admin, ts, job)
		return response
	}
	created := create(time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339Nano))
	if created.Code != http.StatusCreated {
		t.Fatalf("valid create response = %d: %s", created.Code, created.Body.String())
	}
	var payload struct {
		Window store.ChangeWindow `json:"window"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Window.ID == "" || payload.Window.Status != "active" || payload.Window.Reason != "scheduled maintenance" {
		t.Fatalf("created window = %+v", payload.Window)
	}
	conflict := create(time.Now().UTC().Add(4 * time.Hour).Format(time.RFC3339Nano))
	if conflict.Code != http.StatusConflict {
		t.Fatalf("overlapping create response = %d: %s; want conflict", conflict.Code, conflict.Body.String())
	}
}

func TestChangeWindowErrorMapping(t *testing.T) {
	t.Parallel()
	server, _, _ := newUsersTestServer(t)
	cases := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "not found", err: store.ErrNotFound, status: http.StatusNotFound, code: "not_found"},
		{name: "conflict", err: store.ErrConflict, status: http.StatusConflict, code: "conflict"},
		{name: "validation", err: store.NewValidationError(errors.New("invalid window")), status: http.StatusBadRequest, code: "validation_failed"},
		{name: "audit unavailable", err: store.ErrAuditUnavailable, status: http.StatusServiceUnavailable, code: "audit_unavailable"},
		{name: "internal", err: errors.New("injected storage error"), status: http.StatusInternalServerError, code: "store"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job/change-windows", nil)
			response := httptest.NewRecorder()
			server.writeChangeWindowError(response, request, test.err)
			if response.Code != test.status {
				t.Fatalf("error response = %d: %s; want %d", response.Code, response.Body.String(), test.status)
			}
			var payload struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Error.Code != test.code || payload.Error.Message == "" {
				t.Fatalf("error contract = %+v; want code %q", payload.Error, test.code)
			}
			if test.name == "internal" && strings.Contains(payload.Error.Message, "injected storage error") {
				t.Fatal("internal storage error leaked into the API response")
			}
		})
	}
}
