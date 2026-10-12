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
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestChangeWindowHandlerValidationAndStateOutcomes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	ts := defaultTenantStore(server)
	job, err := ts.CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "change-window-handler-outcomes", Schedule: "0 * * * *", Timezone: "UTC",
		Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "443", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	assertError := func(response *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		if response.Code != status {
			t.Fatalf("response = %d: %s; want %d", response.Code, response.Body.String(), status)
		}
		var payload struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Error.Code != code {
			t.Fatalf("response error code = %q; want %q: %s", payload.Error.Code, code, response.Body.String())
		}
	}
	cancel := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/jobs/"+job.ID+"/change-windows", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		server.cancelChangeWindow(response, req, admin, ts, job)
		return response
	}
	review := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/"+job.ID+"/change-windows/review", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		server.reviewChangeWindow(response, req, admin, ts, job)
		return response
	}

	assertError(cancel("{"), http.StatusBadRequest, "invalid_json")
	assertError(cancel(`{}`), http.StatusBadRequest, "validation_failed")
	assertError(cancel(`{"window_id":"missing-window"}`), http.StatusNotFound, "not_found")

	start := time.Now().UTC().Add(time.Hour)
	window, err := ts.CreateChangeWindow(ctx, job.ID, start, start.Add(time.Hour), false, "scheduled maintenance", admin.UserID, admin.Username)
	if err != nil {
		t.Fatal(err)
	}
	cancelBody, err := json.Marshal(map[string]string{"window_id": window.ID})
	if err != nil {
		t.Fatal(err)
	}
	canceled := cancel(string(cancelBody))
	if canceled.Code != http.StatusOK {
		t.Fatalf("future cancellation = %d: %s", canceled.Code, canceled.Body.String())
	}
	var cancelPayload struct {
		Window store.ChangeWindow `json:"window"`
	}
	if err := json.Unmarshal(canceled.Body.Bytes(), &cancelPayload); err != nil {
		t.Fatal(err)
	}
	if cancelPayload.Window.ID != window.ID || cancelPayload.Window.Status != "cancelled" || cancelPayload.Window.EndReason != "cancelled-before-start" || cancelPayload.Window.ClosedAt == nil || cancelPayload.Window.Summary != nil {
		t.Fatalf("future cancel result = %+v; want closed-before-start without a review summary", cancelPayload.Window)
	}
	assertError(cancel(string(cancelBody)), http.StatusConflict, "conflict")

	active, err := ts.CreateChangeWindow(ctx, job.ID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "active maintenance", admin.UserID, admin.Username)
	if err != nil {
		t.Fatal(err)
	}
	assertError(review(`{}`), http.StatusBadRequest, "validation_failed")
	// The store's conditional review update deliberately gives a conflict for
	// both an unknown ID and a stale/non-reviewable revision.
	assertError(review(`{"window_id":"missing-window","revision":1}`), http.StatusConflict, "conflict")
	activeReview, err := json.Marshal(map[string]any{"window_id": active.ID, "revision": active.Revision})
	if err != nil {
		t.Fatal(err)
	}
	assertError(review(string(activeReview)), http.StatusConflict, "conflict")

	missingRequest := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+job.ID+"/change-windows/missing-window", nil)
	missingResponse := httptest.NewRecorder()
	server.getChangeWindow(missingResponse, missingRequest, admin, ts, job, "missing-window")
	assertError(missingResponse, http.StatusNotFound, "not_found")

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	listRequest := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+job.ID+"/change-windows", nil)
	listResponse := httptest.NewRecorder()
	server.listChangeWindows(listResponse, listRequest, admin, ts, job)
	assertError(listResponse, http.StatusInternalServerError, "store")
	if strings.Contains(listResponse.Body.String(), "database is closed") {
		t.Fatalf("list leaked its storage failure: %s", listResponse.Body.String())
	}
	getResponse := httptest.NewRecorder()
	server.getChangeWindow(getResponse, missingRequest, admin, ts, job, window.ID)
	assertError(getResponse, http.StatusInternalServerError, "store")
	if strings.Contains(getResponse.Body.String(), "database is closed") {
		t.Fatalf("detail leaked its storage failure: %s", getResponse.Body.String())
	}
}
