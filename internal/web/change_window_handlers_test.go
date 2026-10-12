package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
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
		request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
		response := httptest.NewRecorder()
		server.api(response, request)
		return response
	}
	viewerDetail := requestDetail(viewerToken, readWindow.ID)
	if viewerDetail.Code != http.StatusOK || strings.Contains(viewerDetail.Body.String(), "private-fingerprint-read") {
		t.Fatalf("jobs.read without incidents.read detail = %d: %s", viewerDetail.Code, viewerDetail.Body.String())
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
