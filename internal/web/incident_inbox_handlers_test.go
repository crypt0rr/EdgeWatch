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

func TestIncidentInboxRoutesExposeReviewAndConflictContract(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	job, err := defaultTenant(db).CreateJob(ctx, config.NormalizeJob(config.Job{
		Name: "incident-inbox-route", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.44"},
		TCP: &config.Protocol{Ports: "443", Mode: "connect"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	incident := model.Incident{
		Change: model.Change{Key: "port|192.0.2.44|tcp|443", Kind: "port", Severity: "critical", Target: "192.0.2.44", Protocol: "tcp", Port: 443, Old: "closed", New: "open"},
		ScanID: "inbox-route-scan", OpenedAt: now, LastSeenAt: now,
	}
	if err := db.System().SaveScan(ctx, model.Scan{ID: incident.ScanID, JobID: job.ID, Job: job.Job.Name, StartedAt: now.Add(-time.Minute), FinishedAt: now, Status: "success", Comparison: model.ScanComparisonCompared}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents[incident.Change.Key] = incident
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}

	rawCookie := "incident-inbox-route-session"
	csrf := "incident-inbox-route-csrf"
	if err := storetest.CreateSession(ctx, db, admin.UserID, digest(rawCookie), csrf, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string, mutation bool) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.RemoteAddr = "127.0.0.1:9000"
		request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: rawCookie})
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		if mutation {
			request.Header.Set("X-CSRF-Token", csrf)
		}
		response := httptest.NewRecorder()
		server.api(response, request)
		return response
	}

	list := call(http.MethodGet, "/api/v1/incidents?view=needs_review&job_id="+job.ID, "", false)
	if list.Code != http.StatusOK {
		t.Fatalf("GET incidents status = %d: %s", list.Code, list.Body.String())
	}
	var page IncidentInboxPage
	if err := json.Unmarshal(list.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Incidents) != 1 || page.Incidents[0].OccurrenceToken == "" || !page.Incidents[0].OpeningScanAvailable || page.Incidents[0].Review.Revision != 0 || page.Incidents[0].ViewStatus != "needs_review" || page.Pagination.Total != 1 || page.ActiveCount != 1 {
		t.Fatalf("needs-review inbox response = %+v", page)
	}
	item := page.Incidents[0]
	exact := call(http.MethodGet, "/api/v1/incidents?view=all_active&job_id="+job.ID+"&occurrence_token="+item.OccurrenceToken, "", false)
	var exactPayload IncidentInboxPage
	if exact.Code != http.StatusOK || json.Unmarshal(exact.Body.Bytes(), &exactPayload) != nil || len(exactPayload.Incidents) != 1 || exactPayload.Incidents[0].OccurrenceToken != item.OccurrenceToken {
		t.Fatalf("exact-occurrence refresh = %d: %s", exact.Code, exact.Body.String())
	}
	unbounded := call(http.MethodGet, "/api/v1/incidents?occurrence_token="+item.OccurrenceToken, "", false)
	var filterError struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if unbounded.Code != http.StatusBadRequest || json.Unmarshal(unbounded.Body.Bytes(), &filterError) != nil || filterError.Error.Code != "incident_filter_invalid" {
		t.Fatalf("token filter without job = %d: %s", unbounded.Code, unbounded.Body.String())
	}

	due := now.Add(-time.Minute).Format(time.RFC3339Nano)
	body, err := json.Marshal(map[string]any{
		"key": item.Incident.Change.Key, "occurrence_token": item.OccurrenceToken, "expected_revision": int64(0),
		"status": "investigating", "note": "private follow-up note", "follow_up_at": due,
	})
	if err != nil {
		t.Fatal(err)
	}
	unitEvents, _ := registerSSEChannel(server, sseSubscriber{tenantID: store.DefaultTenantID})
	otherUnitEvents, _ := registerSSEChannel(server, sseSubscriber{tenantID: tenantAccountsOtherID})
	updated := call(http.MethodPut, "/api/v1/jobs/"+job.ID+"/incidents/review", string(body), true)
	if updated.Code != http.StatusOK {
		t.Fatalf("PUT incident review status = %d: %s", updated.Code, updated.Body.String())
	}
	select {
	case event := <-unitEvents:
		if event.audience != audienceUnit(store.DefaultTenantID) {
			t.Fatalf("review update audience = %+v, want tenant %s", event.audience, store.DefaultTenantID)
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(event.payload, &payload); err != nil {
			t.Fatalf("decode review update event: %v", err)
		}
		var eventType, eventJobID string
		if err := json.Unmarshal(payload["type"], &eventType); err != nil {
			t.Fatalf("decode review update event type: %v", err)
		}
		if err := json.Unmarshal(payload["job_id"], &eventJobID); err != nil {
			t.Fatalf("decode review update job id: %v", err)
		}
		if len(payload) != 2 || eventType != "incident.review.updated" || eventJobID != job.ID {
			t.Fatalf("review update event payload = %s, want only event type and job id", event.payload)
		}
		if strings.Contains(string(event.payload), "private follow-up note") || strings.Contains(string(event.payload), item.OccurrenceToken) || strings.Contains(string(event.payload), item.Incident.Change.Key) {
			t.Fatalf("review update event exposed note or private fingerprint: %s", event.payload)
		}
	case <-time.After(time.Second):
		t.Fatal("review update event was not delivered to its tenant")
	}
	select {
	case event := <-otherUnitEvents:
		t.Fatalf("review update for tenant %s reached another tenant: %s", store.DefaultTenantID, event.payload)
	default:
	}
	var review store.IncidentReview
	if err := json.Unmarshal(updated.Body.Bytes(), &review); err != nil {
		t.Fatal(err)
	}
	if review.Revision != 1 || review.Status != "investigating" || review.Note != "private follow-up note" || review.ReviewerLabel == nil || *review.ReviewerLabel != "Administrator" || review.FollowUpAt == nil || !review.FollowUpAt.Equal(now.Add(-time.Minute)) {
		t.Fatalf("direct updated review response = %+v", review)
	}
	if strings.Contains(updated.Body.String(), item.OccurrenceToken) {
		t.Fatalf("updated review response exposed the occurrence token: %s", updated.Body.String())
	}
	duePage := call(http.MethodGet, "/api/v1/incidents?view=follow_up_due&job_id="+job.ID, "", false)
	var duePayload IncidentInboxPage
	if duePage.Code != http.StatusOK || json.Unmarshal(duePage.Body.Bytes(), &duePayload) != nil || len(duePayload.Incidents) != 1 || duePayload.Incidents[0].ViewStatus != "follow_up_due" {
		t.Fatalf("follow-up-due inbox = %d: %s", duePage.Code, duePage.Body.String())
	}

	staleBody := strings.Replace(string(body), `"expected_revision":0`, `"expected_revision":0`, 1)
	stale := call(http.MethodPut, "/api/v1/jobs/"+job.ID+"/incidents/review", staleBody, true)
	var staleError struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if stale.Code != http.StatusConflict || json.Unmarshal(stale.Body.Bytes(), &staleError) != nil || staleError.Error.Code != "incident_review_revision_conflict" {
		t.Fatalf("stale revision response = %d: %s", stale.Code, stale.Body.String())
	}
	invalidDateBody := strings.Replace(string(body), due, now.Add(time.Hour).In(time.FixedZone("plus-one", 3600)).Format(time.RFC3339), 1)
	invalidDate := call(http.MethodPut, "/api/v1/jobs/"+job.ID+"/incidents/review", invalidDateBody, true)
	var invalidError struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if invalidDate.Code != http.StatusBadRequest || json.Unmarshal(invalidDate.Body.Bytes(), &invalidError) != nil || invalidError.Error.Code != "incident_review_invalid" {
		t.Fatalf("non-UTC follow-up response = %d: %s", invalidDate.Code, invalidDate.Body.String())
	}
	tooLong := strings.Replace(string(body), "private follow-up note", strings.Repeat("n", 4097), 1)
	invalidNote := call(http.MethodPut, "/api/v1/jobs/"+job.ID+"/incidents/review", tooLong, true)
	if invalidNote.Code != http.StatusBadRequest || json.Unmarshal(invalidNote.Body.Bytes(), &invalidError) != nil || invalidError.Error.Code != "incident_review_invalid" {
		t.Fatalf("oversize note response = %d: %s", invalidNote.Code, invalidNote.Body.String())
	}

	// A valid higher-priority incident may already have been scanned when the
	// later row fails to decode. The public handler must return only an error,
	// never a partial inbox page.
	laterIncident := model.Incident{
		Change: model.Change{Key: "later-corrupt-row", Kind: "host", Severity: "warning", Target: "later.example", Old: "absent", New: "present"},
	}
	if _, err := db.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Incidents[laterIncident.Change.Key] = laterIncident
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE runtime_incidents SET incident_json=? WHERE job_id=? AND key=?`, `{broken`, job.ID, laterIncident.Change.Key); err != nil {
		t.Fatal(err)
	}
	failedPage := call(http.MethodGet, "/api/v1/incidents?view=all_active&job_id="+job.ID, "", false)
	var failedPayload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if failedPage.Code != http.StatusInternalServerError || json.Unmarshal(failedPage.Body.Bytes(), &failedPayload) != nil || failedPayload.Error.Code != "store" {
		t.Fatalf("corrupt projection response = %d: %s; want fail-closed store error", failedPage.Code, failedPage.Body.String())
	}
	if strings.Contains(failedPage.Body.String(), `"incidents"`) || strings.Contains(failedPage.Body.String(), item.OccurrenceToken) || strings.Contains(failedPage.Body.String(), laterIncident.Change.Key) {
		t.Fatalf("failed inbox response included partial data: %s", failedPage.Body.String())
	}
}

func TestDecodeIncidentReviewReturnsFieldErrorsWithoutEchoingRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		body        string
		contentType string
		wantStatus  int
		wantCode    string
		wantFields  []string
	}{
		{
			name:        "all required fields are validated together",
			body:        `{"key":" ","occurrence_token":"","expected_revision":-1,"status":"closed","note":"private submitted value","follow_up_at":"2026-10-11T12:00:00Z"}`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "incident_review_invalid",
			wantFields:  []string{"key", "occurrence_token", "expected_revision", "status"},
		},
		{
			name:        "malformed follow-up instant is rejected",
			body:        `{"key":"incident","occurrence_token":"v1:opaque","expected_revision":0,"status":"investigating","follow_up_at":"tomorrow"}`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "incident_review_invalid",
			wantFields:  []string{"follow_up_at"},
		},
		{
			name:        "needs review cannot retain a follow-up date",
			body:        `{"key":"incident","occurrence_token":"v1:opaque","expected_revision":0,"status":"needs_review","follow_up_at":"2026-10-11T12:00:00Z"}`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "incident_review_invalid",
			wantFields:  []string{"follow_up_at"},
		},
		{
			name:        "malformed JSON gets a stable category",
			body:        `{broken`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "invalid_json",
		},
		{
			name:        "unsupported content type is rejected",
			body:        `{}`,
			contentType: "text/plain",
			wantStatus:  http.StatusUnsupportedMediaType,
			wantCode:    "unsupported_media_type",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			_, ok := decodeIncidentReview(response, request)
			if ok || response.Code != test.wantStatus {
				t.Fatalf("decode result = ok %t status %d, want %d", ok, response.Code, test.wantStatus)
			}
			var payload struct {
				Error struct {
					Code    string            `json:"code"`
					Details map[string]string `json:"details"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if payload.Error.Code != test.wantCode {
				t.Fatalf("error code = %q; want %q (%s)", payload.Error.Code, test.wantCode, response.Body.String())
			}
			for _, field := range test.wantFields {
				if payload.Error.Details[field] == "" {
					t.Errorf("error response omitted %q detail: %s", field, response.Body.String())
				}
			}
			if strings.Contains(response.Body.String(), "private submitted value") || strings.Contains(response.Body.String(), "tomorrow") {
				t.Fatalf("error response echoed request content: %s", response.Body.String())
			}
		})
	}
}
