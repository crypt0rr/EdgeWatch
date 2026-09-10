package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestRequiredPermissionAndMutationMatrix(t *testing.T) {
	cases := []struct {
		path, method, want string
	}{
		{"/status", http.MethodGet, "overview.read"},
		{"/stream", http.MethodGet, "stream.read"},
		{"/notifications/destinations", http.MethodGet, "notification_options.read"},
		{"/notifications/destinations", http.MethodPost, "notifications.manage"},
		{"/notifications/destinations/id", http.MethodGet, "notification_options.read"},
		{"/notifications/destinations/id", http.MethodPut, "notifications.manage"},
		{"/users", http.MethodGet, "users.manage"},
		{"/public-dashboard", http.MethodGet, "public_dashboard.manage"},
		{"/scans", http.MethodGet, "scans.read"},
		{"/scans", http.MethodPost, "jobs.run"},
		{"/scans/active", http.MethodGet, "scans.read"},
		{"/hosts", http.MethodGet, "hosts.read"},
		{"/incidents", http.MethodGet, "incidents.read"},
		{"/incidents", http.MethodPost, "incidents.manage"},
		{"/events", http.MethodGet, "scans.read"},
		{"/jobs", http.MethodGet, "jobs.read"},
		{"/jobs", http.MethodPost, "jobs.write"},
		{"/jobs/id/baseline", http.MethodGet, "baselines.read"},
		{"/jobs/id/scans", http.MethodGet, "scans.read"},
		{"/jobs/id/hosts", http.MethodGet, "hosts.read"},
		{"/jobs/id/incidents", http.MethodGet, "incidents.read"},
		{"/jobs/id/baseline/reset", http.MethodPost, "baselines.manage"},
		{"/jobs/id/incidents/accept", http.MethodPost, "incidents.manage"},
		{"/jobs/id/run", http.MethodPost, "jobs.run"},
		{"/jobs/id", http.MethodPut, "jobs.write"},
		{"/unknown", http.MethodGet, ""},
	}
	for _, test := range cases {
		if got := requiredPermission(test.path, test.method); got != test.want {
			t.Errorf("requiredPermission(%q, %q) = %q, want %q", test.path, test.method, got, test.want)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if isMutation(method) {
			t.Errorf("%s classified as mutation", method)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if !isMutation(method) {
			t.Errorf("%s was not classified as mutation", method)
		}
	}
	permanent := httptest.NewRequest(http.MethodDelete, "/api/v1/jobs/id?permanent=true", nil)
	if got := requestPermission("/jobs/id", permanent); got != auth.PermissionJobsDelete {
		t.Fatalf("permanent job delete permission = %q, want %q", got, auth.PermissionJobsDelete)
	}
	archive := httptest.NewRequest(http.MethodDelete, "/api/v1/jobs/id", nil)
	if got := requestPermission("/jobs/id", archive); got != auth.PermissionJobsWrite {
		t.Fatalf("job archive permission = %q, want %q", got, auth.PermissionJobsWrite)
	}
	for _, test := range []struct {
		role       string
		permission string
		allowed    bool
	}{
		{store.RoleAdministrator, auth.PermissionJobsDelete, true},
		{store.RoleOperator, auth.PermissionJobsDelete, false},
		{store.RoleViewer, auth.PermissionJobsDelete, false},
		{store.RoleAdministrator, auth.PermissionScannerProfilesManage, true},
		{store.RoleOperator, auth.PermissionScannerProfilesManage, false},
		{store.RoleViewer, auth.PermissionScannerProfilesManage, false},
	} {
		if got := auth.HasPermission(store.Session{Role: test.role}, test.permission); got != test.allowed {
			t.Errorf("%s permission %s = %t, want %t", test.role, test.permission, got, test.allowed)
		}
	}
}

func TestServerHelpersValidateJSONPaginationAndHeaders(t *testing.T) {
	items := []int{1, 2, 3}
	if page, metadata := pageSlice(items, 10, 20); len(page) != 0 || metadata["total"] != 3 {
		t.Fatalf("out-of-range page = %#v %#v", page, metadata)
	}
	if page, metadata := pageSlice(items, -1, 2000); len(page) != 3 || metadata["limit"] != 50 || metadata["offset"] != 0 {
		t.Fatalf("defaulted page = %#v %#v", page, metadata)
	}
	if page, _ := pageSlice(items, 1, 1); len(page) != 1 || page[0] != 2 {
		t.Fatalf("sliced page = %#v", page)
	}

	decode := func(body string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		var value map[string]any
		if decodeJSON(rec, req, &value) {
			return rec.Code, value
		}
		return rec.Code, nil
	}
	if code, value := decode(`{"value":1}`); code != 200 || value["value"] != float64(1) {
		t.Fatalf("valid JSON decode = %d %#v", code, value)
	}
	if code, _ := decode(`{"unknown":true} extra`); code != http.StatusBadRequest {
		t.Fatalf("invalid/trailing JSON status = %d", code)
	}
	if code, _ := decode(strings.Repeat("x", 1<<20+10)); code != http.StatusBadRequest {
		t.Fatalf("oversized JSON status = %d", code)
	}
	for _, contentType := range []string{"", "text/plain", "application/json-patch+json", "application/json; charset=invalid\""} {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"value":1}`))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		rec := httptest.NewRecorder()
		var value map[string]any
		if decodeJSON(rec, req, &value) {
			t.Fatalf("content type %q was accepted", contentType)
		}
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("content type %q status = %d, want %d", contentType, rec.Code, http.StatusUnsupportedMediaType)
		}
	}
	for _, contentType := range []string{"application/json", "Application/JSON; charset=utf-8"} {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"value":1}`))
		req.Header.Set("Content-Type", contentType)
		rec := httptest.NewRecorder()
		var value map[string]any
		if !decodeJSON(rec, req, &value) || rec.Code != http.StatusOK {
			t.Fatalf("content type %q was rejected with status %d", contentType, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	writeValidationError(rec, errors.New("target is invalid"))
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || rec.Code != http.StatusBadRequest {
		t.Fatalf("validation response = %d %s (%v)", rec.Code, rec.Body.String(), err)
	}
	rec = httptest.NewRecorder()
	writeValidationError(rec, errors.New("something else failed"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("generic validation status = %d", rec.Code)
	}

	wrapped := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	headerRecorder := httptest.NewRecorder()
	wrapped.ServeHTTP(headerRecorder, httptest.NewRequest(http.MethodGet, "/", nil))
	for name, want := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
		if headerRecorder.Header().Get(name) != want {
			t.Errorf("security header %s = %q, want %q", name, headerRecorder.Header().Get(name), want)
		}
	}
	if headerRecorder.Header().Get("Content-Security-Policy") == "" {
		t.Error("content security policy header is missing")
	}

	if value, err := validateDisplayName("  Operator  "); err != nil || value != "Operator" {
		t.Fatalf("valid display name = %q, %v", value, err)
	}
	for _, value := range []string{"", strings.Repeat("x", maxDisplayNameRunes+1), "bad\nname", string([]byte{0xff})} {
		if _, err := validateDisplayName(value); err == nil {
			t.Errorf("invalid display name %q was accepted", value)
		}
	}
}

func TestServerScopeAndDurationHelpers(t *testing.T) {
	old := config.Job{
		Targets: []string{"edge.example"}, MaxExpandedHosts: 4, AssumeAlive: boolPtr(true),
		TCP: &config.Protocol{Ports: "22", Mode: "syn", ServiceDetection: true},
		UDP: &config.Protocol{Ports: "53", ServiceDetection: false},
	}
	next := config.Job{
		Targets: []string{"new.example"}, MaxExpandedHosts: 8, AssumeAlive: boolPtr(false),
		TCP: &config.Protocol{Ports: "443", Mode: "connect", ServiceDetection: false},
	}
	changes := securityScopeChanges(old, next)
	if len(changes) != 7 {
		t.Fatalf("security scope changes = %#v", changes)
	}
	if len(securityScopeChanges(config.Job{TCP: &config.Protocol{Ports: "1"}}, config.Job{})) != 1 {
		t.Fatalf("protocol enable/disable changes = %#v", securityScopeChanges(config.Job{TCP: &config.Protocol{Ports: "1"}}, config.Job{}))
	}
	if !sameStrings([]string{"b", "a"}, []string{"a", "b"}) || sameStrings([]string{"a"}, []string{"a", "b"}) {
		t.Fatal("sameStrings mismatch")
	}
	if protocolSummary(nil) != "disabled" || protocolSummary(&config.Protocol{Ports: "1-3"}) != "1-3" {
		t.Fatal("protocolSummary mismatch")
	}
	if duration, err := parseDuration("1.5d"); err != nil || duration != 36*time.Hour {
		t.Fatalf("day duration = %v, %v", duration, err)
	}
	if duration, err := parseDuration("2h"); err != nil || duration != 2*time.Hour {
		t.Fatalf("standard duration = %v, %v", duration, err)
	}
	if _, err := parseDuration("not-a-duration"); err == nil {
		t.Fatal("invalid duration accepted")
	}
	if !broadScan(config.Job{TCP: &config.Protocol{Ports: "1-65535"}, Targets: []string{"192.0.2.1"}}) {
		t.Fatal("full-range TCP job was not recognized as broad")
	}
	if broadScan(config.Job{Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "22"}}) {
		t.Fatal("small job was recognized as broad")
	}
	cycle := cycleJSON(store.ScanCycleRecord{ID: "cycle", JobID: "job", Status: "paused", TotalUnits: 2, CompletedUnits: 1})
	if cycle["id"] != "cycle" || cycle["completed_units"] != 1 {
		t.Fatalf("cycle JSON = %#v", cycle)
	}
}

func boolPtr(value bool) *bool { return &value }
