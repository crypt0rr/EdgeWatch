package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// scannerProfileBases are the two spellings of the scanner profile routes:
// the console's, and the /scanner/profiles alias that withPathAlias derives
// from it.
var scannerProfileBases = []string{"/scanner-profiles", "/scanner/profiles"}

func scannerProfileRequest(server *Server, session store.Session, method, rest, body string) *httptest.ResponseRecorder {
	return scannerProfileRequestAt(server, session, scannerProfileBases[0], method, rest, body)
}

// scannerProfileRequestAt serves rest, the path after base and a slash, as
// the session, with the handler of the route that serves it.
func scannerProfileRequestAt(server *Server, session store.Session, base, method, rest, body string) *httptest.ResponseRecorder {
	path := base + "/" + rest
	req := httptest.NewRequest(method, consoleAPIBase+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	server.serveRouteAs(rec, req, path, session, defaultTenantStore(server))
	return rec
}

// scannerProfileArchived reads whether the profile is archived through
// request, which serves one spelling of the routes.
func scannerProfileArchived(t *testing.T, request func(store.Session, string, string, string) *httptest.ResponseRecorder, session store.Session, id string) bool {
	t.Helper()
	got := request(session, http.MethodGet, id, "")
	if got.Code != http.StatusOK {
		t.Fatalf("get %s status = %d: %s", id, got.Code, got.Body.String())
	}
	var profile struct {
		Archived bool `json:"archived"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &profile); err != nil {
		t.Fatal(err)
	}
	return profile.Archived
}

// Both spellings of the scanner profile routes serve the same lifecycle and
// apply the same validation rules.
func TestScannerProfilesRouteLifecycleAndValidationBranches(t *testing.T) {
	t.Parallel()
	for _, base := range scannerProfileBases {
		t.Run(strings.TrimPrefix(base, "/"), func(t *testing.T) {
			t.Parallel()
			testScannerProfileRouteLifecycle(t, base)
		})
	}
}

// testScannerProfileRouteLifecycle drives a profile through the routes
// under base, one of scannerProfileBases.
func testScannerProfileRouteLifecycle(t *testing.T, base string) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	request := func(session store.Session, method, rest, body string) *httptest.ResponseRecorder {
		return scannerProfileRequestAt(server, session, base, method, rest, body)
	}

	if got := request(admin, http.MethodGet, "", ""); got.Code != http.StatusOK {
		t.Fatalf("list status = %d: %s", got.Code, got.Body.String())
	}
	if got := request(admin, http.MethodGet, "missing", ""); got.Code != http.StatusNotFound {
		t.Fatalf("missing profile status = %d", got.Code)
	}
	if got := request(admin, http.MethodPost, "", "{}"); got.Code != http.StatusBadRequest {
		t.Fatalf("empty create status = %d", got.Code)
	}
	if got := request(admin, http.MethodPost, "", `{`); got.Code != http.StatusBadRequest {
		t.Fatalf("malformed create status = %d", got.Code)
	}
	contentTypeRequest := httptest.NewRequest(http.MethodPost, consoleAPIBase+base+"/", strings.NewReader(`{"name":"No content type"}`))
	contentTypeResponse := httptest.NewRecorder()
	server.serveRouteAs(contentTypeResponse, contentTypeRequest, base+"/", admin, defaultTenantStore(server))
	if contentTypeResponse.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type status = %d", contentTypeResponse.Code)
	}

	valid := `{"name":"Route profile","description":"safe","engine":"nmap","password":"administrator password"}`
	created := request(admin, http.MethodPost, "", valid)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", created.Code, created.Body.String())
	}
	var createdJSON struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdJSON); err != nil {
		t.Fatal(err)
	}
	if createdJSON.ID == "" || createdJSON.Revision != 1 {
		t.Fatalf("created profile = %#v", createdJSON)
	}

	if got := request(admin, http.MethodGet, createdJSON.ID, ""); got.Code != http.StatusOK {
		t.Fatalf("get status = %d: %s", got.Code, got.Body.String())
	}
	if got := request(admin, http.MethodGet, createdJSON.ID+"/revisions", ""); got.Code != http.StatusOK {
		t.Fatalf("revisions status = %d: %s", got.Code, got.Body.String())
	}
	if got := request(admin, http.MethodGet, createdJSON.ID+"/unknown", ""); got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), `"permission":"route"`) {
		t.Fatalf("unknown child = %d %s, want the gate's 403 route", got.Code, got.Body.String())
	}

	preview := `{"engine":"nmap"}`
	for _, endpoint := range []string{"validate", "preview", createdJSON.ID + "/validate", createdJSON.ID + "/preview"} {
		if got := request(admin, http.MethodPost, endpoint, preview); got.Code != http.StatusOK {
			t.Fatalf("%s status = %d: %s", endpoint, got.Code, got.Body.String())
		}
	}
	if got := request(admin, http.MethodPost, "validate", `{"engine":"invalid"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid validate status = %d", got.Code)
	}
	// Validating a definition applies the rules of a new profile: NSE
	// arguments must be the script's own. Previewing skips them, so that it
	// also renders an existing revision.
	libraryArgument := `{"engine":"nmap","nse_profile":"banner","nse_args":{"newtargets":"1"}}`
	for _, endpoint := range []string{"validate", createdJSON.ID + "/validate"} {
		if got := request(admin, http.MethodPost, endpoint, libraryArgument); got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "nse_args") {
			t.Fatalf("%s with a library NSE argument = %d: %s", endpoint, got.Code, got.Body.String())
		}
	}
	for _, endpoint := range []string{"preview", createdJSON.ID + "/preview"} {
		if got := request(admin, http.MethodPost, endpoint, libraryArgument); got.Code != http.StatusOK {
			t.Fatalf("%s with a library NSE argument = %d: %s", endpoint, got.Code, got.Body.String())
		}
	}

	if got := request(admin, http.MethodPut, createdJSON.ID, `{"name":"missing revision","engine":"nmap","password":"administrator password"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("missing revision status = %d", got.Code)
	}
	if got := request(admin, http.MethodPut, createdJSON.ID, `{"name":"stale","engine":"nmap","password":"administrator password","revision":99}`); got.Code != http.StatusConflict {
		t.Fatalf("stale update status = %d: %s", got.Code, got.Body.String())
	}
	updated := request(admin, http.MethodPut, createdJSON.ID, `{"name":"Route profile v2","engine":"nmap","password":"administrator password","revision":1}`)
	if updated.Code != http.StatusOK {
		t.Fatalf("update status = %d: %s", updated.Code, updated.Body.String())
	}

	if got := request(admin, http.MethodDelete, createdJSON.ID, `{"password":"administrator password"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("missing archive revision status = %d", got.Code)
	}
	if got := request(admin, http.MethodDelete, createdJSON.ID, `{"password":"wrong password","revision":2}`); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid archive password status = %d", got.Code)
	}
	if got := request(admin, http.MethodDelete, createdJSON.ID, `{"password":"administrator password","revision":2}`); got.Code != http.StatusNoContent {
		t.Fatalf("archive status = %d: %s", got.Code, got.Body.String())
	}
	if !scannerProfileArchived(t, request, admin, createdJSON.ID) {
		t.Fatal("the archived profile is not archived")
	}
	if got := request(admin, http.MethodPost, createdJSON.ID+"/restore", `{"password":"administrator password","revision":3}`); got.Code != http.StatusNoContent {
		t.Fatalf("restore status = %d: %s", got.Code, got.Body.String())
	}
	if scannerProfileArchived(t, request, admin, createdJSON.ID) {
		t.Fatal("the restored profile is still archived")
	}
	if got := request(admin, http.MethodPost, "missing/restore", `{"password":"administrator password","revision":1}`); got.Code != http.StatusNotFound {
		t.Fatalf("missing restore status = %d", got.Code)
	}

	// A built-in profile exercises the immutable lifecycle and update guards.
	builtin, err := defaultTenant(db).GetScannerProfile(ctx, store.BuiltinNmapProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if got := request(admin, http.MethodPut, builtin.ID, `{"name":"builtin","engine":"nmap","password":"administrator password","revision":1}`); got.Code != http.StatusBadRequest {
		t.Fatalf("built-in update status = %d", got.Code)
	}
	if got := request(admin, http.MethodDelete, builtin.ID, `{"password":"administrator password","revision":1}`); got.Code != http.StatusBadRequest {
		t.Fatalf("built-in archive status = %d", got.Code)
	}

	// Non-administrators are denied before password confirmation.
	operator := admin
	operator.Role = store.RoleOperator
	if got := request(operator, http.MethodPost, "", valid); got.Code != http.StatusForbidden {
		t.Fatalf("operator create status = %d", got.Code)
	}
	if got := request(operator, http.MethodDelete, createdJSON.ID, `{"password":"administrator password","revision":4}`); got.Code != http.StatusForbidden {
		t.Fatalf("operator archive status = %d", got.Code)
	}

	if err := server.applySelectedScannerProfile(ctx, defaultTenantStore(server), &config.Job{TCP: &config.Protocol{ProfileID: "missing"}}, false, false); err == nil {
		t.Fatal("missing selected profile unexpectedly succeeded")
	}
	if err := server.applySelectedScannerProfile(ctx, defaultTenantStore(server), &config.Job{TCP: &config.Protocol{ProfileID: createdJSON.ID, ProfileRevision: 99}}, false, false); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("historical profile error = %v", err)
	}
}

// Profile names stay unique among the custom profiles and cannot take a
// built-in profile's name, which schema 52 keeps in a namespace of its own.
func TestScannerProfileNameConflictsReturnConflict(t *testing.T) {
	t.Parallel()
	server, _, admin := newUsersTestServer(t)
	created := scannerProfileRequest(server, admin, http.MethodPost, "", `{"name":"Route A","engine":"nmap","password":"administrator password"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", created.Code, created.Body.String())
	}
	var profile struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &profile); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method, rest, body string
	}{
		{"duplicate custom name", http.MethodPost, "", `{"name":"route a","engine":"nmap","password":"administrator password"}`},
		{"built-in name", http.MethodPost, "", `{"name":"NMAP STANDARD","engine":"nmap","password":"administrator password"}`},
		{"rename to a built-in name", http.MethodPut, profile.ID, `{"name":"Naabu full TCP → Nmap","engine":"nmap","password":"administrator password","revision":1}`},
	} {
		got := scannerProfileRequest(server, admin, tc.method, tc.rest, tc.body)
		if got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), "scanner profile name is already in use") {
			t.Fatalf("%s = %d: %s", tc.name, got.Code, got.Body.String())
		}
	}
}
