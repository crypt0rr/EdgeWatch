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

func scannerProfileRequest(server *Server, session store.Session, method, rest, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/v1/scanner-profiles/"+rest, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	server.scannerProfilesRoute(rec, req, session, rest)
	return rec
}

func TestScannerProfilesRouteLifecycleAndValidationBranches(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)

	if got := scannerProfileRequest(server, admin, http.MethodGet, "", ""); got.Code != http.StatusOK {
		t.Fatalf("list status = %d: %s", got.Code, got.Body.String())
	}
	if got := scannerProfileRequest(server, admin, http.MethodGet, "missing", ""); got.Code != http.StatusNotFound {
		t.Fatalf("missing profile status = %d", got.Code)
	}
	if got := scannerProfileRequest(server, admin, http.MethodPost, "", "{}"); got.Code != http.StatusBadRequest {
		t.Fatalf("empty create status = %d", got.Code)
	}
	if got := scannerProfileRequest(server, admin, http.MethodPost, "", `{`); got.Code != http.StatusBadRequest {
		t.Fatalf("malformed create status = %d", got.Code)
	}
	contentTypeRequest := httptest.NewRequest(http.MethodPost, "/api/v1/scanner-profiles/", strings.NewReader(`{"name":"No content type"}`))
	contentTypeResponse := httptest.NewRecorder()
	server.scannerProfilesRoute(contentTypeResponse, contentTypeRequest, admin, "")
	if contentTypeResponse.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type status = %d", contentTypeResponse.Code)
	}

	valid := `{"name":"Route profile","description":"safe","engine":"nmap","password":"administrator password"}`
	created := scannerProfileRequest(server, admin, http.MethodPost, "", valid)
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

	if got := scannerProfileRequest(server, admin, http.MethodGet, createdJSON.ID, ""); got.Code != http.StatusOK {
		t.Fatalf("get status = %d: %s", got.Code, got.Body.String())
	}
	if got := scannerProfileRequest(server, admin, http.MethodGet, createdJSON.ID+"/revisions", ""); got.Code != http.StatusOK {
		t.Fatalf("revisions status = %d: %s", got.Code, got.Body.String())
	}
	if got := scannerProfileRequest(server, admin, http.MethodGet, createdJSON.ID+"/unknown", ""); got.Code != http.StatusNotFound {
		t.Fatalf("unknown child status = %d", got.Code)
	}

	preview := `{"engine":"nmap"}`
	for _, endpoint := range []string{"validate", "preview", createdJSON.ID + "/validate", createdJSON.ID + "/preview"} {
		if got := scannerProfileRequest(server, admin, http.MethodPost, endpoint, preview); got.Code != http.StatusOK {
			t.Fatalf("%s status = %d: %s", endpoint, got.Code, got.Body.String())
		}
	}
	if got := scannerProfileRequest(server, admin, http.MethodPost, "validate", `{"engine":"invalid"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid validate status = %d", got.Code)
	}

	if got := scannerProfileRequest(server, admin, http.MethodPut, createdJSON.ID, `{"name":"missing revision","engine":"nmap","password":"administrator password"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("missing revision status = %d", got.Code)
	}
	if got := scannerProfileRequest(server, admin, http.MethodPut, createdJSON.ID, `{"name":"stale","engine":"nmap","password":"administrator password","revision":99}`); got.Code != http.StatusConflict {
		t.Fatalf("stale update status = %d: %s", got.Code, got.Body.String())
	}
	updated := scannerProfileRequest(server, admin, http.MethodPut, createdJSON.ID, `{"name":"Route profile v2","engine":"nmap","password":"administrator password","revision":1}`)
	if updated.Code != http.StatusOK {
		t.Fatalf("update status = %d: %s", updated.Code, updated.Body.String())
	}

	if got := scannerProfileRequest(server, admin, http.MethodDelete, createdJSON.ID, `{"password":"administrator password"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("missing archive revision status = %d", got.Code)
	}
	if got := scannerProfileRequest(server, admin, http.MethodDelete, createdJSON.ID, `{"password":"wrong password","revision":2}`); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid archive password status = %d", got.Code)
	}
	if got := scannerProfileRequest(server, admin, http.MethodDelete, createdJSON.ID, `{"password":"administrator password","revision":2}`); got.Code != http.StatusNoContent {
		t.Fatalf("archive status = %d: %s", got.Code, got.Body.String())
	}
	if got := scannerProfileRequest(server, admin, http.MethodPost, createdJSON.ID+"/restore", `{"password":"administrator password","revision":3}`); got.Code != http.StatusNoContent {
		t.Fatalf("restore status = %d: %s", got.Code, got.Body.String())
	}
	if got := scannerProfileRequest(server, admin, http.MethodPost, "missing/restore", `{"password":"administrator password","revision":1}`); got.Code != http.StatusNotFound {
		t.Fatalf("missing restore status = %d", got.Code)
	}

	// A built-in profile exercises the immutable lifecycle and update guards.
	builtin, err := db.GetScannerProfile(ctx, store.BuiltinNmapProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if got := scannerProfileRequest(server, admin, http.MethodPut, builtin.ID, `{"name":"builtin","engine":"nmap","password":"administrator password","revision":1}`); got.Code != http.StatusBadRequest {
		t.Fatalf("built-in update status = %d", got.Code)
	}
	if got := scannerProfileRequest(server, admin, http.MethodDelete, builtin.ID, `{"password":"administrator password","revision":1}`); got.Code != http.StatusBadRequest {
		t.Fatalf("built-in archive status = %d", got.Code)
	}

	// Non-administrators are denied before password confirmation.
	operator := admin
	operator.Role = store.RoleOperator
	if got := scannerProfileRequest(server, operator, http.MethodPost, "", valid); got.Code != http.StatusForbidden {
		t.Fatalf("operator create status = %d", got.Code)
	}
	if got := scannerProfileRequest(server, operator, http.MethodDelete, createdJSON.ID, `{"password":"administrator password","revision":4}`); got.Code != http.StatusForbidden {
		t.Fatalf("operator archive status = %d", got.Code)
	}

	if err := server.applySelectedScannerProfile(ctx, &config.Job{TCP: &config.Protocol{ProfileID: "missing"}}, false, false); err == nil {
		t.Fatal("missing selected profile unexpectedly succeeded")
	}
	if err := server.applySelectedScannerProfile(ctx, &config.Job{TCP: &config.Protocol{ProfileID: createdJSON.ID, ProfileRevision: 99}}, false, false); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("historical profile error = %v", err)
	}
}

// Profile names stay unique among the custom profiles and cannot take a
// built-in profile's name, which schema 52 keeps in a namespace of its own.
func TestScannerProfileNameConflictsReturnConflict(t *testing.T) {
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
