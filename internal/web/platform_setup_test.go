package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// postPlatformSetup sends the platform setup without a session.
func postPlatformSetup(t *testing.T, server *Server, body, origin string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, consoleAPIBase+"/setup/platform", strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:9000"
	request.Header.Set("Content-Type", "application/json")
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	recorder := httptest.NewRecorder()
	server.api(recorder, request)
	return recorder
}

// readSetupStatus returns the anonymous setup status as a map, so a test
// can tell an absent key from false.
func readSetupStatus(t *testing.T, server *Server) map[string]any {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, consoleAPIBase+"/setup/status", nil)
	request.RemoteAddr = "127.0.0.1:9000"
	recorder := httptest.NewRecorder()
	server.api(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("/setup/status = %d %s", recorder.Code, recorder.Body.String())
	}
	var status map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	return status
}

// The console redeems the platform setup token that the host printed: the
// setup status offers it while the token is valid, a
// wrong token gets one generic answer, the public username and password
// rules are explained, and the redeemed token creates a platform
// administrator that can sign in, once. Each failed attempt is recorded in
// platform scope, outside every unit's audit.
func TestPlatformSetupRouteRedeemsTheHostToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, _ := newUsersTestServer(t)
	if got, ok := readSetupStatus(t, server)["platform_setup_available"]; !ok || got != false {
		t.Fatalf("platform_setup_available without a token = %v (present %t), want false", got, ok)
	}
	token, err := server.Auth.IssuePlatformSetupToken(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := readSetupStatus(t, server)["platform_setup_available"]; got != true {
		t.Fatalf("platform_setup_available with a valid token = %v, want true", got)
	}

	const password = "platform administrator password"
	body := func(token, username, password string) string {
		value, _ := json.Marshal(map[string]string{"token": token, "username": username, "password": password})
		return string(value)
	}
	for _, refused := range []struct {
		name, body, code, message, field string
		status                           int
	}{
		{"a wrong token", body("not-the-token", "root", password), "setup_failed", "platform administrator setup could not be completed", "", http.StatusBadRequest},
		{"no token", body("", "root", password), "setup_failed", "platform administrator setup could not be completed", "", http.StatusBadRequest},
		{"an invalid username", body(token, "root/admin", password), "validation_failed", `username must not contain control characters, "/", "\", or ":"`, "username", http.StatusBadRequest},
		{"a short password", body(token, "root", "short"), "setup_failed", "password must be at least 12 characters", "password", http.StatusBadRequest},
		{"a unit's username", body(token, "ADMIN", password), "conflict", store.ErrUsernameUnavailable.Error(), "username", http.StatusConflict},
		{"an unknown field", `{"token":"x","username":"root","password":"long enough password","role":"administrator"}`, "invalid_json", "request body is invalid", "", http.StatusBadRequest},
	} {
		response := postPlatformSetup(t, server, refused.body, "")
		var envelope struct {
			Error struct {
				Code    string            `json:"code"`
				Message string            `json:"message"`
				Details map[string]string `json:"details"`
			} `json:"error"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("%s: %v", refused.name, err)
		}
		if response.Code != refused.status || envelope.Error.Code != refused.code || !strings.HasPrefix(envelope.Error.Message, refused.message) {
			t.Errorf("%s = %d %s, want %d %s %q", refused.name, response.Code, response.Body.String(), refused.status, refused.code, refused.message)
		}
		if refused.field != "" && envelope.Error.Details[refused.field] == "" {
			t.Errorf("%s names no %s field: %s", refused.name, refused.field, response.Body.String())
		}
	}
	if response := postPlatformSetup(t, server, body(token, "root", password), "https://attacker.example"); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"origin"`) {
		t.Fatalf("cross-origin platform setup = %d %s", response.Code, response.Body.String())
	}
	var platformFailures, unitFailures int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE action='auth.platform_setup_failed' AND tenant_id IS NULL`).Scan(&platformFailures); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE action='auth.platform_setup_failed' AND tenant_id IS NOT NULL`).Scan(&unitFailures); err != nil {
		t.Fatal(err)
	}
	// The wrong and missing tokens, the short password and the taken
	// username reach the check; the invalid username, the unknown field and
	// the foreign origin are refused before it.
	if platformFailures != 4 || unitFailures != 0 {
		t.Fatalf("failed platform setups recorded %d in platform scope and %d in a unit, want 4 and 0", platformFailures, unitFailures)
	}

	response := postPlatformSetup(t, server, body(token, " Root ", password), "")
	if response.Code != http.StatusCreated || strings.TrimSpace(response.Body.String()) != `{"configured":true,"username":"root"}` {
		t.Fatalf("platform setup = %d %s", response.Code, response.Body.String())
	}
	account := signIn(t, server, store.RolePlatformAdmin, "root", password, "")
	if account.session.Role != store.RolePlatformAdmin || account.session.TenantID != "" {
		t.Fatalf("platform administrator session = %+v", account.session)
	}
	if got := readSetupStatus(t, server)["platform_setup_available"]; got != false {
		t.Fatalf("platform_setup_available after the setup = %v, want false", got)
	}
	if response := postPlatformSetup(t, server, body(token, "second-root", password), ""); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "platform administrator setup could not be completed") {
		t.Fatalf("second use of the token = %d %s", response.Code, response.Body.String())
	}
}

// The live-update counters describe the whole deployment, so a unit's
// status leaves them out once several units exist. With a single unit they
// are reported as before.
func TestAdminStatusLeavesOutLiveUpdateCountersWithSeveralUnits(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	liveUpdates := func(actor string) (any, bool) {
		t.Helper()
		response := callAPI(t, f.server, f.sessions[actor], http.MethodGet, "/status", "")
		if response.Code != http.StatusOK {
			t.Fatalf("/status as %s = %d %s", actor, response.Code, response.Body.String())
		}
		var status map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		value, ok := status["live_updates"]
		return value, ok
	}
	for _, actor := range []string{actorAdminA, actorOperatorA, actorAdminB} {
		if value, ok := liveUpdates(actor); ok {
			t.Errorf("live_updates as %s with two units = %v", actor, value)
		}
	}

	server, _, _ := newUsersTestServer(t)
	admin := signIn(t, server, store.RoleAdministrator, "admin", "administrator password", "")
	response := callAPI(t, server, admin, http.MethodGet, "/status", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"live_updates":{"dropped_events":0,"history_size":0}`) {
		t.Fatalf("/status with a single unit = %d %s", response.Code, response.Body.String())
	}
}
