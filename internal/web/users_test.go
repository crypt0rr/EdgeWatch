package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func newUsersTestServer(t *testing.T) (*Server, *store.Store, store.Session) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	hash, err := auth.PasswordHash("administrator password")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveAdmin(ctx, store.Admin{Username: "admin", DisplayName: "Administrator", PasswordHash: hash, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	a, err := app.New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(a, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return server, db, store.Session{UserID: store.LegacyAdminUserID, Username: "admin", Role: store.RoleAdministrator}
}

func TestUsersRouteLifecycleAndSecretFreeResponses(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	request := func(method, rest, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/users"+rest, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:9000"
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		server.usersRoute(rec, req, admin, strings.TrimPrefix(rest, "/"))
		return rec
	}

	created := request(http.MethodPost, "", `{"username":"operator","display_name":"  Ops  ","role":"operator"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status %d: %s", created.Code, created.Body.String())
	}
	var createResponse struct {
		User            store.UserSummary `json:"user"`
		ActivationToken string            `json:"activation_token"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createResponse); err != nil {
		t.Fatal(err)
	}
	if createResponse.User.ID == "" || createResponse.User.DisplayName != "Ops" || createResponse.User.Role != store.RoleOperator || createResponse.User.Enabled || !createResponse.User.Pending || createResponse.ActivationToken == "" {
		t.Fatalf("created user = %#v", createResponse)
	}
	if strings.Contains(created.Body.String(), "password_hash") || strings.Contains(created.Body.String(), "token_hash") {
		t.Fatalf("secret material leaked from create response: %s", created.Body.String())
	}
	operatorID := createResponse.User.ID

	listed := request(http.MethodGet, "", "")
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"username":"operator"`) {
		t.Fatalf("list response = %d: %s", listed.Code, listed.Body.String())
	}
	got := request(http.MethodGet, "/"+operatorID, "")
	if got.Code != http.StatusOK || strings.Contains(got.Body.String(), "password") {
		t.Fatalf("get response = %d: %s", got.Code, got.Body.String())
	}
	missing := request(http.MethodGet, "/does-not-exist", "")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing user status = %d", missing.Code)
	}

	activatedReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/activate", strings.NewReader(`{"token":"`+createResponse.ActivationToken+`","password":"operator account password"}`))
	activatedReq.Header.Set("Content-Type", "application/json")
	activatedReq.RemoteAddr = "127.0.0.1:9001"
	activated := httptest.NewRecorder()
	server.activateUser(activated, activatedReq)
	if activated.Code != http.StatusOK {
		t.Fatalf("activation status = %d: %s", activated.Code, activated.Body.String())
	}
	operator, err := db.GetUser(ctx, operatorID)
	if err != nil {
		t.Fatal(err)
	}
	if !operator.Enabled || operator.PasswordHash == "!pending" {
		t.Fatalf("activated user = %#v", operator)
	}

	updated := request(http.MethodPatch, "/"+operatorID, `{"display_name":"Operations","role":"viewer"}`)
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"role":"viewer"`) {
		t.Fatalf("update response = %d: %s", updated.Code, updated.Body.String())
	}
	reset := request(http.MethodPost, "/"+operatorID+"/password-reset", "{}")
	if reset.Code != http.StatusOK {
		t.Fatalf("password reset issue status = %d: %s", reset.Code, reset.Body.String())
	}
	var resetResponse struct {
		Token string `json:"activation_token"`
	}
	if err := json.Unmarshal(reset.Body.Bytes(), &resetResponse); err != nil || resetResponse.Token == "" {
		t.Fatalf("password reset response = %s (%v)", reset.Body.String(), err)
	}
	resetReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/activate", strings.NewReader(`{"token":"`+resetResponse.Token+`","password":"new operator password"}`))
	resetReq.Header.Set("Content-Type", "application/json")
	resetReq.RemoteAddr = "127.0.0.1:9002"
	resetRecorder := httptest.NewRecorder()
	server.activateUser(resetRecorder, resetReq)
	if resetRecorder.Code != http.StatusOK {
		t.Fatalf("password reset status = %d: %s", resetRecorder.Code, resetRecorder.Body.String())
	}
}

func TestUsersRouteValidationAndSessionRevocation(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	call := func(method, rest, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/users"+rest, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.usersRoute(rec, req, admin, strings.TrimPrefix(rest, "/"))
		return rec
	}
	if rec := call(http.MethodPost, "", `{"username":"bad","role":"not-a-role"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid role status = %d", rec.Code)
	}
	if rec := call(http.MethodPost, "", `{"username":"bad","unknown":true}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d", rec.Code)
	}
	first := call(http.MethodPost, "", `{"username":"duplicate"}`)
	if first.Code != http.StatusCreated {
		t.Fatalf("first create status = %d: %s", first.Code, first.Body.String())
	}
	if rec := call(http.MethodPost, "", `{"username":"duplicate"}`); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d: %s", rec.Code, rec.Body.String())
	}
	var firstResponse struct {
		User store.UserSummary `json:"user"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstResponse); err != nil {
		t.Fatal(err)
	}
	if rec := call(http.MethodPatch, "/"+firstResponse.User.ID, `{"enabled":true}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "pending") {
		t.Fatalf("pending enable response = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPatch, "/"+store.LegacyAdminUserID, `{"role":"viewer"}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "self") {
		t.Fatalf("self demotion response = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodGet, "/unknown/sessions", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown subresource status = %d", rec.Code)
	}

	hash, err := auth.PasswordHash("operator account password")
	if err != nil {
		t.Fatal(err)
	}
	operator, err := db.CreateUser(ctx, store.User{Username: "session-user", DisplayName: "Session user", Role: store.RoleOperator, PasswordHash: hash, Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSessionForUserWithAudit(ctx, operator.ID, "session-digest", "csrf", time.Now().UTC(), time.Now().UTC().Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	revoked := call(http.MethodDelete, "/"+operator.ID+"/sessions", "")
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("session revoke status = %d: %s", revoked.Code, revoked.Body.String())
	}
	if _, err := db.GetSession(ctx, "session-digest"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session remained after revoke: %v", err)
	}
}

func TestUsersAPIEnforcesAuthenticationCSRFAndRolePermissions(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	now := time.Now().UTC()
	if err := db.CreateSessionForUserWithAudit(ctx, admin.UserID, digest("admin-api-session"), "admin-csrf", now, now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	request := func(raw, csrf, method, path, body string) *http.Response {
		req, err := http.NewRequest(method, httpServer.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: raw})
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		response, err := (&http.Client{}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	unauthenticated, err := (&http.Client{}).Get(httpServer.URL + "/api/v1/users")
	if err != nil {
		t.Fatal(err)
	}
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		unauthenticated.Body.Close()
		t.Fatalf("unauthenticated users status = %d", unauthenticated.StatusCode)
	}
	unauthenticated.Body.Close()
	read := request("admin-api-session", "", http.MethodGet, "/api/v1/users", "")
	if read.StatusCode != http.StatusOK {
		read.Body.Close()
		t.Fatalf("authenticated users read status = %d", read.StatusCode)
	}
	read.Body.Close()
	csrfRejected := request("admin-api-session", "", http.MethodPost, "/api/v1/users", `{"username":"csrf-user"}`)
	if csrfRejected.StatusCode != http.StatusForbidden {
		csrfRejected.Body.Close()
		t.Fatalf("missing CSRF users status = %d", csrfRejected.StatusCode)
	}
	csrfRejected.Body.Close()
	created := request("admin-api-session", "admin-csrf", http.MethodPost, "/api/v1/users", `{"username":"api-user"}`)
	if created.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(created.Body)
		created.Body.Close()
		t.Fatalf("CSRF-protected users create status = %d: %s", created.StatusCode, body)
	}
	created.Body.Close()
	operatorHash, err := auth.PasswordHash("operator account password")
	if err != nil {
		t.Fatal(err)
	}
	operator, err := db.CreateUser(ctx, store.User{Username: "api-operator", DisplayName: "API operator", Role: store.RoleOperator, PasswordHash: operatorHash, Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSessionForUserWithAudit(ctx, operator.ID, digest("operator-api-session"), "operator-csrf", now, now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	operatorRead := request("operator-api-session", "operator-csrf", http.MethodGet, "/api/v1/users", "")
	if operatorRead.StatusCode != http.StatusForbidden {
		operatorRead.Body.Close()
		t.Fatalf("operator users status = %d", operatorRead.StatusCode)
	}
	operatorRead.Body.Close()
}
