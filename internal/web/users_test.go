package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func newUsersTestServer(t *testing.T) (*Server, *store.Store, store.Session) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(storetest.FreshPath(t))
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
	t.Parallel()
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	request := func(method, rest, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/users"+rest, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:9000"
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		server.usersRoute(rec, req, admin, defaultTenantStore(server), strings.TrimPrefix(rest, "/"))
		return rec
	}

	created := request(http.MethodPost, "", `{"username":"operator","display_name":"  Ops  ","role":"operator","password":"administrator password"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status %d: %s", created.Code, created.Body.String())
	}
	var createResponse struct {
		User            store.UserSummary `json:"user"`
		ActivationToken string            `json:"activation_token"`
		ActivationPath  string            `json:"activation_path"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createResponse); err != nil {
		t.Fatal(err)
	}
	if createResponse.User.ID == "" || createResponse.User.DisplayName != "Ops" || createResponse.User.Role != store.RoleOperator || createResponse.User.Enabled || !createResponse.User.Pending || createResponse.ActivationToken == "" {
		t.Fatalf("created user = %#v", createResponse)
	}
	if !strings.HasPrefix(createResponse.ActivationPath, "/activate#token=") || !strings.Contains(createResponse.ActivationPath, createResponse.ActivationToken) || strings.Contains(createResponse.ActivationPath, "?token=") {
		t.Fatalf("new invite activation path = %q", createResponse.ActivationPath)
	}
	if strings.Contains(created.Body.String(), "password_hash") || strings.Contains(created.Body.String(), "token_hash") {
		t.Fatalf("secret material leaked from create response: %s", created.Body.String())
	}
	operatorID := createResponse.User.ID
	assertLatestLinkAudit := func(wantAction, wantDetail string) {
		t.Helper()
		var action, detail string
		if err := db.DB.QueryRowContext(ctx, `SELECT action,detail FROM security_audit WHERE tenant_id=? ORDER BY id DESC LIMIT 1`, store.DefaultTenantID).Scan(&action, &detail); err != nil {
			t.Fatal(err)
		}
		if action != wantAction || detail != wantDetail {
			t.Fatalf("latest link audit = %q / %q, want %q / %q", action, detail, wantAction, wantDetail)
		}
	}

	// A still-pending account receives an activation link, regardless of
	// which compatibility route is used to renew it.
	pendingRenewal := request(http.MethodPost, "/"+operatorID+"/activation", `{"password":"administrator password"}`)
	if pendingRenewal.Code != http.StatusOK {
		t.Fatalf("pending activation renewal = %d: %s", pendingRenewal.Code, pendingRenewal.Body.String())
	}
	var pendingLink struct {
		Token string `json:"activation_token"`
	}
	if err := json.Unmarshal(pendingRenewal.Body.Bytes(), &pendingLink); err != nil || pendingLink.Token == "" {
		t.Fatalf("pending activation renewal response = %s (%v)", pendingRenewal.Body.String(), err)
	}
	assertLatestLinkAudit("user.activation_issued", "activation issued for operator")

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

	activatedReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/activate", strings.NewReader(`{"token":"`+pendingLink.Token+`","password":"operator account password"}`))
	activatedReq.Header.Set("Content-Type", "application/json")
	activatedReq.RemoteAddr = "127.0.0.1:9001"
	activated := httptest.NewRecorder()
	server.activateUser(activated, activatedReq)
	if activated.Code != http.StatusOK {
		t.Fatalf("activation status = %d: %s", activated.Code, activated.Body.String())
	}
	operator, err := defaultTenant(db).GetUser(ctx, operatorID)
	if err != nil {
		t.Fatal(err)
	}
	if !operator.Enabled || operator.PasswordHash == "!pending" {
		t.Fatalf("activated user = %#v", operator)
	}

	updated := request(http.MethodPatch, "/"+operatorID, `{"display_name":"Operations","role":"viewer","password":"administrator password"}`)
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"role":"viewer"`) {
		t.Fatalf("update response = %d: %s", updated.Code, updated.Body.String())
	}
	stale := request(http.MethodPatch, "/"+operatorID, `{"display_name":"Stale update","revision":1,"password":"administrator password"}`)
	if stale.Code != http.StatusConflict || !strings.Contains(stale.Body.String(), "modified") {
		t.Fatalf("stale update response = %d: %s", stale.Code, stale.Body.String())
	}
	reset := request(http.MethodPost, "/"+operatorID+"/password-reset", `{"password":"administrator password"}`)
	if reset.Code != http.StatusOK {
		t.Fatalf("password reset issue status = %d: %s", reset.Code, reset.Body.String())
	}
	assertLatestLinkAudit("user.password_reset_issued", "password reset issued for operator")
	var resetResponse struct {
		Token          string `json:"activation_token"`
		ActivationPath string `json:"activation_path"`
	}
	if err := json.Unmarshal(reset.Body.Bytes(), &resetResponse); err != nil || resetResponse.Token == "" {
		t.Fatalf("password reset response = %s (%v)", reset.Body.String(), err)
	}
	if !strings.HasPrefix(resetResponse.ActivationPath, "/activate#token=") || !strings.Contains(resetResponse.ActivationPath, resetResponse.Token) || strings.Contains(resetResponse.ActivationPath, "?token=") {
		t.Fatalf("password reset activation path = %q", resetResponse.ActivationPath)
	}
	resetReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/activate", strings.NewReader(`{"token":"`+resetResponse.Token+`","password":"new operator password"}`))
	resetReq.Header.Set("Content-Type", "application/json")
	resetReq.RemoteAddr = "127.0.0.1:9002"
	resetRecorder := httptest.NewRecorder()
	server.activateUser(resetRecorder, resetReq)
	if resetRecorder.Code != http.StatusOK {
		t.Fatalf("password reset status = %d: %s", resetRecorder.Code, resetRecorder.Body.String())
	}
	renewed := request(http.MethodPost, "/"+operatorID+"/activation", `{"password":"administrator password"}`)
	if renewed.Code != http.StatusOK {
		t.Fatalf("activation renewal status = %d: %s", renewed.Code, renewed.Body.String())
	}
	assertLatestLinkAudit("user.password_reset_issued", "password reset issued for operator")
	var renewalResponse struct {
		Token          string `json:"activation_token"`
		ActivationPath string `json:"activation_path"`
	}
	if err := json.Unmarshal(renewed.Body.Bytes(), &renewalResponse); err != nil || renewalResponse.Token == "" {
		t.Fatalf("activation renewal response = %s (%v)", renewed.Body.String(), err)
	}
	if !strings.HasPrefix(renewalResponse.ActivationPath, "/activate#token=") || !strings.Contains(renewalResponse.ActivationPath, renewalResponse.Token) || strings.Contains(renewalResponse.ActivationPath, "?token=") {
		t.Fatalf("activation renewal path = %q", renewalResponse.ActivationPath)
	}
}

func TestUsersRouteValidationAndSessionRevocation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	call := func(method, rest, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/users"+rest, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.usersRoute(rec, req, admin, defaultTenantStore(server), strings.TrimPrefix(rest, "/"))
		return rec
	}
	if rec := call(http.MethodPost, "", `{"username":"bad","role":"not-a-role","password":"administrator password"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid role status = %d", rec.Code)
	}
	if rec := call(http.MethodPost, "", `{"username":"bad","unknown":true}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d", rec.Code)
	}
	first := call(http.MethodPost, "", `{"username":"duplicate","password":"administrator password"}`)
	if first.Code != http.StatusCreated {
		t.Fatalf("first create status = %d: %s", first.Code, first.Body.String())
	}
	if rec := call(http.MethodPost, "", `{"username":"duplicate","password":"administrator password"}`); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d: %s", rec.Code, rec.Body.String())
	}
	var firstResponse struct {
		User store.UserSummary `json:"user"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstResponse); err != nil {
		t.Fatal(err)
	}
	if rec := call(http.MethodPatch, "/"+firstResponse.User.ID, `{"enabled":true,"password":"administrator password"}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "pending") {
		t.Fatalf("pending enable response = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPatch, "/"+store.LegacyAdminUserID, `{"role":"viewer","password":"administrator password"}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "self") {
		t.Fatalf("self demotion response = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodGet, "/unknown/sessions", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown subresource status = %d", rec.Code)
	}

	hash, err := auth.PasswordHash("operator account password")
	if err != nil {
		t.Fatal(err)
	}
	operator, err := storetest.CreateUser(ctx, db, store.DefaultTenantScope(), store.User{Username: "session-user", DisplayName: "Session user", Role: store.RoleOperator, PasswordHash: hash, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := storetest.CreateSession(ctx, db, operator.ID, "session-digest", "csrf", time.Now().UTC(), time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	revoked := call(http.MethodDelete, "/"+operator.ID+"/sessions", `{"password":"administrator password"}`)
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("session revoke status = %d: %s", revoked.Code, revoked.Body.String())
	}
	if _, err := db.GetSession(ctx, "session-digest"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session remained after revoke: %v", err)
	}
}

func TestUsersAPIEnforcesAuthenticationCSRFAndRolePermissions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	now := time.Now().UTC()
	if err := storetest.CreateSession(ctx, db, admin.UserID, digest("admin-api-session"), "admin-csrf", now, now.Add(time.Hour)); err != nil {
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
	created := request("admin-api-session", "admin-csrf", http.MethodPost, "/api/v1/users", `{"username":"api-user","password":"administrator password"}`)
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
	operator, err := storetest.CreateUser(ctx, db, store.DefaultTenantScope(), store.User{Username: "api-operator", DisplayName: "API operator", Role: store.RoleOperator, PasswordHash: operatorHash, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := storetest.CreateSession(ctx, db, operator.ID, digest("operator-api-session"), "operator-csrf", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	operatorRead := request("operator-api-session", "operator-csrf", http.MethodGet, "/api/v1/users", "")
	if operatorRead.StatusCode != http.StatusForbidden {
		operatorRead.Body.Close()
		t.Fatalf("operator users status = %d", operatorRead.StatusCode)
	}
	operatorRead.Body.Close()
}

// A unit's administrator ends another account's sessions from Users after
// confirming its password: the account is signed out everywhere, the
// administrator stays signed in, and the unit's audit records the
// revocation with the administrator as its actor. The unit's operator and
// viewer and the platform administrator are refused, another unit's
// administrator gets the answer of an unknown account, and a wrong password
// is refused; none of them ends a session or writes a record.
func TestUnitAdministratorRevokesAnotherAccountsSessions(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	operator := f.users[actorOperatorA]
	path := "/users/" + operator.ID + "/sessions"
	sessions := func() int {
		t.Helper()
		var count int
		if err := f.db.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id=?`, operator.ID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	records := func() []string {
		t.Helper()
		rows, err := f.db.DB.Query(`SELECT COALESCE(tenant_id,'<null>')||'|'||actor_user_id||'|'||actor_kind||'|'||detail FROM security_audit WHERE action='user.sessions_revoked' ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var values []string
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				t.Fatal(err)
			}
			values = append(values, value)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return values
	}
	if sessions() != 1 || len(records()) != 0 {
		t.Fatalf("before the revocation: %d sessions, records %v", sessions(), records())
	}
	for _, refused := range []struct {
		actor, path, body string
		status            int
		code              string
	}{
		{actorOperatorA, path, confirmBody(""), http.StatusForbidden, "forbidden"},
		{actorViewerA, path, confirmBody(""), http.StatusForbidden, "forbidden"},
		{actorPlatform, path, confirmBody(""), http.StatusForbidden, "forbidden"},
		{actorAdminB, path, confirmBody(""), http.StatusNotFound, "not_found"},
		{actorAdminA, path, `{"password":"wrong password"}`, http.StatusUnauthorized, "invalid_password"},
		{actorAdminA, path, `{}`, http.StatusBadRequest, "password_required"},
	} {
		expectError(t, f.call(t, refused.actor, http.MethodDelete, refused.path, refused.body), refused.status, refused.code, refused.actor+" revokes unit A's operator's sessions")
	}
	unknown := f.call(t, actorAdminB, http.MethodDelete, "/users/00000000-0000-0000-0000-00000000dead/sessions", confirmBody(""))
	if other := f.call(t, actorAdminB, http.MethodDelete, path, confirmBody("")); other.Code != unknown.Code || other.Body.String() != unknown.Body.String() {
		t.Fatalf("another unit's account = %d %s, an unknown account = %d %s", other.Code, other.Body.String(), unknown.Code, unknown.Body.String())
	}
	if sessions() != 1 || len(records()) != 0 {
		t.Fatalf("after the refused revocations: %d sessions, records %v", sessions(), records())
	}

	if response := f.call(t, actorAdminA, http.MethodDelete, path, confirmBody("")); response.Code != http.StatusNoContent {
		t.Fatalf("the unit administrator's revocation = %d: %s", response.Code, response.Body.String())
	}
	if got := sessions(); got != 0 {
		t.Fatalf("the operator kept %d sessions", got)
	}
	if response := f.call(t, actorAdminA, http.MethodGet, "/auth/session", ""); response.Code != http.StatusOK {
		t.Fatalf("the administrator's own session after the revocation = %d", response.Code)
	}
	admin := f.users[actorAdminA]
	want := []string{store.DefaultTenantID + "|" + admin.ID + "|" + store.AuditActorUnit + "|sessions of " + operator.Username + " revoked by " + admin.Username}
	if got := records(); !slices.Equal(got, want) {
		t.Fatalf("revocation records = %v, want %v", got, want)
	}
}
