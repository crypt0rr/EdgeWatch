package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// createWebPlatformAdmin creates a platform administrator through the
// platform setup token.
func createWebPlatformAdmin(t *testing.T, server *Server, username, password string) store.User {
	t.Helper()
	ctx := context.Background()
	token, err := server.Auth.IssuePlatformSetupToken(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	user, err := server.Auth.CompletePlatformSetup(ctx, token, username, password)
	if err != nil {
		t.Fatal(err)
	}
	return user
}

// signIn signs the account in and returns it as a route matrix session.
func signIn(t *testing.T, server *Server, role, username, password, otp string) routeMatrixSession {
	t.Helper()
	ctx := context.Background()
	login := httptest.NewRequest(http.MethodPost, consoleAPIBase+"/auth/login", nil)
	login.RemoteAddr = "127.0.0.1:9000"
	raw, _, err := server.Auth.LoginAs(ctx, login, username, password, otp, "")
	if err != nil {
		t.Fatalf("sign-in of %s: %v", username, err)
	}
	probe := httptest.NewRequest(http.MethodGet, consoleAPIBase+"/auth/session", nil)
	probe.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: raw})
	session, ok := server.Auth.AuthenticateReadOnly(ctx, probe)
	if !ok {
		t.Fatalf("session of %s did not authenticate", username)
	}
	return routeMatrixSession{role: role, raw: raw, session: session}
}

// callAPI sends a JSON request through the API router as the session, with
// its CSRF token.
func callAPI(t *testing.T, server *Server, account routeMatrixSession, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, consoleAPIBase+path, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:9000"
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: account.raw})
	request.Header.Set("X-CSRF-Token", account.session.CSRFToken)
	recorder := httptest.NewRecorder()
	server.api(recorder, request)
	return recorder
}

// sessionPayload is the part of /auth/session that describes permissions.
type sessionPayload struct {
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	// Enrollment is a pointer so a test can tell an absent key from false.
	Enrollment *bool `json:"totp_enrollment_required"`
}

func readSession(t *testing.T, server *Server, account routeMatrixSession) sessionPayload {
	t.Helper()
	response := callAPI(t, server, account, http.MethodGet, "/auth/session", "")
	if response.Code != http.StatusOK {
		t.Fatalf("/auth/session = %d: %s", response.Code, response.Body.String())
	}
	var payload sessionPayload
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

// assertOnlySelfService checks through the API router that the session is
// refused every route of the inventory except its own account's
// self-service, before any handler runs. Mutations carry a CSRF token, so the
// refusal comes from the permission gate. A platform administrator with a
// full session also reaches the platform console's routes; the platform
// tests cover those.
func assertOnlySelfService(t *testing.T, server *Server, account *routeMatrixSession) {
	t.Helper()
	for _, route := range apiRoutes {
		if route.Access != routeSession {
			continue
		}
		if route.Permission == auth.PermissionAccountSelf {
			if !auth.HasPermission(account.session, route.Permission) {
				t.Errorf("%s: %s is refused its own account's %s", routeInventoryName(route), account.role, route.Permission)
			}
			continue
		}
		want := route.Permission
		switch {
		case isPlatformPermission(route.Permission) && account.role == store.RolePlatformAdmin && !account.session.TOTPEnrollmentRequired:
			if !auth.HasPermission(account.session, route.Permission) {
				t.Errorf("%s: %s is refused its console's %s", routeInventoryName(route), account.role, route.Permission)
			}
			continue
		case auth.HasPermission(account.session, route.Permission):
			t.Errorf("%s: %s holds %s", routeInventoryName(route), account.role, route.Permission)
		}
		response := serveRouteMatrixRequest(t, server.api, route.Method, routeMatrixTarget(route), account, true, "")
		if response.status != http.StatusForbidden || response.code != "forbidden" || response.details["permission"] != want {
			t.Errorf("%s as %s = %d %s, want 403 forbidden for %s", routeInventoryName(route), account.role, response.status, response.body, want)
		}
	}
}

// Every route of a unit's console that reads or changes the unit's data is
// refused to a platform administrator, which holds no unit permission; only
// its own account's self-service routes and its platform console's routes
// are open to it, and its session lists exactly those permissions.
func TestRouteInventoryDeniesPlatformAdministratorsUnitData(t *testing.T) {
	t.Parallel()
	server, accounts := newRouteMatrixSessions(t)
	platform := &accounts[len(accounts)-1]
	if platform.role != store.RolePlatformAdmin || platform.session.TenantID != "" {
		t.Fatalf("matrix account = %s in tenant %q, want a platform administrator", platform.role, platform.session.TenantID)
	}
	assertOnlySelfService(t, server, platform)
	payload := readSession(t, server, *platform)
	if payload.Role != store.RolePlatformAdmin || !reflect.DeepEqual(payload.Permissions, auth.PermissionsForRole(store.RolePlatformAdmin)) || payload.Enrollment != nil {
		t.Fatalf("platform administrator session = %+v", payload)
	}
}

// A platform administrator has no unit, yet manages its own account: it
// changes its display name and password, enrols and removes TOTP, rotates
// its recovery codes, signs out its sessions, and signs out, through the
// same routes as a unit's account. Each change is recorded in platform
// scope.
func TestPlatformAdministratorSelfService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, _ := newUsersTestServer(t)
	const password, replacement = "platform administrator password", "replacement platform password"
	root := createWebPlatformAdmin(t, server, "root", password)
	account := signIn(t, server, store.RolePlatformAdmin, "root", password, "")
	expectStatus := func(response *httptest.ResponseRecorder, want int, step string) {
		t.Helper()
		if response.Code != want {
			t.Fatalf("%s = %d: %s", step, response.Code, response.Body.String())
		}
	}
	expectStatus(callAPI(t, server, account, http.MethodGet, "/jobs", ""), http.StatusForbidden, "GET /jobs")

	expectStatus(callAPI(t, server, account, http.MethodPut, "/auth/display-name", `{"display_name":"Platform Root"}`), http.StatusOK, "display name")
	setup := callAPI(t, server, account, http.MethodPost, "/auth/totp/setup", `{"password":"`+password+`"}`)
	expectStatus(setup, http.StatusOK, "TOTP setup")
	var secret struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(setup.Body.Bytes(), &secret); err != nil || secret.Secret == "" {
		t.Fatalf("TOTP setup payload = %s, %v", setup.Body.String(), err)
	}
	enable := callAPI(t, server, account, http.MethodPost, "/auth/totp/enable", `{"code":"`+coverageTOTPCode(secret.Secret, time.Now().Unix()/30)+`"}`)
	expectStatus(enable, http.StatusOK, "TOTP enable")
	var codes struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(enable.Body.Bytes(), &codes); err != nil || len(codes.RecoveryCodes) < 2 {
		t.Fatalf("TOTP enable payload = %s, %v", enable.Body.String(), err)
	}
	expectStatus(callAPI(t, server, account, http.MethodPost, "/auth/totp/recovery-codes", `{"password":"`+password+`","recovery_code":"`+codes.RecoveryCodes[0]+`"}`), http.StatusOK, "recovery codes")
	current, err := server.Store.GetAccount(ctx, root.ID)
	if err != nil || current.DisplayName != "Platform Root" || !current.TOTPEnabled {
		t.Fatalf("platform administrator after enrolment = %+v, %v", current, err)
	}
	expectStatus(callAPI(t, server, account, http.MethodDelete, "/auth/totp", `{"password":"`+password+`","code":"`+coverageTOTPCode(secret.Secret, time.Now().Unix()/30+1)+`"}`), http.StatusNoContent, "TOTP disable")

	account = signIn(t, server, store.RolePlatformAdmin, "root", password, "")
	expectStatus(callAPI(t, server, account, http.MethodPut, "/auth/password", `{"current_password":"`+password+`","new_password":"`+replacement+`"}`), http.StatusNoContent, "password change")
	account = signIn(t, server, store.RolePlatformAdmin, "root", replacement, "")
	expectStatus(callAPI(t, server, account, http.MethodDelete, "/auth/sessions", ""), http.StatusNoContent, "sign out every session")
	if _, err := server.Store.GetSession(ctx, digest(account.raw)); err == nil {
		t.Fatal("signing out every session kept the current one")
	}
	account = signIn(t, server, store.RolePlatformAdmin, "root", replacement, "")
	expectStatus(callAPI(t, server, account, http.MethodPost, "/auth/logout", ""), http.StatusNoContent, "sign out")

	for _, action := range []string{"user.login", "user.display_name_changed", "user.totp_enabled", "user.totp_recovery_codes_rotated", "user.totp_disabled", "user.password_changed", "user.sessions_revoked", "user.logout"} {
		var tenant, kind string
		if err := db.DB.QueryRowContext(ctx, `SELECT COALESCE(tenant_id,'<null>'),actor_kind FROM security_audit WHERE action=? AND actor_user_id=? ORDER BY id DESC LIMIT 1`, action, root.ID).Scan(&tenant, &kind); err != nil {
			t.Errorf("%s audit record: %v", action, err)
			continue
		}
		if tenant != "<null>" || kind != store.AuditActorPlatform {
			t.Errorf("%s audit record = %s/%s, want the platform", action, tenant, kind)
		}
	}
}

// Once a second unit exists, an administrator without TOTP gets a restricted
// session: its payload says it must enrol, it holds only its own account's
// self-service, and every other route is refused. Enrolling through those
// routes restores its permissions. With a single unit, the session is
// described exactly as before.
func TestTOTPEnrollmentRestrictsAdministratorSessions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, _ := newUsersTestServer(t)
	const password = "administrator password"
	login := func() map[string]any {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, consoleAPIBase+"/auth/login", strings.NewReader(`{"username":"admin","password":"`+password+`"}`))
		request.RemoteAddr = "127.0.0.1:9000"
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		server.api(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("login = %d: %s", recorder.Code, recorder.Body.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		return payload
	}
	full := auth.PermissionsForRole(store.RoleAdministrator)

	if payload := login(); payload["totp_enrollment_required"] != nil {
		t.Fatalf("single-unit login payload = %v", payload)
	}
	account := signIn(t, server, store.RoleAdministrator, "admin", password, "")
	if payload := readSession(t, server, account); payload.Enrollment != nil || !reflect.DeepEqual(payload.Permissions, full) {
		t.Fatalf("single-unit session = %+v", payload)
	}

	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES('00000000-0000-0000-0000-000000000200','Other','other',?,?)`, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if payload := login(); payload["totp_enrollment_required"] != true || !reflect.DeepEqual(payload["permissions"], []any{auth.PermissionAccountSelf}) {
		t.Fatalf("restricted login payload = %v", payload)
	}
	account = signIn(t, server, store.RoleAdministrator, "admin", password, "")
	if payload := readSession(t, server, account); payload.Enrollment == nil || !*payload.Enrollment || !reflect.DeepEqual(payload.Permissions, []string{auth.PermissionAccountSelf}) {
		t.Fatalf("restricted session = %+v", payload)
	}
	assertOnlySelfService(t, server, &account)

	setup := callAPI(t, server, account, http.MethodPost, "/auth/totp/setup", `{"password":"`+password+`"}`)
	if setup.Code != http.StatusOK {
		t.Fatalf("TOTP setup = %d: %s", setup.Code, setup.Body.String())
	}
	var secret struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(setup.Body.Bytes(), &secret); err != nil || secret.Secret == "" {
		t.Fatalf("TOTP setup payload = %s, %v", setup.Body.String(), err)
	}
	if enable := callAPI(t, server, account, http.MethodPost, "/auth/totp/enable", `{"code":"`+coverageTOTPCode(secret.Secret, time.Now().Unix()/30)+`"}`); enable.Code != http.StatusOK {
		t.Fatalf("TOTP enable = %d: %s", enable.Code, enable.Body.String())
	}
	if payload := readSession(t, server, account); payload.Enrollment != nil || !reflect.DeepEqual(payload.Permissions, full) {
		t.Fatalf("enrolled session = %+v", payload)
	}
	if jobs := callAPI(t, server, account, http.MethodGet, "/jobs", ""); jobs.Code != http.StatusOK {
		t.Fatalf("GET /jobs after enrolment = %d: %s", jobs.Code, jobs.Body.String())
	}
}
