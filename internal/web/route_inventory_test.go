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
	"github.com/crypt0rr/edgewatch/internal/store"
)

func routeInventoryName(route apiRoute) string {
	name := route.Method + " " + route.Template
	if route.Query != "" {
		name += "?" + route.Query
	}
	switch route.Access {
	case routePublic:
		name = route.Method + " " + publicAPIBase + route.Template
	case routeUnauthenticated:
		name += " (unauthenticated)"
	}
	return name
}

func routeSegments(path string) []string {
	return strings.Split(strings.TrimPrefix(path, "/"), "/")
}

func isRoutePlaceholder(segment string) bool {
	return len(segment) > 2 && strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}")
}

// routeTemplateMatches reports whether a concrete path matches a template.
// A placeholder matches exactly one non-empty segment; every other segment
// must be equal.
func routeTemplateMatches(template, path string) bool {
	want, got := routeSegments(template), routeSegments(path)
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if isRoutePlaceholder(want[i]) {
			if got[i] == "" {
				return false
			}
			continue
		}
		if want[i] != got[i] {
			return false
		}
	}
	return true
}

// inventoryRoutesFor returns the console API entries that serve a method and
// concrete path relative to /api/v1 without a query.
func inventoryRoutesFor(routes []apiRoute, method, path string) []apiRoute {
	var matches []apiRoute
	for _, route := range routes {
		if route.Access == routePublic || route.Query != "" || route.Method != method {
			continue
		}
		if routeTemplateMatches(route.Template, path) {
			matches = append(matches, route)
		}
	}
	return matches
}

func TestRouteInventoryEntriesAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, route := range apiRoutes {
		name := routeInventoryName(route)
		if seen[name] {
			t.Errorf("%s is listed more than once", name)
		}
		seen[name] = true
		if !strings.HasPrefix(route.Template, "/") || strings.HasSuffix(route.Template, "/") || strings.Contains(route.Template, "//") {
			t.Errorf("%s template must be a clean absolute path", name)
		}
		if !routeTemplateMatches(route.Template, route.Example) {
			t.Errorf("%s example %q does not match its template", name, route.Example)
		}
		for _, segment := range routeSegments(route.Example) {
			if strings.ContainsAny(segment, "{}") {
				t.Errorf("%s example %q must be concrete", name, route.Example)
			}
		}
		if route.Mutates != isMutation(route.Method) {
			t.Errorf("%s Mutates = %t, but isMutation(%s) = %t", name, route.Mutates, route.Method, isMutation(route.Method))
		}
		switch route.Access {
		case routeSession:
			if route.Permission == "" || route.Permission == auth.PermissionDenied {
				t.Errorf("%s is a session route without a capability", name)
			}
		case routeUnauthenticated, routePublic:
			if route.Permission != "" {
				t.Errorf("%s is %v but lists capability %q", name, route.Access, route.Permission)
			}
			if route.NoHandler {
				t.Errorf("%s cannot be both unauthenticated and without a handler", name)
			}
		default:
			t.Errorf("%s has unknown access %v", name, route.Access)
		}
		if key, value, ok := strings.Cut(route.Query, "="); route.Query != "" && (!ok || key == "" || value == "") {
			t.Errorf("%s query must be key=value", name)
		}
	}
}

// routeMatrixSession is a logged-in fixture account for the gate matrix.
type routeMatrixSession struct {
	role    string
	raw     string
	session store.Session
}

func newRouteMatrixSessions(t *testing.T) (*Server, []routeMatrixSession) {
	t.Helper()
	ctx := context.Background()
	server, db, _ := newUsersTestServer(t)
	accounts := []routeMatrixSession{{role: store.RoleAdministrator}, {role: store.RoleOperator}, {role: store.RoleViewer}}
	for index, account := range accounts {
		username, password := "admin", "administrator password"
		if account.role != store.RoleAdministrator {
			username, password = account.role, account.role+" account password"
			hash, err := auth.PasswordHash(password)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.CreateUser(ctx, store.User{Username: username, DisplayName: username, Role: account.role, PasswordHash: hash, Enabled: true}, store.AuditEntry{}); err != nil {
				t.Fatal(err)
			}
		}
		login := httptest.NewRequest(http.MethodPost, consoleAPIBase+"/auth/login", nil)
		login.RemoteAddr = "127.0.0.1:9000"
		raw, _, err := server.Auth.LoginAs(ctx, login, username, password, "", "")
		if err != nil {
			t.Fatal(err)
		}
		probe := httptest.NewRequest(http.MethodGet, consoleAPIBase+"/status", nil)
		probe.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: raw})
		session, ok := server.Auth.AuthenticateReadOnly(ctx, probe)
		if !ok || session.Role != account.role || session.CSRFToken == "" {
			t.Fatalf("%s session = %#v, authenticated %t", account.role, session, ok)
		}
		accounts[index].raw, accounts[index].session = raw, session
	}
	return server, accounts
}

// cancelOnWriteRecorder cancels the request context once the handler
// responds, so the long-lived live-update stream ends after its first write.
type cancelOnWriteRecorder struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
}

func (w *cancelOnWriteRecorder) WriteHeader(status int) {
	w.cancel()
	w.ResponseRecorder.WriteHeader(status)
}

func (w *cancelOnWriteRecorder) Write(data []byte) (int, error) {
	w.cancel()
	return w.ResponseRecorder.Write(data)
}

func (w *cancelOnWriteRecorder) Flush() {
	w.cancel()
	w.ResponseRecorder.Flush()
}

type routeMatrixResponse struct {
	status  int
	code    string
	message string
	details map[string]any
	body    string
}

func serveRouteMatrixRequest(t *testing.T, handler http.HandlerFunc, method, target string, account *routeMatrixSession, csrf bool, origin string) routeMatrixResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request := httptest.NewRequest(method, target, nil).WithContext(ctx)
	request.RemoteAddr = "127.0.0.1:9000"
	if account != nil {
		request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: account.raw})
		if csrf {
			request.Header.Set("X-CSRF-Token", account.session.CSRFToken)
		}
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	recorder := &cancelOnWriteRecorder{ResponseRecorder: httptest.NewRecorder(), cancel: cancel}
	handler(recorder, request)
	response := routeMatrixResponse{status: recorder.Code, body: recorder.Body.String()}
	var envelope struct {
		Error *struct {
			Code    string         `json:"code"`
			Message string         `json:"message"`
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	if strings.HasPrefix(recorder.Header().Get("Content-Type"), "application/json") && json.Unmarshal(recorder.Body.Bytes(), &envelope) == nil && envelope.Error != nil {
		response.code, response.message, response.details = envelope.Error.Code, envelope.Error.Message, envelope.Error.Details
	}
	return response
}

// routeGateRejected reports whether Server.api answered before dispatch.
func (r routeMatrixResponse) routeGateRejected() bool {
	return r.status == http.StatusUnauthorized ||
		(r.status == http.StatusForbidden && (r.code == "csrf" || r.message == "your account is not allowed to perform this action"))
}

// routeUnrouted reports the fall-through responses of Server.api and its
// sub-routers.
func (r routeMatrixResponse) routeUnrouted() bool {
	if r.status != http.StatusNotFound || r.code != "not_found" {
		return false
	}
	switch r.message {
	case "endpoint not found", "job endpoint not found", "scanner profile endpoint not found", "notification destination endpoint not found":
		return true
	}
	return false
}

func routeMatrixTarget(route apiRoute) string {
	base := consoleAPIBase
	if route.Access == routePublic {
		base = publicAPIBase
	}
	target := base + route.Example
	if route.Query != "" {
		target += "?" + route.Query
	}
	return target
}

// TestRouteInventoryGateMatrix sends every inventory route through the real
// handler as each role and without a session. Session routes must answer 401
// without a session, require CSRF for mutations, and admit exactly the roles
// that auth.HasPermission grants the inventory's capability. Unauthenticated
// and public routes must be served before, or outside, the session gate.
func TestRouteInventoryGateMatrix(t *testing.T) {
	server, accounts := newRouteMatrixSessions(t)
	for _, route := range apiRoutes {
		t.Run(routeInventoryName(route), func(t *testing.T) {
			target := routeMatrixTarget(route)
			switch route.Access {
			case routePublic:
				// The public projection ignores sessions entirely. With no
				// publication configured it reports public_disabled to everyone.
				for _, account := range append([]*routeMatrixSession{nil}, sessionPointers(accounts)...) {
					response := serveRouteMatrixRequest(t, server.publicAPI, route.Method, target, account, false, "")
					if response.status != http.StatusNotFound || response.code != "public_disabled" {
						t.Errorf("%s as %s = %d %s, want 404 public_disabled", target, routeMatrixRole(account), response.status, response.body)
					}
				}
			case routeUnauthenticated:
				for _, account := range append([]*routeMatrixSession{nil}, sessionPointers(accounts)...) {
					if route.Mutates {
						// No session exists yet to bind a CSRF token to, so the
						// early dispatch checks the browser origin instead.
						response := serveRouteMatrixRequest(t, server.api, route.Method, target, account, false, "https://attacker.example")
						if response.status != http.StatusForbidden || response.code != "origin" {
							t.Errorf("cross-origin %s as %s = %d %s, want 403 origin", target, routeMatrixRole(account), response.status, response.body)
						}
						continue
					}
					response := serveRouteMatrixRequest(t, server.api, route.Method, target, account, false, "")
					wantStatus := http.StatusOK
					if account == nil && route.Template == "/auth/session" {
						// The session probe authenticates itself.
						wantStatus = http.StatusUnauthorized
					}
					if response.status != wantStatus || response.code == "forbidden" {
						t.Errorf("%s as %s = %d %s, want %d", target, routeMatrixRole(account), response.status, response.body, wantStatus)
					}
				}
			default:
				response := serveRouteMatrixRequest(t, server.api, route.Method, target, nil, false, "")
				if response.status != http.StatusUnauthorized || response.code != "unauthorized" {
					t.Errorf("%s without a session = %d %s, want 401 unauthorized", target, response.status, response.body)
				}
				for index := range accounts {
					account := &accounts[index]
					allowed := auth.HasPermission(account.session, route.Permission)
					if route.Mutates {
						response := serveRouteMatrixRequest(t, server.api, route.Method, target, account, false, "")
						if response.status != http.StatusForbidden || response.code != "csrf" {
							t.Errorf("%s as %s without CSRF = %d %s, want 403 csrf", target, account.role, response.status, response.body)
						}
					}
					switch {
					case !allowed:
						response := serveRouteMatrixRequest(t, server.api, route.Method, target, account, true, "")
						if response.status != http.StatusForbidden || response.code != "forbidden" || response.details["permission"] != route.Permission {
							t.Errorf("%s as %s = %d %s, want 403 forbidden for %s", target, account.role, response.status, response.body, route.Permission)
						}
					case route.NoHandler:
						response := serveRouteMatrixRequest(t, server.api, route.Method, target, account, true, "")
						if !response.routeUnrouted() {
							t.Errorf("%s as %s = %d %s, want the unrouted 404", target, account.role, response.status, response.body)
						}
					case !route.Mutates:
						// Reads are safe to run against the empty fixture: the
						// gate must admit the role and dispatch to a handler.
						response := serveRouteMatrixRequest(t, server.api, route.Method, target, account, false, "")
						if response.routeGateRejected() || response.routeUnrouted() {
							t.Errorf("%s as %s = %d %s, want the request dispatched to its handler", target, account.role, response.status, response.body)
						}
					}
					// Authorized mutations are not executed here because they
					// change the fixture; auth.HasPermission is what the gate
					// applies, and the CSRF rejection above proves the gate ran.
				}
			}
		})
	}
}

func sessionPointers(accounts []routeMatrixSession) []*routeMatrixSession {
	out := make([]*routeMatrixSession, 0, len(accounts))
	for index := range accounts {
		out = append(out, &accounts[index])
	}
	return out
}

func routeMatrixRole(account *routeMatrixSession) string {
	if account == nil {
		return "no session"
	}
	return account.role
}

// routeSweepMethods are the methods the fail-closed sweep tries on every
// inventory path.
var routeSweepMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodTrace, http.MethodConnect}

// TestRequiredPermissionFailsClosedOutsideInventory checks that every method
// and path outside the route inventory is denied, including unlisted methods
// and extra segments on every listed path.
func TestRequiredPermissionFailsClosedOutsideInventory(t *testing.T) {
	unknown := []struct{ method, path string }{
		{http.MethodGet, ""},
		{http.MethodGet, "/"},
		{http.MethodGet, "/unknown"},
		{http.MethodGet, "/STATUS"},
		{http.MethodGet, "/status/"},
		{http.MethodGet, "/api/v1/status"},
		{http.MethodGet, "/dashboard"},
		{http.MethodGet, "/auth/not-a-route"},
		{http.MethodPost, "/auth/not-a-route"},
		{http.MethodGet, "/auth/login"},
		{http.MethodPost, "/auth/session"},
		{http.MethodDelete, "/setup"},
		{http.MethodPost, "/setup/status"},
		{http.MethodPost, "/incidents"},
		{http.MethodGet, "/notifications/update-routing"},
		{http.MethodGet, "/notifications/destinations/"},
		{http.MethodGet, "/notifications/destinations/id/not-a-route"},
		{http.MethodGet, "/scanner-profiles/id/not-a-route"},
		{http.MethodPost, "/scanner-profiles/id"},
		{http.MethodGet, "/users/id/not-a-route"},
		{http.MethodPost, "/users/id"},
		{http.MethodGet, "/users/a/b/c"},
		{http.MethodGet, "/scans/"},
		{http.MethodGet, "/scans/id/not-a-route"},
		{http.MethodGet, "/scans/id/cancel"},
		{http.MethodPost, "/scans/a/b/cancel"},
		{http.MethodGet, "/jobs/"},
		{http.MethodGet, "/jobs/id/hosts"},
		{http.MethodGet, "/jobs/id/not-a-route"},
		{http.MethodDelete, "/jobs/id/not-a-route"},
		{http.MethodGet, "/jobs/id/scans/scan/not-a-route"},
		{http.MethodDelete, "/jobs/id/scan-cycle"},
	}
	for _, test := range unknown {
		if matches := inventoryRoutesFor(apiRoutes, test.method, test.path); len(matches) > 0 {
			t.Fatalf("%s %s is expected to be unknown but matches %s", test.method, test.path, routeInventoryName(matches[0]))
		}
		if got := requiredPermission(test.path, test.method); got != auth.PermissionDenied {
			t.Errorf("unknown route %s %q returned %q, want %q", test.method, test.path, got, auth.PermissionDenied)
		}
	}
	nestedPermanent := httptest.NewRequest(http.MethodDelete, consoleAPIBase+"/jobs/id/not-a-route?permanent=true", nil)
	if got := requestPermission("/jobs/id/not-a-route", nestedPermanent); got != auth.PermissionDenied {
		t.Fatalf("unknown nested job permission = %q, want %q", got, auth.PermissionDenied)
	}

	// Sweep every method over every inventory example, and over each example
	// with one and two extra segments. A combination the inventory lists gets
	// exactly its capability; anything else fails closed.
	var checked, denied int
	seen := map[string]bool{}
	for _, route := range apiRoutes {
		if route.Access == routePublic {
			continue
		}
		for _, path := range []string{route.Example, route.Example + "/not-a-route", route.Example + "/not-a-route/again"} {
			for _, method := range routeSweepMethods {
				key := method + " " + path
				if seen[key] {
					continue
				}
				seen[key] = true
				checked++
				want := auth.PermissionDenied
				if matches := inventoryRoutesFor(apiRoutes, method, path); len(matches) > 0 {
					want = matches[0].Permission
					for _, match := range matches[1:] {
						if match.Permission != want {
							t.Errorf("%s matches %s and %s with different capabilities", key, routeInventoryName(matches[0]), routeInventoryName(match))
						}
					}
				} else {
					denied++
				}
				if got := requiredPermission(path, method); got != want {
					t.Errorf("requiredPermission(%q, %q) = %q, want %q", path, method, got, want)
				}
			}
		}
	}
	if denied == 0 || denied == checked {
		t.Fatalf("sweep checked %d combinations with %d denied; expected a mix", checked, denied)
	}

	// Through the real handler, an administrator (who holds every
	// capability) is still refused an unknown route before dispatch.
	server, accounts := newRouteMatrixSessions(t)
	admin := &accounts[0]
	for _, test := range []struct{ method, path string }{
		{http.MethodGet, "/unknown"},
		{http.MethodPost, "/incidents"},
		{http.MethodGet, "/jobs/job-1/not-a-route"},
		{http.MethodDelete, "/jobs/job-1/not-a-route?permanent=true"},
		{http.MethodPatch, "/scanner-profiles/profile-1"},
		{http.MethodHead, "/status"},
	} {
		response := serveRouteMatrixRequest(t, server.api, test.method, consoleAPIBase+test.path, admin, true, "")
		if response.status != http.StatusForbidden || response.code != "forbidden" || response.details["permission"] != "route" {
			t.Errorf("administrator %s %s = %d %s, want 403 forbidden route", test.method, test.path, response.status, response.body)
		}
	}
}
