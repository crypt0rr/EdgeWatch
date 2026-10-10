package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/auth"
)

// routeTableOf returns the table that serves a route of apiRoutes.
func routeTableOf(route apiRoute) *routeTable {
	if route.Access == routePublic {
		return publicRoutes
	}
	return consoleRoutes
}

// routeTableRequest is a request for target, an absolute path that may
// carry a query, without decoding it the way a server would not.
func routeTableRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	parsed, err := url.ParseRequestURI(target)
	if err != nil {
		t.Fatalf("%s: %v", target, err)
	}
	return &http.Request{Method: method, URL: parsed}
}

// Every route of the inventory is registered exactly once, in the table of
// its API, and its own example reaches it: the example with the route's
// query, and the example with a trailing slash exactly when the route
// accepts one.
func TestRouteTablesRegisterEveryRouteOnce(t *testing.T) {
	t.Parallel()
	registered := map[*apiRoute]int{}
	patterns := map[string]bool{}
	for _, table := range []*routeTable{consoleRoutes, publicRoutes} {
		for _, group := range table.groups {
			if patterns[group.pattern] {
				t.Errorf("pattern %s is registered twice", group.pattern)
			}
			patterns[group.pattern] = true
			plain := 0
			for _, route := range group.routes {
				registered[route]++
				if want := route.Method + " " + table.base + route.Template; group.pattern != want {
					t.Errorf("%s is registered as %s, want %s", routeInventoryName(*route), group.pattern, want)
				}
				if (table == publicRoutes) != (route.Access == routePublic) {
					t.Errorf("%s is registered under %s", routeInventoryName(*route), table.base)
				}
				if route.Query == "" {
					plain++
				}
			}
			if plain != 1 {
				t.Errorf("pattern %s has %d routes without a query, want 1", group.pattern, plain)
			}
		}
	}
	for index := range apiRoutes {
		route := &apiRoutes[index]
		name := routeInventoryName(*route)
		if registered[route] != 1 {
			t.Errorf("%s is registered %d times, want once", name, registered[route])
		}
		if (route.Handle == nil) != route.NoHandler {
			t.Errorf("%s has a handler %t but NoHandler %t; every route but a NoHandler one needs its handler", name, route.Handle != nil, route.NoHandler)
		}
		table := routeTableOf(*route)
		target := table.base + route.Example
		if route.Query != "" {
			target += "?" + route.Query
		}
		if got := table.match(routeTableRequest(t, route.Method, target)); got != route {
			t.Errorf("%s %s reaches %v, want %s", route.Method, target, describeRoute(got), name)
		}
		slashed := table.base + route.Example + "/"
		if route.Query != "" {
			slashed += "?" + route.Query
		}
		got := table.match(routeTableRequest(t, route.Method, slashed))
		switch {
		case route.TrailingSlash && got != route:
			t.Errorf("%s %s reaches %v, want %s, which accepts a trailing slash", route.Method, slashed, describeRoute(got), name)
		case !route.TrailingSlash && got != nil:
			t.Errorf("%s %s reaches %s, want no route", route.Method, slashed, describeRoute(got))
		}
	}
}

// trailingSlashFamilies are the routes that accept one trailing slash: the
// ones that the sub-routers served, which trimmed the slashes off the rest
// of the path, and the public pages. The scan routes are not among them:
// the old gate admitted a trailing slash there, but no handler ever served
// one.
var trailingSlashFamilies = []string{"/scanner-profiles", "/scanner/profiles", "/users", "/notifications/destinations/{id}", "/jobs/{id}", "/platform/", "/dashboard"}

func TestRouteTrailingSlashesFollowTheSubRouters(t *testing.T) {
	t.Parallel()
	for _, route := range apiRoutes {
		want := false
		for _, family := range trailingSlashFamilies {
			want = want || route.Template == strings.TrimSuffix(family, "/") || strings.HasPrefix(route.Template, strings.TrimSuffix(family, "/")+"/")
		}
		if route.TrailingSlash != want {
			t.Errorf("%s TrailingSlash = %t, want %t", routeInventoryName(route), route.TrailingSlash, want)
		}
	}
}

// Only signing out and recording activity take no tenant store, so they
// work for an account whose unit is paused; every other session route
// resolves the session's tenant.
func TestOnlyAccountRoutesTakeNoTenant(t *testing.T) {
	t.Parallel()
	var untenanted []string
	for _, route := range apiRoutes {
		if route.NoTenant {
			untenanted = append(untenanted, routeInventoryName(route))
		}
	}
	if want := []string{"POST /auth/activity", "POST /auth/logout"}; strings.Join(untenanted, ",") != strings.Join(want, ",") {
		t.Fatalf("routes without a tenant = %q, want %q", untenanted, want)
	}
}

func describeRoute(route *apiRoute) string {
	if route == nil {
		return "no route"
	}
	return routeInventoryName(*route)
}

// newRouteTable refuses a table that ServeMux would route ambiguously or
// that disagrees with itself, so a conflicting route cannot be added.
func TestNewRouteTableRefusesAmbiguousRoutes(t *testing.T) {
	t.Parallel()
	for name, routes := range map[string][]apiRoute{
		"overlapping wildcards": {{Method: http.MethodGet, Template: "/a/{x}/b"}, {Method: http.MethodGet, Template: "/a/c/{y}"}},
		"renamed wildcard":      {{Method: http.MethodGet, Template: "/a/{x}"}, {Method: http.MethodGet, Template: "/a/{y}"}},
		"listed twice":          {{Method: http.MethodGet, Template: "/a"}, {Method: http.MethodGet, Template: "/a"}},
		"query listed twice":    {{Method: http.MethodDelete, Template: "/a", Query: "x=1"}, {Method: http.MethodDelete, Template: "/a", Query: "x=1"}},
		"trailing slash":        {{Method: http.MethodDelete, Template: "/a", TrailingSlash: true}, {Method: http.MethodDelete, Template: "/a", Query: "x=1"}},
		"query without a value": {{Method: http.MethodGet, Template: "/a", Query: "x"}},
		"malformed pattern":     {{Method: http.MethodGet, Template: "/a/{x"}},
		"rest not last":         {{Method: http.MethodGet, Template: "/a/{x...}/b"}},
	} {
		pointers := make([]*apiRoute, len(routes))
		for index := range routes {
			pointers[index] = &routes[index]
		}
		if _, err := newRouteTable(consoleAPIBase, pointers); err == nil {
			t.Errorf("%s: newRouteTable accepted %+v", name, routes)
		}
	}
	routes := []apiRoute{{Method: http.MethodDelete, Template: "/a/{x}"}, {Method: http.MethodDelete, Template: "/a/{x}", Query: "x=1"}, {Method: http.MethodGet, Template: "/a/b"}}
	if _, err := newRouteTable(consoleAPIBase, []*apiRoute{&routes[0], &routes[1], &routes[2]}); err != nil {
		t.Fatalf("newRouteTable refused distinct routes: %v", err)
	}
}

// A route's path values are the decoded segments of the request path, as
// the hand-written routers split them: escapes are decoded, an escaped
// slash separates segments, and a dot segment is a value like any other.
// One trailing slash is dropped where the route accepts it.
func TestRouteTablePathValuesAreDecodedSegments(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		method, target, template string
		values                   map[string]string
	}{
		{http.MethodGet, "/api/v1/scanner-profiles/profile-1", "/scanner-profiles/{id}", map[string]string{"id": "profile-1"}},
		{http.MethodGet, "/api/v1/scanner-profiles/profile-1/", "/scanner-profiles/{id}", map[string]string{"id": "profile-1"}},
		{http.MethodGet, "/api/v1/scanner-profiles/a%20b", "/scanner-profiles/{id}", map[string]string{"id": "a b"}},
		{http.MethodGet, "/api/v1/scanner-profiles/a%25b", "/scanner-profiles/{id}", map[string]string{"id": "a%b"}},
		{http.MethodGet, "/api/v1/scanner-profiles/%2E%2E", "/scanner-profiles/{id}", map[string]string{"id": ".."}},
		{http.MethodGet, "/api/v1/scanner-profiles/%2E", "/scanner-profiles/{id}", map[string]string{"id": "."}},
		{http.MethodGet, "/api/v1/scanner-profiles/%2E%2E/revisions", "/scanner-profiles/{id}/revisions", map[string]string{"id": ".."}},
		{http.MethodGet, "/api/v1/scanner/profiles/a%2Frevisions", "/scanner/profiles/{id}/revisions", map[string]string{"id": "a"}},
		{http.MethodGet, "/api/v1/scanner-profiles/validate", "/scanner-profiles/{id}", map[string]string{"id": "validate"}},
		{http.MethodPost, "/api/v1/scanner-profiles/validate", "/scanner-profiles/validate", nil},
		{http.MethodGet, "/api/v1/scans/scan-1/hosts/2001:db8::1", "/scans/{id}/hosts/{address}", map[string]string{"id": "scan-1", "address": "2001:db8::1"}},
		{http.MethodGet, "/api/v1/scans/scan-1/hosts/fe80::1%25eth0/rdap", "/scans/{id}/hosts/{address}/rdap", map[string]string{"id": "scan-1", "address": "fe80::1%eth0"}},
		{http.MethodGet, "/api/v1/scans/hosts/hosts/rdap", "/scans/{id}/hosts/{address}", map[string]string{"id": "hosts", "address": "rdap"}},
		{http.MethodGet, "/api/v1/scans/hosts/hosts/hosts/rdap", "/scans/{id}/hosts/{address}/rdap", map[string]string{"id": "hosts", "address": "hosts"}},
		{http.MethodGet, "/api/v1/jobs/job-1/scans/scan-1/hosts/198.51.100.1/rdap", "/jobs/{id}/scans/{scan}/hosts/{address}/rdap", map[string]string{"id": "job-1", "scan": "scan-1", "address": "198.51.100.1"}},
		{http.MethodGet, "/api/v1/jobs/job-1/scans/latest-successful", "/jobs/{id}/scans/latest-successful", map[string]string{"id": "job-1"}},
		{http.MethodGet, "/api/v1/jobs/preview", "/jobs/{id}", map[string]string{"id": "preview"}},
		{http.MethodDelete, "/api/v1/jobs/job-1?permanent=true", "/jobs/{id}", map[string]string{"id": "job-1"}},
		{http.MethodDelete, "/api/v1/platform/units/unit-1/accounts/user%201/sessions", "/platform/units/{id}/accounts/{uid}/sessions", map[string]string{"id": "unit-1", "uid": "user 1"}},
		{http.MethodGet, "/api/public/v1/dashboard/other", "/dashboard/{slug...}", map[string]string{"slug": "other"}},
		{http.MethodGet, "/api/public/v1/dashboard/other/", "/dashboard/{slug...}", map[string]string{"slug": "other"}},
		{http.MethodGet, "/api/public/v1/dashboard/other%2Fx", "/dashboard/{slug...}", map[string]string{"slug": "other/x"}},
		{http.MethodGet, "/api/public/v1/dashboard/a/b", "/dashboard/{slug...}", map[string]string{"slug": "a/b"}},
		{http.MethodGet, "/api/public/v1/dashboard/", "/dashboard", nil},
	} {
		table := consoleRoutes
		if strings.HasPrefix(test.target, publicAPIBase) {
			table = publicRoutes
		}
		request := routeTableRequest(t, test.method, test.target)
		route := table.match(request)
		if route == nil || route.Template != test.template {
			t.Errorf("%s %s reaches %s, want %s", test.method, test.target, describeRoute(route), test.template)
			continue
		}
		for name, want := range test.values {
			if got := request.PathValue(name); got != want {
				t.Errorf("%s %s: path value %s = %q, want %q", test.method, test.target, name, got, want)
			}
		}
	}
}

// Paths that no route serves reach no route, whatever their shape, and a
// route serves only its own method.
func TestRouteTableMatchesNoRouteOutsideTheInventory(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ method, target string }{
		{http.MethodGet, "/api/v1"},
		{http.MethodGet, "/api/v1/"},
		{http.MethodGet, "/api/v1//"},
		{http.MethodGet, "/api/v1/status/"},
		{http.MethodGet, "/api/v1/status//"},
		{http.MethodGet, "/api/v1//status"},
		{http.MethodGet, "/api/v1/./status"},
		{http.MethodGet, "/api/v1/scanner-profiles/../status"},
		{http.MethodGet, "/api/v1/scanner-profiles/a%2Fb"},
		{http.MethodGet, "/api/v1/scanner-profiles/profile-1//"},
		{http.MethodGet, "/api/v1/scanner-profiles//profile-1"},
		{http.MethodGet, "/api/v1/scanner-profiles/profile-1/revisions/x"},
		{http.MethodGet, "/api/v1/scanner-profilesx"},
		{http.MethodHead, "/api/v1/status"},
		{http.MethodHead, "/api/v1/scanner-profiles"},
		{http.MethodOptions, "/api/v1/scanner-profiles"},
		{http.MethodPatch, "/api/v1/scanner-profiles"},
		{http.MethodConnect, "/api/v1/scanner-profiles"},
		{http.MethodPost, "/api/v1/auth/login/"},
		{http.MethodGet, "/api/v1/setup/status/"},
		{http.MethodGet, "/api/v1/api/v1/status"},
		{http.MethodGet, "/status"},
		{http.MethodGet, "/api/v1status"},
		{http.MethodGet, "/api/v1/scans/scan-1/"},
		{http.MethodGet, "/api/v1/jobs/schedule-suggestion/"},
		{http.MethodGet, "/api/v1/jobs/job-1/scans/%2Fhosts"},
		{http.MethodGet, "/api/v1/notifications/destinations/"},
		{http.MethodDelete, "/api/v1/jobs/job-1/not-a-route?permanent=true"},
		{http.MethodGet, "/api/v1/dashboard"},
		{http.MethodGet, "/api/public/v1/dashboard//"},
		{http.MethodGet, "/api/public/v1/dashboard/a%2F%2Fb"},
		{http.MethodHead, "/api/public/v1/dashboard"},
		{http.MethodPost, "/api/public/v1/dashboard/other"},
		{http.MethodGet, "/api/public/v1/status"},
		{http.MethodGet, "/api/public/v1/scanner-profiles"},
	} {
		table := consoleRoutes
		if strings.HasPrefix(test.target, publicAPIBase) {
			table = publicRoutes
		}
		if route := table.match(routeTableRequest(t, test.method, test.target)); route != nil {
			t.Errorf("%s %s reaches %s, want no route", test.method, test.target, routeInventoryName(*route))
		}
	}
}

// consoleFailClosedPaths are requests that no route serves, relative to
// /api/v1, in the shapes that ServeMux would otherwise answer itself: with a
// redirect to a cleaned path or to a trailing slash, or with 405 and an
// Allow header.
var consoleFailClosedPaths = []struct{ method, path string }{
	{http.MethodGet, ""},
	{http.MethodGet, "/"},
	{http.MethodGet, "/unknown"},
	{http.MethodGet, "/status/"},
	{http.MethodGet, "/./status"},
	{http.MethodGet, "/scanner-profiles/../status"},
	{http.MethodGet, "/scanner-profiles//profile-1"},
	{http.MethodGet, "/scanner-profiles/profile-1//"},
	{http.MethodGet, "/scanner-profiles/a%2Fb"},
	{http.MethodHead, "/status"},
	{http.MethodOptions, "/status"},
	{http.MethodPatch, "/status"},
	{http.MethodPut, "/scanner-profiles"},
	{http.MethodDelete, "/scanner/capabilities"},
	{http.MethodPost, "/auth/login/"},
	{http.MethodGet, "/setup/status/"},
	{http.MethodPost, "/setup/platform/"},
}

// The gate refuses every request that no route serves in the order it
// always did: 401 without a session, 403 csrf for a mutation without the
// token, and 403 route for an administrator, who holds every unit
// permission. ServeMux never answers: no redirect, and no 405 with Allow.
func TestConsoleAPIFailsClosedOutsideTheRouteTable(t *testing.T) {
	t.Parallel()
	server, accounts := newRouteMatrixSessions(t)
	admin := &accounts[0]
	for _, test := range consoleFailClosedPaths {
		target := consoleAPIBase + test.path
		for _, check := range []struct {
			name    string
			account *routeMatrixSession
			csrf    bool
			status  int
			code    string
		}{
			{"without a session", nil, false, http.StatusUnauthorized, "unauthorized"},
			{"without CSRF", admin, false, http.StatusForbidden, "csrf"},
			{"as administrator", admin, true, http.StatusForbidden, "forbidden"},
		} {
			if check.code == "csrf" && !isMutation(test.method) {
				continue
			}
			request := httptest.NewRequest(test.method, target, nil)
			request.RemoteAddr = "127.0.0.1:9000"
			if check.account != nil {
				request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: check.account.raw})
				if check.csrf {
					request.Header.Set("X-CSRF-Token", check.account.session.CSRFToken)
				}
			}
			recorder := httptest.NewRecorder()
			server.api(recorder, request)
			body := recorder.Body.String()
			if recorder.Code != check.status || !strings.Contains(body, `"code":"`+check.code+`"`) {
				t.Errorf("%s %s %s = %d %s, want %d %s", test.method, target, check.name, recorder.Code, body, check.status, check.code)
			}
			if check.code == "forbidden" && !strings.Contains(body, `"permission":"route"`) {
				t.Errorf("%s %s %s = %s, want the permission route", test.method, target, check.name, body)
			}
			if location, allow := recorder.Header().Get("Location"), recorder.Header().Get("Allow"); location != "" || allow != "" {
				t.Errorf("%s %s %s answered with Location %q and Allow %q", test.method, target, check.name, location, allow)
			}
		}
	}
}

// Through the whole handler, which validates the host first, a request
// outside the table is refused like before; the outer ServeMux still
// redirects only an unclean escaped path, as it always has.
func TestHandlerFailsClosedOutsideTheRouteTable(t *testing.T) {
	t.Parallel()
	server, accounts := newRouteMatrixSessions(t)
	admin := &accounts[0]
	handler := server.Handler()
	for _, test := range []struct {
		method, target string
		status         int
		code           string
	}{
		{http.MethodPatch, "/api/v1/status", http.StatusForbidden, "forbidden"},
		{http.MethodHead, "/api/v1/status", http.StatusForbidden, ""},
		{http.MethodGet, "/api/v1/status/", http.StatusForbidden, "forbidden"},
		{http.MethodGet, "/api/v1/scanner-profiles/a%2Fb", http.StatusForbidden, "forbidden"},
		{http.MethodGet, "/api/v1/scanner-profiles/%2E%2E/revisions", http.StatusNotFound, "not_found"},
		{http.MethodGet, "/api/v1/scanner-profiles/", http.StatusOK, ""},
	} {
		request := httptest.NewRequest(test.method, test.target, nil)
		request.Host = "127.0.0.1:8080"
		request.RemoteAddr = "127.0.0.1:9000"
		request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: admin.raw})
		request.Header.Set("X-CSRF-Token", admin.session.CSRFToken)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != test.status || (test.code != "" && !strings.Contains(recorder.Body.String(), `"code":"`+test.code+`"`)) {
			t.Errorf("%s %s = %d %s, want %d %s", test.method, test.target, recorder.Code, recorder.Body.String(), test.status, test.code)
		}
		if allow := recorder.Header().Get("Allow"); allow != "" {
			t.Errorf("%s %s answered with Allow %q", test.method, test.target, allow)
		}
	}
}

// The public API answers what no route serves with 404 not_found, as it
// always did, and never lets ServeMux redirect or answer 405 with Allow. A
// route of the table is served: without a published page, every page is
// 404 public_disabled.
func TestPublicAPIFailsClosedOutsideTheRouteTable(t *testing.T) {
	t.Parallel()
	server, _ := newRouteMatrixSessions(t)
	for index, test := range []struct {
		method, target, code string
	}{
		{http.MethodGet, "/api/public/v1/dashboard", "public_disabled"},
		{http.MethodGet, "/api/public/v1/dashboard/", "public_disabled"},
		{http.MethodGet, "/api/public/v1/dashboard/unit-slug/", "public_disabled"},
		{http.MethodGet, "/api/public/v1/dashboard/a/b", "public_disabled"},
		{http.MethodGet, "/api/public/v1/dashboard//", "not_found"},
		{http.MethodGet, "/api/public/v1/dashboard/a%2F%2Fb", "not_found"},
		{http.MethodGet, "/api/public/v1/dashboard/./x", "public_disabled"},
		{http.MethodGet, "/api/public/v1/dashboard/../x", "public_disabled"},
		{http.MethodHead, "/api/public/v1/dashboard", "not_found"},
		{http.MethodPost, "/api/public/v1/dashboard", "not_found"},
		{http.MethodOptions, "/api/public/v1/dashboard/unit-slug", "not_found"},
		{http.MethodGet, "/api/public/v1/", "not_found"},
		{http.MethodGet, "/api/public/v1/status", "not_found"},
	} {
		request := httptest.NewRequest(test.method, test.target, nil)
		request.RemoteAddr = fmt.Sprintf("198.51.100.%d:1000", 100+index)
		recorder := httptest.NewRecorder()
		server.publicAPI(recorder, request)
		if recorder.Code != http.StatusNotFound || !strings.Contains(recorder.Body.String(), `"code":"`+test.code+`"`) {
			t.Errorf("%s %s = %d %s, want 404 %s", test.method, test.target, recorder.Code, recorder.Body.String(), test.code)
		}
		if location, allow := recorder.Header().Get("Location"), recorder.Header().Get("Allow"); location != "" || allow != "" {
			t.Errorf("%s %s answered with Location %q and Allow %q", test.method, test.target, location, allow)
		}
	}
}
