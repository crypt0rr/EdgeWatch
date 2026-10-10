package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// The console API and the public API are served from apiRoutes. Each API's
// routeTable registers the method and path pattern of every route on a
// ServeMux, which finds the route of a request. Server.api admits a console
// request through the gate in serveRoute, with that route's access and
// permission, and Server.publicAPI serves a public route without one; the
// route's handler then serves the request.
//
// The ServeMux only matches: the tables look a request up with
// ServeMux.Handler and never let it answer one, so its path-cleaning
// redirects, its trailing-slash redirects and its 405 answers with an Allow
// header never reach a client. A request that no route serves gets the
// answers it always got: on the console API 401 without a session, 403 csrf
// for a mutation without the CSRF token, and otherwise 403 with the
// permission "route"; on the public API 404 not_found.

// routeCall is what the gate resolved for a request that it admitted: the
// session, and the stores through which the route's handler reads and
// changes data. tenant is the store of the session's business unit, and nil
// for the routes that take none; a nil store refuses every call. account
// changes the signed-in account: it is the unit's store, or the platform's
// store bound to a platform administrator's own account.
type routeCall struct {
	session store.Session
	tenant  *store.TenantStore
	account accountStore
}

// routeHandler serves a route that the gate admitted. r carries the route's
// path values, which r.PathValue returns.
type routeHandler func(s *Server, w http.ResponseWriter, r *http.Request, call routeCall)

// requestHandler, tenantHandler, sessionHandler, sessionTenantHandler and
// accountHandler adapt the handlers of routes without path values.
func requestHandler(handle func(*Server, http.ResponseWriter, *http.Request)) routeHandler {
	return func(s *Server, w http.ResponseWriter, r *http.Request, _ routeCall) { handle(s, w, r) }
}

func tenantHandler(handle func(*Server, http.ResponseWriter, *http.Request, *store.TenantStore)) routeHandler {
	return func(s *Server, w http.ResponseWriter, r *http.Request, call routeCall) { handle(s, w, r, call.tenant) }
}

func sessionHandler(handle func(*Server, http.ResponseWriter, *http.Request, store.Session)) routeHandler {
	return func(s *Server, w http.ResponseWriter, r *http.Request, call routeCall) { handle(s, w, r, call.session) }
}

func sessionTenantHandler(handle func(*Server, http.ResponseWriter, *http.Request, store.Session, *store.TenantStore)) routeHandler {
	return func(s *Server, w http.ResponseWriter, r *http.Request, call routeCall) {
		handle(s, w, r, call.session, call.tenant)
	}
}

func accountHandler(handle func(*Server, http.ResponseWriter, *http.Request, store.Session, accountStore)) routeHandler {
	return func(s *Server, w http.ResponseWriter, r *http.Request, call routeCall) {
		handle(s, w, r, call.session, call.account)
	}
}

// idHandler, sessionIDHandler, tenantIDHandler and sessionTenantIDHandler
// adapt the handlers of routes whose one path value is {id}.
func idHandler(handle func(*Server, http.ResponseWriter, *http.Request, string)) routeHandler {
	return func(s *Server, w http.ResponseWriter, r *http.Request, _ routeCall) {
		handle(s, w, r, r.PathValue("id"))
	}
}

func sessionIDHandler(handle func(*Server, http.ResponseWriter, *http.Request, store.Session, string)) routeHandler {
	return func(s *Server, w http.ResponseWriter, r *http.Request, call routeCall) {
		handle(s, w, r, call.session, r.PathValue("id"))
	}
}

func tenantIDHandler(handle func(*Server, http.ResponseWriter, *http.Request, *store.TenantStore, string)) routeHandler {
	return func(s *Server, w http.ResponseWriter, r *http.Request, call routeCall) {
		handle(s, w, r, call.tenant, r.PathValue("id"))
	}
}

func sessionTenantIDHandler(handle func(*Server, http.ResponseWriter, *http.Request, store.Session, *store.TenantStore, string)) routeHandler {
	return func(s *Server, w http.ResponseWriter, r *http.Request, call routeCall) {
		handle(s, w, r, call.session, call.tenant, r.PathValue("id"))
	}
}

// consoleRoutes serves the console API under consoleAPIBase, and
// publicRoutes the public API under publicAPIBase.
var consoleRoutes, publicRoutes = mustRouteTables(apiRoutes)

func mustRouteTables(routes []apiRoute) (console, public *routeTable) {
	var consoleEntries, publicEntries []*apiRoute
	for index := range routes {
		if routes[index].Access == routePublic {
			publicEntries = append(publicEntries, &routes[index])
		} else {
			consoleEntries = append(consoleEntries, &routes[index])
		}
	}
	console, err := newRouteTable(consoleAPIBase, consoleEntries)
	if err == nil {
		public, err = newRouteTable(publicAPIBase, publicEntries)
	}
	if err != nil {
		panic(err)
	}
	return console, public
}

// routeTable is the routes of one API, registered on a ServeMux.
type routeTable struct {
	base   string
	mux    *http.ServeMux
	groups []*routeGroup
}

// routeGroup is the routes that share one method and path, and so one
// ServeMux pattern: the route without a query, and the routes that a query
// selects on the same method and path, such as the permanent delete of a
// job.
type routeGroup struct {
	method  string
	pattern string
	// segments is the template's path segments, relative to the API base.
	segments []string
	routes   []*apiRoute
}

// ServeHTTP lets a group be registered on the ServeMux. The tables never
// call it: they find the group with ServeMux.Handler and run the route
// themselves. Were it called, it would answer like a request that no route
// serves.
func (g *routeGroup) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, "not_found", "endpoint not found", nil)
}

// newRouteTable registers the routes under base. It refuses a route that is
// listed twice, routes of one method and path that disagree about a
// trailing slash, and patterns that ServeMux refuses, including two routes
// that both match a request with neither more specific than the other.
func newRouteTable(base string, routes []*apiRoute) (*routeTable, error) {
	table := &routeTable{base: base, mux: http.NewServeMux()}
	groups := map[string]*routeGroup{}
	for _, route := range routes {
		pattern := route.Method + " " + base + route.Template
		group := groups[pattern]
		if group == nil {
			group = &routeGroup{method: route.Method, pattern: pattern, segments: strings.Split(strings.TrimPrefix(route.Template, "/"), "/")}
			groups[pattern] = group
			table.groups = append(table.groups, group)
		}
		for _, other := range group.routes {
			if other.Query == route.Query {
				return nil, fmt.Errorf("route %s?%s is listed twice", pattern, route.Query)
			}
			if other.TrailingSlash != route.TrailingSlash {
				return nil, fmt.Errorf("the routes of %s disagree about a trailing slash", pattern)
			}
		}
		if key, value, ok := strings.Cut(route.Query, "="); route.Query != "" && (!ok || key == "" || value == "") {
			return nil, fmt.Errorf("route %s query %q is not key=value", pattern, route.Query)
		}
		group.routes = append(group.routes, route)
	}
	for _, group := range table.groups {
		if err := registerRouteGroup(table.mux, group); err != nil {
			return nil, err
		}
	}
	return table, nil
}

// registerRouteGroup returns the panic with which ServeMux refuses a
// pattern as an error.
func registerRouteGroup(mux *http.ServeMux, group *routeGroup) (err error) {
	defer func() {
		if refused := recover(); refused != nil {
			err = fmt.Errorf("route %s: %v", group.pattern, refused)
		}
	}()
	mux.Handle(group.pattern, group)
	return nil
}

// match returns the route that serves r, or nil when none does, and sets
// the route's path values on r. It matches the decoded path segment by
// segment, as the hand-written routers that it replaced split it: an escaped
// slash separates segments too, and a path value is the decoded segment. A
// path with an empty segment matches no route. One trailing slash is
// accepted only by a route with TrailingSlash. The method must be the
// route's own: ServeMux lets a GET pattern match HEAD, which no route
// serves.
func (t *routeTable) match(r *http.Request) *apiRoute {
	segments, trailingSlash, ok := splitRoutePath(r.URL.Path, t.base)
	if !ok {
		return nil
	}
	// The ServeMux matches the escaped path. Escaping each segment, and the
	// dots of a "." or ".." segment, which path cleaning would resolve,
	// gives a clean path whose segments unescape to the request's.
	escaped := make([]string, len(segments))
	for index, segment := range segments {
		escaped[index] = escapeRouteSegment(segment)
	}
	probe := &http.Request{Method: r.Method, URL: &url.URL{Path: t.base + "/" + strings.Join(segments, "/"), RawPath: t.base + "/" + strings.Join(escaped, "/")}}
	handler, _ := t.mux.Handler(probe)
	group, ok := handler.(*routeGroup)
	if !ok || group.method != r.Method {
		return nil
	}
	route := group.selectRoute(r)
	if route == nil || (trailingSlash && !route.TrailingSlash) {
		return nil
	}
	for index, segment := range group.segments {
		if name, rest, ok := routePlaceholder(segment); ok {
			value := segments[index]
			if rest {
				value = strings.Join(segments[index:], "/")
			}
			r.SetPathValue(name, value)
		}
	}
	return route
}

// selectRoute returns the group's route that a query in r selects, or the
// route without a query.
func (g *routeGroup) selectRoute(r *http.Request) *apiRoute {
	var plain *apiRoute
	var query url.Values
	for _, route := range g.routes {
		if route.Query == "" {
			plain = route
			continue
		}
		if query == nil {
			query = r.URL.Query()
		}
		if key, value, _ := strings.Cut(route.Query, "="); query.Get(key) == value {
			return route
		}
	}
	return plain
}

// splitRoutePath returns the segments of path below base, without one
// trailing slash, which it reports. It refuses a path outside base and a
// path with an empty segment.
func splitRoutePath(path, base string) (segments []string, trailingSlash, ok bool) {
	rest, found := strings.CutPrefix(path, base+"/")
	if !found {
		return nil, false, false
	}
	if trimmed, cut := strings.CutSuffix(rest, "/"); cut {
		rest, trailingSlash = trimmed, true
	}
	segments = strings.Split(rest, "/")
	for _, segment := range segments {
		if segment == "" {
			return nil, false, false
		}
	}
	return segments, trailingSlash, true
}

func escapeRouteSegment(segment string) string {
	switch segment {
	case ".":
		return "%2E"
	case "..":
		return "%2E%2E"
	}
	return url.PathEscape(segment)
}

// routePlaceholder returns the name of a {name} or {name...} template
// segment, and whether it takes the rest of the path.
func routePlaceholder(segment string) (name string, rest, ok bool) {
	if len(segment) < 3 || segment[0] != '{' || segment[len(segment)-1] != '}' {
		return "", false, false
	}
	name, rest = strings.CutSuffix(segment[1:len(segment)-1], "...")
	return name, rest, name != ""
}

// isMutation reports whether a request method changes state, which needs a
// CSRF token on the console API.
func isMutation(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

// serveRoute runs the gate for a console request and the route's handler.
// route is nil for a request that no route serves. Unauthenticated routes
// are served without a session, after the browser origin check for those
// that change state. Every other request is authenticated read-only, checked
// for its CSRF token when it is a mutation, and refused unless it has a route
// whose permission the session holds; auth.HasPermission also refuses a
// session that must enrol TOTP first everything but its own account.
func (s *Server) serveRoute(w http.ResponseWriter, r *http.Request, route *apiRoute) {
	if route != nil && route.Access == routeUnauthenticated {
		if route.Mutates && !validateBrowserOrigin(r) {
			writeError(w, http.StatusForbidden, "origin", "request origin is not allowed", nil)
			return
		}
		route.Handle(s, w, r, routeCall{})
		return
	}
	// Authentication and ordinary reads are read-only. Background polling and
	// EventSource reconnects must not keep idle sessions alive or contend for
	// SQLite's single writer connection. Real interactions are recorded below,
	// after CSRF and route authorization have succeeded.
	session, ok := s.Auth.AuthenticateReadOnly(r.Context(), r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}
	if isMutation(r.Method) && !s.Auth.CheckCSRF(r, session) {
		writeError(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token", nil)
		return
	}
	permission := auth.PermissionDenied
	if route != nil {
		permission = route.Permission
	}
	if permission == "" || permission == auth.PermissionDenied || !auth.HasPermission(session, permission) {
		details := map[string]string{"permission": permission}
		if permission == auth.PermissionDenied || permission == "" {
			// Keep the internal sentinel out of the public API. Callers only need
			// to know that the route is not authorized, not how the gate stores
			// its fail-closed default.
			details["permission"] = "route"
		}
		writeError(w, http.StatusForbidden, "forbidden", "your account is not allowed to perform this action", details)
		return
	}
	call, ok := s.routeStores(w, r, session, route)
	if !ok {
		return
	}
	if isMutation(r.Method) {
		if err := s.Auth.RecordActivity(r.Context(), session); err != nil {
			// Activity persistence is opportunistic and bounded. It must never
			// delay or fail the user's actual authorized operation.
			s.Log.Debug("session activity timestamp could not be refreshed", "error", err)
		}
	}
	if route.Handle == nil {
		// A NoHandler route keeps its capability mapping for API clients,
		// but nothing serves it.
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found", nil)
		return
	}
	route.Handle(s, w, r, call)
}

// routeStores resolves the stores of an admitted request. Recording
// activity and signing out need no tenant. Every other route reads or
// changes the data of the account's tenant, including the account's own
// routes under /auth/ that change the account, which belongs to the
// tenant. Its store is resolved once, here, from the session. Each handler
// that reads or changes tenant data takes this store; handlers never choose
// a tenant. A platform administrator has no tenant: the gate admits it only
// to its own account's routes, which change that account through the
// platform's store bound to the signed-in account, and to the platform
// routes, which read and change the platform's own data and the business
// units by ID through the platform's store, never a tenant's.
func (s *Server) routeStores(w http.ResponseWriter, r *http.Request, session store.Session, route *apiRoute) (routeCall, bool) {
	call := routeCall{session: session}
	switch {
	case route.NoTenant:
	case session.Role == store.RolePlatformAdmin && route.Permission == auth.PermissionAccountSelf:
		call.account = s.Store.Platform().Account(session.UserID)
	case session.Role == store.RolePlatformAdmin && isPlatformPermission(route.Permission):
	default:
		ts, ok := s.requestTenant(w, r, session)
		if !ok {
			return routeCall{}, false
		}
		call.tenant, call.account = ts, ts
	}
	return call, true
}
