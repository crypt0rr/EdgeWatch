package web

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// routePermission returns the capability that the console API requires for
// method and path, relative to /api/v1, without a query: the permission of
// the route that serves them, "" for an unauthenticated route, and
// auth.PermissionDenied when no route does.
func routePermission(path, method string) string {
	return routeRequestPermission(path, &http.Request{Method: method, URL: &url.URL{}})
}

// routeRequestPermission is routePermission for a request, whose method and
// query select the route; path replaces the request's path.
func routeRequestPermission(path string, r *http.Request) string {
	target := *r.URL
	target.Path, target.RawPath = consoleAPIBase+path, ""
	request := &http.Request{Method: r.Method, URL: &target}
	if route := consoleRoutes.match(request); route != nil {
		return route.Permission
	}
	return auth.PermissionDenied
}

// serveRouteAs serves path, relative to /api/v1, with the handler of the
// route that serves it, as the session and with ts as its tenant's and
// account's store. It skips the rest of the gate, as the tests of the
// handlers did when they called the sub-routers that the route table
// replaced, and answers a path that no route serves as the gate does.
func (s *Server) serveRouteAs(w http.ResponseWriter, r *http.Request, path string, session store.Session, ts *store.TenantStore) {
	target := *r.URL
	target.Path, target.RawPath = consoleAPIBase+path, ""
	request := r.WithContext(r.Context())
	request.URL = &target
	route := consoleRoutes.match(request)
	if route == nil || route.Handle == nil {
		forbiddenRoute(w)
		return
	}
	call := routeCall{session: session, tenant: ts}
	if ts != nil {
		call.account = ts
	}
	route.Handle(s, w, request, call)
}

// scannerProfilesRoute serves rest, the path after /scanner-profiles/,
// through serveRouteAs.
func (s *Server) scannerProfilesRoute(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, rest string) {
	s.serveRouteAs(w, r, "/scanner-profiles/"+strings.TrimPrefix(rest, "/"), session, ts)
}

// usersRoute serves rest, the path after /users/, through serveRouteAs.
func (s *Server) usersRoute(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, rest string) {
	s.serveRouteAs(w, r, "/users/"+strings.TrimPrefix(rest, "/"), session, ts)
}

// notificationDestinationRoute serves rest, the path after
// /notifications/destinations/, through serveRouteAs.
func (s *Server) notificationDestinationRoute(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, rest string) {
	s.serveRouteAs(w, r, "/notifications/destinations/"+rest, session, ts)
}

// publicDashboardRoute serves the request's method on /public-dashboard
// through serveRouteAs.
func (s *Server) publicDashboardRoute(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore) {
	s.serveRouteAs(w, r, "/public-dashboard", session, ts)
}

// jobRoute serves rest, the path after /jobs/, through serveRouteAs.
func (s *Server) jobRoute(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, rest string) {
	s.serveRouteAs(w, r, "/jobs/"+rest, session, ts)
}

// platformRoute serves rest, the path after /platform/, through
// serveRouteAs.
func (s *Server) platformRoute(w http.ResponseWriter, r *http.Request, session store.Session, rest string) {
	s.serveRouteAs(w, r, "/platform/"+rest, session, nil)
}
