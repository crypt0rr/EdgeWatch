package web

import (
	"net/http"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/auth"
)

// requiredPermission maps an API method and path, relative to /api/v1, to
// the capability a session needs, for the routes that legacyAPI still
// dispatches. Every route it grants must be listed in apiRoutes below; the
// route inventory tests check this function, legacyAPI and its sub-routers
// against that table.
func requiredPermission(path, method string) string {
	switch {
	case strings.HasPrefix(path, "/platform/"):
		return requiredPlatformPermission(path, method)
	case path == "/jobs":
		switch method {
		case http.MethodGet:
			return auth.PermissionJobsRead
		case http.MethodPost:
			return auth.PermissionJobsWrite
		}
	case path == "/jobs/preview" && method == http.MethodPost:
		return auth.PermissionJobsWrite
	}
	if strings.HasPrefix(path, "/jobs/") {
		return requiredJobPermission(path, method)
	}
	return auth.PermissionDenied
}

func routeParts(path, prefix string) ([]string, bool) {
	if path != prefix && !strings.HasPrefix(path, prefix+"/") {
		return nil, false
	}
	rest := strings.Trim(path[len(prefix):], "/")
	if rest == "" {
		return nil, true
	}
	return strings.Split(rest, "/"), true
}

// requiredJobPermission mirrors the explicit grammar in jobRoute. Keeping
// malformed or future nested paths denied is important: a new handler must
// add its route and capability here before it can be reached by a session.
func requiredJobPermission(path, method string) string {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(path, "/jobs/"), "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return auth.PermissionDenied
	}
	switch len(parts) {
	case 1:
		switch method {
		case http.MethodGet:
			return auth.PermissionJobsRead
		case http.MethodPut, http.MethodDelete:
			return auth.PermissionJobsWrite
		default:
			return auth.PermissionDenied
		}
	case 2:
		switch parts[1] {
		case "archive", "restore", "pause", "resume":
			if method == http.MethodPost {
				return auth.PermissionJobsWrite
			}
		case "run":
			if method == http.MethodPost || method == http.MethodDelete {
				return auth.PermissionJobsRun
			}
		case "scan-cycle":
			if method == http.MethodGet {
				return auth.PermissionScansRead
			}
		case "scans":
			if method == http.MethodGet {
				return auth.PermissionScansRead
			}
		case "pending-changes":
			if method == http.MethodGet {
				return auth.PermissionScansRead
			}
		case "incidents":
			if method == http.MethodGet {
				return auth.PermissionIncidentsRead
			}
		case "events":
			if method == http.MethodGet {
				return auth.PermissionScansRead
			}
		case "baseline":
			if method == http.MethodGet {
				return auth.PermissionBaselinesRead
			}
		}
	case 3:
		switch {
		case parts[1] == "scan-cycle" && method == http.MethodDelete:
			return auth.PermissionJobsRun
		case parts[1] == "scans" && method == http.MethodGet:
			return auth.PermissionScansRead
		case parts[1] == "incidents" && (parts[2] == "accept" || parts[2] == "suppress") && method == http.MethodPost:
			return auth.PermissionIncidentsManage
		case parts[1] == "baseline" && (parts[2] == "reset" || parts[2] == "approve") && method == http.MethodPost:
			return auth.PermissionBaselinesManage
		case parts[1] == "baseline" && parts[2] == "hosts" && method == http.MethodGet:
			return auth.PermissionBaselinesRead
		}
	case 4:
		if parts[1] == "scans" && method == http.MethodGet {
			if parts[3] == "hosts" {
				return auth.PermissionHostsRead
			}
			if parts[3] == "results" || parts[3] == "changes" {
				return auth.PermissionScansRead
			}
		}
		if parts[1] == "baseline" && parts[2] == "hosts" && method == http.MethodGet {
			return auth.PermissionBaselinesRead
		}
	case 5:
		if parts[1] == "scans" && parts[3] == "hosts" && method == http.MethodGet {
			return auth.PermissionHostsRead
		}
		if parts[1] == "baseline" && parts[2] == "hosts" && parts[4] == "rdap" && method == http.MethodGet {
			return auth.PermissionBaselinesRead
		}
	case 6:
		if parts[1] == "scans" && parts[3] == "hosts" && parts[5] == "rdap" && method == http.MethodGet {
			return auth.PermissionHostsRead
		}
	}
	return auth.PermissionDenied
}

// requestPermission applies the route matrix and then handles the one
// query-controlled action whose authorization differs from the ordinary
// resource mutation. Keeping this decision next to requiredPermission means
// handlers do not need their own role checks that can drift from the API
// boundary.
func requestPermission(path string, r *http.Request) string {
	permission := requiredPermission(path, r.Method)
	// Only a direct job item supports the permanent-delete query switch. Do
	// not let an unknown nested route opt into the stronger permission.
	if permission != auth.PermissionDenied && isJobItemPath(path) && r.Method == http.MethodDelete && r.URL.Query().Get("permanent") == "true" {
		return auth.PermissionJobsDelete
	}
	return permission
}

func isJobItemPath(path string) bool {
	if !strings.HasPrefix(path, "/jobs/") {
		return false
	}
	rest := strings.Trim(strings.TrimPrefix(path, "/jobs/"), "/")
	return rest != "" && !strings.Contains(rest, "/")
}

func isMutation(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

// routeAccess records which gate a request passes before its handler runs.
type routeAccess int

const (
	// routeSession routes pass session authentication, the CSRF check for
	// mutations, and the requestPermission gate in Server.api.
	routeSession routeAccess = iota
	// routeUnauthenticated routes are dispatched by Server.api before the
	// session gate. requiredPermission returns "" for them, which the gate
	// itself would reject, so they can only be served by that early dispatch.
	// Their state-changing requests are protected by validateBrowserOrigin.
	routeUnauthenticated
	// routePublic routes are served by Server.publicAPI under
	// publicAPIBase. They never consult requiredPermission and may only
	// return explicitly published data.
	routePublic
)

const (
	consoleAPIBase = "/api/v1"
	publicAPIBase  = "/api/public/v1"
)

// apiRoute is one method and path combination that a handler serves.
type apiRoute struct {
	Method string
	// Template is the path relative to the API base, which is also the
	// route's ServeMux pattern. A {name} segment matches exactly one
	// non-empty path segment; a {name...} segment, which must be the last,
	// matches the rest of the path.
	Template string
	// Query, when set, selects a distinct action on the same method and
	// path, with its own capability and handler.
	Query string
	// Permission is the capability the gate requires for the route, or ""
	// for unauthenticated and public routes.
	Permission string
	// Mutates reports whether the method changes state. Session routes that
	// mutate require a CSRF token.
	Mutates bool
	// Example is a concrete path that matches Template, used by the tests.
	Example string
	Access  routeAccess
	// TrailingSlash reports whether the route also answers its path with one
	// trailing slash, as the sub-routers that the table replaced did.
	TrailingSlash bool
	// NoTenant marks a session route whose handler reads and changes no
	// tenant data, so the gate resolves no tenant store for it.
	NoTenant bool
	// Handle serves the route once the gate admitted the request.
	Handle routeHandler
	// NoHandler marks a capability mapping that the gate keeps although
	// nothing serves it. Authorized requests receive the not-found default.
	NoHandler bool
}

// apiRoutes is the route inventory: every method and path that the API
// handlers serve, with the capability requiredPermission assigns to it.
// Tests parse the routing functions and fail when a routed path is missing
// here, and drive the permission matrix from this table, so a new route
// cannot skip authorization tests. Paths that are not listed fail closed.
var apiRoutes = []apiRoute{
	// Entry points dispatched before the session gate.
	{Method: http.MethodGet, Template: "/setup/status", Example: "/setup/status", Access: routeUnauthenticated, Handle: requestHandler((*Server).setupStatus)},
	{Method: http.MethodPost, Template: "/setup", Mutates: true, Example: "/setup", Access: routeUnauthenticated, Handle: requestHandler((*Server).setup)},
	// The platform setup redeems the host's platform setup token.
	{Method: http.MethodPost, Template: "/setup/platform", Mutates: true, Example: "/setup/platform", Access: routeUnauthenticated, Handle: requestHandler((*Server).platformSetup)},
	{Method: http.MethodPost, Template: "/auth/login", Mutates: true, Example: "/auth/login", Access: routeUnauthenticated, Handle: requestHandler((*Server).login)},
	{Method: http.MethodPost, Template: "/auth/activate", Mutates: true, Example: "/auth/activate", Access: routeUnauthenticated, Handle: requestHandler((*Server).activateUser)},
	// The session probe authenticates itself but needs no capability.
	{Method: http.MethodGet, Template: "/auth/session", Example: "/auth/session", Access: routeUnauthenticated, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) { s.withAuth(w, r, s.session) }},

	// Account self-service.
	{Method: http.MethodPost, Template: "/auth/activity", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/activity", NoTenant: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		writeJSON(w, http.StatusNoContent, nil)
	}},
	{Method: http.MethodPost, Template: "/auth/logout", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/logout", NoTenant: true, Handle: sessionHandler((*Server).logout)},
	{Method: http.MethodPut, Template: "/auth/display-name", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/display-name", Handle: accountHandler((*Server).changeDisplayName)},
	{Method: http.MethodPut, Template: "/auth/password", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/password", Handle: accountHandler((*Server).changePassword)},
	{Method: http.MethodPost, Template: "/auth/totp/setup", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/totp/setup", Handle: accountHandler((*Server).totpSetup)},
	{Method: http.MethodPost, Template: "/auth/totp/enable", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/totp/enable", Handle: accountHandler((*Server).totpEnable)},
	{Method: http.MethodPost, Template: "/auth/totp/recovery-codes", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/totp/recovery-codes", Handle: accountHandler((*Server).totpRecoveryCodes)},
	{Method: http.MethodDelete, Template: "/auth/totp", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/totp", Handle: accountHandler((*Server).totpDisable)},
	{Method: http.MethodDelete, Template: "/auth/sessions", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/sessions", Handle: accountHandler((*Server).revokeOwnSessions)},

	// Console status and live updates.
	{Method: http.MethodGet, Template: "/status", Permission: auth.PermissionJobsRead, Example: "/status", Handle: sessionTenantHandler((*Server).adminStatus)},
	{Method: http.MethodGet, Template: "/stream", Permission: auth.PermissionStreamRead, Example: "/stream", Handle: sessionTenantHandler((*Server).stream)},

	// Scanner capabilities and profiles, under both path spellings.
	{Method: http.MethodGet, Template: "/scanner/capabilities", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner/capabilities", Handle: requestHandler((*Server).scannerCapabilities)},
	{Method: http.MethodGet, Template: "/scanner-profiles", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner-profiles", TrailingSlash: true, Handle: tenantHandler((*Server).listScannerProfiles)},
	{Method: http.MethodPost, Template: "/scanner-profiles", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles", TrailingSlash: true, Handle: sessionTenantHandler((*Server).createScannerProfile)},
	{Method: http.MethodPost, Template: "/scanner-profiles/validate", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/validate", TrailingSlash: true, Handle: requestHandler((*Server).validateScannerProfileDraft)},
	{Method: http.MethodPost, Template: "/scanner-profiles/preview", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/preview", TrailingSlash: true, Handle: requestHandler((*Server).renderScannerProfileDraft)},
	{Method: http.MethodGet, Template: "/scanner-profiles/{id}", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner-profiles/profile-1", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.getScannerProfile(w, r, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodPut, Template: "/scanner-profiles/{id}", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/profile-1", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.updateScannerProfile(w, r, c.session, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodDelete, Template: "/scanner-profiles/{id}", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/profile-1", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.setScannerProfileArchived(w, r, c.session, c.tenant, r.PathValue("id"), true)
	}},
	{Method: http.MethodPost, Template: "/scanner-profiles/{id}/restore", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/profile-1/restore", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.setScannerProfileArchived(w, r, c.session, c.tenant, r.PathValue("id"), false)
	}},
	{Method: http.MethodGet, Template: "/scanner-profiles/{id}/revisions", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner-profiles/profile-1/revisions", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.listScannerProfileRevisions(w, r, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodPost, Template: "/scanner-profiles/{id}/validate", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/profile-1/validate", TrailingSlash: true, Handle: requestHandler((*Server).validateScannerProfile)},
	{Method: http.MethodPost, Template: "/scanner-profiles/{id}/preview", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/profile-1/preview", TrailingSlash: true, Handle: requestHandler((*Server).previewScannerProfile)},
	{Method: http.MethodGet, Template: "/scanner/profiles", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner/profiles", TrailingSlash: true, Handle: tenantHandler((*Server).listScannerProfiles)},
	{Method: http.MethodPost, Template: "/scanner/profiles", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner/profiles", TrailingSlash: true, Handle: sessionTenantHandler((*Server).createScannerProfile)},
	{Method: http.MethodPost, Template: "/scanner/profiles/validate", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner/profiles/validate", TrailingSlash: true, Handle: requestHandler((*Server).validateScannerProfileDraft)},
	{Method: http.MethodPost, Template: "/scanner/profiles/preview", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner/profiles/preview", TrailingSlash: true, Handle: requestHandler((*Server).renderScannerProfileDraft)},
	{Method: http.MethodGet, Template: "/scanner/profiles/{id}", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner/profiles/profile-1", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.getScannerProfile(w, r, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodPut, Template: "/scanner/profiles/{id}", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner/profiles/profile-1", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.updateScannerProfile(w, r, c.session, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodDelete, Template: "/scanner/profiles/{id}", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner/profiles/profile-1", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.setScannerProfileArchived(w, r, c.session, c.tenant, r.PathValue("id"), true)
	}},
	{Method: http.MethodPost, Template: "/scanner/profiles/{id}/restore", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner/profiles/profile-1/restore", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.setScannerProfileArchived(w, r, c.session, c.tenant, r.PathValue("id"), false)
	}},
	{Method: http.MethodGet, Template: "/scanner/profiles/{id}/revisions", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner/profiles/profile-1/revisions", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.listScannerProfileRevisions(w, r, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodPost, Template: "/scanner/profiles/{id}/validate", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner/profiles/profile-1/validate", TrailingSlash: true, Handle: requestHandler((*Server).validateScannerProfile)},
	{Method: http.MethodPost, Template: "/scanner/profiles/{id}/preview", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner/profiles/profile-1/preview", TrailingSlash: true, Handle: requestHandler((*Server).previewScannerProfile)},

	// User administration.
	{Method: http.MethodGet, Template: "/users", Permission: auth.PermissionUsersManage, Example: "/users", TrailingSlash: true, Handle: tenantHandler((*Server).listUsers)},
	{Method: http.MethodPost, Template: "/users", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users", TrailingSlash: true, Handle: sessionTenantHandler((*Server).createUser)},
	{Method: http.MethodGet, Template: "/users/{id}", Permission: auth.PermissionUsersManage, Example: "/users/user-1", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.getUser(w, r, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodPatch, Template: "/users/{id}", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users/user-1", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.updateUser(w, r, c.session, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodPost, Template: "/users/{id}/activation", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users/user-1/activation", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.issueAccountLink(w, r, c.session, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodDelete, Template: "/users/{id}/activation", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users/user-1/activation", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.revokeActivation(w, r, c.session, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodPost, Template: "/users/{id}/password-reset", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users/user-1/password-reset", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.issueAccountLink(w, r, c.session, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodDelete, Template: "/users/{id}/sessions", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users/user-1/sessions", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.revokeUserSessions(w, r, c.session, c.tenant, r.PathValue("id"))
	}},

	// Public status publication settings.
	{Method: http.MethodGet, Template: "/public-dashboard", Permission: auth.PermissionPublicManage, Example: "/public-dashboard", Handle: tenantHandler((*Server).getPublicDashboard)},
	{Method: http.MethodPut, Template: "/public-dashboard", Permission: auth.PermissionPublicManage, Mutates: true, Example: "/public-dashboard", Handle: sessionTenantHandler((*Server).savePublicDashboard)},

	// Notifications.
	{Method: http.MethodPost, Template: "/notifications/test", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/test", Handle: sessionTenantHandler((*Server).notificationTest)},
	{Method: http.MethodGet, Template: "/notifications/options", Permission: auth.PermissionNotificationOptions, Example: "/notifications/options", Handle: tenantHandler((*Server).listNotificationDestinations)},
	{Method: http.MethodPut, Template: "/notifications/update-routing", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/update-routing", Handle: sessionTenantHandler((*Server).updateNotificationRouting)},
	{Method: http.MethodPatch, Template: "/notifications/update-routing", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/update-routing", Handle: sessionTenantHandler((*Server).toggleNotificationUpdateRouting)},
	{Method: http.MethodPut, Template: "/notifications/incident-reminders", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/incident-reminders", Handle: sessionTenantHandler((*Server).updateIncidentReminders)},
	{Method: http.MethodGet, Template: "/notifications/destinations", Permission: auth.PermissionNotificationOptions, Example: "/notifications/destinations", Handle: tenantHandler((*Server).listNotificationDestinations)},
	{Method: http.MethodPost, Template: "/notifications/destinations", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/destinations", Handle: sessionTenantHandler((*Server).createNotificationDestination)},
	{Method: http.MethodGet, Template: "/notifications/destinations/{id}", Permission: auth.PermissionNotificationOptions, Example: "/notifications/destinations/destination-1", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.getNotificationDestination(w, r, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodPut, Template: "/notifications/destinations/{id}", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/destinations/destination-1", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.updateNotificationDestination(w, r, c.session, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodDelete, Template: "/notifications/destinations/{id}", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/destinations/destination-1", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.deleteNotificationDestination(w, r, c.session, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodPost, Template: "/notifications/destinations/{id}/test", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/destinations/destination-1/test", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.testNotificationDestination(w, r, c.session, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodGet, Template: "/notifications/destinations/{id}/deliveries", Permission: auth.PermissionNotificationsManage, Example: "/notifications/destinations/destination-1/deliveries", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.listTerminalDeliveries(w, r, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodPost, Template: "/notifications/destinations/{id}/deliveries/redeliver", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/destinations/destination-1/deliveries/redeliver", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.redeliverTerminalDeliveries(w, r, c.session, c.tenant, r.PathValue("id"))
	}},

	// Global inventories.
	{Method: http.MethodGet, Template: "/hosts", Permission: auth.PermissionHostsRead, Example: "/hosts", Handle: tenantHandler((*Server).listHosts)},
	{Method: http.MethodGet, Template: "/incidents", Permission: auth.PermissionIncidentsRead, Example: "/incidents", Handle: tenantHandler((*Server).listIncidents)},
	{Method: http.MethodGet, Template: "/events", Permission: auth.PermissionScansRead, Example: "/events", Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.listEvents(w, r, c.tenant, r.URL.Query().Get("job"))
	}},

	// Scans.
	{Method: http.MethodGet, Template: "/scans", Permission: auth.PermissionScansRead, Example: "/scans", Handle: tenantHandler((*Server).listScans)},
	{Method: http.MethodPost, Template: "/scans", Permission: auth.PermissionJobsRun, Mutates: true, Example: "/scans", NoHandler: true},
	{Method: http.MethodGet, Template: "/scans/active", Permission: auth.PermissionScansRead, Example: "/scans/active", Handle: tenantHandler((*Server).activeScans)},
	{Method: http.MethodGet, Template: "/scans/{id}", Permission: auth.PermissionScansRead, Example: "/scans/scan-1", Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.getScan(w, r, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodGet, Template: "/scans/{id}/summary", Permission: auth.PermissionScansRead, Example: "/scans/scan-1/summary", Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.getScanSummary(w, r, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodPost, Template: "/scans/{id}/cancel", Permission: auth.PermissionJobsRun, Mutates: true, Example: "/scans/scan-1/cancel", Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.cancelScan(w, r, c.session, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodGet, Template: "/scans/{id}/hosts", Permission: auth.PermissionHostsRead, Example: "/scans/scan-1/hosts", Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.scanHostsRoute(w, r, c.tenant, r.PathValue("id"))
	}},
	{Method: http.MethodGet, Template: "/scans/{id}/hosts/{address}", Permission: auth.PermissionHostsRead, Example: "/scans/scan-1/hosts/198.51.100.10", Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.scanHostRoute(w, r, c.tenant, r.PathValue("id"), r.PathValue("address"))
	}},
	{Method: http.MethodGet, Template: "/scans/{id}/hosts/{address}/rdap", Permission: auth.PermissionHostsRead, Example: "/scans/scan-1/hosts/198.51.100.10/rdap", Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.scanHostRDAPRoute(w, r, c.tenant, r.PathValue("id"), r.PathValue("address"))
	}},

	// Jobs.
	{Method: http.MethodGet, Template: "/jobs", Permission: auth.PermissionJobsRead, Example: "/jobs"},
	{Method: http.MethodPost, Template: "/jobs", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs"},
	{Method: http.MethodPost, Template: "/jobs/preview", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs/preview"},
	{Method: http.MethodGet, Template: "/jobs/schedule-suggestion", Permission: auth.PermissionJobsRead, Example: "/jobs/schedule-suggestion"},
	{Method: http.MethodGet, Template: "/jobs/{id}", Permission: auth.PermissionJobsRead, Example: "/jobs/job-1"},
	{Method: http.MethodPut, Template: "/jobs/{id}", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs/job-1"},
	{Method: http.MethodDelete, Template: "/jobs/{id}", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs/job-1"},
	{Method: http.MethodDelete, Template: "/jobs/{id}", Query: "permanent=true", Permission: auth.PermissionJobsDelete, Mutates: true, Example: "/jobs/job-1"},
	{Method: http.MethodPost, Template: "/jobs/{id}/archive", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs/job-1/archive"},
	{Method: http.MethodPost, Template: "/jobs/{id}/restore", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs/job-1/restore"},
	{Method: http.MethodPost, Template: "/jobs/{id}/pause", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs/job-1/pause"},
	{Method: http.MethodPost, Template: "/jobs/{id}/resume", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs/job-1/resume"},
	{Method: http.MethodPost, Template: "/jobs/{id}/run", Permission: auth.PermissionJobsRun, Mutates: true, Example: "/jobs/job-1/run"},
	{Method: http.MethodDelete, Template: "/jobs/{id}/run", Permission: auth.PermissionJobsRun, Mutates: true, Example: "/jobs/job-1/run"},
	{Method: http.MethodGet, Template: "/jobs/{id}/scan-cycle", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/scan-cycle"},
	{Method: http.MethodDelete, Template: "/jobs/{id}/scan-cycle/{cycle}", Permission: auth.PermissionJobsRun, Mutates: true, Example: "/jobs/job-1/scan-cycle/cycle-1"},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/scans"},
	{Method: http.MethodGet, Template: "/jobs/{id}/pending-changes", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/pending-changes"},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans/latest-successful", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/scans/latest-successful"},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans/{scan}", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/scans/scan-1"},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans/{scan}/results", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/scans/scan-1/results"},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans/{scan}/changes", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/scans/scan-1/changes"},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans/{scan}/hosts", Permission: auth.PermissionHostsRead, Example: "/jobs/job-1/scans/scan-1/hosts"},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans/{scan}/hosts/{address}", Permission: auth.PermissionHostsRead, Example: "/jobs/job-1/scans/scan-1/hosts/2001:db8::1"},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans/{scan}/hosts/{address}/rdap", Permission: auth.PermissionHostsRead, Example: "/jobs/job-1/scans/scan-1/hosts/2001:db8::1/rdap"},
	{Method: http.MethodGet, Template: "/jobs/{id}/baseline", Permission: auth.PermissionBaselinesRead, Example: "/jobs/job-1/baseline"},
	{Method: http.MethodPost, Template: "/jobs/{id}/baseline/reset", Permission: auth.PermissionBaselinesManage, Mutates: true, Example: "/jobs/job-1/baseline/reset"},
	{Method: http.MethodPost, Template: "/jobs/{id}/baseline/approve", Permission: auth.PermissionBaselinesManage, Mutates: true, Example: "/jobs/job-1/baseline/approve"},
	{Method: http.MethodGet, Template: "/jobs/{id}/baseline/hosts", Permission: auth.PermissionBaselinesRead, Example: "/jobs/job-1/baseline/hosts"},
	{Method: http.MethodGet, Template: "/jobs/{id}/baseline/hosts/{address}", Permission: auth.PermissionBaselinesRead, Example: "/jobs/job-1/baseline/hosts/198.51.100.1"},
	{Method: http.MethodGet, Template: "/jobs/{id}/baseline/hosts/{address}/rdap", Permission: auth.PermissionBaselinesRead, Example: "/jobs/job-1/baseline/hosts/198.51.100.1/rdap"},
	{Method: http.MethodGet, Template: "/jobs/{id}/incidents", Permission: auth.PermissionIncidentsRead, Example: "/jobs/job-1/incidents"},
	{Method: http.MethodPost, Template: "/jobs/{id}/incidents/accept", Permission: auth.PermissionIncidentsManage, Mutates: true, Example: "/jobs/job-1/incidents/accept"},
	{Method: http.MethodPost, Template: "/jobs/{id}/incidents/suppress", Permission: auth.PermissionIncidentsManage, Mutates: true, Example: "/jobs/job-1/incidents/suppress"},
	{Method: http.MethodGet, Template: "/jobs/{id}/events", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/events"},

	// The unit's security audit, for its administrators.
	{Method: http.MethodGet, Template: "/audit", Permission: auth.PermissionAuditRead, Example: "/audit", Handle: tenantHandler((*Server).unitAudit)},

	// The platform console, for platform administrators: the business
	// units, their administrators and capacity, the platform
	// administrators, the platform audit, the platform's notification
	// destinations and update routing, and the deployment status.
	{Method: http.MethodGet, Template: "/platform/units", Permission: auth.PermissionUnitsManage, Example: "/platform/units"},
	{Method: http.MethodPost, Template: "/platform/units", Permission: auth.PermissionUnitsManage, Mutates: true, Example: "/platform/units"},
	{Method: http.MethodGet, Template: "/platform/units/{id}", Permission: auth.PermissionUnitsManage, Example: "/platform/units/unit-1"},
	{Method: http.MethodPatch, Template: "/platform/units/{id}", Permission: auth.PermissionUnitsManage, Mutates: true, Example: "/platform/units/unit-1"},
	{Method: http.MethodDelete, Template: "/platform/units/{id}", Permission: auth.PermissionUnitsManage, Mutates: true, Example: "/platform/units/unit-1"},
	{Method: http.MethodPost, Template: "/platform/units/{id}/disable", Permission: auth.PermissionUnitsManage, Mutates: true, Example: "/platform/units/unit-1/disable"},
	{Method: http.MethodPost, Template: "/platform/units/{id}/enable", Permission: auth.PermissionUnitsManage, Mutates: true, Example: "/platform/units/unit-1/enable"},
	{Method: http.MethodGet, Template: "/platform/units/{id}/capacity", Permission: auth.PermissionUnitsManage, Example: "/platform/units/unit-1/capacity"},
	{Method: http.MethodPatch, Template: "/platform/units/{id}/capacity", Permission: auth.PermissionUnitsManage, Mutates: true, Example: "/platform/units/unit-1/capacity"},
	{Method: http.MethodGet, Template: "/platform/units/{id}/accounts", Permission: auth.PermissionUnitAccountsManage, Example: "/platform/units/unit-1/accounts"},
	{Method: http.MethodPost, Template: "/platform/units/{id}/accounts", Permission: auth.PermissionUnitAccountsManage, Mutates: true, Example: "/platform/units/unit-1/accounts"},
	{Method: http.MethodPost, Template: "/platform/units/{id}/accounts/{uid}/password-reset", Permission: auth.PermissionUnitAccountsManage, Mutates: true, Example: "/platform/units/unit-1/accounts/user-1/password-reset"},
	{Method: http.MethodDelete, Template: "/platform/units/{id}/accounts/{uid}/sessions", Permission: auth.PermissionUnitAccountsManage, Mutates: true, Example: "/platform/units/unit-1/accounts/user-1/sessions"},
	{Method: http.MethodGet, Template: "/platform/admins", Permission: auth.PermissionUnitAccountsManage, Example: "/platform/admins"},
	{Method: http.MethodPost, Template: "/platform/admins", Permission: auth.PermissionUnitAccountsManage, Mutates: true, Example: "/platform/admins"},
	{Method: http.MethodPatch, Template: "/platform/admins/{id}", Permission: auth.PermissionUnitAccountsManage, Mutates: true, Example: "/platform/admins/user-1"},
	{Method: http.MethodDelete, Template: "/platform/admins/{id}", Permission: auth.PermissionUnitAccountsManage, Mutates: true, Example: "/platform/admins/user-1"},
	{Method: http.MethodPost, Template: "/platform/admins/{id}/activation", Permission: auth.PermissionUnitAccountsManage, Mutates: true, Example: "/platform/admins/user-1/activation"},
	{Method: http.MethodDelete, Template: "/platform/admins/{id}/activation", Permission: auth.PermissionUnitAccountsManage, Mutates: true, Example: "/platform/admins/user-1/activation"},
	{Method: http.MethodGet, Template: "/platform/audit", Permission: auth.PermissionPlatformAuditRead, Example: "/platform/audit"},
	{Method: http.MethodGet, Template: "/platform/notifications", Permission: auth.PermissionPlatformNotificationsManage, Example: "/platform/notifications"},
	{Method: http.MethodPost, Template: "/platform/notifications", Permission: auth.PermissionPlatformNotificationsManage, Mutates: true, Example: "/platform/notifications"},
	{Method: http.MethodPut, Template: "/platform/notifications/update-routing", Permission: auth.PermissionPlatformNotificationsManage, Mutates: true, Example: "/platform/notifications/update-routing"},
	{Method: http.MethodPatch, Template: "/platform/notifications/update-routing", Permission: auth.PermissionPlatformNotificationsManage, Mutates: true, Example: "/platform/notifications/update-routing"},
	{Method: http.MethodPatch, Template: "/platform/notifications/{id}", Permission: auth.PermissionPlatformNotificationsManage, Mutates: true, Example: "/platform/notifications/destination-1"},
	{Method: http.MethodDelete, Template: "/platform/notifications/{id}", Permission: auth.PermissionPlatformNotificationsManage, Mutates: true, Example: "/platform/notifications/destination-1"},
	{Method: http.MethodGet, Template: "/platform/status", Permission: auth.PermissionPlatformStatusRead, Example: "/platform/status"},

	// Unauthenticated public status projection, relative to publicAPIBase:
	// the default business unit's page, and a unit's page by its slug.
	// Server.publicAPI also accepts one trailing slash.
	{Method: http.MethodGet, Template: "/dashboard", Example: "/dashboard", Access: routePublic, TrailingSlash: true},
	{Method: http.MethodGet, Template: "/dashboard/{slug...}", Example: "/dashboard/default", Access: routePublic, TrailingSlash: true},
}
