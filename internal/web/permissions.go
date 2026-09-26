package web

import (
	"net/http"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/auth"
)

// requiredPermission maps an API method and path, relative to /api/v1, to
// the capability a session needs. Every route it grants must be listed in
// apiRoutes below; the route inventory tests check this function,
// Server.api and its sub-routers against that table.
func requiredPermission(path, method string) string {
	// These are the only routes intentionally reachable without a capability.
	// Keep the list exact so an accidentally added /auth/* endpoint cannot
	// silently become an authorization exemption.
	if (path == "/setup/status" && method == http.MethodGet) ||
		(path == "/setup" && method == http.MethodPost) ||
		(path == "/auth/login" && method == http.MethodPost) ||
		(path == "/auth/activate" && method == http.MethodPost) ||
		(path == "/auth/session" && method == http.MethodGet) {
		return ""
	}
	if strings.HasPrefix(path, "/auth/") {
		switch {
		case path == "/auth/logout" && method == http.MethodPost,
			path == "/auth/activity" && method == http.MethodPost,
			path == "/auth/display-name" && method == http.MethodPut,
			path == "/auth/password" && method == http.MethodPut,
			path == "/auth/totp/setup" && method == http.MethodPost,
			path == "/auth/totp/enable" && method == http.MethodPost,
			path == "/auth/totp/recovery-codes" && method == http.MethodPost,
			path == "/auth/totp" && method == http.MethodDelete,
			path == "/auth/sessions" && method == http.MethodDelete:
			return auth.PermissionAccountSelf
		}
	}
	switch {
	case path == "/status":
		if method == http.MethodGet {
			// Every authenticated console role needs the small version status;
			// adminStatus returns only version/update fields to viewers.
			return auth.PermissionJobsRead
		}
	case path == "/scanner/capabilities":
		if method == http.MethodGet {
			return auth.PermissionScannerProfilesRead
		}
	case isScannerProfilesPath(path):
		return requiredScannerProfilePermission(path, method)
	case path == "/stream":
		if method == http.MethodGet {
			return auth.PermissionStreamRead
		}
	case path == "/notifications/test":
		if method == http.MethodPost {
			return auth.PermissionNotificationsManage
		}
	case strings.HasPrefix(path, "/notifications/destinations/"):
		return requiredNotificationDestinationPermission(path, method)
	case path == "/notifications/destinations":
		switch method {
		case http.MethodGet:
			return auth.PermissionNotificationOptions
		case http.MethodPost:
			return auth.PermissionNotificationsManage
		}
	case path == "/notifications/options":
		if method == http.MethodGet {
			return auth.PermissionNotificationOptions
		}
	case path == "/notifications/update-routing":
		if method == http.MethodPut {
			return auth.PermissionNotificationsManage
		}
	case isUsersPath(path):
		return requiredUsersPermission(path, method)
	case path == "/public-dashboard":
		if method == http.MethodGet || method == http.MethodPut {
			return auth.PermissionPublicManage
		}
	case path == "/scans" || path == "/scans/active" || strings.HasPrefix(path, "/scans/"):
		return requiredScanPermission(path, method)
	case path == "/hosts":
		if method == http.MethodGet {
			return auth.PermissionHostsRead
		}
	case path == "/incidents":
		if method == http.MethodGet {
			return auth.PermissionIncidentsRead
		}
	case path == "/events":
		if method == http.MethodGet {
			return auth.PermissionScansRead
		}
	case path == "/jobs":
		switch method {
		case http.MethodGet:
			return auth.PermissionJobsRead
		case http.MethodPost:
			return auth.PermissionJobsWrite
		}
	}
	if strings.HasPrefix(path, "/jobs/") {
		return requiredJobPermission(path, method)
	}
	return auth.PermissionDenied
}

// isScannerProfilesPath and isUsersPath keep the route matrix in lockstep
// with the prefixes handled by api. A prefix match alone is not sufficient:
// the corresponding helper validates the rest of the path grammar.
func isScannerProfilesPath(path string) bool {
	for _, prefix := range []string{"/scanner-profiles", "/scanner/profiles"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func isUsersPath(path string) bool {
	return path == "/users" || strings.HasPrefix(path, "/users/")
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

func requiredScannerProfilePermission(path, method string) string {
	prefix := "/scanner-profiles"
	if strings.HasPrefix(path, "/scanner/profiles") {
		prefix = "/scanner/profiles"
	}
	parts, ok := routeParts(path, prefix)
	if !ok {
		return auth.PermissionDenied
	}
	switch len(parts) {
	case 0:
		switch method {
		case http.MethodGet:
			return auth.PermissionScannerProfilesRead
		case http.MethodPost:
			return auth.PermissionScannerProfilesManage
		}
	case 1:
		if (parts[0] == "validate" || parts[0] == "preview") && method == http.MethodPost {
			return auth.PermissionScannerProfilesManage
		}
		switch method {
		case http.MethodGet:
			return auth.PermissionScannerProfilesRead
		case http.MethodPut, http.MethodDelete:
			return auth.PermissionScannerProfilesManage
		}
	case 2:
		if parts[1] == "revisions" && method == http.MethodGet {
			return auth.PermissionScannerProfilesRead
		}
		if (parts[1] == "restore" || parts[1] == "validate" || parts[1] == "preview") && method == http.MethodPost {
			return auth.PermissionScannerProfilesManage
		}
	}
	return auth.PermissionDenied
}

func requiredUsersPermission(path, method string) string {
	parts, ok := routeParts(path, "/users")
	if !ok {
		return auth.PermissionDenied
	}
	switch len(parts) {
	case 0:
		if method == http.MethodGet || method == http.MethodPost {
			return auth.PermissionUsersManage
		}
	case 1:
		if method == http.MethodGet || method == http.MethodPatch {
			return auth.PermissionUsersManage
		}
	case 2:
		switch parts[1] {
		case "activation":
			if method == http.MethodPost || method == http.MethodDelete {
				return auth.PermissionUsersManage
			}
		case "password-reset":
			if method == http.MethodPost {
				return auth.PermissionUsersManage
			}
		case "sessions":
			if method == http.MethodDelete {
				return auth.PermissionUsersManage
			}
		}
	}
	return auth.PermissionDenied
}

func requiredNotificationDestinationPermission(path, method string) string {
	parts, ok := routeParts(path, "/notifications/destinations")
	if !ok || len(parts) == 0 {
		return auth.PermissionDenied
	}
	if len(parts) == 1 {
		switch method {
		case http.MethodGet:
			return auth.PermissionNotificationOptions
		case http.MethodPut, http.MethodDelete:
			return auth.PermissionNotificationsManage
		}
	}
	if len(parts) == 2 && parts[1] == "test" && method == http.MethodPost {
		return auth.PermissionNotificationsManage
	}
	return auth.PermissionDenied
}

func requiredScanPermission(path, method string) string {
	switch path {
	case "/scans":
		switch method {
		case http.MethodGet:
			return auth.PermissionScansRead
		case http.MethodPost:
			// Retain the historical capability mapping for API clients even
			// though the current router has no POST /scans handler.
			return auth.PermissionJobsRun
		}
		return auth.PermissionDenied
	case "/scans/active":
		if method == http.MethodGet {
			return auth.PermissionScansRead
		}
		return auth.PermissionDenied
	}
	parts, ok := routeParts(path, "/scans")
	if !ok || len(parts) == 0 {
		return auth.PermissionDenied
	}
	switch len(parts) {
	case 1:
		if method == http.MethodGet {
			return auth.PermissionScansRead
		}
	case 2:
		if parts[1] == "cancel" && method == http.MethodPost {
			return auth.PermissionJobsRun
		}
		if parts[1] == "summary" && method == http.MethodGet {
			return auth.PermissionScansRead
		}
		if parts[1] == "hosts" && method == http.MethodGet {
			return auth.PermissionHostsRead
		}
	case 3:
		if parts[1] == "hosts" && method == http.MethodGet {
			return auth.PermissionHostsRead
		}
	case 4:
		if parts[1] == "hosts" && parts[3] == "rdap" && method == http.MethodGet {
			return auth.PermissionHostsRead
		}
	}
	return auth.PermissionDenied
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
			if method == http.MethodPost {
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
	// Template is the path relative to the API base. A {name} segment
	// matches exactly one non-empty path segment.
	Template string
	// Query, when set, selects a distinct action on the same method and
	// path, and requestPermission maps it to a different capability.
	Query string
	// Permission is what requestPermission returns for the route: a
	// capability, or "" for unauthenticated and public routes.
	Permission string
	// Mutates reports whether the method changes state. Session routes that
	// mutate require a CSRF token.
	Mutates bool
	// Example is a concrete path that matches Template, used by the tests.
	Example string
	Access  routeAccess
	// NoHandler marks a capability mapping that requiredPermission keeps
	// although Server.api has no handler for it. Authorized requests receive
	// the not-found default.
	NoHandler bool
}

// apiRoutes is the route inventory: every method and path that the API
// handlers serve, with the capability requiredPermission assigns to it.
// Tests parse the routing functions and fail when a routed path is missing
// here, and drive the permission matrix from this table, so a new route
// cannot skip authorization tests. Paths that are not listed fail closed.
var apiRoutes = []apiRoute{
	// Entry points dispatched before the session gate.
	{Method: http.MethodGet, Template: "/setup/status", Example: "/setup/status", Access: routeUnauthenticated},
	{Method: http.MethodPost, Template: "/setup", Mutates: true, Example: "/setup", Access: routeUnauthenticated},
	{Method: http.MethodPost, Template: "/auth/login", Mutates: true, Example: "/auth/login", Access: routeUnauthenticated},
	{Method: http.MethodPost, Template: "/auth/activate", Mutates: true, Example: "/auth/activate", Access: routeUnauthenticated},
	// The session probe authenticates itself but needs no capability.
	{Method: http.MethodGet, Template: "/auth/session", Example: "/auth/session", Access: routeUnauthenticated},

	// Account self-service.
	{Method: http.MethodPost, Template: "/auth/activity", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/activity"},
	{Method: http.MethodPost, Template: "/auth/logout", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/logout"},
	{Method: http.MethodPut, Template: "/auth/display-name", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/display-name"},
	{Method: http.MethodPut, Template: "/auth/password", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/password"},
	{Method: http.MethodPost, Template: "/auth/totp/setup", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/totp/setup"},
	{Method: http.MethodPost, Template: "/auth/totp/enable", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/totp/enable"},
	{Method: http.MethodPost, Template: "/auth/totp/recovery-codes", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/totp/recovery-codes"},
	{Method: http.MethodDelete, Template: "/auth/totp", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/totp"},
	{Method: http.MethodDelete, Template: "/auth/sessions", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/sessions"},

	// Console status and live updates.
	{Method: http.MethodGet, Template: "/status", Permission: auth.PermissionJobsRead, Example: "/status"},
	{Method: http.MethodGet, Template: "/stream", Permission: auth.PermissionStreamRead, Example: "/stream"},

	// Scanner capabilities and profiles, under both path spellings.
	{Method: http.MethodGet, Template: "/scanner/capabilities", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner/capabilities"},
	{Method: http.MethodGet, Template: "/scanner-profiles", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner-profiles"},
	{Method: http.MethodPost, Template: "/scanner-profiles", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles"},
	{Method: http.MethodPost, Template: "/scanner-profiles/validate", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/validate"},
	{Method: http.MethodPost, Template: "/scanner-profiles/preview", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/preview"},
	{Method: http.MethodGet, Template: "/scanner-profiles/{id}", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner-profiles/profile-1"},
	{Method: http.MethodPut, Template: "/scanner-profiles/{id}", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/profile-1"},
	{Method: http.MethodDelete, Template: "/scanner-profiles/{id}", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/profile-1"},
	{Method: http.MethodPost, Template: "/scanner-profiles/{id}/restore", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/profile-1/restore"},
	{Method: http.MethodGet, Template: "/scanner-profiles/{id}/revisions", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner-profiles/profile-1/revisions"},
	{Method: http.MethodPost, Template: "/scanner-profiles/{id}/validate", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/profile-1/validate"},
	{Method: http.MethodPost, Template: "/scanner-profiles/{id}/preview", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/profile-1/preview"},
	{Method: http.MethodGet, Template: "/scanner/profiles", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner/profiles"},
	{Method: http.MethodPost, Template: "/scanner/profiles", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner/profiles"},
	{Method: http.MethodPost, Template: "/scanner/profiles/validate", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner/profiles/validate"},
	{Method: http.MethodPost, Template: "/scanner/profiles/preview", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner/profiles/preview"},
	{Method: http.MethodGet, Template: "/scanner/profiles/{id}", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner/profiles/profile-1"},
	{Method: http.MethodPut, Template: "/scanner/profiles/{id}", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner/profiles/profile-1"},
	{Method: http.MethodDelete, Template: "/scanner/profiles/{id}", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner/profiles/profile-1"},
	{Method: http.MethodPost, Template: "/scanner/profiles/{id}/restore", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner/profiles/profile-1/restore"},
	{Method: http.MethodGet, Template: "/scanner/profiles/{id}/revisions", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner/profiles/profile-1/revisions"},
	{Method: http.MethodPost, Template: "/scanner/profiles/{id}/validate", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner/profiles/profile-1/validate"},
	{Method: http.MethodPost, Template: "/scanner/profiles/{id}/preview", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner/profiles/profile-1/preview"},

	// User administration.
	{Method: http.MethodGet, Template: "/users", Permission: auth.PermissionUsersManage, Example: "/users"},
	{Method: http.MethodPost, Template: "/users", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users"},
	{Method: http.MethodGet, Template: "/users/{id}", Permission: auth.PermissionUsersManage, Example: "/users/user-1"},
	{Method: http.MethodPatch, Template: "/users/{id}", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users/user-1"},
	{Method: http.MethodPost, Template: "/users/{id}/activation", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users/user-1/activation"},
	{Method: http.MethodDelete, Template: "/users/{id}/activation", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users/user-1/activation"},
	{Method: http.MethodPost, Template: "/users/{id}/password-reset", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users/user-1/password-reset"},
	{Method: http.MethodDelete, Template: "/users/{id}/sessions", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users/user-1/sessions"},

	// Public status publication settings.
	{Method: http.MethodGet, Template: "/public-dashboard", Permission: auth.PermissionPublicManage, Example: "/public-dashboard"},
	{Method: http.MethodPut, Template: "/public-dashboard", Permission: auth.PermissionPublicManage, Mutates: true, Example: "/public-dashboard"},

	// Notifications.
	{Method: http.MethodPost, Template: "/notifications/test", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/test"},
	{Method: http.MethodGet, Template: "/notifications/options", Permission: auth.PermissionNotificationOptions, Example: "/notifications/options"},
	{Method: http.MethodPut, Template: "/notifications/update-routing", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/update-routing"},
	{Method: http.MethodGet, Template: "/notifications/destinations", Permission: auth.PermissionNotificationOptions, Example: "/notifications/destinations"},
	{Method: http.MethodPost, Template: "/notifications/destinations", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/destinations"},
	{Method: http.MethodGet, Template: "/notifications/destinations/{id}", Permission: auth.PermissionNotificationOptions, Example: "/notifications/destinations/destination-1"},
	{Method: http.MethodPut, Template: "/notifications/destinations/{id}", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/destinations/destination-1"},
	{Method: http.MethodDelete, Template: "/notifications/destinations/{id}", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/destinations/destination-1"},
	{Method: http.MethodPost, Template: "/notifications/destinations/{id}/test", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/destinations/destination-1/test"},

	// Global inventories.
	{Method: http.MethodGet, Template: "/hosts", Permission: auth.PermissionHostsRead, Example: "/hosts"},
	{Method: http.MethodGet, Template: "/incidents", Permission: auth.PermissionIncidentsRead, Example: "/incidents"},
	{Method: http.MethodGet, Template: "/events", Permission: auth.PermissionScansRead, Example: "/events"},

	// Scans.
	{Method: http.MethodGet, Template: "/scans", Permission: auth.PermissionScansRead, Example: "/scans"},
	{Method: http.MethodPost, Template: "/scans", Permission: auth.PermissionJobsRun, Mutates: true, Example: "/scans", NoHandler: true},
	{Method: http.MethodGet, Template: "/scans/active", Permission: auth.PermissionScansRead, Example: "/scans/active"},
	{Method: http.MethodGet, Template: "/scans/{id}", Permission: auth.PermissionScansRead, Example: "/scans/scan-1"},
	{Method: http.MethodGet, Template: "/scans/{id}/summary", Permission: auth.PermissionScansRead, Example: "/scans/scan-1/summary"},
	{Method: http.MethodPost, Template: "/scans/{id}/cancel", Permission: auth.PermissionJobsRun, Mutates: true, Example: "/scans/scan-1/cancel"},
	{Method: http.MethodGet, Template: "/scans/{id}/hosts", Permission: auth.PermissionHostsRead, Example: "/scans/scan-1/hosts"},
	{Method: http.MethodGet, Template: "/scans/{id}/hosts/{address}", Permission: auth.PermissionHostsRead, Example: "/scans/scan-1/hosts/198.51.100.10"},
	{Method: http.MethodGet, Template: "/scans/{id}/hosts/{address}/rdap", Permission: auth.PermissionHostsRead, Example: "/scans/scan-1/hosts/198.51.100.10/rdap"},

	// Jobs.
	{Method: http.MethodGet, Template: "/jobs", Permission: auth.PermissionJobsRead, Example: "/jobs"},
	{Method: http.MethodPost, Template: "/jobs", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs"},
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
	{Method: http.MethodGet, Template: "/jobs/{id}/scan-cycle", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/scan-cycle"},
	{Method: http.MethodDelete, Template: "/jobs/{id}/scan-cycle/{cycle}", Permission: auth.PermissionJobsRun, Mutates: true, Example: "/jobs/job-1/scan-cycle/cycle-1"},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/scans"},
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

	// Unauthenticated public status projection, relative to publicAPIBase.
	// Server.publicAPI also accepts one trailing slash.
	{Method: http.MethodGet, Template: "/dashboard", Example: "/dashboard", Access: routePublic},
}
