package web

import (
	"net/http"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/auth"
)

func requiredPermission(path, method string) string {
	// These are the only routes intentionally reachable without a capability.
	// Keep the list exact so an accidentally added /auth/* endpoint cannot
	// silently become an authorization exemption.
	if (path == "/setup/status" && method == http.MethodGet) ||
		(path == "/setup" && method == http.MethodPost) ||
		(path == "/auth/login" && method == http.MethodPost) ||
		(path == "/auth/activate" && method == http.MethodPost) ||
		(path == "/auth/session" && method == http.MethodGet) ||
		(path == "/auth/logout" && method == http.MethodPost) ||
		(path == "/auth/display-name" && method == http.MethodPut) ||
		(path == "/auth/password" && method == http.MethodPut) ||
		(path == "/auth/totp/setup" && method == http.MethodPost) ||
		(path == "/auth/totp/enable" && method == http.MethodPost) ||
		(path == "/auth/totp" && method == http.MethodDelete) ||
		(path == "/auth/sessions" && method == http.MethodDelete) {
		return ""
	}
	switch {
	case path == "/status":
		if method == http.MethodGet {
			return auth.PermissionOverviewRead
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
