package auth

import "github.com/crypt0rr/edgewatch/internal/store"

const (
	PermissionOverviewRead        = "overview.read"
	PermissionJobsRead            = "jobs.read"
	PermissionJobsWrite           = "jobs.write"
	PermissionJobsRun             = "jobs.run"
	PermissionJobsDelete          = "jobs.delete"
	PermissionHostsRead           = "hosts.read"
	PermissionScansRead           = "scans.read"
	PermissionBaselinesRead       = "baselines.read"
	PermissionBaselinesManage     = "baselines.manage"
	PermissionIncidentsRead       = "incidents.read"
	PermissionIncidentsManage     = "incidents.manage"
	PermissionNotificationOptions = "notification_options.read"
	// PermissionNotificationsRead is retained as a source-compatible symbol
	// for clients that imported the old name. Notification reads are covered by
	// PermissionNotificationOptions because no route uses this capability.
	PermissionNotificationsRead   = "notifications.read"
	PermissionNotificationsManage = "notifications.manage"
	PermissionUsersManage         = "users.manage"
	// PermissionAuditRead remains source-compatible until an audit read
	// endpoint exists, but is intentionally not granted to any role.
	PermissionAuditRead             = "audit.read"
	PermissionPublicManage          = "public_dashboard.manage"
	PermissionStreamRead            = "stream.read"
	PermissionScannerProfilesRead   = "scanner_profiles.read"
	PermissionScannerProfilesManage = "scanner_profiles.manage"
)

var rolePermissions = map[string]map[string]bool{
	store.RoleAdministrator: {
		PermissionOverviewRead: true, PermissionJobsRead: true, PermissionJobsWrite: true,
		PermissionJobsRun: true, PermissionJobsDelete: true, PermissionHostsRead: true, PermissionScansRead: true,
		PermissionBaselinesRead: true, PermissionBaselinesManage: true,
		PermissionIncidentsRead: true, PermissionIncidentsManage: true,
		PermissionNotificationOptions: true,
		PermissionNotificationsManage: true, PermissionUsersManage: true,
		PermissionPublicManage: true, PermissionStreamRead: true,
		PermissionScannerProfilesRead: true, PermissionScannerProfilesManage: true,
	},
	store.RoleOperator: {
		PermissionOverviewRead: true, PermissionJobsRead: true, PermissionJobsWrite: true,
		PermissionJobsRun: true, PermissionHostsRead: true, PermissionScansRead: true,
		PermissionBaselinesRead: true, PermissionBaselinesManage: true,
		PermissionIncidentsRead: true, PermissionIncidentsManage: true,
		PermissionNotificationOptions: true, PermissionStreamRead: true,
		PermissionScannerProfilesRead: true,
	},
	store.RoleViewer: {
		// Viewers get the deliberately narrow read-only console: configured
		// jobs and their current baseline. They do not get the overview,
		// global host/scan inventory, or incident stream; the unauthenticated
		// highlights page is the separate guest-facing projection.
		PermissionJobsRead: true, PermissionBaselinesRead: true,
	},
}

func PermissionsForRole(role string) []string {
	values := rolePermissions[role]
	result := make([]string, 0, len(values))
	for permission := range values {
		result = append(result, permission)
	}
	// The list is an API response and should be deterministic. Avoid importing
	// a second sorting helper into callers.
	for i := 1; i < len(result); i++ {
		for j := i; j > 0 && result[j] < result[j-1]; j-- {
			result[j], result[j-1] = result[j-1], result[j]
		}
	}
	return result
}

func HasPermission(session store.Session, permission string) bool {
	return rolePermissions[session.Role][permission]
}
