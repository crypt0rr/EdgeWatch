package auth

import "github.com/crypt0rr/edgewatch/internal/store"

const (
	PermissionOverviewRead          = "overview.read"
	PermissionJobsRead              = "jobs.read"
	PermissionJobsWrite             = "jobs.write"
	PermissionJobsRun               = "jobs.run"
	PermissionJobsDelete            = "jobs.delete"
	PermissionHostsRead             = "hosts.read"
	PermissionScansRead             = "scans.read"
	PermissionBaselinesRead         = "baselines.read"
	PermissionBaselinesManage       = "baselines.manage"
	PermissionIncidentsRead         = "incidents.read"
	PermissionIncidentsManage       = "incidents.manage"
	PermissionNotificationOptions   = "notification_options.read"
	PermissionNotificationsRead     = "notifications.read"
	PermissionNotificationsManage   = "notifications.manage"
	PermissionUsersManage           = "users.manage"
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
		PermissionNotificationOptions: true, PermissionNotificationsRead: true,
		PermissionNotificationsManage: true, PermissionUsersManage: true,
		PermissionAuditRead: true, PermissionPublicManage: true, PermissionStreamRead: true,
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
	// Empty roles are only used by sessions created by pre-RBAC versions. The
	// migration path upgrades those sessions to the legacy administrator, so
	// resolve the compatibility value here as well. Keeping that fallback in
	// this single permission table avoids a second, inevitably drifting list of
	// permissions in HasPermission.
	if role == "" {
		role = store.RoleAdministrator
	}
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
	role := session.Role
	if role == "" {
		// Sessions created by pre-RBAC binaries are only ever valid for the
		// original administrator and are upgraded by Authenticate when possible.
		role = store.RoleAdministrator
	}
	return rolePermissions[role][permission]
}
