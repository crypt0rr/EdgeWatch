package auth

import (
	"slices"

	"github.com/crypt0rr/edgewatch/internal/store"
)

const (
	// PermissionDenied is returned by the web route matrix for paths that are
	// not explicitly known. It is deliberately not granted to any role; the
	// API treats it as a hard authorization failure instead of falling through
	// to an unauthenticated/empty permission result.
	PermissionDenied              = "__edgewatch_permission_denied__"
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
	// PermissionAccountSelf covers authenticated self-service operations such
	// as password, display-name, TOTP, session revocation, and logout. Keeping
	// it explicit prevents a newly added /auth/* mutation from becoming an
	// accidental authorization exemption.
	PermissionAccountSelf = "account.self"

	// The platform permissions belong to the platform administrator, who
	// manages the business units and their administrators, reads the
	// platform audit and status, and routes platform notifications. They
	// grant nothing on a unit's data, and no route grants them yet.
	PermissionUnitsManage                 = "units.manage"
	PermissionUnitAccountsManage          = "unit_accounts.manage"
	PermissionPlatformAuditRead           = "platform_audit.read"
	PermissionPlatformNotificationsManage = "platform_notifications.manage"
	PermissionPlatformStatusRead          = "platform_status.read"
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
		PermissionAccountSelf: true,
	},
	store.RoleOperator: {
		PermissionOverviewRead: true, PermissionJobsRead: true, PermissionJobsWrite: true,
		PermissionJobsRun: true, PermissionHostsRead: true, PermissionScansRead: true,
		PermissionBaselinesRead: true, PermissionBaselinesManage: true,
		PermissionIncidentsRead: true, PermissionIncidentsManage: true,
		PermissionNotificationOptions: true, PermissionStreamRead: true,
		PermissionScannerProfilesRead: true,
		PermissionAccountSelf:         true,
	},
	store.RoleViewer: {
		// Viewers get the deliberately narrow read-only console: configured
		// jobs and their current baseline. They do not get the overview,
		// global host/scan inventory, or incident stream; the unauthenticated
		// highlights page is the separate guest-facing projection.
		PermissionJobsRead: true, PermissionBaselinesRead: true,
		PermissionAccountSelf: true,
	},
	store.RolePlatformAdmin: {
		// A platform administrator has no unit and holds no permission on a
		// unit's data: every route of a unit's console refuses it.
		PermissionUnitsManage: true, PermissionUnitAccountsManage: true,
		PermissionPlatformAuditRead: true, PermissionPlatformNotificationsManage: true,
		PermissionPlatformStatusRead: true,
		PermissionAccountSelf:        true,
	},
}

func PermissionsForRole(role string) []string {
	values := rolePermissions[role]
	result := make([]string, 0, len(values))
	for permission := range values {
		result = append(result, permission)
	}
	// The list is an API response and should be deterministic.
	slices.Sort(result)
	return result
}

// PermissionsForSession returns the permissions of the signed-in session. A
// session that must enrol TOTP first holds only its own account's
// self-service; any other session holds those of its role.
func PermissionsForSession(session store.Session) []string {
	if session.TOTPEnrollmentRequired {
		result := []string{}
		if rolePermissions[session.Role][PermissionAccountSelf] {
			result = append(result, PermissionAccountSelf)
		}
		return result
	}
	return PermissionsForRole(session.Role)
}

// HasPermission reports whether the session holds the permission. A session
// that must enrol TOTP holds only PermissionAccountSelf, which covers the
// enrolment, a password change, and signing out, until the account enrols.
func HasPermission(session store.Session, permission string) bool {
	if session.TOTPEnrollmentRequired && permission != PermissionAccountSelf {
		return false
	}
	return rolePermissions[session.Role][permission]
}
