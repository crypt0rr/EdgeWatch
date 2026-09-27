package auth

import (
	"reflect"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestPermissionsForRoleIsDeterministicAndComplete(t *testing.T) {
	admin := PermissionsForRole(store.RoleAdministrator)
	if len(admin) != 20 || !sortStrings(admin) {
		t.Fatalf("administrator permissions = %#v", admin)
	}
	if !HasPermission(store.Session{Role: store.RoleAdministrator}, PermissionAuditRead) {
		t.Fatal("administrator cannot read the unit audit")
	}
	operator := PermissionsForRole(store.RoleOperator)
	if len(operator) != 14 || !sortStrings(operator) {
		t.Fatalf("operator permissions = %#v", operator)
	}
	viewer := PermissionsForRole(store.RoleViewer)
	wantViewer := []string{PermissionAccountSelf, PermissionBaselinesRead, PermissionJobsRead}
	if !reflect.DeepEqual(viewer, wantViewer) {
		t.Fatalf("viewer permissions = %#v, want %#v", viewer, wantViewer)
	}
	if got := PermissionsForRole("unknown"); len(got) != 0 {
		t.Fatalf("unknown role permissions = %#v", got)
	}
	for _, permission := range []string{PermissionNotificationsRead} {
		if HasPermission(store.Session{Role: store.RoleAdministrator}, permission) {
			t.Fatalf("administrator unexpectedly has unenforced capability %s", permission)
		}
		for _, value := range admin {
			if value == permission {
				t.Fatalf("administrator permissions advertise unenforced capability %s", permission)
			}
		}
	}
}

func TestHasPermissionHandlesLegacyAndRoleScopedSessions(t *testing.T) {
	roleless := store.Session{}
	if HasPermission(roleless, PermissionPublicManage) || HasPermission(roleless, PermissionJobsRead) {
		t.Fatal("role-less session must not receive permissions")
	}
	operator := store.Session{Role: store.RoleOperator}
	for _, permission := range []string{PermissionOverviewRead, PermissionJobsWrite, PermissionJobsRun, PermissionBaselinesManage, PermissionStreamRead} {
		if !HasPermission(operator, permission) {
			t.Fatalf("operator lacks %s", permission)
		}
	}
	for _, permission := range []string{PermissionNotificationsManage, PermissionUsersManage, PermissionPublicManage, PermissionAuditRead} {
		if HasPermission(operator, permission) {
			t.Fatalf("operator unexpectedly has %s", permission)
		}
	}
	viewer := store.Session{Role: store.RoleViewer}
	if !HasPermission(viewer, PermissionBaselinesRead) || HasPermission(viewer, PermissionOverviewRead) || HasPermission(viewer, PermissionHostsRead) || HasPermission(viewer, PermissionJobsWrite) {
		t.Fatal("viewer permission boundary is incorrect")
	}
}

func TestPermissionListsAreTheSingleAuthorizationSource(t *testing.T) {
	permissions := map[string][]string{
		store.RoleAdministrator: PermissionsForRole(store.RoleAdministrator),
		store.RoleOperator:      PermissionsForRole(store.RoleOperator),
		store.RoleViewer:        PermissionsForRole(store.RoleViewer),
	}
	for role, values := range permissions {
		session := store.Session{Role: role}
		for _, permission := range values {
			if !HasPermission(session, permission) {
				t.Fatalf("permission list for %s contains %q but HasPermission rejected it", role, permission)
			}
		}
		for _, permission := range []string{PermissionJobsDelete, PermissionUsersManage, PermissionScannerProfilesManage} {
			listed := false
			for _, value := range values {
				if value == permission {
					listed = true
					break
				}
			}
			if listed != HasPermission(session, permission) {
				t.Fatalf("permission list and HasPermission disagree for %s/%s", role, permission)
			}
		}
	}
	roleless := store.Session{}
	if HasPermission(roleless, PermissionJobsDelete) || len(PermissionsForRole("")) != 0 {
		t.Fatal("role-less session permission compatibility must be fail-closed")
	}
}

func sortStrings(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] > values[i] {
			return false
		}
	}
	return true
}

// The unit audit is the only permission of a unit's role that the routes of
// the experimental business units alone grant; the filter drops it and keeps
// every other permission in order. Those routes alone grant every platform
// permission too, so a platform administrator keeps only its own account's
// self-service.
func TestWithoutBusinessUnitPermissions(t *testing.T) {
	admin := PermissionsForRole(store.RoleAdministrator)
	filtered := WithoutBusinessUnitPermissions(admin)
	if len(filtered) != len(admin)-1 || !sortStrings(filtered) {
		t.Fatalf("filtered administrator permissions = %#v", filtered)
	}
	for _, permission := range filtered {
		if permission == PermissionAuditRead {
			t.Fatal("the filter kept the unit audit permission")
		}
	}
	for _, role := range []string{store.RoleOperator, store.RoleViewer} {
		if got, want := WithoutBusinessUnitPermissions(PermissionsForRole(role)), PermissionsForRole(role); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s permissions filtered = %#v, want %#v", role, got, want)
		}
	}
	if got, want := WithoutBusinessUnitPermissions(PermissionsForRole(store.RolePlatformAdmin)), []string{PermissionAccountSelf}; !reflect.DeepEqual(got, want) {
		t.Fatalf("platform administrator permissions filtered = %#v, want %#v", got, want)
	}
	for _, role := range []string{store.RoleAdministrator, store.RoleOperator, store.RoleViewer, store.RolePlatformAdmin} {
		for _, permission := range PermissionsForRole(role) {
			want := permission == PermissionAuditRead || (role == store.RolePlatformAdmin && permission != PermissionAccountSelf)
			if got := IsBusinessUnitPermission(permission); got != want {
				t.Errorf("IsBusinessUnitPermission(%q) of %s = %t, want %t", permission, role, got, want)
			}
		}
	}
	if got := WithoutBusinessUnitPermissions(nil); got == nil || len(got) != 0 {
		t.Fatalf("filtered nil = %#v, want an empty list", got)
	}
}
