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
	operator := PermissionsForRole(store.RoleOperator)
	if len(operator) != 13 || !sortStrings(operator) {
		t.Fatalf("operator permissions = %#v", operator)
	}
	viewer := PermissionsForRole(store.RoleViewer)
	wantViewer := []string{PermissionBaselinesRead, PermissionJobsRead}
	if !reflect.DeepEqual(viewer, wantViewer) {
		t.Fatalf("viewer permissions = %#v, want %#v", viewer, wantViewer)
	}
	if got := PermissionsForRole("unknown"); len(got) != 0 {
		t.Fatalf("unknown role permissions = %#v", got)
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
