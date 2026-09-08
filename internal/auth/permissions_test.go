package auth

import (
	"reflect"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestPermissionsForRoleIsDeterministicAndComplete(t *testing.T) {
	admin := PermissionsForRole(store.RoleAdministrator)
	if len(admin) != 19 || !sortStrings(admin) {
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
	legacy := store.Session{}
	if !HasPermission(legacy, PermissionPublicManage) || HasPermission(legacy, "not-a-permission") {
		t.Fatal("legacy session permission set is incorrect")
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

func sortStrings(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] > values[i] {
			return false
		}
	}
	return true
}
