package auth

import (
	"reflect"
	"slices"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestPermissionsForRoleIsDeterministicAndComplete(t *testing.T) {
	t.Parallel()
	admin := PermissionsForRole(store.RoleAdministrator)
	if len(admin) != 22 || !sortStrings(admin) {
		t.Fatalf("administrator permissions = %#v", admin)
	}
	if !HasPermission(store.Session{Role: store.RoleAdministrator}, PermissionAuditRead) {
		t.Fatal("administrator cannot read the unit audit")
	}
	operator := PermissionsForRole(store.RoleOperator)
	if len(operator) != 15 || !sortStrings(operator) {
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
	t.Parallel()
	roleless := store.Session{}
	if HasPermission(roleless, PermissionPublicManage) || HasPermission(roleless, PermissionJobsRead) {
		t.Fatal("role-less session must not receive permissions")
	}
	operator := store.Session{Role: store.RoleOperator}
	for _, permission := range []string{PermissionOverviewRead, PermissionJobsWrite, PermissionJobsRun, PermissionBaselinesManage, PermissionStreamRead, PermissionPerimeterRead} {
		if !HasPermission(operator, permission) {
			t.Fatalf("operator lacks %s", permission)
		}
	}
	for _, permission := range []string{PermissionNotificationsManage, PermissionUsersManage, PermissionPublicManage, PermissionAuditRead, PermissionPerimeterManage} {
		if HasPermission(operator, permission) {
			t.Fatalf("operator unexpectedly has %s", permission)
		}
	}
	viewer := store.Session{Role: store.RoleViewer}
	if !HasPermission(viewer, PermissionBaselinesRead) || HasPermission(viewer, PermissionOverviewRead) || HasPermission(viewer, PermissionHostsRead) || HasPermission(viewer, PermissionJobsWrite) {
		t.Fatal("viewer permission boundary is incorrect")
	}
}

// Administrators read and manage the unit's perimeter and operators only
// read it. Viewers and platform administrators hold neither, nor does a
// session that must enrol TOTP first.
func TestPerimeterPermissionsFollowTheRoles(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		session      store.Session
		read, manage bool
	}{
		{store.Session{Role: store.RoleAdministrator}, true, true},
		{store.Session{Role: store.RoleOperator}, true, false},
		{store.Session{Role: store.RoleViewer}, false, false},
		{store.Session{Role: store.RolePlatformAdmin}, false, false},
		{store.Session{Role: store.RoleAdministrator, TOTPEnrollmentRequired: true}, false, false},
		{store.Session{}, false, false},
	} {
		permissions := PermissionsForSession(test.session)
		if got := HasPermission(test.session, PermissionPerimeterRead); got != test.read || slices.Contains(permissions, PermissionPerimeterRead) != test.read {
			t.Errorf("%+v holds %s = %t, listed %v; want %t", test.session, PermissionPerimeterRead, got, permissions, test.read)
		}
		if got := HasPermission(test.session, PermissionPerimeterManage); got != test.manage || slices.Contains(permissions, PermissionPerimeterManage) != test.manage {
			t.Errorf("%+v holds %s = %t, listed %v; want %t", test.session, PermissionPerimeterManage, got, permissions, test.manage)
		}
	}
}

func TestPermissionListsAreTheSingleAuthorizationSource(t *testing.T) {
	t.Parallel()
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
		for _, permission := range []string{PermissionJobsDelete, PermissionUsersManage, PermissionScannerProfilesManage, PermissionPerimeterRead, PermissionPerimeterManage} {
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
