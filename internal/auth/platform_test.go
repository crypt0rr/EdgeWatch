package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

const platformTestTenantID = "00000000-0000-0000-0000-000000000200"

// cheapHash returns the weakest password hash that verification accepts,
// which keeps these checks fast.
func cheapHash(password string) string {
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(password), salt, 1, 8, 1, 32)
	return fmt.Sprintf("$ew$argon2id$v=19$m=8,t=1,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

// platformTestStore returns a fresh store with an enabled administrator
// and operator in the default unit.
func platformTestStore(t *testing.T) (*store.Store, store.User, store.User) {
	t.Helper()
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	unit := s.Tenant(store.DefaultTenantScope())
	admin, err := unit.CreateUser(context.Background(), store.User{Username: "unit-admin", Role: store.RoleAdministrator, PasswordHash: cheapHash("unit administrator password"), Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	operator, err := unit.CreateUser(context.Background(), store.User{Username: "unit-operator", Role: store.RoleOperator, PasswordHash: cheapHash("unit operator password"), Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	return s, admin, operator
}

// addSecondUnit creates a second business unit directly in SQL, as no
// product API does yet.
func addSecondUnit(t *testing.T, s *store.Store) {
	t.Helper()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Other','other',?,?)`, platformTestTenantID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}

// createPlatformAdmin creates a platform administrator through the platform
// setup token, as the host CLI and the platform setup do.
func createPlatformAdmin(t *testing.T, m *Manager, username, password string) store.User {
	t.Helper()
	ctx := context.Background()
	token, err := m.IssuePlatformSetupToken(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	user, err := m.CompletePlatformSetup(ctx, token, username, password)
	if err != nil {
		t.Fatal(err)
	}
	return user
}

// authenticateAs signs the account in with a new session and returns the
// session that authentication makes of it on a request.
func authenticateAs(t *testing.T, m *Manager, user store.User, raw string) store.Session {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := m.Store.CreateSessionForUserWithAuditEntry(ctx, user.ID, digest(raw), "csrf-"+raw, now, now.Add(time.Hour), store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookie, Value: raw})
	session, ok := m.AuthenticateReadOnly(ctx, request)
	if !ok {
		t.Fatalf("session of %s did not authenticate", user.Username)
	}
	return session
}

// A platform administrator holds only the platform permissions and its own
// account's self-service: no permission that any unit role holds on the
// unit's data.
func TestPlatformAdministratorHoldsNoUnitPermission(t *testing.T) {
	want := []string{PermissionAccountSelf, PermissionPlatformAuditRead, PermissionPlatformNotificationsManage, PermissionPlatformStatusRead, PermissionUnitAccountsManage, PermissionUnitsManage}
	slices.Sort(want)
	if got := PermissionsForRole(store.RolePlatformAdmin); !reflect.DeepEqual(got, want) {
		t.Fatalf("platform administrator permissions = %v, want %v", got, want)
	}
	platform := store.Session{Role: store.RolePlatformAdmin}
	for _, role := range []string{store.RoleAdministrator, store.RoleOperator, store.RoleViewer} {
		for _, permission := range PermissionsForRole(role) {
			if permission == PermissionAccountSelf {
				continue
			}
			if HasPermission(platform, permission) {
				t.Errorf("the platform administrator holds the unit permission %s", permission)
			}
		}
	}
	for _, permission := range want {
		if permission == PermissionAccountSelf {
			continue
		}
		for _, role := range []string{store.RoleAdministrator, store.RoleOperator, store.RoleViewer} {
			if HasPermission(store.Session{Role: role}, permission) {
				t.Errorf("a unit %s holds the platform permission %s", role, permission)
			}
		}
	}
}

// The host issues a platform setup token, and redeeming it creates the
// platform administrator; a wrong token costs no password hash and creates
// nothing.
func TestPlatformSetupCreatesThePlatformAdministrator(t *testing.T) {
	ctx := context.Background()
	s, _, _ := platformTestStore(t)
	m := NewManager(s)
	token, err := m.IssuePlatformSetupToken(ctx, false)
	if err != nil || token == "" {
		t.Fatalf("platform setup token = %q, %v", token, err)
	}
	for _, wrong := range []string{"", "not-the-token"} {
		if _, err := m.CompletePlatformSetup(ctx, wrong, "root", "platform administrator password"); err == nil {
			t.Fatalf("setup with token %q succeeded", wrong)
		}
	}
	if _, err := m.CompletePlatformSetup(ctx, token, "root", "short"); err == nil {
		t.Fatal("a short password was accepted")
	}
	user, err := m.CompletePlatformSetup(ctx, token, "root", "platform administrator password")
	if err != nil {
		t.Fatal(err)
	}
	if user.Role != store.RolePlatformAdmin || user.TenantID != "" || !VerifyPassword(user.PasswordHash, "platform administrator password") {
		t.Fatalf("platform administrator = %+v", user)
	}
	if _, err := m.IssuePlatformSetupToken(ctx, true); !errors.Is(err, store.ErrPlatformAdminConfigured) {
		t.Fatalf("second token = %v, want ErrPlatformAdminConfigured", err)
	}
}

// The web platform setup has the first setup's failure budget: each failure
// is recorded in platform scope, a client that sent too many wrong tokens is
// refused before any check, even with the right token, and the refusal is
// recorded once in platform scope too. Another client still redeems the
// token.
func TestPlatformSetupRequestRateLimitsInPlatformScope(t *testing.T) {
	ctx := context.Background()
	s, _, _ := platformTestStore(t)
	m := NewManager(s)
	token, err := m.IssuePlatformSetupToken(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	blocked := httptest.NewRequest(http.MethodPost, "/api/v1/setup/platform", nil)
	blocked.RemoteAddr = "10.0.0.40:4000"
	for attempt := 0; attempt < authFailureThreshold; attempt++ {
		if _, err := m.PlatformSetupRequest(ctx, blocked, "wrong-token", "root", "platform administrator password"); err == nil || errors.Is(err, ErrRateLimited) {
			t.Fatalf("wrong token attempt %d = %v, want a setup failure", attempt, err)
		}
	}
	if _, err := m.PlatformSetupRequest(ctx, blocked, "wrong-token", "root", "platform administrator password"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("attempt over the budget = %v, want ErrRateLimited", err)
	}
	count := func(query string) int {
		t.Helper()
		var rows int
		if err := s.DB.QueryRow(query).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	if got := count(`SELECT COUNT(*) FROM security_audit WHERE action='auth.platform_setup_failed' AND tenant_id IS NULL`); got != authFailureThreshold {
		t.Fatalf("platform setup failures in platform scope = %d, want %d", got, authFailureThreshold)
	}
	if got := count(`SELECT COUNT(*) FROM security_audit WHERE action='auth.rate_limited' AND tenant_id IS NULL AND actor_username='platform-setup'`); got != 1 {
		t.Fatalf("platform setup rate-limit records in platform scope = %d, want 1", got)
	}
	if got := count(`SELECT COUNT(*) FROM security_audit WHERE tenant_id IS NOT NULL AND (action='auth.platform_setup_failed' OR actor_username='platform-setup')`); got != 0 {
		t.Fatalf("platform setup records in a unit = %d", got)
	}

	other := httptest.NewRequest(http.MethodPost, "/api/v1/setup/platform", nil)
	other.RemoteAddr = "10.0.0.41:4000"
	user, err := m.PlatformSetupRequest(ctx, other, token, "root", "platform administrator password")
	if err != nil || user.Role != store.RolePlatformAdmin {
		t.Fatalf("platform setup from another client = %+v, %v", user, err)
	}
}

// Once more than one business unit exists, a unit administrator or a
// platform administrator without TOTP holds only its own account's
// self-service until it enrols; an operator is unaffected. With a single
// unit nothing changes, and the rule fails closed when the units cannot be
// counted.
func TestTOTPEnrollmentRequiredOnceUnitsMultiply(t *testing.T) {
	ctx := context.Background()
	s, admin, operator := platformTestStore(t)
	m := NewManager(s)
	root := createPlatformAdmin(t, m, "root", "platform administrator password")
	restricted := []string{PermissionAccountSelf}

	sessions := map[string]store.Session{}
	for _, user := range []store.User{admin, operator, root} {
		session := authenticateAs(t, m, user, "single-"+user.Username)
		if session.TOTPEnrollmentRequired {
			t.Errorf("%s must enrol TOTP with a single unit", user.Username)
		}
		if got, want := PermissionsForSession(session), PermissionsForRole(user.Role); !reflect.DeepEqual(got, want) {
			t.Errorf("%s permissions with a single unit = %v, want %v", user.Username, got, want)
		}
		sessions[user.Username] = session
	}
	if !HasPermission(sessions["unit-admin"], PermissionUsersManage) {
		t.Fatal("a single unit's administrator lost its permissions")
	}

	addSecondUnit(t, s)
	for _, user := range []store.User{admin, root} {
		session := authenticateAs(t, m, user, "multi-"+user.Username)
		if !session.TOTPEnrollmentRequired {
			t.Fatalf("%s need not enrol TOTP with two units", user.Username)
		}
		if got := PermissionsForSession(session); !reflect.DeepEqual(got, restricted) {
			t.Errorf("%s restricted permissions = %v, want %v", user.Username, got, restricted)
		}
		for _, permission := range PermissionsForRole(user.Role) {
			if got, want := HasPermission(session, permission), permission == PermissionAccountSelf; got != want {
				t.Errorf("%s restricted: HasPermission(%s) = %v, want %v", user.Username, permission, got, want)
			}
		}
	}
	session := authenticateAs(t, m, operator, "multi-operator")
	if session.TOTPEnrollmentRequired || !HasPermission(session, PermissionJobsWrite) {
		t.Fatalf("an operator was restricted: %+v", session)
	}
	if got := PermissionsForSession(store.Session{Role: "unknown", TOTPEnrollmentRequired: true}); len(got) != 0 {
		t.Fatalf("an unknown role's restricted permissions = %v", got)
	}

	// Enrolling lifts the restriction.
	current, err := s.GetAccount(ctx, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	current.TOTPEnabled, current.TOTPSecret = true, "JBSWY3DPEHPK3PXP"
	if err := s.Tenant(store.DefaultTenantScope()).SaveUserSecurity(ctx, current, nil, false, false, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	session = authenticateAs(t, m, admin, "enrolled-"+admin.Username)
	if session.TOTPEnrollmentRequired || !reflect.DeepEqual(PermissionsForSession(session), PermissionsForRole(store.RoleAdministrator)) {
		t.Fatalf("an enrolled administrator is still restricted: %+v", session)
	}

	// The rule fails closed.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if !m.TOTPEnrollmentRequired(canceled, root) {
		t.Fatal("a failed unit count lifted the restriction")
	}
	if m.TOTPEnrollmentRequired(canceled, operator) {
		t.Fatal("an operator was restricted without a unit count")
	}
}

// A failed password or TOTP confirmation is the signed-in account's own
// action, so its record names the account as its actor, by ID and
// username, and its detail names the account, as the other account records
// do. It holds neither the submitted password nor the code. A unit
// account's record belongs to its unit with the unit actor kind, and a
// platform administrator's to the platform with the platform actor kind.
func TestConfirmationFailureRecordsNameTheAccount(t *testing.T) {
	ctx := context.Background()
	s, admin, _ := platformTestStore(t)
	m := NewManager(s)
	root := createPlatformAdmin(t, m, "root", "platform administrator password")
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/users", nil)
		r.RemoteAddr = "198.51.100.90:4000"
		return r
	}
	type record struct{ tenant, kind, actorID, actorName, detail string }
	last := func(action string) record {
		t.Helper()
		var got record
		if err := s.DB.QueryRow(`SELECT COALESCE(tenant_id,'<null>'),actor_kind,actor_user_id,actor_username,detail FROM security_audit WHERE action=? ORDER BY id DESC LIMIT 1`, action).Scan(&got.tenant, &got.kind, &got.actorID, &got.actorName, &got.detail); err != nil {
			t.Fatalf("audit record %s: %v", action, err)
		}
		return got
	}
	const wrongPassword, wrongCode, wrongRecovery = "not the confirmation password", "000000", "NOTARECOVERYCODE"
	for _, check := range []struct {
		name         string
		account      store.User
		tenant, kind string
	}{
		{"a unit administrator", admin, store.DefaultTenantID, store.AuditActorUnit},
		{"the platform administrator", root, "<null>", store.AuditActorPlatform},
	} {
		if err := m.ConfirmPasswordForUser(ctx, request(), check.account.ID, wrongPassword); err == nil {
			t.Fatalf("%s: a wrong password was confirmed", check.name)
		}
		if err := m.ConfirmTOTPForUser(ctx, request(), check.account.ID, wrongCode, wrongRecovery); err == nil {
			t.Fatalf("%s: a wrong code was confirmed", check.name)
		}
		for _, action := range []string{"auth.password_confirmation_failed", "auth.totp_confirmation_failed"} {
			got := last(action)
			if got.tenant != check.tenant || got.kind != check.kind || got.actorID != check.account.ID || got.actorName != check.account.Username {
				t.Errorf("%s: %s record = %+v, want tenant %s, kind %s, actor %s %s", check.name, action, got, check.tenant, check.kind, check.account.ID, check.account.Username)
			}
			if !strings.Contains(got.detail, check.account.Username) {
				t.Errorf("%s: %s detail %q does not name %s", check.name, action, got.detail, check.account.Username)
			}
			for _, secret := range []string{wrongPassword, wrongCode, wrongRecovery} {
				if strings.Contains(got.detail+got.actorName, secret) {
					t.Errorf("%s: %s record holds the submitted %q: %+v", check.name, action, secret, got)
				}
			}
		}
	}
}

// Failed sign-ins of a platform administrator, and those with a username
// that no account has, are recorded in platform scope instead of the
// default unit, while a unit account's stay in its unit.
func TestPlatformAndUnknownSignInFailuresBelongToThePlatform(t *testing.T) {
	ctx := context.Background()
	s, admin, _ := platformTestStore(t)
	m := NewManager(s)
	root := createPlatformAdmin(t, m, "root", "platform administrator password")
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = "127.0.0.1:1234"
		return r
	}
	lastFailure := func(action, subject string) string {
		t.Helper()
		var tenant string
		if err := s.DB.QueryRow(`SELECT COALESCE(tenant_id,'<null>') FROM security_audit WHERE action=? AND actor_username=? ORDER BY id DESC LIMIT 1`, action, subject).Scan(&tenant); err != nil {
			t.Fatalf("audit record %s for %s: %v", action, subject, err)
		}
		return tenant
	}

	for _, attempt := range []struct{ username, want string }{
		{"root", "<null>"},
		{"nobody", "<null>"},
		{admin.Username, store.DefaultTenantID},
	} {
		if _, _, err := m.LoginAs(ctx, request(), attempt.username, "wrong password", "", ""); err == nil {
			t.Fatalf("%s signed in with a wrong password", attempt.username)
		}
		if got := lastFailure("auth.login_failed", attempt.username); got != attempt.want {
			t.Errorf("failed sign-in of %s recorded in %s, want %s", attempt.username, got, attempt.want)
		}
	}
	if err := m.ConfirmPasswordForUser(ctx, request(), root.ID, "wrong password"); err == nil {
		t.Fatal("a wrong password was confirmed")
	}
	if got := lastFailure("auth.password_confirmation_failed", root.Username); got != "<null>" {
		t.Errorf("failed confirmation recorded in %s, want the platform", got)
	}
	raw, user, err := m.LoginAs(ctx, request(), "root", "platform administrator password", "", "")
	if err != nil || raw == "" || user.ID != root.ID {
		t.Fatalf("platform administrator sign-in = %q %+v, %v", raw, user, err)
	}
	var tenant, kind string
	if err := s.DB.QueryRow(`SELECT COALESCE(tenant_id,'<null>'),actor_kind FROM security_audit WHERE action='user.login' AND actor_user_id=?`, root.ID).Scan(&tenant, &kind); err != nil || tenant != "<null>" || kind != store.AuditActorPlatform {
		t.Fatalf("platform sign-in audit record = %s/%s, %v", tenant, kind, err)
	}
}
