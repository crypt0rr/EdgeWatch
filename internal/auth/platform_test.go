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
	admin, err := storetest.CreateUser(context.Background(), s, store.DefaultTenantScope(), store.User{Username: "unit-admin", Role: store.RoleAdministrator, PasswordHash: cheapHash("unit administrator password"), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	operator, err := storetest.CreateUser(context.Background(), s, store.DefaultTenantScope(), store.User{Username: "unit-operator", Role: store.RoleOperator, PasswordHash: cheapHash("unit operator password"), Enabled: true})
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
	if err := storetest.CreateSession(ctx, m.Store, user.ID, digest(raw), "csrf-"+raw, now, now.Add(time.Hour)); err != nil {
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// A failed redemption of an activation or password-reset link, and the
// record that the link's redemptions from a client became rate limited,
// belong where the link's successful redemption is recorded: the unit of
// the link's account, or platform scope for a platform administrator's
// invitation. That holds for a password that is too short, an expired or
// used link, a link of a disabled unit, a refusal of the limiter and one of
// the password-check queue, so no other unit's audit shows them. A token
// that no link has names no account, and its records stay in the default
// unit, whose console serves activation.
func TestFailedLinkRedemptionsBelongToTheLinksAccount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, defaultAdmin, _ := platformTestStore(t)
	addSecondUnit(t, s)
	m := NewManager(s)
	now := time.Now().UTC().Truncate(time.Second)
	m.Now = func() time.Time { return now }
	root := createPlatformAdmin(t, m, "platform-root", "platform administrator password")
	scopeB, err := s.TenantScopeByID(ctx, platformTestTenantID)
	if err != nil {
		t.Fatal(err)
	}
	adminB, err := storetest.CreateUser(ctx, s, scopeB, store.User{Username: "bravo-admin", Role: store.RoleAdministrator, PasswordHash: cheapHash("bravo administrator password"), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	invite := func(scope store.TenantScope, actor, username string, valid time.Duration) string {
		t.Helper()
		plain, hash, err := NewOpaqueToken()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Tenant(scope).CreateUserWithInvite(ctx, store.User{Username: username, Role: store.RoleViewer, PasswordHash: "!pending", Enabled: false}, hash, now, now.Add(valid), store.AuditEntry{ActorUserID: actor}); err != nil {
			t.Fatal(err)
		}
		return plain
	}
	bravoLink := invite(scopeB, adminB.ID, "bravo-invitee", time.Hour)
	bravoLateLink := invite(scopeB, adminB.ID, "bravo-late", time.Minute)
	bravoPausedLink := invite(scopeB, adminB.ID, "bravo-paused", time.Hour)
	defaultLink := invite(store.DefaultTenantScope(), defaultAdmin.ID, "alpha-invitee", time.Hour)
	platformLink, platformHash, err := NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Platform().InvitePlatformAdmin(ctx, store.User{Username: "platform-two"}, platformHash, now, now.Add(30*time.Minute), store.AuditEntry{ActorUserID: root.ID}); err != nil {
		t.Fatal(err)
	}
	from := func(address string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/activate", nil)
		r.RemoteAddr = address + ":4000"
		return r
	}
	records := func(address string) []string {
		t.Helper()
		rows, err := s.DB.Query(`SELECT COALESCE(tenant_id,'<null>'),action,actor_kind FROM security_audit WHERE action IN ('auth.activation_failed','auth.rate_limited') AND source_ip=? ORDER BY id`, address)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var got []string
		for rows.Next() {
			var tenant, action, kind string
			if err := rows.Scan(&tenant, &action, &kind); err != nil {
				t.Fatal(err)
			}
			got = append(got, tenant+" "+action+" "+kind)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return got
	}
	const platform = "<null>"
	failed := func(scope string) string { return scope + " auth.activation_failed " + store.AuditActorUnit }
	limited := func(scope string) string { return scope + " auth.rate_limited " + store.AuditActorUnit }
	const validPassword = "invitee account password"
	for _, check := range []struct {
		name, address, token, password, want string
		before                               func()
	}{
		{"a password that is too short for a unit B link", "198.51.100.21", bravoLink, "too short", platformTestTenantID, nil},
		{"a password that is too short for a platform administrator's invitation", "198.51.100.22", platformLink, "too short", platform, nil},
		{"a password that is too short for a default unit link", "198.51.100.23", defaultLink, "too short", store.DefaultTenantID, nil},
		{"an expired unit B link", "198.51.100.24", bravoLateLink, validPassword, platformTestTenantID, func() { now = now.Add(2 * time.Minute) }},
		{"a token that no link has", "198.51.100.25", "not-a-link", validPassword, store.DefaultTenantID, nil},
		{"a used unit B link", "198.51.100.26", bravoLink, validPassword, platformTestTenantID, func() {
			if _, err := m.ActivateRequest(ctx, from("198.51.100.20"), bravoLink, validPassword); err != nil {
				t.Fatalf("redemption of the unit B link = %v", err)
			}
		}},
		{"a link of a disabled unit", "198.51.100.27", bravoPausedLink, validPassword, platformTestTenantID, func() {
			if _, err := s.DB.Exec(`UPDATE tenants SET state='disabled' WHERE id=?`, platformTestTenantID); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		if check.before != nil {
			check.before()
		}
		if _, err := m.ActivateRequest(ctx, from(check.address), check.token, check.password); err == nil || errors.Is(err, ErrRateLimited) {
			t.Fatalf("%s: redemption = %v, want a failure", check.name, err)
		}
		if got, want := records(check.address), []string{failed(check.want)}; !slices.Equal(got, want) {
			t.Errorf("%s: records = %q, want %q", check.name, got, want)
		}
	}
	var activatedIn string
	if err := s.DB.QueryRow(`SELECT COALESCE(tenant_id,'<null>') FROM security_audit WHERE action='user.activated' AND actor_username='bravo-invitee'`).Scan(&activatedIn); err != nil || activatedIn != platformTestTenantID {
		t.Fatalf("the unit B link's redemption was recorded in %s, %v; want unit B", activatedIn, err)
	}

	// A client that fails a link's redemption five times is refused, and
	// the refusal is recorded where the failures are.
	for _, check := range []struct{ address, token, want string }{
		{"198.51.100.31", platformLink, platform},
		{"198.51.100.32", bravoLink, platformTestTenantID},
		{"198.51.100.33", "another token that no link has", store.DefaultTenantID},
	} {
		var want []string
		for attempt := 0; attempt < authFailureThreshold; attempt++ {
			if _, err := m.ActivateRequest(ctx, from(check.address), check.token, "too short"); err == nil || errors.Is(err, ErrRateLimited) {
				t.Fatalf("failure %d from %s = %v", attempt+1, check.address, err)
			}
			want = append(want, failed(check.want))
		}
		if _, err := m.ActivateRequest(ctx, from(check.address), check.token, validPassword); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("redemption from %s after %d failures = %v, want ErrRateLimited", check.address, authFailureThreshold, err)
		}
		if got := records(check.address); !slices.Equal(got, append(want, limited(check.want))) {
			t.Errorf("records from %s = %q, want %d failures and a refusal in %s", check.address, got, authFailureThreshold, check.want)
		}
	}

	// A redemption that the password-check queue refuses is recorded in the
	// link's scope too.
	for i := 0; i < authArgon2MaxConcurrent; i++ {
		m.argon2Sem <- struct{}{}
	}
	_, err = m.ActivateRequest(ctx, from("198.51.100.34"), platformLink, validPassword)
	for i := 0; i < authArgon2MaxConcurrent; i++ {
		<-m.argon2Sem
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("redemption with every password check busy = %v, want ErrRateLimited", err)
	}
	if got, want := records("198.51.100.34"), []string{limited(platform)}; !slices.Equal(got, want) {
		t.Errorf("records of the refused redemption = %q, want %q", got, want)
	}

	// The default unit's audit shows only the redemptions of its own links
	// and of tokens that no link has.
	var foreign int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE action IN ('auth.activation_failed','auth.rate_limited') AND tenant_id=? AND source_ip NOT IN ('198.51.100.23','198.51.100.25','198.51.100.33')`, store.DefaultTenantID).Scan(&foreign); err != nil || foreign != 0 {
		t.Fatalf("the default unit's audit shows %d records of other scopes' links, %v", foreign, err)
	}
}
