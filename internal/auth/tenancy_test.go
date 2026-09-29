package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// Sign-in and session authentication find an account of any tenant and
// carry its tenant. A failed attempt on a known account is recorded in the
// account's tenant. A tenant that is not active stops sign-in with the
// answer a wrong password gets, and records the attempt in that tenant.
func TestSignInCarriesTheAccountTenant(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const (
		otherTenantID = "00000000-0000-0000-0000-000000000200"
		password      = "correct horse battery staple"
	)
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Other','other',?,?)`, otherTenantID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	scope, err := s.TenantScopeByID(ctx, otherTenantID)
	if err != nil {
		t.Fatal(err)
	}
	// The weakest hash that verification accepts keeps the checks cheap.
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(password), salt, 1, 8, 1, 32)
	hash := fmt.Sprintf("$ew$argon2id$v=19$m=8,t=1,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	user, err := s.Tenant(scope).CreateUser(ctx, store.User{Username: "other-operator", Role: store.RoleOperator, PasswordHash: hash, Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(s)
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = "127.0.0.1:1234"
		return r
	}
	lastAudit := func(action string) [2]string {
		t.Helper()
		var record [2]string
		if err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(tenant_id,'<null>'),actor_kind FROM security_audit WHERE action=? ORDER BY id DESC LIMIT 1`, action).Scan(&record[0], &record[1]); err != nil {
			t.Fatalf("audit record %s: %v", action, err)
		}
		return record
	}
	want := [2]string{otherTenantID, store.AuditActorUnit}

	if _, _, err := m.LoginAs(ctx, request(), "other-operator", "wrong password", "", ""); err == nil {
		t.Fatal("a wrong password signed in")
	}
	if got := lastAudit("auth.login_failed"); got != want {
		t.Fatalf("failed sign-in audit record = %v, want %v", got, want)
	}

	// A session of the account authenticates with the account's tenant.
	if err := s.CreateSessionForUserWithAuditEntry(ctx, user.ID, digest("other-session"), "csrf", now, now.Add(time.Hour), store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	authenticated := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	authenticated.AddCookie(&http.Cookie{Name: SessionCookie, Value: "other-session"})
	session, ok := m.AuthenticateReadOnly(ctx, authenticated)
	if !ok || session.TenantID != otherTenantID || session.Username != "other-operator" {
		t.Fatalf("session = %+v, %v", session, ok)
	}
	if scope, err := s.TenantScopeForSession(ctx, session); err != nil || scope.ID() != otherTenantID {
		t.Fatalf("session scope = %q, %v", scope.ID(), err)
	}

	if _, err := s.DB.ExecContext(ctx, `UPDATE tenants SET state='disabled' WHERE id=?`, otherTenantID); err != nil {
		t.Fatal(err)
	}
	failures := 0
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='auth.login_failed'`).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if raw, _, err := m.LoginAs(ctx, request(), "other-operator", password, "", ""); err == nil || err.Error() != "invalid credentials" || raw != "" {
		t.Fatalf("sign-in to a disabled tenant = %q, %v", raw, err)
	}
	var after int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='auth.login_failed'`).Scan(&after); err != nil || after != failures+1 {
		t.Fatalf("failed sign-ins recorded = %d, %v; want %d", after, err, failures+1)
	}
	if got := lastAudit("auth.login_failed"); got != want {
		t.Fatalf("disabled tenant sign-in audit record = %v, want %v", got, want)
	}
	var sessions int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, user.ID).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("sessions after the refused sign-in = %d, %v", sessions, err)
	}
}

// A sign-in to an account whose unit is disabled, or being deleted, is
// refused before it spends a one-time factor. With the right password and
// an unused recovery code, the current TOTP code, or a wrong code, it gets
// the answer, failure accounting and auth.login_failed record of a wrong
// password; the recovery code stays unused, the time step unrecorded, and
// no auth.recovery_code_used record is written. Once the unit is enabled
// again, the same recovery code and TOTP code sign in.
func TestSignInToAnInactiveUnitSpendsNoOneTimeFactor(t *testing.T) {
	ctx := context.Background()
	s, _, _ := platformTestStore(t)
	addSecondUnit(t, s)
	scope, err := s.TenantScopeByID(ctx, platformTestTenantID)
	if err != nil {
		t.Fatal(err)
	}
	unit := s.Tenant(scope)
	const password = "b operator password"
	operator, err := unit.CreateUser(ctx, store.User{Username: "b-operator", Role: store.RoleOperator, PasswordHash: cheapHash(password), Enabled: true}, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	plain, hashes, err := RecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	operator.TOTPEnabled, operator.TOTPSecret = true, "JBSWY3DPEHPK3PXP"
	if err := unit.SaveUserSecurity(ctx, operator, hashes, true, false, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	m := NewManager(s)
	now := time.Now().UTC()
	m.Now = func() time.Time { return now }
	code := totpCode(operator.TOTPSecret, now.Unix()/30)
	wrongCode := "000000"
	if code == wrongCode {
		wrongCode = "111111"
	}
	count := func(query string, args ...any) int {
		t.Helper()
		var n int
		if err := s.DB.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	unused := func() int {
		return count(`SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at IS NULL`, operator.ID)
	}
	recorded := func(action string) int {
		return count(`SELECT COUNT(*) FROM security_audit WHERE action=? AND tenant_id=?`, action, platformTestTenantID)
	}
	// Each sign-in comes from its own client, so the budgets of one do not
	// throttle the next.
	clients := 0
	signIn := func(password, otp, recovery string) (string, string, error) {
		t.Helper()
		clients++
		address := fmt.Sprintf("192.0.2.%d", clients)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = address + ":1234"
		raw, _, err := m.LoginAs(ctx, r, "b-operator", password, otp, recovery)
		return raw, address, err
	}
	host := store.AuditEntry{ActorUsername: "host-cli", ActorKind: store.AuditActorHost}
	setState := func(change func(store.TenantRecord) error) {
		t.Helper()
		current, err := s.Platform().GetTenant(ctx, platformTestTenantID)
		if err != nil {
			t.Fatal(err)
		}
		if err := change(current); err != nil {
			t.Fatal(err)
		}
	}
	// refused signs in to the inactive unit and checks that the sign-in got
	// what a wrong password gets, and spent nothing.
	refused := func(state, name, password, otp, recovery string) {
		t.Helper()
		codesBefore, failedBefore := unused(), recorded("auth.login_failed")
		raw, address, err := signIn(password, otp, recovery)
		if err == nil || err.Error() != "invalid credentials" || raw != "" {
			t.Errorf("%s unit, %s: sign-in = %q, %v; want invalid credentials", state, name, raw, err)
		}
		if got := recorded("auth.login_failed"); got != failedBefore+1 {
			t.Errorf("%s unit, %s: auth.login_failed records = %d, want %d", state, name, got, failedBefore+1)
		}
		source := "source:login:" + address
		if got := len(m.loginClientFails["login-client:login:"+address]); got != 1 {
			t.Errorf("%s unit, %s: the client's sign-in budget counts %d failures, want 1", state, name, got)
		}
		if got := len(m.accountFails[scopedAccountKey(source, "login:b-operator")]); got != 1 {
			t.Errorf("%s unit, %s: the account bucket counts %d failures, want 1", state, name, got)
		}
		if got := unused(); got != codesBefore {
			t.Errorf("%s unit, %s: unused recovery codes = %d, want %d", state, name, got, codesBefore)
		}
		for _, action := range []string{"auth.recovery_code_used", "auth.totp_failed"} {
			if got := recorded(action); got != 0 {
				t.Errorf("%s unit, %s: %d %s records, want none", state, name, got, action)
			}
		}
		if got := count(`SELECT COUNT(*) FROM totp_replay WHERE user_id=?`, operator.ID); got != 0 {
			t.Errorf("%s unit, %s: the sign-in recorded a TOTP time step", state, name)
		}
	}

	setState(func(current store.TenantRecord) error {
		_, err := s.Platform().DisableTenant(ctx, current.ID, current.Revision, host)
		return err
	})
	refused("disabled", "wrong password", "wrong password", "", plain[0])
	for i := range 3 {
		refused("disabled", fmt.Sprintf("recovery code %d", i+1), password, "", plain[i])
	}
	refused("disabled", "current TOTP code", password, code, "")
	refused("disabled", "wrong TOTP code", password, wrongCode, "")
	if got := unused(); got != len(plain) {
		t.Fatalf("unused recovery codes after the disabled unit's sign-ins = %d, want %d", got, len(plain))
	}

	// Enabled again, the unit's account signs in with the codes presented
	// while it was disabled.
	setState(func(current store.TenantRecord) error {
		_, err := s.Platform().EnableTenant(ctx, current.ID, current.Revision, host)
		return err
	})
	if raw, _, err := signIn(password, "", plain[0]); err != nil || raw == "" {
		t.Fatalf("sign-in with the first recovery code after enabling = %q, %v", raw, err)
	}
	if got, used := unused(), recorded("auth.recovery_code_used"); got != len(plain)-1 || used != 1 {
		t.Fatalf("after one recovery sign-in: unused codes = %d, auth.recovery_code_used records = %d; want %d and 1", got, used, len(plain)-1)
	}
	if raw, _, err := signIn(password, code, ""); err != nil || raw == "" {
		t.Fatalf("sign-in with the TOTP code presented while disabled = %q, %v", raw, err)
	}

	// A unit that is being deleted refuses alike.
	setState(func(current store.TenantRecord) error {
		_, err := s.Platform().DisableTenant(ctx, current.ID, current.Revision, host)
		return err
	})
	setState(func(current store.TenantRecord) error {
		_, err := s.Platform().RequestTenantDeletion(ctx, current.ID, current.Name, host)
		return err
	})
	codesBefore := unused()
	raw, _, err := signIn(password, "", plain[1])
	if err == nil || err.Error() != "invalid credentials" || raw != "" {
		t.Fatalf("sign-in to a unit being deleted = %q, %v; want invalid credentials", raw, err)
	}
	if got, used := unused(), recorded("auth.recovery_code_used"); got != codesBefore || used != 1 {
		t.Fatalf("after the sign-in to a unit being deleted: unused codes = %d, auth.recovery_code_used records = %d; want %d and 1", got, used, codesBefore)
	}
}
