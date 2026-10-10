package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// clientBudgetTOTPSecret is the secret of the account with TOTP in
// clientBudgetStore.
const clientBudgetTOTPSecret = "JBSWY3DPEHPK3PXP"

// wrongTOTPCode returns a six-digit code that the secret does not accept at
// the time.
func wrongTOTPCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	for _, code := range []string{"000000", "111111", "222222", "333333"} {
		if !VerifyTOTPAt(secret, code, at) {
			return code
		}
	}
	t.Fatal("no wrong code found")
	return ""
}

// enableTOTPWithRecoveryCodes enables TOTP with the secret for the account
// with the username in the default unit, gives it new recovery codes, and
// returns the account and the codes.
func enableTOTPWithRecoveryCodes(t *testing.T, s *store.Store, username, secret string) (store.User, []string) {
	t.Helper()
	ctx := context.Background()
	user, err := s.GetUserByUsername(ctx, username)
	if err != nil {
		t.Fatal(err)
	}
	plain, hashes, err := RecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	user.TOTPEnabled, user.TOTPSecret = true, secret
	if err := s.Tenant(store.DefaultTenantScope()).SaveUserSecurity(ctx, user, hashes, true, false, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	return user, plain
}

// auditCount counts the security audit records with the action that name
// the actor.
func auditCount(t *testing.T, s *store.Store, action, actor string) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE action=? AND actor_username=?`, action, actor).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// isWrongCodeAnswer reports whether a sign-in got the answer of a wrong
// one-time code.
func isWrongCodeAnswer(raw string, err error) bool {
	return raw == "" && err != nil && !errors.Is(err, ErrRateLimited) && err.Error() == "one-time code is required"
}

// An account's wrong one-time and recovery codes count against a budget of
// the account's own, whatever clients send them. Wrong codes with the right
// password from as many clients as the threshold, each well within its own
// budget, lock the account's second factor out: every sign-in, with any
// code or recovery code and from any client, then gets exactly the answer
// of a wrong code, and costs the client the same. Wrong passwords never
// reach the budget, other accounts keep signing in, the lockout is
// recorded once, and the right code signs in again once it ends.
func TestSecondFactorFailuresAreLimitedPerAccountWhateverTheClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	s, _ := clientBudgetStore(t, now)
	totpUser, codes := enableTOTPWithRecoveryCodes(t, s, "unit-totp", clientBudgetTOTPSecret)
	const otherSecret = "KRSXG5CTMVRXEZLU"
	enableTOTPWithRecoveryCodes(t, s, "unit-admin", otherSecret)
	m := NewManager(s)
	m.Now = func() time.Time { return now }
	clients := 0
	newClient := func() *http.Request {
		clients++
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = fmt.Sprintf("203.0.%d.%d:4000", 113+clients/250, clients%250+1)
		return r
	}
	signIn := func(r *http.Request, username, otp, recovery string) (string, error) {
		raw, _, err := m.LoginAs(ctx, r, username, username+" password", otp, recovery)
		return raw, err
	}

	// Wrong passwords, with any code, never reach the account's budget.
	for i := 0; i < 2*secondFactorFailureThreshold; i++ {
		if raw, _, err := m.LoginAs(ctx, newClient(), "unit-totp", "wrong password", wrongTOTPCode(t, clientBudgetTOTPSecret, now), ""); raw != "" || err == nil || err.Error() != "invalid credentials" {
			t.Fatalf("wrong password %d = %q, %v", i+1, raw, err)
		}
	}
	m.mu.Lock()
	_, recorded := m.secondFactor[totpUser.ID]
	m.mu.Unlock()
	if recorded {
		t.Fatal("wrong passwords reached the account's second-factor budget")
	}

	// The right password with wrong codes, each from a client of its own.
	for i := 0; i < secondFactorFailureThreshold; i++ {
		if raw, err := signIn(newClient(), "unit-totp", wrongTOTPCode(t, clientBudgetTOTPSecret, now), ""); !isWrongCodeAnswer(raw, err) {
			t.Fatalf("wrong code %d = %q, %v; want the answer of a wrong code", i+1, raw, err)
		}
	}

	// Every sign-in now gets the answer of a wrong code, whatever it sends.
	rightCode := totpCode(clientBudgetTOTPSecret, now.Unix()/30)
	for _, attempt := range []struct{ name, otp, recovery string }{
		{"the right code", rightCode, ""},
		{"a recovery code", "", codes[0]},
		{"a wrong code", wrongTOTPCode(t, clientBudgetTOTPSecret, now), ""},
		{"the right code and a recovery code", rightCode, codes[1]},
	} {
		r := newClient()
		if raw, err := signIn(r, "unit-totp", attempt.otp, attempt.recovery); !isWrongCodeAnswer(raw, err) {
			t.Fatalf("sign-in with %s during the lockout = %q, %v; want the answer of a wrong code", attempt.name, raw, err)
		}
		// The refusal costs the client what a wrong code does.
		budget := "login-client:" + strings.TrimPrefix(m.sourceScopeFor(r, "login"), "source:")
		m.mu.Lock()
		failures := len(m.loginClientFails[budget])
		m.mu.Unlock()
		if failures != 1 {
			t.Fatalf("sign-in with %s during the lockout cost the client %d failures, want 1", attempt.name, failures)
		}
	}
	// A client that sends nothing but refused sign-ins is throttled as a
	// client that sends wrong codes is.
	r := newClient()
	for i := 0; i < authFailureThreshold; i++ {
		if raw, err := signIn(r, "unit-totp", rightCode, ""); !isWrongCodeAnswer(raw, err) {
			t.Fatalf("refused sign-in %d from one client = %q, %v", i+1, raw, err)
		}
	}
	if _, err := signIn(r, "unit-totp", rightCode, ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("sign-in after %d refused sign-ins from one client = %v, want ErrRateLimited", authFailureThreshold, err)
	}

	// Nothing was spent: the codes stay unused, and no session exists.
	var unused, sessions int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at IS NULL`, totpUser.ID).Scan(&unused); err != nil || unused != len(codes) {
		t.Fatalf("unused recovery codes = %d, %v; want %d", unused, err, len(codes))
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id=?`, totpUser.ID).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("sessions = %d, %v; want none", sessions, err)
	}

	// Other accounts are not affected.
	if raw, err := signIn(newClient(), "unit-admin", totpCode(otherSecret, now.Unix()/30), ""); err != nil || raw == "" {
		t.Fatalf("another account with TOTP = %q, %v", raw, err)
	}
	if raw, err := signIn(newClient(), "unit-operator", "", ""); err != nil || raw == "" {
		t.Fatalf("another account without TOTP = %q, %v", raw, err)
	}

	// One record describes the lockout, and every refused sign-in has the
	// record of a wrong code.
	if got := auditCount(t, s, "auth.second_factor_locked", "unit-totp"); got != 1 {
		t.Fatalf("lockout records = %d, want 1", got)
	}
	var detail, tenant string
	if err := s.DB.QueryRow(`SELECT detail,COALESCE(tenant_id,'') FROM security_audit WHERE action='auth.second_factor_locked'`).Scan(&detail, &tenant); err != nil {
		t.Fatal(err)
	}
	if want := "one-time and recovery codes of unit-totp are refused for 15 minutes after 10 wrong codes"; detail != want || tenant != store.DefaultTenantID {
		t.Fatalf("lockout record = %q in %q, want %q in the default unit", detail, tenant, want)
	}
	if got, want := auditCount(t, s, "auth.totp_failed", "unit-totp"), secondFactorFailureThreshold+4+authFailureThreshold; got != want {
		t.Fatalf("wrong-code records = %d, want %d", got, want)
	}

	// The right code signs in once the lockout ends.
	now = now.Add(secondFactorLockoutBase)
	if raw, err := signIn(newClient(), "unit-totp", totpCode(clientBudgetTOTPSecret, now.Unix()/30), ""); err != nil || raw == "" {
		t.Fatalf("right code after the lockout = %q, %v", raw, err)
	}
	// The wrong codes stay counted for the window, so the next wrong code
	// starts the next lockout, twice as long.
	now = now.Add(time.Minute)
	if raw, err := signIn(newClient(), "unit-totp", wrongTOTPCode(t, clientBudgetTOTPSecret, now), ""); !isWrongCodeAnswer(raw, err) {
		t.Fatalf("wrong code after the lockout = %q, %v", raw, err)
	}
	now = now.Add(2*secondFactorLockoutBase - time.Second)
	if raw, err := signIn(newClient(), "unit-totp", "", codes[0]); !isWrongCodeAnswer(raw, err) {
		t.Fatalf("recovery code during the second lockout = %q, %v", raw, err)
	}
	now = now.Add(time.Second)
	if raw, err := signIn(newClient(), "unit-totp", "", codes[0]); err != nil || raw == "" {
		t.Fatalf("recovery code after the second lockout = %q, %v", raw, err)
	}
	if got := auditCount(t, s, "auth.second_factor_locked", "unit-totp"); got != 2 {
		t.Fatalf("lockout records after the second lockout = %d, want 2", got)
	}
}

// Through a shared loopback peer, whose short cooldown otherwise allows a
// wrong code every two seconds, the account's budget still locks its
// second factor out after the threshold, and the refusal is the answer of
// a wrong code, not the cooldown's.
func TestSecondFactorBudgetHoldsThroughASharedLoopbackPeer(t *testing.T) {
	t.Parallel()
	for _, peer := range []string{"127.0.0.1:443", "[::1]:443"} {
		t.Run(peer, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
			s, _ := clientBudgetStore(t, now)
			m := NewManager(s)
			m.Now = func() time.Time { return now }
			request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
			request.RemoteAddr = peer
			signIn := func(otp string) (string, error) {
				now = now.Add(authSharedLoopbackRetryDelay)
				raw, _, err := m.LoginAs(ctx, request, "unit-totp", "unit-totp password", otp, "")
				return raw, err
			}
			for i := 0; i < secondFactorFailureThreshold; i++ {
				if raw, err := signIn(wrongTOTPCode(t, clientBudgetTOTPSecret, now.Add(authSharedLoopbackRetryDelay))); !isWrongCodeAnswer(raw, err) {
					t.Fatalf("wrong code %d through the peer = %q, %v", i+1, raw, err)
				}
			}
			for i := 0; i < 3; i++ {
				if raw, err := signIn(totpCode(clientBudgetTOTPSecret, now.Add(authSharedLoopbackRetryDelay).Unix()/30)); !isWrongCodeAnswer(raw, err) {
					t.Fatalf("right code %d during the lockout through the peer = %q, %v; want the answer of a wrong code", i+1, raw, err)
				}
			}
			now = now.Add(secondFactorLockoutBase)
			if raw, err := signIn(totpCode(clientBudgetTOTPSecret, now.Add(authSharedLoopbackRetryDelay).Unix()/30)); err != nil || raw == "" {
				t.Fatalf("right code after the lockout through the peer = %q, %v", raw, err)
			}
		})
	}
}

// TOTP confirmations of a signed-in account share its budget with its
// sign-ins. A confirmation that the lockout refuses spends neither the time
// step nor the recovery code it carries, and gets the answer of a wrong
// code.
func TestTOTPConfirmationsShareTheAccountsSecondFactorBudget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	s, _ := clientBudgetStore(t, now)
	user, codes := enableTOTPWithRecoveryCodes(t, s, "unit-totp", clientBudgetTOTPSecret)
	m := NewManager(s)
	m.Now = func() time.Time { return now }
	clients := 0
	newClient := func(path string) *http.Request {
		clients++
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r.RemoteAddr = fmt.Sprintf("198.51.100.%d:4000", clients)
		return r
	}
	half := secondFactorFailureThreshold / 2
	for i := 0; i < half; i++ {
		if raw, _, err := m.LoginAs(ctx, newClient("/api/v1/auth/login"), "unit-totp", "unit-totp password", wrongTOTPCode(t, clientBudgetTOTPSecret, now), ""); !isWrongCodeAnswer(raw, err) {
			t.Fatalf("wrong code at sign-in %d = %q, %v", i+1, raw, err)
		}
	}
	for i := half; i < secondFactorFailureThreshold; i++ {
		if err := m.ConfirmTOTPForUser(ctx, newClient("/api/v1/auth/totp"), user.ID, wrongTOTPCode(t, clientBudgetTOTPSecret, now), ""); err == nil || errors.Is(err, ErrRateLimited) {
			t.Fatalf("wrong code at confirmation %d = %v", i+1, err)
		}
	}
	rightCode := totpCode(clientBudgetTOTPSecret, now.Unix()/30)
	for _, attempt := range []struct{ name, otp, recovery string }{{"the right code", rightCode, ""}, {"a recovery code", "", codes[0]}} {
		err := m.ConfirmTOTPForUser(ctx, newClient("/api/v1/auth/totp"), user.ID, attempt.otp, attempt.recovery)
		if err == nil || errors.Is(err, ErrRateLimited) || err.Error() != "current one-time code is required" {
			t.Fatalf("confirmation with %s during the lockout = %v; want the answer of a wrong code", attempt.name, err)
		}
	}
	if raw, _, err := m.LoginAs(ctx, newClient("/api/v1/auth/login"), "unit-totp", "unit-totp password", rightCode, ""); !isWrongCodeAnswer(raw, err) {
		t.Fatalf("sign-in during a lockout that confirmations started = %q, %v", raw, err)
	}
	if got := auditCount(t, s, "auth.second_factor_locked", "unit-totp"); got != 1 {
		t.Fatalf("lockout records = %d, want 1", got)
	}
	// The refused confirmations spent nothing: the right code and the
	// recovery code confirm once the lockout ends.
	now = now.Add(secondFactorLockoutBase)
	if err := m.ConfirmTOTPForUser(ctx, newClient("/api/v1/auth/totp"), user.ID, "", codes[0]); err != nil {
		t.Fatalf("recovery code after the lockout = %v", err)
	}
	var stepsRecorded int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM totp_replay WHERE user_id=?`, user.ID).Scan(&stepsRecorded); err != nil || stepsRecorded != 0 {
		t.Fatalf("time steps recorded = %d, %v; want none", stepsRecorded, err)
	}
	if err := m.ConfirmTOTPForUser(ctx, newClient("/api/v1/auth/totp"), user.ID, totpCode(clientBudgetTOTPSecret, now.Unix()/30), ""); err != nil {
		t.Fatalf("right code after the lockout = %v", err)
	}
}

// The budget admits no more concurrent checks than wrong codes would start
// a lockout, each wrong code after the threshold starts the next lockout,
// twice as long up to the maximum, and the record, with its doubling, ends
// once the account has had no wrong code for the window.
func TestSecondFactorLockoutsDoubleAndTheRecordExpires(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	m := NewManager(nil)
	m.Now = func() time.Time { return now }
	const account = "00000000-0000-0000-0000-00000000aa01"
	for i := 0; i < secondFactorFailureThreshold; i++ {
		if !m.admitSecondFactor(account, now) {
			t.Fatalf("concurrent check %d refused", i+1)
		}
	}
	if m.admitSecondFactor(account, now) {
		t.Fatal("a check beyond the budget was admitted while the others were in flight")
	}
	for i := 0; i < secondFactorFailureThreshold; i++ {
		m.releaseSecondFactor(account)
	}
	m.mu.Lock()
	_, kept := m.secondFactor[account]
	m.mu.Unlock()
	if kept {
		t.Fatal("the record of checks that all succeeded was kept")
	}
	fail := func() time.Duration {
		t.Helper()
		if !m.admitSecondFactor(account, now) {
			t.Fatal("check refused")
		}
		lockout := m.failedSecondFactor(account)
		m.releaseSecondFactor(account)
		return lockout
	}
	for i := 0; i < secondFactorFailureThreshold-2; i++ {
		if lockout := fail(); lockout != 0 {
			t.Fatalf("wrong code %d started a lockout of %s", i+1, lockout)
		}
	}
	// Two wrong codes are left, so two checks may be in flight, and they
	// start the lockout together.
	for i := 0; i < 2; i++ {
		if !m.admitSecondFactor(account, now) {
			t.Fatalf("check %d of the two left was refused", i+1)
		}
	}
	if m.admitSecondFactor(account, now) {
		t.Fatal("a third check was admitted with two wrong codes left")
	}
	if m.failedSecondFactor(account) != 0 || m.failedSecondFactor(account) != secondFactorLockoutBase {
		t.Fatal("the threshold did not start the first lockout")
	}
	m.releaseSecondFactor(account)
	m.releaseSecondFactor(account)
	lockout := secondFactorLockoutBase
	for _, next := range []time.Duration{30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 4 * time.Hour} {
		now = now.Add(lockout - time.Second)
		if m.admitSecondFactor(account, now) {
			t.Fatalf("check admitted a second before the end of a %s lockout", lockout)
		}
		now = now.Add(time.Second)
		// Once the threshold is reached, one check at a time.
		if !m.admitSecondFactor(account, now) || m.admitSecondFactor(account, now) {
			t.Fatalf("after a %s lockout, the checks admitted are not exactly one", lockout)
		}
		if got := m.failedSecondFactor(account); got != next {
			t.Fatalf("lockout after a %s lockout = %s, want %s", lockout, got, next)
		}
		m.releaseSecondFactor(account)
		lockout = next
	}
	now = now.Add(lockout + secondFactorFailureWindow)
	m.mu.Lock()
	m.sweepLimiterLocked(now)
	_, kept = m.secondFactor[account]
	m.mu.Unlock()
	if kept {
		t.Fatal("the record outlived a window without wrong codes")
	}
	for i := 0; i < secondFactorFailureThreshold-1; i++ {
		if lockout := fail(); lockout != 0 {
			t.Fatalf("wrong code %d of a new record started a lockout of %s", i+1, lockout)
		}
	}
	if got := fail(); got != secondFactorLockoutBase {
		t.Fatalf("first lockout of a new record = %s, want %s", got, secondFactorLockoutBase)
	}
	// A release without a record, as after a sweep, changes nothing.
	m.releaseSecondFactor("00000000-0000-0000-0000-00000000aa02")
	for lockout, want := range map[time.Duration]string{15 * time.Minute: "15 minutes", time.Hour: "1 hour", 4 * time.Hour: "4 hours"} {
		if got := lockoutText(lockout); got != want {
			t.Errorf("lockoutText(%s) = %q, want %q", lockout, got, want)
		}
	}
}

// A platform administrator's lockout is recorded in platform scope, where
// the attempts on its account are.
func TestSecondFactorLockoutOfAPlatformAdministratorIsAPlatformRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	s, _ := clientBudgetStore(t, now)
	if _, err := s.DB.Exec(`UPDATE users SET totp_enabled=1 WHERE username='platform-root'`); err != nil {
		t.Fatal(err)
	}
	root, err := s.GetUserByUsername(ctx, "platform-root")
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(s)
	m.Now = func() time.Time { return now }
	for i := 0; i < secondFactorFailureThreshold; i++ {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp", nil)
		r.RemoteAddr = fmt.Sprintf("192.0.2.%d:4000", i+1)
		if err := m.ConfirmTOTPForUser(ctx, r, root.ID, "000000", ""); err == nil {
			t.Fatalf("confirmation %d without a secret succeeded", i+1)
		}
	}
	var tenant string
	if err := s.DB.QueryRow(`SELECT COALESCE(tenant_id,'<null>') FROM security_audit WHERE action='auth.second_factor_locked' AND actor_username='platform-root'`).Scan(&tenant); err != nil || tenant != "<null>" {
		t.Fatalf("platform administrator's lockout record scope = %q, %v; want platform scope", tenant, err)
	}
}
