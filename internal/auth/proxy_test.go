package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestClientIPIgnoresUntrustedForwardingHeaders(t *testing.T) {
	m := NewManager(nil)
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "127.0.0.1:8080"
	request.Header.Set("X-Forwarded-For", "198.51.100.10")
	if got := m.ClientIP(request); got != "127.0.0.1" {
		t.Fatalf("untrusted forwarded client = %q", got)
	}
}

func TestIsTrustedProxyOnlyConsidersDirectPeer(t *testing.T) {
	m := NewManager(nil)
	if err := m.SetTrustedProxies([]string{"127.0.0.1/32"}); err != nil {
		t.Fatal(err)
	}
	trusted := httptest.NewRequest("GET", "/", nil)
	trusted.RemoteAddr = "127.0.0.1:8080"
	trusted.Header.Set("X-Forwarded-For", "198.51.100.10")
	if !m.IsTrustedProxy(trusted) {
		t.Fatal("configured proxy peer was not trusted")
	}
	untrusted := httptest.NewRequest("GET", "/", nil)
	untrusted.RemoteAddr = "198.51.100.10:8080"
	untrusted.Header.Set("X-Forwarded-For", "127.0.0.1")
	if m.IsTrustedProxy(untrusted) {
		t.Fatal("forwarded header changed trust decision")
	}
}

func TestClientIPResolvesConfiguredProxyChain(t *testing.T) {
	m := NewManager(nil)
	if err := m.SetTrustedProxies([]string{"127.0.0.1/32", "10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "127.0.0.1:8080"
	request.Header.Set("X-Forwarded-For", "198.51.100.10, 10.2.3.4")
	if got := m.ClientIP(request); got != "198.51.100.10" {
		t.Fatalf("resolved client = %q", got)
	}
	request.Header.Del("X-Forwarded-For")
	request.Header.Set("Forwarded", `for="[2001:db8::10]:443";proto=https`)
	if err := m.SetForwardedHeader("forwarded"); err != nil {
		t.Fatal(err)
	}
	if got := m.ClientIP(request); got != "2001:db8::10" {
		t.Fatalf("Forwarded client = %q", got)
	}
}

func TestClientIPUsesXForwardedForWhenBothHeadersArePresent(t *testing.T) {
	m := NewManager(nil)
	if err := m.SetTrustedProxies([]string{"10.0.0.5/32"}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "10.0.0.5:8080"
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	request.Header.Set("Forwarded", "for=198.51.100.77")

	if got := m.ClientIP(request); got != "203.0.113.9" {
		t.Fatalf("client IP with both forwarding headers = %q, want proxy-provided X-Forwarded-For", got)
	}
}

func TestClientIPUsesConfiguredForwardedHeaderOnly(t *testing.T) {
	m := NewManager(nil)
	if err := m.SetTrustedProxies([]string{"10.0.0.5/32"}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "10.0.0.5:8080"
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	request.Header.Set("Forwarded", "for=198.51.100.77")
	if err := m.SetForwardedHeader(" Forwarded "); err != nil {
		t.Fatal(err)
	}
	if got := m.ClientIP(request); got != "198.51.100.77" {
		t.Fatalf("client IP with explicit Forwarded policy = %q, want 198.51.100.77", got)
	}
	request.Header.Set("Forwarded", "proto=https;host=edgewatch.example.test")
	if got := m.ClientIP(request); got != "10.0.0.5" {
		t.Fatalf("client IP with configured Forwarded lacking for= = %q, want proxy peer", got)
	}
	if err := m.SetForwardedHeader("none"); err != nil {
		t.Fatal(err)
	}
	if got := m.ClientIP(request); got != "10.0.0.5" {
		t.Fatalf("client IP with forwarding disabled = %q, want trusted proxy peer", got)
	}
	if err := m.SetForwardedHeader("x-real-ip"); err == nil {
		t.Fatal("unsupported forwarding header was accepted")
	}
}

func TestClientIPUsesXForwardedForWhenForwardedHasNoForParameter(t *testing.T) {
	m := NewManager(nil)
	if err := m.SetTrustedProxies([]string{"10.0.0.5/32"}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "10.0.0.5:8080"
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	request.Header.Set("Forwarded", "proto=https;host=edgewatch.example.test")

	if got := m.ClientIP(request); got != "203.0.113.9" {
		t.Fatalf("client IP with unusable Forwarded header = %q, want X-Forwarded-For", got)
	}
}

func TestLoginRateLimitCannotBeBypassedByRotatingForwardedHeader(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := NewManager(s)
	if err := m.SetTrustedProxies([]string{"10.0.0.5/32"}); err != nil {
		t.Fatal(err)
	}
	token, err := m.EnsureSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Setup(ctx, token, "administrator password"); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	request.RemoteAddr = "10.0.0.5:8080"
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	spoofedAddresses := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4", "198.51.100.5"}
	for _, address := range spoofedAddresses {
		request.Header.Set("Forwarded", "for="+address)
		if _, _, err := m.LoginAs(ctx, request, "admin", "wrong administrator password", "", ""); err == nil || errors.Is(err, ErrRateLimited) {
			t.Fatalf("failure from spoofed Forwarded address %s returned %v, want invalid credentials", address, err)
		}
	}
	request.Header.Set("Forwarded", "for=198.51.100.6")
	if _, _, err := m.LoginAs(ctx, request, "admin", "wrong administrator password", "", ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("login after %d failures with rotating Forwarded values = %v, want rate limited", authFailureThreshold, err)
	}
}

func TestSharedLoopbackLoginAttemptsAreCooledDownAndCanRecover(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := NewManager(s)
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { return now }
	token, err := m.EnsureSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Setup(ctx, token, "administrator password"); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "127.0.0.1:443"
	for attempt := 0; attempt < authFailureThreshold; attempt++ {
		if _, _, err := m.LoginAs(ctx, request, "admin", "wrong administrator password", "", ""); err == nil || errors.Is(err, ErrRateLimited) {
			t.Fatalf("failure %d = %v, want invalid credentials before the cooldown", attempt+1, err)
		}
	}
	if _, _, err := m.LoginAs(ctx, request, "admin", "wrong administrator password", "", ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("attempt during shared-loopback cooldown = %v, want rate limited", err)
	} else if got := RetryAfterHeaderValue(err); got != "2" {
		t.Fatalf("shared-loopback Retry-After = %q, want 2", got)
	}
	if _, _, err := m.LoginAs(ctx, request, "not-an-account", "wrong administrator password", "", ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("unknown username during shared-loopback cooldown = %v, want the same rate limit", err)
	} else if got := RetryAfterHeaderValue(err); got != "2" {
		t.Fatalf("unknown username Retry-After = %q, want same 2-second cooldown", got)
	}

	// A client behind the same tunnel can sign in as soon as the short cooldown
	// expires; the shared proxy peer is never placed in a five-minute lockout.
	now = now.Add(authSharedLoopbackRetryDelay)
	raw, user, err := m.LoginAs(ctx, request, "admin", "administrator password", "", "")
	if err != nil || raw == "" || user.Username != "admin" {
		t.Fatalf("valid login after cooldown = session %q, user %#v, err %v", raw, user, err)
	}
}

func TestRetryAfterHeaderValueUsesSharedLoopbackCooldown(t *testing.T) {
	if got := RetryAfterHeaderValue(ErrRateLimited); got != "300" {
		t.Fatalf("default rate-limit Retry-After = %q, want 300", got)
	}
	m := NewManager(nil)
	sharedLimit := m.rateLimitError("source:login:127.0.0.1", "login:admin")
	if !errors.Is(sharedLimit, ErrRateLimited) || sharedLimit.Error() != ErrRateLimited.Error() || RetryAfterHeaderValue(sharedLimit) != "2" {
		t.Fatalf("shared loopback without a failure cooldown = %v, Retry-After %q", sharedLimit, RetryAfterHeaderValue(sharedLimit))
	}
	m.blocked["source:login:127.0.0.1"] = time.Now().Add(-time.Second)
	if got := m.rateLimitError("source:login:127.0.0.1", "login:admin"); !errors.Is(got, ErrRateLimited) || RetryAfterHeaderValue(got) != "2" {
		t.Fatalf("expired shared loopback cooldown = %v, Retry-After %q", got, RetryAfterHeaderValue(got))
	}
}

func TestRotatingUnknownUsernamesRemainThrottledForRemotePeers(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := NewManager(s)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "198.51.100.44:443"
	for attempt := 0; attempt < authFailureThreshold; attempt++ {
		username := "missing-user-" + strconv.Itoa(attempt)
		if _, _, err := m.LoginAs(ctx, request, username, "wrong password", "", ""); err == nil || errors.Is(err, ErrRateLimited) {
			t.Fatalf("unknown login %d = %v, want generic invalid credentials", attempt+1, err)
		}
	}
	if _, _, err := m.LoginAs(ctx, request, "another-missing-user", "wrong password", "", ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("rotating unknown usernames bypassed the remote source budget: %v", err)
	}
}

// Once a client identified by its own address has used its sign-in budget,
// here with usernames that no account has, every sign-in from it gets the
// same rate-limit error until the block ends: an unknown name, an enabled or a
// disabled account of the default unit, an account of another unit, and a
// platform administrator alike, with a wrong or a right password. No
// password is checked and no failed sign-in is recorded, so neither the
// answer nor its cost tells which names exist. Another client still gets
// the ordinary answer, and the client signs in again once the block ends.
func TestThrottledSignInAnswerDoesNotDependOnTheUsername(t *testing.T) {
	ctx := context.Background()
	s, admin, _ := platformTestStore(t)
	addSecondUnit(t, s)
	if _, err := s.Tenant(store.DefaultTenantScope()).CreateUser(ctx, store.User{Username: "unit-disabled", Role: store.RoleViewer, PasswordHash: cheapHash("disabled viewer password"), Enabled: false}, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	scope, err := s.TenantScopeByID(ctx, platformTestTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Tenant(scope).CreateUser(ctx, store.User{Username: "bravo-viewer", Role: store.RoleViewer, PasswordHash: cheapHash("unit b viewer password"), Enabled: true}, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,enabled,created_at,updated_at) VALUES('00000000-0000-0000-0000-00000000fa02',NULL,'platform-root','platform-root',?,?,1,?,?)`, store.RolePlatformAdmin, cheapHash("platform administrator password"), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	m := NewManager(s)
	now := time.Now().UTC()
	m.Now = func() time.Time { return now }
	from := func(address string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = address + ":4000"
		return r
	}
	failedSignIns := func() int {
		t.Helper()
		var count int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE action='auth.login_failed'`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	const client, other = "203.0.113.50", "203.0.113.51"
	for attempt := 0; attempt < authFailureThreshold; attempt++ {
		if _, _, err := m.LoginAs(ctx, from(client), "guess-"+strconv.Itoa(attempt), "wrong password", "", ""); err == nil || errors.Is(err, ErrRateLimited) {
			t.Fatalf("unknown username %d = %v, want invalid credentials", attempt, err)
		}
	}
	failures := failedSignIns()
	for _, attempt := range []struct{ username, password string }{
		{"guess-x", "wrong password"},
		{admin.Username, "wrong password"},
		{"unit-disabled", "wrong password"},
		{"bravo-viewer", "wrong password"},
		{"platform-root", "wrong password"},
		{"nobody-here", "wrong password"},
		{admin.Username, "unit administrator password"},
	} {
		raw, _, err := m.LoginAs(ctx, from(client), attempt.username, attempt.password, "", "")
		if raw != "" || !errors.Is(err, ErrRateLimited) || err.Error() != ErrRateLimited.Error() || RetryAfterHeaderValue(err) != RetryAfterHeaderValue(ErrRateLimited) {
			t.Errorf("throttled sign-in as %s = %q, %v (Retry-After %s), want the rate-limit error every name gets", attempt.username, raw, err, RetryAfterHeaderValue(err))
		}
	}
	if got := failedSignIns(); got != failures {
		t.Errorf("throttled sign-ins recorded %d failed sign-ins, want none", got-failures)
	}

	// Another client gets the ordinary answers.
	if _, _, err := m.LoginAs(ctx, from(other), admin.Username, "wrong password", "", ""); err == nil || errors.Is(err, ErrRateLimited) || err.Error() != "invalid credentials" {
		t.Fatalf("wrong password from another client = %v, want invalid credentials", err)
	}
	if raw, _, err := m.LoginAs(ctx, from(other), admin.Username, "unit administrator password", "", ""); err != nil || raw == "" {
		t.Fatalf("sign-in from another client = %q, %v", raw, err)
	}

	// The block ends after its five minutes.
	now = now.Add(authBlockDuration)
	if raw, _, err := m.LoginAs(ctx, from(client), admin.Username, "unit administrator password", "", ""); err != nil || raw == "" {
		t.Fatalf("sign-in after the block = %q, %v", raw, err)
	}
}

// clientBudgetStore returns a store with accounts for each kind of failed
// sign-in: the default unit's enabled administrator and operator, a
// disabled account, an account with TOTP, an account of a second unit, an
// account of a disabled unit, and a platform administrator. Every
// password is "<username> password".
func clientBudgetStore(t *testing.T, now time.Time) (*store.Store, string) {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	stamp := now.Format(time.RFC3339Nano)
	const pausedTenantID = "00000000-0000-0000-0000-000000000300"
	for _, unit := range []struct{ id, name, slug string }{{platformTestTenantID, "Other", "other"}, {pausedTenantID, "Paused", "paused"}} {
		if _, err := s.DB.Exec(`INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,?,?,?,?)`, unit.id, unit.name, unit.slug, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	create := func(tenantID, username, role string, enabled bool) store.User {
		t.Helper()
		scope, err := s.TenantScopeByID(ctx, tenantID)
		if err != nil {
			t.Fatal(err)
		}
		user, err := s.Tenant(scope).CreateUser(ctx, store.User{Username: username, Role: role, PasswordHash: cheapHash(username + " password"), Enabled: enabled}, store.AuditEntry{})
		if err != nil {
			t.Fatal(err)
		}
		return user
	}
	create(store.DefaultTenantID, "unit-admin", store.RoleAdministrator, true)
	create(store.DefaultTenantID, "unit-operator", store.RoleOperator, true)
	create(store.DefaultTenantID, "unit-disabled", store.RoleViewer, false)
	totp := create(store.DefaultTenantID, "unit-totp", store.RoleViewer, true)
	totp.TOTPEnabled, totp.TOTPSecret = true, "JBSWY3DPEHPK3PXP"
	if err := s.Tenant(store.DefaultTenantScope()).SaveUserSecurity(ctx, totp, nil, false, false, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	create(platformTestTenantID, "bravo-viewer", store.RoleViewer, true)
	create(pausedTenantID, "paused-viewer", store.RoleViewer, true)
	if _, err := s.DB.Exec(`UPDATE tenants SET state='disabled' WHERE id=?`, pausedTenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,enabled,created_at,updated_at) VALUES('00000000-0000-0000-0000-00000000fa04',NULL,'platform-root','platform-root',?,?,1,?,?)`, store.RolePlatformAdmin, cheapHash("platform-root password"), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	// A one-time code that none of the accepted time steps has.
	wrongCode := "000000"
	for step := now.Unix()/30 - 1; step <= now.Unix()/30+1; step++ {
		if totpCode(totp.TOTPSecret, step) == wrongCode {
			wrongCode = "111111"
		}
	}
	return s, wrongCode
}

// A client identified by its own address has one budget of failed
// sign-ins, and every kind of failure costs it the same: a username that
// no account has, a wrong password for one account or for several, a
// disabled account, a wrong one-time or recovery code, and an account whose
// unit is disabled. After the same number of failures, whichever names they
// used, every sign-in from the client is refused with the same answer, even
// one with another account's right password. So the attempts a client has
// left do not tell which names exist. Another client is not affected, the
// client signs in again once the block ends, and the client's own bucket
// for an account still records that account's failures.
func TestEveryFailedSignInCountsAgainstTheClientBudget(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	s, wrongCode := clientBudgetStore(t, now)
	m := NewManager(s)
	m.Now = func() time.Time { return now }
	from := func(address string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = address + ":4000"
		return r
	}
	type attempt struct{ username, password, otp, recovery string }
	unknown := func(name string) attempt { return attempt{name, "wrong password", "", ""} }
	wrongPassword := func(username string) attempt { return attempt{username, "wrong password", "", ""} }
	rightPassword := func(username string) attempt { return attempt{username, username + " password", "", ""} }
	wrongOTP := attempt{"unit-totp", "unit-totp password", wrongCode, ""}
	wrongRecovery := attempt{"unit-totp", "unit-totp password", "", "not-a-recovery-code"}
	repeat := func(a attempt) []attempt {
		attempts := make([]attempt, authFailureThreshold)
		for i := range attempts {
			attempts[i] = a
		}
		return attempts
	}
	checks := []struct {
		name, client string
		attempts     []attempt
	}{
		{"usernames that no account has", "203.0.113.20", []attempt{unknown("guess-0"), unknown("guess-1"), unknown("guess-2"), unknown("guess-3"), unknown("guess-4")}},
		{"wrong passwords for one account", "203.0.113.21", repeat(wrongPassword("unit-admin"))},
		{"wrong passwords for several accounts", "203.0.113.22", []attempt{wrongPassword("unit-admin"), wrongPassword("unit-operator"), wrongPassword("bravo-viewer"), wrongPassword("platform-root"), wrongPassword("unit-totp")}},
		{"a disabled account", "203.0.113.23", repeat(rightPassword("unit-disabled"))},
		{"wrong one-time codes", "203.0.113.24", repeat(wrongOTP)},
		{"wrong recovery codes", "203.0.113.25", repeat(wrongRecovery)},
		{"an account whose unit is disabled", "203.0.113.26", repeat(rightPassword("paused-viewer"))},
		{"every kind of failure", "203.0.113.27", []attempt{unknown("guess-5"), wrongPassword("unit-admin"), rightPassword("unit-disabled"), wrongOTP, rightPassword("paused-viewer")}},
	}
	for _, check := range checks {
		if len(check.attempts) != authFailureThreshold {
			t.Fatalf("%s: %d attempts, want %d", check.name, len(check.attempts), authFailureThreshold)
		}
		for i, a := range check.attempts {
			if raw, _, err := m.LoginAs(ctx, from(check.client), a.username, a.password, a.otp, a.recovery); raw != "" || err == nil || errors.Is(err, ErrRateLimited) {
				t.Fatalf("%s: attempt %d as %s = %q, %v; want a failed sign-in", check.name, i+1, a.username, raw, err)
			}
		}
		for _, a := range []attempt{rightPassword("unit-operator"), unknown("guess-x"), wrongPassword("unit-admin")} {
			raw, _, err := m.LoginAs(ctx, from(check.client), a.username, a.password, a.otp, a.recovery)
			if raw != "" || !errors.Is(err, ErrRateLimited) || err.Error() != ErrRateLimited.Error() || RetryAfterHeaderValue(err) != RetryAfterHeaderValue(ErrRateLimited) {
				t.Errorf("%s: sign-in as %s after %d failures = %q, %v (Retry-After %s); want the rate-limit error", check.name, a.username, authFailureThreshold, raw, err, RetryAfterHeaderValue(err))
			}
		}
	}

	// The client's bucket for one account still records that account's
	// failures and blocks the account for the client.
	accountKey := scopedAccountKey(m.sourceScopeFor(from("203.0.113.21"), "login"), "login:unit-admin")
	m.mu.Lock()
	accountFailures, accountBlockedUntil := len(m.accountFails[accountKey]), m.accountBlocked[accountKey]
	m.mu.Unlock()
	if accountFailures != authFailureThreshold || !accountBlockedUntil.After(now) {
		t.Errorf("the client's bucket for unit-admin = %d failures, blocked until %s; want %d and a block", accountFailures, accountBlockedUntil, authFailureThreshold)
	}

	// Another client is not affected.
	if raw, _, err := m.LoginAs(ctx, from("203.0.113.28"), "unit-operator", "unit-operator password", "", ""); err != nil || raw == "" {
		t.Fatalf("sign-in from another client = %q, %v", raw, err)
	}

	// Each client signs in again once the block ends.
	now = now.Add(authBlockDuration)
	for _, check := range checks {
		if raw, _, err := m.LoginAs(ctx, from(check.client), "unit-operator", "unit-operator password", "", ""); err != nil || raw == "" {
			t.Errorf("%s: sign-in after the block = %q, %v", check.name, raw, err)
		}
	}
}

// A successful sign-in leaves the client's budget as it is: the client's
// failures stay counted until the block or the window ends. A client that
// holds one valid account therefore cannot sign in between failed attempts
// on other names to get more attempts. The success clears the failures in
// the client's bucket for the account it signed in to.
func TestSuccessfulSignInsDoNotExtendTheClientBudget(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	s, _ := clientBudgetStore(t, now)
	m := NewManager(s)
	m.Now = func() time.Time { return now }
	const client = "198.51.100.60"
	from := func(address string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = address + ":4000"
		return r
	}
	signIn := func(username, password string) (string, error) {
		now = now.Add(time.Second)
		raw, _, err := m.LoginAs(ctx, from(client), username, password, "", "")
		return raw, err
	}
	operatorKey := scopedAccountKey(m.sourceScopeFor(from(client), "login"), "login:unit-operator")
	for i, failure := range []struct{ username, password string }{
		{"unit-operator", "wrong password"},
		{"guess-0", "wrong password"},
		{"unit-admin", "wrong password"},
		{"unit-disabled", "unit-disabled password"},
		{"guess-1", "wrong password"},
	} {
		if raw, err := signIn(failure.username, failure.password); raw != "" || err == nil || errors.Is(err, ErrRateLimited) {
			t.Fatalf("failure %d as %s = %q, %v; want a failed sign-in", i+1, failure.username, raw, err)
		}
		if i == authFailureThreshold-1 {
			break
		}
		if raw, err := signIn("unit-operator", "unit-operator password"); err != nil || raw == "" {
			t.Fatalf("sign-in after failure %d = %q, %v", i+1, raw, err)
		}
		m.mu.Lock()
		operatorFailures := len(m.accountFails[operatorKey])
		m.mu.Unlock()
		if operatorFailures != 0 {
			t.Fatalf("after the operator signed in, the client's bucket for the operator holds %d failures, want none", operatorFailures)
		}
	}
	if raw, err := signIn("unit-operator", "unit-operator password"); raw != "" || !errors.Is(err, ErrRateLimited) {
		t.Fatalf("sign-in after %d failures with sign-ins between them = %q, %v; want ErrRateLimited", authFailureThreshold, raw, err)
	}
	if raw, err := signIn("guess-2", "wrong password"); raw != "" || !errors.Is(err, ErrRateLimited) {
		t.Fatalf("unknown username after %d failures with sign-ins between them = %q, %v; want ErrRateLimited", authFailureThreshold, raw, err)
	}

	// Another client signs in, and the client does once the block ends.
	if raw, _, err := m.LoginAs(ctx, from("198.51.100.61"), "unit-operator", "unit-operator password", "", ""); err != nil || raw == "" {
		t.Fatalf("sign-in from another client = %q, %v", raw, err)
	}
	now = now.Add(authBlockDuration)
	if raw, err := signIn("unit-operator", "unit-operator password"); err != nil || raw == "" {
		t.Fatalf("sign-in after the block = %q, %v", raw, err)
	}
}

// A sign-in that the password-check queue refuses checks no password, so
// it costs the client's budget nothing, whether or not the username
// exists: afterwards each client still has its whole budget.
func TestSignInRefusedByThePasswordCheckQueueCostsNoBudget(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	s, _ := clientBudgetStore(t, now)
	m := NewManager(s)
	m.Now = func() time.Time { return now }
	from := func(address string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = address + ":4000"
		return r
	}
	clients := []struct{ address, username string }{
		{"192.0.2.70", "nobody-here"},
		{"192.0.2.71", "unit-admin"},
		{"192.0.2.72", "unit-disabled"},
	}
	for i := 0; i < authArgon2MaxConcurrent; i++ {
		m.argon2Sem <- struct{}{}
	}
	for _, client := range clients {
		if raw, _, err := m.LoginAs(ctx, from(client.address), client.username, "wrong password", "", ""); raw != "" || !errors.Is(err, ErrRateLimited) {
			t.Fatalf("sign-in as %s with every password check busy = %q, %v; want ErrRateLimited", client.username, raw, err)
		}
	}
	for i := 0; i < authArgon2MaxConcurrent; i++ {
		<-m.argon2Sem
	}
	for _, client := range clients {
		for attempt := 0; attempt < authFailureThreshold; attempt++ {
			if _, _, err := m.LoginAs(ctx, from(client.address), "guess-"+strconv.Itoa(attempt), "wrong password", "", ""); err == nil || errors.Is(err, ErrRateLimited) {
				t.Fatalf("client that tried %s: failure %d = %v, want a failed sign-in", client.username, attempt+1, err)
			}
		}
		if _, _, err := m.LoginAs(ctx, from(client.address), "guess-x", "wrong password", "", ""); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("client that tried %s: sign-in over the budget = %v, want ErrRateLimited", client.username, err)
		}
	}
}

// A shared loopback peer keeps its short cooldown for every kind of failed
// sign-in, and has no five-minute block from the per-client budget.
func TestSharedLoopbackPeerKeepsItsCooldownForEveryFailure(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	s, wrongCode := clientBudgetStore(t, now)
	m := NewManager(s)
	m.Now = func() time.Time { return now }
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "127.0.0.1:443"
	for i, failure := range []struct{ username, password, otp string }{
		{"guess-0", "wrong password", ""},
		{"unit-admin", "wrong password", ""},
		{"unit-disabled", "unit-disabled password", ""},
		{"unit-totp", "unit-totp password", wrongCode},
		{"paused-viewer", "paused-viewer password", ""},
	} {
		if _, _, err := m.LoginAs(ctx, request, failure.username, failure.password, failure.otp, ""); err == nil || errors.Is(err, ErrRateLimited) {
			t.Fatalf("failure %d as %s = %v, want a failed sign-in", i+1, failure.username, err)
		}
	}
	for _, username := range []string{"unit-operator", "guess-1"} {
		if _, _, err := m.LoginAs(ctx, request, username, username+" password", "", ""); !errors.Is(err, ErrRateLimited) || RetryAfterHeaderValue(err) != "2" {
			t.Fatalf("sign-in as %s during the cooldown = %v (Retry-After %s), want the 2-second cooldown", username, err, RetryAfterHeaderValue(err))
		}
	}
	now = now.Add(authSharedLoopbackRetryDelay)
	if raw, _, err := m.LoginAs(ctx, request, "unit-operator", "unit-operator password", "", ""); err != nil || raw == "" {
		t.Fatalf("sign-in after the cooldown = %q, %v", raw, err)
	}
}

func TestSharedLoopbackTOTPFailuresAreCooledDown(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := NewManager(s)
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { return now }
	token, err := m.EnsureSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Setup(ctx, token, "administrator password"); err != nil {
		t.Fatal(err)
	}
	admin, err := s.GetAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	admin.TOTPEnabled = true
	admin.TOTPSecret = "JBSWY3DPEHPK3PXP"
	if err := s.SaveAdmin(ctx, admin); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "[::1]:443"
	for attempt := 0; attempt < authFailureThreshold; attempt++ {
		if _, _, err := m.LoginAs(ctx, request, "admin", "administrator password", "000000", ""); err == nil || errors.Is(err, ErrRateLimited) {
			t.Fatalf("wrong TOTP attempt %d = %v, want factor failure before the cooldown", attempt+1, err)
		}
	}
	if _, _, err := m.LoginAs(ctx, request, "admin", "administrator password", "000000", ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("TOTP attempt during cooldown = %v, want rate limited", err)
	}
	now = now.Add(authSharedLoopbackRetryDelay)
	code := totpCode(admin.TOTPSecret, now.Unix()/30)
	if raw, user, err := m.LoginAs(ctx, request, "admin", "administrator password", code, ""); err != nil || raw == "" || user.Username != "admin" {
		t.Fatalf("valid TOTP login after cooldown = session %q, user %#v, err %v", raw, user, err)
	}
}

func TestClientIPResolvesBracketedIPv6ProxyChain(t *testing.T) {
	m := NewManager(nil)
	if err := m.SetTrustedProxies([]string{"2001:db8::1/128"}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "[2001:db8::1]:443"
	request.Header.Set("X-Forwarded-For", "[2001:db8::10]:8443")
	if got := m.ClientIP(request); got != "2001:db8::10" {
		t.Fatalf("resolved bracketed IPv6 client = %q", got)
	}
}

func TestClientIPPreservesBareIPv6Address(t *testing.T) {
	m := NewManager(nil)
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "2001:db8::10"
	if got := m.ClientIP(request); got != "2001:db8::10" {
		t.Fatalf("bare IPv6 client = %q", got)
	}
	request.RemoteAddr = "[2001:db8::10]"
	if got := m.ClientIP(request); got != "2001:db8::10" {
		t.Fatalf("bracketed bare IPv6 client = %q", got)
	}
}

func TestLimiterKeyUsesStandardHostPortParsing(t *testing.T) {
	cases := map[string]string{
		"192.0.2.10:443":        "192.0.2.10",
		"[2001:db8::10]:443":    "2001:db8::10",
		"2001:db8::10":          "2001:db8::10",
		"[2001:db8::10]":        "2001:db8::10",
		"malformed-remote-addr": "malformed-remote-addr",
	}
	for input, want := range cases {
		if got := limiterKey(input); got != want {
			t.Errorf("limiterKey(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestClientIPRejectsInvalidTrustedProxy(t *testing.T) {
	m := NewManager(nil)
	if err := m.SetTrustedProxies([]string{"not-an-ip"}); err == nil {
		t.Fatal("invalid trusted proxy was accepted")
	}
}

func TestLoginAuditRecordsResolvedClientIP(t *testing.T) {
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	hash, err := PasswordHash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.SaveAdmin(context.Background(), store.Admin{Username: "admin", PasswordHash: hash, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	m := NewManager(s)
	if err := m.SetTrustedProxies([]string{"127.0.0.1/32"}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	request.RemoteAddr = "127.0.0.1:8080"
	request.Header.Set("X-Forwarded-For", "198.51.100.20")
	if _, _, err := m.LoginAs(context.Background(), request, "admin", "correct horse battery staple", "", ""); err != nil {
		t.Fatal(err)
	}
	var source string
	if err := s.DB.QueryRowContext(context.Background(), `SELECT source_ip FROM security_audit WHERE action='admin.login' ORDER BY id DESC LIMIT 1`).Scan(&source); err != nil {
		t.Fatal(err)
	}
	if source != "198.51.100.20" {
		t.Fatalf("audit source = %q", source)
	}
}
