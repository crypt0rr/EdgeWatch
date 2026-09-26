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
