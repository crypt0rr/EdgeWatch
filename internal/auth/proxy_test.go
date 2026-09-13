package auth

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
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
	if got := m.ClientIP(request); got != "2001:db8::10" {
		t.Fatalf("Forwarded client = %q", got)
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
	s, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
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
