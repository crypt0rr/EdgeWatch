package auth

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func addAuthTestSessionCookie(request *http.Request, value string) {
	name := SessionCookie
	if SessionCookieSecure(request, false) {
		name = SecureSessionCookie
	}
	request.AddCookie(&http.Cookie{Name: name, Value: value})
}

func TestSessionCookieSecureTransport(t *testing.T) {
	t.Parallel()

	if !SessionCookieSecure(nil, false) {
		t.Fatal("nil request must default to the secure cookie")
	}

	tests := []struct {
		name                string
		target              string
		host                string
		tls                 bool
		trustedForwardedTLS bool
		want                bool
	}{
		{name: "IPv4 loopback", target: "http://127.0.0.1:8080/", host: "127.0.0.1:8080"},
		{name: "IPv6 loopback", target: "http://[::1]:8080/", host: "[::1]:8080"},
		{name: "bracketed IPv6 without port", target: "http://[::1]/", host: "[::1]"},
		{name: "localhost", target: "http://localhost:8080/", host: "LOCALHOST:8080"},
		{name: "URL host fallback", target: "http://localhost:8080/", want: false},
		{name: "empty host", target: "/", host: "", want: true},
		{name: "external host", target: "http://console.example.test/", host: "console.example.test", want: true},
		{name: "HTTPS URL", target: "https://console.example.test/", host: "console.example.test", want: true},
		{name: "TLS loopback", target: "http://127.0.0.1:8080/", host: "127.0.0.1:8080", tls: true, want: true},
		{name: "trusted forwarded HTTPS", target: "http://127.0.0.1:8080/", host: "127.0.0.1:8080", trustedForwardedTLS: true, want: true},
		{name: "malformed host", target: "http://console.example.test/", host: "invalid host", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			request.Host = test.host
			if test.tls {
				request.TLS = &tls.ConnectionState{}
			}
			if got := SessionCookieSecure(request, test.trustedForwardedTLS); got != test.want {
				t.Fatalf("SessionCookieSecure(%q) = %t, want %t", test.host, got, test.want)
			}
		})
	}
}

func TestForwardedRequestIsHTTPS(t *testing.T) {
	t.Parallel()

	if forwardedRequestIsHTTPS(nil) {
		t.Fatal("nil request cannot indicate forwarded HTTPS")
	}
	tests := []struct {
		name       string
		xForwarded []string
		forwarded  []string
		want       bool
	}{
		{name: "X-Forwarded-Proto list", xForwarded: []string{"http", "http, HTTPS"}, want: true},
		{name: "Forwarded parameters and elements", forwarded: []string{"proto=http", `for=198.51.100.10;proto="HTTPS"`}, want: true},
		{name: "non-HTTPS protocols", xForwarded: []string{"http, ftp"}, forwarded: []string{"for=198.51.100.10;proto=http"}},
		{name: "malformed Forwarded parameters", forwarded: []string{"missing-equals;for=198.51.100.10;proto=http"}},
		{name: "no protocol headers"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
			for _, value := range test.xForwarded {
				request.Header.Add("X-Forwarded-Proto", value)
			}
			for _, value := range test.forwarded {
				request.Header.Add("Forwarded", value)
			}
			if got := forwardedRequestIsHTTPS(request); got != test.want {
				t.Fatalf("forwardedRequestIsHTTPS() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestManagerSessionCookieSecureTrustsForwardedHTTPS(t *testing.T) {
	t.Parallel()
	manager := NewManager(nil)
	if err := manager.SetTrustedProxies([]string{"127.0.0.1/32"}); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/", nil)
	request.Host = "127.0.0.1:8080"
	request.RemoteAddr = "127.0.0.1:9000"
	request.Header.Set("X-Forwarded-Proto", "http, HTTPS")
	if !manager.SessionCookieSecure(request) {
		t.Fatal("trusted X-Forwarded-Proto did not select the secure cookie")
	}

	request.Header.Del("X-Forwarded-Proto")
	request.Header.Set("Forwarded", `for=198.51.100.10;proto="https"`)
	if !manager.SessionCookieSecure(request) {
		t.Fatal("trusted Forwarded proto did not select the secure cookie")
	}

	request.RemoteAddr = "198.51.100.20:9000"
	if manager.SessionCookieSecure(request) {
		t.Fatal("untrusted peer changed the cookie security decision")
	}

	var nilManager *Manager
	if !nilManager.SessionCookieSecure(httptest.NewRequest(http.MethodGet, "http://console.example.test/", nil)) {
		t.Fatal("nil manager should retain secure defaults for external hosts")
	}
}

func TestSessionCookieFromRequestRejectsNilRequest(t *testing.T) {
	t.Parallel()
	if cookie, ok := SessionCookieFromRequest(nil, false); cookie != nil || ok {
		t.Fatalf("SessionCookieFromRequest(nil) = (%#v, %t), want (nil, false)", cookie, ok)
	}
}
