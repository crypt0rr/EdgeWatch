package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
)

func TestValidateRequestHostAllowsLoopbackAndConfiguredProxyNames(t *testing.T) {
	server := &Server{App: &app.App{Config: &config.Config{Web: config.Web{
		Listen:       "127.0.0.1:8080",
		AllowedHosts: []string{"console.example.test:8443", "2001:db8::10"},
	}}}}
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1:54321", true},
		{"[::1]:8080", true},
		{"localhost:8080", true},
		{"console.example.test:443", true},
		{"2001:db8::10", true},
		{"attacker.example.test", false},
	}
	for _, test := range cases {
		urlHost := test.host
		if len(urlHost) > 0 && urlHost[0] != '[' && strings.Count(urlHost, ":") > 1 {
			urlHost = "[" + urlHost + "]"
		}
		req := httptest.NewRequest(http.MethodGet, "http://"+urlHost+"/api/v1/status", nil)
		req.Host = test.host
		if got := server.validateRequestHost(req); got != test.want {
			t.Errorf("validateRequestHost(%q) = %v, want %v", test.host, got, test.want)
		}
	}
}

func TestHandlerRejectsForeignAPIHostBeforeAuthentication(t *testing.T) {
	server := &Server{App: &app.App{Config: &config.Config{Web: config.Web{Listen: "127.0.0.1:8080"}}}}
	req := httptest.NewRequest(http.MethodGet, "http://evil.example.test/api/v1/setup/status", nil)
	req.Host = "evil.example.test"
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("foreign API host status = %d, want %d", rec.Code, http.StatusMisdirectedRequest)
	}
}

func TestValidateBrowserOriginRequiresExactRequestOrigin(t *testing.T) {
	cases := []struct {
		name   string
		origin string
		host   string
		want   bool
	}{
		{name: "missing origin", host: "127.0.0.1:8080", want: true},
		{name: "same origin", origin: "https://console.example.test:8443", host: "console.example.test:8443", want: true},
		{name: "case insensitive host", origin: "HTTP://CONSOLE.EXAMPLE.TEST:8443", host: "console.example.test:8443", want: true},
		{name: "null origin", origin: "null", host: "console.example.test:8443", want: false},
		{name: "foreign host", origin: "https://attacker.example.test", host: "console.example.test:8443", want: false},
		{name: "path", origin: "https://console.example.test:8443/console", host: "console.example.test:8443", want: false},
		{name: "query", origin: "https://console.example.test:8443?next=login", host: "console.example.test:8443", want: false},
		{name: "userinfo", origin: "https://admin@console.example.test:8443", host: "console.example.test:8443", want: false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://"+test.host+"/api/v1/auth/login", nil)
			req.Host = test.host
			if test.origin != "" {
				req.Header.Set("Origin", test.origin)
			}
			if got := validateBrowserOrigin(req); got != test.want {
				t.Fatalf("validateBrowserOrigin(%q, %q) = %v, want %v", test.origin, test.host, got, test.want)
			}
		})
	}
	urlFallback := httptest.NewRequest(http.MethodPost, "https://console.example.test:8443/api/v1/auth/login", nil)
	urlFallback.Host = ""
	urlFallback.Header.Set("Origin", "https://console.example.test:8443")
	if !validateBrowserOrigin(urlFallback) {
		t.Fatal("browser origin did not use URL host fallback")
	}
}

func TestUnauthenticatedMutationRoutesRejectForeignOrigins(t *testing.T) {
	server := &Server{}
	for _, path := range []string{"/api/v1/setup", "/api/v1/auth/login", "/api/v1/auth/activate"} {
		req := httptest.NewRequest(http.MethodPost, "http://localhost"+path, strings.NewReader(`{}`))
		req.Header.Set("Origin", "https://attacker.example.test")
		rec := httptest.NewRecorder()
		server.api(rec, req)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"origin"`) {
			t.Fatalf("%s origin response = %d %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestHostHelpersHandleURLFallbackAndEmptyValues(t *testing.T) {
	if requestHostName("[2001:db8::1]") != "2001:db8::1" || requestHostName("Example.TEST.") != "example.test" || requestHostName("") != "" {
		t.Fatal("request host normalization failed")
	}
	server := &Server{App: &app.App{Config: &config.Config{Web: config.Web{Listen: "127.0.0.1:8080"}}}}
	for _, test := range []struct {
		host, urlHost string
		want          bool
	}{
		{host: "", urlHost: "127.0.0.1:8080", want: true},
		{host: "", urlHost: "", want: false},
		{host: "attacker.example.test", urlHost: "", want: false},
	} {
		req := httptest.NewRequest(http.MethodGet, "http://"+test.urlHost+"/api/v1/status", nil)
		req.Host = test.host
		if got := server.validateRequestHost(req); got != test.want {
			t.Errorf("validateRequestHost(%q,%q) = %v, want %v", test.host, test.urlHost, got, test.want)
		}
	}
}
