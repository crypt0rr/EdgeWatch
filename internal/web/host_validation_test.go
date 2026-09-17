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
