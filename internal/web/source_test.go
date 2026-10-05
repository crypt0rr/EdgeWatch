package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
)

func TestPublicSourceLink(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, version, override, want string
	}{
		{"release", "v0.25.0", "", "https://github.com/crypt0rr/EdgeWatch/tree/v0.25.0"},
		{"custom", "v0.25.0", "https://source.example.test/fork/v2", "https://source.example.test/fork/v2"},
		{"development", "dev", "", "https://github.com/crypt0rr/EdgeWatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := NewServer(&app.App{Version: test.version, Config: &config.Config{Web: config.Web{SourceURL: test.override}}}, nil, nil)
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				response := httptest.NewRecorder()
				server.Handler().ServeHTTP(response, httptest.NewRequest(method, "/source", nil))
				if response.Code != http.StatusFound || response.Header().Get("Location") != test.want {
					t.Errorf("%s /source = %d %q, want 302 %q", method, response.Code, response.Header().Get("Location"), test.want)
				}
				if response.Header().Get("Cache-Control") != "no-store" {
					t.Errorf("%s /source cache header = %q", method, response.Header().Get("Cache-Control"))
				}
			}
		})
	}
}

func TestSourceLinkRejectsMutations(t *testing.T) {
	t.Parallel()
	server := NewServer(nil, nil, nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/source", nil))
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST /source = %d, Allow %q", response.Code, response.Header().Get("Allow"))
	}
}
