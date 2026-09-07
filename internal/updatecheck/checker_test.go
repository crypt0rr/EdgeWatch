package updatecheck

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func tlsClient(server *httptest.Server) *Client {
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // test server certificate only
	return &Client{Endpoint: server.URL, HTTPClient: &http.Client{Transport: transport}}
}

func TestNormalizeAndCompareVersions(t *testing.T) {
	for raw, want := range map[string]string{"v1.2.3": "v1.2.3", "1.2.3": "v1.2.3", "v1.2": "v1.2.0", "v1.2.3+build.7": "v1.2.3", "dev": "", "": ""} {
		if got := NormalizeVersion(raw); got != want {
			t.Fatalf("NormalizeVersion(%q) = %q, want %q", raw, got, want)
		}
	}
	if CompareVersions("v1.3.0", "v1.2.9") <= 0 || CompareVersions("v1.2.9", "v1.3.0") >= 0 {
		t.Fatal("semantic comparison did not order releases")
	}
	if got := ReleasePageURL("1.2.3"); got != "https://github.com/crypt0rr/EdgeWatch/releases/tag/v1.2.3" {
		t.Fatalf("release page URL = %q", got)
	}
}

func TestCheckSuccessAndNotModified(t *testing.T) {
	var seenETag string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenETag = r.Header.Get("If-None-Match")
		if seenETag == `"release"` {
			w.Header().Set("ETag", `"release"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("User-Agent") == "" {
			http.Error(w, "missing headers", http.StatusBadRequest)
			return
		}
		w.Header().Set("ETag", `"release"`)
		fmt.Fprint(w, `{"tag_name":"v1.4.0","html_url":"https://github.com/crypt0rr/EdgeWatch/releases/tag/v1.4.0","name":"Release 1.4","published_at":"2026-09-07T12:00:00Z"}`)
	}))
	defer server.Close()
	client := tlsClient(server)
	result, err := client.Check(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Release.Version != "v1.4.0" || result.Release.URL != "https://github.com/crypt0rr/EdgeWatch/releases/tag/v1.4.0" || result.ETag != `"release"` {
		t.Fatalf("unexpected release result %#v", result)
	}
	result, err = client.Check(t.Context(), result.ETag)
	if err != nil || !result.NotModified || seenETag != `"release"` {
		t.Fatalf("304 result %#v err=%v etag=%q", result, err, seenETag)
	}
}

func TestCheckRejectsUnsafeOrInvalidResponses(t *testing.T) {
	for name, body := range map[string]string{
		"prerelease":                  `{"tag_name":"v1.4.0-rc.1","prerelease":true}`,
		"prerelease tag without flag": `{"tag_name":"v1.4.0-rc.1","prerelease":false}`,
		"invalid version":             `{"tag_name":"latest"}`,
		"invalid release URL":         `{"tag_name":"v1.4.0","html_url":"javascript:alert(1)"}`,
		"non-release GitHub URL":      `{"tag_name":"v1.4.0","html_url":"https://github.com/crypt0rr/EdgeWatch"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) }))
			defer server.Close()
			if _, err := tlsClient(server).Check(t.Context(), ""); err == nil {
				t.Fatal("expected response validation error")
			}
		})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, strings.Repeat("x", 32)) }))
	defer server.Close()
	client := tlsClient(server)
	client.MaxResponseBytes = 8
	if _, err := client.Check(t.Context(), ""); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected response size error, got %v", err)
	}
}

func TestCheckRejectsHTTPAndCrossHostRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{}`) }))
	defer server.Close()
	if _, err := (&Client{Endpoint: server.URL}).Check(t.Context(), ""); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS endpoint error, got %v", err)
	}
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.invalid/release", http.StatusFound)
	}))
	defer redirect.Close()
	if _, err := tlsClient(redirect).Check(t.Context(), ""); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect policy error, got %v", err)
	}
}

func TestCheckAllowsThreeSameHostRedirectsButNoMore(t *testing.T) {
	var redirects int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirects++
		if redirects <= 3 {
			http.Redirect(w, r, "/latest", http.StatusFound)
			return
		}
		fmt.Fprint(w, `{"tag_name":"v1.5.0","html_url":"https://github.com/crypt0rr/EdgeWatch/releases/tag/v1.5.0"}`)
	}))
	defer server.Close()
	if _, err := tlsClient(server).Check(t.Context(), ""); err != nil {
		t.Fatalf("three same-host redirects should be allowed: %v", err)
	}

	tooMany := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirects++
		if redirects <= 4 {
			http.Redirect(w, r, "/latest", http.StatusFound)
			return
		}
		fmt.Fprint(w, `{}`)
	}))
	defer tooMany.Close()
	redirects = 0
	if _, err := tlsClient(tooMany).Check(t.Context(), ""); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("four same-host redirects should be rejected: %v", err)
	}
}
