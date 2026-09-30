package web

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// lockedBuffer is a log destination that the request goroutines and the
// test may use at once.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// untrustedProxyWarning is the log message of a request from an untrusted
// proxy with forwarding headers.
const untrustedProxyWarning = "requests from a proxy that is not in web.trusted_proxies carry forwarding headers"

// A request from an address that is not in web.trusted_proxies, but
// carries forwarding headers, comes from a proxy that EdgeWatch does not
// trust: every client behind it shares the proxy's address for sign-in
// limits, the limits of the setups and activation, and the audit. That
// holds for a proxy on the host, which connects from a loopback address, as
// for any other. The daemon logs a warning that recommends
// web.trusted_proxies, at most once per interval, and the platform status
// reports the proxy. Once more than one unit exists, a unit's status leaves
// it out, as it leaves out the other deployment-wide signals. Requests
// without forwarding headers and trusted proxies are not reported.
func TestUntrustedProxyForwardingIsReported(t *testing.T) {
	f := newPlatformFixture(t)
	logs := &lockedBuffer{}
	f.server.Log = slog.New(slog.NewTextHandler(logs, nil))
	now := time.Now().UTC().Truncate(time.Second)
	f.server.Auth.Now = func() time.Time { return now }
	handler := f.server.Handler()
	send := func(remote string, headers map[string]string) {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, consoleAPIBase+"/setup/status", nil)
		request.Host = "127.0.0.1:8080"
		request.RemoteAddr = remote
		for name, value := range headers {
			request.Header.Set(name, value)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("setup status from %s = %d %s", remote, recorder.Code, recorder.Body.String())
		}
	}
	warnings := func() int { return strings.Count(logs.String(), untrustedProxyWarning) }
	platformStatus := func() map[string]any {
		t.Helper()
		response := f.call(t, actorPlatform, http.MethodGet, "/platform/status", "")
		if response.Code != http.StatusOK {
			t.Fatalf("platform status = %d %s", response.Code, response.Body.String())
		}
		var status map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		return status
	}

	send("127.0.0.1:5000", nil)
	send("[::1]:5000", nil)
	send("10.0.0.5:5000", nil)
	if got := warnings(); got != 0 {
		t.Fatalf("warnings for requests without forwarding headers = %d, want none: %s", got, logs.String())
	}
	if _, reported := platformStatus()["untrusted_proxy"]; reported {
		t.Fatal("the platform status reports an untrusted proxy before one was seen")
	}

	for i := range 5 {
		send("10.0.0.5:5000", map[string]string{"X-Forwarded-For": "198.51.100." + strconv.Itoa(i+10)})
	}
	if got := warnings(); got != 1 {
		t.Fatalf("warnings for five requests from an untrusted proxy = %d, want one: %s", got, logs.String())
	}
	for _, want := range []string{"peer=10.0.0.5", "header=X-Forwarded-For", "web.trusted_proxies"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the warning does not name %q: %s", want, logs.String())
		}
	}
	notice, reported := platformStatus()["untrusted_proxy"].(map[string]any)
	if !reported || notice["peer"] != "10.0.0.5" || notice["header"] != "X-Forwarded-For" || notice["last_seen_at"] != now.Format(time.RFC3339) {
		t.Fatalf("platform status untrusted_proxy = %#v", platformStatus()["untrusted_proxy"])
	}
	for _, actor := range []string{actorAdminA, actorAdminB} {
		response := f.call(t, actor, http.MethodGet, "/status", "")
		if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "untrusted_proxy") || strings.Contains(response.Body.String(), "10.0.0.5") {
			t.Errorf("%s's status with several units = %d %s, want no untrusted proxy", actor, response.Code, response.Body.String())
		}
	}

	// The warning repeats once its interval has passed, for the proxy seen
	// then.
	now = now.Add(time.Hour)
	send("10.0.0.6:5000", map[string]string{"Forwarded": "for=198.51.100.20"})
	if got := warnings(); got != 2 || !strings.Contains(logs.String(), "peer=10.0.0.6") || !strings.Contains(logs.String(), "header=Forwarded") {
		t.Fatalf("warnings after the interval = %d, want two, the second for 10.0.0.6: %s", got, logs.String())
	}

	// A proxy on the host that is not trusted connects from a loopback
	// address, and is reported as well.
	for i, peer := range []struct{ remote, header, value, want string }{
		{"127.0.0.1:5000", "X-Forwarded-For", "198.51.100.21", "127.0.0.1"},
		{"[::1]:5000", "Forwarded", "for=198.51.100.22", "::1"},
	} {
		now = now.Add(time.Hour)
		send(peer.remote, map[string]string{peer.header: peer.value})
		if got := warnings(); got != 3+i || !strings.Contains(logs.String(), "peer="+peer.want+" header="+peer.header) {
			t.Fatalf("warnings after a request from an untrusted proxy at %s = %d, want %d: %s", peer.want, got, 3+i, logs.String())
		}
		if notice, reported := f.server.Auth.UntrustedProxy(); !reported || notice.Peer != peer.want || notice.Header != peer.header {
			t.Fatalf("untrusted proxy = %+v, %t; want %s", notice, reported, peer.want)
		}
	}

	// A trusted proxy is not reported.
	if err := f.server.Auth.SetTrustedProxies([]string{"10.0.0.7/32"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	send("10.0.0.7:5000", map[string]string{"X-Forwarded-For": "198.51.100.30"})
	if got := warnings(); got != 4 {
		t.Fatalf("warnings after a request from a trusted proxy = %d, want four: %s", got, logs.String())
	}
}

// When the proxy on the host is trusted, a proxy on another host in front
// of it is the address at which the forwarding chain leaves the trusted
// proxies. When that address forwarded the request for another client, it
// is a proxy that EdgeWatch does not trust: the daemon logs the warning
// with its address and the platform status reports it. A client of the
// trusted proxy, whose chain ends at its own address, is not reported.
func TestUntrustedProxyBehindATrustedProxyIsReported(t *testing.T) {
	f := newPlatformFixture(t)
	logs := &lockedBuffer{}
	f.server.Log = slog.New(slog.NewTextHandler(logs, nil))
	if err := f.server.Auth.SetTrustedProxies([]string{"127.0.0.1/32"}); err != nil {
		t.Fatal(err)
	}
	handler := f.server.Handler()
	send := func(forwardedFor string) {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, consoleAPIBase+"/setup/status", nil)
		request.Host = "127.0.0.1:8080"
		request.RemoteAddr = "127.0.0.1:50000"
		request.Header.Set("X-Forwarded-For", forwardedFor)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("setup status forwarded for %s = %d %s", forwardedFor, recorder.Code, recorder.Body.String())
		}
	}
	platformStatus := func() map[string]any {
		t.Helper()
		response := f.call(t, actorPlatform, http.MethodGet, "/platform/status", "")
		if response.Code != http.StatusOK {
			t.Fatalf("platform status = %d %s", response.Code, response.Body.String())
		}
		var status map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		return status
	}

	send("198.51.100.7")
	if strings.Contains(logs.String(), untrustedProxyWarning) {
		t.Fatalf("warning for a client of the trusted proxy: %s", logs.String())
	}
	if _, reported := platformStatus()["untrusted_proxy"]; reported {
		t.Fatal("the platform status reports a client of the trusted proxy")
	}

	send("198.51.100.7, 203.0.113.9")
	if strings.Count(logs.String(), untrustedProxyWarning) != 1 || !strings.Contains(logs.String(), "peer=203.0.113.9 header=X-Forwarded-For") {
		t.Fatalf("warning for an untrusted proxy behind the trusted proxy: %s", logs.String())
	}
	if notice, reported := platformStatus()["untrusted_proxy"].(map[string]any); !reported || notice["peer"] != "203.0.113.9" || notice["header"] != "X-Forwarded-For" {
		t.Fatalf("platform status untrusted_proxy = %#v, want 203.0.113.9", platformStatus()["untrusted_proxy"])
	}
}

// With one unit, its administrators see the untrusted proxy in the status
// that the console shows them; operators and viewers do not.
func TestUntrustedProxyForwardingInTheSingleUnitStatus(t *testing.T) {
	server, _, admin := newUsersTestServer(t)
	server.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	status := func(role string) string {
		t.Helper()
		session := admin
		session.Role = role
		request := httptest.NewRequest(http.MethodGet, consoleAPIBase+"/status", nil)
		request.RemoteAddr = "127.0.0.1:9000"
		recorder := httptest.NewRecorder()
		server.adminStatus(recorder, request, session, defaultTenantStore(server))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status as %s = %d %s", role, recorder.Code, recorder.Body.String())
		}
		return recorder.Body.String()
	}
	if body := status("administrator"); strings.Contains(body, "untrusted_proxy") {
		t.Fatalf("status before an untrusted proxy was seen = %s", body)
	}
	request := httptest.NewRequest(http.MethodGet, consoleAPIBase+"/setup/status", nil)
	request.Host = "127.0.0.1:8080"
	request.RemoteAddr = "192.168.10.4:6000"
	request.Header.Set("X-Forwarded-For", "198.51.100.40")
	server.Handler().ServeHTTP(httptest.NewRecorder(), request)
	if body := status("administrator"); !strings.Contains(body, `"untrusted_proxy":{`) || !strings.Contains(body, `"peer":"192.168.10.4"`) {
		t.Fatalf("administrator's status after an untrusted proxy was seen = %s", body)
	}
	for _, role := range []string{"operator", "viewer"} {
		if body := status(role); strings.Contains(body, "untrusted_proxy") {
			t.Errorf("%s's status = %s, want no untrusted proxy", role, body)
		}
	}
}

// Through a shared loopback peer, a refused setup, platform setup, or
// activation carries the two-second cooldown in Retry-After, as a refused
// sign-in does.
func TestSharedLoopbackTokenRefusalsCarryTheCooldown(t *testing.T) {
	for path, fields := range map[string]string{
		"/setup":          `"password":"a long enough password"`,
		"/setup/platform": `"username":"root","password":"a long enough password"`,
		"/auth/activate":  `"password":"a long enough password"`,
	} {
		t.Run(path, func(t *testing.T) {
			server, _, _ := newUsersTestServer(t)
			post := func(token string) *httptest.ResponseRecorder {
				body := `{"token":"` + token + `",` + fields + `}`
				request := httptest.NewRequest(http.MethodPost, consoleAPIBase+path, strings.NewReader(body))
				request.RemoteAddr = "127.0.0.1:9000"
				request.Header.Set("Content-Type", "application/json")
				recorder := httptest.NewRecorder()
				server.api(recorder, request)
				return recorder
			}
			for attempt := range 5 {
				if response := post("wrong-token-" + strconv.Itoa(attempt)); response.Code == http.StatusTooManyRequests {
					t.Fatalf("wrong token %d = %d %s, want it refused as wrong", attempt, response.Code, response.Body.String())
				}
			}
			response := post("wrong-token-5")
			if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "2" || !strings.Contains(response.Body.String(), `"rate_limited"`) {
				t.Fatalf("token after five wrong ones = %d, Retry-After %q, %s; want 429 with Retry-After 2", response.Code, response.Header().Get("Retry-After"), response.Body.String())
			}
		})
	}
}
