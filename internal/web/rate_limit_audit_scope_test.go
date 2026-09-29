package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// Once a client with its own address has used its budget for usernames that
// no account has, the sign-in answer is the same for every username, with
// the same status, body and Retry-After, whether the name belongs to an
// account of the default unit, a disabled account, another unit's account,
// the platform administrator, or no account. Another client still gets the
// ordinary answer for an existing name.
func TestThrottledSignInAnswerIsTheSameForEveryUsername(t *testing.T) {
	f := newPlatformFixture(t)
	if _, err := f.a.CreateUser(context.Background(), store.User{Username: "alpha-disabled", Role: store.RoleViewer, PasswordHash: cheapPasswordHash(platformFixturePassword), Enabled: false}, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	type answer struct {
		status           int
		body, retryAfter string
	}
	login := func(remote, username string) answer {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, consoleAPIBase+"/auth/login", strings.NewReader(fmt.Sprintf(`{"username":%q,"password":"not the password"}`, username)))
		request.RemoteAddr = remote
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		f.server.api(recorder, request)
		return answer{recorder.Code, strings.TrimSpace(recorder.Body.String()), recorder.Header().Get("Retry-After")}
	}
	const client = "198.51.100.23:40000"
	for i := 0; i < 5; i++ {
		if got := login(client, fmt.Sprintf("guess-%d", i)); got.status != http.StatusUnauthorized {
			t.Fatalf("unknown username %d = %+v, want 401", i, got)
		}
	}
	want := login(client, "guess-x")
	if want.status != http.StatusTooManyRequests || !strings.Contains(want.body, `"rate_limited"`) {
		t.Fatalf("unknown username over the budget = %+v, want 429 rate_limited", want)
	}
	for _, username := range []string{"alpha-viewer", "alpha-disabled", "bravo-admin", "platform-root", "nobody-here"} {
		if got := login(client, username); got != want {
			t.Errorf("throttled sign-in as %s = %+v, want %+v", username, got, want)
		}
	}
	if got := login("198.51.100.24:40000", "alpha-viewer"); got.status != http.StatusUnauthorized || !strings.Contains(got.body, `"login_failed"`) {
		t.Errorf("wrong password from another client = %+v, want 401 login_failed", got)
	}
}

// A throttled sign-in or password confirmation is recorded where the
// account belongs: a unit account's in its unit, and the platform
// administrator's or an unknown username's in platform scope. No unit's
// audit shows another unit's usernames, an unknown username, or a platform
// administrator's source address.
func TestRateLimitRecordsFollowTheAccount(t *testing.T) {
	f := newPlatformFixture(t)
	send := func(remote, method, path, body string, account *routeMatrixSession) int {
		t.Helper()
		request := httptest.NewRequest(method, consoleAPIBase+path, strings.NewReader(body))
		request.RemoteAddr = remote
		request.Header.Set("Content-Type", "application/json")
		if account != nil {
			request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: account.raw})
			request.Header.Set("X-CSRF-Token", account.session.CSRFToken)
		}
		recorder := httptest.NewRecorder()
		f.server.api(recorder, request)
		return recorder.Code
	}
	login := func(username string) string {
		return fmt.Sprintf(`{"username":%q,"password":"wrong password"}`, username)
	}
	platform, adminB := f.sessions[actorPlatform], f.sessions[actorAdminB]
	wrongPassword := `{"password":"not the password"}`
	for _, attempt := range []struct {
		name, remote, method, path, body string
		account                          *routeMatrixSession
	}{
		{"unit B's administrator's sign-in", "203.0.113.77:4000", http.MethodPost, "/auth/login", login("bravo-admin"), nil},
		{"the platform administrator's sign-in", "192.0.2.99:4000", http.MethodPost, "/auth/login", login("platform-root"), nil},
		{"an unknown username's sign-in", "203.0.113.78:4000", http.MethodPost, "/auth/login", login("nobody-anywhere"), nil},
		{"the platform administrator's password confirmation", "198.51.100.200:4000", http.MethodPost, "/platform/units/" + f.unitB + "/disable", wrongPassword, &platform},
		{"unit B's administrator's password confirmation", "198.51.100.201:4000", http.MethodDelete, "/users/" + f.viewerB + "/sessions", wrongPassword, &adminB},
	} {
		for try := 1; try <= 6; try++ {
			want := http.StatusUnauthorized
			if try == 6 {
				want = http.StatusTooManyRequests
			}
			if got := send(attempt.remote, attempt.method, attempt.path, attempt.body, attempt.account); got != want {
				t.Fatalf("%s, attempt %d = %d, want %d", attempt.name, try, got, want)
			}
		}
	}
	unitAudit := func(actor string) string {
		t.Helper()
		response := f.call(t, actor, http.MethodGet, "/audit?action=auth.rate_limited", "")
		if response.Code != http.StatusOK {
			t.Fatalf("%s's audit = %d %s", actor, response.Code, response.Body.String())
		}
		return response.Body.String()
	}
	auditA, auditB := unitAudit(actorAdminA), unitAudit(actorAdminB)
	for _, foreign := range []string{"bravo-admin", "platform-root", "nobody-anywhere", "password-confirmation", "203.0.113.77", "192.0.2.99", "203.0.113.78", "198.51.100.200", "198.51.100.201"} {
		if strings.Contains(auditA, foreign) {
			t.Errorf("the default unit's audit shows %q: %s", foreign, auditA)
		}
	}
	for _, own := range []string{"login:bravo-admin", "203.0.113.77", "password-confirmation", "198.51.100.201"} {
		if !strings.Contains(auditB, own) {
			t.Errorf("unit B's audit does not show %q: %s", own, auditB)
		}
	}
	for _, foreign := range []string{"platform-root", "nobody-anywhere", "192.0.2.99", "203.0.113.78", "198.51.100.200"} {
		if strings.Contains(auditB, foreign) {
			t.Errorf("unit B's audit shows %q: %s", foreign, auditB)
		}
	}
	rateLimited := func(query string, args ...any) int {
		t.Helper()
		var count int
		if err := f.db.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE action='auth.rate_limited' AND `+query, args...).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	for _, source := range []string{"192.0.2.99", "203.0.113.78", "198.51.100.200"} {
		if got := rateLimited(`source_ip=? AND tenant_id IS NULL`, source); got != 1 {
			t.Errorf("platform-scope rate-limit records from %s = %d, want 1", source, got)
		}
	}
	for _, source := range []string{"203.0.113.77", "198.51.100.201"} {
		if got := rateLimited(`source_ip=? AND tenant_id=?`, source, f.unitB); got != 1 {
			t.Errorf("unit B's rate-limit records from %s = %d, want 1", source, got)
		}
	}
}
