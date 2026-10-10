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
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// Once a client with its own address has used its sign-in budget, here with
// usernames that no account has, the sign-in answer is the same for every
// username, with the same status, body and Retry-After, whether the name
// belongs to an account of the default unit, a disabled account, another
// unit's account, the platform administrator, or no account. Another client
// still gets the ordinary answer for an existing name.
func TestThrottledSignInAnswerIsTheSameForEveryUsername(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	if _, err := storetest.CreateUser(context.Background(), f.db, store.DefaultTenantScope(), store.User{Username: "alpha-disabled", Role: store.RoleViewer, PasswordHash: cheapPasswordHash(platformFixturePassword), Enabled: false}); err != nil {
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

// A client's sign-in budget counts every failed sign-in alike. A client
// that fails with existing usernames, a wrong password for an enabled
// account or any password for a disabled one, is refused after as many
// failures as a client that fails with unknown usernames, and from then on
// both get the same answer for every username, including a right password.
func TestSignInBudgetDoesNotDependOnWhichUsernamesExist(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	if _, err := storetest.CreateUser(context.Background(), f.db, store.DefaultTenantScope(), store.User{Username: "alpha-disabled", Role: store.RoleViewer, PasswordHash: cheapPasswordHash(platformFixturePassword), Enabled: false}); err != nil {
		t.Fatal(err)
	}
	type answer struct {
		status           int
		body, retryAfter string
	}
	login := func(remote, username, password string) answer {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, consoleAPIBase+"/auth/login", strings.NewReader(fmt.Sprintf(`{"username":%q,"password":%q}`, username, password)))
		request.RemoteAddr = remote
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		f.server.api(recorder, request)
		return answer{recorder.Code, strings.TrimSpace(recorder.Body.String()), recorder.Header().Get("Retry-After")}
	}
	const unknownClient, existingClient = "198.51.100.30:40000", "198.51.100.31:40000"
	existing := []string{"alpha-viewer", "alpha-disabled", "bravo-admin", "platform-root", "alpha-admin"}
	for i := 0; i < 5; i++ {
		if got := login(unknownClient, fmt.Sprintf("guess-%d", i), "not the password"); got.status != http.StatusUnauthorized || !strings.Contains(got.body, `"login_failed"`) {
			t.Fatalf("unknown username %d = %+v, want 401 login_failed", i, got)
		}
		if got := login(existingClient, existing[i], "not the password"); got.status != http.StatusUnauthorized || !strings.Contains(got.body, `"login_failed"`) {
			t.Fatalf("wrong password for %s = %+v, want 401 login_failed", existing[i], got)
		}
	}
	want := login(unknownClient, "guess-x", "not the password")
	if want.status != http.StatusTooManyRequests || !strings.Contains(want.body, `"rate_limited"`) || want.retryAfter != "300" {
		t.Fatalf("unknown username over the budget = %+v, want 429 rate_limited", want)
	}
	for _, attempt := range []struct{ username, password string }{
		{"guess-y", "not the password"},
		{"alpha-viewer", "not the password"},
		{"alpha-operator", platformFixturePassword},
		{"bravo-viewer", platformFixturePassword},
	} {
		for _, client := range []string{unknownClient, existingClient} {
			if got := login(client, attempt.username, attempt.password); got != want {
				t.Errorf("sign-in as %s from %s after five failures = %+v, want %+v", attempt.username, client, got, want)
			}
		}
	}
	if got := login("198.51.100.32:40000", "alpha-operator", platformFixturePassword); got.status != http.StatusOK {
		t.Errorf("sign-in from another client = %+v, want 200", got)
	}
}

// A throttled sign-in or password confirmation is recorded where the
// account belongs: a unit account's in its unit, and the platform
// administrator's or an unknown username's in platform scope. No unit's
// audit shows another unit's usernames, an unknown username, or a platform
// administrator's source address.
func TestRateLimitRecordsFollowTheAccount(t *testing.T) {
	t.Parallel()
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
	// A refused sign-in writes its record in the background.
	if err := f.server.Auth.WaitForRateLimitRecords(context.Background()); err != nil {
		t.Fatal(err)
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
