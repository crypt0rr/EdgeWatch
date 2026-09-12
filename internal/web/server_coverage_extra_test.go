package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestServerErrorMappingHelpers(t *testing.T) {
	server, _, _ := newUsersTestServer(t)
	for _, test := range []struct {
		name string
		err  error
		code int
		want string
	}{
		{"conflict", store.ErrConflict, http.StatusConflict, "conflict"},
		{"not found", store.ErrNotFound, http.StatusNotFound, "not_found"},
		{"key locked", notify.ErrManagedNotificationLocked, http.StatusServiceUnavailable, "notification_key_unavailable"},
		{"key unavailable", notify.ErrKeyUnavailable, http.StatusServiceUnavailable, "notification_key_unavailable"},
		{"key invalid", notify.ErrKeyInvalid, http.StatusServiceUnavailable, "notification_key_unavailable"},
		{"key permissions", notify.ErrKeyPermissions, http.StatusServiceUnavailable, "notification_key_unavailable"},
		{"unique", errors.New("UNIQUE constraint failed"), http.StatusConflict, "conflict"},
		{"URL validation", errors.New("notification URL is invalid"), http.StatusBadRequest, "validation_failed"},
		{"name validation", errors.New("notification name is empty"), http.StatusBadRequest, "validation_failed"},
		{"delivery failure", errors.New("notification delivery failed (fingerprint)"), http.StatusBadGateway, "notification_failed"},
		{"other", errors.New("delivery failed"), http.StatusInternalServerError, "notification_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.writeNotificationError(recorder, test.err)
			if recorder.Code != test.code || !strings.Contains(recorder.Body.String(), `"code":"`+test.want+`"`) {
				t.Fatalf("notification error = %d %s", recorder.Code, recorder.Body.String())
			}
		})
	}
	for _, test := range []struct {
		err  error
		code int
		want string
	}{
		{auth.ErrRateLimited, http.StatusTooManyRequests, "rate_limited"},
		{errors.New("wrong password"), http.StatusUnauthorized, "invalid_password"},
	} {
		recorder := httptest.NewRecorder()
		server.writeNotificationAuthError(recorder, test.err)
		if recorder.Code != test.code || !strings.Contains(recorder.Body.String(), `"code":"`+test.want+`"`) {
			t.Fatalf("notification auth error = %d %s", recorder.Code, recorder.Body.String())
		}
	}
	for _, test := range []struct {
		err  error
		code int
		want string
	}{
		{store.ErrIncidentNotFound, http.StatusNotFound, "incident_not_found"},
		{store.ErrJobScanActive, http.StatusConflict, "job_active"},
		{store.ErrBaselineNotReady, http.StatusConflict, "baseline_not_ready"},
		{store.ErrUnsupportedIncidentChange, http.StatusBadRequest, "incident_change_invalid"},
		{errors.New("unexpected"), http.StatusInternalServerError, "store"},
	} {
		recorder := httptest.NewRecorder()
		server.writeIncidentActionError(recorder, test.err, "incident.test")
		if recorder.Code != test.code || !strings.Contains(recorder.Body.String(), `"code":"`+test.want+`"`) {
			t.Fatalf("incident error = %d %s", recorder.Code, recorder.Body.String())
		}
	}
	if server.writeAuditUnavailable(httptest.NewRecorder(), errors.New("not audit"), "action") {
		t.Fatal("non-audit error was treated as audit unavailable")
	}
	recorder := httptest.NewRecorder()
	if !server.writeAuditUnavailable(recorder, store.ErrAuditUnavailable, "action") || recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("audit unavailable response = %d %v", recorder.Code, recorder.Body.String())
	}
}

func TestNotificationDestinationRouteGuardsAndTestDelivery(t *testing.T) {
	server, _, admin := newUsersTestServer(t)
	for _, test := range []struct {
		name, method, rest string
	}{
		{name: "empty id", method: http.MethodGet, rest: ""},
		{name: "nested endpoint", method: http.MethodGet, rest: "id/other"},
		{name: "unsupported method", method: http.MethodPatch, rest: "id"},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.notificationDestinationRoute(recorder, httptest.NewRequest(test.method, "/api/v1/notifications/destinations/"+test.rest, nil), admin, test.rest)
			if recorder.Code != http.StatusNotFound {
				t.Fatalf("route status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
		})
	}

	missing := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/destinations/missing/test", nil)
	missing.RemoteAddr = "127.0.0.1:4001"
	recorder := httptest.NewRecorder()
	server.notificationDestinationRoute(recorder, missing, admin, "missing/test")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing destination test status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	limited := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/destinations/missing/test", nil)
	limited.RemoteAddr = missing.RemoteAddr
	recorder = httptest.NewRecorder()
	server.notificationDestinationRoute(recorder, limited, admin, "missing/test")
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited destination test status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	parsed, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := server.App.Notifier.CreateManaged(context.Background(), "Route test", "generic://"+parsed.Host+"/edgewatch?disabletls=yes&template=json", true)
	if err != nil {
		t.Fatal(err)
	}
	testRequest := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/destinations/"+destination.ID+"/test", nil)
	// Notification-test throttling follows the resolved client address, not
	// the ephemeral source port. Use a distinct client for the successful call.
	testRequest.RemoteAddr = "127.0.0.2:4002"
	recorder = httptest.NewRecorder()
	server.notificationDestinationRoute(recorder, testRequest, admin, destination.ID+"/test")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"sent":1`) || calls.Load() != 1 {
		t.Fatalf("successful destination test = %d %s (calls=%d)", recorder.Code, recorder.Body.String(), calls.Load())
	}

	server.testLast["expired"] = time.Now().UTC().Add(-11 * time.Minute)
	identity := httptest.NewRequest(http.MethodPost, "/", nil)
	identity.RemoteAddr = "127.0.0.1:4003"
	identity.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "session-cookie"})
	if !server.allowNotificationTest(identity) {
		t.Fatal("expired notification test identity was unexpectedly limited")
	}
}

func TestNotificationDestinationDeliveryFailureUsesGatewayStatus(t *testing.T) {
	server, _, admin := newUsersTestServer(t)
	destination, err := server.App.Notifier.CreateManaged(context.Background(), "Unreachable", "generic://127.0.0.1:1/edgewatch?disabletls=yes&template=json", true)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/destinations/"+destination.ID+"/test", nil)
	request.RemoteAddr = "127.0.0.3:4003"
	recorder := httptest.NewRecorder()
	server.notificationDestinationRoute(recorder, request, admin, destination.ID+"/test")
	if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), `"code":"notification_failed"`) {
		t.Fatalf("destination delivery failure = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestNotificationTestRateLimitIsScopedPerDestination(t *testing.T) {
	server, _, _ := newUsersTestServer(t)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/destinations/one/test", nil)
	request.RemoteAddr = "127.0.0.8:4008"
	if !server.allowNotificationTest(request, "one") {
		t.Fatal("first destination test was unexpectedly limited")
	}
	if server.allowNotificationTest(request, "one") {
		t.Fatal("repeated test for one destination was not limited")
	}
	if !server.allowNotificationTest(request, "two") {
		t.Fatal("a different destination test was incorrectly limited")
	}
}

func TestServerSetupStatusAndRouteGuards(t *testing.T) {
	server, db, admin := newUsersTestServer(t)
	ctx := context.Background()
	status := httptest.NewRecorder()
	server.setupStatus(status, httptest.NewRequest(http.MethodGet, "/api/v1/setup/status", nil))
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"configured":true`) || !strings.Contains(status.Body.String(), server.Version) {
		t.Fatalf("setup status = %d %s", status.Code, status.Body.String())
	}
	for _, rest := range []string{"", "/unknown", "job/unknown"} {
		recorder := httptest.NewRecorder()
		server.jobRoute(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+rest, nil), admin, rest)
		if recorder.Code != http.StatusNotFound {
			t.Errorf("job route %q status = %d", rest, recorder.Code)
		}
	}
	missing := httptest.NewRecorder()
	server.getJob(missing, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/missing", nil), "missing")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing get job status = %d", missing.Code)
	}
	baseline := httptest.NewRecorder()
	server.jobBaseline(baseline, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/missing/baseline", nil), "missing")
	if baseline.Code != http.StatusNotFound {
		t.Fatalf("missing baseline status = %d", baseline.Code)
	}
	active := httptest.NewRecorder()
	server.activeScans(active, httptest.NewRequest(http.MethodGet, "/api/v1/scans/active", nil))
	if active.Code != http.StatusOK || !strings.Contains(active.Body.String(), `"scans":[]`) {
		t.Fatalf("empty active scans = %d %s", active.Code, active.Body.String())
	}
	if _, err := db.GetUser(ctx, admin.UserID); err != nil {
		t.Fatal(err)
	}
}

func TestServerAuthenticationAndAuditFailureResponses(t *testing.T) {
	server, db, admin := newUsersTestServer(t)
	badSetup := httptest.NewRecorder()
	setupRequest := httptest.NewRequest(http.MethodPost, "/api/v1/setup", strings.NewReader(`{"token":"bad","password":"short"}`))
	setupRequest.Header.Set("Content-Type", "application/json")
	server.setup(badSetup, setupRequest)
	if badSetup.Code != http.StatusBadRequest {
		t.Fatalf("invalid setup status = %d", badSetup.Code)
	}
	badLogin := httptest.NewRecorder()
	loginRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"wrong"}`))
	loginRequest.Header.Set("Content-Type", "application/json")
	server.login(badLogin, loginRequest)
	if badLogin.Code != http.StatusUnauthorized {
		t.Fatalf("invalid login status = %d", badLogin.Code)
	}
	if _, err := db.DB.ExecContext(context.Background(), `CREATE TRIGGER fail_web_audit BEFORE INSERT ON security_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	if server.requireAuditEntry(context.Background(), recorder, store.AuditEntry{Action: "test"}) || recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("required audit failure = %d %s", recorder.Code, recorder.Body.String())
	}
	if _, err := db.DB.ExecContext(context.Background(), `DROP TRIGGER fail_web_audit`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := db.CreateSessionForUserWithAudit(context.Background(), admin.UserID, "logout-failure", "csrf", now, now.Add(time.Hour), "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(context.Background(), `CREATE TRIGGER fail_web_logout BEFORE INSERT ON security_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	logout := httptest.NewRecorder()
	logoutRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logoutRequest.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "logout-failure"})
	server.logout(logout, logoutRequest, admin)
	if logout.Code != http.StatusServiceUnavailable {
		t.Fatalf("audit logout status = %d %s", logout.Code, logout.Body.String())
	}
	if _, err := db.DB.ExecContext(context.Background(), `DROP TRIGGER fail_web_logout`); err != nil {
		t.Fatal(err)
	}
}

func TestRunJobGuardsMissingArchivedAndActive(t *testing.T) {
	server, db, admin := newUsersTestServer(t)
	ctx := context.Background()
	missing := httptest.NewRecorder()
	server.runJob(missing, httptest.NewRequest(http.MethodPost, "/api/v1/jobs/missing/run", nil), admin, "missing")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing run status = %d", missing.Code)
	}
	job := config.NormalizeJob(config.Job{Name: "run-guards", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}})
	record, err := db.CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetJobArchived(ctx, record.ID, true); err != nil {
		t.Fatal(err)
	}
	archived := httptest.NewRecorder()
	server.runJob(archived, httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+record.ID+"/run", nil), admin, record.ID)
	if archived.Code != http.StatusConflict {
		t.Fatalf("archived run status = %d", archived.Code)
	}
	if err := db.SetJobArchived(ctx, record.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := db.AcquireJobLease(ctx, record.ID, "active-owner", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	active := httptest.NewRecorder()
	server.runJob(active, httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+record.ID+"/run", nil), admin, record.ID)
	if active.Code != http.StatusConflict {
		t.Fatalf("active run status = %d", active.Code)
	}
	_ = db.ReleaseJobLease(ctx, record.ID, "active-owner")
}

func TestServerPaginationAndSSEBoundaryHelpers(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/?limit=bad&offset=-1", nil)
	if queryLimit(request) != 50 || queryOffset(request) != 0 {
		t.Fatal("invalid query values did not default")
	}
	request = httptest.NewRequest(http.MethodGet, "/?limit=2001&offset=99999999", nil)
	if queryLimit(request) != 1000 || queryOffset(request) != 10000000 {
		t.Fatal("query values were not capped")
	}
	if paginationJSON(0, 10, 5)["has_more"] != false || paginationJSON(0, 10, 15)["next_offset"] != 10 {
		t.Fatal("pagination metadata is incorrect")
	}
	maxInt := int(^uint(0) >> 1)
	overflow := paginationJSON(maxInt, 50, maxInt)
	if overflow["has_more"] != false || overflow["next_offset"] != nil {
		t.Fatalf("pagination overflow was not suppressed: %#v", overflow)
	}
	if got, _ := pageSlice([]string{"a", "b"}, -1, 0); len(got) != 2 {
		t.Fatal("default page slice failed")
	}
	server, db, _ := newUsersTestServer(t)
	server.broadcast(map[string]any{"type": "first"})
	server.broadcast(map[string]any{"type": "second"})
	server.mu.Lock()
	if got := server.replayLocked(1); len(got) != 1 || got[0].id != 2 {
		server.mu.Unlock()
		t.Fatalf("normal replay = %#v", got)
	}
	beforeFuture := server.nextEventID
	futureID := sseEventIDBlockSize + 42
	if got := server.replayLocked(futureID); len(got) != 0 || server.nextEventID != beforeFuture {
		server.mu.Unlock()
		t.Fatalf("future replay changed server cursor: messages=%#v cursor=%d before=%d", got, server.nextEventID, beforeFuture)
	}
	restarted := &Server{subscribers: map[chan sseMessage]struct{}{}}
	if got := restarted.replayLocked(999999); len(got) != 0 || restarted.nextEventID != 0 {
		t.Fatalf("restart replay did not request refresh: %#v", got)
	}
	server.history = []sseMessage{{id: 10, payload: []byte(`{"type":"old"}`)}}
	if got := server.replayLocked(1); len(got) != 2 || !strings.Contains(string(got[0].payload), "refresh_required") {
		server.mu.Unlock()
		t.Fatalf("gap replay = %#v", got)
	}
	server.mu.Unlock()
	server.broadcast(map[string]any{"type": "after-future-replay"})
	var durableCursor int64
	if err := db.DB.QueryRow(`SELECT next_id FROM sse_event_cursor WHERE id=1`).Scan(&durableCursor); err != nil {
		t.Fatal(err)
	}
	if durableCursor != int64(sseEventIDBlockSize) {
		t.Fatalf("future replay advanced durable cursor to %d, want reserved block end %d", durableCursor, sseEventIDBlockSize)
	}
	if len(boundedSSEPayload(map[string]any{"value": strings.Repeat("x", maxSSEPayloadBytes)})) > maxSSEPayloadBytes {
		t.Fatal("oversized SSE payload was not bounded")
	}
	if len(boundedSSEPayload(map[string]any{"value": "ok"})) == 0 {
		t.Fatal("normal SSE payload was empty")
	}
	for _, test := range []struct {
		value string
		want  uint64
	}{
		{value: "1", want: 1},
		{value: " 42 ", want: 42},
		{value: "", want: 0},
		{value: "not-a-number", want: 0},
		{value: strings.Repeat("9", maxSSELastEventIDLength+1), want: 0},
	} {
		if got := parseSSELastEventID(test.value); got != test.want {
			t.Fatalf("parse Last-Event-ID %q = %d, want %d", test.value, got, test.want)
		}
	}
	if !isMutation(http.MethodDelete) && isMutation(http.MethodGet) {
		t.Fatal("mutation classifier failed")
	}
}
