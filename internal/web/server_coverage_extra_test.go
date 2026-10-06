package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestServerErrorMappingHelpers(t *testing.T) {
	t.Parallel()
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
		if errors.Is(test.err, auth.ErrRateLimited) && recorder.Header().Get("Retry-After") != "300" {
			t.Fatalf("notification auth Retry-After = %q, want actual budget cooldown 300", recorder.Header().Get("Retry-After"))
		}
	}
	confirmationRecorder := httptest.NewRecorder()
	server.writePasswordConfirmationError(confirmationRecorder, auth.ErrRateLimited, "confirmation failed")
	if confirmationRecorder.Code != http.StatusTooManyRequests || confirmationRecorder.Header().Get("Retry-After") != "300" {
		t.Fatalf("password confirmation rate-limit response = %d Retry-After %q", confirmationRecorder.Code, confirmationRecorder.Header().Get("Retry-After"))
	}
	for _, test := range []struct {
		err  error
		code int
		want string
	}{
		{store.ErrIncidentNotFound, http.StatusNotFound, "incident_not_found"},
		{store.ErrIncidentConflict, http.StatusConflict, "incident_conflict"},
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
	for _, test := range []struct {
		name       string
		err        error
		code       int
		wantHeader string
	}{
		{name: "rate limited factor", err: auth.ErrRateLimited, code: http.StatusTooManyRequests, wantHeader: "300"},
		{name: "missing factor", err: errors.New("factor missing"), code: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.writeCurrentFactorError(recorder, test.err)
			if recorder.Code != test.code {
				t.Fatalf("factor error status = %d, want %d", recorder.Code, test.code)
			}
			if test.wantHeader != "" && recorder.Header().Get("Retry-After") != test.wantHeader {
				t.Fatalf("Retry-After = %q, want %q", recorder.Header().Get("Retry-After"), test.wantHeader)
			}
		})
	}
	if server.writeAuditUnavailable(httptest.NewRecorder(), errors.New("not audit"), "action") {
		t.Fatal("non-audit error was treated as audit unavailable")
	}
	recorder := httptest.NewRecorder()
	if !server.writeAuditUnavailable(recorder, store.ErrAuditUnavailable, "action") || recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("audit unavailable response = %d %v", recorder.Code, recorder.Body.String())
	}
}

func TestWriteInternalErrorRedactsDetailsAndIncludesRequestID(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request = request.WithContext(context.WithValue(request.Context(), requestIDContextKey{}, "req-123"))
	for _, test := range []struct {
		name   string
		server *Server
		code   string
		wantID bool
	}{
		{name: "logged server", server: &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, code: "store", wantID: true},
		{name: "nil server", server: nil, code: "", wantID: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			test.server.writeInternalError(rec, request, test.code, errors.New("secret database detail"))
			if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret database") || !strings.Contains(rec.Body.String(), `"internal_error"`) && test.code == "" {
				t.Fatalf("internal error response = %d %s", rec.Code, rec.Body.String())
			}
			if test.wantID && !strings.Contains(rec.Body.String(), "req-123") {
				t.Fatalf("request ID missing: %s", rec.Body.String())
			}
		})
	}
}

func TestNotificationDestinationRouteGuardsAndTestDelivery(t *testing.T) {
	t.Parallel()
	server, db, admin := newUsersTestServer(t)
	for _, test := range []struct {
		name, method, rest string
	}{
		{name: "empty id", method: http.MethodGet, rest: ""},
		{name: "nested endpoint", method: http.MethodGet, rest: "id/other"},
		{name: "unsupported method", method: http.MethodPatch, rest: "id"},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.notificationDestinationRoute(recorder, httptest.NewRequest(test.method, "/api/v1/notifications/destinations/"+test.rest, nil), admin, defaultTenantStore(server), test.rest)
			if recorder.Code != http.StatusNotFound {
				t.Fatalf("route status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
		})
	}

	missing := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/destinations/missing/test", nil)
	missing.RemoteAddr = "127.0.0.1:4001"
	recorder := httptest.NewRecorder()
	server.notificationDestinationRoute(recorder, missing, admin, defaultTenantStore(server), "missing/test")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing destination test status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var failedAudits int
	if err := db.DB.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM security_audit WHERE action='notifications.test_failed'`).Scan(&failedAudits); err != nil {
		t.Fatal(err)
	}
	if failedAudits != 0 {
		t.Fatalf("unknown destination test wrote %d failure audit rows", failedAudits)
	}
	limited := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/destinations/missing-again/test", nil)
	limited.RemoteAddr = missing.RemoteAddr
	recorder = httptest.NewRecorder()
	server.notificationDestinationRoute(recorder, limited, admin, defaultTenantStore(server), "missing-again/test")
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited destination test status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if err := db.DB.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM security_audit WHERE action='notifications.test_failed'`).Scan(&failedAudits); err != nil {
		t.Fatal(err)
	}
	if failedAudits != 0 {
		t.Fatalf("rate-limited unknown destination test wrote %d failure audit rows", failedAudits)
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
	destination, err := server.App.Notifier.Tenant(defaultTenantStore(server)).CreateManagedWithAudit(context.Background(), "Route test", "generic://"+parsed.Host+"/edgewatch?disabletls=yes&template=json", true, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	testRequest := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/destinations/"+destination.ID+"/test", nil)
	// Notification-test throttling follows the resolved client address, not
	// the ephemeral source port. Use a distinct client for the successful call.
	testRequest.RemoteAddr = "127.0.0.2:4002"
	recorder = httptest.NewRecorder()
	server.notificationDestinationRoute(recorder, testRequest, admin, defaultTenantStore(server), destination.ID+"/test")
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
	t.Parallel()
	server, _, admin := newUsersTestServer(t)
	destination, err := server.App.Notifier.Tenant(defaultTenantStore(server)).CreateManagedWithAudit(context.Background(), "Unreachable", "generic://127.0.0.1:1/edgewatch?disabletls=yes&template=json", true, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/destinations/"+destination.ID+"/test", nil)
	request.RemoteAddr = "127.0.0.3:4003"
	recorder := httptest.NewRecorder()
	server.notificationDestinationRoute(recorder, request, admin, defaultTenantStore(server), destination.ID+"/test")
	if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), `"code":"notification_failed"`) {
		t.Fatalf("destination delivery failure = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestNotificationTestRateLimitIsScopedPerSession(t *testing.T) {
	t.Parallel()
	server, _, _ := newUsersTestServer(t)
	first := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/destinations/one/test", nil)
	first.RemoteAddr = "127.0.0.8:4008"
	first.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "shared-session"})
	if !server.allowNotificationTest(first) {
		t.Fatal("first session notification test was unexpectedly limited")
	}
	second := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/destinations/two/test", nil)
	second.RemoteAddr = "127.0.0.8:4010"
	second.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "shared-session"})
	if server.allowNotificationTest(second) {
		t.Fatal("different destination test bypassed the session limit")
	}
	differentSession := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/destinations/two/test", nil)
	differentSession.RemoteAddr = second.RemoteAddr
	differentSession.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "different-session"})
	if !server.allowNotificationTest(differentSession) {
		t.Fatal("a different session was unexpectedly limited")
	}
}

func TestServerSetupStatusAndRouteGuards(t *testing.T) {
	t.Parallel()
	server, db, admin := newUsersTestServer(t)
	ctx := context.Background()
	status := httptest.NewRecorder()
	server.setupStatus(status, httptest.NewRequest(http.MethodGet, "/api/v1/setup/status", nil))
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"configured":true`) || strings.Contains(status.Body.String(), `"version"`) {
		t.Fatalf("setup status = %d %s", status.Code, status.Body.String())
	}
	for _, rest := range []string{"", "/unknown", "job/unknown"} {
		recorder := httptest.NewRecorder()
		server.jobRoute(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+rest, nil), admin, defaultTenantStore(server), rest)
		if recorder.Code != http.StatusNotFound {
			t.Errorf("job route %q status = %d", rest, recorder.Code)
		}
	}
	missing := httptest.NewRecorder()
	server.jobRoute(missing, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/missing", nil), admin, defaultTenantStore(server), "missing")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing get job status = %d", missing.Code)
	}
	baseline := httptest.NewRecorder()
	server.jobRoute(baseline, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/missing/baseline", nil), admin, defaultTenantStore(server), "missing/baseline")
	if baseline.Code != http.StatusNotFound {
		t.Fatalf("missing baseline status = %d", baseline.Code)
	}
	active := httptest.NewRecorder()
	server.activeScans(active, httptest.NewRequest(http.MethodGet, "/api/v1/scans/active", nil), defaultTenantStore(server))
	if active.Code != http.StatusOK || !strings.Contains(active.Body.String(), `"scans":[]`) {
		t.Fatalf("empty active scans = %d %s", active.Code, active.Body.String())
	}
	if _, err := defaultTenant(db).GetUser(ctx, admin.UserID); err != nil {
		t.Fatal(err)
	}
}

func TestServerAuthenticationAndAuditFailureResponses(t *testing.T) {
	t.Parallel()
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
	if server.requireAuditEntry(context.Background(), recorder, server.Store, store.AuditEntry{Action: "test"}) || recorder.Code != http.StatusServiceUnavailable {
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
	t.Parallel()
	server, db, admin := newUsersTestServer(t)
	ctx := context.Background()
	missing := httptest.NewRecorder()
	server.jobRoute(missing, httptest.NewRequest(http.MethodPost, "/api/v1/jobs/missing/run", nil), admin, defaultTenantStore(server), "missing/run")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing run status = %d", missing.Code)
	}
	job := config.NormalizeJob(config.Job{Name: "run-guards", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect"}})
	record, err := defaultTenant(db).CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(db).SetJobArchived(ctx, record.ID, true); err != nil {
		t.Fatal(err)
	}
	archived := httptest.NewRecorder()
	server.jobRoute(archived, httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+record.ID+"/run", nil), admin, defaultTenantStore(server), record.ID+"/run")
	if archived.Code != http.StatusConflict {
		t.Fatalf("archived run status = %d", archived.Code)
	}
	if err := defaultTenant(db).SetJobArchived(ctx, record.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := db.System().AcquireJobLease(ctx, record.ID, "active-owner", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	active := httptest.NewRecorder()
	server.jobRoute(active, httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+record.ID+"/run", nil), admin, defaultTenantStore(server), record.ID+"/run")
	if active.Code != http.StatusConflict {
		t.Fatalf("active run status = %d", active.Code)
	}
	_ = db.System().ReleaseJobLease(ctx, record.ID, "active-owner")
}

func TestServerPaginationAndSSEBoundaryHelpers(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodGet, "/?limit=bad", nil)
	if offset, err := queryOffset(request); queryLimit(request) != 50 || offset != 0 || err != nil {
		t.Fatal("invalid query values did not default")
	}
	request = httptest.NewRequest(http.MethodGet, "/?limit=2001&offset=10000000", nil)
	if offset, err := queryOffset(request); queryLimit(request) != 1000 || offset != 10000000 || err != nil {
		t.Fatal("query values at the pagination limit were not accepted")
	}
	request = httptest.NewRequest(http.MethodGet, "/?offset=10000001", nil)
	if _, err := queryOffset(request); !errors.Is(err, errPaginationOffsetTooLarge) {
		t.Fatal("oversized query offset was not rejected")
	}
	invalidOffset := httptest.NewRecorder()
	if _, ok := requestOffset(invalidOffset, request); ok || invalidOffset.Code != http.StatusBadRequest {
		t.Fatalf("oversized query offset response = %d, accepted=%t", invalidOffset.Code, ok)
	}
	for _, raw := range []string{"-1", "not-a-number", "999999999999999999999999999999999999"} {
		if _, err := queryOffset(httptest.NewRequest(http.MethodGet, "/?offset="+raw, nil)); !errors.Is(err, errPaginationOffsetInvalid) {
			t.Errorf("invalid offset %q was not rejected", raw)
		}
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

func TestSSECursorReservationRecoversAfterStartupFailure(t *testing.T) {
	t.Parallel()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.DB.ExecContext(context.Background(), `CREATE TRIGGER fail_sse_reservation BEFORE UPDATE ON sse_event_cursor BEGIN SELECT RAISE(ABORT, 'temporary cursor failure'); END`); err != nil {
		t.Fatal(err)
	}
	server := NewServer(nil, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.broadcast(map[string]any{"type": "during-cursor-outage"})
	server.mu.Lock()
	degradedID := server.nextEventID
	degraded := !server.sseDurable
	server.mu.Unlock()
	if !degraded || degradedID == 0 {
		t.Fatalf("startup cursor failure did not produce a fallback ID: durable=%v id=%d", !degraded, degradedID)
	}
	if _, err := db.DB.ExecContext(context.Background(), `DROP TRIGGER fail_sse_reservation`); err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return time.Now().UTC().Add(2 * time.Second) }
	server.broadcast(map[string]any{"type": "after-cursor-recovery"})
	server.mu.Lock()
	recoveredID := server.nextEventID
	durable := server.sseDurable
	server.mu.Unlock()
	if !durable || recoveredID <= degradedID {
		t.Fatalf("cursor did not recover monotonically: durable=%v degraded=%d recovered=%d", durable, degradedID, recoveredID)
	}
	var durableCursor int64
	if err := db.DB.QueryRowContext(context.Background(), `SELECT next_id FROM sse_event_cursor WHERE id=1`).Scan(&durableCursor); err != nil {
		t.Fatal(err)
	}
	if durableCursor < int64(recoveredID) {
		t.Fatalf("durable cursor=%d is behind recovered event=%d", durableCursor, recoveredID)
	}
}

func TestSSEReservationFailureBackoffCapsAndRecoversMonotonically(t *testing.T) {
	t.Parallel()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.DB.ExecContext(context.Background(), `CREATE TRIGGER fail_sse_reservation BEFORE UPDATE ON sse_event_cursor BEGIN SELECT RAISE(ABORT, 'temporary cursor failure'); END`); err != nil {
		t.Fatal(err)
	}
	server := NewServer(nil, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	server.now = func() time.Time { return now }
	server.mu.Lock()
	server.sseDurable = false
	server.sseRetryAt = now.Add(-time.Second)
	server.nextEventID = 100
	server.eventIDLimit = 99
	server.mu.Unlock()

	server.retrySSEReservationContext(context.Background())
	server.mu.Lock()
	if server.sseDurable || server.sseRetryDelay != 2*defaultSSEReservationRetry || !server.sseRetryAt.Equal(now.Add(2*defaultSSEReservationRetry)) || server.nextEventID <= 100 || server.eventIDLimit != ^uint64(0) {
		got := fmt.Sprintf("durable=%t delay=%s retry=%s next=%d limit=%d", server.sseDurable, server.sseRetryDelay, server.sseRetryAt, server.nextEventID, server.eventIDLimit)
		server.mu.Unlock()
		t.Fatalf("first failed reservation state: %s", got)
	}
	fallbackID := server.nextEventID
	server.sseRetryDelay = maxSSEReservationRetry/2 + time.Nanosecond
	server.mu.Unlock()

	now = now.Add(2 * defaultSSEReservationRetry)
	server.retrySSEReservationContext(context.Background())
	server.mu.Lock()
	if server.sseDurable || server.sseRetryDelay != maxSSEReservationRetry || !server.sseRetryAt.Equal(now.Add(maxSSEReservationRetry)) {
		got := fmt.Sprintf("durable=%t delay=%s retry=%s", server.sseDurable, server.sseRetryDelay, server.sseRetryAt)
		server.mu.Unlock()
		t.Fatalf("capped reservation retry state: %s", got)
	}
	server.mu.Unlock()

	if _, err := db.DB.ExecContext(context.Background(), `DROP TRIGGER fail_sse_reservation`); err != nil {
		t.Fatal(err)
	}
	now = now.Add(maxSSEReservationRetry + time.Second)
	server.retrySSEReservationContext(context.Background())
	server.mu.Lock()
	recoveredID, durable, delay, retryAt := server.nextEventID, server.sseDurable, server.sseRetryDelay, server.sseRetryAt
	server.mu.Unlock()
	if !durable || recoveredID < fallbackID || delay != 0 || !retryAt.IsZero() {
		t.Fatalf("recovered cursor state: durable=%t previous=%d recovered=%d delay=%s retry=%s", durable, fallbackID, recoveredID, delay, retryAt)
	}
	server.broadcast(map[string]any{"type": "after-reservation-recovery"})
	server.mu.Lock()
	monotonicID := server.nextEventID
	server.mu.Unlock()
	if monotonicID <= fallbackID {
		t.Fatalf("post-recovery event ID %d did not advance beyond fallback ID %d", monotonicID, fallbackID)
	}
}

func TestListenAndServeEnforcesLoopbackAndJoinsOnShutdown(t *testing.T) {
	t.Parallel()
	server, _, _ := newUsersTestServer(t)
	for _, address := range []string{"0.0.0.0:8080", "example.com:8080", "127.0.0.1:0", "not-a-listener"} {
		if err := server.ListenAndServe(context.Background(), address); err == nil {
			t.Errorf("ListenAndServe accepted unsafe or invalid address %q", address)
		}
	}

	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ListenAndServe(context.Background(), reserved.Addr().String()); err == nil {
		t.Fatal("ListenAndServe unexpectedly bound an address already in use")
	}
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe(ctx, address) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		connection, dialErr := net.DialTimeout("tcp", address, 25*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("loopback listener did not start: %v", dialErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful listener shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not join after context cancellation")
	}
}
