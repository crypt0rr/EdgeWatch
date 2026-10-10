package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/sandbox"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// newHealthServer returns a server on a fresh database whose daemon
// heartbeat and startup state the test sets.
func newHealthServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	db, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}}
	application, err := app.New(cfg, db, "missing-nmap", logger)
	if err != nil {
		t.Fatal(err)
	}
	return NewServer(application, db, logger), db
}

// getHealthz sends GET /healthz through the HTTP boundary from a client at
// address, with a host name that the console API would refuse.
func getHealthz(server *Server, method, address string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "/healthz", nil)
	request.Host = "status.example.net"
	request.RemoteAddr = address + ":4000"
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

// GET /healthz maps each outcome of the daemon's health to one word and its
// status code, and answers with nothing else: no reason, phase, or unit.
func TestHealthzAnswersEachHealthOutcome(t *testing.T) {
	t.Parallel()
	server, db := newHealthServer(t)
	now := time.Now().UTC()
	fresh, stale := now.Format(time.RFC3339Nano), now.Add(-time.Hour).Format(time.RFC3339Nano)
	for _, test := range []struct {
		name, state, updated, heartbeat, want string
		code                                  int
	}{
		{"ready", "ready", fresh, fresh, healthReady, http.StatusOK},
		{"migrating", "migrating", fresh, "", healthStarting, http.StatusServiceUnavailable},
		{"stalled migration", "migrating", stale, "", healthUnhealthy, http.StatusServiceUnavailable},
		{"failed migration", "failed", fresh, fresh, healthUnhealthy, http.StatusServiceUnavailable},
		{"stale heartbeat", "ready", fresh, stale, healthUnhealthy, http.StatusServiceUnavailable},
		{"no daemon", "ready", fresh, "", healthUnhealthy, http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := db.DB.Exec(`UPDATE startup_state SET state=?,phase='host-search:secret-phase',updated_at=?,last_error='index rebuild failed at /data/edgewatch.db' WHERE id=1`, test.state, test.updated); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.Exec(`DELETE FROM daemon_lease`); err != nil {
				t.Fatal(err)
			}
			if test.heartbeat != "" {
				if _, err := db.DB.Exec(`INSERT INTO daemon_lease(id,owner,heartbeat) VALUES(1,'daemon',?)`, test.heartbeat); err != nil {
					t.Fatal(err)
				}
			}
			server.healthMu.Lock()
			server.health = healthAnswer{}
			server.healthMu.Unlock()
			response := getHealthz(server, http.MethodGet, "192.0.2.50")
			var body map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code != test.code || len(body) != 1 || body["status"] != test.want {
				t.Errorf("GET /healthz = %d %s, want %d {\"status\":%q}", response.Code, response.Body.String(), test.code, test.want)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("cache header = %q", response.Header().Get("Cache-Control"))
			}
		})
	}
	// A repeated request within the cache's second reads nothing again.
	if _, err := db.DB.Exec(`DELETE FROM daemon_lease`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO daemon_lease(id,owner,heartbeat) VALUES(1,'daemon',?)`, fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE startup_state SET state='ready' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	server.healthMu.Lock()
	server.health = healthAnswer{}
	server.healthMu.Unlock()
	if response := getHealthz(server, http.MethodHead, "192.0.2.50"); response.Code != http.StatusOK {
		t.Fatalf("HEAD /healthz = %d", response.Code)
	}
	if _, err := db.DB.Exec(`DELETE FROM daemon_lease`); err != nil {
		t.Fatal(err)
	}
	if response := getHealthz(server, http.MethodGet, "192.0.2.50"); response.Code != http.StatusOK {
		t.Errorf("cached GET /healthz = %d, want the cached ready answer", response.Code)
	}
}

// recordDaemonHeartbeat records a fresh daemon heartbeat, so a fresh
// database's health is ready.
func recordDaemonHeartbeat(t *testing.T, db *store.Store) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO daemon_lease(id,owner,heartbeat) VALUES(1,'daemon',?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

// A client that drops its connection cancels its request's context. The
// answer that its request reads is every client's, so the read ignores that
// cancellation: the next client still gets ready, not an unhealthy answer
// cached from a cancelled read.
func TestHealthzIgnoresACancelledRequest(t *testing.T) {
	t.Parallel()
	server, db := newHealthServer(t)
	recordDaemonHeartbeat(t, db)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil).WithContext(ctx)
	request.RemoteAddr = "198.51.100.7:4000"
	dropped := httptest.NewRecorder()
	server.Handler().ServeHTTP(dropped, request)
	if dropped.Code != http.StatusOK {
		t.Errorf("cancelled GET /healthz = %d %s, want the deployment's ready answer", dropped.Code, dropped.Body.String())
	}
	if response := getHealthz(server, http.MethodGet, "192.0.2.64"); response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"status":"ready"}` {
		t.Errorf("GET /healthz after a cancelled request = %d %s, want 200 ready", response.Code, response.Body.String())
	}
}

// The cached answer is dated when its read ends, so an answer whose read
// took longer than the TTL is still reused for the TTL after it, and the
// requests that waited for it do not each read again.
func TestHealthzDatesTheAnswerWhenTheReadEnds(t *testing.T) {
	t.Parallel()
	server, db := newHealthServer(t)
	recordDaemonHeartbeat(t, db)
	// The first read starts at start and ends 1.5 s later, as a slow
	// database read would. The next requests come 2 s and 2.6 s after
	// start, and the last read ends then too.
	start := time.Now().UTC()
	readings := []time.Duration{0, 1500 * time.Millisecond, 2 * time.Second, 2600 * time.Millisecond}
	var next atomic.Int64
	server.now = func() time.Time {
		return start.Add(readings[min(int(next.Add(1)-1), len(readings)-1)])
	}
	if status := server.readHealth(context.Background()); status != healthReady {
		t.Fatalf("first answer = %q", status)
	}
	if _, err := db.DB.Exec(`DELETE FROM daemon_lease`); err != nil {
		t.Fatal(err)
	}
	// 500 ms after the first read ended, its answer is reused.
	if status := server.readHealth(context.Background()); status != healthReady {
		t.Errorf("answer 500 ms after the read ended = %q, want the cached ready answer", status)
	}
	// 1.1 s after it ended, the answer is read again.
	if status := server.readHealth(context.Background()); status != healthUnhealthy {
		t.Errorf("answer 1.1 s after the read ended = %q, want a new unhealthy answer", status)
	}
}

// /healthz takes GET and HEAD only, and a client gets the public pages'
// budget of 120 requests a minute; beyond it the answer is rate_limited,
// for that client only.
func TestHealthzMethodsAndRateLimit(t *testing.T) {
	t.Parallel()
	server, _ := newHealthServer(t)
	if response := getHealthz(server, http.MethodPost, "192.0.2.60"); response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" || !strings.Contains(response.Body.String(), "method_not_allowed") {
		t.Errorf("POST /healthz = %d %q %s", response.Code, response.Header().Get("Allow"), response.Body.String())
	}
	for i := 0; i < anonymousRequestLimit; i++ {
		if response := getHealthz(server, http.MethodGet, "192.0.2.61"); response.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d was rate limited", i+1)
		}
	}
	response := getHealthz(server, http.MethodGet, "192.0.2.61")
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "60" || strings.TrimSpace(response.Body.String()) != `{"status":"rate_limited"}` {
		t.Errorf("request beyond the budget = %d %q %s", response.Code, response.Header().Get("Retry-After"), response.Body.String())
	}
	if response := getHealthz(server, http.MethodGet, "192.0.2.62"); response.Code == http.StatusTooManyRequests {
		t.Error("another client was rate limited")
	}
	// Without a database the answer is unhealthy.
	bare := NewServer(nil, nil, nil)
	if response := getHealthz(bare, http.MethodGet, "192.0.2.63"); response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), healthUnhealthy) {
		t.Errorf("GET /healthz without a database = %d %s", response.Code, response.Body.String())
	}
}

// writeMetricsToken writes a token file with the mode and returns its path.
func writeMetricsToken(t *testing.T, token string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "metrics.token")
	if err := os.WriteFile(path, []byte(token+"\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// getMetrics sends GET /metrics through the HTTP boundary with the
// Authorization header, when it is not empty.
func getMetrics(server *Server, authorization, address string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.RemoteAddr = address + ":4000"
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

const metricsTestToken = "metrics-token-0123456789abcdef0123456789"

// The metrics endpoint is off unless it is enabled, refuses a request
// without the bearer token or with another one, and closes when the token
// file cannot be read.
func TestMetricsRefusesRequestsWithoutTheToken(t *testing.T) {
	t.Parallel()
	server, _ := newHealthServer(t)
	if response := getMetrics(server, "Bearer "+metricsTestToken, "192.0.2.70"); response.Code != http.StatusNotFound {
		t.Errorf("disabled /metrics = %d", response.Code)
	}
	server.configureMetrics(config.WebMetrics{Enabled: true, TokenFile: writeMetricsToken(t, metricsTestToken, 0o600)})
	for _, authorization := range []string{"", "Bearer wrong-token-0123456789abcdef0123456789", "Basic " + metricsTestToken, metricsTestToken} {
		response := getMetrics(server, authorization, "192.0.2.71")
		if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != `Bearer realm="edgewatch-metrics"` || strings.Contains(response.Body.String(), "edgewatch_") {
			t.Errorf("/metrics with %q = %d %s", authorization, response.Code, response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /metrics = %d", response.Code)
	}
	for i := 0; i < anonymousRequestLimit; i++ {
		getMetrics(server, "", "192.0.2.72")
	}
	if response := getMetrics(server, "Bearer "+metricsTestToken, "192.0.2.72"); response.Code != http.StatusTooManyRequests {
		t.Errorf("/metrics beyond the budget = %d", response.Code)
	}
	unreadable, _ := newHealthServer(t)
	unreadable.configureMetrics(config.WebMetrics{Enabled: true, TokenFile: writeMetricsToken(t, metricsTestToken, 0o644)})
	if response := getMetrics(unreadable, "Bearer "+metricsTestToken, "192.0.2.73"); response.Code != http.StatusServiceUnavailable {
		t.Errorf("/metrics with an unusable token file = %d %s", response.Code, response.Body.String())
	}
}

// With the token, /metrics reports deployment aggregates in the Prometheus
// text format. In a deployment with two units it names no unit, slug, job,
// target, account, or destination.
func TestMetricsReportDeploymentAggregatesOnly(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	server := f.server
	server.configureMetrics(config.WebMetrics{Enabled: true, TokenFile: writeMetricsToken(t, metricsTestToken, 0o400)})
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := f.db.DB.Exec(`INSERT OR REPLACE INTO daemon_lease(id,owner,heartbeat) VALUES(1,'daemon',?)`, now); err != nil {
		t.Fatal(err)
	}
	response := getMetrics(server, "Bearer "+metricsTestToken, "192.0.2.80")
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("/metrics = %d %q: %s", response.Code, response.Header().Get("Content-Type"), response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		`edgewatch_health_status{status="ready"} 1`,
		`edgewatch_migration_state{state="ready"} 1`,
		"edgewatch_daemon_heartbeat_age_seconds ",
		"edgewatch_scan_slots_capacity 2",
		"edgewatch_scan_slots_in_use 0",
		"edgewatch_scans_queued 0",
		"edgewatch_database_bytes ",
		"edgewatch_notification_outbox_pending 0",
		"edgewatch_notification_outbox_retrying 0",
		"edgewatch_notification_outbox_terminal 0",
		"edgewatch_notification_destinations_locked 0",
		`edgewatch_update_check_status{status="development_build"} 1`,
		"edgewatch_update_available 0",
		`edgewatch_build_info{version="dev"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics lacks %q:\n%s", want, body)
		}
	}
	for _, unitData := range []string{f.unitB, store.DefaultTenantID, "bravo", "Bravo", "alpha", "Default", "default", "shared-job", "192.0.2.10", platformFixtureAddress, "platform-root", f.destinationA, f.destinationB} {
		if strings.Contains(body, unitData) {
			t.Errorf("/metrics names %q:\n%s", unitData, body)
		}
	}
	sample := regexp.MustCompile(`^[a-z_]+(\{[a-z_]+="[^"\n]*"(,[a-z_]+="[^"\n]*")*\})? [0-9.e+-]+$`)
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if !strings.HasPrefix(line, "# ") && !sample.MatchString(line) {
			t.Errorf("malformed sample %q", line)
		}
	}
}

// A lost or replaced notification key locks every web-managed destination,
// the platform's too, so no alert can report it; /metrics counts the
// enabled destinations that are locked once a delivery pass loads them
// again. A paused destination gets no alert and is not counted.
func TestMetricsCountLockedNotificationDestinations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db := newHealthServer(t)
	server.configureMetrics(config.WebMetrics{Enabled: true, TokenFile: writeMetricsToken(t, metricsTestToken, 0o600)})
	unit := server.App.Notifier.Tenant(defaultTenantStore(server))
	for name, enabled := range map[string]bool{"Ops": true, "Paused": false} {
		if _, err := unit.CreateManagedWithAudit(ctx, name, "generic://127.0.0.1:9/"+strings.ToLower(name)+"?disabletls=yes", enabled, store.AuditEntry{}); err != nil {
			t.Fatal(err)
		}
	}
	if body := getMetrics(server, "Bearer "+metricsTestToken, "192.0.2.85").Body.String(); !strings.Contains(body, "\nedgewatch_notification_destinations_locked 0\n") {
		t.Errorf("/metrics with the key lacks a zero locked count:\n%s", body)
	}
	if err := os.Remove(filepath.Join(filepath.Dir(db.Path), "notification.key")); err != nil {
		t.Fatal(err)
	}
	if err := server.App.Notifier.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	body := getMetrics(server, "Bearer "+metricsTestToken, "192.0.2.85").Body.String()
	if !strings.Contains(body, "\nedgewatch_notification_destinations_locked 1\n") {
		t.Errorf("/metrics without the key lacks one locked destination:\n%s", body)
	}
	for _, detail := range []string{"generic://", "127.0.0.1:9", "Ops", "Paused"} {
		if strings.Contains(body, detail) {
			t.Errorf("/metrics names %q:\n%s", detail, body)
		}
	}
}

// The sandbox states and a running migration are reported as state sets,
// and a label value is escaped.
func TestMetricsReportSandboxesAndMigrations(t *testing.T) {
	t.Parallel()
	server, db := newHealthServer(t)
	confined, err := app.NewWithOptions(server.App.Config, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)), app.Options{Sandbox: sandbox.NewEnforced(), NotificationSandbox: sandbox.NewEnforcedFor(sandbox.Notifier).WithLandlock("/usr/local/bin/edgewatch", 3)})
	if err != nil {
		t.Fatal(err)
	}
	server.App = confined
	server.Version = "v0.36.0\"x"
	server.configureMetrics(config.WebMetrics{Enabled: true, TokenFile: writeMetricsToken(t, metricsTestToken, 0o600)})
	if _, err := db.DB.Exec(`UPDATE startup_state SET state='migrating',phase='host-search:scan_hosts',updated_at=?,progress=25,total=100 WHERE id=1`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	body := getMetrics(server, "Bearer "+metricsTestToken, "192.0.2.90").Body.String()
	for _, want := range []string{
		`edgewatch_scanner_sandbox_state{state="identity_only"} 1`,
		`edgewatch_scanner_sandbox_state{state="sandboxed"} 0`,
		`edgewatch_notification_sandbox_state{state="sandboxed"} 1`,
		`edgewatch_health_status{status="starting"} 1`,
		`edgewatch_migration_state{state="migrating"} 1`,
		`edgewatch_migration_phase_info{phase="host-search:scan_hosts"} 1`,
		"edgewatch_migration_progress_ratio 0.25",
		`edgewatch_build_info{version="v0.36.0\"x"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "edgewatch_daemon_heartbeat_age_seconds") {
		t.Error("/metrics reports a heartbeat age while the daemon is not ready")
	}
}

// Every metric family that /metrics writes is documented, so the names
// stay a deliberate contract.
func TestMetricNamesAreDocumented(t *testing.T) {
	t.Parallel()
	server, db := newHealthServer(t)
	confined, err := app.NewWithOptions(server.App.Config, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)), app.Options{Sandbox: sandbox.NewEnforced(), NotificationSandbox: sandbox.NewEnforcedFor(sandbox.Notifier)})
	if err != nil {
		t.Fatal(err)
	}
	server.App = confined
	server.configureMetrics(config.WebMetrics{Enabled: true, TokenFile: writeMetricsToken(t, metricsTestToken, 0o600)})
	docs, err := os.ReadFile(filepath.Join("..", "..", "docs", "src", "content", "docs", "reference", "api-compatibility.md"))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{"edgewatch_migration_phase_info": true, "edgewatch_migration_progress_ratio": true, "edgewatch_daemon_heartbeat_age_seconds": true, "edgewatch_update_last_successful_check_timestamp_seconds": true}
	body := getMetrics(server, "Bearer "+metricsTestToken, "192.0.2.95").Body.String()
	for _, line := range strings.Split(body, "\n") {
		if name, ok := strings.CutPrefix(line, "# TYPE "); ok {
			names[strings.Fields(name)[0]] = true
		}
	}
	for name := range names {
		if !strings.Contains(string(docs), "`"+name+"`") {
			t.Errorf("metric %s is not documented in the API reference", name)
		}
	}
}

// The platform status reports the deployment's telemetry, as counts.
func TestPlatformStatusReportsDeploymentTelemetry(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	response := f.call(t, actorPlatform, http.MethodGet, "/platform/status", "")
	var status struct {
		Telemetry *store.DeploymentTelemetry `json:"telemetry"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil || status.Telemetry == nil {
		t.Fatalf("platform status %s: %v", response.Body.String(), err)
	}
	if status.Telemetry.DatabaseBytes <= 0 || status.Telemetry.Jobs != 3 || status.Telemetry.CollectedAt.IsZero() {
		t.Errorf("telemetry = %+v", status.Telemetry)
	}
	for _, unitData := range []string{"bravo", "shared-job", platformFixtureAddress} {
		if strings.Contains(response.Body.String(), unitData) {
			t.Errorf("platform status names %q", unitData)
		}
	}
}
