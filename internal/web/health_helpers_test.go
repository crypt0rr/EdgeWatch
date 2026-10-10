package web

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// healthStatus answers unhealthy for anything that is neither ready nor
// starting.
func TestHealthStatusOfUnknownStates(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		health store.HealthStatus
		err    error
		want   string
	}{
		{store.HealthStatus{Status: "ready"}, nil, healthReady},
		{store.HealthStatus{Status: "starting"}, nil, healthStarting},
		{store.HealthStatus{Status: "starting"}, errors.New("stalled"), healthUnhealthy},
		{store.HealthStatus{Status: "failed"}, nil, healthUnhealthy},
		{store.HealthStatus{}, nil, healthUnhealthy},
	} {
		if got := healthStatus(test.health, test.err); got != test.want {
			t.Errorf("healthStatus(%+v, %v) = %s, want %s", test.health, test.err, got, test.want)
		}
	}
}

// The metrics writer escapes label values and joins several labels.
func TestMetricsWriterFormat(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	m := metricsWriter{b: &b}
	m.family("edgewatch_example", "An example.")
	m.sample("edgewatch_example", 1.5, "a", "x\"y", "b", "line\nbreak\\")
	m.gauge("edgewatch_flag", "A flag.", boolMetric(true))
	want := "# HELP edgewatch_example An example.\n# TYPE edgewatch_example gauge\nedgewatch_example{a=\"x\\\"y\",b=\"line\\nbreak\\\\\"} 1.5\n# HELP edgewatch_flag A flag.\n# TYPE edgewatch_flag gauge\nedgewatch_flag 1\n"
	if b.String() != want {
		t.Errorf("metrics = %q, want %q", b.String(), want)
	}
	if boolMetric(false) != 0 {
		t.Error("false is not 0")
	}
}

// Without a database the metrics report an unhealthy deployment and no
// database counts, and a build without a version reports dev.
func TestMetricsWithoutADatabase(t *testing.T) {
	t.Parallel()
	server := NewServer(nil, nil, nil)
	var b bytes.Buffer
	server.writeMetrics(context.Background(), &b)
	body := b.String()
	for _, want := range []string{`edgewatch_build_info{version="dev"} 1`, `edgewatch_health_status{status="unhealthy"} 1`, `edgewatch_migration_state{state="unknown"} 1`} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "edgewatch_database_bytes") {
		t.Error("metrics without a database report its size")
	}
	if _, err := server.cachedDeploymentTelemetry(context.Background()); err == nil {
		t.Error("telemetry without a database was read")
	}
}

// A failed migration and a release check that succeeded are reported.
func TestMetricsReportAFailedMigrationAndTheReleaseCheck(t *testing.T) {
	t.Parallel()
	server, db := newHealthServer(t)
	server.Version = "v0.36.0"
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.DB.Exec(`UPDATE startup_state SET state='failed',updated_at=?,last_error='broken' WHERE id=1`, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE application_update_state SET latest_version='v0.37.0',check_status='ok',last_checked_at=?,last_successful_check_at=? WHERE id=1`, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	server.writeMetrics(context.Background(), &b)
	body := b.String()
	for _, want := range []string{`edgewatch_migration_state{state="failed"} 1`, `edgewatch_update_check_status{status="update_available"} 1`, "edgewatch_update_available 1", "edgewatch_update_last_successful_check_timestamp_seconds "} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q:\n%s", want, body)
		}
	}
}

// The single-flight cache shares one load between concurrent callers,
// releases them when the load panics, and stops waiting when the caller's
// context ends.
func TestSingleFlightCache(t *testing.T) {
	t.Parallel()
	var cache singleFlight[int]
	release := make(chan struct{})
	started := make(chan struct{})
	loads := 0
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		value, err := cache.get(context.Background(), time.Minute, func(context.Context) (int, error) {
			loads++
			close(started)
			<-release
			return 7, nil
		})
		if err != nil || value != 7 {
			t.Errorf("first get = %d, %v", value, err)
		}
	}()
	<-started
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.get(canceled, time.Minute, func(context.Context) (int, error) { return 0, nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("a waiter with an ended context = %v", err)
	}
	waited := make(chan int)
	go func() {
		value, _ := cache.get(context.Background(), time.Minute, func(context.Context) (int, error) { return 0, errors.New("not called") })
		waited <- value
	}()
	close(release)
	if value := <-waited; value != 7 {
		t.Errorf("a waiter got %d, want the shared load", value)
	}
	wg.Wait()
	if loads != 1 {
		t.Errorf("loads = %d, want 1", loads)
	}
	var panicking singleFlight[int]
	if _, err := panicking.get(context.Background(), time.Minute, func(context.Context) (int, error) { panic("boom") }); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("a panicking load = %v", err)
	}
	if value, err := panicking.get(context.Background(), time.Minute, func(context.Context) (int, error) { return 3, nil }); err != nil || value != 3 {
		t.Errorf("a load after the panic = %d, %v", value, err)
	}
}

// The routing handlers answer a malformed body, a wrong password, and a
// store that fails, without changing anything.
func TestAlertRoutingFailures(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	for _, request := range []struct{ actor, method, path, body string }{
		{actorAdminB, http.MethodPatch, "/notifications/security-routing", "{"},
		{actorAdminB, http.MethodPut, "/notifications/security-routing", `{"destinations":[],"password":"wrong password"}`},
		{actorPlatform, http.MethodPatch, "/platform/notifications/health-routing", "{"},
		{actorPlatform, http.MethodPut, "/platform/notifications/security-routing", `{"destinations":[],"password":"wrong password"}`},
	} {
		if response := f.call(t, request.actor, request.method, request.path, request.body); response.Code < 400 || response.Code >= 500 {
			t.Errorf("%s %s %s = %d", request.method, request.path, request.body, response.Code)
		}
	}
	if _, err := f.db.DB.Exec(`CREATE TRIGGER fail_routing BEFORE UPDATE OF security_destinations_json ON tenants BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if response := f.call(t, actorAdminB, http.MethodPut, "/notifications/security-routing", confirmBody(`"destinations":[]`)); response.Code != http.StatusInternalServerError {
		t.Errorf("a failed save = %d: %s", response.Code, response.Body.String())
	}
	if _, err := f.db.DB.Exec(`CREATE TRIGGER fail_platform_routing BEFORE UPDATE ON platform_alert_state BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if response := f.call(t, actorPlatform, http.MethodPut, "/platform/notifications/health-routing", confirmBody(`"destinations":[]`)); response.Code < 500 {
		t.Errorf("a failed platform save = %d: %s", response.Code, response.Body.String())
	}
	if _, err := f.db.DB.Exec(`DROP TRIGGER fail_routing`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DB.Exec(`UPDATE tenants SET security_destinations_json='not json'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DB.Exec(`DROP TRIGGER fail_platform_routing`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DB.Exec(`UPDATE platform_alert_state SET security_destinations_json='not json'`); err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct{ actor, method, path, body string }{
		{actorAdminB, http.MethodPatch, "/notifications/security-routing", confirmBody(`"destination_id":"` + f.destinationB + `","enabled":true`)},
		{actorAdminB, http.MethodGet, "/notifications/destinations", ""},
		{actorPlatform, http.MethodPatch, "/platform/notifications/security-routing", confirmBody(`"destination_id":"` + f.destinationB + `","enabled":true`)},
		{actorPlatform, http.MethodGet, "/platform/notifications", ""},
	} {
		if response := f.call(t, request.actor, request.method, request.path, request.body); response.Code != http.StatusInternalServerError {
			t.Errorf("%s %s with a malformed routing = %d: %s", request.method, request.path, response.Code, response.Body.String())
		}
	}
	// The platform status leaves out the telemetry that cannot be read.
	if _, err := f.db.DB.Exec(`DROP TABLE events`); err != nil {
		t.Fatal(err)
	}
	f.server.deploymentTelemetry = singleFlight[store.DeploymentTelemetry]{}
	status := f.call(t, actorPlatform, http.MethodGet, "/platform/status", "")
	if status.Code != http.StatusOK || strings.Contains(status.Body.String(), `"telemetry"`) {
		t.Errorf("platform status without telemetry = %d: %s", status.Code, status.Body.String())
	}
	if view := alertRoutingView(nil); view["destinations"] == nil {
		t.Error("a nil routing is not an empty list")
	}
}
