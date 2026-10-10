package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// The answers of GET /healthz. The endpoint is unauthenticated, so it
// reports one word and nothing else: no reason, warning, phase, or unit.
const (
	healthReady       = "ready"
	healthStarting    = "starting"
	healthUnhealthy   = "unhealthy"
	healthRateLimited = "rate_limited"
)

// healthCacheTTL is how long one health answer is reused, so anonymous
// requests cannot add database reads beyond one every TTL.
const healthCacheTTL = time.Second

// healthReadTimeout bounds the database reads of one health answer.
const healthReadTimeout = 2 * time.Second

// healthAnswer is a cached health state with the time it was read.
type healthAnswer struct {
	status string
	at     time.Time
}

// healthStatus maps the daemon's health to the endpoint's answer: ready
// while the daemon's heartbeat is recent, starting while a migration with a
// recent heartbeat runs, and unhealthy for a failed or stalled migration, a
// stale or missing heartbeat, and a database that cannot be read.
func healthStatus(health store.HealthStatus, err error) string {
	switch {
	case err != nil:
		return healthUnhealthy
	case health.Status == healthReady:
		return healthReady
	case health.Status == healthStarting:
		return healthStarting
	default:
		return healthUnhealthy
	}
}

// readHealth returns the health answer, from the cache when it is fresh.
// The lock is held while the answer is read, so concurrent requests share
// one read. The answer is every client's, so the read ignores the
// cancellation of the request that makes it: a client that drops its
// connection must not cache unhealthy for the others. The answer is dated
// when the read ends, so a slow read is still reused for the whole TTL.
func (s *Server) readHealth(ctx context.Context) string {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	now := s.currentTime()
	if s.health.status != "" && now.Sub(s.health.at) < healthCacheTTL && !now.Before(s.health.at) {
		return s.health.status
	}
	status := healthUnhealthy
	if s.Store != nil {
		readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), healthReadTimeout)
		health, err := s.Store.Platform().HealthStatus(readCtx)
		cancel()
		status = healthStatus(health, err)
	}
	s.health = healthAnswer{status: status, at: s.currentTime()}
	return status
}

// healthz serves GET /healthz for uptime checks and container orchestrators:
// {"status":"ready"} with 200, or {"status":"starting"} or
// {"status":"unhealthy"} with 503. Like the public status pages, it needs no
// session and no approved host name, and each client may send 120 requests
// a minute; beyond that it gets {"status":"rate_limited"} with 429.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"status": "method_not_allowed"})
		return
	}
	if !s.allowAnonymousRequest(r, "healthz") {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"status": healthRateLimited})
		return
	}
	status := s.readHealth(r.Context())
	code := http.StatusOK
	if status != healthReady {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]string{"status": status})
}

// metricsSettings is the metrics endpoint as NewServer configured it.
type metricsSettings struct {
	enabled bool
	// digest is the SHA-256 of the bearer token, or nil when the token file
	// could not be read.
	digest []byte
}

// configureMetrics reads the metrics token when the endpoint is enabled.
// The daemon checked the token file before it opened the database; a file
// that cannot be read now keeps the endpoint closed.
func (s *Server) configureMetrics(settings config.WebMetrics) {
	s.metrics = metricsSettings{enabled: settings.Enabled}
	if !settings.Enabled {
		return
	}
	token, err := config.ReadMetricsToken(settings.TokenFile)
	if err != nil {
		if s.Log != nil {
			s.Log.Error("metrics endpoint unavailable", "error", err)
		}
		return
	}
	digest := sha256.Sum256([]byte(token))
	s.metrics.digest = digest[:]
}

// metricsAuthorized reports whether the request carries the metrics bearer
// token. The digests are compared in constant time.
func (s *Server) metricsAuthorized(r *http.Request) bool {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || s.metrics.digest == nil {
		return false
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return subtle.ConstantTimeCompare(digest[:], s.metrics.digest) == 1
}

// metricsEndpoint serves GET /metrics in the Prometheus text format when
// web.metrics.enabled is true, to a request with the bearer token of
// web.metrics.token_file; see writeMetrics for what it reports. Each client
// may send 120 requests a minute.
func (s *Server) metricsEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.metrics.enabled {
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found", nil)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", nil)
		return
	}
	if !s.allowAnonymousRequest(r, "metrics") {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "metrics requests are temporarily rate limited", nil)
		return
	}
	if s.metrics.digest == nil {
		writeError(w, http.StatusServiceUnavailable, "metrics_unavailable", "the metrics token could not be read", nil)
		return
	}
	if !s.metricsAuthorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="edgewatch-metrics"`)
		writeError(w, http.StatusUnauthorized, "unauthorized", "a valid metrics bearer token is required", nil)
		return
	}
	var body bytes.Buffer
	s.writeMetrics(r.Context(), &body)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body.Bytes())
}

// metricsWriter writes metric families in the Prometheus text format.
type metricsWriter struct {
	b *bytes.Buffer
}

// family writes the help and type of a gauge.
func (m metricsWriter) family(name, help string) {
	fmt.Fprintf(m.b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
}

// sample writes one sample of a gauge, with its labels in the order given.
func (m metricsWriter) sample(name string, value float64, labels ...string) {
	m.b.WriteString(name)
	if len(labels) > 0 {
		m.b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				m.b.WriteByte(',')
			}
			m.b.WriteString(labels[i])
			m.b.WriteString(`="`)
			m.b.WriteString(metricLabelValue(labels[i+1]))
			m.b.WriteByte('"')
		}
		m.b.WriteByte('}')
	}
	m.b.WriteByte(' ')
	m.b.WriteString(strconv.FormatFloat(value, 'g', -1, 64))
	m.b.WriteByte('\n')
}

// gauge writes a gauge with one unlabelled sample.
func (m metricsWriter) gauge(name, help string, value float64) {
	m.family(name, help)
	m.sample(name, value)
}

// stateSet writes a gauge with one sample for each of the states, 1 for the
// current one and 0 for the others, labelled with label.
func (m metricsWriter) stateSet(name, help, label, current string, states []string) {
	m.family(name, help)
	for _, state := range states {
		value := 0.0
		if state == current {
			value = 1
		}
		m.sample(name, value, label, state)
	}
}

// metricLabelValue escapes a label value of the text format.
func metricLabelValue(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(value)
}

// boolMetric is 1 for true and 0 for false.
func boolMetric(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

// The states that the metrics report, in the order they are written.
var (
	metricsHealthStates    = []string{healthReady, healthStarting, healthUnhealthy}
	metricsMigrationStates = []string{"migrating", "ready", "failed", "unknown"}
	metricsSandboxStates   = []string{model.SandboxStateSandboxed, model.SandboxStateIdentityOnly, model.SandboxStateLandlockOnly, model.SandboxStateUnconfined}
	metricsUpdateStatuses  = []string{"up_to_date", "update_available", "ahead", "check_failed", "disabled", "development_build"}
)

// writeMetrics writes the deployment's metrics. They are deployment
// aggregates only: the build, the health and its heartbeat, the migration
// state, the scan slots, the notification outbox, the locked notification
// destinations, the database size, the sandbox states, and the update
// check. No metric has a label that names a business unit, an account, a
// job, a target, or a destination, and the names are stable; see the API
// reference.
func (s *Server) writeMetrics(ctx context.Context, b *bytes.Buffer) {
	m := metricsWriter{b: b}
	version := s.Version
	if version == "" {
		version = "dev"
	}
	m.family("edgewatch_build_info", "The running EdgeWatch build, by version.")
	m.sample("edgewatch_build_info", 1, "version", version)

	var health store.HealthStatus
	var healthErr error
	if s.Store != nil {
		readCtx, cancel := context.WithTimeout(ctx, healthReadTimeout)
		health, healthErr = s.Store.Platform().HealthStatus(readCtx)
		cancel()
	} else {
		healthErr = context.Canceled
	}
	status := healthStatus(health, healthErr)
	m.stateSet("edgewatch_health_status", "The answer of GET /healthz, 1 for the current status.", "status", status, metricsHealthStates)
	if status == healthReady && !health.UpdatedAt.IsZero() {
		m.gauge("edgewatch_daemon_heartbeat_age_seconds", "Seconds since the daemon last renewed its lease.", max(s.currentTime().Sub(health.UpdatedAt).Seconds(), 0))
	}
	migration := "unknown"
	switch health.Status {
	case healthStarting:
		migration = "migrating"
	case healthReady:
		migration = "ready"
	case "failed":
		migration = "failed"
	}
	m.stateSet("edgewatch_migration_state", "The startup migration state, 1 for the current state.", "state", migration, metricsMigrationStates)
	if migration == "migrating" {
		// The phases are the fixed steps of the migration, such as schema or
		// host-search:scan_hosts, never a unit's data.
		m.family("edgewatch_migration_phase_info", "The running migration phase.")
		m.sample("edgewatch_migration_phase_info", 1, "phase", health.Phase)
		if health.Total > 0 {
			m.gauge("edgewatch_migration_progress_ratio", "The progress of the running migration phase, from 0 to 1.", min(float64(health.Progress)/float64(health.Total), 1))
		}
	}

	if s.App != nil {
		usage := s.App.SlotUsage()
		m.gauge("edgewatch_scan_slots_capacity", "The deployment's scan slots.", float64(usage.Capacity))
		m.gauge("edgewatch_scan_slots_in_use", "The scan slots that running scans hold.", float64(usage.InUse))
		m.gauge("edgewatch_scans_queued", "The accepted scans that wait for a scan slot.", float64(usage.Queued))
	}

	if telemetry, err := s.cachedDeploymentTelemetry(ctx); err == nil {
		m.gauge("edgewatch_database_bytes", "The size that SQLite has allocated for the database.", float64(telemetry.DatabaseBytes))
		m.gauge("edgewatch_notification_outbox_pending", "Alerts not yet sent that are still to be delivered, including those retrying.", float64(max(telemetry.OutboxPending-telemetry.OutboxFailed, 0)))
		m.gauge("edgewatch_notification_outbox_retrying", "Alerts whose delivery failed at least once and is retried.", float64(telemetry.OutboxRetrying))
		m.gauge("edgewatch_notification_outbox_terminal", "Alerts whose delivery failed for good.", float64(telemetry.OutboxFailed))
		m.gauge("edgewatch_telemetry_collected_timestamp_seconds", "When the database and outbox counts were read, as a Unix time.", float64(telemetry.CollectedAt.Unix()))
	}
	if s.App != nil && s.App.Notifier != nil {
		// A lost or replaced notification key locks every web-managed
		// destination, the platform's too, so no alert can report it.
		m.gauge("edgewatch_notification_destinations_locked", "Enabled web-managed destinations that alerts cannot reach, because the notification key cannot open them or their URL is no longer valid.", float64(s.App.Notifier.LockedDestinationCount()))
	}

	if s.App != nil {
		sandboxes := s.App.SandboxHealth()
		if sandboxes.Scanner != "" {
			m.stateSet("edgewatch_scanner_sandbox_state", "How scanner processes are confined, 1 for the current state.", "state", sandboxes.Scanner, metricsSandboxStates)
		}
		if sandboxes.Notification != "" {
			m.stateSet("edgewatch_notification_sandbox_state", "How the notification process is confined, 1 for the current state.", "state", sandboxes.Notification, metricsSandboxStates)
		}
	}

	updates := s.applicationUpdateStatus(ctx)
	m.stateSet("edgewatch_update_check_status", "The release check, 1 for the current status.", "status", updates.Status, metricsUpdateStatuses)
	m.gauge("edgewatch_update_available", "Whether a newer release is available.", boolMetric(updates.Available))
	if !updates.LastSuccessfulCheckAt.IsZero() {
		m.gauge("edgewatch_update_last_successful_check_timestamp_seconds", "When the release check last succeeded, as a Unix time.", float64(updates.LastSuccessfulCheckAt.Unix()))
	}
}

// singleFlight caches one value for a TTL and lets one caller refresh it
// while the others wait for that refresh.
type singleFlight[T any] struct {
	mu      sync.Mutex
	value   T
	at      time.Time
	valid   bool
	running bool
	done    chan struct{}
}

// get returns the cached value, or the value that load returns when the
// cache is older than ttl. A load that fails is not cached.
func (c *singleFlight[T]) get(ctx context.Context, ttl time.Duration, load func(context.Context) (T, error)) (T, error) {
	for {
		c.mu.Lock()
		if c.valid && time.Since(c.at) < ttl {
			value := c.value
			c.mu.Unlock()
			return value, nil
		}
		if !c.running {
			c.running = true
			c.done = make(chan struct{})
			done := c.done
			c.mu.Unlock()
			var value T
			var err error
			func() {
				// Release the waiters even when load panics.
				defer func() {
					if recovered := recover(); recovered != nil {
						err = fmt.Errorf("telemetry panic: %v", recovered)
					}
					c.mu.Lock()
					if err == nil {
						c.value, c.at, c.valid = value, time.Now(), true
					}
					c.running = false
					close(done)
					c.mu.Unlock()
				}()
				value, err = load(ctx)
			}()
			return value, err
		}
		done := c.done
		c.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		}
	}
}

// cachedDeploymentTelemetry returns the deployment's telemetry, read at
// most once every deploymentTelemetryTTL. The platform status and the
// metrics endpoint share it.
func (s *Server) cachedDeploymentTelemetry(ctx context.Context) (store.DeploymentTelemetry, error) {
	if s.Store == nil {
		return store.DeploymentTelemetry{}, context.Canceled
	}
	return s.deploymentTelemetry.get(ctx, deploymentTelemetryTTL, s.Store.Platform().DeploymentTelemetry)
}
