package web

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/rdap"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/updatecheck"
)

type Server struct {
	App       *app.App
	Store     *store.Store
	Auth      *auth.Manager
	RDAP      *rdap.Client
	Log       *slog.Logger
	Version   string
	sourceURL string

	mu sync.Mutex
	// sseReservationMu serializes durable cursor reservations and ID allocation
	// without holding mu while SQLite is contacted. A transient startup failure
	// therefore cannot block subscriber registration or history reads.
	sseReservationMu sync.Mutex
	subscribers      map[chan sseMessage]struct{}
	subscriberKey    map[chan sseMessage]string
	subscriberUse    map[string]int
	history          []sseMessage
	historyBytes     int
	nextEventID      uint64
	eventIDLimit     uint64
	sseDurable       bool
	sseRetryAt       time.Time
	sseRetryDelay    time.Duration
	dropped          uint64
	shutdown         chan struct{}
	shutdownOnce     sync.Once
	sseWG            sync.WaitGroup
	handlerWG        sync.WaitGroup
	sseCancels       map[chan sseMessage]context.CancelFunc
	sseSessionKey    map[chan sseMessage]string
	sseUserKey       map[chan sseMessage]string
	sseIdentity      map[chan sseMessage]sseSubscriber
	sseUnitUse       map[sseSubscriber]int // open streams of each unit and the platform
	sseAuthMu        sync.Mutex
	sseAuthCache     map[string]sseAuthCacheEntry
	sseAuthTTL       time.Duration
	pendingTOTP      map[string]pendingTOTP
	now              func() time.Time
	testMu           sync.Mutex
	testLast         map[string]time.Time
	// updateRoutingMu serializes read/modify/write changes to update-alert
	// routing. The routing API exposes a per-destination toggle, so two admins
	// changing different destinations cannot overwrite one another.
	updateRoutingMu sync.Mutex
	publicMu        sync.Mutex
	// publicHits holds the anonymous rate-limit buckets, under publicMu.
	publicHits    anonymousBuckets
	publicCacheMu sync.Mutex
	// publicPageCache caches the default tenant's page, which the legacy
	// public URLs serve, and publicPages the page of any other tenant, by
	// tenant ID. A request reads and fills only the cache of its public
	// scope, so one tenant's page is never served for another's, and a save
	// invalidates only the cache of the page it saved.
	publicPageCache
	publicPages map[string]*publicPageCache
	// publicDashboardBuildFunc is used by deterministic tests to control the
	// cache-fill workload. Production requests use publicPageResponse.
	publicDashboardBuildFunc func(context.Context, store.PublicDashboard) (publicDashboardResponse, error)
	telemetryMu              sync.Mutex
	// telemetry caches each tenant's status telemetry by tenant ID.
	telemetry map[string]*tenantTelemetryCache
	// writeTimeout bounds ordinary HTTP responses. SSE clears this deadline
	// explicitly in stream because that endpoint is intentionally long-lived.
	// It is configurable only for deterministic server tests; production uses
	// the default below.
	writeTimeout time.Duration
	// sseWriteTimeout bounds each individual SSE write and flush. It is
	// configurable only for deterministic server tests; production uses the
	// default below.
	sseWriteTimeout time.Duration
	// The stream limits: web.max_live_streams, the per-account limit, and
	// web.max_live_streams_per_unit. NewServer sets the configured ones; a
	// zero limit uses the default below.
	sseMaxSubscribers        int
	sseMaxSubscribersPerUser int
	sseMaxSubscribersPerUnit int
	// fullScanSlots bounds the full-result scan responses in flight; see
	// getScan.
	fullScanSlots    chan struct{}
	fullScanSlotOnce sync.Once
}

type sseMessage struct {
	id      uint64
	payload []byte
	// audience decides which streams receive and replay the message.
	audience sseAudience
}

// publicDashboardBuild represents one shared cache fill. The result is
// published before done is closed so every waiter observes the same outcome.
// generation is the publication generation the build's dashboard was read
// under; a waiter from a newer generation must not adopt its error.
type publicDashboardBuild struct {
	done       chan struct{}
	err        error
	generation uint64
}

type publicDashboardFailure struct {
	retryAt time.Time
	err     error
}

type sseAuthCacheEntry struct {
	session store.Session
	checked time.Time
}

type pendingTOTP struct {
	Secret  string
	Expires time.Time
	// Failures counts wrong verification codes; see pendingTOTPMaxAttempts.
	Failures int
	// Step is the time step of the code that confirmed the enrolment. It is
	// set only on the enrolment that verifyPendingTOTP returns.
	Step int64
}

const defaultHTTPWriteTimeout = 60 * time.Second
const defaultSSEWriteTimeout = 30 * time.Second

const (
	defaultMaxSSESubscribers        = config.DefaultMaxLiveStreams
	defaultMaxSSESubscribersPerUser = 4
	defaultMaxSSESubscribersPerUnit = config.DefaultMaxLiveStreamsPerUnit
	defaultSSEAuthCacheTTL          = 2 * time.Second
	sseEventIDBlockSize             = uint64(1 << 20)
	defaultSSEReservationRetry      = time.Second
	maxSSEReservationRetry          = time.Minute
)

// pendingTOTPMaxEntries bounds secrets held for enrolments that were started
// but never completed. The enrolment window is short, so a large ceiling keeps
// normal administration unaffected while preventing an unbounded map under
// deliberate or accidental repeated setup requests.
const pendingTOTPMaxEntries = 4096

// pendingTOTPMaxAttempts bounds the verification codes that may be tried
// against one pending enrolment secret. /auth/totp/enable has no separate
// rate limiter, so this budget is what limits guessing; a mistyped code keeps
// the enrolment usable until the budget or its ten-minute expiry runs out.
const pendingTOTPMaxAttempts = 5

func NewServer(a *app.App, s *store.Store, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	buildVersion := "dev"
	if a != nil && a.Version != "" {
		buildVersion = a.Version
	}
	rdapEnabled := true
	if a != nil && a.Config != nil {
		rdapEnabled = a.Config.RDAPEnabled()
	}
	rdapClient := rdap.New(s, rdapEnabled)
	rdapClient.OnCacheWriteError = func(err error) {
		logger.Warn("rdap cache write failed", "error", err)
	}
	if variables := rdap.IgnoredProxyVariables(rdapEnabled); len(variables) > 0 {
		logger.Warn("RDAP lookups ignore the proxy environment and need direct HTTPS egress to the registries; set enrichment.rdap.enabled: false where only a proxy reaches the internet", "variables", variables)
	}
	sourceURL := updatecheck.BuildSourceTreeURL(buildVersion)
	if sourceURL == "" {
		sourceURL = "https://github.com/crypt0rr/EdgeWatch"
	}
	if a != nil && a.Config != nil && a.Config.Web.SourceURL != "" {
		sourceURL = a.Config.Web.SourceURL
	}
	var maxStreams, maxUnitStreams int
	if a != nil && a.Config != nil {
		maxStreams, maxUnitStreams = a.Config.Web.LiveStreamLimits()
	}
	v := &Server{App: a, Store: s, Auth: auth.NewManager(s), RDAP: rdapClient, Log: logger, Version: buildVersion, sourceURL: sourceURL, now: time.Now, subscribers: map[chan sseMessage]struct{}{}, shutdown: make(chan struct{}), sseCancels: map[chan sseMessage]context.CancelFunc{}, sseSessionKey: map[chan sseMessage]string{}, sseUserKey: map[chan sseMessage]string{}, sseAuthCache: map[string]sseAuthCacheEntry{}, sseAuthTTL: defaultSSEAuthCacheTTL, pendingTOTP: map[string]pendingTOTP{}, testLast: map[string]time.Time{}, sseMaxSubscribers: maxStreams, sseMaxSubscribersPerUnit: maxUnitStreams}
	if s != nil {
		if start, end, err := s.SSECursor().Reserve(context.Background(), sseEventIDBlockSize); err != nil {
			logger.Warn("SSE event cursor could not be reserved", "error", err)
			// A timestamp seed keeps a degraded/read-only fixture monotonic for
			// the lifetime of this process. The recoverable cursor state below
			// retries the durable reservation on a bounded backoff; a successful
			// retry advances past every fallback ID before switching modes.
			v.seedSSEFallbackCursor(context.Background())
			v.sseDurable = false
			v.sseRetryDelay = defaultSSEReservationRetry
			v.sseRetryAt = v.streamNow().Add(v.sseRetryDelay)
		} else {
			v.nextEventID = start - 1
			v.eventIDLimit = end
			v.sseDurable = true
		}
	}
	if a != nil && a.Config != nil {
		if s != nil {
			if err := s.SetTargetExclusions(a.Config.Scanner.TargetExclusions); err != nil {
				logger.Error("scanner target exclusion configuration rejected", "error", err)
			}
		}
		if err := v.Auth.SetTrustedProxies(a.Config.Web.TrustedProxies); err != nil {
			logger.Error("trusted proxy configuration rejected", "error", err)
		}
		if err := v.Auth.SetForwardedHeader(a.Config.Web.ForwardedHeader); err != nil {
			logger.Error("trusted proxy forwarding header configuration rejected", "error", err)
		}
		if err := v.Auth.SetIPv6RateLimitPrefix(a.Config.Web.RateLimitIPv6Prefix()); err != nil {
			logger.Error("IPv6 rate-limit prefix configuration rejected", "error", err)
		}
		if len(a.Config.Web.AllowedHosts) > 0 && (len(a.Config.Web.TrustedProxies) == 0 || strings.EqualFold(strings.TrimSpace(a.Config.Web.ForwardedHeader), "none")) {
			logger.Warn("approved proxy hosts have no trusted client-IP forwarding; remote clients share the loopback login cooldown and audit identity", "hint", "configure web.trusted_proxies and the sanitized web.forwarded_header")
		}
	}
	if s != nil {
		if token, err := v.Auth.EnsureSetupToken(context.Background()); err != nil {
			logger.Error("admin setup token generation failed", "error", err)
		} else if token != "" {
			logger.Warn("EdgeWatch admin setup required; setup token is valid for 15 minutes", "setup_token", token)
		}
	}
	if a != nil {
		a.SetEventHandler(v.publishAppEvent)
		// A business unit that is disabled or deleted loses its live
		// updates and its cached public page at once, whichever caller
		// paused it.
		a.SetUnitPausedHandler(v.unitPaused)
	}
	return v
}

// unitPaused is the application's unit-paused hook, which runs once
// DisableUnit or RequestUnitDeletion has committed the pause of a business
// unit. It ends the unit's live-update streams and drops the unit's public
// page from the cache, so the page answers as a page that is not enabled
// from the next request on, on the legacy URL as on the slug URL.
func (s *Server) unitPaused(tenantID string) {
	s.revokeSSETenant(tenantID)
	s.invalidateTenantPublicPage(tenantID)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/public/v1/", s.publicAPI)
	mux.HandleFunc("/api/v1/", s.api)
	mux.HandleFunc("/assets/", s.asset)
	mux.HandleFunc("/source", s.source)
	mux.HandleFunc("/", s.spa)
	// Apply Host validation at the HTTP boundary, before API routing and
	// authentication. Direct handler calls used by package tests intentionally
	// bypass this network-boundary middleware.
	hostGuard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.noteUntrustedProxy(r)
		if strings.HasPrefix(r.URL.Path, "/api/v1") && !s.validateRequestHost(r) {
			writeError(w, http.StatusMisdirectedRequest, "host", "request host is not allowed", nil)
			return
		}
		mux.ServeHTTP(w, r)
	})
	return s.requestLogging(securityHeaders(hostGuard))
}

// source offers a public, stable link to the running build's corresponding
// source without adding release metadata to the setup or public-status APIs.
func (s *Server) source(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, s.sourceURL, http.StatusFound)
}

// noteUntrustedProxy logs a warning, at most once an hour, when requests
// come through a proxy that is not in web.trusted_proxies but forwards them
// for other clients, as auth.UntrustedProxy describes it: the proxy on the
// host, which connects from a loopback address, or one behind the trusted
// proxies. EdgeWatch then sees every client behind the proxy as the proxy's
// address, which the clients share for the sign-in limits, the limits of
// the setups and activation, and the audit. The console's status shows the
// proxy to administrators, see adminStatus and platformStatus.
func (s *Server) noteUntrustedProxy(r *http.Request) {
	if s == nil || s.Auth == nil || s.Log == nil {
		return
	}
	if proxy, logNow := s.Auth.NoteForwarding(r); logNow {
		s.Log.Warn("requests from a proxy that is not in web.trusted_proxies carry forwarding headers; every client behind it shares the proxy's address for sign-in limits, setup and activation limits, and the audit", "peer", proxy.Peer, "header", proxy.Header, "hint", "if the address is a proxy that you run, add it to web.trusted_proxies and set web.forwarded_header to the header that the proxy sanitizes")
	}
}

func (s *Server) ListenAndServe(ctx context.Context, address string) error {
	if address == "" {
		address = "127.0.0.1:8080"
	}
	if err := validateListenAddress(address); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return s.serveListener(ctx, listener, address, s.Handler())
}

// serveListener runs the HTTP server and does not return until a graceful
// shutdown has completed. Keeping the shutdown join in this call prevents the
// database owner from closing while handlers or SSE subscribers are still
// draining.
func (s *Server) serveListener(ctx context.Context, listener net.Listener, address string, handler http.Handler) error {
	writeTimeout := s.writeTimeout
	if writeTimeout <= 0 {
		writeTimeout = defaultHTTPWriteTimeout
	}
	// Keep a startup cursor outage recoverable even when no browser is
	// connected. The retry loop is scoped to this listener and is cancelled and
	// joined before the server (and its database owner) is allowed to stop.
	retryCtx, retryCancel := context.WithCancel(ctx)
	var retryWG sync.WaitGroup
	retryWG.Add(1)
	go func() {
		defer retryWG.Done()
		s.runSSEReservationRetry(retryCtx)
	}()
	// Ordinary handlers get a generous write deadline so a peer that stops
	// reading cannot pin a goroutine indefinitely. The SSE handler clears this
	// deadline with ResponseController before it starts its long-lived stream.
	// Track every request, including handlers supplied by deterministic tests or
	// future embedders that do not use the normal request-logging middleware.
	// Shutdown joins this counter before the caller is allowed to close SQLite.
	server := &http.Server{Handler: s.trackHandlers(handler), ErrorLog: slog.NewLogLogger(s.Log.Handler(), slog.LevelError), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: writeTimeout, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10}
	serveDone := make(chan struct{})
	shutdownDone := make(chan struct{})
	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			retryCancel()
			retryWG.Wait()
			// http.Server.Shutdown does not cancel active streaming request
			// contexts. Signal and join SSE handlers first so the application
			// cannot close SQLite while a stream is still re-authenticating or
			// writing a final event.
			s.signalShutdown()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.waitForSSEShutdown(shutdownCtx)
			_ = server.Shutdown(shutdownCtx)
			s.waitForHandlers(shutdownCtx)
			// A refused sign-in writes its rate-limit record in the
			// background; let it finish before the database closes.
			if s.Auth != nil {
				_ = s.Auth.WaitForRateLimitRecords(shutdownCtx)
			}
			close(shutdownDone)
		})
	}
	go func() {
		select {
		case <-ctx.Done():
			shutdown()
		case <-serveDone:
		}
	}()
	s.Log.Info("web interface listening", "address", address)
	err := server.Serve(listener)
	close(serveDone)
	if errors.Is(err, http.ErrServerClosed) {
		shutdown()
		<-shutdownDone
		return nil
	}
	// A listener error is terminal too. Stop the server and join the watcher so
	// it cannot outlive this component when the daemon supervisor closes state.
	shutdown()
	<-shutdownDone
	return err
}

func (s *Server) trackHandlers(next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handlerWG.Add(1)
		defer s.handlerWG.Done()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) waitForHandlers(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		s.handlerWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		if s.Log != nil {
			s.Log.Warn("HTTP handlers did not drain before shutdown deadline")
		}
	}
}

func validateListenAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return errors.New("web listener must be a host:port address")
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return errors.New("web listener must be a loopback address")
	}
	if value, err := strconv.Atoi(port); err != nil || value < 1 || value > 65535 {
		return errors.New("web listener port must be between 1 and 65535")
	}
	return nil
}

// validateBrowserOrigin protects the unauthenticated state-changing entry
// points (setup, login, and activation) when the loopback service is exposed
// through a tunnel or reverse proxy. Browsers omit Origin for ordinary CLI
// clients, so absence remains allowed; a supplied origin must be an exact
// same-origin HTTPS/HTTP request for the Host the server received.
func validateBrowserOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	if strings.EqualFold(origin, "null") {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host := strings.TrimSpace(r.Host)
	if host == "" && r.URL != nil {
		host = strings.TrimSpace(r.URL.Host)
	}
	return host != "" && strings.EqualFold(parsed.Host, host)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Keep both the console shell and the unauthenticated public HTML out
		// of search indexes. The API handler also sets this header explicitly,
		// but the global middleware is what covers the document crawlers fetch.
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// api serves the console API from consoleRoutes. A route with a handler
// passes the gate in serveRoute; the routes that are not yet in the table
// pass legacyAPI's gate, with the capability that requestPermission
// assigns, and its dispatch.
func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	if route := consoleRoutes.match(r); route != nil && (route.Handle != nil || route.NoHandler) {
		s.serveRoute(w, r, route)
		return
	}
	s.legacyAPI(w, r)
}

func (s *Server) legacyAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if path == "" {
		path = "/"
	}
	session, ok := s.Auth.AuthenticateReadOnly(r.Context(), r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}
	if isMutation(r.Method) && !s.Auth.CheckCSRF(r, session) {
		writeError(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token", nil)
		return
	}
	permission := requestPermission(path, r)
	if permission == "" || permission == auth.PermissionDenied || !auth.HasPermission(session, permission) {
		details := map[string]string{"permission": permission}
		if permission == auth.PermissionDenied || permission == "" {
			details["permission"] = "route"
		}
		writeError(w, http.StatusForbidden, "forbidden", "your account is not allowed to perform this action", details)
		return
	}
	if session.Role != store.RolePlatformAdmin || !isPlatformPermission(permission) {
		if _, ok := s.requestTenant(w, r, session); !ok {
			return
		}
	}
	if isMutation(r.Method) {
		if err := s.Auth.RecordActivity(r.Context(), session); err != nil {
			s.Log.Debug("session activity timestamp could not be refreshed", "error", err)
		}
	}

	switch {
	case strings.HasPrefix(path, "/platform/"):
		s.platformRoute(w, r, session, strings.TrimPrefix(path, "/platform/"))
	default:
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found", nil)
	}
}

// validateRequestHost accepts only loopback/localhost host names, the
// configured listener host, or an explicitly configured reverse-proxy name.
// The public dashboard intentionally does not use this guard: it is an
// unauthenticated publication endpoint and may be served under a public host.
func (s *Server) validateRequestHost(r *http.Request) bool {
	if s == nil || s.App == nil || s.App.Config == nil {
		// Unit callers can invoke the API with a lightweight Server fixture. A
		// real daemon always has a validated deployment configuration.
		return true
	}
	host := requestHostName(r.Host)
	if host == "" && r.URL != nil {
		host = requestHostName(r.URL.Host)
	}
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	if configured := requestHostName(s.App.Config.Web.Listen); configured != "" && strings.EqualFold(host, configured) {
		return true
	}
	for _, allowed := range s.App.Config.Web.AllowedHosts {
		if strings.EqualFold(host, requestHostName(allowed)) {
			return true
		}
	}
	return false
}

// sessionCookieSecure keeps direct loopback administration usable over the
// documented HTTP listener while protecting cookies for every externally named
// host. The host guard runs before API handlers and only allows configured
// non-loopback names, so a non-loopback request represents a deliberately
// configured proxy or tunnel endpoint that is expected to use HTTPS.
//
// The standalone helper is retained for focused tests and callers that do not
// have a configured authentication manager. Network-bound handlers use the
// Server method below so a trusted TLS-terminating proxy can describe the
// browser's HTTPS scheme even when it forwards a loopback Host header.
func sessionCookieSecure(r *http.Request) bool {
	return sessionCookieSecureWithForwardedTLS(r, false)
}

func (s *Server) sessionCookieSecure(r *http.Request) bool {
	trustedHTTPS := s != nil && s.Auth != nil && s.Auth.IsTrustedProxy(r) && forwardedRequestIsHTTPS(r)
	return sessionCookieSecureWithForwardedTLS(r, trustedHTTPS)
}

func sessionCookieSecureWithForwardedTLS(r *http.Request, trustedForwardedTLS bool) bool {
	if r == nil {
		return true
	}
	if trustedForwardedTLS || r.TLS != nil || (r.URL != nil && strings.EqualFold(strings.TrimSpace(r.URL.Scheme), "https")) {
		return true
	}
	host := strings.TrimSpace(r.Host)
	if host == "" && r.URL != nil {
		host = strings.TrimSpace(r.URL.Host)
	}
	host = requestHostName(host)
	if host == "" {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return false
	}
	return true
}

// forwardedRequestIsHTTPS recognizes the two common proxy protocol headers.
// The caller must first prove that the direct peer is trusted; parsing these
// headers alone would let a client manufacture a Secure cookie decision.
func forwardedRequestIsHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}
	for _, value := range r.Header.Values("X-Forwarded-Proto") {
		for _, protocol := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(protocol), "https") {
				return true
			}
		}
	}
	for _, value := range r.Header.Values("Forwarded") {
		for _, element := range strings.Split(value, ",") {
			for _, parameter := range strings.Split(element, ";") {
				key, raw, ok := strings.Cut(strings.TrimSpace(parameter), "=")
				if !ok || !strings.EqualFold(key, "proto") {
					continue
				}
				if strings.EqualFold(strings.Trim(strings.TrimSpace(raw), `"`), "https") {
					return true
				}
			}
		}
	}
	return false
}

// requestHostName strips an optional port while preserving bracketed IPv6
// literals. Host values are normalized for case-insensitive DNS comparison.
func requestHostName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	}
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		raw = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	}
	return strings.TrimSuffix(strings.ToLower(raw), ".")
}

// requiredPermission centralizes the route authorization boundary. The
// frontend may hide controls for a role, but every API request is checked here
// so a viewer cannot turn a read-only screen into a write primitive by calling
// an endpoint directly.
