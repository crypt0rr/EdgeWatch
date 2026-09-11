package web

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/rdap"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type Server struct {
	App     *app.App
	Store   *store.Store
	Auth    *auth.Manager
	RDAP    *rdap.Client
	Log     *slog.Logger
	Version string

	mu            sync.Mutex
	subscribers   map[chan sseMessage]struct{}
	subscriberKey map[chan sseMessage]string
	subscriberUse map[string]int
	history       []sseMessage
	historyBytes  int
	nextEventID   uint64
	eventIDLimit  uint64
	dropped       uint64
	shutdown      chan struct{}
	shutdownOnce  sync.Once
	sseWG         sync.WaitGroup
	sseCancels    map[chan sseMessage]context.CancelFunc
	sseAuthMu     sync.Mutex
	sseAuthCache  map[string]sseAuthCacheEntry
	sseAuthTTL    time.Duration
	pendingTOTP   map[string]pendingTOTP
	now           func() time.Time
	testMu        sync.Mutex
	testLast      map[string]time.Time
	publicMu      sync.Mutex
	publicHits    map[string][]time.Time
	publicCacheMu sync.Mutex
	publicCache   *publicDashboardCache
	publicBuild   chan struct{}
	publicGen     uint64
	telemetryMu   sync.Mutex
	telemetry     *store.DeploymentTelemetry
	telemetryAt   time.Time
	telemetryRun  bool
	telemetryDone chan struct{}
	// writeTimeout bounds ordinary HTTP responses. SSE clears this deadline
	// explicitly in stream because that endpoint is intentionally long-lived.
	// It is configurable only for deterministic server tests; production uses
	// the default below.
	writeTimeout time.Duration
	// These limits are configurable only for deterministic server tests;
	// production uses the bounded defaults below.
	sseMaxSubscribers        int
	sseMaxSubscribersPerUser int
}

type sseMessage struct {
	id      uint64
	payload []byte
}

type sseAuthCacheEntry struct {
	session store.Session
	checked time.Time
}

type pendingTOTP struct {
	Secret  string
	Expires time.Time
}

const defaultHTTPWriteTimeout = 60 * time.Second

const (
	defaultMaxSSESubscribers        = 256
	defaultMaxSSESubscribersPerUser = 4
	defaultSSEAuthCacheTTL          = 2 * time.Second
	sseEventIDBlockSize             = uint64(1 << 20)
)

// pendingTOTPMaxEntries bounds secrets held for enrolments that were started
// but never completed. The enrolment window is short, so a large ceiling keeps
// normal administration unaffected while preventing an unbounded map under
// deliberate or accidental repeated setup requests.
const pendingTOTPMaxEntries = 4096

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
	v := &Server{App: a, Store: s, Auth: auth.NewManager(s), RDAP: rdapClient, Log: logger, Version: buildVersion, now: time.Now, subscribers: map[chan sseMessage]struct{}{}, shutdown: make(chan struct{}), sseCancels: map[chan sseMessage]context.CancelFunc{}, sseAuthCache: map[string]sseAuthCacheEntry{}, sseAuthTTL: defaultSSEAuthCacheTTL, pendingTOTP: map[string]pendingTOTP{}, testLast: map[string]time.Time{}, publicHits: map[string][]time.Time{}}
	if s != nil {
		if start, end, err := s.ReserveSSEEventIDs(context.Background(), sseEventIDBlockSize); err != nil {
			logger.Warn("SSE event cursor could not be reserved", "error", err)
			// A timestamp seed keeps a degraded/read-only fixture monotonic for
			// the lifetime of this process even when the durable cursor cannot be
			// updated. Normal daemon databases use the reserved durable range.
			if id, maxErr := s.MaxEventID(context.Background()); maxErr == nil {
				v.nextEventID = id
			}
			if seed := uint64(time.Now().UnixNano()); seed > v.nextEventID {
				v.nextEventID = seed
			}
			v.eventIDLimit = ^uint64(0)
		} else {
			v.nextEventID = start - 1
			v.eventIDLimit = end
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
	}
	if s != nil {
		if token, err := v.Auth.EnsureSetupToken(context.Background()); err != nil {
			logger.Error("admin setup token generation failed", "error", err)
		} else if token != "" {
			logger.Warn("EdgeWatch admin setup required; setup token is valid for 15 minutes", "setup_token", token)
		}
	}
	if a != nil {
		a.SetEventHandler(func(event model.Event) {
			payload := map[string]any{"type": event.Type, "job_id": event.JobID, "job": event.Job, "scan_id": event.ScanID, "message": event.Message}
			if event.PreviousVersion != "" {
				payload["previous_version"] = event.PreviousVersion
			}
			if event.CurrentVersion != "" {
				payload["current_version"] = event.CurrentVersion
			}
			if event.LatestVersion != "" {
				payload["latest_version"] = event.LatestVersion
			}
			if event.ReleaseURL != "" {
				payload["release_url"] = event.ReleaseURL
			}
			v.broadcast(payload)
		})
	}
	return v
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/public/v1/", s.publicAPI)
	mux.HandleFunc("/api/v1/", s.api)
	mux.HandleFunc("/assets/", s.asset)
	mux.HandleFunc("/", s.spa)
	return s.requestLogging(securityHeaders(mux))
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
	// Ordinary handlers get a generous write deadline so a peer that stops
	// reading cannot pin a goroutine indefinitely. The SSE handler clears this
	// deadline with ResponseController before it starts its long-lived stream.
	server := &http.Server{Handler: handler, ErrorLog: slog.NewLogLogger(s.Log.Handler(), slog.LevelError), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: writeTimeout, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10}
	serveDone := make(chan struct{})
	shutdownDone := make(chan struct{})
	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			// http.Server.Shutdown does not cancel active streaming request
			// contexts. Signal and join SSE handlers first so the application
			// cannot close SQLite while a stream is still re-authenticating or
			// writing a final event.
			s.signalShutdown()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.waitForSSEShutdown(shutdownCtx)
			_ = server.Shutdown(shutdownCtx)
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

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if path == "" {
		path = "/"
	}
	if path == "/setup/status" && r.Method == http.MethodGet {
		s.setupStatus(w, r)
		return
	}
	if path == "/setup" && r.Method == http.MethodPost {
		s.setup(w, r)
		return
	}
	if path == "/auth/login" && r.Method == http.MethodPost {
		s.login(w, r)
		return
	}
	if path == "/auth/activate" && r.Method == http.MethodPost {
		s.activateUser(w, r)
		return
	}
	if path == "/auth/session" && r.Method == http.MethodGet {
		s.withAuth(w, r, s.session)
		return
	}

	session, ok := s.Auth.Authenticate(r.Context(), r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}
	if isMutation(r.Method) && !s.Auth.CheckCSRF(r, session) {
		writeError(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token", nil)
		return
	}
	if permission := requestPermission(path, r); permission == auth.PermissionDenied || (permission != "" && !auth.HasPermission(session, permission)) {
		details := map[string]string{"permission": permission}
		if permission == auth.PermissionDenied {
			// Keep the internal sentinel out of the public API. Callers only need
			// to know that the route is not authorized, not how the matrix stores
			// its fail-closed default.
			details["permission"] = "route"
		}
		writeError(w, http.StatusForbidden, "forbidden", "your account is not allowed to perform this action", details)
		return
	}

	switch {
	case path == "/auth/logout" && r.Method == http.MethodPost:
		s.logout(w, r, session)
	case path == "/auth/display-name" && r.Method == http.MethodPut:
		s.changeDisplayName(w, r, session)
	case path == "/auth/password" && r.Method == http.MethodPut:
		s.changePassword(w, r, session)
	case path == "/auth/totp/setup" && r.Method == http.MethodPost:
		s.totpSetup(w, r, session)
	case path == "/auth/totp/enable" && r.Method == http.MethodPost:
		s.totpEnable(w, r, session)
	case path == "/auth/totp" && r.Method == http.MethodDelete:
		s.totpDisable(w, r, session)
	case path == "/auth/sessions" && r.Method == http.MethodDelete:
		action := "user.sessions_revoked"
		if session.Role == store.RoleAdministrator {
			action = "admin.sessions_revoked"
		}
		if err := s.Auth.Store.DeleteUserSessionsWithAudit(r.Context(), session.UserID, actorAudit(session, action, "all sessions revoked")); err != nil {
			if errors.Is(err, store.ErrAuditUnavailable) {
				s.auditFailure(err, action)
				writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "sessions were not revoked because the security audit could not be recorded", nil)
				return
			}
			writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusNoContent, nil)
	case path == "/status" && r.Method == http.MethodGet:
		s.adminStatus(w, r, session)
	case path == "/scanner/capabilities" && r.Method == http.MethodGet:
		s.scannerCapabilities(w, r)
	case path == "/scanner-profiles" || strings.HasPrefix(path, "/scanner-profiles/"):
		s.scannerProfilesRoute(w, r, session, strings.TrimPrefix(path, "/scanner-profiles"))
	case path == "/scanner/profiles" || strings.HasPrefix(path, "/scanner/profiles/"):
		s.scannerProfilesRoute(w, r, session, strings.TrimPrefix(path, "/scanner/profiles"))
	case path == "/users" || strings.HasPrefix(path, "/users/"):
		s.usersRoute(w, r, session, strings.TrimPrefix(path, "/users"))
	case path == "/public-dashboard" && (r.Method == http.MethodGet || r.Method == http.MethodPut):
		s.publicDashboardRoute(w, r, session)
	case path == "/notifications/test" && r.Method == http.MethodPost:
		s.notificationTest(w, r, session)
	case path == "/notifications/destinations" && r.Method == http.MethodGet:
		s.listNotificationDestinations(w, r)
	case path == "/notifications/options" && r.Method == http.MethodGet:
		s.listNotificationDestinations(w, r)
	case path == "/notifications/update-routing" && r.Method == http.MethodPut:
		s.updateNotificationRouting(w, r, session)
	case path == "/notifications/destinations" && r.Method == http.MethodPost:
		s.createNotificationDestination(w, r, session)
	case strings.HasPrefix(path, "/notifications/destinations/"):
		s.notificationDestinationRoute(w, r, session, strings.TrimPrefix(path, "/notifications/destinations/"))
	case path == "/stream" && r.Method == http.MethodGet:
		s.stream(w, r, session)
	case path == "/jobs" && r.Method == http.MethodGet:
		s.listJobs(w, r)
	case path == "/jobs" && r.Method == http.MethodPost:
		s.createJob(w, r, session)
	case path == "/jobs/schedule-suggestion" && r.Method == http.MethodGet:
		s.scheduleSuggestion(w, r)
	case path == "/scans" && r.Method == http.MethodGet:
		s.listScans(w, r)
	case path == "/hosts" && r.Method == http.MethodGet:
		s.listHosts(w, r)
	case path == "/scans/active" && r.Method == http.MethodGet:
		s.activeScans(w, r)
	case strings.HasPrefix(path, "/scans/") && strings.HasSuffix(path, "/cancel") && r.Method == http.MethodPost:
		s.cancelScan(w, r, session, strings.TrimSuffix(strings.TrimPrefix(path, "/scans/"), "/cancel"))
	case strings.HasPrefix(path, "/scans/") && strings.HasSuffix(path, "/hosts") && r.Method == http.MethodGet:
		s.scanHostsRoute(w, r, strings.TrimSuffix(strings.TrimPrefix(path, "/scans/"), "/hosts"))
	case strings.HasPrefix(path, "/scans/") && strings.Contains(strings.TrimPrefix(path, "/scans/"), "/hosts/") && r.Method == http.MethodGet:
		if strings.HasSuffix(path, "/rdap") {
			value := strings.TrimPrefix(path, "/scans/")
			parts := strings.SplitN(value, "/hosts/", 2)
			s.scanHostRDAPRoute(w, r, parts[0], strings.TrimSuffix(parts[1], "/rdap"))
			break
		}
		value := strings.TrimPrefix(path, "/scans/")
		parts := strings.SplitN(value, "/hosts/", 2)
		s.scanHostRoute(w, r, parts[0], parts[1])
	case strings.HasPrefix(path, "/scans/") && r.Method == http.MethodGet:
		s.getScan(w, r, strings.TrimPrefix(path, "/scans/"))
	case path == "/incidents" && r.Method == http.MethodGet:
		s.listIncidents(w, r)
	case path == "/events" && r.Method == http.MethodGet:
		s.listEvents(w, r, r.URL.Query().Get("job"))
	case strings.HasPrefix(path, "/jobs/"):
		s.jobRoute(w, r, session, strings.TrimPrefix(path, "/jobs/"))
	default:
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found", nil)
	}
}

// requiredPermission centralizes the route authorization boundary. The
// frontend may hide controls for a role, but every API request is checked here
// so a viewer cannot turn a read-only screen into a write primitive by calling
// an endpoint directly.
