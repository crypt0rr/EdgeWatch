package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/engine"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/rdap"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/webui"
)

type Server struct {
	App     *app.App
	Store   *store.Store
	Auth    *auth.Manager
	RDAP    *rdap.Client
	Log     *slog.Logger
	Version string

	mu           sync.Mutex
	subscribers  map[chan sseMessage]struct{}
	history      []sseMessage
	historyBytes int
	nextEventID  uint64
	dropped      uint64
	pendingTOTP  map[string]pendingTOTP
	testMu       sync.Mutex
	testLast     map[string]time.Time
}

type sseMessage struct {
	id      uint64
	payload []byte
}

type pendingTOTP struct {
	Secret  string
	Expires time.Time
}

func NewServer(a *app.App, s *store.Store, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	buildVersion := "dev"
	if a != nil && a.Version != "" {
		buildVersion = a.Version
	}
	rdapClient := rdap.New(s, a.Config.RDAPEnabled())
	rdapClient.OnCacheWriteError = func(err error) {
		logger.Warn("rdap cache write failed", "error", err)
	}
	v := &Server{App: a, Store: s, Auth: auth.NewManager(s), RDAP: rdapClient, Log: logger, Version: buildVersion, subscribers: map[chan sseMessage]struct{}{}, pendingTOTP: map[string]pendingTOTP{}, testLast: map[string]time.Time{}}
	if token, err := v.Auth.EnsureSetupToken(context.Background()); err != nil {
		logger.Error("admin setup token generation failed", "error", err)
	} else if token != "" {
		logger.Warn("EdgeWatch admin setup required; setup token is valid for 15 minutes", "setup_token", token)
	}
	a.SetEventHandler(func(event model.Event) {
		v.broadcast(map[string]any{"type": event.Type, "job_id": event.JobID, "job": event.Job, "scan_id": event.ScanID, "message": event.Message})
	})
	return v
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/", s.api)
	mux.HandleFunc("/assets/", s.asset)
	mux.HandleFunc("/", s.spa)
	return securityHeaders(mux)
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
	// WriteTimeout must stay disabled for the SSE endpoint; its heartbeat keeps
	// the connection alive and individual API writes are small and bounded.
	server := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	s.Log.Info("web interface listening", "address", address)
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
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

	switch {
	case path == "/auth/logout" && r.Method == http.MethodPost:
		s.logout(w, r)
	case path == "/auth/password" && r.Method == http.MethodPut:
		s.changePassword(w, r, session)
	case path == "/auth/totp/setup" && r.Method == http.MethodPost:
		s.totpSetup(w, r, session)
	case path == "/auth/totp/enable" && r.Method == http.MethodPost:
		s.totpEnable(w, r, session)
	case path == "/auth/totp" && r.Method == http.MethodDelete:
		s.totpDisable(w, r, session)
	case path == "/auth/sessions" && r.Method == http.MethodDelete:
		if err := s.Auth.Store.DeleteAllSessionsWithAudit(r.Context(), "admin.sessions_revoked", "all sessions revoked"); err != nil {
			if errors.Is(err, store.ErrAuditUnavailable) {
				s.auditFailure(err, "admin.sessions_revoked")
				writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "sessions were not revoked because the security audit could not be recorded", nil)
				return
			}
			writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusNoContent, nil)
	case path == "/status" && r.Method == http.MethodGet:
		s.adminStatus(w, r)
	case path == "/notifications/test" && r.Method == http.MethodPost:
		s.notificationTest(w, r)
	case path == "/notifications/destinations" && r.Method == http.MethodGet:
		s.listNotificationDestinations(w, r)
	case path == "/notifications/destinations" && r.Method == http.MethodPost:
		s.createNotificationDestination(w, r)
	case strings.HasPrefix(path, "/notifications/destinations/"):
		s.notificationDestinationRoute(w, r, strings.TrimPrefix(path, "/notifications/destinations/"))
	case path == "/stream" && r.Method == http.MethodGet:
		s.stream(w, r)
	case path == "/jobs" && r.Method == http.MethodGet:
		s.listJobs(w, r)
	case path == "/jobs" && r.Method == http.MethodPost:
		s.createJob(w, r)
	case path == "/jobs/schedule-suggestion" && r.Method == http.MethodGet:
		s.scheduleSuggestion(w, r)
	case path == "/scans" && r.Method == http.MethodGet:
		s.listScans(w, r)
	case path == "/hosts" && r.Method == http.MethodGet:
		s.listHosts(w, r)
	case path == "/scans/active" && r.Method == http.MethodGet:
		s.activeScans(w, r)
	case strings.HasPrefix(path, "/scans/") && strings.HasSuffix(path, "/cancel") && r.Method == http.MethodPost:
		s.cancelScan(w, r, strings.TrimSuffix(strings.TrimPrefix(path, "/scans/"), "/cancel"))
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

func isMutation(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func (s *Server) withAuth(w http.ResponseWriter, r *http.Request, fn func(http.ResponseWriter, *http.Request, store.Session)) {
	session, ok := s.Auth.Authenticate(r.Context(), r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}
	fn(w, r, session)
}

func (s *Server) setupStatus(w http.ResponseWriter, r *http.Request) {
	_, err := s.Store.GetAdmin(r.Context())
	configured := err == nil
	status := map[string]any{
		"configured":            configured,
		"username":              "admin",
		"version":               s.Version,
		"password_requirements": auth.PasswordRequirements(),
	}
	if !configured {
		if token, tokenErr := s.Store.GetSetupToken(r.Context()); tokenErr == nil {
			status["setup_available"] = !token.Used && time.Now().UTC().Before(token.ExpiresAt)
		}
	}
	writeJSON(w, http.StatusOK, status)
}

// adminStatus contains operational details used by the authenticated console.
// Keeping this separate from setupStatus prevents pre-auth callers from
// learning notification state, scheduler capacity, or legacy job names.
func (s *Server) adminStatus(w http.ResponseWriter, r *http.Request) {
	if reloadErr := s.App.Notifier.Reload(r.Context()); reloadErr != nil {
		s.Log.Warn("notification state refresh failed", "error", reloadErr)
	}
	notificationStatus := s.App.Notifier.Status()
	status := map[string]any{
		"configured":                true,
		"username":                  "admin",
		"version":                   s.Version,
		"notification_destinations": notificationStatus["active"],
		"notifications":             notificationStatus,
		"retention":                 s.App.Config.Retention.Value().String(),
		"max_concurrent_scans":      s.App.Config.Scheduler.MaxConcurrent,
		"max_probe_count":           s.App.Config.Scheduler.MaxProbeCount,
		"rdap_enabled":              s.App.Config.RDAPEnabled(),
	}
	if len(s.App.Config.Jobs) > 0 {
		legacy := make([]string, 0, len(s.App.Config.Jobs))
		for _, job := range s.App.Config.Jobs {
			legacy = append(legacy, job.Name)
		}
		status["legacy_yaml_jobs"] = legacy
	}
	s.mu.Lock()
	status["live_updates"] = map[string]any{"history_size": len(s.history), "dropped_events": s.dropped}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if err := s.Auth.SetupRequest(r.Context(), r, input.Token, input.Password); err != nil {
		if errors.Is(err, store.ErrAuditUnavailable) {
			s.auditFailure(err, "admin.setup")
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "setup could not be completed because the security audit is unavailable", nil)
			return
		}
		writeError(w, http.StatusBadRequest, "setup_failed", err.Error(), nil)
		return
	}
	s.Log.Info("administrator configured")
	writeJSON(w, http.StatusCreated, map[string]any{"configured": true})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Password string `json:"password"`
		OTP      string `json:"otp"`
		Recovery string `json:"recovery_code"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	raw, admin, err := s.Auth.Login(r.Context(), r, input.Password, input.OTP, input.Recovery)
	if err != nil {
		if errors.Is(err, store.ErrAuditUnavailable) {
			s.auditFailure(err, "admin.login")
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "login could not be completed because the security audit is unavailable", nil)
			return
		}
		writeError(w, http.StatusUnauthorized, "login_failed", err.Error(), nil)
		return
	}
	auth.SetSessionCookie(w, raw)
	session, _ := s.Store.GetSession(r.Context(), digest(raw))
	writeJSON(w, http.StatusOK, map[string]any{"username": admin.Username, "csrf_token": session.CSRFToken, "totp_required": admin.TOTPEnabled})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	err := s.Auth.Logout(r.Context(), r)
	auth.ClearSessionCookie(w)
	if err != nil {
		if errors.Is(err, store.ErrAuditUnavailable) {
			s.auditFailure(err, "admin.logout")
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "logout could not be recorded by the security audit", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) session(w http.ResponseWriter, r *http.Request, session store.Session) {
	admin, err := s.Store.GetAdmin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "admin_missing", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": admin.Username, "csrf_token": session.CSRFToken, "totp_enabled": admin.TOTPEnabled, "password_requirements": auth.PasswordRequirements()})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, session store.Session) {
	var input struct {
		Current  string `json:"current_password"`
		Password string `json:"new_password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	admin, err := s.Store.GetAdmin(r.Context())
	if err != nil || !auth.VerifyPassword(admin.PasswordHash, input.Current) {
		writeError(w, http.StatusBadRequest, "invalid_password", "current password is incorrect", nil)
		return
	}
	hash, err := auth.PasswordHash(input.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_password", err.Error(), nil)
		return
	}
	admin.PasswordHash, admin.UpdatedAt = hash, time.Now().UTC()
	if err := s.Store.SaveAdminSecurity(r.Context(), admin, nil, false, true, "admin.password_changed", "password changed"); err != nil {
		if s.writeAuditUnavailable(w, err, "admin.password_changed") {
			return
		}
		writeError(w, http.StatusInternalServerError, "save_failed", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) totpSetup(w http.ResponseWriter, r *http.Request, session store.Session) {
	var input struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	admin, err := s.Store.GetAdmin(r.Context())
	if err != nil || !auth.VerifyPassword(admin.PasswordHash, input.Password) {
		writeError(w, http.StatusBadRequest, "invalid_password", "password is incorrect", nil)
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "totp_failed", err.Error(), nil)
		return
	}
	cookie, _ := r.Cookie(auth.SessionCookie)
	key := digest(cookie.Value)
	s.mu.Lock()
	s.pendingTOTP[key] = pendingTOTP{Secret: secret, Expires: time.Now().UTC().Add(10 * time.Minute)}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "otpauth": "otpauth://totp/EdgeWatch:admin?secret=" + secret + "&issuer=EdgeWatch"})
}

func (s *Server) totpEnable(w http.ResponseWriter, r *http.Request, session store.Session) {
	var input struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	cookie, _ := r.Cookie(auth.SessionCookie)
	key := digest(cookie.Value)
	s.mu.Lock()
	pending, ok := s.pendingTOTP[key]
	delete(s.pendingTOTP, key)
	s.mu.Unlock()
	if !ok || time.Now().UTC().After(pending.Expires) || !auth.VerifyTOTP(pending.Secret, input.Code) {
		writeError(w, http.StatusBadRequest, "totp_failed", "invalid or expired TOTP setup", nil)
		return
	}
	plain, hashes, err := auth.RecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "totp_failed", err.Error(), nil)
		return
	}
	admin, err := s.Store.GetAdmin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "totp_failed", err.Error(), nil)
		return
	}
	admin.TOTPSecret, admin.TOTPEnabled, admin.UpdatedAt = pending.Secret, true, time.Now().UTC()
	if err := s.Store.SaveAdminSecurity(r.Context(), admin, hashes, true, true, "admin.totp_enabled", "TOTP enabled"); err != nil {
		if s.writeAuditUnavailable(w, err, "admin.totp_enabled") {
			return
		}
		writeError(w, http.StatusInternalServerError, "totp_failed", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": plain})
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request, session store.Session) {
	var input struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	admin, err := s.Store.GetAdmin(r.Context())
	if err != nil || !auth.VerifyPassword(admin.PasswordHash, input.Password) {
		writeError(w, http.StatusBadRequest, "invalid_password", "password is incorrect", nil)
		return
	}
	admin.TOTPEnabled, admin.TOTPSecret, admin.UpdatedAt = false, "", time.Now().UTC()
	if err := s.Store.SaveAdminSecurity(r.Context(), admin, []string{}, true, true, "admin.totp_disabled", "TOTP disabled"); err != nil {
		if s.writeAuditUnavailable(w, err, "admin.totp_disabled") {
			return
		}
		writeError(w, http.StatusInternalServerError, "totp_failed", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

type protocolPayload struct {
	Ports            string `json:"ports"`
	Mode             string `json:"mode,omitempty"`
	ServiceDetection bool   `json:"service_detection"`
}
type jobPayload struct {
	Name                string           `json:"name"`
	Schedule            string           `json:"schedule"`
	Timezone            string           `json:"timezone"`
	RunOnStart          *bool            `json:"run_on_start"`
	AssumeAlive         *bool            `json:"assume_alive"`
	Targets             []string         `json:"targets"`
	MaxExpandedHosts    int              `json:"max_expanded_hosts"`
	TCP                 *protocolPayload `json:"tcp"`
	UDP                 *protocolPayload `json:"udp"`
	Timing              string           `json:"timing"`
	Timeout             string           `json:"timeout"`
	BaselineSamples     int              `json:"baseline_samples"`
	ChangeConfirmations int              `json:"change_confirmations"`
	Enabled             *bool            `json:"enabled,omitempty"`
	Archived            bool             `json:"archived,omitempty"`
	Revision            int64            `json:"revision,omitempty"`
	ConfirmRebaseline   bool             `json:"confirm_rebaseline,omitempty"`
	AllowHighCost       bool             `json:"allow_high_cost,omitempty"`
}

type lifecyclePayload struct {
	Revision *int64 `json:"revision"`
}

func (p jobPayload) config() (config.Job, error) {
	job := config.Job{Name: strings.TrimSpace(p.Name), Schedule: strings.TrimSpace(p.Schedule), Timezone: strings.TrimSpace(p.Timezone), RunOnStart: p.RunOnStart, AssumeAlive: p.AssumeAlive, Targets: p.Targets, MaxExpandedHosts: p.MaxExpandedHosts, Timing: p.Timing, AllowHighCost: p.AllowHighCost}
	if p.Timeout != "" {
		d, err := parseDuration(p.Timeout)
		if err != nil {
			return job, fmt.Errorf("timeout: %w", err)
		}
		job.Timeout = config.Duration(d)
	}
	if p.TCP != nil {
		job.TCP = &config.Protocol{Ports: p.TCP.Ports, Mode: p.TCP.Mode, ServiceDetection: p.TCP.ServiceDetection}
	}
	if p.UDP != nil {
		job.UDP = &config.Protocol{Ports: p.UDP.Ports, Mode: p.UDP.Mode, ServiceDetection: p.UDP.ServiceDetection}
	}
	job.Baseline.Samples, job.Change.Confirmations = p.BaselineSamples, p.ChangeConfirmations
	return config.NormalizeJob(job), nil
}

func parseDuration(raw string) (time.Duration, error) {
	if strings.HasSuffix(raw, "d") {
		days, err := strconv.ParseFloat(strings.TrimSuffix(raw, "d"), 64)
		return time.Duration(days * float64(24*time.Hour)), err
	}
	return time.ParseDuration(raw)
}

func jobJSON(record store.JobRecord, state model.JobState) map[string]any {
	p := fromConfig(record.Job)
	estimate, _ := config.EstimateJobWork(record.Job)
	return map[string]any{"id": record.ID, "revision": record.Revision, "enabled": record.Enabled, "archived": record.Archived, "created_at": record.CreatedAt, "updated_at": record.UpdatedAt, "security_hash": record.Job.SecurityHash(), "job": p, "baseline": baselineJSON(state, record.Job.SecurityHash()), "scan_estimate": estimate}
}

func fromConfig(j config.Job) jobPayload {
	p := jobPayload{Name: j.Name, Schedule: j.Schedule, Timezone: j.Timezone, RunOnStart: j.RunOnStart, AssumeAlive: j.AssumeAlive, Targets: j.Targets, MaxExpandedHosts: j.MaxExpandedHosts, Timing: j.Timing, Timeout: j.Timeout.Value().String(), BaselineSamples: j.Baseline.Samples, ChangeConfirmations: j.Change.Confirmations, AllowHighCost: j.AllowHighCost}
	if j.TCP != nil {
		p.TCP = &protocolPayload{Ports: j.TCP.Ports, Mode: j.TCP.Mode, ServiceDetection: j.TCP.ServiceDetection}
	}
	if j.UDP != nil {
		p.UDP = &protocolPayload{Ports: j.UDP.Ports, Mode: j.UDP.Mode, ServiceDetection: j.UDP.ServiceDetection}
	}
	return p
}

func baselineJSON(state model.JobState, currentHash string) map[string]any {
	if state.Baseline == nil {
		return map[string]any{"status": "collecting", "samples": state.CandidateCount, "attempts": state.CandidateAttempts}
	}
	status := "complete"
	if currentHash != "" && state.BaselineConfigHash != "" && state.BaselineConfigHash != currentHash {
		status = "updating"
	}
	hostCount := 0
	if page, err := observationsForSnapshot(*state.Baseline); err == nil {
		hostCount = len(page.Items)
	}
	return map[string]any{"status": status, "scan_id": state.BaselineScanID, "config_hash": state.BaselineConfigHash, "samples": state.CandidateCount, "attempts": state.CandidateAttempts, "incidents": len(state.Incidents), "pending": len(state.Pending), "host_count": hostCount}
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	include := r.URL.Query().Get("include_archived") == "true"
	jobs, err := s.Store.ListJobs(r.Context(), include)
	if err != nil {
		writeError(w, 500, "store", err.Error(), nil)
		return
	}
	out := make([]map[string]any, 0, len(jobs))
	for _, j := range jobs {
		state, stateErr := s.Store.RuntimeState(r.Context(), j.ID)
		if stateErr != nil {
			writeError(w, 500, "store", stateErr.Error(), nil)
			return
		}
		out = append(out, jobJSON(j, state))
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": out})
}

func (s *Server) createJob(w http.ResponseWriter, r *http.Request) {
	var p jobPayload
	if !decodeJSON(w, r, &p) {
		return
	}
	job, err := p.config()
	if err != nil {
		writeValidationError(w, err)
		return
	}
	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	record, err := s.Store.CreateJobWithEnabledAndAudit(r.Context(), job, enabled, store.AuditEntry{Action: "job.created", Detail: job.Name})
	if err != nil {
		if s.writeAuditUnavailable(w, err, "job.created") {
			return
		}
		if isUnique(err) {
			writeError(w, 409, "conflict", "job name is already in use", nil)
		} else {
			writeValidationError(w, err)
		}
		return
	}
	s.App.RefreshSchedules()
	state, _ := s.Store.RuntimeState(r.Context(), record.ID)
	s.broadcast(map[string]any{"type": "job.created", "job_id": record.ID})
	writeJSON(w, http.StatusCreated, jobJSON(record, state))
}

func isUnique(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}

func (s *Server) jobRoute(w http.ResponseWriter, r *http.Request, session store.Session, rest string) {
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	id := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		s.getJob(w, r, id)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodPut {
		s.updateJob(w, r, id)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodDelete {
		if r.URL.Query().Get("permanent") == "true" {
			s.permanentDelete(w, r, id)
		} else {
			s.archiveJob(w, r, id, true)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "archive" && r.Method == http.MethodPost {
		s.archiveJob(w, r, id, true)
		return
	}
	if len(parts) == 2 && parts[1] == "restore" && r.Method == http.MethodPost {
		s.archiveJob(w, r, id, false)
		return
	}
	if len(parts) == 2 && parts[1] == "pause" && r.Method == http.MethodPost {
		s.enableJob(w, r, id, false)
		return
	}
	if len(parts) == 2 && parts[1] == "resume" && r.Method == http.MethodPost {
		s.enableJob(w, r, id, true)
		return
	}
	if len(parts) == 2 && parts[1] == "run" && r.Method == http.MethodPost {
		s.runJob(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "scans" && r.Method == http.MethodGet {
		s.jobScans(w, r, id)
		return
	}
	if len(parts) == 3 && parts[1] == "scans" && r.Method == http.MethodGet {
		s.jobScan(w, r, id, parts[2])
		return
	}
	if len(parts) == 4 && parts[1] == "scans" && parts[3] == "results" && r.Method == http.MethodGet {
		s.jobScanResults(w, r, id, parts[2])
		return
	}
	if len(parts) == 4 && parts[1] == "scans" && parts[3] == "hosts" && r.Method == http.MethodGet {
		s.jobScanHosts(w, r, id, parts[2])
		return
	}
	if len(parts) == 5 && parts[1] == "scans" && parts[3] == "hosts" && r.Method == http.MethodGet {
		s.jobScanHost(w, r, id, parts[2], parts[4])
		return
	}
	if len(parts) == 6 && parts[1] == "scans" && parts[3] == "hosts" && parts[5] == "rdap" && r.Method == http.MethodGet {
		s.jobScanHostRDAP(w, r, id, parts[2], parts[4])
		return
	}
	if len(parts) == 3 && parts[1] == "baseline" && parts[2] == "hosts" && r.Method == http.MethodGet {
		s.jobBaselineHosts(w, r, id)
		return
	}
	if len(parts) == 4 && parts[1] == "baseline" && parts[2] == "hosts" && r.Method == http.MethodGet {
		s.jobBaselineHost(w, r, id, parts[3])
		return
	}
	if len(parts) == 5 && parts[1] == "baseline" && parts[2] == "hosts" && parts[4] == "rdap" && r.Method == http.MethodGet {
		s.jobBaselineHostRDAP(w, r, id, parts[3])
		return
	}
	if len(parts) == 4 && parts[1] == "scans" && parts[3] == "changes" && r.Method == http.MethodGet {
		s.jobScanChanges(w, r, id, parts[2])
		return
	}
	if len(parts) == 2 && parts[1] == "incidents" && r.Method == http.MethodGet {
		s.jobIncidents(w, r, id)
		return
	}
	if len(parts) == 3 && parts[1] == "incidents" && parts[2] == "accept" && r.Method == http.MethodPost {
		s.acceptIncident(w, r, id)
		return
	}
	if len(parts) == 3 && parts[1] == "incidents" && parts[2] == "suppress" && r.Method == http.MethodPost {
		s.suppressIncident(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "events" && r.Method == http.MethodGet {
		s.jobEvents(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "baseline" && r.Method == http.MethodGet {
		s.jobBaseline(w, r, id)
		return
	}
	if len(parts) == 3 && parts[1] == "baseline" && parts[2] == "reset" && r.Method == http.MethodPost {
		s.resetBaseline(w, r, id)
		return
	}
	if len(parts) == 3 && parts[1] == "baseline" && parts[2] == "approve" && r.Method == http.MethodPost {
		s.approveBaseline(w, r, id)
		return
	}
	writeError(w, 404, "not_found", "job endpoint not found", nil)
}

func (s *Server) activeScans(w http.ResponseWriter, r *http.Request) {
	scans := s.App.ActiveScans()
	if scans == nil {
		scans = []model.ActiveScan{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": scans})
}

func (s *Server) cancelScan(w http.ResponseWriter, r *http.Request, id string) {
	if strings.TrimSpace(id) == "" {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	if err := s.App.CancelScan(id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusConflict, "scan_not_active", "scan is no longer active", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "cancel_failed", err.Error(), nil)
		return
	}
	// Cancellation is an operational action; keep its audit detail opaque and
	// never include scanner command lines or target payloads.
	s.auditOptional(r.Context(), "scan.cancel_requested", id)
	s.broadcast(map[string]any{"type": "scan.cancellation_requested", "scan_id": id})
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "cancelling", "scan_id": id})
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request, id string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	state, err := s.Store.RuntimeState(r.Context(), id)
	if err != nil {
		writeError(w, 500, "store", err.Error(), nil)
		return
	}
	writeJSON(w, 200, jobJSON(record, state))
}

func (s *Server) updateJob(w http.ResponseWriter, r *http.Request, id string) {
	var p jobPayload
	if !decodeJSON(w, r, &p) {
		return
	}
	job, err := p.config()
	if err != nil {
		writeValidationError(w, err)
		return
	}
	current, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	active, activeErr := s.Store.JobActive(r.Context(), id)
	if activeErr != nil {
		writeError(w, http.StatusInternalServerError, "store", activeErr.Error(), nil)
		return
	}
	scopeChanged := current.Job.SecurityHash() != job.SecurityHash()
	if active && scopeChanged {
		writeError(w, 409, "job_active", "security-relevant settings cannot change during an active scan", nil)
		return
	}
	enabled := current.Enabled
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	var destinations []string
	if scopeChanged && p.ConfirmRebaseline {
		destinations, err = s.App.Notifier.QueueDestinations(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "notification", "unable to prepare notification delivery", nil)
			return
		}
	}
	audits := []store.AuditEntry{{Action: "job.updated", Detail: id}}
	if scopeChanged {
		audits = append([]store.AuditEntry{{Action: "job.rebaseline_requested", Detail: id}}, audits...)
	}
	record, changed, events, err := s.Store.UpdateJobWithEventsWithOutboxAndAudit(r.Context(), id, p.Revision, job, enabled, current.Archived, p.ConfirmRebaseline, destinations, audits...)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, 409, "conflict", "job was modified; reload before saving", nil)
		return
	}
	if errors.Is(err, store.ErrRebaselineRequired) {
		writeError(w, 409, "rebaseline_confirmation_required", "security-relevant settings changed; confirm rebaseline to continue", map[string]any{"previous_hash": current.Job.SecurityHash(), "new_hash": job.SecurityHash(), "changes": securityScopeChanges(current.Job, job)})
		return
	}
	if errors.Is(err, store.ErrJobScanActive) {
		writeError(w, http.StatusConflict, "job_active", "security-relevant settings cannot change during an active scan", nil)
		return
	}
	if err != nil {
		if s.writeAuditUnavailable(w, err, "job.updated") {
			return
		}
		if isUnique(err) {
			writeError(w, 409, "conflict", "job name is already in use", nil)
		} else {
			writeValidationError(w, err)
		}
		return
	}
	if changed {
		for _, event := range events {
			s.broadcast(map[string]any{"type": event.Type, "job_id": id, "job": event.Job, "scan_id": event.ScanID, "message": event.Message})
		}
		s.App.WakeDelivery()
	}
	s.App.RefreshSchedules()
	state, _ := s.Store.RuntimeState(r.Context(), id)
	s.broadcast(map[string]any{"type": "job.updated", "job_id": id})
	writeJSON(w, 200, jobJSON(record, state))
}

func securityScopeChanges(old, next config.Job) []string {
	var changes []string
	if !sameStrings(old.Targets, next.Targets) {
		changes = append(changes, fmt.Sprintf("targets: %s → %s", strings.Join(old.Targets, ", "), strings.Join(next.Targets, ", ")))
	}
	if old.MaxExpandedHosts != next.MaxExpandedHosts {
		changes = append(changes, fmt.Sprintf("maximum expanded hosts: %d → %d", old.MaxExpandedHosts, next.MaxExpandedHosts))
	}
	if old.AssumesAlive() != next.AssumesAlive() {
		changes = append(changes, fmt.Sprintf("assume alive: %t → %t", old.AssumesAlive(), next.AssumesAlive()))
	}
	if (old.TCP == nil) != (next.TCP == nil) {
		changes = append(changes, fmt.Sprintf("TCP scan: %s → %s", protocolSummary(old.TCP), protocolSummary(next.TCP)))
	} else if old.TCP != nil && next.TCP != nil {
		if old.TCP.Ports != next.TCP.Ports {
			changes = append(changes, fmt.Sprintf("TCP ports: %s → %s", old.TCP.Ports, next.TCP.Ports))
		}
		if old.TCP.Mode != next.TCP.Mode {
			changes = append(changes, fmt.Sprintf("TCP mode: %s → %s", old.TCP.Mode, next.TCP.Mode))
		}
		if old.TCP.ServiceDetection != next.TCP.ServiceDetection {
			changes = append(changes, fmt.Sprintf("TCP service detection: %t → %t", old.TCP.ServiceDetection, next.TCP.ServiceDetection))
		}
	}
	if (old.UDP == nil) != (next.UDP == nil) {
		changes = append(changes, fmt.Sprintf("UDP scan: %s → %s", protocolSummary(old.UDP), protocolSummary(next.UDP)))
	} else if old.UDP != nil && next.UDP != nil {
		if old.UDP.Ports != next.UDP.Ports {
			changes = append(changes, fmt.Sprintf("UDP ports: %s → %s", old.UDP.Ports, next.UDP.Ports))
		}
		if old.UDP.ServiceDetection != next.UDP.ServiceDetection {
			changes = append(changes, fmt.Sprintf("UDP service detection: %t → %t", old.UDP.ServiceDetection, next.UDP.ServiceDetection))
		}
	}
	return changes
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	left, right := append([]string(nil), a...), append([]string(nil), b...)
	slices.Sort(left)
	slices.Sort(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func protocolSummary(p *config.Protocol) string {
	if p == nil {
		return "disabled"
	}
	return p.Ports
}

func (s *Server) archiveJob(w http.ResponseWriter, r *http.Request, id string, archive bool) {
	var payload lifecyclePayload
	if !decodeJSON(w, r, &payload) {
		return
	}
	if payload.Revision == nil {
		writeError(w, http.StatusBadRequest, "revision_required", "job revision is required", nil)
		return
	}
	action := map[bool]string{true: "job.archived", false: "job.restored"}[archive]
	if err := s.Store.SetJobArchivedWithRevisionAndAudit(r.Context(), id, archive, *payload.Revision, store.AuditEntry{Action: action, Detail: id}); err != nil {
		if s.writeAuditUnavailable(w, err, action) {
			return
		}
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "job was modified; reload before changing its lifecycle", nil)
		} else if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		} else {
			writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		}
		return
	}
	s.App.RefreshSchedules()
	s.broadcast(map[string]any{"type": action, "job_id": id})
	writeJSON(w, 204, nil)
}

func (s *Server) permanentDelete(w http.ResponseWriter, r *http.Request, id string) {
	var input struct {
		ConfirmName string `json:"confirm_name"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	if input.ConfirmName != record.Job.Name {
		writeError(w, http.StatusBadRequest, "confirmation_required", "type the job name to permanently delete it", nil)
		return
	}
	if !record.Archived {
		writeError(w, http.StatusConflict, "archive_required", "archive the job before permanently deleting it", nil)
		return
	}
	if err := s.Store.DeleteJobWithAudit(r.Context(), id, store.AuditEntry{Action: "job.deleted", Detail: id}); err != nil {
		if s.writeAuditUnavailable(w, err, "job.deleted") {
			return
		}
		if errors.Is(err, store.ErrJobScanActive) {
			writeError(w, http.StatusConflict, "job_active", err.Error(), nil)
		} else {
			writeError(w, http.StatusConflict, "delete_blocked", err.Error(), nil)
		}
		return
	}
	s.App.RefreshSchedules()
	s.broadcast(map[string]any{"type": "job.deleted", "job_id": id})
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) enableJob(w http.ResponseWriter, r *http.Request, id string, enabled bool) {
	var payload lifecyclePayload
	if !decodeJSON(w, r, &payload) {
		return
	}
	if payload.Revision == nil {
		writeError(w, http.StatusBadRequest, "revision_required", "job revision is required", nil)
		return
	}
	action := map[bool]string{true: "job.resumed", false: "job.paused"}[enabled]
	if err := s.Store.SetJobEnabledWithRevisionAndAudit(r.Context(), id, enabled, *payload.Revision, store.AuditEntry{Action: action, Detail: id}); err != nil {
		if s.writeAuditUnavailable(w, err, action) {
			return
		}
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "job was modified; reload before changing its lifecycle", nil)
		} else if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		} else {
			writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		}
		return
	}
	s.App.RefreshSchedules()
	writeJSON(w, 204, nil)
}

func (s *Server) runJob(w http.ResponseWriter, r *http.Request, id string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	if record.Archived {
		writeError(w, 409, "archived", "archived jobs cannot run", nil)
		return
	}
	if estimate, budgetErr := s.App.CheckScanWorkBudget(record.Job); budgetErr != nil {
		var workErr *app.ScanWorkBudgetError
		if errors.As(budgetErr, &workErr) {
			writeError(w, http.StatusUnprocessableEntity, "scan_work_budget_exceeded", budgetErr.Error(), map[string]any{"estimate": workErr.Estimate, "budget": workErr.Budget, "allow_high_cost": record.Job.AllowHighCost})
			return
		}
		writeError(w, http.StatusBadRequest, "scan_work_estimate_failed", budgetErr.Error(), map[string]any{"estimate": estimate})
		return
	}
	if active, activeErr := s.Store.JobActive(r.Context(), id); activeErr != nil {
		writeError(w, http.StatusInternalServerError, "store", activeErr.Error(), nil)
		return
	} else if active {
		writeError(w, http.StatusConflict, "job_active", "job already has a scan in progress", nil)
		return
	}
	if runErr := s.App.StartManagedRun(id, func(scan model.Scan, events []model.Event, err error) {
		if err != nil {
			s.Log.Error("manual scan failed", "job_id", id, "scan_id", scan.ID, "error", err)
		}
		if scan.ID != "" {
			s.broadcast(map[string]any{"type": "scan.completed", "job_id": id, "scan_id": scan.ID, "status": scan.Status, "events": len(events)})
		}
	}); runErr != nil {
		if errors.Is(runErr, app.ErrShuttingDown) {
			writeError(w, http.StatusServiceUnavailable, "shutting_down", "the application is shutting down", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "scan", runErr.Error(), nil)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted", "job_id": id})
}

func (s *Server) jobScans(w http.ResponseWriter, r *http.Request, id string) {
	if _, err := s.Store.GetJob(r.Context(), id); err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	limit := queryLimit(r)
	offset := queryOffset(r)
	page, err := s.Store.ListJobScanSummariesPage(r.Context(), id, limit, offset)
	if err != nil {
		writeError(w, 500, "store", err.Error(), nil)
		return
	}
	if page.Items == nil {
		page.Items = []model.ScanSummary{}
	}
	writeJSON(w, 200, map[string]any{"scans": page.Items, "pagination": paginationJSON(offset, limit, page.Total)})
}

func (s *Server) jobScan(w http.ResponseWriter, r *http.Request, id, scanID string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	summary, err := s.Store.GetScanSummary(r.Context(), scanID)
	if err != nil || summary.JobID != id {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	offset, limit := queryOffset(r), queryLimit(r)
	value := map[string]any{"scan": summary, "changes": []model.Change{}, "changes_pagination": paginationJSON(offset, limit, 0), "comparison_source": "none"}
	var state model.JobState
	var stateErr error
	needsCurrentBaseline := summary.Status == "success" && summary.BaselineScanID == "" && summary.BaselineConfigHash == ""
	if needsCurrentBaseline {
		state, stateErr = s.Store.RuntimeState(r.Context(), id)
	}
	if summary.Status == "success" {
		if summary.BaselineScanID != "" || summary.BaselineConfigHash != "" {
			page, pageErr := s.Store.ListScanChangesPage(r.Context(), scanID, limit, offset)
			if pageErr != nil {
				writeError(w, http.StatusInternalServerError, "store", pageErr.Error(), nil)
				return
			}
			items := page.Items
			if items == nil {
				items = []model.Change{}
			}
			value["changes"], value["changes_pagination"] = items, paginationJSON(offset, limit, page.Total)
			value["comparison_source"] = "scan_time"
			value["baseline_scan_id"] = summary.BaselineScanID
		} else if stateErr == nil && state.Baseline != nil {
			// Legacy scans from before the immutable comparison columns were
			// introduced retain the previous current-baseline behavior.
			// Only this compatibility path needs the full snapshot. Managed scans
			// always carry their immutable comparison in changes_json.
			scan, scanErr := s.Store.GetScan(r.Context(), scanID)
			if scanErr != nil {
				writeError(w, http.StatusInternalServerError, "store", scanErr.Error(), nil)
				return
			}
			changes := engine.Diff(*state.Baseline, scan.Snapshot, state.BaselineConfigHash != summary.ConfigHash)
			value["changes"], value["changes_pagination"] = pageSlice(changes, offset, limit)
			value["comparison_source"] = "current_baseline_legacy"
		}
	}
	value["current_security_hash"] = record.Job.SecurityHash()
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) jobScanResults(w http.ResponseWriter, r *http.Request, id, scanID string) {
	if _, err := s.Store.GetJob(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	summary, err := s.Store.GetScanSummary(r.Context(), scanID)
	if err != nil || summary.JobID != id {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	offset, limit := queryOffset(r), queryLimit(r)
	resultPage, err := s.Store.ListScanResultsPage(r.Context(), scanID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	results := resultPage.Items
	if results == nil {
		results = []model.Unit{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "pagination": paginationJSON(offset, limit, resultPage.Total)})
}

func (s *Server) jobScanChanges(w http.ResponseWriter, r *http.Request, id, scanID string) {
	if _, err := s.Store.GetJob(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	summary, err := s.Store.GetScanSummary(r.Context(), scanID)
	if err != nil || summary.JobID != id {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	offset, limit := queryOffset(r), queryLimit(r)
	changes := []model.Change{}
	var total int
	comparisonSource := "none"
	if summary.Status == "success" {
		if summary.BaselineScanID != "" || summary.BaselineConfigHash != "" {
			page, pageErr := s.Store.ListScanChangesPage(r.Context(), scanID, limit, offset)
			if pageErr != nil {
				writeError(w, http.StatusInternalServerError, "store", pageErr.Error(), nil)
				return
			}
			changes, total = page.Items, page.Total
			comparisonSource = "scan_time"
		} else if state, stateErr := s.Store.RuntimeState(r.Context(), id); stateErr == nil && state.Baseline != nil {
			scan, scanErr := s.Store.GetScan(r.Context(), scanID)
			if scanErr != nil {
				writeError(w, http.StatusInternalServerError, "store", scanErr.Error(), nil)
				return
			}
			changes = engine.Diff(*state.Baseline, scan.Snapshot, state.BaselineConfigHash != summary.ConfigHash)
			comparisonSource = "current_baseline_legacy"
		} else if stateErr != nil {
			writeError(w, http.StatusInternalServerError, "store", stateErr.Error(), nil)
			return
		}
	}
	items, page := changes, paginationJSON(offset, limit, total)
	if comparisonSource != "scan_time" {
		items, page = pageSlice(changes, offset, limit)
	}
	if items == nil {
		items = []model.Change{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": items, "pagination": page, "comparison_source": comparisonSource, "baseline_scan_id": summary.BaselineScanID})
}
func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	limit := queryLimit(r)
	offset := queryOffset(r)
	page, err := s.Store.ListScanSummariesPage(r.Context(), r.URL.Query().Get("job"), limit, offset)
	if err != nil {
		writeError(w, 500, "store", err.Error(), nil)
		return
	}
	if page.Items == nil {
		page.Items = []model.ScanSummary{}
	}
	writeJSON(w, 200, map[string]any{"scans": page.Items, "pagination": paginationJSON(offset, limit, page.Total)})
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request, id string) {
	scan, err := s.Store.GetScan(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scan": scan})
}

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	offset, limit := queryOffset(r), queryLimit(r)
	incidentPage, err := s.Store.ListIncidentsPage(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	items := make([]map[string]any, 0, len(incidentPage.Items))
	for _, item := range incidentPage.Items {
		items = append(items, map[string]any{"job_id": item.JobID, "job": item.Job, "incident": item.Incident})
	}
	writeJSON(w, http.StatusOK, map[string]any{"incidents": items, "pagination": paginationJSON(offset, limit, incidentPage.Total), "truncated": false})
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request, job string) {
	if jobID := r.URL.Query().Get("job_id"); jobID != "" {
		offset, limit := queryOffset(r), queryLimit(r)
		page, err := s.Store.ListJobEventsPage(r.Context(), jobID, limit, offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
			return
		}
		if page.Items == nil {
			page.Items = []model.Event{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"events": page.Items, "pagination": paginationJSON(offset, limit, page.Total)})
		return
	}
	if job != "" {
		if record, err := s.Store.GetJobByName(r.Context(), job); err == nil {
			job = record.Job.Name
		}
	}
	offset, limit := queryOffset(r), queryLimit(r)
	page, err := s.Store.ListEventsPage(r.Context(), job, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	if page.Items == nil {
		page.Items = []model.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": page.Items, "pagination": paginationJSON(offset, limit, page.Total)})
}

func (s *Server) jobEvents(w http.ResponseWriter, r *http.Request, id string) {
	if _, err := s.Store.GetJob(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	offset, limit := queryOffset(r), queryLimit(r)
	page, err := s.Store.ListJobEventsPage(r.Context(), id, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	if page.Items == nil {
		page.Items = []model.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": page.Items, "pagination": paginationJSON(offset, limit, page.Total)})
}
func (s *Server) jobIncidents(w http.ResponseWriter, r *http.Request, id string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	offset, limit := queryOffset(r), queryLimit(r)
	incidentPage, err := s.Store.ListJobIncidentsPage(r.Context(), id, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	items := incidentPage.Items
	if items == nil {
		items = []model.Incident{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": record.Job.Name, "incidents": items, "pagination": paginationJSON(offset, limit, incidentPage.Total), "truncated": false})
}

type incidentActionRequest struct {
	Key string `json:"key"`
}

func (s *Server) acceptIncident(w http.ResponseWriter, r *http.Request, id string) {
	var input incidentActionRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	key := strings.TrimSpace(input.Key)
	if key == "" {
		writeError(w, http.StatusBadRequest, "key_required", "incident key is required", map[string]string{"key": "incident key is required"})
		return
	}
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	events, err := s.Store.AcceptIncidentWithAudit(r.Context(), id, record.Job.Name, key, store.AuditEntry{Action: "incident.accepted", Detail: id + ":" + key})
	if err != nil {
		s.writeIncidentActionError(w, err, "incident.accepted")
		return
	}
	s.broadcastIncidentEvents(id, events)
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) suppressIncident(w http.ResponseWriter, r *http.Request, id string) {
	var input incidentActionRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	key := strings.TrimSpace(input.Key)
	if key == "" {
		writeError(w, http.StatusBadRequest, "key_required", "incident key is required", map[string]string{"key": "incident key is required"})
		return
	}
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	events, err := s.Store.SuppressIncidentWithAudit(r.Context(), id, record.Job.Name, key, store.AuditEntry{Action: "incident.suppressed", Detail: id + ":" + key})
	if err != nil {
		s.writeIncidentActionError(w, err, "incident.suppressed")
		return
	}
	s.broadcastIncidentEvents(id, events)
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) writeIncidentActionError(w http.ResponseWriter, err error, action string) {
	if s.writeAuditUnavailable(w, err, action) {
		return
	}
	switch {
	case errors.Is(err, store.ErrIncidentNotFound):
		writeError(w, http.StatusNotFound, "incident_not_found", "incident is no longer active", nil)
	case errors.Is(err, store.ErrJobScanActive):
		writeError(w, http.StatusConflict, "job_active", "incident actions cannot change the baseline during an active scan", nil)
	case errors.Is(err, store.ErrBaselineNotReady):
		writeError(w, http.StatusConflict, "baseline_not_ready", "the job does not have an active baseline", nil)
	case errors.Is(err, store.ErrUnsupportedIncidentChange):
		writeError(w, http.StatusBadRequest, "incident_change_invalid", "this incident cannot be applied to the baseline", nil)
	default:
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
	}
}

func (s *Server) broadcastIncidentEvents(jobID string, events []model.Event) {
	for _, event := range events {
		s.broadcast(map[string]any{"type": event.Type, "job_id": jobID, "job": event.Job, "scan_id": event.ScanID, "message": event.Message, "changes": event.Changes})
	}
}

// jobBaseline exposes the current comparison state without requiring clients
// to fetch the full job record. Baseline units are paginated because a broad
// CIDR can produce a large snapshot; the scope metadata remains intact on
// every page.
func (s *Server) jobBaseline(w http.ResponseWriter, r *http.Request, id string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	state, err := s.Store.RuntimeState(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	value := map[string]any{
		"job_id":        id,
		"job":           record.Job.Name,
		"revision":      record.Revision,
		"security_hash": record.Job.SecurityHash(),
		"baseline":      baselineJSON(state, record.Job.SecurityHash()),
	}
	if state.Baseline == nil {
		value["snapshot"] = nil
		value["pagination"] = paginationJSON(queryOffset(r), queryLimit(r), 0)
		writeJSON(w, http.StatusOK, value)
		return
	}
	offset, limit := queryOffset(r), queryLimit(r)
	units, page := pageSlice(state.Baseline.Units, offset, limit)
	snapshot := *state.Baseline
	snapshot.Units = units
	value["snapshot"], value["pagination"] = snapshot, page
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) resetBaseline(w http.ResponseWriter, r *http.Request, id string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	destinations, err := s.App.Notifier.QueueDestinations(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "notification", "unable to prepare notification delivery", nil)
		return
	}
	events, err := s.Store.ResetRuntimeWithOutboxAndAudit(r.Context(), id, record.Job.Name, destinations, store.AuditEntry{Action: "baseline.reset", Detail: id})
	if err != nil {
		if s.writeAuditUnavailable(w, err, "baseline.reset") {
			return
		}
		writeError(w, 500, "store", err.Error(), nil)
		return
	}
	s.App.WakeDelivery()
	for _, event := range events {
		s.broadcast(map[string]any{"type": event.Type, "job_id": id, "job": event.Job, "scan_id": event.ScanID, "message": event.Message})
	}
	writeJSON(w, 200, map[string]any{"events": events})
}

func (s *Server) approveBaseline(w http.ResponseWriter, r *http.Request, id string) {
	var input struct {
		ScanID string `json:"scan_id"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	scan, err := s.Store.GetScan(r.Context(), input.ScanID)
	if err != nil || scan.JobID != id || scan.ConfigHash != record.Job.SecurityHash() {
		writeError(w, 400, "invalid_scan", "scan does not belong to this job or current scope", nil)
		return
	}
	destinations, err := s.App.Notifier.QueueDestinations(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "notification", "unable to prepare notification delivery", nil)
		return
	}
	events, err := s.Store.ApproveRuntimeWithOutboxAndAudit(r.Context(), id, record.Job.Name, scan, destinations, store.AuditEntry{Action: "baseline.approved", Detail: id})
	if err != nil {
		if s.writeAuditUnavailable(w, err, "baseline.approved") {
			return
		}
		writeError(w, 400, "approve_failed", err.Error(), nil)
		return
	}
	s.App.WakeDelivery()
	for _, event := range events {
		s.broadcast(map[string]any{"type": event.Type, "job_id": id, "job": event.Job, "scan_id": event.ScanID, "message": event.Message})
	}
	writeJSON(w, 200, map[string]any{"events": events})
}

type notificationPayload struct {
	Name     string  `json:"name"`
	URL      *string `json:"url"`
	Password string  `json:"password"`
	Enabled  *bool   `json:"enabled"`
	Revision *int64  `json:"revision"`
}

func (s *Server) listNotificationDestinations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := s.App.Notifier.Reload(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "notification_failed", "notification state could not be loaded", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"destinations": s.App.Notifier.Destinations(), "status": s.App.Notifier.Status()})
}

func (s *Server) createNotificationDestination(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input notificationPayload
	if !decodeJSON(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.Password) == "" {
		writeError(w, http.StatusBadRequest, "password_required", "administrator password confirmation is required", map[string]string{"password": "password confirmation is required"})
		return
	}
	if err := s.Auth.ConfirmPassword(r.Context(), r, input.Password); err != nil {
		s.writeNotificationAuthError(w, err)
		return
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	if input.URL == nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "notification URL is required", map[string]string{"url": "notification URL is required"})
		return
	}
	view, err := s.App.Notifier.CreateManagedWithAudit(r.Context(), input.Name, *input.URL, enabled, store.AuditEntry{Action: "notifications.created", Detail: "managed notification created"})
	if err != nil {
		if s.writeAuditUnavailable(w, err, "notifications.created") {
			return
		}
		s.writeNotificationError(w, err)
		return
	}
	s.broadcast(map[string]any{"type": "notification.changed", "notification_id": view.ID})
	writeJSON(w, http.StatusCreated, view)
}

func (s *Server) notificationDestinationRoute(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "not_found", "notification destination not found", nil)
		return
	}
	id := parts[0]
	if len(parts) == 2 && parts[1] == "test" && r.Method == http.MethodPost {
		w.Header().Set("Cache-Control", "no-store")
		if !s.allowNotificationTest(r) {
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "notification tests are temporarily rate limited", nil)
			return
		}
		if err := s.App.Notifier.TestDestinationContext(r.Context(), id); err != nil {
			s.auditOptional(r.Context(), "notifications.test_failed", "managed notification test failed: "+id)
			s.writeNotificationError(w, err)
			return
		}
		if !s.requireAudit(r.Context(), w, "notifications.test", "managed notification tested: "+id) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"sent": 1})
		return
	}
	if len(parts) != 1 {
		writeError(w, http.StatusNotFound, "not_found", "notification destination endpoint not found", nil)
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Cache-Control", "no-store")
		view, err := s.App.Notifier.Destination(r.Context(), id)
		if err != nil {
			s.writeNotificationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, view)
	case http.MethodPut:
		s.updateNotificationDestination(w, r, id)
	case http.MethodDelete:
		s.deleteNotificationDestination(w, r, id)
	default:
		writeError(w, http.StatusNotFound, "not_found", "notification destination endpoint not found", nil)
	}
}

func (s *Server) updateNotificationDestination(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "no-store")
	var input notificationPayload
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Revision == nil {
		writeError(w, http.StatusBadRequest, "revision_required", "notification revision is required", nil)
		return
	}
	if strings.TrimSpace(input.Password) == "" {
		writeError(w, http.StatusBadRequest, "password_required", "administrator password confirmation is required", map[string]string{"password": "password confirmation is required"})
		return
	}
	if err := s.Auth.ConfirmPassword(r.Context(), r, input.Password); err != nil {
		s.writeNotificationAuthError(w, err)
		return
	}
	view, err := s.App.Notifier.UpdateManagedWithAudit(r.Context(), id, *input.Revision, input.Name, input.URL, input.Enabled, store.AuditEntry{Action: "notifications.updated", Detail: "managed notification updated: " + id})
	if err != nil {
		if s.writeAuditUnavailable(w, err, "notifications.updated") {
			return
		}
		s.writeNotificationError(w, err)
		return
	}
	s.broadcast(map[string]any{"type": "notification.changed", "notification_id": id})
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) deleteNotificationDestination(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "no-store")
	var input notificationPayload
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Revision == nil {
		writeError(w, http.StatusBadRequest, "revision_required", "notification revision is required", nil)
		return
	}
	if strings.TrimSpace(input.Password) == "" {
		writeError(w, http.StatusBadRequest, "password_required", "administrator password confirmation is required", map[string]string{"password": "password confirmation is required"})
		return
	}
	if err := s.Auth.ConfirmPassword(r.Context(), r, input.Password); err != nil {
		s.writeNotificationAuthError(w, err)
		return
	}
	if err := s.App.Notifier.DeleteManagedWithAudit(r.Context(), id, *input.Revision, store.AuditEntry{Action: "notifications.deleted", Detail: "managed notification deleted: " + id}); err != nil {
		if s.writeAuditUnavailable(w, err, "notifications.deleted") {
			return
		}
		s.writeNotificationError(w, err)
		return
	}
	s.broadcast(map[string]any{"type": "notification.changed", "notification_id": id})
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) writeNotificationAuthError(w http.ResponseWriter, err error) {
	if errors.Is(err, auth.ErrRateLimited) {
		w.Header().Set("Retry-After", "300")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many password confirmation attempts; try again later", nil)
		return
	}
	writeError(w, http.StatusUnauthorized, "invalid_password", "password confirmation failed", nil)
}

func (s *Server) writeNotificationError(w http.ResponseWriter, err error) {
	lower := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", "notification was modified; reload before saving", nil)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "notification destination not found", nil)
	case errors.Is(err, notify.ErrManagedNotificationLocked), errors.Is(err, notify.ErrKeyUnavailable), errors.Is(err, notify.ErrKeyInvalid), errors.Is(err, notify.ErrKeyPermissions):
		writeError(w, http.StatusServiceUnavailable, "notification_key_unavailable", "managed notification credentials are unavailable; restore the encryption key before replacing or enabling this destination", nil)
	case isUnique(err):
		writeError(w, http.StatusConflict, "conflict", "notification name is already in use", map[string]string{"name": "notification name is already in use"})
	case strings.Contains(lower, "notification url"), strings.Contains(lower, "notification name"):
		field := "url"
		if strings.Contains(lower, "name") {
			field = "name"
		}
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error(), map[string]string{field: err.Error()})
	default:
		writeError(w, http.StatusInternalServerError, "notification_failed", "notification configuration could not be saved", nil)
	}
}

func (s *Server) allowNotificationTest(r *http.Request) bool {
	key := r.RemoteAddr
	if cookie, err := r.Cookie(auth.SessionCookie); err == nil && cookie.Value != "" {
		key = digest(cookie.Value)
	}
	now := time.Now().UTC()
	s.testMu.Lock()
	defer s.testMu.Unlock()
	for identity, previous := range s.testLast {
		if now.Sub(previous) > 10*time.Minute {
			delete(s.testLast, identity)
		}
	}
	if previous, ok := s.testLast[key]; ok && now.Sub(previous) < 5*time.Second {
		return false
	}
	s.testLast[key] = now
	return true
}

func (s *Server) notificationTest(w http.ResponseWriter, r *http.Request) {
	if !s.allowNotificationTest(r) {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "notification tests are temporarily rate limited", nil)
		return
	}
	if err := s.App.Notifier.TestContext(r.Context()); err != nil {
		// Shoutrrr implementations may include destination details in an error;
		// keep those credentials out of both API responses and logs.
		s.auditOptional(r.Context(), "notifications.test_failed", "configured destination test failed")
		writeError(w, http.StatusBadGateway, "notification_failed", "one or more notification destinations failed", nil)
		return
	}
	if !s.requireAudit(r.Context(), w, "notifications.test", "configured destinations tested") {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sent": s.App.Notifier.ActiveCount()})
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, 500, "stream_unsupported", "streaming is unavailable", nil)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	lastID, _ := strconv.ParseUint(strings.TrimSpace(r.Header.Get("Last-Event-ID")), 10, 64)
	ch := make(chan sseMessage, 64)
	s.mu.Lock()
	if s.subscribers == nil {
		s.subscribers = map[chan sseMessage]struct{}{}
	}
	replay := s.replayLocked(lastID)
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.subscribers, ch); close(ch); s.mu.Unlock() }()
	_, _ = w.Write([]byte(": connected\n\n"))
	flusher.Flush()
	for _, message := range replay {
		writeSSEMessage(w, message)
	}
	if len(replay) > 0 {
		flusher.Flush()
	}
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case message, ok := <-ch:
			if !ok {
				return
			}
			writeSSEMessage(w, message)
			flusher.Flush()
		case <-heartbeat.C:
			_, _ = w.Write([]byte(": heartbeat\n\n"))
			flusher.Flush()
		}
	}
}

func (s *Server) broadcast(value map[string]any) {
	payload := boundedSSEPayload(value)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subscribers == nil {
		s.subscribers = map[chan sseMessage]struct{}{}
	}
	s.nextEventID++
	message := sseMessage{id: s.nextEventID, payload: payload}
	s.history = append(s.history, message)
	s.historyBytes += len(payload)
	const maxHistory = 256
	const maxHistoryBytes = 1 << 20
	for len(s.history) > maxHistory || s.historyBytes > maxHistoryBytes {
		s.historyBytes -= len(s.history[0].payload)
		s.history = s.history[1:]
	}
	for ch := range s.subscribers {
		select {
		case ch <- message:
		default:
			// Never silently lose a live update. Replace one queued item with a
			// refresh marker; the browser will invalidate all views and the next
			// reconnect can replay any durable events it missed by ID.
			s.dropped++
			select {
			case <-ch:
			default:
			}
			refresh := boundedSSEPayload(map[string]any{"type": "refresh_required", "after": message.id - 1})
			select {
			case ch <- sseMessage{id: message.id, payload: refresh}:
			default:
				s.dropped++
			}
		}
	}
}

const maxSSEPayloadBytes = 64 << 10

func boundedSSEPayload(value map[string]any) []byte {
	payload, err := json.Marshal(value)
	if err == nil && len(payload) <= maxSSEPayloadBytes {
		return payload
	}
	// Live updates are invalidation hints, not a second results API. A bounded
	// refresh marker keeps oversized messages from exhausting subscriber
	// buffers while the browser can fetch the durable, paginated resource.
	marker, markerErr := json.Marshal(map[string]any{"type": "refresh_required", "reason": "live_update_too_large"})
	if markerErr != nil {
		return []byte(`{"type":"refresh_required"}`)
	}
	return marker
}

func (s *Server) replayLocked(lastID uint64) []sseMessage {
	if lastID == 0 || len(s.history) == 0 {
		return nil
	}
	oldest := s.history[0].id
	var replay []sseMessage
	if lastID+1 < oldest {
		payload, _ := json.Marshal(map[string]any{"type": "refresh_required", "after": lastID})
		replay = append(replay, sseMessage{id: oldest - 1, payload: payload})
	}
	for _, message := range s.history {
		if message.id > lastID {
			replay = append(replay, message)
		}
	}
	return replay
}

func writeSSEMessage(w io.Writer, message sseMessage) {
	_, _ = fmt.Fprintf(w, "id: %d\ndata: %s\n\n", message.id, message.payload)
}

func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(webui.Files(), "dist")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	http.FileServer(http.FS(sub)).ServeHTTP(w, r)
}
func (s *Server) spa(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path != "/" {
		sub, err := fs.Sub(webui.Files(), "dist")
		if err == nil {
			if _, statErr := fs.Stat(sub, strings.TrimPrefix(r.URL.Path, "/")); statErr == nil {
				http.FileServer(http.FS(sub)).ServeHTTP(w, r)
				return
			}
		}
	}
	data, err := fs.ReadFile(webui.Files(), "dist/index.html")
	if err != nil {
		data = []byte(fallbackHTML)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

const fallbackHTML = `<!doctype html><html><head><meta charset="utf-8"><title>EdgeWatch</title></head><body><main><h1>EdgeWatch</h1><p>The web assets have not been built into this binary yet.</p></main></body></html>`

func queryLimit(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 {
		n = 50
	}
	if n > 1000 {
		n = 1000
	}
	return n
}

func queryOffset(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if n < 0 {
		return 0
	}
	// Keep offsets bounded so an accidental huge value cannot turn into an
	// expensive SQLite scan. Clients can continue walking pages from zero.
	if n > 10_000_000 {
		return 10_000_000
	}
	return n
}

func paginationJSON(offset, limit, total int) map[string]any {
	hasMore := offset+limit < total
	var next any
	if hasMore {
		next = offset + limit
	}
	return map[string]any{"limit": limit, "offset": offset, "total": total, "has_more": hasMore, "next_offset": next}
}

func pageSlice[T any](items []T, offset, limit int) ([]T, map[string]any) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	total := len(items)
	if offset >= total {
		return []T{}, paginationJSON(offset, limit, total)
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return items[offset:end], paginationJSON(offset, limit, total)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		writeError(w, 400, "invalid_json", "request body is invalid", map[string]any{"error": err.Error()})
		return false
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = errors.New("request body must contain one JSON value")
		}
		writeError(w, http.StatusBadRequest, "invalid_json", "request body is invalid", map[string]any{"error": err.Error()})
		return false
	}
	return true
}
func writeValidationError(w http.ResponseWriter, err error) {
	message := err.Error()
	details := map[string]string{}
	lower := strings.ToLower(message)
	// Keep validation responses useful to form clients without exposing an
	// implementation-specific error type. The API returns a stable field name
	// when the validator can identify one, while preserving the full message.
	fields := []string{"schedule", "timezone", "target", "tcp", "udp", "ports", "timeout", "timing", "baseline", "confirmations", "max_expanded_hosts", "name"}
	for _, field := range fields {
		if strings.Contains(lower, field) {
			details[field] = message
		}
	}
	if len(details) == 0 {
		details["job"] = message
	}
	writeError(w, http.StatusBadRequest, "validation_failed", message, details)
}

// auditFailure logs only the action and storage error; callers must not echo
// credential-bearing details when an audit insert fails. Sensitive handlers
// use this before writing their success response and fail closed.
func (s *Server) auditFailure(err error, action string) {
	s.Log.Error("security audit write failed", "action", action, "error", err)
}

func (s *Server) auditOptional(ctx context.Context, action, detail string) {
	if err := s.Store.Audit(ctx, action, detail); err != nil {
		s.auditFailure(err, action)
	}
}

func (s *Server) writeAuditUnavailable(w http.ResponseWriter, err error, action string) bool {
	if !errors.Is(err, store.ErrAuditUnavailable) {
		return false
	}
	s.auditFailure(err, action)
	writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "the action was not committed because the security audit could not be recorded", nil)
	return true
}

func (s *Server) requireAudit(ctx context.Context, w http.ResponseWriter, action, detail string) bool {
	if err := s.Store.Audit(ctx, action, detail); err != nil {
		s.auditFailure(err, action)
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "the action completed but its security audit record could not be written; verify the state before retrying", nil)
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, status int, code, message string, details any) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message, "details": details}})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if status != http.StatusNoContent && value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}
func digest(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
