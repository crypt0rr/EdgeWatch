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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/engine"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/webui"
)

type Server struct {
	App   *app.App
	Store *store.Store
	Auth  *auth.Manager
	Log   *slog.Logger

	mu          sync.Mutex
	subscribers map[chan []byte]struct{}
	pendingTOTP map[string]pendingTOTP
}

type pendingTOTP struct {
	Secret  string
	Expires time.Time
}

func NewServer(a *app.App, s *store.Store, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	v := &Server{App: a, Store: s, Auth: auth.NewManager(s), Log: logger, subscribers: map[chan []byte]struct{}{}, pendingTOTP: map[string]pendingTOTP{}}
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
		if err := s.Auth.Store.DeleteAllSessions(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
			return
		}
		_ = s.Store.Audit(r.Context(), "admin.sessions_revoked", "all sessions revoked")
		writeJSON(w, http.StatusNoContent, nil)
	case path == "/notifications/test" && r.Method == http.MethodPost:
		s.notificationTest(w, r)
	case path == "/stream" && r.Method == http.MethodGet:
		s.stream(w, r)
	case path == "/jobs" && r.Method == http.MethodGet:
		s.listJobs(w, r)
	case path == "/jobs" && r.Method == http.MethodPost:
		s.createJob(w, r)
	case path == "/scans" && r.Method == http.MethodGet:
		s.listScans(w, r)
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
	status := map[string]any{"configured": configured, "username": "admin", "password_requirements": auth.PasswordRequirements()}
	if len(s.App.Config.Jobs) > 0 {
		legacy := make([]string, 0, len(s.App.Config.Jobs))
		for _, job := range s.App.Config.Jobs {
			legacy = append(legacy, job.Name)
		}
		status["legacy_yaml_jobs"] = legacy
	}
	if !configured {
		if token, tokenErr := s.Store.GetSetupToken(r.Context()); tokenErr == nil {
			status["setup_available"] = !token.Used && time.Now().UTC().Before(token.ExpiresAt)
		}
	}
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
		writeError(w, http.StatusUnauthorized, "login_failed", err.Error(), nil)
		return
	}
	auth.SetSessionCookie(w, raw)
	session, _ := s.Store.GetSession(r.Context(), digest(raw))
	writeJSON(w, http.StatusOK, map[string]any{"username": admin.Username, "csrf_token": session.CSRFToken, "totp_required": admin.TOTPEnabled})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.Auth.Logout(r.Context(), r)
	_ = s.Store.Audit(r.Context(), "admin.logout", "session ended")
	auth.ClearSessionCookie(w)
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
	if err := s.Store.SaveAdmin(r.Context(), admin); err != nil {
		writeError(w, http.StatusInternalServerError, "save_failed", err.Error(), nil)
		return
	}
	_ = s.Store.DeleteAllSessions(r.Context())
	_ = s.Store.Audit(r.Context(), "admin.password_changed", "password changed")
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
	if err := s.Store.SaveAdmin(r.Context(), admin); err != nil {
		writeError(w, http.StatusInternalServerError, "totp_failed", err.Error(), nil)
		return
	}
	if err := s.Store.SaveRecoveryCodes(r.Context(), hashes); err != nil {
		writeError(w, http.StatusInternalServerError, "totp_failed", err.Error(), nil)
		return
	}
	_ = s.Store.Audit(r.Context(), "admin.totp_enabled", "TOTP enabled")
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
	if err := s.Store.SaveAdmin(r.Context(), admin); err != nil {
		writeError(w, http.StatusInternalServerError, "totp_failed", err.Error(), nil)
		return
	}
	_ = s.Store.SaveRecoveryCodes(r.Context(), nil)
	_ = s.Store.DeleteAllSessions(r.Context())
	_ = s.Store.Audit(r.Context(), "admin.totp_disabled", "TOTP disabled")
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
}

func (p jobPayload) config() (config.Job, error) {
	job := config.Job{Name: strings.TrimSpace(p.Name), Schedule: strings.TrimSpace(p.Schedule), Timezone: strings.TrimSpace(p.Timezone), RunOnStart: p.RunOnStart, AssumeAlive: p.AssumeAlive, Targets: p.Targets, MaxExpandedHosts: p.MaxExpandedHosts, Timing: p.Timing}
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
	return map[string]any{"id": record.ID, "revision": record.Revision, "enabled": record.Enabled, "archived": record.Archived, "created_at": record.CreatedAt, "updated_at": record.UpdatedAt, "security_hash": record.Job.SecurityHash(), "job": p, "baseline": baselineJSON(state)}
}

func fromConfig(j config.Job) jobPayload {
	p := jobPayload{Name: j.Name, Schedule: j.Schedule, Timezone: j.Timezone, RunOnStart: j.RunOnStart, AssumeAlive: j.AssumeAlive, Targets: j.Targets, MaxExpandedHosts: j.MaxExpandedHosts, Timing: j.Timing, Timeout: j.Timeout.Value().String(), BaselineSamples: j.Baseline.Samples, ChangeConfirmations: j.Change.Confirmations}
	if j.TCP != nil {
		p.TCP = &protocolPayload{Ports: j.TCP.Ports, Mode: j.TCP.Mode, ServiceDetection: j.TCP.ServiceDetection}
	}
	if j.UDP != nil {
		p.UDP = &protocolPayload{Ports: j.UDP.Ports, Mode: j.UDP.Mode, ServiceDetection: j.UDP.ServiceDetection}
	}
	return p
}

func baselineJSON(state model.JobState) map[string]any {
	if state.Baseline == nil {
		return map[string]any{"status": "collecting", "samples": state.CandidateCount, "attempts": state.CandidateAttempts}
	}
	return map[string]any{"status": "complete", "scan_id": state.BaselineScanID, "config_hash": state.BaselineConfigHash, "incidents": len(state.Incidents), "pending": len(state.Pending)}
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
	record, err := s.Store.CreateJob(r.Context(), job)
	if err != nil {
		if isUnique(err) {
			writeError(w, 409, "conflict", "job name is already in use", nil)
		} else {
			writeValidationError(w, err)
		}
		return
	}
	if p.Enabled != nil && !*p.Enabled {
		if err := s.Store.SetJobEnabled(r.Context(), record.ID, false); err != nil {
			writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
			return
		}
		record.Enabled = false
	}
	s.App.RefreshSchedules()
	_ = s.Store.Audit(r.Context(), "job.created", record.ID)
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
	if len(parts) == 4 && parts[1] == "scans" && parts[3] == "changes" && r.Method == http.MethodGet {
		s.jobScanChanges(w, r, id, parts[2])
		return
	}
	if len(parts) == 2 && parts[1] == "incidents" && r.Method == http.MethodGet {
		s.jobIncidents(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "events" && r.Method == http.MethodGet {
		s.jobEvents(w, r, id)
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
	record, changed, events, err := s.Store.UpdateJobWithEvents(r.Context(), id, p.Revision, job, enabled, current.Archived, p.ConfirmRebaseline)
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
		if isUnique(err) {
			writeError(w, 409, "conflict", "job name is already in use", nil)
		} else {
			writeValidationError(w, err)
		}
		return
	}
	if changed {
		if err := s.App.Notifier.Queue(r.Context(), events); err != nil {
			s.Log.Warn("baseline reset notification deferred", "job_id", id, "error", err)
		}
		for _, event := range events {
			s.broadcast(map[string]any{"type": event.Type, "job_id": id, "job": event.Job, "scan_id": event.ScanID, "message": event.Message})
		}
		_ = s.Store.Audit(r.Context(), "job.rebaseline_requested", id)
	}
	s.App.RefreshSchedules()
	_ = s.Store.Audit(r.Context(), "job.updated", id)
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
	if err := s.Store.SetJobArchived(r.Context(), id, archive); err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	s.App.RefreshSchedules()
	_ = s.Store.Audit(r.Context(), map[bool]string{true: "job.archived", false: "job.restored"}[archive], id)
	s.broadcast(map[string]any{"type": map[bool]string{true: "job.archived", false: "job.restored"}[archive], "job_id": id})
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
	if err := s.Store.DeleteJob(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrJobScanActive) {
			writeError(w, http.StatusConflict, "job_active", err.Error(), nil)
		} else {
			writeError(w, http.StatusConflict, "delete_blocked", err.Error(), nil)
		}
		return
	}
	s.App.RefreshSchedules()
	_ = s.Store.Audit(r.Context(), "job.deleted", id)
	s.broadcast(map[string]any{"type": "job.deleted", "job_id": id})
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) enableJob(w http.ResponseWriter, r *http.Request, id string, enabled bool) {
	if err := s.Store.SetJobEnabled(r.Context(), id, enabled); err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	s.App.RefreshSchedules()
	_ = s.Store.Audit(r.Context(), map[bool]string{true: "job.resumed", false: "job.paused"}[enabled], id)
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
	if active, activeErr := s.Store.JobActive(r.Context(), id); activeErr != nil {
		writeError(w, http.StatusInternalServerError, "store", activeErr.Error(), nil)
		return
	} else if active {
		writeError(w, http.StatusConflict, "job_active", "job already has a scan in progress", nil)
		return
	}
	go func() {
		scan, events, runErr := s.App.RunJobRecord(context.Background(), record)
		if runErr != nil {
			s.Log.Error("manual scan failed", "job", record.Job.Name, "scan_id", scan.ID, "error", runErr)
		}
		s.broadcast(map[string]any{"type": "scan.completed", "job_id": id, "scan_id": scan.ID, "status": scan.Status, "events": len(events)})
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted", "job_id": id})
}

func (s *Server) jobScans(w http.ResponseWriter, r *http.Request, id string) {
	if _, err := s.Store.GetJob(r.Context(), id); err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	limit := queryLimit(r)
	offset := queryOffset(r)
	page, err := s.Store.ListJobScansPage(r.Context(), id, limit, offset)
	if err != nil {
		writeError(w, 500, "store", err.Error(), nil)
		return
	}
	if page.Items == nil {
		page.Items = []model.Scan{}
	}
	writeJSON(w, 200, map[string]any{"scans": page.Items, "pagination": paginationJSON(offset, limit, page.Total)})
}

func (s *Server) jobScan(w http.ResponseWriter, r *http.Request, id, scanID string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	scan, err := s.Store.GetScan(r.Context(), scanID)
	if err != nil || scan.JobID != id {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	offset, limit := queryOffset(r), queryLimit(r)
	value := map[string]any{"scan": scan, "changes": []model.Change{}, "changes_pagination": paginationJSON(offset, limit, 0)}
	state, stateErr := s.Store.RuntimeState(r.Context(), id)
	if scan.Status == "success" && stateErr == nil && state.Baseline != nil {
		changes := engine.Diff(*state.Baseline, scan.Snapshot, state.BaselineConfigHash != scan.ConfigHash)
		value["changes"], value["changes_pagination"] = pageSlice(changes, offset, limit)
	}
	value["current_security_hash"] = record.Job.SecurityHash()
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) jobScanResults(w http.ResponseWriter, r *http.Request, id, scanID string) {
	if _, err := s.Store.GetJob(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	scan, err := s.Store.GetScan(r.Context(), scanID)
	if err != nil || scan.JobID != id {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	offset, limit := queryOffset(r), queryLimit(r)
	results, page := pageSlice(scan.Snapshot.Units, offset, limit)
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "pagination": page})
}

func (s *Server) jobScanChanges(w http.ResponseWriter, r *http.Request, id, scanID string) {
	if _, err := s.Store.GetJob(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	scan, err := s.Store.GetScan(r.Context(), scanID)
	if err != nil || scan.JobID != id {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	state, err := s.Store.RuntimeState(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	changes := []model.Change{}
	if scan.Status == "success" && state.Baseline != nil {
		changes = engine.Diff(*state.Baseline, scan.Snapshot, state.BaselineConfigHash != scan.ConfigHash)
	}
	offset, limit := queryOffset(r), queryLimit(r)
	items, page := pageSlice(changes, offset, limit)
	writeJSON(w, http.StatusOK, map[string]any{"changes": items, "pagination": page})
}
func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	limit := queryLimit(r)
	offset := queryOffset(r)
	page, err := s.Store.ListScansPage(r.Context(), r.URL.Query().Get("job"), limit, offset)
	if err != nil {
		writeError(w, 500, "store", err.Error(), nil)
		return
	}
	if page.Items == nil {
		page.Items = []model.Scan{}
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
	jobs, err := s.Store.ListJobs(r.Context(), true)
	if err != nil {
		writeError(w, 500, "store", err.Error(), nil)
		return
	}
	var out []map[string]any
	for _, job := range jobs {
		state, stateErr := s.Store.RuntimeState(r.Context(), job.ID)
		if stateErr != nil {
			writeError(w, 500, "store", stateErr.Error(), nil)
			return
		}
		for _, incident := range state.Incidents {
			out = append(out, map[string]any{"job_id": job.ID, "job": job.Job.Name, "incident": incident})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		left, _ := out[i]["incident"].(model.Incident)
		right, _ := out[j]["incident"].(model.Incident)
		if out[i]["job"].(string) != out[j]["job"].(string) {
			return out[i]["job"].(string) < out[j]["job"].(string)
		}
		return left.Change.Key < right.Change.Key
	})
	offset, limit := queryOffset(r), queryLimit(r)
	items, page := pageSlice(out, offset, limit)
	writeJSON(w, 200, map[string]any{"incidents": items, "pagination": page})
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
	state, err := s.Store.RuntimeState(r.Context(), id)
	if err != nil {
		writeError(w, 500, "store", err.Error(), nil)
		return
	}
	items := make([]model.Incident, 0, len(state.Incidents))
	for _, incident := range state.Incidents {
		items = append(items, incident)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Change.Key < items[j].Change.Key })
	offset, limit := queryOffset(r), queryLimit(r)
	pageItems, page := pageSlice(items, offset, limit)
	writeJSON(w, 200, map[string]any{"job_id": id, "job": record.Job.Name, "incidents": pageItems, "pagination": page})
}

func (s *Server) resetBaseline(w http.ResponseWriter, r *http.Request, id string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	events, err := s.Store.ResetRuntime(r.Context(), id, record.Job.Name)
	if err != nil {
		writeError(w, 500, "store", err.Error(), nil)
		return
	}
	_ = s.App.Notifier.Queue(r.Context(), events)
	_ = s.Store.Audit(r.Context(), "baseline.reset", id)
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
	events, err := s.Store.ApproveRuntime(r.Context(), id, record.Job.Name, scan)
	if err != nil {
		writeError(w, 400, "approve_failed", err.Error(), nil)
		return
	}
	_ = s.App.Notifier.Queue(r.Context(), events)
	_ = s.Store.Audit(r.Context(), "baseline.approved", id)
	writeJSON(w, 200, map[string]any{"events": events})
}

func (s *Server) notificationTest(w http.ResponseWriter, r *http.Request) {
	if err := s.App.Notifier.Test(); err != nil {
		// Shoutrrr implementations may include destination details in an error;
		// keep those credentials out of both API responses and logs.
		writeError(w, http.StatusBadGateway, "notification_failed", "one or more notification destinations failed", nil)
		return
	}
	_ = s.Store.Audit(r.Context(), "notifications.test", "configured destinations tested")
	writeJSON(w, 200, map[string]any{"sent": len(s.App.Notifier.URLs)})
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
	ch := make(chan []byte, 8)
	s.mu.Lock()
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.subscribers, ch); close(ch); s.mu.Unlock() }()
	_, _ = w.Write([]byte(": connected\n\n"))
	flusher.Flush()
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case payload := <-ch:
			_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()
		case <-heartbeat.C:
			_, _ = w.Write([]byte(": heartbeat\n\n"))
			flusher.Flush()
		}
	}
}

func (s *Server) broadcast(value map[string]any) {
	payload, _ := json.Marshal(value)
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.subscribers {
		select {
		case ch <- payload:
		default:
		}
	}
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
