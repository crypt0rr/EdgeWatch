package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/updatecheck"
)

func (s *Server) withAuth(w http.ResponseWriter, r *http.Request, fn func(http.ResponseWriter, *http.Request, store.Session)) {
	session, ok := s.Auth.Authenticate(r.Context(), r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}
	fn(w, r, session)
}

func (s *Server) setupStatus(w http.ResponseWriter, r *http.Request) {
	if !s.allowAnonymousRequest(r, "setup-status") {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "setup status requests are temporarily rate limited", nil)
		return
	}
	configured, err := s.Store.HasAdministrator(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", "setup status could not be loaded", nil)
		return
	}
	status := map[string]any{"configured": configured, "username": "admin", "password_requirements": auth.PasswordRequirements()}
	if configured {
		// Keep the pre-setup endpoint useful without advertising the exact
		// installed release to unauthenticated callers.
		status["version"] = s.Version
	}
	if dashboard, dashboardErr := s.Store.GetPublicDashboard(r.Context()); dashboardErr == nil {
		status["public_dashboard_enabled"] = dashboard.Enabled
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
func (s *Server) adminStatus(w http.ResponseWriter, r *http.Request, session store.Session) {
	user, err := s.Store.GetUser(r.Context(), session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user_missing", "account could not be loaded", nil)
		return
	}
	if reloadErr := s.App.Notifier.Reload(r.Context()); reloadErr != nil {
		s.Log.Warn("notification state refresh failed", "error", reloadErr)
	}
	notificationStatus := s.App.Notifier.StatusContext(r.Context())
	status := map[string]any{
		"configured":                true,
		"username":                  user.Username,
		"display_name":              user.DisplayName,
		"role":                      user.Role,
		"permissions":               auth.PermissionsForRole(user.Role),
		"version":                   s.Version,
		"notification_destinations": notificationStatus["active"],
		"notifications":             notificationStatus,
		"retention":                 s.App.Config.Retention.Value().String(),
		"max_concurrent_scans":      s.App.Config.Scheduler.MaxConcurrent,
		"max_probe_count":           s.App.Config.Scheduler.MaxProbeCount,
		"max_naabu_probe_count":     s.App.Config.Scheduler.MaxNaabuProbeCount,
		"rdap_enabled":              s.App.Config.RDAPEnabled(),
	}
	if user.Role != store.RoleViewer && len(s.App.Config.Jobs) > 0 {
		legacy := make([]string, 0, len(s.App.Config.Jobs))
		for _, job := range s.App.Config.Jobs {
			legacy = append(legacy, job.Name)
		}
		status["legacy_yaml_jobs"] = legacy
	}
	s.mu.Lock()
	status["live_updates"] = map[string]any{"history_size": len(s.history), "dropped_events": s.dropped}
	s.mu.Unlock()
	status["updates"] = s.applicationUpdateStatus(r.Context())
	if telemetry, telemetryErr := s.cachedDeploymentTelemetry(r.Context()); telemetryErr != nil {
		s.Log.Warn("deployment telemetry refresh failed", "error", telemetryErr)
	} else {
		status["telemetry"] = telemetry
	}
	writeJSON(w, http.StatusOK, status)
}

const deploymentTelemetryTTL = 30 * time.Second

// cachedDeploymentTelemetry keeps status polling cheap while still reflecting
// normal scan and retention activity promptly. Concurrent requests share one
// refresh instead of issuing duplicate aggregate queries.
func (s *Server) cachedDeploymentTelemetry(ctx context.Context) (store.DeploymentTelemetry, error) {
	if s.Store == nil {
		return store.DeploymentTelemetry{}, errors.New("store is unavailable")
	}
	for {
		s.telemetryMu.Lock()
		if s.telemetry != nil && time.Since(s.telemetryAt) < deploymentTelemetryTTL {
			value := *s.telemetry
			s.telemetryMu.Unlock()
			return value, nil
		}
		if !s.telemetryRun {
			s.telemetryRun = true
			s.telemetryDone = make(chan struct{})
			done := s.telemetryDone
			s.telemetryMu.Unlock()

			var value store.DeploymentTelemetry
			var err error
			// Always release the single-flight gate, including when a storage
			// implementation panics. net/http recovers a handler panic, but
			// without this cleanup every later status request would wait forever.
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						err = fmt.Errorf("deployment telemetry panic: %v", recovered)
					}
					s.telemetryMu.Lock()
					if err == nil {
						s.telemetry = &value
						s.telemetryAt = time.Now()
					}
					s.telemetryRun = false
					close(done)
					s.telemetryMu.Unlock()
				}()
				value, err = s.Store.DeploymentTelemetry(ctx)
			}()
			return value, err
		}
		done := s.telemetryDone
		s.telemetryMu.Unlock()
		select {
		case <-done:
			continue
		case <-ctx.Done():
			return store.DeploymentTelemetry{}, ctx.Err()
		}
	}
}

func (s *Server) applicationUpdateStatus(ctx context.Context) map[string]any {
	enabled := true
	if s.App != nil && s.App.Config != nil {
		enabled = s.App.Config.UpdatesEnabled()
	}
	current := "dev"
	if s.Version != "" {
		current = s.Version
	}
	result := map[string]any{"enabled": enabled, "current_version": current, "status": "development_build", "stale": false, "available": false}
	if !enabled {
		result["status"] = "disabled"
		return result
	}
	currentVersion := updatecheck.NormalizeVersion(current)
	if currentVersion == "" || s.Store == nil {
		return result
	}
	state, err := s.Store.GetApplicationUpdateState(ctx)
	if err != nil {
		result["status"] = "check_failed"
		return result
	}
	if state.LatestVersion != "" {
		result["latest_version"] = state.LatestVersion
	}
	if state.ReleaseURL != "" {
		result["release_url"] = state.ReleaseURL
	}
	if state.ReleaseName != "" {
		result["release_name"] = state.ReleaseName
	}
	if state.PublishedAt != "" {
		result["published_at"] = state.PublishedAt
	}
	if !state.LastCheckedAt.IsZero() {
		result["last_checked_at"] = state.LastCheckedAt
	}
	if !state.LastSuccessfulCheckAt.IsZero() {
		result["last_successful_check_at"] = state.LastSuccessfulCheckAt
	}
	available := updatecheck.CompareVersions(state.LatestVersion, currentVersion) > 0
	result["available"] = available
	if available && result["release_url"] == nil {
		if releaseURL := updatecheck.ReleasePageURL(state.LatestVersion); releaseURL != "" {
			result["release_url"] = releaseURL
		}
	}
	switch {
	case state.CheckStatus == "failed":
		result["status"] = "check_failed"
		result["stale"] = available || !state.LastSuccessfulCheckAt.IsZero()
		if state.LastError != "" {
			result["error"] = state.LastError
		}
	case available:
		result["status"] = "update_available"
	case state.LatestVersion != "" && updatecheck.CompareVersions(currentVersion, state.LatestVersion) > 0:
		result["status"] = "ahead"
	case state.CheckStatus == "ok":
		result["status"] = "up_to_date"
	default:
		result["status"] = "check_failed"
	}
	return result
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
		if errors.Is(err, auth.ErrRateLimited) {
			w.Header().Set("Retry-After", "300")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many setup attempts; try again later", nil)
			return
		}
		if errors.Is(err, store.ErrAuditUnavailable) {
			s.auditFailure(err, "admin.setup")
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "setup could not be completed because the security audit is unavailable", nil)
			return
		}
		// Password policy errors are safe and actionable; storage/authentication
		// failures use a generic response so SQLite and encryption details never
		// reach an unauthenticated caller.
		if strings.HasPrefix(err.Error(), "password must be at least ") {
			writeError(w, http.StatusBadRequest, "setup_failed", err.Error(), nil)
		} else {
			writeError(w, http.StatusBadRequest, "setup_failed", "administrator setup could not be completed", nil)
		}
		return
	}
	s.Log.Info("administrator configured")
	writeJSON(w, http.StatusCreated, map[string]any{"configured": true})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
		OTP      string `json:"otp"`
		Recovery string `json:"recovery_code"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	username := strings.TrimSpace(input.Username)
	if username == "" {
		username = "admin"
	}
	raw, user, err := s.Auth.LoginAs(r.Context(), r, username, input.Password, input.OTP, input.Recovery)
	if err != nil {
		if errors.Is(err, auth.ErrRateLimited) {
			w.Header().Set("Retry-After", "300")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many login attempts; try again later", nil)
			return
		}
		if errors.Is(err, store.ErrAuditUnavailable) {
			action := "user.login"
			if user.Role == store.RoleAdministrator {
				action = "admin.login"
			}
			s.auditFailure(err, action)
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "login could not be completed because the security audit is unavailable", nil)
			return
		}
		writeError(w, http.StatusUnauthorized, "login_failed", "invalid credentials", nil)
		return
	}
	auth.SetSessionCookie(w, raw)
	session, sessionErr := s.Store.GetSession(r.Context(), digest(raw))
	if sessionErr != nil || strings.TrimSpace(session.CSRFToken) == "" {
		// A successful password check without a readable session would leave the
		// browser with a cookie that cannot pass CSRF validation. Clear it and
		// return a generic server error rather than issuing a partially usable
		// login response.
		auth.ClearSessionCookie(w)
		writeError(w, http.StatusInternalServerError, "session_unavailable", "login session could not be established", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": user.Username, "display_name": user.DisplayName, "role": user.Role, "permissions": auth.PermissionsForRole(user.Role), "csrf_token": session.CSRFToken, "totp_required": user.TOTPEnabled})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, session store.Session) {
	err := s.Auth.LogoutSession(r.Context(), r, session)
	auth.ClearSessionCookie(w)
	if err != nil {
		if errors.Is(err, store.ErrAuditUnavailable) {
			action := "user.logout"
			if session.Role == store.RoleAdministrator {
				action = "admin.logout"
			}
			s.auditFailure(err, action)
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "logout could not be recorded by the security audit", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "store", "session could not be ended", nil)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) session(w http.ResponseWriter, r *http.Request, session store.Session) {
	user, err := s.Store.GetUser(r.Context(), session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user_missing", "account could not be loaded", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user_id": user.ID, "username": user.Username, "display_name": user.DisplayName, "role": user.Role, "permissions": auth.PermissionsForRole(user.Role), "csrf_token": session.CSRFToken, "totp_enabled": user.TOTPEnabled, "password_requirements": auth.PasswordRequirements()})
}

const maxDisplayNameRunes = 80

func validateDisplayName(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", errors.New("display name must be valid UTF-8")
	}
	name := strings.TrimSpace(value)
	if name == "" {
		return "", errors.New("display name cannot be empty")
	}
	if utf8.RuneCountInString(name) > maxDisplayNameRunes {
		return "", fmt.Errorf("display name must be at most %d characters", maxDisplayNameRunes)
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return "", errors.New("display name must not contain control characters")
		}
	}
	return name, nil
}

func (s *Server) changeDisplayName(w http.ResponseWriter, r *http.Request, session store.Session) {
	var input struct {
		DisplayName string `json:"display_name"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	displayName, err := validateDisplayName(input.DisplayName)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_display_name", err.Error(), map[string]string{"display_name": err.Error()})
		return
	}
	user, err := s.Store.GetUser(r.Context(), session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user_missing", "account could not be loaded", nil)
		return
	}
	user.DisplayName = displayName
	user.UpdatedAt = time.Now().UTC()
	var saveErr error
	auditAction := "user.display_name_changed"
	if user.ID == store.LegacyAdminUserID {
		admin := store.Admin{Username: user.Username, DisplayName: user.DisplayName, PasswordHash: user.PasswordHash, TOTPSecret: user.TOTPSecret, TOTPSecretStored: user.TOTPSecretStored, TOTPEnabled: user.TOTPEnabled, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, Revision: user.Revision}
		auditAction = "admin.display_name_changed"
		saveErr = s.Store.SaveAdminSecurityWithAudit(r.Context(), admin, nil, false, false, store.AuditEntry{Action: auditAction, Detail: "administrator display name changed", ActorUserID: session.UserID, ActorUsername: session.Username})
	} else {
		saveErr = s.Store.UpdateUser(r.Context(), user, false, store.AuditEntry{Action: auditAction, Detail: "display name changed", ActorUserID: session.UserID, ActorUsername: session.Username})
	}
	if err := saveErr; err != nil {
		if s.writeAuditUnavailable(w, err, auditAction) {
			return
		}
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "account was modified; reload and try again", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "save_failed", "display name could not be saved", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"display_name": displayName})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, session store.Session) {
	var input struct {
		Current  string `json:"current_password"`
		Password string `json:"new_password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	user, err := s.Store.GetUser(r.Context(), session.UserID)
	if err != nil {
		s.writePasswordConfirmationError(w, err, "current password is incorrect")
		return
	}
	if err := s.Auth.ConfirmPasswordForUser(r.Context(), r, session.UserID, input.Current); err != nil {
		s.writePasswordConfirmationError(w, err, "current password is incorrect")
		return
	}
	hash, err := auth.PasswordHash(input.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_password", err.Error(), nil)
		return
	}
	user.PasswordHash, user.UpdatedAt = hash, time.Now().UTC()
	auditAction := "user.password_changed"
	var saveErr error
	if user.ID == store.LegacyAdminUserID {
		admin := store.Admin{Username: user.Username, DisplayName: user.DisplayName, PasswordHash: user.PasswordHash, TOTPSecret: user.TOTPSecret, TOTPSecretStored: user.TOTPSecretStored, TOTPEnabled: user.TOTPEnabled, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, Revision: user.Revision}
		auditAction = "admin.password_changed"
		saveErr = s.Store.SaveAdminSecurityWithAudit(r.Context(), admin, nil, false, true, store.AuditEntry{Action: auditAction, Detail: "password changed", ActorUserID: session.UserID, ActorUsername: session.Username})
	} else {
		saveErr = s.Store.UpdateUser(r.Context(), user, true, store.AuditEntry{Action: auditAction, Detail: "password changed", ActorUserID: session.UserID, ActorUsername: session.Username})
	}
	if err := saveErr; err != nil {
		if s.writeAuditUnavailable(w, err, auditAction) {
			return
		}
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "account was modified; reload and try again", nil)
			return
		}
		writeSecurityMutationError(w, err, "save_failed", "password could not be changed")
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
	user, err := s.Store.GetUser(r.Context(), session.UserID)
	if err != nil {
		s.writePasswordConfirmationError(w, err, "password is incorrect")
		return
	}
	if err := s.Auth.ConfirmPasswordForUser(r.Context(), r, session.UserID, input.Password); err != nil {
		s.writePasswordConfirmationError(w, err, "password is incorrect")
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "totp_failed", "TOTP setup could not be initialized", nil)
		return
	}
	cookie, cookieErr := r.Cookie(auth.SessionCookie)
	if cookieErr != nil || cookie.Value == "" {
		writeError(w, http.StatusBadRequest, "totp_failed", "an authenticated session cookie is required for TOTP setup", nil)
		return
	}
	key := digest(cookie.Value)
	s.storePendingTOTP(key, secret, s.currentTime())
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "otpauth": "otpauth://totp/EdgeWatch:" + url.QueryEscape(user.Username) + "?secret=" + secret + "&issuer=EdgeWatch"})
}

func (s *Server) totpEnable(w http.ResponseWriter, r *http.Request, session store.Session) {
	var input struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	cookie, cookieErr := r.Cookie(auth.SessionCookie)
	if cookieErr != nil || cookie.Value == "" {
		writeError(w, http.StatusBadRequest, "totp_failed", "an authenticated session cookie is required for TOTP setup", nil)
		return
	}
	key := digest(cookie.Value)
	now := s.currentTime()
	s.mu.Lock()
	s.prunePendingTOTPLocked(now)
	pending, ok := s.pendingTOTP[key]
	delete(s.pendingTOTP, key)
	s.mu.Unlock()
	if !ok || !now.Before(pending.Expires) || !auth.VerifyTOTP(pending.Secret, input.Code) {
		writeError(w, http.StatusBadRequest, "totp_failed", "invalid or expired TOTP setup", nil)
		return
	}
	plain, hashes, err := auth.RecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "totp_failed", "recovery codes could not be generated", nil)
		return
	}
	user, err := s.Store.GetUser(r.Context(), session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "totp_failed", "account could not be loaded for TOTP setup", nil)
		return
	}
	user.TOTPSecret, user.TOTPEnabled, user.UpdatedAt = pending.Secret, true, time.Now().UTC()
	preserveSessionHash := digest(cookie.Value)
	auditAction := "user.totp_enabled"
	var saveErr error
	if user.ID == store.LegacyAdminUserID {
		admin := store.Admin{Username: user.Username, DisplayName: user.DisplayName, PasswordHash: user.PasswordHash, TOTPSecret: user.TOTPSecret, TOTPSecretStored: user.TOTPSecretStored, TOTPEnabled: user.TOTPEnabled, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, Revision: user.Revision}
		auditAction = "admin.totp_enabled"
		saveErr = s.Store.SaveAdminSecurityWithAuditPreservingSession(r.Context(), admin, hashes, true, true, store.AuditEntry{Action: auditAction, Detail: "TOTP enabled", ActorUserID: session.UserID, ActorUsername: session.Username}, preserveSessionHash)
	} else {
		saveErr = s.Store.SaveUserSecurityPreservingSession(r.Context(), user, hashes, true, true, store.AuditEntry{Action: auditAction, Detail: "TOTP enabled", ActorUserID: session.UserID, ActorUsername: session.Username}, preserveSessionHash)
	}
	if err := saveErr; err != nil {
		if s.writeAuditUnavailable(w, err, auditAction) {
			return
		}
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "account was modified; reload and try again", nil)
			return
		}
		writeSecurityMutationError(w, err, "totp_failed", "TOTP could not be enabled")
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
	user, err := s.Store.GetUser(r.Context(), session.UserID)
	if err != nil {
		s.writePasswordConfirmationError(w, err, "password is incorrect")
		return
	}
	if err := s.Auth.ConfirmPasswordForUser(r.Context(), r, session.UserID, input.Password); err != nil {
		s.writePasswordConfirmationError(w, err, "password is incorrect")
		return
	}
	user.TOTPEnabled, user.TOTPSecret, user.UpdatedAt = false, "", time.Now().UTC()
	auditAction := "user.totp_disabled"
	var saveErr error
	if user.ID == store.LegacyAdminUserID {
		admin := store.Admin{Username: user.Username, DisplayName: user.DisplayName, PasswordHash: user.PasswordHash, TOTPSecret: user.TOTPSecret, TOTPSecretStored: user.TOTPSecretStored, TOTPEnabled: user.TOTPEnabled, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, Revision: user.Revision}
		auditAction = "admin.totp_disabled"
		saveErr = s.Store.SaveAdminSecurityWithAudit(r.Context(), admin, []string{}, true, true, store.AuditEntry{Action: auditAction, Detail: "TOTP disabled", ActorUserID: session.UserID, ActorUsername: session.Username})
	} else {
		saveErr = s.Store.SaveUserSecurity(r.Context(), user, []string{}, true, true, store.AuditEntry{Action: auditAction, Detail: "TOTP disabled", ActorUserID: session.UserID, ActorUsername: session.Username})
	}
	if err := saveErr; err != nil {
		if s.writeAuditUnavailable(w, err, auditAction) {
			return
		}
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "account was modified; reload and try again", nil)
			return
		}
		writeSecurityMutationError(w, err, "totp_failed", "TOTP could not be disabled")
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}
