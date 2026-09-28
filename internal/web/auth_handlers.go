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

// accountStore changes the signed-in account itself. A tenant's account is
// changed through its tenant's store, and a platform administrator's, which
// has no tenant, through the platform's store bound to that one account.
type accountStore interface {
	GetUser(ctx context.Context, id string) (store.User, error)
	UpdateUser(ctx context.Context, u store.User, revokeSessions bool, audit store.AuditEntry) error
	SaveUserSecurity(ctx context.Context, u store.User, recoveryCodes []string, replaceRecoveryCodes, revokeSessions bool, audit store.AuditEntry) error
	SaveUserSecurityPreservingSession(ctx context.Context, u store.User, recoveryCodes []string, replaceRecoveryCodes, revokeSessions bool, audit store.AuditEntry, preserveSessionHash string) error
	DeleteUserSessionsWithAudit(ctx context.Context, userID string, audit store.AuditEntry) error
}

func (s *Server) withAuth(w http.ResponseWriter, r *http.Request, fn func(http.ResponseWriter, *http.Request, store.Session)) {
	session, ok := s.Auth.AuthenticateReadOnly(r.Context(), r)
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
	configured, err := s.Store.Platform().HasAdministrator(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", "setup status could not be loaded", nil)
		return
	}
	status := map[string]any{"configured": configured, "username": "admin", "password_requirements": auth.PasswordRequirements()}
	// Sign-in serves the legacy /public page, the default tenant's, so the
	// flag reads it through that public scope. The scope finds only a page
	// that anonymous visitors may see; a page that is not published is
	// ErrNotFound, which is the false the flag has always reported.
	if dashboard, dashboardErr := s.Store.Public(store.DefaultPublicScope()).GetPublicDashboard(r.Context()); dashboardErr == nil {
		status["public_dashboard_enabled"] = dashboard.Enabled
	} else if errors.Is(dashboardErr, store.ErrNotFound) {
		status["public_dashboard_enabled"] = false
	}
	if !configured {
		if token, tokenErr := s.Store.Platform().GetSetupToken(r.Context()); tokenErr == nil {
			status["setup_available"] = !token.Used && time.Now().UTC().Before(token.ExpiresAt)
		}
	}
	// Once the first administrator exists, the sign-in page offers the
	// platform setup while the host's platform setup token is valid, as it
	// offers the first setup while that token is.
	if configured {
		token, tokenErr := s.Store.Platform().GetPlatformSetupToken(r.Context())
		status["platform_setup_available"] = tokenErr == nil && !token.Used && time.Now().UTC().Before(token.ExpiresAt)
	}
	writeJSON(w, http.StatusOK, status)
}

// adminStatus contains operational details used by the authenticated console.
// Keeping this separate from setupStatus prevents pre-auth callers from
// learning notification state, scheduler capacity, or legacy job names.
func (s *Server) adminStatus(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore) {
	user, err := ts.GetUser(r.Context(), session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user_missing", "account could not be loaded", nil)
		return
	}
	if !auth.HasPermission(session, auth.PermissionOverviewRead) {
		// Viewers are authenticated users too, but must not inherit operational
		// overview data just to show the product version and release indicator.
		viewerStatus := map[string]any{
			"version": s.Version,
			"updates": s.applicationUpdateStatus(r.Context()),
		}
		s.addVersionReleaseURL(viewerStatus)
		writeJSON(w, http.StatusOK, viewerStatus)
		return
	}
	if reloadErr := s.App.Notifier.Reload(r.Context()); reloadErr != nil {
		s.Log.Warn("notification state refresh failed", "error", reloadErr)
	}
	status := map[string]any{
		"configured":   true,
		"username":     user.Username,
		"display_name": user.DisplayName,
		"role":         user.Role,
		"permissions":  auth.PermissionsForRole(user.Role),
		"version":      s.Version,
		"retention":    s.App.Config.Retention.Value().String(),
		"rdap_enabled": s.App.Config.RDAPEnabled(),
	}
	// The scan capacity is the tenant's own, as the scheduler enforces it
	// for its runs: the deployment's slots and probe budgets, lowered to the
	// tenant's caps. A tenant without caps reports the deployment's. Like the
	// telemetry below, it is left out when it cannot be read.
	if limits, limitsErr := s.App.TenantCapacityLimits(r.Context(), ts); limitsErr != nil {
		s.Log.Warn("scan capacity could not be read", "error", limitsErr)
	} else {
		status["max_concurrent_scans"] = limits.MaxConcurrentScans
		status["max_probe_count"] = limits.MaxProbeCount
		status["max_naabu_probe_count"] = limits.MaxNaabuProbeCount
	}
	// The destination counts and delivery totals are the tenant's own. Like
	// the telemetry below, they are left out when they cannot be read.
	if notificationStatus, notificationErr := s.App.Notifier.Tenant(ts).Status(r.Context()); notificationErr != nil {
		s.Log.Warn("notification status refresh failed", "error", notificationErr)
	} else {
		status["notification_destinations"] = notificationStatus["active"]
		status["notifications"] = notificationStatus
	}
	s.addVersionReleaseURL(status)
	// The inactive config.yaml jobs predate business units and belong to the
	// default unit, as the CLI status reports them, so another unit's status
	// names none.
	scope, scopeErr := ts.Scope()
	if user.Role != store.RoleViewer && len(s.App.Config.Jobs) > 0 && scopeErr == nil && scope == store.DefaultTenantScope() {
		legacy := make([]string, 0, len(s.App.Config.Jobs))
		for _, job := range s.App.Config.Jobs {
			legacy = append(legacy, job.Name)
		}
		status["legacy_yaml_jobs"] = legacy
	}
	// The live-update counters describe the whole deployment's stream, so
	// once several business units exist they are left out: they would tell a
	// unit about the others' activity. If the units cannot be counted, the
	// counters are left out.
	multiple, unitsErr := s.Store.Platform().HasMultipleTenants(r.Context())
	if unitsErr == nil && !multiple {
		s.mu.Lock()
		status["live_updates"] = map[string]any{"history_size": len(s.history), "dropped_events": s.dropped}
		s.mu.Unlock()
	}
	status["updates"] = s.applicationUpdateStatus(r.Context())
	if telemetry, telemetryErr := s.cachedTenantTelemetry(r.Context(), ts); telemetryErr != nil {
		s.Log.Warn("deployment telemetry refresh failed", "error", telemetryErr)
	} else {
		status["telemetry"] = telemetry
	}
	writeJSON(w, http.StatusOK, status)
}

const deploymentTelemetryTTL = 30 * time.Second

// tenantTelemetryCache is one tenant's cached telemetry and its single-flight
// refresh gate.
type tenantTelemetryCache struct {
	value   store.TenantTelemetry
	at      time.Time
	valid   bool
	running bool
	done    chan struct{}
}

// cachedTenantTelemetry keeps status polling cheap while still reflecting
// normal scan and retention activity promptly. Each tenant has its own cache
// entry, keyed by the tenant of ts itself, so a tenant never reads another's
// counters. Concurrent requests of one tenant share one refresh instead of
// issuing duplicate aggregate queries.
func (s *Server) cachedTenantTelemetry(ctx context.Context, ts *store.TenantStore) (store.TenantTelemetry, error) {
	// The public scope of ts names the tenant of ts; it is only the key here.
	scope, err := ts.PublicScope()
	if err != nil {
		return store.TenantTelemetry{}, err
	}
	key := scope.TenantID()
	for {
		s.telemetryMu.Lock()
		if s.telemetry == nil {
			s.telemetry = map[string]*tenantTelemetryCache{}
		}
		entry := s.telemetry[key]
		if entry == nil {
			entry = &tenantTelemetryCache{}
			s.telemetry[key] = entry
		}
		if entry.valid && time.Since(entry.at) < deploymentTelemetryTTL {
			value := entry.value
			s.telemetryMu.Unlock()
			return value, nil
		}
		if !entry.running {
			entry.running = true
			entry.done = make(chan struct{})
			done := entry.done
			s.telemetryMu.Unlock()

			var value store.TenantTelemetry
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
						entry.value, entry.at, entry.valid = value, time.Now(), true
					}
					entry.running = false
					close(done)
					s.telemetryMu.Unlock()
				}()
				value, err = ts.Telemetry(ctx)
			}()
			return value, err
		}
		done := entry.done
		s.telemetryMu.Unlock()
		select {
		case <-done:
			continue
		case <-ctx.Done():
			return store.TenantTelemetry{}, ctx.Err()
		}
	}
}

// addVersionReleaseURL links the running version to its release page. The URL
// is derived locally from the build version, so it needs no update check and
// is omitted for development and other unpublished builds.
func (s *Server) addVersionReleaseURL(status map[string]any) {
	if releaseURL := updatecheck.BuildReleasePageURL(s.Version); releaseURL != "" {
		status["version_release_url"] = releaseURL
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
	// The status shows only the release check, which is platform data; the
	// update routing it would also carry is not read here.
	state, err := s.Store.Platform().GetApplicationUpdateState(ctx)
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

// platformSetup redeems the platform setup token that the host printed with
// `edgewatch admin platform-setup-token` and creates the first platform
// administrator with the chosen username and password. A wrong, used, or
// expired token, and an enabled platform administrator that already exists,
// get one generic answer; the username and password rules, which are public,
// are explained.
func (s *Server) platformSetup(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if _, err := store.NormalizeUsername(input.Username); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error(), map[string]string{"username": err.Error()})
		return
	}
	user, err := s.Auth.PlatformSetupRequest(r.Context(), r, input.Token, input.Username, input.Password)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrRateLimited):
			w.Header().Set("Retry-After", "300")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many setup attempts; try again later", nil)
		case errors.Is(err, store.ErrAuditUnavailable):
			s.auditFailure(err, "platform_admin.setup")
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "setup could not be completed because the security audit is unavailable", nil)
		case errors.Is(err, store.ErrUsernameUnavailable):
			writeError(w, http.StatusConflict, "conflict", store.ErrUsernameUnavailable.Error(), map[string]string{"username": store.ErrUsernameUnavailable.Error()})
		case strings.HasPrefix(err.Error(), "password must be at least "):
			writeError(w, http.StatusBadRequest, "setup_failed", err.Error(), map[string]string{"password": err.Error()})
		default:
			writeError(w, http.StatusBadRequest, "setup_failed", "platform administrator setup could not be completed", nil)
		}
		return
	}
	s.Log.Info("platform administrator configured", "username", user.Username)
	writeJSON(w, http.StatusCreated, map[string]any{"configured": true, "username": user.Username})
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
			w.Header().Set("Retry-After", auth.RetryAfterHeaderValue(err))
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
	secureCookie := s.sessionCookieSecure(r)
	auth.SetSessionCookie(w, raw, secureCookie)
	session, sessionErr := s.Store.GetSession(r.Context(), digest(raw))
	if sessionErr != nil || strings.TrimSpace(session.CSRFToken) == "" {
		// A successful password check without a readable session would leave the
		// browser with a cookie that cannot pass CSRF validation. Clear it and
		// return a generic server error rather than issuing a partially usable
		// login response.
		auth.ClearSessionCookie(w, secureCookie)
		writeError(w, http.StatusInternalServerError, "session_unavailable", "login session could not be established", nil)
		return
	}
	response := map[string]any{"username": user.Username, "display_name": user.DisplayName, "role": user.Role, "csrf_token": session.CSRFToken, "totp_required": user.TOTPEnabled}
	s.addSessionPermissions(response, store.Session{Role: user.Role, TOTPEnrollmentRequired: s.Auth.TOTPEnrollmentRequired(r.Context(), user)})
	writeJSON(w, http.StatusOK, response)
}

// addSessionPermissions adds the session's permissions to a response that
// describes the signed-in account. A session that must enrol TOTP before it
// may do anything else also carries totp_enrollment_required, and holds only
// its own account's self-service; the key is absent otherwise, so a session
// without the requirement is described exactly as before.
func (s *Server) addSessionPermissions(response map[string]any, session store.Session) {
	response["permissions"] = auth.PermissionsForSession(session)
	if session.TOTPEnrollmentRequired {
		response["totp_enrollment_required"] = true
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, session store.Session) {
	err := s.Auth.LogoutSession(r.Context(), r, session)
	auth.ClearSessionCookie(w, s.sessionCookieSecure(r))
	// Logout deletes the session even when the audit write reports its
	// deliberate degraded-but-safe error. Drop any matching in-process stream
	// in both successful cases rather than waiting for its next heartbeat.
	if err == nil || errors.Is(err, store.ErrAuditUnavailable) {
		s.revokeSSESession(session.IDHash)
	}
	if err != nil {
		if errors.Is(err, store.ErrAuditUnavailable) {
			action := "user.logout"
			if session.Role == store.RoleAdministrator {
				action = "admin.logout"
			}
			s.auditFailure(err, action)
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "logout was completed, but the security audit is temporarily unavailable", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "store", "session could not be ended", nil)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

// session describes the signed-in account. It needs no tenant: the account
// comes from the session that authentication verified, whatever its tenant.
func (s *Server) session(w http.ResponseWriter, r *http.Request, session store.Session) {
	user, err := s.Store.GetAccount(r.Context(), session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user_missing", "account could not be loaded", nil)
		return
	}
	response := map[string]any{"user_id": user.ID, "username": user.Username, "display_name": user.DisplayName, "role": user.Role, "csrf_token": session.CSRFToken, "totp_enabled": user.TOTPEnabled, "password_requirements": auth.PasswordRequirements(), "timezone": s.deploymentTimezone()}
	s.addSessionPermissions(response, store.Session{Role: user.Role, TOTPEnrollmentRequired: session.TOTPEnrollmentRequired})
	// The session also names its console, the platform's or a unit's, and
	// its unit.
	if err := s.addSessionScope(r.Context(), response, user); err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// deploymentTimezone is the optional IANA zone from config.yaml. Signed-in
// consoles render timestamps in it and use it as the default for new jobs; an
// empty value keeps each browser's own timezone. It is deliberately absent
// from unauthenticated and public-status responses.
func (s *Server) deploymentTimezone() string {
	if s == nil || s.App == nil || s.App.Config == nil {
		return ""
	}
	return strings.TrimSpace(s.App.Config.Timezone)
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

func (s *Server) changeDisplayName(w http.ResponseWriter, r *http.Request, session store.Session, account accountStore) {
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
	user, err := account.GetUser(r.Context(), session.UserID)
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
		saveErr = account.UpdateUser(r.Context(), user, false, store.AuditEntry{Action: auditAction, Detail: "display name changed", ActorUserID: session.UserID, ActorUsername: session.Username})
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

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, session store.Session, account accountStore) {
	var input struct {
		Current  string `json:"current_password"`
		Password string `json:"new_password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	user, err := account.GetUser(r.Context(), session.UserID)
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
		saveErr = account.UpdateUser(r.Context(), user, true, store.AuditEntry{Action: auditAction, Detail: "password changed", ActorUserID: session.UserID, ActorUsername: session.Username})
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
	s.revokeSSEUser(session.UserID)
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) totpSetup(w http.ResponseWriter, r *http.Request, session store.Session, account accountStore) {
	var input struct {
		Password string `json:"password"`
		Code     string `json:"code"`
		Recovery string `json:"recovery_code"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	user, err := account.GetUser(r.Context(), session.UserID)
	if err != nil {
		s.writePasswordConfirmationError(w, err, "password is incorrect")
		return
	}
	if err := s.Auth.ConfirmPasswordForUser(r.Context(), r, session.UserID, input.Password); err != nil {
		s.writePasswordConfirmationError(w, err, "password is incorrect")
		return
	}
	if user.TOTPEnabled {
		if err := s.Auth.ConfirmTOTPForUser(r.Context(), r, session.UserID, input.Code, input.Recovery); err != nil {
			s.writeCurrentFactorError(w, err)
			return
		}
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

func (s *Server) totpEnable(w http.ResponseWriter, r *http.Request, session store.Session, account accountStore) {
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
	pending, remaining, ok := s.verifyPendingTOTP(key, input.Code, s.currentTime())
	if !ok {
		if remaining > 0 {
			attempts := "attempts"
			if remaining == 1 {
				attempts = "attempt"
			}
			writeError(w, http.StatusBadRequest, "totp_failed", fmt.Sprintf("the verification code is incorrect; %d %s remaining", remaining, attempts), map[string]any{"remaining_attempts": remaining})
			return
		}
		writeError(w, http.StatusBadRequest, "totp_setup_expired", "TOTP setup expired or had too many incorrect codes; start setup again", nil)
		return
	}
	plain, hashes, err := auth.RecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "totp_failed", "recovery codes could not be generated", nil)
		return
	}
	user, err := account.GetUser(r.Context(), session.UserID)
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
		saveErr = account.SaveUserSecurityPreservingSession(r.Context(), user, hashes, true, true, store.AuditEntry{Action: auditAction, Detail: "TOTP enabled", ActorUserID: session.UserID, ActorUsername: session.Username}, preserveSessionHash)
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
	s.revokeSSEUserExcept(session.UserID, preserveSessionHash)
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": plain})
}

// verifyPendingTOTP checks code against the enrolment pending for key. A
// correct code consumes the enrolment and returns it. A wrong code keeps the
// enrolment for a retry and returns how many attempts remain; the last
// permitted failure discards it. remaining is zero when no enrolment is
// pending, it expired, or its attempts are spent, so the user must start
// setup again. Verification and counting happen under one lock so parallel
// requests cannot exceed pendingTOTPMaxAttempts.
func (s *Server) verifyPendingTOTP(key, code string, now time.Time) (pendingTOTP, int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prunePendingTOTPLocked(now)
	pending, found := s.pendingTOTP[key]
	if !found || !now.Before(pending.Expires) {
		delete(s.pendingTOTP, key)
		return pendingTOTP{}, 0, false
	}
	if auth.VerifyTOTP(pending.Secret, code) {
		delete(s.pendingTOTP, key)
		return pending, 0, true
	}
	pending.Failures++
	remaining := pendingTOTPMaxAttempts - pending.Failures
	if remaining <= 0 {
		delete(s.pendingTOTP, key)
		return pendingTOTP{}, 0, false
	}
	s.pendingTOTP[key] = pending
	return pendingTOTP{}, remaining, false
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request, session store.Session, account accountStore) {
	var input struct {
		Password string `json:"password"`
		Code     string `json:"code"`
		Recovery string `json:"recovery_code"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	user, err := account.GetUser(r.Context(), session.UserID)
	if err != nil {
		s.writePasswordConfirmationError(w, err, "password is incorrect")
		return
	}
	if err := s.Auth.ConfirmPasswordForUser(r.Context(), r, session.UserID, input.Password); err != nil {
		s.writePasswordConfirmationError(w, err, "password is incorrect")
		return
	}
	if user.TOTPEnabled {
		if err := s.Auth.ConfirmTOTPForUser(r.Context(), r, session.UserID, input.Code, input.Recovery); err != nil {
			s.writeCurrentFactorError(w, err)
			return
		}
	}
	user.TOTPEnabled, user.TOTPSecret, user.UpdatedAt = false, "", time.Now().UTC()
	auditAction := "user.totp_disabled"
	var saveErr error
	if user.ID == store.LegacyAdminUserID {
		admin := store.Admin{Username: user.Username, DisplayName: user.DisplayName, PasswordHash: user.PasswordHash, TOTPSecret: user.TOTPSecret, TOTPSecretStored: user.TOTPSecretStored, TOTPEnabled: user.TOTPEnabled, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, Revision: user.Revision}
		auditAction = "admin.totp_disabled"
		saveErr = s.Store.SaveAdminSecurityWithAudit(r.Context(), admin, []string{}, true, true, store.AuditEntry{Action: auditAction, Detail: "TOTP disabled", ActorUserID: session.UserID, ActorUsername: session.Username})
	} else {
		saveErr = account.SaveUserSecurity(r.Context(), user, []string{}, true, true, store.AuditEntry{Action: auditAction, Detail: "TOTP disabled", ActorUserID: session.UserID, ActorUsername: session.Username})
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
	s.revokeSSEUser(session.UserID)
	writeJSON(w, http.StatusNoContent, nil)
}

// totpRecoveryCodes rotates the one-use recovery set without exposing the
// existing hashes. Both the password and the currently configured factor are
// required, and the current browser session is preserved so the newly issued
// codes can be copied before the page is left.
func (s *Server) totpRecoveryCodes(w http.ResponseWriter, r *http.Request, session store.Session, account accountStore) {
	var input struct {
		Password string `json:"password"`
		Code     string `json:"code"`
		Recovery string `json:"recovery_code"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	user, err := account.GetUser(r.Context(), session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "totp_failed", "account could not be loaded for recovery-code rotation", nil)
		return
	}
	if !user.TOTPEnabled {
		writeError(w, http.StatusBadRequest, "totp_required", "TOTP must be enabled before recovery codes can be regenerated", nil)
		return
	}
	if err := s.Auth.ConfirmPasswordForUser(r.Context(), r, session.UserID, input.Password); err != nil {
		s.writePasswordConfirmationError(w, err, "password is incorrect")
		return
	}
	if err := s.Auth.ConfirmTOTPForUser(r.Context(), r, session.UserID, input.Code, input.Recovery); err != nil {
		s.writeCurrentFactorError(w, err)
		return
	}
	plain, hashes, err := auth.RecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "totp_failed", "recovery codes could not be generated", nil)
		return
	}
	cookie, cookieErr := r.Cookie(auth.SessionCookie)
	preserve := ""
	if cookieErr == nil && cookie.Value != "" {
		preserve = digest(cookie.Value)
	}
	user.UpdatedAt = s.currentTime()
	auditAction := "user.totp_recovery_codes_rotated"
	var saveErr error
	if user.ID == store.LegacyAdminUserID {
		auditAction = "admin.totp_recovery_codes_rotated"
		admin := store.Admin{Username: user.Username, DisplayName: user.DisplayName, PasswordHash: user.PasswordHash, TOTPSecret: user.TOTPSecret, TOTPSecretStored: user.TOTPSecretStored, TOTPEnabled: user.TOTPEnabled, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, Revision: user.Revision}
		saveErr = s.Store.SaveAdminSecurityWithAuditPreservingSession(r.Context(), admin, hashes, true, true, actorAudit(session, auditAction, "TOTP recovery codes rotated"), preserve)
	} else {
		saveErr = account.SaveUserSecurityPreservingSession(r.Context(), user, hashes, true, true, actorAudit(session, auditAction, "TOTP recovery codes rotated"), preserve)
	}
	if saveErr != nil {
		if s.writeAuditUnavailable(w, saveErr, auditAction) {
			return
		}
		writeSecurityMutationError(w, saveErr, "totp_failed", "recovery codes could not be saved")
		return
	}
	s.revokeSSEUserExcept(session.UserID, preserve)
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": plain})
}

func (s *Server) writeCurrentFactorError(w http.ResponseWriter, err error) {
	if errors.Is(err, auth.ErrRateLimited) {
		w.Header().Set("Retry-After", "300")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many authenticator confirmation attempts; try again later", nil)
		return
	}
	writeError(w, http.StatusUnauthorized, "totp_required", "the current authenticator code or recovery code is required", nil)
}
