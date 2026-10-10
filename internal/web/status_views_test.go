package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/updatecheck"
)

// The status, the platform status, and the update status that both show
// were maps before they became the structs in status_views.go. The legacy
// handlers below are those map-based handlers as they were, kept to prove
// that the structs write the same bytes for every role and number of units.
// Only the notification status is read through notify.Status, which
// notify's own test compares with the map it was. When a status response
// changes on purpose, change its legacy handler with it.

// legacyNotificationStatus returns the tenant's notification status as the
// map that TenantNotifier.Status returned before it returned notify.Status.
func legacyNotificationStatus(ctx context.Context, notifier *notify.TenantNotifier) (map[string]any, error) {
	status, err := notifier.Status(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(status)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var legacy map[string]any
	if err := decoder.Decode(&legacy); err != nil {
		return nil, err
	}
	return legacy, nil
}

func (s *Server) legacyAdminStatus(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore) {
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
			"updates": s.legacyApplicationUpdateStatus(r.Context()),
		}
		s.legacyAddVersionReleaseURL(viewerStatus)
		writeJSON(w, http.StatusOK, viewerStatus)
		return
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
		// How scanner and notification processes start is deployment-wide
		// and names no unit's data.
		"scanner_sandbox":      s.App.ScannerSandbox(),
		"notification_sandbox": s.App.NotificationSandbox(),
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
	// Tenant.Status reads only this tenant's destinations and opens them for
	// the status response. A global Reload here would decrypt every tenant's
	// credentials on every status poll without improving this response.
	if notificationStatus, notificationErr := legacyNotificationStatus(r.Context(), s.App.Notifier.Tenant(ts)); notificationErr != nil {
		s.Log.Warn("notification status refresh failed", "error", notificationErr)
	} else {
		status["notification_destinations"] = notificationStatus["active"]
		status["notifications"] = notificationStatus
	}
	s.legacyAddVersionReleaseURL(status)
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
		// An untrusted proxy in front of the deployment is the host
		// operator's to fix. With one unit, its administrators see it; with
		// more, only the platform status reports it.
		if proxy, seen := s.Auth.UntrustedProxy(); seen && session.Role == store.RoleAdministrator {
			status["untrusted_proxy"] = proxy
		}
		// The scheduled backups cover the whole deployment and are the host
		// operator's too, and their status names no unit's data. With one
		// unit, its administrators see it; with more, only the platform
		// status reports it.
		if backups := s.App.BackupStatus(); backups != nil && session.Role == store.RoleAdministrator {
			status["backups"] = backups
		}
	}
	status["updates"] = s.legacyApplicationUpdateStatus(r.Context())
	if telemetry, telemetryErr := s.cachedTenantTelemetry(r.Context(), ts); telemetryErr != nil {
		s.Log.Warn("deployment telemetry refresh failed", "error", telemetryErr)
	} else {
		status["telemetry"] = telemetry
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) legacyAddVersionReleaseURL(status map[string]any) {
	if releaseURL := updatecheck.BuildReleasePageURL(s.Version); releaseURL != "" {
		status["version_release_url"] = releaseURL
	}
}

func (s *Server) legacyApplicationUpdateStatus(ctx context.Context) map[string]any {
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

func (s *Server) legacyPlatformStatus(w http.ResponseWriter, r *http.Request) {
	platform := s.Store.Platform()
	records, err := platform.ListTenants(r.Context())
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	admins, err := platform.PlatformAdmins(r.Context())
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	units := map[string]int{"total": len(records), store.TenantStateActive: 0, store.TenantStateDisabled: 0, store.TenantStateDeleting: 0}
	var accounts, jobs int
	var storedScans int64
	for _, record := range records {
		units[record.State]++
		accounts += record.Accounts
		jobs += record.Jobs
		storedScans += record.StoredScans
	}
	enabledAdmins := 0
	for _, admin := range admins {
		if admin.Enabled {
			enabledAdmins++
		}
	}
	usage := s.App.SlotUsage()
	status := map[string]any{
		"version":         s.Version,
		"updates":         s.legacyApplicationUpdateStatus(r.Context()),
		"units":           units,
		"accounts":        accounts,
		"jobs":            jobs,
		"stored_scans":    storedScans,
		"platform_admins": map[string]int{"total": len(admins), "enabled": enabledAdmins},
		"capacity": map[string]any{
			"limits": s.platformLimits(),
			"slots":  map[string]int{"capacity": usage.Capacity, "in_use": usage.InUse, "queued": usage.Queued},
		},
	}
	if proxy, seen := s.Auth.UntrustedProxy(); seen {
		status["untrusted_proxy"] = proxy
	}
	if backups := s.App.BackupStatus(); backups != nil {
		status["backups"] = backups
	}
	s.legacyAddVersionReleaseURL(status)
	writeJSON(w, http.StatusOK, status)
}

// statusBody returns the body that the handler writes.
func statusBody(t *testing.T, handler func(http.ResponseWriter, *http.Request), path string) []byte {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler(recorder, httptest.NewRequest(http.MethodGet, consoleAPIBase+path, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s = %d %s", path, recorder.Code, recorder.Body.String())
	}
	return recorder.Body.Bytes()
}

// statusAccount is a signed-in account and its unit's store.
type statusAccount struct {
	name    string
	session store.Session
	ts      *store.TenantStore
}

// compareStatuses compares, for each account, the status that adminStatus
// writes with the legacy one, and the platform status with its legacy one.
// It returns the accounts' statuses by name.
func compareStatuses(t *testing.T, server *Server, situation string, accounts []statusAccount) map[string]string {
	t.Helper()
	bodies := map[string]string{}
	for _, account := range accounts {
		current := statusBody(t, func(w http.ResponseWriter, r *http.Request) { server.adminStatus(w, r, account.session, account.ts) }, "/status")
		legacy := statusBody(t, func(w http.ResponseWriter, r *http.Request) {
			server.legacyAdminStatus(w, r, account.session, account.ts)
		}, "/status")
		if !bytes.Equal(current, legacy) {
			t.Errorf("%s: the status of %s =\n%s\nwant the legacy\n%s", situation, account.name, current, legacy)
		}
		bodies[account.name] = string(current)
	}
	current := statusBody(t, server.platformStatus, "/platform/status")
	legacy := statusBody(t, server.legacyPlatformStatus, "/platform/status")
	if !bytes.Equal(current, legacy) {
		t.Errorf("%s: the platform status =\n%s\nwant the legacy\n%s", situation, current, legacy)
	}
	bodies["platform"] = string(current)
	return bodies
}

// requireFields checks that the body has each of the JSON fields, or has
// none of them.
func requireFields(t *testing.T, situation, name, body string, present bool, fields ...string) {
	t.Helper()
	for _, field := range fields {
		if strings.Contains(body, `"`+field+`":`) != present {
			t.Errorf("%s: the status of %s has %s %t, want %t: %s", situation, name, field, !present, present, body)
		}
	}
}

// fillDeploymentSignals turns on what the status reports only when it
// exists: a release version, a seen untrusted proxy, scheduled backups with
// a recorded outcome, inactive config.yaml jobs, and a web-managed
// notification destination of the default unit.
func fillDeploymentSignals(t *testing.T, server *Server, ts *store.TenantStore) {
	t.Helper()
	ctx := context.Background()
	server.Version = "v0.35.0"
	request := httptest.NewRequest(http.MethodGet, consoleAPIBase+"/setup/status", nil)
	request.Host = "127.0.0.1:8080"
	request.RemoteAddr = "192.168.10.4:6000"
	request.Header.Set("X-Forwarded-For", "198.51.100.40")
	server.Handler().ServeHTTP(httptest.NewRecorder(), request)
	if _, seen := server.Auth.UntrustedProxy(); !seen {
		t.Fatal("the untrusted proxy was not recorded")
	}
	server.App.Config.Backup = config.Backup{Directory: "/var/lib/edgewatch/backups", Schedule: "0 3 * * *", Keep: 7}
	// The newest good backup lies in the future, so its age is zero whenever
	// the status is read and both handlers report the same age.
	at := time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC)
	raw, err := json.Marshal(app.BackupStatus{Directory: "/var/lib/edgewatch/backups", NextRunAt: at.Add(24 * time.Hour), LastSuccessAt: time.Now().UTC().Add(24 * time.Hour), LastBackup: "edgewatch-scheduled-20261001T030000Z.db", LastBackupBytes: 4096, LastBackupSchemaVersion: 60, LastFailureAt: at, LastError: "disk full", ConsecutiveFailures: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app.BackupStatusPath(server.Store.Path), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	server.App.Config.Jobs = []config.Job{{Name: "legacy-nightly"}, {Name: "legacy-weekly"}}
	if _, err := server.App.Notifier.Tenant(ts).CreateManagedWithAudit(ctx, "status-hook", "generic://localhost/status-hook?disabletls=yes", true, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
}

// compareUpdateStatuses compares the statuses for each outcome of the
// release check.
func compareUpdateStatuses(t *testing.T, server *Server, accounts []statusAccount) {
	t.Helper()
	ctx := context.Background()
	platform := server.Store.Platform()
	if _, err := platform.RecordInstalledVersion(ctx, server.Version, "", false, nil); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		situation, latest, releaseURL string
		failed                        bool
	}{
		{situation: "a newer release", latest: "v0.36.0", releaseURL: "https://github.com/crypt0rr/EdgeWatch/releases/tag/v0.36.0"},
		{situation: "a newer release without its page", latest: "v0.37.0"},
		{situation: "a failed check after a newer release", latest: "v0.37.0", failed: true},
		{situation: "the current release", latest: "v0.35.0"},
		{situation: "an older release", latest: "v0.34.0"},
	} {
		if _, err := platform.RecordReleaseCheck(ctx, server.Version, check.latest, check.releaseURL, "EdgeWatch "+check.latest, "2026-10-01T12:00:00Z", `"etag"`, false, nil); err != nil {
			t.Fatal(err)
		}
		if check.failed {
			if err := platform.RecordReleaseCheckFailure(ctx, "registry unavailable"); err != nil {
				t.Fatal(err)
			}
		}
		compareStatuses(t, server, check.situation, accounts)
	}
	disabled := false
	server.App.Config.Updates.Enabled = &disabled
	compareStatuses(t, server, "update checks turned off", accounts)
	server.App.Config.Updates.Enabled = nil
	version := server.Version
	server.Version = "dev"
	compareStatuses(t, server, "a development build", accounts)
	server.Version = ""
	compareStatuses(t, server, "a build without a version", accounts)
	server.Version = version
}

// With one unit, the structs write the bytes of the legacy maps for an
// administrator, an operator, and a viewer, and for the platform status,
// before and after the deployment signals exist and for each update status.
func TestStatusStructsWriteTheLegacyBytesWithOneUnit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, _, admin := newUsersTestServer(t)
	ts := defaultTenantStore(server)
	accounts := []statusAccount{{name: store.RoleAdministrator, session: admin, ts: ts}}
	for _, role := range []string{store.RoleOperator, store.RoleViewer} {
		// The operator has no display name, which the status still names.
		display := ""
		if role == store.RoleViewer {
			display = "Viewer"
		}
		user, err := ts.CreateUser(ctx, store.User{Username: role + "-account", DisplayName: display, Role: role, PasswordHash: cheapPasswordHash("status password"), Enabled: true}, store.AuditEntry{})
		if err != nil {
			t.Fatal(err)
		}
		accounts = append(accounts, statusAccount{name: role, session: store.Session{UserID: user.ID, Username: user.Username, Role: role}, ts: ts})
	}

	bodies := compareStatuses(t, server, "a new deployment", accounts)
	requireFields(t, "a new deployment", store.RoleOperator, bodies[store.RoleOperator], true, "display_name", "live_updates", "notifications", "telemetry", "max_concurrent_scans")
	requireFields(t, "a new deployment", store.RoleAdministrator, bodies[store.RoleAdministrator], false, "untrusted_proxy", "backups", "legacy_yaml_jobs", "version_release_url")

	fillDeploymentSignals(t, server, ts)
	bodies = compareStatuses(t, server, "a deployment with every signal", accounts)
	requireFields(t, "a deployment with every signal", store.RoleAdministrator, bodies[store.RoleAdministrator], true, "untrusted_proxy", "backups", "legacy_yaml_jobs", "version_release_url", "live_updates", "last_success_age_seconds")
	requireFields(t, "a deployment with every signal", store.RoleOperator, bodies[store.RoleOperator], true, "legacy_yaml_jobs", "live_updates")
	requireFields(t, "a deployment with every signal", store.RoleOperator, bodies[store.RoleOperator], false, "untrusted_proxy", "backups")
	requireFields(t, "a deployment with every signal", store.RoleViewer, bodies[store.RoleViewer], true, "version", "version_release_url", "updates")
	requireFields(t, "a deployment with every signal", store.RoleViewer, bodies[store.RoleViewer], false, "configured", "username", "permissions", "notifications", "live_updates", "untrusted_proxy", "backups", "legacy_yaml_jobs", "telemetry", "scanner_sandbox")
	requireFields(t, "a deployment with every signal", "the platform", bodies["platform"], true, "untrusted_proxy", "backups", "version_release_url")

	compareUpdateStatuses(t, server, accounts)
}

// With several units, the structs write the bytes of the legacy maps for
// each role of the default unit, another unit's administrator, and the
// platform status, with units in every state.
func TestStatusStructsWriteTheLegacyBytesWithSeveralUnits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPlatformFixture(t)
	accounts := []statusAccount{
		{name: actorAdminA, session: f.sessions[actorAdminA].session, ts: f.a},
		{name: actorOperatorA, session: f.sessions[actorOperatorA].session, ts: f.a},
		{name: actorViewerA, session: f.sessions[actorViewerA].session, ts: f.a},
		{name: actorAdminB, session: f.sessions[actorAdminB].session, ts: f.b},
	}
	compareStatuses(t, f.server, "two units", accounts)

	audit := store.AuditEntry{ActorUserID: f.users[actorPlatform].ID, ActorUsername: "platform-root"}
	for _, name := range []string{"Charlie Unit", "Delta Unit"} {
		unit, err := f.server.App.CreateUnit(ctx, name, strings.ToLower(strings.Fields(name)[0]), audit)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.server.App.DisableUnit(ctx, unit.ID, unit.Revision, audit); err != nil {
			t.Fatal(err)
		}
		if name == "Delta Unit" {
			if _, err := f.server.App.RequestUnitDeletion(ctx, unit.ID, name, audit); err != nil {
				t.Fatal(err)
			}
		}
	}
	insertPlatformAdmin(t, f.db, "platform-disabled", cheapPasswordHash(platformFixturePassword), false)
	fillDeploymentSignals(t, f.server, f.a)
	bodies := compareStatuses(t, f.server, "units in every state with every signal", accounts)
	for _, actor := range []string{actorAdminA, actorAdminB} {
		requireFields(t, "several units", actor, bodies[actor], false, "untrusted_proxy", "backups", "live_updates")
	}
	requireFields(t, "several units", actorAdminA, bodies[actorAdminA], true, "legacy_yaml_jobs")
	requireFields(t, "several units", actorAdminB, bodies[actorAdminB], false, "legacy_yaml_jobs")
	var platform struct {
		Units          platformUnitCountsView  `json:"units"`
		PlatformAdmins platformAdminCountsView `json:"platform_admins"`
	}
	if err := json.Unmarshal([]byte(bodies["platform"]), &platform); err != nil {
		t.Fatal(err)
	}
	if platform.Units != (platformUnitCountsView{Active: 2, Disabled: 1, Deleting: 1, Total: 4}) || platform.PlatformAdmins != (platformAdminCountsView{Enabled: 2, Total: 3}) {
		t.Fatalf("platform status counts = %+v, want every unit state and a disabled platform administrator", platform)
	}

	compareUpdateStatuses(t, f.server, accounts)
}
