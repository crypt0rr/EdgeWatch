package web

import (
	"net/http"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/auth"
)

// routeAccess records which gate a request passes before its handler runs.
type routeAccess int

const (
	// routeSession routes pass the gate in serveRoute: session
	// authentication, the CSRF check for mutations, and the route's
	// Permission.
	routeSession routeAccess = iota
	// routeUnauthenticated routes are served by serveRoute before the
	// session gate. They have no Permission, which the session gate would
	// refuse. Their state-changing requests are protected by
	// validateBrowserOrigin.
	routeUnauthenticated
	// routePublic routes are served by Server.publicAPI under
	// publicAPIBase, without a session or a permission, and may only return
	// explicitly published data.
	routePublic
)

const (
	consoleAPIBase = "/api/v1"
	publicAPIBase  = "/api/public/v1"
)

// apiRoute is one method and path combination that a handler serves.
type apiRoute struct {
	Method string
	// Template is the path relative to the API base. With the method and
	// the base, it is the route's ServeMux pattern. A {name} segment matches
	// exactly one non-empty path segment; a {name...} segment, which must be
	// the last, matches the rest of the path.
	Template string
	// Query, when set, selects a distinct action on the same method and
	// path, with its own capability and handler.
	Query string
	// Permission is the capability the gate requires for the route, or ""
	// for unauthenticated and public routes.
	Permission string
	// Mutates reports whether the method changes state. Session routes that
	// mutate require a CSRF token.
	Mutates bool
	// Example is a concrete path that matches Template, used by the tests.
	Example string
	Access  routeAccess
	// TrailingSlash reports whether the route also answers its path with one
	// trailing slash. The scanner profile, user, notification destination,
	// job item, platform console and public page routes always have.
	TrailingSlash bool
	// NoTenant marks a session route whose handler reads and changes no
	// tenant data, so the gate resolves no tenant store for it.
	NoTenant bool
	// Handle serves the route once the gate admitted the request.
	Handle routeHandler
	// NoHandler marks a capability mapping that the gate keeps although
	// nothing serves it. Authorized requests receive the not-found default.
	NoHandler bool
}

// apiRoutes is the route inventory and the router: every method and path
// that the APIs serve, with the capability the gate requires and the handler
// that serves it. consoleRoutes and publicRoutes register these entries, and
// nothing else in the package dispatches an API path. Tests drive the
// permission and isolation matrices from this table, so a new route cannot
// skip authorization tests. Paths that are not listed fail closed. The
// scanner profile routes are listed once, under /scanner-profiles, and
// withPathAlias adds their /scanner/profiles spelling.
var apiRoutes = withPathAlias("/scanner-profiles", "/scanner/profiles", []apiRoute{
	// Entry points served before the session gate.
	{Method: http.MethodGet, Template: "/setup/status", Example: "/setup/status", Access: routeUnauthenticated, Handle: requestHandler((*Server).setupStatus)},
	{Method: http.MethodPost, Template: "/setup", Mutates: true, Example: "/setup", Access: routeUnauthenticated, Handle: requestHandler((*Server).setup)},
	// The platform setup redeems the host's platform setup token.
	{Method: http.MethodPost, Template: "/setup/platform", Mutates: true, Example: "/setup/platform", Access: routeUnauthenticated, Handle: requestHandler((*Server).platformSetup)},
	{Method: http.MethodPost, Template: "/auth/login", Mutates: true, Example: "/auth/login", Access: routeUnauthenticated, Handle: requestHandler((*Server).login)},
	{Method: http.MethodPost, Template: "/auth/activate", Mutates: true, Example: "/auth/activate", Access: routeUnauthenticated, Handle: requestHandler((*Server).activateUser)},
	// The session probe authenticates itself but needs no capability.
	{Method: http.MethodGet, Template: "/auth/session", Example: "/auth/session", Access: routeUnauthenticated, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) { s.withAuth(w, r, s.session) }},

	// Account self-service.
	{Method: http.MethodPost, Template: "/auth/activity", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/activity", NoTenant: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		writeJSON(w, http.StatusNoContent, nil)
	}},
	{Method: http.MethodPost, Template: "/auth/logout", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/logout", NoTenant: true, Handle: sessionHandler((*Server).logout)},
	{Method: http.MethodPut, Template: "/auth/display-name", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/display-name", Handle: accountHandler((*Server).changeDisplayName)},
	{Method: http.MethodPut, Template: "/auth/password", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/password", Handle: accountHandler((*Server).changePassword)},
	{Method: http.MethodPost, Template: "/auth/totp/setup", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/totp/setup", Handle: accountHandler((*Server).totpSetup)},
	{Method: http.MethodPost, Template: "/auth/totp/enable", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/totp/enable", Handle: accountHandler((*Server).totpEnable)},
	{Method: http.MethodPost, Template: "/auth/totp/recovery-codes", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/totp/recovery-codes", Handle: accountHandler((*Server).totpRecoveryCodes)},
	{Method: http.MethodDelete, Template: "/auth/totp", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/totp", Handle: accountHandler((*Server).totpDisable)},
	{Method: http.MethodDelete, Template: "/auth/sessions", Permission: auth.PermissionAccountSelf, Mutates: true, Example: "/auth/sessions", Handle: accountHandler((*Server).revokeOwnSessions)},

	// Console status and live updates.
	{Method: http.MethodGet, Template: "/status", Permission: auth.PermissionJobsRead, Example: "/status", Handle: sessionTenantHandler((*Server).adminStatus)},
	{Method: http.MethodGet, Template: "/stream", Permission: auth.PermissionStreamRead, Example: "/stream", Handle: sessionTenantHandler((*Server).stream)},

	// Scanner capabilities and profiles. withPathAlias also serves each
	// /scanner-profiles route under /scanner/profiles.
	{Method: http.MethodGet, Template: "/scanner/capabilities", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner/capabilities", Handle: requestHandler((*Server).scannerCapabilities)},
	{Method: http.MethodGet, Template: "/scanner-profiles", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner-profiles", TrailingSlash: true, Handle: tenantHandler((*Server).listScannerProfiles)},
	{Method: http.MethodPost, Template: "/scanner-profiles", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles", TrailingSlash: true, Handle: sessionTenantHandler((*Server).createScannerProfile)},
	{Method: http.MethodPost, Template: "/scanner-profiles/validate", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/validate", TrailingSlash: true, Handle: requestHandler((*Server).validateScannerProfileDraft)},
	{Method: http.MethodPost, Template: "/scanner-profiles/preview", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/preview", TrailingSlash: true, Handle: requestHandler((*Server).renderScannerProfileDraft)},
	{Method: http.MethodGet, Template: "/scanner-profiles/{id}", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner-profiles/profile-1", TrailingSlash: true, Handle: tenantIDHandler((*Server).getScannerProfile)},
	{Method: http.MethodPut, Template: "/scanner-profiles/{id}", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/profile-1", TrailingSlash: true, Handle: sessionTenantIDHandler((*Server).updateScannerProfile)},
	{Method: http.MethodDelete, Template: "/scanner-profiles/{id}", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/profile-1", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.setScannerProfileArchived(w, r, c.session, c.tenant, r.PathValue("id"), true)
	}},
	{Method: http.MethodPost, Template: "/scanner-profiles/{id}/restore", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/profile-1/restore", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.setScannerProfileArchived(w, r, c.session, c.tenant, r.PathValue("id"), false)
	}},
	{Method: http.MethodGet, Template: "/scanner-profiles/{id}/revisions", Permission: auth.PermissionScannerProfilesRead, Example: "/scanner-profiles/profile-1/revisions", TrailingSlash: true, Handle: tenantIDHandler((*Server).listScannerProfileRevisions)},
	{Method: http.MethodPost, Template: "/scanner-profiles/{id}/validate", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/profile-1/validate", TrailingSlash: true, Handle: requestHandler((*Server).validateScannerProfile)},
	{Method: http.MethodPost, Template: "/scanner-profiles/{id}/preview", Permission: auth.PermissionScannerProfilesManage, Mutates: true, Example: "/scanner-profiles/profile-1/preview", TrailingSlash: true, Handle: requestHandler((*Server).previewScannerProfile)},

	// User administration.
	{Method: http.MethodGet, Template: "/users", Permission: auth.PermissionUsersManage, Example: "/users", TrailingSlash: true, Handle: tenantHandler((*Server).listUsers)},
	{Method: http.MethodPost, Template: "/users", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users", TrailingSlash: true, Handle: sessionTenantHandler((*Server).createUser)},
	{Method: http.MethodGet, Template: "/users/{id}", Permission: auth.PermissionUsersManage, Example: "/users/user-1", TrailingSlash: true, Handle: tenantIDHandler((*Server).getUser)},
	{Method: http.MethodPatch, Template: "/users/{id}", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users/user-1", TrailingSlash: true, Handle: sessionTenantIDHandler((*Server).updateUser)},
	{Method: http.MethodPost, Template: "/users/{id}/activation", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users/user-1/activation", TrailingSlash: true, Handle: sessionTenantIDHandler((*Server).issueAccountLink)},
	{Method: http.MethodDelete, Template: "/users/{id}/activation", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users/user-1/activation", TrailingSlash: true, Handle: sessionTenantIDHandler((*Server).revokeActivation)},
	{Method: http.MethodPost, Template: "/users/{id}/password-reset", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users/user-1/password-reset", TrailingSlash: true, Handle: sessionTenantIDHandler((*Server).issueAccountLink)},
	{Method: http.MethodDelete, Template: "/users/{id}/sessions", Permission: auth.PermissionUsersManage, Mutates: true, Example: "/users/user-1/sessions", TrailingSlash: true, Handle: sessionTenantIDHandler((*Server).revokeUserSessions)},

	// Public status publication settings.
	{Method: http.MethodGet, Template: "/public-dashboard", Permission: auth.PermissionPublicManage, Example: "/public-dashboard", Handle: tenantHandler((*Server).getPublicDashboard)},
	{Method: http.MethodPut, Template: "/public-dashboard", Permission: auth.PermissionPublicManage, Mutates: true, Example: "/public-dashboard", Handle: sessionTenantHandler((*Server).savePublicDashboard)},

	// Notifications.
	{Method: http.MethodPost, Template: "/notifications/test", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/test", Handle: sessionTenantHandler((*Server).notificationTest)},
	{Method: http.MethodGet, Template: "/notifications/options", Permission: auth.PermissionNotificationOptions, Example: "/notifications/options", Handle: tenantHandler((*Server).listNotificationDestinations)},
	{Method: http.MethodPut, Template: "/notifications/update-routing", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/update-routing", Handle: sessionTenantHandler((*Server).updateNotificationRouting)},
	{Method: http.MethodPatch, Template: "/notifications/update-routing", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/update-routing", Handle: sessionTenantHandler((*Server).toggleNotificationUpdateRouting)},
	{Method: http.MethodPut, Template: "/notifications/incident-reminders", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/incident-reminders", Handle: sessionTenantHandler((*Server).updateIncidentReminders)},
	{Method: http.MethodGet, Template: "/notifications/destinations", Permission: auth.PermissionNotificationOptions, Example: "/notifications/destinations", Handle: tenantHandler((*Server).listNotificationDestinations)},
	{Method: http.MethodPost, Template: "/notifications/destinations", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/destinations", Handle: sessionTenantHandler((*Server).createNotificationDestination)},
	{Method: http.MethodGet, Template: "/notifications/destinations/{id}", Permission: auth.PermissionNotificationOptions, Example: "/notifications/destinations/destination-1", TrailingSlash: true, Handle: tenantIDHandler((*Server).getNotificationDestination)},
	{Method: http.MethodPut, Template: "/notifications/destinations/{id}", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/destinations/destination-1", TrailingSlash: true, Handle: sessionTenantIDHandler((*Server).updateNotificationDestination)},
	{Method: http.MethodDelete, Template: "/notifications/destinations/{id}", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/destinations/destination-1", TrailingSlash: true, Handle: sessionTenantIDHandler((*Server).deleteNotificationDestination)},
	{Method: http.MethodPost, Template: "/notifications/destinations/{id}/test", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/destinations/destination-1/test", TrailingSlash: true, Handle: sessionTenantIDHandler((*Server).testNotificationDestination)},
	{Method: http.MethodGet, Template: "/notifications/destinations/{id}/deliveries", Permission: auth.PermissionNotificationsManage, Example: "/notifications/destinations/destination-1/deliveries", TrailingSlash: true, Handle: tenantIDHandler((*Server).listTerminalDeliveries)},
	{Method: http.MethodPost, Template: "/notifications/destinations/{id}/deliveries/redeliver", Permission: auth.PermissionNotificationsManage, Mutates: true, Example: "/notifications/destinations/destination-1/deliveries/redeliver", TrailingSlash: true, Handle: sessionTenantIDHandler((*Server).redeliverTerminalDeliveries)},

	// Global inventories.
	{Method: http.MethodGet, Template: "/hosts", Permission: auth.PermissionHostsRead, Example: "/hosts", Handle: tenantHandler((*Server).listHosts)},
	{Method: http.MethodGet, Template: "/incidents", Permission: auth.PermissionIncidentsRead, Example: "/incidents", Handle: tenantHandler((*Server).listIncidents)},
	{Method: http.MethodGet, Template: "/events", Permission: auth.PermissionScansRead, Example: "/events", Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.listEvents(w, r, c.tenant, r.URL.Query().Get("job"))
	}},

	// Scans.
	{Method: http.MethodGet, Template: "/scans", Permission: auth.PermissionScansRead, Example: "/scans", Handle: tenantHandler((*Server).listScans)},
	{Method: http.MethodPost, Template: "/scans", Permission: auth.PermissionJobsRun, Mutates: true, Example: "/scans", NoHandler: true},
	{Method: http.MethodGet, Template: "/scans/active", Permission: auth.PermissionScansRead, Example: "/scans/active", Handle: tenantHandler((*Server).activeScans)},
	{Method: http.MethodGet, Template: "/scans/{id}", Permission: auth.PermissionScansRead, Example: "/scans/scan-1", Handle: tenantIDHandler((*Server).getScan)},
	{Method: http.MethodGet, Template: "/scans/{id}/summary", Permission: auth.PermissionScansRead, Example: "/scans/scan-1/summary", Handle: tenantIDHandler((*Server).getScanSummary)},
	{Method: http.MethodPost, Template: "/scans/{id}/cancel", Permission: auth.PermissionJobsRun, Mutates: true, Example: "/scans/scan-1/cancel", Handle: sessionTenantIDHandler((*Server).cancelScan)},
	{Method: http.MethodGet, Template: "/scans/{id}/hosts", Permission: auth.PermissionHostsRead, Example: "/scans/scan-1/hosts", Handle: tenantIDHandler((*Server).scanHostsRoute)},
	{Method: http.MethodGet, Template: "/scans/{id}/hosts/{address}", Permission: auth.PermissionHostsRead, Example: "/scans/scan-1/hosts/198.51.100.10", Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.scanHostRoute(w, r, c.tenant, r.PathValue("id"), r.PathValue("address"))
	}},
	{Method: http.MethodGet, Template: "/scans/{id}/hosts/{address}/rdap", Permission: auth.PermissionHostsRead, Example: "/scans/scan-1/hosts/198.51.100.10/rdap", Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.scanHostRDAPRoute(w, r, c.tenant, r.PathValue("id"), r.PathValue("address"))
	}},

	// Jobs.
	{Method: http.MethodGet, Template: "/jobs", Permission: auth.PermissionJobsRead, Example: "/jobs", Handle: tenantHandler((*Server).listJobs)},
	{Method: http.MethodPost, Template: "/jobs", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs", Handle: sessionTenantHandler((*Server).createJob)},
	{Method: http.MethodPost, Template: "/jobs/preview", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs/preview", Handle: sessionTenantHandler((*Server).previewJob)},
	{Method: http.MethodGet, Template: "/jobs/schedule-suggestion", Permission: auth.PermissionJobsRead, Example: "/jobs/schedule-suggestion", Handle: tenantHandler((*Server).scheduleSuggestion)},
	{Method: http.MethodGet, Template: "/jobs/{id}", Permission: auth.PermissionJobsRead, Example: "/jobs/job-1", TrailingSlash: true, Handle: jobHandler(jobMissingOnAnyError, (*Server).getJob)},
	{Method: http.MethodPut, Template: "/jobs/{id}", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs/job-1", TrailingSlash: true, Handle: (*Server).updateJobRoute},
	{Method: http.MethodDelete, Template: "/jobs/{id}", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs/job-1", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.archiveJob(w, r, c.session, c.tenant, r.PathValue("id"), true)
	}},
	{Method: http.MethodDelete, Template: "/jobs/{id}", Query: "permanent=true", Permission: auth.PermissionJobsDelete, Mutates: true, Example: "/jobs/job-1", TrailingSlash: true, Handle: (*Server).permanentDeleteJobRoute},
	{Method: http.MethodPost, Template: "/jobs/{id}/archive", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs/job-1/archive", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.archiveJob(w, r, c.session, c.tenant, r.PathValue("id"), true)
	}},
	{Method: http.MethodPost, Template: "/jobs/{id}/restore", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs/job-1/restore", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.archiveJob(w, r, c.session, c.tenant, r.PathValue("id"), false)
	}},
	{Method: http.MethodPost, Template: "/jobs/{id}/pause", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs/job-1/pause", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.enableJob(w, r, c.session, c.tenant, r.PathValue("id"), false)
	}},
	{Method: http.MethodPost, Template: "/jobs/{id}/resume", Permission: auth.PermissionJobsWrite, Mutates: true, Example: "/jobs/job-1/resume", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.enableJob(w, r, c.session, c.tenant, r.PathValue("id"), true)
	}},
	{Method: http.MethodPost, Template: "/jobs/{id}/run", Permission: auth.PermissionJobsRun, Mutates: true, Example: "/jobs/job-1/run", TrailingSlash: true, Handle: jobSessionHandler(jobMissingOnAnyError, (*Server).runJob)},
	{Method: http.MethodDelete, Template: "/jobs/{id}/run", Permission: auth.PermissionJobsRun, Mutates: true, Example: "/jobs/job-1/run", TrailingSlash: true, Handle: jobSessionHandler(jobMissingOnAnyError, (*Server).cancelQueuedRun)},
	{Method: http.MethodGet, Template: "/jobs/{id}/scan-cycle", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/scan-cycle", TrailingSlash: true, Handle: jobHandler(jobStoreErrorInternal, (*Server).scanCycle)},
	{Method: http.MethodDelete, Template: "/jobs/{id}/scan-cycle/{cycle}", Permission: auth.PermissionJobsRun, Mutates: true, Example: "/jobs/job-1/scan-cycle/cycle-1", TrailingSlash: true, Handle: (*Server).discardScanCycleRoute},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/scans", TrailingSlash: true, Handle: jobHandler(jobStoreErrorInternal, (*Server).jobScans)},
	{Method: http.MethodGet, Template: "/jobs/{id}/pending-changes", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/pending-changes", TrailingSlash: true, Handle: jobHandler(jobStoreErrorInternal, (*Server).jobPendingChanges)},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans/latest-successful", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/scans/latest-successful", TrailingSlash: true, Handle: jobHandler(jobMissingOnAnyError, (*Server).latestSuccessfulScan)},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans/{scan}", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/scans/scan-1", TrailingSlash: true, Handle: jobScanHandler(jobStoreErrorInternal, scanStoreErrorInternal, (*Server).jobScan)},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans/{scan}/results", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/scans/scan-1/results", TrailingSlash: true, Handle: (*Server).jobScanResultsRoute},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans/{scan}/changes", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/scans/scan-1/changes", TrailingSlash: true, Handle: jobScanHandler(jobStoreErrorInternal, scanStoreErrorInternal, (*Server).jobScanChanges)},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans/{scan}/hosts", Permission: auth.PermissionHostsRead, Example: "/jobs/job-1/scans/scan-1/hosts", TrailingSlash: true, Handle: jobScanHandler(jobStoreErrorInternal, scanStoreErrorInternal, (*Server).jobScanHosts)},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans/{scan}/hosts/{address}", Permission: auth.PermissionHostsRead, Example: "/jobs/job-1/scans/scan-1/hosts/2001:db8::1", TrailingSlash: true, Handle: (*Server).jobScanHostRoute},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans/{scan}/hosts/{address}/rdap", Permission: auth.PermissionHostsRead, Example: "/jobs/job-1/scans/scan-1/hosts/2001:db8::1/rdap", TrailingSlash: true, Handle: (*Server).jobScanHostRDAPRoute},
	{Method: http.MethodGet, Template: "/jobs/{id}/baseline", Permission: auth.PermissionBaselinesRead, Example: "/jobs/job-1/baseline", TrailingSlash: true, Handle: jobHandler(jobMissingOnAnyError, (*Server).jobBaseline)},
	{Method: http.MethodPost, Template: "/jobs/{id}/baseline/reset", Permission: auth.PermissionBaselinesManage, Mutates: true, Example: "/jobs/job-1/baseline/reset", TrailingSlash: true, Handle: (*Server).resetBaselineRoute},
	{Method: http.MethodPost, Template: "/jobs/{id}/baseline/approve", Permission: auth.PermissionBaselinesManage, Mutates: true, Example: "/jobs/job-1/baseline/approve", TrailingSlash: true, Handle: (*Server).approveBaselineRoute},
	{Method: http.MethodGet, Template: "/jobs/{id}/baseline/hosts", Permission: auth.PermissionBaselinesRead, Example: "/jobs/job-1/baseline/hosts", TrailingSlash: true, Handle: jobHandler(jobStoreErrorInternal, (*Server).jobBaselineHosts)},
	{Method: http.MethodGet, Template: "/jobs/{id}/baseline/hosts/{address}", Permission: auth.PermissionBaselinesRead, Example: "/jobs/job-1/baseline/hosts/198.51.100.1", TrailingSlash: true, Handle: (*Server).jobBaselineHostRoute},
	{Method: http.MethodGet, Template: "/jobs/{id}/baseline/hosts/{address}/rdap", Permission: auth.PermissionBaselinesRead, Example: "/jobs/job-1/baseline/hosts/198.51.100.1/rdap", TrailingSlash: true, Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.jobBaselineHostRDAP(w, r, c.tenant, r.PathValue("id"), r.PathValue("address"))
	}},
	{Method: http.MethodGet, Template: "/jobs/{id}/incidents", Permission: auth.PermissionIncidentsRead, Example: "/jobs/job-1/incidents", TrailingSlash: true, Handle: jobHandler(jobMissingOnAnyError, (*Server).jobIncidents)},
	{Method: http.MethodPost, Template: "/jobs/{id}/incidents/accept", Permission: auth.PermissionIncidentsManage, Mutates: true, Example: "/jobs/job-1/incidents/accept", TrailingSlash: true, Handle: (*Server).acceptIncidentRoute},
	{Method: http.MethodPost, Template: "/jobs/{id}/incidents/suppress", Permission: auth.PermissionIncidentsManage, Mutates: true, Example: "/jobs/job-1/incidents/suppress", TrailingSlash: true, Handle: (*Server).suppressIncidentRoute},
	{Method: http.MethodGet, Template: "/jobs/{id}/events", Permission: auth.PermissionScansRead, Example: "/jobs/job-1/events", TrailingSlash: true, Handle: jobHandler(jobMissingOnAnyError, (*Server).jobEvents)},

	// The unit's security audit, for its administrators.
	{Method: http.MethodGet, Template: "/audit", Permission: auth.PermissionAuditRead, Example: "/audit", Handle: tenantHandler((*Server).unitAudit)},

	// The platform console, for platform administrators: the business
	// units, their administrators and capacity, the platform
	// administrators, the platform audit, the platform's notification
	// destinations and update routing, and the deployment status.
	{Method: http.MethodGet, Template: "/platform/units", Permission: auth.PermissionUnitsManage, Example: "/platform/units", TrailingSlash: true, Handle: platformHandler(requestHandler((*Server).listPlatformUnits))},
	{Method: http.MethodPost, Template: "/platform/units", Permission: auth.PermissionUnitsManage, Mutates: true, Example: "/platform/units", TrailingSlash: true, Handle: platformHandler(sessionHandler((*Server).createPlatformUnit))},
	{Method: http.MethodGet, Template: "/platform/units/{id}", Permission: auth.PermissionUnitsManage, Example: "/platform/units/unit-1", TrailingSlash: true, Handle: platformHandler(idHandler((*Server).getPlatformUnit))},
	{Method: http.MethodPatch, Template: "/platform/units/{id}", Permission: auth.PermissionUnitsManage, Mutates: true, Example: "/platform/units/unit-1", TrailingSlash: true, Handle: platformHandler(sessionIDHandler((*Server).renamePlatformUnit))},
	{Method: http.MethodDelete, Template: "/platform/units/{id}", Permission: auth.PermissionUnitsManage, Mutates: true, Example: "/platform/units/unit-1", TrailingSlash: true, Handle: platformHandler(sessionIDHandler((*Server).deletePlatformUnit))},
	{Method: http.MethodPost, Template: "/platform/units/{id}/disable", Permission: auth.PermissionUnitsManage, Mutates: true, Example: "/platform/units/unit-1/disable", TrailingSlash: true, Handle: platformHandler(func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.setPlatformUnitState(w, r, c.session, r.PathValue("id"), false)
	})},
	{Method: http.MethodPost, Template: "/platform/units/{id}/enable", Permission: auth.PermissionUnitsManage, Mutates: true, Example: "/platform/units/unit-1/enable", TrailingSlash: true, Handle: platformHandler(func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.setPlatformUnitState(w, r, c.session, r.PathValue("id"), true)
	})},
	{Method: http.MethodGet, Template: "/platform/units/{id}/capacity", Permission: auth.PermissionUnitsManage, Example: "/platform/units/unit-1/capacity", TrailingSlash: true, Handle: platformHandler(idHandler((*Server).getPlatformUnitCapacity))},
	{Method: http.MethodPatch, Template: "/platform/units/{id}/capacity", Permission: auth.PermissionUnitsManage, Mutates: true, Example: "/platform/units/unit-1/capacity", TrailingSlash: true, Handle: platformHandler(sessionIDHandler((*Server).updatePlatformUnitCapacity))},
	{Method: http.MethodGet, Template: "/platform/units/{id}/accounts", Permission: auth.PermissionUnitAccountsManage, Example: "/platform/units/unit-1/accounts", TrailingSlash: true, Handle: platformHandler(idHandler((*Server).listPlatformUnitAccounts))},
	{Method: http.MethodPost, Template: "/platform/units/{id}/accounts", Permission: auth.PermissionUnitAccountsManage, Mutates: true, Example: "/platform/units/unit-1/accounts", TrailingSlash: true, Handle: platformHandler(sessionIDHandler((*Server).invitePlatformUnitAdmin))},
	{Method: http.MethodPost, Template: "/platform/units/{id}/accounts/{uid}/password-reset", Permission: auth.PermissionUnitAccountsManage, Mutates: true, Example: "/platform/units/unit-1/accounts/user-1/password-reset", TrailingSlash: true, Handle: platformHandler(func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.resetPlatformUnitAdmin(w, r, c.session, r.PathValue("id"), r.PathValue("uid"))
	})},
	{Method: http.MethodDelete, Template: "/platform/units/{id}/accounts/{uid}/sessions", Permission: auth.PermissionUnitAccountsManage, Mutates: true, Example: "/platform/units/unit-1/accounts/user-1/sessions", TrailingSlash: true, Handle: platformHandler(func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) {
		s.revokePlatformUnitAccountSessions(w, r, c.session, r.PathValue("id"), r.PathValue("uid"))
	})},
	{Method: http.MethodGet, Template: "/platform/admins", Permission: auth.PermissionUnitAccountsManage, Example: "/platform/admins", TrailingSlash: true, Handle: platformHandler(requestHandler((*Server).listPlatformAdmins))},
	{Method: http.MethodPost, Template: "/platform/admins", Permission: auth.PermissionUnitAccountsManage, Mutates: true, Example: "/platform/admins", TrailingSlash: true, Handle: platformHandler(sessionHandler((*Server).invitePlatformAdmin))},
	{Method: http.MethodPatch, Template: "/platform/admins/{id}", Permission: auth.PermissionUnitAccountsManage, Mutates: true, Example: "/platform/admins/user-1", TrailingSlash: true, Handle: platformHandler(sessionIDHandler((*Server).updatePlatformAdmin))},
	{Method: http.MethodDelete, Template: "/platform/admins/{id}", Permission: auth.PermissionUnitAccountsManage, Mutates: true, Example: "/platform/admins/user-1", TrailingSlash: true, Handle: platformHandler(sessionIDHandler((*Server).deletePendingPlatformAdmin))},
	{Method: http.MethodPost, Template: "/platform/admins/{id}/activation", Permission: auth.PermissionUnitAccountsManage, Mutates: true, Example: "/platform/admins/user-1/activation", TrailingSlash: true, Handle: platformHandler(sessionIDHandler((*Server).renewPlatformAdminInvitation))},
	{Method: http.MethodDelete, Template: "/platform/admins/{id}/activation", Permission: auth.PermissionUnitAccountsManage, Mutates: true, Example: "/platform/admins/user-1/activation", TrailingSlash: true, Handle: platformHandler(sessionIDHandler((*Server).revokePlatformAdminInvitation))},
	{Method: http.MethodGet, Template: "/platform/audit", Permission: auth.PermissionPlatformAuditRead, Example: "/platform/audit", TrailingSlash: true, Handle: platformHandler(requestHandler((*Server).platformAudit))},
	{Method: http.MethodGet, Template: "/platform/notifications", Permission: auth.PermissionPlatformNotificationsManage, Example: "/platform/notifications", TrailingSlash: true, Handle: platformHandler(requestHandler((*Server).listPlatformNotifications))},
	{Method: http.MethodPost, Template: "/platform/notifications", Permission: auth.PermissionPlatformNotificationsManage, Mutates: true, Example: "/platform/notifications", TrailingSlash: true, Handle: platformHandler(sessionHandler((*Server).createPlatformNotification))},
	{Method: http.MethodPut, Template: "/platform/notifications/update-routing", Permission: auth.PermissionPlatformNotificationsManage, Mutates: true, Example: "/platform/notifications/update-routing", TrailingSlash: true, Handle: platformHandler(sessionHandler((*Server).updatePlatformNotificationRouting))},
	{Method: http.MethodPatch, Template: "/platform/notifications/update-routing", Permission: auth.PermissionPlatformNotificationsManage, Mutates: true, Example: "/platform/notifications/update-routing", TrailingSlash: true, Handle: platformHandler(sessionHandler((*Server).togglePlatformNotificationRouting))},
	{Method: http.MethodPatch, Template: "/platform/notifications/{id}", Permission: auth.PermissionPlatformNotificationsManage, Mutates: true, Example: "/platform/notifications/destination-1", TrailingSlash: true, Handle: platformHandler(sessionIDHandler((*Server).updatePlatformNotification))},
	{Method: http.MethodDelete, Template: "/platform/notifications/{id}", Permission: auth.PermissionPlatformNotificationsManage, Mutates: true, Example: "/platform/notifications/destination-1", TrailingSlash: true, Handle: platformHandler(sessionIDHandler((*Server).deletePlatformNotification))},
	{Method: http.MethodGet, Template: "/platform/status", Permission: auth.PermissionPlatformStatusRead, Example: "/platform/status", TrailingSlash: true, Handle: platformHandler(requestHandler((*Server).platformStatus))},

	// Unauthenticated public status projection, relative to publicAPIBase:
	// the default business unit's page, and a unit's page by its slug,
	// which is the rest of the path.
	{Method: http.MethodGet, Template: "/dashboard", Example: "/dashboard", Access: routePublic, TrailingSlash: true, Handle: requestHandler((*Server).defaultPublicPage)},
	{Method: http.MethodGet, Template: "/dashboard/{slug...}", Example: "/dashboard/default", Access: routePublic, TrailingSlash: true, Handle: requestHandler((*Server).slugPublicPage)},
})

// withPathAlias returns routes with a copy of each route under prefix that
// serves the same path under alias, placed after the last route under
// prefix. A copy differs from its route only in its template and example,
// so the two spellings of a path share their method, capability and
// handler and cannot drift apart.
func withPathAlias(prefix, alias string, routes []apiRoute) []apiRoute {
	var copies []apiRoute
	last := -1
	for index, route := range routes {
		if route.Template != prefix && !strings.HasPrefix(route.Template, prefix+"/") {
			continue
		}
		route.Template = alias + strings.TrimPrefix(route.Template, prefix)
		route.Example = alias + strings.TrimPrefix(route.Example, prefix)
		copies = append(copies, route)
		last = index
	}
	result := make([]apiRoute, 0, len(routes)+len(copies))
	result = append(result, routes[:last+1]...)
	result = append(result, copies...)
	return append(result, routes[last+1:]...)
}
