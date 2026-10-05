package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type notificationPayload struct {
	Name     string  `json:"name"`
	URL      *string `json:"url"`
	Password string  `json:"password"`
	Enabled  *bool   `json:"enabled"`
	Revision *int64  `json:"revision"`
}

// listNotificationDestinations lists the destinations of the session's
// tenant, their status, update alert routing, and incident reminder setting.
// Another tenant's notification settings are never shown.
func (s *Server) listNotificationDestinations(w http.ResponseWriter, r *http.Request, ts *store.TenantStore) {
	w.Header().Set("Cache-Control", "no-store")
	notifier := s.App.Notifier.Tenant(ts)
	current, err := ts.ApplicationUpdateRouting(r.Context())
	if err != nil {
		if s.Log != nil {
			s.Log.Warn("application update routing state unavailable", "error", err)
		}
		writeError(w, http.StatusInternalServerError, "notification_failed", "notification state could not be loaded", nil)
		return
	}
	// Show legacy deployment digests as current selectors. The console
	// drops selectors that are not in the destination list before saving.
	destinations, _, err := notifier.CanonicalSelection(r.Context(), current.Destinations)
	if err != nil {
		if s.Log != nil {
			s.Log.Warn("application update routing destinations unavailable", "error", err)
		}
		writeError(w, http.StatusInternalServerError, "notification_failed", "notification state could not be loaded", nil)
		return
	}
	views, err := notifier.Destinations(r.Context())
	var status map[string]any
	if err == nil {
		status, err = notifier.Status(r.Context())
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "notification_failed", "notification state could not be loaded", nil)
		return
	}
	if destinations == nil {
		destinations = []string{}
	}
	routing := map[string]any{"configured": current.Configured, "destinations": destinations}
	reminderSettings, err := ts.IncidentReminderSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "notification_failed", "incident reminder setting could not be loaded", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"destinations": views, "status": status, "update_routing": routing, "incident_reminders_enabled": reminderSettings.Enabled, "incident_reminder_cadence": reminderSettings.Cadence})
}

type incidentReminderPayload struct {
	Enabled  *bool   `json:"enabled"`
	Cadence  *string `json:"cadence"`
	Password string  `json:"password"`
}

func (s *Server) updateIncidentReminders(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore) {
	w.Header().Set("Cache-Control", "no-store")
	var input incidentReminderPayload
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Enabled == nil && input.Cadence == nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "an incident reminder setting is required", map[string]string{"enabled": "choose whether reminders are enabled or set a cadence"})
		return
	}
	if input.Cadence != nil && !store.ValidIncidentReminderCadence(*input.Cadence) {
		writeError(w, http.StatusBadRequest, "validation_failed", "incident reminder cadence is invalid", map[string]string{"cadence": "choose every scan, hourly, every six hours, or daily"})
		return
	}
	if strings.TrimSpace(input.Password) == "" {
		writeError(w, http.StatusBadRequest, "password_required", "account password confirmation is required", map[string]string{"password": "password confirmation is required"})
		return
	}
	if err := s.Auth.ConfirmPasswordForUser(r.Context(), r, session.UserID, input.Password); err != nil {
		s.writeNotificationAuthError(w, err)
		return
	}
	settings, err := ts.SetIncidentReminderSettings(r.Context(), input.Enabled, input.Cadence, store.AuditEntry{Action: "notifications.incident_reminders_changed", Detail: "incident reminder settings changed", ActorUserID: session.UserID, ActorUsername: session.Username})
	if err != nil {
		if s.writeAuditUnavailable(w, err, "notifications.incident_reminders_changed") {
			return
		}
		writeError(w, http.StatusInternalServerError, "notification", "incident reminder setting could not be saved", nil)
		return
	}
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "notification.changed"})
	writeJSON(w, http.StatusOK, settings)
}

type updateNotificationRoutingPayload struct {
	Destinations []string `json:"destinations"`
	Password     string   `json:"password"`
}

// updateNotificationRouting lets an administrator explicitly choose the
// configured destinations that receive application release/upgrade events.
// A present empty array intentionally disables those notifications; omitting
// the field is rejected so a browser cannot accidentally reset routing.
func (s *Server) updateNotificationRouting(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore) {
	w.Header().Set("Cache-Control", "no-store")
	var input updateNotificationRoutingPayload
	if !decodeJSON(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.Password) == "" {
		writeError(w, http.StatusBadRequest, "password_required", "account password confirmation is required", map[string]string{"password": "password confirmation is required"})
		return
	}
	if err := s.Auth.ConfirmPasswordForUser(r.Context(), r, session.UserID, input.Password); err != nil {
		s.writeNotificationAuthError(w, err)
		return
	}
	if input.Destinations == nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "destinations must be an array", map[string]string{"destinations": "select zero or more configured destinations"})
		return
	}
	s.updateRoutingMu.Lock()
	defer s.updateRoutingMu.Unlock()
	// The routing may select only the tenant's own destinations; another
	// tenant's destination is refused as an unknown one. The store checks
	// the selection again when it writes it.
	if err := s.App.Notifier.Tenant(ts).ValidateDestinationSelection(r.Context(), input.Destinations); err != nil {
		if !writeDestinationSelectionError(w, err) {
			writeError(w, http.StatusInternalServerError, "notification", "notification destinations could not be loaded", nil)
		}
		return
	}
	if err := ts.SetApplicationUpdateDestinations(r.Context(), input.Destinations, store.AuditEntry{Action: "notifications.update_routing", Detail: "application update notification routing changed", ActorUserID: session.UserID, ActorUsername: session.Username}); err != nil {
		if writeDestinationSelectionError(w, err) || s.writeAuditUnavailable(w, err, "notifications.update_routing") {
			return
		}
		writeError(w, http.StatusInternalServerError, "notification", "application update notification routing could not be saved", nil)
		return
	}
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "notification.changed"})
	// Return the normalized, deterministic selector order persisted by the
	// store so the client and any other administrator sessions converge on the
	// same representation.
	destinations := input.Destinations
	if current, err := ts.ApplicationUpdateRouting(r.Context()); err == nil {
		destinations = current.Destinations
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "destinations": destinations})
}

type toggleNotificationUpdateRoutingPayload struct {
	DestinationID string `json:"destination_id"`
	Enabled       *bool  `json:"enabled"`
	Password      string `json:"password"`
}

// toggleNotificationUpdateRouting changes one selector against the latest
// persisted routing, instead of replacing the full list a browser may have
// read before another administrator changed a different destination.
func (s *Server) toggleNotificationUpdateRouting(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore) {
	w.Header().Set("Cache-Control", "no-store")
	var input toggleNotificationUpdateRoutingPayload
	if !decodeJSON(w, r, &input) {
		return
	}
	input.DestinationID = strings.TrimSpace(input.DestinationID)
	if input.DestinationID == "" || input.Enabled == nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "destination_id and enabled are required", map[string]string{"destination_id": "select one configured destination"})
		return
	}
	if strings.TrimSpace(input.Password) == "" {
		writeError(w, http.StatusBadRequest, "password_required", "account password confirmation is required", map[string]string{"password": "password confirmation is required"})
		return
	}
	if err := s.Auth.ConfirmPasswordForUser(r.Context(), r, session.UserID, input.Password); err != nil {
		s.writeNotificationAuthError(w, err)
		return
	}
	s.updateRoutingMu.Lock()
	defer s.updateRoutingMu.Unlock()
	notifier := s.App.Notifier.Tenant(ts)
	if err := notifier.ValidateDestinationSelection(r.Context(), []string{input.DestinationID}); err != nil {
		if !writeDestinationSelectionError(w, err) {
			writeError(w, http.StatusInternalServerError, "notification", "notification destinations could not be loaded", nil)
		}
		return
	}
	current, err := ts.ApplicationUpdateRouting(r.Context())
	if err != nil {
		if s.Log != nil {
			s.Log.Warn("application update routing state unavailable", "error", err)
		}
		writeError(w, http.StatusInternalServerError, "notification_failed", "notification state could not be loaded", nil)
		return
	}
	selection := current.Destinations
	if !current.Configured {
		selection, err = notifier.LegacySelection(r.Context())
		if err != nil {
			if s.Log != nil {
				s.Log.Warn("legacy application update routing unavailable", "error", err)
			}
			writeError(w, http.StatusInternalServerError, "notification_failed", "notification state could not be loaded", nil)
			return
		}
	}
	selection, _, err = notifier.CanonicalSelection(r.Context(), selection)
	if err != nil {
		if s.Log != nil {
			s.Log.Warn("application update routing destinations unavailable", "error", err)
		}
		writeError(w, http.StatusInternalServerError, "notification_failed", "notification state could not be loaded", nil)
		return
	}
	selection = toggleUpdateDestination(selection, input.DestinationID, *input.Enabled)
	if err := ts.SetApplicationUpdateDestinations(r.Context(), selection, store.AuditEntry{Action: "notifications.update_routing", Detail: "application update notification routing changed", ActorUserID: session.UserID, ActorUsername: session.Username}); err != nil {
		if writeDestinationSelectionError(w, err) || s.writeAuditUnavailable(w, err, "notifications.update_routing") {
			return
		}
		writeError(w, http.StatusInternalServerError, "notification", "application update notification routing could not be saved", nil)
		return
	}
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "notification.changed"})
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "destinations": selection})
}

func toggleUpdateDestination(selection []string, destinationID string, enabled bool) []string {
	selected := make(map[string]struct{}, len(selection)+1)
	for _, id := range selection {
		if id = strings.TrimSpace(id); id != "" {
			selected[id] = struct{}{}
		}
	}
	if enabled {
		selected[destinationID] = struct{}{}
	} else {
		delete(selected, destinationID)
	}
	result := make([]string, 0, len(selected))
	for id := range selected {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

// writeDestinationSelectionError answers a routing selection that names a
// destination outside the caller's own with a 400 that repeats the
// selector, and reports whether err was one. The notifier's check and the
// store's check in the routing write refuse with the same error, so both
// get the same answer, and another owner's destination gets the answer of
// an unknown one.
func writeDestinationSelectionError(w http.ResponseWriter, err error) bool {
	if !errors.Is(err, notify.ErrInvalidDestinationSelection) {
		return false
	}
	writeError(w, http.StatusBadRequest, "validation_failed", err.Error(), map[string]string{"destinations": err.Error()})
	return true
}

func (s *Server) createNotificationDestination(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore) {
	w.Header().Set("Cache-Control", "no-store")
	var input notificationPayload
	if !decodeJSON(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.Password) == "" {
		writeError(w, http.StatusBadRequest, "password_required", "account password confirmation is required", map[string]string{"password": "password confirmation is required"})
		return
	}
	if err := s.Auth.ConfirmPasswordForUser(r.Context(), r, session.UserID, input.Password); err != nil {
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
	view, err := s.App.Notifier.Tenant(ts).CreateManagedWithAudit(r.Context(), input.Name, *input.URL, enabled, store.AuditEntry{Action: "notifications.created", Detail: "managed notification created", ActorUserID: session.UserID, ActorUsername: session.Username})
	if err != nil {
		if s.writeAuditUnavailable(w, err, "notifications.created") {
			return
		}
		s.writeNotificationError(w, err)
		return
	}
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "notification.changed", "notification_id": view.ID})
	writeJSON(w, http.StatusCreated, view)
}

func (s *Server) notificationDestinationRoute(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, rest string) {
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "not_found", "notification destination not found", nil)
		return
	}
	id := parts[0]
	if len(parts) == 2 && parts[1] == "test" && r.Method == http.MethodPost {
		w.Header().Set("Cache-Control", "no-store")
		if !s.allowNotificationTest(r, id) {
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "notification tests are temporarily rate limited", nil)
			return
		}
		if err := s.App.Notifier.Tenant(ts).TestDestination(r.Context(), id); err != nil {
			s.auditOptionalEntry(r.Context(), ts, store.AuditEntry{Action: "notifications.test_failed", Detail: "managed notification test failed: " + id, ActorUserID: session.UserID, ActorUsername: session.Username})
			s.writeNotificationError(w, err)
			return
		}
		if !s.requireAuditEntry(r.Context(), w, ts, store.AuditEntry{Action: "notifications.test", Detail: "managed notification tested: " + id, ActorUserID: session.UserID, ActorUsername: session.Username}) {
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
		view, err := s.App.Notifier.Tenant(ts).Destination(r.Context(), id)
		if err != nil {
			s.writeNotificationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, view)
	case http.MethodPut:
		s.updateNotificationDestination(w, r, session, ts, id)
	case http.MethodDelete:
		s.deleteNotificationDestination(w, r, session, ts, id)
	default:
		writeError(w, http.StatusNotFound, "not_found", "notification destination endpoint not found", nil)
	}
}

func (s *Server) updateNotificationDestination(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, id string) {
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
		writeError(w, http.StatusBadRequest, "password_required", "account password confirmation is required", map[string]string{"password": "password confirmation is required"})
		return
	}
	if err := s.Auth.ConfirmPasswordForUser(r.Context(), r, session.UserID, input.Password); err != nil {
		s.writeNotificationAuthError(w, err)
		return
	}
	view, err := s.App.Notifier.Tenant(ts).UpdateManagedWithAudit(r.Context(), id, *input.Revision, input.Name, input.URL, input.Enabled, store.AuditEntry{Action: "notifications.updated", Detail: "managed notification updated: " + id, ActorUserID: session.UserID, ActorUsername: session.Username})
	if err != nil {
		if s.writeAuditUnavailable(w, err, "notifications.updated") {
			return
		}
		s.writeNotificationError(w, err)
		return
	}
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "notification.changed", "notification_id": id})
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) deleteNotificationDestination(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, id string) {
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
		writeError(w, http.StatusBadRequest, "password_required", "account password confirmation is required", map[string]string{"password": "password confirmation is required"})
		return
	}
	if err := s.Auth.ConfirmPasswordForUser(r.Context(), r, session.UserID, input.Password); err != nil {
		s.writeNotificationAuthError(w, err)
		return
	}
	changedJobs, err := s.App.Notifier.Tenant(ts).DeleteManagedWithAudit(r.Context(), id, *input.Revision, store.AuditEntry{Action: "notifications.deleted", Detail: "managed notification deleted: " + id, ActorUserID: session.UserID, ActorUsername: session.Username})
	if err != nil {
		if s.writeAuditUnavailable(w, err, "notifications.deleted") {
			return
		}
		s.writeNotificationError(w, err)
		return
	}
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "notification.changed", "notification_id": id})
	// The delete also removed the destination from these jobs' routing and
	// gave each a new revision. Let open editors reload before they save.
	for _, jobID := range changedJobs {
		s.broadcastTo(r.Context(), audienceTenant(ts), map[string]any{"type": "job.updated", "job_id": jobID})
	}
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

func (s *Server) writePasswordConfirmationError(w http.ResponseWriter, err error, message string) {
	if errors.Is(err, auth.ErrRateLimited) {
		w.Header().Set("Retry-After", "300")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many password confirmation attempts; try again later", nil)
		return
	}
	writeError(w, http.StatusBadRequest, "invalid_password", message, nil)
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
	case errors.Is(err, store.ErrDeliveryProvider), strings.Contains(lower, "notification delivery failed"):
		// A managed destination test reached the provider, but the provider
		// rejected or could not deliver the message. Report this as a bad
		// gateway so clients can distinguish destination failures from an
		// EdgeWatch configuration/server error (500).
		writeError(w, http.StatusBadGateway, "notification_failed", "notification destination delivery failed", nil)
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

// allowNotificationTest rate-limits each destination independently. A failed
// test for one provider must not temporarily block an operator from checking a
// different configured channel. The optional scope is a stable destination ID
// (or "all" for the aggregate endpoint), never a URL or credential-bearing
// value; keeping it variadic preserves source compatibility for internal
// callers that use the historical global bucket.
func (s *Server) allowNotificationTest(r *http.Request, destination ...string) bool {
	key := s.clientIP(r)
	if cookie, err := r.Cookie(auth.SessionCookie); err == nil && cookie.Value != "" {
		key = digest(cookie.Value)
	}
	scope := "all"
	if len(destination) > 0 && strings.TrimSpace(destination[0]) != "" {
		scope = strings.TrimSpace(destination[0])
	}
	key += "\x00" + scope
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

func (s *Server) clientIP(r *http.Request) string {
	if s.Auth != nil {
		return s.Auth.ClientIP(r)
	}
	if r == nil {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func (s *Server) notificationTest(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore) {
	if !s.allowNotificationTest(r, "all") {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "notification tests are temporarily rate limited", nil)
		return
	}
	summary, err := s.App.Notifier.Tenant(ts).TestSummary(r.Context())
	if err != nil {
		// Shoutrrr implementations may include destination details in an error;
		// keep those credentials out of both API responses and logs.
		s.auditOptionalEntry(r.Context(), ts, store.AuditEntry{Action: "notifications.test_failed", Detail: "configured destination test failed", ActorUserID: session.UserID, ActorUsername: session.Username})
		if errors.Is(err, notify.ErrManagedNotificationLocked) {
			writeError(w, http.StatusServiceUnavailable, "notification_key_unavailable", "one or more web-managed notification destinations are locked; restore the notification encryption key and test again", nil)
			return
		}
		writeError(w, http.StatusBadGateway, "notification_failed", "one or more notification destinations failed", nil)
		return
	}
	if !s.requireAuditEntry(r.Context(), w, ts, store.AuditEntry{Action: "notifications.test", Detail: "configured destinations tested", ActorUserID: session.UserID, ActorUsername: session.Username}) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sent": summary.Tested})
}
