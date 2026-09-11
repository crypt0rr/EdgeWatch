package web

import (
	"errors"
	"net"
	"net/http"
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

func (s *Server) listNotificationDestinations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := s.App.Notifier.Reload(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "notification_failed", "notification state could not be loaded", nil)
		return
	}
	routing := map[string]any{"configured": false, "destinations": []string{}}
	if state, err := s.Store.GetApplicationUpdateState(r.Context()); err == nil {
		destinations := state.UpdateNotificationDestinations
		if destinations == nil {
			destinations = []string{}
		}
		routing = map[string]any{"configured": state.UpdateNotificationDestinationsConfigured, "destinations": destinations}
	} else {
		if s.Log != nil {
			s.Log.Warn("application update routing state unavailable", "error", err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"destinations": s.App.Notifier.DestinationsContext(r.Context()), "status": s.App.Notifier.StatusContext(r.Context()), "update_routing": routing})
}

type updateNotificationRoutingPayload struct {
	Destinations []string `json:"destinations"`
	Password     string   `json:"password"`
}

// updateNotificationRouting lets an administrator explicitly choose the
// configured destinations that receive application release/upgrade events.
// A present empty array intentionally disables those notifications; omitting
// the field is rejected so a browser cannot accidentally reset routing.
func (s *Server) updateNotificationRouting(w http.ResponseWriter, r *http.Request, session store.Session) {
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
	if err := s.App.Notifier.ValidateDestinationSelection(r.Context(), input.Destinations); err != nil {
		if errors.Is(err, notify.ErrInvalidDestinationSelection) {
			writeError(w, http.StatusBadRequest, "validation_failed", err.Error(), map[string]string{"destinations": err.Error()})
		} else {
			writeError(w, http.StatusInternalServerError, "notification", "notification destinations could not be loaded", nil)
		}
		return
	}
	if err := s.Store.SetApplicationUpdateDestinations(r.Context(), input.Destinations, store.AuditEntry{Action: "notifications.update_routing", Detail: "application update notification routing changed", ActorUserID: session.UserID, ActorUsername: session.Username}); err != nil {
		if s.writeAuditUnavailable(w, err, "notifications.update_routing") {
			return
		}
		writeError(w, http.StatusInternalServerError, "notification", "application update notification routing could not be saved", nil)
		return
	}
	s.broadcast(map[string]any{"type": "notification.changed"})
	// Return the normalized, deterministic selector order persisted by the
	// store so the client and any other administrator sessions converge on the
	// same representation.
	destinations := input.Destinations
	if state, err := s.Store.GetApplicationUpdateState(r.Context()); err == nil {
		destinations = state.UpdateNotificationDestinations
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "destinations": destinations})
}

func (s *Server) createNotificationDestination(w http.ResponseWriter, r *http.Request, session store.Session) {
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
	view, err := s.App.Notifier.CreateManagedWithAudit(r.Context(), input.Name, *input.URL, enabled, store.AuditEntry{Action: "notifications.created", Detail: "managed notification created", ActorUserID: session.UserID, ActorUsername: session.Username})
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

func (s *Server) notificationDestinationRoute(w http.ResponseWriter, r *http.Request, session store.Session, rest string) {
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
		if err := s.App.Notifier.TestDestinationContext(r.Context(), id); err != nil {
			s.auditOptionalEntry(r.Context(), store.AuditEntry{Action: "notifications.test_failed", Detail: "managed notification test failed: " + id, ActorUserID: session.UserID, ActorUsername: session.Username})
			s.writeNotificationError(w, err)
			return
		}
		if !s.requireAuditEntry(r.Context(), w, store.AuditEntry{Action: "notifications.test", Detail: "managed notification tested: " + id, ActorUserID: session.UserID, ActorUsername: session.Username}) {
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
		s.updateNotificationDestination(w, r, session, id)
	case http.MethodDelete:
		s.deleteNotificationDestination(w, r, session, id)
	default:
		writeError(w, http.StatusNotFound, "not_found", "notification destination endpoint not found", nil)
	}
}

func (s *Server) updateNotificationDestination(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
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
	view, err := s.App.Notifier.UpdateManagedWithAudit(r.Context(), id, *input.Revision, input.Name, input.URL, input.Enabled, store.AuditEntry{Action: "notifications.updated", Detail: "managed notification updated: " + id, ActorUserID: session.UserID, ActorUsername: session.Username})
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

func (s *Server) deleteNotificationDestination(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
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
	if err := s.App.Notifier.DeleteManagedWithAudit(r.Context(), id, *input.Revision, store.AuditEntry{Action: "notifications.deleted", Detail: "managed notification deleted: " + id, ActorUserID: session.UserID, ActorUsername: session.Username}); err != nil {
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

func (s *Server) notificationTest(w http.ResponseWriter, r *http.Request, session store.Session) {
	if !s.allowNotificationTest(r, "all") {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "notification tests are temporarily rate limited", nil)
		return
	}
	if err := s.App.Notifier.TestContext(r.Context()); err != nil {
		// Shoutrrr implementations may include destination details in an error;
		// keep those credentials out of both API responses and logs.
		s.auditOptionalEntry(r.Context(), store.AuditEntry{Action: "notifications.test_failed", Detail: "configured destination test failed", ActorUserID: session.UserID, ActorUsername: session.Username})
		writeError(w, http.StatusBadGateway, "notification_failed", "one or more notification destinations failed", nil)
		return
	}
	if !s.requireAuditEntry(r.Context(), w, store.AuditEntry{Action: "notifications.test", Detail: "configured destinations tested", ActorUserID: session.UserID, ActorUsername: session.Username}) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sent": s.App.Notifier.ActiveCount()})
}
