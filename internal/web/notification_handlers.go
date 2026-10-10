package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type notificationPayload struct {
	Name     string                 `json:"name"`
	URL      *string                `json:"url"`
	Config   *notify.ProviderConfig `json:"config"`
	Password string                 `json:"password"`
	Enabled  *bool                  `json:"enabled"`
	Revision *int64                 `json:"revision"`
	// KeepPending moves the destination's queued alerts to the replacement
	// credentials instead of discarding them. It applies only to an update
	// that replaces the credentials.
	KeepPending bool `json:"keep_pending"`
}

func notificationDestinationURL(rawURL *string, providerConfig *notify.ProviderConfig, required bool) (*string, error) {
	if rawURL != nil && providerConfig != nil {
		return nil, notify.ErrInvalidProviderConfiguration
	}
	if providerConfig != nil {
		compiled, err := notify.CompileProviderConfig(*providerConfig)
		if err != nil {
			return nil, err
		}
		return &compiled, nil
	}
	if rawURL == nil && required {
		return nil, errors.New("notification URL is required")
	}
	return rawURL, nil
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
	var status notify.Status
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
	if err := notifier.ValidateDestinationSelection(r.Context(), []string{input.DestinationID}); err != nil {
		if !writeDestinationSelectionError(w, err) {
			writeError(w, http.StatusInternalServerError, "notification", "notification destinations could not be loaded", nil)
		}
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
	rawURL, err := notificationDestinationURL(input.URL, input.Config, true)
	if err != nil {
		s.writeNotificationError(w, err)
		return
	}
	view, err := s.App.Notifier.Tenant(ts).CreateManagedWithAudit(r.Context(), input.Name, *rawURL, enabled, store.AuditEntry{Action: "notifications.created", Detail: "managed notification created", ActorUserID: session.UserID, ActorUsername: session.Username})
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

// testNotificationDestination serves POST
// /notifications/destinations/{id}/test: it sends a test notification
// through the destination, within the notification test rate limit.
func (s *Server) testNotificationDestination(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, id string) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.allowNotificationTest(r) {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "notification tests are temporarily rate limited", nil)
		return
	}
	if err := s.App.Notifier.Tenant(ts).TestDestination(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeNotificationError(w, err)
			return
		}
		s.auditOptionalEntry(r.Context(), ts, store.AuditEntry{Action: "notifications.test_failed", Detail: "managed notification test failed: " + id, ActorUserID: session.UserID, ActorUsername: session.Username})
		s.writeNotificationError(w, err)
		return
	}
	if !s.requireAuditEntry(r.Context(), w, ts, store.AuditEntry{Action: "notifications.test", Detail: "managed notification tested: " + id, ActorUserID: session.UserID, ActorUsername: session.Username}) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sent": 1})
}

// getNotificationDestination serves GET /notifications/destinations/{id},
// the destination without its URL.
func (s *Server) getNotificationDestination(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, id string) {
	w.Header().Set("Cache-Control", "no-store")
	view, err := s.App.Notifier.Tenant(ts).Destination(r.Context(), id)
	if err != nil {
		s.writeNotificationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
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
	rawURL, err := notificationDestinationURL(input.URL, input.Config, false)
	if err != nil {
		s.writeNotificationError(w, err)
		return
	}
	audit := store.AuditEntry{Action: "notifications.updated", Detail: "managed notification updated: " + id, ActorUserID: session.UserID, ActorUsername: session.Username}
	notifier := s.App.Notifier.Tenant(ts)
	var view notify.DestinationView
	if input.KeepPending {
		view, err = notifier.UpdateManagedKeepingPendingWithAudit(r.Context(), id, *input.Revision, input.Name, rawURL, input.Enabled, audit)
	} else {
		view, err = notifier.UpdateManagedWithAudit(r.Context(), id, *input.Revision, input.Name, rawURL, input.Enabled, audit)
	}
	if err != nil {
		if s.writeAuditUnavailable(w, err, "notifications.updated") {
			return
		}
		s.writeNotificationError(w, err)
		return
	}
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "notification.changed", "notification_id": id})
	if input.KeepPending && rawURL != nil {
		// The kept alerts are due at once.
		s.App.WakeDelivery()
	}
	writeJSON(w, http.StatusOK, view)
}

// terminalDeliveryPageSize is the default page of the terminal delivery list.
const terminalDeliveryPageSize = 50

// listTerminalDeliveries lists, newest first, the alerts that one of the
// unit's destinations dropped for good and that a redelivery would send
// again: their metadata only, never a message, URL, or provider text. Pass
// next_before as before for the next page. Another unit's destination is
// 404, as an unknown one is.
func (s *Server) listTerminalDeliveries(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, id string) {
	w.Header().Set("Cache-Control", "no-store")
	query := r.URL.Query()
	if state := query.Get("state"); state != "" && state != "terminal" {
		writeError(w, http.StatusBadRequest, "validation_failed", "only terminal deliveries can be listed", map[string]string{"state": "use terminal"})
		return
	}
	limit := terminalDeliveryPageSize
	if raw := query.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > store.MaxTerminalDeliveriesPage {
			writeError(w, http.StatusBadRequest, "validation_failed", "limit must be between 1 and 100", map[string]string{"limit": "use 1 to 100"})
			return
		}
		limit = parsed
	}
	var before int64
	if raw := query.Get("before"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 1 {
			writeError(w, http.StatusBadRequest, "validation_failed", "before must be a delivery ID", map[string]string{"before": "use next_before from the previous page"})
			return
		}
		before = parsed
	}
	// One more than the page shows whether another page follows.
	deliveries, err := s.App.Notifier.Tenant(ts).TerminalDeliveries(r.Context(), id, before, limit+1)
	if err != nil {
		s.writeNotificationError(w, err)
		return
	}
	var next any
	if len(deliveries) > limit {
		deliveries = deliveries[:limit]
		next = deliveries[limit-1].ID
	}
	items := make([]map[string]any, 0, len(deliveries))
	for _, delivery := range deliveries {
		item := map[string]any{"id": delivery.ID, "event_type": delivery.EventType, "attempts": delivery.Attempts, "deferrals": delivery.Deferrals, "error_code": delivery.ErrorCode, "terminal_at": delivery.TerminalAt.UTC().Format(time.RFC3339Nano)}
		if delivery.Job != "" {
			item["job"] = delivery.Job
		}
		if !delivery.EventAt.IsZero() {
			item["event_at"] = delivery.EventAt.UTC().Format(time.RFC3339Nano)
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"deliveries": items, "next_before": next})
}

type redeliverPayload struct {
	// DeliveryIDs names the deliveries to queue again; omitted, every
	// terminal delivery of the destination is.
	DeliveryIDs []int64 `json:"delivery_ids"`
}

// redeliverTerminalDeliveries queues again the alerts that one of the unit's
// destinations dropped for good, or those of them that delivery_ids names,
// for the destination's current URL, and records the count in the unit's
// audit. Another unit's destination is 404, as an unknown one is, and
// nothing changes.
func (s *Server) redeliverTerminalDeliveries(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, id string) {
	w.Header().Set("Cache-Control", "no-store")
	var input redeliverPayload
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.DeliveryIDs != nil && len(input.DeliveryIDs) == 0 {
		writeError(w, http.StatusBadRequest, "validation_failed", "delivery_ids must name at least one delivery", map[string]string{"delivery_ids": "omit delivery_ids to redeliver every failed alert"})
		return
	}
	if len(input.DeliveryIDs) > store.MaxTerminalDeliveriesPage {
		writeError(w, http.StatusBadRequest, "validation_failed", "delivery_ids may name at most 100 deliveries", map[string]string{"delivery_ids": "redeliver at most 100 deliveries at once"})
		return
	}
	count, err := s.App.Notifier.Tenant(ts).RedeliverTerminalDeliveries(r.Context(), id, input.DeliveryIDs, store.AuditEntry{Action: "notifications.redelivered", ActorUserID: session.UserID, ActorUsername: session.Username})
	if err != nil {
		if s.writeAuditUnavailable(w, err, "notifications.redelivered") {
			return
		}
		s.writeNotificationError(w, err)
		return
	}
	if count > 0 {
		s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "notification.changed", "notification_id": id})
		s.App.WakeDelivery()
	}
	writeJSON(w, http.StatusOK, map[string]any{"redelivered": count})
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
		w.Header().Set("Retry-After", auth.RetryAfterHeaderValue(err))
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many password confirmation attempts; try again later", nil)
		return
	}
	writeError(w, http.StatusUnauthorized, "invalid_password", "password confirmation failed", nil)
}

func (s *Server) writePasswordConfirmationError(w http.ResponseWriter, err error, message string) {
	if errors.Is(err, auth.ErrRateLimited) {
		w.Header().Set("Retry-After", auth.RetryAfterHeaderValue(err))
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many password confirmation attempts; try again later", nil)
		return
	}
	writeError(w, http.StatusBadRequest, "invalid_password", message, nil)
}

func (s *Server) writeNotificationError(w http.ResponseWriter, err error) {
	lower := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, notify.ErrInvalidProviderConfiguration):
		writeError(w, http.StatusBadRequest, "validation_failed", "notification provider configuration is invalid", map[string]string{"config": "check the selected provider and its required fields"})
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", "notification was modified; reload before saving", nil)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "notification destination not found", nil)
	case errors.Is(err, notify.ErrManagedNotificationLocked), errors.Is(err, notify.ErrKeyUnavailable), errors.Is(err, notify.ErrKeyInvalid), errors.Is(err, notify.ErrKeyPermissions):
		writeError(w, http.StatusServiceUnavailable, "notification_key_unavailable", "managed notification credentials are unavailable; restore the encryption key before replacing or enabling this destination", nil)
	case errors.Is(err, notify.ErrDestinationExcluded):
		// The message is fixed: it names neither the URL nor the address.
		const message = "notification URL points to an address that this deployment does not allow"
		writeError(w, http.StatusBadRequest, "validation_failed", message, map[string]string{"url": "use a destination outside scanner.target_exclusions and the loopback, link-local, and unspecified addresses"})
	case errors.Is(err, notify.ErrNotificationSendIndeterminate), errors.Is(err, context.DeadlineExceeded):
		// A test that the provider did not answer in time saved nothing,
		// and the provider may still deliver the message.
		writeError(w, http.StatusGatewayTimeout, "notification_timeout", "the destination did not answer in time; the message may still arrive", nil)
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

// allowNotificationTest rate-limits by session, or by resolved client address
// when no session cookie is available. Destination IDs must not participate in
// the key because arbitrary IDs would let callers bypass the limit and grow the
// in-memory map without bound.
func (s *Server) allowNotificationTest(r *http.Request) bool {
	key := s.clientIP(r)
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

// rateLimitIdentity returns the client identity under which the anonymous
// rate limits count the request, the client address with an IPv6 network
// grouped as the sign-in limits group it; see auth.Manager.RateLimitIdentity.
func (s *Server) rateLimitIdentity(r *http.Request) string {
	if s.Auth != nil {
		return s.Auth.RateLimitIdentity(r)
	}
	return s.clientIP(r)
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
	if !s.allowNotificationTest(r) {
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
