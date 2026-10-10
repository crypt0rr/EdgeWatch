package web

import (
	"context"
	"net/http"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// The security and deployment alert routing. A unit's administrators choose
// which of the unit's web-managed destinations receive its security alerts;
// platform administrators choose which platform destinations receive the
// platform's security alerts and the deployment-health alerts. Each routing
// starts empty, so the alerts are opt-in. A PUT replaces a routing and a
// PATCH turns one destination on or off against the latest saved routing;
// both need the account password. The store checks every ID in the write's
// transaction, so another owner's destination is refused as an unknown one.

// writeAlertRouting answers a routing change with the saved routing.
func writeAlertRouting(w http.ResponseWriter, destinations []string) {
	writeJSON(w, http.StatusOK, alertRoutingView(destinations))
}

// alertRoutingView is a routing as the destination lists report it.
func alertRoutingView(destinations []string) map[string]any {
	if destinations == nil {
		destinations = []string{}
	}
	return map[string]any{"configured": true, "destinations": destinations}
}

// decodeAlertRoutingToggle reads and checks a PATCH of a routing.
func decodeAlertRoutingToggle(w http.ResponseWriter, r *http.Request) (toggleNotificationUpdateRoutingPayload, bool) {
	var input toggleNotificationUpdateRoutingPayload
	if !decodeJSON(w, r, &input) {
		return input, false
	}
	input.DestinationID = strings.TrimSpace(input.DestinationID)
	if input.DestinationID == "" || input.Enabled == nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "destination_id and enabled are required", map[string]string{"destination_id": "select one configured destination"})
		return input, false
	}
	return input, true
}

// updateSecurityRouting replaces the unit's security alert routing. An empty
// array turns the unit's security alerts off; omitting the field is
// refused.
func (s *Server) updateSecurityRouting(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore) {
	w.Header().Set("Cache-Control", "no-store")
	var input updateNotificationRoutingPayload
	if !decodeJSON(w, r, &input) || !s.confirmNotificationPassword(w, r, session, input.Password) {
		return
	}
	if input.Destinations == nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "destinations must be an array", map[string]string{"destinations": "select zero or more web-managed destinations"})
		return
	}
	s.updateRoutingMu.Lock()
	defer s.updateRoutingMu.Unlock()
	s.saveSecurityRouting(w, r, session, ts, input.Destinations)
}

// toggleSecurityRouting turns one destination of the unit's security alert
// routing on or off.
func (s *Server) toggleSecurityRouting(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore) {
	w.Header().Set("Cache-Control", "no-store")
	input, ok := decodeAlertRoutingToggle(w, r)
	if !ok || !s.confirmNotificationPassword(w, r, session, input.Password) {
		return
	}
	s.updateRoutingMu.Lock()
	defer s.updateRoutingMu.Unlock()
	current, err := ts.SecurityAlertRouting(r.Context())
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	s.saveSecurityRouting(w, r, session, ts, toggleUpdateDestination(current, input.DestinationID, *input.Enabled))
}

// saveSecurityRouting writes the unit's security alert routing and answers
// with it.
func (s *Server) saveSecurityRouting(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, destinations []string) {
	if err := ts.SetSecurityAlertDestinations(r.Context(), destinations, actorAudit(session, "", "security alert routing changed")); err != nil {
		if writeDestinationSelectionError(w, err) || s.writeAuditUnavailable(w, err, "notifications.security_routing") {
			return
		}
		writeError(w, http.StatusInternalServerError, "notification", "security alert routing could not be saved", nil)
		return
	}
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "notification.changed"})
	saved, err := ts.SecurityAlertRouting(r.Context())
	if err != nil {
		saved = destinations
	}
	writeAlertRouting(w, saved)
}

// The platform's alert routings, by the last segment of their path.
const (
	platformSecurityRouting = "security-routing"
	platformHealthRouting   = "health-routing"
)

// updatePlatformAlertRouting replaces the platform's security or deployment
// alert routing, which kind names.
func (s *Server) updatePlatformAlertRouting(w http.ResponseWriter, r *http.Request, session store.Session, kind string) {
	var input updateNotificationRoutingPayload
	if !decodeJSON(w, r, &input) || !s.confirmNotificationPassword(w, r, session, input.Password) {
		return
	}
	if input.Destinations == nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "destinations must be an array", map[string]string{"destinations": "select zero or more platform destinations"})
		return
	}
	s.updateRoutingMu.Lock()
	defer s.updateRoutingMu.Unlock()
	s.savePlatformAlertRouting(w, r, session, kind, input.Destinations)
}

// togglePlatformAlertRouting turns one platform destination of the
// platform's security or deployment alert routing on or off.
func (s *Server) togglePlatformAlertRouting(w http.ResponseWriter, r *http.Request, session store.Session, kind string) {
	input, ok := decodeAlertRoutingToggle(w, r)
	if !ok || !s.confirmNotificationPassword(w, r, session, input.Password) {
		return
	}
	s.updateRoutingMu.Lock()
	defer s.updateRoutingMu.Unlock()
	routing, err := s.Store.Platform().PlatformAlertRouting(r.Context())
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	current := routing.Security
	if kind == platformHealthRouting {
		current = routing.Health
	}
	s.savePlatformAlertRouting(w, r, session, kind, toggleUpdateDestination(current, input.DestinationID, *input.Enabled))
}

// savePlatformAlertRouting writes one of the platform's alert routings and
// answers with it.
func (s *Server) savePlatformAlertRouting(w http.ResponseWriter, r *http.Request, session store.Session, kind string, destinations []string) {
	platform := s.Store.Platform()
	write, action, detail := platform.SetPlatformSecurityAlertDestinations, "platform_notifications.security_routing", "platform security alert routing changed"
	if kind == platformHealthRouting {
		write, action, detail = platform.SetPlatformHealthAlertDestinations, "platform_notifications.health_routing", "deployment alert routing changed"
	}
	if err := write(r.Context(), destinations, platformActorAudit(session, "", detail)); err != nil {
		if !writeDestinationSelectionError(w, err) {
			s.writePlatformError(w, r, err, action, "notification destination not found")
		}
		return
	}
	saved := destinations
	if routing, err := platform.PlatformAlertRouting(r.Context()); err == nil {
		saved = routing.Security
		if kind == platformHealthRouting {
			saved = routing.Health
		}
	}
	writeAlertRouting(w, saved)
}
