package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type createChangeWindowRequest struct {
	StartNow *bool  `json:"start_now"`
	StartAt  string `json:"start_at"`
	EndAt    string `json:"end_at"`
	Reason   string `json:"reason"`
}

type cancelChangeWindowRequest struct {
	WindowID string `json:"window_id"`
}

type reviewChangeWindowRequest struct {
	WindowID string `json:"window_id"`
	Revision int64  `json:"revision"`
}

func (s *Server) listChangeWindows(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, job store.JobRecord) {
	windows, err := ts.ListChangeWindows(r.Context(), job.ID)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	for i := range windows {
		// The history endpoint stays bounded to metadata. The summary endpoint
		// loads evidence for one selected window and applies incidents.read.
		windows[i].Summary = nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"windows": windows})
}

func (s *Server) getChangeWindow(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, job store.JobRecord, windowID string) {
	window, err := ts.GetChangeWindow(r.Context(), job.ID, windowID)
	if err != nil {
		s.writeChangeWindowError(w, r, err)
		return
	}
	if !auth.HasPermission(session, auth.PermissionIncidentsRead) {
		window.Summary = nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"window": window})
}

func (s *Server) createChangeWindow(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, job store.JobRecord) {
	var input createChangeWindowRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.StartNow == nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "start_now is required", map[string]string{"start_now": "start_now is required"})
		return
	}
	var startAt time.Time
	var err error
	if !*input.StartNow {
		startAt, err = time.Parse(time.RFC3339Nano, strings.TrimSpace(input.StartAt))
		if err != nil {
			writeError(w, http.StatusBadRequest, "validation_failed", "start_at must include a UTC offset", map[string]string{"start_at": "start_at must include a UTC offset"})
			return
		}
	} else if strings.TrimSpace(input.StartAt) != "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "start_at must be empty when start_now is true", map[string]string{"start_at": "start_at must be empty when start_now is true"})
		return
	}
	endAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(input.EndAt))
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "end_at must include a UTC offset", map[string]string{"end_at": "end_at must include a UTC offset"})
		return
	}
	window, err := ts.CreateChangeWindow(r.Context(), job.ID, startAt, endAt, *input.StartNow, input.Reason, session.UserID, session.Username)
	if err != nil {
		s.writeChangeWindowError(w, r, err)
		return
	}
	s.broadcastTo(r.Context(), audienceTenant(ts), map[string]any{"type": "change-window.updated", "job_id": job.ID, "window_id": window.ID})
	writeJSON(w, http.StatusCreated, map[string]any{"window": window})
}

func (s *Server) cancelChangeWindow(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, job store.JobRecord) {
	var input cancelChangeWindowRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.WindowID) == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "window_id is required", map[string]string{"window_id": "window_id is required"})
		return
	}
	destinations := []string{}
	if notifier := s.tenantNotifier(ts); notifier != nil {
		selected, err := notifier.QueueDestinationsForJob(r.Context(), job.Job)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "notification", "notification destinations could not be loaded", nil)
			return
		}
		destinations = selected
	}
	window, changed, err := ts.CancelChangeWindow(r.Context(), job.ID, input.WindowID, session.UserID, session.Username, destinations, actorAudit(session, "change_window.cancelled", ""))
	if err != nil {
		s.writeChangeWindowError(w, r, err)
		return
	}
	if !changed {
		writeError(w, http.StatusConflict, "conflict", "change window is already closed", nil)
		return
	}
	if s.App != nil {
		s.App.WakeDelivery()
	}
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "change-window.updated", "job_id": job.ID, "window_id": window.ID})
	if !auth.HasPermission(session, auth.PermissionIncidentsRead) {
		window.Summary = nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"window": window})
}

func (s *Server) reviewChangeWindow(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, job store.JobRecord) {
	var input reviewChangeWindowRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.WindowID) == "" || input.Revision < 1 {
		writeError(w, http.StatusBadRequest, "validation_failed", "window_id and a positive revision are required", map[string]string{"window_id": "window_id and a positive revision are required"})
		return
	}
	window, err := ts.ReviewChangeWindow(r.Context(), job.ID, input.WindowID, input.Revision, session.UserID, session.Username, actorAudit(session, "change_window.reviewed", ""))
	if err != nil {
		s.writeChangeWindowError(w, r, err)
		return
	}
	if !auth.HasPermission(session, auth.PermissionIncidentsRead) {
		window.Summary = nil
	}
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "change-window.updated", "job_id": job.ID, "window_id": window.ID})
	writeJSON(w, http.StatusOK, map[string]any{"window": window})
}

func (s *Server) writeChangeWindowError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "change window not found", nil)
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", "change window conflicts with current state", nil)
	case errors.Is(err, store.ErrValidation):
		writeValidationError(w, err)
	case s.writeAuditUnavailable(w, err, "change_window"):
		return
	default:
		s.writeInternalError(w, r, "store", err)
	}
}
