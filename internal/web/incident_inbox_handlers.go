package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request, ts *store.TenantStore) {
	offset, ok := requestOffset(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	serverNow := time.Now().UTC()
	result, err := ts.ListIncidentInbox(r.Context(), store.IncidentInboxFilter{
		View: query.Get("view"), JobID: query.Get("job_id"), OccurrenceToken: query.Get("occurrence_token"), Severity: query.Get("severity"), Kind: query.Get("kind"),
		Limit: queryLimit(r), Offset: offset, Now: serverNow,
	})
	if err != nil {
		if errors.Is(err, store.ErrIncidentReviewInvalid) {
			writeError(w, http.StatusBadRequest, "incident_filter_invalid", "incident filter is invalid", map[string]string{
				"view":             "view must be needs_review, investigating, follow_up_due, or all_active",
				"occurrence_token": "occurrence_token requires job_id",
			})
			return
		}
		s.writeInternalError(w, r, "store", err)
		return
	}
	if result.Items == nil {
		result.Items = []store.IncidentInboxItem{}
	}
	writeJSON(w, http.StatusOK, IncidentInboxPage{
		Incidents: result.Items,
		Pagination: store.IncidentInboxPagination{Limit: result.Limit, Offset: result.Offset, Total: result.Total,
			HasMore: result.HasMore, NextOffset: result.NextOffset},
		Truncated: false, ActiveCount: result.ActiveCount, ServerNow: serverNow, NextFollowUpAt: result.NextFollowUpAt,
	})
}

func (s *Server) incidentInboxSummary(w http.ResponseWriter, r *http.Request, ts *store.TenantStore) {
	count, err := ts.CountActiveIncidents(r.Context())
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	writeJSON(w, http.StatusOK, IncidentInboxSummary{ActiveCount: count})
}

type incidentReviewRequest struct {
	Key              string  `json:"key"`
	OccurrenceToken  string  `json:"occurrence_token"`
	ExpectedRevision int64   `json:"expected_revision"`
	Status           string  `json:"status"`
	Note             string  `json:"note"`
	FollowUpAt       *string `json:"follow_up_at"`
}

func decodeIncidentReview(w http.ResponseWriter, r *http.Request) (store.IncidentReviewWrite, bool) {
	var input incidentReviewRequest
	if !decodeJSON(w, r, &input) {
		return store.IncidentReviewWrite{}, false
	}
	details := map[string]string{}
	if strings.TrimSpace(input.Key) == "" {
		details["key"] = "incident key is required"
	}
	if strings.TrimSpace(input.OccurrenceToken) == "" {
		details["occurrence_token"] = "occurrence token is required"
	}
	if input.ExpectedRevision < 0 {
		details["expected_revision"] = "revision must be zero or greater"
	}
	if input.Status != "needs_review" && input.Status != "investigating" {
		details["status"] = "status must be needs_review or investigating"
	}
	if !utf8.ValidString(input.Note) || len([]byte(input.Note)) > 4096 {
		details["note"] = "note must be valid UTF-8 and at most 4096 bytes"
	}
	var followUpAt *time.Time
	if input.FollowUpAt != nil {
		parsed, err := time.Parse(time.RFC3339Nano, *input.FollowUpAt)
		if err != nil {
			details["follow_up_at"] = "follow-up time must be RFC3339 UTC"
		} else if _, offset := parsed.Zone(); offset != 0 {
			details["follow_up_at"] = "follow-up time must be RFC3339 UTC"
		} else {
			utc := parsed.UTC()
			followUpAt = &utc
		}
	}
	if input.Status == "needs_review" && followUpAt != nil {
		details["follow_up_at"] = "follow-up time must be empty when returning to needs review"
	}
	if len(details) > 0 {
		writeError(w, http.StatusBadRequest, "incident_review_invalid", "incident review is invalid", details)
		return store.IncidentReviewWrite{}, false
	}
	return store.IncidentReviewWrite{Key: input.Key, OccurrenceToken: input.OccurrenceToken, ExpectedRevision: input.ExpectedRevision,
		Status: input.Status, Note: input.Note, FollowUpAt: followUpAt}, true
}

func (s *Server) updateIncidentReview(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, record store.JobRecord) {
	input, ok := decodeIncidentReview(w, r)
	if !ok {
		return
	}
	label := strings.TrimSpace(session.DisplayName)
	if label == "" {
		label = session.Username
	}
	audit := actorAudit(session, "incident.review.updated", "")
	review, err := ts.SaveIncidentReview(r.Context(), record.ID, input, session.UserID, label, audit)
	if err != nil {
		s.writeIncidentReviewError(w, r, err)
		return
	}
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "incident.review.updated", "job_id": record.ID})
	writeJSON(w, http.StatusOK, review)
}

func (s *Server) writeIncidentReviewError(w http.ResponseWriter, r *http.Request, err error) {
	if s.writeAuditUnavailable(w, err, "incident.review.updated") {
		return
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
	case errors.Is(err, store.ErrIncidentNotFound), errors.Is(err, store.ErrIncidentOccurrenceChanged):
		writeError(w, http.StatusConflict, "incident_occurrence_conflict", "the active incident occurrence changed; refresh before retrying", nil)
	case errors.Is(err, store.ErrIncidentReviewRevisionConflict):
		writeError(w, http.StatusConflict, "incident_review_revision_conflict", "the review changed; refresh before retrying", nil)
	case errors.Is(err, store.ErrIncidentReviewInvalid):
		writeError(w, http.StatusBadRequest, "incident_review_invalid", "incident review is invalid", nil)
	default:
		s.writeInternalError(w, r, "store", err)
	}
}
