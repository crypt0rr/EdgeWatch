package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// The perimeter routes serve a unit's declared address space and the report
// that compares it with what the unit's monitors scan. They only read and
// change the unit's declarations: nothing here scans, resolves a name, or
// creates, changes or starts a job.

// perimeterRangeNotFound answers an unknown range ID and another unit's
// alike, without naming the ID.
const perimeterRangeNotFound = "perimeter range not found"

// perimeterDeclareRequest is the body of POST /perimeter/seeds.
type perimeterDeclareRequest struct {
	Entries []store.PerimeterEntry `json:"entries"`
}

// perimeterUpdated tells the unit's own streams that its declarations
// changed. The message names no range.
func (s *Server) perimeterUpdated(r *http.Request, ts *store.TenantStore) {
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "perimeter.updated"})
}

// perimeterOverview serves the unit's perimeter report. A store error, or a
// probe budget that cannot be read, fails the request: a partial report is
// never returned.
func (s *Server) perimeterOverview(w http.ResponseWriter, r *http.Request, ts *store.TenantStore) {
	report, err := s.App.PerimeterReport(r.Context(), ts)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// perimeterRangeDetail serves one declared range with its gaps and the
// monitors suggested to fill them.
func (s *Server) perimeterRangeDetail(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, id string) {
	detail, err := s.App.PerimeterRangeDetail(r.Context(), ts, id)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, detail)
	case errors.Is(err, app.ErrProbeBudgetUnavailable):
		// A budget that cannot be read fails the request even when it wraps
		// a unit that is no longer found: the range itself was found.
		s.writeInternalError(w, r, "store", err)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", perimeterRangeNotFound, nil)
	default:
		s.writeInternalError(w, r, "store", err)
	}
}

// declarePerimeterSeeds adds ranges to the unit's perimeter, all or nothing.
// The store validates every entry and writes the audit record in the same
// transaction. Its typed refusals are checked before the general validation
// error, which they also match: the entry count, then the range limit, then
// the refused entries, each listed in details.entries. An audit record that
// cannot be written rolls the declaration back and answers 503
// audit_unavailable, like the job routes.
func (s *Server) declarePerimeterSeeds(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore) {
	var input perimeterDeclareRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	// The store sets the record's action and detail.
	result, err := ts.DeclarePerimeterSeeds(r.Context(), input.Entries, actorAudit(session, "", ""))
	var limitErr *store.PerimeterLimitError
	var validationErr *store.PerimeterValidationError
	switch {
	case err == nil:
	case errors.Is(err, store.ErrPerimeterEntryCount):
		limit := store.MaxPerimeterEntriesPerRequest
		writeError(w, http.StatusBadRequest, "validation_failed", fmt.Sprintf("Declare between 1 and %d entries.", limit), map[string]any{"limit": limit})
		return
	case errors.As(err, &limitErr):
		writeError(w, http.StatusBadRequest, "perimeter_limit", fmt.Sprintf("A business unit holds at most %d perimeter ranges; nothing was saved.", limitErr.Limit), map[string]any{"limit": limitErr.Limit, "held": limitErr.Held, "new": limitErr.New})
		return
	case errors.As(err, &validationErr):
		writeError(w, http.StatusBadRequest, "validation_failed", "Some entries were refused; nothing was saved.", map[string]any{"entries": validationErr.Entries})
		return
	case s.writeAuditUnavailable(w, err, "perimeter.seeds_added"):
		return
	default:
		s.writeInternalError(w, r, "store", err)
		return
	}
	if result.Created > 0 {
		s.perimeterUpdated(r, ts)
	}
	writeJSON(w, http.StatusOK, result)
}

// deletePerimeterSeed removes one of the unit's ranges and records it in the
// audit, in one transaction. It reads no request body. An audit record that
// cannot be written keeps the range and answers 503 audit_unavailable.
func (s *Server) deletePerimeterSeed(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, id string) {
	// The store sets the record's action and detail.
	err := ts.DeletePerimeterSeed(r.Context(), id, actorAudit(session, "", ""))
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", perimeterRangeNotFound, nil)
		return
	case s.writeAuditUnavailable(w, err, "perimeter.seed_removed"):
		return
	default:
		s.writeInternalError(w, r, "store", err)
		return
	}
	s.perimeterUpdated(r, ts)
	writeJSON(w, http.StatusNoContent, nil)
}
