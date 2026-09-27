package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// The audit views are read-only. A unit's administrators read their unit's
// audit, including a platform administrator's actions on the unit's
// accounts, whose source address the store leaves out. A platform
// administrator reads the platform audit: the records without a unit and
// the account and platform records of every unit, never a unit's data
// records. Both are paged newest first with a keyset: next_before is the
// before parameter of the next page, and null on the last one.

// auditEntryView is one audit record as the API returns it.
type auditEntryView struct {
	ID        int64          `json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	Action    string         `json:"action"`
	Category  string         `json:"category"`
	Actor     auditActorView `json:"actor"`
	Detail    string         `json:"detail"`
	RequestID string         `json:"request_id,omitempty"`
	SourceIP  string         `json:"source_ip,omitempty"`
	// Unit is the unit the record belongs to, in the platform view only;
	// null for a record without a unit.
	Unit *unitRefView `json:"unit,omitempty"`
}

// auditActorView says who acted: kind is unit, platform, host, or system,
// and empty for a record from before business units.
type auditActorView struct {
	Kind        string `json:"kind"`
	UserID      string `json:"user_id,omitempty"`
	Username    string `json:"username,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

// auditPageView is one page of an audit view.
type auditPageView struct {
	Entries    []auditEntryView `json:"entries"`
	NextBefore *int64           `json:"next_before"`
}

// auditPageRequest reads the paging and filter parameters shared by both
// views: before, limit, action (a prefix), since and until (RFC 3339), and
// actor (an account ID). It writes a 400 response and returns false when
// one is malformed.
func auditPageRequest(w http.ResponseWriter, r *http.Request) (store.AuditFilter, int64, int, bool) {
	query := r.URL.Query()
	var filter store.AuditFilter
	var before int64
	var limit int
	invalid := func(field, message string) (store.AuditFilter, int64, int, bool) {
		writeError(w, http.StatusBadRequest, "validation_failed", message, map[string]string{field: message})
		return store.AuditFilter{}, 0, 0, false
	}
	if value := strings.TrimSpace(query.Get("before")); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsed < 1 {
			return invalid("before", "before must be the ID of an audit entry")
		}
		before = parsed
	}
	if value := strings.TrimSpace(query.Get("limit")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > store.AuditPageMaxLimit {
			return invalid("limit", "limit must be between 1 and "+strconv.Itoa(store.AuditPageMaxLimit))
		}
		limit = parsed
	}
	for _, bound := range []struct {
		name   string
		target *time.Time
	}{{"since", &filter.Since}, {"until", &filter.Until}} {
		if value := strings.TrimSpace(query.Get(bound.name)); value != "" {
			parsed, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return invalid(bound.name, bound.name+" must be an RFC 3339 time")
			}
			*bound.target = parsed
		}
	}
	filter.ActionPrefix = strings.TrimSpace(query.Get("action"))
	filter.ActorUserID = strings.TrimSpace(query.Get("actor"))
	return filter, before, limit, true
}

// writeAuditPageError maps a failed page read. A cursor that names no entry
// of the view is not found, whether the entry is unknown or belongs to
// another view.
func (s *Server) writeAuditPageError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrValidation):
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error(), map[string]string{"action": err.Error()})
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "audit entry not found", nil)
	default:
		s.writeInternalError(w, r, "store", err)
	}
}

// auditPageViewOf converts a page. unit, when not nil, names the unit of
// each record for the platform view.
func auditPageViewOf(page store.AuditLogPage, unit func(id string) *unitRefView) auditPageView {
	view := auditPageView{Entries: make([]auditEntryView, 0, len(page.Entries))}
	if page.NextBefore > 0 {
		next := page.NextBefore
		view.NextBefore = &next
	}
	for _, entry := range page.Entries {
		item := auditEntryView{ID: entry.ID, CreatedAt: entry.CreatedAt, Action: entry.Action, Category: entry.Category, Detail: entry.Detail, RequestID: entry.RequestID, SourceIP: entry.SourceIP,
			Actor: auditActorView{Kind: entry.ActorKind, UserID: entry.ActorUserID, Username: entry.ActorUsername, DisplayName: entry.ActorDisplayName}}
		if unit != nil && entry.TenantID != "" {
			item.Unit = unit(entry.TenantID)
		}
		view.Entries = append(view.Entries, item)
	}
	return view
}

// unitAudit serves the unit's own audit to its administrators.
func (s *Server) unitAudit(w http.ResponseWriter, r *http.Request, ts *store.TenantStore) {
	w.Header().Set("Cache-Control", "no-store")
	filter, before, limit, ok := auditPageRequest(w, r)
	if !ok {
		return
	}
	page, err := ts.AuditPage(r.Context(), filter, before, limit)
	if err != nil {
		s.writeAuditPageError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, auditPageViewOf(page, nil))
}

// platformAudit serves the platform audit to platform administrators. The
// unit parameter limits it to one unit's account and platform records.
func (s *Server) platformAudit(w http.ResponseWriter, r *http.Request) {
	filter, before, limit, ok := auditPageRequest(w, r)
	if !ok {
		return
	}
	platform := s.Store.Platform()
	page, err := platform.AuditPage(r.Context(), store.PlatformAuditFilter{AuditFilter: filter, TenantID: strings.TrimSpace(r.URL.Query().Get("unit"))}, before, limit)
	if err != nil {
		s.writeAuditPageError(w, r, err)
		return
	}
	// A page names few units; each is read once, deleted ones included.
	units := map[string]*unitRefView{}
	for _, entry := range page.Entries {
		if entry.TenantID == "" || units[entry.TenantID] != nil {
			continue
		}
		ref := &unitRefView{ID: entry.TenantID}
		if record, err := platform.GetTenant(r.Context(), entry.TenantID); err == nil {
			ref.Name, ref.Slug = record.Name, record.Slug
		}
		units[entry.TenantID] = ref
	}
	writeJSON(w, http.StatusOK, auditPageViewOf(page, func(id string) *unitRefView { return units[id] }))
}
