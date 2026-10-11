package web

import "github.com/crypt0rr/edgewatch/internal/store"

// IncidentInboxPage is the paginated response from GET /api/v1/incidents.
// ActiveCount is independent of the current page and filters.
type IncidentInboxPage struct {
	Incidents   []store.IncidentInboxItem     `json:"incidents"`
	Pagination  store.IncidentInboxPagination `json:"pagination"`
	Truncated   bool                          `json:"truncated"`
	ActiveCount int                           `json:"active_count"`
}
