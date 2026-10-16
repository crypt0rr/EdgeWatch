package web

import (
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// IncidentInboxPage is the paginated response from GET /api/v1/incidents.
// ActiveCount is independent of the current page and filters.
type IncidentInboxPage struct {
	Incidents      []store.IncidentInboxItem     `json:"incidents"`
	Pagination     store.IncidentInboxPagination `json:"pagination"`
	Truncated      bool                          `json:"truncated"`
	ActiveCount    int                           `json:"active_count"`
	ServerNow      time.Time                     `json:"server_now"`
	NextFollowUpAt *time.Time                    `json:"next_follow_up_at"`
}

// IncidentInboxSummary is the count-only response used by the console's
// navigation badge. It deliberately contains no incident or scan evidence.
type IncidentInboxSummary struct {
	ActiveCount int `json:"active_count"`
}
