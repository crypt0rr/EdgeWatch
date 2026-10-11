package store

import (
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// IncidentReview is the shared review state for one active incident
// occurrence. A missing database row is represented as an empty needs_review
// value with revision zero, so clients can save it with optimistic locking.
type IncidentReview struct {
	Status        string     `json:"status"`
	ReviewerLabel *string    `json:"reviewer_label"`
	ReviewedAt    *time.Time `json:"reviewed_at"`
	Note          string     `json:"note"`
	FollowUpAt    *time.Time `json:"follow_up_at"`
	Revision      int64      `json:"revision"`
}

// IncidentObservationUncertainty describes the newest classifiable evidence
// relevant to an active incident. Unknown is an explicit state for legacy or
// insufficient evidence; no state implies that an incident is healthy or
// recovered.
type IncidentObservationUncertainty struct {
	Status     string     `json:"status"`
	Reason     string     `json:"reason,omitempty"`
	ScanID     string     `json:"scan_id,omitempty"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
}

// IncidentInboxItem is one tenant-scoped active incident and its durable
// review metadata.
type IncidentInboxItem struct {
	JobID                  string                         `json:"job_id"`
	Job                    string                         `json:"job"`
	Incident               model.Incident                 `json:"incident"`
	OccurrenceToken        string                         `json:"occurrence_token"`
	OpeningTimeKnown       bool                           `json:"opening_time_known"`
	ViewStatus             string                         `json:"view_status"`
	Review                 IncidentReview                 `json:"review"`
	ObservationUncertainty IncidentObservationUncertainty `json:"observation_uncertainty"`
}

// IncidentInboxPagination describes the matching result set after every
// inbox filter and view has been applied.
type IncidentInboxPagination struct {
	Limit      int  `json:"limit"`
	Offset     int  `json:"offset"`
	Total      int  `json:"total"`
	HasMore    bool `json:"has_more"`
	NextOffset *int `json:"next_offset"`
}
