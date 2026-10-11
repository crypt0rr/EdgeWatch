package store

import (
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// IncidentObservationStatus is the conservative state assigned to newer
// evidence for an active finding. Unknown never implies that the finding has
// recovered.
type IncidentObservationStatus string

const (
	IncidentObservationUnknown    IncidentObservationStatus = "unknown"
	IncidentObservationIncomplete IncidentObservationStatus = "incomplete"
)

// IncidentObservationReason identifies why evidence is incomplete or cannot
// be classified for this finding.
type IncidentObservationReason string

const (
	IncidentReasonLegacyOriginUnknown                IncidentObservationReason = "legacy_origin_unknown"
	IncidentReasonNoNewerObservation                 IncidentObservationReason = "no_newer_observation"
	IncidentReasonLatestScanFailed                   IncidentObservationReason = "latest_scan_failed"
	IncidentReasonLatestScanIncomplete               IncidentObservationReason = "latest_scan_incomplete"
	IncidentReasonLatestScanNotCompared              IncidentObservationReason = "latest_scan_not_compared"
	IncidentReasonLatestScanUnclassifiable           IncidentObservationReason = "latest_scan_unclassifiable"
	IncidentReasonTargetResolutionFailed             IncidentObservationReason = "target_resolution_failed"
	IncidentReasonTargetHostDown                     IncidentObservationReason = "target_host_down"
	IncidentReasonTargetUnobserved                   IncidentObservationReason = "target_unobserved"
	IncidentReasonProtocolUnobserved                 IncidentObservationReason = "protocol_unobserved"
	IncidentReasonTargetObservationIncomplete        IncidentObservationReason = "target_observation_incomplete"
	IncidentReasonLatestScanDoesNotEstablishRecovery IncidentObservationReason = "latest_scan_does_not_establish_recovery"
)

func validIncidentObservationStatus(status IncidentObservationStatus) bool {
	return status == IncidentObservationUnknown || status == IncidentObservationIncomplete
}

func validIncidentObservationReason(reason IncidentObservationReason) bool {
	switch reason {
	case IncidentReasonLegacyOriginUnknown, IncidentReasonNoNewerObservation,
		IncidentReasonLatestScanFailed, IncidentReasonLatestScanIncomplete,
		IncidentReasonLatestScanNotCompared, IncidentReasonLatestScanUnclassifiable,
		IncidentReasonTargetResolutionFailed, IncidentReasonTargetHostDown,
		IncidentReasonTargetUnobserved, IncidentReasonProtocolUnobserved,
		IncidentReasonTargetObservationIncomplete, IncidentReasonLatestScanDoesNotEstablishRecovery:
		return true
	default:
		return false
	}
}

func (u IncidentObservationUncertainty) valid() bool {
	if !validIncidentObservationStatus(u.Status) || !validIncidentObservationReason(u.Reason) {
		return false
	}
	switch u.Status {
	case IncidentObservationUnknown:
		return u.Reason == IncidentReasonLegacyOriginUnknown ||
			u.Reason == IncidentReasonNoNewerObservation ||
			u.Reason == IncidentReasonLatestScanUnclassifiable ||
			u.Reason == IncidentReasonLatestScanDoesNotEstablishRecovery
	case IncidentObservationIncomplete:
		return u.Reason == IncidentReasonLatestScanFailed ||
			u.Reason == IncidentReasonLatestScanIncomplete ||
			u.Reason == IncidentReasonLatestScanNotCompared ||
			u.Reason == IncidentReasonTargetResolutionFailed ||
			u.Reason == IncidentReasonTargetHostDown ||
			u.Reason == IncidentReasonTargetUnobserved ||
			u.Reason == IncidentReasonProtocolUnobserved ||
			u.Reason == IncidentReasonTargetObservationIncomplete
	default:
		return false
	}
}

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
	Status     IncidentObservationStatus `json:"status"`
	Reason     IncidentObservationReason `json:"reason,omitempty"`
	ScanID     string                    `json:"scan_id,omitempty"`
	ObservedAt *time.Time                `json:"observed_at,omitempty"`
	ScanStatus string                    `json:"scan_status,omitempty"`
	Comparison string                    `json:"comparison,omitempty"`
}

// IncidentInboxItem is one tenant-scoped active incident and its durable
// review metadata.
type IncidentInboxItem struct {
	JobID                  string                         `json:"job_id"`
	Job                    string                         `json:"job"`
	Incident               model.Incident                 `json:"incident"`
	OccurrenceToken        string                         `json:"occurrence_token"`
	OpeningTimeKnown       bool                           `json:"opening_time_known"`
	OpeningScanAvailable   bool                           `json:"opening_scan_available"`
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
