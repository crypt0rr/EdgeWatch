package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/google/uuid"
)

const (
	changeWindowMaximumDuration = 24 * time.Hour
	changeWindowReasonMaxBytes  = 512
	changeWindowActorMaxRunes   = 160
	changeWindowBatchSize       = 64
	changeWindowDetailLimit     = 20
	changeWindowSummaryMaxBytes = 128 * 1024
)

var (
	ErrDeliveryWindowHeld        = errors.New("notification is held by a planned change window")
	ErrDeliveryAttemptNotStarted = errors.New("notification provider invocation was not started")
)

// ChangeWindowSummary keeps exact identities for references captured before
// the event payload bound, and an explicit count of old truncated events for
// which exact identities cannot be recovered. NewCount and RecoveredCount
// are unique per category and window, not event or destination counts.
type ChangeWindowSummary struct {
	NewCount                      int              `json:"new_count"`
	RecoveredCount                int              `json:"recovered_count"`
	StillOpenCount                int              `json:"still_open_count"`
	SuppressedEventCount          int              `json:"suppressed_event_count"`
	InFlightEventCount            int              `json:"in_flight_event_count"`
	UnknownOutcomeEventCount      int              `json:"unknown_outcome_event_count"`
	IncompleteEventCount          int              `json:"incomplete_event_count"`
	IncompleteReportedChangeCount int              `json:"incomplete_reported_change_count"`
	KnownChangeDetailsTruncated   bool             `json:"known_change_details_truncated"`
	StillOpenDetailsTruncated     bool             `json:"still_open_details_truncated"`
	KnownChanges                  []model.Change   `json:"known_changes"`
	StillOpen                     []model.Incident `json:"still_open"`
}

// ChangeWindow is the tenant-scoped record of one finite planned change
// period. UTC instants are stored; Timezone identifies the job's IANA zone
// used to render them with an explicit offset.
type ChangeWindow struct {
	ID                       string               `json:"id"`
	JobID                    string               `json:"job_id"`
	StartAt                  time.Time            `json:"start_at"`
	EndAt                    time.Time            `json:"end_at"`
	Timezone                 string               `json:"timezone"`
	Reason                   string               `json:"reason"`
	ActorLabel               string               `json:"actor_label"`
	CreatedAt                time.Time            `json:"created_at"`
	Status                   string               `json:"status"`
	EndReason                string               `json:"end_reason,omitempty"`
	ClosedAt                 *time.Time           `json:"closed_at"`
	EffectiveEnd             *time.Time           `json:"effective_end"`
	NewCount                 int                  `json:"new_count"`
	RecoveredCount           int                  `json:"recovered_count"`
	StillOpenCount           int                  `json:"still_open_count"`
	SuppressedEventCount     int                  `json:"suppressed_event_count"`
	InFlightEventCount       int                  `json:"in_flight_event_count"`
	UnknownOutcomeEventCount int                  `json:"unknown_outcome_event_count"`
	IncompleteEventCount     int                  `json:"incomplete_event_count"`
	ReviewState              string               `json:"review_state"`
	ReviewedAt               *time.Time           `json:"reviewed_at"`
	ReviewerLabel            string               `json:"reviewer_label,omitempty"`
	Revision                 int64                `json:"revision"`
	Summary                  *ChangeWindowSummary `json:"summary"`
}

// ChangeWindowStatus is the bounded latest-window projection used by job
// inventories. It carries counts and metadata only; detailed change and
// incident identities are fetched from a single window detail endpoint.
type ChangeWindowStatus struct {
	ID                       string     `json:"id"`
	StartAt                  time.Time  `json:"start_at"`
	EndAt                    time.Time  `json:"end_at"`
	Timezone                 string     `json:"timezone"`
	Reason                   string     `json:"reason"`
	Status                   string     `json:"status"`
	EndReason                string     `json:"end_reason,omitempty"`
	ClosedAt                 *time.Time `json:"closed_at"`
	ReviewState              string     `json:"review_state"`
	NewCount                 int        `json:"new_count"`
	RecoveredCount           int        `json:"recovered_count"`
	KnownChangeCount         int        `json:"known_change_count"`
	StillOpenCount           int        `json:"still_open_count"`
	SuppressedEventCount     int        `json:"suppressed_event_count"`
	InFlightEventCount       int        `json:"in_flight_event_count"`
	UnknownOutcomeEventCount int        `json:"unknown_outcome_event_count"`
	IncompleteEventCount     int        `json:"incomplete_event_count"`
	Revision                 int64      `json:"revision"`
}

// DueChangeWindow is the daemon's compact cross-tenant expiry work item.
// Unit detail is loaded through TenantStore before closing it.
type DueChangeWindow struct {
	ID       string
	TenantID string
	JobID    string
	JobName  string
}

// CreateChangeWindow creates one job-scoped window and attaches currently
// pending change alerts to it. A start-now request is anchored to the time
// sampled after SQLite's writer lock is acquired.
func (ts *TenantStore) CreateChangeWindow(ctx context.Context, jobID string, startAt, endAt time.Time, startNow bool, reason, actorUserID, actorLabel string) (ChangeWindow, error) {
	if err := ts.ready(); err != nil {
		return ChangeWindow{}, err
	}
	reason = strings.TrimSpace(reason)
	actorLabel = strings.TrimSpace(actorLabel)
	if len([]byte(reason)) == 0 || len([]byte(reason)) > changeWindowReasonMaxBytes {
		return ChangeWindow{}, NewValidationError(fmt.Errorf("reason must contain 1 to %d UTF-8 bytes", changeWindowReasonMaxBytes))
	}
	if actorLabel == "" {
		return ChangeWindow{}, NewValidationError(errors.New("actor label is required"))
	}
	if len([]rune(actorLabel)) > changeWindowActorMaxRunes {
		actorLabel = string([]rune(actorLabel)[:changeWindowActorMaxRunes])
	}
	tx, err := beginWriteTx(ctx, ts.store.DB)
	if err != nil {
		return ChangeWindow{}, err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT definition_json FROM jobs WHERE id=? AND tenant_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=jobs.tenant_id AND purge.job_id=jobs.id)`, jobID, ts.scope.id).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ChangeWindow{}, ErrNotFound
		}
		return ChangeWindow{}, err
	}
	job, err := unmarshalJob(raw)
	if err != nil {
		return ChangeWindow{}, err
	}
	zone := strings.TrimSpace(job.Timezone)
	if zone == "" {
		zone = "UTC"
	}
	location, err := time.LoadLocation(zone)
	if err != nil {
		return ChangeWindow{}, NewValidationError(fmt.Errorf("job timezone %q is invalid", zone))
	}
	if startNow {
		startAt = now.In(location)
	} else if startAt.IsZero() || startAt.Before(now) {
		return ChangeWindow{}, NewValidationError(errors.New("start time must be now or in the future"))
	}
	if endAt.IsZero() || !validJobZoneInstant(endAt, location) {
		return ChangeWindow{}, NewValidationError(errors.New("end time must be a valid local time in the job timezone with its explicit UTC offset"))
	}
	if !startNow && !validJobZoneInstant(startAt, location) {
		return ChangeWindow{}, NewValidationError(errors.New("start time must be a valid local time in the job timezone with its explicit UTC offset"))
	}
	startUTC, endUTC := startAt.UTC(), endAt.UTC()
	if !endUTC.After(startUTC) || !endUTC.After(now) {
		return ChangeWindow{}, NewValidationError(errors.New("end time must be after the start time and in the future"))
	}
	if endUTC.Sub(startUTC) > changeWindowMaximumDuration {
		return ChangeWindow{}, NewValidationError(fmt.Errorf("change windows may last at most %s", changeWindowMaximumDuration))
	}
	var overlap int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM change_windows AS w WHERE w.job_id=? AND w.closed_at='' AND w.start_at<? AND w.end_at>? AND EXISTS (SELECT 1 FROM jobs AS j WHERE j.id=w.job_id AND j.tenant_id=?))`, jobID, sqliteTimestamp(endUTC), sqliteTimestamp(startUTC), ts.scope.id).Scan(&overlap); err != nil {
		return ChangeWindow{}, err
	}
	if overlap != 0 {
		return ChangeWindow{}, fmt.Errorf("%w: this job already has an overlapping planned change window", ErrConflict)
	}
	id := uuid.NewString()
	status := "scheduled"
	if !now.Before(startUTC) {
		status = "active"
	}
	createdAt := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO change_windows(id,job_id,start_at,end_at,timezone,reason,actor_user_id,actor_label,created_at,status) SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM jobs WHERE jobs.id=? AND jobs.tenant_id=?)`, id, jobID, sqliteTimestamp(startUTC), sqliteTimestamp(endUTC), zone, reason, actorUserID, actorLabel, createdAt, status, jobID, ts.scope.id); err != nil {
		return ChangeWindow{}, err
	}
	// Existing pending rows are associated now so they cannot escape a later
	// window merely because they were queued immediately before its start.
	// They become summary references only if still pending when the window is
	// closed; rows delivered before start do not inflate the summary.
	if _, err := tx.ExecContext(ctx, `UPDATE outbox SET change_window_id=? WHERE event_job_id=? AND tenant_id=? AND event_type IN ('changes-detected','changes-reminder','changes-recovered') AND sent_at IS NULL AND terminal_at='' AND coalesced_at='' AND change_window_id=''`, id, jobID, ts.scope.id); err != nil {
		return ChangeWindow{}, err
	}
	if err := ts.insertAuditEntries(ctx, tx, []AuditEntry{{Action: "change_window.created", Detail: "job " + jobID + "; window " + id, ActorUserID: actorUserID, ActorUsername: actorLabel}}, now); err != nil {
		return ChangeWindow{}, err
	}
	if err := tx.Commit(); err != nil {
		return ChangeWindow{}, err
	}
	return ChangeWindow{ID: id, JobID: jobID, StartAt: startUTC, EndAt: endUTC, Timezone: zone, Reason: reason, ActorLabel: actorLabel, CreatedAt: now, Status: status, ReviewState: "none", Revision: 1}, nil
}

// ListChangeWindows returns retained windows for one of the tenant's jobs.
func (ts *TenantStore) ListChangeWindows(ctx context.Context, jobID string) ([]ChangeWindow, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	if _, err := ts.GetJob(ctx, jobID); err != nil {
		return nil, err
	}
	rows, err := ts.store.reader().QueryContext(ctx, `SELECT id,job_id,start_at,end_at,timezone,reason,actor_label,created_at,status,end_reason,closed_at,effective_end,new_count,recovered_count,still_open_count,suppressed_event_count,in_flight_event_count,unknown_outcome_event_count,incomplete_event_count,X'',review_state,reviewed_at,reviewer_label,revision FROM change_windows WHERE job_id=? AND EXISTS (SELECT 1 FROM jobs WHERE jobs.id=change_windows.job_id AND jobs.tenant_id=?) ORDER BY start_at DESC,id DESC LIMIT 100`, jobID, ts.scope.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ChangeWindow
	for rows.Next() {
		window, err := scanChangeWindow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, window)
	}
	return out, rows.Err()
}

// GetChangeWindow returns a retained window only when it belongs to the
// caller's tenant and job.
func (ts *TenantStore) GetChangeWindow(ctx context.Context, jobID, id string) (ChangeWindow, error) {
	if err := ts.ready(); err != nil {
		return ChangeWindow{}, err
	}
	row := ts.store.reader().QueryRowContext(ctx, `SELECT id,job_id,start_at,end_at,timezone,reason,actor_label,created_at,status,end_reason,closed_at,effective_end,new_count,recovered_count,still_open_count,suppressed_event_count,in_flight_event_count,unknown_outcome_event_count,incomplete_event_count,summary_json,review_state,reviewed_at,reviewer_label,revision FROM change_windows WHERE id=? AND job_id=? AND EXISTS (SELECT 1 FROM jobs WHERE jobs.id=change_windows.job_id AND jobs.tenant_id=?)`, id, jobID, ts.scope.id)
	window, err := scanChangeWindow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ChangeWindow{}, ErrNotFound
	}
	return window, err
}

type changeWindowScanner interface{ Scan(...any) error }

func optionalScannedTime(raw string) *time.Time {
	if raw == "" {
		return nil
	}
	value := scanTime(raw)
	return &value
}

func scanChangeWindow(scanner changeWindowScanner) (ChangeWindow, error) {
	var out ChangeWindow
	var startAt, endAt, createdAt, status, endReason, closedAt, effectiveEnd, reviewedAt string
	summaryJSON := []byte{}
	if err := scanner.Scan(&out.ID, &out.JobID, &startAt, &endAt, &out.Timezone, &out.Reason, &out.ActorLabel, &createdAt, &status, &endReason, &closedAt, &effectiveEnd, &out.NewCount, &out.RecoveredCount, &out.StillOpenCount, &out.SuppressedEventCount, &out.InFlightEventCount, &out.UnknownOutcomeEventCount, &out.IncompleteEventCount, &summaryJSON, &out.ReviewState, &reviewedAt, &out.ReviewerLabel, &out.Revision); err != nil {
		return out, err
	}
	out.StartAt = scanTime(startAt)
	out.EndAt = scanTime(endAt)
	out.CreatedAt = scanTime(createdAt)
	out.Status = status
	out.EndReason = endReason
	out.ClosedAt = optionalScannedTime(closedAt)
	out.EffectiveEnd = optionalScannedTime(effectiveEnd)
	out.ReviewedAt = optionalScannedTime(reviewedAt)
	if closedAt == "" {
		now := time.Now().UTC()
		switch {
		case now.Before(out.StartAt):
			out.Status = "scheduled"
		case now.Before(out.EndAt):
			out.Status = "active"
		default:
			out.Status = "expired"
		}
	} else if endReason == "cancelled" || endReason == "cancelled-before-start" {
		out.Status = "cancelled"
	} else if endReason == "expired" {
		out.Status = "expired"
	}
	if len(summaryJSON) != 0 {
		var summary ChangeWindowSummary
		if err := json.Unmarshal(summaryJSON, &summary); err != nil {
			return out, err
		}
		out.Summary = &summary
	}
	return out, nil
}

// LatestChangeWindowSummaries returns at most one relevant window per job in
// one tenant-scoped query. Unclosed windows outrank retained review-due
// windows; among those, the most recent window wins. A due review remains
// visible after newer windows have been reviewed.
func (ts *TenantStore) LatestChangeWindowSummaries(ctx context.Context, includeArchived bool, now time.Time) (map[string]ChangeWindowStatus, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := ts.store.reader().QueryContext(ctx, `SELECT w.job_id,w.id,w.start_at,w.end_at,w.timezone,w.reason,w.status,w.end_reason,w.closed_at,w.review_state,w.new_count,w.recovered_count,w.still_open_count,w.suppressed_event_count,w.in_flight_event_count,w.unknown_outcome_event_count,w.incomplete_event_count,w.revision
FROM change_windows AS w JOIN jobs AS j ON j.id=w.job_id AND j.tenant_id=?
WHERE (? OR j.archived=0) AND (w.closed_at='' OR w.review_state='due')
 AND w.id=(SELECT candidate.id FROM change_windows AS candidate WHERE candidate.job_id=w.job_id AND (candidate.closed_at='' OR candidate.review_state='due') ORDER BY CASE WHEN candidate.closed_at='' THEN 0 ELSE 1 END,candidate.start_at DESC,candidate.id DESC LIMIT 1)
ORDER BY w.job_id`, ts.scope.id, boolInt(includeArchived))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]ChangeWindowStatus)
	for rows.Next() {
		var jobID, startRaw, endRaw, closedRaw string
		var item ChangeWindowStatus
		if err := rows.Scan(&jobID, &item.ID, &startRaw, &endRaw, &item.Timezone, &item.Reason, &item.Status, &item.EndReason, &closedRaw, &item.ReviewState, &item.NewCount, &item.RecoveredCount, &item.StillOpenCount, &item.SuppressedEventCount, &item.InFlightEventCount, &item.UnknownOutcomeEventCount, &item.IncompleteEventCount, &item.Revision); err != nil {
			return nil, err
		}
		item.StartAt = scanTime(startRaw)
		item.EndAt = scanTime(endRaw)
		item.ClosedAt = optionalScannedTime(closedRaw)
		item.KnownChangeCount = item.NewCount + item.RecoveredCount
		if closedRaw == "" {
			switch {
			case now.Before(item.StartAt):
				item.Status = "scheduled"
			case now.Before(item.EndAt):
				item.Status = "active"
			default:
				item.Status = "expired"
			}
		} else if item.EndReason == "cancelled-before-start" {
			item.Status = "cancelled"
		} else if item.EndReason == "cancelled" {
			item.Status = "cancelled"
		} else if item.EndReason == "expired" {
			item.Status = "expired"
		}
		out[jobID] = item
	}
	return out, rows.Err()
}

func validJobZoneInstant(value time.Time, location *time.Location) bool {
	if value.IsZero() || location == nil {
		return false
	}
	local := value.In(location)
	_, requestedOffset := value.Zone()
	_, actualOffset := local.Zone()
	if requestedOffset != actualOffset || value.Format("2006-01-02T15:04:05.999999999") != local.Format("2006-01-02T15:04:05.999999999") {
		return false
	}
	// RFC3339 requires an explicit offset. Matching it to the job's IANA zone
	// rejects gaps and wrong offsets while allowing an operator to select one
	// of the two valid instants in a repeated daylight-saving hour.
	return true
}

// DueChangeWindows lists expired, unclosed windows for the daemon worker.
// It returns only identifiers needed to route the closure through a tenant
// store; no unit details are exposed to a platform-facing read.
func (ss *SystemStore) DueChangeWindows(ctx context.Context, now time.Time, limit int) ([]DueChangeWindow, error) {
	if limit < 1 {
		limit = changeWindowBatchSize
	}
	rows, err := ss.store.reader().QueryContext(ctx, `SELECT w.id,j.tenant_id,w.job_id,j.name FROM change_windows AS w JOIN jobs AS j ON j.id=w.job_id WHERE w.closed_at='' AND w.end_at<=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id) ORDER BY w.end_at,w.id LIMIT ?`, sqliteTimestamp(now), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DueChangeWindow
	for rows.Next() {
		var item DueChangeWindow
		if err := rows.Scan(&item.ID, &item.TenantID, &item.JobID, &item.JobName); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// ExpireChangeWindow closes a due window in the job's tenant and queues its
// one summary in the same transaction as the durable review state.
func (ts *TenantStore) ExpireChangeWindow(ctx context.Context, id string, clock func() time.Time, destinations []string) (ChangeWindowSummary, bool, error) {
	if err := ts.ready(); err != nil {
		return ChangeWindowSummary{}, false, err
	}
	tx, err := beginWriteTx(ctx, ts.store.DB)
	if err != nil {
		return ChangeWindowSummary{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	if clock == nil {
		clock = time.Now
	}
	// Sample only after beginWriteTx acquires SQLite's writer. This lets the
	// commit order of expiry and scan finalization define the event boundary.
	closeAt := clock().UTC()
	summary, changed, err := closeChangeWindowTx(ctx, tx, ts.scope, id, closeAt, "expired", destinations)
	if err != nil {
		return ChangeWindowSummary{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return ChangeWindowSummary{}, false, err
	}
	return summary, changed, nil
}

// CancelChangeWindow closes an active window or cancels one that has not
// started. An active cancellation ends at the transaction's actual close
// time and creates a summary only when the window contains change evidence.
func (ts *TenantStore) CancelChangeWindow(ctx context.Context, jobID, id, actorUserID, actorLabel string, destinations []string, audit AuditEntry) (ChangeWindow, bool, error) {
	if err := ts.ready(); err != nil {
		return ChangeWindow{}, false, err
	}
	tx, err := beginWriteTx(ctx, ts.store.DB)
	if err != nil {
		return ChangeWindow{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	closeAt := time.Now().UTC()
	var windowTenant TenantScope
	var windowJob string
	var startRaw, endRaw, closedAt string
	if err := tx.QueryRowContext(ctx, `SELECT w.job_id,w.start_at,w.end_at,w.closed_at FROM change_windows AS w JOIN jobs AS j ON j.id=w.job_id AND j.tenant_id=? WHERE w.id=? AND w.job_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id)`, ts.scope.id, id, jobID).Scan(&windowJob, &startRaw, &endRaw, &closedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ChangeWindow{}, false, ErrNotFound
		}
		return ChangeWindow{}, false, err
	}
	if closedAt != "" {
		return ChangeWindow{}, false, ErrConflict
	}
	windowTenant = ts.scope
	startAt, endAt := scanTime(startRaw), scanTime(endRaw)
	changed := false
	if !closeAt.Before(startAt) && closeAt.Before(endAt) {
		_, changed, err = closeChangeWindowTx(ctx, tx, windowTenant, id, closeAt, "cancelled", destinations)
		if err != nil {
			return ChangeWindow{}, false, err
		}
	} else if !closeAt.Before(endAt) {
		_, changed, err = closeChangeWindowTx(ctx, tx, windowTenant, id, closeAt, "expired", destinations)
		if err != nil {
			return ChangeWindow{}, false, err
		}
	} else {
		stamp := sqliteTimestamp(closeAt)
		if _, err := tx.ExecContext(ctx, `UPDATE change_windows SET status='cancelled',end_reason='cancelled-before-start',closed_at=?,effective_end='',revision=revision+1 WHERE id=? AND job_id=? AND closed_at='' AND EXISTS (SELECT 1 FROM jobs WHERE jobs.id=change_windows.job_id AND jobs.tenant_id=?)`, stamp, id, jobID, ts.scope.id); err != nil {
			return ChangeWindow{}, false, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE outbox SET change_window_id='',coalesce_after_attempt=0,attempt_started_at='' WHERE change_window_id=? AND tenant_id=? AND sent_at IS NULL AND terminal_at='' AND coalesced_at=''`, id, ts.scope.id); err != nil {
			return ChangeWindow{}, false, err
		}
		changed = true
	}
	if changed {
		audit.Action = "change_window.cancelled"
		audit.Detail = "job " + windowJob + "; window " + id
		if audit.ActorUserID == "" {
			audit.ActorUserID = actorUserID
		}
		if audit.ActorUsername == "" {
			audit.ActorUsername = actorLabel
		}
		if err := ts.insertAuditEntries(ctx, tx, []AuditEntry{audit}, closeAt); err != nil {
			return ChangeWindow{}, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return ChangeWindow{}, false, err
	}
	window, err := ts.GetChangeWindow(ctx, jobID, id)
	if err != nil {
		return ChangeWindow{}, changed, err
	}
	return window, changed, nil
}

// ReviewChangeWindow marks a close summary reviewed using an expected
// revision so concurrent operators cannot overwrite each other's action.
func (ts *TenantStore) ReviewChangeWindow(ctx context.Context, jobID, id string, expectedRevision int64, reviewerUserID, reviewerLabel string, audit AuditEntry) (ChangeWindow, error) {
	if err := ts.ready(); err != nil {
		return ChangeWindow{}, err
	}
	reviewerLabel = strings.TrimSpace(reviewerLabel)
	if reviewerLabel == "" || len([]rune(reviewerLabel)) > changeWindowActorMaxRunes {
		return ChangeWindow{}, NewValidationError(fmt.Errorf("reviewer label must contain 1 to %d characters", changeWindowActorMaxRunes))
	}
	tx, err := beginWriteTx(ctx, ts.store.DB)
	if err != nil {
		return ChangeWindow{}, err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `UPDATE change_windows SET review_state='reviewed',reviewed_at=?,reviewer_label=?,revision=revision+1 WHERE id=? AND job_id=? AND review_state='due' AND revision=? AND EXISTS (SELECT 1 FROM jobs WHERE jobs.id=change_windows.job_id AND jobs.tenant_id=?)`, now.Format(time.RFC3339Nano), reviewerLabel, id, jobID, expectedRevision, ts.scope.id)
	if err != nil {
		return ChangeWindow{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ChangeWindow{}, ErrConflict
	}
	audit.Action = "change_window.reviewed"
	audit.Detail = "job " + jobID + "; window " + id
	if audit.ActorUserID == "" {
		audit.ActorUserID = reviewerUserID
	}
	if audit.ActorUsername == "" {
		audit.ActorUsername = reviewerLabel
	}
	if err := ts.insertAuditEntries(ctx, tx, []AuditEntry{audit}, now); err != nil {
		return ChangeWindow{}, err
	}
	if err := tx.Commit(); err != nil {
		return ChangeWindow{}, err
	}
	return ts.GetChangeWindow(ctx, jobID, id)
}

func closeChangeWindowTx(ctx context.Context, tx *sql.Tx, scope TenantScope, id string, closeAt time.Time, reason string, destinations []string) (ChangeWindowSummary, bool, error) {
	var jobID, jobName, startRaw, endRaw, windowStatus, closedAt string
	var tenantID string
	if err := tx.QueryRowContext(ctx, `SELECT w.job_id,j.name,j.tenant_id,w.start_at,w.end_at,w.status,w.closed_at FROM change_windows AS w JOIN jobs AS j ON j.id=w.job_id AND j.tenant_id=? WHERE w.id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id)`, scope.id, id).Scan(&jobID, &jobName, &tenantID, &startRaw, &endRaw, &windowStatus, &closedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ChangeWindowSummary{}, false, ErrNotFound
		}
		return ChangeWindowSummary{}, false, err
	}
	if closedAt != "" {
		return ChangeWindowSummary{}, false, nil
	}
	startAt, endAt := scanTime(startRaw), scanTime(endRaw)
	if reason == "expired" && closeAt.Before(endAt) {
		return ChangeWindowSummary{}, false, ErrConflict
	}
	if reason == "cancelled" && closeAt.Before(startAt) {
		return ChangeWindowSummary{}, false, ErrConflict
	}
	if reason == "cancelled" && !closeAt.Before(endAt) {
		reason = "expired"
	}
	if reason == "cancelled" && windowStatus == "scheduled" && closeAt.Before(startAt) {
		return ChangeWindowSummary{}, false, ErrConflict
	}
	stamp := sqliteTimestamp(closeAt)
	effectiveEnd := sqliteTimestamp(endAt)
	if reason == "cancelled" {
		effectiveEnd = stamp
	}
	if err := capturePendingWindowRowsTx(ctx, tx, id, scope.id, sqliteTimestamp(startAt), sqliteTimestamp(closeAt)); err != nil {
		return ChangeWindowSummary{}, false, err
	}
	var summary ChangeWindowSummary
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM change_window_refs AS refs JOIN change_windows AS w ON w.id=refs.window_id JOIN jobs AS j ON j.id=w.job_id WHERE refs.window_id=? AND refs.category='new' AND j.tenant_id=?`, id, scope.id).Scan(&summary.NewCount); err != nil {
		return summary, false, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM change_window_refs AS refs JOIN change_windows AS w ON w.id=refs.window_id JOIN jobs AS j ON j.id=w.job_id WHERE refs.window_id=? AND refs.category='recovered' AND j.tenant_id=?`, id, scope.id).Scan(&summary.RecoveredCount); err != nil {
		return summary, false, err
	}
	newDetails, err := loadWindowChangeDetailsTx(ctx, tx, id, scope.id, "new")
	if err != nil {
		return summary, false, err
	}
	recoveredDetails, err := loadWindowChangeDetailsTx(ctx, tx, id, scope.id, "recovered")
	if err != nil {
		return summary, false, err
	}
	summary.KnownChanges = append(newDetails, recoveredDetails...)
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM change_window_events AS events JOIN change_windows AS w ON w.id=events.window_id JOIN jobs AS j ON j.id=w.job_id WHERE events.window_id=? AND events.details_complete=0 AND j.tenant_id=?`, id, scope.id).Scan(&summary.IncompleteEventCount); err != nil {
		return summary, false, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(events.reported_count),0) FROM change_window_events AS events JOIN change_windows AS w ON w.id=events.window_id JOIN jobs AS j ON j.id=w.job_id WHERE events.window_id=? AND events.details_complete=0 AND j.tenant_id=?`, id, scope.id).Scan(&summary.IncompleteReportedChangeCount); err != nil {
		return summary, false, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM change_window_events AS events JOIN change_windows AS w ON w.id=events.window_id JOIN jobs AS j ON j.id=w.job_id WHERE events.window_id=? AND events.disposition='suppressed' AND j.tenant_id=?`, id, scope.id).Scan(&summary.SuppressedEventCount); err != nil {
		return summary, false, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM change_window_events AS events JOIN change_windows AS w ON w.id=events.window_id JOIN jobs AS j ON j.id=w.job_id WHERE events.window_id=? AND events.disposition='in_flight' AND j.tenant_id=?`, id, scope.id).Scan(&summary.InFlightEventCount); err != nil {
		return summary, false, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM change_window_events AS events JOIN change_windows AS w ON w.id=events.window_id JOIN jobs AS j ON j.id=w.job_id WHERE events.window_id=? AND events.disposition='unknown_outcome' AND j.tenant_id=?`, id, scope.id).Scan(&summary.UnknownOutcomeEventCount); err != nil {
		return summary, false, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM runtime_incidents AS incidents JOIN jobs AS j ON j.id=incidents.job_id WHERE incidents.job_id=? AND j.tenant_id=?`, jobID, scope.id).Scan(&summary.StillOpenCount); err != nil {
		return summary, false, err
	}
	incidentRows, err := tx.QueryContext(ctx, `SELECT incidents.incident_json FROM runtime_incidents AS incidents JOIN jobs AS j ON j.id=incidents.job_id WHERE incidents.job_id=? AND j.tenant_id=? ORDER BY incidents.key LIMIT ?`, jobID, scope.id, changeWindowDetailLimit+1)
	if err != nil {
		return summary, false, err
	}
	defer incidentRows.Close()
	for incidentRows.Next() {
		var raw []byte
		var incident model.Incident
		if err := incidentRows.Scan(&raw); err != nil {
			_ = incidentRows.Close()
			return summary, false, err
		}
		if err := json.Unmarshal(raw, &incident); err != nil {
			_ = incidentRows.Close()
			return summary, false, err
		}
		summary.StillOpen = append(summary.StillOpen, incident)
	}
	if err := incidentRows.Err(); err != nil {
		_ = incidentRows.Close()
		return summary, false, err
	}
	if err := incidentRows.Close(); err != nil {
		return summary, false, err
	}
	if len(summary.StillOpen) > changeWindowDetailLimit {
		summary.StillOpen = summary.StillOpen[:changeWindowDetailLimit]
		summary.StillOpenDetailsTruncated = true
	} else {
		summary.StillOpenDetailsTruncated = summary.StillOpenCount > len(summary.StillOpen)
	}
	summary.KnownChangeDetailsTruncated = summary.NewCount > len(newDetails) || summary.RecoveredCount > len(recoveredDetails)
	hasEvidence := summary.SuppressedEventCount+summary.InFlightEventCount+summary.UnknownOutcomeEventCount > 0
	summaryJSON := []byte{}
	reviewState := "none"
	var summaryEvent *model.Event
	if hasEvidence {
		summaryJSON, err = marshalBoundedChangeWindowSummary(&summary)
		if err != nil {
			return summary, false, err
		}
		reviewState = "due"
		message := fmt.Sprintf("Planned change window closed: %d known newly opened, %d known recovered, %d currently open", summary.NewCount, summary.RecoveredCount, summary.StillOpenCount)
		if summary.InFlightEventCount > 0 {
			message += fmt.Sprintf("; %d change event(s) were already in flight at close, with provider outcomes unknown", summary.InFlightEventCount)
		}
		if summary.UnknownOutcomeEventCount > 0 {
			message += fmt.Sprintf("; %d earlier provider attempt(s) had unknown outcomes at close", summary.UnknownOutcomeEventCount)
		}
		if summary.IncompleteEventCount > 0 {
			message += fmt.Sprintf("; details incomplete for %d older truncated event(s)", summary.IncompleteEventCount)
		}
		event := model.Event{Type: "change-window-summary", JobID: jobID, Job: jobName, Message: message, Reason: reason, CreatedAt: closeAt.UTC(), TenantID: tenantID}
		summaryEvent = &event
	}
	if _, err := tx.ExecContext(ctx, `UPDATE change_windows SET status='closed',end_reason=?,closed_at=?,effective_end=?,new_count=?,recovered_count=?,still_open_count=?,suppressed_event_count=?,in_flight_event_count=?,unknown_outcome_event_count=?,incomplete_event_count=?,summary_json=?,review_state=?,revision=revision+1 WHERE id=? AND closed_at='' AND EXISTS (SELECT 1 FROM jobs AS j WHERE j.id=change_windows.job_id AND j.tenant_id=?)`, reason, stamp, effectiveEnd, summary.NewCount, summary.RecoveredCount, summary.StillOpenCount, summary.SuppressedEventCount, summary.InFlightEventCount, summary.UnknownOutcomeEventCount, summary.IncompleteEventCount, summaryJSON, reviewState, id, scope.id); err != nil {
		return summary, false, err
	}
	// Pending rows that never crossed the application invocation boundary are
	// coalesced now. A provider call already handed off keeps its lease until
	// its outcome arrives, but is marked so a failed result cannot retry or
	// penalize destination health after close.
	if _, err := tx.ExecContext(ctx, `UPDATE outbox SET coalesced_at=?,last_error='',claim_token='',claim_until='' WHERE change_window_id=? AND tenant_id=? AND sent_at IS NULL AND terminal_at='' AND coalesced_at='' AND attempt_started_at=''`, stamp, id, scope.id); err != nil {
		return summary, false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE outbox SET coalesce_after_attempt=1 WHERE change_window_id=? AND tenant_id=? AND sent_at IS NULL AND terminal_at='' AND coalesced_at='' AND attempt_started_at<>''`, id, scope.id); err != nil {
		return summary, false, err
	}
	// A restarted process has no provider owner for a released claim. The
	// summary above preserves its in-flight evidence, so close can now finish
	// coalescing those orphaned attempts immediately.
	if _, err := tx.ExecContext(ctx, `UPDATE outbox SET coalesced_at=?,attempt_started_at='',coalesce_after_attempt=0,last_error='' WHERE change_window_id=? AND tenant_id=? AND sent_at IS NULL AND terminal_at='' AND coalesced_at='' AND attempt_started_at<>'' AND claim_token=''`, stamp, id, scope.id); err != nil {
		return summary, false, err
	}
	if summaryEvent != nil {
		bounded, payload, err := model.MarshalBoundedEvent(*summaryEvent, model.EventPayloadLimit)
		if err != nil {
			return summary, false, err
		}
		if err := insertEventExec(ctx, tx, bounded, payload, closeAt.UTC()); err != nil {
			return summary, false, err
		}
		if err := queueEventsTx(ctx, tx, []model.Event{bounded}, destinations); err != nil {
			return summary, false, err
		}
	}
	return summary, true, nil
}

func capturePendingWindowRowsTx(ctx context.Context, tx *sql.Tx, windowID, tenantID, startAt, closeAt string) error {
	var after int64
	for {
		rows, err := tx.QueryContext(ctx, `SELECT id,payload_json,attempt_started_at,claim_token,claim_until FROM outbox WHERE change_window_id=? AND tenant_id=? AND sent_at IS NULL AND terminal_at='' AND coalesced_at='' AND id>? ORDER BY id LIMIT ?`, windowID, tenantID, after, changeWindowBatchSize)
		if err != nil {
			return err
		}
		defer rows.Close()
		type pendingEvent struct {
			id         int64
			event      model.Event
			startedAt  string
			claimToken string
			claimUntil string
		}
		batch := make([]pendingEvent, 0, changeWindowBatchSize)
		readCount := 0
		for rows.Next() {
			var item pendingEvent
			var payload []byte
			if err := rows.Scan(&item.id, &payload, &item.startedAt, &item.claimToken, &item.claimUntil); err != nil {
				_ = rows.Close()
				return err
			}
			readCount++
			if err := json.Unmarshal(payload, &item.event); err == nil {
				batch = append(batch, item)
			}
			after = item.id
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if readCount == 0 {
			return nil
		}
		for _, item := range batch {
			disposition := "suppressed"
			if item.startedAt != "" && item.startedAt < startAt {
				disposition = "unknown_outcome"
				if item.claimToken != "" && item.claimUntil != "" && scanTime(item.claimUntil).After(scanTime(closeAt)) {
					disposition = "in_flight"
				}
			}
			if err := recordChangeWindowEventDispositionTx(ctx, tx, windowID, tenantID, item.event, disposition); err != nil {
				return err
			}
		}
	}
}

func changeWindowEventType(eventType string) bool {
	switch eventType {
	case "changes-detected", "changes-reminder", "changes-recovered":
		return true
	default:
		return false
	}
}

func changeWindowEventKey(event model.Event) string {
	created := event.CreatedAt.UTC().Format(time.RFC3339Nano)
	key := event.Type + "\x00" + event.JobID + "\x00" + event.ScanID + "\x00" + created
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func recordChangeWindowEventTx(ctx context.Context, tx *sql.Tx, windowID, tenantID string, event model.Event) error {
	return recordChangeWindowEventDispositionTx(ctx, tx, windowID, tenantID, event, "suppressed")
}

func recordChangeWindowEventDispositionTx(ctx context.Context, tx *sql.Tx, windowID, tenantID string, event model.Event, disposition string) error {
	if !changeWindowEventType(event.Type) {
		return nil
	}
	if disposition != "in_flight" && disposition != "unknown_outcome" {
		disposition = "suppressed"
	}
	key := changeWindowEventKey(event)
	complete := !event.ChangesTruncated
	reported := event.ChangesCount
	if reported <= 0 {
		reported = len(event.Changes)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO change_window_events(window_id,event_key,event_type,scan_id,event_at,disposition,details_complete,reported_count) SELECT ?,?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM change_windows AS w JOIN jobs AS j ON j.id=w.job_id WHERE w.id=? AND j.tenant_id=?) ON CONFLICT(window_id,event_key) DO UPDATE SET disposition=CASE WHEN change_window_events.disposition='in_flight' OR excluded.disposition='in_flight' THEN 'in_flight' WHEN change_window_events.disposition='unknown_outcome' OR excluded.disposition='unknown_outcome' THEN 'unknown_outcome' ELSE 'suppressed' END`, windowID, key, event.Type, event.ScanID, sqliteTimestamp(event.CreatedAt), disposition, boolInt(complete), reported, windowID, tenantID); err != nil {
		return err
	}
	category := ""
	switch event.Type {
	case "changes-detected":
		category = "new"
	case "changes-recovered":
		category = "recovered"
	}
	if category == "" || event.ChangesTruncated {
		return nil
	}
	var detailed int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM change_window_refs AS refs JOIN change_windows AS w ON w.id=refs.window_id JOIN jobs AS j ON j.id=w.job_id WHERE refs.window_id=? AND refs.category=? AND refs.change_json<>X'' AND j.tenant_id=?`, windowID, category, tenantID).Scan(&detailed); err != nil {
		return err
	}
	for _, change := range event.Changes {
		if strings.TrimSpace(change.Key) == "" {
			continue
		}
		raw := []byte{}
		if detailed < changeWindowDetailLimit {
			var err error
			raw, err = json.Marshal(change)
			if err != nil {
				return err
			}
		}
		result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO change_window_refs(window_id,category,change_key,change_json,event_key,event_type,scan_id,event_at) SELECT ?,?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM change_windows AS w JOIN jobs AS j ON j.id=w.job_id WHERE w.id=? AND j.tenant_id=?)`, windowID, category, stableChangeWindowKey(change.Key), raw, key, event.Type, event.ScanID, sqliteTimestamp(event.CreatedAt), windowID, tenantID)
		if err != nil {
			return err
		}
		if len(raw) != 0 {
			if inserted, _ := result.RowsAffected(); inserted == 1 {
				detailed++
			}
		}
	}
	return nil
}

func stableChangeWindowKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func loadWindowChangeDetailsTx(ctx context.Context, tx *sql.Tx, windowID, tenantID, category string) ([]model.Change, error) {
	rows, err := tx.QueryContext(ctx, `SELECT refs.change_json FROM change_window_refs AS refs JOIN change_windows AS w ON w.id=refs.window_id JOIN jobs AS j ON j.id=w.job_id WHERE refs.window_id=? AND refs.category=? AND refs.change_json<>X'' AND j.tenant_id=? ORDER BY refs.change_key LIMIT ?`, windowID, category, tenantID, changeWindowDetailLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.Change, 0, changeWindowDetailLimit)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var change model.Change
		if err := json.Unmarshal(raw, &change); err != nil {
			return nil, err
		}
		out = append(out, change)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func marshalBoundedChangeWindowSummary(summary *ChangeWindowSummary) ([]byte, error) {
	for {
		raw, err := json.Marshal(summary)
		if err != nil {
			return nil, err
		}
		if len(raw) <= changeWindowSummaryMaxBytes {
			return raw, nil
		}
		if len(summary.StillOpen) > 0 {
			summary.StillOpen = summary.StillOpen[:len(summary.StillOpen)-1]
			summary.StillOpenDetailsTruncated = true
			continue
		}
		if len(summary.KnownChanges) > 0 {
			summary.KnownChanges = summary.KnownChanges[:len(summary.KnownChanges)-1]
			summary.KnownChangeDetailsTruncated = true
			continue
		}
		return nil, errors.New("change window summary metadata exceeds its storage bound")
	}
}

func windowForQueuedChangeTx(ctx context.Context, tx *sql.Tx, jobID, tenantID string, now time.Time) (string, bool, string, error) {
	var id, startRaw, endRaw string
	err := tx.QueryRowContext(ctx, `SELECT w.id,w.start_at,w.end_at FROM change_windows AS w JOIN jobs AS j ON j.id=w.job_id AND j.tenant_id=? WHERE w.job_id=? AND w.closed_at='' AND w.end_at>? ORDER BY w.start_at,w.id LIMIT 1`, tenantID, jobID, sqliteTimestamp(now)).Scan(&id, &startRaw, &endRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, "", nil
	}
	if err != nil {
		return "", false, "", err
	}
	startAt, endAt := scanTime(startRaw), scanTime(endRaw)
	if !now.Before(startAt) && now.Before(endAt) {
		return id, true, endRaw, nil
	}
	if now.Before(startAt) {
		return id, false, startRaw, nil
	}
	return "", false, "", nil
}

func referencedChangeWindowTx(ctx context.Context, tx *sql.Tx, event model.Event, tenantID string) (string, bool, error) {
	var windowID string
	err := tx.QueryRowContext(ctx, `SELECT events.window_id FROM change_window_events AS events JOIN change_windows AS w ON w.id=events.window_id JOIN jobs AS j ON j.id=w.job_id WHERE events.event_key=? AND events.event_type=? AND j.tenant_id=? LIMIT 1`, changeWindowEventKey(event), event.Type, tenantID).Scan(&windowID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return windowID, err == nil, err
}

// BeginDeliveryAttempt is the final durable gate before a notifier invokes
// the provider runner. Its commit is the application's invocation boundary:
// a provider call whose marker committed before a window starts is already
// in flight and cannot be recalled. A claimed batch is never treated as an
// invocation. This method releases a held claim without changing retry or
// deferral budgets.
func (ss *SystemStore) BeginDeliveryAttempt(ctx context.Context, id int64, claim string) error {
	if claim == "" {
		return ErrDeliveryClaimLost
	}
	tx, err := beginWriteTx(ctx, ss.store.DB)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDeliveryAttemptNotStarted, err)
	}
	defer func() { _ = tx.Rollback() }()
	var eventType, jobID, windowID, coalescedAt, tenantID string
	var sendable bool
	var payload []byte
	var coalesceAfter int
	if err := tx.QueryRowContext(ctx, `SELECT `+heldDeliverySQL+`,event_type,event_job_id,change_window_id,coalesced_at,coalesce_after_attempt,payload_json,COALESCE(tenant_id,'') FROM outbox AS due WHERE id=? AND sent_at IS NULL AND terminal_at='' AND claim_token=?`, id, claim).Scan(&sendable, &eventType, &jobID, &windowID, &coalescedAt, &coalesceAfter, &payload, &tenantID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeliveryClaimLost
		}
		return fmt.Errorf("%w: %v", ErrDeliveryAttemptNotStarted, err)
	}
	now := time.Now().UTC()
	if !sendable {
		if _, err := tx.ExecContext(ctx, `UPDATE outbox SET claim_token='',claim_until='',last_error='' WHERE id=? AND claim_token=?`, id, claim); err != nil {
			return fmt.Errorf("%w: %v", ErrDeliveryAttemptNotStarted, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("%w: %v", ErrDeliveryAttemptNotStarted, err)
		}
		return ErrDeliveryHeld
	}
	if !changeWindowEventType(eventType) {
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("%w: %v", ErrDeliveryAttemptNotStarted, err)
		}
		return nil
	}
	if coalescedAt != "" || coalesceAfter != 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE outbox SET coalesced_at=CASE WHEN coalesced_at='' THEN ? ELSE coalesced_at END,claim_token='',claim_until='',last_error='' WHERE id=? AND claim_token=?`, sqliteTimestamp(now), id, claim); err != nil {
			return fmt.Errorf("%w: %v", ErrDeliveryAttemptNotStarted, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("%w: %v", ErrDeliveryAttemptNotStarted, err)
		}
		return ErrDeliveryWindowHeld
	}
	if windowID == "" && jobID != "" {
		windowID, _, _, err = windowForQueuedChangeTx(ctx, tx, jobID, tenantID, now)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrDeliveryAttemptNotStarted, err)
		}
	}
	if windowID != "" {
		var startRaw, endRaw, closedAt string
		err := tx.QueryRowContext(ctx, `SELECT quiet.start_at,quiet.end_at,quiet.closed_at FROM change_windows AS quiet JOIN jobs AS j ON j.id=quiet.job_id WHERE quiet.id=? AND j.tenant_id=?`, windowID, tenantID).Scan(&startRaw, &endRaw, &closedAt)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %v", ErrDeliveryAttemptNotStarted, err)
		}
		if err == nil {
			startAt, endAt := scanTime(startRaw), scanTime(endRaw)
			// An unclosed due window continues to hold the row until the
			// expiry worker commits its summary and coalesces the backlog.
			if closedAt == "" && !now.Before(startAt) {
				var event model.Event
				if json.Unmarshal(payload, &event) == nil {
					if event.JobID == "" {
						event.JobID = jobID
					}
					if err := recordChangeWindowEventTx(ctx, tx, windowID, tenantID, event); err != nil {
						return fmt.Errorf("%w: %v", ErrDeliveryAttemptNotStarted, err)
					}
				}
				next := endAt.Format(time.RFC3339Nano)
				if _, err := tx.ExecContext(ctx, `UPDATE outbox SET change_window_id=?,next_at=?,claim_token='',claim_until='',last_error='' WHERE id=? AND claim_token=?`, windowID, next, id, claim); err != nil {
					return fmt.Errorf("%w: %v", ErrDeliveryAttemptNotStarted, err)
				}
				if err := tx.Commit(); err != nil {
					return fmt.Errorf("%w: %v", ErrDeliveryAttemptNotStarted, err)
				}
				return ErrDeliveryWindowHeld
			}
			if closedAt != "" {
				if _, err := tx.ExecContext(ctx, `UPDATE outbox SET coalesced_at=?,claim_token='',claim_until='',last_error='' WHERE id=? AND claim_token=?`, sqliteTimestamp(now), id, claim); err != nil {
					return fmt.Errorf("%w: %v", ErrDeliveryAttemptNotStarted, err)
				}
				if err := tx.Commit(); err != nil {
					return fmt.Errorf("%w: %v", ErrDeliveryAttemptNotStarted, err)
				}
				return ErrDeliveryWindowHeld
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE outbox SET attempt_started_at=? WHERE id=? AND claim_token=?`, sqliteTimestamp(now), id, claim); err != nil {
		return fmt.Errorf("%w: %v", ErrDeliveryAttemptNotStarted, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: %v", ErrDeliveryAttemptNotStarted, err)
	}
	return nil
}
