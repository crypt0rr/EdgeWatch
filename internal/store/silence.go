package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// RecordJobSilenceAlert records a deduplicated warning when a managed job has
// not produced a successful scan within threshold. The latest successful
// result, active lease, deduplication check, event, and notification outbox
// rows are handled in one transaction so a daemon tick cannot emit an alert
// without its durable event (or emit duplicate alerts after a restart).
//
// createdAt is used as the reference point for jobs that have never completed
// a scan. A zero reference means the job is not old enough to evaluate yet.
// The location of now selects the timezone of the human-readable last-success
// time in the alert text; persisted timestamps remain UTC.
// The returned bool reports whether a new event was committed. A job of a
// tenant that is not active is never due, as in JobSilenceDue.
func (ss *SystemStore) RecordJobSilenceAlert(ctx context.Context, jobID, job string, createdAt, now time.Time, threshold time.Duration, destinations []string) (model.Event, bool, error) {
	if jobID == "" || threshold <= 0 {
		return model.Event{}, false, nil
	}
	display := now.Location()
	now = now.UTC()
	createdAt = createdAt.UTC()
	tx, err := ss.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return model.Event{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	decision, err := jobSilenceDecisionTx(ctx, tx, jobID, createdAt, now, threshold)
	if err != nil {
		return model.Event{}, false, err
	}
	if !decision.due {
		return model.Event{}, false, nil
	}
	lastReference := decision.lastReference

	message := fmt.Sprintf("No successful scan completed in %s", humanSilenceDuration(threshold))
	if !lastReference.IsZero() {
		message += "; last success " + lastReference.In(display).Format(time.RFC3339)
	}
	event := model.Event{
		Type:      "job-silent",
		JobID:     jobID,
		Job:       job,
		Message:   message,
		CreatedAt: now,
	}
	bounded, payload, err := model.MarshalBoundedEvent(event, model.EventPayloadLimit)
	if err != nil {
		return model.Event{}, false, err
	}
	if err := insertEventExec(ctx, tx, bounded, payload, now); err != nil {
		return model.Event{}, false, err
	}
	if err := queueEventsTx(ctx, tx, []model.Event{bounded}, destinations); err != nil {
		return model.Event{}, false, err
	}
	// Advance the durable watchdog state together with the event/outbox. The
	// next alert is exponentially backed off so a permanently broken schedule
	// cannot generate a notification on every heartbeat while still recovering
	// automatically after a successful scan.
	level := decision.backoffLevel + 1
	if level > maxSilenceBackoffLevel {
		level = maxSilenceBackoffLevel
	}
	nextAlert := now.Add(silenceRepeatDelay(threshold, level)).Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO job_silence_state(job_id,eligible_at,backoff_level,next_alert_at,last_success_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(job_id) DO UPDATE SET backoff_level=excluded.backoff_level,next_alert_at=excluded.next_alert_at,updated_at=excluded.updated_at`, jobID, createdAt.Format(time.RFC3339Nano), level, nextAlert, "", now.Format(time.RFC3339Nano)); err != nil {
		if !isMissingSilenceState(err) {
			return model.Event{}, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return model.Event{}, false, err
	}
	return bounded, true, nil
}

// JobSilenceDue is a cheap preflight used by the application before it reloads
// notification destinations. Destination decryption/reload is therefore only
// performed for jobs that are actually overdue; RecordJobSilenceAlert repeats
// the same decision in its write transaction before committing the event.
// The jobs of a tenant that is not active are never due: a disabled tenant is
// paused, so its jobs do not scan and its alerts are held.
func (ss *SystemStore) JobSilenceDue(ctx context.Context, jobID string, createdAt, now time.Time, threshold time.Duration) (bool, error) {
	if jobID == "" || threshold <= 0 {
		return false, nil
	}
	decision, err := jobSilenceDecisionQuery(ctx, ss.store.reader(), jobID, createdAt, now, threshold)
	return decision.due, err
}

// JobSilenceReference returns the timestamp from which the watchdog should
// calculate a schedule window. It mirrors the reference precedence used by
// jobSilenceDecisionQuery: creation time, lifecycle eligibility, the newest
// successful scan, and the denormalized last-success marker. Keeping this
// read on the read pool lets the application derive a calendar-aware deadline
// without making the silence decision itself non-transactional.
func (ss *SystemStore) JobSilenceReference(ctx context.Context, jobID string, createdAt, now time.Time) (time.Time, error) {
	if jobID == "" {
		return time.Time{}, nil
	}
	return jobSilenceReferenceQuery(ctx, ss.store.reader(), jobID, createdAt, now)
}

type jobSilenceDecision struct {
	due           bool
	lastReference time.Time
	backoffLevel  int
}

func isMissingSilenceState(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table")
}

func jobSilenceReferenceQuery(ctx context.Context, queryer rowQueryer, jobID string, createdAt, now time.Time) (time.Time, error) {
	if jobID == "" {
		return time.Time{}, nil
	}
	now = now.UTC()
	createdAt = createdAt.UTC()
	lastReference := createdAt
	var eligible, lastSuccess string
	stateErr := queryer.QueryRowContext(ctx, `SELECT eligible_at,last_success_at FROM job_silence_state WHERE job_id=?`, jobID).Scan(&eligible, &lastSuccess)
	if stateErr != nil && !errors.Is(stateErr, sql.ErrNoRows) && !isMissingSilenceState(stateErr) {
		return time.Time{}, stateErr
	}
	// Keep eligibility as a lower bound even when it is in the future. A
	// lifecycle write may race the watchdog (or recover from a clock skew), and
	// dropping a future marker would let a resumed job be judged against an
	// older creation/scan timestamp before its grace period begins.
	if parsed := scanTime(eligible); !parsed.IsZero() && parsed.After(lastReference) {
		lastReference = parsed
	}
	var finished string
	err := queryer.QueryRowContext(ctx, `SELECT finished_at FROM scans WHERE job_id=? AND status='success' ORDER BY finished_at DESC,id DESC LIMIT 1`, jobID).Scan(&finished)
	if err == nil {
		if parsed := scanTime(finished); !parsed.IsZero() && parsed.After(lastReference) {
			lastReference = parsed
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, err
	}
	if parsed := scanTime(lastSuccess); !parsed.IsZero() && parsed.After(lastReference) {
		lastReference = parsed
	}
	return lastReference, nil
}

func jobSilenceDecisionTx(ctx context.Context, tx *sql.Tx, jobID string, createdAt, now time.Time, threshold time.Duration) (jobSilenceDecision, error) {
	return jobSilenceDecisionQuery(ctx, tx, jobID, createdAt, now, threshold)
}

func jobSilenceDecisionQuery(ctx context.Context, queryer rowQueryer, jobID string, createdAt, now time.Time, threshold time.Duration) (jobSilenceDecision, error) {
	if jobID == "" || threshold <= 0 {
		return jobSilenceDecision{}, nil
	}
	// A paused tenant's jobs are not expected to scan, so their silence is
	// not an alert. The watchdog judges them again once the tenant is active.
	var tenantState string
	var definition []byte
	err := queryer.QueryRowContext(ctx, `SELECT tenants.state,jobs.definition_json FROM jobs JOIN tenants ON tenants.id=jobs.tenant_id WHERE jobs.id=?`, jobID).Scan(&tenantState, &definition)
	if errors.Is(err, sql.ErrNoRows) {
		return jobSilenceDecision{}, nil
	}
	if err != nil {
		return jobSilenceDecision{}, err
	}
	if tenantState != TenantStateActive {
		return jobSilenceDecision{}, nil
	}
	currentScopeHash, legacyScopeHash, err := jobSilenceScopeHashes(definition)
	if err != nil {
		return jobSilenceDecision{}, err
	}
	now = now.UTC()
	createdAt = createdAt.UTC()
	var eligible, nextAlert, lastSuccess string
	var backoff int
	stateErr := queryer.QueryRowContext(ctx, `SELECT eligible_at,next_alert_at,last_success_at,backoff_level FROM job_silence_state WHERE job_id=?`, jobID).Scan(&eligible, &nextAlert, &lastSuccess, &backoff)
	if stateErr != nil && !errors.Is(stateErr, sql.ErrNoRows) && !strings.Contains(strings.ToLower(stateErr.Error()), "no such table") {
		return jobSilenceDecision{}, stateErr
	}
	lastReference, err := jobSilenceReferenceQuery(ctx, queryer, jobID, createdAt, now)
	if err != nil {
		return jobSilenceDecision{}, err
	}
	if lastReference.IsZero() || now.Sub(lastReference) < threshold {
		return jobSilenceDecision{}, nil
	}
	if parsed := scanTime(nextAlert); !parsed.IsZero() && now.Before(parsed) {
		return jobSilenceDecision{}, nil
	}

	// A scan that is currently running is still making progress. Do not alert
	// while it owns a live lease, even if the previous successful result is old.
	var active int
	if err := queryer.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_leases WHERE job=? AND expires_at>?`, jobID, now.Format(time.RFC3339Nano)).Scan(&active); err != nil {
		return jobSilenceDecision{}, err
	}
	if active > 0 {
		return jobSilenceDecision{}, nil
	}
	// A resumable cycle can make durable progress over several scheduled
	// attempts without producing a successful scan yet. Count an in-window
	// cycle with a recently completed work-unit checkpoint as activity.
	progressCutoff := sqliteTimestamp(now.Add(-threshold))
	var progressing int
	if err := queryer.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_cycles
 WHERE job_id=? AND status IN ('running','paused') AND (expires_at>? OR (status='paused' AND expires_at=''))
   AND (config_hash=? OR (?<>'' AND config_hash=?))
	 AND (completed_units>0 OR completed_probes>0)
	 AND EXISTS (SELECT 1 FROM scan_cycle_units checkpoint
	   WHERE checkpoint.cycle_id=scan_cycles.id AND checkpoint.status='completed' AND checkpoint.finished_at>?)
	 AND completed_units<total_units`, jobID, sqliteTimestamp(now), currentScopeHash, legacyScopeHash, legacyScopeHash, progressCutoff).Scan(&progressing); err != nil {
		return jobSilenceDecision{}, err
	}
	if progressing > 0 {
		return jobSilenceDecision{}, nil
	}

	if stateErr == nil {
		return jobSilenceDecision{due: true, lastReference: lastReference, backoffLevel: backoff}, nil
	}
	// Databases from before migration 27 retain event-based deduplication until
	// a lifecycle write materializes the state row.
	var alerted string
	err = queryer.QueryRowContext(ctx, `SELECT created_at FROM events WHERE type='job-silent' AND job_id=? ORDER BY created_at DESC,id DESC LIMIT 1`, jobID).Scan(&alerted)
	if err == nil {
		if parsed := scanTime(alerted); !parsed.IsZero() && now.Sub(parsed) < threshold {
			return jobSilenceDecision{}, nil
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return jobSilenceDecision{}, err
	}
	return jobSilenceDecision{due: true, lastReference: lastReference, backoffLevel: backoff}, nil
}

// jobSilenceScopeHashes loads the current persisted job definition so the
// watchdog counts checkpoints only when their pinned security scope can still
// resume. NormalizeStoredJob also supplies the one-time legacy hash for
// definitions whose port spelling changed during canonicalization.
func jobSilenceScopeHashes(definition []byte) (string, string, error) {
	job, err := unmarshalJob(definition)
	if err != nil {
		return "", "", fmt.Errorf("decode job scope for silence watchdog: %w", err)
	}
	return job.SecurityHash(), job.LegacySecurityHash(), nil
}

const maxSilenceBackoffLevel = 8

func silenceRepeatDelay(threshold time.Duration, level int) time.Duration {
	if threshold <= 0 {
		return time.Hour
	}
	if level < 0 {
		level = 0
	}
	if level > maxSilenceBackoffLevel {
		level = maxSilenceBackoffLevel
	}
	delay := threshold
	for i := 0; i < level; i++ {
		if delay >= 15*24*time.Hour {
			return 30 * 24 * time.Hour
		}
		delay *= 2
	}
	if delay > 30*24*time.Hour {
		return 30 * 24 * time.Hour
	}
	return delay
}

func humanSilenceDuration(value time.Duration) string {
	if value >= 24*time.Hour && value%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", int(value/(24*time.Hour)))
	}
	if value >= time.Hour && value%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(value/time.Hour))
	}
	if value >= time.Minute && value%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(value/time.Minute))
	}
	return value.Round(time.Second).String()
}
