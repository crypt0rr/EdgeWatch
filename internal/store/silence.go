package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
// The returned bool reports whether a new event was committed.
func (s *Store) RecordJobSilenceAlert(ctx context.Context, jobID, job string, createdAt, now time.Time, threshold time.Duration, destinations []string) (model.Event, bool, error) {
	if jobID == "" || threshold <= 0 {
		return model.Event{}, false, nil
	}
	now = now.UTC()
	createdAt = createdAt.UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
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
		message += "; last success " + lastReference.Format(time.RFC3339)
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
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(type,job,job_id,scan_id,payload_json,created_at) VALUES(?,?,?,?,?,?)`, bounded.Type, bounded.Job, bounded.JobID, bounded.ScanID, payload, now.Format(time.RFC3339Nano)); err != nil {
		return model.Event{}, false, err
	}
	if err := queueEventsTx(ctx, tx, []model.Event{bounded}, destinations); err != nil {
		return model.Event{}, false, err
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
func (s *Store) JobSilenceDue(ctx context.Context, jobID string, createdAt, now time.Time, threshold time.Duration) (bool, error) {
	if jobID == "" || threshold <= 0 {
		return false, nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	decision, err := jobSilenceDecisionTx(ctx, tx, jobID, createdAt, now, threshold)
	return decision.due, err
}

type jobSilenceDecision struct {
	due           bool
	lastReference time.Time
}

func jobSilenceDecisionTx(ctx context.Context, tx *sql.Tx, jobID string, createdAt, now time.Time, threshold time.Duration) (jobSilenceDecision, error) {
	if jobID == "" || threshold <= 0 {
		return jobSilenceDecision{}, nil
	}
	now = now.UTC()
	createdAt = createdAt.UTC()
	lastReference := createdAt
	var finished string
	err := tx.QueryRowContext(ctx, `SELECT finished_at FROM scans WHERE job_id=? AND status='success' ORDER BY finished_at DESC,id DESC LIMIT 1`, jobID).Scan(&finished)
	if err == nil {
		if parsed := scanTime(finished); !parsed.IsZero() {
			lastReference = parsed
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return jobSilenceDecision{}, err
	}
	if lastReference.IsZero() || now.Sub(lastReference) < threshold {
		return jobSilenceDecision{}, nil
	}

	// A scan that is currently running is still making progress. Do not alert
	// while it owns a live lease, even if the previous successful result is old.
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_leases WHERE job=? AND expires_at>?`, jobID, now.Format(time.RFC3339Nano)).Scan(&active); err != nil {
		return jobSilenceDecision{}, err
	}
	if active > 0 {
		return jobSilenceDecision{}, nil
	}

	// Use the schedule interval as the deduplication window. If the daemon is
	// restarted or its heartbeat fires repeatedly, one warning is retained per
	// window while the job remains silent.
	var alerted string
	err = tx.QueryRowContext(ctx, `SELECT created_at FROM events WHERE type='job-silent' AND job_id=? ORDER BY created_at DESC,id DESC LIMIT 1`, jobID).Scan(&alerted)
	if err == nil {
		if parsed := scanTime(alerted); !parsed.IsZero() && now.Sub(parsed) < threshold {
			return jobSilenceDecision{}, nil
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return jobSilenceDecision{}, err
	}
	return jobSilenceDecision{due: true, lastReference: lastReference}, nil
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
