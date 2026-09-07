package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// ApplicationUpdateState is the durable, non-secret release-check state used
// by the daemon and authenticated status API.
type ApplicationUpdateState struct {
	InstalledVersion          string
	LatestVersion             string
	ReleaseURL                string
	ReleaseName               string
	PublishedAt               string
	ETag                      string
	LastCheckedAt             time.Time
	LastSuccessfulCheckAt     time.Time
	CheckStatus               string
	LastError                 string
	AnnouncedAvailableVersion string
	AnnouncedUpgradeVersion   string
}

func scanApplicationUpdateState(scanner interface{ Scan(...any) error }) (ApplicationUpdateState, error) {
	var state ApplicationUpdateState
	var checked, successful string
	if err := scanner.Scan(
		&state.InstalledVersion,
		&state.LatestVersion,
		&state.ReleaseURL,
		&state.ReleaseName,
		&state.PublishedAt,
		&state.ETag,
		&checked,
		&successful,
		&state.CheckStatus,
		&state.LastError,
		&state.AnnouncedAvailableVersion,
		&state.AnnouncedUpgradeVersion,
	); err != nil {
		return state, err
	}
	state.LastCheckedAt = scanTime(checked)
	state.LastSuccessfulCheckAt = scanTime(successful)
	return state, nil
}

func (s *Store) GetApplicationUpdateState(ctx context.Context) (ApplicationUpdateState, error) {
	state, err := scanApplicationUpdateState(s.DB.QueryRowContext(ctx, `SELECT installed_version,latest_version,release_url,release_name,published_at,etag,last_checked_at,last_successful_check_at,check_status,last_error,announced_available_version,announced_upgrade_version FROM application_update_state WHERE id=1`))
	if errors.Is(err, sql.ErrNoRows) {
		if _, insertErr := s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO application_update_state(id,check_status) VALUES(1,'unknown')`); insertErr != nil {
			return state, insertErr
		}
		return scanApplicationUpdateState(s.DB.QueryRowContext(ctx, `SELECT installed_version,latest_version,release_url,release_name,published_at,etag,last_checked_at,last_successful_check_at,check_status,last_error,announced_available_version,announced_upgrade_version FROM application_update_state WHERE id=1`))
	}
	return state, err
}

// RecordInstalledVersion persists the running build version. When notify is
// true, the transition and its notification intent are committed atomically.
// The first observed version is intentionally seeded without an event by the
// caller, preventing a false "updated from unknown" alert after migration.
func (s *Store) RecordInstalledVersion(ctx context.Context, current, releaseURL string, notify bool, destinations []string) ([]model.Event, error) {
	current = strings.TrimSpace(current)
	if current == "" {
		return nil, nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var previous, announced string
	if err := tx.QueryRowContext(ctx, `SELECT installed_version,announced_upgrade_version FROM application_update_state WHERE id=1`).Scan(&previous, &announced); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO application_update_state(id,installed_version,check_status) VALUES(1,?,'unknown')`, current); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE application_update_state SET installed_version=? WHERE id=1`, current); err != nil {
		return nil, err
	}
	// A rollback is recorded but is not an upgrade notification. Clear the
	// previous announcement marker so a later re-install of that version is a
	// genuine transition again rather than being suppressed as a duplicate.
	if !notify && previous != "" && previous != current {
		if _, err = tx.ExecContext(ctx, `UPDATE application_update_state SET announced_upgrade_version='' WHERE id=1`); err != nil {
			return nil, err
		}
	}
	if !notify || previous == "" || previous == current || announced == current {
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	now := time.Now().UTC()
	event := model.Event{
		Type:            "application-updated",
		Message:         "EdgeWatch updated",
		PreviousVersion: previous,
		CurrentVersion:  current,
		ReleaseURL:      strings.TrimSpace(releaseURL),
		CreatedAt:       now,
	}
	bounded, payload, err := model.MarshalBoundedEvent(event, model.EventPayloadLimit)
	if err != nil {
		return nil, err
	}
	event = bounded
	if _, err = tx.ExecContext(ctx, `INSERT INTO events(type,job,job_id,scan_id,payload_json,created_at) VALUES(?,?,?,?,?,?)`, event.Type, event.Job, event.JobID, event.ScanID, payload, now.Format(time.RFC3339Nano)); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE application_update_state SET announced_upgrade_version=? WHERE id=1`, current); err != nil {
		return nil, err
	}
	if err = queueEventsTx(ctx, tx, []model.Event{event}, destinations); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return []model.Event{event}, nil
}

// RecordReleaseCheck stores a successful release response and, when a newer
// release is available, queues one notification for the installation.
func (s *Store) RecordReleaseCheck(ctx context.Context, current, version, releaseURL, releaseName, publishedAt, etag string, notify bool, destinations []string) ([]model.Event, error) {
	current = strings.TrimSpace(current)
	version = strings.TrimSpace(version)
	releaseURL = strings.TrimSpace(releaseURL)
	releaseName = strings.TrimSpace(releaseName)
	publishedAt = strings.TrimSpace(publishedAt)
	etag = strings.TrimSpace(etag)
	now := time.Now().UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var announced string
	if err := tx.QueryRowContext(ctx, `SELECT announced_available_version FROM application_update_state WHERE id=1`).Scan(&announced); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO application_update_state(id,installed_version,latest_version,release_url,release_name,published_at,etag,last_checked_at,last_successful_check_at,check_status,last_error) VALUES(?,?,?,?,?,?,?,?,?,'ok','') ON CONFLICT(id) DO UPDATE SET latest_version=excluded.latest_version,release_url=excluded.release_url,release_name=excluded.release_name,published_at=excluded.published_at,etag=excluded.etag,last_checked_at=excluded.last_checked_at,last_successful_check_at=excluded.last_successful_check_at,check_status='ok',last_error=''`, 1, current, version, releaseURL, releaseName, publishedAt, etag, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return nil, err
	}
	// The caller only invokes this method for a semantic-version newer than the
	// current build. Keeping the comparison outside the store avoids coupling
	// SQLite persistence to a version parser.
	var events []model.Event
	if notify && version != "" && version != current && announced != version {
		event := model.Event{Type: "application-update-available", Message: "EdgeWatch update available", CurrentVersion: current, LatestVersion: version, ReleaseURL: releaseURL, CreatedAt: now}
		bounded, payload, marshalErr := model.MarshalBoundedEvent(event, model.EventPayloadLimit)
		if marshalErr != nil {
			return nil, marshalErr
		}
		event = bounded
		if _, err = tx.ExecContext(ctx, `INSERT INTO events(type,job,job_id,scan_id,payload_json,created_at) VALUES(?,?,?,?,?,?)`, event.Type, event.Job, event.JobID, event.ScanID, payload, now.Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE application_update_state SET announced_available_version=? WHERE id=1`, version); err != nil {
			return nil, err
		}
		if err = queueEventsTx(ctx, tx, []model.Event{event}, destinations); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

// RecordReleaseNotModified refreshes check timestamps while retaining the
// cached release metadata and current availability state.
func (s *Store) RecordReleaseNotModified(ctx context.Context, etag string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.DB.ExecContext(ctx, `UPDATE application_update_state SET etag=CASE WHEN ? <> '' THEN ? ELSE etag END,last_checked_at=?,last_successful_check_at=?,check_status='ok',last_error='' WHERE id=1`, strings.TrimSpace(etag), strings.TrimSpace(etag), now, now)
	return err
}

// RecordReleaseCheckFailure leaves the last successful release untouched and
// records only a bounded diagnostic for the authenticated status view.
func (s *Store) RecordReleaseCheckFailure(ctx context.Context, message string) error {
	message = strings.TrimSpace(message)
	if len(message) > 256 {
		message = message[:256]
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE application_update_state SET last_checked_at=?,check_status='failed',last_error=? WHERE id=1`, time.Now().UTC().Format(time.RFC3339Nano), message)
	return err
}
