package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
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
	// UpdateNotificationDestinations is nil when the administrator has not
	// configured update routing yet, preserving the legacy "all enabled"
	// behavior. An explicitly configured empty slice intentionally silences
	// update notifications while retaining the update state and UI indicator.
	// Store.GetApplicationUpdateState returns the default tenant's routing
	// here, and PlatformStore.GetApplicationUpdateState the platform's.
	UpdateNotificationDestinations           []string
	UpdateNotificationDestinationsConfigured bool
}

func scanApplicationUpdateState(scanner interface{ Scan(...any) error }) (ApplicationUpdateState, error) {
	var state ApplicationUpdateState
	var checked, successful string
	var destinationsJSON string
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
		&destinationsJSON,
	); err != nil {
		return state, err
	}
	state.LastCheckedAt = scanTime(checked)
	state.LastSuccessfulCheckAt = scanTime(successful)
	if strings.TrimSpace(destinationsJSON) != "" {
		var destinations []string
		if err := json.Unmarshal([]byte(destinationsJSON), &destinations); err != nil {
			return state, err
		}
		state.UpdateNotificationDestinations = normalizeUpdateDestinations(destinations)
		state.UpdateNotificationDestinationsConfigured = true
	}
	return state, nil
}

// applicationReleaseColumns are the release check columns of the platform's
// application_update_state row.
const applicationReleaseColumns = `installed_version,latest_version,release_url,release_name,published_at,etag,last_checked_at,last_successful_check_at,check_status,last_error,announced_available_version,announced_upgrade_version`

// applicationUpdateStateColumns reads the release check with the update
// routing of the default tenant. Since schema 51,
// application_update_state.notification_destinations_json holds the routing
// to platform destinations only; with a single tenant there are none, so the
// default tenant's routing is the complete update alert routing.
const applicationUpdateStateColumns = applicationReleaseColumns + `,COALESCE((SELECT update_destinations_json FROM tenants WHERE id='` + DefaultTenantID + `'),'')`

// platformUpdateStateColumns reads the release check with the platform's own
// update routing.
const platformUpdateStateColumns = applicationReleaseColumns + `,notification_destinations_json`

func applicationUpdateStateQuery() string {
	return `SELECT ` + applicationUpdateStateColumns + ` FROM application_update_state WHERE id=1`
}

// insertApplicationUpdateStateRow creates the singleton row when it is
// missing. Its notification_destinations_json is the platform routing, which
// has no destinations.
const insertApplicationUpdateStateRow = `INSERT OR IGNORE INTO application_update_state(id,check_status,notification_destinations_json) VALUES(1,'unknown','[]')`

// readTenantUpdateDestinationsTx returns a tenant's raw update routing. An
// empty value means that the routing was never configured.
func readTenantUpdateDestinationsTx(ctx context.Context, tx *sql.Tx, tenantID string) (string, error) {
	var destinationsJSON string
	err := tx.QueryRowContext(ctx, `SELECT update_destinations_json FROM tenants WHERE id=?`, tenantID).Scan(&destinationsJSON)
	return destinationsJSON, err
}

// writeTenantUpdateDestinationsTx replaces a tenant's update routing.
func writeTenantUpdateDestinationsTx(ctx context.Context, tx *sql.Tx, tenantID, destinationsJSON string) error {
	result, err := tx.ExecContext(ctx, `UPDATE tenants SET update_destinations_json=? WHERE id=?`, destinationsJSON, tenantID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return fmt.Errorf("tenant %s: %w", tenantID, ErrNotFound)
	}
	return nil
}

func normalizeUpdateDestinations(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// GetApplicationUpdateState returns the release check with the default
// tenant's update routing, which drives the update alerts while there is one
// tenant.
//
// Deprecated: bound to DefaultTenantScope for the routing. Use
// PlatformStore.GetApplicationUpdateState for the release check and
// TenantStore.ApplicationUpdateRouting for a tenant's routing.
func (s *Store) GetApplicationUpdateState(ctx context.Context) (ApplicationUpdateState, error) {
	return readApplicationUpdateState(ctx, s, applicationUpdateStateColumns)
}

// GetApplicationUpdateState returns the release check with the platform's
// own update routing, which may select platform destinations only. A
// tenant's routing is read with TenantStore.ApplicationUpdateRouting.
func (ps *PlatformStore) GetApplicationUpdateState(ctx context.Context) (ApplicationUpdateState, error) {
	return readApplicationUpdateState(ctx, ps.store, platformUpdateStateColumns)
}

// readApplicationUpdateState reads the singleton row with the given columns
// and creates the row first when it is missing.
func readApplicationUpdateState(ctx context.Context, s *Store, columns string) (ApplicationUpdateState, error) {
	query := `SELECT ` + columns + ` FROM application_update_state WHERE id=1`
	readDB := s.reader()
	state, err := scanApplicationUpdateState(readDB.QueryRowContext(ctx, query))
	if errors.Is(err, sql.ErrNoRows) {
		if _, insertErr := s.DB.ExecContext(ctx, insertApplicationUpdateStateRow); insertErr != nil {
			return state, insertErr
		}
		return scanApplicationUpdateState(readDB.QueryRowContext(ctx, query))
	}
	return state, err
}

// ApplicationUpdateRouting is a tenant's routing of the application update
// alerts. Destinations holds stable destination selectors, never URLs.
type ApplicationUpdateRouting struct {
	// Destinations is nil when the routing was never configured, which keeps
	// the legacy "every enabled destination" behavior. A configured empty
	// slice silences the update alerts.
	Destinations []string
	Configured   bool
}

// ApplicationUpdateRouting returns the tenant's update alert routing. Each
// tenant has its own; another tenant's routing is never read.
func (ts *TenantStore) ApplicationUpdateRouting(ctx context.Context) (ApplicationUpdateRouting, error) {
	if err := ts.ready(); err != nil {
		return ApplicationUpdateRouting{}, err
	}
	var destinationsJSON string
	err := ts.store.reader().QueryRowContext(ctx, `SELECT update_destinations_json FROM tenants WHERE id=?`, ts.scope.id).Scan(&destinationsJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return ApplicationUpdateRouting{}, fmt.Errorf("tenant %s: %w", ts.scope.id, ErrNotFound)
	}
	if err != nil {
		return ApplicationUpdateRouting{}, err
	}
	if strings.TrimSpace(destinationsJSON) == "" {
		return ApplicationUpdateRouting{}, nil
	}
	var destinations []string
	if err := json.Unmarshal([]byte(destinationsJSON), &destinations); err != nil {
		return ApplicationUpdateRouting{}, err
	}
	return ApplicationUpdateRouting{Destinations: normalizeUpdateDestinations(destinations), Configured: true}, nil
}

// SetApplicationUpdateDestinations stores the administrator's explicit update
// notification routing.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.SetApplicationUpdateDestinations.
func (s *Store) SetApplicationUpdateDestinations(ctx context.Context, destinations []string, audit AuditEntry) error {
	return s.Tenant(DefaultTenantScope()).SetApplicationUpdateDestinations(ctx, destinations, audit)
}

// SetApplicationUpdateDestinations stores the tenant administrator's explicit
// update notification routing. The destination identifiers are stable opaque
// selectors; URLs and credentials never enter this record. The caller checks
// the selection against the tenant's destinations first. Another tenant's
// routing is never changed.
func (ts *TenantStore) SetApplicationUpdateDestinations(ctx context.Context, destinations []string, audit AuditEntry) error {
	if err := ts.ready(); err != nil {
		return err
	}
	destinations = normalizeUpdateDestinations(destinations)
	raw, err := json.Marshal(destinations)
	if err != nil {
		return err
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := writeTenantUpdateDestinationsTx(ctx, tx, ts.scope.id, string(raw)); err != nil {
		return err
	}
	if audit.Action != "" {
		if err := insertAuditEntryExec(ctx, tx, audit, time.Now().UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// removeApplicationUpdateDestinationTx drops a deleted destination from a
// tenant's explicitly configured update routing. When it was the only
// selection, the routing stays configured and empty, which keeps update
// alerts silent rather than reverting to the legacy "every destination"
// fallback.
func removeApplicationUpdateDestinationTx(ctx context.Context, tx *sql.Tx, tenantID, id string) (bool, error) {
	destinationsJSON, err := readTenantUpdateDestinationsTx(ctx, tx, tenantID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && strings.TrimSpace(destinationsJSON) == "") {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var destinations []string
	if err := json.Unmarshal([]byte(destinationsJSON), &destinations); err != nil {
		return false, err
	}
	current := normalizeUpdateDestinations(destinations)
	kept := slices.DeleteFunc(slices.Clone(current), func(selector string) bool { return selector == id })
	if len(kept) == len(current) {
		return false, nil
	}
	raw, err := json.Marshal(kept)
	if err != nil {
		return false, err
	}
	if err := writeTenantUpdateDestinationsTx(ctx, tx, tenantID, string(raw)); err != nil {
		return false, err
	}
	return true, nil
}

// replaceApplicationUpdateDestinationsTx applies replacements, a map from an
// old destination selector to its replacement, to a tenant's explicitly
// configured update routing, and returns the old selectors it replaced.
// Routing that was never configured keeps following every enabled
// destination, and an explicitly empty routing stays silent.
func replaceApplicationUpdateDestinationsTx(ctx context.Context, tx *sql.Tx, tenantID string, replacements map[string]string) ([]string, error) {
	destinationsJSON, err := readTenantUpdateDestinationsTx(ctx, tx, tenantID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && strings.TrimSpace(destinationsJSON) == "") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var destinations []string
	if err := json.Unmarshal([]byte(destinationsJSON), &destinations); err != nil {
		return nil, err
	}
	current := normalizeUpdateDestinations(destinations)
	updated := make([]string, 0, len(current))
	var replaced []string
	for _, selector := range current {
		if replacement, ok := replacements[selector]; ok {
			replaced = append(replaced, selector)
			selector = replacement
		}
		updated = append(updated, selector)
	}
	if len(replaced) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(normalizeUpdateDestinations(updated))
	if err != nil {
		return nil, err
	}
	if err := writeTenantUpdateDestinationsTx(ctx, tx, tenantID, string(raw)); err != nil {
		return nil, err
	}
	return replaced, nil
}

// RecordInstalledVersion persists the running build version. It forwards to
// PlatformStore.RecordInstalledVersion.
func (s *Store) RecordInstalledVersion(ctx context.Context, current, releaseURL string, notify bool, destinations []string) ([]model.Event, error) {
	return s.Platform().RecordInstalledVersion(ctx, current, releaseURL, notify, destinations)
}

// RecordInstalledVersion persists the running build version. When notify is
// true, the transition and its notification intent are committed atomically.
// The first observed version is intentionally seeded without an event by the
// caller, preventing a false "updated from unknown" alert after migration.
// The alert is a platform event, and destinations are the selectors that the
// update routing resolved.
func (ps *PlatformStore) RecordInstalledVersion(ctx context.Context, current, releaseURL string, notify bool, destinations []string) ([]model.Event, error) {
	current = strings.TrimSpace(current)
	if current == "" {
		return nil, nil
	}
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var previous, announced string
	if err := tx.QueryRowContext(ctx, `SELECT installed_version,announced_upgrade_version FROM application_update_state WHERE id=1`).Scan(&previous, &announced); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO application_update_state(id,installed_version,check_status,notification_destinations_json) VALUES(1,?,'unknown','[]')`, current); err != nil {
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
	// The update alert is a platform event, so the event and its deliveries
	// have no tenant.
	if err = insertEventExec(ctx, tx, event, payload, now); err != nil {
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

// RecordReleaseCheck stores a successful release response. It forwards to
// PlatformStore.RecordReleaseCheck.
func (s *Store) RecordReleaseCheck(ctx context.Context, current, version, releaseURL, releaseName, publishedAt, etag string, notify bool, destinations []string) ([]model.Event, error) {
	return s.Platform().RecordReleaseCheck(ctx, current, version, releaseURL, releaseName, publishedAt, etag, notify, destinations)
}

// RecordReleaseCheck stores a successful release response and, when a newer
// release is available, queues one notification for the installation to the
// destinations that the update routing resolved.
func (ps *PlatformStore) RecordReleaseCheck(ctx context.Context, current, version, releaseURL, releaseName, publishedAt, etag string, notify bool, destinations []string) ([]model.Event, error) {
	current = strings.TrimSpace(current)
	version = strings.TrimSpace(version)
	releaseURL = strings.TrimSpace(releaseURL)
	releaseName = strings.TrimSpace(releaseName)
	publishedAt = strings.TrimSpace(publishedAt)
	etag = strings.TrimSpace(etag)
	now := time.Now().UTC()
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var announced string
	if err := tx.QueryRowContext(ctx, `SELECT announced_available_version FROM application_update_state WHERE id=1`).Scan(&announced); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO application_update_state(id,installed_version,latest_version,release_url,release_name,published_at,etag,last_checked_at,last_successful_check_at,check_status,last_error,notification_destinations_json) VALUES(?,?,?,?,?,?,?,?,?,'ok','','[]') ON CONFLICT(id) DO UPDATE SET latest_version=excluded.latest_version,release_url=excluded.release_url,release_name=excluded.release_name,published_at=excluded.published_at,etag=excluded.etag,last_checked_at=excluded.last_checked_at,last_successful_check_at=excluded.last_successful_check_at,check_status='ok',last_error=''`, 1, current, version, releaseURL, releaseName, publishedAt, etag, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
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
		// A platform event, like the upgrade alert above.
		if err = insertEventExec(ctx, tx, event, payload, now); err != nil {
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

// RecordReleaseNotModified refreshes the check timestamps. It forwards to
// PlatformStore.RecordReleaseNotModified.
func (s *Store) RecordReleaseNotModified(ctx context.Context, etag string) error {
	return s.Platform().RecordReleaseNotModified(ctx, etag)
}

// RecordReleaseNotModified refreshes check timestamps while retaining the
// cached release metadata and current availability state.
func (ps *PlatformStore) RecordReleaseNotModified(ctx context.Context, etag string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := ps.store.DB.ExecContext(ctx, `UPDATE application_update_state SET etag=CASE WHEN ? <> '' THEN ? ELSE etag END,last_checked_at=?,last_successful_check_at=?,check_status='ok',last_error='' WHERE id=1`, strings.TrimSpace(etag), strings.TrimSpace(etag), now, now)
	return err
}

// RecordReleaseCheckFailure records a failed release check. It forwards to
// PlatformStore.RecordReleaseCheckFailure.
func (s *Store) RecordReleaseCheckFailure(ctx context.Context, message string) error {
	return s.Platform().RecordReleaseCheckFailure(ctx, message)
}

// RecordReleaseCheckFailure leaves the last successful release untouched and
// records only a bounded diagnostic for the authenticated status view.
func (ps *PlatformStore) RecordReleaseCheckFailure(ctx context.Context, message string) error {
	message = strings.TrimSpace(message)
	if len(message) > 256 {
		message = message[:256]
	}
	_, err := ps.store.DB.ExecContext(ctx, `UPDATE application_update_state SET last_checked_at=?,check_status='failed',last_error=? WHERE id=1`, time.Now().UTC().Format(time.RFC3339Nano), message)
	return err
}
