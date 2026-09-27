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
	// UpdateNotificationDestinations is the platform's update routing, the
	// platform destinations that the platform's copy of an update alert goes
	// to. It is nil when the routing was never configured, and the platform
	// routing has no legacy "every destination" mode, so nil and an empty
	// slice both select nothing. A tenant's routing is read with
	// TenantStore.ApplicationUpdateRouting.
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

// platformUpdateStateColumns reads the release check with the platform's own
// update routing. Since schema 51,
// application_update_state.notification_destinations_json holds the routing
// to platform destinations only; each tenant's routing is on its tenants row.
const platformUpdateStateColumns = applicationReleaseColumns + `,notification_destinations_json`

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

// ErrInvalidDestinationSelection reports a routing selection that names a
// destination its owner does not have. The notifier's selection check
// refuses with the same error, so a caller handles both alike.
var ErrInvalidDestinationSelection = errors.New("invalid notification destination selection")

// unknownDestinationSelection is the ValidationError for a selector that
// names no destination of the routing's owner. It names only the selector,
// with the notifier's text, so another owner's destination and a deleted one
// read exactly as an unknown ID.
func unknownDestinationSelection(selector string) error {
	return NewValidationError(fmt.Errorf("%w: notification destination %q was not found", ErrInvalidDestinationSelection, selector))
}

// requireTenantUpdateDestinationsTx refuses a tenant's normalized update
// routing unless each selector names a destination of the tenant: a
// web-managed destination of the tenant, paused or not, or, for the default
// tenant, which owns them, a deployment destination from config.yaml.
// Deployment destinations are not stored, so a file: selector is checked
// for its owner only; the notifier checks that config.yaml lists it.
func requireTenantUpdateDestinationsTx(ctx context.Context, tx *sql.Tx, tenantID string, destinations []string) error {
	for _, selector := range destinations {
		if id, deployment := strings.CutPrefix(selector, "file:"); deployment {
			if tenantID != DefaultTenantID || id == "" {
				return unknownDestinationSelection(selector)
			}
			continue
		}
		var found int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM managed_notifications WHERE id=? AND tenant_id=?`, selector, tenantID).Scan(&found)
		if errors.Is(err, sql.ErrNoRows) {
			return unknownDestinationSelection(selector)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// requirePlatformUpdateDestinationsTx refuses the platform's normalized
// update routing unless each selector names a platform destination, a
// web-managed destination without a tenant, paused or not. The deployment
// destinations from config.yaml are the default tenant's, so a file:
// selector is refused too.
func requirePlatformUpdateDestinationsTx(ctx context.Context, tx *sql.Tx, destinations []string) error {
	for _, selector := range destinations {
		if strings.HasPrefix(selector, "file:") {
			return unknownDestinationSelection(selector)
		}
		var found int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM managed_notifications WHERE id=? AND tenant_id IS NULL`, selector).Scan(&found)
		if errors.Is(err, sql.ErrNoRows) {
			return unknownDestinationSelection(selector)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// SetApplicationUpdateDestinations stores the tenant administrator's explicit
// update notification routing. The destination identifiers are stable opaque
// selectors; URLs and credentials never enter this record. Callers check the
// selection with the notifier first, for its message; the store checks it
// again in the transaction of the write, so the routing selects only the
// tenant's own destinations, as requireTenantUpdateDestinationsTx describes,
// even when a caller skipped its check or a destination was deleted since.
// Another tenant's destination, a platform destination, and an unknown ID
// are refused alike with an ErrInvalidDestinationSelection ValidationError,
// and nothing changes. Another tenant's routing is never changed.
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
	if err := requireTenantUpdateDestinationsTx(ctx, tx, ts.scope.id, destinations); err != nil {
		return err
	}
	if err := writeTenantUpdateDestinationsTx(ctx, tx, ts.scope.id, string(raw)); err != nil {
		return err
	}
	if audit.Action != "" {
		if err := ts.insertAuditEntry(ctx, tx, audit, time.Now().UTC()); err != nil {
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

// UpdateAlertRoute is where one owner's copy of an update alert goes. The
// platform and each tenant have their own copy, which only their own
// administrators see and which goes only to their own destinations.
type UpdateAlertRoute struct {
	// TenantID is the tenant whose copy this is, or "" for the platform's.
	TenantID string
	// Destinations are the queue keys that the owner's update routing
	// resolved to. The platform's may name only platform destinations,
	// which are web-managed destinations without a tenant. A tenant's may
	// name only that tenant's destinations, and the deployment destinations
	// from config.yaml only for the default tenant, which owns them.
	Destinations []string
}

// recordUpdateAlertTx records one update alert in tx: the platform's event,
// which has no tenant, and a copy for each tenant route whose tenant is
// still active, each queued only to its owner's destinations. A tenant that
// is paused or being deleted gets no copy, and neither does an active tenant
// without a route. The events are returned in the order of the routes, the
// platform's first.
//
// The owner of each destination is checked here as well as by the caller's
// routing: queueEventsTx discards a managed destination of another owner as
// a deleted one, and a deployment destination, which is not a managed one,
// is queued only for the default tenant's copy.
func recordUpdateAlertTx(ctx context.Context, tx *sql.Tx, event model.Event, now time.Time, routes []UpdateAlertRoute) ([]model.Event, error) {
	event.JobID, event.Job, event.TenantID = "", "", ""
	bounded, payload, err := model.MarshalBoundedEvent(event, model.EventPayloadLimit)
	if err != nil {
		return nil, err
	}
	var platform []string
	var tenantRoutes []UpdateAlertRoute
	seen := map[string]bool{}
	for _, route := range routes {
		if route.TenantID == "" {
			platform = append(platform, route.Destinations...)
			continue
		}
		if !seen[route.TenantID] {
			seen[route.TenantID] = true
			tenantRoutes = append(tenantRoutes, route)
		}
	}
	if err := insertEventExec(ctx, tx, bounded, payload, now); err != nil {
		return nil, err
	}
	if err := queueEventsTx(ctx, tx, []model.Event{bounded}, ownedUpdateDestinations("", platform)); err != nil {
		return nil, err
	}
	events := []model.Event{bounded}
	for _, route := range tenantRoutes {
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants WHERE id=? AND state=?`, route.TenantID, TenantStateActive).Scan(&active); err != nil {
			return nil, err
		}
		if active == 0 {
			continue
		}
		tenantCopy := bounded
		tenantCopy.TenantID = route.TenantID
		if err := insertEventExec(ctx, tx, tenantCopy, payload, now); err != nil {
			return nil, err
		}
		if err := queueEventsTx(ctx, tx, []model.Event{tenantCopy}, ownedUpdateDestinations(route.TenantID, route.Destinations)); err != nil {
			return nil, err
		}
		events = append(events, tenantCopy)
	}
	return events, nil
}

// ownedUpdateDestinations drops the deployment destinations from the
// destinations of an update alert copy, unless the copy is the default
// tenant's: config.yaml destinations belong to the default tenant. The
// managed destinations are checked against the copy's owner when they are
// queued.
func ownedUpdateDestinations(tenantID string, destinations []string) []string {
	if tenantID == DefaultTenantID {
		return destinations
	}
	owned := make([]string, 0, len(destinations))
	for _, destination := range destinations {
		if strings.HasPrefix(destination, "managed:") {
			owned = append(owned, destination)
		}
	}
	return owned
}

// RecordInstalledVersion persists the running build version. When notify is
// true, the transition and its notification intent are committed atomically.
// The first observed version is intentionally seeded without an event by the
// caller, preventing a false "updated from unknown" alert after migration.
// The alert is recorded for the platform and for each active tenant of
// routes, and queued to the destinations of each route, as
// recordUpdateAlertTx describes.
func (ps *PlatformStore) RecordInstalledVersion(ctx context.Context, current, releaseURL string, notify bool, routes []UpdateAlertRoute) ([]model.Event, error) {
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
	events, err := recordUpdateAlertTx(ctx, tx, event, now, routes)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE application_update_state SET announced_upgrade_version=? WHERE id=1`, current); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

// RecordReleaseCheck stores a successful release response and, when a newer
// release is available, records one alert for the installation: the
// platform's and each active tenant's copy of routes, queued to the
// destinations of each route, as recordUpdateAlertTx describes.
func (ps *PlatformStore) RecordReleaseCheck(ctx context.Context, current, version, releaseURL, releaseName, publishedAt, etag string, notify bool, routes []UpdateAlertRoute) ([]model.Event, error) {
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
		if events, err = recordUpdateAlertTx(ctx, tx, event, now, routes); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE application_update_state SET announced_available_version=? WHERE id=1`, version); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

// RecordReleaseNotModified refreshes check timestamps while retaining the
// cached release metadata and current availability state.
func (ps *PlatformStore) RecordReleaseNotModified(ctx context.Context, etag string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := ps.store.DB.ExecContext(ctx, `UPDATE application_update_state SET etag=CASE WHEN ? <> '' THEN ? ELSE etag END,last_checked_at=?,last_successful_check_at=?,check_status='ok',last_error='' WHERE id=1`, strings.TrimSpace(etag), strings.TrimSpace(etag), now, now)
	return err
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
