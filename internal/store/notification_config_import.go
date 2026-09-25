package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// DeploymentNotificationImport is one notification URL from config.yaml that
// the notify package has sealed for a new web-managed destination. The store
// never receives the URL itself: LegacyHash is the URL's internal SHA-256
// digest, which also keys its deployment ID row.
type DeploymentNotificationImport struct {
	LegacyHash string
	ID         string
	Name       string
	Provider   string
	Ciphertext []byte
	Nonce      []byte
}

// ImportedDeploymentNotification identifies one destination created by an
// import. DeploymentID is the opaque ID of the deployment destination that it
// replaces; neither value is derived from the URL.
type ImportedDeploymentNotification struct {
	ID           string
	Name         string
	DeploymentID string
}

// DeploymentNotificationImportResult summarizes a committed import with
// counts and stable IDs only.
type DeploymentNotificationImportResult struct {
	Imported []ImportedDeploymentNotification
	// Skipped counts URLs that an earlier import had already recorded.
	Skipped              int
	ChangedJobs          []string
	UpdateRoutingChanged bool
	// MovedDeliveries counts pending deliveries now addressed to an imported
	// destination; MergedDeliveries counts duplicate rows folded into them.
	MovedDeliveries  int64
	MergedDeliveries int64
}

// Notification config import states recorded for the health command.
const (
	NotificationConfigImportNone     = "none"
	NotificationConfigImportImported = "imported"
	NotificationConfigImportFailed   = "failed"
)

// NotificationConfigImport is the outcome of the latest daemon start's import
// of notification URLs from config.yaml. It holds counts and a bounded error
// code; URLs and their digests are never stored here.
type NotificationConfigImport struct {
	Status string
	// ConfiguredURLs is the number of distinct URLs config.yaml listed.
	ConfiguredURLs int
	// ImportedURLs is the number of those URLs that are recorded as imported
	// and are therefore no longer delivered from config.yaml.
	ImportedURLs int
	ErrorCode    string
	UpdatedAt    time.Time
}

// Health warnings reported while config.yaml still lists notification URLs.
const (
	NotificationURLsImportedWarning = "notification URLs in config.yaml were imported; remove them from config.yaml"
	notificationURLsFailedWarning   = "notification URLs in config.yaml could not be imported (%s); they are still delivered from config.yaml"
)

// Warnings returns the operator-facing health warnings for the import state.
func (state NotificationConfigImport) Warnings() []string {
	var warnings []string
	if state.ImportedURLs > 0 {
		warnings = append(warnings, NotificationURLsImportedWarning)
	}
	if state.Status == NotificationConfigImportFailed {
		code := state.ErrorCode
		if code == "" {
			code = "import_failed"
		}
		warnings = append(warnings, fmt.Sprintf(notificationURLsFailedWarning, code))
	}
	return warnings
}

// importedDeploymentColumnExists lets host commands that open an existing,
// not yet migrated database keep the pre-import behavior instead of failing.
func importedDeploymentColumnExists(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (bool, error) {
	var columns int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('deployment_notification_ids') WHERE name='imported_at'`).Scan(&columns); err != nil {
		return false, err
	}
	return columns > 0, nil
}

// ImportedDeploymentNotifications returns the supplied URL digests that an
// import has recorded, including those whose destination was deleted later.
// Such a URL is no longer a deployment destination.
func (s *Store) ImportedDeploymentNotifications(ctx context.Context, legacyHashes []string) (map[string]bool, error) {
	imported := make(map[string]bool, len(legacyHashes))
	if len(legacyHashes) == 0 {
		return imported, nil
	}
	reader := s.reader()
	exists, err := importedDeploymentColumnExists(ctx, reader)
	if err != nil || !exists {
		return imported, err
	}
	wanted := make(map[string]struct{}, len(legacyHashes))
	for _, hash := range legacyHashes {
		wanted[hash] = struct{}{}
	}
	rows, err := reader.QueryContext(ctx, `SELECT legacy_hash FROM deployment_notification_ids WHERE imported_at<>''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, err
		}
		if _, ok := wanted[hash]; ok {
			imported[hash] = true
		}
	}
	return imported, rows.Err()
}

// ImportDeploymentNotifications creates each sealed destination and moves every
// reference to its deployment destination onto it in one transaction: job
// selections, the application update routing, pending deliveries (including
// rows queued under the legacy URL-digest alias), and delivery health. A URL
// that an earlier import recorded is skipped, even when its destination has
// since been deleted. Any error rolls the whole import back.
func (s *Store) ImportDeploymentNotifications(ctx context.Context, items []DeploymentNotificationImport) (DeploymentNotificationImportResult, error) {
	var result DeploymentNotificationImportResult
	if len(items) == 0 {
		return result, nil
	}
	for _, item := range items {
		if strings.TrimSpace(item.LegacyHash) == "" || strings.TrimSpace(item.ID) == "" || strings.TrimSpace(item.Provider) == "" {
			return result, errors.New("imported notification requires a digest, ID, and provider")
		}
		if strings.TrimSpace(item.Name) == "" {
			return result, errors.New("notification name is required")
		}
		if len(item.Ciphertext) == 0 || len(item.Nonce) == 0 {
			return result, errors.New("notification ciphertext is required")
		}
	}
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback() }()
	var audits []AuditEntry
	// Job and update routing may name a deployment destination by its opaque
	// ID or, from before opaque IDs, by its URL digest. Both spellings map to
	// the imported destination and are rewritten once all rows exist, so a job
	// that selects several imported URLs gets a single new revision.
	replacements := map[string]string{}
	deployments := map[string]ImportedDeploymentNotification{}
	for _, item := range items {
		deploymentID, imported, err := deploymentNotificationIDTx(ctx, tx, item.LegacyHash, stamp)
		if err != nil {
			return DeploymentNotificationImportResult{}, err
		}
		if imported {
			result.Skipped++
			continue
		}
		name, err := uniqueManagedNotificationNameTx(ctx, tx, strings.TrimSpace(item.Name))
		if err != nil {
			return DeploymentNotificationImportResult{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO managed_notifications(id,name,provider,ciphertext,nonce,enabled,revision,credential_revision,created_at,updated_at) VALUES(?,?,?,?,?,1,1,1,?,?)`, item.ID, name, item.Provider, item.Ciphertext, item.Nonce, stamp, stamp); err != nil {
			return DeploymentNotificationImportResult{}, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE deployment_notification_ids SET managed_notification_id=?,imported_at=? WHERE legacy_hash=?`, item.ID, stamp, item.LegacyHash); err != nil {
			return DeploymentNotificationImportResult{}, err
		}
		created := ImportedDeploymentNotification{ID: item.ID, Name: name, DeploymentID: deploymentID}
		for _, selector := range []string{"file:" + deploymentID, "file:" + item.LegacyHash} {
			replacements[selector] = item.ID
			deployments[selector] = created
		}
		identities := []string{deploymentID, item.LegacyHash}
		target := managedNotificationKey(item.ID, 1)
		moved, merged, err := moveDeploymentDeliveriesTx(ctx, tx, identities, target)
		if err != nil {
			return DeploymentNotificationImportResult{}, err
		}
		if err := mergeDeploymentDeliveryHealthTx(ctx, tx, identities, deliveryIdentity(target), moved > 0, now); err != nil {
			return DeploymentNotificationImportResult{}, err
		}
		result.Imported = append(result.Imported, created)
		result.MovedDeliveries += moved
		result.MergedDeliveries += merged
	}
	if len(replacements) > 0 {
		changedJobs, err := replaceNotificationDestinationsInJobsTx(ctx, tx, replacements, now)
		if err != nil {
			return DeploymentNotificationImportResult{}, err
		}
		for _, job := range changedJobs {
			result.ChangedJobs = append(result.ChangedJobs, job.jobID)
			for _, created := range importedFor(job.replaced, deployments) {
				audits = append(audits, AuditEntry{Action: "job.notification_destination_replaced", Detail: fmt.Sprintf("%s: replaced deployment notification destination %s with imported destination %s", job.jobID, created.DeploymentID, created.ID)})
			}
		}
		routed, err := replaceApplicationUpdateDestinationsTx(ctx, tx, replacements)
		if err != nil {
			return DeploymentNotificationImportResult{}, err
		}
		result.UpdateRoutingChanged = len(routed) > 0
		for _, created := range importedFor(routed, deployments) {
			audits = append(audits, AuditEntry{Action: "notifications.update_routing", Detail: fmt.Sprintf("replaced deployment notification destination %s with imported destination %s in application update notification routing", created.DeploymentID, created.ID)})
		}
	}
	if len(result.Imported) > 0 {
		ids := make([]string, 0, len(result.Imported))
		for _, imported := range result.Imported {
			ids = append(ids, imported.ID)
		}
		summary := AuditEntry{Action: "notifications.config_imported", Detail: fmt.Sprintf("imported %d notification URLs from config.yaml as web-managed destinations %s; %d jobs rerouted; %d pending deliveries moved, %d duplicates merged", len(ids), strings.Join(ids, ","), len(result.ChangedJobs), result.MovedDeliveries, result.MergedDeliveries)}
		audits = append([]AuditEntry{summary}, audits...)
	}
	if err := insertAuditEntries(ctx, tx, audits, now); err != nil {
		return DeploymentNotificationImportResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeploymentNotificationImportResult{}, err
	}
	return result, nil
}

// importedFor returns the imported destinations behind the replaced
// selectors, once each and in the order of the selectors given.
func importedFor(selectors []string, deployments map[string]ImportedDeploymentNotification) []ImportedDeploymentNotification {
	var out []ImportedDeploymentNotification
	seen := map[string]struct{}{}
	for _, selector := range selectors {
		created, ok := deployments[selector]
		if !ok {
			continue
		}
		if _, duplicate := seen[created.ID]; duplicate {
			continue
		}
		seen[created.ID] = struct{}{}
		out = append(out, created)
	}
	return out
}

// deploymentNotificationIDTx returns the opaque deployment ID for a digest,
// creating it as EnsureDeploymentNotificationIDs would when the URL has never
// been loaded, and whether an import has already recorded the digest.
func deploymentNotificationIDTx(ctx context.Context, tx *sql.Tx, legacyHash, stamp string) (string, bool, error) {
	var opaque, importedAt string
	err := tx.QueryRowContext(ctx, `SELECT opaque_id,imported_at FROM deployment_notification_ids WHERE legacy_hash=?`, legacyHash).Scan(&opaque, &importedAt)
	if err == nil {
		return opaque, importedAt != "", nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", false, err
	}
	opaque = uuid.NewString()
	if _, err := tx.ExecContext(ctx, `INSERT INTO deployment_notification_ids(legacy_hash,opaque_id,created_at) VALUES(?,?,?)`, legacyHash, opaque, stamp); err != nil {
		return "", false, err
	}
	return opaque, false, nil
}

// maxImportedNameSuffix bounds the search for a free destination name.
const maxImportedNameSuffix = 10000

// uniqueManagedNotificationNameTx returns base, or base with the lowest free
// numeric suffix ("Deployment destination 2"), so an import never collides
// with the unique name of an existing web-managed destination.
func uniqueManagedNotificationNameTx(ctx context.Context, tx *sql.Tx, base string) (string, error) {
	for suffix := 1; suffix <= maxImportedNameSuffix; suffix++ {
		candidate := base
		if suffix > 1 {
			candidate = fmt.Sprintf("%s %d", base, suffix)
		}
		var taken int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM managed_notifications WHERE name=?`, candidate).Scan(&taken); err != nil {
			return "", err
		}
		if taken == 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no free notification name for %q", base)
}

type pendingDeliveryRow struct {
	id        int64
	attempts  int
	deferrals int
	nextAt    string
	keeper    int64
}

// moveDeploymentDeliveriesTx re-addresses the unsent deliveries of the given
// deployment selectors to target. A payload queued under both the opaque ID
// and the legacy digest alias is the same alert for the same URL; the rows are
// folded into the lowest row ID, which keeps the fewest attempts and
// deferrals and the earliest due time, so the alert is still delivered once
// and the outbox uniqueness constraint holds.
func moveDeploymentDeliveriesTx(ctx context.Context, tx *sql.Tx, selectors []string, target string) (moved, merged int64, err error) {
	selectors = uniqueStrings(selectors)
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(selectors)), ",")
	args := make([]any, 0, 2*len(selectors))
	for _, selector := range selectors {
		args = append(args, selector)
	}
	pending, err := pendingDeploymentDeliveriesTx(ctx, tx, placeholders, append(append([]any{}, args...), args...))
	if err != nil {
		return 0, 0, err
	}
	groups := map[int64][]pendingDeliveryRow{}
	var keepers []int64
	for _, row := range pending {
		if _, seen := groups[row.keeper]; !seen {
			keepers = append(keepers, row.keeper)
		}
		groups[row.keeper] = append(groups[row.keeper], row)
	}
	for _, keeper := range keepers {
		group := groups[keeper]
		if len(group) < 2 {
			continue
		}
		best := group[0]
		for _, row := range group[1:] {
			best.attempts = min(best.attempts, row.attempts)
			best.deferrals = min(best.deferrals, row.deferrals)
			if scanTime(row.nextAt).Before(scanTime(best.nextAt)) {
				best.nextAt = row.nextAt
			}
		}
		for _, row := range group {
			if row.id == keeper {
				continue
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM outbox WHERE id=?`, row.id); err != nil {
				return 0, 0, err
			}
			merged++
		}
		if _, err := tx.ExecContext(ctx, `UPDATE outbox SET attempts=?,deferrals=?,next_at=? WHERE id=?`, best.attempts, best.deferrals, best.nextAt, keeper); err != nil {
			return 0, 0, err
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE outbox SET destination=? WHERE destination IN (`+placeholders+`) AND sent_at IS NULL AND terminal_at=''`, append([]any{target}, args...)...)
	if err != nil {
		return 0, 0, err
	}
	moved, err = result.RowsAffected()
	return moved, merged, err
}

// pendingDeploymentDeliveriesTx lists the unsent deliveries of the selectors
// with the lowest row ID that holds the same payload. Payloads are compared by
// SQLite and never loaded. The rows are closed before the caller writes.
func pendingDeploymentDeliveriesTx(ctx context.Context, tx *sql.Tx, placeholders string, args []any) ([]pendingDeliveryRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT o.id,o.attempts,o.deferrals,o.next_at,
 (SELECT MIN(k.id) FROM outbox k WHERE k.destination IN (`+placeholders+`) AND k.sent_at IS NULL AND k.terminal_at='' AND k.payload_json=o.payload_json)
FROM outbox o
WHERE o.destination IN (`+placeholders+`) AND o.sent_at IS NULL AND o.terminal_at=''
ORDER BY o.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pending []pendingDeliveryRow
	for rows.Next() {
		var row pendingDeliveryRow
		if err := rows.Scan(&row.id, &row.attempts, &row.deferrals, &row.nextAt, &row.keeper); err != nil {
			return nil, err
		}
		pending = append(pending, row)
	}
	return pending, rows.Err()
}

type deliveryHealthRow struct {
	terminal    int
	success     string
	failure     string
	terminalAt  string
	code        string
	fingerprint string
	updated     string
}

// mergeDeploymentDeliveryHealthTx folds the delivery health of a deployment
// destination and its legacy digest alias into the imported destination's
// identity: terminal failures are summed, the latest timestamps are kept, and
// the error code and fingerprint come from the most recently updated row. A
// health row is also created when pending deliveries moved without one.
func mergeDeploymentDeliveryHealthTx(ctx context.Context, tx *sql.Tx, identities []string, target string, pending bool, now time.Time) error {
	all := uniqueStrings(append(append([]string{}, identities...), target))
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(all)), ",")
	args := make([]any, 0, len(all))
	for _, identity := range all {
		args = append(args, identity)
	}
	found, err := deliveryHealthRowsTx(ctx, tx, placeholders, args)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		if pending {
			return ensureDeliveryHealthTx(ctx, tx, target, now)
		}
		return nil
	}
	later := func(current, candidate string) string {
		if scanTime(candidate).After(scanTime(current)) {
			return candidate
		}
		return current
	}
	merged := found[0]
	for _, row := range found[1:] {
		merged.terminal += row.terminal
		merged.success = later(merged.success, row.success)
		merged.failure = later(merged.failure, row.failure)
		merged.terminalAt = later(merged.terminalAt, row.terminalAt)
		if scanTime(row.updated).After(scanTime(merged.updated)) {
			merged.code, merged.fingerprint, merged.updated = row.code, row.fingerprint, row.updated
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM notification_delivery_health WHERE destination_identity IN (`+placeholders+`)`, args...); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO notification_delivery_health(destination_identity,terminal_failures,last_success_at,last_failure_at,last_terminal_at,last_error_code,last_error_fingerprint,updated_at) VALUES(?,?,?,?,?,?,?,?)`, target, merged.terminal, merged.success, merged.failure, merged.terminalAt, merged.code, merged.fingerprint, now.Format(time.RFC3339Nano))
	return err
}

// deliveryHealthRowsTx reads the health rows of the given identities. The
// rows are closed before the caller writes.
func deliveryHealthRowsTx(ctx context.Context, tx *sql.Tx, placeholders string, args []any) ([]deliveryHealthRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT terminal_failures,last_success_at,last_failure_at,last_terminal_at,last_error_code,last_error_fingerprint,updated_at FROM notification_delivery_health WHERE destination_identity IN (`+placeholders+`) ORDER BY destination_identity`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var found []deliveryHealthRow
	for rows.Next() {
		var row deliveryHealthRow
		if err := rows.Scan(&row.terminal, &row.success, &row.failure, &row.terminalAt, &row.code, &row.fingerprint, &row.updated); err != nil {
			return nil, err
		}
		found = append(found, row)
	}
	return found, rows.Err()
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// RecordNotificationConfigImport stores the outcome of this daemon start's
// import for the read-only health command and the console.
func (s *Store) RecordNotificationConfigImport(ctx context.Context, state NotificationConfigImport) error {
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO notification_config_import(id,status,configured_urls,imported_urls,error_code,updated_at) VALUES(1,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET status=excluded.status,configured_urls=excluded.configured_urls,imported_urls=excluded.imported_urls,error_code=excluded.error_code,updated_at=excluded.updated_at`,
		state.Status, state.ConfiguredURLs, state.ImportedURLs, truncate(state.ErrorCode, 64), state.UpdatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

// NotificationConfigImportState returns the recorded import outcome. A
// database without the table, or without a recorded start, reports none.
func (s *Store) NotificationConfigImportState(ctx context.Context) (NotificationConfigImport, error) {
	return notificationConfigImportState(ctx, s.reader())
}

func notificationConfigImportState(ctx context.Context, reader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (NotificationConfigImport, error) {
	state := NotificationConfigImport{Status: NotificationConfigImportNone}
	var tables int
	if err := reader.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='notification_config_import'`).Scan(&tables); err != nil {
		return state, err
	}
	if tables == 0 {
		return state, nil
	}
	var updated string
	err := reader.QueryRowContext(ctx, `SELECT status,configured_urls,imported_urls,error_code,updated_at FROM notification_config_import WHERE id=1`).Scan(&state.Status, &state.ConfiguredURLs, &state.ImportedURLs, &state.ErrorCode, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return NotificationConfigImport{Status: NotificationConfigImportNone}, nil
	}
	if err != nil {
		return NotificationConfigImport{Status: NotificationConfigImportNone}, err
	}
	state.UpdatedAt = scanTime(updated)
	return state, nil
}
