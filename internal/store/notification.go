package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/google/uuid"
)

// ManagedNotification is the durable metadata and ciphertext for a
// web-managed Shoutrrr destination. The store deliberately has no knowledge
// of the encryption format; that boundary belongs to the notify package.
type ManagedNotification struct {
	ID string
	// TenantID is the tenant that owns the destination, or "" for a
	// platform destination.
	TenantID   string
	Name       string
	Provider   string
	Ciphertext []byte
	Nonce      []byte
	Enabled    bool
	Revision   int64
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// managedNotificationColumns are the columns that scanManagedNotification
// reads, in order.
const managedNotificationColumns = `id,name,provider,ciphertext,nonce,enabled,revision,created_at,updated_at`

// ownedDestinationSQL limits a statement on the outbox to the deliveries of a
// destination that the tenant owns. It takes two arguments, the destination
// ID and the tenant ID. Each write that uses it has already found the
// destination in the tenant in the same transaction; the predicate keeps the
// tenant check in the statement that changes the deliveries.
const ownedDestinationSQL = ` AND EXISTS (SELECT 1 FROM managed_notifications AS owner WHERE owner.id=? AND owner.tenant_id=?)`

func scanManagedNotification(scanner interface{ Scan(...any) error }, tail ...any) (ManagedNotification, error) {
	var destination ManagedNotification
	var enabled int
	var created, updated string
	columns := append([]any{&destination.ID, &destination.Name, &destination.Provider, &destination.Ciphertext, &destination.Nonce, &enabled, &destination.Revision, &created, &updated}, tail...)
	if err := scanner.Scan(columns...); err != nil {
		return destination, err
	}
	destination.Enabled = enabled != 0
	destination.CreatedAt = scanTime(created)
	destination.UpdatedAt = scanTime(updated)
	return destination, nil
}

// ListManagedNotifications returns the destinations, ordered by name.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.ListManagedNotifications.
func (s *Store) ListManagedNotifications(ctx context.Context) ([]ManagedNotification, error) {
	return s.Tenant(DefaultTenantScope()).ListManagedNotifications(ctx)
}

// ListManagedNotifications returns the tenant's destinations, ordered by
// name. Another tenant's destinations and the platform's are never listed.
func (ts *TenantStore) ListManagedNotifications(ctx context.Context) ([]ManagedNotification, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	rows, err := ts.store.reader().QueryContext(ctx, `SELECT `+managedNotificationColumns+` FROM managed_notifications WHERE tenant_id=? ORDER BY name`, ts.scope.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ManagedNotification
	for rows.Next() {
		destination, scanErr := scanManagedNotification(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		destination.TenantID = ts.scope.id
		out = append(out, destination)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ListManagedNotifications returns the destinations of every tenant and of
// the platform, ordered by name, each with its owner in TenantID. The
// notifier decrypts them all, because its delivery worker delivers the
// alerts of every tenant, and it checks that the encryption key opens every
// destination before it creates or imports with a key.
func (ss *SystemStore) ListManagedNotifications(ctx context.Context) ([]ManagedNotification, error) {
	rows, err := ss.store.reader().QueryContext(ctx, `SELECT `+managedNotificationColumns+`,COALESCE(tenant_id,'') FROM managed_notifications ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ManagedNotification
	for rows.Next() {
		var tenantID string
		destination, scanErr := scanManagedNotification(rows, &tenantID)
		if scanErr != nil {
			return nil, scanErr
		}
		destination.TenantID = tenantID
		out = append(out, destination)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// GetManagedNotification returns one destination.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.GetManagedNotification.
func (s *Store) GetManagedNotification(ctx context.Context, id string) (ManagedNotification, error) {
	return s.Tenant(DefaultTenantScope()).GetManagedNotification(ctx, id)
}

// GetManagedNotification returns one of the tenant's destinations. A
// destination of another tenant or of the platform is ErrNotFound, exactly as
// an unknown ID.
func (ts *TenantStore) GetManagedNotification(ctx context.Context, id string) (ManagedNotification, error) {
	if err := ts.ready(); err != nil {
		return ManagedNotification{}, err
	}
	destination, err := scanManagedNotification(ts.store.reader().QueryRowContext(ctx, `SELECT `+managedNotificationColumns+` FROM managed_notifications WHERE id=? AND tenant_id=?`, id, ts.scope.id))
	if errors.Is(err, sql.ErrNoRows) {
		return ManagedNotification{}, fmt.Errorf("%w: notification %s", ErrNotFound, id)
	}
	if err != nil {
		return ManagedNotification{}, err
	}
	destination.TenantID = ts.scope.id
	return destination, nil
}

// OwnsDeploymentNotifications reports whether the tenant owns the
// notification URLs that config.yaml lists and the daemon has not imported.
// Those URLs were the installation's destinations before tenants existed,
// and the import moves them into the default tenant, so they are delivered
// as the default tenant's destinations: only that tenant sees, selects,
// tests and counts them.
func (ts *TenantStore) OwnsDeploymentNotifications(_ context.Context) (bool, error) {
	if err := ts.ready(); err != nil {
		return false, err
	}
	return ts.scope.id == DefaultTenantID, nil
}

// CreateManagedNotification creates a destination.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.CreateManagedNotification.
func (s *Store) CreateManagedNotification(ctx context.Context, id, name, provider string, ciphertext, nonce []byte, enabled bool) (ManagedNotification, error) {
	return s.Tenant(DefaultTenantScope()).CreateManagedNotification(ctx, id, name, provider, ciphertext, nonce, enabled)
}

// CreateManagedNotification creates a destination in the tenant. Names are
// unique within a tenant, so another tenant may use the same name.
func (ts *TenantStore) CreateManagedNotification(ctx context.Context, id, name, provider string, ciphertext, nonce []byte, enabled bool) (ManagedNotification, error) {
	return ts.createManagedNotificationWithAuditsAndSelection(ctx, id, name, provider, ciphertext, nonce, enabled, nil, nil)
}

// CreateManagedNotificationWithAudit commits a new encrypted destination and
// its audit record together.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.CreateManagedNotificationWithAudit.
func (s *Store) CreateManagedNotificationWithAudit(ctx context.Context, id, name, provider string, ciphertext, nonce []byte, enabled bool, audit AuditEntry) (ManagedNotification, error) {
	return s.Tenant(DefaultTenantScope()).CreateManagedNotificationWithAudit(ctx, id, name, provider, ciphertext, nonce, enabled, audit)
}

// CreateManagedNotificationWithAudit commits a new encrypted destination of
// the tenant and its audit record together. The URL ciphertext is never
// included in the audit detail; callers provide only a redacted action
// description.
func (ts *TenantStore) CreateManagedNotificationWithAudit(ctx context.Context, id, name, provider string, ciphertext, nonce []byte, enabled bool, audit AuditEntry) (ManagedNotification, error) {
	return ts.createManagedNotificationWithAuditsAndSelection(ctx, id, name, provider, ciphertext, nonce, enabled, nil, []AuditEntry{audit})
}

// CreateManagedNotificationWithLegacySelection creates a destination and
// freezes the jobs that still use the pre-routing global fallback.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.CreateManagedNotificationWithLegacySelection.
func (s *Store) CreateManagedNotificationWithLegacySelection(ctx context.Context, id, name, provider string, ciphertext, nonce []byte, enabled bool, selection []string) (ManagedNotification, error) {
	return s.Tenant(DefaultTenantScope()).CreateManagedNotificationWithLegacySelection(ctx, id, name, provider, ciphertext, nonce, enabled, selection)
}

// CreateManagedNotificationWithLegacySelection creates a destination in the
// tenant and freezes the tenant's jobs that still use the pre-routing global
// fallback in the same transaction. The selection must describe the
// tenant's destinations that existed before the new destination; this keeps
// the new endpoint opt-in for existing jobs. Other tenants' jobs are never
// changed.
func (ts *TenantStore) CreateManagedNotificationWithLegacySelection(ctx context.Context, id, name, provider string, ciphertext, nonce []byte, enabled bool, selection []string) (ManagedNotification, error) {
	return ts.createManagedNotificationWithAuditsAndSelection(ctx, id, name, provider, ciphertext, nonce, enabled, cloneNotificationSelection(selection), nil)
}

// CreateManagedNotificationWithLegacySelectionAndAudit is the audited variant
// of CreateManagedNotificationWithLegacySelection.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.CreateManagedNotificationWithLegacySelectionAndAudit.
func (s *Store) CreateManagedNotificationWithLegacySelectionAndAudit(ctx context.Context, id, name, provider string, ciphertext, nonce []byte, enabled bool, selection []string, audit AuditEntry) (ManagedNotification, error) {
	return s.Tenant(DefaultTenantScope()).CreateManagedNotificationWithLegacySelectionAndAudit(ctx, id, name, provider, ciphertext, nonce, enabled, selection, audit)
}

// CreateManagedNotificationWithLegacySelectionAndAudit is the audited variant
// of TenantStore.CreateManagedNotificationWithLegacySelection.
func (ts *TenantStore) CreateManagedNotificationWithLegacySelectionAndAudit(ctx context.Context, id, name, provider string, ciphertext, nonce []byte, enabled bool, selection []string, audit AuditEntry) (ManagedNotification, error) {
	return ts.createManagedNotificationWithAuditsAndSelection(ctx, id, name, provider, ciphertext, nonce, enabled, cloneNotificationSelection(selection), []AuditEntry{audit})
}

func (ts *TenantStore) createManagedNotificationWithAuditsAndSelection(ctx context.Context, id, name, provider string, ciphertext, nonce []byte, enabled bool, selection []string, audits []AuditEntry) (ManagedNotification, error) {
	if err := ts.ready(); err != nil {
		return ManagedNotification{}, err
	}
	if name == "" {
		return ManagedNotification{}, errors.New("notification name is required")
	}
	if len(ciphertext) == 0 || len(nonce) == 0 {
		return ManagedNotification{}, errors.New("notification ciphertext is required")
	}
	if id == "" {
		id = uuid.NewString()
	}
	now := time.Now().UTC()
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return ManagedNotification{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO managed_notifications(id,tenant_id,name,provider,ciphertext,nonce,enabled,revision,credential_revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,1,1,?,?)`, id, ts.scope.id, name, provider, ciphertext, nonce, boolInt(enabled), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return ManagedNotification{}, err
	}
	if selection != nil {
		if _, err := materializeLegacyNotificationSelectionsTx(ctx, tx, ts.scope.id, selection); err != nil {
			return ManagedNotification{}, err
		}
	}
	if err := insertAuditEntries(ctx, tx, audits, now); err != nil {
		return ManagedNotification{}, err
	}
	if err := tx.Commit(); err != nil {
		return ManagedNotification{}, err
	}
	return ManagedNotification{ID: id, TenantID: ts.scope.id, Name: name, Provider: provider, Ciphertext: append([]byte(nil), ciphertext...), Nonce: append([]byte(nil), nonce...), Enabled: enabled, Revision: 1, CreatedAt: now, UpdatedAt: now}, nil
}

// MaterializeLegacyNotificationSelections freezes every job whose routing is
// still nil to the supplied destination set.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.MaterializeLegacyNotificationSelections.
func (s *Store) MaterializeLegacyNotificationSelections(ctx context.Context, selection []string) (int, error) {
	return s.Tenant(DefaultTenantScope()).MaterializeLegacyNotificationSelections(ctx, selection)
}

// MaterializeLegacyNotificationSelections freezes every job of the tenant
// whose routing is still nil to the supplied destination set, which names
// the tenant's destinations. A nil slice means that no destinations existed,
// so it is deliberately converted to a non-nil empty selection. The
// operation appends a job revision for each changed job without changing its
// effective scope: when normalization canonicalizes a legacy port spelling,
// the stored baseline and cycle scope hashes move from the legacy alias to
// the canonical hash in the same transaction. Other tenants' jobs are never
// changed.
func (ts *TenantStore) MaterializeLegacyNotificationSelections(ctx context.Context, selection []string) (int, error) {
	if err := ts.ready(); err != nil {
		return 0, err
	}
	selection = cloneNotificationSelection(selection)
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	count, err := materializeLegacyNotificationSelectionsTx(ctx, tx, ts.scope.id, selection)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

type legacyNotificationJob struct {
	id       string
	job      config.Job
	revision int64
}

// materializeLegacyNotificationSelectionsTx freezes the nil selection of the
// jobs of one tenant.
func materializeLegacyNotificationSelectionsTx(ctx context.Context, tx *sql.Tx, tenantID string, selection []string) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,definition_json,revision FROM jobs WHERE tenant_id=? ORDER BY id`, tenantID)
	if err != nil {
		return 0, err
	}
	var legacy []legacyNotificationJob
	for rows.Next() {
		var item legacyNotificationJob
		var raw []byte
		if err := rows.Scan(&item.id, &raw, &item.revision); err != nil {
			rows.Close()
			return 0, err
		}
		job, err := unmarshalJob(raw)
		if err != nil {
			rows.Close()
			return 0, err
		}
		if job.NotificationDestinations != nil {
			continue
		}
		item.job = job
		legacy = append(legacy, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	for _, item := range legacy {
		// The rewrite stores canonical port expressions, which removes the
		// legacy scope hash alias. Move matching baseline and cycle hashes to
		// the canonical hash first, as an equivalent job edit does.
		if err := migrateLegacyScopeHashTx(ctx, tx, item.id, item.job.LegacySecurityHash(), item.job.SecurityHash()); err != nil {
			return 0, err
		}
		item.job.NotificationDestinations = cloneNotificationSelection(selection)
		item.job = config.NormalizeJob(item.job)
		raw, err := marshalJob(item.job)
		if err != nil {
			return 0, err
		}
		next := item.revision + 1
		result, err := tx.ExecContext(ctx, `UPDATE jobs SET definition_json=?,revision=?,updated_at=? WHERE id=? AND revision=? AND tenant_id=?`, raw, next, now.Format(time.RFC3339Nano), item.id, item.revision, tenantID)
		if err != nil {
			return 0, err
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return 0, ErrConflict
		}
		if err := appendJobRevisionTx(ctx, tx, item.id, next, raw, item.job.SecurityHash(), now); err != nil {
			return 0, err
		}
	}
	return len(legacy), nil
}

func cloneNotificationSelection(selection []string) []string {
	cloned := make([]string, len(selection))
	copy(cloned, selection)
	return cloned
}

func managedNotificationKey(id string, revision int64) string {
	return fmt.Sprintf("managed:%s:%d", id, revision)
}

func pendingManagedDeliveryDiscardAudit(audits []AuditEntry, id string, count int64) AuditEntry {
	entry := AuditEntry{
		Action: "notifications.pending_discarded",
		Detail: fmt.Sprintf("discarded %d pending deliveries for managed notification %s after credential rotation", count, id),
	}
	// Preserve request attribution when the caller supplied the normal update
	// audit entry. No URL, provider response, or credential material is copied.
	if len(audits) > 0 {
		entry.ActorUserID = audits[0].ActorUserID
		entry.ActorUsername = audits[0].ActorUsername
		entry.RequestID = audits[0].RequestID
		entry.SourceIP = audits[0].SourceIP
	}
	return entry
}

// UpdateManagedNotification atomically updates metadata and ciphertext.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.UpdateManagedNotification.
func (s *Store) UpdateManagedNotification(ctx context.Context, id string, expectedRevision int64, name, provider string, ciphertext, nonce []byte, enabled bool) (ManagedNotification, error) {
	return s.Tenant(DefaultTenantScope()).UpdateManagedNotification(ctx, id, expectedRevision, name, provider, ciphertext, nonce, enabled)
}

// UpdateManagedNotification atomically updates the metadata and ciphertext
// of one of the tenant's destinations. Metadata only changes keep pending
// delivery intents by moving the current revision selector to the new
// revision. Credential changes deliberately discard pending intents so a
// queued event can never be sent with stale credentials; the discard is
// recorded as a redacted security-audit event. A destination of another
// tenant or of the platform is ErrNotFound, and nothing changes.
func (ts *TenantStore) UpdateManagedNotification(ctx context.Context, id string, expectedRevision int64, name, provider string, ciphertext, nonce []byte, enabled bool) (ManagedNotification, error) {
	return ts.updateManagedNotificationWithAudits(ctx, id, expectedRevision, name, provider, ciphertext, nonce, enabled, nil)
}

// UpdateManagedNotificationWithAudit atomically updates an encrypted
// destination, invalidates old pending deliveries, and records the action.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.UpdateManagedNotificationWithAudit.
func (s *Store) UpdateManagedNotificationWithAudit(ctx context.Context, id string, expectedRevision int64, name, provider string, ciphertext, nonce []byte, enabled bool, audit AuditEntry) (ManagedNotification, error) {
	return s.Tenant(DefaultTenantScope()).UpdateManagedNotificationWithAudit(ctx, id, expectedRevision, name, provider, ciphertext, nonce, enabled, audit)
}

// UpdateManagedNotificationWithAudit atomically updates one of the tenant's
// encrypted destinations, invalidates old pending deliveries, and records
// the action.
func (ts *TenantStore) UpdateManagedNotificationWithAudit(ctx context.Context, id string, expectedRevision int64, name, provider string, ciphertext, nonce []byte, enabled bool, audit AuditEntry) (ManagedNotification, error) {
	return ts.updateManagedNotificationWithAudits(ctx, id, expectedRevision, name, provider, ciphertext, nonce, enabled, []AuditEntry{audit})
}

func (ts *TenantStore) updateManagedNotificationWithAudits(ctx context.Context, id string, expectedRevision int64, name, provider string, ciphertext, nonce []byte, enabled bool, audits []AuditEntry) (ManagedNotification, error) {
	if err := ts.ready(); err != nil {
		return ManagedNotification{}, err
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return ManagedNotification{}, err
	}
	defer tx.Rollback()
	current, err := scanManagedNotification(tx.QueryRowContext(ctx, `SELECT `+managedNotificationColumns+` FROM managed_notifications WHERE id=? AND tenant_id=?`, id, ts.scope.id))
	if errors.Is(err, sql.ErrNoRows) {
		return ManagedNotification{}, fmt.Errorf("%w: notification %s", ErrNotFound, id)
	}
	if err != nil {
		return ManagedNotification{}, err
	}
	if current.Revision != expectedRevision {
		return ManagedNotification{}, ErrConflict
	}
	if name == "" {
		return ManagedNotification{}, errors.New("notification name is required")
	}
	if len(ciphertext) == 0 || len(nonce) == 0 {
		return ManagedNotification{}, errors.New("notification ciphertext is required")
	}
	now := time.Now().UTC()
	next := current.Revision + 1
	oldKey := managedNotificationKey(id, current.Revision)
	newKey := managedNotificationKey(id, next)
	credentialsChanged := current.Provider != provider || !bytes.Equal(current.Ciphertext, ciphertext) || !bytes.Equal(current.Nonce, nonce)
	// credential_revision advances only with the credentials, so an alert that
	// captured an earlier metadata revision can still be queued (see
	// resolveManagedIntentTx).
	result, err := tx.ExecContext(ctx, `UPDATE managed_notifications SET name=?,provider=?,ciphertext=?,nonce=?,enabled=?,revision=?,credential_revision=CASE WHEN ? THEN ? ELSE credential_revision END,updated_at=? WHERE id=? AND revision=? AND tenant_id=?`, name, provider, ciphertext, nonce, boolInt(enabled), next, boolInt(credentialsChanged), next, now.Format(time.RFC3339Nano), id, expectedRevision, ts.scope.id)
	if err != nil {
		return ManagedNotification{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ManagedNotification{}, ErrConflict
	}
	if credentialsChanged {
		var pending int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination LIKE ? AND sent_at IS NULL AND terminal_at=''`+ownedDestinationSQL, "managed:"+id+":%", id, ts.scope.id).Scan(&pending); err != nil {
			return ManagedNotification{}, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM outbox WHERE destination LIKE ? AND sent_at IS NULL`+ownedDestinationSQL, "managed:"+id+":%", id, ts.scope.id); err != nil {
			return ManagedNotification{}, err
		}
		if pending > 0 {
			audits = append(audits, pendingManagedDeliveryDiscardAudit(audits, id, pending))
		}
	} else {
		// A rename, provider-neutral enable/disable, or other metadata-only
		// edit does not invalidate an alert. Keep the row id and claim state so
		// an in-flight delivery can finish safely while its selector advances.
		if _, err := tx.ExecContext(ctx, `UPDATE outbox SET destination=? WHERE destination=? AND sent_at IS NULL AND terminal_at=''`+ownedDestinationSQL, newKey, oldKey, id, ts.scope.id); err != nil {
			return ManagedNotification{}, err
		}
	}
	if err := insertAuditEntries(ctx, tx, audits, now); err != nil {
		return ManagedNotification{}, err
	}
	if err := tx.Commit(); err != nil {
		return ManagedNotification{}, err
	}
	return ManagedNotification{ID: id, TenantID: ts.scope.id, Name: name, Provider: provider, Ciphertext: append([]byte(nil), ciphertext...), Nonce: append([]byte(nil), nonce...), Enabled: enabled, Revision: next, CreatedAt: current.CreatedAt, UpdatedAt: now}, nil
}

// DeleteManagedNotification removes a destination.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.DeleteManagedNotification.
func (s *Store) DeleteManagedNotification(ctx context.Context, id string, expectedRevision int64) error {
	return s.Tenant(DefaultTenantScope()).DeleteManagedNotification(ctx, id, expectedRevision)
}

// DeleteManagedNotification removes one of the tenant's destinations, as
// DeleteManagedNotificationWithAudit does, without an audit record.
func (ts *TenantStore) DeleteManagedNotification(ctx context.Context, id string, expectedRevision int64) error {
	_, err := ts.deleteManagedNotificationWithAudits(ctx, id, expectedRevision, nil)
	return err
}

// DeleteManagedNotificationWithAudit removes a destination with its audit
// row.
//
// Deprecated: bound to DefaultTenantScope. Use
// TenantStore.DeleteManagedNotificationWithAudit.
func (s *Store) DeleteManagedNotificationWithAudit(ctx context.Context, id string, expectedRevision int64, audit AuditEntry) ([]string, error) {
	return s.Tenant(DefaultTenantScope()).DeleteManagedNotificationWithAudit(ctx, id, expectedRevision, audit)
}

// DeleteManagedNotificationWithAudit removes one of the tenant's
// destinations, its pending delivery intents, and its audit row in one
// transaction. The same transaction removes the destination from the routing
// of every job of the tenant and from the tenant's application update
// routing, so no saved selection keeps pointing at it. It returns the IDs of
// the jobs whose routing changed. A destination of another tenant or of the
// platform is ErrNotFound, and nothing changes.
func (ts *TenantStore) DeleteManagedNotificationWithAudit(ctx context.Context, id string, expectedRevision int64, audit AuditEntry) ([]string, error) {
	return ts.deleteManagedNotificationWithAudits(ctx, id, expectedRevision, []AuditEntry{audit})
}

func (ts *TenantStore) deleteManagedNotificationWithAudits(ctx context.Context, id string, expectedRevision int64, audits []AuditEntry) ([]string, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM managed_notifications WHERE id=? AND tenant_id=?`, id, ts.scope.id).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: notification %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	if revision != expectedRevision {
		return nil, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM outbox WHERE destination LIKE ? AND sent_at IS NULL`+ownedDestinationSQL, "managed:"+id+":%", id, ts.scope.id); err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM managed_notifications WHERE id=? AND revision=? AND tenant_id=?`, id, expectedRevision, ts.scope.id)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, ErrConflict
	}
	now := time.Now().UTC()
	changedJobs, err := removeNotificationDestinationFromJobsTx(ctx, tx, ts.scope.id, id, now)
	if err != nil {
		return nil, err
	}
	routingChanged, err := removeApplicationUpdateDestinationTx(ctx, tx, ts.scope.id, id)
	if err != nil {
		return nil, err
	}
	for _, jobID := range changedJobs {
		audits = append(audits, deletedDestinationRoutingAudit(audits, "job.notification_destination_removed", fmt.Sprintf("%s: removed deleted notification destination %s from job routing", jobID, id)))
	}
	if routingChanged {
		audits = append(audits, deletedDestinationRoutingAudit(audits, "notifications.update_routing", fmt.Sprintf("removed deleted notification destination %s from application update notification routing", id)))
	}
	if err := insertAuditEntries(ctx, tx, audits, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return changedJobs, nil
}

// deletedDestinationRoutingAudit attributes an automatic routing change to the
// operator who deleted the destination. Only stable IDs enter the detail.
func deletedDestinationRoutingAudit(audits []AuditEntry, action, detail string) AuditEntry {
	entry := AuditEntry{Action: action, Detail: detail}
	if len(audits) > 0 {
		entry.ActorUserID = audits[0].ActorUserID
		entry.ActorUsername = audits[0].ActorUsername
		entry.RequestID = audits[0].RequestID
		entry.SourceIP = audits[0].SourceIP
	}
	return entry
}

type routedNotificationJob struct {
	id       string
	job      config.Job
	revision int64
}

// jobsSelectingNotificationDestinationTx reads every job of the tenant,
// archived or not, whose saved routing selects any of the given destination
// selectors. The rows are closed before the caller writes to the same
// transaction.
func jobsSelectingNotificationDestinationTx(ctx context.Context, tx *sql.Tx, tenantID string, ids ...string) ([]routedNotificationJob, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,definition_json,revision FROM jobs WHERE tenant_id=? ORDER BY id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var selecting []routedNotificationJob
	for rows.Next() {
		var item routedNotificationJob
		var raw []byte
		if err := rows.Scan(&item.id, &raw, &item.revision); err != nil {
			return nil, err
		}
		job, err := unmarshalJob(raw)
		if err != nil {
			return nil, err
		}
		if !slices.ContainsFunc(job.NotificationDestinations, func(selector string) bool { return slices.Contains(ids, selector) }) {
			continue
		}
		item.job = job
		selecting = append(selecting, item)
	}
	return selecting, rows.Err()
}

// removeNotificationDestinationFromJobsTx drops a deleted destination from
// every job of the tenant that selected it, including archived jobs, and
// appends a job revision for each change. Routing is not part of the
// security scope, so the baseline and any in-flight scan are unaffected.
func removeNotificationDestinationFromJobsTx(ctx context.Context, tx *sql.Tx, tenantID, id string, now time.Time) ([]string, error) {
	affected, err := jobsSelectingNotificationDestinationTx(ctx, tx, tenantID, id)
	if err != nil {
		return nil, err
	}
	changed := make([]string, 0, len(affected))
	for _, item := range affected {
		legacyHash := item.job.LegacySecurityHash()
		// Keep an explicit empty selection when the deleted destination was the
		// only one: the job stays silent instead of reverting to the legacy
		// "every destination" fallback.
		item.job.NotificationDestinations = slices.DeleteFunc(cloneNotificationSelection(item.job.NotificationDestinations), func(selector string) bool { return selector == id })
		raw, err := marshalJob(item.job)
		if err != nil {
			return nil, err
		}
		next := item.revision + 1
		result, err := tx.ExecContext(ctx, `UPDATE jobs SET definition_json=?,revision=?,updated_at=? WHERE id=? AND revision=? AND tenant_id=?`, raw, next, now.Format(time.RFC3339Nano), item.id, item.revision, tenantID)
		if err != nil {
			return nil, err
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return nil, ErrConflict
		}
		if err := appendJobRevisionTx(ctx, tx, item.id, next, raw, item.job.SecurityHash(), now); err != nil {
			return nil, err
		}
		// Rewriting the stored definition persists its canonical port spelling.
		// Move matching baseline metadata along, as a normal job edit does.
		if err := migrateLegacyScopeHashTx(ctx, tx, item.id, legacyHash, item.job.SecurityHash()); err != nil {
			return nil, err
		}
		changed = append(changed, item.id)
	}
	return changed, nil
}

// replaceNotificationDestinationsInJobsTx applies replacements, a map from an
// old destination selector to its replacement, to every job of the tenant
// that selects any of the old selectors, including archived jobs. Each
// changed job gets one new revision, however many of its selectors change.
// It mirrors removeNotificationDestinationFromJobsTx: a nil selection is
// never selected, so it keeps following every enabled destination, and
// routing is not part of the security scope, so baselines and in-flight
// scans are unaffected. The selection stays sorted and free of duplicates,
// as a normalized job definition is. It returns, per changed job, the old
// selectors it replaced.
func replaceNotificationDestinationsInJobsTx(ctx context.Context, tx *sql.Tx, tenantID string, replacements map[string]string, now time.Time) ([]replacedJobSelection, error) {
	selectors := make([]string, 0, len(replacements))
	for selector := range replacements {
		selectors = append(selectors, selector)
	}
	affected, err := jobsSelectingNotificationDestinationTx(ctx, tx, tenantID, selectors...)
	if err != nil {
		return nil, err
	}
	changed := make([]replacedJobSelection, 0, len(affected))
	for _, item := range affected {
		legacyHash := item.job.LegacySecurityHash()
		var replaced []string
		item.job.NotificationDestinations, replaced = replaceNotificationSelectors(item.job.NotificationDestinations, replacements)
		raw, err := marshalJob(item.job)
		if err != nil {
			return nil, err
		}
		next := item.revision + 1
		result, err := tx.ExecContext(ctx, `UPDATE jobs SET definition_json=?,revision=?,updated_at=? WHERE id=? AND revision=? AND tenant_id=?`, raw, next, now.Format(time.RFC3339Nano), item.id, item.revision, tenantID)
		if err != nil {
			return nil, err
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return nil, ErrConflict
		}
		if err := appendJobRevisionTx(ctx, tx, item.id, next, raw, item.job.SecurityHash(), now); err != nil {
			return nil, err
		}
		// Rewriting the stored definition persists its canonical port spelling.
		// Move matching baseline metadata along, as a normal job edit does.
		if err := migrateLegacyScopeHashTx(ctx, tx, item.id, legacyHash, item.job.SecurityHash()); err != nil {
			return nil, err
		}
		changed = append(changed, replacedJobSelection{jobID: item.id, replaced: replaced})
	}
	return changed, nil
}

// replacedJobSelection names a job whose routing changed and the old
// selectors that were replaced in it.
type replacedJobSelection struct {
	jobID    string
	replaced []string
}

// replaceNotificationSelectors returns a sorted, duplicate-free copy of
// selection with each selector in replacements swapped for its replacement,
// and the old selectors that were found.
func replaceNotificationSelectors(selection []string, replacements map[string]string) ([]string, []string) {
	out := make([]string, 0, len(selection))
	var replaced []string
	seen := make(map[string]struct{}, len(selection))
	for _, selector := range selection {
		if replacement, ok := replacements[selector]; ok {
			replaced = append(replaced, selector)
			selector = replacement
		}
		if _, duplicate := seen[selector]; duplicate {
			continue
		}
		seen[selector] = struct{}{}
		out = append(out, selector)
	}
	slices.Sort(out)
	return out, replaced
}
