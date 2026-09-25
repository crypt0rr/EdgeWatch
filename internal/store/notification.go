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
	ID         string
	Name       string
	Provider   string
	Ciphertext []byte
	Nonce      []byte
	Enabled    bool
	Revision   int64
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func scanManagedNotification(scanner interface{ Scan(...any) error }) (ManagedNotification, error) {
	var destination ManagedNotification
	var enabled int
	var created, updated string
	if err := scanner.Scan(&destination.ID, &destination.Name, &destination.Provider, &destination.Ciphertext, &destination.Nonce, &enabled, &destination.Revision, &created, &updated); err != nil {
		return destination, err
	}
	destination.Enabled = enabled != 0
	destination.CreatedAt = scanTime(created)
	destination.UpdatedAt = scanTime(updated)
	return destination, nil
}

func (s *Store) ListManagedNotifications(ctx context.Context) ([]ManagedNotification, error) {
	rows, err := s.reader().QueryContext(ctx, `SELECT id,name,provider,ciphertext,nonce,enabled,revision,created_at,updated_at FROM managed_notifications ORDER BY name`)
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
		out = append(out, destination)
	}
	return out, rows.Err()
}

func (s *Store) GetManagedNotification(ctx context.Context, id string) (ManagedNotification, error) {
	row := s.reader().QueryRowContext(ctx, `SELECT id,name,provider,ciphertext,nonce,enabled,revision,created_at,updated_at FROM managed_notifications WHERE id=?`, id)
	destination, err := scanManagedNotification(row)
	if errors.Is(err, sql.ErrNoRows) {
		return destination, fmt.Errorf("%w: notification %s", ErrNotFound, id)
	}
	return destination, err
}

func (s *Store) CreateManagedNotification(ctx context.Context, id, name, provider string, ciphertext, nonce []byte, enabled bool) (ManagedNotification, error) {
	return s.createManagedNotificationWithAuditsAndSelection(ctx, id, name, provider, ciphertext, nonce, enabled, nil, nil)
}

// CreateManagedNotificationWithAudit commits a new encrypted destination and
// its audit record together. The URL ciphertext is never included in the
// audit detail; callers provide only a redacted action description.
func (s *Store) CreateManagedNotificationWithAudit(ctx context.Context, id, name, provider string, ciphertext, nonce []byte, enabled bool, audit AuditEntry) (ManagedNotification, error) {
	return s.createManagedNotificationWithAuditsAndSelection(ctx, id, name, provider, ciphertext, nonce, enabled, nil, []AuditEntry{audit})
}

// CreateManagedNotificationWithLegacySelection creates a destination and
// freezes jobs that still use the pre-routing global fallback in the same
// transaction. The selection must describe destinations that existed before
// the new destination; this keeps the new endpoint opt-in for existing jobs.
func (s *Store) CreateManagedNotificationWithLegacySelection(ctx context.Context, id, name, provider string, ciphertext, nonce []byte, enabled bool, selection []string) (ManagedNotification, error) {
	return s.createManagedNotificationWithAuditsAndSelection(ctx, id, name, provider, ciphertext, nonce, enabled, cloneNotificationSelection(selection), nil)
}

// CreateManagedNotificationWithLegacySelectionAndAudit is the audited variant
// of CreateManagedNotificationWithLegacySelection.
func (s *Store) CreateManagedNotificationWithLegacySelectionAndAudit(ctx context.Context, id, name, provider string, ciphertext, nonce []byte, enabled bool, selection []string, audit AuditEntry) (ManagedNotification, error) {
	return s.createManagedNotificationWithAuditsAndSelection(ctx, id, name, provider, ciphertext, nonce, enabled, cloneNotificationSelection(selection), []AuditEntry{audit})
}

func (s *Store) createManagedNotificationWithAuditsAndSelection(ctx context.Context, id, name, provider string, ciphertext, nonce []byte, enabled bool, selection []string, audits []AuditEntry) (ManagedNotification, error) {
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
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ManagedNotification{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO managed_notifications(id,name,provider,ciphertext,nonce,enabled,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?)`, id, name, provider, ciphertext, nonce, boolInt(enabled), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return ManagedNotification{}, err
	}
	if selection != nil {
		if _, err := materializeLegacyNotificationSelectionsTx(ctx, tx, selection); err != nil {
			return ManagedNotification{}, err
		}
	}
	if err := insertAuditEntries(ctx, tx, audits, now); err != nil {
		return ManagedNotification{}, err
	}
	if err := tx.Commit(); err != nil {
		return ManagedNotification{}, err
	}
	return ManagedNotification{ID: id, Name: name, Provider: provider, Ciphertext: append([]byte(nil), ciphertext...), Nonce: append([]byte(nil), nonce...), Enabled: enabled, Revision: 1, CreatedAt: now, UpdatedAt: now}, nil
}

// MaterializeLegacyNotificationSelections freezes every job whose routing is
// still nil to the supplied global destination set. A nil slice means that
// no destinations existed, so it is deliberately converted to a non-nil
// empty selection. The operation appends a job revision for each changed job
// without changing its effective scope: when normalization canonicalizes a
// legacy port spelling, the stored baseline and cycle scope hashes move from
// the legacy alias to the canonical hash in the same transaction.
func (s *Store) MaterializeLegacyNotificationSelections(ctx context.Context, selection []string) (int, error) {
	selection = cloneNotificationSelection(selection)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	count, err := materializeLegacyNotificationSelectionsTx(ctx, tx, selection)
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

func materializeLegacyNotificationSelectionsTx(ctx context.Context, tx *sql.Tx, selection []string) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,definition_json,revision FROM jobs ORDER BY id`)
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
		result, err := tx.ExecContext(ctx, `UPDATE jobs SET definition_json=?,revision=?,updated_at=? WHERE id=? AND revision=?`, raw, next, now.Format(time.RFC3339Nano), item.id, item.revision)
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

// UpdateManagedNotification atomically updates metadata/ciphertext. Metadata
// only changes keep pending delivery intents by moving the current revision
// selector to the new revision. Credential changes deliberately discard
// pending intents so a queued event can never be sent with stale credentials;
// the discard is recorded as a redacted security-audit event.
func (s *Store) UpdateManagedNotification(ctx context.Context, id string, expectedRevision int64, name, provider string, ciphertext, nonce []byte, enabled bool) (ManagedNotification, error) {
	return s.updateManagedNotificationWithAudits(ctx, id, expectedRevision, name, provider, ciphertext, nonce, enabled, nil)
}

// UpdateManagedNotificationWithAudit atomically updates an encrypted
// destination, invalidates old pending deliveries, and records the action.
func (s *Store) UpdateManagedNotificationWithAudit(ctx context.Context, id string, expectedRevision int64, name, provider string, ciphertext, nonce []byte, enabled bool, audit AuditEntry) (ManagedNotification, error) {
	return s.updateManagedNotificationWithAudits(ctx, id, expectedRevision, name, provider, ciphertext, nonce, enabled, []AuditEntry{audit})
}

func (s *Store) updateManagedNotificationWithAudits(ctx context.Context, id string, expectedRevision int64, name, provider string, ciphertext, nonce []byte, enabled bool, audits []AuditEntry) (ManagedNotification, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ManagedNotification{}, err
	}
	defer tx.Rollback()
	current, err := scanManagedNotification(tx.QueryRowContext(ctx, `SELECT id,name,provider,ciphertext,nonce,enabled,revision,created_at,updated_at FROM managed_notifications WHERE id=?`, id))
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
	result, err := tx.ExecContext(ctx, `UPDATE managed_notifications SET name=?,provider=?,ciphertext=?,nonce=?,enabled=?,revision=?,updated_at=? WHERE id=? AND revision=?`, name, provider, ciphertext, nonce, boolInt(enabled), next, now.Format(time.RFC3339Nano), id, expectedRevision)
	if err != nil {
		return ManagedNotification{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ManagedNotification{}, ErrConflict
	}
	if credentialsChanged {
		var pending int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination LIKE ? AND sent_at IS NULL AND terminal_at=''`, "managed:"+id+":%").Scan(&pending); err != nil {
			return ManagedNotification{}, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM outbox WHERE destination LIKE ? AND sent_at IS NULL`, "managed:"+id+":%"); err != nil {
			return ManagedNotification{}, err
		}
		if pending > 0 {
			audits = append(audits, pendingManagedDeliveryDiscardAudit(audits, id, pending))
		}
	} else {
		// A rename, provider-neutral enable/disable, or other metadata-only
		// edit does not invalidate an alert. Keep the row id and claim state so
		// an in-flight delivery can finish safely while its selector advances.
		if _, err := tx.ExecContext(ctx, `UPDATE outbox SET destination=? WHERE destination=? AND sent_at IS NULL AND terminal_at=''`, newKey, oldKey); err != nil {
			return ManagedNotification{}, err
		}
	}
	if err := insertAuditEntries(ctx, tx, audits, now); err != nil {
		return ManagedNotification{}, err
	}
	if err := tx.Commit(); err != nil {
		return ManagedNotification{}, err
	}
	return ManagedNotification{ID: id, Name: name, Provider: provider, Ciphertext: append([]byte(nil), ciphertext...), Nonce: append([]byte(nil), nonce...), Enabled: enabled, Revision: next, CreatedAt: current.CreatedAt, UpdatedAt: now}, nil
}

func (s *Store) DeleteManagedNotification(ctx context.Context, id string, expectedRevision int64) error {
	_, err := s.deleteManagedNotificationWithAudits(ctx, id, expectedRevision, nil)
	return err
}

// DeleteManagedNotificationWithAudit removes a destination, pending delivery
// intents, and its audit row in one transaction. The same transaction removes
// the destination from every job's routing and from the application update
// routing, so no saved selection keeps pointing at it. It returns the IDs of
// the jobs whose routing changed.
func (s *Store) DeleteManagedNotificationWithAudit(ctx context.Context, id string, expectedRevision int64, audit AuditEntry) ([]string, error) {
	return s.deleteManagedNotificationWithAudits(ctx, id, expectedRevision, []AuditEntry{audit})
}

func (s *Store) deleteManagedNotificationWithAudits(ctx context.Context, id string, expectedRevision int64, audits []AuditEntry) ([]string, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM managed_notifications WHERE id=?`, id).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: notification %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	if revision != expectedRevision {
		return nil, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM outbox WHERE destination LIKE ? AND sent_at IS NULL`, "managed:"+id+":%"); err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM managed_notifications WHERE id=? AND revision=?`, id, expectedRevision)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, ErrConflict
	}
	now := time.Now().UTC()
	changedJobs, err := removeNotificationDestinationFromJobsTx(ctx, tx, id, now)
	if err != nil {
		return nil, err
	}
	routingChanged, err := removeApplicationUpdateDestinationTx(ctx, tx, id)
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

// jobsSelectingNotificationDestinationTx reads every job, archived or not,
// whose saved routing selects the destination. The rows are closed before
// the caller writes to the same transaction.
func jobsSelectingNotificationDestinationTx(ctx context.Context, tx *sql.Tx, id string) ([]routedNotificationJob, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,definition_json,revision FROM jobs ORDER BY id`)
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
		if !slices.Contains(job.NotificationDestinations, id) {
			continue
		}
		item.job = job
		selecting = append(selecting, item)
	}
	return selecting, rows.Err()
}

// removeNotificationDestinationFromJobsTx drops a deleted destination from
// every job that selected it, including archived jobs, and appends a job
// revision for each change. Routing is not part of the security scope, so the
// baseline and any in-flight scan are unaffected.
func removeNotificationDestinationFromJobsTx(ctx context.Context, tx *sql.Tx, id string, now time.Time) ([]string, error) {
	affected, err := jobsSelectingNotificationDestinationTx(ctx, tx, id)
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
		result, err := tx.ExecContext(ctx, `UPDATE jobs SET definition_json=?,revision=?,updated_at=? WHERE id=? AND revision=?`, raw, next, now.Format(time.RFC3339Nano), item.id, item.revision)
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
