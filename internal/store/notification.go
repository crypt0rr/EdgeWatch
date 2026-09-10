package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
// but leaves its security hash and runtime comparison state untouched.
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

// UpdateManagedNotification atomically updates metadata/ciphertext and
// invalidates pending deliveries from every previous revision. A delivery
// key includes the revision so a replaced URL can never receive an event that
// was queued for the old URL.
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
	result, err := tx.ExecContext(ctx, `UPDATE managed_notifications SET name=?,provider=?,ciphertext=?,nonce=?,enabled=?,revision=?,updated_at=? WHERE id=? AND revision=?`, name, provider, ciphertext, nonce, boolInt(enabled), next, now.Format(time.RFC3339Nano), id, expectedRevision)
	if err != nil {
		return ManagedNotification{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ManagedNotification{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM outbox WHERE destination LIKE ? AND sent_at IS NULL`, "managed:"+id+":%"); err != nil {
		return ManagedNotification{}, err
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
	return s.deleteManagedNotificationWithAudits(ctx, id, expectedRevision, nil)
}

// DeleteManagedNotificationWithAudit removes a destination, pending delivery
// intents, and its audit row in one transaction.
func (s *Store) DeleteManagedNotificationWithAudit(ctx context.Context, id string, expectedRevision int64, audit AuditEntry) error {
	return s.deleteManagedNotificationWithAudits(ctx, id, expectedRevision, []AuditEntry{audit})
}

func (s *Store) deleteManagedNotificationWithAudits(ctx context.Context, id string, expectedRevision int64, audits []AuditEntry) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM managed_notifications WHERE id=?`, id).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: notification %s", ErrNotFound, id)
	}
	if err != nil {
		return err
	}
	if revision != expectedRevision {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM outbox WHERE destination LIKE ? AND sent_at IS NULL`, "managed:"+id+":%"); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM managed_notifications WHERE id=? AND revision=?`, id, expectedRevision)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrConflict
	}
	if err := insertAuditEntries(ctx, tx, audits, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}
