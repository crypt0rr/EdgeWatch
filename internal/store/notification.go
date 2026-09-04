package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

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
	rows, err := s.DB.QueryContext(ctx, `SELECT id,name,provider,ciphertext,nonce,enabled,revision,created_at,updated_at FROM managed_notifications ORDER BY name`)
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
	row := s.DB.QueryRowContext(ctx, `SELECT id,name,provider,ciphertext,nonce,enabled,revision,created_at,updated_at FROM managed_notifications WHERE id=?`, id)
	destination, err := scanManagedNotification(row)
	if errors.Is(err, sql.ErrNoRows) {
		return destination, fmt.Errorf("%w: notification %s", ErrNotFound, id)
	}
	return destination, err
}

func (s *Store) CreateManagedNotification(ctx context.Context, id, name, provider string, ciphertext, nonce []byte, enabled bool) (ManagedNotification, error) {
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
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO managed_notifications(id,name,provider,ciphertext,nonce,enabled,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?)`, id, name, provider, ciphertext, nonce, boolInt(enabled), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return ManagedNotification{}, err
	}
	return ManagedNotification{ID: id, Name: name, Provider: provider, Ciphertext: append([]byte(nil), ciphertext...), Nonce: append([]byte(nil), nonce...), Enabled: enabled, Revision: 1, CreatedAt: now, UpdatedAt: now}, nil
}

// UpdateManagedNotification atomically updates metadata/ciphertext and
// invalidates pending deliveries from every previous revision. A delivery
// key includes the revision so a replaced URL can never receive an event that
// was queued for the old URL.
func (s *Store) UpdateManagedNotification(ctx context.Context, id string, expectedRevision int64, name, provider string, ciphertext, nonce []byte, enabled bool) (ManagedNotification, error) {
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
	if err := tx.Commit(); err != nil {
		return ManagedNotification{}, err
	}
	return ManagedNotification{ID: id, Name: name, Provider: provider, Ciphertext: append([]byte(nil), ciphertext...), Nonce: append([]byte(nil), nonce...), Enabled: enabled, Revision: next, CreatedAt: current.CreatedAt, UpdatedAt: now}, nil
}

func (s *Store) DeleteManagedNotification(ctx context.Context, id string, expectedRevision int64) error {
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
	return tx.Commit()
}
