package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// EnsureDeploymentNotificationIDs returns stable opaque selectors for the
// deployment-managed destination hashes supplied by the notifier. The legacy
// hash is retained only as an internal lookup key so existing job selections
// can be translated without exposing the digest to API clients.
func (s *Store) EnsureDeploymentNotificationIDs(ctx context.Context, legacyHashes []string) (map[string]string, error) {
	result := make(map[string]string, len(legacyHashes))
	if len(legacyHashes) == 0 {
		return result, nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	for _, raw := range legacyHashes {
		hash := strings.TrimSpace(raw)
		if hash == "" {
			continue
		}
		var opaque string
		err := tx.QueryRowContext(ctx, `SELECT opaque_id FROM deployment_notification_ids WHERE legacy_hash=?`, hash).Scan(&opaque)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if errors.Is(err, sql.ErrNoRows) {
			opaque = uuid.NewString()
			if _, err = tx.ExecContext(ctx, `INSERT INTO deployment_notification_ids(legacy_hash,opaque_id,created_at) VALUES(?,?,?)`, hash, opaque, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
				return nil, err
			}
		}
		result[hash] = opaque
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}
