package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// MigrateAdminCompatibility upgrades the original administrator's legacy TOTP
// ciphertext during daemon startup. It is intentionally separate from
// GetAdmin so authentication reads remain safe on a query-only database
// connection. Schema 52 retired the legacy admins row, so the users row is
// the only administrator record and nothing else is synchronized. The upgrade
// commits in one transaction; callers receive any decryption, encryption,
// SQL, or commit failure.
func (s *Store) MigrateAdminCompatibility(ctx context.Context) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin administrator compatibility migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var stored string
	err = tx.QueryRowContext(ctx, `SELECT totp_secret FROM users WHERE id=?`, LegacyAdminUserID).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return tx.Commit()
	}
	if err != nil {
		return fmt.Errorf("read authoritative administrator for compatibility migration: %w", err)
	}
	if stored != "" {
		secret, migrate, secretErr := s.openTOTPSecretForOwner(LegacyAdminUserID, stored)
		if secretErr != nil {
			return fmt.Errorf("read administrator TOTP secret for compatibility migration: %w", secretErr)
		}
		if migrate && secret != "" {
			stored, err = s.sealTOTPSecretForOwner(LegacyAdminUserID, secret)
			if err != nil {
				return fmt.Errorf("upgrade administrator TOTP secret: %w", err)
			}
			if _, err = tx.ExecContext(ctx, `UPDATE users SET totp_secret=? WHERE id=?`, stored, LegacyAdminUserID); err != nil {
				return fmt.Errorf("store upgraded administrator TOTP secret: %w", err)
			}
		}
	}
	return tx.Commit()
}
