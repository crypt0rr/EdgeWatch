package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// MigrateAdminCompatibility performs the legacy administrator synchronization
// and TOTP ciphertext upgrade during daemon startup. It is intentionally
// separate from GetAdmin so authentication reads remain safe on a query-only
// database connection. All database changes commit together; callers receive
// any decryption, encryption, SQL, or commit failure.
func (s *Store) MigrateAdminCompatibility(ctx context.Context) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin administrator compatibility migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var username, displayName, passwordHash, stored, created, updated string
	var totpEnabled int
	err = tx.QueryRowContext(ctx, `SELECT username,display_name,password_hash,totp_secret,totp_enabled,created_at,updated_at FROM users WHERE id=?`, LegacyAdminUserID).
		Scan(&username, &displayName, &passwordHash, &stored, &totpEnabled, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return migrateLegacyAdminRow(ctx, tx, s)
	}
	if err != nil {
		return fmt.Errorf("read authoritative administrator for compatibility migration: %w", err)
	}
	displayName = adminDisplayName(Admin{Username: username, DisplayName: displayName})
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

	var legacyUsername, legacyDisplayName, legacyPasswordHash, legacySecret, legacyCreated, legacyUpdated string
	var legacyTOTPEnabled int
	legacyErr := tx.QueryRowContext(ctx, `SELECT username,display_name,password_hash,totp_secret,totp_enabled,created_at,updated_at FROM admins WHERE id=1`).
		Scan(&legacyUsername, &legacyDisplayName, &legacyPasswordHash, &legacySecret, &legacyTOTPEnabled, &legacyCreated, &legacyUpdated)
	if legacyErr == nil && legacyUsername == username && legacyDisplayName == displayName && legacyPasswordHash == passwordHash && legacySecret == stored && legacyTOTPEnabled == totpEnabled && legacyCreated == created && legacyUpdated == updated {
		return tx.Commit()
	}
	if legacyErr != nil && !errors.Is(legacyErr, sql.ErrNoRows) {
		return fmt.Errorf("read legacy administrator compatibility row: %w", legacyErr)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO admins(id,username,display_name,password_hash,totp_secret,totp_enabled,created_at,updated_at) VALUES(1,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET username=excluded.username,display_name=excluded.display_name,password_hash=excluded.password_hash,totp_secret=excluded.totp_secret,totp_enabled=excluded.totp_enabled,created_at=excluded.created_at,updated_at=excluded.updated_at`, username, displayName, passwordHash, stored, totpEnabled, created, updated); err != nil {
		return fmt.Errorf("synchronize legacy administrator compatibility row: %w", err)
	}
	return tx.Commit()
}

func migrateLegacyAdminRow(ctx context.Context, tx *sql.Tx, s *Store) error {
	var username, displayName, passwordHash, stored, created, updated string
	var totpEnabled int
	err := tx.QueryRowContext(ctx, `SELECT username,display_name,password_hash,totp_secret,totp_enabled,created_at,updated_at FROM admins WHERE id=1`).
		Scan(&username, &displayName, &passwordHash, &stored, &totpEnabled, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return tx.Commit()
	}
	if err != nil {
		return fmt.Errorf("read legacy administrator row for compatibility migration: %w", err)
	}
	if stored != "" {
		secret, migrate, secretErr := s.openTOTPSecretForOwner(LegacyAdminUserID, stored)
		if secretErr != nil {
			return fmt.Errorf("read legacy administrator TOTP secret for compatibility migration: %w", secretErr)
		}
		if migrate && secret != "" {
			stored, err = s.sealTOTPSecretForOwner(LegacyAdminUserID, secret)
			if err != nil {
				return fmt.Errorf("upgrade legacy administrator TOTP secret: %w", err)
			}
			if _, err = tx.ExecContext(ctx, `UPDATE admins SET totp_secret=? WHERE id=1`, stored); err != nil {
				return fmt.Errorf("store upgraded legacy administrator TOTP secret: %w", err)
			}
		}
	}
	return tx.Commit()
}
