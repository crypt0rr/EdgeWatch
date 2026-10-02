package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// IncidentRemindersEnabled reports whether this business unit sends a reminder
// after each fully successful scan that still observes an open incident.
func (ts *TenantStore) IncidentRemindersEnabled(ctx context.Context) (bool, error) {
	if err := ts.ready(); err != nil {
		return false, err
	}
	var enabled bool
	err := ts.store.reader().QueryRowContext(ctx, `SELECT incident_reminders_enabled FROM tenants WHERE id=?`, ts.scope.id).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("tenant %s: %w", ts.scope.id, ErrNotFound)
	}
	return enabled, err
}

// SetIncidentRemindersEnabled changes only this unit's reminder preference and
// records the administrator's action in the same transaction.
func (ts *TenantStore) SetIncidentRemindersEnabled(ctx context.Context, enabled bool, audit AuditEntry) error {
	if err := ts.ready(); err != nil {
		return err
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE tenants SET incident_reminders_enabled=? WHERE id=? AND state='active'`, enabled, ts.scope.id)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return fmt.Errorf("tenant %s: %w", ts.scope.id, ErrNotFound)
	}
	if audit.Action != "" {
		if err := ts.insertAuditEntry(ctx, tx, audit, time.Now().UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
