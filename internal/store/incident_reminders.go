package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	IncidentReminderCadenceEveryScan = "every_scan"
	IncidentReminderCadenceHourly    = "hourly"
	IncidentReminderCadenceSixHours  = "every_6_hours"
	IncidentReminderCadenceDaily     = "daily"
)

// IncidentReminderSettings contains a unit's reminder enablement and cadence.
type IncidentReminderSettings struct {
	Enabled bool   `json:"enabled"`
	Cadence string `json:"cadence"`
}

func validIncidentReminderCadence(cadence string) bool {
	switch cadence {
	case IncidentReminderCadenceEveryScan, IncidentReminderCadenceHourly, IncidentReminderCadenceSixHours, IncidentReminderCadenceDaily:
		return true
	default:
		return false
	}
}

// ValidIncidentReminderCadence reports whether cadence is a supported bounded
// reminder interval.
func ValidIncidentReminderCadence(cadence string) bool {
	return validIncidentReminderCadence(cadence)
}

// IncidentReminderSettings reports whether this business unit sends reminders
// and the minimum interval between reminders for each job.
func (ts *TenantStore) IncidentReminderSettings(ctx context.Context) (IncidentReminderSettings, error) {
	if err := ts.ready(); err != nil {
		return IncidentReminderSettings{}, err
	}
	var settings IncidentReminderSettings
	err := ts.store.reader().QueryRowContext(ctx, `SELECT incident_reminders_enabled,incident_reminder_cadence FROM tenants WHERE id=?`, ts.scope.id).Scan(&settings.Enabled, &settings.Cadence)
	if errors.Is(err, sql.ErrNoRows) {
		return IncidentReminderSettings{}, fmt.Errorf("tenant %s: %w", ts.scope.id, ErrNotFound)
	}
	return settings, err
}

// IncidentRemindersEnabled reports whether this business unit sends reminders
// after successful scans that still observe open incidents.
func (ts *TenantStore) IncidentRemindersEnabled(ctx context.Context) (bool, error) {
	settings, err := ts.IncidentReminderSettings(ctx)
	return settings.Enabled, err
}

// SetIncidentRemindersEnabled changes only this unit's reminder preference and
// records the administrator's action in the same transaction.
func (ts *TenantStore) SetIncidentRemindersEnabled(ctx context.Context, enabled bool, audit AuditEntry) error {
	_, err := ts.SetIncidentReminderSettings(ctx, &enabled, nil, audit)
	return err
}

// SetIncidentReminderSettings updates only the supplied fields for this unit
// and records the administrator's action in the same transaction.
func (ts *TenantStore) SetIncidentReminderSettings(ctx context.Context, enabled *bool, cadence *string, audit AuditEntry) (IncidentReminderSettings, error) {
	if err := ts.ready(); err != nil {
		return IncidentReminderSettings{}, err
	}
	if enabled == nil && cadence == nil {
		return IncidentReminderSettings{}, errors.New("at least one incident reminder setting is required")
	}
	if cadence != nil && !validIncidentReminderCadence(*cadence) {
		return IncidentReminderSettings{}, fmt.Errorf("invalid incident reminder cadence %q", *cadence)
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return IncidentReminderSettings{}, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE tenants SET incident_reminders_enabled=COALESCE(?,incident_reminders_enabled),incident_reminder_cadence=COALESCE(?,incident_reminder_cadence) WHERE id=? AND state='active'`, enabled, cadence, ts.scope.id)
	if err != nil {
		return IncidentReminderSettings{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return IncidentReminderSettings{}, err
	}
	if changed == 0 {
		return IncidentReminderSettings{}, fmt.Errorf("tenant %s: %w", ts.scope.id, ErrNotFound)
	}
	var settings IncidentReminderSettings
	if err := tx.QueryRowContext(ctx, `SELECT incident_reminders_enabled,incident_reminder_cadence FROM tenants WHERE id=? AND state='active'`, ts.scope.id).Scan(&settings.Enabled, &settings.Cadence); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return IncidentReminderSettings{}, fmt.Errorf("tenant %s: %w", ts.scope.id, ErrNotFound)
		}
		return IncidentReminderSettings{}, err
	}
	if audit.Action != "" {
		if err := ts.insertAuditEntry(ctx, tx, audit, time.Now().UTC()); err != nil {
			return IncidentReminderSettings{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return IncidentReminderSettings{}, err
	}
	return settings, nil
}
