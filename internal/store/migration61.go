package store

import "database/sql"

// migration61ConditionalStatements makes inherited per-scan reminder defaults
// hourly. A prior reminder-setting audit record is treated conservatively as
// an explicit preference because older releases did not record which field
// changed; this preserves an administrator's possible every-scan selection.
func migration61ConditionalStatements(tx *sql.Tx) ([]string, error) {
	exists, err := migrationColumnExists(tx, "tenants", "incident_reminder_cadence_explicit")
	if err != nil || exists {
		return nil, err
	}
	return []string{
		`ALTER TABLE tenants ADD COLUMN incident_reminder_cadence_explicit INTEGER NOT NULL DEFAULT 0 CHECK(incident_reminder_cadence_explicit IN (0,1))`,
		`UPDATE tenants SET incident_reminder_cadence_explicit=1
WHERE incident_reminder_cadence<>'every_scan'
   OR EXISTS (SELECT 1 FROM security_audit AS audit
              WHERE audit.tenant_id=tenants.id
                AND audit.action='notifications.incident_reminders_changed')`,
		`UPDATE tenants SET incident_reminder_cadence='hourly'
WHERE incident_reminder_cadence='every_scan' AND incident_reminder_cadence_explicit=0`,
	}, nil
}
