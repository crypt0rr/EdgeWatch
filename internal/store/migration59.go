package store

import "database/sql"

func migration59ConditionalStatements(tx *sql.Tx) ([]string, error) {
	exists, err := migrationColumnExists(tx, "tenants", "incident_reminders_enabled")
	if err != nil || exists {
		return nil, err
	}
	return []string{`ALTER TABLE tenants ADD COLUMN incident_reminders_enabled INTEGER NOT NULL DEFAULT 1 CHECK(incident_reminders_enabled IN (0,1))`}, nil
}
