package store

import (
	"context"
	"database/sql"
)

func migration60ConditionalStatements(ctx context.Context, tx *sql.Tx) ([]string, error) {
	exists, err := migrationColumnExists(ctx, tx, "tenants", "incident_reminder_cadence")
	if err != nil || exists {
		return nil, err
	}
	return []string{`ALTER TABLE tenants ADD COLUMN incident_reminder_cadence TEXT NOT NULL DEFAULT 'every_scan' CHECK(incident_reminder_cadence IN ('every_scan','hourly','every_6_hours','daily'))`}, nil
}
