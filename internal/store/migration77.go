package store

import (
	"context"
	"database/sql"
)

// migration77Statements adds durable transition state for scheduled-backup
// failures and a scanner identity pool below the configured scan capacity.
func migration77Statements() []string { return nil }

// migration77ConditionalStatements also handles reconstructed migration test
// databases copied from the current schema, where these columns may exist
// even after the schema marker is lowered.
func migration77ConditionalStatements(ctx context.Context, tx *sql.Tx) ([]string, error) {
	columns := []struct{ name, statement string }{
		{"scheduled_backup_failing", `ALTER TABLE platform_alert_state ADD COLUMN scheduled_backup_failing INTEGER NOT NULL DEFAULT 0`},
		{"scheduled_backup_alerted_at", `ALTER TABLE platform_alert_state ADD COLUMN scheduled_backup_alerted_at TEXT NOT NULL DEFAULT ''`},
		{"scanner_identity_pool_low", `ALTER TABLE platform_alert_state ADD COLUMN scanner_identity_pool_low INTEGER NOT NULL DEFAULT 0`},
		{"scanner_identity_pool_alerted_at", `ALTER TABLE platform_alert_state ADD COLUMN scanner_identity_pool_alerted_at TEXT NOT NULL DEFAULT ''`},
	}
	var statements []string
	for _, column := range columns {
		exists, err := migrationColumnExists(ctx, tx, "platform_alert_state", column.name)
		if err != nil {
			return nil, err
		}
		if !exists {
			statements = append(statements, column.statement)
		}
	}
	return statements, nil
}
