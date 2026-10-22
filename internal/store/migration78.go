package store

import (
	"context"
	"database/sql"
)

func migration78Statements() []string { return nil }

func migration78ConditionalStatements(ctx context.Context, tx *sql.Tx) ([]string, error) {
	exists, err := migrationColumnExists(ctx, tx, "scan_cycles", "attempt_started_at")
	if err != nil || exists {
		return nil, err
	}
	return []string{`ALTER TABLE scan_cycles ADD COLUMN attempt_started_at TEXT NOT NULL DEFAULT ''`}, nil
}
