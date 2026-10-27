package store

import (
	"context"
	"database/sql"
)

// migration80Statements adds no fixed DDL because test databases may already
// have the column when they reconstruct schema 79 from a current template.
func migration80Statements() []string { return nil }

func migration80ConditionalStatements(ctx context.Context, tx *sql.Tx) ([]string, error) {
	columnExists, err := migrationColumnExists(ctx, tx, "scans", "cycle_execution_hash")
	if err != nil {
		return nil, err
	}
	statements := make([]string, 0, 4)
	if !columnExists {
		statements = append(statements,
			`ALTER TABLE scans ADD COLUMN cycle_execution_hash TEXT NOT NULL DEFAULT ''`,
			`UPDATE scans SET cycle_execution_hash=(SELECT c.execution_hash FROM scan_cycles AS c WHERE c.id=scans.cycle_id AND c.job_id=scans.job_id) WHERE cycle_id<>'' AND EXISTS (SELECT 1 FROM scan_cycles AS c WHERE c.id=scans.cycle_id AND c.job_id=scans.job_id)`,
		)
	}
	statements = append(statements,
		`CREATE INDEX IF NOT EXISTS `+scansTimeoutCycleKeyIndex+` ON scans(tenant_id,job_id,cycle_execution_hash,finished_at DESC,id DESC,status,cycle_id) WHERE cycle_id<>''`,
		`CREATE INDEX IF NOT EXISTS `+scansTimeoutConfigKeyIndex+` ON scans(tenant_id,job_id,config_hash,scanner_profile_id,scanner_profile_revision,finished_at DESC,id DESC,status) WHERE cycle_id=''`,
	)
	return statements, nil
}
