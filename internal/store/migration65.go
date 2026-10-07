package store

import "database/sql"

// migration65ConditionalStatements adds the comparison outcome that a managed
// scan records when it is finalized: compared, baseline_sample,
// baseline_established, or not_compared. Existing rows keep the empty value,
// which marks them as recorded before the outcome was stored, so only they
// keep the compatibility comparison with the current baseline. The values are
// validated in Go rather than by a CHECK constraint, because changing such a
// constraint later would require rebuilding the scans table. The column may
// already exist in a test database reconstructed from a newer template.
func migration65ConditionalStatements(tx *sql.Tx) ([]string, error) {
	exists, err := migrationColumnExists(tx, "scans", "comparison")
	if err != nil || exists {
		return nil, err
	}
	return []string{`ALTER TABLE scans ADD COLUMN comparison TEXT NOT NULL DEFAULT ''`}, nil
}
