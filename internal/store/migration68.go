package store

import "database/sql"

// migration68Statements adds durable, per-occurrence incident review state.
// Reviews reference the managed job but not either the replaceable active
// incident projection or prunable scan rows. History is a bounded child of
// the current review and is erased with it.
func migration68Statements() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS incident_reviews (
 job_id TEXT NOT NULL,
 occurrence_token TEXT NOT NULL,
 incident_key TEXT NOT NULL,
 opening_scan_id TEXT NOT NULL DEFAULT '',
 opened_at TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL CHECK(status IN ('needs_review','investigating')),
 reviewer_user_id TEXT NOT NULL DEFAULT '',
 reviewer_label TEXT NOT NULL,
 reviewed_at TEXT NOT NULL,
 note TEXT NOT NULL DEFAULT '' CHECK(length(CAST(note AS BLOB))<=4096),
 follow_up_at TEXT NOT NULL DEFAULT '',
 revision INTEGER NOT NULL CHECK(revision>0),
 closed_at TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(job_id,occurrence_token),
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
);`,
		`CREATE TABLE IF NOT EXISTS incident_review_history (
 job_id TEXT NOT NULL,
 occurrence_token TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0),
 status TEXT NOT NULL CHECK(status IN ('needs_review','investigating')),
 reviewer_user_id TEXT NOT NULL DEFAULT '',
 reviewer_label TEXT NOT NULL,
 reviewed_at TEXT NOT NULL,
 note TEXT NOT NULL DEFAULT '' CHECK(length(CAST(note AS BLOB))<=4096),
 follow_up_at TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(job_id,occurrence_token,revision),
 FOREIGN KEY(job_id,occurrence_token) REFERENCES incident_reviews(job_id,occurrence_token) ON DELETE CASCADE
);`,
		`CREATE INDEX IF NOT EXISTS incident_reviews_closed_retention
 ON incident_reviews(closed_at) WHERE closed_at<>''`,
	}
}

// migration68ConditionalStatements adds the inbox columns to the replaceable
// runtime incident projection. Conditional column checks keep migration
// reconstruction and recovery fixtures safe if a newer template has already
// installed one of them.
func migration68ConditionalStatements(tx *sql.Tx) ([]string, error) {
	var statements []string
	for _, column := range []struct {
		name       string
		definition string
	}{
		{"occurrence_token", `TEXT NOT NULL DEFAULT ''`},
		{"severity", `TEXT NOT NULL DEFAULT ''`},
		{"kind", `TEXT NOT NULL DEFAULT ''`},
		{"opened_at_sort", `TEXT NOT NULL DEFAULT ''`},
		{"last_seen_at_sort", `TEXT NOT NULL DEFAULT ''`},
	} {
		exists, err := migrationColumnExists(tx, "runtime_incidents", column.name)
		if err != nil {
			return nil, err
		}
		if !exists {
			statements = append(statements, `ALTER TABLE runtime_incidents ADD COLUMN `+column.name+` `+column.definition)
		}
	}
	statements = append(statements,
		`CREATE INDEX IF NOT EXISTS runtime_incidents_inbox_order ON runtime_incidents(job_id,severity,kind,opened_at_sort,key)`,
		`CREATE INDEX IF NOT EXISTS runtime_incidents_inbox_occurrence ON runtime_incidents(job_id,occurrence_token)`,
	)
	return statements, nil
}
