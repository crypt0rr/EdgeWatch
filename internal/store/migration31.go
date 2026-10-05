package store

// migration31TerminalDeliveryBackfill runs immediately after terminal_at is
// introduced. Before that schema, eight attempts was the delivery limit, so
// every unsent row at or above that count was already exhausted.
const migration31TerminalDeliveryBackfill = `UPDATE outbox
SET terminal_at=CASE WHEN next_at<>'' THEN next_at ELSE strftime('%Y-%m-%dT%H:%M:%fZ','now') END
WHERE sent_at IS NULL AND terminal_at='' AND attempts>=8`

func migration31Statements() []string {
	return []string{
		// Delivery deferrals (for example an unavailable managed key or an
		// indeterminate provider outcome) must be bounded just like ordinary
		// retry attempts. Keeping a separate counter preserves the useful
		// property that a deferral does not pretend a provider request failed,
		// while terminal_at makes the row visible to health and retention
		// accounting instead of leaving it pending forever.
		// Some supported recovery fixtures carry a schema marker without the
		// legacy outbox table. Create the complete current shape first so the
		// additive columns below remain safe for those databases.
		`CREATE TABLE IF NOT EXISTS outbox (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 destination TEXT NOT NULL,
 payload_json BLOB NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 next_at TEXT NOT NULL,
 sent_at TEXT,
 last_error TEXT NOT NULL DEFAULT '',
 claim_token TEXT NOT NULL DEFAULT '',
 claim_until TEXT NOT NULL DEFAULT '',
 deferrals INTEGER NOT NULL DEFAULT 0,
 terminal_at TEXT NOT NULL DEFAULT '',
 UNIQUE(destination, payload_json)
);`,
		"ALTER TABLE outbox ADD COLUMN deferrals INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE outbox ADD COLUMN terminal_at TEXT NOT NULL DEFAULT ''",
		migration31TerminalDeliveryBackfill,
		"CREATE INDEX IF NOT EXISTS outbox_terminal_due ON outbox(sent_at,terminal_at,next_at)",
	}
}
