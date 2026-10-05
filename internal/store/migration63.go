package store

// v0.22.1 raised the retry budget from eight to fifteen attempts. Databases
// that had already applied schema 31 need to distinguish rows exhausted by
// the old policy from retries still progressing under the new policy. The
// scheduled retry time is the only persisted attempt timestamp on those
// rows, so leave rows scheduled on or after the release untouched.
const legacyDeliveryRetryBudgetStart = "2026-10-03T00:16:38Z"

// migration63Statements marks legacy exhausted deliveries terminal without
// replaying them under the newer, larger retry budget.
func migration63Statements() []string {
	return []string{
		`UPDATE outbox
SET terminal_at=CASE WHEN next_at<>'' THEN next_at ELSE strftime('%Y-%m-%dT%H:%M:%fZ','now') END
WHERE sent_at IS NULL AND terminal_at='' AND attempts>=8 AND next_at < '` + legacyDeliveryRetryBudgetStart + `'`,
	}
}
