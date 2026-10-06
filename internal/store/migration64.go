package store

// migration64Statements adds the ordering index used by batched retention of
// quarantined notification deliveries.
func migration64Statements() []string {
	return []string{
		`CREATE INDEX IF NOT EXISTS restore_quarantined_retention ON restore_quarantined_deliveries(quarantined_at)`,
	}
}
