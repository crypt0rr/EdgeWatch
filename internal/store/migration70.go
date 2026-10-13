package store

// migration70Statements extends the scan identity index with comparison so
// Inbox metadata lookups can classify completed scans without reading their
// snapshot rows. The existing index is replaced in place; scan data does not
// change.
func migration70Statements() []string {
	return []string{
		"DROP INDEX IF EXISTS " + scansIdentityIndex,
		"CREATE INDEX " + scansIdentityIndex + " ON scans(id,tenant_id,job_id,status,finished_at,job,comparison)",
	}
}
