package store

const (
	eventsTenantHistoryIndex      = "events_tenant_history"
	eventsTenantJobHistoryIndex   = "events_tenant_job_history"
	eventsTenantJobIDHistoryIndex = "events_tenant_job_id_history"
)

// migration72Statements replaces the tenant event-order index with one that
// also carries job_id for the history-purge predicate, then adds tenant- and
// job-qualified orderings for legacy name and stable-ID history reads. The
// payload stays in the table: counts can remain covering, while pages fetch
// only the payloads for rows that survive the indexed filters and page bounds.
func migration72Statements() []string {
	return []string{
		`DROP INDEX IF EXISTS events_tenant_id_time`,
		`CREATE INDEX IF NOT EXISTS ` + eventsTenantHistoryIndex + ` ON events(tenant_id,created_at DESC,id DESC,job_id)`,
		`CREATE INDEX IF NOT EXISTS ` + eventsTenantJobHistoryIndex + ` ON events(tenant_id,job,created_at DESC,id DESC,job_id)`,
		`CREATE INDEX IF NOT EXISTS ` + eventsTenantJobIDHistoryIndex + ` ON events(tenant_id,job_id,created_at DESC,id DESC)`,
	}
}
