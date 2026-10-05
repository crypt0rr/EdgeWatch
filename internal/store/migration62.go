package store

// migration62Statements creates the durable work queues used to erase a
// permanently deleted job's history in bounded transactions. These tables do
// not reference jobs: the purge marker must survive independently while the
// job itself remains hidden from normal reads, and its completed row remains
// as a small ID tombstone so delayed work cannot resurrect deleted history.
// Host keys survive as the latest-host projection is rebuilt.
func migration62Statements() []string {
	return []string{
		`CREATE INDEX IF NOT EXISTS outbox_job_purge ON outbox(tenant_id,json_extract(CAST(payload_json AS TEXT),'$.job_id')) WHERE json_valid(CAST(payload_json AS TEXT))`,
		`CREATE INDEX IF NOT EXISTS restore_quarantined_job_purge ON restore_quarantined_deliveries(tenant_id,json_extract(CAST(payload_json AS TEXT),'$.job_id')) WHERE json_valid(CAST(payload_json AS TEXT))`,
		`CREATE TABLE IF NOT EXISTS job_history_purges (
 tenant_id TEXT NOT NULL,
 job_id TEXT NOT NULL,
 phase TEXT NOT NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 PRIMARY KEY(tenant_id,job_id)
);`,
		`CREATE INDEX IF NOT EXISTS job_history_purges_order ON job_history_purges(created_at,tenant_id,job_id) WHERE phase<>'complete'`,
		`CREATE TABLE IF NOT EXISTS job_history_purge_host_keys (
 tenant_id TEXT NOT NULL,
 job_id TEXT NOT NULL,
 address TEXT NOT NULL,
 PRIMARY KEY(tenant_id,job_id,address)
);`,
	}
}
