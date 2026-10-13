package store

// migration71Statements adds an all-row tenant-leading outbox index so tenant
// deletion can select bounded cleanup batches without decoding payloads or
// depending on optional event/window metadata.
func migration71Statements() []string {
	return []string{
		`CREATE INDEX IF NOT EXISTS outbox_tenant_purge ON outbox(tenant_id,id)`,
	}
}
