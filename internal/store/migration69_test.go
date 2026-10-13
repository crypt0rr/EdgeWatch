package store

import (
	"context"
	"fmt"
	"testing"
)

func TestMigration69BackfillsOutboxEventMetadataSafely(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	path := s.Path
	rows := []struct {
		destination string
		payload     []byte
		wantType    string
		wantJob     string
	}{
		{"migration69-valid", []byte(`{"type":"changes-detected","job_id":"job-valid","changes":[{"key":"one"}]}`), "changes-detected", "job-valid"},
		{"migration69-truncated", []byte(`{"type":"changes-reminder","job_id":"job-truncated","changes_truncated":true,"changes_count":7}`), "changes-reminder", "job-truncated"},
		{"migration69-malformed", []byte(`{"type":"changes-recovered","job_id":`), "", ""},
	}
	for _, row := range rows {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,next_at,tenant_id) VALUES(?,?,?,?)`, row.destination, row.payload, "2000-01-01T00:00:00Z", DefaultTenantID); err != nil {
			t.Fatalf("insert legacy row %s: %v", row.destination, err)
		}
	}
	for _, statement := range []string{
		`DROP INDEX IF EXISTS outbox_change_window_pending`,
		`DROP INDEX IF EXISTS outbox_job_change_pending`,
		`DROP INDEX IF EXISTS change_windows_job_interval`,
		`DROP INDEX IF EXISTS change_windows_job_latest`,
		`DROP INDEX IF EXISTS change_windows_expiry`,
		`DROP INDEX IF EXISTS change_windows_retention`,
		`DROP INDEX IF EXISTS change_window_refs_event`,
		`DROP TABLE change_window_refs`,
		`DROP TABLE change_window_events`,
		`DROP TABLE change_windows`,
		`ALTER TABLE outbox DROP COLUMN coalesced_at`,
		`ALTER TABLE outbox DROP COLUMN coalesce_after_attempt`,
		`ALTER TABLE outbox DROP COLUMN attempt_started_at`,
		`ALTER TABLE outbox DROP COLUMN change_window_id`,
		`ALTER TABLE outbox DROP COLUMN event_job_id`,
		`ALTER TABLE outbox DROP COLUMN event_type`,
		`PRAGMA user_version=68`,
	} {
		if _, err := s.DB.ExecContext(ctx, statement); err != nil {
			t.Fatalf("reconstruct schema 68 with %s: %v", statement, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade from schema 68: %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	if version := countRows(t, upgraded.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
	for _, want := range rows {
		var eventType, jobID string
		if err := upgraded.DB.QueryRowContext(ctx, `SELECT event_type,event_job_id FROM outbox WHERE destination=?`, want.destination).Scan(&eventType, &jobID); err != nil {
			t.Fatalf("read migrated row %s: %v", want.destination, err)
		}
		if eventType != want.wantType || jobID != want.wantJob {
			t.Errorf("migrated row %s = type %q job %q; want %q %q", want.destination, eventType, jobID, want.wantType, want.wantJob)
		}
	}
	if violations := countRows(t, upgraded.DB, `SELECT COUNT(*) FROM pragma_foreign_key_check`); violations != 0 {
		t.Fatalf("foreign-key violations after migration 69 = %d", violations)
	}
	if err := runMigration(ctx, upgraded.DB, 69, migration69Statements(), false); err == nil || err.Error() != fmt.Sprintf("schema migration 69: the database is at schema %d, not 68; another process is migrating it", schemaVersion) {
		t.Errorf("repeated schema 69 migration = %v, want moved-marker refusal", err)
	}
}
