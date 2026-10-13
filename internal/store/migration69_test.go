package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
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
		sent        bool
	}{
		{"migration69-valid", []byte(`{"type":"changes-detected","job_id":"job-valid","changes":[{"key":"one"}]}`), "changes-detected", "job-valid", false},
		{"migration69-truncated", []byte(`{"type":"changes-reminder","job_id":"job-truncated","changes_truncated":true,"changes_count":7}`), "changes-reminder", "job-truncated", false},
		{"migration69-malformed", []byte(`{"type":"changes-recovered","job_id":`), "", "", false},
		{"migration69-terminal", []byte(`{"type":"changes-recovered","job_id":"job-terminal"}`), "changes-recovered", "job-terminal", false},
		{"migration69-sent", []byte(`{"type":"changes-detected","job_id":"job-sent","changes":[{"key":"history"}]}`), "", "", true},
	}
	for _, row := range rows {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,next_at,tenant_id) VALUES(?,?,?,?)`, row.destination, row.payload, "2000-01-01T00:00:00Z", DefaultTenantID); err != nil {
			t.Fatalf("insert legacy row %s: %v", row.destination, err)
		}
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET terminal_at='2026-10-10T00:00:00Z' WHERE destination=?`, "migration69-terminal"); err != nil {
		t.Fatalf("mark terminal fixture: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET sent_at='2026-10-10T00:00:00Z' WHERE destination=?`, "migration69-sent"); err != nil {
		t.Fatalf("mark sent fixture: %v", err)
	}
	path = reconstructSchema68(t, s)

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
		if want.sent {
			var payload []byte
			if err := upgraded.DB.QueryRowContext(ctx, `SELECT payload_json FROM outbox WHERE destination=?`, want.destination).Scan(&payload); err != nil {
				t.Fatalf("read sent payload %s: %v", want.destination, err)
			}
			if !bytes.Equal(payload, want.payload) {
				t.Errorf("sent payload %s changed: got %q, want byte-for-byte %q", want.destination, payload, want.payload)
			}
		}
	}
	if violations := countRows(t, upgraded.DB, `SELECT COUNT(*) FROM pragma_foreign_key_check`); violations != 0 {
		t.Fatalf("foreign-key violations after migration 69 = %d", violations)
	}
	if err := runMigration(ctx, upgraded.DB, 69, migration69Statements(), false); err == nil || err.Error() != fmt.Sprintf("schema migration 69: the database is at schema %d, not 68; another process is migrating it", schemaVersion) {
		t.Errorf("repeated schema 69 migration = %v, want moved-marker refusal", err)
	}
}

func reconstructSchema68(t *testing.T, s *Store) string {
	t.Helper()
	path := s.Path
	for _, statement := range []string{
		`DROP INDEX IF EXISTS scans_identity`,
		`CREATE INDEX scans_identity ON scans(id,tenant_id,job_id,status,finished_at,job)`,
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
		if _, err := s.DB.ExecContext(context.Background(), statement); err != nil {
			t.Fatalf("reconstruct schema 68 with %s: %v", statement, err)
		}
	}
	if _, err := s.DB.ExecContext(context.Background(), `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatalf("checkpoint schema 68 fixture: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMigration69SentHistoryDoesNotRewriteLargePayloadRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := openTestStore(t)
	const rowCount = 5000
	padding := strings.Repeat("x", 4000)
	payload := []byte(fmt.Sprintf(`{"type":"changes-detected","job_id":"legacy-sent","padding":"%s"}`, padding))
	tx, err := store.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO outbox(destination,payload_json,next_at,sent_at,tenant_id) VALUES(?,?,?, ?,?)`)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			t.Fatalf("prepare sent-history insert: %v (rollback: %v)", err, rollbackErr)
		}
		t.Fatal(err)
	}
	statementOpen := true
	committed := false
	defer func() {
		if statementOpen {
			if closeErr := stmt.Close(); closeErr != nil {
				t.Errorf("close sent-history insert: %v", closeErr)
			}
		}
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				t.Errorf("rollback sent-history insert: %v", rollbackErr)
			}
		}
	}()
	for index := 0; index < rowCount; index++ {
		if _, err := stmt.ExecContext(ctx, fmt.Sprintf("migration69-sent-load:%05d", index), payload, "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", DefaultTenantID); err != nil {
			t.Fatalf("insert sent history row %d: %v", index, err)
		}
	}
	if err := stmt.Close(); err != nil {
		t.Fatal(err)
	}
	statementOpen = false
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	committed = true
	path := reconstructSchema68(t, store)

	legacy, err := OpenExisting(path)
	if err != nil {
		t.Fatalf("open schema 68 fixture: %v", err)
	}
	if _, err := legacy.DB.ExecContext(ctx, `PRAGMA wal_autocheckpoint=0`); err != nil {
		legacy.Close()
		t.Fatal(err)
	}
	if err := runMigration(ctx, legacy.DB, 69, migration69Statements(), false); err != nil {
		legacy.Close()
		t.Fatalf("apply schema 69: %v", err)
	}
	info, err := os.Stat(path + "-wal")
	if err != nil {
		legacy.Close()
		t.Fatalf("stat migration WAL: %v", err)
	}
	const maxSchema69WALBytes = 8 << 20
	if info.Size() > maxSchema69WALBytes {
		legacy.Close()
		t.Fatalf("schema 69 wrote %d WAL bytes for sent-only history; limit %d", info.Size(), maxSchema69WALBytes)
	}
	var untouched int
	if err := legacy.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination LIKE 'migration69-sent-load:%' AND event_type='' AND event_job_id='' AND payload_json=?`, payload).Scan(&untouched); err != nil {
		legacy.Close()
		t.Fatal(err)
	}
	if untouched != rowCount {
		legacy.Close()
		t.Fatalf("unchanged sent rows = %d, want %d", untouched, rowCount)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(path)
	if err != nil {
		t.Fatalf("complete upgrade from schema 69: %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	var sentPayload []byte
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT payload_json FROM outbox WHERE destination='migration69-sent-load:00000'`).Scan(&sentPayload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sentPayload, payload) {
		t.Fatalf("sent history payload changed after full upgrade")
	}
}
