package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func assertHostSearchSchemaContract(t *testing.T, s *Store) {
	t.Helper()
	for _, object := range []struct {
		kind string
		name string
	}{
		{kind: "table", name: "scan_hosts"},
		{kind: "table", name: "latest_scan_hosts"},
		{kind: "table", name: "scan_host_search"},
		{kind: "table", name: "latest_host_search"},
		{kind: "table", name: "fts_backfill_state"},
	} {
		var count int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type=? AND name=?`, object.kind, object.name).Scan(&count); err != nil {
			t.Fatalf("check %s %s: %v", object.kind, object.name, err)
		}
		if count != 1 {
			t.Fatalf("missing %s %s", object.kind, object.name)
		}
	}
	for _, index := range []string{"scan_hosts_address", "scan_hosts_scan_address", "scan_hosts_job_address", "scan_hosts_open", "latest_scan_hosts_open", "latest_scan_hosts_protocol_open"} {
		var count int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, index).Scan(&count); err != nil {
			t.Fatalf("check index %s: %v", index, err)
		}
		if count != 1 {
			t.Fatalf("missing index %s", index)
		}
	}
	for _, trigger := range scanHostSearchTriggerNames {
		var count int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=?`, trigger).Scan(&count); err != nil {
			t.Fatalf("check trigger %s: %v", trigger, err)
		}
		if count != 1 {
			t.Fatalf("missing trigger %s", trigger)
		}
	}
}

func TestMigration22RepairsScanHostsCascade(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	for _, trigger := range scanHostSearchTriggerNames {
		if _, err := s.DB.ExecContext(ctx, `DROP TRIGGER IF EXISTS `+trigger); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.ExecContext(ctx, `
DROP TABLE scan_hosts;
DROP TABLE fts_backfill_state;
CREATE TABLE scan_hosts (
 scan_id TEXT NOT NULL,
 address TEXT NOT NULL,
 job TEXT NOT NULL DEFAULT '',
 address_family TEXT NOT NULL DEFAULT '',
 source_targets_json BLOB NOT NULL DEFAULT '[]',
 dns_names_json BLOB NOT NULL DEFAULT '[]',
 host_json BLOB NOT NULL,
 data_quality TEXT NOT NULL DEFAULT 'detailed',
 open_ports INTEGER NOT NULL DEFAULT 0,
 open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 tcp_present INTEGER NOT NULL DEFAULT 0,
 udp_present INTEGER NOT NULL DEFAULT 0,
 tcp_open_ports INTEGER NOT NULL DEFAULT 0,
 tcp_open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 udp_open_ports INTEGER NOT NULL DEFAULT 0,
 udp_open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(scan_id,address)
);
INSERT INTO scans(id,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json)
 VALUES('cascade-source','edge','2026-09-09T00:00:00Z','2026-09-09T00:00:01Z','success','','','hash','{}');
INSERT INTO scan_hosts(scan_id,address,host_json) VALUES('cascade-source','198.51.100.9','{"address":"198.51.100.9"}');
PRAGMA user_version = 21;`); err != nil {
		t.Fatal(err)
	}
	if err := migrate(s.DB); err != nil {
		t.Fatal(err)
	}
	assertHostSearchSchemaContract(t, s)
	// The supported recovery fixture contract is structurally idempotent. A
	// restart after the upgrade must not remove or duplicate any projection
	// object while the resumable backfill sees an already-complete state.
	if err := migrate(s.DB); err != nil {
		t.Fatalf("repeat migration of recovery fixture: %v", err)
	}
	assertHostSearchSchemaContract(t, s)
	var definition string
	if err := s.DB.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='table' AND name='scan_hosts'`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	upperDefinition := strings.ToUpper(definition)
	if !strings.Contains(upperDefinition, "FOREIGN KEY") || !strings.Contains(upperDefinition, "ON DELETE CASCADE") {
		t.Fatalf("repaired scan_hosts definition = %q", definition)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM scans WHERE id='cascade-source'`); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_hosts WHERE scan_id='cascade-source'`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("cascade left %d source host rows", remaining)
	}
	rows, err := s.DB.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("foreign_key_check reported a violation after cascade repair")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestMigration22BackfillsFTSWithProgress(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `
INSERT INTO scans(id,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json)
 VALUES('fts-source','edge','2026-09-09T00:00:00Z','2026-09-09T00:00:01Z','success','','','hash','{}');
DROP TABLE fts_backfill_state;
PRAGMA user_version = 21;`); err != nil {
		t.Fatal(err)
	}
	const hostCount = ftsBackfillBatchSize*2 + 37
	for i := 0; i < hostCount; i++ {
		address := fmt.Sprintf("198.18.%d.%d", i/256, i%256)
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO scan_hosts(scan_id,address,job,host_json) VALUES(?,?,?,?)`, "fts-source", address, "edge", []byte(`{"address":"`+address+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := migrate(s.DB); err != nil {
		t.Fatal(err)
	}
	var indexed int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_host_search`).Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if indexed != hostCount {
		t.Fatalf("scan host FTS rows = %d, want %d", indexed, hostCount)
	}
	var completed int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM fts_backfill_state WHERE complete=1`).Scan(&completed); err != nil {
		t.Fatal(err)
	}
	if completed != 2 {
		t.Fatalf("completed FTS backfill states = %d, want 2", completed)
	}
	var searchText string
	if err := s.DB.QueryRowContext(ctx, `SELECT search_text FROM scan_hosts WHERE address=?`, "198.18.2.36").Scan(&searchText); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(searchText, "198.18.2.36") {
		t.Fatalf("backfilled search text = %q", searchText)
	}
}

func TestMigration28AddsFTSProgressToLegacyState(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	if _, err := s.DB.ExecContext(ctx, `
DROP TABLE fts_backfill_state;
CREATE TABLE fts_backfill_state (
 table_name TEXT PRIMARY KEY,
 last_rowid INTEGER NOT NULL DEFAULT 0,
 initialized INTEGER NOT NULL DEFAULT 0,
 complete INTEGER NOT NULL DEFAULT 0,
 updated_at TEXT NOT NULL DEFAULT ''
);
INSERT INTO fts_backfill_state(table_name) VALUES('scan_hosts'),('latest_scan_hosts');
PRAGMA user_version = 24;`); err != nil {
		t.Fatal(err)
	}
	if err := migrate(s.DB); err != nil {
		t.Fatalf("migrate legacy FTS state: %v", err)
	}
	var present int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('fts_backfill_state') WHERE name='processed_rows'`).Scan(&present); err != nil {
		t.Fatal(err)
	}
	if present != 1 {
		t.Fatal("migration 28 did not add processed_rows to legacy FTS state")
	}
}

func TestFTSBackfillCancellationResumesFromCheckpoint(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	if _, err := s.DB.ExecContext(ctx, `
INSERT INTO scans(id,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json)
 VALUES('fts-cancel-source','edge','2026-09-09T00:00:00Z','2026-09-09T00:00:01Z','success','','','hash','{}')`); err != nil {
		t.Fatal(err)
	}
	const hostCount = ftsBackfillBatchSize*2 + 17
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < hostCount; i++ {
		address := fmt.Sprintf("198.18.%d.%d", i/256, i%256)
		if _, err := tx.ExecContext(ctx, `INSERT INTO scan_hosts(scan_id,address,job,host_json) VALUES(?,?,?,?)`, "fts-cancel-source", address, "edge", []byte(`{"address":"`+address+`"}`)); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`DELETE FROM scan_host_search`,
		`DELETE FROM latest_host_search`,
		`UPDATE fts_backfill_state SET last_rowid=0,processed_rows=0,initialized=1,complete=0`,
	} {
		if _, err := s.DB.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}

	backfillCtx, cancel := context.WithCancel(ctx)
	err = backfillHostSearchIndexesContextWithProgress(backfillCtx, s.DB, func(progress ftsBatchProgress) {
		if progress.table == "scan_hosts" && progress.processedRows >= ftsBackfillBatchSize {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled backfill error = %v, want context.Canceled", err)
	}
	var lastRowID int64
	var processedRows, complete int
	if err := s.DB.QueryRowContext(ctx, `SELECT last_rowid,processed_rows,complete FROM fts_backfill_state WHERE table_name='scan_hosts'`).Scan(&lastRowID, &processedRows, &complete); err != nil {
		t.Fatal(err)
	}
	if lastRowID == 0 || processedRows < ftsBackfillBatchSize || complete != 0 {
		t.Fatalf("cancelled checkpoint = last_rowid %d, processed_rows %d, complete %d", lastRowID, processedRows, complete)
	}
	readOnly, err := OpenReadOnlyExisting(s.Path)
	if err != nil {
		t.Fatalf("open read-only store for cancelled backfill: %v", err)
	}
	verification, err := readOnly.Verify(ctx)
	_ = readOnly.Close()
	if err != nil {
		t.Fatalf("verify cancelled backfill: %v", err)
	}
	var incomplete int
	for _, progress := range verification.FTSBackfill {
		if !progress.Complete {
			incomplete++
		}
	}
	if incomplete == 0 {
		t.Fatalf("verification did not report incomplete FTS progress: %#v", verification.FTSBackfill)
	}

	if err := backfillHostSearchIndexesContext(ctx, s.DB); err != nil {
		t.Fatalf("resume backfill: %v", err)
	}
	var indexed int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_host_search`).Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if indexed != hostCount {
		t.Fatalf("resumed scan host FTS rows = %d, want %d", indexed, hostCount)
	}
	readOnly, err = OpenReadOnlyExisting(s.Path)
	if err != nil {
		t.Fatalf("open read-only store for resumed backfill: %v", err)
	}
	verification, err = readOnly.Verify(ctx)
	_ = readOnly.Close()
	if err != nil {
		t.Fatalf("verify resumed backfill: %v", err)
	}
	for _, progress := range verification.FTSBackfill {
		if !progress.Complete {
			t.Fatalf("resumed verification still incomplete: %#v", progress)
		}
	}
}

func TestFTSBackfillBookkeepingWaitsForConcurrentWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fts-lock.db")
	writer, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	writer.SetMaxOpenConns(1)
	reader.SetMaxOpenConns(1)
	for _, db := range []*sql.DB{writer, reader} {
		if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := writer.Exec(`CREATE TABLE fts_backfill_state (
 table_name TEXT PRIMARY KEY,
 last_rowid INTEGER NOT NULL DEFAULT 0,
 processed_rows INTEGER NOT NULL DEFAULT 0,
 initialized INTEGER NOT NULL DEFAULT 0,
 complete INTEGER NOT NULL DEFAULT 0,
 updated_at TEXT NOT NULL
); INSERT INTO fts_backfill_state(table_name,updated_at) VALUES ('scan_hosts','now'),('latest_scan_hosts','now')`); err != nil {
		t.Fatal(err)
	}
	lock, err := writer.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lock.Exec(`UPDATE fts_backfill_state SET updated_at=updated_at WHERE table_name='scan_hosts'`); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- ensureFTSBackfillStateContext(context.Background(), reader)
	}()
	select {
	case err := <-done:
		t.Fatalf("bookkeeping returned while writer was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := lock.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("bookkeeping after writer release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bookkeeping did not resume after writer release")
	}
}

func TestMigration29AddsBaselineHostProjection(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if _, err := s.DB.ExecContext(ctx, `DROP TABLE baseline_hosts; PRAGMA user_version = 28;`); err != nil {
		t.Fatal(err)
	}
	if err := migrate(s.DB); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := s.DB.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
	var table string
	if err := s.DB.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='baseline_hosts'`).Scan(&table); err != nil {
		t.Fatal(err)
	}
}
