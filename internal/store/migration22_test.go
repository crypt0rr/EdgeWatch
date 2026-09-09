package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

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
