package store

import (
	"strings"
	"testing"
	"time"
)

func TestMigration64IndexesRestoreQuarantineRetention(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	path := s.Path
	if _, err := s.DB.Exec(`DROP INDEX restore_quarantined_retention`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`PRAGMA user_version=63`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade from schema 63: %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	if version := countRows(t, upgraded.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
	var indexCount int
	if err := upgraded.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='restore_quarantined_retention'`).Scan(&indexCount); err != nil || indexCount != 1 {
		t.Fatalf("retention index count = %d, %v; want 1", indexCount, err)
	}
	rows, err := upgraded.DB.Query(`EXPLAIN QUERY PLAN SELECT rowid FROM restore_quarantined_deliveries WHERE quarantined_at < ? ORDER BY quarantined_at,rowid LIMIT ?`, time.Now().UTC().Format(time.RFC3339Nano), retentionBatchSize)
	if err != nil {
		t.Fatalf("explain quarantine retention: %v", err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(details, " "), "restore_quarantined_retention") {
		t.Fatalf("quarantine retention query plan = %v, want indexed scan", details)
	}
}
