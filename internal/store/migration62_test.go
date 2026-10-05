package store

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
)

func TestMigration62CreatesJobHistoryPurgeQueue(t *testing.T) {
	s := openTestStore(t)
	for _, object := range []struct{ kind, name string }{
		{kind: "index", name: "outbox_job_purge"},
		{kind: "index", name: "restore_quarantined_job_purge"},
		{kind: "table", name: "job_history_purges"},
		{kind: "index", name: "job_history_purges_order"},
		{kind: "table", name: "job_history_purge_host_keys"},
	} {
		var count int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type=? AND name=?`, object.kind, object.name).Scan(&count); err != nil || count != 1 {
			t.Fatalf("schema object %s %s count = %d, %v; want 1", object.kind, object.name, count, err)
		}
	}
	for _, query := range []struct{ table, index string }{
		{table: "outbox", index: "outbox_job_purge"},
		{table: "restore_quarantined_deliveries", index: "restore_quarantined_job_purge"},
	} {
		rows, err := s.DB.Query(`EXPLAIN QUERY PLAN SELECT rowid FROM `+query.table+` WHERE tenant_id=? AND json_valid(CAST(payload_json AS TEXT)) AND json_extract(CAST(payload_json AS TEXT),'$.job_id')=? ORDER BY rowid LIMIT ?`, "tenant", "job", jobHistoryPurgeBatchSize)
		if err != nil {
			t.Fatalf("explain %s job purge lookup: %v", query.table, err)
		}
		var details []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			details = append(details, detail)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(details, " "), query.index) {
			t.Fatalf("%s job purge query plan = %v; want indexed lookup through %s", query.table, details, query.index)
		}
	}
	rows, err := s.DB.Query(`EXPLAIN QUERY PLAN SELECT p.tenant_id,p.job_id,p.phase FROM job_history_purges AS p JOIN tenants AS t ON t.id=p.tenant_id WHERE t.state IN (?,?) AND p.phase<>'complete' ORDER BY p.created_at,p.tenant_id,p.job_id LIMIT 1`, TenantStateActive, TenantStateDisabled)
	if err != nil {
		t.Fatalf("explain pending purge queue query: %v", err)
	}
	var queuePlan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		queuePlan = append(queuePlan, detail)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(queuePlan, " "), "job_history_purges_order") {
		t.Fatalf("pending purge queue plan = %v; want ordered partial-index scan", queuePlan)
	}
	path := s.Path
	if _, err := s.DB.Exec(`DROP INDEX job_history_purges_order`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DROP TABLE job_history_purge_host_keys`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DROP TABLE job_history_purges`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`PRAGMA user_version=61`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade from schema 61: %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	if version := countRows(t, upgraded.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
	for _, table := range []string{"job_history_purges", "job_history_purge_host_keys"} {
		var rowid int
		if err := upgraded.DB.QueryRow(`SELECT rowid FROM ` + table + ` LIMIT 1`).Scan(&rowid); err != nil && !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("%s is not a rowid table: %v", table, err)
		}
	}
}
