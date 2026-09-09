package store

import (
	"context"
	"strings"
	"testing"
)

func TestScanHistoryIndexesSupportManagedQueries(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	// Exercise the actual 20 -> 22 upgrade path rather than only checking a
	// fresh database. This also catches a future migration that forgets to add
	// an index when an operator upgrades an existing installation.
	if _, err := s.DB.ExecContext(ctx, `DROP INDEX IF EXISTS scans_job_id_time;
DROP INDEX IF EXISTS scans_job_id_revision;
DROP INDEX IF EXISTS scans_finished_at;
DROP INDEX IF EXISTS scans_cycle_id;
PRAGMA user_version = 20;`); err != nil {
		t.Fatal(err)
	}
	if err := migrate(s.DB); err != nil {
		t.Fatalf("reapply schema 22 migration: %v", err)
	}

	want := map[string]bool{
		"scans_job_id_time":     false,
		"scans_job_id_revision": false,
		"scans_finished_at":     false,
		"scans_cycle_id":        false,
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT name FROM pragma_index_list('scans')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for name, found := range want {
		if !found {
			t.Errorf("missing scan index %s", name)
		}
	}

	assertPlanUses := func(label, query, expected string) {
		t.Helper()
		planRows, err := s.DB.QueryContext(ctx, "EXPLAIN QUERY PLAN "+query, "job-id")
		if err != nil {
			t.Fatalf("%s explain: %v", label, err)
		}
		defer planRows.Close()
		var details []string
		for planRows.Next() {
			var id, parent, notUsed int
			var detail string
			if err := planRows.Scan(&id, &parent, &notUsed, &detail); err != nil {
				t.Fatalf("%s explain scan: %v", label, err)
			}
			details = append(details, detail)
		}
		if err := planRows.Err(); err != nil {
			t.Fatalf("%s explain rows: %v", label, err)
		}
		if !strings.Contains(strings.Join(details, " | "), expected) {
			t.Fatalf("%s plan = %v, want %q", label, details, expected)
		}
	}

	assertPlanUses("job count", `SELECT COUNT(*) FROM scans WHERE job_id=?`, "scans_job_id_")
	assertPlanUses("job history", `SELECT id FROM scans WHERE job_id=? ORDER BY finished_at DESC,id DESC LIMIT 50 OFFSET 0`, "scans_job_id_time")
	assertPlanUses("cycle lookup", `SELECT COUNT(*) FROM scans WHERE cycle_id=?`, "scans_cycle_id")
}
