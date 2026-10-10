package store

import (
	"context"
	"slices"
	"testing"
)

func TestScanHistoryIndexesSupportManagedQueries(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)

	// Exercise the upgrade path from schema 54, the oldest that this release
	// upgrades, rather than only checking a fresh database: schema 66
	// replaces the job, tenant and cycle indexes with indexes that hold the
	// columns the history reads test. This also catches a future migration
	// that forgets an index when an operator upgrades an existing
	// installation.
	for _, statement := range append(slices.Clone(schema66UndoStatements), "PRAGMA user_version = 54") {
		if _, err := s.DB.ExecContext(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	if err := migrate(s.DB); err != nil {
		t.Fatalf("reapply migrations from schema 54: %v", err)
	}

	want := map[string]bool{
		"scans_job_id_revision": true,
		"scans_finished_at":     true,
	}
	for index := range schema66ScanIndexes {
		want[index] = true
	}
	for index := range schema65ScanIndexes {
		want[index] = false
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT name FROM pragma_index_list('scans')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		found[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for name, present := range want {
		if found[name] != present {
			t.Errorf("scan index %s present = %t, want %t", name, found[name], present)
		}
	}
	for index, keys := range schema66ScanIndexes {
		if got := indexKeys(t, s.DB, index); got != keys {
			t.Errorf("%s keys = %q, want %q", index, got, keys)
		}
	}

	jobQueries := jobScansPageQueries(DefaultTenantID, "job-id", 50, 0)
	assertScanPlans(t, s.DB, []planCase{
		{label: "job count", statement: jobQueries.countSQL, args: jobQueries.countArg, aliases: []string{"s"}},
		{label: "job history", statement: jobQueries.pageSQL, args: jobQueries.pageArg, aliases: []string{"s"}, index: scansJobHistoryIndex, pageRows: true},
		{label: "cycle lookup", statement: scanCycleHasScanQuery, args: []any{"cycle-id", DefaultTenantID}, index: scansCycleOutcomeIndex},
	})
}
