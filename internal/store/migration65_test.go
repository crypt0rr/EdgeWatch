package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// Schema 65 adds the comparison outcome to scans. A scan recorded before it
// keeps the empty legacy value, so its history keeps the compatibility
// comparison, and a repeated upgrade with the column present is harmless.
func TestMigration65AddsScanComparisonAndKeepsLegacyRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("migration-65"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`ALTER TABLE scans DROP COLUMN comparison`); err != nil {
		t.Fatal(err)
	}
	stamp := sqliteTimestamp(time.Now())
	for _, row := range []struct{ id, baselineScanID string }{
		{id: "schema-64-sample"},
		{id: "schema-64-compared", baselineScanID: "schema-64-sample"},
	} {
		if _, err := s.DB.Exec(`INSERT INTO scans(id,job_id,job_revision,job,started_at,finished_at,status,config_hash,snapshot_json,baseline_scan_id,baseline_config_hash,tenant_id) VALUES(?,?,?,?,?,?,'success',?,'{}',?,?,?)`,
			row.id, record.ID, record.Revision, record.Job.Name, stamp, stamp, record.Job.SecurityHash(), row.baselineScanID, "", DefaultTenantID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.Exec(`PRAGMA user_version=64`); err != nil {
		t.Fatal(err)
	}
	path := s.Path
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade from schema 64: %v", err)
	}
	if version := countRows(t, upgraded.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
	var columnType string
	var notNull int
	var defaultValue sql.NullString
	if err := upgraded.DB.QueryRow(`SELECT type,"notnull",dflt_value FROM pragma_table_info('scans') WHERE name='comparison'`).Scan(&columnType, &notNull, &defaultValue); err != nil {
		t.Fatalf("comparison column: %v", err)
	}
	if columnType != "TEXT" || notNull != 1 || defaultValue.String != "''" {
		t.Fatalf("comparison column = %s not null %d default %v; want TEXT NOT NULL DEFAULT ''", columnType, notNull, defaultValue)
	}
	for _, id := range []string{"schema-64-sample", "schema-64-compared"} {
		summary, err := defaultTenant(upgraded).GetScanSummary(ctx, id)
		if err != nil || summary.Comparison != model.ScanComparisonLegacy {
			t.Fatalf("upgraded scan %s comparison = %q, %v; want the legacy marker", id, summary.Comparison, err)
		}
	}

	// A test database reconstructed from a newer template already has the
	// column, and the upgrade leaves it alone.
	if _, err := upgraded.DB.Exec(`PRAGMA user_version=64`); err != nil {
		t.Fatal(err)
	}
	if err := upgraded.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatalf("repeated upgrade from schema 64: %v", err)
	}
	t.Cleanup(func() { _ = again.Close() })
	if version := countRows(t, again.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("repeated upgrade schema version = %d, want %d", version, schemaVersion)
	}
	if columns := countRows(t, again.DB, `SELECT COUNT(*) FROM pragma_table_info('scans') WHERE name='comparison'`); columns != 1 {
		t.Fatalf("comparison columns after a repeated upgrade = %d, want 1", columns)
	}
}

// Every read of a tenant's scans returns the recorded comparison outcome,
// and a backup and its restore keep it.
func TestScanComparisonRoundTripsThroughReadsBackupAndRestore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("comparison-round-trip"))
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	want := map[string]string{}
	for i, comparison := range []string{
		model.ScanComparisonLegacy,
		model.ScanComparisonBaselineSample,
		model.ScanComparisonBaselineEstablished,
		model.ScanComparisonCompared,
		model.ScanComparisonNotCompared,
	} {
		id := "comparison-" + comparison
		if comparison == model.ScanComparisonLegacy {
			id = "comparison-legacy"
		}
		status := "success"
		if comparison == model.ScanComparisonNotCompared {
			status = "failed"
		}
		finished := base.Add(time.Duration(i) * time.Minute)
		scan := model.Scan{ID: id, JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: finished, FinishedAt: finished, Status: status, ConfigHash: record.Job.SecurityHash(), Comparison: comparison}
		if err := s.System().SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
		want[id] = comparison
	}
	ts := defaultTenant(s)
	check := func(source, id, got string) {
		t.Helper()
		if expected, ok := want[id]; !ok || got != expected {
			t.Fatalf("%s scan %s comparison = %q, want %q", source, id, got, expected)
		}
	}
	for id := range want {
		scan, err := ts.GetScan(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		check("GetScan", id, scan.Comparison)
		summary, err := ts.GetScanSummary(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		check("GetScanSummary", id, summary.Comparison)
		compared, _, err := ts.GetScanComparison(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		check("GetScanComparison", id, compared.Comparison)
		exported, err := getScanSummaryForQuery(ctx, s.DB, DefaultTenantID, id)
		if err != nil {
			t.Fatal(err)
		}
		check("getScanSummaryForQuery", id, exported.Comparison)
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		inTx, err := getScanTx(ctx, tx, id)
		_ = tx.Rollback()
		if err != nil {
			t.Fatal(err)
		}
		check("getScanTx", id, inTx.Comparison)
	}
	latest, err := ts.GetLatestSuccessfulJobScanSummary(ctx, record.ID)
	if err != nil || latest == nil {
		t.Fatalf("latest successful scan = %v, %v", latest, err)
	}
	check("GetLatestSuccessfulJobScanSummary", latest.ID, latest.Comparison)
	jobScans, err := ts.ListJobScansPage(ctx, record.ID, 10, 0)
	if err != nil || len(jobScans.Items) != len(want) {
		t.Fatalf("job scans = %d, %v", len(jobScans.Items), err)
	}
	for _, scan := range jobScans.Items {
		check("ListJobScansPage", scan.ID, scan.Comparison)
	}
	jobSummaries, err := ts.ListJobScanSummariesPage(ctx, record.ID, 10, 0)
	if err != nil || len(jobSummaries.Items) != len(want) {
		t.Fatalf("job scan summaries = %d, %v", len(jobSummaries.Items), err)
	}
	for _, summary := range jobSummaries.Items {
		check("ListJobScanSummariesPage", summary.ID, summary.Comparison)
	}
	scans, err := ts.ListScansPage(ctx, record.Job.Name, 10, 0)
	if err != nil || len(scans.Items) != len(want) {
		t.Fatalf("scans = %d, %v", len(scans.Items), err)
	}
	for _, scan := range scans.Items {
		check("ListScansPage", scan.ID, scan.Comparison)
	}
	summaries, err := ts.ListScanSummariesPage(ctx, record.Job.Name, 10, 0)
	if err != nil || len(summaries.Items) != len(want) {
		t.Fatalf("scan summaries = %d, %v", len(summaries.Items), err)
	}
	for _, summary := range summaries.Items {
		check("ListScanSummariesPage", summary.ID, summary.Comparison)
	}

	dir := t.TempDir()
	backup, err := s.Backup(ctx, filepath.Join(dir, "backup.db"))
	if err != nil {
		t.Fatal(err)
	}
	destination := freshTestDatabasePath(t)
	if _, err := Restore(ctx, backup, destination, RestoreOptions{}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	restored, err := OpenReadOnlyExisting(destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.Close() })
	for id := range want {
		summary, err := restored.Tenant(DefaultTenantScope()).GetScanSummary(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		check("restored GetScanSummary", id, summary.Comparison)
	}
}
