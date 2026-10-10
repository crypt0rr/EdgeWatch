package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestMigration58RebuildsPrioritizedHostSearchIndexes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO jobs(id,tenant_id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES('search-migration-job',?,'search-migration-job','{}',1,0,1,'now','now')`, DefaultTenantID); err != nil {
		t.Fatal(err)
	}
	ports := make([]model.PortObservation, 10_000)
	for i := range ports {
		ports[i] = model.PortObservation{Port: i + 1, State: "open", Service: &model.ServiceObservation{Product: fmt.Sprintf("product-%05d", i), Version: strings.Repeat("v", 16)}}
	}
	ports[len(ports)-1].Service.Name = "lateuniqueservice"
	host := model.HostObservation{Address: "198.51.100.77", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: ports}}}
	now := time.Now().UTC()
	scan := model.Scan{ID: "search-migration-scan", JobID: "search-migration-job", Job: "search-migration-job", StartedAt: now, FinishedAt: now, Status: "success", Snapshot: model.Snapshot{Hosts: []model.HostObservation{host}}}
	if err := s.System().SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if err := s.System().ReplaceBaselineHostProjection(ctx, scan.JobID, scan.Snapshot); err != nil {
		t.Fatal(err)
	}

	// Simulate the prior capped document in all three projections. The FTS
	// triggers follow these updates, so the term cannot be found before the
	// migration rebuilds search_text from the retained host evidence.
	oldDocument := host.Address + " " + strings.Repeat("legacyproduct ", 4_000)
	for _, table := range []string{"scan_hosts", "latest_scan_hosts", "baseline_hosts"} {
		if _, err := s.DB.ExecContext(ctx, `UPDATE `+table+` SET search_text=?`, oldDocument); err != nil {
			t.Fatalf("simulate old %s document: %v", table, err)
		}
	}
	old, err := defaultTenant(s).ListLatestScanHostsPage(ctx, "lateuniqueservice", "", nil, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if old.Total != 0 {
		t.Fatal("old latest-host document unexpectedly matches the late service")
	}
	path := s.Path
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	legacyDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyDB.ExecContext(ctx, `PRAGMA user_version=57`); err != nil {
		legacyDB.Close()
		t.Fatal(err)
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade from schema 57: %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	if version := countRows(t, upgraded.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}

	latest, err := defaultTenant(upgraded).ListLatestScanHostsPage(ctx, "lateuniqueservice", "", nil, 10, 0)
	if err != nil || latest.Total != 1 {
		t.Fatalf("latest-host search after migration = %#v, %v", latest, err)
	}
	scanPage, err := defaultTenant(upgraded).ListScanHostsPage(ctx, scan.ID, "lateuniqueservice", "", nil, 10, 0)
	if err != nil || scanPage.Total != 1 {
		t.Fatalf("per-scan search after migration = %#v, %v", scanPage, err)
	}
	baseline, err := defaultTenant(upgraded).ListBaselineHostsPage(ctx, scan.JobID, "lateuniqueservice", "", nil, 10, 0)
	if err != nil || baseline.Total != 1 {
		t.Fatalf("baseline search after migration = %#v, %v", baseline, err)
	}
	if len(baseline.Items) != 1 || len(baseline.Items[0].Host.Protocols[0].Ports) != len(ports) || baseline.Items[0].Host.Protocols[0].Ports[len(ports)-1].Service.Name != "lateuniqueservice" {
		t.Fatal("search-index migration changed or lost full baseline host evidence")
	}
	for _, check := range []struct {
		name  string
		query string
		args  []any
	}{
		{"scan", `SELECT length(CAST(content AS BLOB)) FROM scan_host_search WHERE rowid=(SELECT rowid FROM scan_hosts WHERE scan_id=? AND address=?)`, []any{scan.ID, host.Address}},
		{"latest", `SELECT length(CAST(content AS BLOB)) FROM latest_host_search WHERE rowid=(SELECT rowid FROM latest_scan_hosts WHERE scan_id=? AND address=?)`, []any{scan.ID, host.Address}},
		{"baseline", `SELECT length(CAST(content AS BLOB)) FROM baseline_host_search WHERE rowid=(SELECT rowid FROM baseline_hosts WHERE job_id=? AND address=?)`, []any{scan.JobID, host.Address}},
	} {
		var bytes int
		if err := upgraded.DB.QueryRowContext(ctx, check.query, check.args...).Scan(&bytes); err != nil {
			t.Fatalf("read %s search document size: %v", check.name, err)
		}
		if bytes > maxHostSearchTextBytes {
			t.Errorf("%s FTS document is %d bytes, exceeds %d-byte limit", check.name, bytes, maxHostSearchTextBytes)
		}
	}
}

// A host search rebuild, such as schema 58's, drops the scan and latest-host
// projections and creates them again instead of deleting their rows: an
// FTS5 DELETE rewrites the whole index in one transaction, which holds the
// writer and grows the write-ahead log with the retained history.
func TestHostSearchRebuildDropsTheOldIndexes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	const scans, hostsPerScan = 5, 10_000
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO jobs(id,tenant_id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES('search-rebuild-job',?,'search-rebuild-job','{}',1,0,1,'now','now')`, DefaultTenantID); err != nil {
		t.Fatal(err)
	}
	ids := seedLargeEvidenceScans(t, s.DB, DefaultTenantID, "search-rebuild-job", "search-rebuild", scans, 1<<10, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	seedLargeEvidenceHosts(t, s.DB, ids, hostsPerScan)
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM scan_host_search`); got != scans*hostsPerScan {
		t.Fatalf("seeded search rows = %d, want %d", got, scans*hostsPerScan)
	}
	indexBytes := countRows(t, s.DB, `SELECT SUM(length(block)) FROM scan_host_search_data`)
	rootPage := countRows(t, s.DB, `SELECT rootpage FROM sqlite_master WHERE name='scan_host_search_data'`)
	if _, err := s.DB.ExecContext(ctx, `UPDATE fts_backfill_state SET last_rowid=0,processed_rows=0,initialized=0,complete=0 WHERE table_name IN ('scan_hosts','latest_scan_hosts')`); err != nil {
		t.Fatal(err)
	}
	// Start from an empty log, so its size afterwards is what the rebuild
	// wrote.
	if _, err := s.DB.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}

	// Stop after the first committed batch: the old index is already gone,
	// and the log holds only the reset and one batch.
	stopped, stop := context.WithCancel(ctx)
	defer stop()
	var searchRows, walBytes int64
	var newRootPage int
	err := backfillHostSearchIndexesContextWithProgress(stopped, s.DB, func(progress ftsBatchProgress) {
		if progress.table != "scan_hosts" || searchRows != 0 {
			return
		}
		searchRows = int64(countRows(t, s.DB, `SELECT COUNT(*) FROM scan_host_search`))
		newRootPage = countRows(t, s.DB, `SELECT rootpage FROM sqlite_master WHERE name='scan_host_search_data'`)
		info, err := os.Stat(s.FilePath() + "-wal")
		if err != nil {
			t.Error(err)
		}
		walBytes = info.Size()
		stop()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("stopped rebuild error = %v", err)
	}
	t.Logf("index %d bytes; after the reset and one batch the log is %d bytes and the index holds %d rows", indexBytes, walBytes, searchRows)
	if searchRows == 0 || searchRows > ftsBackfillBatchSize {
		t.Fatalf("search rows after the first batch = %d, want at most one batch of %d: the old index must be gone", searchRows, ftsBackfillBatchSize)
	}
	if newRootPage == rootPage {
		t.Fatalf("scan_host_search_data keeps root page %d: the index was cleared row by row, not rebuilt", rootPage)
	}
	if walBytes*4 > int64(indexBytes) {
		t.Fatalf("write-ahead log = %d bytes after the reset, want far less than the %d-byte index", walBytes, indexBytes)
	}

	// The next start resumes the rebuild and indexes every row again.
	if err := backfillHostSearchIndexesContext(ctx, s.DB); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM scan_host_search`); got != scans*hostsPerScan {
		t.Fatalf("search rows after the rebuild = %d, want %d", got, scans*hostsPerScan)
	}
	page, err := defaultTenant(s).ListScanHostsPage(ctx, ids[0], "10.0.39.15", "", nil, 10, 0)
	if err != nil || page.Total != 1 {
		t.Fatalf("search after the rebuild = %#v, %v", page, err)
	}
}

// largeLogBytes is the size of the transaction with which
// crashCopyWithLargeLog grows the write-ahead log, as a large upgrade step
// does.
const largeLogBytes = 8 << 20

// crashCopyWithLargeLog prepares a copy of the migrated template with the
// statements and returns it as a start that was killed leaves it: beside the
// database file is a write-ahead log at the size of a large transaction,
// which no clean close has removed.
func crashCopyWithLargeLog(t *testing.T, statements ...string) string {
	t.Helper()
	path := freshTestDatabasePath(t)
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	statements = append([]string{`PRAGMA journal_mode=WAL`}, statements...)
	// The filler is dropped in a later transaction, which reuses the log from
	// its start once it has been checkpointed: the file keeps its size.
	statements = append(statements,
		`CREATE TABLE wal_filler(data BLOB NOT NULL)`,
		fmt.Sprintf(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<%d) INSERT INTO wal_filler(data) SELECT zeroblob(65536) FROM n`, largeLogBytes/65536),
		`DROP TABLE wal_filler`)
	for _, statement := range statements {
		if _, err := raw.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	crashed := filepath.Join(t.TempDir(), "edgewatch.db")
	for _, suffix := range []string{"", "-wal"} {
		contents, err := os.ReadFile(path + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(crashed+suffix, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if info, err := os.Stat(crashed + "-wal"); err != nil || info.Size() < largeLogBytes {
		t.Fatalf("crash copy's write-ahead log = %v, %v; want at least %d bytes", info, err, largeLogBytes)
	}
	return crashed
}

// The daemon truncates the write-ahead log once its startup work has
// finished, so a large migration step does not leave a log of its size
// beside the database while the daemon runs. That holds for a start that
// upgrades the schema and for one that finds the schema current and
// finishes the startup work that a killed start left, such as a pending
// host search rebuild.
func TestOpenTruncatesTheWriteAheadLogAfterItsStartupWork(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		statements []string
	}{
		{
			name:       "upgrade",
			statements: []string{fmt.Sprintf(`PRAGMA user_version=%d`, schemaVersion-1)},
		},
		{
			name: "resumed upgrade",
			statements: []string{
				`UPDATE startup_state SET state='migrating',owner='migration/1',phase='host-search',started_at='2026-01-02T03:04:05Z',updated_at='2026-01-02T03:04:06Z' WHERE id=1`,
				`UPDATE fts_backfill_state SET last_rowid=0,processed_rows=0,initialized=0,complete=0 WHERE table_name IN ('scan_hosts','latest_scan_hosts')`,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := crashCopyWithLargeLog(t, test.statements...)
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			info, err := os.Stat(path + "-wal")
			if err != nil {
				t.Fatal(err)
			}
			if info.Size() > 64<<10 {
				t.Fatalf("write-ahead log = %d bytes after the start, want it truncated from at least %d", info.Size(), largeLogBytes)
			}
			if got := countRows(t, s.DB, `PRAGMA user_version`); got != schemaVersion {
				t.Fatalf("user_version = %d, want %d", got, schemaVersion)
			}
			if got := queryStrings(t, s.DB, `SELECT state FROM startup_state WHERE id=1`); len(got) != 1 || got[0] != "ready" {
				t.Fatalf("startup state after the start = %v, want ready", got)
			}
			if got := countRows(t, s.DB, `SELECT COUNT(*) FROM fts_backfill_state WHERE table_name IN ('scan_hosts','latest_scan_hosts') AND initialized=1 AND complete=1`); got != 2 {
				t.Fatalf("finished host search rebuilds = %d, want 2", got)
			}
		})
	}
}
