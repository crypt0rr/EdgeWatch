package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// latestHostSearchTriggerNames are the search triggers of latest_scan_hosts.
var latestHostSearchTriggerNames = []string{"latest_scan_hosts_search_ai", "latest_scan_hosts_search_au", "latest_scan_hosts_search_ad"}

// schema54Triggers are the guard triggers that schema 54 installs when its
// copy completes.
var schema54Triggers = []string{latestScanHostsTenantInsertTrigger, latestScanHostsTenantUpdateTrigger}

// schema54RekeyTriggers refuse other writes while the copy runs.
var schema54RekeyTriggers = []string{latestScanHostsRekeyInsertTrigger, latestScanHostsRekeyUpdateTrigger, latestScanHostsRekeyDeleteTrigger}

var latestScanHostsStableColumnList = strings.Split(strings.TrimSuffix(latestScanHostsCopyColumns, ",search_text"), ",")

// schema53FixtureStatements turn a current database into the schema-53
// shape. They first undo schema 66, see schema66UndoStatements. Then
// latest_scan_hosts goes back to the address key with the schema 53 indexes
// and search triggers, each row keeping its rowid, and the schema 54 guard
// triggers and checkpoint are removed.
var schema53FixtureStatements = slices.Concat(schema66UndoStatements, []string{
	"DROP TRIGGER " + latestScanHostsTenantInsertTrigger,
	"DROP TRIGGER " + latestScanHostsTenantUpdateTrigger,
	"DROP TRIGGER latest_scan_hosts_search_ai",
	"DROP TRIGGER latest_scan_hosts_search_au",
	"DROP TRIGGER latest_scan_hosts_search_ad",
	`CREATE TABLE latest_scan_hosts_schema53 (
 address TEXT PRIMARY KEY,
 scan_id TEXT NOT NULL,
 job_id TEXT NOT NULL DEFAULT '',
 job TEXT NOT NULL DEFAULT '',
 finished_at TEXT NOT NULL,
 data_quality TEXT NOT NULL DEFAULT 'detailed',
 address_family TEXT NOT NULL DEFAULT '',
 source_targets_json BLOB NOT NULL DEFAULT '[]',
 dns_names_json BLOB NOT NULL DEFAULT '[]',
 host_json BLOB NOT NULL,
 open_ports INTEGER NOT NULL DEFAULT 0,
 open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 tcp_present INTEGER NOT NULL DEFAULT 0,
 udp_present INTEGER NOT NULL DEFAULT 0,
 tcp_open_ports INTEGER NOT NULL DEFAULT 0,
 tcp_open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 udp_open_ports INTEGER NOT NULL DEFAULT 0,
 udp_open_filtered_ports INTEGER NOT NULL DEFAULT 0,
 search_text TEXT NOT NULL DEFAULT ''
)`,
	"INSERT INTO latest_scan_hosts_schema53(rowid," + latestScanHostsCopyColumns + ") SELECT rowid," + latestScanHostsCopyColumns + " FROM latest_scan_hosts",
	"DROP TABLE latest_scan_hosts",
	"ALTER TABLE latest_scan_hosts_schema53 RENAME TO latest_scan_hosts",
	"CREATE INDEX latest_scan_hosts_open ON latest_scan_hosts(open_ports, open_filtered_ports)",
	"CREATE INDEX latest_scan_hosts_protocol_open ON latest_scan_hosts(tcp_present, udp_present, tcp_open_ports, udp_open_ports)",
}, latestHostSearchTriggerSQL, []string{
	"DELETE FROM fts_backfill_state WHERE table_name='" + latestScanHostsTenantRekeyState + "'",
	"PRAGMA user_version=53",
})

// schema54SwapStatements turn a schema 53 fixture into the state in which
// the schema 54 step, now part of the baseline, left an upgraded database:
// latest_scan_hosts renamed to latestScanHostsPreTenantTable, without its
// search triggers and indexes, beside an empty tenant-keyed projection whose
// triggers refuse other writes, and the checkpoint of the copy at its start.
// A database that v0.20.0 to v0.35.0 upgraded to schema 54 stays in this
// state until its startup copy completes. The new table, its indexes and
// its triggers are the baseline's.
var schema54SwapStatements = slices.Concat([]string{
	"DROP TRIGGER IF EXISTS latest_scan_hosts_search_ai",
	"DROP TRIGGER IF EXISTS latest_scan_hosts_search_au",
	"DROP TRIGGER IF EXISTS latest_scan_hosts_search_ad",
	"ALTER TABLE latest_scan_hosts RENAME TO " + latestScanHostsPreTenantTable,
	"DROP INDEX IF EXISTS latest_scan_hosts_open",
	"DROP INDEX IF EXISTS latest_scan_hosts_protocol_open",
}, baselineStatementsWithPrefix("CREATE TABLE latest_scan_hosts ", "CREATE INDEX latest_scan_hosts_", "CREATE TRIGGER latest_scan_hosts_rekey_"), []string{
	`INSERT INTO fts_backfill_state(table_name,last_rowid,processed_rows,initialized,complete,updated_at)
VALUES('` + latestScanHostsTenantRekeyState + `',0,0,1,0,strftime('%Y-%m-%dT%H:%M:%fZ','now'))
ON CONFLICT(table_name) DO UPDATE SET last_rowid=0,processed_rows=0,initialized=1,complete=0,updated_at=excluded.updated_at`,
	"PRAGMA user_version=54",
})

// baselineStatementsWithPrefix returns the baseline statements that start
// with one of the prefixes, in their order.
func baselineStatementsWithPrefix(prefixes ...string) []string {
	var statements []string
	for _, statement := range baselineSchemaStatements {
		if slices.ContainsFunc(prefixes, func(prefix string) bool { return strings.HasPrefix(statement, prefix) }) {
			statements = append(statements, statement)
		}
	}
	return statements
}

// Fixture hosts: the first job scans hosts [0, fixtureJobAHosts) and, in an
// older scan, the first few of them; the second job scans the overlapping
// range [fixtureJobBFirst, fixtureHostRange). Each address has one latest
// row, the newest observation of the two jobs.
const (
	fixtureJobAHosts = 800
	fixtureJobBFirst = 600
	fixtureHostRange = 1100
)

// Addresses of the fixture rows that are not in a job's range.
var (
	fixtureConfigAddresses  = []string{fixtureHost(5000).Address, fixtureHost(5001).Address}
	fixtureSecondTenantAddr = fixtureHost(6000).Address
	fixtureDanglingAddress  = fixtureHost(7000).Address
)

// fixtureLatestRows is the number of latest_scan_hosts rows in the fixture.
const fixtureLatestRows = fixtureHostRange + 2 + 1 + 1

// fixtureSearchTerms match hosts in several batches of the copy, the second
// tenant's host and the host whose scan is gone.
var fixtureSearchTerms = []string{"nginx", "openssh", "asset-7.example", "host-0042", "10.54.3.", "edge-b", fixtureConfigAddresses[0], fixtureSecondTenantAddr, fixtureDanglingAddress}

func fixtureHost(i int) model.HostObservation {
	port := model.PortObservation{Port: 443, State: "open"}
	switch {
	case i%3 == 0:
		port.Service = &model.ServiceObservation{Name: "https", Product: "nginx"}
	case i%5 == 0:
		port = model.PortObservation{Port: 22, State: "open", Service: &model.ServiceObservation{Name: "ssh", Product: "openssh"}}
	case i%7 == 0:
		port.State = "closed"
	}
	return model.HostObservation{
		Address:       fmt.Sprintf("10.54.%d.%d", i/250, i%250+1),
		AddressFamily: "IPv4",
		SourceTargets: []string{fmt.Sprintf("asset-%d.example", i%40)},
		DNSNames:      []string{fmt.Sprintf("host-%04d.example", i)},
		Protocols:     []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "22,443", ScannedPortCount: 2, Ports: []model.PortObservation{port}}},
	}
}

func fixtureHosts(first, last int) []model.HostObservation {
	hosts := make([]model.HostObservation, 0, last-first)
	for i := first; i < last; i++ {
		hosts = append(hosts, fixtureHost(i))
	}
	return hosts
}

func fixtureScan(id, jobID, job string, finished time.Time, hosts []model.HostObservation) model.Scan {
	return model.Scan{ID: id, JobID: jobID, Job: job, StartedAt: finished.Add(-time.Minute), FinishedAt: finished, Status: "success", ConfigHash: "config-" + job, Snapshot: model.Snapshot{Hosts: hosts}}
}

// schema53FixtureFile holds the database file that buildSchema53Fixture
// writes. Saving the scans is the slow part of a fixture, so the tests build
// it once and each copies the file.
var schema53FixtureFile struct {
	once     sync.Once
	contents []byte
}

// newSchema53Fixture returns the path of a private copy of the schema 53
// fixture that buildSchema53Fixture writes.
func newSchema53Fixture(t *testing.T) string {
	t.Helper()
	schema53FixtureFile.once.Do(func() {
		dir, err := os.MkdirTemp("", "schema53-fixture-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		path := filepath.Join(dir, "schema53.db")
		buildSchema53Fixture(t, path)
		for _, sidecar := range []string{"-wal", "-shm", "-journal"} {
			if _, err := os.Stat(path + sidecar); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("schema 53 fixture left %s behind: %v", sidecar, err)
			}
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		schema53FixtureFile.contents = contents
	})
	if len(schema53FixtureFile.contents) == 0 {
		t.Fatal("the schema 53 fixture could not be built")
	}
	path := filepath.Join(t.TempDir(), "schema53.db")
	if err := os.WriteFile(path, schema53FixtureFile.contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// buildSchema53Fixture writes a populated database with the current code and
// rewrites it into the schema-53 shape. Its latest hosts come from two jobs
// with overlapping addresses, a config.yaml job, a job of a second tenant,
// and a scan that retention has removed, so its row is left dangling. Every
// row is in latest_host_search, and the search checkpoints are complete.
func buildSchema53Fixture(t *testing.T, path string) {
	t.Helper()
	ctx := context.Background()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	jobA, err := defaultTenant(s).CreateJob(ctx, testJob("edge-a"))
	if err != nil {
		t.Fatal(err)
	}
	jobB, err := defaultTenant(s).CreateJob(ctx, testJob("edge-b"))
	if err != nil {
		t.Fatal(err)
	}
	insertSecondTenant(t, s)
	const secondTenantJob = "00000000-0000-0000-0000-000000000b54"
	insertSecondTenantJob(t, s, jobA.ID, secondTenantJob)
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	for _, scan := range []model.Scan{
		fixtureScan("scan-a-old", jobA.ID, "edge-a", now, fixtureHosts(0, 50)),
		fixtureScan("scan-a", jobA.ID, "edge-a", now.Add(time.Minute), fixtureHosts(0, fixtureJobAHosts)),
		fixtureScan("scan-b", jobB.ID, "edge-b", now.Add(2*time.Minute), fixtureHosts(fixtureJobBFirst, fixtureHostRange)),
		fixtureScan("scan-config", "", "config-job", now.Add(3*time.Minute), []model.HostObservation{fixtureHost(5000), fixtureHost(5001)}),
		fixtureScan("scan-second-tenant", secondTenantJob, "edge-a", now.Add(4*time.Minute), []model.HostObservation{fixtureHost(6000)}),
		fixtureScan("scan-dangling", jobA.ID, "edge-a", now.Add(5*time.Minute), []model.HostObservation{fixtureHost(7000)}),
	} {
		if err := s.System().SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	// Retention removed the scan but has not repaired the projection yet.
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM scans WHERE id='scan-dangling'`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	execFixtureStatements(t, path, schema53FixtureStatements)

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if got := countRows(t, raw, `SELECT COUNT(*) FROM pragma_table_info('latest_scan_hosts') WHERE name='tenant_id'`); got != 0 {
		t.Fatal("schema 53 fixture latest_scan_hosts still has tenant_id")
	}
	if got := countRows(t, raw, `SELECT COUNT(*) FROM latest_scan_hosts`); got != fixtureLatestRows {
		t.Fatalf("schema 53 fixture latest rows = %d, want %d", got, fixtureLatestRows)
	}
	if got := countRows(t, raw, `SELECT COUNT(*) FROM latest_scan_hosts h JOIN latest_host_search hs ON hs.rowid=h.rowid AND hs.address=h.address`); got != fixtureLatestRows {
		t.Fatalf("schema 53 fixture search rows keyed by rowid = %d, want %d", got, fixtureLatestRows)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
}

// latestSearchAddresses runs a search the way the host inventory does,
// through the rowid-keyed search projection, without a tenant filter.
func latestSearchAddresses(t *testing.T, db *sql.DB, term string) []string {
	t.Helper()
	return queryStrings(t, db, `SELECT h.address FROM latest_scan_hosts h JOIN latest_host_search hs ON hs.rowid=h.rowid WHERE latest_host_search MATCH ? ORDER BY h.address`, hostSearchMatchQuery(term))
}

// hostSearchCheckpoints renders the search checkpoints, which must not be
// reset: a reset rebuilds the search projections from scratch.
func hostSearchCheckpoints(t *testing.T, db *sql.DB) string {
	t.Helper()
	var out strings.Builder
	if err := snapshotRows(db, `SELECT table_name,last_rowid,processed_rows,initialized,complete,updated_at FROM fts_backfill_state WHERE table_name IN ('scan_hosts','latest_scan_hosts','baseline_hosts') ORDER BY table_name`, &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// latestSearchRows renders latest_host_search with its rowids.
func latestSearchRows(t *testing.T, db *sql.DB) string {
	t.Helper()
	var out strings.Builder
	if err := snapshotRows(db, `SELECT rowid,address,content FROM latest_host_search ORDER BY rowid`, &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func latestSearchSourceRows(t *testing.T, db *sql.DB) string {
	t.Helper()
	var out strings.Builder
	if err := snapshotRows(db, `SELECT rowid,address,lower(coalesce(search_text,'') || ' ' || substr(coalesce(job,''),1,`+boundedHostSearchJobRunes+`)) FROM latest_scan_hosts ORDER BY rowid`, &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

type latestHostsBefore struct {
	rows        string
	search      string
	checkpoints string
	results     map[string][]string
	maxRowID    int
}

func readLatestHostsBefore(t *testing.T, path string) latestHostsBefore {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	before := latestHostsBefore{
		rows:        columnSnapshot(t, raw, "latest_scan_hosts", latestScanHostsStableColumnList),
		search:      latestSearchRows(t, raw),
		checkpoints: hostSearchCheckpoints(t, raw),
		results:     map[string][]string{},
		maxRowID:    countRows(t, raw, `SELECT MAX(rowid) FROM latest_scan_hosts`),
	}
	for _, term := range fixtureSearchTerms {
		before.results[term] = latestSearchAddresses(t, raw, term)
		if len(before.results[term]) == 0 {
			t.Fatalf("fixture search %q matches nothing", term)
		}
	}
	return before
}

// assertLatestHostsRekeyed checks the migrated projection against the rows
// read before the upgrade.
func assertLatestHostsRekeyed(t *testing.T, s *Store, before latestHostsBefore) {
	t.Helper()
	ctx := context.Background()
	if version := countRows(t, s.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
	// Every source row is copied with its rowid and evidence values. The
	// derived search_text is intentionally regenerated by schema 58.
	if after := columnSnapshot(t, s.DB, "latest_scan_hosts", latestScanHostsStableColumnList); after != before.rows {
		t.Fatalf("latest_scan_hosts rows changed:\nbefore:\n%s\nafter:\n%s", before.rows, after)
	}
	// Each row has the tenant of its scan; the row whose scan is gone gets
	// the default tenant.
	if got := queryStrings(t, s.DB, `SELECT address || ' ' || tenant_id FROM latest_scan_hosts WHERE tenant_id<>? ORDER BY address`, DefaultTenantID); !slices.Equal(got, []string{fixtureSecondTenantAddr + " " + secondTenantID}) {
		t.Fatalf("rows outside the default tenant = %v", got)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM latest_scan_hosts WHERE address=? AND tenant_id=?`, fixtureDanglingAddress, DefaultTenantID); got != 1 {
		t.Fatalf("dangling row in the default tenant = %d", got)
	}
	// Schema 58 refreshes the bounded search documents and checkpoints. The
	// FTS table must exactly mirror the regenerated source projection.
	if after := latestSearchRows(t, s.DB); after != latestSearchSourceRows(t, s.DB) {
		t.Fatalf("latest_host_search does not match its source projection:\nfts:\n%s\nsource:\n%s", after, latestSearchSourceRows(t, s.DB))
	}
	var searchLastRowID, searchProcessed, searchInitialized, searchComplete int
	if err := s.DB.QueryRow(`SELECT last_rowid,processed_rows,initialized,complete FROM fts_backfill_state WHERE table_name='latest_scan_hosts'`).Scan(&searchLastRowID, &searchProcessed, &searchInitialized, &searchComplete); err != nil {
		t.Fatal(err)
	}
	if searchLastRowID != before.maxRowID || searchProcessed != fixtureLatestRows || searchInitialized != 1 || searchComplete != 1 {
		t.Fatalf("latest-host search checkpoint = %d/%d initialized=%d complete=%d; want %d/%d initialized=1 complete=1", searchLastRowID, searchProcessed, searchInitialized, searchComplete, before.maxRowID, fixtureLatestRows)
	}
	var lastRowID, processed, initialized, complete int
	if err := s.DB.QueryRow(`SELECT last_rowid,processed_rows,initialized,complete FROM fts_backfill_state WHERE table_name=?`, latestScanHostsTenantRekeyState).Scan(&lastRowID, &processed, &initialized, &complete); err != nil {
		t.Fatal(err)
	}
	if lastRowID != before.maxRowID || processed != fixtureLatestRows || initialized != 1 || complete != 1 {
		t.Fatalf("re-key checkpoint = last_rowid %d, processed %d, initialized %d, complete %d; want %d, %d, 1, 1", lastRowID, processed, initialized, complete, before.maxRowID, fixtureLatestRows)
	}
	// The same searches find the same hosts. The host inventory shows the
	// default tenant, which holds every row but the second tenant's.
	for _, term := range fixtureSearchTerms {
		want := before.results[term]
		if got := latestSearchAddresses(t, s.DB, term); !slices.Equal(got, want) {
			t.Fatalf("search %q after the upgrade = %v, want %v", term, got, want)
		}
		page, err := defaultTenant(s).ListLatestScanHostsPage(ctx, term, "", nil, 1000, 0)
		if err != nil {
			t.Fatal(err)
		}
		var listed []string
		for _, item := range page.Items {
			listed = append(listed, item.Host.Address)
		}
		slices.Sort(listed)
		wantListed := slices.DeleteFunc(slices.Clone(want), func(address string) bool { return address == fixtureSecondTenantAddr })
		if page.Total != len(wantListed) || !slices.Equal(listed, wantListed) {
			t.Fatalf("host inventory search %q = %d %v, want %v", term, page.Total, listed, wantListed)
		}
	}

	// The schema objects of the tenant-keyed projection.
	if got := tableColumns(t, s.DB, "latest_scan_hosts"); got[len(got)-1] != "tenant_id TEXT notnull=1 default=<none> pk=1" || !strings.HasPrefix(got[0], "address TEXT notnull=1 default=<none> pk=2") {
		t.Fatalf("latest_scan_hosts columns = %v", got)
	}
	for index, want := range map[string]string{
		"latest_scan_hosts_open":          "tenant_id,open_ports,open_filtered_ports",
		"latest_scan_hosts_protocol_open": "tenant_id,tcp_present,udp_present,tcp_open_ports,udp_open_ports",
		"latest_scan_hosts_scan":          "scan_id",
	} {
		if got := indexKeys(t, s.DB, index); got != want {
			t.Fatalf("%s keys = %q, want %q", index, got, want)
		}
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND tbl_name='latest_scan_hosts'`); got != 4 {
		t.Fatalf("latest_scan_hosts indexes = %d, want the primary key and three indexes", got)
	}
	for _, trigger := range slices.Concat(latestHostSearchTriggerNames, schema54Triggers) {
		if got := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=? AND tbl_name='latest_scan_hosts'`, trigger); got != 1 {
			t.Fatalf("trigger %s is missing", trigger)
		}
	}
	// Schema 66 leaves the guard triggers to the copy, which installs them
	// in their schema 66 form once the row whose scan retention removed has
	// been copied; installed before, they would refuse that row.
	for _, trigger := range schema54Triggers {
		if got := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=? AND instr(sql,?)>0`, trigger, latestScanHostScanTenantSQL); got != 1 {
			t.Fatalf("trigger %s does not check the scan through its tenant", trigger)
		}
	}
	for _, name := range append(slices.Clone(schema54RekeyTriggers), latestScanHostsPreTenantTable) {
		if got := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE name=?`, name); got != 0 {
			t.Fatalf("%s is left after the copy", name)
		}
	}
	var integrity string
	if err := s.DB.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("integrity_check = %q, %v", integrity, err)
	}
	assertForeignKeysClean(t, s.DB)
}

func TestMigration54KeysLatestHostsByTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := newSchema53Fixture(t)
	before := readLatestHostsBefore(t, path)
	execFixtureStatements(t, path, schema54SwapStatements)
	// Record every startup heartbeat so the copy must report its progress
	// while it runs.
	execFixtureStatements(t, path, []string{
		`CREATE TABLE migration_progress_observations(phase TEXT NOT NULL,progress INTEGER NOT NULL,total INTEGER NOT NULL)`,
		`CREATE TRIGGER migration_progress_capture AFTER UPDATE OF phase,updated_at,progress ON startup_state WHEN NEW.state='migrating' BEGIN INSERT INTO migration_progress_observations(phase,progress,total) VALUES(NEW.phase,NEW.progress,NEW.total); END`,
	})

	s, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade from schema 54: %v", err)
	}
	defer s.Close()
	assertLatestHostsRekeyed(t, s, before)

	// edgewatch health shows the phase with its progress while it runs.
	var progress []string
	for batch := 1; batch*latestScanHostsRekeyBatchSize < fixtureLatestRows+latestScanHostsRekeyBatchSize; batch++ {
		progress = append(progress, fmt.Sprintf("%d/%d", min(batch*latestScanHostsRekeyBatchSize, fixtureLatestRows), fixtureLatestRows))
	}
	if got := queryStrings(t, s.DB, `SELECT progress || '/' || total FROM migration_progress_observations WHERE phase=? AND progress>0 ORDER BY rowid`, latestScanHostsTenantPhase); !slices.Equal(got, progress) {
		t.Fatalf("%s heartbeats = %v, want %v", latestScanHostsTenantPhase, got, progress)
	}
	phases := queryStrings(t, s.DB, `SELECT phase FROM migration_progress_observations WHERE phase NOT LIKE 'timestamp-normalization:%' AND phase NOT LIKE 'host-search:%' GROUP BY phase ORDER BY MIN(rowid)`)
	if len(phases) < 3 || phases[0] != "schema" || phases[1] != latestScanHostsTenantPhase || phases[2] != "timestamp-normalization" {
		t.Fatalf("startup phases = %v, want %s right after the schema steps", phases, latestScanHostsTenantPhase)
	}

	// The writers use the tenant key: a newer scan replaces the row in
	// place, and the search follows through the recreated triggers.
	jobA := queryStrings(t, s.DB, `SELECT id FROM jobs WHERE name='edge-a' AND tenant_id=?`, DefaultTenantID)[0]
	host := fixtureHost(1)
	host.Protocols[0].Ports[0].Service = &model.ServiceObservation{Name: "http", Product: "caddy"}
	address := host.Address
	rowID := countRows(t, s.DB, `SELECT rowid FROM latest_scan_hosts WHERE address=?`, address)
	if err := s.System().SaveScan(ctx, fixtureScan("scan-a-newer", jobA, "edge-a", time.Now().UTC(), []model.HostObservation{host})); err != nil {
		t.Fatal(err)
	}
	if got := queryStrings(t, s.DB, `SELECT rowid || ' ' || scan_id || ' ' || tenant_id FROM latest_scan_hosts WHERE address=?`, address); !slices.Equal(got, []string{fmt.Sprintf("%d scan-a-newer %s", rowID, DefaultTenantID)}) {
		t.Fatalf("upserted row = %v", got)
	}
	if got := latestSearchAddresses(t, s.DB, "caddy"); !slices.Equal(got, []string{address}) {
		t.Fatalf("search after an upsert = %v", got)
	}
	// Retention repairs the dangling row: its scan is gone and no other
	// scan observed the address.
	if _, err := s.System().PruneWithStats(ctx, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM latest_scan_hosts WHERE address=?`, fixtureDanglingAddress); got != 0 {
		t.Fatalf("dangling rows after retention = %d", got)
	}
	if got := latestSearchAddresses(t, s.DB, fixtureDanglingAddress); len(got) != 0 {
		t.Fatalf("search for the repaired row = %v", got)
	}
}

// openRekeyPending applies the schema 54 table swap to a schema 53 fixture
// and opens it without migrating it, so the copy is pending.
func openRekeyPending(t *testing.T, path string) *Store {
	t.Helper()
	execFixtureStatements(t, path, schema54SwapStatements)
	s, err := OpenExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for _, name := range append(slices.Clone(schema54RekeyTriggers), latestScanHostsPreTenantTable) {
		if got := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE name=?`, name); got != 1 {
			t.Fatalf("%s is missing after the table swap", name)
		}
	}
	for _, trigger := range latestHostSearchTriggerNames {
		if got := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE name=?`, trigger); got != 0 {
			t.Fatalf("search trigger %s is still installed during the copy", trigger)
		}
	}
	return s
}

func TestMigration54ResumesAfterCancellation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := newSchema53Fixture(t)
	before := readLatestHostsBefore(t, path)
	pending := openRekeyPending(t, path)

	// Cancel after the first committed batch. The heartbeat that the daemon
	// writes after each batch is what edgewatch health reports.
	copyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var health []HealthStatus
	err := rekeyLatestScanHostsByTenantContext(copyCtx, pending.DB, func(processed, total int64) {
		if err := updateMigrationStatus(ctx, pending.DB, latestScanHostsTenantPhase, processed, total); err != nil {
			t.Error(err)
		}
		reader, err := OpenReadOnlyExistingContext(ctx, path)
		if err != nil {
			t.Error(err)
			return
		}
		status, err := reader.System().HealthStatus(ctx)
		_ = reader.Close()
		if err != nil {
			t.Error(err)
		}
		health = append(health, status)
		cancel()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled copy error = %v, want context.Canceled", err)
	}
	if len(health) != 1 || health[0].Status != "starting" || health[0].Phase != latestScanHostsTenantPhase || health[0].Progress != latestScanHostsRekeyBatchSize || health[0].Total != fixtureLatestRows {
		t.Fatalf("health during the copy = %#v", health)
	}
	var lastRowID, processed, complete int
	if err := pending.DB.QueryRow(`SELECT last_rowid,processed_rows,complete FROM fts_backfill_state WHERE table_name=?`, latestScanHostsTenantRekeyState).Scan(&lastRowID, &processed, &complete); err != nil {
		t.Fatal(err)
	}
	if lastRowID == 0 || processed != latestScanHostsRekeyBatchSize || complete != 0 {
		t.Fatalf("cancelled checkpoint = last_rowid %d, processed %d, complete %d", lastRowID, processed, complete)
	}
	if got := countRows(t, pending.DB, `SELECT COUNT(*) FROM latest_scan_hosts`); got != latestScanHostsRekeyBatchSize {
		t.Fatalf("copied rows after one batch = %d", got)
	}
	if got := countRows(t, pending.DB, `SELECT COUNT(*) FROM `+latestScanHostsPreTenantTable); got != fixtureLatestRows {
		t.Fatalf("rows left in %s = %d", latestScanHostsPreTenantTable, got)
	}

	// Until the copy completes the projection refuses other writes, such as a
	// scan saved by a host command, instead of losing rows or search terms.
	jobA := queryStrings(t, pending.DB, `SELECT id FROM jobs WHERE name='edge-a' AND tenant_id=?`, DefaultTenantID)[0]
	const refused = "latest_scan_hosts is being keyed by tenant"
	if err := pending.System().SaveScan(ctx, fixtureScan("scan-during-copy", jobA, "edge-a", time.Now().UTC(), []model.HostObservation{fixtureHost(9000)})); err == nil || !strings.Contains(err.Error(), refused) {
		t.Fatalf("scan saved during the copy: %v", err)
	}
	for _, statement := range []string{
		`UPDATE latest_scan_hosts SET job='changed'`,
		`DELETE FROM latest_scan_hosts`,
		`INSERT INTO latest_scan_hosts(tenant_id,address,scan_id,finished_at,host_json) VALUES('` + DefaultTenantID + `','192.0.2.99','scan-a','now','{}')`,
	} {
		if _, err := pending.DB.Exec(statement); err == nil || !strings.Contains(err.Error(), refused) {
			t.Fatalf("%s during the copy: %v", statement, err)
		}
	}
	if got := countRows(t, pending.DB, `SELECT COUNT(*) FROM scans WHERE id='scan-during-copy'`); got != 0 {
		t.Fatal("the refused scan was saved")
	}

	// edgewatch verify reports the interrupted copy.
	readOnly, err := OpenReadOnlyExistingContext(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := readOnly.Verify(ctx)
	_ = readOnly.Close()
	if err != nil {
		t.Fatalf("verify the interrupted copy: %v", err)
	}
	reported := false
	for _, progress := range verification.FTSBackfill {
		if progress.TableName == latestScanHostsTenantRekeyState {
			reported = !progress.Complete && progress.ProcessedRows == latestScanHostsRekeyBatchSize
		}
	}
	if !reported {
		t.Fatalf("verification did not report the interrupted copy: %#v", verification.FTSBackfill)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}

	// The next start resumes from the checkpoint and copies each row once.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("resume the copy: %v", err)
	}
	defer s.Close()
	assertLatestHostsRekeyed(t, s, before)
}

// The startup phases that repair, index or backfill latest_scan_hosts wait
// for a pending copy. Otherwise the host search phase would find the search
// triggers missing and rebuild both search projections, and its search text
// and legacy updates would be refused.
func TestMigration54StartupPhasesWaitForTheCopy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		phase func(*sql.DB) error
	}{
		{name: "host search", phase: func(db *sql.DB) error { return backfillHostSearchIndexesContext(context.Background(), db) }},
		{name: "scan host repair", phase: func(db *sql.DB) error { return repairScanHostsForeignKeyContext(context.Background(), db) }},
		{name: "legacy host index", phase: func(db *sql.DB) error { return backfillLegacyScanHostsContext(context.Background(), db) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			path := newSchema53Fixture(t)
			before := readLatestHostsBefore(t, path)
			pending := openRekeyPending(t, path)
			// One batch is copied, as after an interrupted start.
			if _, done, err := copyLatestScanHostsRekeyBatchContext(ctx, pending.DB); err != nil || done {
				t.Fatalf("first batch = done %v, %v", done, err)
			}
			if err := tc.phase(pending.DB); err != nil {
				t.Fatalf("%s during the copy: %v", tc.name, err)
			}
			if got := countRows(t, pending.DB, `SELECT COUNT(*) FROM sqlite_master WHERE name=?`, latestScanHostsPreTenantTable); got != 0 {
				t.Fatalf("%s ran before the copy completed", tc.name)
			}
			if got := hostSearchCheckpoints(t, pending.DB); got != before.checkpoints {
				t.Fatalf("%s reset the host search checkpoints:\nbefore:\n%s\nafter:\n%s", tc.name, before.checkpoints, got)
			}
			if got := latestSearchRows(t, pending.DB); got != before.search {
				t.Fatalf("%s changed latest_host_search", tc.name)
			}
			if err := pending.Close(); err != nil {
				t.Fatal(err)
			}
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			assertLatestHostsRekeyed(t, s, before)
		})
	}
}

// A second tenant that scans the same address keeps its own row. Upserts,
// the retention repair and the full rebuild keep the tenants apart, and the
// guard triggers refuse a row outside its scan's tenant.
func TestSchema54KeepsTheLatestHostOfEachTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	insertSecondTenant(t, s)
	jobA, err := defaultTenant(s).CreateJob(ctx, testJob("edge"))
	if err != nil {
		t.Fatal(err)
	}
	const jobB = "00000000-0000-0000-0000-000000000b02"
	insertSecondTenantJob(t, s, jobA.ID, jobB)
	address := fixtureHost(0).Address
	observed := func(product string) []model.HostObservation {
		host := fixtureHost(0)
		host.Protocols[0].Ports[0].Service = &model.ServiceObservation{Name: "https", Product: product}
		return []model.HostObservation{host}
	}
	base := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	save := func(id, jobID string, minute int, product string) {
		t.Helper()
		if err := s.System().SaveScan(ctx, fixtureScan(id, jobID, "edge", base.Add(time.Duration(minute)*time.Minute), observed(product))); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
	}
	latest := func() []string {
		t.Helper()
		return queryStrings(t, s.DB, `SELECT tenant_id || ' ' || address || ' ' || scan_id FROM latest_scan_hosts ORDER BY tenant_id,address`)
	}
	want := func(scanA, scanB string) []string {
		rows := []string{DefaultTenantID + " " + address + " " + scanA}
		if scanB != "" {
			rows = append(rows, secondTenantID+" "+address+" "+scanB)
		}
		return rows
	}
	assertSearch := func(product string, want []string) {
		t.Helper()
		got := queryStrings(t, s.DB, `SELECT h.tenant_id FROM latest_scan_hosts h JOIN latest_host_search hs ON hs.rowid=h.rowid WHERE latest_host_search MATCH ? ORDER BY h.tenant_id`, hostSearchMatchQuery(product))
		if !slices.Equal(got, want) {
			t.Fatalf("search %q = %v, want %v", product, got, want)
		}
	}

	save("a1", jobA.ID, 1, "nginx")
	save("b1", jobB, 2, "openssh")
	if got := latest(); !slices.Equal(got, want("a1", "b1")) {
		t.Fatalf("latest rows = %v", got)
	}
	assertSearch("nginx", []string{DefaultTenantID})
	assertSearch("openssh", []string{secondTenantID})
	// The host inventory shows the default tenant only.
	page, err := defaultTenant(s).ListLatestScanHostsPage(ctx, "", "", nil, 50, 0)
	if err != nil || page.Total != 1 || page.Items[0].ScanID != "a1" {
		t.Fatalf("host inventory = %#v, %v", page, err)
	}
	if page, err := defaultTenant(s).ListLatestScanHostsPage(ctx, "openssh", "", nil, 50, 0); err != nil || page.Total != 0 {
		t.Fatalf("host inventory search for the second tenant = %#v, %v", page, err)
	}

	// A newer scan replaces only its tenant's row; an older one changes
	// nothing.
	save("a2", jobA.ID, 3, "caddy")
	save("b0", jobB, 0, "telnet")
	if got := latest(); !slices.Equal(got, want("a2", "b1")) {
		t.Fatalf("latest rows after the upserts = %v", got)
	}
	assertSearch("caddy", []string{DefaultTenantID})
	assertSearch("nginx", nil)
	assertSearch("openssh", []string{secondTenantID})

	// The public status lookup reads each job's row under its tenant's
	// public scope, which resolves only its own job's selection.
	scopes := map[string]PublicScope{jobA.ID: DefaultPublicScope(), jobB: {tenant: TenantScope{id: secondTenantID}}}
	selections := []PublicDashboardHost{{JobID: jobA.ID, Address: address}, {JobID: jobB, Address: address}}
	publicLookup := func() ([]PublicDashboardHostResult, error) {
		t.Helper()
		var results []PublicDashboardHostResult
		for _, job := range []string{jobA.ID, jobB} {
			found, err := s.Public(scopes[job]).GetLatestSuccessfulJobHosts(ctx, selections)
			if err != nil {
				return nil, err
			}
			for _, result := range found {
				if result.Selection.JobID != job {
					t.Fatalf("tenant %s resolved job %s's selection", scopes[job].TenantID(), result.Selection.JobID)
				}
			}
			results = append(results, found...)
		}
		return results, nil
	}
	results, err := publicLookup()
	if err != nil || len(results) != 2 {
		t.Fatalf("public lookup = %#v, %v", results, err)
	}
	for _, result := range results {
		wantScan := map[string]string{jobA.ID: "a2", jobB: "b1"}[result.Selection.JobID]
		if result.Host.ScanID != wantScan || result.Summary.ID != wantScan {
			t.Fatalf("public lookup for %s = %s/%s, want %s", result.Selection.JobID, result.Host.ScanID, result.Summary.ID, wantScan)
		}
	}

	// Retention repairs the row of the tenant whose scan it removed.
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM scans WHERE id='a2'`); err != nil {
		t.Fatal(err)
	}
	if err := s.repairLatestScanHosts(ctx); err != nil {
		t.Fatal(err)
	}
	if got := latest(); !slices.Equal(got, want("a1", "b1")) {
		t.Fatalf("latest rows after the repair = %v", got)
	}
	assertSearch("nginx", []string{DefaultTenantID})
	if err := s.rebuildLatestScanHosts(ctx); err != nil {
		t.Fatal(err)
	}
	if got := latest(); !slices.Equal(got, want("a1", "b1")) {
		t.Fatalf("latest rows after the rebuild = %v", got)
	}
	assertSearch("openssh", []string{secondTenantID})

	// The projection answers the public lookup for both tenants without the
	// retained host history.
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM scan_hosts WHERE scan_id IN ('a1','b1')`); err != nil {
		t.Fatal(err)
	}
	results, err = publicLookup()
	if err != nil || len(results) != 2 {
		t.Fatalf("public lookup from the projection = %#v, %v", results, err)
	}
	if err := s.rebuildLatestScanHosts(ctx); err != nil {
		t.Fatal(err)
	}
	// Only the second tenant's older scan b0 still has retained hosts.
	if got := latest(); !slices.Equal(got, []string{secondTenantID + " " + address + " b0"}) {
		t.Fatalf("latest rows rebuilt from the remaining history = %v", got)
	}
	save("a3", jobA.ID, 4, "nginx")
	save("b2", jobB, 5, "openssh")

	// A tenant that is being deleted gets no rows back from retention.
	setTenantState(t, s, secondTenantID, "deleting")
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM scans WHERE id='b2'`); err != nil {
		t.Fatal(err)
	}
	if err := s.repairLatestScanHosts(ctx); err != nil {
		t.Fatalf("repair with a tenant that is being deleted: %v", err)
	}
	if got := latest(); !slices.Equal(got, want("a3", "")) {
		t.Fatalf("latest rows after repairing a deleted tenant's row = %v", got)
	}
	if err := s.rebuildLatestScanHosts(ctx); err != nil {
		t.Fatalf("rebuild with a tenant that is being deleted: %v", err)
	}
	if got := latest(); !slices.Equal(got, want("a3", "")) {
		t.Fatalf("latest rows rebuilt with a deleted tenant = %v", got)
	}

	// The guard triggers.
	stamp := sqliteTimestamp(time.Now())
	insert := func(tenant, scanID, address string) error {
		_, err := s.DB.Exec(`INSERT INTO latest_scan_hosts(tenant_id,address,scan_id,finished_at,host_json) VALUES(?,?,?,?,'{}')`, tenant, address, scanID, stamp)
		return err
	}
	const (
		scanTenant   = "latest_scan_hosts.tenant_id must be the tenant of the row's scan"
		activeTenant = "latest_scan_hosts.tenant_id must name an active or disabled tenant"
	)
	for _, tc := range []struct {
		name    string
		write   func() error
		wantErr string
	}{
		{name: "another tenant than the scan's", write: func() error { return insert(secondTenantID, "a3", "192.0.2.1") }, wantErr: scanTenant},
		{name: "an unknown scan", write: func() error { return insert(DefaultTenantID, "unknown-scan", "192.0.2.2") }, wantErr: scanTenant},
		{name: "no tenant", write: func() error {
			_, err := s.DB.Exec(`INSERT INTO latest_scan_hosts(address,scan_id,finished_at,host_json) VALUES('192.0.2.3','a3',?,'{}')`, stamp)
			return err
		}, wantErr: scanTenant},
		{name: "a tenant that is being deleted", write: func() error { return insert(secondTenantID, "b1", "192.0.2.4") }, wantErr: activeTenant},
		{name: "a scan of another tenant", write: func() error {
			_, err := s.DB.Exec(`UPDATE latest_scan_hosts SET scan_id='b1' WHERE tenant_id=?`, DefaultTenantID)
			return err
		}, wantErr: scanTenant},
		{name: "a moved row", write: func() error {
			_, err := s.DB.Exec(`UPDATE latest_scan_hosts SET tenant_id=? WHERE tenant_id=?`, secondTenantID, DefaultTenantID)
			return err
		}, wantErr: scanTenant},
		{name: "the scan's tenant", write: func() error { return insert(DefaultTenantID, "a3", "192.0.2.5") }},
	} {
		err := tc.write()
		if tc.wantErr == "" {
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: error = %v, want %q", tc.name, err, tc.wantErr)
		}
	}
	// A disabled tenant keeps its rows current.
	setTenantState(t, s, secondTenantID, "disabled")
	save("b3", jobB, 6, "openssh")
	if got := latest(); !slices.Contains(got, secondTenantID+" "+address+" b3") {
		t.Fatalf("latest rows of a disabled tenant = %v", got)
	}
	// An update that keeps the scan, such as the search text backfill, still
	// works on a row whose scan retention has removed.
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM scans WHERE id='a3'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE latest_scan_hosts SET search_text='repaired' WHERE scan_id='a3'`); err != nil {
		t.Fatalf("search text update of a dangling row: %v", err)
	}
}

// Reopening a current-schema database changes no row and no schema object.
func TestCurrentSchemaOpenIsANoOpWhenRepeated(t *testing.T) {
	t.Parallel()
	path := newSchema53Fixture(t)
	execFixtureStatements(t, path, schema54SwapStatements)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func(db *sql.DB) string {
		var out strings.Builder
		for _, query := range []string{
			`SELECT rowid,* FROM latest_scan_hosts ORDER BY rowid`,
			`SELECT rowid,address,content FROM latest_host_search ORDER BY rowid`,
			`SELECT * FROM fts_backfill_state ORDER BY table_name`,
			`SELECT type,name,tbl_name,COALESCE(sql,'') FROM sqlite_master ORDER BY type,name`,
		} {
			if err := snapshotRows(db, query, &out); err != nil {
				t.Fatal(err)
			}
		}
		return out.String()
	}
	before := snapshot(s.DB)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	repeated, err := Open(path)
	if err != nil {
		t.Fatalf("repeat open: %v", err)
	}
	defer repeated.Close()
	if after := snapshot(repeated.DB); after != before {
		t.Fatalf("repeating the open changed the database:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	assertForeignKeysClean(t, repeated.DB)
}

// The retention repair looks up the retained observations of each affected
// address through scan_hosts_address, not by reading every scan of the
// tenant, and deletes the affected rows by their primary key.
func TestLatestScanHostRepairFollowsTheAddressIndex(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	stamp := sqliteTimestamp(time.Now())
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for i := range 200 {
		scanID := fmt.Sprintf("history-%d", i)
		if _, err := tx.Exec(`INSERT INTO scans(id,job,started_at,finished_at,status,config_hash,snapshot_json) VALUES(?,'edge',?,?,'success','hash','{}')`, scanID, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO scan_hosts(scan_id,address,job,host_json) VALUES(?,?,'edge','{}')`, scanID, fixtureHost(i%50).Address); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	deleteSQL, insertSQL, args := latestScanHostRepairQueries([]latestScanHostKey{{DefaultTenantID, fixtureHost(1).Address}, {DefaultTenantID, fixtureHost(2).Address}})
	if plan := queryPlan(t, s.DB, insertSQL, args...); !strings.Contains(plan, "SEARCH h USING INDEX scan_hosts_address (address=?)") || strings.Contains(plan, "SCAN s") || !strings.Contains(plan, "SEARCH s USING COVERING INDEX "+scansIdentityIndex) {
		t.Fatalf("repair insert plan = %q", plan)
	}
	if plan := queryPlan(t, s.DB, deleteSQL, args...); !strings.Contains(plan, "sqlite_autoindex_latest_scan_hosts_1 (tenant_id=? AND address=?)") {
		t.Fatalf("repair delete plan = %q", plan)
	}
}

// benchmarkRekeyHosts is the size of the projection that
// BenchmarkMigration54Rekey copies.
const benchmarkRekeyHosts = 100_000

// BenchmarkMigration54Rekey times the schema 54 table swap and the complete
// startup copy of a schema 53 projection with benchmarkRekeyHosts rows, each
// indexed in latest_host_search. Building the fixture takes longer than the
// copy, so run it once:
//
//	go test ./internal/store -run '^$' -bench Migration54Rekey -benchtime 1x
func BenchmarkMigration54Rekey(b *testing.B) {
	ctx := context.Background()
	for range b.N {
		b.StopTimer()
		path := newRekeyBenchmarkFixture(b)
		s, err := OpenExisting(path)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		started := time.Now()
		for _, statement := range schema54SwapStatements {
			if _, err := s.DB.Exec(statement); err != nil {
				b.Fatal(err)
			}
		}
		if err := rekeyLatestScanHostsByTenantContext(ctx, s.DB, nil); err != nil {
			b.Fatal(err)
		}
		elapsed := time.Since(started)
		b.StopTimer()
		var rows int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM latest_scan_hosts`).Scan(&rows); err != nil || rows != benchmarkRekeyHosts {
			b.Fatalf("copied rows = %d, %v", rows, err)
		}
		var pages, pageSize int64
		if err := s.DB.QueryRow(`SELECT page_count,page_size FROM pragma_page_count, pragma_page_size`).Scan(&pages, &pageSize); err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(benchmarkRekeyHosts)/elapsed.Seconds(), "rows/s")
		b.ReportMetric(float64(pages*pageSize)/(1<<20), "MiB")
		if err := s.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

// newRekeyBenchmarkFixture writes a schema 53 database whose projection
// holds benchmarkRekeyHosts rows that name 1,000 scans.
func newRekeyBenchmarkFixture(b *testing.B) string {
	b.Helper()
	path := filepath.Join(b.TempDir(), "rekey.db")
	fixture, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	if err := fixture.Close(); err != nil {
		b.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		b.Fatal(err)
	}
	defer raw.Close()
	tx, err := raw.Begin()
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, statement := range schema53FixtureStatements {
		if _, err := tx.Exec(statement); err != nil {
			b.Fatal(err)
		}
	}
	stamp := sqliteTimestamp(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
	for i := range 1000 {
		if _, err := tx.Exec(`INSERT INTO scans(id,job,started_at,finished_at,status,config_hash,snapshot_json) VALUES(?,'edge',?,?,'success','hash','{}')`, fmt.Sprintf("scan-%d", i), stamp, stamp); err != nil {
			b.Fatal(err)
		}
	}
	insert, err := tx.Prepare(`INSERT INTO latest_scan_hosts(address,scan_id,job_id,job,finished_at,address_family,source_targets_json,dns_names_json,host_json,search_text,open_ports,tcp_present,tcp_open_ports) VALUES(?,?,'','edge',?,'IPv4',?,?,?,?,1,1,1)`)
	if err != nil {
		b.Fatal(err)
	}
	defer insert.Close()
	for i := range benchmarkRekeyHosts {
		host := fixtureHost(i)
		host.Address = fmt.Sprintf("10.%d.%d.%d", i/65536, i/256%256, i%256)
		hostJSON, err := json.Marshal(host)
		if err != nil {
			b.Fatal(err)
		}
		targets, _ := json.Marshal(host.SourceTargets)
		names, _ := json.Marshal(host.DNSNames)
		if _, err := insert.Exec(host.Address, fmt.Sprintf("scan-%d", i%1000), stamp, targets, names, hostJSON, hostSearchContent("edge", host)); err != nil {
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	return path
}
