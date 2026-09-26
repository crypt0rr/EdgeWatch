package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// schema53Triggers are the guard triggers that schema 53 adds.
var schema53Triggers = []string{
	scansTenantInsertTrigger,
	scansTenantImmutableTrigger,
	eventsTenantInsertTrigger,
	eventsTenantImmutableTrigger,
	publicDashboardHostsTenantInsertTrigger,
	publicDashboardHostsTenantUpdateTrigger,
	publicDashboardsTenantImmutableTrigger,
	jobsTenantImmutableTrigger,
}

// schema53Tables are the tables that gain tenant_id in schema 53.
var schema53Tables = []string{"scans", "events", "outbox", "restore_quarantined_deliveries"}

// schema52FixtureStatements turn a current database into the schema-52
// shape. They first undo schema 54, see schema53FixtureStatements. Then the
// guard triggers, the tenant indexes and the tenant_id columns of schema 53
// are removed.
var schema52FixtureStatements = func() []string {
	statements := slices.Clone(schema53FixtureStatements)
	for _, trigger := range schema53Triggers {
		statements = append(statements, "DROP TRIGGER "+trigger)
	}
	statements = append(statements, "DROP INDEX scans_tenant_id_time", "DROP INDEX events_tenant_id_time")
	for _, table := range schema53Tables {
		statements = append(statements, "ALTER TABLE "+table+" DROP COLUMN tenant_id")
	}
	return append(statements, "PRAGMA user_version=52")
}()

const defaultTenantLiteral = "'" + DefaultTenantID + "'"

// largeSnapshotHosts is the number of hosts in a largeSnapshotScan.
const largeSnapshotHosts = 48

// largeSnapshotScan is a successful scan whose snapshot is large enough to
// spill into overflow pages.
func largeSnapshotScan(id, jobID, job string, finished time.Time) model.Scan {
	hosts := make([]model.HostObservation, 0, largeSnapshotHosts)
	for i := range largeSnapshotHosts {
		hosts = append(hosts, model.HostObservation{
			Address:       fmt.Sprintf("192.0.2.%d", 10+i),
			AddressFamily: "IPv4",
			SourceTargets: []string{job + ".example"},
			DNSNames:      []string{strings.Repeat(fmt.Sprintf("host-%02d-", i), 60) + ".example"},
		})
	}
	return model.Scan{
		ID: id, JobID: jobID, Job: job, StartedAt: finished.Add(-time.Minute), FinishedAt: finished,
		Status: "success", ConfigHash: "config-" + job, Snapshot: model.Snapshot{Hosts: hosts},
		Changes: []model.Change{{Key: "change-" + id, Kind: "port-opened", Target: job, New: strings.Repeat("d", 512)}},
	}
}

// fixtureScansPerJob is the number of large scans of each fixture job.
const fixtureScansPerJob = 6

type schema52Fixture struct {
	path   string
	jobIDs []string
}

// newSchema52Fixture writes a populated database with the current code and
// rewrites it into the schema-52 shape. It has scans of two jobs, a legacy
// scan without a job ID stored as NULL and one stored as an empty string;
// job, legacy and platform events; the deliveries queued for them;
// quarantined deliveries; and published hosts of both jobs.
func newSchema52Fixture(t *testing.T) schema52Fixture {
	t.Helper()
	ctx := context.Background()
	fixture := schema52Fixture{path: filepath.Join(t.TempDir(), "schema52.db")}
	s, err := Open(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := s.DB.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	for i, name := range []string{"edge-a", "edge-b"} {
		job, err := s.CreateJob(ctx, testJob(name))
		if err != nil {
			t.Fatal(err)
		}
		fixture.jobIDs = append(fixture.jobIDs, job.ID)
		for j := range fixtureScansPerJob {
			if err := s.SaveScan(ctx, largeSnapshotScan(fmt.Sprintf("scan-%s-%d", name, j), job.ID, name, now.Add(time.Duration(10*i+j)*time.Minute))); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.ResetRuntimeWithOutbox(ctx, job.ID, name, []string{"deployment-alerts"}); err != nil {
			t.Fatal(err)
		}
	}
	// A config.yaml job has no job ID: SaveScan stores NULL, and older
	// releases stored an empty string.
	if err := s.SaveScan(ctx, largeSnapshotScan("scan-legacy-null", "", "legacy", now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO scans(id,job_id,job,started_at,finished_at,status,config_hash,snapshot_json) VALUES('scan-legacy-empty','','legacy',?,?,'failed','config-legacy','{}')`, sqliteTimestamp(now), sqliteTimestamp(now.Add(2*time.Hour)))
	if _, err := s.UpdateState(ctx, "legacy", func(*model.JobState) ([]model.Event, error) {
		return []model.Event{{Type: "change", Job: "legacy", Message: "legacy change", CreatedAt: now}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueEvent(ctx, "deployment-legacy", model.Event{Type: "change", Job: "legacy", Message: "legacy change", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordReleaseCheck(ctx, "1.0.0", "1.1.0", "https://example.invalid/releases/1.1.0", "EdgeWatch 1.1.0", "", "etag", true, []string{"deployment-alerts"}); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO restore_quarantined_deliveries(restore_epoch,destination,payload_json,next_at,quarantined_at,tenant_id) VALUES('epoch-1','deployment-alerts','{"type":"job"}',?,?,?)`, sqliteTimestamp(now), sqliteTimestamp(now), DefaultTenantID)
	exec(`INSERT INTO restore_quarantined_deliveries(restore_epoch,destination,payload_json,next_at,quarantined_at,tenant_id) VALUES('epoch-1','deployment-alerts','{"type":"platform"}',?,?,NULL)`, sqliteTimestamp(now), sqliteTimestamp(now))
	if err := s.SavePublicDashboard(ctx, PublicDashboard{Enabled: true, Title: "Perimeter"}, []PublicDashboardHost{
		{JobID: fixture.jobIDs[0], Address: "192.0.2.10"},
		{JobID: fixture.jobIDs[1], Address: "192.0.2.11"},
	}, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	execFixtureStatements(t, fixture.path, schema52FixtureStatements)

	raw, err := sql.Open("sqlite", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, table := range schema53Tables {
		if got := countRows(t, raw, `SELECT COUNT(*) FROM pragma_table_info(?) WHERE name='tenant_id'`, table); got != 0 {
			t.Fatalf("schema 52 fixture %s still has tenant_id", table)
		}
		if got := countRows(t, raw, `SELECT COUNT(*) FROM `+table); got < 2 {
			t.Fatalf("schema 52 fixture has %d %s rows", got, table)
		}
	}
	if got := countRows(t, raw, `SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name IN ('`+strings.Join(schema53Triggers, "','")+`')`); got != 0 {
		t.Fatalf("schema 52 fixture still has %d schema 53 triggers", got)
	}
	return fixture
}

// columnSnapshot renders the rows of table with the given columns, each with
// its rowid.
func columnSnapshot(t *testing.T, db *sql.DB, table string, columns []string) string {
	t.Helper()
	var out strings.Builder
	query := `SELECT rowid,"` + strings.Join(columns, `","`) + `" FROM ` + table + ` ORDER BY rowid`
	if err := snapshotRows(db, query, &out); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return out.String()
}

// queryStrings returns the first column of every row of query, with NULL
// as "<null>".
func queryStrings(t *testing.T, db *sql.DB, query string, args ...any) []string {
	t.Helper()
	rows, err := db.Query(query, args...)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value sql.NullString
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		if !value.Valid {
			value.String = "<null>"
		}
		values = append(values, value.String)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return values
}

func columnNames(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	return queryStrings(t, db, `SELECT name FROM pragma_table_info(?) ORDER BY cid`, table)
}

// tablePages returns the bytes of every page of the given tables' b-trees,
// including their overflow pages, keyed by page number.
func tablePages(t *testing.T, path string, tables ...string) map[int64][]byte {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	var pageSize int64
	if err := raw.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pages := map[int64][]byte{}
	for _, table := range tables {
		for _, number := range queryStrings(t, raw, `SELECT pageno FROM dbstat WHERE name=?`, table) {
			page, err := strconv.ParseInt(number, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			pages[page] = contents[(page-1)*pageSize : page*pageSize]
		}
	}
	return pages
}

// indexKeys lists the key columns of index with their sort order.
func indexKeys(t *testing.T, db *sql.DB, index string) string {
	t.Helper()
	var keys sql.NullString
	if err := db.QueryRow(`SELECT group_concat(k,',') FROM (SELECT name || CASE WHEN "desc" THEN ' DESC' ELSE '' END AS k FROM pragma_index_xinfo(?) WHERE key=1 ORDER BY seqno)`, index).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	return keys.String
}

// queryPlan returns the EXPLAIN QUERY PLAN details of query.
func queryPlan(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	rows, err := db.Query(`EXPLAIN QUERY PLAN `+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(details, "; ")
}

func TestMigration53AttributesHistoryToTheDefaultTenant(t *testing.T) {
	ctx := context.Background()
	fixture := newSchema52Fixture(t)
	tables := append(slices.Clone(schema53Tables), "public_dashboard_hosts")
	raw, err := sql.Open("sqlite", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	columnsBefore := map[string][]string{}
	rowsBefore := map[string]string{}
	for _, table := range tables {
		columnsBefore[table] = columnNames(t, raw, table)
		rowsBefore[table] = columnSnapshot(t, raw, table, columnsBefore[table])
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	pagesBefore := tablePages(t, fixture.path, "scans", "events")

	s, err := Open(fixture.path)
	if err != nil {
		t.Fatalf("upgrade from schema 52: %v", err)
	}
	open := true
	defer func() {
		if open {
			s.Close()
		}
	}()
	if version := countRows(t, s.DB, `PRAGMA user_version`); version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}

	// Every row keeps its rowid and values, and gains the default tenant.
	wantTenantColumn := map[string]string{
		"scans":                          "tenant_id TEXT notnull=1 default=" + defaultTenantLiteral + " pk=0",
		"events":                         "tenant_id TEXT notnull=0 default=" + defaultTenantLiteral + " pk=0",
		"outbox":                         "tenant_id TEXT notnull=0 default=" + defaultTenantLiteral + " pk=0",
		"restore_quarantined_deliveries": "tenant_id TEXT notnull=0 default=" + defaultTenantLiteral + " pk=0",
	}
	for _, table := range tables {
		if after := columnSnapshot(t, s.DB, table, columnsBefore[table]); after != rowsBefore[table] {
			t.Fatalf("%s rows changed:\nbefore:\n%s\nafter:\n%s", table, rowsBefore[table], after)
		}
		want, gainsTenant := wantTenantColumn[table]
		columns := tableColumns(t, s.DB, table)
		if !gainsTenant {
			if len(columns) != len(columnsBefore[table]) {
				t.Fatalf("%s columns = %v, want them unchanged", table, columns)
			}
			continue
		}
		if len(columns) != len(columnsBefore[table])+1 || columns[len(columns)-1] != want {
			t.Fatalf("%s columns = %v, want %q appended", table, columns, want)
		}
		if got := countRows(t, s.DB, `SELECT COUNT(*) FROM `+table+` WHERE tenant_id IS NOT `+defaultTenantLiteral); got != 0 {
			t.Fatalf("%s rows outside the default tenant = %d", table, got)
		}
	}
	// The table pages, including the overflow pages of the snapshots and
	// payloads, are not rewritten. The database uses auto-vacuum, where a new
	// index takes the lowest free page number for its root page: SQLite moves
	// the page that holds that number, unchanged, and updates the one pointer
	// to it. So each of the two new indexes, and each of the five b-trees of
	// the tenant-keyed latest host projection that the upgrade to schema 54
	// creates next, can change two pages, while rewriting the rows would
	// change nearly every page.
	open = false
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	pagesAfter := tablePages(t, fixture.path, "scans", "events")
	if len(pagesAfter) != len(pagesBefore) {
		t.Fatalf("scans and events pages = %d, want %d", len(pagesAfter), len(pagesBefore))
	}
	var changed []int64
	for page, contents := range pagesBefore {
		if !bytes.Equal(pagesAfter[page], contents) {
			changed = append(changed, page)
		}
	}
	if len(pagesBefore) < 50 || len(changed) > 2*(2+5) {
		t.Fatalf("%d of %d scans and events pages changed: %v", len(changed), len(pagesBefore), changed)
	}
	s, err = Open(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	open = true

	for index, want := range map[string]string{
		"scans_tenant_id_time":  "tenant_id,finished_at DESC,id DESC",
		"events_tenant_id_time": "tenant_id,created_at DESC,id DESC",
	} {
		if got := indexKeys(t, s.DB, index); got != want {
			t.Fatalf("%s keys = %q, want %q", index, got, want)
		}
	}
	for _, trigger := range schema53Triggers {
		if got := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=?`, trigger); got != 1 {
			t.Fatalf("trigger %s is missing", trigger)
		}
	}
	// A tenant-filtered history list is served in order by the tenant
	// index, without sorting the history.
	for _, check := range []struct {
		query string
		index string
	}{
		{`SELECT id,job_id,job,started_at,finished_at,status FROM scans WHERE tenant_id=? ORDER BY finished_at DESC,id DESC LIMIT ? OFFSET ?`, "scans_tenant_id_time"},
		{`SELECT COUNT(*) FROM scans WHERE tenant_id=?`, "scans_tenant_id_time"},
		{`SELECT payload_json FROM events WHERE tenant_id=? ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, "events_tenant_id_time"},
	} {
		args := []any{DefaultTenantID, 50, 0}[:strings.Count(check.query, "?")]
		plan := queryPlan(t, s.DB, check.query, args...)
		if !strings.Contains(plan, check.index) || strings.Contains(plan, "TEMP B-TREE") {
			t.Fatalf("plan of %s = %q, want %s without a sort", check.query, plan, check.index)
		}
	}
	var integrity string
	if err := s.DB.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("integrity_check = %q, %v", integrity, err)
	}
	assertForeignKeysClean(t, s.DB)

	// The store reads the migrated rows as before.
	scans, err := s.ListScanSummariesPage(ctx, "", 50, 0)
	if err != nil || scans.Total != 2*fixtureScansPerJob+2 {
		t.Fatalf("scan history = %d, %v; want %d", scans.Total, err, 2*fixtureScansPerJob+2)
	}
	events, err := s.ListEventsPage(ctx, "", 50, 0)
	if err != nil || events.Total != 4 {
		t.Fatalf("event history = %d, %v; want 4", events.Total, err)
	}
	dashboard, err := s.GetPublicDashboard(ctx)
	if err != nil || len(dashboard.Hosts) != 2 {
		t.Fatalf("public dashboard = %#v, %v", dashboard, err)
	}
	scan, err := s.GetScan(ctx, "scan-edge-a-0")
	if err != nil || len(scan.Snapshot.Hosts) != largeSnapshotHosts || len(scan.Changes) != 1 {
		t.Fatalf("scan after the upgrade = %d hosts, %d changes, %v", len(scan.Snapshot.Hosts), len(scan.Changes), err)
	}
}

// Some recovery databases carry a schema marker without every table. The
// migration creates the tables it changes and the tables its triggers read,
// and the writers work on the result.
func TestMigration53UpgradesRecoveryDatabasesWithMissingTables(t *testing.T) {
	all := []string{"scans", "events", "outbox", "restore_quarantined_deliveries", "public_dashboard_hosts", "public_dashboards", "jobs", "tenants"}
	cases := []struct {
		name    string
		missing []string
	}{{name: "all", missing: all}}
	for _, table := range all {
		cases = append(cases, struct {
			name    string
			missing []string
		}{name: table, missing: []string{table}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fixture := newSchema52Fixture(t)
			extra := make([]string, 0, len(tc.missing))
			for _, table := range tc.missing {
				extra = append(extra, "DROP TABLE "+table)
			}
			execFixtureStatements(t, fixture.path, extra)

			s, err := Open(fixture.path)
			if err != nil {
				t.Fatalf("upgrade without %v: %v", tc.missing, err)
			}
			defer s.Close()
			if version := countRows(t, s.DB, `PRAGMA user_version`); version != schemaVersion {
				t.Fatalf("schema version = %d, want %d", version, schemaVersion)
			}
			if got := countRows(t, s.DB, `SELECT COUNT(*) FROM tenants WHERE id=? AND is_default=1`, DefaultTenantID); got != 1 {
				t.Fatalf("default tenant rows = %d", got)
			}
			for _, table := range schema53Tables {
				if got := countRows(t, s.DB, `SELECT COUNT(*) FROM pragma_table_info(?) WHERE name='tenant_id'`, table); got != 1 {
					t.Fatalf("%s has no tenant_id", table)
				}
			}
			for _, trigger := range schema53Triggers {
				if got := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=?`, trigger); got != 1 {
					t.Fatalf("trigger %s is missing", trigger)
				}
			}

			job, err := s.CreateJob(ctx, testJob("recovered"))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.SaveScan(ctx, largeSnapshotScan("scan-recovered", job.ID, "recovered", time.Now().UTC())); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ResetRuntimeWithOutbox(ctx, job.ID, "recovered", []string{"deployment-recovered"}); err != nil {
				t.Fatal(err)
			}
			if err := s.SavePublicDashboard(ctx, PublicDashboard{Enabled: true}, []PublicDashboardHost{{JobID: job.ID, Address: "192.0.2.10"}}, AuditEntry{}); err != nil {
				t.Fatal(err)
			}
			for query, want := range map[string]int{
				`SELECT COUNT(*) FROM scans WHERE id='scan-recovered' AND tenant_id=` + defaultTenantLiteral:                                1,
				`SELECT COUNT(*) FROM events WHERE type='baseline-reset' AND job_id='` + job.ID + `' AND tenant_id=` + defaultTenantLiteral: 1,
				`SELECT COUNT(*) FROM outbox WHERE destination='deployment-recovered' AND tenant_id=` + defaultTenantLiteral:                1,
				`SELECT COUNT(*) FROM public_dashboard_hosts WHERE job_id='` + job.ID + `'`:                                                 1,
			} {
				if got := countRows(t, s.DB, query); got != want {
					t.Fatalf("%s = %d, want %d", query, got, want)
				}
			}
		})
	}
}

// Running the migration again, after the schema marker was reset, changes
// no row and no schema object.
func TestMigration53IsANoOpWhenRepeated(t *testing.T) {
	fixture := newSchema52Fixture(t)
	s, err := Open(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func(db *sql.DB) string {
		var out strings.Builder
		for _, table := range append(slices.Clone(schema53Tables), "public_dashboard_hosts", "public_dashboards", "jobs", "tenants") {
			if err := snapshotRows(db, `SELECT rowid,* FROM `+table+` ORDER BY rowid`, &out); err != nil {
				t.Fatal(err)
			}
		}
		if err := snapshotRows(db, `SELECT type,name,tbl_name,COALESCE(sql,'') FROM sqlite_master ORDER BY type,name`, &out); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	before := snapshot(s.DB)
	if _, err := s.DB.Exec(`PRAGMA user_version=52`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	repeated, err := Open(fixture.path)
	if err != nil {
		t.Fatalf("repeat migration 53: %v", err)
	}
	defer repeated.Close()
	if after := snapshot(repeated.DB); after != before {
		t.Fatalf("repeating migration 53 changed the database:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	assertForeignKeysClean(t, repeated.DB)
}

// insertJobRows creates bare default-tenant jobs rows for fixtures that save
// scans of made-up job IDs. From schema 53 a scan with a job ID must belong
// to the tenant of an existing job.
func insertJobRows(t *testing.T, s *Store, ids ...string) {
	t.Helper()
	stamp := sqliteTimestamp(time.Now())
	for _, id := range ids {
		if _, err := s.DB.Exec(`INSERT INTO jobs(id,tenant_id,name,definition_json,created_at,updated_at) VALUES(?,?,?,'{}',?,?)`, id, DefaultTenantID, id, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
}

// insertSecondTenantJob copies the job source into the second tenant under
// the same name, with its revisions and silence state, because no product
// API creates a job in another tenant yet.
func insertSecondTenantJob(t *testing.T, s *Store, source, id string) {
	t.Helper()
	for _, statement := range []string{
		`INSERT INTO jobs(id,tenant_id,name,definition_json,enabled,archived,revision,created_at,updated_at) SELECT ?1,'` + secondTenantID + `',name,definition_json,enabled,archived,revision,created_at,updated_at FROM jobs WHERE id=?2`,
		`INSERT INTO job_revisions(job_id,revision,definition_json,security_hash,created_at) SELECT ?1,revision,definition_json,security_hash,created_at FROM job_revisions WHERE job_id=?2`,
		`INSERT INTO job_silence_state(job_id,eligible_at,updated_at) SELECT ?1,eligible_at,updated_at FROM job_silence_state WHERE job_id=?2`,
	} {
		if _, err := s.DB.Exec(statement, id, source); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

func setTenantState(t *testing.T, s *Store, tenant, state string) {
	t.Helper()
	if _, err := s.DB.Exec(`UPDATE tenants SET state=? WHERE id=?`, state, tenant); err != nil {
		t.Fatal(err)
	}
}

// The guard triggers refuse a row whose tenant does not follow its job or
// dashboard, a tenant that is being deleted, and a changed tenant.
func TestSchema53GuardTriggers(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	insertSecondTenant(t, s)
	jobA, err := s.CreateJob(ctx, testJob("edge"))
	if err != nil {
		t.Fatal(err)
	}
	const jobB = "00000000-0000-0000-0000-000000000b01"
	insertSecondTenantJob(t, s, jobA.ID, jobB)
	stamp := sqliteTimestamp(time.Now())
	var tenantNone any
	sequence := 0
	scan := func(jobID any, tenant ...any) func() error {
		return func() error {
			sequence++
			columns, values := "id,job_id,job,started_at,finished_at,status,config_hash,snapshot_json", "?,?,'edge',?,?,'success','hash','{}'"
			args := []any{fmt.Sprintf("guard-scan-%d", sequence), jobID, stamp, stamp}
			if len(tenant) == 1 {
				columns, values, args = columns+",tenant_id", values+",?", append(args, tenant[0])
			}
			_, err := s.DB.Exec(`INSERT INTO scans(`+columns+`) VALUES(`+values+`)`, args...)
			return err
		}
	}
	event := func(jobID any, tenant ...any) func() error {
		return func() error {
			columns, values := "type,job,job_id,payload_json,created_at", "'guard','edge',?,'{}',?"
			args := []any{jobID, stamp}
			if len(tenant) == 1 {
				columns, values, args = columns+",tenant_id", values+",?", append(args, tenant[0])
			}
			_, err := s.DB.Exec(`INSERT INTO events(`+columns+`) VALUES(`+values+`)`, args...)
			return err
		}
	}
	const (
		scanJob      = "scans.tenant_id must be the tenant of the scan's job"
		scanState    = "scans.tenant_id must name an active or disabled tenant"
		eventJob     = "events.tenant_id must be the tenant of the event's job"
		eventState   = "events.tenant_id must name an active or disabled tenant"
		hostTenant   = "a public dashboard host must belong to a job of the dashboard's tenant"
		unknownJob   = "00000000-0000-0000-0000-00000000dead"
		unknownOwner = "00000000-0000-0000-0000-000000000999"
	)
	type guardCase struct {
		name    string
		write   func() error
		wantErr string
	}
	run := func(label string, cases []guardCase) {
		t.Helper()
		for _, tc := range cases {
			err := tc.write()
			if tc.wantErr == "" && err != nil {
				t.Errorf("%s: %s: %v, want success", label, tc.name, err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("%s: %s: %v, want %q", label, tc.name, err, tc.wantErr)
			}
		}
	}

	run("active tenants", []guardCase{
		{"scan in its job's tenant", scan(jobA.ID, DefaultTenantID), ""},
		{"scan of a default-tenant job by the column default", scan(jobA.ID), ""},
		{"scan of a second-tenant job", scan(jobB, secondTenantID), ""},
		{"scan in another tenant than its job", scan(jobA.ID, secondTenantID), scanJob},
		// The column default is the default tenant, and the trigger refuses
		// it for a job of another tenant.
		{"scan of a second-tenant job by the column default", scan(jobB), scanJob},
		{"scan without a tenant", scan(jobA.ID, tenantNone), scanJob},
		{"scan of an unknown job", scan(unknownJob, DefaultTenantID), scanJob},
		{"legacy scan with a NULL job ID", scan(tenantNone), ""},
		{"legacy scan with an empty job ID", scan("", DefaultTenantID), ""},
		{"legacy scan in the second tenant", scan("", secondTenantID), scanJob},
		{"legacy scan in an unknown tenant", scan("", unknownOwner), scanJob},

		{"event in its job's tenant", event(jobA.ID, DefaultTenantID), ""},
		{"event of a default-tenant job by the column default", event(jobA.ID), ""},
		{"event of a second-tenant job", event(jobB, secondTenantID), ""},
		{"event in another tenant than its job", event(jobA.ID, secondTenantID), eventJob},
		{"event of a second-tenant job by the column default", event(jobB), eventJob},
		{"job event without a tenant", event(jobA.ID, tenantNone), eventJob},
		{"event of an unknown job", event(unknownJob, DefaultTenantID), eventJob},
		{"platform event", event("", tenantNone), ""},
		{"platform event with a NULL job ID", event(tenantNone, tenantNone), ""},
		{"event without a job in the second tenant", event("", secondTenantID), ""},
		{"event without a job in an unknown tenant", event("", unknownOwner), eventState},
	})

	// A disabled tenant keeps its history growing; a tenant that is being
	// deleted, or is deleted, takes no new rows.
	for _, tc := range []struct {
		state   string
		allowed bool
	}{{"disabled", true}, {"deleting", false}, {"deleted", false}} {
		setTenantState(t, s, secondTenantID, tc.state)
		scanErr, eventErr := scanState, eventState
		if tc.allowed {
			scanErr, eventErr = "", ""
		}
		run("second tenant "+tc.state, []guardCase{
			{"scan", scan(jobB, secondTenantID), scanErr},
			{"job event", event(jobB, secondTenantID), eventErr},
			{"event without a job", event("", secondTenantID), eventErr},
			{"platform event", event("", tenantNone), ""},
			{"default tenant scan", scan(jobA.ID, DefaultTenantID), ""},
		})
	}
	setTenantState(t, s, secondTenantID, "active")

	// The tenant of a history row, a job and a dashboard cannot change,
	// even to the same value. Other columns stay writable.
	if err := s.SavePublicDashboard(ctx, PublicDashboard{}, nil, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		statement string
		wantErr   string
	}{
		{`UPDATE scans SET tenant_id=tenant_id WHERE job_id='` + jobA.ID + `'`, "scans.tenant_id cannot be changed"},
		{`UPDATE scans SET tenant_id='` + secondTenantID + `' WHERE job_id='` + jobA.ID + `'`, "scans.tenant_id cannot be changed"},
		{`UPDATE events SET tenant_id=NULL WHERE job_id='` + jobA.ID + `'`, "events.tenant_id cannot be changed"},
		{`UPDATE jobs SET tenant_id='` + secondTenantID + `' WHERE id='` + jobA.ID + `'`, "jobs.tenant_id cannot be changed"},
		{`UPDATE public_dashboards SET tenant_id='` + secondTenantID + `'`, "public_dashboards.tenant_id cannot be changed"},
		{`UPDATE scans SET status='failed' WHERE job_id='` + jobA.ID + `'`, ""},
		{`UPDATE events SET created_at=created_at WHERE job_id='` + jobA.ID + `'`, ""},
		{`UPDATE jobs SET name='renamed' WHERE id='` + jobA.ID + `'`, ""},
	} {
		_, err := s.DB.Exec(tc.statement)
		if tc.wantErr == "" && err != nil {
			t.Errorf("%s: %v", tc.statement, err)
		}
		if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%s: %v, want %q", tc.statement, err, tc.wantErr)
		}
	}

	// A published host belongs to a job of the dashboard's tenant.
	var defaultDashboard int64
	if err := s.DB.QueryRow(`SELECT id FROM public_dashboards WHERE tenant_id=?`, DefaultTenantID).Scan(&defaultDashboard); err != nil {
		t.Fatal(err)
	}
	var secondDashboard int64
	if err := s.DB.QueryRow(`INSERT INTO public_dashboards(tenant_id,updated_at) VALUES(?,?) RETURNING id`, secondTenantID, stamp).Scan(&secondDashboard); err != nil {
		t.Fatal(err)
	}
	host := func(dashboard int64, jobID, address string) func() error {
		return func() error {
			_, err := s.DB.Exec(`INSERT INTO public_dashboard_hosts(dashboard_id,job_id,address,created_at) VALUES(?,?,?,?)`, dashboard, jobID, address, stamp)
			return err
		}
	}
	update := func(statement string) func() error {
		return func() error {
			_, err := s.DB.Exec(statement)
			return err
		}
	}
	run("public dashboard hosts", []guardCase{
		{"host of a job in the dashboard's tenant", host(defaultDashboard, jobA.ID, "192.0.2.10"), ""},
		{"host of a second-tenant job in the second dashboard", host(secondDashboard, jobB, "192.0.2.10"), ""},
		{"host of a second-tenant job", host(defaultDashboard, jobB, "192.0.2.11"), hostTenant},
		{"host of a default-tenant job in the second dashboard", host(secondDashboard, jobA.ID, "192.0.2.11"), hostTenant},
		{"host of an unknown dashboard", host(999, jobA.ID, "192.0.2.12"), hostTenant},
		{"move a host to a job of another tenant", update(`UPDATE public_dashboard_hosts SET job_id='` + jobB + `' WHERE job_id='` + jobA.ID + `'`), hostTenant},
		{"move a host to the dashboard of another tenant", update(fmt.Sprintf(`UPDATE public_dashboard_hosts SET dashboard_id=%d WHERE job_id='%s'`, secondDashboard, jobA.ID)), hostTenant},
		{"change the address of a host", update(`UPDATE public_dashboard_hosts SET address='192.0.2.20' WHERE job_id='` + jobA.ID + `'`), ""},
	})
	if err := s.SavePublicDashboard(ctx, PublicDashboard{Enabled: true}, []PublicDashboardHost{{JobID: jobB, Address: "192.0.2.10"}}, AuditEntry{}); err == nil || !strings.Contains(err.Error(), hostTenant) {
		t.Fatalf("publish a host of another tenant's job = %v, want %q", err, hostTenant)
	}
}

// tenantOf returns the tenant_id of the one row that query selects, or
// "<null>".
func tenantOf(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	tenants := queryStrings(t, db, query, args...)
	if len(tenants) != 1 {
		t.Fatalf("%s selects %d rows %v, want one", query, len(tenants), tenants)
	}
	return tenants[0]
}

// Every writer of scans, events and outbox names the tenant, derived from
// the job, or none for a platform event, in the write transaction.
func TestSchema53WritersAttributeTheirTenant(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	insertSecondTenant(t, s)
	jobA, err := s.CreateJob(ctx, testJob("edge"))
	if err != nil {
		t.Fatal(err)
	}
	const jobB = "00000000-0000-0000-0000-000000000b01"
	insertSecondTenantJob(t, s, jobA.ID, jobB)
	now := time.Now().UTC()
	const platform = "<null>"

	// Scans follow their job; a legacy scan without a job ID belongs to the
	// default tenant; a scan of an unknown job is refused.
	for id, jobID := range map[string]string{"scan-a": jobA.ID, "scan-b": jobB, "scan-legacy": ""} {
		if err := s.SaveScan(ctx, largeSnapshotScan(id, jobID, "edge", now)); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
	}
	if err := s.SaveScan(ctx, largeSnapshotScan("scan-unknown", "00000000-0000-0000-0000-00000000dead", "edge", now)); err == nil || !strings.Contains(err.Error(), "scans.tenant_id must be the tenant of the scan's job") {
		t.Fatalf("save a scan of an unknown job = %v", err)
	}
	for id, want := range map[string]string{"scan-a": DefaultTenantID, "scan-b": secondTenantID, "scan-legacy": DefaultTenantID} {
		if got := tenantOf(t, s.DB, `SELECT tenant_id FROM scans WHERE id=?`, id); got != want {
			t.Fatalf("%s tenant = %s, want %s", id, got, want)
		}
	}

	// Runtime, silence and job events, with the deliveries queued for them.
	for jobID, want := range map[string]string{jobA.ID: DefaultTenantID, jobB: secondTenantID} {
		destination := "reset-" + want
		if _, err := s.ResetRuntimeWithOutbox(ctx, jobID, "edge", []string{destination}); err != nil {
			t.Fatal(err)
		}
		if got := tenantOf(t, s.DB, `SELECT tenant_id FROM events WHERE type='baseline-reset' AND job_id=?`, jobID); got != want {
			t.Fatalf("runtime event tenant = %s, want %s", got, want)
		}
		if got := tenantOf(t, s.DB, `SELECT tenant_id FROM outbox WHERE destination=?`, destination); got != want {
			t.Fatalf("runtime delivery tenant = %s, want %s", got, want)
		}
		destination = "silence-" + want
		// Two days after the last successful scan.
		if _, created, err := s.RecordJobSilenceAlert(ctx, jobID, "edge", now.Add(-24*time.Hour), now.Add(48*time.Hour), time.Hour, []string{destination}); err != nil || !created {
			t.Fatalf("silence alert = %v, %v", created, err)
		}
		if got := tenantOf(t, s.DB, `SELECT tenant_id FROM events WHERE type='job-silent' AND job_id=?`, jobID); got != want {
			t.Fatalf("silence event tenant = %s, want %s", got, want)
		}
		if got := tenantOf(t, s.DB, `SELECT tenant_id FROM outbox WHERE destination=?`, destination); got != want {
			t.Fatalf("silence delivery tenant = %s, want %s", got, want)
		}
	}
	job := testJob("edge")
	job.Targets = []string{"192.0.2.20"}
	if _, _, events, err := s.UpdateJobWithEventsWithOutbox(ctx, jobA.ID, jobA.Revision, job, true, false, true, []string{"job-update"}); err != nil || len(events) != 1 {
		t.Fatalf("scope change events = %v, %v", events, err)
	}
	if got := tenantOf(t, s.DB, `SELECT tenant_id FROM outbox WHERE destination='job-update'`); got != DefaultTenantID {
		t.Fatalf("job update delivery tenant = %s", got)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM events WHERE type='baseline-reset' AND job_id=? AND tenant_id=?`, jobA.ID, DefaultTenantID); got != 2 {
		t.Fatalf("default-tenant reset events = %d, want 2", got)
	}

	// Update alerts are platform events: neither they nor their deliveries
	// have a tenant.
	if _, err := s.RecordInstalledVersion(ctx, "1.0.0", "", false, nil); err != nil {
		t.Fatal(err)
	}
	if events, err := s.RecordInstalledVersion(ctx, "1.1.0", "https://example.invalid/1.1.0", true, []string{"updates"}); err != nil || len(events) != 1 {
		t.Fatalf("upgrade alert = %v, %v", events, err)
	}
	if events, err := s.RecordReleaseCheck(ctx, "1.1.0", "1.2.0", "https://example.invalid/1.2.0", "EdgeWatch 1.2.0", "", "etag", true, []string{"updates"}); err != nil || len(events) != 1 {
		t.Fatalf("update available alert = %v, %v", events, err)
	}
	for _, eventType := range []string{"application-updated", "application-update-available"} {
		if got := tenantOf(t, s.DB, `SELECT tenant_id FROM events WHERE type=?`, eventType); got != platform {
			t.Fatalf("%s event tenant = %s, want none", eventType, got)
		}
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE destination='updates' AND tenant_id IS NULL`); got != 2 {
		t.Fatalf("platform update deliveries = %d, want 2", got)
	}

	// A config.yaml job's events and deliveries belong to the default
	// tenant; a delivery queued directly follows its event.
	if _, err := s.UpdateState(ctx, "legacy", func(*model.JobState) ([]model.Event, error) {
		return []model.Event{{Type: "legacy-change", Job: "legacy", CreatedAt: now}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := tenantOf(t, s.DB, `SELECT tenant_id FROM events WHERE type='legacy-change'`); got != DefaultTenantID {
		t.Fatalf("legacy event tenant = %s", got)
	}
	for destination, event := range map[string]model.Event{
		"queued-legacy":   {Type: "legacy-change", Job: "legacy", CreatedAt: now},
		"queued-job-b":    {Type: "change", JobID: jobB, Job: "edge", CreatedAt: now},
		"queued-platform": {Type: "notice", Message: "platform", CreatedAt: now},
	} {
		if err := s.QueueEvent(ctx, destination, event); err != nil {
			t.Fatal(err)
		}
	}
	for destination, want := range map[string]string{"queued-legacy": DefaultTenantID, "queued-job-b": secondTenantID, "queued-platform": platform} {
		if got := tenantOf(t, s.DB, `SELECT tenant_id FROM outbox WHERE destination=?`, destination); got != want {
			t.Fatalf("%s delivery tenant = %s, want %s", destination, got, want)
		}
	}

	// A dropped delivery's event belongs to the delivery's tenant.
	for _, destination := range []string{"queued-job-b", "queued-platform"} {
		for attempt := 0; attempt < deliveryMaxAttempts; attempt++ {
			if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE destination=?`, sqliteTimestamp(time.Now().Add(-time.Minute)), destination); err != nil {
				t.Fatal(err)
			}
			due, err := s.ClaimDueDeliveriesExcluding(ctx, 1, "terminal-owner", excludeAllBut(t, s, destination))
			if err != nil || len(due) != 1 || due[0].Destination != destination {
				t.Fatalf("claim %s attempt %d = %#v, %v", destination, attempt, due, err)
			}
			if err := s.DeliveryResultClaim(ctx, due[0].ID, due[0].ClaimToken, errors.New("provider failed")); err != nil {
				t.Fatal(err)
			}
		}
	}
	terminal := queryStrings(t, s.DB, `SELECT tenant_id FROM events WHERE type='notification-delivery-terminal' ORDER BY id`)
	if !slices.Equal(terminal, []string{secondTenantID, platform}) {
		t.Fatalf("terminal delivery event tenants = %v", terminal)
	}

	// A tenant that is being deleted takes no new history, and the write
	// that would add it fails as a whole.
	setTenantState(t, s, secondTenantID, "deleting")
	if err := s.SaveScan(ctx, largeSnapshotScan("scan-deleting", jobB, "edge", now)); err == nil || !strings.Contains(err.Error(), "must name an active or disabled tenant") {
		t.Fatalf("save a scan of a deleting tenant = %v", err)
	}
	if _, err := s.ResetRuntimeWithOutbox(ctx, jobB, "edge", []string{"reset-deleting"}); err == nil || !strings.Contains(err.Error(), "must name an active or disabled tenant") {
		t.Fatalf("reset a job of a deleting tenant = %v", err)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE destination='reset-deleting'`); got != 0 {
		t.Fatalf("deliveries of a refused event = %d", got)
	}
}

// excludeAllBut returns every pending destination except keep, so a claim
// takes only keep's delivery.
func excludeAllBut(t *testing.T, s *Store, keep string) []string {
	t.Helper()
	return queryStrings(t, s.DB, `SELECT DISTINCT destination FROM outbox WHERE destination<>?`, keep)
}

// A quarantined delivery keeps the tenant of its outbox row. A backup from
// before schema 53 has no tenant yet; the migration after the restore gives
// its rows the default tenant.
func TestRestoreQuarantineKeepsTheDeliveryTenant(t *testing.T) {
	for _, tc := range []struct {
		name string
		// staged turns the source into the staged schema.
		staged []string
		want   map[string]string
	}{
		{
			name: "schema 53 backup",
			want: map[string]string{"queued-job-a": DefaultTenantID, "queued-job-b": secondTenantID, "queued-platform": "<null>"},
		},
		{
			// The quarantine table is created by the restore, in its
			// schema-35 shape, and gains the tenant column.
			name:   "schema 53 backup without a quarantine table",
			staged: []string{"DROP TABLE restore_quarantined_deliveries"},
			want:   map[string]string{"queued-job-a": DefaultTenantID, "queued-job-b": secondTenantID, "queued-platform": "<null>"},
		},
		{
			name:   "schema 52 backup",
			staged: schema52FixtureStatements,
			want:   map[string]string{"queued-job-a": DefaultTenantID, "queued-job-b": DefaultTenantID, "queued-platform": DefaultTenantID},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			source := filepath.Join(dir, "source.db")
			destination := filepath.Join(dir, "destination.db")
			s, err := Open(source)
			if err != nil {
				t.Fatal(err)
			}
			insertSecondTenant(t, s)
			jobA, err := s.CreateJob(ctx, testJob("edge"))
			if err != nil {
				t.Fatal(err)
			}
			const jobB = "00000000-0000-0000-0000-000000000b01"
			insertSecondTenantJob(t, s, jobA.ID, jobB)
			for destination, event := range map[string]model.Event{
				"queued-job-a":    {Type: "change", JobID: jobA.ID, Job: "edge"},
				"queued-job-b":    {Type: "change", JobID: jobB, Job: "edge"},
				"queued-platform": {Type: "notice", Message: "platform"},
			} {
				if err := s.QueueEvent(ctx, destination, event); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			execFixtureStatements(t, source, tc.staged)
			createRestoreFixture(t, destination, "destination")

			result, err := Restore(ctx, source, destination, RestoreOptions{})
			if err != nil {
				t.Fatalf("restore: %v", err)
			}
			if result.PendingDeliveriesAffected != 3 {
				t.Fatalf("restore result = %#v", result)
			}
			restored, err := Open(destination)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close()
			if got := countRows(t, restored.DB, `SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL`); got != 0 {
				t.Fatalf("pending deliveries after the restore = %d", got)
			}
			for destination, want := range tc.want {
				if got := tenantOf(t, restored.DB, `SELECT tenant_id FROM restore_quarantined_deliveries WHERE destination=? AND restore_epoch=?`, destination, result.RestoreEpoch); got != want {
					t.Fatalf("%s quarantine tenant = %s, want %s", destination, got, want)
				}
			}
			if got := tableColumns(t, restored.DB, "restore_quarantined_deliveries"); got[len(got)-1] != "tenant_id TEXT notnull=0 default="+defaultTenantLiteral+" pk=0" {
				t.Fatalf("quarantine columns = %v", got)
			}
		})
	}
}
