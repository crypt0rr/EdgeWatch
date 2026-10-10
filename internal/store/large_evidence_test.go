package store

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// The scans table stores each scan's snapshot before the columns that later
// schemas added, so a statement that reads job_id, tenant_id or cycle_status
// from a scan row reads its snapshot pages too. Such a regression only shows
// with large snapshots: a test database of small scans answers it as fast as
// an index. The fixtures below write scans with large snapshots and many
// host rows quickly, and the plan helpers check that a statement reads the
// scans through indexes that hold every column it needs.

// largeEvidenceSnapshotBytes is the snapshot size of a large-evidence scan:
// several dozen overflow pages, as a broad scan stores.
const largeEvidenceSnapshotBytes = 256 << 10

// seedLargeEvidenceScans writes count scans of the tenant's job in one
// statement, one second apart from start, each with a snapshot of about
// snapshotBytes. Every fifth scan failed; the others succeeded. It returns
// the scan IDs, oldest first.
func seedLargeEvidenceScans(tb testing.TB, db *sql.DB, tenantID, jobID, prefix string, count, snapshotBytes int, start time.Time) []string {
	tb.Helper()
	base := start.UTC().Format("2006-01-02 15:04:05")
	if _, err := db.Exec(`WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i+1<?)
INSERT INTO scans(id,job_id,job,started_at,finished_at,status,config_hash,snapshot_json,tenant_id)
SELECT printf('%s-%06d',?,i),?,?,
 strftime('%Y-%m-%dT%H:%M:%S',?,printf('+%d seconds',i))||'.000000000Z',
 strftime('%Y-%m-%dT%H:%M:%S',?,printf('+%d seconds',i))||'.000000000Z',
 CASE WHEN i%5=4 THEN 'failed' ELSE 'success' END,'hash',
 printf('{"pad":"%s"}',substr(hex(zeroblob(?)),1,?)),?
FROM n`, count, prefix, jobID, jobID, base, base, snapshotBytes/2+1, snapshotBytes, tenantID); err != nil {
		tb.Fatal(err)
	}
	ids := make([]string, count)
	for index := range ids {
		ids[index] = fmt.Sprintf("%s-%06d", prefix, index)
	}
	return ids
}

// seedLargeEvidenceHosts writes hostsPerScan host rows, and through their
// trigger the search rows, for each of the scans, in one statement per scan.
func seedLargeEvidenceHosts(tb testing.TB, db *sql.DB, scanIDs []string, hostsPerScan int) {
	tb.Helper()
	for _, id := range scanIDs {
		if _, err := db.Exec(`WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i+1<?)
INSERT INTO scan_hosts(scan_id,address,job,host_json,search_text,tcp_present,open_ports,tcp_open_ports)
SELECT ?,printf('10.%d.%d.%d',i/65536,(i/256)%256,i%256),'evidence',printf('{"address":"10.%d.%d.%d","status":"up"}',i/65536,(i/256)%256,i%256),printf('10.%d.%d.%d https nginx',i/65536,(i/256)%256,i%256),1,1,1
FROM n`, hostsPerScan, id); err != nil {
			tb.Fatal(err)
		}
	}
}

// explainPlan returns the EXPLAIN QUERY PLAN steps of a statement.
func explainPlan(tb testing.TB, db *sql.DB, statement string, args ...any) []string {
	tb.Helper()
	rows, err := db.Query(`EXPLAIN QUERY PLAN `+statement, args...)
	if err != nil {
		tb.Fatalf("explain %s: %v", statement, err)
	}
	defer rows.Close()
	var steps []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			tb.Fatal(err)
		}
		steps = append(steps, detail)
	}
	if err := rows.Err(); err != nil {
		tb.Fatal(err)
	}
	return steps
}

// scanRowReads returns the steps of a plan that read rows of the scans
// table, under one of the aliases, instead of one of its covering indexes. A
// lookup by rowid reads the row too.
func scanRowReads(plan []string, aliases ...string) []string {
	var reads []string
	for _, step := range plan {
		fields := strings.Fields(step)
		if len(fields) < 2 || (fields[0] != "SCAN" && fields[0] != "SEARCH") || !slices.Contains(aliases, fields[1]) {
			continue
		}
		if !strings.Contains(step, "USING COVERING INDEX ") {
			reads = append(reads, step)
		}
	}
	return reads
}

// planCase is a statement whose plan a test checks.
type planCase struct {
	label     string
	statement string
	args      []any
	// aliases name the scans table in the statement; the default is scans.
	aliases []string
	// index, when set, must be in the plan.
	index string
	// pageRows allows the scan row to be read for the rows of a page, which
	// the result needs, when the order and every predicate come from index.
	pageRows bool
	// sorts allows a temporary B-tree for a statement that orders the rows
	// it has selected, such as rowids to delete or a window over one job's
	// hosts, rather than a page of the history.
	sorts bool
}

// assertScanPlans checks each case: the statement reads the scans table
// only through covering indexes, or, for a page, through index alone, and
// never sorts its result into a temporary B-tree.
func assertScanPlans(t *testing.T, db *sql.DB, cases []planCase) {
	t.Helper()
	for _, check := range cases {
		aliases := check.aliases
		if len(aliases) == 0 {
			aliases = []string{"scans"}
		}
		plan := explainPlan(t, db, check.statement, check.args...)
		joined := strings.Join(plan, " | ")
		if check.index != "" && !strings.Contains(joined, " INDEX "+check.index+" ") {
			t.Errorf("%s: plan %s does not use %s", check.label, joined, check.index)
		}
		if !check.sorts && strings.Contains(joined, "TEMP B-TREE") {
			t.Errorf("%s: plan %s sorts into a temporary B-tree", check.label, joined)
		}
		reads := scanRowReads(plan, aliases...)
		if check.pageRows {
			var unexpected []string
			for _, read := range reads {
				if check.index == "" || !strings.Contains(read, "USING INDEX "+check.index+" ") {
					unexpected = append(unexpected, read)
				}
			}
			reads = unexpected
		}
		if len(reads) > 0 {
			t.Errorf("%s: plan %s reads scan rows: %q", check.label, joined, reads)
		}
	}
}

// fastestOf returns the shortest of runs of fn, which a busy machine
// disturbs least.
func fastestOf(tb testing.TB, runs int, fn func() error) time.Duration {
	tb.Helper()
	best := time.Duration(1<<63 - 1)
	for range runs {
		started := time.Now()
		if err := fn(); err != nil {
			tb.Fatal(err)
		}
		if elapsed := time.Since(started); elapsed < best {
			best = elapsed
		}
	}
	return best
}

// The history statements read a job's or a tenant's scans through indexes
// that hold the job, the tenant and the outcome, so a count, the rows that
// an offset passes, a lookup by ID and the retention checks never read a
// scan row, and with it the scan's snapshot. Page statements read the scan
// row for the rows of the page only. SQLite plans these statements the same
// way for any number of rows.
func TestScanHistoryReadsUseCoveringIndexes(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	insertJobRows(t, s, "evidence-job")
	seedLargeEvidenceScans(t, s.DB, DefaultTenantID, "evidence-job", "evidence", 8, 16<<10, time.Now().Add(-time.Hour))
	tenant, job := DefaultTenantID, "evidence-job"
	jobPage := jobScanSummariesPageQueries(tenant, job, 50, 2000)
	fullJobPage := jobScansPageQueries(tenant, job, 50, 2000)
	tenantPage := tenantScansPageQueries(tenant, "", scanSummaryColumnsSQL, 50, 2000)
	namedPage := tenantScansPageQueries(tenant, job, scanSummaryColumnsSQL, 50, 2000)
	hostPage := scanHostsPageQueries(tenant, "evidence-000001", "", "", nil, 50, 0)
	_, repairSQL, repairArgs := latestScanHostRepairQueries([]latestScanHostKey{{tenant, "10.0.0.1"}})
	trigger := strings.NewReplacer("NEW.tenant_id", "?", "NEW.scan_id", "?").Replace(latestScanHostScanTenantSQL)
	cases := []planCase{
		{label: "job history count", statement: jobPage.countSQL, args: jobPage.countArg, aliases: []string{"s"}},
		{label: "job history page", statement: jobPage.pageSQL, args: jobPage.pageArg, aliases: []string{"s"}, index: scansJobHistoryIndex, pageRows: true},
		{label: "job history page with results", statement: fullJobPage.pageSQL, args: fullJobPage.pageArg, aliases: []string{"s"}, index: scansJobHistoryIndex, pageRows: true},
		{label: "scan list count", statement: tenantPage.countSQL, args: tenantPage.countArg, aliases: []string{"s"}, index: scansTenantHistoryIndex},
		{label: "scan list page", statement: tenantPage.pageSQL, args: tenantPage.pageArg, aliases: []string{"s"}, index: scansTenantHistoryIndex, pageRows: true},
		{label: "scan list count by job name", statement: namedPage.countSQL, args: namedPage.countArg, aliases: []string{"s"}, index: scansTenantHistoryIndex},
		{label: "scan list page by job name", statement: namedPage.pageSQL, args: namedPage.pageArg, aliases: []string{"s"}, index: scansTenantHistoryIndex, pageRows: true},
		{label: "latest successful job scan", statement: `SELECT ` + scanSummaryColumnsSQL + jobScansFromSQL + ` AND s.status='success' ORDER BY s.finished_at DESC,s.id DESC LIMIT 1`, args: []any{tenant, job}, aliases: []string{"s"}, index: scansJobHistoryIndex, pageRows: true},
		{label: "scan host page count", statement: hostPage.countSQL, args: hostPage.countArg, aliases: []string{"s"}, index: scansIdentityIndex},
		{label: "successful host index", statement: `SELECT EXISTS(SELECT 1 FROM scan_hosts h JOIN scans s ON s.id=h.scan_id WHERE s.tenant_id=? AND s.status='success' AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=s.tenant_id AND purge.job_id=s.job_id))`, args: []any{tenant}, aliases: []string{"s"}},
		{label: "latest host guard trigger", statement: `SELECT ` + trigger, args: []any{tenant, "evidence-000001"}, index: scansIdentityIndex},
		// A successful scan writes one latest observation per host; the
		// statement takes the scan's tenant as an argument and reads no scan.
		{label: "latest host upsert", statement: upsertLatestScanHostSQL, args: []any{tenant, "10.0.0.1", "evidence-000001", job, job, "2026-10-01T00:00:00.000000000Z", "detailed", "IPv4", "[]", "[]", "{}", "", 0, 0, 1, 0, 0, 0, 0, 0}},
		{label: "latest host repair", statement: repairSQL, args: repairArgs, aliases: []string{"s"}, index: scansIdentityIndex, sorts: true},
		{label: "cycle promotion", statement: scanCycleHasScanQuery, args: []any{"cycle", tenant}, index: scansCycleOutcomeIndex},
		{label: "retention protection of each job's newest scan", statement: strings.TrimPrefix(retentionNewestJobScanSQL, `INSERT OR IGNORE INTO `+retentionProtectedScans+`(scan_id)`), index: scansJobHistoryIndex},
		// The scans without a job ID, which only earlier releases saved,
		// are few, and the window sorts them alone.
		{label: "retention protection of each unmanaged job's newest scan", statement: strings.TrimPrefix(retentionNewestUnmanagedScanSQL, `INSERT OR IGNORE INTO `+retentionProtectedScans+`(scan_id)`), sorts: true},
	}
	// A job purge step orders the rowids of the job's rows that it deletes.
	for _, step := range jobHistoryPurgeSteps {
		if strings.Contains(step.rowids, " scans ") {
			cases = append(cases, planCase{label: "job purge " + step.phase, statement: step.rowids + " LIMIT 500", args: []any{tenant, job}, aliases: []string{"scans", "s"}, index: scansJobHistoryIndex, sorts: true})
		}
	}
	assertScanPlans(t, s.DB, cases)

	// The cycle checks of a retention pass read the scans' cycle outcome
	// from scans_cycle_outcome.
	for _, statement := range []string{
		`SELECT 1 FROM scan_cycles AS cycle WHERE cycle.status='completed' AND EXISTS (SELECT 1 FROM scans WHERE scans.cycle_id=cycle.id AND scans.cycle_status='completed' AND scans.status IN ('success','incomplete'))`,
		`SELECT 1 FROM scan_cycles AS candidate WHERE candidate.finished_at <> '' AND NOT EXISTS (SELECT 1 FROM scans WHERE scans.cycle_id = candidate.id)`,
	} {
		plan := explainPlan(t, s.DB, statement)
		if reads := scanRowReads(plan, "scans"); len(reads) > 0 || !strings.Contains(strings.Join(plan, " | "), scansCycleOutcomeIndex) {
			t.Errorf("cycle retention check plan %q reads scan rows: %q", plan, reads)
		}
	}
}

// The plan helpers find the reads they look for: a plan that reads scan
// rows, a sort, and an index that is not used.
func TestScanPlanHelpersReportRowReads(t *testing.T) {
	t.Parallel()
	plan := []string{
		"SEARCH j USING INDEX sqlite_autoindex_jobs_1 (id=?)",
		"SEARCH s USING INDEX scans_job_id_revision (job_id=?)",
		"SEARCH newer USING COVERING INDEX scans_job_id_history (job_id=?)",
		"SCAN scans",
		"SEARCH scans USING INTEGER PRIMARY KEY (rowid=?)",
	}
	if got := scanRowReads(plan, "s", "newer", "scans"); !slices.Equal(got, []string{plan[1], plan[3], plan[4]}) {
		t.Fatalf("scan row reads = %q", got)
	}
	if got := scanRowReads(plan, "newer"); len(got) != 0 {
		t.Fatalf("covering index reads = %q", got)
	}
	s := openTestStore(t)
	failing := []planCase{
		{label: "full scan", statement: `SELECT snapshot_json FROM scans WHERE comparison=''`},
		{label: "sort", statement: `SELECT id FROM scans ORDER BY comparison`},
		{label: "unused index", statement: `SELECT COUNT(*) FROM scans WHERE tenant_id=?`, args: []any{DefaultTenantID}, index: scansJobHistoryIndex},
		// The latest host upsert of earlier releases, which read the tenant
		// from the scan row for each host.
		{label: "upsert reading the scan's tenant", statement: strings.Replace(upsertLatestScanHostSQL, "VALUES(?,", "VALUES((SELECT tenant_id FROM scans WHERE id=?),", 1), args: []any{"scan", "10.0.0.1", "scan", "job", "job", "x", "detailed", "IPv4", "[]", "[]", "{}", "", 0, 0, 1, 0, 0, 0, 0, 0}},
	}
	for _, check := range failing {
		plan := explainPlan(t, s.DB, check.statement, check.args...)
		joined := strings.Join(plan, " | ")
		failed := len(scanRowReads(plan, "scans")) > 0 || strings.Contains(joined, "TEMP B-TREE") || (check.index != "" && !strings.Contains(joined, " INDEX "+check.index+" "))
		if !failed {
			t.Errorf("%s: plan %s passed the checks", check.label, joined)
		}
	}
}

// withoutAutoVacuum turns the store's database into one without
// auto-vacuum, as databases created before v0.18.31 are. In a database with
// incremental auto-vacuum, SQLite finds the next page of a contiguous
// overflow chain from the pointer map without reading the page, which hides
// the cost of reading past a snapshot in a fresh test database; in one
// without, and in any database whose freed pages have scattered the chains,
// it reads every page. Call it before writing large rows.
func withoutAutoVacuum(tb testing.TB, s *Store) {
	tb.Helper()
	if _, err := s.DB.Exec(`PRAGMA auto_vacuum=0`); err != nil {
		tb.Fatal(err)
	}
	if _, err := s.DB.Exec(`VACUUM`); err != nil {
		tb.Fatal(err)
	}
	var mode int
	if err := s.DB.QueryRow(`PRAGMA auto_vacuum`).Scan(&mode); err != nil || mode != 0 {
		tb.Fatalf("auto_vacuum = %d, %v; want none", mode, err)
	}
}

// largeAndSmallEvidence writes, in one store, a job of the default
// tenant with large snapshots and a job of a second tenant with small
// ones, with the same number of scans each.
func largeAndSmallEvidence(t *testing.T, scans int) *Store {
	t.Helper()
	s := openTestStore(t)
	withoutAutoVacuum(t, s)
	insertSecondTenant(t, s)
	stamp := sqliteTimestamp(time.Now())
	insertJobRows(t, s, "large-evidence")
	if _, err := s.DB.Exec(`INSERT INTO jobs(id,tenant_id,name,definition_json,created_at,updated_at) VALUES('small-evidence',?,'small-evidence','{}',?,?)`, secondTenantID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-48 * time.Hour)
	seedLargeEvidenceScans(t, s.DB, DefaultTenantID, "large-evidence", "large", scans, largeEvidenceSnapshotBytes, start)
	seedLargeEvidenceScans(t, s.DB, secondTenantID, "small-evidence", "small", scans, 64, start)
	return s
}

// A job's history count, a deep page of it, and the tenant's scan list cost
// about as much over scans with large snapshots as over scans with small
// ones. The statements that tested the scan row's tenant and job read every
// snapshot that a count or an offset passed: in this database without
// auto-vacuum the job count took 60 times, and a deep page 300 times, as
// long over the large snapshots. The bound is loose so that it holds on a
// slow or busy machine. The race detector slows SQLite down too much to
// build the fixture, so the test runs only without it.
func TestScanHistoryCountsDoNotReadSnapshots(t *testing.T) {
	if raceEnabled || testing.Short() {
		t.Skip("the large-evidence fixture takes minutes to build under the race detector")
	}
	t.Parallel()
	ctx := context.Background()
	const scans = 200
	s := largeAndSmallEvidence(t, scans)
	large, small := defaultTenant(s), s.Tenant(TenantScope{id: secondTenantID})
	for _, check := range []struct {
		label string
		run   func(*TenantStore, string) error
	}{
		{"job history count", func(ts *TenantStore, job string) error {
			q := jobScanSummariesPageQueries(ts.scope.id, job, 50, 0)
			var count int
			if err := s.reader().QueryRowContext(ctx, q.countSQL, q.countArg...).Scan(&count); err != nil || count != scans {
				return fmt.Errorf("count %d: %v", count, err)
			}
			return nil
		}},
		{"deep job history page", func(ts *TenantStore, job string) error {
			page, err := ts.ListJobScanSummariesPage(ctx, job, 10, scans-10)
			if err == nil && len(page.Items) != 10 {
				err = fmt.Errorf("%d items", len(page.Items))
			}
			return err
		}},
		{"deep scan list page", func(ts *TenantStore, _ string) error {
			page, err := ts.ListScanSummariesPage(ctx, "", 10, scans-10)
			if err == nil && (len(page.Items) != 10 || page.Total != scans) {
				err = fmt.Errorf("%d items of %d", len(page.Items), page.Total)
			}
			return err
		}},
		{"scan list count by job name", func(ts *TenantStore, job string) error {
			page, err := ts.ListScanSummariesPage(ctx, job, 1, 0)
			if err == nil && page.Total != scans {
				err = fmt.Errorf("total %d", page.Total)
			}
			return err
		}},
	} {
		largeTime := fastestOf(t, 3, func() error { return check.run(large, "large-evidence") })
		smallTime := fastestOf(t, 3, func() error { return check.run(small, "small-evidence") })
		t.Logf("%s: %s over large snapshots, %s over small ones", check.label, largeTime, smallTime)
		if largeTime > 5*smallTime+20*time.Millisecond {
			t.Errorf("%s took %s over large snapshots, %s over small ones", check.label, largeTime, smallTime)
		}
	}
}

// broadScanSnapshot returns the snapshot of a broad scan: hosts addresses
// from first, each with ports open services, and the unit that found each.
func broadScanSnapshot(first, hosts, ports int) model.Snapshot {
	var snapshot model.Snapshot
	for index := first; index < first+hosts; index++ {
		address := fmt.Sprintf("10.%d.%d.%d", index/65536, (index/256)%256, index%256)
		unit := model.Unit{Target: "10.0.0.0/8", Protocol: "tcp", Addresses: []string{address}}
		protocol := model.ProtocolObservation{Protocol: "tcp", ScannedPorts: "1-1024", ScannedPortCount: 1024}
		for port := 0; port < ports; port++ {
			unit.Ports = append(unit.Ports, model.PortState{Port: 8000 + port, State: "open", Service: "http"})
			protocol.Ports = append(protocol.Ports, model.PortObservation{Port: 8000 + port, State: "open", Reason: "syn-ack", Service: &model.ServiceObservation{Name: "http", Product: "nginx", Version: "1.27.0"}})
		}
		snapshot.Units = append(snapshot.Units, unit)
		snapshot.Hosts = append(snapshot.Hosts, model.HostObservation{Address: address, AddressFamily: "IPv4", Status: "up", SourceTargets: []string{"10.0.0.0/8"}, Protocols: []model.ProtocolObservation{protocol}})
	}
	return snapshot
}

// Finalizing a successful scan of four times as many hosts costs about
// four times as much, as finalizing a failed one does. A successful scan
// also writes each host's latest observation, whose tenant was read from
// the scan row, past its snapshot, once in the statement and once in the
// guard trigger for every host: the cost grew with the square of the hosts,
// and in this database without auto-vacuum a successful save cost 2.8 times
// a failed one at 500 hosts and 10 times at 2,000. The bound is loose so that it
// holds on a slow or busy machine. The race detector slows SQLite down too
// much for scans of this size, so the test runs only without it.
func TestSaveScanCostGrowsLinearlyWithHosts(t *testing.T) {
	if raceEnabled || testing.Short() {
		t.Skip("scans of thousands of hosts take minutes to save under the race detector")
	}
	t.Parallel()
	// Each size is measured in a database of its own, and each save
	// observes new addresses, so every successful save inserts its latest
	// observations into a projection of the same size.
	ratio := func(hosts int) float64 {
		s := openTestStore(t)
		withoutAutoVacuum(t, s)
		insertJobRows(t, s, "broad-job")
		ctx := context.Background()
		first := 0
		save := func(status string) time.Duration {
			return fastestOf(t, 2, func() error {
				snapshot := broadScanSnapshot(first, hosts, 8)
				id := fmt.Sprintf("broad-%s-%d", status, first)
				first += hosts
				now := time.Now().UTC()
				return s.System().SaveScan(ctx, model.Scan{ID: id, JobID: "broad-job", Job: "broad-job", StartedAt: now, FinishedAt: now, Status: status, Snapshot: snapshot})
			})
		}
		failed, success := save("failed"), save("success")
		t.Logf("%d hosts: failed %s, success %s", hosts, failed, success)
		return float64(success) / float64(failed)
	}
	small, large := ratio(500), ratio(2000)
	if large > 2*small+1 {
		t.Fatalf("a successful save costs %.1f times a failed one at 2,000 hosts and %.1f times at 500", large, small)
	}
}
