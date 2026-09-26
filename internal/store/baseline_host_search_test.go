package store

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

type queryPlanRow struct {
	id     int
	parent int
	detail string
}

func explainQueryPlanRows(t *testing.T, db *sql.DB, query string, args ...any) []queryPlanRow {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `EXPLAIN QUERY PLAN `+query, args...)
	if err != nil {
		t.Fatalf("explain %s: %v", query, err)
	}
	defer rows.Close()
	var plan []queryPlanRow
	for rows.Next() {
		var row queryPlanRow
		var notUsed int
		if err := rows.Scan(&row.id, &row.parent, &notUsed, &row.detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return plan
}

// ftsPlanIndex captures the FTS5 idxStr. An empty value is a full scan of the
// virtual table; "=" is a rowid lookup and "M" a full-text MATCH.
var ftsPlanIndex = regexp.MustCompile(`VIRTUAL TABLE INDEX \d+:(\S*)`)

// assertFTSPlanUses fails when any FTS access in the plan scans the whole
// virtual table or does not use the expected FTS5 constraint.
func assertFTSPlanUses(t *testing.T, label string, plan []queryPlanRow, want string) []queryPlanRow {
	t.Helper()
	var accesses []queryPlanRow
	for _, row := range plan {
		match := ftsPlanIndex.FindStringSubmatch(row.detail)
		if match == nil {
			continue
		}
		accesses = append(accesses, row)
		if match[1] == "" {
			t.Fatalf("%s scans every baseline search row: %v", label, plan)
		}
		if !strings.Contains(match[1], want) {
			t.Fatalf("%s uses FTS index %q, want %q: %v", label, match[1], want, plan)
		}
	}
	if len(accesses) == 0 {
		t.Fatalf("%s does not use baseline_host_search: %v", label, plan)
	}
	return accesses
}

// assertBaselineHostSearchTriggersUseRowid explains the DELETE statements of
// the installed maintenance triggers. EXPLAIN QUERY PLAN does not descend into
// trigger programs, so the trigger bodies are explained with their OLD/NEW
// references bound as parameters.
func assertBaselineHostSearchTriggersUseRowid(t *testing.T, db *sql.DB) {
	t.Helper()
	rowReference := regexp.MustCompile(`(?i)\b(OLD|NEW)\.[a-z_]+`)
	for _, trigger := range []string{"baseline_hosts_search_au", "baseline_hosts_search_ad"} {
		var definition string
		if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?`, trigger).Scan(&definition); err != nil {
			t.Fatalf("read trigger %s: %v", trigger, err)
		}
		upper := strings.ToUpper(definition)
		begin, end := strings.Index(upper, "BEGIN"), strings.LastIndex(upper, "END")
		if begin < 0 || end <= begin {
			t.Fatalf("trigger %s has no body: %q", trigger, definition)
		}
		deletes := 0
		for _, statement := range strings.Split(definition[begin+len("BEGIN"):end], ";") {
			statement = strings.TrimSpace(statement)
			if !strings.HasPrefix(strings.ToUpper(statement), "DELETE") {
				continue
			}
			deletes++
			bound := rowReference.ReplaceAllString(statement, "?")
			args := make([]any, strings.Count(bound, "?"))
			for i := range args {
				args[i] = int64(1)
			}
			assertFTSPlanUses(t, trigger+" delete", explainQueryPlanRows(t, db, bound, args...), "=")
		}
		if deletes == 0 {
			t.Fatalf("trigger %s does not delete its search row: %q", trigger, definition)
		}
	}
}

func baselineSearchSnapshot(prefix, count int) model.Snapshot {
	snapshot := model.Snapshot{Hosts: make([]model.HostObservation, 0, count)}
	for i := 0; i < count; i++ {
		snapshot.Hosts = append(snapshot.Hosts, model.HostObservation{
			Address:   fmt.Sprintf("10.%d.%d.%d", prefix, i/250, i%250+1),
			Protocols: []model.ProtocolObservation{{Protocol: "tcp", Ports: []model.PortObservation{{Port: 80, State: "open", Service: &model.ServiceObservation{Name: "http", Product: "nginx"}}}}},
		})
	}
	return snapshot
}

func insertBaselineSearchJob(t *testing.T, s *Store, id, name string) {
	t.Helper()
	if _, err := s.DB.ExecContext(context.Background(), `INSERT INTO jobs(id,tenant_id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES(?,?,?,'{}',1,0,1,'now','now')`, id, DefaultTenantID, name); err != nil {
		t.Fatal(err)
	}
}

func TestBaselineHostSearchTriggersDeleteByRowid(t *testing.T) {
	s := openTestStore(t)
	// A job/address delete cannot use the FTS index, so every removed baseline
	// host scanned the search rows of every job.
	assertBaselineHostSearchTriggersUseRowid(t, s.DB)
}

func TestBaselineHostSearchQueriesUseRowidLookups(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	insertBaselineSearchJob(t, s, "plan-job", "plan-job")
	insertBaselineSearchJob(t, s, "plan-other", "plan-other")
	for jobID, prefix := range map[string]int{"plan-job": 1, "plan-other": 2} {
		if err := s.ReplaceBaselineHostProjection(ctx, jobID, baselineSearchSnapshot(prefix, 8)); err != nil {
			t.Fatal(err)
		}
	}
	open := true
	for _, tc := range []struct {
		name     string
		query    string
		protocol string
		hasOpen  *bool
		want     string
	}{
		// Three or more characters use the trigram index once per query and
		// join its rowids; the lookup must not be repeated for every host.
		{name: "match", query: "nginx", want: "M"},
		{name: "filtered match", query: "nginx", protocol: "tcp", hasOpen: &open, want: "M"},
		// Shorter values cannot use trigrams. Each host of the job reads only
		// its own search row by rowid instead of scanning every job's rows.
		{name: "short", query: "80", want: "="},
		{name: "filtered short", query: "8", protocol: "tcp", hasOpen: &open, want: "="},
	} {
		queries := baselineHostsPageQueries("plan-job", tc.query, tc.protocol, tc.hasOpen, 50, 0)
		for _, statement := range []struct {
			kind string
			sql  string
			args []any
		}{
			{kind: "count", sql: queries.countSQL, args: queries.countArg},
			{kind: "page", sql: queries.pageSQL, args: queries.pageArg},
		} {
			label := tc.name + " " + statement.kind
			plan := explainQueryPlanRows(t, s.DB, statement.sql, statement.args...)
			accesses := assertFTSPlanUses(t, label, plan, tc.want)
			if tc.want != "M" {
				continue
			}
			parents := make(map[int]queryPlanRow, len(plan))
			for _, row := range plan {
				parents[row.id] = row
			}
			for _, access := range accesses {
				for parent, ok := parents[access.parent]; ok; parent, ok = parents[parent.parent] {
					if strings.HasPrefix(parent.detail, "CORRELATED") {
						t.Fatalf("%s repeats the full-text query for every host: %v", label, plan)
					}
				}
			}
		}
		page, err := s.ListBaselineHostsPage(ctx, "plan-job", tc.query, tc.protocol, tc.hasOpen, 50, 0)
		if err != nil {
			t.Fatalf("%s search: %v", tc.name, err)
		}
		if page.Total != 8 || len(page.Items) != 8 {
			t.Fatalf("%s search = total %d, items %d; want only the job's 8 hosts", tc.name, page.Total, len(page.Items))
		}
	}
}

func TestBaselineHostProjectionReplaceIsIndependentOfOtherJobs(t *testing.T) {
	ctx := context.Background()
	const ownHosts, otherHosts = 128, 3072
	alone := openTestStore(t)
	crowded := openTestStore(t)
	snapshot := baselineSearchSnapshot(1, ownHosts)
	for _, s := range []*Store{alone, crowded} {
		insertBaselineSearchJob(t, s, "small", "small")
		insertBaselineSearchJob(t, s, "large", "large")
		if err := s.ReplaceBaselineHostProjection(ctx, "small", snapshot); err != nil {
			t.Fatal(err)
		}
	}
	// Another job's baseline is seeded in one statement so the comparison is
	// dominated by the measured replacement, not by fixture construction.
	if _, err := crowded.DB.ExecContext(ctx, `WITH RECURSIVE seq(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM seq WHERE i<?)
INSERT INTO baseline_hosts(job_id,address,host_json,search_text)
SELECT 'large','10.2.'||(i/250)||'.'||(i%250+1),'{}','10.2.'||(i/250)||'.'||(i%250+1)||' 80 http nginx' FROM seq`, otherHosts-1); err != nil {
		t.Fatal(err)
	}
	var indexed int
	if err := crowded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM baseline_host_search`).Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if indexed != ownHosts+otherHosts {
		t.Fatalf("crowded search rows = %d, want %d", indexed, ownHosts+otherHosts)
	}
	// Compact both indexes so the comparison measures trigger maintenance
	// rather than FTS5's amortized segment merging.
	for _, s := range []*Store{alone, crowded} {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO baseline_host_search(baseline_host_search) VALUES('optimize')`); err != nil {
			t.Fatal(err)
		}
	}

	// Interleave the two stores and keep the fastest run of each so a busy
	// machine slows both sides alike. With job/address trigger deletes the
	// crowded replacement was seven to ten times slower at this size; rowid
	// deletes keep it within about 1.4 times the job-only cost.
	best := map[*Store]time.Duration{}
	for round := 0; round < 3; round++ {
		for _, s := range []*Store{alone, crowded} {
			started := time.Now()
			if err := s.ReplaceBaselineHostProjection(ctx, "small", snapshot); err != nil {
				t.Fatal(err)
			}
			if elapsed := time.Since(started); best[s] == 0 || elapsed < best[s] {
				best[s] = elapsed
			}
		}
	}
	t.Logf("replacing %d hosts: %s alone, %s beside %d other baseline hosts", ownHosts, best[alone], best[crowded], otherHosts)
	if best[crowded] > 3*best[alone] {
		t.Fatalf("replacing %d hosts took %s beside %d other baseline hosts and %s alone; maintenance depends on other jobs", ownHosts, best[crowded], otherHosts, best[alone])
	}
	page, err := crowded.ListBaselineHostsPage(ctx, "small", "nginx", "", nil, 10, 0)
	if err != nil || page.Total != ownHosts {
		t.Fatalf("crowded baseline search = total %d, err %v; want %d", page.Total, err, ownHosts)
	}
}
