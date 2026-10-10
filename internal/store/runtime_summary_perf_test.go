package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// largeRuntimeState returns a runtime state whose baseline and candidate
// each hold hosts with ports open on every host, the shape a broad job
// stores in job_runtime.state_json.
func largeRuntimeState(hosts, ports int) model.JobState {
	snapshot := model.Snapshot{Scopes: []model.Scope{{Target: "198.18.0.0/16", Protocol: "tcp", Ports: "1-1024"}}}
	for index := 0; index < hosts; index++ {
		address := fmt.Sprintf("198.18.%d.%d", index/250, index%250+1)
		unit := model.Unit{Target: address, Protocol: "tcp", Addresses: []string{address}}
		observed := make([]model.PortObservation, 0, ports)
		for port := 0; port < ports; port++ {
			unit.Ports = append(unit.Ports, model.PortState{Port: 1000 + port, State: "open", Service: "http"})
			observed = append(observed, model.PortObservation{Port: 1000 + port, State: "open", Reason: "syn-ack", Verification: "confirmed", Service: &model.ServiceObservation{Name: "http", Product: "nginx", Version: "1.27.0", Method: "probed", Confidence: 10}})
		}
		snapshot.Units = append(snapshot.Units, unit)
		snapshot.Hosts = append(snapshot.Hosts, model.HostObservation{Address: address, AddressFamily: "IPv4", Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "1-1024", ScannedPortCount: 1024, Ports: observed}}})
		snapshot.HostStates = append(snapshot.HostStates, model.HostState{Address: address, State: "up"})
	}
	candidate := snapshot
	return model.JobState{Baseline: &snapshot, BaselineConfigHash: "hash", Candidate: &candidate, CandidateCount: 1, CandidateAttempts: 1}
}

// seedLargeRuntimeJobs writes jobs whose runtime rows hold the given state
// and whose compact metadata is current, as persistRuntimeTx leaves them.
// The baseline scan of each job has indexedHosts indexed host rows.
func seedLargeRuntimeJobs(tb testing.TB, s *Store, prefix string, jobs int, state model.JobState, indexedHosts int) []string {
	tb.Helper()
	ctx := context.Background()
	stamp := sqliteTimestamp(time.Now())
	ids := make([]string, 0, jobs)
	for index := 0; index < jobs; index++ {
		id := fmt.Sprintf("%s-%02d", prefix, index)
		scanID := "baseline-" + id
		state.BaselineScanID = scanID
		raw, err := json.Marshal(state)
		if err != nil {
			tb.Fatal(err)
		}
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO jobs(id,tenant_id,name,definition_json,created_at,updated_at) VALUES(?,?,?,'{}',?,?)`, []any{id, DefaultTenantID, id, stamp, stamp}},
			{`INSERT INTO scans(id,job_id,job,started_at,finished_at,status,config_hash,snapshot_json) VALUES(?,?,?,?,?,'success','hash','{}')`, []any{scanID, id, id, stamp, stamp}},
			{`INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?)`, []any{id, raw, stamp}},
			{`INSERT INTO job_runtime_meta(job_id,metadata_version,baseline_scan_id,baseline_config_hash,baseline_modified,projection_version,candidate_count,candidate_attempts,incomplete_candidate_attempts,pending_count,updated_at) VALUES(?,1,?,'hash',0,1,1,1,0,0,?)`, []any{id, scanID, stamp}},
		} {
			if _, err := s.DB.ExecContext(ctx, statement.sql, statement.args...); err != nil {
				tb.Fatal(err)
			}
		}
		for host := 0; host < indexedHosts; host++ {
			if _, err := s.DB.ExecContext(ctx, `INSERT INTO scan_hosts(scan_id,address,host_json) VALUES(?,?,'{}')`, scanID, fmt.Sprintf("198.18.%d.%d", host/250, host%250+1)); err != nil {
				tb.Fatal(err)
			}
		}
		ids = append(ids, id)
	}
	return ids
}

// limitReadValueLength leaves the store's read pool one connection that
// refuses to load any string or blob longer than limit bytes. A read path
// that loads a larger runtime JSON value, or passes it to a JSON function,
// then fails with "string or blob too big", while reading the other columns
// of the same row still works.
func limitReadValueLength(tb testing.TB, s *Store, limit int) {
	tb.Helper()
	s.ReadDB.SetMaxOpenConns(1)
	conn, err := s.ReadDB.Conn(context.Background())
	if err != nil {
		tb.Fatal(err)
	}
	defer conn.Close()
	if _, err := sqlite.Limit(conn, sqlite3.SQLITE_LIMIT_LENGTH, limit); err != nil {
		tb.Fatal(err)
	}
}

// metadataOnlySummaries reads only the compact runtime metadata of the
// tenant's jobs; it is the reference cost for the job list.
func metadataOnlySummaries(ctx context.Context, s *Store) (int, error) {
	rows, err := s.reader().QueryContext(ctx, `SELECT j.id,m.metadata_version,m.projection_version,m.baseline_scan_id,m.baseline_config_hash,m.baseline_modified,m.candidate_count,m.candidate_attempts,m.incomplete_candidate_attempts,m.pending_count,m.updated_at FROM jobs j LEFT JOIN job_runtime_meta m ON m.job_id=j.id WHERE j.tenant_id=?`, DefaultTenantID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
	}
	return count, rows.Err()
}

// TestRuntimeStateSummariesDoNotReadCurrentRuntimeJSON keeps the job list and
// job detail summaries independent of the size of the runtime JSON. Every
// job below has multi-megabyte runtime JSON, and the read pool cannot load a
// value of that size, so any read of it fails the summary. The summaries
// must come from the compact metadata and the indexed host tables instead:
// the indexed baseline scans, an accepted overlay in baseline_hosts, and a
// job that is still collecting its baseline, whose large candidate must not
// be parsed for a host count it does not have.
func TestRuntimeStateSummariesDoNotReadCurrentRuntimeJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	state := largeRuntimeState(400, 20)
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	const limit = 1 << 20
	if len(raw) < 3*limit {
		t.Fatalf("runtime JSON fixture is %d bytes, want several MiB", len(raw))
	}
	indexed := seedLargeRuntimeJobs(t, s, "indexed", 3, state, 7)
	modified := seedLargeRuntimeJobs(t, s, "modified", 1, state, 0)[0]
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_runtime_meta SET baseline_modified=1 WHERE job_id=?`, modified); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"198.18.0.1", "198.18.0.2"} {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO baseline_hosts(job_id,address,host_json) VALUES(?,?,'{}')`, modified, address); err != nil {
			t.Fatal(err)
		}
	}
	collecting := seedLargeRuntimeJobs(t, s, "collecting", 1, state, 0)[0]
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_runtime_meta SET baseline_scan_id='',projection_version=0 WHERE job_id=?`, collecting); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{modified: 2, collecting: 0}
	for _, id := range indexed {
		want[id] = 7
	}

	limitReadValueLength(t, s, limit)
	tenant := defaultTenant(s)
	if _, err := tenant.RuntimeState(ctx, indexed[0]); err == nil || !strings.Contains(err.Error(), "too big") {
		t.Fatalf("RuntimeState under the read limit = %v, want the limit to refuse the runtime JSON", err)
	}
	summaries, err := tenant.RuntimeStateSummaries(ctx, false)
	if err != nil {
		t.Fatalf("RuntimeStateSummaries read the runtime JSON: %v", err)
	}
	if len(summaries) != len(want) {
		t.Fatalf("summaries = %#v, want %d jobs", summaries, len(want))
	}
	for id, hosts := range want {
		summary, err := tenant.RuntimeStateSummary(ctx, id)
		if err != nil {
			t.Fatalf("RuntimeStateSummary(%s) read the runtime JSON: %v", id, err)
		}
		if summaries[id] != summary {
			t.Errorf("batched summary of %s = %#v, single summary %#v", id, summaries[id], summary)
		}
		if summary.BaselineHostCount != hosts || summary.HasBaseline != (id != collecting) {
			t.Errorf("summary of %s = %#v, want %d baseline hosts", id, summary, hosts)
		}
	}

	// The list costs about as much as reading the metadata alone. The
	// bound is loose so that it holds on a slow or busy machine, but the
	// earlier statement, which evaluated JSON functions on every runtime
	// row, took seconds per job on rows of this size.
	fastest := func(run func() error) time.Duration {
		best := time.Duration(1<<63 - 1)
		for range 5 {
			started := time.Now()
			if err := run(); err != nil {
				t.Fatal(err)
			}
			if elapsed := time.Since(started); elapsed < best {
				best = elapsed
			}
		}
		return best
	}
	list := fastest(func() error { _, err := tenant.RuntimeStateSummaries(ctx, false); return err })
	metadata := fastest(func() error { _, err := metadataOnlySummaries(ctx, s); return err })
	if list > 50*metadata+250*time.Millisecond {
		t.Fatalf("RuntimeStateSummaries took %s, metadata alone %s", list, metadata)
	}
}

// BenchmarkRuntimeStateSummariesLargeRuntimeJSON compares the job list, the
// job detail summary, a full runtime decode, and a baseline page with
// reading the metadata alone, for ten jobs with about 5.6 MB of runtime
// JSON each.
func BenchmarkRuntimeStateSummariesLargeRuntimeJSON(b *testing.B) {
	ctx := context.Background()
	s, err := Open(freshTestDatabasePath(b))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close() })
	ids := seedLargeRuntimeJobs(b, s, "large", 10, largeRuntimeState(600, 20), 8)
	tenant := defaultTenant(s)
	b.Run("summaries", func(b *testing.B) {
		for b.Loop() {
			if _, err := tenant.RuntimeStateSummaries(ctx, false); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("summary", func(b *testing.B) {
		for b.Loop() {
			if _, err := tenant.RuntimeStateSummary(ctx, ids[0]); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("state", func(b *testing.B) {
		for b.Loop() {
			if _, err := tenant.RuntimeState(ctx, ids[0]); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("baseline-page", func(b *testing.B) {
		for b.Loop() {
			if _, err := tenant.RuntimeBaselinePage(ctx, ids[0], 10, 0); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("metadata-only", func(b *testing.B) {
		for b.Loop() {
			if _, err := metadataOnlySummaries(ctx, s); err != nil {
				b.Fatal(err)
			}
		}
	})
}
