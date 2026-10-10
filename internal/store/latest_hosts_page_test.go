package store

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// seedLatestHostInventory writes count latest-host rows of about hostBytes
// of host_json each in one statement, so a large inventory is quick to
// build. Every tenth row belongs to an archived job.
func seedLatestHostInventory(t *testing.T, s *Store, count, hostBytes int) {
	t.Helper()
	ctx := context.Background()
	insertJobRows(t, s, "inventory-job", "inventory-archived")
	stamp := sqliteTimestamp(time.Now())
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE jobs SET archived=1 WHERE id='inventory-archived'`, nil},
		{`INSERT INTO scans(id,job_id,job,started_at,finished_at,status,config_hash,snapshot_json,tenant_id) VALUES('inventory-scan','inventory-job','inventory-job',?,?,'success','hash','{}',?)`, []any{stamp, stamp, DefaultTenantID}},
		// Addresses go out of order with the job, so neither segment is a
		// contiguous run of the primary key.
		{`WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i+1<?)
INSERT INTO latest_scan_hosts(tenant_id,address,scan_id,job_id,job,finished_at,host_json,tcp_present,tcp_open_ports,open_ports)
SELECT ?,printf('10.%d.%d.%d',i/65536,(i/256)%256,i%256),'inventory-scan',
 CASE WHEN i%10=3 THEN 'inventory-archived' ELSE 'inventory-job' END,
 CASE WHEN i%10=3 THEN 'inventory-archived' ELSE 'inventory-job' END,?,
 printf('{"address":"10.%d.%d.%d","status":"up","dns_names":["%s"]}',i/65536,(i/256)%256,i%256,substr(hex(zeroblob(?)),1,?)),
 1,i%2,i%2
FROM n`, []any{count, DefaultTenantID, stamp, hostBytes / 2, hostBytes}},
	} {
		if _, err := s.DB.ExecContext(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

// TestLatestScanHostsPagesReadTheInventoryInIndexOrder keeps a Hosts page
// from sorting the tenant's whole inventory: each segment of a page reads
// latest_scan_hosts in primary key order, so no page builds a temporary
// B-tree. SQLite plans the statement the same way for any number of rows.
func TestLatestScanHostsPagesReadTheInventoryInIndexOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	seedLatestHostInventory(t, s, 2000, 512)
	queries := latestScanHostsPageQueries(DefaultTenantID, "", "", nil)
	for _, archived := range []bool{false, true} {
		statement, args := queries.segment(archived, 50, 0)
		if plan := queryPlan(t, s.DB, statement, args...); strings.Contains(strings.ToUpper(plan), "TEMP B-TREE") {
			t.Errorf("archived=%t segment sorts the inventory: %s", archived, plan)
		}
	}
	page, err := defaultTenant(s).ListLatestScanHostsPage(ctx, "", "", nil, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2000 || len(page.Items) != 50 || page.Items[0].Host.Address != "10.0.0.0" || page.Items[0].Archived {
		t.Fatalf("first inventory page = total %d, %d items", page.Total, len(page.Items))
	}
}

// TestLatestScanHostsFirstPageOfALargeInventoryReadsOnlyThePage times the
// first page of a 65,000-host inventory with about 3 KB of host_json per
// host. It costs about as much as reading 50 hosts by their key; the
// statement that sorted every row, host_json included, took several hundred
// times as long. The race detector slows SQLite down too much to build the
// inventory, so the test runs only without it.
func TestLatestScanHostsFirstPageOfALargeInventoryReadsOnlyThePage(t *testing.T) {
	if raceEnabled {
		t.Skip("the 65,000-host inventory takes minutes to build under the race detector")
	}
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	seedLatestHostInventory(t, s, 65000, 3000)
	fastest := func(statement string, args ...any) time.Duration {
		best := time.Duration(1<<63 - 1)
		for range 3 {
			started := time.Now()
			if count := readRows(ctx, t, s, statement, args...); count != 50 {
				t.Fatalf("%d rows, want 50", count)
			}
			if elapsed := time.Since(started); elapsed < best {
				best = elapsed
			}
		}
		return best
	}
	statement, args := latestScanHostsPageQueries(DefaultTenantID, "", "", nil).segment(false, 50, 0)
	page := fastest(statement, args...)
	key := fastest(`SELECT h.scan_id,h.address,h.data_quality,h.host_json,h.job_id,h.job,h.finished_at FROM latest_scan_hosts h WHERE h.tenant_id=? ORDER BY h.address LIMIT 50`, DefaultTenantID)
	// The bound is loose so that it holds on a slow or busy machine.
	if page > 20*key+50*time.Millisecond {
		t.Fatalf("first inventory page took %s, a page by key %s", page, key)
	}
}

// readRows reads every row of statement and returns how many it read.
func readRows(ctx context.Context, t *testing.T, s *Store, statement string, args ...any) int {
	t.Helper()
	rows, err := s.reader().QueryContext(ctx, statement, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestLatestScanHostsPagesListCurrentJobsBeforeArchivedOnes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	seedLatestHostInventory(t, s, 40, 64)
	tenant := defaultTenant(s)
	all, err := tenant.ListLatestScanHosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 40 {
		t.Fatalf("full inventory = %d hosts", len(all))
	}
	var current, archived []string
	for index := 0; index < 40; index++ {
		address := fmt.Sprintf("10.0.0.%d", index)
		if index%10 == 3 {
			archived = append(archived, address)
		} else {
			current = append(current, address)
		}
	}
	// Addresses sort as text within each segment.
	sortText := func(values []string) []string {
		sorted := append([]string(nil), values...)
		for i := range sorted {
			for j := i + 1; j < len(sorted); j++ {
				if sorted[j] < sorted[i] {
					sorted[i], sorted[j] = sorted[j], sorted[i]
				}
			}
		}
		return sorted
	}
	want := append(sortText(current), sortText(archived)...)
	var got []string
	for index, host := range all {
		got = append(got, host.Host.Address)
		if host.Archived != (index >= len(current)) || (host.Archived && host.JobID != "inventory-archived") {
			t.Errorf("host %s at %d: archived %t, job %q", host.Host.Address, index, host.Archived, host.JobID)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("full inventory order = %v, want %v", got, want)
	}
	// Pages of seven cross the boundary between the segments at 36.
	var paged []string
	for offset := 0; offset < 45; offset += 7 {
		page, err := tenant.ListLatestScanHostsPage(ctx, "", "", nil, 7, offset)
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != 40 {
			t.Fatalf("page at %d has total %d", offset, page.Total)
		}
		for _, host := range page.Items {
			paged = append(paged, host.Host.Address)
		}
	}
	if !reflect.DeepEqual(paged, want) {
		t.Fatalf("paged inventory = %v, want %v", paged, want)
	}
	// A filter applies to both segments: the odd rows have an open port.
	hasOpen := true
	page, err := tenant.ListLatestScanHostsPage(ctx, "", "tcp", &hasOpen, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 20 || len(page.Items) != 20 || !page.Items[len(page.Items)-1].Archived {
		t.Fatalf("open hosts = total %d, %d items", page.Total, len(page.Items))
	}
}
