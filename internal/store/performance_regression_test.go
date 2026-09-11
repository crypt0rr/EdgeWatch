package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

const seededPerformanceHostCount = 2048

// seedLatestHostsForPerformance creates a representative projection without
// relying on wall-clock thresholds. The test below then checks result bounds
// and query-plan ownership, which remain stable across CI hardware.
func seedLatestHostsForPerformance(t *testing.T, s *Store, count int) {
	t.Helper()
	tx, err := s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for i := 0; i < count; i++ {
		address := fmt.Sprintf("198.51.%d.%d", i/254, i%254+1)
		open := i%3 == 0
		ports := []model.PortObservation{}
		openCount := 0
		if open {
			ports = append(ports, model.PortObservation{Port: 443, State: "open"})
			openCount = 1
		}
		host := model.HostObservation{Address: address, AddressFamily: "IPv4", SourceTargets: []string{fmt.Sprintf("asset-%d.example", i%32)}, Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "1-1024", ScannedPortCount: 1024, Ports: ports}}}
		raw, err := json.Marshal(host)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO latest_scan_hosts(address,scan_id,job_id,job,finished_at,data_quality,address_family,source_targets_json,dns_names_json,host_json,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports) VALUES(?,?,?,?,?,'detailed','IPv4',?,?,?, ?,0,1,0,?,?,0,0)`, address, fmt.Sprintf("seed-scan-%d", i), "seed-job", "seed", now, fmt.Sprintf(`["asset-%d.example"]`, i%32), `[]`, raw, openCount, openCount, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestSeededPerformanceRegressionInvariants(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	seedLatestHostsForPerformance(t, s, seededPerformanceHostCount)

	hasOpen := true
	page, err := s.ListLatestScanHostsPage(ctx, "", "tcp", &hasOpen, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantOpen := (seededPerformanceHostCount + 2) / 3
	if page.Total != wantOpen || len(page.Items) != 50 {
		t.Fatalf("seeded host inventory = total %d/items %d, want total %d/items 50", page.Total, len(page.Items), wantOpen)
	}

	// Explain the exact page statement used by ListLatestScanHostsPage. The
	// maintained projection must answer inventory requests without joining or
	// ranking the retained scans/host-history tables.
	queries := latestScanHostsPageQueries("", "tcp", &hasOpen, 50, 0)
	rows, err := s.DB.QueryContext(ctx, `EXPLAIN QUERY PLAN `+queries.pageSQL, queries.pageArg...)
	if err != nil {
		t.Fatal(err)
	}
	var plan []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	joinedPlan := strings.ToLower(strings.Join(plan, " "))
	if !strings.Contains(joinedPlan, "latest_scan_hosts") || strings.Contains(joinedPlan, " scan_hosts ") || strings.Contains(joinedPlan, " scans ") {
		t.Fatalf("host inventory query plan escaped maintained projection: %v", plan)
	}

	// Public-dashboard lookups should remain set-based at a representative
	// selection size. One indexed scan supplies all selected addresses.
	job := model.Scan{ID: "seed-public-scan", JobID: "seed-public-job", Job: "seed-public", StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), Status: "success", Snapshot: model.Snapshot{Hosts: make([]model.HostObservation, 0, 256)}}
	selections := make([]PublicDashboardHost, 0, 200)
	for i := 0; i < 200; i++ {
		address := fmt.Sprintf("203.0.113.%d", i%254+1)
		job.Snapshot.Hosts = append(job.Snapshot.Hosts, model.HostObservation{Address: address, AddressFamily: "IPv4", Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "443", ScannedPortCount: 1, Ports: []model.PortObservation{{Port: 443, State: "open"}}}}})
		selections = append(selections, PublicDashboardHost{JobID: job.JobID, Address: address})
	}
	if err := s.SaveScan(ctx, job); err != nil {
		t.Fatal(err)
	}
	results, err := s.GetLatestSuccessfulJobHosts(ctx, selections)
	if err != nil || len(results) != len(selections) {
		t.Fatalf("seeded public-dashboard lookup = %d, %v; want %d", len(results), err, len(selections))
	}
}
