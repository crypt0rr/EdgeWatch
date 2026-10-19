package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestMigration75BackfillsCompactScanEvidenceAndResumes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()
	scan := model.Scan{
		ID: "legacy-projection", Job: "legacy", StartedAt: now, FinishedAt: now, Status: "success",
		Snapshot: model.Snapshot{
			Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "443"}},
			Units:  []model.Unit{{Target: "edge.example", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open"}}}},
			Hosts:  []model.HostObservation{{Address: "192.0.2.4", SourceTargets: []string{"edge.example"}, Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", Status: "up", DiscoveryState: "up", Ports: []model.PortObservation{{Port: 443, State: "open", Service: &model.ServiceObservation{Name: "https"}}}}}}},
		},
	}
	if err := s.System().SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"coverage_summary_json", "results_unit_count", "results_json"} {
		if _, err := s.DB.ExecContext(ctx, `ALTER TABLE scans DROP COLUMN `+column); err != nil {
			t.Fatalf("reconstruct schema 74 without %s: %v", column, err)
		}
	}
	if _, err := s.DB.ExecContext(ctx, `PRAGMA user_version=74`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER reject_scan_projection BEFORE UPDATE OF results_json ON scans WHEN OLD.id='legacy-projection' BEGIN SELECT RAISE(ABORT,'injected projection failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := migrateContext(ctx, s.DB); err == nil || !strings.Contains(err.Error(), "injected projection failure") {
		t.Fatalf("migration with rejected projection update = %v", err)
	}
	if got := countRows(t, s.DB, `PRAGMA user_version`); got != 75 {
		t.Fatalf("schema after projection backfill failure = %d, want 75", got)
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TRIGGER reject_scan_projection`); err != nil {
		t.Fatal(err)
	}
	if err := migrateContext(ctx, s.DB); err != nil {
		t.Fatalf("resume schema 75 backfill: %v", err)
	}
	var resultsRaw, coverageRaw []byte
	var units int
	if err := s.DB.QueryRowContext(ctx, `SELECT results_json,results_unit_count,coverage_summary_json FROM scans WHERE id='legacy-projection'`).Scan(&resultsRaw, &units, &coverageRaw); err != nil {
		t.Fatal(err)
	}
	var results []model.Unit
	if err := json.Unmarshal(resultsRaw, &results); err != nil || units != 1 || len(results) != 1 || results[0].Target != "edge.example" {
		t.Fatalf("results projection = %#v count %d, err %v", results, units, err)
	}
	var coverage model.Snapshot
	if err := json.Unmarshal(coverageRaw, &coverage); err != nil || len(coverage.Scopes) != 1 || len(coverage.Hosts) != 1 || len(coverage.Hosts[0].Protocols) != 1 || len(coverage.Hosts[0].Protocols[0].Ports) != 0 {
		t.Fatalf("coverage projection = %#v, err %v; expected status and scope fields without port evidence", coverage, err)
	}
	page, err := defaultTenant(s).ListScanResultsPage(ctx, scan.ID, 10, 0)
	if err != nil || page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("results page after backfill = %#v, %v", page, err)
	}
}
