package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestMigration58RebuildsPrioritizedHostSearchIndexes(t *testing.T) {
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
	if version := countRows(t, upgraded.DB, `PRAGMA user_version`); version != 58 {
		t.Fatalf("schema version = %d, want 58", version)
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
