package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestRebuildLatestScanHostsWrapperRecreatesProjection(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	insertJobRows(t, s, "job-wrapper")
	scan := model.Scan{
		ID: "projection-wrapper", JobID: "job-wrapper", Job: "wrapper", StartedAt: time.Unix(100, 0).UTC(), FinishedAt: time.Unix(100, 0).UTC(), Status: "success",
		Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.90", AddressFamily: "IPv4", Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "443", ScannedPortCount: 1, Ports: []model.PortObservation{{Port: 443, State: "open"}}}}}}},
	}
	if err := s.System().SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM latest_scan_hosts`); err != nil {
		t.Fatal(err)
	}
	if err := s.rebuildLatestScanHosts(ctx); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := s.DB.QueryRowContext(ctx, `SELECT scan_id FROM latest_scan_hosts WHERE address=?`, scan.Snapshot.Hosts[0].Address).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != scan.ID {
		t.Fatalf("rebuilt projection scan = %q, want %q", got, scan.ID)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.rebuildLatestScanHosts(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled rebuild error = %v, want context.Canceled", err)
	}
}

func TestRepairLatestScanHostsCancellationAndRollback(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.repairLatestScanHosts(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled repair error = %v, want context.Canceled", err)
	}

	insertJobRows(t, s, "repair-rollback")
	address := fixtureHost(0).Address
	base := time.Date(2026, time.September, 20, 12, 0, 0, 0, time.UTC)
	for _, scan := range []model.Scan{
		fixtureScan("repair-old", "repair-rollback", "repair-rollback", base, []model.HostObservation{fixtureHost(0)}),
		fixtureScan("repair-new", "repair-rollback", "repair-rollback", base.Add(time.Minute), []model.HostObservation{fixtureHost(0)}),
	} {
		if err := s.System().SaveScan(ctx, scan); err != nil {
			t.Fatalf("save %s: %v", scan.ID, err)
		}
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM scans WHERE id='repair-new'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER reject_latest_host_repair BEFORE INSERT ON latest_scan_hosts BEGIN SELECT RAISE(ABORT, 'temporary projection failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.repairLatestScanHosts(ctx); err == nil {
		t.Fatal("repair insert failure was ignored")
	}
	var scanID string
	if err := s.DB.QueryRowContext(ctx, `SELECT scan_id FROM latest_scan_hosts WHERE tenant_id=? AND address=?`, DefaultTenantID, address).Scan(&scanID); err != nil {
		t.Fatal(err)
	}
	if scanID != "repair-new" {
		t.Fatalf("failed repair partially deleted the projection row: scan_id=%q", scanID)
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TRIGGER reject_latest_host_repair`); err != nil {
		t.Fatal(err)
	}
	if err := s.repairLatestScanHosts(ctx); err != nil {
		t.Fatalf("repair after removing transient failure: %v", err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT scan_id FROM latest_scan_hosts WHERE tenant_id=? AND address=?`, DefaultTenantID, address).Scan(&scanID); err != nil {
		t.Fatal(err)
	}
	if scanID != "repair-old" {
		t.Fatalf("repaired projection scan = %q, want retained older scan", scanID)
	}
}
