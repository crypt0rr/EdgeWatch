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
	scan := model.Scan{
		ID: "projection-wrapper", JobID: "job-wrapper", Job: "wrapper", StartedAt: time.Unix(100, 0).UTC(), FinishedAt: time.Unix(100, 0).UTC(), Status: "success",
		Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: "198.51.100.90", AddressFamily: "IPv4", Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "443", ScannedPortCount: 1, Ports: []model.PortObservation{{Port: 443, State: "open"}}}}}}},
	}
	if err := s.SaveScan(ctx, scan); err != nil {
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
