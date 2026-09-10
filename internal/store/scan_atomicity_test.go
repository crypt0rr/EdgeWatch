package store

import (
	"context"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestSaveScanRollsBackScanAndHostIndexesOnHostFailure(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_scan_host BEFORE INSERT ON scan_hosts
WHEN NEW.address='198.51.100.2'
BEGIN
  SELECT RAISE(ABORT, 'injected host failure');
END`); err != nil {
		t.Fatal(err)
	}

	scan := model.Scan{
		ID:         "atomic-host-failure",
		Job:        "edge",
		StartedAt:  time.Unix(100, 0).UTC(),
		FinishedAt: time.Unix(100, 0).UTC(),
		Status:     "success",
		Snapshot: model.Snapshot{Hosts: []model.HostObservation{
			{Address: "198.51.100.1", AddressFamily: "IPv4"},
			{Address: "198.51.100.2", AddressFamily: "IPv4"},
		}},
	}
	if err := s.SaveScan(ctx, scan); err == nil {
		t.Fatal("SaveScan unexpectedly succeeded")
	}

	for _, table := range []string{"scans", "scan_hosts", "latest_scan_hosts"} {
		var count int
		if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE "+map[string]string{
			"scans":             "id='atomic-host-failure'",
			"scan_hosts":        "scan_id='atomic-host-failure'",
			"latest_scan_hosts": "address IN ('198.51.100.1','198.51.100.2')",
		}[table]).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("%s retained %d rows after failed SaveScan", table, count)
		}
	}
}
