package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestNewStoreEnablesIncrementalAutoVacuum(t *testing.T) {
	s := openTestStore(t)
	var mode int
	if err := s.DB.QueryRowContext(context.Background(), "PRAGMA auto_vacuum").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != 2 { // SQLITE_AUTOVACUUM_INCREMENTAL
		t.Fatalf("auto_vacuum mode = %d, want incremental (2)", mode)
	}
}

func TestPruneOptimizesFTSAndReclaimsPages(t *testing.T) {
	ctx := context.Background()
	database := filepath.Join(t.TempDir(), "retention.db")
	s, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	old := time.Now().UTC().Add(-48 * time.Hour)
	for i := 0; i < 24; i++ {
		address := fmt.Sprintf("198.51.100.%d", i+1)
		host := model.HostObservation{
			Address: address,
			Status:  "up",
			Protocols: []model.ProtocolObservation{{
				Protocol:     "tcp",
				ScannedPorts: "1-65535",
				Ports:        []model.PortObservation{{Port: 443, State: "open"}},
			}},
		}
		if err := s.SaveScan(ctx, model.Scan{
			ID:         fmt.Sprintf("expired-%02d", i),
			Job:        "retention-maintenance",
			StartedAt:  old,
			FinishedAt: old,
			Status:     "success",
			Snapshot:   model.Snapshot{Hosts: []model.HostObservation{host}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	var beforePages int64
	if err := s.DB.QueryRowContext(ctx, "PRAGMA page_count").Scan(&beforePages); err != nil {
		t.Fatal(err)
	}
	stats, err := s.PruneWithStats(ctx, time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Scans != 24 || !stats.FTSOptimized {
		t.Fatalf("retention stats = %#v, want all scans removed and FTS optimized", stats)
	}
	var indexed int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM scan_host_search").Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if indexed != 0 {
		t.Fatalf("expired FTS rows = %d, want 0", indexed)
	}
	var afterPages int64
	if err := s.DB.QueryRowContext(ctx, "PRAGMA page_count").Scan(&afterPages); err != nil {
		t.Fatal(err)
	}
	if afterPages >= beforePages {
		t.Fatalf("page count after retention = %d, before = %d; incremental vacuum did not reclaim storage", afterPages, beforePages)
	}
}

func TestSearchMaintenanceHonorsCancellation(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "cancel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.maintainSearchIndexes(ctx); err == nil {
		t.Fatal("canceled maintenance unexpectedly succeeded")
	}
}

func TestExistingDatabaseAutoVacuumModeIsPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("CREATE TABLE legacy (id INTEGER)"); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var mode int
	if err := s.DB.QueryRowContext(context.Background(), "PRAGMA auto_vacuum").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != 0 { // Existing files are not rewritten implicitly.
		t.Fatalf("legacy auto_vacuum mode = %d, want unchanged mode 0", mode)
	}
}
