package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestNewStoreEnablesIncrementalAutoVacuum(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
		if err := s.System().SaveScan(ctx, model.Scan{
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
	stats, err := s.System().PruneWithStats(ctx, time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Scans != 23 || !stats.FTSOptimized {
		t.Fatalf("retention stats = %#v, want 23 old scans removed and FTS optimized", stats)
	}
	var indexed int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM scan_host_search").Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if indexed != 1 {
		t.Fatalf("retained latest FTS rows = %d, want 1", indexed)
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
	t.Parallel()
	s, err := Open(freshTestDatabasePath(t))
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

func TestSearchMaintenanceReportsErrorsAndDefersBudgetExpiry(t *testing.T) {
	t.Parallel()
	s, err := Open(freshTestDatabasePath(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.maintainSearchIndexes(context.Background()); err == nil {
		t.Fatal("closed database maintenance unexpectedly succeeded")
	}

	maintenanceCtx, cancel := context.WithCancel(context.Background())
	cancel()
	stats := searchMaintenanceStats{}
	if err := maintenanceError(context.Background(), maintenanceCtx, &stats, "test operation", errors.New("busy")); err != nil {
		t.Fatalf("expired maintenance budget returned an error: %v", err)
	}
	if !stats.Deferred {
		t.Fatal("expired maintenance budget was not marked deferred")
	}
	activeCtx, activeCancel := context.WithCancel(context.Background())
	activeCancel()
	stats = searchMaintenanceStats{}
	if err := maintenanceError(activeCtx, context.Background(), &stats, "test operation", errors.New("canceled")); err == nil {
		t.Fatal("caller cancellation was swallowed")
	}
}

func TestRetentionProtectionPreparationReportsClosedDatabase(t *testing.T) {
	t.Parallel()
	s, err := Open(freshTestDatabasePath(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().deleteScanRetentionBatches(context.Background(), time.Now().UTC().Format(time.RFC3339Nano), defaultRetentionOptions); err == nil {
		t.Fatal("closed database retention protection unexpectedly succeeded")
	}
}

func TestExistingDatabaseAutoVacuumModeIsPreserved(t *testing.T) {
	t.Parallel()
	// The file holds a table before the first open, the startup state that a
	// start which stopped before the baseline committed leaves.
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(startupStateSchema); err != nil {
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
