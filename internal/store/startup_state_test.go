package store

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHealthStatusReportsMigrationProgressAsHealthyStarting(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(context.Background(), `UPDATE startup_state SET state='migrating',owner='migration/test',phase='host-search',started_at=?,updated_at=?,progress=500,total=1000,last_error='' WHERE id=1`, now, now); err != nil {
		t.Fatal(err)
	}

	status, err := s.HealthStatus(context.Background())
	if err != nil {
		t.Fatalf("active migration reported unhealthy: %v", err)
	}
	if status.Status != "starting" || status.Phase != "host-search" || status.Progress != 500 || status.Total != 1000 {
		t.Fatalf("migration health status = %#v", status)
	}
	if err := s.Healthy(context.Background()); err != nil {
		t.Fatalf("Healthy rejected active migration: %v", err)
	}
}

func TestHealthStatusRejectsStaleOrFailedMigration(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	old := time.Now().UTC().Add(-migrationHeartbeatTimeout - time.Second).Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(context.Background(), `UPDATE startup_state SET state='migrating',updated_at=?,last_error='' WHERE id=1`, old); err != nil {
		t.Fatal(err)
	}
	if err := s.Healthy(context.Background()); err == nil || !strings.Contains(err.Error(), "migration heartbeat is stale") {
		t.Fatalf("stale migration health error = %v", err)
	}

	if _, err := s.DB.ExecContext(context.Background(), `UPDATE startup_state SET state='failed',updated_at=?,last_error='index rebuild failed' WHERE id=1`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := s.Healthy(context.Background()); err == nil || !strings.Contains(err.Error(), "index rebuild failed") {
		t.Fatalf("failed migration health error = %v", err)
	}
}

func TestHealthStatusFallsBackToDaemonLeaseWhenReady(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.AcquireLease(context.Background(), "health-test"); err != nil {
		t.Fatal(err)
	}
	status, err := s.HealthStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "ready" {
		t.Fatalf("ready health status = %#v", status)
	}

	if _, err := s.DB.ExecContext(context.Background(), `UPDATE startup_state SET state='ready',last_error='' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := s.Healthy(context.Background()); err != nil {
		t.Fatalf("ready health unexpectedly failed: %v", err)
	}
}

func TestOpenWithLoggerRoutesMigrationProgress(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelInfo}))
	s, err := OpenWithLogger(filepath.Join(t.TempDir(), "edgewatch.db"), logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	logs := output.String()
	if !strings.Contains(logs, "database migration started") || !strings.Contains(logs, "database migration completed") {
		t.Fatalf("configured migration logger output = %q", logs)
	}
}
