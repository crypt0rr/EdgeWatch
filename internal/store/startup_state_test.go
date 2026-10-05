package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHealthStatusReportsMigrationProgressAsHealthyStarting(t *testing.T) {
	t.Parallel()
	s, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(context.Background(), `UPDATE startup_state SET state='migrating',owner='migration/test',phase='host-search',started_at=?,updated_at=?,progress=500,total=1000,last_error='' WHERE id=1`, now, now); err != nil {
		t.Fatal(err)
	}

	status, err := s.System().HealthStatus(context.Background())
	if err != nil {
		t.Fatalf("active migration reported unhealthy: %v", err)
	}
	if status.Status != "starting" || status.Phase != "host-search" || status.Progress != 500 || status.Total != 1000 {
		t.Fatalf("migration health status = %#v", status)
	}
	if err := s.System().Healthy(context.Background()); err != nil {
		t.Fatalf("Healthy rejected active migration: %v", err)
	}
}

func TestHealthStatusRejectsStaleOrFailedMigration(t *testing.T) {
	t.Parallel()
	s, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	old := time.Now().UTC().Add(-migrationHeartbeatTimeout - time.Second).Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(context.Background(), `UPDATE startup_state SET state='migrating',updated_at=?,last_error='' WHERE id=1`, old); err != nil {
		t.Fatal(err)
	}
	if err := s.System().Healthy(context.Background()); err == nil || !strings.Contains(err.Error(), "migration heartbeat is stale") {
		t.Fatalf("stale migration health error = %v", err)
	}

	if _, err := s.DB.ExecContext(context.Background(), `UPDATE startup_state SET state='failed',updated_at=?,last_error='index rebuild failed' WHERE id=1`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := s.System().Healthy(context.Background()); err == nil || !strings.Contains(err.Error(), "index rebuild failed") {
		t.Fatalf("failed migration health error = %v", err)
	}
}

func TestHealthStatusFallsBackToDaemonLeaseWhenReady(t *testing.T) {
	t.Parallel()
	s, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.System().AcquireLease(context.Background(), "health-test"); err != nil {
		t.Fatal(err)
	}
	status, err := s.System().HealthStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "ready" {
		t.Fatalf("ready health status = %#v", status)
	}

	if _, err := s.DB.ExecContext(context.Background(), `UPDATE startup_state SET state='ready',last_error='' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := s.System().Healthy(context.Background()); err != nil {
		t.Fatalf("ready health unexpectedly failed: %v", err)
	}
}

func TestHealthStatusNamesMissingDaemonLeaseAfterReleaseAndRestore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	checkMissingHeartbeat := func(t *testing.T, s *Store) {
		t.Helper()
		_, err := s.System().HealthStatus(ctx)
		if err == nil || errors.Is(err, sql.ErrNoRows) || !strings.Contains(err.Error(), "no daemon heartbeat recorded; the daemon is not running") {
			t.Fatalf("health error = %v, want a named missing-daemon-heartbeat error", err)
		}
	}

	t.Run("after graceful lease release", func(t *testing.T) {
		t.Parallel()
		s, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.System().AcquireLease(ctx, "health-test"); err != nil {
			t.Fatal(err)
		}
		if err := s.System().ReleaseLease(ctx, "health-test"); err != nil {
			t.Fatal(err)
		}
		checkMissingHeartbeat(t, s)
	})

	t.Run("after restore clears copied lease", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		source := filepath.Join(dir, "source.db")
		createRestoreFixture(t, source, "source")
		live, err := Open(source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := live.System().AcquireDaemonLease(ctx, "backup-daemon"); err != nil {
			live.Close()
			t.Fatal(err)
		}
		backup, err := live.Backup(ctx, filepath.Join(dir, "backup.db"))
		if closeErr := live.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if err != nil {
			t.Fatal(err)
		}

		destination := filepath.Join(dir, "restored.db")
		if _, err := Restore(ctx, backup, destination, RestoreOptions{}); err != nil {
			t.Fatalf("restore: %v", err)
		}
		restored, err := Open(destination)
		if err != nil {
			t.Fatal(err)
		}
		defer restored.Close()
		checkMissingHeartbeat(t, restored)
	})
}

func TestOpenWithLoggerRoutesMigrationProgress(t *testing.T) {
	t.Parallel()
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
