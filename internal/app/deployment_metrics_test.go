package app

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/sandbox"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestDeploymentMetricsInspectIdentityPoolAndAggregateOverdueJobs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, func(name string) config.Job {
		return config.Job{Name: name, Schedule: "* * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"}, TCP: &config.Protocol{Ports: "443", Mode: "connect", Engine: config.EngineNmap}}
	})
	a := f.app
	now := time.Now().UTC()
	old := now.Add(-10 * time.Minute).Format(time.RFC3339Nano)
	for _, id := range []string{f.jobA.ID, f.jobB.ID} {
		if _, err := f.db.DB.ExecContext(ctx, `UPDATE jobs SET created_at=? WHERE id=?`, old, id); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.ExecContext(ctx, `UPDATE job_silence_state SET eligible_at=? WHERE job_id=?`, old, id); err != nil {
			t.Fatal(err)
		}
	}
	a.Config.Backup.Directory = t.TempDir()
	if err := writeBackupStatusFile(BackupStatusPath(f.db.Path), BackupStatus{Directory: a.Config.Backup.Directory, LastSuccessAt: now.Add(-48 * time.Hour), ConsecutiveFailures: 2}); err != nil {
		t.Fatal(err)
	}
	a.sandbox = sandbox.NewEnforced()
	inspections := 0
	a.inspectScannerIdentities = func(ctx context.Context) (*sandbox.ScannerIdentityPoolStatus, error) {
		inspections++
		if _, ok := ctx.Deadline(); !ok {
			t.Error("scanner identity inspection had no deadline")
		}
		return &sandbox.ScannerIdentityPoolStatus{State: sandbox.StateEnforced, Active: 2, Quarantined: 1, InUseByOtherProcesses: 3, Free: 58}, nil
	}

	metrics := a.DeploymentMetrics(ctx, now)
	if metrics.Backups == nil || metrics.Backups.ConsecutiveFailures != 2 || metrics.Backups.LastSuccessAt.IsZero() {
		t.Fatalf("backup metrics = %+v", metrics.Backups)
	}
	if metrics.ScannerIdentities == nil || metrics.ScannerIdentities.Free != 58 || metrics.ScannerIdentities.Active != 2 {
		t.Fatalf("scanner identity metrics = %+v", metrics.ScannerIdentities)
	}
	if !metrics.JobsOverdueKnown || metrics.JobsOverdue != 2 {
		t.Fatalf("overdue jobs = %d, known=%v; want both units", metrics.JobsOverdue, metrics.JobsOverdueKnown)
	}
	if !metrics.StalledCyclesKnown || metrics.StalledCycles != 0 {
		t.Fatalf("stalled cycles = %d, known=%v; want known zero", metrics.StalledCycles, metrics.StalledCyclesKnown)
	}
	if inspections != 1 {
		t.Fatalf("scanner identity inspections = %d, want one bounded read", inspections)
	}
}

func TestMissingBackupStatusPreservesFailureUntilRecordedRecovery(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	a := f.app
	now := time.Now().UTC()
	a.Config.Backup.Directory = t.TempDir()
	statusPath := BackupStatusPath(f.db.Path)
	if err := writeBackupStatusFile(statusPath, BackupStatus{Directory: a.Config.Backup.Directory, ConsecutiveFailures: 2}); err != nil {
		t.Fatal(err)
	}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now); err != nil || recorded != 1 {
		t.Fatalf("initial failed backup = %d, %v; want one transition", recorded, err)
	}
	assertScheduledBackupAlertState(t, f.db, 1)

	if err := os.Remove(statusPath); err != nil {
		t.Fatal(err)
	}
	if metrics := a.DeploymentMetrics(ctx, now.Add(time.Minute)); metrics.Backups != nil {
		t.Fatalf("missing backup status was exported as a known zero: %+v", metrics.Backups)
	}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now.Add(time.Minute)); err != nil || recorded != 0 {
		t.Fatalf("missing backup status = %d, %v; want no transition", recorded, err)
	}
	assertScheduledBackupAlertState(t, f.db, 1)

	if err := writeBackupStatusFile(statusPath, BackupStatus{Directory: a.Config.Backup.Directory}); err != nil {
		t.Fatal(err)
	}
	metrics := a.DeploymentMetrics(ctx, now.Add(2*time.Minute))
	if metrics.Backups == nil || metrics.Backups.ConsecutiveFailures != 0 {
		t.Fatalf("recorded recovery metrics = %+v; want known zero failures", metrics.Backups)
	}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now.Add(2*time.Minute)); err != nil || recorded != 0 {
		t.Fatalf("recorded backup recovery = %d, %v; want a silent recovery", recorded, err)
	}
	assertScheduledBackupAlertState(t, f.db, 0)
}

func TestDeploymentMetricsBoundsScannerIdentityInspection(t *testing.T) {
	t.Parallel()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	a := f.app
	a.sandbox = sandbox.NewEnforced()
	inspectionCanceled := false
	a.inspectScannerIdentities = func(ctx context.Context) (*sandbox.ScannerIdentityPoolStatus, error) {
		<-ctx.Done()
		inspectionCanceled = errors.Is(ctx.Err(), context.DeadlineExceeded)
		return nil, ctx.Err()
	}
	started := time.Now()
	metrics := a.DeploymentMetrics(context.Background(), started)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("scanner identity inspection exceeded its deadline by too much: %s", elapsed)
	}
	if !inspectionCanceled {
		t.Fatal("scanner identity inspection did not observe the caller's deadline")
	}
	if metrics.ScannerIdentities != nil {
		t.Fatalf("timed-out scanner identity inspection was exported: %+v", metrics.ScannerIdentities)
	}
}

func assertScheduledBackupAlertState(t *testing.T, db *store.Store, want int) {
	t.Helper()
	var failing int
	if err := db.DB.QueryRowContext(context.Background(), `SELECT scheduled_backup_failing FROM platform_alert_state WHERE id=1`).Scan(&failing); err != nil || failing != want {
		t.Fatalf("scheduled backup alert state = %d, %v; want %d", failing, err, want)
	}
}
