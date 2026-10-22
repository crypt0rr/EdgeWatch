package app

import (
	"context"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/sandbox"
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
