package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
	if !metrics.BackupsEnabled || !metrics.BackupStatusKnown || metrics.Backups == nil || metrics.Backups.ConsecutiveFailures != 2 || metrics.Backups.LastSuccessAt.IsZero() {
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
	a.Config.Backup.Schedule = "0 3 * * *"
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
	if metrics := a.DeploymentMetrics(ctx, now.Add(time.Minute)); !metrics.BackupsEnabled || metrics.BackupStatusKnown || metrics.Backups != nil {
		t.Fatalf("missing backup status metrics = %+v; want enabled and unknown", metrics)
	}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now.Add(time.Minute)); err != nil || recorded != 0 {
		t.Fatalf("missing backup status = %d, %v; want no transition", recorded, err)
	}
	assertScheduledBackupAlertState(t, f.db, 1)

	// The worker can persist the configured directory before its first run.
	// That status says nothing about whether a backup has succeeded, so it
	// must not clear the durable failure alert.
	if err := writeBackupStatusFile(statusPath, BackupStatus{Directory: a.Config.Backup.Directory}); err != nil {
		t.Fatal(err)
	}
	a.backupWait = func(context.Context, time.Time) bool { return false }
	<-a.startBackupWorker(ctx)
	if metrics := a.DeploymentMetrics(ctx, now.Add(2*time.Minute)); !metrics.BackupsEnabled || metrics.BackupStatusKnown || metrics.Backups != nil {
		t.Fatalf("pre-run backup status metrics = %+v; want enabled and unknown", metrics)
	}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now.Add(2*time.Minute)); err != nil || recorded != 0 {
		t.Fatalf("pre-run backup status = %d, %v; want no transition", recorded, err)
	}
	assertScheduledBackupAlertState(t, f.db, 1)

	if err := writeBackupStatusFile(statusPath, BackupStatus{
		Directory:     a.Config.Backup.Directory,
		LastSuccessAt: now.Add(3 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if metrics := a.DeploymentMetrics(ctx, now.Add(3*time.Minute)); !metrics.BackupsEnabled || metrics.BackupStatusKnown || metrics.Backups != nil {
		t.Fatalf("incomplete backup success metrics = %+v; want enabled and unknown", metrics)
	}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now.Add(3*time.Minute)); err != nil || recorded != 0 {
		t.Fatalf("incomplete backup success = %d, %v; want no transition", recorded, err)
	}
	assertScheduledBackupAlertState(t, f.db, 1)

	if err := writeBackupStatusFile(statusPath, BackupStatus{
		Directory:     a.Config.Backup.Directory,
		LastSuccessAt: now.Add(4 * time.Minute),
		LastBackup:    scheduledBackupPrefix + now.Add(4*time.Minute).Format(scheduledBackupTimeLayout) + ".db",
	}); err != nil {
		t.Fatal(err)
	}
	metrics := a.DeploymentMetrics(ctx, now.Add(4*time.Minute))
	if !metrics.BackupsEnabled || !metrics.BackupStatusKnown || metrics.Backups == nil || metrics.Backups.ConsecutiveFailures != 0 {
		t.Fatalf("recorded recovery metrics = %+v; want known zero failures", metrics.Backups)
	}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now.Add(4*time.Minute)); err != nil || recorded != 0 {
		t.Fatalf("recorded backup recovery = %d, %v; want a silent recovery", recorded, err)
	}
	assertScheduledBackupAlertState(t, f.db, 0)
}

func TestDeploymentMetricsTreatsUnreadableBackupStatusAsUnknown(t *testing.T) {
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
	if err := os.WriteFile(statusPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if metrics := a.DeploymentMetrics(ctx, now.Add(time.Minute)); !metrics.BackupsEnabled || metrics.BackupStatusKnown || metrics.Backups != nil {
		t.Fatalf("unreadable backup status metrics = %+v; want enabled and unknown", metrics)
	}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now.Add(time.Minute)); err != nil || recorded != 0 {
		t.Fatalf("unreadable backup status = %d, %v; want no transition", recorded, err)
	}
	assertScheduledBackupAlertState(t, f.db, 1)
}

func TestNilApplicationOperationalMetricsAreEmpty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var nilApp *App
	if got := nilApp.deploymentHealthObservation(ctx, time.Now()); got != (deploymentHealthObservation{}) {
		t.Fatalf("nil-app observation = %+v; want empty", got)
	}
	if got := nilApp.DeploymentMetrics(ctx, time.Now()); got != (DeploymentMetrics{}) {
		t.Fatalf("nil-app metrics = %+v; want empty", got)
	}
	if active, stalled := nilApp.ScheduledRunSkips(); active != 0 || stalled != 0 {
		t.Fatalf("nil-app scheduled skips = %d, %d; want zero", active, stalled)
	}
	if count, err := nilApp.CountOverdueJobs(ctx, time.Now()); count != 0 || err != nil {
		t.Fatalf("nil-app overdue jobs = %d, %v; want zero, nil", count, err)
	}
	if count, err := nilApp.RecordDeploymentOperationalHealth(ctx, time.Now()); count != 0 || err != nil {
		t.Fatalf("nil-app health transitions = %d, %v; want zero, nil", count, err)
	}

	empty := &App{}
	if got := empty.deploymentHealthObservation(ctx, time.Now()); got != (deploymentHealthObservation{}) {
		t.Fatalf("uninitialized observation = %+v; want empty", got)
	}
	if got := empty.DeploymentMetrics(ctx, time.Now()); got != (DeploymentMetrics{}) {
		t.Fatalf("uninitialized metrics = %+v; want empty", got)
	}
	if count, err := empty.CountOverdueJobs(ctx, time.Now()); count != 0 || err != nil {
		t.Fatalf("uninitialized overdue jobs = %d, %v; want zero, nil", count, err)
	}
	if count, err := empty.RecordDeploymentOperationalHealth(ctx, time.Now()); count != 0 || err != nil {
		t.Fatalf("uninitialized health transitions = %d, %v; want zero, nil", count, err)
	}
}

func TestOffScannerSandboxClearsCapacityAlert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	a := f.app
	a.Config.Scheduler.MaxConcurrent = 1
	a.sandbox = sandbox.NewEnforced()
	a.inspectScannerIdentities = func(context.Context) (*sandbox.ScannerIdentityPoolStatus, error) {
		return &sandbox.ScannerIdentityPoolStatus{State: sandbox.StateEnforced, MaxParallel: 64, Quarantined: 64}, nil
	}
	now := time.Now().UTC()
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now); err != nil || recorded != 1 {
		t.Fatalf("low identity capacity = %d, %v; want one alert transition", recorded, err)
	}

	a.sandbox = sandbox.InspectScanner(sandbox.Options{Mode: sandbox.ModeOff})
	if metrics := a.DeploymentMetrics(ctx, now.Add(time.Minute)); metrics.ScannerIdentities != nil {
		t.Fatalf("disabled identity pool was exported as a capacity metric: %+v", metrics.ScannerIdentities)
	}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now.Add(time.Minute)); err != nil || recorded != 0 {
		t.Fatalf("disabled identity pool recovery = %d, %v; want a silent recovery", recorded, err)
	}
	var low int
	if err := f.db.DB.QueryRowContext(ctx, `SELECT scanner_identity_pool_low FROM platform_alert_state WHERE id=1`).Scan(&low); err != nil || low != 0 {
		t.Fatalf("scanner identity low-capacity state = %d, %v; want recovery", low, err)
	}
}

func TestDeploymentMetricsKeepDatabaseErrorsUnknown(t *testing.T) {
	t.Parallel()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	a := f.app
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	metrics := a.DeploymentMetrics(canceled, time.Now().UTC())
	if metrics.JobsOverdueKnown || metrics.StalledCyclesKnown {
		t.Fatalf("metrics from a canceled database inspection were known: %+v", metrics)
	}
	if _, err := a.CountOverdueJobs(canceled, time.Now().UTC()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled overdue-job count error = %v; want context.Canceled", err)
	}

	a.Config.Backup.Directory = t.TempDir()
	if err := writeBackupStatusFile(BackupStatusPath(f.db.Path), BackupStatus{Directory: a.Config.Backup.Directory, ConsecutiveFailures: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RecordDeploymentOperationalHealth(canceled, time.Now().UTC()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled backup-health write error = %v; want context.Canceled", err)
	}

	a.Config.Backup = config.Backup{}
	a.sandbox = sandbox.InspectScanner(sandbox.Options{Mode: sandbox.ModeOff})
	if _, err := a.RecordDeploymentOperationalHealth(canceled, time.Now().UTC()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled identity-health write error = %v; want context.Canceled", err)
	}
}

func TestChangedBackupDirectoryPreservesFailureUntilRecordedRecovery(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTwoTenants(t, schedulerFake{}, lifecycleJob)
	a := f.app
	now := time.Now().UTC()
	oldDirectory := t.TempDir()
	newDirectory := t.TempDir()
	statusPath := BackupStatusPath(f.db.Path)
	a.Config.Backup = config.Backup{Directory: oldDirectory, Schedule: "0 3 * * *", Keep: 1}
	if err := writeBackupStatusFile(statusPath, BackupStatus{Directory: oldDirectory, ConsecutiveFailures: 2}); err != nil {
		t.Fatal(err)
	}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now); err != nil || recorded != 1 {
		t.Fatalf("initial failed backup = %d, %v; want one transition", recorded, err)
	}
	assertScheduledBackupAlertState(t, f.db, 1)

	// A status for the previous directory is unknown under the new settings;
	// the reset status written before the first scheduled run must stay unknown
	// too, because no backup has produced an outcome for the new directory.
	a.Config.Backup.Directory = newDirectory
	if metrics := a.DeploymentMetrics(ctx, now.Add(time.Minute)); !metrics.BackupsEnabled || metrics.BackupStatusKnown || metrics.Backups != nil {
		t.Fatalf("status from another directory metrics = %+v; want enabled and unknown", metrics)
	}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now.Add(time.Minute)); err != nil || recorded != 0 {
		t.Fatalf("mismatched backup status = %d, %v; want no transition", recorded, err)
	}
	assertScheduledBackupAlertState(t, f.db, 1)

	a.backupWait = func(context.Context, time.Time) bool { return false }
	<-a.startBackupWorker(ctx)
	if metrics := a.DeploymentMetrics(ctx, now.Add(2*time.Minute)); !metrics.BackupsEnabled || metrics.BackupStatusKnown || metrics.Backups != nil {
		t.Fatalf("worker's pre-run status metrics = %+v; want enabled and unknown", metrics)
	}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now.Add(2*time.Minute)); err != nil || recorded != 0 {
		t.Fatalf("pre-run backup status = %d, %v; want no transition", recorded, err)
	}
	assertScheduledBackupAlertState(t, f.db, 1)

	recovered := a.runScheduledBackup(ctx, a.Config.Backup, BackupStatus{Directory: oldDirectory, ConsecutiveFailures: 2})
	if recovered.Directory != newDirectory || recovered.ConsecutiveFailures != 0 || recovered.LastSuccessAt.IsZero() || recovered.LastBackup == "" {
		t.Fatalf("successful backup did not record matching-directory recovery: %+v", recovered)
	}
	if _, err := os.Stat(filepath.Join(newDirectory, recovered.LastBackup)); err != nil {
		t.Fatalf("matching-directory backup was not created: %v", err)
	}
	a.recordBackupStatus(recovered)
	metrics := a.DeploymentMetrics(ctx, now.Add(3*time.Minute))
	if !metrics.BackupsEnabled || !metrics.BackupStatusKnown || metrics.Backups == nil || metrics.Backups.ConsecutiveFailures != 0 || metrics.Backups.LastSuccessAt.IsZero() {
		t.Fatalf("recorded matching-directory recovery metrics = %+v", metrics.Backups)
	}
	if recorded, err := a.RecordDeploymentOperationalHealth(ctx, now.Add(3*time.Minute)); err != nil || recorded != 0 {
		t.Fatalf("recorded matching-directory recovery = %d, %v; want a silent recovery", recorded, err)
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
