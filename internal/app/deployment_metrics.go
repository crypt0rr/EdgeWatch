package app

import (
	"context"
	"fmt"
	"time"

	"github.com/crypt0rr/edgewatch/internal/sandbox"
	"github.com/robfig/cron/v3"
)

const scannerIdentityHealthInspectionTimeout = 250 * time.Millisecond

// DeploymentMetrics contains aggregate operational signals for the
// deployment. Its job and cycle values contain no tenant, job, or target
// identifiers.
type DeploymentMetrics struct {
	BackupsEnabled     bool
	BackupStatusKnown  bool
	Backups            *BackupStatus
	ScannerIdentities  *sandbox.ScannerIdentityPoolStatus
	JobActiveSkips     uint64
	CycleStalledSkips  uint64
	JobsOverdue        int64
	JobsOverdueKnown   bool
	StalledCycles      int64
	StalledCyclesKnown bool
}

type deploymentHealthObservation struct {
	backupsEnabled   bool
	backupKnown      bool
	backups          *BackupStatus
	identitiesKnown  bool
	identities       *sandbox.ScannerIdentityPoolStatus
	identityPoolOff  bool
	identityRequired int
}

// deploymentHealthObservation reads the existing scheduled-backup status
// and makes the scanner identity pool's bounded read-only inspection. Failed
// reads remain unknown, so they cannot clear a previously recorded failure.
func (a *App) deploymentHealthObservation(ctx context.Context, now time.Time) deploymentHealthObservation {
	var observed deploymentHealthObservation
	if a == nil || a.Store == nil || a.Config == nil {
		return observed
	}
	var backup *BackupStatus
	backupRecorded := false
	if a.Config.Backup.Enabled() {
		observed.backupsEnabled = true
		status, recorded, backupErr := readBackupStatusFileWithPresence(BackupStatusPath(a.Store.Path))
		if backupErr != nil {
			a.silenceLogger().Warn("scheduled backup health could not be read", "error", backupErr)
		} else if recorded && status.Directory == a.Config.Backup.Directory && (status.ConsecutiveFailures > 0 || status.hasSuccessfulBackup()) {
			// A status for another directory describes backups that are not
			// available under the current settings. A directory-only pre-run
			// status is also unknown; recovery requires a recorded successful
			// backup for this directory.
			status = withBackupSettings(status, a.Config.Backup)
			backup = status.reported(now)
			backupRecorded = true
		}
	}
	if backupRecorded {
		observed.backupKnown = true
		observed.backups = backup
	}

	if a.sandbox == nil {
		return observed
	}
	sandboxStatus := a.sandbox.Status()
	if sandboxStatus.Mode == sandbox.ModeOff {
		observed.identitiesKnown = true
		observed.identityPoolOff = true
		return observed
	}
	// The policy keeps the pool state that startup found. A pool that was not
	// enforced then, as for a daemon that does not run as root, refuses every
	// scanner launch for the daemon's life, so inspecting it would only repeat
	// that failure with each heartbeat and /metrics refresh.
	if sandboxStatus.IdentityPool == nil || sandboxStatus.IdentityPool.State != sandbox.StateEnforced {
		return observed
	}
	inspect := a.inspectScannerIdentities
	if inspect == nil {
		inspect = sandbox.InspectScannerIdentityPool
	}
	inspectCtx, cancel := context.WithTimeout(ctx, scannerIdentityHealthInspectionTimeout)
	pool, inspectErr := inspect(inspectCtx)
	cancel()
	a.noteScannerIdentityInspection(inspectErr)
	if inspectErr != nil || pool == nil || pool.State != sandbox.StateEnforced {
		return observed
	}
	observed.identitiesKnown = true
	observed.identities = pool
	observed.identityRequired = a.Config.Scheduler.MaxConcurrent
	return observed
}

// noteScannerIdentityInspection logs when the inspection of a pool that
// startup enforced starts to fail and when it recovers. The heartbeat and the
// /metrics refresh both inspect the pool, so a lasting failure is logged once
// rather than with each of them.
func (a *App) noteScannerIdentityInspection(err error) {
	if err != nil {
		if !a.scannerIdentityInspectionFailing.Swap(true) {
			a.silenceLogger().Warn("scanner identity pool health could not be inspected", "error", err)
		}
		return
	}
	if a.scannerIdentityInspectionFailing.Swap(false) {
		a.silenceLogger().Info("scanner identity pool health can be inspected again")
	}
}

// DeploymentMetrics returns cached-by-caller deployment aggregates and
// operational state for /metrics. The caller should cache this snapshot
// because overdue-job inspection visits each active tenant's jobs.
func (a *App) DeploymentMetrics(ctx context.Context, now time.Time) DeploymentMetrics {
	var metrics DeploymentMetrics
	if a == nil {
		return metrics
	}
	now = now.UTC()
	observed := a.deploymentHealthObservation(ctx, now)
	metrics.BackupsEnabled = observed.backupsEnabled
	metrics.BackupStatusKnown = observed.backupKnown
	if observed.backupKnown && observed.backups != nil {
		metrics.Backups = observed.backups
	}
	if observed.identitiesKnown && observed.identities != nil && observed.identities.State == sandbox.StateEnforced {
		metrics.ScannerIdentities = observed.identities
	}
	metrics.JobActiveSkips, metrics.CycleStalledSkips = a.ScheduledRunSkips()
	if a.Store == nil {
		return metrics
	}
	if count, err := a.CountOverdueJobs(ctx, now); err != nil {
		a.silenceLogger().Warn("overdue scheduled jobs could not be counted", "error", err)
	} else {
		metrics.JobsOverdue, metrics.JobsOverdueKnown = count, true
	}
	if count, err := a.Store.System().StalledScanCycleCount(ctx); err != nil {
		a.silenceLogger().Warn("stalled scan cycles could not be counted", "error", err)
	} else {
		metrics.StalledCycles, metrics.StalledCyclesKnown = count, true
	}
	return metrics
}

// ScheduledRunSkips returns the process-lifetime counts of scheduled runs
// skipped because a job was already active or its resumable cycle was stalled.
func (a *App) ScheduledRunSkips() (jobActive, cycleStalled uint64) {
	if a == nil {
		return 0, 0
	}
	return a.scheduledJobActiveSkips.Load(), a.scheduledCycleStalledSkips.Load()
}

// CountOverdueJobs counts active, enabled schedules currently due for the
// job-silence watchdog. The store's due check excludes a live scan and an
// alert retry window. It returns only an aggregate across active tenants.
func (a *App) CountOverdueJobs(ctx context.Context, now time.Time) (int64, error) {
	if a == nil || a.Store == nil {
		return 0, nil
	}
	system := a.Store.System()
	scopes, err := system.ActiveTenantScopes(ctx)
	if err != nil {
		return 0, err
	}
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	var count int64
	for _, scope := range scopes {
		jobs, err := a.Store.Tenant(scope).ListJobs(ctx, false)
		if err != nil {
			return 0, err
		}
		for _, record := range jobs {
			if !record.Enabled || record.Archived {
				continue
			}
			reference, err := system.JobSilenceReference(ctx, record.ID, record.CreatedAt, now)
			if err != nil {
				return 0, err
			}
			if reference.IsZero() {
				continue
			}
			threshold, err := jobSilenceThreshold(parser, record.Job, reference)
			if err != nil {
				// The silence watchdog leaves invalid schedules out of its own
				// checks. Keep this aggregate aligned with that behavior.
				continue
			}
			due, err := system.JobSilenceDue(ctx, record.ID, record.CreatedAt, now, threshold)
			if err != nil {
				return 0, fmt.Errorf("check scheduled job silence: %w", err)
			}
			if due {
				count++
			}
		}
	}
	return count, nil
}

// RecordDeploymentOperationalHealth records transitions that the
// deployment-alert loop can safely observe. An unavailable inspection is
// omitted rather than interpreted as healthy or empty.
func (a *App) RecordDeploymentOperationalHealth(ctx context.Context, now time.Time) (int, error) {
	if a == nil || a.Store == nil {
		return 0, nil
	}
	observed := a.deploymentHealthObservation(ctx, now)
	platform := a.Store.Platform()
	queued := 0
	if observed.backupKnown {
		failures := 0
		if observed.backups != nil {
			failures = observed.backups.ConsecutiveFailures
		}
		recorded, err := platform.RecordScheduledBackupHealth(ctx, failures, now)
		if err != nil {
			return queued, err
		}
		if recorded {
			queued++
		}
	}
	if observed.identitiesKnown && (observed.identityPoolOff || observed.identities != nil) {
		reachable, required := 0, observed.identityRequired
		if observed.identityPoolOff {
			required = 0
		} else {
			reachable = observed.identities.ReachableByDaemon()
		}
		recorded, err := platform.RecordScannerIdentityHealth(ctx, reachable, required, now)
		if err != nil {
			return queued, err
		}
		if recorded {
			queued++
		}
	}
	return queued, nil
}
