package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// Business units are the console's name for tenants. The methods here are
// the application's entry points for their lifecycle, which the web console
// and the host CLI call.

// unitPurgeInterval is how often the daemon looks for deleted business units
// whose data it has not erased yet. A deletion request wakes it at once.
const unitPurgeInterval = time.Minute

// unitLifecycle is the application's state of the business unit lifecycle.
type unitLifecycle struct {
	// mu orders pausing a unit against registering a run, so a run of a
	// unit that is being paused is either cancelled by the pause or sees
	// that the unit is paused when it registers.
	mu sync.Mutex
	// paused holds the IDs of the units this process paused, disabled or
	// deleting, until EnableUnit makes one active again.
	paused map[string]bool
	// purgeWake wakes the purge worker; see purgeWakeChannel.
	purgeOnce sync.Once
	purgeWake chan struct{}
}

// purgeWakeChannel returns the channel that wakes the purge worker, creating
// it on first use.
func (u *unitLifecycle) purgeWakeChannel() chan struct{} {
	u.purgeOnce.Do(func() { u.purgeWake = make(chan struct{}, 1) })
	return u.purgeWake
}

// CreateUnit creates an active business unit. It inherits the deployment's
// scan slots and probe budgets, and may not run high-cost work until a
// platform administrator raises its high-cost ceiling (SetTenantCapacity).
// Its update alerts are off: its copy of an update alert goes to none of its
// destinations until its administrators select some.
func (a *App) CreateUnit(ctx context.Context, name, slug string, audit store.AuditEntry) (store.TenantRecord, error) {
	return a.Store.Platform().CreateTenant(ctx, name, slug, a.capacityLimits(), audit)
}

// RenameUnit changes a business unit's name and slug. A new slug changes the
// address of the unit's public status page.
func (a *App) RenameUnit(ctx context.Context, id string, expectedRevision int64, name, slug string, audit store.AuditEntry) (store.TenantRecord, error) {
	return a.Store.Platform().RenameTenant(ctx, id, expectedRevision, name, slug, audit)
}

// DisableUnit pauses an active business unit. The store ends the sessions of
// its accounts and revokes their invitations, and from then on refuses them
// sign-in, and holds the unit's alerts. The application then fails the
// unit's runs that wait for a scan slot, cancels its running scans, and
// removes the unit's jobs from the schedule. A scan of the unit that
// finishes after the disable, cancelled here or run by another process
// such as a host command, is recorded as canceled and changes no baseline,
// incident or alert: SystemStore.FinalizeManagedScan checks the unit's
// state as it saves the scan.
func (a *App) DisableUnit(ctx context.Context, id string, expectedRevision int64, audit store.AuditEntry) (store.TenantRecord, error) {
	record, err := a.Store.Platform().DisableTenant(ctx, id, expectedRevision, audit)
	if err != nil {
		return store.TenantRecord{}, err
	}
	a.pauseUnit(id)
	a.RefreshSchedules()
	return record, nil
}

// EnableUnit makes a disabled business unit active again. Its accounts can
// sign in, its held alerts are delivered, and the schedule refresh returns
// its jobs to the schedule and its slot cap to the scan slot pool. The silence watchdog judges its jobs from now on, so the pause
// does not count as silence.
func (a *App) EnableUnit(ctx context.Context, id string, expectedRevision int64, audit store.AuditEntry) (store.TenantRecord, error) {
	record, err := a.Store.Platform().EnableTenant(ctx, id, expectedRevision, audit)
	if err != nil {
		return store.TenantRecord{}, err
	}
	a.units.mu.Lock()
	delete(a.units.paused, id)
	a.units.mu.Unlock()
	a.RefreshSchedules()
	a.wakeDelivery()
	return record, nil
}

// RequestUnitDeletion deletes a disabled business unit that is not the
// default one. typedName must be exactly the unit's name. The unit's jobs are
// archived at once, and the daemon's purge worker then erases its data and
// keeps the unit as a tombstone.
func (a *App) RequestUnitDeletion(ctx context.Context, id, typedName string, audit store.AuditEntry) (store.TenantRecord, error) {
	record, err := a.Store.Platform().RequestTenantDeletion(ctx, id, typedName, audit)
	if err != nil {
		return store.TenantRecord{}, err
	}
	a.pauseUnit(id)
	a.RefreshSchedules()
	a.wakeUnitPurge()
	return record, nil
}

// pauseUnit applies a pause that the store has committed to the unit's work
// in this process. Its runs that wait for a scan slot fail with
// store.ErrTenantNotActive, and its running scans are cancelled. A run that
// registers later is cancelled by registerRun, and one that has not taken
// its scan lease yet is refused by the lease.
func (a *App) pauseUnit(id string) {
	if a.slots != nil {
		a.slots.FailWaiters(id, fmt.Errorf("%w: the business unit was paused", store.ErrTenantNotActive))
	}
	a.units.mu.Lock()
	if a.units.paused == nil {
		a.units.paused = map[string]bool{}
	}
	a.units.paused[id] = true
	a.running.Range(func(_, value any) bool {
		if run, ok := value.(*activeRun); ok && run.tenant == id {
			run.requestCancel()
		}
		return true
	})
	a.units.mu.Unlock()
	a.eventMu.RLock()
	handler := a.unitPausedHandler
	a.eventMu.RUnlock()
	if handler != nil {
		handler(id)
	}
}

// SetUnitPausedHandler registers an optional sink that is told the ID of
// each business unit that DisableUnit or RequestUnitDeletion pauses in this
// process, after the store has committed the pause. The web console uses it
// to end the unit's live-update streams and drop its cached public page at
// once, whichever caller paused the unit. Like SetEventHandler it is a
// callback, so the application stays independent of HTTP.
func (a *App) SetUnitPausedHandler(handler func(tenantID string)) {
	a.eventMu.Lock()
	a.unitPausedHandler = handler
	a.eventMu.Unlock()
}

// registerRun makes a run of the tenant visible to ActiveScans and
// CancelScan. A run of a unit that this process paused is cancelled at
// once: it took its scan lease before the pause was committed, and the
// pause could not see it yet.
func (a *App) registerRun(tenantID, id string, run *activeRun) {
	a.units.mu.Lock()
	defer a.units.mu.Unlock()
	run.tenant = tenantID
	a.running.Store(id, run)
	if a.units.paused[tenantID] {
		run.requestCancel()
	}
}

// requestCancel cancels the run, as CancelScan does.
func (run *activeRun) requestCancel() {
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.cancel != nil {
		run.cancel()
		run.scan.Phase = "cancelling"
	}
}

// wakeUnitPurge asks the purge worker to look for deleted units now.
func (a *App) wakeUnitPurge() {
	select {
	case a.units.purgeWakeChannel() <- struct{}{}:
	default:
	}
}

// startUnitPurgeWorker erases the data of deleted business units from the
// daemon, at startup, when a deletion is requested, and every
// unitPurgeInterval. The purge takes SQLite's writer for one bounded batch
// at a time. Each pass then continues the cleanup after the units that
// earlier releases deleted, while it is pending.
func (a *App) startUnitPurgeWorker(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	wake := a.units.purgeWakeChannel()
	go func() {
		defer close(done)
		defer a.recoverBackgroundPanic("business-unit-purge-worker")
		ticker := time.NewTicker(unitPurgeInterval)
		defer ticker.Stop()
		for {
			a.purgeDeletedUnits(ctx)
			select {
			case <-ctx.Done():
				return
			case <-wake:
			case <-ticker.C:
			}
		}
	}()
	return done
}

// purgeDeletedUnits runs one purge pass and logs its outcome. The logs name
// unit IDs and counts only.
func (a *App) purgeDeletedUnits(ctx context.Context) {
	defer a.recoverBackgroundPanic("business-unit-purge")
	results, err := a.Store.System().PurgeDeletingTenants(ctx)
	logger := a.Logger
	if logger == nil {
		logger = slog.Default()
	}
	for _, result := range results {
		// A deferred pass waits for a running scan to release its lease. A
		// pass with maintenance pending has erased the unit's rows, but has
		// not finished compacting the search indexes, overwriting the free
		// pages, or truncating the write-ahead log; the unit stays deleting
		// until a later pass has.
		logger.Info("business unit purge pass", "tenant_id", result.TenantID, "phase", result.Phase, "rows", result.TotalRows, "complete", result.Complete, "deferred", result.Deferred, "maintenance_pending", result.MaintenancePending)
		if result.CheckpointBusy {
			logger.Warn("a reader of the database, such as a running backup, kept the business unit purge from truncating the write-ahead log, which may still hold the erased rows; the next pass retries it", "tenant_id", result.TenantID)
		}
		if result.LegacyMaintenanceCompleted {
			logger.Info(legacyUnitCleanupFinished, "completed_by_tenant_id", result.TenantID)
		}
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Warn("business unit purge stopped; the next pass resumes it", "error", err)
	}
	a.cleanUpAfterLegacyDeletions(ctx, logger)
}

// legacyUnitCleanupFinished is the log message of the finished cleanup after
// the business units that earlier releases deleted.
const legacyUnitCleanupFinished = "cleanup after business units deleted by earlier releases finished: the search indexes are compacted, the free pages overwritten or returned to the file system, and the write-ahead log truncated"

// cleanUpAfterLegacyDeletions runs one pass of the cleanup after the
// business units that earlier releases deleted, while it is pending, and
// logs its outcome. Those releases could leave the search indexes, the free
// pages of a database without incremental auto-vacuum, and the write-ahead
// log holding the units' erased rows. While a unit is being deleted, the
// pass waits: that unit's purge compacts the indexes, overwrites those free
// pages, and truncates the log, which completes the cleanup too.
func (a *App) cleanUpAfterLegacyDeletions(ctx context.Context, logger *slog.Logger) {
	result, err := a.Store.System().RunLegacyPurgeMaintenance(ctx)
	if result.Started {
		logger.Info("cleanup after business units deleted by earlier releases started: the search indexes, the free pages, or the write-ahead log may still hold their erased rows")
	}
	if result.Pending {
		logger.Info("business unit cleanup pass", "phase", result.Phase, "complete", result.Complete, "deferred", result.Deferred)
	}
	if result.CheckpointBusy {
		logger.Warn("a reader of the database, such as a running backup, kept the cleanup after business units deleted by earlier releases from truncating the write-ahead log, which may still hold their erased rows; the next pass retries it")
	}
	if result.Complete {
		logger.Info(legacyUnitCleanupFinished)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Warn("cleanup after business units deleted by earlier releases stopped; the next pass resumes it", "error", err)
	}
}
