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
// and the host CLI call. Each one refuses with ErrBusinessUnitsDisabled while
// experimental.business_units is off, so an installation keeps its single
// default unit. The store methods behind them do not check the flag.

// ErrBusinessUnitsDisabled reports a business unit operation while the
// experimental feature is switched off.
var ErrBusinessUnitsDisabled = errors.New("business units are an experimental feature that is switched off; set experimental.business_units: true in config.yaml to manage them")

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

// requireBusinessUnits refuses a business unit operation while the
// experimental feature is off.
func (a *App) requireBusinessUnits() error {
	if a.Config == nil || !a.Config.BusinessUnitsEnabled() {
		return ErrBusinessUnitsDisabled
	}
	return nil
}

// CreateUnit creates an active business unit. It inherits the deployment's
// scan slots and probe budgets, and may not run high-cost work until a
// platform administrator raises its high-cost ceiling (SetTenantCapacity).
func (a *App) CreateUnit(ctx context.Context, name, slug string, audit store.AuditEntry) (store.TenantRecord, error) {
	if err := a.requireBusinessUnits(); err != nil {
		return store.TenantRecord{}, err
	}
	return a.Store.Platform().CreateTenant(ctx, name, slug, a.capacityLimits(), audit)
}

// RenameUnit changes a business unit's name and slug. A new slug changes the
// address of the unit's public status page.
func (a *App) RenameUnit(ctx context.Context, id string, expectedRevision int64, name, slug string, audit store.AuditEntry) (store.TenantRecord, error) {
	if err := a.requireBusinessUnits(); err != nil {
		return store.TenantRecord{}, err
	}
	return a.Store.Platform().RenameTenant(ctx, id, expectedRevision, name, slug, audit)
}

// DisableUnit pauses an active business unit. The store ends the sessions of
// its accounts and revokes their invitations, and from then on refuses them
// sign-in, and holds the unit's alerts. The application then fails the
// unit's runs that wait for a scan slot, cancels its running scans, which
// record a canceled scan and leave the baselines as they are, and removes
// the unit's jobs from the schedule.
func (a *App) DisableUnit(ctx context.Context, id string, expectedRevision int64, audit store.AuditEntry) (store.TenantRecord, error) {
	if err := a.requireBusinessUnits(); err != nil {
		return store.TenantRecord{}, err
	}
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
	if err := a.requireBusinessUnits(); err != nil {
		return store.TenantRecord{}, err
	}
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
	if err := a.requireBusinessUnits(); err != nil {
		return store.TenantRecord{}, err
	}
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
// to end the unit's live-update streams at once, whichever caller paused
// the unit. Like SetEventHandler it is a callback, so the application stays
// independent of HTTP.
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
// unitPurgeInterval. It runs whatever the experimental flag says, so a
// deletion requested while the feature was on still completes. The purge
// takes SQLite's writer for one bounded batch at a time.
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
		// A deferred pass waits for a running scan to release its lease.
		logger.Info("business unit purge pass", "tenant_id", result.TenantID, "phase", result.Phase, "rows", result.TotalRows, "complete", result.Complete, "deferred", result.Deferred)
		if result.MaintenanceErr != nil {
			logger.Warn("index maintenance after a business unit purge failed; later maintenance continues it", "tenant_id", result.TenantID, "error", result.MaintenanceErr)
		}
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Warn("business unit purge stopped; the next pass resumes it", "error", err)
	}
}
