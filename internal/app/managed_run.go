package app

import (
	"context"
	"errors"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/engine"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// managedRun is one run of a job, from the moment it holds a scan slot
// until runJob returns. It carries the run's scan record and owns its job
// lease, its entry among the running scans, and its one scan.completed
// event.
type managedRun struct {
	app    *App
	scope  store.TenantScope
	ts     *store.TenantStore
	system *store.SystemStore
	job    config.Job
	jobID  string
	manual bool
	// budget is the tenant's probe budget, read once for the run.
	budget   probeBudget
	estimate config.WorkEstimate
	scan     model.Scan
	// active is the scan's live view for ActiveScans and CancelScan, and
	// cancel ends the scan's context.
	active     *activeRun
	cancel     context.CancelFunc
	leaseOwner string
	// leaseReleased is set once the finalization released the job lease.
	leaseReleased bool
	// legacySelection is the frozen notification selection of a job without
	// one, when legacySelectionCaptured is set.
	legacySelection         []string
	legacySelectionCaptured bool
	// publishLifecycleCompletion is false for a web-triggered run, whose
	// callback publishes the completion event.
	publishLifecycleCompletion bool
	completionPublished        bool
	// exitMessage is the completion message of a run that ends before its
	// result is finalized, and scanErr the scanner's error.
	exitMessage string
	scanErr     error
}

// runJobWithQueueMarker runs one scan of a job. It claims the job in the run
// registry and sets *accepted once it has, waits for a scan slot, prepares
// the run, takes the job lease, scans and finalizes the result. Each step
// that holds something releases it when runJob returns, in reverse order.
func (a *App) runJobWithQueueMarker(ctx context.Context, scope store.TenantScope, job config.Job, jobID string, revision int64, manual, publishLifecycleCompletion bool, accepted *bool) (model.Scan, []model.Event, error) {
	if err := a.runs.claim(jobID, manual); err != nil {
		return model.Scan{}, nil, err
	}
	defer a.runs.unclaim(jobID)
	if accepted != nil {
		*accepted = true
	}
	releaseSlot, err := a.acquireSlot(ctx, scope, job.Name, jobID, manual)
	if err != nil {
		return model.Scan{}, nil, err
	}
	defer releaseSlot()
	run, err := a.prepareRun(ctx, scope, job, jobID, revision, manual)
	if err != nil {
		return model.Scan{}, nil, err
	}
	run.publishLifecycleCompletion = publishLifecycleCompletion
	scanCtx, err := run.start(ctx)
	if err != nil {
		return model.Scan{}, nil, err
	}
	defer run.finish()
	run.announce(ctx)
	defer run.publishPendingCompletion()
	defer run.releaseLeaseFallback(ctx)
	snapshot, resumable, scanErr := run.execute(ctx, scanCtx)
	if errors.Is(scanErr, ErrScanCycleStalled) {
		// A scheduled trigger that races with a newly stalled cycle must
		// not create a synthetic failed scan or notification. The cycle's
		// original stall attempt already recorded the actionable alert.
		run.exitMessage = "Scan attempt stopped because its resumable cycle became stalled"
		return model.Scan{}, nil, scanErr
	}
	return run.finalize(ctx, scanCtx, snapshot, resumable)
}

// acquireSlot waits for a scan slot in the tenant of scope. While the run
// waits, the run registry lists it as queued and CancelQueuedRun can end the
// wait, which returns ErrQueuedRunCanceled. The returned function gives the
// slot back.
func (a *App) acquireSlot(ctx context.Context, scope store.TenantScope, jobName, jobID string, manual bool) (func(), error) {
	trigger := "scheduled"
	if manual {
		trigger = "manual"
	}
	// The wait has its own context, so CancelQueuedRun can end it without
	// touching the run context the scan itself will use.
	waitCtx, cancelWait := context.WithCancelCause(ctx)
	queued := &queuedRun{run: model.QueuedRun{JobID: jobID, Job: jobName, QueuedAt: time.Now().UTC(), Trigger: trigger, TenantID: scope.ID()}, cancel: cancelWait}
	queuedInPool := false
	releaseSlot, slotErr := a.slots.AcquireWithQueued(waitCtx, scope.ID(), func() {
		a.runs.enqueue(jobID, queued)
		queuedInPool = true
	})
	if slotErr != nil {
		if queuedInPool {
			a.runs.dequeue(jobID, queued)
		}
		canceled := errors.Is(context.Cause(waitCtx), ErrQueuedRunCanceled)
		cancelWait(nil)
		if canceled {
			return nil, ErrQueuedRunCanceled
		}
		return nil, slotErr
	}
	release := func() {
		releaseSlot()
		if queuedInPool {
			a.runs.dequeue(jobID, queued)
		}
		cancelWait(nil)
	}
	if !queued.start() {
		// The cancellation arrived as the slot was granted.
		release()
		return nil, ErrQueuedRunCanceled
	}
	return release, nil
}

// prepareRun reads the job's current definition and its tenant's probe
// budget for a run that holds a scan slot, checks the run against them, and
// prepares its scan record. A scheduled run of a stalled cycle stops here.
func (a *App) prepareRun(ctx context.Context, scope store.TenantScope, job config.Job, jobID string, revision int64, manual bool) (*managedRun, error) {
	ts, system := a.Store.Tenant(scope), a.Store.System()
	job, revision, err := a.queuedManagedJob(ctx, ts, job, jobID, revision, manual)
	if err != nil {
		return nil, err
	}
	estimate, err := config.EstimateJobWork(job)
	if err != nil {
		return nil, err
	}
	// The run reads its tenant's probe budget once. The estimate, the
	// resolved plan and the direct scanner's own check all use it; the
	// resumable path checks each attempt against the current budget.
	budget, err := a.tenantProbeBudget(ctx, ts)
	if err != nil {
		return nil, err
	}
	if err := checkEstimatedProbeBudget(budget, job, estimate); err != nil {
		return nil, err
	}
	if !manual {
		if cycle, cycleErr := ts.GetActiveScanCycle(ctx, jobID); cycleErr == nil && cycle.Status == "stalled" && !cycleResumeWindowElapsed(cycle, time.Now().UTC()) {
			return nil, ErrScanCycleStalled
		}
	}
	started := time.Now().UTC()
	engineName := config.EngineNmap
	profileID, profileRevision := "", int64(0)
	if job.TCP != nil {
		if job.TCP.Engine != "" {
			engineName = job.TCP.Engine
		}
		profileID, profileRevision = job.TCP.ProfileID, job.TCP.ProfileRevision
		// A profile revision saved before NSE arguments were limited to the
		// script's own keeps scanning, and says so.
		if keys := config.NSEArgumentsOutsideScript(job.TCP.NSEProfile, job.TCP.NSEArgs); len(keys) > 0 {
			a.Logger.Warn("the job's scanner profile revision passes NSE arguments that are not its script's own; save the profile again without them and update the job to the new revision",
				"job_id", jobID, "profile_id", profileID, "profile_revision", profileRevision, "nse_profile", job.TCP.NSEProfile, "nse_arguments", keys)
		}
	}
	scan := model.Scan{ID: scanner.NewID(started), JobID: jobID, JobRevision: revision, Job: job.Name, StartedAt: started, ConfigHash: job.SecurityHash(), NmapVersion: a.nmapVersion, ScannerEngine: engineName, ScannerProfileID: profileID, ScannerProfileRevision: profileRevision}
	if engineName == config.EngineNaabuNmap {
		scan.NaabuVersion = a.naabuVersion
	}
	leaseOwner := scan.ID
	if daemonOwner := a.currentDaemonOwner(); daemonOwner != "" {
		leaseOwner = "daemon/" + daemonOwner + "/" + scan.ID
	}
	return &managedRun{app: a, scope: scope, ts: ts, system: system, job: job, jobID: jobID, manual: manual, budget: budget, estimate: estimate, scan: scan, leaseOwner: leaseOwner}, nil
}

// start takes the job lease for the run's revision and registers the run's
// scan, which ends its wait in the queue. It returns the scan's context,
// which the job's timeout bounds and CancelScan cancels.
func (r *managedRun) start(ctx context.Context) (context.Context, error) {
	a, job, scan := r.app, r.job, r.scan
	// The lease also refuses a job whose tenant is not active, so a paused
	// tenant starts no scan, whether scheduled or manual.
	if err := r.system.AcquireJobLeaseForRevision(ctx, r.jobID, r.leaseOwner, scan.JobRevision, scan.StartedAt.Add(job.Timeout.Value()+time.Minute)); err != nil {
		if errors.Is(err, store.ErrJobBusy) {
			return nil, scanner.ErrBusy
		}
		return nil, err
	}
	scanCtx, cancel := context.WithTimeout(ctx, job.Timeout.Value())
	r.cancel = cancel
	engineName := scan.ScannerEngine
	r.active = &activeRun{scan: model.ActiveScan{ID: scan.ID, JobID: r.jobID, Job: job.Name, JobRevision: scan.JobRevision, StartedAt: scan.StartedAt, EstimatedProbes: r.estimate.Probes, NmapInvocations: r.estimate.NmapInvocations, EstimatedSeconds: r.estimate.EstimatedSeconds, TotalProbes: r.estimate.Probes, TotalInvocations: r.estimate.NmapInvocations, Phase: "starting", Scanner: engineName, ScannerProfileID: scan.ScannerProfileID, ScannerProfileRevision: scan.ScannerProfileRevision}, cancel: r.cancel}
	a.registerRun(r.scope.ID(), scan.ID, r.active)
	return scanCtx, nil
}

// finish cancels the scan's context and removes the run's scan from the
// registry.
func (r *managedRun) finish() {
	r.cancel()
	r.app.runs.finish(r.jobID, r.scan.ID)
}

// announce freezes the notification selection of a job without one and
// publishes scan.started.
func (r *managedRun) announce(ctx context.Context) {
	a, job := r.app, r.job
	// Legacy nil selections are frozen at scan start as well as when they are
	// persisted. This closes the race where a new endpoint is added while an
	// older scan is running: that scan must not deliver its completion events to
	// an endpoint that did not exist when the scan began. Stable selectors are
	// resolved again at finalization so managed credential rotations still use
	// the current revision. Both follow the destinations of the job's tenant,
	// so a nil selection never reaches another tenant's destinations.
	if job.NotificationDestinations == nil {
		if selection, selectionErr := a.Notifier.Tenant(r.ts).LegacySelection(ctx); selectionErr != nil {
			a.Logger.Warn("legacy notification selection snapshot failed", "job", job.Name, "error", selectionErr)
		} else {
			r.legacySelection = selection
			r.legacySelectionCaptured = true
		}
	}
	// Publish lifecycle updates to the web console without persisting them as
	// alert events. This keeps SSE subscribers responsive even when a scan has
	// no baseline or incident event to emit.
	a.emitTenantEvents(r.scope, []model.Event{{Type: "scan.started", JobID: r.jobID, Job: job.Name, ScanID: r.scan.ID, Message: "Scan started", CreatedAt: r.scan.StartedAt}})
}

// publishCompletion publishes the run's scan.completed event with message,
// once. A web-triggered run leaves the event to its callback.
func (r *managedRun) publishCompletion(message string) {
	if r.completionPublished {
		return
	}
	r.completionPublished = true
	if !r.publishLifecycleCompletion {
		return
	}
	event := model.Event{Type: "scan.completed", JobID: r.jobID, Job: r.job.Name, ScanID: r.scan.ID, Message: message, CreatedAt: r.scan.FinishedAt}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	r.app.emitTenantEvents(r.scope, []model.Event{event})
}

// publishPendingCompletion publishes the completion of a run that ended
// before its result was finalized.
func (r *managedRun) publishPendingCompletion() {
	if r.completionPublished {
		return
	}
	if r.exitMessage == "" {
		switch {
		case errors.Is(r.scanErr, ErrScanCycleStalled):
			r.exitMessage = "Scan attempt stopped because its resumable cycle is stalled"
		case r.scanErr != nil:
			r.exitMessage = "Scan attempt stopped before finalization"
		default:
			r.exitMessage = "Scan attempt ended before finalization"
		}
	}
	r.publishCompletion(r.exitMessage)
}

// releaseLeaseFallback releases the job lease of a run whose finalization
// did not, also after ctx ended.
func (r *managedRun) releaseLeaseFallback(ctx context.Context) {
	if r.leaseReleased {
		return
	}
	releaseCtx, releaseCancel := context.WithTimeout(context.WithoutCancel(ctx), scanPersistenceWriterWaitTimeout)
	defer releaseCancel()
	if err := r.system.ReleaseJobLease(releaseCtx, r.jobID, r.leaseOwner); err != nil && r.app.Logger != nil {
		r.app.Logger.Warn("scan lease fallback release failed", "job", r.job.Name, "scan_id", r.scan.ID, "error", err)
	}
}

// execute runs the scan: one attempt of a resumable cycle, or the scanner's
// direct path. It returns the snapshot, whether the resumable path handled
// the scan, and the scanner's error.
func (r *managedRun) execute(ctx, scanCtx context.Context) (model.Snapshot, bool, error) {
	a, job := r.app, r.job
	var snapshot model.Snapshot
	resumableRun := false
	// The scanner planner owns both ordinary Nmap units and Naabu pipeline
	// batches. Naabu units checkpoint a pinned address batch after discovery and
	// enrichment, so a paused cycle can resume without replaying completed
	// batches or bypassing the discovery phase.
	if resumableScanner, ok := a.Scanner.(scanner.ResumableScanner); ok {
		var handled bool
		handled, snapshot, r.scanErr = a.runResumableAttempt(ctx, scanCtx, r.ts, job, r.jobID, &r.scan, r.active, resumableScanner, r.manual)
		resumableRun = handled
		if errors.Is(r.scanErr, ErrScanCycleStalled) {
			return snapshot, resumableRun, r.scanErr
		}
	}
	if !resumableRun && r.scanErr == nil {
		scanID := r.scan.ID
		// The direct scanner path resolves DNS again. A budgeted scanner
		// checks the work of that resolution before it starts, so a DNS
		// answer that grew since the plan cannot bypass the probe budget.
		if budgetedScanner, ok := a.Scanner.(BudgetedProgressScanner); ok {
			snapshot, r.scanErr = budgetedScanner.ScanWithProgressBudget(scanCtx, job, func(progress scanner.Progress) {
				a.updateActiveProgress(scanID, progress)
			}, func(discoveryProbes, nmapProbes int64) error {
				return checkResolvedProbeBudget(r.budget, job, discoveryProbes, nmapProbes)
			})
		} else if progressScanner, ok := a.Scanner.(ProgressScanner); ok {
			snapshot, r.scanErr = progressScanner.ScanWithProgress(scanCtx, job, func(progress scanner.Progress) {
				a.updateActiveProgress(scanID, progress)
			})
		} else {
			snapshot, r.scanErr = a.Scanner.Scan(scanCtx, job)
		}
	}
	return snapshot, resumableRun, r.scanErr
}

// finalize records the scan's outcome and saves it with the baseline
// comparison, its events and their notifications in one transaction, and
// publishes the completion.
func (r *managedRun) finalize(ctx, scanCtx context.Context, snapshot model.Snapshot, resumableRun bool) (model.Scan, []model.Event, error) {
	a, job, jobID, scope := r.app, r.job, r.jobID, r.scope
	scanErr, run := r.scanErr, r.active
	scan := &r.scan
	// Scanner progress carries phase timing for the optional Naabu pipeline.
	// Capture it before the active run is removed by the deferred cleanup so
	// the immutable scan record remains useful after completion.
	if current := run.snapshot(); current.DiscoveryDurationMS > 0 || current.EnrichmentDurationMS > 0 {
		scan.DiscoveryDurationMS = current.DiscoveryDurationMS
		scan.EnrichmentDurationMS = current.EnrichmentDurationMS
	}
	scan.FinishedAt = time.Now().UTC()
	scan.Snapshot = snapshot
	if scan.ScannerEngine == config.EngineNaabuNmap {
		scan.DiscoveryPorts, scan.ConfirmedPorts = scannerDiscoveryStats(snapshot)
	}
	if scanErr != nil {
		if !resumableRun {
			if errors.Is(scanCtx.Err(), context.Canceled) {
				scan.Status = "canceled"
				scan.Error = "scan canceled"
				if run.interruptedByShutdown(ctx, scanCtx) {
					scan.Error = ScanInterruptedMessage
					scan.Interrupted = true
				}
			} else if errors.Is(scanCtx.Err(), context.DeadlineExceeded) || errors.Is(scanErr, context.DeadlineExceeded) {
				scan.Status = "timed_out"
				scan.Error = "scan timed out"
			} else {
				scan.Status = "failed"
				scan.Error = scanErr.Error()
			}
		}
	} else if !resumableRun {
		scan.Status = "success"
	}
	if scanErr == nil {
		// Preserve reachable evidence from a partial discovery pass while making
		// the terminal result explicit. The engine will compare only complete
		// target scopes and will not advance a baseline from this scan.
		engine.MarkIncompleteScan(scan)
	}
	a.beginActiveFinalization(scan.ID)
	persistTimeout := scanPersistenceTimeout(len(scan.Snapshot.Hosts))
	if a.persistenceBudget != nil {
		persistTimeout = a.persistenceBudget(len(scan.Snapshot.Hosts))
	}
	if a.Logger != nil {
		a.Logger.Debug("persisting scan result", "scan_id", scan.ID, "hosts", len(scan.Snapshot.Hosts), "timeout", persistTimeout)
	}
	// The result is persisted even when the run was canceled, so the
	// persistence context keeps ctx's values but not its cancellation.
	persistCtx := context.WithoutCancel(ctx)
	destinationCtx, destinationCancel := context.WithTimeout(persistCtx, scanPersistenceWriterWaitTimeout)
	var destinations []string
	var destinationErr error
	notifier := a.Notifier.Tenant(r.ts)
	if r.legacySelectionCaptured {
		destinations, destinationErr = notifier.QueueDestinationsForSelection(destinationCtx, r.legacySelection)
	} else {
		destinations, destinationErr = notifier.QueueDestinationsForJob(destinationCtx, job)
	}
	destinationCancel()
	if destinationErr != nil {
		if completedCycleResult(*scan) {
			// The merged result of a completed resumable cycle stays in its
			// checkpoints until a scan promotes it. Saving it now as not
			// compared would discard the whole cycle's comparison; leaving the
			// cycle unpromoted lets the next trigger promote and compare it,
			// as after a crash in this window.
			if a.Logger != nil {
				a.Logger.Warn("notification destinations unavailable; the completed scan cycle is compared on the next run", "job", job.Name, "scan_id", scan.ID, "cycle_id", scan.CycleID, "error", destinationErr)
			}
			r.exitMessage = "Scan attempt could not be finalized because notification destinations were unavailable; the completed cycle is compared on the next run"
			return *scan, nil, destinationErr
		}
		// Preserve the completed scan even when notification configuration
		// cannot be read. Runtime state is deliberately left unchanged,
		// matching the pre-transaction behavior, so the scan is recorded as
		// not compared.
		scan.Comparison = model.ScanComparisonNotCompared
		saveCtx, saveCancel := context.WithTimeout(persistCtx, scanPersistenceWriterWaitTimeout+persistTimeout)
		defer saveCancel()
		if saveErr := r.system.SaveScan(saveCtx, *scan); saveErr != nil {
			r.exitMessage = "Scan attempt could not be finalized because its result could not be saved"
			return *scan, nil, saveErr
		}
		r.exitMessage = "Scan attempt could not be finalized because notification destinations were unavailable"
		return *scan, nil, destinationErr
	}
	// Renew and release the lease inside the finalization transaction. Its
	// writer wait has a separate bound; the size-based work deadline begins only
	// after SQLite grants this transaction the writer lock.
	// A daemon's finalization also renews the daemon lease for its work
	// budget when it takes the writer, because the heartbeat cannot write
	// while it holds SQLite's only writer.
	finalizeOptions := store.ManagedScanFinalizationOptions{
		WriterWaitTimeout: scanPersistenceWriterWaitTimeout,
		WorkTimeout:       persistTimeout,
		LeaseOwner:        r.leaseOwner,
		LeaseUntil:        time.Now().UTC().Add(scanPersistenceWriterWaitTimeout + persistTimeout + time.Minute),
		DaemonOwner:       a.currentDaemonOwner(),
	}
	events, finalizeErr := a.Engine.FinalizeManagedScanWithOptions(persistCtx, jobID, job, scan, destinations, finalizeOptions)
	if errors.Is(finalizeErr, store.ErrJobRevisionChanged) {
		// Keep the scan in immutable history, but do not let a result from a
		// superseded security scope seed or mutate the current baseline. A
		// lifecycle-only revision retains the same hash and is still accepted.
		a.Logger.Info("scan completed for superseded security scope; runtime state unchanged", "job", job.Name, "scan_id", scan.ID)
		events, finalizeErr = nil, nil
		r.leaseReleased = true
	}
	if errors.Is(finalizeErr, store.ErrTenantNotActive) {
		// The job's business unit was paused while the scan ran, whether this
		// process cancelled the scan or another one, such as a host command,
		// ran it. The store recorded the scan as the pause cancelled it and
		// changed no baseline, incident or alert, so there are no events.
		r.leaseReleased = true
		a.Logger.Info("scan finished after its business unit was paused; runtime state unchanged", "job", job.Name, "scan_id", scan.ID, "status", scan.Status)
		r.publishCompletion("Scan " + scan.Status)
		return *scan, nil, errors.Join(finalizeErr, scanErr)
	}
	if errors.Is(finalizeErr, store.ErrCycleNotResumable) {
		// The store retained this result as immutable history but deliberately
		// skipped runtime comparison because the cycle was discarded or expired.
		r.leaseReleased = true
		r.publishCompletion("Scan " + scan.Status)
		return *scan, nil, finalizeErr
	}
	if finalizeErr != nil {
		if a.Logger != nil {
			a.Logger.Error("scan result finalization failed", "job", job.Name, "scan_id", scan.ID, "error", finalizeErr)
		}
		failureScan := *scan
		failureScan.Status = "failed"
		failureScan.Error = "scan result could not be finalized; inspect the EdgeWatch server log"
		failureScan.Snapshot = model.Snapshot{
			Scopes:         append([]model.Scope(nil), scan.Snapshot.Scopes...),
			TargetFailures: append([]model.TargetCoverageFailure(nil), scan.Snapshot.TargetFailures...),
		}
		failureScan.Changes = nil
		failureOptions := finalizeOptions
		if failureOptions.WorkTimeout < scanPersistenceTimeoutFloor {
			failureOptions.WorkTimeout = scanPersistenceTimeoutFloor
		}
		failureOptions.LeaseUntil = time.Now().UTC().Add(scanPersistenceWriterWaitTimeout + persistTimeout + time.Minute)
		failureEvents, failureErr := a.Engine.FinalizeManagedScanWithOptions(persistCtx, jobID, job, &failureScan, destinations, failureOptions)
		*scan = failureScan
		if failureErr == nil {
			r.leaseReleased = true
			events = failureEvents
			a.emitTenantEvents(scope, events)
			a.wakeDelivery()
		} else if a.Logger != nil {
			a.Logger.Error("failed to persist scan finalization failure", "job", job.Name, "scan_id", scan.ID, "error", failureErr)
		}
		r.exitMessage = "Scan failed because its result could not be finalized"
		r.publishCompletion(r.exitMessage)
		return *scan, events, errors.Join(finalizeErr, failureErr)
	}
	r.leaseReleased = true
	a.emitTenantEvents(scope, events)
	r.publishCompletion("Scan " + scan.Status)
	a.wakeDelivery()
	if scanErr != nil {
		return *scan, events, scanErr
	}
	return *scan, events, nil
}

// completedCycleResult reports whether scan carries the merged result of a
// resumable cycle that completed, which only its promotion compares with the
// baseline.
func completedCycleResult(scan model.Scan) bool {
	return scan.Resumable && scan.CycleID != "" && scan.CycleStatus == "completed" && (scan.Status == "success" || scan.Status == "incomplete")
}
