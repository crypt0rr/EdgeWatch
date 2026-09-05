package app

import (
	"context"
	"errors"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// runResumableAttempt executes one time-bounded portion of a broad scan. It
// returns handled=false when the scanner's plan fits in one invocation and the
// caller should use the ordinary Scanner path. Every other outcome is handled
// here, including persistence of an intermediate timeout/cancellation record.
func (a *App) runResumableAttempt(ctx, scanCtx context.Context, job config.Job, jobID string, scan *model.Scan, run *activeRun, rs scanner.ResumableScanner, manual bool) (handled bool, snapshot model.Snapshot, runErr error) {
	if jobID == "" {
		return false, model.Snapshot{}, nil
	}
	// Persistence must outlive scanCtx: a timed-out/canceled Nmap process still
	// needs to checkpoint its result and cycle state. SQLite's busy timeout
	// bounds each operation, while the caller's daemon context remains free to
	// stop future work.
	stateCtx := context.Background()
	// Capture the active cycle before expiry housekeeping. If this trigger is
	// the first one to notice an expired resume window, retain that fact as a
	// terminal failed scan so the operator receives the promised failure
	// notification. The following trigger will see no active cycle and start a
	// fresh plan.
	previousCycle, previousCycleErr := a.Store.GetActiveScanCycle(stateCtx, jobID)
	if previousCycleErr != nil && !errors.Is(previousCycleErr, store.ErrNoScanCycle) {
		scan.Status = "failed"
		scan.Error = previousCycleErr.Error()
		return true, model.Snapshot{}, previousCycleErr
	}
	now := time.Now().UTC()
	if _, expiryErr := a.Store.ExpireScanCycles(stateCtx, now); expiryErr != nil {
		scan.Status = "failed"
		scan.Error = expiryErr.Error()
		return true, model.Snapshot{}, expiryErr
	}
	if previousCycleErr == nil {
		if expiredCycle, cycleErr := a.Store.GetScanCycle(stateCtx, previousCycle.ID); cycleErr == nil && expiredCycle.Status == "expired" {
			return expiredCycleAttempt(scan, expiredCycle)
		}
	}
	// The daemon also performs expiry housekeeping once per day. If it expired
	// the cycle before this trigger arrived, surface the expiry once now rather
	// than silently starting a new cycle; the following trigger can then begin
	// fresh after the terminal record is persisted.
	if latestCycle, latestErr := a.Store.GetLatestScanCycle(stateCtx, jobID); latestErr == nil && latestCycle.Status == "expired" {
		notified, notifyErr := a.Store.ScanCycleExpiryNotified(stateCtx, latestCycle.ID)
		if notifyErr != nil {
			scan.Status = "failed"
			scan.Error = notifyErr.Error()
			return true, model.Snapshot{}, notifyErr
		}
		if !notified {
			return expiredCycleAttempt(scan, latestCycle)
		}
	} else if latestErr != nil && !errors.Is(latestErr, store.ErrNoScanCycle) {
		scan.Status = "failed"
		scan.Error = latestErr.Error()
		return true, model.Snapshot{}, latestErr
	}

	cycle, err := a.Store.GetActiveScanCycle(stateCtx, jobID)
	if err != nil && !errors.Is(err, store.ErrNoScanCycle) {
		scan.Status = "failed"
		scan.Error = err.Error()
		return true, model.Snapshot{}, err
	}
	if errors.Is(err, store.ErrNoScanCycle) {
		// Completing the cycle and promoting its merged snapshot to scan history
		// are separate transactions. If the process stopped between them, recover
		// that already-complete cycle before planning a new one; otherwise a full
		// range could be scanned twice while its first result never reaches the
		// baseline engine.
		if latest, latestErr := a.Store.GetLatestScanCycle(stateCtx, jobID); latestErr == nil && latest.Status == "completed" {
			hasScan, scanErr := a.Store.ScanCycleHasScan(stateCtx, latest.ID)
			if scanErr != nil {
				scan.Status = "failed"
				scan.Error = scanErr.Error()
				return true, model.Snapshot{}, scanErr
			}
			if !hasScan {
				return a.recoverCompletedCycle(stateCtx, scan, run, latest)
			}
		} else if latestErr != nil && !errors.Is(latestErr, store.ErrNoScanCycle) {
			scan.Status = "failed"
			scan.Error = latestErr.Error()
			return true, model.Snapshot{}, latestErr
		}
		plan, planErr := rs.Plan(scanCtx, job)
		if planErr != nil {
			if errors.Is(scanCtx.Err(), context.Canceled) {
				scan.Status = "canceled"
				scan.Error = "scan canceled while creating the scan plan"
			} else if errors.Is(scanCtx.Err(), context.DeadlineExceeded) || errors.Is(planErr, context.DeadlineExceeded) {
				scan.Status = "timed_out"
				scan.Error = "scan timed out while creating the scan plan"
			} else {
				scan.Status = "failed"
				scan.Error = planErr.Error()
			}
			return true, model.Snapshot{}, planErr
		}
		if len(plan.Units) <= 1 {
			return false, model.Snapshot{}, nil
		}
		// A scanner may return only the resolved work units from Plan. Persist the
		// exact managed job alongside them so a resumed attempt has a complete
		// immutable configuration even for alternate scanner implementations.
		plan.Job = job
		now := time.Now().UTC()
		cycle, err = a.Store.CreateScanCycle(stateCtx, store.ScanCycleRecord{
			JobID:         jobID,
			Job:           job.Name,
			JobRevision:   scan.JobRevision,
			ConfigHash:    job.SecurityHash(),
			ExecutionHash: job.ExecutionHash(),
			Plan:          plan,
			StartedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(job.ResumeWindowValue()),
		})
		if err != nil {
			scan.Status = "failed"
			scan.Error = err.Error()
			return true, model.Snapshot{}, err
		}
	}
	if cycle.Status == "stalled" && !manual {
		// Scheduled triggers must not spin a known-stalled cycle forever. The
		// scheduler performs the same guard before acquiring a lease; this second
		// check protects against a race with a manual retry or another process.
		return true, model.Snapshot{}, ErrScanCycleStalled
	}

	if cycle.ConfigHash != job.SecurityHash() {
		message := "scan cycle settings changed; discard the paused cycle before retrying"
		_, _ = a.Store.MarkScanCycleStalled(stateCtx, cycle.ID, message)
		scan.Resumable = true
		scan.CycleID = cycle.ID
		scan.CycleStatus = "stalled"
		scan.Status = "failed"
		scan.Error = message
		return true, model.Snapshot{}, errors.New(message)
	}

	cycle, err = a.Store.StartScanCycleAttempt(stateCtx, cycle.ID)
	if err != nil {
		if errors.Is(err, store.ErrCycleNotResumable) {
			scan.Resumable = true
			scan.CycleID = cycle.ID
			scan.CycleStatus = "expired"
			scan.Status = "timed_out"
			scan.Error = "scan cycle expired; a future trigger will start a fresh scan"
			return true, model.Snapshot{}, err
		}
		scan.Status = "failed"
		scan.Error = err.Error()
		return true, model.Snapshot{}, err
	}
	setScanCycleMetadata(scan, cycle)
	setActiveCycle(run, cycle, "starting", 0)

	completedThisAttempt := 0
	for {
		unit, nextErr := a.Store.NextScanCycleUnit(stateCtx, cycle.ID)
		if errors.Is(nextErr, store.ErrNoPendingUnit) {
			return a.finishResumableCycle(stateCtx, scan, run, cycle)
		}
		if nextErr != nil {
			if errors.Is(nextErr, store.ErrCycleNotResumable) {
				applyCycleFailureState(stateCtx, a.Store, scan, cycle.ID, nextErr.Error())
				return true, model.Snapshot{}, nextErr
			}
			scan.Status = "failed"
			scan.Error = nextErr.Error()
			if stalled, stallErr := a.Store.MarkScanCycleStalled(stateCtx, cycle.ID, nextErr.Error()); stallErr == nil {
				setScanCycleMetadata(scan, stalled)
			} else {
				scan.CycleStatus = "stalled"
			}
			return true, model.Snapshot{}, nextErr
		}
		claimed, claimErr := a.Store.ClaimScanCycleUnit(stateCtx, cycle.ID, unit.Sequence)
		if claimErr != nil {
			if errors.Is(claimErr, store.ErrNoPendingUnit) {
				continue
			}
			scan.Status = "failed"
			scan.Error = claimErr.Error()
			if errors.Is(claimErr, store.ErrCycleNotResumable) {
				applyCycleFailureState(stateCtx, a.Store, scan, cycle.ID, claimErr.Error())
			} else if stalled, stallErr := a.Store.MarkScanCycleStalled(stateCtx, cycle.ID, claimErr.Error()); stallErr == nil {
				setScanCycleMetadata(scan, stalled)
			} else {
				scan.CycleStatus = "stalled"
			}
			return true, model.Snapshot{}, claimErr
		}
		setActiveCycle(run, cycle, "scanning", claimed.Sequence+1)
		attemptJob := cycle.Plan.Job
		// The scope and pinned DNS expansion remain immutable, while execution
		// settings such as timing may be updated between paused attempts.
		attemptJob.Timing = job.Timing
		fragment, scanErr := rs.ScanWorkUnit(scanCtx, attemptJob, claimed.Unit, func(progress scanner.Progress) {
			progress.TotalUnits = cycle.TotalUnits
			progress.CurrentUnit = claimed.Sequence + 1
			a.updateActiveProgress(scan.ID, progress)
			setActiveCycleProgress(run, cycle, progress, claimed.Unit)
		})
		// A scanner implementation must honor the context, but treat a late
		// successful return after cancellation as interrupted work as well. This
		// prevents a result produced outside the attempt deadline from being
		// checkpointed into the cycle.
		if scanErr == nil && scanCtx.Err() != nil {
			scanErr = scanCtx.Err()
		}
		if scanErr == nil {
			if completeErr := a.Store.CompleteScanCycleUnit(stateCtx, cycle.ID, claimed.Sequence, fragment); completeErr != nil {
				if errors.Is(completeErr, store.ErrCycleNotResumable) {
					applyCycleFailureState(stateCtx, a.Store, scan, cycle.ID, completeErr.Error())
				} else {
					scan.Status = "failed"
					scan.Error = completeErr.Error()
					if stalled, stallErr := a.Store.MarkScanCycleStalled(stateCtx, cycle.ID, completeErr.Error()); stallErr == nil {
						setScanCycleMetadata(scan, stalled)
					} else {
						scan.CycleStatus = "stalled"
					}
				}
				return true, model.Snapshot{}, completeErr
			}
			completedThisAttempt++
			cycle, err = a.Store.GetScanCycle(stateCtx, cycle.ID)
			if err != nil {
				scan.Status = "failed"
				scan.Error = err.Error()
				return true, model.Snapshot{}, err
			}
			setScanCycleMetadata(scan, cycle)
			setActiveCycle(run, cycle, "checkpointed", claimed.Sequence)
			continue
		}

		timedOut := errors.Is(scanCtx.Err(), context.DeadlineExceeded) || errors.Is(scanErr, context.DeadlineExceeded)
		canceled := errors.Is(scanCtx.Err(), context.Canceled) || errors.Is(scanErr, context.Canceled)
		if timedOut || canceled {
			lastError := "scan canceled"
			if timedOut {
				lastError = "scan timed out"
			}
			if scanErr != nil {
				lastError = scanErr.Error()
			}
			if first, second, split := scanner.SplitWorkUnit(claimed.Unit); timedOut && split {
				if splitErr := a.Store.SplitScanCycleUnit(stateCtx, cycle.ID, claimed.Sequence, first, second, lastError); splitErr != nil {
					if errors.Is(splitErr, store.ErrCycleNotResumable) {
						applyCycleFailureState(stateCtx, a.Store, scan, cycle.ID, splitErr.Error())
					} else {
						scan.Status = "failed"
						scan.Error = splitErr.Error()
						if stalled, stallErr := a.Store.MarkScanCycleStalled(stateCtx, cycle.ID, splitErr.Error()); stallErr == nil {
							setScanCycleMetadata(scan, stalled)
						} else {
							scan.CycleStatus = "stalled"
						}
					}
					return true, model.Snapshot{}, splitErr
				}
			} else if retryErr := a.Store.RetryScanCycleUnit(stateCtx, cycle.ID, claimed.Sequence, lastError); retryErr != nil {
				if errors.Is(retryErr, store.ErrCycleNotResumable) {
					applyCycleFailureState(stateCtx, a.Store, scan, cycle.ID, retryErr.Error())
				} else {
					scan.Status = "failed"
					scan.Error = retryErr.Error()
					if stalled, stallErr := a.Store.MarkScanCycleStalled(stateCtx, cycle.ID, retryErr.Error()); stallErr == nil {
						setScanCycleMetadata(scan, stalled)
					} else {
						scan.CycleStatus = "stalled"
					}
				}
				return true, model.Snapshot{}, retryErr
			}
			paused, pauseErr := a.Store.PauseScanCycle(stateCtx, cycle.ID, timedOut && completedThisAttempt == 0, lastError)
			if pauseErr != nil {
				// A persistence failure must not be reported as resumable progress.
				scan.Status = "failed"
				scan.Error = pauseErr.Error()
				return true, model.Snapshot{}, pauseErr
			}
			cycle = paused
			if cycle.Status == "paused" && cycle.NoProgressAttempts >= 3 {
				stalled, stallErr := a.Store.MarkScanCycleStalled(stateCtx, cycle.ID, "scan made no progress in three consecutive attempts")
				if stallErr != nil {
					scan.Status = "failed"
					scan.Error = stallErr.Error()
					return true, model.Snapshot{}, stallErr
				}
				cycle = stalled
				scan.Status = "failed"
				scan.Error = "scan stalled after three attempts without progress"
			} else if canceled {
				scan.Status = "canceled"
				scan.Error = "scan canceled; progress was saved"
			} else {
				scan.Status = "timed_out"
				scan.Error = "scan timed out; progress was saved for the next trigger"
			}
			scan.Resumable = true
			setScanCycleMetadata(scan, cycle)
			return true, model.Snapshot{}, scanErr
		}

		stalled, stallErr := a.Store.MarkScanCycleStalled(stateCtx, cycle.ID, scanErr.Error())
		if stallErr == nil {
			cycle = stalled
		} else {
			scan.Status = "failed"
			scan.Error = stallErr.Error()
			return true, model.Snapshot{}, stallErr
		}
		scan.Resumable = true
		scan.Status = "failed"
		scan.Error = scanErr.Error()
		setScanCycleMetadata(scan, cycle)
		return true, model.Snapshot{}, scanErr
	}
}

// recoverCompletedCycle promotes checkpoints left behind by a process crash
// after CompleteScanCycle committed but before FinalizeManagedScan persisted
// the immutable scan and baseline transition.
func (a *App) recoverCompletedCycle(ctx context.Context, scan *model.Scan, run *activeRun, cycle store.ScanCycleRecord) (bool, model.Snapshot, error) {
	plan, fragments, err := a.Store.LoadScanCycleFragments(ctx, cycle.ID)
	if err != nil {
		scan.Status = "failed"
		scan.Error = err.Error()
		return true, model.Snapshot{}, err
	}
	if cycle.CompletedUnits != cycle.TotalUnits || len(fragments) != cycle.TotalUnits {
		scan.Status = "failed"
		scan.Error = "completed scan cycle is missing one or more checkpoints"
		return true, model.Snapshot{}, errors.New(scan.Error)
	}
	snapshot := scanner.MergeWorkSnapshots(plan, fragments)
	// Preserve the scope and revision that produced the cycle. If the current
	// job has since changed security settings, FinalizeManagedScan will retain
	// this recovered result as superseded without mutating the new baseline.
	scan.ConfigHash = cycle.ConfigHash
	scan.JobRevision = cycle.JobRevision
	scan.Status = "success"
	scan.Resumable = true
	scan.Snapshot = snapshot
	setScanCycleMetadata(scan, cycle)
	setActiveCycle(run, cycle, "complete", cycle.TotalUnits)
	return true, snapshot, nil
}

func expiredCycleAttempt(scan *model.Scan, cycle store.ScanCycleRecord) (bool, model.Snapshot, error) {
	scan.Resumable = true
	scan.CycleID = cycle.ID
	scan.CycleAttempt = cycle.AttemptCount
	scan.CycleStatus = cycle.Status
	scan.CompletedProbes = cycle.CompletedProbes
	scan.TotalProbes = cycle.TotalProbes
	scan.CompletedUnits = cycle.CompletedUnits
	scan.TotalUnits = cycle.TotalUnits
	scan.NoProgressTries = cycle.NoProgressAttempts
	scan.Status = "timed_out"
	scan.Error = "scan cycle expired; a future trigger will start a fresh scan"
	return true, model.Snapshot{}, errors.New(scan.Error)
}

func (a *App) finishResumableCycle(ctx context.Context, scan *model.Scan, run *activeRun, cycle store.ScanCycleRecord) (bool, model.Snapshot, error) {
	plan, fragments, err := a.Store.LoadScanCycleFragments(ctx, cycle.ID)
	if err != nil {
		scan.Status = "failed"
		scan.Error = err.Error()
		if stalled, stallErr := a.Store.MarkScanCycleStalled(ctx, cycle.ID, err.Error()); stallErr == nil {
			setScanCycleMetadata(scan, stalled)
		} else {
			scan.CycleStatus = "stalled"
		}
		return true, model.Snapshot{}, err
	}
	snapshot := scanner.MergeWorkSnapshots(plan, fragments)
	cycleID := cycle.ID
	cycle, err = a.Store.CompleteScanCycle(ctx, cycleID)
	if err != nil {
		if errors.Is(err, store.ErrCycleNotResumable) {
			applyCycleFailureState(ctx, a.Store, scan, cycleID, err.Error())
		} else {
			scan.Status = "failed"
			scan.Error = err.Error()
		}
		return true, model.Snapshot{}, err
	}
	scan.Status = "success"
	scan.Resumable = true
	scan.Snapshot = snapshot
	setScanCycleMetadata(scan, cycle)
	setActiveCycle(run, cycle, "complete", cycle.TotalUnits)
	return true, snapshot, nil
}

func setScanCycleMetadata(scan *model.Scan, cycle store.ScanCycleRecord) {
	scan.Resumable = true
	scan.CycleID = cycle.ID
	scan.CycleAttempt = cycle.AttemptCount
	scan.CycleStatus = cycle.Status
	scan.CompletedProbes = cycle.CompletedProbes
	scan.TotalProbes = cycle.TotalProbes
	scan.CompletedUnits = cycle.CompletedUnits
	scan.TotalUnits = cycle.TotalUnits
	scan.NoProgressTries = cycle.NoProgressAttempts
}

// applyCycleFailureState refreshes scan metadata after a cycle operation was
// rejected because the durable cycle became terminal concurrently (most
// commonly expiry housekeeping racing a returning Nmap process). In that case
// preserve the terminal state instead of relabelling an expired cycle as
// stalled; the engine will emit the normal failure event and never compare its
// partial snapshot.
func applyCycleFailureState(ctx context.Context, cycles *store.Store, scan *model.Scan, cycleID, fallback string) {
	if cycle, err := cycles.GetScanCycle(ctx, cycleID); err == nil {
		setScanCycleMetadata(scan, cycle)
		if cycle.Status == "expired" {
			scan.Status = "timed_out"
			scan.Error = "scan cycle expired; a future trigger will start a fresh scan"
			return
		}
	}
	scan.Status = "failed"
	scan.Error = fallback
}

func setActiveCycle(run *activeRun, cycle store.ScanCycleRecord, phase string, unit int) {
	if run == nil {
		return
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	run.scan.CycleID = cycle.ID
	run.scan.CycleAttempt = cycle.AttemptCount
	run.scan.CycleStatus = cycle.Status
	run.scan.CycleCompletedProbes = cycle.CompletedProbes
	run.scan.CycleTotalProbes = cycle.TotalProbes
	run.scan.CycleCompletedUnits = cycle.CompletedUnits
	run.scan.CycleTotalUnits = cycle.TotalUnits
	run.scan.CycleNoProgressAttempts = cycle.NoProgressAttempts
	run.scan.CompletedProbes = cycle.CompletedProbes
	run.scan.TotalProbes = cycle.TotalProbes
	run.scan.ProgressPercent = progressPercent(scanner.Progress{CompletedProbes: cycle.CompletedProbes, TotalProbes: cycle.TotalProbes})
	if phase != "" {
		run.scan.Phase = phase
	}
	if unit > 0 {
		run.scan.CurrentUnit = int64(unit)
	}
}

func setActiveCycleProgress(run *activeRun, cycle store.ScanCycleRecord, progress scanner.Progress, unit scanner.WorkUnit) {
	if run == nil {
		return
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	run.scan.CycleID = cycle.ID
	run.scan.CycleAttempt = cycle.AttemptCount
	run.scan.CycleStatus = "running"
	run.scan.CycleCompletedProbes = cycle.CompletedProbes + progress.CompletedProbes
	run.scan.CycleTotalProbes = cycle.TotalProbes
	run.scan.CycleCompletedUnits = cycle.CompletedUnits
	run.scan.CycleTotalUnits = cycle.TotalUnits
	run.scan.CurrentUnitPorts = unit.Ports
	run.scan.CurrentUnitAddresses = len(unit.Addresses)
	run.scan.CompletedProbes = run.scan.CycleCompletedProbes
	run.scan.TotalProbes = cycle.TotalProbes
	run.scan.ProgressPercent = progressPercent(scanner.Progress{CompletedProbes: run.scan.CompletedProbes, TotalProbes: cycle.TotalProbes})
}
