package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

const maintenanceInterval = 24 * time.Hour

// maintenanceRetryDelay is the first delay before a pass that panicked is
// retried. Each further panic doubles it, up to maintenanceInterval.
const maintenanceRetryDelay = time.Minute

// startMaintenanceWorker runs history and session maintenance independently
// of the heartbeat and schedule-reconciliation loop. It performs one startup
// pass, then repeats once a day until the daemon stops. A pass that panics
// is logged and retried after a delay that backs off to the daily interval,
// so one defect cannot stop retention pruning, session cleanup and cycle
// expiry for the rest of the process lifetime.
func (a *App) startMaintenanceWorker(ctx context.Context, system *store.SystemStore) <-chan struct{} {
	done := make(chan struct{})
	pruneHistory := a.pruneHistory
	if pruneHistory == nil {
		pruneHistory = system.PruneWithStats
	}
	retryDelay := a.maintenanceRetry
	if retryDelay <= 0 {
		retryDelay = maintenanceRetryDelay
	}
	go func() {
		defer close(done)
		defer a.recoverBackgroundPanic("history-maintenance-worker")
		backoff := retryDelay
		for startup := true; ; startup = false {
			wait := maintenanceInterval
			if a.runMaintenancePass(ctx, system, pruneHistory, startup) {
				wait, backoff = backoff, min(2*backoff, maintenanceInterval)
				a.maintenanceLogger().Warn("history maintenance pass panicked; retrying", "retry_in", wait.String())
			} else {
				backoff = retryDelay
			}
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return done
}

func (a *App) maintenanceLogger() *slog.Logger {
	if a.Logger == nil {
		return slog.Default()
	}
	return a.Logger
}

// runMaintenancePass prunes expired sessions and history and expires scan
// cycles. Each step recovers from its own panic, so a defect in one does not
// skip the others; panicked reports whether one did.
func (a *App) runMaintenancePass(ctx context.Context, system *store.SystemStore, pruneHistory func(context.Context, time.Time) (store.PruneStats, error), startup bool) (panicked bool) {
	logger := a.maintenanceLogger()
	step := func(name string, run func()) {
		finished := false
		defer func() { panicked = panicked || !finished }()
		defer a.recoverBackgroundPanic("history-maintenance-" + name)
		run()
		finished = true
	}
	step("sessions", func() { a.pruneExpiredSessions(ctx, logger, startup) })
	step("retention", func() { a.pruneRetainedHistory(ctx, logger, pruneHistory, startup) })
	step("cycle-expiry", func() { expireScanCycles(ctx, logger, system, startup) })
	return panicked
}

func (a *App) pruneExpiredSessions(ctx context.Context, logger *slog.Logger, startup bool) {
	if removed, err := a.Store.DeleteExpiredSessions(ctx, time.Now().UTC()); err != nil {
		if !errors.Is(err, context.Canceled) {
			message := "expired-session cleanup failed"
			if startup {
				message = "startup " + message
			}
			logger.Error(message, "error", err)
		}
	} else if removed > 0 {
		message := "expired sessions pruned"
		if startup {
			message = "startup " + message
		}
		logger.Info(message, "sessions", removed)
	}
}

func (a *App) pruneRetainedHistory(ctx context.Context, logger *slog.Logger, pruneHistory func(context.Context, time.Time) (store.PruneStats, error), startup bool) {
	stats, err := pruneHistory(ctx, time.Now().Add(-a.Config.Retention.Value()))
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			message := "history pruning failed"
			if startup {
				message = "startup " + message
			}
			logger.Error(message, "error", err)
		}
	} else if !startup || stats.Total() > 0 || stats.FTSOptimized {
		message := "history pruned"
		if startup {
			message = "startup " + message
		}
		logger.Info(message, "rows", stats.Total(), "scans", stats.Scans, "events", stats.Events, "sent_outbox", stats.SentOutbox, "failed_outbox", stats.FailedOutbox, "quarantined_outbox", stats.QuarantinedOutbox, "revisions", stats.Revisions, "cycles", stats.Cycles, "fts_optimized", stats.FTSOptimized, "reclaimed_pages", stats.ReclaimedPages)
	}
}

func expireScanCycles(ctx context.Context, logger *slog.Logger, system *store.SystemStore, startup bool) {
	if expired, err := system.ExpireScanCycles(ctx, time.Now().UTC()); err != nil {
		if !errors.Is(err, context.Canceled) {
			message := "scan-cycle expiry failed"
			if startup {
				message = "startup " + message
			}
			logger.Error(message, "error", err)
		}
	} else if expired > 0 {
		logger.Info("expired scan cycles", "cycles", expired)
	}
}
