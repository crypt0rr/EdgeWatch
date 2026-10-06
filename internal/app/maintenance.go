package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

const maintenanceInterval = 24 * time.Hour

// startMaintenanceWorker runs history and session maintenance independently
// of the heartbeat and schedule-reconciliation loop. It performs one startup
// pass, then repeats once a day until the daemon stops.
func (a *App) startMaintenanceWorker(ctx context.Context, system *store.SystemStore) <-chan struct{} {
	done := make(chan struct{})
	pruneHistory := a.pruneHistory
	if pruneHistory == nil {
		pruneHistory = system.PruneWithStats
	}
	go func() {
		defer close(done)
		defer a.recoverBackgroundPanic("history-maintenance-worker")
		ticker := time.NewTicker(maintenanceInterval)
		defer ticker.Stop()
		a.runMaintenancePass(ctx, system, pruneHistory, true)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.runMaintenancePass(ctx, system, pruneHistory, false)
			}
		}
	}()
	return done
}

func (a *App) runMaintenancePass(ctx context.Context, system *store.SystemStore, pruneHistory func(context.Context, time.Time) (store.PruneStats, error), startup bool) {
	logger := a.Logger
	if logger == nil {
		logger = slog.Default()
	}
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
