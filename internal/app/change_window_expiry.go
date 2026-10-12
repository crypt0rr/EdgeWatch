package app

import (
	"context"
	"errors"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

const changeWindowExpiryBatchSize = 64

// expireChangeWindows closes due windows on startup and from the daemon
// heartbeat. The store commits the review state and summary notification
// intent atomically; a destination lookup failure cannot discard that review.
func (a *App) expireChangeWindows(ctx context.Context, system *store.SystemStore, startup bool) {
	if a == nil || a.Store == nil || system == nil {
		return
	}
	due, err := system.DueChangeWindows(ctx, a.nowUTC(), changeWindowExpiryBatchSize)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			a.maintenanceLogger().Error("planned change window expiry lookup failed", "startup", startup, "error", err)
		}
		return
	}
	for _, item := range due {
		if err := ctx.Err(); err != nil {
			return
		}
		scope, err := a.Store.TenantScopeByID(ctx, item.TenantID)
		if err != nil {
			if !errors.Is(err, store.ErrNoTenantScope) && !errors.Is(err, context.Canceled) {
				a.maintenanceLogger().Warn("planned change window tenant could not be loaded", "window_id", item.ID, "error", err)
			}
			continue
		}
		ts := a.Store.Tenant(scope)
		job, err := ts.GetJob(ctx, item.JobID)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, context.Canceled) {
				a.maintenanceLogger().Warn("planned change window job could not be loaded", "window_id", item.ID, "error", err)
			}
			continue
		}
		destinations := []string{}
		if a.Notifier != nil {
			selected, selectErr := a.Notifier.Tenant(ts).QueueDestinationsForJob(ctx, job.Job)
			if selectErr != nil {
				// Review state is more important than its optional delivery. A later
				// event cannot be replayed, but the due review remains in storage.
				a.maintenanceLogger().Warn("planned change window summary destinations could not be loaded", "window_id", item.ID, "error", selectErr)
			} else {
				destinations = selected
			}
		}
		summary, changed, err := ts.ExpireChangeWindow(ctx, item.ID, a.nowUTC, destinations)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				a.maintenanceLogger().Error("planned change window expiry failed", "window_id", item.ID, "error", err)
			}
			continue
		}
		if !changed {
			continue
		}
		a.emitTenantEvents(scope, []model.Event{{Type: "change-window.updated", JobID: item.JobID, Job: job.Job.Name, Message: "Planned change window closed", TenantID: item.TenantID, CreatedAt: a.nowUTC()}})
		if summary.SuppressedEventCount+summary.InFlightEventCount+summary.UnknownOutcomeEventCount > 0 {
			a.wakeDelivery()
		}
	}
}
