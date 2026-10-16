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
	now := a.nowUTC()
	due, err := system.DueChangeWindows(ctx, now, changeWindowExpiryBatchSize)
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
		summaryNotificationUnavailable := false
		if a.Notifier != nil {
			selected, selectErr := a.Notifier.Tenant(ts).QueueDestinationsForJob(ctx, job.Job)
			if selectErr != nil {
				summaryNotificationUnavailable = true
				now = a.nowUTC()
				if now.Before(item.EndAt.Add(store.ChangeWindowSummaryDestinationGrace)) {
					// Preserve the due window and its held alerts. The regular heartbeat
					// retries this read until its documented one-hour bound.
					a.maintenanceLogger().Warn("planned change window summary destinations are temporarily unavailable", "window_id", item.ID)
					continue
				}
				a.maintenanceLogger().Warn("planned change window summary notification not queued after destination retry grace", "window_id", item.ID)
			} else {
				destinations = selected
			}
		}
		var summary store.ChangeWindowSummary
		var changed bool
		if summaryNotificationUnavailable {
			summary, changed, err = ts.ExpireChangeWindowWithoutSummaryNotification(ctx, item.ID, a.nowUTC)
		} else {
			summary, changed, err = ts.ExpireChangeWindow(ctx, item.ID, a.nowUTC, destinations)
		}
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
