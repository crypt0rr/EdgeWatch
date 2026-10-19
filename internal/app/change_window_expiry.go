package app

import (
	"context"
	"errors"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

const changeWindowExpiryBatchSize = 64

const changeWindowExpiryHeartbeatBudget = 5 * time.Second

// expireChangeWindows closes due windows on startup and from the daemon
// heartbeat. The store commits the review state and summary notification
// intent atomically; a destination lookup failure cannot discard that review.
func (a *App) expireChangeWindows(ctx context.Context, system *store.SystemStore, startup bool) {
	if a == nil || a.Store == nil || system == nil {
		return
	}
	budget := changeWindowExpiryHeartbeatBudget
	if a.heartbeatInterval > 0 && a.heartbeatInterval/2 < budget {
		budget = a.heartbeatInterval / 2
	}
	if budget <= 0 {
		budget = time.Second
	}
	passCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	now := a.nowUTC()
	due, err := system.DueChangeWindows(passCtx, now, changeWindowExpiryBatchSize)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			a.maintenanceLogger().Error("planned change window expiry lookup failed", "startup", startup, "error", err)
		}
		return
	}
	for _, item := range due {
		if err := passCtx.Err(); err != nil {
			return
		}
		scope, err := a.Store.TenantScopeByID(passCtx, item.TenantID)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || store.IsSQLiteBusy(err) {
				return
			}
			if !errors.Is(err, store.ErrNoTenantScope) && !errors.Is(err, context.Canceled) {
				a.maintenanceLogger().Warn("planned change window tenant could not be loaded", "window_id", item.ID, "error", err)
			}
			continue
		}
		ts := a.Store.Tenant(scope)
		job, err := ts.GetJob(passCtx, item.JobID)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || store.IsSQLiteBusy(err) {
				return
			}
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, context.Canceled) {
				a.maintenanceLogger().Warn("planned change window job could not be loaded", "window_id", item.ID, "error", err)
			}
			continue
		}
		destinations := []string{}
		summaryNotificationUnavailable := false
		if a.Notifier != nil {
			selected, selectErr := a.Notifier.Tenant(ts).QueueDestinationsForJob(passCtx, job.Job)
			if selectErr != nil {
				if errors.Is(selectErr, context.DeadlineExceeded) || store.IsSQLiteBusy(selectErr) {
					return
				}
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
			summary, changed, err = ts.ExpireChangeWindowWithoutSummaryNotification(passCtx, item.ID, a.nowUTC)
		} else {
			summary, changed, err = ts.ExpireChangeWindow(passCtx, item.ID, a.nowUTC, destinations)
		}
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || store.IsSQLiteBusy(err) {
				return
			}
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
