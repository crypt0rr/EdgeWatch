package app

import (
	"context"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/sandbox"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// deploymentAlertsBudget bounds one pass of checkDeploymentAlerts, so a
// busy SQLite writer cannot hold up the daemon loop. A pass that runs out of
// time is safe; the next heartbeat repeats it.
const deploymentAlertsBudget = 5 * time.Second

// sandboxHealthState returns the confinement state of a sandbox status: whether
// its processes keep an identity without root, by the sandbox or because
// the daemon itself does not run as root, and whether Landlock restricts
// them.
func sandboxHealthState(status sandbox.Status) string {
	identity := status.State == sandbox.StateEnforced || status.ProcessUID != 0
	landlock := status.Landlock.State == sandbox.StateEnforced
	switch {
	case identity && landlock:
		return model.SandboxStateSandboxed
	case identity:
		return model.SandboxStateIdentityOnly
	case landlock:
		return model.SandboxStateLandlockOnly
	default:
		return model.SandboxStateUnconfined
	}
}

// SandboxHealth returns the confinement states of the scanner and
// notification processes of this daemon. A sandbox without a policy, as in
// a library caller, is left out.
func (a *App) SandboxHealth() store.SandboxHealth {
	var observed store.SandboxHealth
	if a == nil {
		return observed
	}
	if a.sandbox != nil {
		observed.Scanner = sandboxHealthState(a.sandbox.Status())
	}
	if a.notificationSandbox != nil {
		observed.Notification = sandboxHealthState(a.notificationSandbox.Status())
	}
	return observed
}

// checkDeploymentAlerts records the deployment-health alerts that are due
// and reports the security alerts that ended windows held back: a sandbox
// whose state changed since the last alert, deliveries that failed for good
// since the last report, and the summaries of the security alert windows.
// The daemon runs it when it starts and with each heartbeat, so a change
// that an alert window held back is reported once the window ends. It wakes
// the delivery worker when it queued anything.
func (a *App) checkDeploymentAlerts(ctx context.Context, now time.Time) {
	if a.Store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deploymentAlertsBudget)
	defer cancel()
	logger := a.silenceLogger()
	queued := false
	if recorded, err := a.Store.Platform().RecordSandboxHealth(ctx, a.SandboxHealth(), now); err != nil {
		logger.Warn("sandbox health alert could not be recorded", "error", err)
	} else if recorded > 0 {
		queued = true
	}
	if recorded, err := a.Store.Platform().RecordDeliveryFailureHealth(ctx, now); err != nil {
		logger.Warn("failed delivery alert could not be recorded", "error", err)
	} else if recorded {
		queued = true
	}
	if summaries, err := a.Store.System().FlushSecurityAlertWindows(ctx, now); err != nil {
		logger.Warn("security alert summaries could not be queued", "error", err)
	} else if summaries > 0 {
		queued = true
	}
	if queued {
		a.wakeDelivery()
	}
}
