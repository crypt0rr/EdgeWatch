package web

import (
	"github.com/crypt0rr/edgewatch/internal/apitypes"
	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/sandbox"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// ResponseTypes lists the response structs whose TypeScript declarations
// src/generated/api-types.ts holds, under the names that the console uses.
// go run ./scripts/gen-api-types writes that file from this list. A named
// struct that a listed struct contains must be listed too, and every
// exported field of a listed struct needs a json tag.
func ResponseTypes() []apitypes.Type {
	return []apitypes.Type{
		// The console's status, GET /api/v1/status.
		{Name: "AdminStatus", Value: adminStatusView{}},
		{Name: "LiveUpdateStatus", Value: liveUpdateStatusView{}},
		{Name: "ApplicationUpdateStatus", Value: applicationUpdateStatusView{}},
		{Name: "NotificationStatus", Value: notify.Status{}},
		{Name: "ScannerSandboxStatus", Value: sandbox.Status{}},
		{Name: "ScannerLandlockStatus", Value: sandbox.LandlockStatus{}},
		{Name: "ScannerSeccompStatus", Value: sandbox.SeccompStatus{}},
		{Name: "ScannerProcessLimits", Value: sandbox.ProcessLimits{}},
		{Name: "ScheduledBackupStatus", Value: app.BackupStatus{}},
		{Name: "UntrustedProxy", Value: auth.UntrustedProxy{}},
		{Name: "DeploymentTelemetry", Value: store.TenantTelemetry{}},

		// The platform status, GET /api/v1/platform/status.
		{Name: "PlatformStatus", Value: platformStatusView{}},
		{Name: "PlatformUnitCounts", Value: platformUnitCountsView{}},
		{Name: "PlatformAdminCounts", Value: platformAdminCountsView{}},
		{Name: "PlatformCapacityStatus", Value: platformCapacityStatusView{}},
		{Name: "DeploymentLimits", Value: platformLimitsView{}},
		{Name: "DeploymentSlots", Value: platformDeploymentSlotsView{}},
		{Name: "PlatformTelemetry", Value: store.DeploymentTelemetry{}},

		// A scan with its snapshot, and the summary that scan lists hold.
		{Name: "Scan", Value: model.Scan{}},
		{Name: "ScanSummary", Value: model.ScanSummary{}},
		{Name: "Change", Value: model.Change{}},
		{Name: "Snapshot", Value: model.Snapshot{}},
		{Name: "Unit", Value: model.Unit{}},
		{Name: "PortState", Value: model.PortState{}},
		{Name: "Scope", Value: model.Scope{}},
		{Name: "HostState", Value: model.HostState{}},
		{Name: "TargetCoverageFailure", Value: model.TargetCoverageFailure{}},
		{Name: "HostObservation", Value: model.HostObservation{}},
		{Name: "LinkAddress", Value: model.LinkAddress{}},
		{Name: "Hostname", Value: model.Hostname{}},
		{Name: "ProtocolObservation", Value: model.ProtocolObservation{}},
		{Name: "PortObservation", Value: model.PortObservation{}},
		{Name: "ServiceObservation", Value: model.ServiceObservation{}},
		{Name: "StateSummary", Value: model.StateSummary{}},
		{Name: "StateReason", Value: model.StateReason{}},
	}
}
