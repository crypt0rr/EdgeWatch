package web

import (
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/sandbox"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// The status responses below were maps before they became structs. Their
// fields are in the order of their JSON names, as encoding/json wrote the
// keys of those maps, so the responses kept their bytes.

// adminStatusView is the status that the console shows a signed-in account.
// A viewer's holds only the version, its release page, and the update
// status. An operator's and an administrator's hold the rest too, except
// what cannot be read: the scan capacity, the notification state, and the
// telemetry are then left out. The live-update counters, the untrusted
// proxy, and the scheduled backups describe the whole deployment, so they
// are present only while one unit exists, the last two for its
// administrators alone. The inactive config.yaml jobs are the default
// unit's.
type adminStatusView struct {
	Backups                  *app.BackupStatus           `json:"backups,omitempty"`
	Configured               bool                        `json:"configured,omitempty"`
	DisplayName              *string                     `json:"display_name,omitempty"`
	LegacyYAMLJobs           []string                    `json:"legacy_yaml_jobs,omitempty"`
	LiveUpdates              *liveUpdateStatusView       `json:"live_updates,omitempty"`
	MaxConcurrentScans       *int                        `json:"max_concurrent_scans,omitempty"`
	MaxNaabuProbeCount       *int64                      `json:"max_naabu_probe_count,omitempty"`
	MaxProbeCount            *int64                      `json:"max_probe_count,omitempty"`
	NotificationDestinations *int                        `json:"notification_destinations,omitempty"`
	NotificationSandbox      *sandbox.Status             `json:"notification_sandbox,omitempty"`
	Notifications            *notify.Status              `json:"notifications,omitempty"`
	Permissions              []string                    `json:"permissions,omitempty"`
	RDAPEnabled              *bool                       `json:"rdap_enabled,omitempty"`
	Retention                string                      `json:"retention,omitempty"`
	Role                     string                      `json:"role,omitempty"`
	ScannerSandbox           *sandbox.Status             `json:"scanner_sandbox,omitempty"`
	Telemetry                *store.TenantTelemetry      `json:"telemetry,omitempty"`
	UntrustedProxy           *auth.UntrustedProxy        `json:"untrusted_proxy,omitempty"`
	Updates                  applicationUpdateStatusView `json:"updates"`
	Username                 string                      `json:"username,omitempty"`
	Version                  string                      `json:"version"`
	VersionReleaseURL        string                      `json:"version_release_url,omitempty"`
}

// liveUpdateStatusView counts the live updates that the server keeps for
// reconnecting consoles and the ones that it dropped.
type liveUpdateStatusView struct {
	DroppedEvents uint64 `json:"dropped_events"`
	HistorySize   int    `json:"history_size"`
}

// applicationUpdateStatusView is the outcome of the release check, which
// both the console's status and the platform status show. Status is
// up_to_date, update_available, ahead, check_failed, disabled, or
// development_build.
type applicationUpdateStatusView struct {
	Available             bool      `json:"available"`
	CurrentVersion        string    `json:"current_version"`
	Enabled               bool      `json:"enabled"`
	Error                 string    `json:"error,omitempty"`
	LastCheckedAt         time.Time `json:"last_checked_at,omitzero"`
	LastSuccessfulCheckAt time.Time `json:"last_successful_check_at,omitzero"`
	LatestVersion         string    `json:"latest_version,omitempty"`
	PublishedAt           string    `json:"published_at,omitempty"`
	ReleaseName           string    `json:"release_name,omitempty"`
	ReleaseURL            string    `json:"release_url,omitempty"`
	Stale                 bool      `json:"stale"`
	Status                string    `json:"status"`
}

// platformStatusView reports the deployment to the platform administrators
// as numbers: the units by state, their accounts, jobs, and stored scans,
// the platform administrators, the scan capacity and its use, the version
// and update status, the untrusted proxy once one was seen, and the outcome
// of the scheduled backups when they are on.
type platformStatusView struct {
	Accounts          int                         `json:"accounts"`
	Backups           *app.BackupStatus           `json:"backups,omitempty"`
	Capacity          platformCapacityStatusView  `json:"capacity"`
	Jobs              int                         `json:"jobs"`
	PlatformAdmins    platformAdminCountsView     `json:"platform_admins"`
	StoredScans       int64                       `json:"stored_scans"`
	Units             platformUnitCountsView      `json:"units"`
	UntrustedProxy    *auth.UntrustedProxy        `json:"untrusted_proxy,omitempty"`
	Updates           applicationUpdateStatusView `json:"updates"`
	Version           string                      `json:"version"`
	VersionReleaseURL string                      `json:"version_release_url,omitempty"`
}

// platformUnitCountsView counts the units that are not deleted, by state.
type platformUnitCountsView struct {
	Active   int `json:"active"`
	Deleting int `json:"deleting"`
	Disabled int `json:"disabled"`
	Total    int `json:"total"`
}

// platformAdminCountsView counts the platform administrators and the
// enabled ones.
type platformAdminCountsView struct {
	Enabled int `json:"enabled"`
	Total   int `json:"total"`
}

// platformCapacityStatusView is the deployment's scan settings and the use
// of its scan slots.
type platformCapacityStatusView struct {
	Limits platformLimitsView          `json:"limits"`
	Slots  platformDeploymentSlotsView `json:"slots"`
}

// platformDeploymentSlotsView is the deployment's scan slots: how many
// exist, how many hold a scan, and how many runs wait for one.
type platformDeploymentSlotsView struct {
	Capacity int `json:"capacity"`
	InUse    int `json:"in_use"`
	Queued   int `json:"queued"`
}
