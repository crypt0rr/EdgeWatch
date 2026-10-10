package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type protocolPayload struct {
	Ports                  string               `json:"ports"`
	Mode                   string               `json:"mode,omitempty"`
	ServiceDetection       bool                 `json:"service_detection"`
	Engine                 string               `json:"engine,omitempty"`
	ProfileID              string               `json:"profile_id,omitempty"`
	ProfileRevision        int64                `json:"profile_revision,omitempty"`
	Naabu                  *config.NaabuOptions `json:"naabu,omitempty"`
	NaabuArgs              []string             `json:"naabu_args,omitempty"`
	NmapArgs               []string             `json:"nmap_args,omitempty"`
	EnrichmentArgs         []string             `json:"enrichment_args,omitempty"`
	NSEProfile             string               `json:"nse_profile,omitempty"`
	NSEArgs                map[string]string    `json:"nse_args,omitempty"`
	ProfileUpdateAvailable bool                 `json:"profile_update_available,omitempty"`
	ProfileLatestRevision  int64                `json:"profile_latest_revision,omitempty"`
}
type jobPayload struct {
	Name                string           `json:"name"`
	Schedule            string           `json:"schedule"`
	Timezone            string           `json:"timezone"`
	RunOnStart          *bool            `json:"run_on_start"`
	AssumeAlive         *bool            `json:"assume_alive"`
	Targets             []string         `json:"targets"`
	DNSComparisonMode   string           `json:"dns_comparison_mode,omitempty"`
	MaxExpandedHosts    int              `json:"max_expanded_hosts"`
	TCP                 *protocolPayload `json:"tcp"`
	UDP                 *protocolPayload `json:"udp"`
	Timing              string           `json:"timing"`
	Timeout             string           `json:"timeout"`
	ResumeWindow        string           `json:"resume_window,omitempty"`
	BaselineSamples     int              `json:"baseline_samples"`
	ChangeConfirmations int              `json:"change_confirmations"`
	Enabled             *bool            `json:"enabled,omitempty"`
	Archived            bool             `json:"archived,omitempty"`
	Revision            int64            `json:"revision,omitempty"`
	ConfirmRebaseline   bool             `json:"confirm_rebaseline,omitempty"`
	// A pointer preserves whether an update actually supplied this field. An
	// operator must not be able to clear an administrator's high-cost approval
	// simply by sending an older payload that predates the field.
	AllowHighCost            *bool     `json:"allow_high_cost,omitempty"`
	NotificationDestinations *[]string `json:"notification_destinations,omitempty"`
}

type lifecyclePayload struct {
	Revision *int64 `json:"revision"`
}

// validateManagedScannerInput keeps the browser job API from becoming a
// second command-customization surface. Scanner argument arrays, NSE
// selection, and Naabu tuning are administrator-owned profile data; a job may
// only reference a profile revision. Legacy records already stored in SQLite
// remain readable and executable, but new writes must use the profile API.
func validateManagedScannerInput(protocol *protocolPayload, label string) error {
	if protocol == nil {
		return nil
	}
	// UDP is intentionally Nmap-only. Do not let a profile ID bypass this
	// boundary and smuggle Naabu/NSE or custom argv into a UDP job payload.
	if label == "udp" {
		if strings.TrimSpace(protocol.ProfileID) != "" || len(protocol.NaabuArgs) > 0 || len(protocol.NmapArgs) > 0 || len(protocol.EnrichmentArgs) > 0 || strings.TrimSpace(protocol.NSEProfile) != "" || len(protocol.NSEArgs) > 0 || protocol.Naabu != nil {
			return config.NewFieldValidationError("udp", errors.New("udp scanner profiles and custom scanner arguments are not supported; UDP uses Nmap defaults"))
		}
		return nil
	}
	if strings.TrimSpace(protocol.ProfileID) != "" {
		return nil
	}
	if len(protocol.NaabuArgs) > 0 || len(protocol.NmapArgs) > 0 || len(protocol.EnrichmentArgs) > 0 || strings.TrimSpace(protocol.NSEProfile) != "" || len(protocol.NSEArgs) > 0 || protocol.Naabu != nil {
		return config.NewFieldValidationError("tcp", fmt.Errorf("%s scanner arguments and Naabu tuning require an administrator-managed profile", label))
	}
	if strings.TrimSpace(protocol.Engine) == config.EngineNaabuNmap {
		return config.NewFieldValidationError("tcp", fmt.Errorf("%s naabu_nmap jobs must select an administrator-managed scanner profile", label))
	}
	return nil
}

func (p jobPayload) config() (config.Job, error) {
	allowHighCost := false
	if p.AllowHighCost != nil {
		allowHighCost = *p.AllowHighCost
	}
	job := config.Job{Name: strings.TrimSpace(p.Name), Schedule: strings.TrimSpace(p.Schedule), Timezone: strings.TrimSpace(p.Timezone), RunOnStart: p.RunOnStart, AssumeAlive: p.AssumeAlive, Targets: p.Targets, DNSComparisonMode: p.DNSComparisonMode, MaxExpandedHosts: p.MaxExpandedHosts, Timing: p.Timing, AllowHighCost: allowHighCost}
	if p.NotificationDestinations != nil {
		job.NotificationDestinations = cloneStrings(*p.NotificationDestinations)
	}
	if p.Timeout != "" {
		d, err := parseDuration(p.Timeout)
		if err != nil {
			return job, config.NewFieldValidationError("timeout", fmt.Errorf("timeout: %w", err))
		}
		job.Timeout = config.Duration(d)
	}
	if p.ResumeWindow != "" {
		d, err := parseDuration(p.ResumeWindow)
		if err != nil {
			return job, config.NewFieldValidationError("resume_window", fmt.Errorf("resume_window: %w", err))
		}
		job.ResumeWindow = config.Duration(d)
	}
	if p.TCP != nil {
		if err := validateManagedScannerInput(p.TCP, "tcp"); err != nil {
			return job, err
		}
		job.TCP = &config.Protocol{Ports: p.TCP.Ports, Mode: p.TCP.Mode, ServiceDetection: p.TCP.ServiceDetection, Engine: p.TCP.Engine, ProfileID: strings.TrimSpace(p.TCP.ProfileID), ProfileRevision: p.TCP.ProfileRevision, Naabu: p.TCP.Naabu, NaabuArgs: cloneStrings(p.TCP.NaabuArgs), NmapArgs: cloneStrings(p.TCP.NmapArgs), EnrichmentArgs: cloneStrings(p.TCP.EnrichmentArgs), NSEProfile: strings.TrimSpace(p.TCP.NSEProfile), NSEArgs: cloneStringMap(p.TCP.NSEArgs)}
	}
	if p.UDP != nil {
		if err := validateManagedScannerInput(p.UDP, "udp"); err != nil {
			return job, err
		}
		job.UDP = &config.Protocol{Ports: p.UDP.Ports, Mode: p.UDP.Mode, ServiceDetection: p.UDP.ServiceDetection, Engine: p.UDP.Engine, ProfileID: strings.TrimSpace(p.UDP.ProfileID), ProfileRevision: p.UDP.ProfileRevision, Naabu: p.UDP.Naabu, NaabuArgs: cloneStrings(p.UDP.NaabuArgs), NmapArgs: cloneStrings(p.UDP.NmapArgs), EnrichmentArgs: cloneStrings(p.UDP.EnrichmentArgs), NSEProfile: strings.TrimSpace(p.UDP.NSEProfile), NSEArgs: cloneStringMap(p.UDP.NSEArgs)}
	}
	job.Baseline.Samples, job.Change.Confirmations = p.BaselineSamples, p.ChangeConfirmations
	return config.NormalizeJob(job), nil
}

func parseDuration(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, errors.New("duration is required")
	}
	if strings.HasSuffix(raw, "d") {
		days, err := strconv.ParseFloat(strings.TrimSuffix(raw, "d"), 64)
		if err != nil || math.IsNaN(days) || math.IsInf(days, 0) || days <= 0 || days > 30 {
			return 0, errors.New("duration must be greater than zero and no more than 30d")
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	duration, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	if duration <= 0 || duration > 30*24*time.Hour {
		return 0, errors.New("duration must be greater than zero and no more than 30d")
	}
	return duration, nil
}

func jobJSONFromStateSummary(record store.JobRecord, summary store.RuntimeStateSummary) map[string]any {
	p := fromConfig(record.Job)
	estimate, _ := config.EstimateJobWork(record.Job)
	return map[string]any{"id": record.ID, "revision": record.Revision, "enabled": record.Enabled, "archived": record.Archived, "created_at": record.CreatedAt, "updated_at": record.UpdatedAt, "security_hash": record.Job.SecurityHash(), "job": p, "baseline": baselineJSONFromSummary(summary, record.Job.SecurityHash()), "scan_estimate": estimate}
}

// jobJSONWithCycle builds the job detail response from the bounded runtime
// summary, so a job page costs the same whatever the size of the job's
// baseline and candidate snapshots.
func (s *Server) jobJSONWithCycle(ctx context.Context, ts *store.TenantStore, record store.JobRecord, summary store.RuntimeStateSummary) map[string]any {
	value := s.addNotificationRouting(ctx, s.tenantNotifier(ts), jobJSONFromStateSummary(record, summary))
	value = s.addJobCycleAndProfile(ctx, ts, record, value)
	if budget, ok := s.jobScanBudget(ctx, ts, record.Job); ok {
		value["scan_budget"] = budget
	}
	return value
}

// jobScanBudget reports whether the job's estimated work fits the probe
// budget of its unit, so the job page can explain why its scheduled runs are
// skipped. approval_would_fit says whether an administrator's high-cost
// approval would let it run. It is left out when the budget cannot be read.
func (s *Server) jobScanBudget(ctx context.Context, ts *store.TenantStore, job config.Job) (map[string]any, bool) {
	if s.App == nil {
		return nil, false
	}
	_, err := s.App.CheckScanWorkBudget(ctx, ts, job)
	var budgetErr *app.ScanWorkBudgetError
	switch {
	case err == nil:
		return map[string]any{"exceeded": false}, true
	case !errors.As(err, &budgetErr):
		return nil, false
	}
	budget := map[string]any{"exceeded": true, "estimated_probes": budgetErr.Estimate.Probes, "limit": budgetErr.Budget, "approval_would_fit": false}
	if !job.AllowHighCost {
		approved := job
		approved.AllowHighCost = true
		_, approvedErr := s.App.CheckScanWorkBudget(ctx, ts, approved)
		budget["approval_would_fit"] = approvedErr == nil
	}
	return budget, true
}

// jobScanBudgetOutcome returns an estimate only with a complete budget
// decision. Preview uses this stricter helper so an unavailable unit capacity
// read cannot be mistaken for a fit or for a definite over-budget result.
func (s *Server) jobScanBudgetOutcome(ctx context.Context, ts *store.TenantStore, job config.Job) (config.WorkEstimate, map[string]any, error) {
	if s.App == nil || s.App.Config == nil {
		return config.WorkEstimate{}, nil, app.ErrProbeBudgetUnavailable
	}
	estimate, err := s.App.CheckScanWorkBudget(ctx, ts, job)
	var budgetErr *app.ScanWorkBudgetError
	switch {
	case err == nil:
		return estimate, map[string]any{"exceeded": false}, nil
	case !errors.As(err, &budgetErr):
		return estimate, nil, err
	}
	budget := map[string]any{"exceeded": true, "estimated_probes": budgetErr.Estimate.Probes, "limit": budgetErr.Budget, "approval_would_fit": false}
	if !job.AllowHighCost {
		approved := job
		approved.AllowHighCost = true
		_, approvedErr := s.App.CheckScanWorkBudget(ctx, ts, approved)
		var approvedBudgetErr *app.ScanWorkBudgetError
		switch {
		case approvedErr == nil:
			budget["approval_would_fit"] = true
		case errors.As(approvedErr, &approvedBudgetErr):
			// The elevated budget and absolute ceiling were both available and
			// the estimate still did not fit.
		default:
			return estimate, nil, approvedErr
		}
	}
	return estimate, budget, nil
}

type pendingChangeView struct {
	Key    string       `json:"key"`
	Change model.Change `json:"change"`
	Count  int          `json:"count"`
}

// jobPendingChanges pages the job's unconfirmed changes, ordered by target,
// protocol, port, kind and key. The store decodes only the pending changes
// of the runtime state, not its baseline or candidate snapshots.
func (s *Server) jobPendingChanges(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, record store.JobRecord) {
	offset, ok := requestOffset(w, r)
	if !ok {
		return
	}
	limit := queryLimit(r)
	page, err := ts.RuntimePendingChangesPage(r.Context(), record.ID, limit, offset)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	items := make([]pendingChangeView, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, pendingChangeView{Key: item.Key, Change: item.Change, Count: item.Count})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"job_id":          record.ID,
		"job":             record.Job.Name,
		"pending_changes": items,
		"pagination":      paginationJSON(offset, limit, page.Total),
	})
}

// tenantNotifier returns the notifier of the tenant of ts, or nil when the
// server runs without one.
func (s *Server) tenantNotifier(ts *store.TenantStore) *notify.TenantNotifier {
	if s.App == nil || s.App.Notifier == nil {
		return nil
	}
	return s.App.Notifier.Tenant(ts)
}

// addNotificationRouting reports a job's routing as the console can use it.
// Legacy deployment digests are shown as the current opaque selector. Saved
// selectors that no longer identify a destination of the job's tenant, for
// example after a deployment URL changed, are also listed in
// missing_notification_destinations so the console can show them and let an
// operator remove them. The job already exposes these selectors to the same
// readers; no URL is added. When the destinations cannot be read, the saved
// selection is shown as it is.
func (s *Server) addNotificationRouting(ctx context.Context, notifier *notify.TenantNotifier, value map[string]any) map[string]any {
	payload, ok := value["job"].(jobPayload)
	if !ok || payload.NotificationDestinations == nil || notifier == nil {
		return value
	}
	selection, missing, err := notifier.CanonicalSelection(ctx, *payload.NotificationDestinations)
	if err != nil {
		return value
	}
	payload.NotificationDestinations = &selection
	value["job"] = payload
	if len(missing) > 0 {
		value["missing_notification_destinations"] = missing
	}
	return value
}

func (s *Server) addJobCycleAndProfile(ctx context.Context, ts *store.TenantStore, record store.JobRecord, value map[string]any) map[string]any {
	// A profile edit is intentionally non-breaking: jobs retain their pinned
	// revision until an operator explicitly applies the newer one. Surface the
	// availability on the job payload so the editor can offer that deliberate
	// upgrade (and its rebaseline confirmation) instead of silently changing a
	// running scope.
	if payload, ok := value["job"].(jobPayload); ok && payload.TCP != nil && payload.TCP.ProfileID != "" {
		if profile, err := ts.GetScannerProfile(ctx, payload.TCP.ProfileID); err == nil && profile.Revision > payload.TCP.ProfileRevision {
			payload.TCP.ProfileUpdateAvailable = true
			payload.TCP.ProfileLatestRevision = profile.Revision
			value["job"] = payload
		}
	}
	cycle, err := ts.GetActiveScanCycle(ctx, record.ID)
	if errors.Is(err, store.ErrNoScanCycle) {
		value["scan_cycle"] = nil
		return value
	}
	if err != nil {
		logger := s.Log
		if logger == nil {
			logger = slog.Default()
		}
		logger.ErrorContext(ctx, "active scan cycle lookup failed",
			"request_id", RequestID(ctx),
			"job_id", record.ID,
			"error", err,
		)
		// Keep implementation details in the correlated server log. Job payloads
		// are visible to every role with jobs.read, so expose only a stable marker
		// that the UI can translate into a safe, actionable message.
		value["scan_cycle_error"] = "cycle_status_unavailable"
		return value
	}
	value["scan_cycle"] = cycleJSON(cycle)
	return value
}

func cycleJSON(cycle store.ScanCycleRecord) map[string]any {
	return cycleSummaryJSON(store.ScanCycleSummary{
		ID: cycle.ID, JobID: cycle.JobID, JobRevision: cycle.JobRevision, Status: cycle.Status,
		AttemptCount: cycle.AttemptCount, NoProgressAttempts: cycle.NoProgressAttempts,
		TotalUnits: cycle.TotalUnits, CompletedUnits: cycle.CompletedUnits,
		TotalProbes: cycle.TotalProbes, CompletedProbes: cycle.CompletedProbes,
		StartedAt: cycle.StartedAt, UpdatedAt: cycle.UpdatedAt, ExpiresAt: cycle.ExpiresAt,
		FinishedAt: cycle.FinishedAt, LastError: cycle.LastError,
	})
}

func cycleSummaryJSON(cycle store.ScanCycleSummary) map[string]any {
	return map[string]any{"id": cycle.ID, "job_id": cycle.JobID, "job_revision": cycle.JobRevision, "status": cycle.Status, "attempt_count": cycle.AttemptCount, "no_progress_attempts": cycle.NoProgressAttempts, "total_units": cycle.TotalUnits, "completed_units": cycle.CompletedUnits, "total_probes": cycle.TotalProbes, "completed_probes": cycle.CompletedProbes, "started_at": cycle.StartedAt, "updated_at": cycle.UpdatedAt, "expires_at": cycle.ExpiresAt, "finished_at": cycle.FinishedAt, "last_error": cycle.LastError}
}

func fromConfig(j config.Job) jobPayload {
	allowHighCost := j.AllowHighCost
	p := jobPayload{Name: j.Name, Schedule: j.Schedule, Timezone: j.Timezone, RunOnStart: j.RunOnStart, AssumeAlive: j.AssumeAlive, Targets: j.Targets, DNSComparisonMode: j.DNSComparisonMode, MaxExpandedHosts: j.MaxExpandedHosts, Timing: j.Timing, Timeout: j.Timeout.Value().String(), ResumeWindow: j.ResumeWindowValue().String(), BaselineSamples: j.Baseline.Samples, ChangeConfirmations: j.Change.Confirmations, AllowHighCost: &allowHighCost}
	if j.NotificationDestinations != nil {
		selection := make([]string, len(j.NotificationDestinations))
		copy(selection, j.NotificationDestinations)
		p.NotificationDestinations = &selection
	}
	if j.TCP != nil {
		p.TCP = &protocolPayload{Ports: j.TCP.Ports, Mode: j.TCP.Mode, ServiceDetection: j.TCP.ServiceDetection, Engine: j.TCP.Engine, ProfileID: j.TCP.ProfileID, ProfileRevision: j.TCP.ProfileRevision, Naabu: j.TCP.Naabu, NaabuArgs: cloneStrings(j.TCP.NaabuArgs), NmapArgs: cloneStrings(j.TCP.NmapArgs), EnrichmentArgs: cloneStrings(j.TCP.EnrichmentArgs), NSEProfile: j.TCP.NSEProfile, NSEArgs: cloneStringMap(j.TCP.NSEArgs)}
	}
	if j.UDP != nil {
		p.UDP = &protocolPayload{Ports: j.UDP.Ports, Mode: j.UDP.Mode, ServiceDetection: j.UDP.ServiceDetection, Engine: j.UDP.Engine, ProfileID: j.UDP.ProfileID, ProfileRevision: j.UDP.ProfileRevision, Naabu: j.UDP.Naabu, NaabuArgs: cloneStrings(j.UDP.NaabuArgs), NmapArgs: cloneStrings(j.UDP.NmapArgs), EnrichmentArgs: cloneStrings(j.UDP.EnrichmentArgs), NSEProfile: j.UDP.NSEProfile, NSEArgs: cloneStringMap(j.UDP.NSEArgs)}
	}
	return p
}

func baselineJSONFromSummary(summary store.RuntimeStateSummary, currentHash string) map[string]any {
	if !summary.HasBaseline {
		status := "collecting"
		if summary.IncompleteCandidateAttempts >= 3 {
			status = "stalled"
		}
		return map[string]any{"status": status, "samples": summary.CandidateCount, "attempts": summary.CandidateAttempts, "incomplete_attempts": summary.IncompleteCandidateAttempts}
	}
	status := "complete"
	if currentHash != "" && summary.BaselineConfigHash != "" && summary.BaselineConfigHash != currentHash {
		status = "updating"
	}
	return map[string]any{"status": status, "scan_id": summary.BaselineScanID, "config_hash": summary.BaselineConfigHash, "modified": summary.BaselineModified, "samples": summary.CandidateCount, "attempts": summary.CandidateAttempts, "incomplete_attempts": summary.IncompleteCandidateAttempts, "incidents": summary.IncidentCount, "pending": summary.PendingCount, "host_count": summary.BaselineHostCount}
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request, ts *store.TenantStore) {
	include := r.URL.Query().Get("include_archived") == "true"
	jobs, err := ts.ListJobs(r.Context(), include)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	summaries, err := ts.RuntimeStateSummaries(r.Context(), include)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	cycles, cycleErr := ts.ListActiveScanCycleSummaries(r.Context(), include)
	if cycleErr != nil {
		logger := s.Log
		if logger == nil {
			logger = slog.Default()
		}
		logger.ErrorContext(r.Context(), "active scan cycle list lookup failed", "request_id", RequestID(r.Context()), "error", cycleErr)
	}
	profileRevisions, profileErr := ts.CurrentScannerProfileRevisions(r.Context())
	if profileErr != nil {
		logger := s.Log
		if logger == nil {
			logger = slog.Default()
		}
		logger.ErrorContext(r.Context(), "scanner profile revision list lookup failed", "request_id", RequestID(r.Context()), "error", profileErr)
		profileRevisions = nil
	}
	out := make([]map[string]any, 0, len(jobs))
	notifier := s.tenantNotifier(ts)
	for _, j := range jobs {
		value := s.addNotificationRouting(r.Context(), notifier, jobJSONFromStateSummary(j, summaries[j.ID]))
		if payload, ok := value["job"].(jobPayload); ok && payload.TCP != nil && payload.TCP.ProfileID != "" && profileErr == nil {
			if revision := profileRevisions[payload.TCP.ProfileID]; revision > payload.TCP.ProfileRevision {
				payload.TCP.ProfileUpdateAvailable = true
				payload.TCP.ProfileLatestRevision = revision
				value["job"] = payload
			}
		}
		if cycleErr != nil {
			value["scan_cycle_error"] = "cycle_status_unavailable"
		} else if cycle, ok := cycles[j.ID]; ok {
			value["scan_cycle"] = cycleSummaryJSON(cycle)
		} else {
			value["scan_cycle"] = nil
		}
		out = append(out, value)
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": out})
}

func (s *Server) createJob(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore) {
	job, enabled, ok := s.prepareNewJob(w, r, session, ts)
	if !ok {
		return
	}
	record, err := ts.CreateJobWithEnabledAndAudit(r.Context(), job, enabled, actorAudit(session, "job.created", job.Name))
	if err != nil {
		if s.writeAuditUnavailable(w, err, "job.created") {
			return
		}
		if isUnique(err) {
			writeError(w, 409, "conflict", "job name is already in use", nil)
		} else {
			s.writeStoreWriteError(w, r, err, "job not found")
		}
		return
	}
	s.App.RefreshSchedules()
	summary, _ := ts.RuntimeStateSummary(r.Context(), record.ID)
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "job.created", "job_id": record.ID})
	writeJSON(w, http.StatusCreated, s.jobJSONWithCycle(r.Context(), ts, record, summary))
}

// prepareNewJob centralizes the new-job defaults and policy checks shared by
// create and preview. The final create transaction repeats storage validation
// and profile ownership checks, so this advisory pass cannot reserve or pin
// resources and a create still revalidates against concurrent changes.
func (s *Server) prepareNewJob(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore) (config.Job, bool, bool) {
	var p jobPayload
	if !decodeJSON(w, r, &p) {
		return config.Job{}, false, false
	}
	if strings.TrimSpace(p.Timezone) == "" {
		// New jobs without an explicit schedule timezone follow config.yaml;
		// without a deployment timezone, job normalization keeps UTC.
		p.Timezone = s.deploymentTimezone()
	}
	defaultNewScannerProfile(&p)
	job, err := p.config()
	if err != nil {
		writeValidationError(w, err)
		return config.Job{}, false, false
	}
	if job.AllowHighCost && !canOverrideHighCost(session) {
		writeError(w, http.StatusForbidden, "high_cost_admin_required", "only administrators may enable high-cost scans", nil)
		return config.Job{}, false, false
	}
	if err := s.applySelectedScannerProfile(r.Context(), ts, &job, false, auth.HasPermission(session, auth.PermissionScannerProfilesManage)); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "profile_conflict", "scanner profile was modified; reload and select its current revision", nil)
		} else {
			s.writeStoreWriteError(w, r, err, "scanner profile not found")
		}
		return config.Job{}, false, false
	}
	if !s.validateNotificationSelection(w, r, ts, job) {
		return config.Job{}, false, false
	}
	if err := ts.ValidateManagedJob(job); err != nil {
		s.writeStoreWriteError(w, r, err, "job not found")
		return config.Job{}, false, false
	}
	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	return job, enabled, true
}

type jobPreviewWarning struct {
	Code    string `json:"code"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

const maxJobPreviewWarnings = 5

func jobPreviewWarnings(job config.Job, estimate config.WorkEstimate) []jobPreviewWarning {
	warnings := make([]jobPreviewWarning, 0, maxJobPreviewWarnings)
	add := func(warning jobPreviewWarning) {
		if len(warnings) < maxJobPreviewWarnings {
			warnings = append(warnings, warning)
		}
	}
	add(jobPreviewWarning{
		Code:    "elapsed_time_unknown",
		Message: "Probe and process counts are preflight estimates; elapsed scan time depends on DNS, scanner behavior, target responses, retries, and discovered ports.",
	})
	if estimate.UnknownDNS > 0 {
		add(jobPreviewWarning{
			Code:    "dns_expansion_unknown",
			Field:   "targets",
			Message: "Each DNS name counts as one address here. Preview does not resolve DNS, so the address count and work may change when the scan runs.",
		})
	}
	if job.TCP != nil && job.TCP.Engine == config.EngineNaabuNmap {
		add(jobPreviewWarning{
			Code:    "naabu_enrichment_data_dependent",
			Field:   "tcp",
			Message: "Naabu discovery uses the full TCP port range. The later Nmap confirmation work depends on discovered ports and is not included in this preflight estimate.",
		})
	}
	if job.TCP != nil && job.TCP.Engine == config.EngineNmap {
		if ports, err := config.ParsePorts(job.TCP.Ports); err == nil && len(ports) < 65535 {
			add(jobPreviewWarning{
				Code:    "tcp_partial_coverage",
				Field:   "tcp.ports",
				Message: "This Nmap TCP selection covers only the configured ports, not the full TCP port range.",
			})
		}
	}
	if job.AllowHighCost {
		add(jobPreviewWarning{
			Code:    "high_cost_approved",
			Field:   "allow_high_cost",
			Message: "High-cost approval uses the unit's elevated probe budget; the absolute probe ceiling still applies.",
		})
	}
	return warnings
}

func (s *Server) previewJob(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore) {
	job, enabled, ok := s.prepareNewJob(w, r, session, ts)
	if !ok {
		return
	}
	estimate, budget, err := s.jobScanBudgetOutcome(r.Context(), ts, job)
	if err != nil {
		if s.Log != nil {
			s.Log.WarnContext(r.Context(), "job preview could not confirm scan budget", "request_id", RequestID(r.Context()), "error", err)
		}
		writeError(w, http.StatusServiceUnavailable, "preview_unavailable", "job preview could not confirm the unit scan budget", map[string]string{"reason": "scan_budget_unavailable"})
		return
	}

	publicJob := fromConfig(job)
	publicJob.Enabled = &enabled
	value := s.addNotificationRouting(r.Context(), s.tenantNotifier(ts), map[string]any{"job": publicJob})
	if normalized, ok := value["job"].(jobPayload); ok {
		publicJob = normalized
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"job":           publicJob,
		"scan_estimate": estimate,
		"scan_budget":   budget,
		"warnings":      jobPreviewWarnings(job, estimate),
	})
}

// defaultNewScannerProfile keeps new web-created TCP jobs on the faster,
// full-range Naabu discovery pipeline while preserving the Nmap behavior of
// legacy jobs and direct callers. An explicit engine/profile or any managed
// scanner field is always respected; only a completely unspecified TCP
// scanner gets the built-in Naabu profile.
func defaultNewScannerProfile(p *jobPayload) {
	if p == nil || p.TCP == nil {
		return
	}
	tcp := p.TCP
	if strings.TrimSpace(tcp.Engine) != "" || strings.TrimSpace(tcp.ProfileID) != "" || tcp.ProfileRevision != 0 || len(tcp.NaabuArgs) > 0 || len(tcp.NmapArgs) > 0 || len(tcp.EnrichmentArgs) > 0 || strings.TrimSpace(tcp.NSEProfile) != "" || len(tcp.NSEArgs) > 0 || tcp.Naabu != nil {
		return
	}
	tcp.Engine = config.EngineNaabuNmap
	tcp.ProfileID = store.BuiltinNaabuProfileID
	// Leave the revision unresolved here. applySelectedScannerProfile resolves
	// it from the current built-in profile, so a new job never pins a stale
	// hard-coded revision after a forward profile upgrade.
	tcp.ProfileRevision = 0
}

func isUnique(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

// validateNotificationSelection accepts a job's routing only when it selects
// destinations of the job's tenant. Another tenant's destination is refused
// exactly as an unknown one.
func (s *Server) validateNotificationSelection(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, job config.Job) bool {
	if job.NotificationDestinations == nil {
		return true
	}
	if err := s.App.Notifier.Tenant(ts).ValidateDestinationSelection(r.Context(), job.NotificationDestinations); err != nil {
		if errors.Is(err, notify.ErrInvalidDestinationSelection) {
			// Selectors are opaque caller input. A foreign destination must be
			// indistinguishable from an unknown one, and neither error should
			// reflect arbitrary IDs back to the caller.
			message := "notification destination selection is invalid"
			writeError(w, http.StatusBadRequest, "validation_failed", message, map[string]string{"notification_destinations": message})
		} else {
			writeError(w, http.StatusInternalServerError, "notification", "notification destinations could not be loaded", nil)
		}
		return false
	}
	return true
}

// jobRoute dispatches /jobs/{id}/* and loads the job once for the handler.
// Routes that validated their request before looking up the job still do so
// first, so a malformed request for a missing job stays a 400 and the
// administrator check for a permanent delete stays a 403. Each route keeps
// its historical response to a failed lookup through its jobLookupFailure.
//
// The lifecycle writes (archive, restore, pause, resume) and the baseline
// host RDAP route never loaded the job record. The lifecycle writes look the
// job up in the request's tenant inside their revision-guarded transaction,
// so another tenant's job is not found there; the RDAP route answers a
// missing job as a missing baseline host. They keep taking the ID, because a
// lookup here would add a query and change those responses.
func (s *Server) jobRoute(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, rest string) {
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	id := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		if job, ok := s.resolveJob(w, r, ts, id, jobMissingOnAnyError); ok {
			s.getJob(w, r, ts, job)
		}
		return
	}
	if len(parts) == 1 && r.Method == http.MethodPut {
		update, ok := decodeJobUpdate(w, r)
		if !ok {
			return
		}
		if job, ok := s.resolveJob(w, r, ts, id, jobStoreErrorInternal); ok {
			s.updateJob(w, r, session, ts, job, update)
		}
		return
	}
	if len(parts) == 1 && r.Method == http.MethodDelete {
		if r.URL.Query().Get("permanent") == "true" {
			confirmName, ok := decodePermanentDelete(w, r, session)
			if !ok {
				return
			}
			if job, ok := s.resolveJob(w, r, ts, id, jobMissingOnAnyError); ok {
				s.permanentDelete(w, r, session, ts, job, confirmName)
			}
		} else {
			s.archiveJob(w, r, session, ts, id, true)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "archive" && r.Method == http.MethodPost {
		s.archiveJob(w, r, session, ts, id, true)
		return
	}
	if len(parts) == 2 && parts[1] == "restore" && r.Method == http.MethodPost {
		s.archiveJob(w, r, session, ts, id, false)
		return
	}
	if len(parts) == 2 && parts[1] == "pause" && r.Method == http.MethodPost {
		s.enableJob(w, r, session, ts, id, false)
		return
	}
	if len(parts) == 2 && parts[1] == "resume" && r.Method == http.MethodPost {
		s.enableJob(w, r, session, ts, id, true)
		return
	}
	if len(parts) == 2 && parts[1] == "run" && r.Method == http.MethodPost {
		if job, ok := s.resolveJob(w, r, ts, id, jobMissingOnAnyError); ok {
			s.runJob(w, r, session, ts, job)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "run" && r.Method == http.MethodDelete {
		if job, ok := s.resolveJob(w, r, ts, id, jobMissingOnAnyError); ok {
			s.cancelQueuedRun(w, r, session, ts, job)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "scan-cycle" && r.Method == http.MethodGet {
		if job, ok := s.resolveJob(w, r, ts, id, jobStoreErrorInternal); ok {
			s.scanCycle(w, r, ts, job)
		}
		return
	}
	if len(parts) == 3 && parts[1] == "scan-cycle" && r.Method == http.MethodDelete {
		if job, ok := s.resolveJob(w, r, ts, id, jobStoreErrorInternal); ok {
			s.discardScanCycle(w, r, session, ts, job, parts[2])
		}
		return
	}
	if len(parts) == 2 && parts[1] == "scans" && r.Method == http.MethodGet {
		if job, ok := s.resolveJob(w, r, ts, id, jobStoreErrorInternal); ok {
			s.jobScans(w, r, ts, job)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "pending-changes" && r.Method == http.MethodGet {
		if job, ok := s.resolveJob(w, r, ts, id, jobStoreErrorInternal); ok {
			s.jobPendingChanges(w, r, ts, job)
		}
		return
	}
	if len(parts) == 3 && parts[1] == "scans" && parts[2] == "latest-successful" && r.Method == http.MethodGet {
		if job, ok := s.resolveJob(w, r, ts, id, jobMissingOnAnyError); ok {
			s.latestSuccessfulScan(w, r, ts, job)
		}
		return
	}
	if len(parts) == 3 && parts[1] == "scans" && r.Method == http.MethodGet {
		if job, scan, ok := s.resolveJobAndScan(w, r, ts, id, jobStoreErrorInternal, parts[2], scanStoreErrorInternal); ok {
			s.jobScan(w, r, ts, job, scan)
		}
		return
	}
	if len(parts) == 4 && parts[1] == "scans" && parts[3] == "results" && r.Method == http.MethodGet {
		if _, scan, ok := s.resolveJobAndScan(w, r, ts, id, jobStoreErrorInternal, parts[2], scanStoreErrorInternal); ok {
			s.jobScanResults(w, r, ts, scan)
		}
		return
	}
	if len(parts) == 4 && parts[1] == "scans" && parts[3] == "hosts" && r.Method == http.MethodGet {
		if job, scan, ok := s.resolveJobAndScan(w, r, ts, id, jobStoreErrorInternal, parts[2], scanStoreErrorInternal); ok {
			s.jobScanHosts(w, r, ts, job, scan)
		}
		return
	}
	if len(parts) == 5 && parts[1] == "scans" && parts[3] == "hosts" && r.Method == http.MethodGet {
		if job, scan, ok := s.resolveJobAndScan(w, r, ts, id, jobStoreErrorJobDetail, parts[2], scanStoreErrorDetail); ok {
			s.jobScanHost(w, r, ts, job, scan, parts[4])
		}
		return
	}
	if len(parts) == 6 && parts[1] == "scans" && parts[3] == "hosts" && parts[5] == "rdap" && r.Method == http.MethodGet {
		if _, scan, ok := s.resolveJobAndScan(w, r, ts, id, jobStoreErrorHostDetail, parts[2], scanStoreErrorDetail); ok {
			s.jobScanHostRDAP(w, r, ts, scan, parts[4])
		}
		return
	}
	if len(parts) == 3 && parts[1] == "baseline" && parts[2] == "hosts" && r.Method == http.MethodGet {
		if job, ok := s.resolveJob(w, r, ts, id, jobStoreErrorInternal); ok {
			s.jobBaselineHosts(w, r, ts, job)
		}
		return
	}
	if len(parts) == 4 && parts[1] == "baseline" && parts[2] == "hosts" && r.Method == http.MethodGet {
		if job, ok := s.resolveJob(w, r, ts, id, jobStoreErrorInternal); ok {
			s.jobBaselineHost(w, r, ts, job, parts[3])
		}
		return
	}
	if len(parts) == 5 && parts[1] == "baseline" && parts[2] == "hosts" && parts[4] == "rdap" && r.Method == http.MethodGet {
		s.jobBaselineHostRDAP(w, r, ts, id, parts[3])
		return
	}
	if len(parts) == 4 && parts[1] == "scans" && parts[3] == "changes" && r.Method == http.MethodGet {
		if job, scan, ok := s.resolveJobAndScan(w, r, ts, id, jobStoreErrorInternal, parts[2], scanStoreErrorInternal); ok {
			s.jobScanChanges(w, r, ts, job, scan)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "incidents" && r.Method == http.MethodGet {
		if job, ok := s.resolveJob(w, r, ts, id, jobMissingOnAnyError); ok {
			s.jobIncidents(w, r, ts, job)
		}
		return
	}
	if len(parts) == 3 && parts[1] == "incidents" && parts[2] == "accept" && r.Method == http.MethodPost {
		action, ok := decodeIncidentAction(w, r)
		if !ok {
			return
		}
		if job, ok := s.resolveJob(w, r, ts, id, jobStoreErrorInternal); ok {
			s.acceptIncident(w, r, session, ts, job, action)
		}
		return
	}
	if len(parts) == 3 && parts[1] == "incidents" && parts[2] == "suppress" && r.Method == http.MethodPost {
		action, ok := decodeIncidentAction(w, r)
		if !ok {
			return
		}
		if job, ok := s.resolveJob(w, r, ts, id, jobStoreErrorInternal); ok {
			s.suppressIncident(w, r, session, ts, job, action)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "events" && r.Method == http.MethodGet {
		if job, ok := s.resolveJob(w, r, ts, id, jobMissingOnAnyError); ok {
			s.jobEvents(w, r, ts, job)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "baseline" && r.Method == http.MethodGet {
		if job, ok := s.resolveJob(w, r, ts, id, jobMissingOnAnyError); ok {
			s.jobBaseline(w, r, ts, job)
		}
		return
	}
	if len(parts) == 3 && parts[1] == "baseline" && parts[2] == "reset" && r.Method == http.MethodPost {
		input, ok := decodeResetBaseline(w, r)
		if !ok {
			return
		}
		if job, ok := s.resolveJob(w, r, ts, id, jobMissingOnAnyError); ok {
			s.resetBaseline(w, r, session, ts, job, input)
		}
		return
	}
	if len(parts) == 3 && parts[1] == "baseline" && parts[2] == "approve" && r.Method == http.MethodPost {
		input, ok := decodeApproveBaseline(w, r)
		if !ok {
			return
		}
		if job, ok := s.resolveJob(w, r, ts, id, jobMissingOnAnyError); ok {
			s.approveBaseline(w, r, session, ts, job, input)
		}
		return
	}
	writeError(w, 404, "not_found", "job endpoint not found", nil)
}
