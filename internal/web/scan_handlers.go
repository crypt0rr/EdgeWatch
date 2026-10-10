package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/engine"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// activeScans lists the running scans of the request's tenant only.
func (s *Server) activeScans(w http.ResponseWriter, r *http.Request, ts *store.TenantStore) {
	scope, err := ts.Scope()
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	queuedRuns := s.App.QueuedRuns(scope)
	scans := s.App.ActiveScans(scope)
	if scans == nil {
		scans = []model.ActiveScan{}
	}
	activeJobs := make(map[string]struct{}, len(scans))
	for _, scan := range scans {
		activeJobs[scan.JobID] = struct{}{}
	}
	filteredQueued := queuedRuns[:0]
	for _, run := range queuedRuns {
		if _, started := activeJobs[run.JobID]; !started {
			filteredQueued = append(filteredQueued, run)
		}
	}
	queuedRuns = filteredQueued
	if queuedRuns == nil {
		queuedRuns = []model.QueuedRun{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": scans, "queued_runs": queuedRuns})
}

// cancelScan cancels a running scan of the request's tenant. Another tenant's
// scan is answered as a scan that is no longer active, and keeps running.
func (s *Server) cancelScan(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, id string) {
	if strings.TrimSpace(id) == "" {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	scope, err := ts.Scope()
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	if err := s.App.CancelScan(scope, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusConflict, "scan_not_active", "scan is no longer active", nil)
			return
		}
		if errors.Is(err, app.ErrScanFinalizing) {
			writeError(w, http.StatusConflict, "scan_finalizing", "The scan is saving its result and can no longer be canceled.", nil)
			return
		}
		s.writeInternalError(w, r, "cancel_failed", err)
		return
	}
	// Cancellation is an operational action; keep its audit detail opaque and
	// never include scanner command lines or target payloads.
	s.auditOptionalEntry(r.Context(), ts, actorAudit(session, "scan.cancel_requested", id))
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "scan.cancellation_requested", "scan_id": id})
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "cancelling", "scan_id": id})
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, record store.JobRecord) {
	summary, err := ts.RuntimeStateSummary(r.Context(), record.ID)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	writeJSON(w, 200, s.jobJSONWithCycle(r.Context(), ts, record, summary))
}

// latestSuccessfulScan returns only the newest completed scan summary. The
// router's job lookup keeps the null response unambiguous: a known job with
// no successful history is 200/null, while an unknown job remains 404.
func (s *Server) latestSuccessfulScan(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, job store.JobRecord) {
	scan, err := ts.GetLatestSuccessfulJobScanSummary(r.Context(), job.ID)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scan": scan})
}

// jobUpdateRequest is a job update that passed request validation.
type jobUpdateRequest struct {
	payload jobPayload
	job     config.Job
}

// decodeJobUpdate validates a job update before the job is loaded.
func decodeJobUpdate(w http.ResponseWriter, r *http.Request) (jobUpdateRequest, bool) {
	var p jobPayload
	if !decodeJSON(w, r, &p) {
		return jobUpdateRequest{}, false
	}
	if p.Revision < 1 {
		writeError(w, http.StatusBadRequest, "revision_required", "job revision is required", map[string]string{"revision": "job revision is required"})
		return jobUpdateRequest{}, false
	}
	job, err := p.config()
	if err != nil {
		writeValidationError(w, err)
		return jobUpdateRequest{}, false
	}
	return jobUpdateRequest{payload: p, job: job}, true
}

// updateJob applies a validated update to the job the router loaded. The
// write re-checks the revision inside its transaction, so an edit made after
// the lookup is still reported as a conflict.
func (s *Server) updateJob(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, current store.JobRecord, update jobUpdateRequest) {
	id, p, job := current.ID, update.payload, update.job
	// High-cost approval is administrator-owned. Preserve it for older clients
	// that omit the field until the immutable security scope is known below;
	// any scope change then clears the approval unless an administrator
	// explicitly re-approves it in the same update.
	if p.AllowHighCost == nil {
		job.AllowHighCost = current.Job.AllowHighCost
	} else if job.AllowHighCost != current.Job.AllowHighCost && job.AllowHighCost && !canOverrideHighCost(session) {
		writeError(w, http.StatusForbidden, "high_cost_admin_required", "only administrators may change high-cost scan approval", map[string]string{"allow_high_cost": "administrator permission is required"})
		return
	}
	// Preserve the immutable profile revision when an older client sends the
	// profile ID without a revision. This also permits routine edits to jobs
	// pinned to a profile that has since been archived; selecting that archived
	// profile for a new job remains disallowed.
	allowArchivedProfile := false
	if job.TCP != nil && current.Job.TCP != nil && strings.TrimSpace(job.TCP.ProfileID) != "" && job.TCP.ProfileID == current.Job.TCP.ProfileID {
		if job.TCP.ProfileRevision == 0 {
			job.TCP.ProfileRevision = current.Job.TCP.ProfileRevision
		}
		allowArchivedProfile = job.TCP.ProfileRevision > 0 && job.TCP.ProfileRevision == current.Job.TCP.ProfileRevision
	}
	// An operator may retain the exact profile revision already pinned to this
	// job (including an archived revision), but cannot select a historical
	// revision as a new profile choice. Administrators may explicitly roll back
	// to any retained revision.
	allowHistoricalProfile := auth.HasPermission(session, auth.PermissionScannerProfilesManage) || allowArchivedProfile
	if err := s.applySelectedScannerProfile(r.Context(), ts, &job, allowArchivedProfile, allowHistoricalProfile); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "profile_conflict", "scanner profile was modified; reload and select its current revision", nil)
		} else {
			s.writeStoreWriteError(w, r, err, "scanner profile not found")
		}
		return
	}
	if !s.validateNotificationSelection(w, r, ts, job) {
		return
	}
	// Routing is additive to the job API. Older clients that do not send the
	// field must not accidentally reset a job's saved notification selection.
	if p.NotificationDestinations == nil {
		job.NotificationDestinations = cloneStrings(current.Job.NotificationDestinations)
	}
	active, activeErr := ts.JobActive(r.Context(), id)
	if activeErr != nil {
		// A job deleted since the router loaded it is not found, as it would be
		// by the update below.
		s.writeStoreWriteError(w, r, activeErr, "job not found")
		return
	}
	scopeChanged := current.Job.SecurityHash() != job.SecurityHash()
	// High-cost approval is bound to the exact security scope that was
	// reviewed. Any target/protocol/port/engine change invalidates the old
	// approval. An administrator may explicitly set allow_high_cost=true in
	// this same request to make a fresh approval; operators can never carry an
	// approval across a scope change.
	if scopeChanged {
		if !canOverrideHighCost(session) || p.AllowHighCost == nil {
			job.AllowHighCost = false
		}
	}
	approvalCleared := current.Job.AllowHighCost && !job.AllowHighCost
	if active && scopeChanged {
		writeError(w, 409, "job_active", "security-relevant settings cannot change during an active scan", nil)
		return
	}
	enabled := current.Enabled
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	var destinations []string
	var err error
	if scopeChanged && p.ConfirmRebaseline {
		destinations, err = s.App.Notifier.Tenant(ts).QueueDestinationsForJob(r.Context(), job)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "notification", "unable to prepare notification delivery", nil)
			return
		}
	}
	audits := []store.AuditEntry{actorAudit(session, "job.updated", id)}
	if scopeChanged {
		audits = append([]store.AuditEntry{actorAudit(session, "job.rebaseline_requested", id)}, audits...)
	}
	record, changed, events, err := ts.UpdateJobWithEventsWithOutboxAndAudit(r.Context(), id, p.Revision, job, enabled, current.Archived, p.ConfirmRebaseline, destinations, audits...)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, 409, "conflict", "job was modified; reload before saving", nil)
		return
	}
	if errors.Is(err, store.ErrRebaselineRequired) {
		changes := securityScopeChanges(current.Job, job)
		if approvalCleared {
			changes = append(changes, s.highCostClearedChange(r.Context(), ts, job))
		}
		writeError(w, 409, "rebaseline_confirmation_required", "security-relevant settings changed; confirm rebaseline to continue", map[string]any{"previous_hash": current.Job.SecurityHash(), "new_hash": job.SecurityHash(), "changes": changes})
		return
	}
	if errors.Is(err, store.ErrJobScanActive) {
		message := "pause or resume is unavailable while a scan is running; wait for it to finish and try again"
		if scopeChanged {
			message = "security-relevant settings cannot change during an active scan; wait for it to finish and try again"
		}
		writeError(w, http.StatusConflict, "job_active", message, nil)
		return
	}
	if err != nil {
		if s.writeAuditUnavailable(w, err, "job.updated") {
			return
		}
		if isUnique(err) {
			writeError(w, 409, "conflict", "job name is already in use", nil)
		} else {
			s.writeStoreWriteError(w, r, err, "job not found")
		}
		return
	}
	if changed {
		for _, event := range events {
			s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": event.Type, "job_id": id, "job": event.Job, "scan_id": event.ScanID, "message": event.Message})
		}
		s.App.WakeDelivery()
	}
	s.App.RefreshSchedules()
	summary, _ := ts.RuntimeStateSummary(r.Context(), id)
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "job.updated", "job_id": id})
	response := s.jobJSONWithCycle(r.Context(), ts, record, summary)
	if approvalCleared {
		response["high_cost_approval_cleared"] = true
	}
	writeJSON(w, 200, response)
}

// highCostClearedChange describes, in the scope-change confirmation, the
// high-cost approval that saving the new scope clears, and whether the new
// scope still needs one.
func (s *Server) highCostClearedChange(ctx context.Context, ts *store.TenantStore, job config.Job) string {
	const cleared = "high-cost approval: cleared; an administrator must approve the new scope again"
	budget, ok := s.jobScanBudget(ctx, ts, job)
	if !ok {
		return cleared
	}
	if exceeded, _ := budget["exceeded"].(bool); exceeded {
		return fmt.Sprintf("%s (about %d probes exceed the budget of %d, so scheduled scans are skipped until then)", cleared, budget["estimated_probes"], budget["limit"])
	}
	return cleared + " (the new scope fits the probe budget without it)"
}

// canOverrideHighCost deliberately reuses the administrator-only users.manage
// permission instead of checking role strings in job handlers. Empty roles
// are treated as legacy administrator sessions by the auth permission table;
// every managed operator and viewer is denied.
func canOverrideHighCost(session store.Session) bool {
	return auth.HasPermission(session, auth.PermissionUsersManage)
}

func securityScopeChanges(old, next config.Job) []string {
	// Compare effective jobs so omitted legacy defaults (notably Nmap engine,
	// SYN mode, and assume_alive) produce the same human-readable scope as an
	// explicitly configured value.
	old = config.NormalizeJob(old)
	next = config.NormalizeJob(next)
	var changes []string
	if !sameStrings(old.Targets, next.Targets) {
		changes = append(changes, fmt.Sprintf("targets: %s → %s", strings.Join(old.Targets, ", "), strings.Join(next.Targets, ", ")))
	}
	if old.MaxExpandedHosts != next.MaxExpandedHosts {
		changes = append(changes, fmt.Sprintf("maximum expanded hosts: %d → %d", old.MaxExpandedHosts, next.MaxExpandedHosts))
	}
	if old.AssumesAlive() != next.AssumesAlive() {
		changes = append(changes, fmt.Sprintf("assume alive: %t → %t", old.AssumesAlive(), next.AssumesAlive()))
	}
	if old.DNSComparisonMode != next.DNSComparisonMode {
		changes = append(changes, fmt.Sprintf("DNS comparison: %s → %s", dnsComparisonSummary(old.DNSComparisonMode), dnsComparisonSummary(next.DNSComparisonMode)))
	}
	if (old.TCP == nil) != (next.TCP == nil) {
		changes = append(changes, fmt.Sprintf("TCP scan: %s → %s", protocolSummary(old.TCP), protocolSummary(next.TCP)))
	} else if old.TCP != nil && next.TCP != nil {
		if old.TCP.Engine != next.TCP.Engine {
			changes = append(changes, fmt.Sprintf("TCP scanner: %s → %s", old.TCP.Engine, next.TCP.Engine))
		}
		if old.TCP.Ports != next.TCP.Ports {
			changes = append(changes, fmt.Sprintf("TCP ports: %s → %s", old.TCP.Ports, next.TCP.Ports))
		}
		if old.TCP.Mode != next.TCP.Mode {
			changes = append(changes, fmt.Sprintf("TCP mode: %s → %s", old.TCP.Mode, next.TCP.Mode))
		}
		if old.TCP.ServiceDetection != next.TCP.ServiceDetection {
			changes = append(changes, fmt.Sprintf("TCP service detection: %t → %t", old.TCP.ServiceDetection, next.TCP.ServiceDetection))
		}
		if !sameStringMap(old.TCP.NSEArgs, next.TCP.NSEArgs) || old.TCP.NSEProfile != next.TCP.NSEProfile {
			changes = append(changes, fmt.Sprintf("TCP NSE: %s → %s", nseSummary(old.TCP), nseSummary(next.TCP)))
		}
		if (old.TCP.Naabu == nil) != (next.TCP.Naabu == nil) {
			changes = append(changes, fmt.Sprintf("TCP Naabu verification: %s → %s", naabuSecuritySummary(old.TCP), naabuSecuritySummary(next.TCP)))
		} else if old.TCP.Naabu != nil && next.TCP.Naabu != nil {
			if old.TCP.Naabu.ScanType != next.TCP.Naabu.ScanType {
				changes = append(changes, fmt.Sprintf("TCP discovery mode: %s → %s", old.TCP.Naabu.ScanType, next.TCP.Naabu.ScanType))
			}
			if old.TCP.Naabu.Verify != next.TCP.Naabu.Verify {
				changes = append(changes, fmt.Sprintf("TCP discovery verification: %t → %t", old.TCP.Naabu.Verify, next.TCP.Naabu.Verify))
			}
		}
	}
	if (old.UDP == nil) != (next.UDP == nil) {
		changes = append(changes, fmt.Sprintf("UDP scan: %s → %s", protocolSummary(old.UDP), protocolSummary(next.UDP)))
	} else if old.UDP != nil && next.UDP != nil {
		if old.UDP.Ports != next.UDP.Ports {
			changes = append(changes, fmt.Sprintf("UDP ports: %s → %s", old.UDP.Ports, next.UDP.Ports))
		}
		if old.UDP.ServiceDetection != next.UDP.ServiceDetection {
			changes = append(changes, fmt.Sprintf("UDP service detection: %t → %t", old.UDP.ServiceDetection, next.UDP.ServiceDetection))
		}
	}
	return changes
}

func dnsComparisonSummary(mode string) string {
	switch mode {
	case config.DNSComparisonAggregate:
		return "aggregate port/service surface"
	case config.DNSComparisonAddressSensitive:
		return "address-sensitive"
	default:
		return "address-sensitive"
	}
}

func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func nseSummary(protocol *config.Protocol) string {
	if protocol == nil || strings.TrimSpace(protocol.NSEProfile) == "" {
		return "disabled"
	}
	return protocol.NSEProfile
}

func naabuSecuritySummary(protocol *config.Protocol) string {
	if protocol == nil || protocol.Naabu == nil {
		return "disabled"
	}
	return fmt.Sprintf("%s (verify=%t)", protocol.Naabu.ScanType, protocol.Naabu.Verify)
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	left, right := append([]string(nil), a...), append([]string(nil), b...)
	slices.Sort(left)
	slices.Sort(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func protocolSummary(p *config.Protocol) string {
	if p == nil {
		return "disabled"
	}
	return p.Ports
}

func (s *Server) archiveJob(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, id string, archive bool) {
	var payload lifecyclePayload
	if !decodeJSON(w, r, &payload) {
		return
	}
	if payload.Revision == nil {
		writeError(w, http.StatusBadRequest, "revision_required", "job revision is required", nil)
		return
	}
	action := map[bool]string{true: "job.archived", false: "job.restored"}[archive]
	if err := ts.SetJobArchivedWithRevisionAndAudit(r.Context(), id, archive, *payload.Revision, actorAudit(session, action, id)); err != nil {
		if s.writeAuditUnavailable(w, err, action) {
			return
		}
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "job was modified; reload before changing its lifecycle", nil)
		} else if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		} else if errors.Is(err, store.ErrJobScanActive) {
			writeError(w, http.StatusConflict, "job_active", "archive or restore is unavailable while a scan is running; wait for it to finish and try again", nil)
		} else {
			s.writeInternalError(w, r, "store", err)
		}
		return
	}
	s.App.RefreshSchedules()
	s.broadcastTo(r.Context(), audienceTenant(ts), map[string]any{"type": action, "job_id": id})
	writeJSON(w, 204, nil)
}

// decodePermanentDelete checks the administrator permission and reads the
// typed confirmation before the job is loaded. The permission check stays
// ahead of the lookup, so an operator never learns whether the job exists.
func decodePermanentDelete(w http.ResponseWriter, r *http.Request, session store.Session) (string, bool) {
	if !auth.HasPermission(session, auth.PermissionJobsDelete) {
		writeError(w, http.StatusForbidden, "forbidden", "only an administrator can permanently delete a job", map[string]string{"permission": auth.PermissionJobsDelete})
		return "", false
	}
	var input struct {
		ConfirmName string `json:"confirm_name"`
	}
	if !decodeJSON(w, r, &input) {
		return "", false
	}
	return input.ConfirmName, true
}

func (s *Server) permanentDelete(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, record store.JobRecord, confirmName string) {
	id := record.ID
	if confirmName != record.Job.Name {
		writeError(w, http.StatusBadRequest, "confirmation_required", "type the job name to permanently delete it", nil)
		return
	}
	if !record.Archived {
		writeError(w, http.StatusConflict, "archive_required", "archive the job before permanently deleting it", nil)
		return
	}
	if err := ts.DeleteJobWithAuditAtRevision(r.Context(), id, record.Revision, actorAudit(session, "job.deleted", id)); err != nil {
		if s.writeAuditUnavailable(w, err, "job.deleted") {
			return
		}
		if errors.Is(err, store.ErrJobScanActive) {
			writeError(w, http.StatusConflict, "job_active", "job is still active", nil)
		} else if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "job was modified; reload before deleting it", nil)
		} else if errors.Is(err, store.ErrJobNotArchived) {
			writeError(w, http.StatusConflict, "archive_required", "archive the job before permanently deleting it", nil)
		} else {
			s.writeInternalError(w, r, "job_delete", err)
		}
		return
	}
	s.App.WakePurgeWorker()
	s.App.RefreshSchedules()
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "job.deleted", "job_id": id})
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) enableJob(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, id string, enabled bool) {
	var payload lifecyclePayload
	if !decodeJSON(w, r, &payload) {
		return
	}
	if payload.Revision == nil {
		writeError(w, http.StatusBadRequest, "revision_required", "job revision is required", nil)
		return
	}
	action := map[bool]string{true: "job.resumed", false: "job.paused"}[enabled]
	if err := ts.SetJobEnabledWithRevisionAndAudit(r.Context(), id, enabled, *payload.Revision, actorAudit(session, action, id)); err != nil {
		if s.writeAuditUnavailable(w, err, action) {
			return
		}
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "job was modified; reload before changing its lifecycle", nil)
		} else if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		} else if errors.Is(err, store.ErrJobScanActive) {
			writeError(w, http.StatusConflict, "job_active", "pause or resume is unavailable while a scan is running; wait for it to finish and try again", nil)
		} else {
			writeError(w, http.StatusInternalServerError, "store", "job state could not be changed", nil)
		}
		return
	}
	s.App.RefreshSchedules()
	s.broadcastTo(r.Context(), audienceTenant(ts), map[string]any{"type": action, "job_id": id})
	writeJSON(w, 204, nil)
}

// cancelQueuedRun withdraws the job's run that is waiting for a scan slot.
// The run is then reported as skipped and never starts. A run that has taken
// its slot is canceled with POST /scans/{id}/cancel instead.
func (s *Server) cancelQueuedRun(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, record store.JobRecord) {
	scope, err := ts.Scope()
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	if err := s.App.CancelQueuedRun(scope, record.ID); err != nil {
		if errors.Is(err, app.ErrRunNotQueued) {
			writeError(w, http.StatusConflict, "run_not_queued", "The job has no scan waiting for a slot.", nil)
			return
		}
		s.writeInternalError(w, r, "cancel_failed", err)
		return
	}
	s.auditOptionalEntry(r.Context(), ts, actorAudit(session, "scan.queued_run_canceled", record.ID))
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "canceled", "job_id": record.ID})
}

func (s *Server) runJob(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, record store.JobRecord) {
	id := record.ID
	if record.Archived {
		writeError(w, 409, "archived", "archived jobs cannot run", nil)
		return
	}
	if estimate, budgetErr := s.App.CheckScanWorkBudget(r.Context(), ts, record.Job); budgetErr != nil {
		var workErr *app.ScanWorkBudgetError
		if errors.As(budgetErr, &workErr) {
			writeError(w, http.StatusUnprocessableEntity, "scan_work_budget_exceeded", budgetErr.Error(), map[string]any{"estimate": workErr.Estimate, "budget": workErr.Budget, "allow_high_cost": record.Job.AllowHighCost})
			return
		}
		if errors.Is(budgetErr, app.ErrProbeBudgetUnavailable) {
			s.writeStoreWriteError(w, r, budgetErr, "job not found")
			return
		}
		writeError(w, http.StatusBadRequest, "scan_work_estimate_failed", budgetErr.Error(), map[string]any{"estimate": estimate})
		return
	}
	if active, activeErr := ts.JobActive(r.Context(), id); activeErr != nil {
		s.writeStoreWriteError(w, r, activeErr, "job not found")
		return
	} else if active {
		writeError(w, http.StatusConflict, "job_active", "job already has a scan in progress", nil)
		return
	}
	// Manual scans intentionally use the app-owned lifecycle context so they
	// continue after this HTTP request returns.
	//nolint:contextcheck // the lifecycle context is managed by App, not the request
	if runErr := s.App.StartManagedRun(ts, id, func(scan model.Scan, events []model.Event, err error) {
		if err != nil {
			if errors.Is(err, scanner.ErrBusy) {
				s.Log.Info("manual scan was already in progress", "job_id", id, "scan_id", scan.ID)
			} else {
				s.Log.Error("manual scan failed", "job_id", id, "scan_id", scan.ID, "error", err)
			}
		}
		if scan.ID != "" {
			s.broadcastTo(context.Background(), audienceTenant(ts), map[string]any{"type": "scan.completed", "job": scan.Job, "job_id": id, "scan_id": scan.ID, "status": scan.Status, "message": "Scan " + scan.Status, "events": len(events)})
		}
	}); runErr != nil {
		if errors.Is(runErr, scanner.ErrBusy) {
			writeError(w, http.StatusConflict, "job_active", "job already has a scan in progress", nil)
			return
		}
		if errors.Is(runErr, app.ErrShuttingDown) {
			writeError(w, http.StatusServiceUnavailable, "shutting_down", "the application is shutting down", nil)
			return
		}
		s.writeInternalError(w, r, "scan", runErr)
		return
	}
	mode := "standard"
	if broadScan(record.Job) {
		mode = "resumable"
	}
	cycleID := ""
	if cycle, cycleErr := ts.GetActiveScanCycle(r.Context(), id); cycleErr == nil {
		cycleID = cycle.ID
		mode = "resumable"
	}
	s.auditOptionalEntry(r.Context(), ts, actorAudit(session, "scan.run_requested", id))
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted", "job_id": id, "mode": mode, "cycle_id": cycleID})
}

func broadScan(job config.Job) bool {
	estimate, err := config.EstimateJobWork(job)
	if err != nil {
		return false
	}
	return estimate.TCPPorts > 4096 || estimate.UDPPorts > 4096 || estimate.Probes > 65_536
}

func (s *Server) scanCycle(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, job store.JobRecord) {
	cycle, err := ts.GetRecoverableScanCycle(r.Context(), job.ID)
	if errors.Is(err, store.ErrNoScanCycle) {
		writeJSON(w, http.StatusOK, map[string]any{"cycle": nil})
		return
	}
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	// The plan contains the immutable job and target expansion needed to
	// explain progress, but it is intentionally returned without raw scanner
	// arguments or completed snapshot fragments.
	limit := queryLimit(r)
	offset, ok := requestOffset(w, r)
	if !ok {
		return
	}
	unitsPage, unitsErr := ts.ListScanCycleUnitSummariesPage(r.Context(), cycle.ID, limit, offset)
	if unitsErr != nil {
		s.writeInternalError(w, r, "store", unitsErr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cycle": map[string]any{
		"id": cycle.ID, "job_id": cycle.JobID, "job_revision": cycle.JobRevision,
		"status": cycle.Status, "attempt_count": cycle.AttemptCount,
		"no_progress_attempts": cycle.NoProgressAttempts, "total_units": cycle.TotalUnits,
		"completed_units": cycle.CompletedUnits, "total_probes": cycle.TotalProbes,
		"completed_probes": cycle.CompletedProbes, "started_at": cycle.StartedAt,
		"updated_at": cycle.UpdatedAt, "expires_at": cycle.ExpiresAt,
		"finished_at": cycle.FinishedAt, "last_error": cycle.LastError,
		"units": unitsPage.Items, "units_pagination": paginationJSON(offset, limit, unitsPage.Total),
	}})
}

func (s *Server) discardScanCycle(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, job store.JobRecord, cycleID string) {
	id := job.ID
	cycle, err := ts.GetScanCycle(r.Context(), cycleID)
	if err != nil || cycle.JobID != id {
		writeError(w, http.StatusNotFound, "not_found", "scan cycle not found", nil)
		return
	}
	if err := ts.DiscardScanCycle(r.Context(), cycleID); err != nil {
		writeError(w, http.StatusConflict, "cycle_discard_failed", "scan cycle could not be discarded", nil)
		return
	}
	s.auditOptionalEntry(r.Context(), ts, actorAudit(session, "scan.cycle_discarded", cycleID))
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "scan.cycle_discarded", "job_id": id, "cycle_id": cycleID})
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) jobScans(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, job store.JobRecord) {
	limit := queryLimit(r)
	offset, ok := requestOffset(w, r)
	if !ok {
		return
	}
	page, err := ts.ListJobScanSummariesPage(r.Context(), job.ID, limit, offset)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	if page.Items == nil {
		page.Items = []model.ScanSummary{}
	}
	writeJSON(w, 200, map[string]any{"scans": page.Items, "pagination": paginationJSON(offset, limit, page.Total)})
}

// scanComparisonView is how the job scan endpoints report a scan's
// comparison: its comparison_state and comparison_source, and where its
// changes come from.
type scanComparisonView struct {
	state  string
	source string
	// scanTime reads the change list stored with the scan.
	scanTime bool
	// legacy compares the scan with the job's current baseline, when there
	// is one. Only rows recorded before scans stored their outcome use it.
	legacy bool
}

// resolveScanComparison reads the comparison outcome that was recorded when
// the scan was finalized. A baseline sample, and the sample that established
// the baseline, keep that meaning after the baseline is established,
// changed, or reset. Only a row without a recorded outcome or a scan-time
// comparison falls back to the current baseline, as releases before schema
// 65 did.
func resolveScanComparison(summary model.ScanSummary) scanComparisonView {
	notCompared := scanComparisonView{state: model.ScanComparisonNotCompared, source: "none"}
	if summary.Status != "success" && summary.Status != "incomplete" {
		return notCompared
	}
	switch summary.Comparison {
	case model.ScanComparisonCompared:
		return scanComparisonView{state: model.ScanComparisonCompared, source: "scan_time", scanTime: true}
	case model.ScanComparisonBaselineSample, model.ScanComparisonBaselineEstablished:
		return scanComparisonView{state: summary.Comparison, source: "none"}
	case model.ScanComparisonLegacy:
		if summary.BaselineScanID != "" || summary.BaselineConfigHash != "" {
			return scanComparisonView{state: model.ScanComparisonCompared, source: "scan_time", scanTime: true}
		}
		notCompared.legacy = true
		return notCompared
	default:
		return notCompared
	}
}

// legacyScanChanges compares a legacy scan with the job's current baseline.
// It reports false when the job has no baseline, which leaves the scan not
// compared.
func legacyScanChanges(ctx context.Context, ts *store.TenantStore, jobID string, summary model.ScanSummary) ([]model.Change, bool, error) {
	state, err := ts.RuntimeState(ctx, jobID)
	if err != nil || state.Baseline == nil {
		return nil, false, err
	}
	// Only this compatibility path needs the full snapshot. Managed scans
	// carry their immutable comparison in changes_json.
	scan, err := ts.GetScan(ctx, summary.ID)
	if err != nil {
		return nil, false, err
	}
	return engine.Diff(*state.Baseline, scan.Snapshot, state.BaselineConfigHash != summary.ConfigHash), true, nil
}

func (s *Server) jobScan(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, record store.JobRecord, summary model.ScanSummary) {
	id, scanID := record.ID, summary.ID
	offset, ok := requestOffset(w, r)
	if !ok {
		return
	}
	limit := queryLimit(r)
	view := resolveScanComparison(summary)
	value := map[string]any{"scan": summary, "changes": []model.Change{}, "changes_pagination": paginationJSON(offset, limit, 0), "comparison_source": view.source, "comparison_state": view.state}
	switch {
	case view.scanTime:
		page, pageErr := ts.ListScanChangesPage(r.Context(), scanID, limit, offset)
		if pageErr != nil {
			s.writeInternalError(w, r, "store", pageErr)
			return
		}
		items := page.Items
		if items == nil {
			items = []model.Change{}
		}
		value["changes"], value["changes_pagination"] = items, paginationJSON(offset, limit, page.Total)
		value["baseline_scan_id"] = summary.BaselineScanID
	case view.state == model.ScanComparisonBaselineEstablished:
		value["baseline_scan_id"] = summary.BaselineScanID
	case view.legacy:
		changes, compared, legacyErr := legacyScanChanges(r.Context(), ts, id, summary)
		if legacyErr != nil {
			s.writeInternalError(w, r, "store", legacyErr)
			return
		}
		if compared {
			value["changes"], value["changes_pagination"] = pageSlice(changes, offset, limit)
			value["comparison_source"] = "current_baseline_legacy"
			value["comparison_state"] = model.ScanComparisonCompared
		}
	}
	value["current_security_hash"] = record.Job.SecurityHash()
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) jobScanResults(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, summary model.ScanSummary) {
	offset, ok := requestOffset(w, r)
	if !ok {
		return
	}
	limit := queryLimit(r)
	resultPage, err := ts.ListScanResultsPage(r.Context(), summary.ID, limit, offset)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	results := resultPage.Items
	if results == nil {
		results = []model.Unit{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "pagination": paginationJSON(offset, limit, resultPage.Total)})
}

func (s *Server) jobScanChanges(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, job store.JobRecord, summary model.ScanSummary) {
	id, scanID := job.ID, summary.ID
	offset, ok := requestOffset(w, r)
	if !ok {
		return
	}
	limit := queryLimit(r)
	changes := []model.Change{}
	var total int
	view := resolveScanComparison(summary)
	comparisonSource, comparisonState := view.source, view.state
	switch {
	case view.scanTime:
		page, pageErr := ts.ListScanChangesPage(r.Context(), scanID, limit, offset)
		if pageErr != nil {
			s.writeInternalError(w, r, "store", pageErr)
			return
		}
		changes, total = page.Items, page.Total
	case view.legacy:
		legacy, compared, legacyErr := legacyScanChanges(r.Context(), ts, id, summary)
		if legacyErr != nil {
			s.writeInternalError(w, r, "store", legacyErr)
			return
		}
		if compared {
			changes = legacy
			comparisonSource = "current_baseline_legacy"
			comparisonState = model.ScanComparisonCompared
		}
	}
	items, page := changes, paginationJSON(offset, limit, total)
	if !view.scanTime {
		items, page = pageSlice(changes, offset, limit)
	}
	if items == nil {
		items = []model.Change{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": items, "pagination": page, "comparison_source": comparisonSource, "comparison_state": comparisonState, "baseline_scan_id": summary.BaselineScanID})
}
func (s *Server) listScans(w http.ResponseWriter, r *http.Request, ts *store.TenantStore) {
	limit := queryLimit(r)
	offset, ok := requestOffset(w, r)
	if !ok {
		return
	}
	page, err := ts.ListScanSummariesPage(r.Context(), r.URL.Query().Get("job"), limit, offset)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	if page.Items == nil {
		page.Items = []model.ScanSummary{}
	}
	writeJSON(w, 200, map[string]any{"scans": page.Items, "pagination": paginationJSON(offset, limit, page.Total)})
}

// maxConcurrentFullScans bounds the full-result scan responses in flight.
// Each holds its scan's snapshot in memory, and a read connection, until the
// client has received it.
const maxConcurrentFullScans = 2

// getScan serves the full-result compatibility endpoint. It writes the
// stored snapshot and change list as they were saved, without decoding and
// encoding them again, so a broad scan is held in memory once rather than
// as decoded structs and a second encoding. For a scan that EdgeWatch saved,
// the response is the one that decoding and encoding it gave. A request
// waits for one of maxConcurrentFullScans slots, so parallel requests cannot
// multiply that memory without bound.
func (s *Server) getScan(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, id string) {
	s.fullScanSlotOnce.Do(func() { s.fullScanSlots = make(chan struct{}, maxConcurrentFullScans) })
	select {
	case s.fullScanSlots <- struct{}{}:
	case <-r.Context().Done():
		return
	}
	defer func() { <-s.fullScanSlots }()
	err := ts.WithScanDocument(r.Context(), id, func(scan model.Scan, snapshot, changes []byte) error {
		return writeStoredScan(w, scan, snapshot, changes)
	})
	if errors.Is(err, errScanNotVerbatim) {
		// The stored values are not what EdgeWatch writes. Decode them, as
		// releases before this one did for every scan.
		if scan, ok := s.resolveScan(w, r, ts, id); ok {
			writeJSON(w, http.StatusOK, map[string]any{"scan": scan})
		}
		return
	}
	if err != nil && !errors.Is(err, errScanResponseStarted) {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
	}
}

// errScanNotVerbatim reports a stored snapshot or change list that cannot
// be written out as it is. errScanResponseStarted reports a failed write
// after the response status was sent.
var (
	errScanNotVerbatim     = errors.New("stored scan cannot be written verbatim")
	errScanResponseStarted = errors.New("scan response interrupted")
)

// fullScanMetadata encodes a scan without its snapshot and changes: the
// fields of the same JSON names hide those of the embedded scan.
type fullScanMetadata struct {
	model.Scan
	Changes  *struct{} `json:"changes,omitempty"`
	Snapshot *struct{} `json:"snapshot,omitempty"`
}

// writeStoredScan writes {"scan": scan} with the stored snapshot and
// changes in place of the scan's own, as encoding the decoded scan with
// writeJSON would: changes come before the snapshot, as in model.Scan, and
// an empty change list is left out. A snapshot that is not a JSON object, or
// changes that are not null or a JSON array, are errScanNotVerbatim, and
// nothing is written.
func writeStoredScan(w http.ResponseWriter, scan model.Scan, snapshot, changes []byte) error {
	snapshot, changes = bytes.TrimSpace(snapshot), bytes.TrimSpace(changes)
	if len(snapshot) == 0 || snapshot[0] != '{' || !json.Valid(snapshot) {
		return errScanNotVerbatim
	}
	switch {
	case len(changes) == 0 || bytes.Equal(changes, []byte("null")):
		changes = nil
	case changes[0] != '[' || !json.Valid(changes):
		return errScanNotVerbatim
	case len(bytes.TrimSpace(changes[1:len(changes)-1])) == 0:
		changes = nil
	}
	scan.Snapshot, scan.Changes = model.Snapshot{}, nil
	metadata, err := json.Marshal(fullScanMetadata{Scan: scan})
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	parts := [][]byte{[]byte(`{"scan":`), metadata[:len(metadata)-1]}
	if changes != nil {
		parts = append(parts, []byte(`,"changes":`), changes)
	}
	parts = append(parts, []byte(`,"snapshot":`), snapshot, []byte("}}\n"))
	for _, part := range parts {
		if _, err := w.Write(part); err != nil {
			return errScanResponseStarted
		}
	}
	return nil
}

// getScanSummary serves metadata for historical scan views without decoding
// or returning the potentially large snapshot and change payloads. The legacy
// /scans/{id} endpoint remains the full-result compatibility endpoint.
func (s *Server) getScanSummary(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, id string) {
	if summary, ok := s.resolveScanSummary(w, r, ts, id, scanStoreErrorInternal); ok {
		writeJSON(w, http.StatusOK, map[string]any{"scan": summary})
	}
}

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request, ts *store.TenantStore) {
	offset, ok := requestOffset(w, r)
	if !ok {
		return
	}
	limit := queryLimit(r)
	incidentPage, err := ts.ListIncidentsPage(r.Context(), limit, offset)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	items := make([]map[string]any, 0, len(incidentPage.Items))
	for _, item := range incidentPage.Items {
		items = append(items, map[string]any{"job_id": item.JobID, "job": item.Job, "incident": item.Incident})
	}
	writeJSON(w, http.StatusOK, map[string]any{"incidents": items, "pagination": paginationJSON(offset, limit, incidentPage.Total), "truncated": false})
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, job string) {
	if jobID := r.URL.Query().Get("job_id"); jobID != "" {
		offset, ok := requestOffset(w, r)
		if !ok {
			return
		}
		limit := queryLimit(r)
		page, err := ts.ListJobEventsPage(r.Context(), jobID, limit, offset)
		if err != nil {
			s.writeInternalError(w, r, "store", err)
			return
		}
		if page.Items == nil {
			page.Items = []model.Event{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"events": page.Items, "pagination": paginationJSON(offset, limit, page.Total)})
		return
	}
	if job != "" {
		if record, err := ts.GetJobByName(r.Context(), job); err == nil {
			job = record.Job.Name
		}
	}
	offset, ok := requestOffset(w, r)
	if !ok {
		return
	}
	limit := queryLimit(r)
	page, err := ts.ListEventsPage(r.Context(), job, limit, offset)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	if page.Items == nil {
		page.Items = []model.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": page.Items, "pagination": paginationJSON(offset, limit, page.Total)})
}

func (s *Server) jobEvents(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, job store.JobRecord) {
	offset, ok := requestOffset(w, r)
	if !ok {
		return
	}
	limit := queryLimit(r)
	page, err := ts.ListJobEventsPage(r.Context(), job.ID, limit, offset)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	if page.Items == nil {
		page.Items = []model.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": page.Items, "pagination": paginationJSON(offset, limit, page.Total)})
}
func (s *Server) jobIncidents(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, record store.JobRecord) {
	id := record.ID
	offset, ok := requestOffset(w, r)
	if !ok {
		return
	}
	limit := queryLimit(r)
	incidentPage, err := ts.ListJobIncidentsPage(r.Context(), id, limit, offset)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	items := incidentPage.Items
	if items == nil {
		items = []model.Incident{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": record.Job.Name, "incidents": items, "pagination": paginationJSON(offset, limit, incidentPage.Total), "truncated": false})
}

type incidentActionRequest struct {
	Key            string        `json:"key"`
	ExpectedChange *model.Change `json:"expected_change"`
}

// incidentAction is an accept or suppress request that passed validation.
type incidentAction struct {
	key      string
	expected model.Change
}

// decodeIncidentAction validates an incident action before the job is loaded.
func decodeIncidentAction(w http.ResponseWriter, r *http.Request) (incidentAction, bool) {
	var input incidentActionRequest
	if !decodeJSON(w, r, &input) {
		return incidentAction{}, false
	}
	key := strings.TrimSpace(input.Key)
	if key == "" {
		writeError(w, http.StatusBadRequest, "key_required", "incident key is required", map[string]string{"key": "incident key is required"})
		return incidentAction{}, false
	}
	if input.ExpectedChange == nil {
		writeError(w, http.StatusBadRequest, "expected_change_required", "the reviewed incident change is required; refresh before retrying", map[string]string{"expected_change": "reload the incident before confirming this action"})
		return incidentAction{}, false
	}
	return incidentAction{key: key, expected: *input.ExpectedChange}, true
}

func (s *Server) acceptIncident(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, record store.JobRecord, action incidentAction) {
	id, key := record.ID, action.key
	var destinations []string
	var err error
	if s.App != nil && s.App.Notifier != nil {
		destinations, err = s.App.Notifier.Tenant(ts).QueueDestinationsForJob(r.Context(), record.Job)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "notification", "notification destinations could not be loaded", nil)
			return
		}
	}
	events, err := ts.AcceptIncidentWithExpectedOutboxAndAudit(r.Context(), id, record.Job.Name, key, &store.IncidentExpectation{Change: action.expected}, destinations, actorAudit(session, "incident.accepted", id+":"+key))
	if err != nil {
		s.writeIncidentActionErrorWithRequest(w, r, err, "incident.accepted")
		return
	}
	if s.App != nil {
		s.App.WakeDelivery()
	}
	s.broadcastIncidentEvents(context.WithoutCancel(r.Context()), audienceTenant(ts), id, events)
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) suppressIncident(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, record store.JobRecord, action incidentAction) {
	id, key := record.ID, action.key
	var destinations []string
	var err error
	if s.App != nil && s.App.Notifier != nil {
		destinations, err = s.App.Notifier.Tenant(ts).QueueDestinationsForJob(r.Context(), record.Job)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "notification", "notification destinations could not be loaded", nil)
			return
		}
	}
	events, err := ts.SuppressIncidentWithExpectedOutboxAndAudit(r.Context(), id, record.Job.Name, key, &store.IncidentExpectation{Change: action.expected}, destinations, actorAudit(session, "incident.suppressed", id+":"+key))
	if err != nil {
		s.writeIncidentActionErrorWithRequest(w, r, err, "incident.suppressed")
		return
	}
	if s.App != nil {
		s.App.WakeDelivery()
	}
	s.broadcastIncidentEvents(context.WithoutCancel(r.Context()), audienceTenant(ts), id, events)
	writeJSON(w, http.StatusNoContent, nil)
}

// writeIncidentActionError retains the small helper contract used by package
// callers that do not have an HTTP request. Routed handlers use the request-
// aware variant so failures carry a correlation ID.
func (s *Server) writeIncidentActionError(w http.ResponseWriter, err error, action string) {
	s.writeIncidentActionErrorWithRequest(w, nil, err, action)
}

func (s *Server) writeIncidentActionErrorWithRequest(w http.ResponseWriter, r *http.Request, err error, action string) {
	if s.writeAuditUnavailable(w, err, action) {
		return
	}
	switch {
	case errors.Is(err, store.ErrIncidentNotFound):
		writeError(w, http.StatusNotFound, "incident_not_found", "incident is no longer active", nil)
	case errors.Is(err, store.ErrIncidentConflict):
		writeError(w, http.StatusConflict, "incident_conflict", "the incident changed since it was loaded; refresh before retrying", nil)
	case errors.Is(err, store.ErrJobScanActive):
		writeError(w, http.StatusConflict, "job_active", "incident actions cannot change the baseline during an active scan", nil)
	case errors.Is(err, store.ErrBaselineNotReady):
		writeError(w, http.StatusConflict, "baseline_not_ready", "the job does not have an active baseline", nil)
	case errors.Is(err, store.ErrUnsupportedIncidentChange):
		writeError(w, http.StatusBadRequest, "incident_change_invalid", "this incident cannot be applied to the baseline", nil)
	default:
		if r != nil {
			s.writeInternalError(w, r, "store", err)
		} else {
			writeError(w, http.StatusInternalServerError, "store", "internal server error", nil)
		}
	}
}

func (s *Server) broadcastIncidentEvents(ctx context.Context, audience sseAudience, jobID string, events []model.Event) {
	for _, event := range events {
		s.broadcastTo(ctx, audience, map[string]any{"type": event.Type, "job_id": jobID, "job": event.Job, "scan_id": event.ScanID, "message": event.Message, "changes": event.Changes})
	}
}

// jobBaseline exposes the current comparison state without requiring clients
// to fetch the full job record. Baseline units are paginated because a broad
// CIDR can produce a large snapshot; the scope metadata remains intact on
// every page. Host observations and host states grow with every address in
// the scope, so no page carries them: the dedicated, filtered baseline host
// endpoints serve the observations. The store decodes only the units on the
// page and the scope metadata.
func (s *Server) jobBaseline(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, record store.JobRecord) {
	id := record.ID
	offset, ok := requestOffset(w, r)
	if !ok {
		return
	}
	limit := queryLimit(r)
	summary, err := ts.RuntimeStateSummary(r.Context(), id)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	value := map[string]any{
		"job_id":        id,
		"job":           record.Job.Name,
		"revision":      record.Revision,
		"security_hash": record.Job.SecurityHash(),
		"baseline":      baselineJSONFromSummary(summary, record.Job.SecurityHash()),
		"snapshot":      nil,
		"pagination":    paginationJSON(offset, limit, 0),
	}
	if !summary.HasBaseline {
		writeJSON(w, http.StatusOK, value)
		return
	}
	page, err := ts.RuntimeBaselinePage(r.Context(), id, limit, offset)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	if page.Present {
		value["snapshot"], value["pagination"] = page.Snapshot, paginationJSON(offset, limit, page.Total)
	}
	writeJSON(w, http.StatusOK, value)
}

// resetBaselineRequest names the baseline the operator reviewed. Both fields
// are optional, and the request body itself may be empty.
type resetBaselineRequest struct {
	ExpectedBaselineScanID   *string `json:"expected_baseline_scan_id"`
	ExpectedBaselineModified *bool   `json:"expected_baseline_modified"`
}

// decodeResetBaseline reads an optional reset request before the job is loaded.
func decodeResetBaseline(w http.ResponseWriter, r *http.Request) (resetBaselineRequest, bool) {
	var input resetBaselineRequest
	if r.Body != nil && r.Body != http.NoBody {
		if !decodeJSON(w, r, &input) {
			return resetBaselineRequest{}, false
		}
	}
	return input, true
}

func (s *Server) resetBaseline(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, record store.JobRecord, input resetBaselineRequest) {
	id := record.ID
	state, stateErr := ts.RuntimeState(r.Context(), id)
	if stateErr != nil {
		writeError(w, http.StatusInternalServerError, "store", "baseline state could not be loaded", nil)
		return
	}
	expected := store.BaselineExpectation{ScanID: state.BaselineScanID, ScanIDSet: true, Modified: state.BaselineModified, ModifiedSet: true}
	if input.ExpectedBaselineScanID != nil {
		expected.ScanID, expected.ScanIDSet = strings.TrimSpace(*input.ExpectedBaselineScanID), true
	}
	if input.ExpectedBaselineModified != nil {
		expected.Modified, expected.ModifiedSet = *input.ExpectedBaselineModified, true
	}
	destinations, err := s.App.Notifier.Tenant(ts).QueueDestinationsForJob(r.Context(), record.Job)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "notification", "unable to prepare notification delivery", nil)
		return
	}
	events, err := ts.ResetRuntimeWithExpectationAndAudit(r.Context(), id, record.Job.Name, destinations, actorAudit(session, "baseline.reset", id), expected)
	if err != nil {
		if s.writeAuditUnavailable(w, err, "baseline.reset") {
			return
		}
		if errors.Is(err, store.ErrJobScanActive) {
			writeError(w, http.StatusConflict, "job_active", "baseline reset is unavailable while a scan is running; wait for it to finish and try again", nil)
			return
		}
		if errors.Is(err, store.ErrConflict) {
			s.writeBaselineConflict(w, r, ts, id)
			return
		}
		writeError(w, 500, "store", "baseline reset could not be completed", nil)
		return
	}
	s.App.WakeDelivery()
	for _, event := range events {
		s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": event.Type, "job_id": id, "job": event.Job, "scan_id": event.ScanID, "message": event.Message})
	}
	writeJSON(w, 200, map[string]any{"events": events})
}

// approveBaselineRequest names the scan to approve and the baseline the
// operator reviewed.
type approveBaselineRequest struct {
	ScanID                   string  `json:"scan_id"`
	ExpectedBaselineScanID   *string `json:"expected_baseline_scan_id"`
	ExpectedBaselineModified *bool   `json:"expected_baseline_modified"`
}

// decodeApproveBaseline reads an approval request before the job is loaded.
func decodeApproveBaseline(w http.ResponseWriter, r *http.Request) (approveBaselineRequest, bool) {
	var input approveBaselineRequest
	if !decodeJSON(w, r, &input) {
		return approveBaselineRequest{}, false
	}
	return input, true
}

func (s *Server) approveBaseline(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, record store.JobRecord, input approveBaselineRequest) {
	id := record.ID
	state, stateErr := ts.RuntimeState(r.Context(), id)
	if stateErr != nil {
		s.writeInternalError(w, r, "store", stateErr)
		return
	}
	expected := store.BaselineExpectation{ScanID: state.BaselineScanID, ScanIDSet: true, Modified: state.BaselineModified, ModifiedSet: true}
	if input.ExpectedBaselineScanID != nil {
		expected.ScanID, expected.ScanIDSet = strings.TrimSpace(*input.ExpectedBaselineScanID), true
	}
	if input.ExpectedBaselineModified != nil {
		expected.Modified, expected.ModifiedSet = *input.ExpectedBaselineModified, true
	}
	scan, err := ts.GetScan(r.Context(), input.ScanID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "invalid_scan", "scan must be successful and belong to this job's current scope", nil)
		} else {
			s.writeInternalError(w, r, "scan_read", err)
		}
		return
	}
	if scan.JobID != id || scan.ConfigHash != record.Job.SecurityHash() || scan.Status != "success" {
		writeError(w, http.StatusBadRequest, "invalid_scan", "scan must be successful and belong to this job's current scope", nil)
		return
	}
	destinations, err := s.App.Notifier.Tenant(ts).QueueDestinationsForJob(r.Context(), record.Job)
	if err != nil {
		s.writeInternalError(w, r, "notification", err)
		return
	}
	events, err := ts.ApproveRuntimeWithExpectationAndAudit(r.Context(), id, record.Job.Name, scan, destinations, actorAudit(session, "baseline.approved", id), expected)
	if err != nil {
		s.writeBaselineApprovalError(w, r, ts, id, err)
		return
	}
	s.App.WakeDelivery()
	for _, event := range events {
		s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": event.Type, "job_id": id, "job": event.Job, "scan_id": event.ScanID, "message": event.Message})
	}
	writeJSON(w, 200, map[string]any{"events": events})
}

func (s *Server) writeBaselineApprovalError(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, jobID string, err error) {
	if s.writeAuditUnavailable(w, err, "baseline.approved") {
		return
	}
	switch {
	case errors.Is(err, store.ErrJobScanActive):
		writeError(w, http.StatusConflict, "job_active", "baseline approval is unavailable while a scan is running; wait for it to finish and try again", nil)
	case errors.Is(err, store.ErrConflict):
		s.writeBaselineConflict(w, r, ts, jobID)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "job or scan was not found", nil)
	case errors.Is(err, store.ErrValidation):
		writeValidationError(w, err)
	default:
		s.writeInternalError(w, r, "baseline_approval", err)
	}
}

func (s *Server) writeBaselineConflict(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, id string) {
	current := map[string]any{}
	if info, err := ts.RuntimeBaselineInfo(r.Context(), id); err == nil {
		current = map[string]any{"baseline_scan_id": info.BaselineScanID, "baseline_modified": info.BaselineModified, "baseline_config_hash": info.BaselineConfigHash}
	}
	writeError(w, http.StatusConflict, "baseline_conflict", "the baseline changed; refresh before retrying", map[string]any{"current": current})
}
