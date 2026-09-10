package web

import (
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
	"github.com/crypt0rr/edgewatch/internal/store"
)

func (s *Server) activeScans(w http.ResponseWriter, r *http.Request) {
	scans := s.App.ActiveScans()
	if scans == nil {
		scans = []model.ActiveScan{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": scans})
}

func (s *Server) cancelScan(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	if strings.TrimSpace(id) == "" {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	if err := s.App.CancelScan(id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusConflict, "scan_not_active", "scan is no longer active", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "cancel_failed", err.Error(), nil)
		return
	}
	// Cancellation is an operational action; keep its audit detail opaque and
	// never include scanner command lines or target payloads.
	s.auditOptionalEntry(r.Context(), actorAudit(session, "scan.cancel_requested", id))
	s.broadcast(map[string]any{"type": "scan.cancellation_requested", "scan_id": id})
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "cancelling", "scan_id": id})
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request, id string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	state, err := s.Store.RuntimeState(r.Context(), id)
	if err != nil {
		writeError(w, 500, "store", err.Error(), nil)
		return
	}
	writeJSON(w, 200, s.jobJSONWithCycle(r.Context(), record, state))
}

func (s *Server) updateJob(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	var p jobPayload
	if !decodeJSON(w, r, &p) {
		return
	}
	if p.Revision < 1 {
		writeError(w, http.StatusBadRequest, "revision_required", "job revision is required", map[string]string{"revision": "job revision is required"})
		return
	}
	job, err := p.config()
	if err != nil {
		writeValidationError(w, err)
		return
	}
	if job.AllowHighCost && !canOverrideHighCost(session) {
		writeError(w, http.StatusForbidden, "high_cost_admin_required", "only administrators may enable high-cost scans", nil)
		return
	}
	current, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
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
	if err := s.applySelectedScannerProfile(r.Context(), &job, allowArchivedProfile); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "profile_conflict", "scanner profile was modified; reload and select its current revision", nil)
		} else {
			writeValidationError(w, err)
		}
		return
	}
	if !s.validateNotificationSelection(w, r, job) {
		return
	}
	// Routing is additive to the job API. Older clients that do not send the
	// field must not accidentally reset a job's saved notification selection.
	if p.NotificationDestinations == nil {
		job.NotificationDestinations = cloneStrings(current.Job.NotificationDestinations)
	}
	active, activeErr := s.Store.JobActive(r.Context(), id)
	if activeErr != nil {
		writeError(w, http.StatusInternalServerError, "store", activeErr.Error(), nil)
		return
	}
	scopeChanged := current.Job.SecurityHash() != job.SecurityHash()
	if active && scopeChanged {
		writeError(w, 409, "job_active", "security-relevant settings cannot change during an active scan", nil)
		return
	}
	enabled := current.Enabled
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	var destinations []string
	if scopeChanged && p.ConfirmRebaseline {
		destinations, err = s.App.Notifier.QueueDestinationsForJob(r.Context(), job)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "notification", "unable to prepare notification delivery", nil)
			return
		}
	}
	audits := []store.AuditEntry{actorAudit(session, "job.updated", id)}
	if scopeChanged {
		audits = append([]store.AuditEntry{actorAudit(session, "job.rebaseline_requested", id)}, audits...)
	}
	record, changed, events, err := s.Store.UpdateJobWithEventsWithOutboxAndAudit(r.Context(), id, p.Revision, job, enabled, current.Archived, p.ConfirmRebaseline, destinations, audits...)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, 409, "conflict", "job was modified; reload before saving", nil)
		return
	}
	if errors.Is(err, store.ErrRebaselineRequired) {
		writeError(w, 409, "rebaseline_confirmation_required", "security-relevant settings changed; confirm rebaseline to continue", map[string]any{"previous_hash": current.Job.SecurityHash(), "new_hash": job.SecurityHash(), "changes": securityScopeChanges(current.Job, job)})
		return
	}
	if errors.Is(err, store.ErrJobScanActive) {
		writeError(w, http.StatusConflict, "job_active", "security-relevant settings cannot change during an active scan", nil)
		return
	}
	if err != nil {
		if s.writeAuditUnavailable(w, err, "job.updated") {
			return
		}
		if isUnique(err) {
			writeError(w, 409, "conflict", "job name is already in use", nil)
		} else {
			writeValidationError(w, err)
		}
		return
	}
	if changed {
		for _, event := range events {
			s.broadcast(map[string]any{"type": event.Type, "job_id": id, "job": event.Job, "scan_id": event.ScanID, "message": event.Message})
		}
		s.App.WakeDelivery()
	}
	s.App.RefreshSchedules()
	state, _ := s.Store.RuntimeState(r.Context(), id)
	s.broadcast(map[string]any{"type": "job.updated", "job_id": id})
	writeJSON(w, 200, s.jobJSONWithCycle(r.Context(), record, state))
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

func (s *Server) archiveJob(w http.ResponseWriter, r *http.Request, session store.Session, id string, archive bool) {
	var payload lifecyclePayload
	if !decodeJSON(w, r, &payload) {
		return
	}
	if payload.Revision == nil {
		writeError(w, http.StatusBadRequest, "revision_required", "job revision is required", nil)
		return
	}
	action := map[bool]string{true: "job.archived", false: "job.restored"}[archive]
	if err := s.Store.SetJobArchivedWithRevisionAndAudit(r.Context(), id, archive, *payload.Revision, actorAudit(session, action, id)); err != nil {
		if s.writeAuditUnavailable(w, err, action) {
			return
		}
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "job was modified; reload before changing its lifecycle", nil)
		} else if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		} else {
			writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		}
		return
	}
	s.App.RefreshSchedules()
	s.broadcast(map[string]any{"type": action, "job_id": id})
	writeJSON(w, 204, nil)
}

func (s *Server) permanentDelete(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	if !auth.HasPermission(session, auth.PermissionJobsDelete) {
		writeError(w, http.StatusForbidden, "forbidden", "only an administrator can permanently delete a job", map[string]string{"permission": auth.PermissionJobsDelete})
		return
	}
	var input struct {
		ConfirmName string `json:"confirm_name"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	if input.ConfirmName != record.Job.Name {
		writeError(w, http.StatusBadRequest, "confirmation_required", "type the job name to permanently delete it", nil)
		return
	}
	if !record.Archived {
		writeError(w, http.StatusConflict, "archive_required", "archive the job before permanently deleting it", nil)
		return
	}
	if err := s.Store.DeleteJobWithAudit(r.Context(), id, actorAudit(session, "job.deleted", id)); err != nil {
		if s.writeAuditUnavailable(w, err, "job.deleted") {
			return
		}
		if errors.Is(err, store.ErrJobScanActive) {
			writeError(w, http.StatusConflict, "job_active", err.Error(), nil)
		} else {
			writeError(w, http.StatusConflict, "delete_blocked", err.Error(), nil)
		}
		return
	}
	s.App.RefreshSchedules()
	s.broadcast(map[string]any{"type": "job.deleted", "job_id": id})
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) enableJob(w http.ResponseWriter, r *http.Request, session store.Session, id string, enabled bool) {
	var payload lifecyclePayload
	if !decodeJSON(w, r, &payload) {
		return
	}
	if payload.Revision == nil {
		writeError(w, http.StatusBadRequest, "revision_required", "job revision is required", nil)
		return
	}
	action := map[bool]string{true: "job.resumed", false: "job.paused"}[enabled]
	if err := s.Store.SetJobEnabledWithRevisionAndAudit(r.Context(), id, enabled, *payload.Revision, actorAudit(session, action, id)); err != nil {
		if s.writeAuditUnavailable(w, err, action) {
			return
		}
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "job was modified; reload before changing its lifecycle", nil)
		} else if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		} else {
			writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		}
		return
	}
	s.App.RefreshSchedules()
	writeJSON(w, 204, nil)
}

func (s *Server) runJob(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	if record.Archived {
		writeError(w, 409, "archived", "archived jobs cannot run", nil)
		return
	}
	if estimate, budgetErr := s.App.CheckScanWorkBudget(record.Job); budgetErr != nil {
		var workErr *app.ScanWorkBudgetError
		if errors.As(budgetErr, &workErr) {
			writeError(w, http.StatusUnprocessableEntity, "scan_work_budget_exceeded", budgetErr.Error(), map[string]any{"estimate": workErr.Estimate, "budget": workErr.Budget, "allow_high_cost": record.Job.AllowHighCost})
			return
		}
		writeError(w, http.StatusBadRequest, "scan_work_estimate_failed", budgetErr.Error(), map[string]any{"estimate": estimate})
		return
	}
	if active, activeErr := s.Store.JobActive(r.Context(), id); activeErr != nil {
		writeError(w, http.StatusInternalServerError, "store", activeErr.Error(), nil)
		return
	} else if active {
		writeError(w, http.StatusConflict, "job_active", "job already has a scan in progress", nil)
		return
	}
	// Manual scans intentionally use the app-owned lifecycle context so they
	// continue after this HTTP request returns.
	//nolint:contextcheck // the lifecycle context is managed by App, not the request
	if runErr := s.App.StartManagedRun(id, func(scan model.Scan, events []model.Event, err error) {
		if err != nil {
			s.Log.Error("manual scan failed", "job_id", id, "scan_id", scan.ID, "error", err)
		}
		if scan.ID != "" {
			s.broadcast(map[string]any{"type": "scan.completed", "job_id": id, "scan_id": scan.ID, "status": scan.Status, "events": len(events)})
		}
	}); runErr != nil {
		if errors.Is(runErr, app.ErrShuttingDown) {
			writeError(w, http.StatusServiceUnavailable, "shutting_down", "the application is shutting down", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "scan", runErr.Error(), nil)
		return
	}
	mode := "standard"
	if broadScan(record.Job) {
		mode = "resumable"
	}
	cycleID := ""
	if cycle, cycleErr := s.Store.GetActiveScanCycle(r.Context(), id); cycleErr == nil {
		cycleID = cycle.ID
		mode = "resumable"
	}
	s.auditOptionalEntry(r.Context(), actorAudit(session, "scan.run_requested", id))
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted", "job_id": id, "mode": mode, "cycle_id": cycleID})
}

func broadScan(job config.Job) bool {
	estimate, err := config.EstimateJobWork(job)
	if err != nil {
		return false
	}
	return estimate.TCPPorts > 4096 || estimate.UDPPorts > 4096 || estimate.Probes > 65_536
}

func (s *Server) scanCycle(w http.ResponseWriter, r *http.Request, id string) {
	if _, err := s.Store.GetJob(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	cycle, err := s.Store.GetActiveScanCycle(r.Context(), id)
	if errors.Is(err, store.ErrNoScanCycle) {
		writeJSON(w, http.StatusOK, map[string]any{"cycle": nil})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	// The plan contains the immutable job and target expansion needed to
	// explain progress, but it is intentionally returned without raw scanner
	// arguments or completed snapshot fragments.
	units, unitsErr := s.Store.ListScanCycleUnitSummaries(r.Context(), cycle.ID)
	if unitsErr != nil {
		writeError(w, http.StatusInternalServerError, "store", unitsErr.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cycle": map[string]any{
		"id": cycle.ID, "job_id": cycle.JobID, "job_revision": cycle.JobRevision,
		"status": cycle.Status, "attempt_count": cycle.AttemptCount,
		"no_progress_attempts": cycle.NoProgressAttempts, "total_units": cycle.TotalUnits,
		"completed_units": cycle.CompletedUnits, "total_probes": cycle.TotalProbes,
		"completed_probes": cycle.CompletedProbes, "started_at": cycle.StartedAt,
		"updated_at": cycle.UpdatedAt, "expires_at": cycle.ExpiresAt,
		"finished_at": cycle.FinishedAt, "last_error": cycle.LastError, "units": units,
	}})
}

func (s *Server) discardScanCycle(w http.ResponseWriter, r *http.Request, session store.Session, id, cycleID string) {
	if _, err := s.Store.GetJob(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	cycle, err := s.Store.GetScanCycle(r.Context(), cycleID)
	if err != nil || cycle.JobID != id {
		writeError(w, http.StatusNotFound, "not_found", "scan cycle not found", nil)
		return
	}
	if err := s.Store.DiscardScanCycle(r.Context(), cycleID); err != nil {
		writeError(w, http.StatusConflict, "cycle_discard_failed", err.Error(), nil)
		return
	}
	s.auditOptionalEntry(r.Context(), actorAudit(session, "scan.cycle_discarded", cycleID))
	s.broadcast(map[string]any{"type": "scan.cycle_discarded", "job_id": id, "cycle_id": cycleID})
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) jobScans(w http.ResponseWriter, r *http.Request, id string) {
	if _, err := s.Store.GetJob(r.Context(), id); err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	limit := queryLimit(r)
	offset := queryOffset(r)
	page, err := s.Store.ListJobScanSummariesPage(r.Context(), id, limit, offset)
	if err != nil {
		writeError(w, 500, "store", err.Error(), nil)
		return
	}
	if page.Items == nil {
		page.Items = []model.ScanSummary{}
	}
	writeJSON(w, 200, map[string]any{"scans": page.Items, "pagination": paginationJSON(offset, limit, page.Total)})
}

func (s *Server) jobScan(w http.ResponseWriter, r *http.Request, id, scanID string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	summary, err := s.Store.GetScanSummary(r.Context(), scanID)
	if err != nil || summary.JobID != id {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	offset, limit := queryOffset(r), queryLimit(r)
	value := map[string]any{"scan": summary, "changes": []model.Change{}, "changes_pagination": paginationJSON(offset, limit, 0), "comparison_source": "none"}
	var state model.JobState
	var stateErr error
	needsCurrentBaseline := summary.Status == "success" && summary.BaselineScanID == "" && summary.BaselineConfigHash == ""
	if needsCurrentBaseline {
		state, stateErr = s.Store.RuntimeState(r.Context(), id)
	}
	if summary.Status == "success" {
		if summary.BaselineScanID != "" || summary.BaselineConfigHash != "" {
			page, pageErr := s.Store.ListScanChangesPage(r.Context(), scanID, limit, offset)
			if pageErr != nil {
				writeError(w, http.StatusInternalServerError, "store", pageErr.Error(), nil)
				return
			}
			items := page.Items
			if items == nil {
				items = []model.Change{}
			}
			value["changes"], value["changes_pagination"] = items, paginationJSON(offset, limit, page.Total)
			value["comparison_source"] = "scan_time"
			value["baseline_scan_id"] = summary.BaselineScanID
		} else if stateErr == nil && state.Baseline != nil {
			// Legacy scans from before the immutable comparison columns were
			// introduced retain the previous current-baseline behavior.
			// Only this compatibility path needs the full snapshot. Managed scans
			// always carry their immutable comparison in changes_json.
			scan, scanErr := s.Store.GetScan(r.Context(), scanID)
			if scanErr != nil {
				writeError(w, http.StatusInternalServerError, "store", scanErr.Error(), nil)
				return
			}
			changes := engine.Diff(*state.Baseline, scan.Snapshot, state.BaselineConfigHash != summary.ConfigHash)
			value["changes"], value["changes_pagination"] = pageSlice(changes, offset, limit)
			value["comparison_source"] = "current_baseline_legacy"
		}
	}
	value["current_security_hash"] = record.Job.SecurityHash()
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) jobScanResults(w http.ResponseWriter, r *http.Request, id, scanID string) {
	if _, err := s.Store.GetJob(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	summary, err := s.Store.GetScanSummary(r.Context(), scanID)
	if err != nil || summary.JobID != id {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	offset, limit := queryOffset(r), queryLimit(r)
	resultPage, err := s.Store.ListScanResultsPage(r.Context(), scanID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	results := resultPage.Items
	if results == nil {
		results = []model.Unit{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "pagination": paginationJSON(offset, limit, resultPage.Total)})
}

func (s *Server) jobScanChanges(w http.ResponseWriter, r *http.Request, id, scanID string) {
	if _, err := s.Store.GetJob(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	summary, err := s.Store.GetScanSummary(r.Context(), scanID)
	if err != nil || summary.JobID != id {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	offset, limit := queryOffset(r), queryLimit(r)
	changes := []model.Change{}
	var total int
	comparisonSource := "none"
	if summary.Status == "success" {
		if summary.BaselineScanID != "" || summary.BaselineConfigHash != "" {
			page, pageErr := s.Store.ListScanChangesPage(r.Context(), scanID, limit, offset)
			if pageErr != nil {
				writeError(w, http.StatusInternalServerError, "store", pageErr.Error(), nil)
				return
			}
			changes, total = page.Items, page.Total
			comparisonSource = "scan_time"
		} else if state, stateErr := s.Store.RuntimeState(r.Context(), id); stateErr == nil && state.Baseline != nil {
			scan, scanErr := s.Store.GetScan(r.Context(), scanID)
			if scanErr != nil {
				writeError(w, http.StatusInternalServerError, "store", scanErr.Error(), nil)
				return
			}
			changes = engine.Diff(*state.Baseline, scan.Snapshot, state.BaselineConfigHash != summary.ConfigHash)
			comparisonSource = "current_baseline_legacy"
		} else if stateErr != nil {
			writeError(w, http.StatusInternalServerError, "store", stateErr.Error(), nil)
			return
		}
	}
	items, page := changes, paginationJSON(offset, limit, total)
	if comparisonSource != "scan_time" {
		items, page = pageSlice(changes, offset, limit)
	}
	if items == nil {
		items = []model.Change{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": items, "pagination": page, "comparison_source": comparisonSource, "baseline_scan_id": summary.BaselineScanID})
}
func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	limit := queryLimit(r)
	offset := queryOffset(r)
	page, err := s.Store.ListScanSummariesPage(r.Context(), r.URL.Query().Get("job"), limit, offset)
	if err != nil {
		writeError(w, 500, "store", err.Error(), nil)
		return
	}
	if page.Items == nil {
		page.Items = []model.ScanSummary{}
	}
	writeJSON(w, 200, map[string]any{"scans": page.Items, "pagination": paginationJSON(offset, limit, page.Total)})
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request, id string) {
	scan, err := s.Store.GetScan(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scan": scan})
}

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	offset, limit := queryOffset(r), queryLimit(r)
	incidentPage, err := s.Store.ListIncidentsPage(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	items := make([]map[string]any, 0, len(incidentPage.Items))
	for _, item := range incidentPage.Items {
		items = append(items, map[string]any{"job_id": item.JobID, "job": item.Job, "incident": item.Incident})
	}
	writeJSON(w, http.StatusOK, map[string]any{"incidents": items, "pagination": paginationJSON(offset, limit, incidentPage.Total), "truncated": false})
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request, job string) {
	if jobID := r.URL.Query().Get("job_id"); jobID != "" {
		offset, limit := queryOffset(r), queryLimit(r)
		page, err := s.Store.ListJobEventsPage(r.Context(), jobID, limit, offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
			return
		}
		if page.Items == nil {
			page.Items = []model.Event{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"events": page.Items, "pagination": paginationJSON(offset, limit, page.Total)})
		return
	}
	if job != "" {
		if record, err := s.Store.GetJobByName(r.Context(), job); err == nil {
			job = record.Job.Name
		}
	}
	offset, limit := queryOffset(r), queryLimit(r)
	page, err := s.Store.ListEventsPage(r.Context(), job, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	if page.Items == nil {
		page.Items = []model.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": page.Items, "pagination": paginationJSON(offset, limit, page.Total)})
}

func (s *Server) jobEvents(w http.ResponseWriter, r *http.Request, id string) {
	if _, err := s.Store.GetJob(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	offset, limit := queryOffset(r), queryLimit(r)
	page, err := s.Store.ListJobEventsPage(r.Context(), id, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	if page.Items == nil {
		page.Items = []model.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": page.Items, "pagination": paginationJSON(offset, limit, page.Total)})
}
func (s *Server) jobIncidents(w http.ResponseWriter, r *http.Request, id string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	offset, limit := queryOffset(r), queryLimit(r)
	incidentPage, err := s.Store.ListJobIncidentsPage(r.Context(), id, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	items := incidentPage.Items
	if items == nil {
		items = []model.Incident{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": record.Job.Name, "incidents": items, "pagination": paginationJSON(offset, limit, incidentPage.Total), "truncated": false})
}

type incidentActionRequest struct {
	Key string `json:"key"`
}

func (s *Server) acceptIncident(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	var input incidentActionRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	key := strings.TrimSpace(input.Key)
	if key == "" {
		writeError(w, http.StatusBadRequest, "key_required", "incident key is required", map[string]string{"key": "incident key is required"})
		return
	}
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	events, err := s.Store.AcceptIncidentWithAudit(r.Context(), id, record.Job.Name, key, actorAudit(session, "incident.accepted", id+":"+key))
	if err != nil {
		s.writeIncidentActionError(w, err, "incident.accepted")
		return
	}
	s.broadcastIncidentEvents(id, events)
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) suppressIncident(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	var input incidentActionRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	key := strings.TrimSpace(input.Key)
	if key == "" {
		writeError(w, http.StatusBadRequest, "key_required", "incident key is required", map[string]string{"key": "incident key is required"})
		return
	}
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	events, err := s.Store.SuppressIncidentWithAudit(r.Context(), id, record.Job.Name, key, actorAudit(session, "incident.suppressed", id+":"+key))
	if err != nil {
		s.writeIncidentActionError(w, err, "incident.suppressed")
		return
	}
	s.broadcastIncidentEvents(id, events)
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) writeIncidentActionError(w http.ResponseWriter, err error, action string) {
	if s.writeAuditUnavailable(w, err, action) {
		return
	}
	switch {
	case errors.Is(err, store.ErrIncidentNotFound):
		writeError(w, http.StatusNotFound, "incident_not_found", "incident is no longer active", nil)
	case errors.Is(err, store.ErrJobScanActive):
		writeError(w, http.StatusConflict, "job_active", "incident actions cannot change the baseline during an active scan", nil)
	case errors.Is(err, store.ErrBaselineNotReady):
		writeError(w, http.StatusConflict, "baseline_not_ready", "the job does not have an active baseline", nil)
	case errors.Is(err, store.ErrUnsupportedIncidentChange):
		writeError(w, http.StatusBadRequest, "incident_change_invalid", "this incident cannot be applied to the baseline", nil)
	default:
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
	}
}

func (s *Server) broadcastIncidentEvents(jobID string, events []model.Event) {
	for _, event := range events {
		s.broadcast(map[string]any{"type": event.Type, "job_id": jobID, "job": event.Job, "scan_id": event.ScanID, "message": event.Message, "changes": event.Changes})
	}
}

// jobBaseline exposes the current comparison state without requiring clients
// to fetch the full job record. Baseline units are paginated because a broad
// CIDR can produce a large snapshot; the scope metadata remains intact on
// every page.
func (s *Server) jobBaseline(w http.ResponseWriter, r *http.Request, id string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	state, err := s.Store.RuntimeState(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	value := map[string]any{
		"job_id":        id,
		"job":           record.Job.Name,
		"revision":      record.Revision,
		"security_hash": record.Job.SecurityHash(),
		"baseline":      baselineJSON(state, record.Job.SecurityHash()),
	}
	if state.Baseline == nil {
		value["snapshot"] = nil
		value["pagination"] = paginationJSON(queryOffset(r), queryLimit(r), 0)
		writeJSON(w, http.StatusOK, value)
		return
	}
	offset, limit := queryOffset(r), queryLimit(r)
	units, page := pageSlice(state.Baseline.Units, offset, limit)
	snapshot := *state.Baseline
	snapshot.Units = units
	value["snapshot"], value["pagination"] = snapshot, page
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) resetBaseline(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	destinations, err := s.App.Notifier.QueueDestinationsForJob(r.Context(), record.Job)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "notification", "unable to prepare notification delivery", nil)
		return
	}
	events, err := s.Store.ResetRuntimeWithOutboxAndAudit(r.Context(), id, record.Job.Name, destinations, actorAudit(session, "baseline.reset", id))
	if err != nil {
		if s.writeAuditUnavailable(w, err, "baseline.reset") {
			return
		}
		writeError(w, 500, "store", err.Error(), nil)
		return
	}
	s.App.WakeDelivery()
	for _, event := range events {
		s.broadcast(map[string]any{"type": event.Type, "job_id": id, "job": event.Job, "scan_id": event.ScanID, "message": event.Message})
	}
	writeJSON(w, 200, map[string]any{"events": events})
}

func (s *Server) approveBaseline(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	var input struct {
		ScanID string `json:"scan_id"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	scan, err := s.Store.GetScan(r.Context(), input.ScanID)
	if err != nil || scan.JobID != id || scan.ConfigHash != record.Job.SecurityHash() {
		writeError(w, 400, "invalid_scan", "scan does not belong to this job or current scope", nil)
		return
	}
	destinations, err := s.App.Notifier.QueueDestinationsForJob(r.Context(), record.Job)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "notification", "unable to prepare notification delivery", nil)
		return
	}
	events, err := s.Store.ApproveRuntimeWithOutboxAndAudit(r.Context(), id, record.Job.Name, scan, destinations, actorAudit(session, "baseline.approved", id))
	if err != nil {
		if s.writeAuditUnavailable(w, err, "baseline.approved") {
			return
		}
		writeError(w, 400, "approve_failed", err.Error(), nil)
		return
	}
	s.App.WakeDelivery()
	for _, event := range events {
		s.broadcast(map[string]any{"type": event.Type, "job_id": id, "job": event.Job, "scan_id": event.ScanID, "message": event.Message})
	}
	writeJSON(w, 200, map[string]any{"events": events})
}
