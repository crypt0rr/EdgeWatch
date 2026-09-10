package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

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
			return errors.New("udp scanner profiles and custom scanner arguments are not supported; UDP uses Nmap defaults")
		}
		return nil
	}
	if strings.TrimSpace(protocol.ProfileID) != "" {
		return nil
	}
	if len(protocol.NaabuArgs) > 0 || len(protocol.NmapArgs) > 0 || len(protocol.EnrichmentArgs) > 0 || strings.TrimSpace(protocol.NSEProfile) != "" || len(protocol.NSEArgs) > 0 || protocol.Naabu != nil {
		return fmt.Errorf("%s scanner arguments and Naabu tuning require an administrator-managed profile", label)
	}
	if strings.TrimSpace(protocol.Engine) == config.EngineNaabuNmap {
		return fmt.Errorf("%s naabu_nmap jobs must select an administrator-managed scanner profile", label)
	}
	return nil
}

func (p jobPayload) config() (config.Job, error) {
	allowHighCost := false
	if p.AllowHighCost != nil {
		allowHighCost = *p.AllowHighCost
	}
	job := config.Job{Name: strings.TrimSpace(p.Name), Schedule: strings.TrimSpace(p.Schedule), Timezone: strings.TrimSpace(p.Timezone), RunOnStart: p.RunOnStart, AssumeAlive: p.AssumeAlive, Targets: p.Targets, MaxExpandedHosts: p.MaxExpandedHosts, Timing: p.Timing, AllowHighCost: allowHighCost}
	if p.NotificationDestinations != nil {
		job.NotificationDestinations = cloneStrings(*p.NotificationDestinations)
	}
	if p.Timeout != "" {
		d, err := parseDuration(p.Timeout)
		if err != nil {
			return job, fmt.Errorf("timeout: %w", err)
		}
		job.Timeout = config.Duration(d)
	}
	if p.ResumeWindow != "" {
		d, err := parseDuration(p.ResumeWindow)
		if err != nil {
			return job, fmt.Errorf("resume_window: %w", err)
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
	if strings.HasSuffix(raw, "d") {
		days, err := strconv.ParseFloat(strings.TrimSuffix(raw, "d"), 64)
		return time.Duration(days * float64(24*time.Hour)), err
	}
	return time.ParseDuration(raw)
}

func jobJSON(record store.JobRecord, state model.JobState) map[string]any {
	p := fromConfig(record.Job)
	estimate, _ := config.EstimateJobWork(record.Job)
	return map[string]any{"id": record.ID, "revision": record.Revision, "enabled": record.Enabled, "archived": record.Archived, "created_at": record.CreatedAt, "updated_at": record.UpdatedAt, "security_hash": record.Job.SecurityHash(), "job": p, "baseline": baselineJSON(state, record.Job.SecurityHash()), "scan_estimate": estimate}
}

func (s *Server) jobJSONWithCycle(ctx context.Context, record store.JobRecord, state model.JobState) map[string]any {
	value := jobJSON(record, state)
	// A profile edit is intentionally non-breaking: jobs retain their pinned
	// revision until an operator explicitly applies the newer one. Surface the
	// availability on the job payload so the editor can offer that deliberate
	// upgrade (and its rebaseline confirmation) instead of silently changing a
	// running scope.
	if payload, ok := value["job"].(jobPayload); ok && payload.TCP != nil && payload.TCP.ProfileID != "" {
		if profile, err := s.Store.GetScannerProfile(ctx, payload.TCP.ProfileID); err == nil && profile.Revision > payload.TCP.ProfileRevision {
			payload.TCP.ProfileUpdateAvailable = true
			payload.TCP.ProfileLatestRevision = profile.Revision
			value["job"] = payload
		}
	}
	cycle, err := s.Store.GetActiveScanCycle(ctx, record.ID)
	if errors.Is(err, store.ErrNoScanCycle) {
		value["scan_cycle"] = nil
		return value
	}
	if err != nil {
		value["scan_cycle_error"] = err.Error()
		return value
	}
	value["scan_cycle"] = cycleJSON(cycle)
	return value
}

func cycleJSON(cycle store.ScanCycleRecord) map[string]any {
	return map[string]any{"id": cycle.ID, "job_id": cycle.JobID, "job_revision": cycle.JobRevision, "status": cycle.Status, "attempt_count": cycle.AttemptCount, "no_progress_attempts": cycle.NoProgressAttempts, "total_units": cycle.TotalUnits, "completed_units": cycle.CompletedUnits, "total_probes": cycle.TotalProbes, "completed_probes": cycle.CompletedProbes, "started_at": cycle.StartedAt, "updated_at": cycle.UpdatedAt, "expires_at": cycle.ExpiresAt, "finished_at": cycle.FinishedAt, "last_error": cycle.LastError}
}

func fromConfig(j config.Job) jobPayload {
	allowHighCost := j.AllowHighCost
	p := jobPayload{Name: j.Name, Schedule: j.Schedule, Timezone: j.Timezone, RunOnStart: j.RunOnStart, AssumeAlive: j.AssumeAlive, Targets: j.Targets, MaxExpandedHosts: j.MaxExpandedHosts, Timing: j.Timing, Timeout: j.Timeout.Value().String(), ResumeWindow: j.ResumeWindowValue().String(), BaselineSamples: j.Baseline.Samples, ChangeConfirmations: j.Change.Confirmations, AllowHighCost: &allowHighCost}
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

func baselineJSON(state model.JobState, currentHash string) map[string]any {
	if state.Baseline == nil {
		return map[string]any{"status": "collecting", "samples": state.CandidateCount, "attempts": state.CandidateAttempts}
	}
	status := "complete"
	if currentHash != "" && state.BaselineConfigHash != "" && state.BaselineConfigHash != currentHash {
		status = "updating"
	}
	hostCount := 0
	if page, err := observationsForSnapshot(*state.Baseline); err == nil {
		hostCount = len(page.Items)
	}
	return map[string]any{"status": status, "scan_id": state.BaselineScanID, "config_hash": state.BaselineConfigHash, "samples": state.CandidateCount, "attempts": state.CandidateAttempts, "incidents": len(state.Incidents), "pending": len(state.Pending), "host_count": hostCount}
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	include := r.URL.Query().Get("include_archived") == "true"
	jobs, err := s.Store.ListJobs(r.Context(), include)
	if err != nil {
		writeError(w, 500, "store", err.Error(), nil)
		return
	}
	out := make([]map[string]any, 0, len(jobs))
	for _, j := range jobs {
		state, stateErr := s.Store.RuntimeState(r.Context(), j.ID)
		if stateErr != nil {
			writeError(w, 500, "store", stateErr.Error(), nil)
			return
		}
		out = append(out, s.jobJSONWithCycle(r.Context(), j, state))
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": out})
}

func (s *Server) createJob(w http.ResponseWriter, r *http.Request, session store.Session) {
	var p jobPayload
	if !decodeJSON(w, r, &p) {
		return
	}
	defaultNewScannerProfile(&p)
	job, err := p.config()
	if err != nil {
		writeValidationError(w, err)
		return
	}
	if job.AllowHighCost && !canOverrideHighCost(session) {
		writeError(w, http.StatusForbidden, "high_cost_admin_required", "only administrators may enable high-cost scans", nil)
		return
	}
	if err := s.applySelectedScannerProfile(r.Context(), &job, false); err != nil {
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
	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	record, err := s.Store.CreateJobWithEnabledAndAudit(r.Context(), job, enabled, actorAudit(session, "job.created", job.Name))
	if err != nil {
		if s.writeAuditUnavailable(w, err, "job.created") {
			return
		}
		if isUnique(err) {
			writeError(w, 409, "conflict", "job name is already in use", nil)
		} else {
			writeValidationError(w, err)
		}
		return
	}
	s.App.RefreshSchedules()
	state, _ := s.Store.RuntimeState(r.Context(), record.ID)
	s.broadcast(map[string]any{"type": "job.created", "job_id": record.ID})
	writeJSON(w, http.StatusCreated, s.jobJSONWithCycle(r.Context(), record, state))
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

func (s *Server) validateNotificationSelection(w http.ResponseWriter, r *http.Request, job config.Job) bool {
	if job.NotificationDestinations == nil {
		return true
	}
	if err := s.App.Notifier.ValidateDestinationSelection(r.Context(), job.NotificationDestinations); err != nil {
		if errors.Is(err, notify.ErrInvalidDestinationSelection) {
			writeError(w, http.StatusBadRequest, "validation_failed", err.Error(), map[string]string{"notification_destinations": err.Error()})
		} else {
			writeError(w, http.StatusInternalServerError, "notification", "notification destinations could not be loaded", nil)
		}
		return false
	}
	return true
}

func (s *Server) jobRoute(w http.ResponseWriter, r *http.Request, session store.Session, rest string) {
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, 404, "not_found", "job not found", nil)
		return
	}
	id := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		s.getJob(w, r, id)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodPut {
		s.updateJob(w, r, session, id)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodDelete {
		if r.URL.Query().Get("permanent") == "true" {
			s.permanentDelete(w, r, session, id)
		} else {
			s.archiveJob(w, r, session, id, true)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "archive" && r.Method == http.MethodPost {
		s.archiveJob(w, r, session, id, true)
		return
	}
	if len(parts) == 2 && parts[1] == "restore" && r.Method == http.MethodPost {
		s.archiveJob(w, r, session, id, false)
		return
	}
	if len(parts) == 2 && parts[1] == "pause" && r.Method == http.MethodPost {
		s.enableJob(w, r, session, id, false)
		return
	}
	if len(parts) == 2 && parts[1] == "resume" && r.Method == http.MethodPost {
		s.enableJob(w, r, session, id, true)
		return
	}
	if len(parts) == 2 && parts[1] == "run" && r.Method == http.MethodPost {
		s.runJob(w, r, session, id)
		return
	}
	if len(parts) == 2 && parts[1] == "scan-cycle" && r.Method == http.MethodGet {
		s.scanCycle(w, r, id)
		return
	}
	if len(parts) == 3 && parts[1] == "scan-cycle" && r.Method == http.MethodDelete {
		s.discardScanCycle(w, r, session, id, parts[2])
		return
	}
	if len(parts) == 2 && parts[1] == "scans" && r.Method == http.MethodGet {
		s.jobScans(w, r, id)
		return
	}
	if len(parts) == 3 && parts[1] == "scans" && r.Method == http.MethodGet {
		s.jobScan(w, r, id, parts[2])
		return
	}
	if len(parts) == 4 && parts[1] == "scans" && parts[3] == "results" && r.Method == http.MethodGet {
		s.jobScanResults(w, r, id, parts[2])
		return
	}
	if len(parts) == 4 && parts[1] == "scans" && parts[3] == "hosts" && r.Method == http.MethodGet {
		s.jobScanHosts(w, r, id, parts[2])
		return
	}
	if len(parts) == 5 && parts[1] == "scans" && parts[3] == "hosts" && r.Method == http.MethodGet {
		s.jobScanHost(w, r, id, parts[2], parts[4])
		return
	}
	if len(parts) == 6 && parts[1] == "scans" && parts[3] == "hosts" && parts[5] == "rdap" && r.Method == http.MethodGet {
		s.jobScanHostRDAP(w, r, id, parts[2], parts[4])
		return
	}
	if len(parts) == 3 && parts[1] == "baseline" && parts[2] == "hosts" && r.Method == http.MethodGet {
		s.jobBaselineHosts(w, r, id)
		return
	}
	if len(parts) == 4 && parts[1] == "baseline" && parts[2] == "hosts" && r.Method == http.MethodGet {
		s.jobBaselineHost(w, r, id, parts[3])
		return
	}
	if len(parts) == 5 && parts[1] == "baseline" && parts[2] == "hosts" && parts[4] == "rdap" && r.Method == http.MethodGet {
		s.jobBaselineHostRDAP(w, r, id, parts[3])
		return
	}
	if len(parts) == 4 && parts[1] == "scans" && parts[3] == "changes" && r.Method == http.MethodGet {
		s.jobScanChanges(w, r, id, parts[2])
		return
	}
	if len(parts) == 2 && parts[1] == "incidents" && r.Method == http.MethodGet {
		s.jobIncidents(w, r, id)
		return
	}
	if len(parts) == 3 && parts[1] == "incidents" && parts[2] == "accept" && r.Method == http.MethodPost {
		s.acceptIncident(w, r, session, id)
		return
	}
	if len(parts) == 3 && parts[1] == "incidents" && parts[2] == "suppress" && r.Method == http.MethodPost {
		s.suppressIncident(w, r, session, id)
		return
	}
	if len(parts) == 2 && parts[1] == "events" && r.Method == http.MethodGet {
		s.jobEvents(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "baseline" && r.Method == http.MethodGet {
		s.jobBaseline(w, r, id)
		return
	}
	if len(parts) == 3 && parts[1] == "baseline" && parts[2] == "reset" && r.Method == http.MethodPost {
		s.resetBaseline(w, r, session, id)
		return
	}
	if len(parts) == 3 && parts[1] == "baseline" && parts[2] == "approve" && r.Method == http.MethodPost {
		s.approveBaseline(w, r, session, id)
		return
	}
	writeError(w, 404, "not_found", "job endpoint not found", nil)
}
