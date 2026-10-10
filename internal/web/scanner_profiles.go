package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type scannerProfilePayload struct {
	Name               string                         `json:"name"`
	Description        string                         `json:"description,omitempty"`
	Engine             string                         `json:"engine"`
	Naabu              config.NaabuOptions            `json:"naabu"`
	NaabuArgs          []string                       `json:"naabu_args,omitempty"`
	NmapArgs           []string                       `json:"nmap_args,omitempty"`
	EnrichmentArgs     []string                       `json:"enrichment_args,omitempty"`
	NSEProfile         string                         `json:"nse_profile,omitempty"`
	NSEArgs            map[string]string              `json:"nse_args,omitempty"`
	OperatorAdjustable []string                       `json:"operator_adjustable,omitempty"`
	OperatorBounds     map[string]config.NumericBound `json:"operator_bounds,omitempty"`
	Password           string                         `json:"password,omitempty"`
	Revision           int64                          `json:"revision,omitempty"`
}

// applySelectedScannerProfile resolves a profile at write time and pins its
// revision into the job definition. Operators may select a profile but cannot
// smuggle a second command surface through the job payload; all argv and NSE
// settings come from the validated administrator-owned definition. Historical
// revisions are readable for audit and may be selected only through an
// administrator-controlled rollback; operator writes must use the profile's
// current active revision.
//
// The profile is resolved through the request's tenant store: every tenant
// may select a built-in profile, but another tenant's custom profile is not
// found, with the same error as an unknown ID.
//
// Selection problems are returned as store.ValidationError values. Storage
// failures are returned unchanged so the caller reports them as internal
// errors instead of echoing SQLite text as a validation message.
func (s *Server) applySelectedScannerProfile(ctx context.Context, ts *store.TenantStore, job *config.Job, allowArchived, allowHistorical bool) error {
	if job == nil || job.TCP == nil || strings.TrimSpace(job.TCP.ProfileID) == "" {
		return nil
	}
	profile, err := ts.GetScannerProfile(ctx, job.TCP.ProfileID)
	if errors.Is(err, store.ErrNotFound) {
		return store.ErrScannerProfileNotFound
	}
	if err != nil {
		return err
	}
	requestedRevision := job.TCP.ProfileRevision
	if requestedRevision == 0 {
		requestedRevision = profile.Revision
	}
	if requestedRevision < 1 {
		return store.ErrConflict
	}
	if requestedRevision != profile.Revision && !allowHistorical {
		return store.ErrConflict
	}
	definition := profile.Definition
	if requestedRevision != profile.Revision {
		historical, revisionErr := ts.GetScannerProfileRevision(ctx, profile.ID, requestedRevision)
		if errors.Is(revisionErr, store.ErrNotFound) {
			return store.ErrConflict
		}
		if revisionErr != nil {
			return revisionErr
		}
		definition = historical.Definition
	}
	if profile.Archived && !allowArchived {
		return invalidProfileSelection("profile", "selected scanner profile is archived")
	}
	if definition.Engine != config.EngineNmap && definition.Engine != config.EngineNaabuNmap {
		return invalidProfileSelection("profile", "selected scanner profile has an invalid engine")
	}
	job.TCP.Engine = definition.Engine
	job.TCP.ProfileRevision = requestedRevision
	job.TCP.NaabuArgs = cloneStrings(definition.NaabuArgs)
	job.TCP.NmapArgs = cloneStrings(definition.NmapArgs)
	job.TCP.EnrichmentArgs = cloneStrings(definition.EnrichmentArgs)
	job.TCP.NSEProfile = definition.NSEProfile
	job.TCP.NSEArgs = cloneStringMap(definition.NSEArgs)
	if definition.Engine == config.EngineNaabuNmap {
		hasRequested := job.TCP.Naabu != nil
		requested := config.NaabuOptions{}
		if hasRequested {
			requested = *job.TCP.Naabu
		}
		options := definition.Naabu
		config.ApplyNaabuDefaultsForScanner(&options)
		// Operators may tune only fields explicitly marked adjustable by the
		// profile and only inside the administrator-defined inclusive bounds.
		// Administrators receive the same bounded behavior; profile defaults
		// remain authoritative for every other field.
		for _, field := range definition.OperatorAdjustable {
			if !hasRequested {
				break
			}
			switch field {
			case "scan_type":
				if requested.ScanType != "" {
					if requested.ScanType != "connect" && requested.ScanType != "syn" {
						return invalidProfileSelection("scan_type", "naabu scan_type must be connect or syn")
					}
					options.ScanType = requested.ScanType
				}
				continue
			case "verify":
				if requested.VerifySet {
					options.Verify = requested.Verify
					options.VerifySet = true
				}
				continue
			}
			bound, ok := definition.OperatorBounds[field]
			if !ok {
				continue
			}
			if !naabuOptionSet(requested, field) {
				continue
			}
			value := naabuOptionValue(requested, field)
			if value < bound.Min || value > bound.Max {
				return invalidProfileSelection(field, fmt.Sprintf("naabu %s must be between %d and %d", field, bound.Min, bound.Max))
			}
			setNaabuOptionValue(&options, field, value)
		}
		job.TCP.Naabu = &options
		// Naabu owns discovery scope; leave the field present for API
		// compatibility but make the fixed range explicit in the revision.
		job.TCP.Ports = "1-65535"
	} else {
		// Naabu controls all of its own execution fields. Clear a stale Naabu
		// block when switching a job back to Nmap so an old profile selection
		// cannot leak into hashes, JSON, or a later profile change.
		job.TCP.Naabu = nil
	}
	return nil
}

func invalidProfileSelection(field, message string) error {
	return store.NewValidationError(config.NewFieldValidationError(field, errors.New(message)))
}

func naabuOptionValue(options config.NaabuOptions, field string) int {
	switch field {
	case "rate":
		return options.Rate
	case "workers":
		return options.Workers
	case "retries":
		return options.Retries
	case "timeout_ms":
		return options.TimeoutMS
	case "warm_up_seconds":
		return options.WarmUpSeconds
	case "address_batch_size":
		return options.AddressBatchSize
	default:
		return 0
	}
}

func naabuOptionSet(options config.NaabuOptions, field string) bool {
	switch field {
	case "rate":
		return options.RateSet || options.Rate != 0
	case "workers":
		return options.WorkersSet || options.Workers != 0
	case "retries":
		return options.RetriesSet || options.Retries != 0
	case "timeout_ms":
		return options.TimeoutMSSet || options.TimeoutMS != 0
	case "warm_up_seconds":
		return options.WarmUpSecondsSet || options.WarmUpSeconds != 0
	case "address_batch_size":
		return options.AddressBatchSizeSet || options.AddressBatchSize != 0
	default:
		return false
	}
}

func setNaabuOptionValue(options *config.NaabuOptions, field string, value int) {
	if options == nil {
		return
	}
	switch field {
	case "rate":
		options.Rate = value
	case "workers":
		options.Workers = value
	case "retries":
		options.Retries = value
	case "timeout_ms":
		options.TimeoutMS = value
	case "warm_up_seconds":
		options.WarmUpSeconds = value
	case "address_batch_size":
		options.AddressBatchSize = value
	}
}

func (p scannerProfilePayload) definition() config.ScannerProfile {
	return config.ScannerProfile{Engine: strings.TrimSpace(p.Engine), Naabu: p.Naabu, NaabuArgs: cloneStrings(p.NaabuArgs), NmapArgs: cloneStrings(p.NmapArgs), EnrichmentArgs: cloneStrings(p.EnrichmentArgs), NSEProfile: strings.TrimSpace(p.NSEProfile), NSEArgs: cloneStringMap(p.NSEArgs), OperatorAdjustable: cloneStrings(p.OperatorAdjustable), OperatorBounds: p.OperatorBounds, Description: strings.TrimSpace(p.Description)}
}

func scannerProfileJSON(profile store.ScannerProfileRecord, includeDefinition bool) map[string]any {
	value := map[string]any{"id": profile.ID, "name": profile.Name, "description": profile.Description, "built_in": profile.BuiltIn, "archived": profile.Archived, "revision": profile.Revision, "created_by": profile.CreatedBy, "updated_by": profile.UpdatedBy, "created_at": profile.CreatedAt, "updated_at": profile.UpdatedAt}
	if includeDefinition {
		value["definition"] = profile.Definition
	}
	return value
}

func scannerProfileDefinitionJSON(profile config.ScannerProfile) map[string]any {
	return map[string]any{"engine": profile.Engine, "naabu": profile.Naabu, "naabu_args": profile.NaabuArgs, "nmap_args": profile.NmapArgs, "enrichment_args": profile.EnrichmentArgs, "nse_profile": profile.NSEProfile, "nse_args": profile.NSEArgs, "operator_adjustable": profile.OperatorAdjustable, "operator_bounds": profile.OperatorBounds, "description": profile.Description}
}

// scannerCapabilities reports the fixed scanners and scanner.max_job_hosts,
// the most addresses one job may scan, which the editor warns about. Both are
// the deployment's and name no unit's data.
func (s *Server) scannerCapabilities(w http.ResponseWriter, r *http.Request) {
	capabilities := map[string]any{"engines": []string{config.EngineNmap, config.EngineNaabuNmap}, "nmap": map[string]any{"path": "/usr/bin/nmap", "version": "unknown", "available": false}, "naabu": map[string]any{"path": "/usr/local/bin/naabu", "version": "unknown", "available": false, "syn_supported": false}, "max_job_hosts": config.DefaultMaxJobHosts}
	if s.App != nil && s.App.Config != nil {
		capabilities["max_job_hosts"] = s.App.Config.Scanner.MaxJobHostsValue()
	}
	if s.App != nil {
		if versioned, ok := s.App.Scanner.(interface{ Version(context.Context) string }); ok {
			version := versioned.Version(r.Context())
			capabilities["nmap"].(map[string]any)["version"] = version
			capabilities["nmap"].(map[string]any)["available"] = version != "unknown"
		}
		if versioned, ok := s.App.Scanner.(interface{ NaabuVersion(context.Context) string }); ok {
			version := versioned.NaabuVersion(r.Context())
			naabu := capabilities["naabu"].(map[string]any)
			naabu["version"] = version
			naabu["available"] = version != "unknown"
			if supported, ok := s.App.Scanner.(interface{ NaabuSYNSupported() bool }); ok {
				naabu["syn_supported"] = version != "unknown" && supported.NaabuSYNSupported()
			}
		}
	}
	writeJSON(w, http.StatusOK, capabilities)
}

// listScannerProfiles serves GET /scanner-profiles: the tenant's profiles,
// with the archived ones when include_archived=true, and the stored
// profiles that no longer validate.
func (s *Server) listScannerProfiles(w http.ResponseWriter, r *http.Request, ts *store.TenantStore) {
	result, err := ts.ListScannerProfilesReport(r.Context(), r.URL.Query().Get("include_archived") == "true")
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	items := make([]map[string]any, 0, len(result.Profiles))
	for _, profile := range result.Profiles {
		items = append(items, scannerProfileJSON(profile, true))
	}
	invalid := result.Invalid
	if invalid == nil {
		invalid = []store.InvalidScannerProfile{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": items, "invalid_profiles": invalid})
}

// validateScannerProfileDraft serves POST /scanner-profiles/validate: it
// checks the submitted definition with the rules of a definition being
// saved, and renders it.
func (s *Server) validateScannerProfileDraft(w http.ResponseWriter, r *http.Request) {
	var payload scannerProfilePayload
	if !decodeJSON(w, r, &payload) {
		return
	}
	if err := config.ValidateNewScannerProfile(payload.definition()); err != nil {
		writeValidationError(w, err)
		return
	}
	preview, err := config.RenderScannerProfilePreview(payload.definition())
	if err != nil {
		writeValidationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "preview": preview})
}

// renderScannerProfileDraft serves POST /scanner-profiles/preview: it
// renders the submitted definition, which also renders an existing
// revision.
func (s *Server) renderScannerProfileDraft(w http.ResponseWriter, r *http.Request) {
	var payload scannerProfilePayload
	if !decodeJSON(w, r, &payload) {
		return
	}
	preview, err := config.RenderScannerProfilePreview(payload.definition())
	if err != nil {
		writeValidationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "preview": preview})
}

func (s *Server) getScannerProfile(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, id string) {
	profile, err := ts.GetScannerProfile(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "scanner profile not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, scannerProfileJSON(profile, true))
}

func (s *Server) listScannerProfileRevisions(w http.ResponseWriter, r *http.Request, ts *store.TenantStore, id string) {
	revisions, err := ts.ListScannerProfileRevisions(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "scanner profile not found", nil)
		return
	}
	items := make([]map[string]any, 0, len(revisions))
	for _, revision := range revisions {
		items = append(items, map[string]any{"profile_id": revision.ProfileID, "revision": revision.Revision, "created_by": revision.CreatedBy, "created_at": revision.CreatedAt, "definition": scannerProfileDefinitionJSON(revision.Definition)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"revisions": items})
}

// validateScannerProfile serves POST /scanner-profiles/{id}/validate. It
// validates the submitted definition with the rules of a definition being
// saved and renders it, and never reads the profile.
func (s *Server) validateScannerProfile(w http.ResponseWriter, r *http.Request) {
	var payload scannerProfilePayload
	if !decodeJSON(w, r, &payload) {
		return
	}
	if err := config.ValidateNewScannerProfile(payload.definition()); err != nil {
		writeValidationError(w, err)
		return
	}
	preview, err := config.RenderScannerProfilePreview(payload.definition())
	if err != nil {
		writeValidationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "preview": preview})
}

// previewScannerProfile serves POST /scanner-profiles/{id}/preview. It
// renders the submitted definition and never reads the profile.
func (s *Server) previewScannerProfile(w http.ResponseWriter, r *http.Request) {
	var payload scannerProfilePayload
	if !decodeJSON(w, r, &payload) {
		return
	}
	preview, err := config.RenderScannerProfilePreview(payload.definition())
	if err != nil {
		writeValidationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"preview": preview})
}

func (s *Server) confirmProfilePassword(w http.ResponseWriter, r *http.Request, session store.Session, password string) bool {
	if !auth.HasPermission(session, auth.PermissionScannerProfilesManage) {
		writeError(w, http.StatusForbidden, "forbidden", "only an administrator can manage scanner profiles", map[string]string{"permission": auth.PermissionScannerProfilesManage})
		return false
	}
	if err := s.Auth.ConfirmPasswordForUser(r.Context(), r, session.UserID, password); err != nil {
		if errors.Is(err, auth.ErrRateLimited) {
			w.Header().Set("Retry-After", auth.RetryAfterHeaderValue(err))
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many password confirmations; try again later", nil)
		} else {
			writeError(w, http.StatusBadRequest, "invalid_password", "password confirmation failed", nil)
		}
		return false
	}
	return true
}

func (s *Server) createScannerProfile(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore) {
	var payload scannerProfilePayload
	if !decodeJSON(w, r, &payload) {
		return
	}
	if !s.confirmProfilePassword(w, r, session, payload.Password) {
		return
	}
	definition := payload.definition()
	profile, err := ts.CreateScannerProfile(r.Context(), payload.Name, payload.Description, definition, session.Username, actorAudit(session, "scanner_profile.created", strings.TrimSpace(payload.Name)))
	if err != nil {
		if s.writeAuditUnavailable(w, err, "scanner_profile.created") {
			return
		}
		if isUnique(err) || errors.Is(err, store.ErrScannerProfileNameInUse) {
			writeError(w, http.StatusConflict, "conflict", "scanner profile name is already in use", nil)
		} else {
			s.writeStoreWriteError(w, r, err, "scanner profile not found")
		}
		return
	}
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "scanner-profile.changed", "profile_id": profile.ID})
	writeJSON(w, http.StatusCreated, scannerProfileJSON(profile, true))
}

func (s *Server) updateScannerProfile(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, id string) {
	var payload scannerProfilePayload
	if !decodeJSON(w, r, &payload) {
		return
	}
	if payload.Revision < 1 {
		writeError(w, http.StatusBadRequest, "revision_required", "profile revision is required", nil)
		return
	}
	if !s.confirmProfilePassword(w, r, session, payload.Password) {
		return
	}
	profile, err := ts.UpdateScannerProfile(r.Context(), id, payload.Revision, payload.Name, payload.Description, payload.definition(), session.Username, actorAudit(session, "scanner_profile.updated", id))
	if s.writeAuditUnavailable(w, err, "scanner_profile.updated") {
		return
	}
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "conflict", "scanner profile was modified; reload before saving", nil)
		return
	}
	if err != nil {
		if isUnique(err) || errors.Is(err, store.ErrScannerProfileNameInUse) {
			writeError(w, http.StatusConflict, "conflict", "scanner profile name is already in use", nil)
		} else {
			s.writeStoreWriteError(w, r, err, "scanner profile not found")
		}
		return
	}
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "scanner-profile.changed", "profile_id": id})
	writeJSON(w, http.StatusOK, scannerProfileJSON(profile, true))
}

func (s *Server) setScannerProfileArchived(w http.ResponseWriter, r *http.Request, session store.Session, ts *store.TenantStore, id string, archived bool) {
	var payload struct {
		Password string `json:"password"`
		Revision int64  `json:"revision"`
	}
	if !decodeJSON(w, r, &payload) {
		return
	}
	if payload.Revision < 1 {
		writeError(w, http.StatusBadRequest, "revision_required", "profile revision is required", nil)
		return
	}
	if !s.confirmProfilePassword(w, r, session, payload.Password) {
		return
	}
	action := "scanner_profile.archived"
	if !archived {
		action = "scanner_profile.restored"
	}
	err := ts.SetScannerProfileArchived(r.Context(), id, archived, payload.Revision, session.Username, actorAudit(session, action, id))
	if s.writeAuditUnavailable(w, err, action) {
		return
	}
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "conflict", "scanner profile was modified; reload before changing its lifecycle", nil)
		return
	}
	if err != nil {
		s.writeStoreWriteError(w, r, err, "scanner profile not found")
		return
	}
	s.broadcastTo(context.WithoutCancel(r.Context()), audienceTenant(ts), map[string]any{"type": "scanner-profile.changed", "profile_id": id})
	writeJSON(w, http.StatusNoContent, nil)
}
