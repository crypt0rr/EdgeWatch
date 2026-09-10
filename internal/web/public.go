package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/rdap"
	"github.com/crypt0rr/edgewatch/internal/store"
)

const (
	// Public dashboards are deliberately cached only in memory. The cache is
	// short-lived so an administrator's publication changes become visible
	// quickly, while repeated anonymous requests cannot repeatedly walk legacy
	// scan history.
	publicDashboardCacheTTL     = 5 * time.Second
	publicDashboardBuildTimeout = 5 * time.Second
)

type publicDashboardCache struct {
	key       string
	expiresAt time.Time
	payload   []byte
}

// publicAPI is intentionally separate from /api/v1. It has no session
// middleware and exposes one fixed, sanitized projection without resource
// selectors that could be used to enumerate jobs or hosts.
func (s *Server) publicAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || strings.TrimSuffix(r.URL.Path, "/") != "/api/public/v1/dashboard" {
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found", nil)
		return
	}
	if !s.allowPublicRequest(r) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "public status requests are temporarily rate limited", nil)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	ctx, cancel := context.WithTimeout(r.Context(), publicDashboardBuildTimeout)
	defer cancel()
	dashboard, err := s.Store.GetPublicDashboard(ctx)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "public_disabled", "public status is not enabled", nil)
		return
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusGatewayTimeout, "public_dashboard_timeout", "public status took too long to load", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "public_dashboard", "public status could not be loaded", nil)
		return
	}
	if !dashboard.Enabled {
		writeError(w, http.StatusNotFound, "public_disabled", "public status is not enabled", nil)
		return
	}
	payload, err := s.cachedPublicDashboardPayload(ctx, dashboard)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusGatewayTimeout, "public_dashboard_timeout", "public status took too long to load", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "public_dashboard", "public status could not be loaded", nil)
		return
	}
	writeJSON(w, http.StatusOK, json.RawMessage(payload))
}

func publicDashboardCacheKey(dashboard store.PublicDashboard) string {
	raw, err := json.Marshal(dashboard)
	if err != nil {
		return ""
	}
	return string(raw)
}

func (s *Server) cachedPublicDashboardPayload(ctx context.Context, dashboard store.PublicDashboard) ([]byte, error) {
	key := publicDashboardCacheKey(dashboard)
	now := time.Now().UTC()
	s.publicCacheMu.Lock()
	if cached := s.publicCache; cached != nil && cached.key == key && now.Before(cached.expiresAt) {
		payload := append([]byte(nil), cached.payload...)
		s.publicCacheMu.Unlock()
		return payload, nil
	}
	s.publicCacheMu.Unlock()

	response, err := s.publicDashboardResponse(ctx, dashboard)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	s.publicCacheMu.Lock()
	s.publicCache = &publicDashboardCache{key: key, expiresAt: time.Now().UTC().Add(publicDashboardCacheTTL), payload: append([]byte(nil), payload...)}
	s.publicCacheMu.Unlock()
	return payload, nil
}

func (s *Server) invalidatePublicDashboardCache() {
	s.publicCacheMu.Lock()
	s.publicCache = nil
	s.publicCacheMu.Unlock()
}

func (s *Server) allowPublicRequest(r *http.Request) bool {
	key := s.clientIP(r)
	now := time.Now().UTC()
	cutoff := now.Add(-time.Minute)
	s.publicMu.Lock()
	defer s.publicMu.Unlock()
	if s.publicHits == nil {
		s.publicHits = map[string][]time.Time{}
	}
	hits := s.publicHits[key][:0]
	for _, hit := range s.publicHits[key] {
		if hit.After(cutoff) {
			hits = append(hits, hit)
		}
	}
	if len(hits) >= 120 {
		s.publicHits[key] = hits
		return false
	}
	s.publicHits[key] = append(hits, now)
	if len(s.publicHits) > 4096 {
		for candidate, values := range s.publicHits {
			if len(values) == 0 || !values[len(values)-1].After(cutoff) {
				delete(s.publicHits, candidate)
			}
		}
	}
	return true
}

type publicDashboardPayload struct {
	Enabled      bool                         `json:"enabled"`
	Title        string                       `json:"title"`
	Introduction string                       `json:"introduction"`
	Hosts        []publicDashboardHostPayload `json:"hosts"`
}

// publicDashboardHostPayload contains only the writable host selection. The
// GET response includes created_at as read-only metadata, so accept that
// field when a client round-trips a response but never require it (or decode
// it as time.Time). Older console builds sent an empty created_at string,
// which strict JSON decoding correctly rejected as an invalid timestamp.
type publicDashboardHostPayload struct {
	JobID     string  `json:"job_id"`
	Address   string  `json:"address"`
	CreatedAt *string `json:"created_at,omitempty"`
}

func (s *Server) publicDashboardRoute(w http.ResponseWriter, r *http.Request, session store.Session) {
	dashboard, err := s.Store.GetPublicDashboard(r.Context())
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "store", "public dashboard could not be loaded", nil)
		return
	}
	if r.Method == http.MethodGet {
		if errors.Is(err, store.ErrNotFound) {
			dashboard = store.PublicDashboard{Title: "EdgeWatch public status", Hosts: []store.PublicDashboardHost{}}
		}
		writeJSON(w, http.StatusOK, dashboard)
		return
	}
	var input publicDashboardPayload
	if !decodeJSON(w, r, &input) {
		return
	}
	input.Title = strings.TrimSpace(input.Title)
	input.Introduction = strings.TrimSpace(input.Introduction)
	if input.Title == "" {
		input.Title = "EdgeWatch public status"
	}
	if len(input.Title) > 120 || len(input.Introduction) > 500 || strings.ContainsAny(input.Title+input.Introduction, "\r\n") {
		writeError(w, http.StatusBadRequest, "validation_failed", "public dashboard text is invalid or too long", map[string]string{"title": "use at most 120 characters", "introduction": "use at most 500 characters and no line breaks"})
		return
	}
	if len(input.Hosts) > 1000 {
		writeError(w, http.StatusBadRequest, "validation_failed", "at most 1000 hosts may be published", nil)
		return
	}
	selections := make([]store.PublicDashboardHost, 0, len(input.Hosts))
	for _, selection := range input.Hosts {
		if strings.TrimSpace(selection.JobID) == "" || net.ParseIP(strings.TrimSpace(selection.Address)) == nil {
			writeError(w, http.StatusBadRequest, "validation_failed", fmt.Sprintf("host %s is not present in a successful scan for this job", selection.Address), map[string]string{"hosts": "each published host must belong to a successful scan"})
			return
		}
		selections = append(selections, store.PublicDashboardHost{JobID: strings.TrimSpace(selection.JobID), Address: canonicalHostAddress(selection.Address)})
	}
	// Validate against retained history even when a job is archived. Archived
	// selections remain visible in the admin picker so they can be removed (or
	// become publishable again if the job is restored), while the public
	// response below deliberately omits them.
	published, err := s.loadPublishedHosts(r.Context(), selections, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", "published hosts could not be checked", nil)
		return
	}
	hosts := make([]store.PublicDashboardHost, 0, len(selections))
	for _, selection := range selections {
		key := publicSelectionKey(selection.JobID, selection.Address)
		if _, ok := published[key]; !ok {
			writeError(w, http.StatusBadRequest, "validation_failed", fmt.Sprintf("host %s is not present in a successful scan for this job", selection.Address), map[string]string{"hosts": "each published host must belong to a successful scan"})
			return
		}
		hosts = append(hosts, selection)
	}
	dashboard.Enabled, dashboard.Title, dashboard.Introduction = input.Enabled, input.Title, input.Introduction
	if err := s.Store.SavePublicDashboard(r.Context(), dashboard, hosts, store.AuditEntry{Action: "public_dashboard.updated", Detail: fmt.Sprintf("dashboard updated by %s; enabled=%t; hosts=%d", session.Username, input.Enabled, len(hosts)), ActorUserID: session.UserID, ActorUsername: session.Username}); err != nil {
		if s.writeAuditUnavailable(w, err, "public_dashboard.updated") {
			return
		}
		writeError(w, http.StatusBadRequest, "save_failed", err.Error(), nil)
		return
	}
	s.invalidatePublicDashboardCache()
	result, err := s.Store.GetPublicDashboard(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", "public dashboard could not be loaded after saving", nil)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) latestPublishedHost(ctx context.Context, jobID, address string) (store.ScanHost, error) {
	lookup, err := s.loadPublishedHosts(ctx, []store.PublicDashboardHost{{JobID: jobID, Address: address}}, false)
	if err != nil {
		return store.ScanHost{}, err
	}
	if item, ok := lookup[publicSelectionKey(jobID, canonicalHostAddress(address))]; ok {
		return item.Host, nil
	}
	return store.ScanHost{}, store.ErrNotFound
}

type publicHostLookup struct {
	Job     store.JobRecord
	Host    store.ScanHost
	Summary model.ScanSummary
}

func publicSelectionKey(jobID, address string) string {
	return strings.TrimSpace(jobID) + "\x00" + canonicalHostAddress(address)
}

// loadPublishedHosts resolves all selected addresses through bounded set-based
// reads. Indexed observations are loaded in one query; only selections absent
// from that projection use the bounded legacy fallback.
func (s *Server) loadPublishedHosts(ctx context.Context, selections []store.PublicDashboardHost, includeArchived bool) (map[string]publicHostLookup, error) {
	lookup := map[string]publicHostLookup{}
	if len(selections) == 0 {
		return lookup, nil
	}
	jobs, err := s.Store.ListJobs(ctx, true)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]store.JobRecord, len(jobs))
	for _, job := range jobs {
		byID[job.ID] = job
	}
	normalized := make([]store.PublicDashboardHost, 0, len(selections))
	seen := make(map[string]struct{}, len(selections))
	for _, selection := range selections {
		selection.JobID = strings.TrimSpace(selection.JobID)
		selection.Address = canonicalHostAddress(selection.Address)
		key := publicSelectionKey(selection.JobID, selection.Address)
		if selection.JobID == "" || net.ParseIP(selection.Address) == nil {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, selection)
	}
	indexed, err := s.Store.GetLatestSuccessfulJobHosts(ctx, normalized)
	if err != nil {
		return nil, err
	}
	for _, item := range indexed {
		job, ok := byID[item.Selection.JobID]
		if !ok || (!includeArchived && job.Archived) {
			continue
		}
		lookup[publicSelectionKey(item.Selection.JobID, item.Selection.Address)] = publicHostLookup{Job: job, Host: item.Host, Summary: item.Summary}
	}
	missing := make([]store.PublicDashboardHost, 0)
	for _, selection := range normalized {
		if _, ok := lookup[publicSelectionKey(selection.JobID, selection.Address)]; ok {
			continue
		}
		job, ok := byID[selection.JobID]
		if ok && (includeArchived || !job.Archived) {
			missing = append(missing, selection)
		}
	}
	legacy, err := s.latestLegacyPublicHosts(ctx, missing)
	if err != nil {
		return nil, err
	}
	for _, item := range legacy {
		job, ok := byID[item.Selection.JobID]
		if !ok || (!includeArchived && job.Archived) {
			continue
		}
		lookup[publicSelectionKey(item.Selection.JobID, item.Selection.Address)] = publicHostLookup{Job: job, Host: item.Host, Summary: item.Summary}
	}
	return lookup, nil
}

type publicDashboardResponse struct {
	Title        string               `json:"title"`
	Introduction string               `json:"introduction,omitempty"`
	UpdatedAt    interface{}          `json:"updated_at"`
	Hosts        []publicHostResponse `json:"hosts"`
}

type publicHostResponse struct {
	Job            string               `json:"job"`
	Address        string               `json:"address"`
	AddressFamily  string               `json:"address_family,omitempty"`
	Public         bool                 `json:"public"`
	Private        bool                 `json:"private"`
	LastSuccessful interface{}          `json:"last_successful_scan,omitempty"`
	OpenPorts      []publicPortResponse `json:"open_ports,omitempty"`
	OpenFiltered   []publicPortResponse `json:"open_filtered_ports,omitempty"`
	Rdap           *publicRdapResponse  `json:"rdap,omitempty"`
}

type publicPortResponse struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Service  string `json:"service,omitempty"`
}

type publicRdapResponse struct {
	Status       string      `json:"status"`
	NetworkName  string      `json:"network_name,omitempty"`
	Country      string      `json:"country,omitempty"`
	Registry     string      `json:"registry,omitempty"`
	Organization []string    `json:"organizations,omitempty"`
	Prefix       string      `json:"prefix,omitempty"`
	SourceURL    string      `json:"source_url,omitempty"`
	FetchedAt    interface{} `json:"fetched_at,omitempty"`
	Stale        bool        `json:"stale,omitempty"`
	Message      string      `json:"message,omitempty"`
}

func (s *Server) publicDashboardResponse(ctx context.Context, dashboard store.PublicDashboard) (publicDashboardResponse, error) {
	response := publicDashboardResponse{Title: dashboard.Title, Introduction: dashboard.Introduction, UpdatedAt: dashboard.UpdatedAt, Hosts: []publicHostResponse{}}
	lookup, err := s.loadPublishedHosts(ctx, dashboard.Hosts, false)
	if err != nil {
		return response, err
	}
	for _, selection := range dashboard.Hosts {
		item, ok := lookup[publicSelectionKey(selection.JobID, selection.Address)]
		if !ok {
			continue
		}
		response.Hosts = append(response.Hosts, s.publicHostFromObservation(ctx, item.Job.Job.Name, item.Host.Host, item.Summary))
	}
	return response, nil
}

func (s *Server) latestLegacyPublicHost(ctx context.Context, jobID, address string) (store.ScanHost, model.ScanSummary, error) {
	results, err := s.latestLegacyPublicHosts(ctx, []store.PublicDashboardHost{{JobID: jobID, Address: address}})
	if err != nil {
		return store.ScanHost{}, model.ScanSummary{}, err
	}
	if item, ok := results[publicSelectionKey(jobID, address)]; ok {
		return item.Host, item.Summary, nil
	}
	return store.ScanHost{}, model.ScanSummary{}, store.ErrNotFound
}

const legacyPublicScanLimit = 1000

func (s *Server) latestLegacyPublicHosts(ctx context.Context, selections []store.PublicDashboardHost) (map[string]store.PublicDashboardHostResult, error) {
	wanted := make(map[string]store.PublicDashboardHost, len(selections))
	jobIDs := make([]string, 0, len(selections))
	seenJobs := map[string]struct{}{}
	for _, selection := range selections {
		selection.JobID = strings.TrimSpace(selection.JobID)
		selection.Address = canonicalHostAddress(selection.Address)
		if selection.JobID == "" || net.ParseIP(selection.Address) == nil {
			continue
		}
		key := publicSelectionKey(selection.JobID, selection.Address)
		wanted[key] = selection
		if _, ok := seenJobs[selection.JobID]; !ok {
			seenJobs[selection.JobID] = struct{}{}
			jobIDs = append(jobIDs, selection.JobID)
		}
	}
	results := make(map[string]store.PublicDashboardHostResult, len(wanted))
	if len(wanted) == 0 {
		return results, nil
	}
	// Query each job independently. A single LIMIT across all jobs lets a
	// high-volume job consume the entire window and starve a low-volume job's
	// published host.
	for _, requestedJobID := range jobIDs {
		rows, err := s.Store.DB.QueryContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json
FROM scans WHERE status='success' AND job_id=?
ORDER BY finished_at DESC,id DESC LIMIT ?`, requestedJobID, legacyPublicScanLimit)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id, job string
			var jobID sql.NullString
			var revision sql.NullInt64
			var started, finished, status, scanError, nmapVersion, configHash string
			var raw []byte
			if err := rows.Scan(&id, &jobID, &revision, &job, &started, &finished, &status, &scanError, &nmapVersion, &configHash, &raw); err != nil {
				_ = rows.Close()
				return nil, err
			}
			if !jobID.Valid || len(raw) > 8<<20 {
				continue
			}
			page, err := observationsForSnapshotBytes(raw)
			if err != nil {
				_ = rows.Close()
				return nil, err
			}
			for _, host := range page.Items {
				key := publicSelectionKey(jobID.String, host.Address)
				selection, ok := wanted[key]
				if !ok {
					continue
				}
				if _, already := results[key]; already {
					continue
				}
				summary := model.ScanSummary{ID: id, JobID: jobID.String, Job: job, Status: status, Error: scanError, NmapVersion: nmapVersion, ConfigHash: configHash, StartedAt: parsePublicTime(started), FinishedAt: parsePublicTime(finished)}
				if revision.Valid {
					summary.JobRevision = revision.Int64
				}
				results[key] = store.PublicDashboardHostResult{Selection: selection, Host: store.ScanHost{ScanID: id, DataQuality: page.DataQuality, Host: host}, Summary: summary}
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
		if len(results) == len(wanted) {
			break
		}
	}
	return results, nil
}

func observationsForSnapshotBytes(raw []byte) (hostPage, error) {
	var snapshot model.Snapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return hostPage{}, err
	}
	return observationsForSnapshot(snapshot)
}

func parsePublicTime(raw string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05"} {
		if value, err := time.ParseInLocation(layout, strings.TrimSpace(raw), time.UTC); err == nil {
			return value
		}
	}
	return time.Time{}
}

func (s *Server) publicHostFromObservation(ctx context.Context, job string, host model.HostObservation, scan model.ScanSummary) publicHostResponse {
	address := canonicalHostAddress(host.Address)
	ip := net.ParseIP(address)
	result := publicHostResponse{Job: job, Address: address, AddressFamily: host.AddressFamily, LastSuccessful: scan.FinishedAt}
	if ip != nil {
		result.Private = isPrivateAddress(ip)
		result.Public = !result.Private
	}
	for _, protocol := range host.Protocols {
		for _, port := range protocol.Ports {
			entry := publicPortResponse{Protocol: protocol.Protocol, Port: port.Port}
			if port.Service != nil {
				entry.Service = port.Service.Name
			}
			switch port.State {
			case "open":
				result.OpenPorts = append(result.OpenPorts, entry)
			case "open|filtered":
				result.OpenFiltered = append(result.OpenFiltered, entry)
			}
		}
	}
	// RDAP is deliberately cache-only for guests. Opening the public page must
	// not turn an unauthenticated request into an outbound registry proxy.
	if result.Public && s.App != nil && s.App.Config != nil && s.App.Config.RDAPEnabled() {
		if cached, err := s.Store.GetRDAPCache(ctx, address); err == nil {
			if payload, decodeErr := decodeCachedPublicRDAP(cached.Payload); decodeErr == nil {
				now := time.Now().UTC()
				if s.now != nil {
					now = s.now().UTC()
				}
				// Guests may receive a stale cache entry only during the
				// bounded seven-day fallback window. Once stale_until passes,
				// omit registration data rather than publishing indefinitely old
				// ownership information.
				if cached.StaleUntil.IsZero() || !now.Before(cached.StaleUntil) {
					return result
				}
				if !now.Before(cached.ExpiresAt) {
					payload.Status, payload.Stale = "stale", true
				} else if payload.Status == "" {
					payload.Status = "cached"
				}
				result.Rdap = payload
			}
		}
	}
	return result
}

func isPrivateAddress(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	private := []*net.IPNet{}
	for _, raw := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"} {
		if _, network, err := net.ParseCIDR(raw); err == nil {
			private = append(private, network)
		}
	}
	for _, network := range private {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func publicRdapFromResult(result rdap.Result) *publicRdapResponse {
	return &publicRdapResponse{Status: result.Status, NetworkName: result.NetworkName, Country: result.Country, Registry: result.Registry, Organization: append([]string(nil), result.Organizations...), Prefix: result.Prefix, SourceURL: result.SourceURL, FetchedAt: result.FetchedAt, Stale: result.Stale, Message: result.Message}
}

func decodeCachedPublicRDAP(raw []byte) (*publicRdapResponse, error) {
	var result rdap.Result
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return publicRdapFromResult(result), nil
}
