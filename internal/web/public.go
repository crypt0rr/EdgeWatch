package web

import (
	"context"
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

// publicAPI is intentionally separate from /api/v1. It has no session
// middleware and exposes one fixed, sanitized projection without resource
// selectors that could be used to enumerate jobs or hosts.
func (s *Server) publicAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || strings.TrimSuffix(r.URL.Path, "/") != "/api/public/v1/dashboard" {
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found", nil)
		return
	}
	if !s.allowPublicRequest(r) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "public status requests are temporarily rate limited", nil)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	dashboard, err := s.Store.GetPublicDashboard(r.Context())
	if errors.Is(err, store.ErrNotFound) || !dashboard.Enabled {
		writeError(w, http.StatusNotFound, "public_disabled", "public status is not enabled", nil)
		return
	}
	response, err := s.publicDashboardResponse(r.Context(), dashboard)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "public_dashboard", "public status could not be loaded", nil)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) allowPublicRequest(r *http.Request) bool {
	key := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		key = host
	}
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
	Enabled      bool                        `json:"enabled"`
	Title        string                      `json:"title"`
	Introduction string                      `json:"introduction"`
	Hosts        []store.PublicDashboardHost `json:"hosts"`
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
	for _, selection := range input.Hosts {
		if _, err := s.latestPublishedHost(r.Context(), selection.JobID, selection.Address); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusBadRequest, "validation_failed", fmt.Sprintf("host %s is not present in a successful scan for this job", selection.Address), map[string]string{"hosts": "each published host must belong to a successful scan"})
				return
			}
			writeError(w, http.StatusInternalServerError, "store", "published host could not be checked", nil)
			return
		}
	}
	dashboard.Enabled, dashboard.Title, dashboard.Introduction = input.Enabled, input.Title, input.Introduction
	if err := s.Store.SavePublicDashboard(r.Context(), dashboard, input.Hosts, store.AuditEntry{Action: "public_dashboard.updated", Detail: fmt.Sprintf("dashboard updated by %s; enabled=%t; hosts=%d", session.Username, input.Enabled, len(input.Hosts)), ActorUserID: session.UserID, ActorUsername: session.Username}); err != nil {
		if s.writeAuditUnavailable(w, err, "public_dashboard.updated") {
			return
		}
		writeError(w, http.StatusBadRequest, "save_failed", err.Error(), nil)
		return
	}
	result, _ := s.Store.GetPublicDashboard(r.Context())
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) latestPublishedHost(ctx context.Context, jobID, address string) (store.ScanHost, error) {
	if strings.TrimSpace(jobID) == "" {
		return store.ScanHost{}, store.ErrNotFound
	}
	job, err := s.Store.GetJob(ctx, jobID)
	if err != nil || job.Archived {
		return store.ScanHost{}, store.ErrNotFound
	}
	host, _, err := s.Store.GetLatestSuccessfulJobHost(ctx, jobID, address)
	if err == nil {
		return host, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.ScanHost{}, err
	}
	host, _, err = s.latestLegacyPublicHost(ctx, jobID, address)
	return host, err
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
	Available      bool                 `json:"available"`
	Stale          bool                 `json:"stale,omitempty"`
	LastSuccessful interface{}          `json:"last_successful_scan,omitempty"`
	OpenPorts      []publicPortResponse `json:"open_ports,omitempty"`
	OpenFiltered   []publicPortResponse `json:"open_filtered_ports,omitempty"`
	Rdap           *publicRdapResponse  `json:"rdap,omitempty"`
}

type publicPortResponse struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
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
	for _, selection := range dashboard.Hosts {
		job, err := s.Store.GetJob(ctx, selection.JobID)
		if errors.Is(err, store.ErrNotFound) || job.Archived {
			continue
		}
		if err != nil {
			return response, err
		}
		host, summary, err := s.Store.GetLatestSuccessfulJobHost(ctx, selection.JobID, selection.Address)
		if errors.Is(err, store.ErrNotFound) {
			// Legacy scans can predate scan_hosts. Keep their publication safe by
			// deriving only the selected address from the snapshot; no arbitrary
			// host lookup is exposed to the caller.
			host, summary, err = s.latestLegacyPublicHost(ctx, selection.JobID, selection.Address)
		}
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return response, err
		}
		response.Hosts = append(response.Hosts, s.publicHostFromObservation(ctx, job.Job.Name, host.Host, summary))
	}
	return response, nil
}

func (s *Server) latestLegacyPublicHost(ctx context.Context, jobID, address string) (store.ScanHost, model.ScanSummary, error) {
	wanted := canonicalHostAddress(address)
	for offset := 0; ; offset += 100 {
		page, err := s.Store.ListJobScansPage(ctx, jobID, 100, offset)
		if err != nil {
			return store.ScanHost{}, model.ScanSummary{}, err
		}
		for _, scan := range page.Items {
			if scan.Status != "success" {
				continue
			}
			hostPage, err := observationsForSnapshot(scan.Snapshot)
			if err != nil {
				return store.ScanHost{}, model.ScanSummary{}, err
			}
			for _, host := range hostPage.Items {
				if canonicalHostAddress(host.Address) == wanted {
					return store.ScanHost{ScanID: scan.ID, DataQuality: hostPage.DataQuality, Host: host}, model.ScanSummary{ID: scan.ID, JobID: scan.JobID, Job: scan.Job, JobRevision: scan.JobRevision, StartedAt: scan.StartedAt, FinishedAt: scan.FinishedAt, Status: scan.Status, NmapVersion: scan.NmapVersion, ConfigHash: scan.ConfigHash}, nil
				}
			}
		}
		if len(page.Items) == 0 || offset+len(page.Items) >= page.Total {
			break
		}
	}
	return store.ScanHost{}, model.ScanSummary{}, store.ErrNotFound
}

func (s *Server) publicHostFromObservation(ctx context.Context, job string, host model.HostObservation, scan model.ScanSummary) publicHostResponse {
	address := canonicalHostAddress(host.Address)
	ip := net.ParseIP(address)
	result := publicHostResponse{Job: job, Address: address, AddressFamily: host.AddressFamily, Available: true, LastSuccessful: scan.FinishedAt}
	if ip != nil {
		result.Private = isPrivateAddress(ip)
		result.Public = !result.Private
	}
	for _, protocol := range host.Protocols {
		for _, port := range protocol.Ports {
			entry := publicPortResponse{Protocol: protocol.Protocol, Port: port.Port}
			if port.Service != nil {
				entry.Service, entry.Product, entry.Version = port.Service.Name, port.Service.Product, port.Service.Version
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
				if !time.Now().UTC().Before(cached.ExpiresAt) {
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
