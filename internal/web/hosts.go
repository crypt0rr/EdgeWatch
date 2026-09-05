package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/rdap"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type hostSummary struct {
	Address           string                `json:"address"`
	AddressFamily     string                `json:"address_family,omitempty"`
	SourceTargets     []string              `json:"source_targets,omitempty"`
	DNSNames          []string              `json:"dns_names,omitempty"`
	Protocols         []hostProtocolSummary `json:"protocols,omitempty"`
	OpenPorts         int                   `json:"open_ports"`
	OpenFilteredPorts int                   `json:"open_filtered_ports"`
	HasOpenPorts      bool                  `json:"has_open_ports"`
	Legacy            bool                  `json:"legacy,omitempty"`
}

// allHostSummary is the latest successful scan result for one effective IP.
// The scan and job references make the existing historical host-detail route
// the canonical drill-down without duplicating detailed observations here.
type allHostSummary struct {
	hostSummary
	JobID       string    `json:"job_id,omitempty"`
	Job         string    `json:"job"`
	ScanID      string    `json:"scan_id"`
	ScannedAt   time.Time `json:"scanned_at"`
	DataQuality string    `json:"data_quality"`
}

type hostProtocolSummary struct {
	Protocol          string `json:"protocol"`
	ScanType          string `json:"scan_type,omitempty"`
	ScannedPorts      string `json:"scanned_ports"`
	ScannedPortCount  int    `json:"scanned_port_count"`
	ServiceDetection  bool   `json:"service_detection"`
	OpenPorts         int    `json:"open_ports"`
	OpenFilteredPorts int    `json:"open_filtered_ports"`
}

type hostPage struct {
	Items       []model.HostObservation
	DataQuality string
}

func summaryFromIndexedHost(item store.ScanHost) hostSummary {
	return summaryForHost(item.Host, item.DataQuality == "legacy")
}

func allSummaryFromIndexedHost(item store.LatestScanHost) allHostSummary {
	return allHostSummary{
		hostSummary: summaryFromIndexedHost(item.ScanHost),
		JobID:       item.JobID,
		Job:         item.Job,
		ScanID:      item.ScanID,
		ScannedAt:   item.ScannedAt,
		DataQuality: item.DataQuality,
	}
}

func parseHostPagination(r *http.Request) (int, int, error) {
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			return 0, 0, errors.New("limit must be between 1 and 100")
		}
		limit = value
	}
	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 {
			return 0, 0, errors.New("offset must be zero or greater")
		}
		offset = value
	}
	return limit, offset, nil
}

func normalizedHostAddress(raw string) (string, error) {
	decoded, err := url.PathUnescape(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(decoded)
	if ip == nil {
		return "", errors.New("address is not a valid IP")
	}
	return ip.String(), nil
}

func observationsForSnapshot(snapshot model.Snapshot) (hostPage, error) {
	if len(snapshot.Hosts) > 0 {
		result := append([]model.HostObservation(nil), snapshot.Hosts...)
		normalizeHostSlice(result)
		return hostPage{Items: result, DataQuality: "detailed"}, nil
	}
	return hostPage{Items: deriveLegacyHosts(snapshot), DataQuality: "legacy"}, nil
}

func deriveLegacyHosts(snapshot model.Snapshot) []model.HostObservation {
	byAddress := map[string]model.HostObservation{}
	scopes := map[string]model.Scope{}
	for _, scope := range snapshot.Scopes {
		scopes[scope.Target+"\x00"+scope.Protocol] = scope
	}
	for _, unit := range snapshot.Units {
		addresses := append([]string(nil), unit.Addresses...)
		if len(addresses) == 0 {
			addresses = []string{unit.Target}
		}
		scope := scopes[unit.Target+"\x00"+unit.Protocol]
		portByAddress := map[string][]model.PortState{}
		for _, port := range unit.Ports {
			if len(port.Evidence) == 0 {
				for _, address := range addresses {
					portByAddress[canonicalHostAddress(address)] = append(portByAddress[canonicalHostAddress(address)], port)
				}
				continue
			}
			for _, address := range port.Evidence {
				canonical := canonicalHostAddress(address)
				portByAddress[canonical] = append(portByAddress[canonical], port)
			}
		}
		for _, address := range addresses {
			address = canonicalHostAddress(address)
			if address == "" {
				continue
			}
			host := byAddress[address]
			host.Address = address
			host.AddressFamily = familyForAddress(address)
			host.Status = "up"
			host.SourceTargets = append(host.SourceTargets, unit.Target)
			if net.ParseIP(unit.Target) == nil {
				if _, _, err := net.ParseCIDR(unit.Target); err != nil {
					host.DNSNames = append(host.DNSNames, unit.Target)
				}
			}
			protocol := model.ProtocolObservation{Protocol: unit.Protocol, ScannedPorts: scope.Ports, ScannedPortCount: portCount(scope.Ports), ServiceDetection: scope.ServiceDetection}
			for _, port := range portByAddress[address] {
				protocol.Ports = append(protocol.Ports, model.PortObservation{Port: port.Port, State: port.State, Service: legacyService(port.Service)})
				addLegacySummary(&protocol, port.State)
			}
			mergeLegacyProtocol(&host, protocol)
			byAddress[address] = host
		}
	}
	result := make([]model.HostObservation, 0, len(byAddress))
	for _, host := range byAddress {
		dedupeHost(&host)
		result = append(result, host)
	}
	normalizeHostSlice(result)
	return result
}

func canonicalHostAddress(raw string) string {
	if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
		return ip.String()
	}
	return strings.TrimSpace(raw)
}

func familyForAddress(address string) string {
	ip := net.ParseIP(address)
	if ip != nil && ip.To4() != nil {
		return "IPv4"
	}
	if ip != nil {
		return "IPv6"
	}
	return ""
}

func portCount(raw string) int {
	ports, err := config.ParsePorts(raw)
	if err != nil {
		return 0
	}
	return len(ports)
}

func legacyService(fingerprint string) *model.ServiceObservation {
	if strings.TrimSpace(fingerprint) == "" {
		return nil
	}
	return &model.ServiceObservation{Product: fingerprint, Method: "legacy"}
}

func addLegacySummary(protocol *model.ProtocolObservation, state string) {
	for i := range protocol.StateSummaries {
		if protocol.StateSummaries[i].State == state {
			protocol.StateSummaries[i].Count++
			return
		}
	}
	protocol.StateSummaries = append(protocol.StateSummaries, model.StateSummary{State: state, Count: 1})
}

func mergeLegacyProtocol(host *model.HostObservation, addition model.ProtocolObservation) {
	for i := range host.Protocols {
		if host.Protocols[i].Protocol != addition.Protocol {
			continue
		}
		host.Protocols[i].Ports = append(host.Protocols[i].Ports, addition.Ports...)
		for _, incoming := range addition.StateSummaries {
			found := false
			for j := range host.Protocols[i].StateSummaries {
				if host.Protocols[i].StateSummaries[j].State == incoming.State {
					host.Protocols[i].StateSummaries[j].Count += incoming.Count
					found = true
					break
				}
			}
			if !found {
				host.Protocols[i].StateSummaries = append(host.Protocols[i].StateSummaries, incoming)
			}
		}
		if host.Protocols[i].ScannedPorts == "" {
			host.Protocols[i].ScannedPorts = addition.ScannedPorts
		}
		if host.Protocols[i].ScannedPortCount == 0 {
			host.Protocols[i].ScannedPortCount = addition.ScannedPortCount
		}
		host.Protocols[i].ServiceDetection = host.Protocols[i].ServiceDetection || addition.ServiceDetection
		return
	}
	host.Protocols = append(host.Protocols, addition)
}

func dedupeHost(host *model.HostObservation) {
	stringsUnique := func(values []string) []string {
		seen := map[string]bool{}
		result := make([]string, 0, len(values))
		for _, value := range values {
			if strings.TrimSpace(value) != "" && !seen[value] {
				seen[value] = true
				result = append(result, value)
			}
		}
		return result
	}
	host.SourceTargets = stringsUnique(host.SourceTargets)
	host.DNSNames = stringsUnique(host.DNSNames)
	for i := range host.Protocols {
		ports := map[int]model.PortObservation{}
		for _, port := range host.Protocols[i].Ports {
			previous, exists := ports[port.Port]
			if !exists {
				ports[port.Port] = port
				continue
			}
			// Legacy snapshots can contain one logical port per address. Keep
			// the strongest positive state and retain whichever evidence fields
			// are available instead of letting map iteration choose arbitrarily.
			if previous.State != "open" && port.State == "open" {
				previous.State = port.State
			}
			if previous.Reason == "" {
				previous.Reason, previous.ReasonTTL = port.Reason, port.ReasonTTL
			}
			if previous.Service == nil {
				previous.Service = port.Service
			}
			ports[port.Port] = previous
		}
		host.Protocols[i].Ports = host.Protocols[i].Ports[:0]
		for _, port := range ports {
			host.Protocols[i].Ports = append(host.Protocols[i].Ports, port)
		}
	}
	// The model normalizer gives all nested arrays deterministic order.
	holder := model.Snapshot{Hosts: []model.HostObservation{*host}}
	holder.Normalize()
	*host = holder.Hosts[0]
}

func normalizeHostSlice(hosts []model.HostObservation) {
	for i := range hosts {
		hosts[i].Address = canonicalHostAddress(hosts[i].Address)
		dedupeHost(&hosts[i])
	}
	snapshot := model.Snapshot{Hosts: hosts}
	snapshot.Normalize()
	copy(hosts, snapshot.Hosts)
}

func summaryForHost(host model.HostObservation, legacy bool) hostSummary {
	result := hostSummary{Address: host.Address, AddressFamily: host.AddressFamily, SourceTargets: append([]string(nil), host.SourceTargets...), DNSNames: append([]string(nil), host.DNSNames...), Legacy: legacy}
	for _, protocol := range host.Protocols {
		summary := hostProtocolSummary{Protocol: protocol.Protocol, ScanType: protocol.ScanType, ScannedPorts: protocol.ScannedPorts, ScannedPortCount: protocol.ScannedPortCount, ServiceDetection: protocol.ServiceDetection}
		for _, port := range protocol.Ports {
			switch port.State {
			case "open":
				summary.OpenPorts++
			case "open|filtered":
				summary.OpenFilteredPorts++
			}
		}
		result.OpenPorts += summary.OpenPorts
		result.OpenFilteredPorts += summary.OpenFilteredPorts
		result.Protocols = append(result.Protocols, summary)
	}
	result.HasOpenPorts = result.OpenPorts > 0 || result.OpenFilteredPorts > 0
	return result
}

func (s *Server) latestScannedHosts(ctx context.Context) ([]allHostSummary, error) {
	latest := make(map[string]allHostSummary)
	// Legacy snapshots have no host index. Keep this compatibility walk bounded
	// so an old database cannot defeat the indexed path with an unbounded scan.
	const pageSize = 100
	const maxLegacyScans = 100
	for offset := 0; offset < maxLegacyScans; offset += pageSize {
		page, err := s.Store.ListScansPage(ctx, "", pageSize, offset)
		if err != nil {
			return nil, err
		}
		for _, scan := range page.Items {
			// A failed or cancelled scan is not a historical result. Successful
			// scans are returned newest first by ListScansPage, so the first
			// observation for an address is its latest result.
			if scan.Status != "success" {
				continue
			}
			hostPage, err := observationsForSnapshot(scan.Snapshot)
			if err != nil {
				return nil, err
			}
			for _, host := range hostPage.Items {
				address := canonicalHostAddress(host.Address)
				if address == "" || net.ParseIP(address) == nil {
					continue
				}
				if _, exists := latest[address]; exists {
					continue
				}
				latest[address] = allHostSummary{
					hostSummary: summaryForHost(host, hostPage.DataQuality == "legacy"),
					JobID:       scan.JobID,
					Job:         scan.Job,
					ScanID:      scan.ID,
					ScannedAt:   scan.FinishedAt,
					DataQuality: hostPage.DataQuality,
				}
			}
		}
		if len(page.Items) == 0 || offset+len(page.Items) >= page.Total {
			break
		}
	}
	result := make([]allHostSummary, 0, len(latest))
	for _, host := range latest {
		result = append(result, host)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Address < result[j].Address
	})
	return result, nil
}

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := parseHostPagination(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_pagination", err.Error(), nil)
		return
	}
	hasOpen, err := parseHasOpen(r.URL.Query().Get("has_open_ports"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_filter", err.Error(), nil)
		return
	}
	protocol, err := parseHostProtocol(r.URL.Query().Get("protocol"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_filter", err.Error(), nil)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	indexed, err := s.Store.ListLatestScanHostsPage(r.Context(), query, protocol, hasOpen, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	indexedExists, err := s.Store.SuccessfulScanHostIndexExists(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	if indexedExists {
		items := make([]allHostSummary, 0, len(indexed.Items))
		for _, item := range indexed.Items {
			items = append(items, allSummaryFromIndexedHost(item))
		}
		writeJSON(w, http.StatusOK, map[string]any{"hosts": items, "pagination": paginationJSON(offset, limit, indexed.Total)})
		return
	}
	hosts, err := s.latestScannedHosts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	filtered := make([]allHostSummary, 0, len(hosts))
	for _, item := range hosts {
		host := model.HostObservation{Address: item.Address, SourceTargets: item.SourceTargets, DNSNames: item.DNSNames}
		if !hostMatches(host, item.hostSummary, "", protocol, hasOpen) {
			continue
		}
		matches := hostMatches(host, item.hostSummary, query, "", nil)
		if !matches && query != "" && strings.Contains(strings.ToLower(item.Job), strings.ToLower(query)) {
			matches = true
		}
		if !matches {
			continue
		}
		filtered = append(filtered, item)
	}
	total := len(filtered)
	if offset >= total {
		filtered = nil
	} else {
		end := offset + limit
		if end > total {
			end = total
		}
		filtered = filtered[offset:end]
	}
	if filtered == nil {
		filtered = []allHostSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": filtered, "pagination": paginationJSON(offset, limit, total)})
}

func hostMatches(host model.HostObservation, summary hostSummary, query, protocol string, hasOpen *bool) bool {
	if protocol != "" {
		found := false
		protocolHasOpen := false
		for _, item := range summary.Protocols {
			if strings.EqualFold(item.Protocol, protocol) {
				found = true
				protocolHasOpen = item.OpenPorts > 0 || item.OpenFilteredPorts > 0
				break
			}
		}
		if !found {
			return false
		}
		if hasOpen != nil && protocolHasOpen != *hasOpen {
			return false
		}
	} else if hasOpen != nil && summary.HasOpenPorts != *hasOpen {
		return false
	}
	if query == "" {
		return true
	}
	query = strings.ToLower(query)
	if strings.Contains(strings.ToLower(host.Address), query) {
		return true
	}
	for _, target := range host.SourceTargets {
		if strings.Contains(strings.ToLower(target), query) {
			return true
		}
	}
	for _, dnsName := range host.DNSNames {
		if strings.Contains(strings.ToLower(dnsName), query) {
			return true
		}
	}
	for _, name := range host.Hostnames {
		if strings.Contains(strings.ToLower(name.Name), query) {
			return true
		}
	}
	return false
}

func filterHosts(hosts []model.HostObservation, quality, query, protocol string, hasOpen *bool, offset, limit int) ([]hostSummary, int) {
	filtered := make([]model.HostObservation, 0, len(hosts))
	for _, host := range hosts {
		summary := summaryForHost(host, quality == "legacy")
		if hostMatches(host, summary, query, protocol, hasOpen) {
			filtered = append(filtered, host)
		}
	}
	normalizeHostSlice(filtered)
	total := len(filtered)
	if offset >= total {
		return []hostSummary{}, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	items := make([]hostSummary, 0, end-offset)
	for _, host := range filtered[offset:end] {
		items = append(items, summaryForHost(host, quality == "legacy"))
	}
	return items, total
}

func hostFromSnapshot(snapshot model.Snapshot, address string) (model.HostObservation, string, bool) {
	page, _ := observationsForSnapshot(snapshot)
	for _, host := range page.Items {
		if host.Address == address {
			return host, page.DataQuality, true
		}
	}
	return model.HostObservation{}, page.DataQuality, false
}

func parseHasOpen(raw string) (*bool, error) {
	if raw == "" {
		return nil, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, fmt.Errorf("has_open_ports must be true or false")
	}
	return &value, nil
}

func parseHostProtocol(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value != "" && value != "tcp" && value != "udp" {
		return "", errors.New("protocol must be tcp or udp")
	}
	return value, nil
}

func (s *Server) jobBaselineHosts(w http.ResponseWriter, r *http.Request, id string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	limit, offset, err := parseHostPagination(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_pagination", err.Error(), nil)
		return
	}
	hasOpen, err := parseHasOpen(r.URL.Query().Get("has_open_ports"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_filter", err.Error(), nil)
		return
	}
	protocol, err := parseHostProtocol(r.URL.Query().Get("protocol"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_filter", err.Error(), nil)
		return
	}
	query := r.URL.Query().Get("q")
	baselineScanID, _, metaErr := s.Store.RuntimeBaselineMeta(r.Context(), id)
	if metaErr != nil {
		writeError(w, http.StatusInternalServerError, "store", metaErr.Error(), nil)
		return
	}
	if baselineScanID != "" {
		indexed, indexErr := s.Store.ListScanHostsPage(r.Context(), baselineScanID, query, protocol, hasOpen, limit, offset)
		if indexErr != nil {
			writeError(w, http.StatusInternalServerError, "store", indexErr.Error(), nil)
			return
		}
		indexedExists, existsErr := s.Store.ScanHostIndexExists(r.Context(), baselineScanID)
		if existsErr != nil {
			writeError(w, http.StatusInternalServerError, "store", existsErr.Error(), nil)
			return
		}
		if indexedExists {
			items := make([]hostSummary, 0, len(indexed.Items))
			for _, item := range indexed.Items {
				items = append(items, summaryFromIndexedHost(item))
			}
			var source any
			if summary, summaryErr := s.Store.GetScanSummary(r.Context(), baselineScanID); summaryErr == nil {
				source = summary
			}
			writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": record.Job.Name, "source_scan": source, "data_quality": "detailed", "hosts": items, "pagination": paginationJSON(offset, limit, indexed.Total)})
			return
		}
	}
	state, err := s.Store.RuntimeState(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	quality := "none"
	var hosts []model.HostObservation
	var source any
	if state.Baseline != nil {
		page, pageErr := observationsForSnapshot(*state.Baseline)
		if pageErr != nil {
			writeError(w, http.StatusInternalServerError, "snapshot", pageErr.Error(), nil)
			return
		}
		hosts, quality = page.Items, page.DataQuality
		if state.BaselineScanID != "" {
			if summary, summaryErr := s.Store.GetScanSummary(r.Context(), state.BaselineScanID); summaryErr == nil {
				source = summary
			}
		}
	}
	items, total := filterHosts(hosts, quality, query, protocol, hasOpen, offset, limit)
	writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": record.Job.Name, "source_scan": source, "data_quality": quality, "hosts": items, "pagination": paginationJSON(offset, limit, total)})
}

func (s *Server) jobBaselineHost(w http.ResponseWriter, r *http.Request, id, rawAddress string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	address, err := normalizedHostAddress(rawAddress)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "host not found", nil)
		return
	}
	if baselineScanID, _, metaErr := s.Store.RuntimeBaselineMeta(r.Context(), id); metaErr == nil && baselineScanID != "" {
		if indexed, indexErr := s.Store.GetScanHost(r.Context(), baselineScanID, address); indexErr == nil {
			var source any
			if summary, summaryErr := s.Store.GetScanSummary(r.Context(), baselineScanID); summaryErr == nil {
				source = summary
			}
			writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": record.Job.Name, "data_quality": indexed.DataQuality, "host": indexed.Host, "expected": indexed.Host, "source_scan": source})
			return
		} else if !errors.Is(indexErr, store.ErrNotFound) {
			writeError(w, http.StatusInternalServerError, "store", indexErr.Error(), nil)
			return
		} else if indexedExists, existsErr := s.Store.ScanHostIndexExists(r.Context(), baselineScanID); existsErr != nil {
			writeError(w, http.StatusInternalServerError, "store", existsErr.Error(), nil)
			return
		} else if indexedExists {
			writeError(w, http.StatusNotFound, "not_found", "baseline host not found", nil)
			return
		}
	} else if metaErr != nil {
		writeError(w, http.StatusInternalServerError, "store", metaErr.Error(), nil)
		return
	}
	state, err := s.Store.RuntimeState(r.Context(), id)
	if err != nil || state.Baseline == nil {
		writeError(w, http.StatusNotFound, "not_found", "baseline host not found", nil)
		return
	}
	host, quality, ok := hostFromSnapshot(*state.Baseline, address)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "baseline host not found", nil)
		return
	}
	var source any
	if state.BaselineScanID != "" {
		if summary, summaryErr := s.Store.GetScanSummary(r.Context(), state.BaselineScanID); summaryErr == nil {
			source = summary
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": record.Job.Name, "data_quality": quality, "host": host, "expected": host, "source_scan": source})
}

func (s *Server) jobBaselineHostRDAP(w http.ResponseWriter, r *http.Request, id, rawAddress string) {
	address, err := normalizedHostAddress(rawAddress)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "host not found", nil)
		return
	}
	if baselineScanID, _, metaErr := s.Store.RuntimeBaselineMeta(r.Context(), id); metaErr == nil && baselineScanID != "" {
		if _, indexErr := s.Store.GetScanHost(r.Context(), baselineScanID, address); indexErr == nil {
			result := rdapUnavailable(address)
			if s.RDAP != nil {
				result, _ = s.RDAP.Lookup(r.Context(), address)
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, map[string]any{"rdap": result})
			return
		} else if !errors.Is(indexErr, store.ErrNotFound) {
			writeError(w, http.StatusInternalServerError, "store", indexErr.Error(), nil)
			return
		} else if indexedExists, existsErr := s.Store.ScanHostIndexExists(r.Context(), baselineScanID); existsErr != nil {
			writeError(w, http.StatusInternalServerError, "store", existsErr.Error(), nil)
			return
		} else if indexedExists {
			writeError(w, http.StatusNotFound, "not_found", "baseline host not found", nil)
			return
		}
	} else if metaErr != nil {
		writeError(w, http.StatusInternalServerError, "store", metaErr.Error(), nil)
		return
	}
	state, err := s.Store.RuntimeState(r.Context(), id)
	if err != nil || state.Baseline == nil {
		writeError(w, http.StatusNotFound, "not_found", "baseline host not found", nil)
		return
	}
	if _, _, ok := hostFromSnapshot(*state.Baseline, address); !ok {
		writeError(w, http.StatusNotFound, "not_found", "baseline host not found", nil)
		return
	}
	result := rdapUnavailable(address)
	if s.RDAP != nil {
		result, err = s.RDAP.Lookup(r.Context(), address)
	}
	// Registry status is intentionally independent from local host evidence.
	// Even a timeout or malformed upstream response gets a stable JSON result.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"rdap": result})
}

func rdapUnavailable(address string) rdap.Result {
	return rdap.Result{Status: "unavailable", Address: address, Message: "RDAP lookup is not available"}
}

func (s *Server) jobScanHosts(w http.ResponseWriter, r *http.Request, id, scanID string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	s.renderScanHosts(w, r, id, record.Job.Name, scanID)
}

func (s *Server) renderScanHosts(w http.ResponseWriter, r *http.Request, id, jobName, scanID string) {
	summary, err := s.Store.GetScanSummary(r.Context(), scanID)
	if err != nil || (id != "" && summary.JobID != id) {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	limit, offset, err := parseHostPagination(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_pagination", err.Error(), nil)
		return
	}
	hasOpen, err := parseHasOpen(r.URL.Query().Get("has_open_ports"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_filter", err.Error(), nil)
		return
	}
	protocol, err := parseHostProtocol(r.URL.Query().Get("protocol"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_filter", err.Error(), nil)
		return
	}
	indexed, indexErr := s.Store.ListScanHostsPage(r.Context(), scanID, r.URL.Query().Get("q"), protocol, hasOpen, limit, offset)
	if indexErr != nil {
		writeError(w, http.StatusInternalServerError, "store", indexErr.Error(), nil)
		return
	}
	indexedExists, existsErr := s.Store.ScanHostIndexExists(r.Context(), scanID)
	if existsErr != nil {
		writeError(w, http.StatusInternalServerError, "store", existsErr.Error(), nil)
		return
	}
	if indexedExists {
		items := make([]hostSummary, 0, len(indexed.Items))
		for _, item := range indexed.Items {
			items = append(items, summaryFromIndexedHost(item))
		}
		writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": jobName, "scan": summary, "data_quality": "detailed", "hosts": items, "pagination": paginationJSON(offset, limit, indexed.Total)})
		return
	}
	scan, err := s.Store.GetScan(r.Context(), scanID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	page, _ := observationsForSnapshot(scan.Snapshot)
	items, total := filterHosts(page.Items, page.DataQuality, r.URL.Query().Get("q"), protocol, hasOpen, offset, limit)
	writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": jobName, "scan": summary, "data_quality": page.DataQuality, "hosts": items, "pagination": paginationJSON(offset, limit, total)})
}

// scanHostsRoute is the additive top-level historical-results form. The job
// nested route remains available for callers that already scope every request
// by job ID; both paths enforce the same ownership check.
func (s *Server) scanHostsRoute(w http.ResponseWriter, r *http.Request, scanID string) {
	summary, err := s.Store.GetScanSummary(r.Context(), scanID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	if summary.JobID != "" {
		s.jobScanHosts(w, r, summary.JobID, scanID)
		return
	}
	s.renderScanHosts(w, r, "", summary.Job, scanID)
}

func (s *Server) jobScanHost(w http.ResponseWriter, r *http.Request, id, scanID, rawAddress string) {
	record, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	s.renderScanHost(w, r, id, record.Job.Name, scanID, rawAddress)
}

func (s *Server) renderScanHost(w http.ResponseWriter, r *http.Request, id, jobName, scanID, rawAddress string) {
	summary, err := s.Store.GetScanSummary(r.Context(), scanID)
	if err != nil || (id != "" && summary.JobID != id) {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	address, err := normalizedHostAddress(rawAddress)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "host not found", nil)
		return
	}
	if indexed, indexErr := s.Store.GetScanHost(r.Context(), scanID, address); indexErr == nil {
		var expected any
		if id != "" {
			if baselineID, _, metaErr := s.Store.RuntimeBaselineMeta(r.Context(), id); metaErr == nil && baselineID != "" {
				if baselineHost, baselineErr := s.Store.GetScanHost(r.Context(), baselineID, address); baselineErr == nil {
					expected = baselineHost.Host
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": jobName, "scan": summary, "data_quality": indexed.DataQuality, "host": indexed.Host, "expected": expected})
		return
	} else if !errors.Is(indexErr, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "store", indexErr.Error(), nil)
		return
	} else if indexedExists, existsErr := s.Store.ScanHostIndexExists(r.Context(), scanID); existsErr != nil {
		writeError(w, http.StatusInternalServerError, "store", existsErr.Error(), nil)
		return
	} else if indexedExists {
		writeError(w, http.StatusNotFound, "not_found", "scan host not found", nil)
		return
	}
	scan, err := s.Store.GetScan(r.Context(), scanID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	host, quality, ok := hostFromSnapshot(scan.Snapshot, address)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "scan host not found", nil)
		return
	}
	var expected any
	if state, stateErr := s.Store.RuntimeState(r.Context(), id); stateErr == nil && state.Baseline != nil {
		if baselineHost, _, found := hostFromSnapshot(*state.Baseline, address); found {
			expected = baselineHost
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": jobName, "scan": summary, "data_quality": quality, "host": host, "expected": expected})
}

func (s *Server) scanHostRoute(w http.ResponseWriter, r *http.Request, scanID, rawAddress string) {
	summary, err := s.Store.GetScanSummary(r.Context(), scanID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	if summary.JobID != "" {
		s.jobScanHost(w, r, summary.JobID, scanID, rawAddress)
		return
	}
	s.renderScanHost(w, r, "", summary.Job, scanID, rawAddress)
}

func (s *Server) jobScanHostRDAP(w http.ResponseWriter, r *http.Request, id, scanID, rawAddress string) {
	if _, err := s.Store.GetJob(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "job not found", nil)
		return
	}
	s.renderScanHostRDAP(w, r, id, scanID, rawAddress)
}

func (s *Server) renderScanHostRDAP(w http.ResponseWriter, r *http.Request, id, scanID, rawAddress string) {
	summary, err := s.Store.GetScanSummary(r.Context(), scanID)
	if err != nil || (id != "" && summary.JobID != id) {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	address, err := normalizedHostAddress(rawAddress)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "host not found", nil)
		return
	}
	if _, indexErr := s.Store.GetScanHost(r.Context(), scanID, address); indexErr == nil {
		result := rdapUnavailable(address)
		if s.RDAP != nil {
			result, _ = s.RDAP.Lookup(r.Context(), address)
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]any{"rdap": result})
		return
	} else if !errors.Is(indexErr, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "store", indexErr.Error(), nil)
		return
	} else if indexedExists, existsErr := s.Store.ScanHostIndexExists(r.Context(), scanID); existsErr != nil {
		writeError(w, http.StatusInternalServerError, "store", existsErr.Error(), nil)
		return
	} else if indexedExists {
		writeError(w, http.StatusNotFound, "not_found", "scan host not found", nil)
		return
	}
	scan, err := s.Store.GetScan(r.Context(), scanID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	if _, _, ok := hostFromSnapshot(scan.Snapshot, address); !ok {
		writeError(w, http.StatusNotFound, "not_found", "scan host not found", nil)
		return
	}
	result := rdapUnavailable(address)
	if s.RDAP != nil {
		result, _ = s.RDAP.Lookup(r.Context(), address)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"rdap": result})
}

func (s *Server) scanHostRDAPRoute(w http.ResponseWriter, r *http.Request, scanID, rawAddress string) {
	summary, err := s.Store.GetScanSummary(r.Context(), scanID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
		return
	}
	if summary.JobID != "" {
		s.jobScanHostRDAP(w, r, summary.JobID, scanID, rawAddress)
		return
	}
	s.renderScanHostRDAP(w, r, "", scanID, rawAddress)
}
