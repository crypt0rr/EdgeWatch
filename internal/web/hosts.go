package web

import (
	"context"
	"database/sql"
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

func hostStoreNotFound(err error) bool {
	return errors.Is(err, store.ErrNotFound) || errors.Is(err, sql.ErrNoRows)
}

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
	Archived    bool      `json:"archived,omitempty"`
	ScanID      string    `json:"scan_id"`
	ScannedAt   time.Time `json:"scanned_at"`
	DataQuality string    `json:"data_quality"`
	// host keeps the complete evidence for compatibility merges. It is not
	// serialized; the regular indexed path already returns the summary from
	// SQLite, while the mixed legacy path needs service/hostname fields for the
	// same search semantics.
	host model.HostObservation
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
		Archived:    item.Archived,
		ScanID:      item.ScanID,
		ScannedAt:   item.ScannedAt,
		DataQuality: item.DataQuality,
		host:        item.Host,
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
		if value > maxPaginationOffset {
			value = maxPaginationOffset
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
		restoreHostScopes(result, snapshot.Scopes)
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
	links := map[string]model.LinkAddress{}
	for _, link := range host.LinkAddresses {
		links[link.Type+"\x00"+link.Address] = link
	}
	host.LinkAddresses = host.LinkAddresses[:0]
	for _, link := range links {
		host.LinkAddresses = append(host.LinkAddresses, link)
	}
	names := map[string]model.Hostname{}
	for _, name := range host.Hostnames {
		names[name.Type+"\x00"+name.Name] = name
	}
	host.Hostnames = host.Hostnames[:0]
	for _, name := range names {
		host.Hostnames = append(host.Hostnames, name)
	}
	// Broad scans are assembled from port chunks, so a single effective host
	// may contain many TCP (or UDP) protocol observations. Merge those records
	// before presenting or indexing them; otherwise the UI renders one coverage
	// chip per chunk and counts the same protocol repeatedly.
	protocols := map[string]int{}
	merged := make([]model.ProtocolObservation, 0, len(host.Protocols))
	for _, incoming := range host.Protocols {
		index, exists := protocols[incoming.Protocol]
		if !exists {
			protocols[incoming.Protocol] = len(merged)
			merged = append(merged, incoming)
			continue
		}
		mergeProtocolObservation(&merged[index], incoming)
	}
	host.Protocols = merged
	for i := range host.Protocols {
		dedupeProtocolPorts(&host.Protocols[i])
	}
	// The model normalizer gives all nested arrays deterministic order.
	holder := model.Snapshot{Hosts: []model.HostObservation{*host}}
	holder.Normalize()
	*host = holder.Hosts[0]
}

func mergeProtocolObservation(destination *model.ProtocolObservation, incoming model.ProtocolObservation) {
	destination.Ports = append(destination.Ports, incoming.Ports...)
	destination.DiscoveredPorts = append(destination.DiscoveredPorts, incoming.DiscoveredPorts...)
	destination.UnconfirmedPorts = append(destination.UnconfirmedPorts, incoming.UnconfirmedPorts...)
	if destination.ScanType == "" {
		destination.ScanType = incoming.ScanType
	}
	if destination.ScannedPorts == "" {
		destination.ScannedPorts = incoming.ScannedPorts
	}
	if incoming.ScannedPortCount > destination.ScannedPortCount {
		destination.ScannedPortCount = incoming.ScannedPortCount
	}
	destination.ServiceDetection = destination.ServiceDetection || incoming.ServiceDetection
	if destination.DiscoveryEngine == "" {
		destination.DiscoveryEngine = incoming.DiscoveryEngine
	}
	if destination.NSEProfile == "" {
		destination.NSEProfile = incoming.NSEProfile
	}
	if destination.NSEArgs == nil && incoming.NSEArgs != nil {
		destination.NSEArgs = cloneStringMap(incoming.NSEArgs)
	}
	destination.NSEOutput = append(destination.NSEOutput, incoming.NSEOutput...)
	if destination.CommandFingerprint == "" {
		destination.CommandFingerprint = incoming.CommandFingerprint
	}
	for _, summary := range incoming.StateSummaries {
		found := false
		for index := range destination.StateSummaries {
			if destination.StateSummaries[index].State != summary.State {
				continue
			}
			destination.StateSummaries[index].Count += summary.Count
			for _, reason := range summary.Reasons {
				reasonFound := false
				for reasonIndex := range destination.StateSummaries[index].Reasons {
					if destination.StateSummaries[index].Reasons[reasonIndex].Reason != reason.Reason {
						continue
					}
					destination.StateSummaries[index].Reasons[reasonIndex].Count += reason.Count
					reasonFound = true
					break
				}
				if !reasonFound {
					destination.StateSummaries[index].Reasons = append(destination.StateSummaries[index].Reasons, reason)
				}
			}
			found = true
			break
		}
		if !found {
			destination.StateSummaries = append(destination.StateSummaries, summary)
		}
	}
}

func dedupeProtocolPorts(protocol *model.ProtocolObservation) {
	ports := map[int]int{}
	merged := make([]model.PortObservation, 0, len(protocol.Ports))
	for _, incoming := range protocol.Ports {
		index, exists := ports[incoming.Port]
		if !exists {
			ports[incoming.Port] = len(merged)
			merged = append(merged, incoming)
			continue
		}
		destination := &merged[index]
		// Keep the strongest positive state and whichever evidence fields are
		// available instead of relying on map iteration order.
		if destination.State != "open" && incoming.State == "open" {
			destination.State = incoming.State
		}
		if destination.Reason == "" {
			destination.Reason, destination.ReasonTTL = incoming.Reason, incoming.ReasonTTL
		}
		if verificationRank(incoming.Verification) > verificationRank(destination.Verification) {
			destination.Verification = incoming.Verification
		}
		mergeServiceObservation(destination, incoming)
	}
	protocol.Ports = merged
	for _, field := range []*[]model.PortObservation{&protocol.DiscoveredPorts, &protocol.UnconfirmedPorts} {
		seen := map[int]int{}
		mergedEvidence := make([]model.PortObservation, 0, len(*field))
		for _, incoming := range *field {
			if index, exists := seen[incoming.Port]; exists {
				if verificationRank(incoming.Verification) > verificationRank(mergedEvidence[index].Verification) {
					mergedEvidence[index].Verification = incoming.Verification
				}
				if mergedEvidence[index].Reason == "" {
					mergedEvidence[index].Reason, mergedEvidence[index].ReasonTTL = incoming.Reason, incoming.ReasonTTL
				}
				continue
			}
			seen[incoming.Port] = len(mergedEvidence)
			mergedEvidence = append(mergedEvidence, incoming)
		}
		*field = mergedEvidence
	}
}

func verificationRank(value string) int {
	switch value {
	case "confirmed":
		return 3
	case "discovered":
		return 2
	case "unconfirmed":
		return 1
	default:
		return 0
	}
}

func mergeServiceObservation(destination *model.PortObservation, incoming model.PortObservation) {
	if destination.Service == nil {
		destination.Service = incoming.Service
		return
	}
	if incoming.Service == nil {
		return
	}
	if destination.Service.Name == "" {
		destination.Service.Name = incoming.Service.Name
	}
	if destination.Service.Product == "" {
		destination.Service.Product = incoming.Service.Product
	}
	if destination.Service.Version == "" {
		destination.Service.Version = incoming.Service.Version
	}
	if destination.Service.ExtraInfo == "" {
		destination.Service.ExtraInfo = incoming.Service.ExtraInfo
	}
	if destination.Service.Method == "" {
		destination.Service.Method = incoming.Service.Method
	}
	if destination.Service.Confidence == 0 {
		destination.Service.Confidence = incoming.Service.Confidence
	}
	if destination.Service.Tunnel == "" {
		destination.Service.Tunnel = incoming.Service.Tunnel
	}
	if destination.Service.OSType == "" {
		destination.Service.OSType = incoming.Service.OSType
	}
	if destination.Service.DeviceType == "" {
		destination.Service.DeviceType = incoming.Service.DeviceType
	}
	destination.Service.CPEs = append(destination.Service.CPEs, incoming.Service.CPEs...)
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

func restoreHostScopes(hosts []model.HostObservation, scopes []model.Scope) {
	byProtocol := map[string]model.Scope{}
	for _, scope := range scopes {
		protocol := strings.ToLower(strings.TrimSpace(scope.Protocol))
		if protocol == "" {
			continue
		}
		if _, exists := byProtocol[protocol]; !exists {
			byProtocol[protocol] = scope
		}
	}
	for hostIndex := range hosts {
		for protocolIndex := range hosts[hostIndex].Protocols {
			protocol := &hosts[hostIndex].Protocols[protocolIndex]
			scope, exists := byProtocol[strings.ToLower(strings.TrimSpace(protocol.Protocol))]
			if !exists {
				continue
			}
			protocol.ScannedPorts = scope.Ports
			protocol.ServiceDetection = scope.ServiceDetection
			protocol.ScannedPortCount = portCount(scope.Ports)
		}
	}
}

func scopesForJob(job config.Job) []model.Scope {
	scopes := make([]model.Scope, 0, 2)
	if job.TCP != nil {
		scopes = append(scopes, model.Scope{Protocol: "tcp", Ports: job.TCP.Ports, ServiceDetection: job.TCP.ServiceDetection})
	}
	if job.UDP != nil {
		scopes = append(scopes, model.Scope{Protocol: "udp", Ports: job.UDP.Ports, ServiceDetection: job.UDP.ServiceDetection})
	}
	return scopes
}

func summaryForHost(host model.HostObservation, legacy bool) hostSummary {
	// Indexed hosts may have been written by an older broad-scan merge that
	// retained one protocol record per port chunk. Normalize the copy before
	// calculating counts so legacy rows cannot render duplicate TCP/UDP chips.
	dedupeHost(&host)
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
	archivedJobs := make(map[string]bool)
	jobs, err := s.Store.ListJobs(ctx, true)
	if err != nil {
		return nil, err
	}
	for _, job := range jobs {
		archivedJobs[job.ID] = job.Archived
	}
	// Legacy snapshots have no host index. Read only the raw snapshot and the
	// small metadata projection, in bounded pages, and walk every page so hosts
	// are not silently lost after an arbitrary scan-count cap. Indexed scans are
	// excluded by the store query and therefore never get decoded here.
	const pageSize = 100
	const maxLegacySnapshotBytes = 8 << 20
	for offset := 0; ; offset += pageSize {
		page, err := s.Store.ListLegacySuccessfulScanSnapshotsPage(ctx, pageSize, offset)
		if err != nil {
			return nil, err
		}
		for _, scan := range page.Items {
			if len(scan.Snapshot) > maxLegacySnapshotBytes {
				s.Log.Warn("skipping oversized legacy scan snapshot", "scan_id", scan.ID, "bytes", len(scan.Snapshot))
				continue
			}
			hostPage, err := observationsForSnapshotBytes(scan.Snapshot)
			if err != nil {
				// A malformed retained snapshot cannot produce trustworthy host
				// inventory, but it must not make the global Hosts endpoint fail.
				s.Log.Warn("skipping malformed legacy scan snapshot", "scan_id", scan.ID, "error", err)
				continue
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
					Archived:    archivedJobs[scan.JobID],
					ScanID:      scan.ID,
					ScannedAt:   scan.FinishedAt,
					DataQuality: hostPage.DataQuality,
					host:        host,
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
		if result[i].Archived != result[j].Archived {
			return !result[i].Archived
		}
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
	indexedExists, err := s.Store.SuccessfulScanHostIndexExists(r.Context())
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	legacyExists, err := s.Store.LegacySuccessfulScanExists(r.Context())
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	if indexedExists && !legacyExists {
		indexed, err := s.Store.ListLatestScanHostsPage(r.Context(), query, protocol, hasOpen, limit, offset)
		if err != nil {
			s.writeInternalError(w, r, "store", err)
			return
		}
		items := make([]allHostSummary, 0, len(indexed.Items))
		for _, item := range indexed.Items {
			items = append(items, allSummaryFromIndexedHost(item))
		}
		writeJSON(w, http.StatusOK, map[string]any{"hosts": items, "pagination": paginationJSON(offset, limit, indexed.Total)})
		return
	}

	// Databases upgraded from before scan_hosts can contain both indexed scans
	// and legacy snapshots. Merge the maintained projection with the bounded
	// legacy walk before filtering and paginating, otherwise whichever path is
	// selected would silently hide hosts from the other history format.
	var hosts []allHostSummary
	if indexedExists {
		indexed, err := s.Store.ListLatestScanHosts(r.Context())
		if err != nil {
			s.writeInternalError(w, r, "store", err)
			return
		}
		hosts = make([]allHostSummary, 0, len(indexed))
		for _, item := range indexed {
			hosts = append(hosts, allSummaryFromIndexedHost(item))
		}
	}
	legacyHosts, err := s.latestScannedHosts(r.Context())
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	if !indexedExists {
		hosts = legacyHosts
	} else {
		byAddress := make(map[string]int, len(hosts))
		for index := range hosts {
			byAddress[hosts[index].Address] = index
		}
		for _, incoming := range legacyHosts {
			index, exists := byAddress[incoming.Address]
			if !exists || incoming.ScannedAt.After(hosts[index].ScannedAt) ||
				(incoming.ScannedAt.Equal(hosts[index].ScannedAt) && incoming.ScanID > hosts[index].ScanID) {
				if !exists {
					byAddress[incoming.Address] = len(hosts)
					hosts = append(hosts, incoming)
				} else {
					hosts[index] = incoming
				}
			}
		}
	}
	filtered := make([]allHostSummary, 0, len(hosts))
	for _, item := range hosts {
		host := item.host
		if host.Address == "" {
			host = model.HostObservation{Address: item.Address, SourceTargets: item.SourceTargets, DNSNames: item.DNSNames}
		}
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
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Archived != filtered[j].Archived {
			return !filtered[i].Archived
		}
		return filtered[i].Address < filtered[j].Address
	})
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
	// Keep the legacy fallback on exactly the same bounded normalized document
	// as the indexed scan/baseline searches. This prevents the old path from
	// accepting a field (or casing) that the normal FTS path cannot find.
	return strings.Contains(storeHostSearchContent(host), query)
}

func storeHostSearchContent(host model.HostObservation) string {
	var values []string
	values = append(values, host.Address)
	values = append(values, host.SourceTargets...)
	values = append(values, host.DNSNames...)
	for _, name := range host.Hostnames {
		values = append(values, name.Name)
	}
	for _, protocol := range host.Protocols {
		for _, port := range protocol.Ports {
			values = append(values, strconv.Itoa(port.Port))
			if port.Service != nil {
				values = append(values, port.Service.Name, port.Service.Product, port.Service.Version, port.Service.ExtraInfo, port.Service.OSType, port.Service.DeviceType)
				values = append(values, port.Service.CPEs...)
			}
		}
	}
	return strings.ToLower(strings.Join(values, " "))
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

// expectedHostForScan returns the current comparison baseline for a host shown
// through a historical scan route. The immutable source scan is the normal
// source, but accepting an incident deliberately creates a runtime overlay;
// historical pages must use that overlay too or they will continue to display
// ports that the administrator already accepted as removed.
func (s *Server) expectedHostForScan(ctx context.Context, jobID, address string, job config.Job) (model.HostObservation, bool, error) {
	baselineInfo, err := s.Store.RuntimeBaselineInfo(ctx, jobID)
	if err != nil {
		return model.HostObservation{}, false, err
	}
	baselineID := baselineInfo.BaselineScanID
	if baselineID == "" {
		return model.HostObservation{}, false, nil
	}
	modified := baselineInfo.BaselineModified
	if modified {
		// Accepted incident changes are stored in baseline_hosts alongside the
		// runtime state. Prefer that indexed projection so the historical route
		// remains bounded and reflects the exact current expectation.
		if projected, projectionErr := s.Store.GetBaselineHost(ctx, jobID, address); projectionErr == nil {
			hosts := []model.HostObservation{projected.Host}
			restoreHostScopes(hosts, scopesForJob(job))
			return hosts[0], true, nil
		} else if !hostStoreNotFound(projectionErr) {
			return model.HostObservation{}, false, projectionErr
		}
		// Databases from before the indexed overlay projection may still carry
		// an accepted baseline in runtime JSON. Keep that legacy fallback rather
		// than silently reverting to the immutable source scan.
		state, stateErr := s.Store.RuntimeState(ctx, jobID)
		if stateErr != nil {
			return model.HostObservation{}, false, stateErr
		}
		if state.Baseline != nil {
			if host, _, found := hostFromSnapshot(*state.Baseline, address); found {
				hosts := []model.HostObservation{host}
				restoreHostScopes(hosts, scopesForJob(job))
				return hosts[0], true, nil
			}
		}
		return model.HostObservation{}, false, nil
	}
	// With no runtime overlay, use the immutable source scan that established
	// the active baseline. This preserves the historical context shown today.
	indexedExists, indexErr := s.Store.ScanHostIndexExists(ctx, baselineID)
	if indexErr != nil {
		return model.HostObservation{}, false, indexErr
	}
	if indexedExists {
		if baselineHost, sourceErr := s.Store.GetScanHost(ctx, baselineID, address); sourceErr == nil {
			hosts := []model.HostObservation{baselineHost.Host}
			restoreHostScopes(hosts, scopesForJob(job))
			return hosts[0], true, nil
		} else if !hostStoreNotFound(sourceErr) {
			return model.HostObservation{}, false, sourceErr
		}
		return model.HostObservation{}, false, nil
	}
	// A pre-index baseline may still be represented by the runtime snapshot.
	// Use it only after confirming that no indexed projection exists.
	state, stateErr := s.Store.RuntimeState(ctx, jobID)
	if stateErr != nil {
		return model.HostObservation{}, false, stateErr
	}
	if state.Baseline != nil {
		if host, _, found := hostFromSnapshot(*state.Baseline, address); found {
			hosts := []model.HostObservation{host}
			restoreHostScopes(hosts, scopesForJob(job))
			return hosts[0], true, nil
		}
	}
	return model.HostObservation{}, false, nil
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

func (s *Server) jobBaselineHosts(w http.ResponseWriter, r *http.Request, record store.JobRecord) {
	id := record.ID
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
	baselineInfo, metaErr := s.Store.RuntimeBaselineInfo(r.Context(), id)
	if metaErr != nil {
		s.writeInternalError(w, r, "store", metaErr)
		return
	}
	baselineScanID := baselineInfo.BaselineScanID
	baselineModified := baselineInfo.BaselineModified
	if baselineScanID != "" && !baselineModified {
		indexedExists, existsErr := s.Store.ScanHostIndexExists(r.Context(), baselineScanID)
		if existsErr != nil {
			s.writeInternalError(w, r, "store", existsErr)
			return
		}
		if indexedExists {
			indexed, indexErr := s.Store.ListScanHostsPage(r.Context(), baselineScanID, query, protocol, hasOpen, limit, offset)
			if indexErr != nil {
				s.writeInternalError(w, r, "store", indexErr)
				return
			}
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
	if baselineModified {
		projectionExists, projectionErr := s.Store.BaselineHostProjectionExists(r.Context(), id)
		if projectionErr != nil {
			s.writeInternalError(w, r, "store", projectionErr)
			return
		}
		if projectionExists {
			projected, listErr := s.Store.ListBaselineHostsPage(r.Context(), id, query, protocol, hasOpen, limit, offset)
			if listErr != nil {
				s.writeInternalError(w, r, "store", listErr)
				return
			}
			items := make([]hostSummary, 0, len(projected.Items))
			for _, item := range projected.Items {
				items = append(items, summaryFromIndexedHost(item))
			}
			var source any
			if baselineScanID != "" {
				if summary, summaryErr := s.Store.GetScanSummary(r.Context(), baselineScanID); summaryErr == nil {
					source = summary
				}
			}
			writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": record.Job.Name, "source_scan": source, "data_quality": "detailed", "hosts": items, "pagination": paginationJSON(offset, limit, projected.Total)})
			return
		}
	}
	state, err := s.Store.RuntimeState(r.Context(), id)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	quality := "none"
	var hosts []model.HostObservation
	var source any
	if state.Baseline != nil {
		page, pageErr := observationsForSnapshot(*state.Baseline)
		if pageErr != nil {
			s.writeInternalError(w, r, "snapshot", pageErr)
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

func (s *Server) jobBaselineHost(w http.ResponseWriter, r *http.Request, record store.JobRecord, rawAddress string) {
	id := record.ID
	address, err := normalizedHostAddress(rawAddress)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "host not found", nil)
		return
	}
	baselineInfo, infoErr := s.Store.RuntimeBaselineInfo(r.Context(), id)
	if infoErr != nil {
		s.writeInternalError(w, r, "store", infoErr)
		return
	}
	baselineScanID := baselineInfo.BaselineScanID
	baselineModified := baselineInfo.BaselineModified
	if baselineScanID != "" && !baselineModified {
		indexedExists, existsErr := s.Store.ScanHostIndexExists(r.Context(), baselineScanID)
		if existsErr != nil {
			s.writeInternalError(w, r, "store", existsErr)
			return
		}
		if indexedExists {
			if indexed, indexErr := s.Store.GetScanHost(r.Context(), baselineScanID, address); indexErr == nil {
				dedupeHost(&indexed.Host)
				hosts := []model.HostObservation{indexed.Host}
				restoreHostScopes(hosts, scopesForJob(record.Job))
				indexed.Host = hosts[0]
				var source any
				if summary, summaryErr := s.Store.GetScanSummary(r.Context(), baselineScanID); summaryErr == nil {
					source = summary
				}
				writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": record.Job.Name, "data_quality": indexed.DataQuality, "host": indexed.Host, "expected": indexed.Host, "source_scan": source})
				return
			} else if !hostStoreNotFound(indexErr) {
				s.writeInternalError(w, r, "store", indexErr)
				return
			}
			writeError(w, http.StatusNotFound, "not_found", "baseline host not found", nil)
			return
		}
	}
	if baselineModified {
		if projectionExists, projectionErr := s.Store.BaselineHostProjectionExists(r.Context(), id); projectionErr != nil {
			s.writeInternalError(w, r, "store", projectionErr)
			return
		} else if projectionExists {
			if projected, projectionErr := s.Store.GetBaselineHost(r.Context(), id, address); projectionErr == nil {
				dedupeHost(&projected.Host)
				var source any
				if baselineScanID != "" {
					if summary, summaryErr := s.Store.GetScanSummary(r.Context(), baselineScanID); summaryErr == nil {
						source = summary
					}
				}
				writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": record.Job.Name, "data_quality": projected.DataQuality, "host": projected.Host, "expected": projected.Host, "source_scan": source})
				return
			} else if !hostStoreNotFound(projectionErr) {
				s.writeInternalError(w, r, "store", projectionErr)
				return
			}
			writeError(w, http.StatusNotFound, "not_found", "baseline host not found", nil)
			return
		}
	}
	state, err := s.Store.RuntimeState(r.Context(), id)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	if state.Baseline == nil {
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
	baselineInfo, infoErr := s.Store.RuntimeBaselineInfo(r.Context(), id)
	if infoErr != nil {
		s.writeInternalError(w, r, "store", infoErr)
		return
	}
	baselineScanID := baselineInfo.BaselineScanID
	baselineModified := baselineInfo.BaselineModified
	if baselineScanID != "" && !baselineModified {
		indexedExists, existsErr := s.Store.ScanHostIndexExists(r.Context(), baselineScanID)
		if existsErr != nil {
			s.writeInternalError(w, r, "store", existsErr)
			return
		}
		if indexedExists {
			if _, indexErr := s.Store.GetScanHost(r.Context(), baselineScanID, address); indexErr == nil {
				result := rdapUnavailable(address)
				if s.RDAP != nil {
					result, _ = s.RDAP.Lookup(r.Context(), address)
				}
				w.Header().Set("Cache-Control", "no-store")
				writeJSON(w, http.StatusOK, map[string]any{"rdap": result})
				return
			} else if !hostStoreNotFound(indexErr) {
				s.writeInternalError(w, r, "store", indexErr)
				return
			}
			writeError(w, http.StatusNotFound, "not_found", "baseline host not found", nil)
			return
		}
	}
	if baselineModified {
		if projectionExists, projectionErr := s.Store.BaselineHostProjectionExists(r.Context(), id); projectionErr != nil {
			s.writeInternalError(w, r, "store", projectionErr)
			return
		} else if projectionExists {
			if _, projectionErr := s.Store.GetBaselineHost(r.Context(), id, address); projectionErr == nil {
				result := rdapUnavailable(address)
				if s.RDAP != nil {
					result, _ = s.RDAP.Lookup(r.Context(), address)
				}
				w.Header().Set("Cache-Control", "no-store")
				writeJSON(w, http.StatusOK, map[string]any{"rdap": result})
				return
			} else if !hostStoreNotFound(projectionErr) {
				s.writeInternalError(w, r, "store", projectionErr)
				return
			}
			writeError(w, http.StatusNotFound, "not_found", "baseline host not found", nil)
			return
		}
	}
	state, err := s.Store.RuntimeState(r.Context(), id)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	if state.Baseline == nil {
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

func (s *Server) jobScanHosts(w http.ResponseWriter, r *http.Request, record store.JobRecord, summary model.ScanSummary) {
	s.renderScanHosts(w, r, record.ID, record.Job.Name, summary)
}

// renderScanHosts lists the hosts of a resolved scan. id is the owning job's
// ID, or empty for a legacy scan that only records its job name.
func (s *Server) renderScanHosts(w http.ResponseWriter, r *http.Request, id, jobName string, summary model.ScanSummary) {
	scanID := summary.ID
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
	indexedExists, existsErr := s.Store.ScanHostIndexExists(r.Context(), scanID)
	if existsErr != nil {
		s.writeInternalError(w, r, "store", existsErr)
		return
	}
	if indexedExists {
		indexed, indexErr := s.Store.ListScanHostsPage(r.Context(), scanID, r.URL.Query().Get("q"), protocol, hasOpen, limit, offset)
		if indexErr != nil {
			s.writeInternalError(w, r, "store", indexErr)
			return
		}
		items := make([]hostSummary, 0, len(indexed.Items))
		for _, item := range indexed.Items {
			items = append(items, summaryFromIndexedHost(item))
		}
		writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": jobName, "scan": summary, "data_quality": "detailed", "hosts": items, "pagination": paginationJSON(offset, limit, indexed.Total)})
		return
	}
	scan, err := s.Store.GetScan(r.Context(), scanID)
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	page, _ := observationsForSnapshot(scan.Snapshot)
	items, total := filterHosts(page.Items, page.DataQuality, r.URL.Query().Get("q"), protocol, hasOpen, offset, limit)
	writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": jobName, "scan": summary, "data_quality": page.DataQuality, "hosts": items, "pagination": paginationJSON(offset, limit, total)})
}

// scanHostsRoute is the additive top-level historical-results form. The job
// nested route remains available for callers that already scope every request
// by job ID; both paths enforce the same ownership check. A scan that records
// its job ID is listed under that job; a legacy scan keeps its job name.
func (s *Server) scanHostsRoute(w http.ResponseWriter, r *http.Request, scanID string) {
	summary, ok := s.resolveScanSummary(w, r, scanID, scanStoreErrorInternal)
	if !ok {
		return
	}
	if summary.JobID == "" {
		s.renderScanHosts(w, r, "", summary.Job, summary)
		return
	}
	if job, ok := s.resolveJob(w, r, summary.JobID, jobStoreErrorInternal); ok {
		s.renderScanHosts(w, r, job.ID, job.Job.Name, summary)
	}
}

func (s *Server) jobScanHost(w http.ResponseWriter, r *http.Request, record store.JobRecord, summary model.ScanSummary, rawAddress string) {
	s.renderScanHostWithSummary(w, r, record.ID, record.Job.Name, rawAddress, summary, &record)
}

// renderScanHostWithSummary shows one host of a resolved scan. id and record
// name the owning job, or are empty and nil for a legacy scan.
func (s *Server) renderScanHostWithSummary(w http.ResponseWriter, r *http.Request, id, jobName, rawAddress string, summary model.ScanSummary, record *store.JobRecord) {
	scanID := summary.ID
	address, err := normalizedHostAddress(rawAddress)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "host not found", nil)
		return
	}
	expectedJobID := id
	if expectedJobID == "" {
		// The top-level /scans/:scanID route has already verified the scan's
		// ownership and carries the owning job ID in its summary. Use it for
		// the expected-state lookup so global host history also reflects an
		// accepted runtime baseline overlay.
		expectedJobID = summary.JobID
	}
	var expectedJob config.Job
	haveExpectedJob := record != nil
	if record != nil {
		expectedJob = record.Job
	}
	indexedExists, existsErr := s.Store.ScanHostIndexExists(r.Context(), scanID)
	if existsErr != nil {
		writeError(w, http.StatusInternalServerError, "store", "scan host detail could not be loaded", nil)
		return
	}
	if indexedExists {
		if indexed, indexErr := s.Store.GetScanHost(r.Context(), scanID, address); indexErr == nil {
			dedupeHost(&indexed.Host)
			var expected any
			if haveExpectedJob {
				if baselineHost, found, expectedErr := s.expectedHostForScan(r.Context(), expectedJobID, address, expectedJob); expectedErr == nil && found {
					dedupeHost(&baselineHost)
					expected = baselineHost
				} else if expectedErr != nil {
					writeError(w, http.StatusInternalServerError, "store", "baseline host detail could not be loaded", nil)
					return
				}
			}
			writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": jobName, "scan": summary, "data_quality": indexed.DataQuality, "host": indexed.Host, "expected": expected})
			return
		} else if !hostStoreNotFound(indexErr) {
			writeError(w, http.StatusInternalServerError, "store", "scan host detail could not be loaded", nil)
			return
		}
		writeError(w, http.StatusNotFound, "not_found", "scan host not found", nil)
		return
	}
	scan, err := s.Store.GetScan(r.Context(), scanID)
	if err != nil {
		if hostStoreNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "store", "scan detail could not be loaded", nil)
		return
	}
	host, quality, ok := hostFromSnapshot(scan.Snapshot, address)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "scan host not found", nil)
		return
	}
	var expected any
	if expectedJobID != "" {
		state, stateErr := s.Store.RuntimeState(r.Context(), expectedJobID)
		if stateErr != nil {
			s.writeInternalError(w, r, "store", stateErr)
			return
		}
		if state.Baseline != nil {
			if baselineHost, _, found := hostFromSnapshot(*state.Baseline, address); found {
				expected = baselineHost
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"job_id": id, "job": jobName, "scan": summary, "data_quality": quality, "host": host, "expected": expected})
}

func (s *Server) scanHostRoute(w http.ResponseWriter, r *http.Request, scanID, rawAddress string) {
	summary, ok := s.resolveScanSummary(w, r, scanID, scanStoreErrorDetail)
	if !ok {
		return
	}
	if summary.JobID == "" {
		s.renderScanHostWithSummary(w, r, "", summary.Job, rawAddress, summary, nil)
		return
	}
	if job, ok := s.resolveJob(w, r, summary.JobID, jobStoreErrorJobDetail); ok {
		s.renderScanHostWithSummary(w, r, job.ID, job.Job.Name, rawAddress, summary, &job)
	}
}

// jobScanHostRDAP serves /jobs/{id}/scans/{scan}/hosts/{address}/rdap. The
// router has already confirmed that the scan belongs to the job.
func (s *Server) jobScanHostRDAP(w http.ResponseWriter, r *http.Request, summary model.ScanSummary, rawAddress string) {
	s.renderScanHostRDAPWithSummary(w, r, summary, rawAddress)
}

// renderScanHostRDAPWithSummary answers an RDAP request for a host that the
// resolved scan observed.
func (s *Server) renderScanHostRDAPWithSummary(w http.ResponseWriter, r *http.Request, summary model.ScanSummary, rawAddress string) {
	scanID := summary.ID
	address, err := normalizedHostAddress(rawAddress)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "host not found", nil)
		return
	}
	indexedExists, existsErr := s.Store.ScanHostIndexExists(r.Context(), scanID)
	if existsErr != nil {
		writeError(w, http.StatusInternalServerError, "store", "scan host detail could not be loaded", nil)
		return
	}
	if indexedExists {
		if _, indexErr := s.Store.GetScanHost(r.Context(), scanID, address); indexErr == nil {
			result := rdapUnavailable(address)
			if s.RDAP != nil {
				result, _ = s.RDAP.Lookup(r.Context(), address)
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, map[string]any{"rdap": result})
			return
		} else if !hostStoreNotFound(indexErr) {
			writeError(w, http.StatusInternalServerError, "store", "scan host detail could not be loaded", nil)
			return
		}
		writeError(w, http.StatusNotFound, "not_found", "scan host not found", nil)
		return
	}
	scan, err := s.Store.GetScan(r.Context(), scanID)
	if err != nil {
		if hostStoreNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "scan not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "store", "scan detail could not be loaded", nil)
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
	summary, ok := s.resolveScanSummary(w, r, scanID, scanStoreErrorDetail)
	if !ok {
		return
	}
	if summary.JobID != "" {
		if _, ok := s.resolveJob(w, r, summary.JobID, jobStoreErrorHostDetail); !ok {
			return
		}
	}
	s.renderScanHostRDAPWithSummary(w, r, summary, rawAddress)
}
