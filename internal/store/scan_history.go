package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func (s *Store) SaveScan(ctx context.Context, scan model.Scan) error {
	// Keep the scan row and its derived host indexes in one transaction. The
	// host index is consumed as an authoritative projection by the web API, so
	// exposing a scan with only a prefix of its hosts would be worse than
	// rejecting the write and retrying it later.
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := saveScanExec(ctx, tx, scan); err != nil {
		return err
	}
	if err := clearCompletedScanCycleCheckpointsTx(ctx, tx, scan.CycleID); err != nil {
		return err
	}
	return tx.Commit()
}

// clearCompletedScanCycleCheckpointsTx reclaims the large per-unit payloads
// only after the merged scan has been persisted. CompleteScanCycle and scan
// promotion are intentionally separate transactions so a process crash in
// between can still recover the merged result from its checkpoints.
func clearCompletedScanCycleCheckpointsTx(ctx context.Context, tx *sql.Tx, cycleID string) error {
	if strings.TrimSpace(cycleID) == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `UPDATE scan_cycle_units SET snapshot_json='{}' WHERE cycle_id=? AND EXISTS (SELECT 1 FROM scan_cycles WHERE id=? AND status='completed')`, cycleID, cycleID)
	return err
}

func saveScanExec(ctx context.Context, execer contextExecer, scan model.Scan) error {
	snapshot, err := json.Marshal(scan.Snapshot)
	if err != nil {
		return err
	}
	changes := scan.Changes
	if changes == nil {
		changes = []model.Change{}
	}
	changesJSON, err := json.Marshal(changes)
	if err != nil {
		return err
	}
	_, err = execer.ExecContext(ctx, `INSERT INTO scans(id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,changes_json,snapshot_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		scan.ID, nullString(scan.JobID), nullInt64(scan.JobRevision), scan.Job, scan.StartedAt.UTC().Format(time.RFC3339Nano), scan.FinishedAt.UTC().Format(time.RFC3339Nano), scan.Status, scan.Error, scan.NmapVersion, scan.ScannerEngine, scan.ScannerProfileID, scan.ScannerProfileRevision, scan.NaabuVersion, scan.DiscoveryPorts, scan.ConfirmedPorts, scan.DiscoveryDurationMS, scan.EnrichmentDurationMS, scan.ConfigHash, scan.CycleID, scan.CycleAttempt, scan.CycleStatus, boolInt(scan.Resumable), scan.CompletedProbes, scan.TotalProbes, scan.CompletedUnits, scan.TotalUnits, scan.NoProgressTries, scan.BaselineScanID, scan.BaselineConfigHash, changesJSON, snapshot)
	if err != nil {
		return err
	}
	return saveScanHostsExec(ctx, execer, scan)
}

func loadScanMetadata(ctx context.Context, queryer rowQueryer, id string, scan *model.Scan) error {
	if scan == nil {
		return nil
	}
	return queryer.QueryRowContext(ctx, `SELECT scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms FROM scans WHERE id=?`, id).Scan(&scan.ScannerEngine, &scan.ScannerProfileID, &scan.ScannerProfileRevision, &scan.NaabuVersion, &scan.DiscoveryPorts, &scan.ConfirmedPorts, &scan.DiscoveryDurationMS, &scan.EnrichmentDurationMS)
}

func loadScanSummaryMetadata(ctx context.Context, queryer rowQueryer, id string, scan *model.ScanSummary) error {
	if scan == nil {
		return nil
	}
	return queryer.QueryRowContext(ctx, `SELECT scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms FROM scans WHERE id=?`, id).Scan(&scan.ScannerEngine, &scan.ScannerProfileID, &scan.ScannerProfileRevision, &scan.NaabuVersion, &scan.DiscoveryPorts, &scan.ConfirmedPorts, &scan.DiscoveryDurationMS, &scan.EnrichmentDurationMS)
}

func saveScanHostsExec(ctx context.Context, execer contextExecer, scan model.Scan) error {
	if len(scan.Snapshot.Hosts) == 0 {
		return nil
	}
	// Normalize a copy so the indexed payload has stable ordering without
	// mutating the immutable snapshot that the caller may still hold.
	hosts := append([]model.HostObservation(nil), scan.Snapshot.Hosts...)
	hostSnapshot := model.Snapshot{Hosts: hosts}
	hostSnapshot.Normalize()
	for _, host := range hostSnapshot.Hosts {
		address := strings.TrimSpace(host.Address)
		if net.ParseIP(address) == nil {
			continue
		}
		hostJSON, err := json.Marshal(host)
		if err != nil {
			return err
		}
		sourceTargets, err := json.Marshal(host.SourceTargets)
		if err != nil {
			return err
		}
		dnsNames, err := json.Marshal(host.DNSNames)
		if err != nil {
			return err
		}
		searchText := hostSearchContent(scan.Job, host)
		open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered := scanHostStats(host)
		if _, err := execer.ExecContext(ctx, `INSERT INTO scan_hosts(scan_id,address,job,address_family,source_targets_json,dns_names_json,host_json,search_text,data_quality,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			scan.ID, address, scan.Job, host.AddressFamily, sourceTargets, dnsNames, hostJSON, searchText, "detailed", open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered); err != nil {
			return err
		}
		if scan.Status == "success" {
			if err := upsertLatestScanHostExec(ctx, execer, scan, address, host.AddressFamily, sourceTargets, dnsNames, hostJSON, searchText, open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered); err != nil {
				return err
			}
		}
	}
	return nil
}

const maxHostSearchTextBytes = 64 * 1024

// hostSearchContent is deliberately built from the small set of fields that
// the host inventory promises to search. Keeping the serialized evidence out
// of this document bounds FTS maintenance time as service and Nmap metadata
// grows while preserving address, job, target, DNS, hostname, port, and
// service searches. Values are de-duplicated and the document has a hard byte
// cap so a host with thousands of open services cannot recreate the old
// host_json write amplification through the search projection.
func hostSearchContent(job string, host model.HostObservation) string {
	var builder strings.Builder
	seen := make(map[string]struct{})
	appendValue := func(raw string) bool {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value == "" {
			return true
		}
		if _, exists := seen[value]; exists {
			return true
		}
		if builder.Len()+len(value)+1 > maxHostSearchTextBytes {
			return false
		}
		seen[value] = struct{}{}
		builder.WriteString(value)
		builder.WriteByte(' ')
		return true
	}
	if !appendValue(host.Address) || !appendValue(job) {
		return strings.TrimSpace(builder.String())
	}
	for _, target := range host.SourceTargets {
		if !appendValue(target) {
			return strings.TrimSpace(builder.String())
		}
	}
	for _, name := range host.DNSNames {
		if !appendValue(name) {
			return strings.TrimSpace(builder.String())
		}
	}
	for _, hostname := range host.Hostnames {
		if !appendValue(hostname.Name) {
			return strings.TrimSpace(builder.String())
		}
	}
	for _, protocol := range host.Protocols {
		for _, port := range protocol.Ports {
			if !appendValue(strconv.Itoa(port.Port)) {
				return strings.TrimSpace(builder.String())
			}
			if port.Service == nil {
				continue
			}
			service := port.Service
			for _, value := range []string{service.Name, service.Product, service.Version, service.ExtraInfo, service.OSType, service.DeviceType} {
				if !appendValue(value) {
					return strings.TrimSpace(builder.String())
				}
			}
			for _, cpe := range service.CPEs {
				if !appendValue(cpe) {
					return strings.TrimSpace(builder.String())
				}
			}
		}
	}
	return strings.TrimSpace(builder.String())
}

// upsertLatestScanHostExec maintains the exact latest successful observation
// for one effective address. The finished-at/id ordering mirrors the historical
// ranking query, including deterministic ties between scans with equal times.
func upsertLatestScanHostExec(ctx context.Context, execer contextExecer, scan model.Scan, address, addressFamily string, sourceTargets, dnsNames, hostJSON []byte, searchText string, open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered int) error {
	finishedAt := scan.FinishedAt.UTC().Format(time.RFC3339Nano)
	_, err := execer.ExecContext(ctx, `INSERT INTO latest_scan_hosts(address,scan_id,job_id,job,finished_at,data_quality,address_family,source_targets_json,dns_names_json,host_json,search_text,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(address) DO UPDATE SET
 scan_id=excluded.scan_id,
 job_id=excluded.job_id,
 job=excluded.job,
 finished_at=excluded.finished_at,
 data_quality=excluded.data_quality,
 address_family=excluded.address_family,
 source_targets_json=excluded.source_targets_json,
	dns_names_json=excluded.dns_names_json,
	host_json=excluded.host_json,
	search_text=excluded.search_text,
	open_ports=excluded.open_ports,
 open_filtered_ports=excluded.open_filtered_ports,
 tcp_present=excluded.tcp_present,
 udp_present=excluded.udp_present,
 tcp_open_ports=excluded.tcp_open_ports,
 tcp_open_filtered_ports=excluded.tcp_open_filtered_ports,
 udp_open_ports=excluded.udp_open_ports,
 udp_open_filtered_ports=excluded.udp_open_filtered_ports
WHERE excluded.finished_at > latest_scan_hosts.finished_at
   OR (excluded.finished_at = latest_scan_hosts.finished_at AND excluded.scan_id > latest_scan_hosts.scan_id)`,
		address, scan.ID, scan.JobID, scan.Job, finishedAt, "detailed", addressFamily, sourceTargets, dnsNames, hostJSON, searchText, open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered)
	return err
}

func normalizeStoredHostAddress(raw string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "", fmt.Errorf("host address is not a valid IP: %s", raw)
	}
	return ip.String(), nil
}

func decodeScanHost(address, dataQuality string, raw []byte) (ScanHost, error) {
	normalized, err := normalizeStoredHostAddress(address)
	if err != nil {
		return ScanHost{}, err
	}
	var host model.HostObservation
	if err := json.Unmarshal(raw, &host); err != nil {
		return ScanHost{}, err
	}
	host.Address = normalized
	return ScanHost{DataQuality: dataQuality, Host: host}, nil
}

// ListScanHostsPage reads indexed effective hosts for one scan. The SQL
// predicates run before LIMIT/OFFSET, so a page request never needs to load
// unrelated host payloads into Go.
func (s *Store) ListScanHostsPage(ctx context.Context, scanID, query, protocol string, hasOpen *bool, limit, offset int) (Page[ScanHost], error) {
	limit, offset = normalizePage(limit, offset)
	filter := buildHostFilter(query, protocol, hasOpen)
	where := append([]string{"h.scan_id=?"}, filter.where...)
	args := append([]any{scanID}, filter.args...)
	join, predicate, searchArgs := hostSearchPredicate(filter, "scan_host_search", "hs.scan_id=h.scan_id AND hs.address=h.address")
	if predicate != "" {
		where = append(where, predicate)
		args = append(args, searchArgs...)
	}
	var page Page[ScanHost]
	countQuery := `SELECT COUNT(*) FROM scan_hosts h` + join + ` WHERE ` + strings.Join(where, " AND ")
	reader := s.reader()
	if err := reader.QueryRowContext(ctx, countQuery, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	querySQL := `SELECT h.address,h.data_quality,h.host_json FROM scan_hosts h` + join + ` WHERE ` + strings.Join(where, " AND ") + ` ORDER BY h.address LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := reader.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var address, dataQuality string
		var raw []byte
		if err := rows.Scan(&address, &dataQuality, &raw); err != nil {
			return page, err
		}
		item, err := decodeScanHost(address, dataQuality, raw)
		if err != nil {
			return page, err
		}
		item.ScanID = scanID
		page.Items = append(page.Items, item)
	}
	return page, rows.Err()
}

// ScanHostIndexExists reports whether a scan has the incremental host index.
// It is separate from a filtered page's Total: a valid indexed scan can have
// zero matches for a particular query and must not fall back to decoding its
// complete snapshot.
func (s *Store) ScanHostIndexExists(ctx context.Context, scanID string) (bool, error) {
	var exists bool
	err := s.reader().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM scan_hosts WHERE scan_id=?)`, scanID).Scan(&exists)
	return exists, err
}

// SuccessfulScanHostIndexExists is the global equivalent used by the Hosts
// view to distinguish an indexed database (including a zero-match filter)
// from a wholly legacy database.
func (s *Store) SuccessfulScanHostIndexExists(ctx context.Context) (bool, error) {
	var exists bool
	err := s.reader().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM scan_hosts h JOIN scans s ON s.id=h.scan_id WHERE s.status='success')`).Scan(&exists)
	return exists, err
}

// GetScanHost returns one indexed effective host, or ErrNotFound when the scan
// predates the host index or the address was not part of that scan.
func (s *Store) GetScanHost(ctx context.Context, scanID, address string) (ScanHost, error) {
	normalized, err := normalizeStoredHostAddress(address)
	if err != nil {
		return ScanHost{}, fmt.Errorf("%w: host %s", ErrNotFound, address)
	}
	var dataQuality string
	var raw []byte
	err = s.reader().QueryRowContext(ctx, `SELECT data_quality,host_json FROM scan_hosts WHERE scan_id=? AND address=?`, scanID, normalized).Scan(&dataQuality, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ScanHost{}, fmt.Errorf("%w: host %s", ErrNotFound, normalized)
	}
	if err != nil {
		return ScanHost{}, err
	}
	item, err := decodeScanHost(normalized, dataQuality, raw)
	if err != nil {
		return ScanHost{}, err
	}
	item.ScanID = scanID
	return item, nil
}

// ListLatestScanHostsPage returns the maintained newest successful observation
// for each effective address across all jobs. The projection is updated in the
// same transaction as a successful scan and rebuilt after retention deletes.
func (s *Store) ListLatestScanHostsPage(ctx context.Context, query, protocol string, hasOpen *bool, limit, offset int) (Page[LatestScanHost], error) {
	limit, offset = normalizePage(limit, offset)
	filter := buildHostFilter(query, protocol, hasOpen)
	where := filter.where
	if len(where) == 0 {
		where = []string{"1=1"}
	}
	args := append([]any(nil), filter.args...)
	join, predicate, searchArgs := hostSearchPredicate(filter, "latest_host_search", "hs.address=h.address")
	if predicate != "" {
		where = append(where, predicate)
		args = append(args, searchArgs...)
	}
	var page Page[LatestScanHost]
	countQuery := `SELECT COUNT(*) FROM latest_scan_hosts h` + join + ` WHERE ` + strings.Join(where, " AND ")
	reader := s.reader()
	if err := reader.QueryRowContext(ctx, countQuery, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	querySQL := `SELECT h.scan_id,h.address,h.data_quality,h.host_json,h.job_id,h.job,h.finished_at,COALESCE(j.archived,0) FROM latest_scan_hosts h LEFT JOIN jobs j ON j.id=h.job_id` + join + ` WHERE ` + strings.Join(where, " AND ") + ` ORDER BY COALESCE(j.archived,0) ASC,h.address LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := reader.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var scanID, address, dataQuality, job, finished string
		var jobID sql.NullString
		var archived int
		var raw []byte
		if err := rows.Scan(&scanID, &address, &dataQuality, &raw, &jobID, &job, &finished, &archived); err != nil {
			return page, err
		}
		item, err := decodeScanHost(address, dataQuality, raw)
		if err != nil {
			return page, err
		}
		parsed := scanTime(finished)
		page.Items = append(page.Items, LatestScanHost{ScanHost: ScanHost{ScanID: scanID, DataQuality: dataQuality, Host: item.Host}, JobID: jobID.String, Job: job, Archived: archived != 0, ScannedAt: parsed})
	}
	return page, rows.Err()
}

// ListLatestScanHosts returns the complete maintained projection. It is used
// only when a database still contains legacy successful snapshots that cannot
// be represented by latest_scan_hosts; the normal Hosts endpoint stays on the
// filtered, paginated query above.
func (s *Store) ListLatestScanHosts(ctx context.Context) ([]LatestScanHost, error) {
	const pageSize = 1000
	var result []LatestScanHost
	for offset := 0; ; offset += pageSize {
		page, err := s.ListLatestScanHostsPage(ctx, "", "", nil, pageSize, offset)
		if err != nil {
			return nil, err
		}
		result = append(result, page.Items...)
		if len(page.Items) == 0 || offset+len(page.Items) >= page.Total {
			return result, nil
		}
	}
}

// LegacySuccessfulScanExists reports whether at least one successful scan has
// no derived host index. Such rows are expected in databases upgraded from a
// release predating scan_hosts and require the bounded compatibility merge in
// the global Hosts endpoint.
func (s *Store) LegacySuccessfulScanExists(ctx context.Context) (bool, error) {
	var exists bool
	err := s.reader().QueryRowContext(ctx, `SELECT EXISTS(
SELECT 1 FROM scans s
WHERE s.status='success'
  AND NOT EXISTS (SELECT 1 FROM scan_hosts h WHERE h.scan_id=s.id)
)`).Scan(&exists)
	return exists, err
}

func (s *Store) GetScan(ctx context.Context, id string) (model.Scan, error) {
	var v model.Scan
	var started, finished string
	var snapshot, changesJSON []byte
	var baselineScanID, baselineConfigHash string
	var jobID sql.NullString
	var revision sql.NullInt64
	var resumable int
	readDB := s.reader()
	err := readDB.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,changes_json,snapshot_json FROM scans WHERE id=?`, id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &baselineScanID, &baselineConfigHash, &changesJSON, &snapshot)
	if err != nil {
		return v, err
	}
	if jobID.Valid {
		v.JobID = jobID.String
	}
	if revision.Valid {
		v.JobRevision = revision.Int64
	}
	v.Resumable = resumable != 0
	v.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
	v.FinishedAt, _ = time.Parse(time.RFC3339Nano, finished)
	v.BaselineScanID, v.BaselineConfigHash = baselineScanID, baselineConfigHash
	if len(changesJSON) > 0 && string(changesJSON) != "null" {
		if err := json.Unmarshal(changesJSON, &v.Changes); err != nil {
			return v, err
		}
	}
	if err := json.Unmarshal(snapshot, &v.Snapshot); err != nil {
		return v, err
	}
	if err := loadScanMetadata(ctx, readDB, id, &v); err != nil {
		return v, err
	}
	return v, nil
}

// GetScanSummary returns scan metadata without reading either the snapshot or
// the serialized change list. History/detail views use this method so a broad
// scan cannot cause a hidden full-result allocation.
func (s *Store) GetScanSummary(ctx context.Context, id string) (model.ScanSummary, error) {
	var v model.ScanSummary
	var started, finished string
	var jobID sql.NullString
	var revision sql.NullInt64
	var resumable int
	readDB := s.reader()
	err := readDB.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash FROM scans WHERE id=?`, id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &v.BaselineScanID, &v.BaselineConfigHash)
	if err != nil {
		return v, err
	}
	if jobID.Valid {
		v.JobID = jobID.String
	}
	if revision.Valid {
		v.JobRevision = revision.Int64
	}
	v.Resumable = resumable != 0
	v.StartedAt, v.FinishedAt = scanTime(started), scanTime(finished)
	if err := loadScanSummaryMetadata(ctx, readDB, id, &v); err != nil {
		return v, err
	}
	return v, nil
}

// GetScanComparison returns scan metadata and the immutable scan-time change
// list without loading snapshot_json. Legacy rows without a scan-time
// comparison can be resolved through GetScan when callers need to recreate
// their historical diff against the then-current baseline behavior.
func (s *Store) GetScanComparison(ctx context.Context, id string) (model.ScanSummary, []model.Change, error) {
	var v model.ScanSummary
	var started, finished string
	var changesJSON []byte
	var jobID sql.NullString
	var revision sql.NullInt64
	var resumable int
	readDB := s.reader()
	err := readDB.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,changes_json FROM scans WHERE id=?`, id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &v.BaselineScanID, &v.BaselineConfigHash, &changesJSON)
	if err != nil {
		return v, nil, err
	}
	if jobID.Valid {
		v.JobID = jobID.String
	}
	if revision.Valid {
		v.JobRevision = revision.Int64
	}
	v.Resumable = resumable != 0
	v.StartedAt, v.FinishedAt = scanTime(started), scanTime(finished)
	if err := loadScanSummaryMetadata(ctx, readDB, id, &v); err != nil {
		return v, nil, err
	}
	var changes []model.Change
	if len(changesJSON) > 0 && string(changesJSON) != "null" {
		if err := json.Unmarshal(changesJSON, &changes); err != nil {
			return v, nil, err
		}
	}
	return v, changes, nil
}

// ListScanChangesPage reads only one page of the immutable scan-time diff.
// Changes are stored as a JSON array for backwards-compatible scan records;
// SQLite's json_each keeps pagination in the database so the web handler does
// not deserialize the entire change list merely to return the first page.
// Legacy rows with a NULL/empty array naturally return an empty page and are
// handled by the caller's explicit compatibility path.
func (s *Store) ListScanChangesPage(ctx context.Context, id string, limit, offset int) (Page[model.Change], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[model.Change]
	readDB := s.reader()
	if err := readDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans, json_each(scans.changes_json) WHERE scans.id=?`, id).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := readDB.QueryContext(ctx, `SELECT json_each.value FROM scans, json_each(scans.changes_json) WHERE scans.id=? ORDER BY json_each.key LIMIT ? OFFSET ?`, id, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return page, err
		}
		var change model.Change
		if err := json.Unmarshal(raw, &change); err != nil {
			return page, err
		}
		page.Items = append(page.Items, change)
	}
	return page, rows.Err()
}

// ListScanResultsPage reads one page of snapshot units directly from the
// persisted JSON document. The explicit results endpoint can therefore show a
// broad scan incrementally without first materializing every host in Go.
func (s *Store) ListScanResultsPage(ctx context.Context, id string, limit, offset int) (Page[model.Unit], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[model.Unit]
	readDB := s.reader()
	if err := readDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans, json_each(scans.snapshot_json, '$.units') WHERE scans.id=?`, id).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := readDB.QueryContext(ctx, `SELECT json_each.value FROM scans, json_each(scans.snapshot_json, '$.units') WHERE scans.id=? ORDER BY json_each.key LIMIT ? OFFSET ?`, id, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return page, err
		}
		var unit model.Unit
		if err := json.Unmarshal(raw, &unit); err != nil {
			return page, err
		}
		page.Items = append(page.Items, unit)
	}
	return page, rows.Err()
}

// RDAPCacheEntry is the normalized, deliberately non-sensitive representation
// kept for on-demand registry enrichment. Raw RDAP documents and contact
// details never enter this table.
type RDAPCacheEntry struct {
	Address    string
	Payload    []byte
	FetchedAt  time.Time
	ExpiresAt  time.Time
	StaleUntil time.Time
}

func normalizeRDAPAddress(raw string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "", errors.New("RDAP cache address must be a valid IP")
	}
	return ip.String(), nil
}

func (s *Store) GetRDAPCache(ctx context.Context, address string) (RDAPCacheEntry, error) {
	normalized, err := normalizeRDAPAddress(address)
	if err != nil {
		return RDAPCacheEntry{}, fmt.Errorf("%w: %s", ErrNotFound, strings.TrimSpace(address))
	}
	var entry RDAPCacheEntry
	var fetched, expires, stale string
	var payload []byte
	err = s.reader().QueryRowContext(ctx, `SELECT address,payload_json,fetched_at,expires_at,stale_until FROM rdap_cache WHERE address=?`, normalized).Scan(&entry.Address, &payload, &fetched, &expires, &stale)
	if errors.Is(err, sql.ErrNoRows) {
		return RDAPCacheEntry{}, fmt.Errorf("%w: RDAP cache %s", ErrNotFound, address)
	}
	if err != nil {
		return RDAPCacheEntry{}, err
	}
	entry.Payload = append([]byte(nil), payload...)
	entry.FetchedAt, entry.ExpiresAt, entry.StaleUntil = scanTime(fetched), scanTime(expires), scanTime(stale)
	return entry, nil
}

func (s *Store) PutRDAPCache(ctx context.Context, entry RDAPCacheEntry) error {
	address, err := normalizeRDAPAddress(entry.Address)
	if err != nil || len(entry.Payload) == 0 {
		return errors.New("RDAP cache entry is incomplete")
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO rdap_cache(address,payload_json,fetched_at,expires_at,stale_until) VALUES(?,?,?,?,?) ON CONFLICT(address) DO UPDATE SET payload_json=excluded.payload_json,fetched_at=excluded.fetched_at,expires_at=excluded.expires_at,stale_until=excluded.stale_until`, address, entry.Payload, entry.FetchedAt.UTC().Format(time.RFC3339Nano), entry.ExpiresAt.UTC().Format(time.RFC3339Nano), entry.StaleUntil.UTC().Format(time.RFC3339Nano))
	return err
}
