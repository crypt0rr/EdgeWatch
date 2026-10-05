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

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

// SaveScan stores a finished scan with its host indexes. It is the daemon's
// writer, and the caller does not name a tenant: the scan belongs to its
// job's tenant, or to the default tenant when it has no job ID, which the
// insert reads in the same transaction.
func (ss *SystemStore) SaveScan(ctx context.Context, scan model.Scan) error {
	// Keep the scan row and its derived host indexes in one transaction. The
	// host index is consumed as an authoritative projection by the web API, so
	// exposing a scan with only a prefix of its hosts would be worse than
	// rejecting the write and retrying it later.
	tx, err := ss.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if scan.JobID != "" {
		var purging int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM job_history_purges WHERE job_id=?)`, scan.JobID).Scan(&purging); err != nil {
			return err
		}
		if purging != 0 {
			return fmt.Errorf("%w: job %s", ErrNotFound, scan.JobID)
		}
	}
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
	// A cycle is marked completed before its merged scan is promoted.  Do not
	// reclaim the source checkpoints merely because an attempt row happens to
	// reference that cycle: timed-out/failed attempt rows are written before a
	// successful (or explicitly incomplete) final scan and must remain
	// recoverable across a crash in that window.
	_, err := tx.ExecContext(ctx, `UPDATE scan_cycle_units SET snapshot_json='{}' WHERE cycle_id=? AND EXISTS (SELECT 1 FROM scans WHERE scans.cycle_id=? AND scans.cycle_status='completed' AND scans.status IN ('success','incomplete'))`, cycleID, cycleID)
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
	// The scan belongs to its job's tenant, read in the same transaction.
	_, err = execer.ExecContext(ctx, `INSERT INTO scans(id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,changes_json,snapshot_json,tenant_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,`+jobTenantSQL+`)`,
		scan.ID, nullString(scan.JobID), nullInt64(scan.JobRevision), scan.Job, sqliteTimestamp(scan.StartedAt), sqliteTimestamp(scan.FinishedAt), scan.Status, scan.Error, scan.NmapVersion, scan.ScannerEngine, scan.ScannerProfileID, scan.ScannerProfileRevision, scan.NaabuVersion, scan.DiscoveryPorts, scan.ConfirmedPorts, scan.DiscoveryDurationMS, scan.EnrichmentDurationMS, scan.ConfigHash, scan.CycleID, scan.CycleAttempt, scan.CycleStatus, boolInt(scan.Resumable), scan.CompletedProbes, scan.TotalProbes, scan.CompletedUnits, scan.TotalUnits, scan.NoProgressTries, scan.BaselineScanID, scan.BaselineConfigHash, changesJSON, snapshot, scan.JobID)
	if err != nil {
		return err
	}
	return saveScanHostsExec(ctx, execer, scan)
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

const (
	maxHostSearchTextBytes = 64 * 1024
	// Leave room for the bounded current job name, which the SQLite FTS
	// triggers append separately so a job rename remains searchable.
	maxHostSearchJobBytes = config.MaxJobNameRunes * 4
)

// hostSearchContent is deliberately built from a bounded, prioritized set of
// fields that the host inventory promises to search. Identity and target
// fields are retained first, followed by distinct service names and products
// before verbose details and port numbers. This lets a distinctive service
// late in a large port list remain searchable without copying serialized
// evidence or growing FTS writes without bound.
func hostSearchContent(_ string, host model.HostObservation) string {
	var builder strings.Builder
	seen := make(map[string]struct{})
	contentLimit := maxHostSearchTextBytes - maxHostSearchJobBytes - 1
	appendValues := func(values []string, maxBytes int) {
		for _, raw := range values {
			value := strings.ToLower(strings.TrimSpace(raw))
			if value == "" {
				continue
			}
			if _, exists := seen[value]; exists {
				continue
			}
			if builder.Len()+len(value)+1 > maxBytes {
				continue
			}
			seen[value] = struct{}{}
			builder.WriteString(value)
			builder.WriteByte(' ')
		}
	}
	appendValues([]string{host.Address}, contentLimit)
	var targetValues []string
	for _, target := range host.SourceTargets {
		targetValues = append(targetValues, target)
	}
	for _, name := range host.DNSNames {
		targetValues = append(targetValues, name)
	}
	for _, hostname := range host.Hostnames {
		targetValues = append(targetValues, hostname.Name)
	}
	// Keep numerous target metadata values from consuming the budget intended
	// for searchable service identifiers.
	appendValues(targetValues, min(contentLimit, builder.Len()+8*1024))
	var serviceNames, serviceProducts, serviceDetails, portNumbers []string
	for _, protocol := range host.Protocols {
		for _, port := range protocol.Ports {
			portNumbers = append(portNumbers, strconv.Itoa(port.Port))
			if port.Service == nil {
				continue
			}
			service := port.Service
			serviceNames = append(serviceNames, service.Name)
			serviceProducts = append(serviceProducts, service.Product)
			serviceDetails = append(serviceDetails, service.Version, service.ExtraInfo, service.OSType, service.DeviceType)
			serviceDetails = append(serviceDetails, service.CPEs...)
		}
	}
	appendValues(serviceNames, contentLimit)
	appendValues(serviceProducts, contentLimit)
	appendValues(serviceDetails, contentLimit)
	appendValues(portNumbers, contentLimit)
	return strings.TrimSpace(builder.String())
}

// upsertLatestScanHostExec maintains the exact latest successful observation
// for one effective address of the scan's tenant. The finished-at/id ordering
// mirrors the historical ranking query, including deterministic ties between
// scans with equal times. The tenant is read from the scan row, which the
// caller has written in the same transaction.
func upsertLatestScanHostExec(ctx context.Context, execer contextExecer, scan model.Scan, address, addressFamily string, sourceTargets, dnsNames, hostJSON []byte, searchText string, open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered int) error {
	finishedAt := sqliteTimestamp(scan.FinishedAt)
	_, err := execer.ExecContext(ctx, `INSERT INTO latest_scan_hosts(tenant_id,address,scan_id,job_id,job,finished_at,data_quality,address_family,source_targets_json,dns_names_json,host_json,search_text,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports)
VALUES((SELECT tenant_id FROM scans WHERE id=?),?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(tenant_id,address) DO UPDATE SET
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
		scan.ID, address, scan.ID, scan.JobID, scan.Job, finishedAt, "detailed", addressFamily, sourceTargets, dnsNames, hostJSON, searchText, open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered)
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

// scanNotFound reports a scan that the tenant does not have. An unknown ID
// and a scan of another tenant give the same error, so a caller cannot tell
// them apart.
func scanNotFound(id string) error {
	return fmt.Errorf("%w: scan %s", ErrNotFound, id)
}

// ListScanHostsPage reads indexed effective hosts for one of the tenant's
// scans; a scan of another tenant has none. The SQL predicates run before
// LIMIT/OFFSET, so a page request never needs to load unrelated host
// payloads into Go.
func (ts *TenantStore) ListScanHostsPage(ctx context.Context, scanID, query, protocol string, hasOpen *bool, limit, offset int) (Page[ScanHost], error) {
	if err := ts.ready(); err != nil {
		return Page[ScanHost]{}, err
	}
	query = strings.TrimSpace(query)
	if err := ValidateHostSearchQuery(query); err != nil {
		return Page[ScanHost]{}, err
	}
	queries := scanHostsPageQueries(ts.scope.id, scanID, query, protocol, hasOpen, limit, offset)
	var page Page[ScanHost]
	reader := ts.store.reader()
	if err := reader.QueryRowContext(ctx, queries.countSQL, queries.countArg...).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := reader.QueryContext(ctx, queries.pageSQL, queries.pageArg...)
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

// ScanHostIndexExists reports whether one of the tenant's scans has the
// incremental host index; a scan of another tenant has none. It is separate
// from a filtered page's Total: a valid indexed scan can have zero matches
// for a particular query and must not fall back to decoding its complete
// snapshot.
func (ts *TenantStore) ScanHostIndexExists(ctx context.Context, scanID string) (bool, error) {
	if err := ts.ready(); err != nil {
		return false, err
	}
	var exists bool
	err := ts.store.reader().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM scan_hosts h JOIN scans s ON s.id=h.scan_id AND s.tenant_id=? WHERE h.scan_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=s.tenant_id AND purge.job_id=s.job_id))`, ts.scope.id, scanID).Scan(&exists)
	return exists, err
}

// SuccessfulScanHostIndexExists is the tenant-wide equivalent used by the
// Hosts view to distinguish an indexed history (including a zero-match
// filter) from a wholly legacy one. Only the tenant's scans count.
func (ts *TenantStore) SuccessfulScanHostIndexExists(ctx context.Context) (bool, error) {
	if err := ts.ready(); err != nil {
		return false, err
	}
	var exists bool
	err := ts.store.reader().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM scan_hosts h JOIN scans s ON s.id=h.scan_id WHERE s.tenant_id=? AND s.status='success' AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=s.tenant_id AND purge.job_id=s.job_id))`, ts.scope.id).Scan(&exists)
	return exists, err
}

// GetScanHost returns one indexed effective host of the tenant's scan, or
// ErrNotFound when the scan predates the host index, the address was not
// part of that scan, or the scan belongs to another tenant.
func (ts *TenantStore) GetScanHost(ctx context.Context, scanID, address string) (ScanHost, error) {
	if err := ts.ready(); err != nil {
		return ScanHost{}, err
	}
	normalized, err := normalizeStoredHostAddress(address)
	if err != nil {
		return ScanHost{}, fmt.Errorf("%w: host %s", ErrNotFound, address)
	}
	var dataQuality string
	var raw []byte
	err = ts.store.reader().QueryRowContext(ctx, `SELECT h.data_quality,h.host_json FROM scan_hosts h JOIN scans s ON s.id=h.scan_id AND s.tenant_id=? WHERE h.scan_id=? AND h.address=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=s.tenant_id AND purge.job_id=s.job_id)`, ts.scope.id, scanID, normalized).Scan(&dataQuality, &raw)
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

// ListLatestScanHostsPage returns the maintained newest successful
// observation for each effective address across all jobs of the tenant.
// Another tenant's observation of the same address is a row of its own and
// never matches. The projection is updated in the same transaction as a
// successful scan and rebuilt after retention deletes.
func (ts *TenantStore) ListLatestScanHostsPage(ctx context.Context, query, protocol string, hasOpen *bool, limit, offset int) (Page[LatestScanHost], error) {
	if err := ts.ready(); err != nil {
		return Page[LatestScanHost]{}, err
	}
	query = strings.TrimSpace(query)
	if err := ValidateHostSearchQuery(query); err != nil {
		return Page[LatestScanHost]{}, err
	}
	queries := latestScanHostsPageQueries(ts.scope.id, query, protocol, hasOpen, limit, offset)
	var page Page[LatestScanHost]
	reader := ts.store.reader()
	if err := reader.QueryRowContext(ctx, queries.countSQL, queries.countArg...).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := reader.QueryContext(ctx, queries.pageSQL, queries.pageArg...)
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

// ListLatestScanHosts returns the tenant's complete maintained projection.
// It is used only when the tenant's history still contains legacy successful
// snapshots that cannot be represented by latest_scan_hosts; the normal Hosts
// endpoint stays on the filtered, paginated query above.
func (ts *TenantStore) ListLatestScanHosts(ctx context.Context) ([]LatestScanHost, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	const pageSize = 1000
	var result []LatestScanHost
	for offset := 0; ; offset += pageSize {
		page, err := ts.ListLatestScanHostsPage(ctx, "", "", nil, pageSize, offset)
		if err != nil {
			return nil, err
		}
		result = append(result, page.Items...)
		if len(page.Items) == 0 || offset+len(page.Items) >= page.Total {
			return result, nil
		}
	}
}

// LegacySuccessfulScanExists reports whether at least one of the tenant's
// successful scans has no derived host index or completed backfill
// checkpoint. Such rows are expected in databases upgraded from a release
// predating scan_hosts and require the bounded compatibility merge in the
// Hosts endpoint.
func (ts *TenantStore) LegacySuccessfulScanExists(ctx context.Context) (bool, error) {
	if err := ts.ready(); err != nil {
		return false, err
	}
	var exists bool
	err := ts.store.reader().QueryRowContext(ctx, `SELECT EXISTS(
	SELECT 1 FROM scans s
	WHERE s.tenant_id=? AND s.status='success'
	  AND NOT EXISTS (SELECT 1 FROM scan_hosts h WHERE h.scan_id=s.id)
	  AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=s.tenant_id AND purge.job_id=s.job_id)
	  AND NOT EXISTS (SELECT 1 FROM legacy_scan_host_backfill b WHERE b.scan_id=s.id)
)`, ts.scope.id).Scan(&exists)
	return exists, err
}

// GetScan returns one of the tenant's scans with its snapshot and change
// list. A scan of another tenant is ErrNotFound, like an unknown ID.
func (ts *TenantStore) GetScan(ctx context.Context, id string) (model.Scan, error) {
	if err := ts.ready(); err != nil {
		return model.Scan{}, err
	}
	var v model.Scan
	var started, finished string
	var snapshot, changesJSON []byte
	var baselineScanID, baselineConfigHash string
	var jobID sql.NullString
	var revision sql.NullInt64
	var resumable int
	readDB := ts.store.reader()
	err := readDB.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,changes_json,snapshot_json FROM scans WHERE id=? AND tenant_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=scans.tenant_id AND purge.job_id=scans.job_id)`, id, ts.scope.id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &baselineScanID, &baselineConfigHash, &changesJSON, &snapshot)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Scan{}, scanNotFound(id)
	}
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
	return v, nil
}

// GetScanSummary returns the metadata of one of the tenant's scans without
// reading either the snapshot or the serialized change list. History/detail
// views use this method so a broad scan cannot cause a hidden full-result
// allocation. A scan of another tenant is ErrNotFound, like an unknown ID.
func (ts *TenantStore) GetScanSummary(ctx context.Context, id string) (model.ScanSummary, error) {
	if err := ts.ready(); err != nil {
		return model.ScanSummary{}, err
	}
	var v model.ScanSummary
	var started, finished string
	var jobID sql.NullString
	var revision sql.NullInt64
	var resumable int
	readDB := ts.store.reader()
	err := readDB.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash FROM scans WHERE id=? AND tenant_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=scans.tenant_id AND purge.job_id=scans.job_id)`, id, ts.scope.id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &v.BaselineScanID, &v.BaselineConfigHash)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ScanSummary{}, scanNotFound(id)
	}
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
	v.TenantID = ts.scope.id
	return v, nil
}

// GetLatestSuccessfulJobScanSummary returns the newest fully successful scan
// of one of the tenant's jobs without loading its snapshot or change payload.
// The ordering is deterministic for scans that finish at the same instant
// and is backed by the scans_job_id_time index. A job with no successful
// scan, or a job of another tenant, returns a nil summary and a nil error.
// The tenant predicate is on the job, as jobScansPageQueries explains.
func (ts *TenantStore) GetLatestSuccessfulJobScanSummary(ctx context.Context, jobID string) (*model.ScanSummary, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	var v model.ScanSummary
	var started, finished string
	var jid sql.NullString
	var revision sql.NullInt64
	var resumable int
	err := ts.store.reader().QueryRowContext(ctx, `SELECT s.id,s.job_id,s.job_revision,s.job,s.started_at,s.finished_at,s.status,s.error,s.nmap_version,s.scanner_engine,s.scanner_profile_id,s.scanner_profile_revision,s.naabu_version,s.discovery_ports,s.confirmed_ports,s.discovery_duration_ms,s.enrichment_duration_ms,s.config_hash,s.cycle_id,s.cycle_attempt,s.cycle_status,s.resumable,s.completed_probes,s.total_probes,s.completed_units,s.total_units,s.no_progress_attempts,s.baseline_scan_id,s.baseline_config_hash FROM scans s JOIN jobs j ON j.id=s.job_id AND j.tenant_id=? WHERE s.job_id=? AND s.status='success' AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=s.tenant_id AND purge.job_id=s.job_id) ORDER BY s.finished_at DESC,s.id DESC LIMIT 1`, ts.scope.id, jobID).
		Scan(&v.ID, &jid, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &v.BaselineScanID, &v.BaselineConfigHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if jid.Valid {
		v.JobID = jid.String
	}
	if revision.Valid {
		v.JobRevision = revision.Int64
	}
	v.Resumable = resumable != 0
	v.StartedAt, v.FinishedAt = scanTime(started), scanTime(finished)
	v.TenantID = ts.scope.id
	return &v, nil
}

// GetScanComparison returns the metadata and the immutable scan-time change
// list of one of the tenant's scans without loading snapshot_json. Legacy
// rows without a scan-time comparison can be resolved through GetScan when
// callers need to recreate their historical diff against the then-current
// baseline behavior. A scan of another tenant is ErrNotFound, like an
// unknown ID.
func (ts *TenantStore) GetScanComparison(ctx context.Context, id string) (model.ScanSummary, []model.Change, error) {
	if err := ts.ready(); err != nil {
		return model.ScanSummary{}, nil, err
	}
	var v model.ScanSummary
	var started, finished string
	var changesJSON []byte
	var jobID sql.NullString
	var revision sql.NullInt64
	var resumable int
	readDB := ts.store.reader()
	err := readDB.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,changes_json FROM scans WHERE id=? AND tenant_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=scans.tenant_id AND purge.job_id=scans.job_id)`, id, ts.scope.id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &v.BaselineScanID, &v.BaselineConfigHash, &changesJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ScanSummary{}, nil, scanNotFound(id)
	}
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
	v.TenantID = ts.scope.id
	var changes []model.Change
	if len(changesJSON) > 0 && string(changesJSON) != "null" {
		if err := json.Unmarshal(changesJSON, &changes); err != nil {
			return v, nil, err
		}
	}
	return v, changes, nil
}

// ListScanChangesPage reads only one page of the immutable scan-time diff of
// one of the tenant's scans; a scan of another tenant has no changes.
// Changes are stored as a JSON array for backwards-compatible scan records;
// SQLite's json_each keeps pagination in the database so the web handler does
// not deserialize the entire change list merely to return the first page.
// Legacy rows with a NULL/empty array naturally return an empty page and are
// handled by the caller's explicit compatibility path.
func (ts *TenantStore) ListScanChangesPage(ctx context.Context, id string, limit, offset int) (Page[model.Change], error) {
	if err := ts.ready(); err != nil {
		return Page[model.Change]{}, err
	}
	limit, offset = normalizePage(limit, offset)
	var page Page[model.Change]
	readDB := ts.store.reader()
	if err := readDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans, json_each(scans.changes_json) WHERE scans.id=? AND scans.tenant_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=scans.tenant_id AND purge.job_id=scans.job_id)`, id, ts.scope.id).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := readDB.QueryContext(ctx, `SELECT json_each.value FROM scans, json_each(scans.changes_json) WHERE scans.id=? AND scans.tenant_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=scans.tenant_id AND purge.job_id=scans.job_id) ORDER BY json_each.key LIMIT ? OFFSET ?`, id, ts.scope.id, limit, offset)
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

// ListScanResultsPage reads one page of snapshot units of one of the
// tenant's scans directly from the persisted JSON document; a scan of
// another tenant has no units. The explicit results endpoint can therefore
// show a broad scan incrementally without first materializing every host in
// Go.
func (ts *TenantStore) ListScanResultsPage(ctx context.Context, id string, limit, offset int) (Page[model.Unit], error) {
	if err := ts.ready(); err != nil {
		return Page[model.Unit]{}, err
	}
	limit, offset = normalizePage(limit, offset)
	var page Page[model.Unit]
	readDB := ts.store.reader()
	// json_each emits a single SQL NULL row for a JSON null value. Treat a
	// missing/null units member as an empty array so failed or legacy scans do
	// not produce a row that cannot be decoded as model.Unit.
	if err := readDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans, json_each(scans.snapshot_json, '$.units') WHERE scans.id=? AND scans.tenant_id=? AND json_type(scans.snapshot_json, '$.units')='array' AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=scans.tenant_id AND purge.job_id=scans.job_id)`, id, ts.scope.id).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := readDB.QueryContext(ctx, `SELECT json_each.value FROM scans, json_each(scans.snapshot_json, '$.units') WHERE scans.id=? AND scans.tenant_id=? AND json_type(scans.snapshot_json, '$.units')='array' AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=scans.tenant_id AND purge.job_id=scans.job_id) ORDER BY json_each.key LIMIT ? OFFSET ?`, id, ts.scope.id, limit, offset)
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

// GetRDAPCache returns the cached registry data of an address. The cache is
// shared by every tenant: it holds only public registry data about an
// address, never whether or when a tenant observed it. The web routes look
// an address up only after a scan or baseline read of the request's tenant,
// or the public status page's published hosts, has found it.
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
	_, err = s.DB.ExecContext(ctx, `INSERT INTO rdap_cache(address,payload_json,fetched_at,expires_at,stale_until) VALUES(?,?,?,?,?) ON CONFLICT(address) DO UPDATE SET payload_json=excluded.payload_json,fetched_at=excluded.fetched_at,expires_at=excluded.expires_at,stale_until=excluded.stale_until`, address, entry.Payload, sqliteTimestamp(entry.FetchedAt), sqliteTimestamp(entry.ExpiresAt), sqliteTimestamp(entry.StaleUntil))
	return err
}
