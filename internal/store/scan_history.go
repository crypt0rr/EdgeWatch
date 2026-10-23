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
	tx, err := beginWriteTx(ctx, ss.store.DB)
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

func saveScanExec(ctx context.Context, tx *sql.Tx, scan model.Scan) error {
	snapshot, err := json.Marshal(scan.Snapshot)
	if err != nil {
		return err
	}
	results, coverage, err := marshalScanEvidenceProjections(scan.Snapshot)
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
	// The insert returns it, so the host rows take it from here rather than
	// from the scan row, which stores it after the snapshot.
	var tenantID string
	err = tx.QueryRowContext(ctx, `INSERT INTO scans(id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,comparison,changes_json,snapshot_json,results_json,results_unit_count,coverage_summary_json,tenant_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,`+jobTenantSQL+`) RETURNING tenant_id`,
		scan.ID, nullString(scan.JobID), nullInt64(scan.JobRevision), scan.Job, sqliteTimestamp(scan.StartedAt), sqliteTimestamp(scan.FinishedAt), scan.Status, scan.Error, scan.NmapVersion, scan.ScannerEngine, scan.ScannerProfileID, scan.ScannerProfileRevision, scan.NaabuVersion, scan.DiscoveryPorts, scan.ConfirmedPorts, scan.DiscoveryDurationMS, scan.EnrichmentDurationMS, scan.ConfigHash, scan.CycleID, scan.CycleAttempt, scan.CycleStatus, boolInt(scan.Resumable), scan.CompletedProbes, scan.TotalProbes, scan.CompletedUnits, scan.TotalUnits, scan.NoProgressTries, scan.BaselineScanID, scan.BaselineConfigHash, scan.Comparison, changesJSON, snapshot, results, len(scan.Snapshot.Units), coverage, scan.JobID).Scan(&tenantID)
	if err != nil {
		return err
	}
	return saveScanHostsExec(ctx, tx, scan, tenantID)
}

// marshalScanEvidenceProjections keeps frequently requested projections
// separate from the immutable full snapshot. Results pages need only units,
// while Inbox recovery classification needs status and scope metadata without
// service evidence or port inventories.
func marshalScanEvidenceProjections(snapshot model.Snapshot) ([]byte, []byte, error) {
	units := snapshot.Units
	if units == nil {
		units = []model.Unit{}
	}
	results, err := json.Marshal(units)
	if err != nil {
		return nil, nil, err
	}
	coverage := model.Snapshot{
		Scopes:         append([]model.Scope(nil), snapshot.Scopes...),
		TargetFailures: append([]model.TargetCoverageFailure(nil), snapshot.TargetFailures...),
		HostStates:     append([]model.HostState(nil), snapshot.HostStates...),
		Hosts:          make([]model.HostObservation, 0, len(snapshot.Hosts)),
	}
	for _, host := range snapshot.Hosts {
		projected := model.HostObservation{
			Address:       host.Address,
			SourceTargets: append([]string(nil), host.SourceTargets...),
			DNSNames:      append([]string(nil), host.DNSNames...),
			Status:        host.Status,
			StatusReason:  host.StatusReason,
			Protocols:     make([]model.ProtocolObservation, 0, len(host.Protocols)),
		}
		for _, protocol := range host.Protocols {
			projected.Protocols = append(projected.Protocols, model.ProtocolObservation{
				Protocol:       protocol.Protocol,
				Status:         protocol.Status,
				StatusReason:   protocol.StatusReason,
				DiscoveryState: protocol.DiscoveryState,
			})
		}
		coverage.Hosts = append(coverage.Hosts, projected)
	}
	encodedCoverage, err := json.Marshal(coverage)
	if err != nil {
		return nil, nil, err
	}
	return results, encodedCoverage, nil
}

// saveScanHostsExec writes the host rows of a scan that the transaction has
// just saved for the tenant. A successful scan without a host row is one
// that the legacy host backfill looks for. When its snapshot holds nothing
// that the backfill could index, it gets the backfill's checkpoint now, so
// the backfill's completion marker, which lets the Hosts view and the
// daemon start skip that search, stays accurate. A snapshot of units
// without host observations, as releases before scan_hosts recorded, is
// left to the backfill and the compatibility readers, and the marker goes
// back to pending until the next start indexes it.
func saveScanHostsExec(ctx context.Context, tx *sql.Tx, scan model.Scan, tenantID string) error {
	written, err := writeScanHostsExec(ctx, tx, scan, tenantID)
	if err != nil || written > 0 || scan.Status != "success" {
		return err
	}
	for _, host := range legacyHostObservations(scan.Snapshot) {
		if net.ParseIP(strings.TrimSpace(host.Address)) != nil {
			return markLegacyScanHostIndexPendingTx(ctx, tx)
		}
	}
	return checkpointLegacyScanTx(ctx, tx, scan.ID)
}

// writeScanHostsExec writes a host row for each host of the scan with a
// valid address, and for a successful scan the tenant's latest observation
// of that address, and returns how many host rows it wrote.
func writeScanHostsExec(ctx context.Context, tx *sql.Tx, scan model.Scan, tenantID string) (int, error) {
	if len(scan.Snapshot.Hosts) == 0 {
		return 0, nil
	}
	insertStmt, err := tx.PrepareContext(ctx, `INSERT INTO scan_hosts(scan_id,address,job,address_family,source_targets_json,dns_names_json,host_json,search_text,data_quality,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer insertStmt.Close()
	var latestStmt *sql.Stmt
	if scan.Status == "success" {
		latestStmt, err = tx.PrepareContext(ctx, upsertLatestScanHostSQL)
		if err != nil {
			return 0, err
		}
		defer latestStmt.Close()
	}
	// Normalize a copy so the indexed payload has stable ordering without
	// mutating the immutable snapshot that the caller may still hold.
	hosts := append([]model.HostObservation(nil), scan.Snapshot.Hosts...)
	hostSnapshot := model.Snapshot{Hosts: hosts}
	hostSnapshot.Normalize()
	written := 0
	for _, host := range hostSnapshot.Hosts {
		address := strings.TrimSpace(host.Address)
		if net.ParseIP(address) == nil {
			continue
		}
		hostJSON, err := json.Marshal(host)
		if err != nil {
			return written, err
		}
		sourceTargets, err := json.Marshal(host.SourceTargets)
		if err != nil {
			return written, err
		}
		dnsNames, err := json.Marshal(host.DNSNames)
		if err != nil {
			return written, err
		}
		searchText := hostSearchContent(scan.Job, host)
		open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered := scanHostStats(host)
		if _, err := insertStmt.ExecContext(ctx,
			scan.ID, address, scan.Job, host.AddressFamily, sourceTargets, dnsNames, hostJSON, searchText, "detailed", open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered); err != nil {
			return written, err
		}
		written++
		if latestStmt != nil {
			if err := upsertLatestScanHostExec(ctx, latestStmt, scan, tenantID, address, host.AddressFamily, sourceTargets, dnsNames, hostJSON, searchText, open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered); err != nil {
				return written, err
			}
		}
	}
	return written, nil
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

// upsertLatestScanHostSQL writes the tenant's latest successful observation
// of an address, in the argument order of upsertLatestScanHostExec. The
// tenant is an argument: reading it from the scan row for each host would
// read the scan's snapshot each time, which made finalizing a broad scan
// grow with the square of its hosts. The plan test explains it verbatim.
const upsertLatestScanHostSQL = `INSERT INTO latest_scan_hosts(tenant_id,address,scan_id,job_id,job,finished_at,data_quality,address_family,source_targets_json,dns_names_json,host_json,search_text,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
   OR (excluded.finished_at = latest_scan_hosts.finished_at AND excluded.scan_id > latest_scan_hosts.scan_id)`

// upsertLatestScanHostExec maintains the exact latest successful observation
// for one effective address of the scan's tenant. The finished-at/id ordering
// mirrors the historical ranking query, including deterministic ties between
// scans with equal times. The caller passes the tenant of the scan row that
// it has written in the same transaction, as upsertLatestScanHostSQL
// explains. The guard trigger still refuses a tenant that is not the scan's.
func upsertLatestScanHostExec(ctx context.Context, stmt *sql.Stmt, scan model.Scan, tenantID, address, addressFamily string, sourceTargets, dnsNames, hostJSON []byte, searchText string, open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered int) error {
	finishedAt := sqliteTimestamp(scan.FinishedAt)
	_, err := stmt.ExecContext(ctx,
		tenantID, address, scan.ID, scan.JobID, scan.Job, finishedAt, "detailed", addressFamily, sourceTargets, dnsNames, hostJSON, searchText, open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered)
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
// observation for each effective address across all jobs of the tenant:
// the hosts of jobs that are not archived first, then those of archived
// jobs, each by address. Another tenant's observation of the same address is
// a row of its own and never matches. The projection is updated in the same
// transaction as a successful scan and rebuilt after retention deletes.
func (ts *TenantStore) ListLatestScanHostsPage(ctx context.Context, query, protocol string, hasOpen *bool, limit, offset int) (Page[LatestScanHost], error) {
	if err := ts.ready(); err != nil {
		return Page[LatestScanHost]{}, err
	}
	query = strings.TrimSpace(query)
	if err := ValidateHostSearchQuery(query); err != nil {
		return Page[LatestScanHost]{}, err
	}
	limit, offset = normalizePage(limit, offset)
	queries := latestScanHostsPageQueries(ts.scope.id, query, protocol, hasOpen)
	var page Page[LatestScanHost]
	var current int
	if err := ts.store.reader().QueryRowContext(ctx, queries.countSQL, queries.countArg...).Scan(&page.Total, &current); err != nil {
		return page, err
	}
	// The page starts in the segment of jobs that are not archived and
	// continues into the archived one when it reaches its end.
	if offset < current {
		items, err := ts.latestScanHostSegment(ctx, queries, false, limit, offset)
		if err != nil {
			return page, err
		}
		page.Items = items
		limit -= len(items)
		offset = current
	}
	if limit > 0 && offset < page.Total {
		items, err := ts.latestScanHostSegment(ctx, queries, true, limit, offset-current)
		if err != nil {
			return page, err
		}
		page.Items = append(page.Items, items...)
	}
	return page, nil
}

// ListLatestScanHosts returns the tenant's complete maintained projection.
// It is used only when the tenant's history still contains legacy successful
// snapshots that cannot be represented by latest_scan_hosts; the normal Hosts
// endpoint stays on the filtered, paginated query above. Each segment is
// read once, in index order.
func (ts *TenantStore) ListLatestScanHosts(ctx context.Context) ([]LatestScanHost, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	queries := latestScanHostsPageQueries(ts.scope.id, "", "", nil)
	var result []LatestScanHost
	for _, archived := range []bool{false, true} {
		items, err := ts.latestScanHostSegment(ctx, queries, archived, -1, 0)
		if err != nil {
			return nil, err
		}
		result = append(result, items...)
	}
	return result, nil
}

// latestScanHostSegment reads limit hosts from offset of one segment of the
// tenant's host inventory; a negative limit reads the rest of it.
func (ts *TenantStore) latestScanHostSegment(ctx context.Context, queries latestHostPageQueries, archived bool, limit, offset int) ([]LatestScanHost, error) {
	statement, args := queries.segment(archived, limit, offset)
	rows, err := ts.store.reader().QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []LatestScanHost
	for rows.Next() {
		var scanID, address, dataQuality, job, finished string
		var jobID sql.NullString
		var archived int
		var raw []byte
		if err := rows.Scan(&scanID, &address, &dataQuality, &raw, &jobID, &job, &finished, &archived); err != nil {
			return nil, err
		}
		item, err := decodeScanHost(address, dataQuality, raw)
		if err != nil {
			return nil, err
		}
		items = append(items, LatestScanHost{ScanHost: ScanHost{ScanID: scanID, DataQuality: dataQuality, Host: item.Host}, JobID: jobID.String, Job: job, Archived: archived != 0, ScannedAt: scanTime(finished)})
	}
	return items, rows.Err()
}

// LegacySuccessfulScanExists reports whether at least one of the tenant's
// successful scans has no derived host index or completed backfill
// checkpoint. Such rows are expected in databases upgraded from a release
// predating scan_hosts and require the bounded compatibility merge in the
// Hosts endpoint. It reads the scans that the legacy host backfill indexes
// (legacyHostBackfillCandidateSQL), so a tenant that is being deleted, whose
// purge erases its host rows before its scans, has none. Once the legacy
// host backfill has completed, no such scan is left, and the answer comes
// from its marker: the search would otherwise read every successful scan of
// the tenant on each Hosts request.
func (ts *TenantStore) LegacySuccessfulScanExists(ctx context.Context) (bool, error) {
	if err := ts.ready(); err != nil {
		return false, err
	}
	reader := ts.store.reader()
	if complete, err := legacyScanHostIndexComplete(ctx, reader); err != nil || complete {
		return false, err
	}
	var exists bool
	err := reader.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM scans s WHERE s.tenant_id=? AND `+legacyHostBackfillCandidateSQL+`)`, ts.scope.id).Scan(&exists)
	return exists, err
}

// GetScan returns one of the tenant's scans with its snapshot and change
// list. A scan of another tenant is ErrNotFound, like an unknown ID.
func (ts *TenantStore) GetScan(ctx context.Context, id string) (model.Scan, error) {
	if err := ts.ready(); err != nil {
		return model.Scan{}, err
	}
	var row fullScanRow
	var snapshot, changesJSON []byte
	err := ts.store.reader().QueryRowContext(ctx, fullScanQuery, id, ts.scope.id).Scan(row.dest(&changesJSON, &snapshot)...)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Scan{}, scanNotFound(id)
	}
	v := row.scan()
	if err != nil {
		return v, err
	}
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

// WithScanDocument calls fn with one of the tenant's scans and the JSON of
// its snapshot and change list as they were saved. The scan passed to fn has
// neither a snapshot nor changes. The two JSON values are the driver's copy
// of the stored columns and are valid only while fn runs, so a large
// snapshot is held in memory once and can be written out without being
// decoded. A scan of another tenant is ErrNotFound, like an unknown ID, and
// fn is not called.
func (ts *TenantStore) WithScanDocument(ctx context.Context, id string, fn func(scan model.Scan, snapshot, changes []byte) error) error {
	if err := ts.ready(); err != nil {
		return err
	}
	rows, err := ts.store.reader().QueryContext(ctx, fullScanQuery, id, ts.scope.id)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return scanNotFound(id)
	}
	var row fullScanRow
	var snapshot, changes sql.RawBytes
	if err := rows.Scan(row.dest(&changes, &snapshot)...); err != nil {
		return err
	}
	if err := fn(row.scan(), snapshot, changes); err != nil {
		return err
	}
	return rows.Close()
}

// fullScanQuery reads one of the tenant's scans with its stored change list
// and snapshot, in the column order of fullScanRow.dest.
const fullScanQuery = `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,comparison,changes_json,snapshot_json FROM scans WHERE id=? AND tenant_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=scans.tenant_id AND purge.job_id=scans.job_id)`

// fullScanRow receives the metadata columns of fullScanQuery.
type fullScanRow struct {
	v                  model.Scan
	started, finished  string
	baselineScanID     string
	baselineConfigHash string
	jobID              sql.NullString
	revision           sql.NullInt64
	resumable          int
}

// dest returns the scan destinations of fullScanQuery, with changes and
// snapshot for its last two columns.
func (row *fullScanRow) dest(changes, snapshot any) []any {
	v := &row.v
	return []any{&v.ID, &row.jobID, &row.revision, &v.Job, &row.started, &row.finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &row.resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &row.baselineScanID, &row.baselineConfigHash, &v.Comparison, changes, snapshot}
}

// scan returns the scanned metadata as a scan without snapshot or changes.
func (row *fullScanRow) scan() model.Scan {
	v := row.v
	if row.jobID.Valid {
		v.JobID = row.jobID.String
	}
	if row.revision.Valid {
		v.JobRevision = row.revision.Int64
	}
	v.Resumable = row.resumable != 0
	v.StartedAt, _ = time.Parse(time.RFC3339Nano, row.started)
	v.FinishedAt, _ = time.Parse(time.RFC3339Nano, row.finished)
	v.BaselineScanID, v.BaselineConfigHash = row.baselineScanID, row.baselineConfigHash
	return v
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
	err := readDB.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,comparison FROM scans WHERE id=? AND tenant_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=scans.tenant_id AND purge.job_id=scans.job_id)`, id, ts.scope.id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &v.BaselineScanID, &v.BaselineConfigHash, &v.Comparison)
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
// and is backed by the scans_job_id_history index, which also holds each
// scan's outcome. A job with no successful scan, or a job of another tenant,
// returns a nil summary and a nil error. The tenant predicate is on the job,
// as jobScansFromSQL explains.
func (ts *TenantStore) GetLatestSuccessfulJobScanSummary(ctx context.Context, jobID string) (*model.ScanSummary, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	var v model.ScanSummary
	var started, finished string
	var jid sql.NullString
	var revision sql.NullInt64
	var resumable int
	err := ts.store.reader().QueryRowContext(ctx, `SELECT `+scanSummaryColumnsSQL+jobScansFromSQL+` AND s.status='success' ORDER BY s.finished_at DESC,s.id DESC LIMIT 1`, ts.scope.id, jobID).
		Scan(&v.ID, &jid, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &v.BaselineScanID, &v.BaselineConfigHash, &v.Comparison)
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

// JobScanStatusSummary is the bounded execution metadata shown in the Jobs
// list. It deliberately omits scan errors, comparison payloads, and snapshots.
type JobScanStatusSummary struct {
	ID          string
	Status      string
	StartedAt   time.Time
	FinishedAt  time.Time
	ConfigHash  string
	CycleID     string
	CycleStatus string
	Resumable   bool
}

// JobExecutionSummary keeps the latest attempt separate from the latest
// successful scan. Either pointer is nil when that job has no matching scan.
type JobExecutionSummary struct {
	LatestAttempt        *JobScanStatusSummary
	LatestSuccessfulScan *JobScanStatusSummary
}

// recoveredCycleFailureSQL matches a failed candidate scan of
// jobExecutionSummariesSQL that a recovered cycle superseded: a failed row
// that claims its cycle completed, of a cycle that has a promoted scan by the
// rule of scanCycleHasScanQuery. When a completed cycle's finalization fails,
// its fallback row finishes when finalization gave up, and the run that
// recovers the cycle records the promoted scan at the cycle's own, earlier
// finish time; ordered by finish time alone, the superseded failure would
// stay the job's latest attempt.
//
// scans_job_id_history holds the candidate's status and rowid, so a
// candidate that did not fail never reads its scan row. The cycle columns
// are stored after the snapshot, so a failed candidate reads its own row, by
// rowid, and the promotion check reads only scans_cycle_outcome.
const recoveredCycleFailureSQL = `SELECT 1 FROM scans AS fallback
 JOIN scans AS promoted ON promoted.cycle_id=fallback.cycle_id AND promoted.cycle_status='completed' AND promoted.status IN ('success','incomplete') AND promoted.tenant_id=fallback.tenant_id
 WHERE fallback.rowid=candidate.rowid AND fallback.tenant_id=candidate.tenant_id AND fallback.cycle_id<>'' AND fallback.cycle_status='completed'`

// jobExecutionSummariesSQL selects each visible job's latest attempt and
// latest successful scan. The latest attempt is the newest scan by finish
// time, skipping a failed fallback row whose cycle a later run recovered and
// promoted (recoveredCycleFailureSQL): the promoted scan supersedes it, even
// though it records the cycle's earlier finish time.
const jobExecutionSummariesSQL = `SELECT j.id,
 attempt.id,attempt.status,attempt.started_at,attempt.finished_at,attempt.config_hash,attempt.cycle_id,attempt.cycle_status,attempt.resumable,
 successful.id,successful.status,successful.started_at,successful.finished_at,successful.config_hash
FROM jobs AS j
LEFT JOIN scans AS attempt ON attempt.id=(
 SELECT candidate.id FROM scans AS candidate
 WHERE candidate.tenant_id=j.tenant_id AND candidate.job_id=j.id
 AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id)
 AND (candidate.status<>'failed' OR NOT EXISTS (` + recoveredCycleFailureSQL + `))
 ORDER BY candidate.finished_at DESC,candidate.id DESC LIMIT 1
) AND attempt.tenant_id=j.tenant_id
LEFT JOIN scans AS successful ON successful.id=(
 SELECT candidate.id FROM scans AS candidate
 WHERE candidate.tenant_id=j.tenant_id AND candidate.job_id=j.id AND candidate.status='success'
 AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id)
 ORDER BY candidate.finished_at DESC,candidate.id DESC LIMIT 1
) AND successful.tenant_id=j.tenant_id
WHERE j.tenant_id=? AND (?=1 OR j.archived=0)
 AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id)`

// ListJobExecutionSummaries returns at most one latest attempt and one latest
// successful scan for each visible job in one tenant-scoped query. The
// correlated lookups use the job-history index and never select scan JSON;
// only a failed candidate reads its scan row, for its cycle.
func (ts *TenantStore) ListJobExecutionSummaries(ctx context.Context, includeArchived bool) (map[string]JobExecutionSummary, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	rows, err := ts.store.reader().QueryContext(ctx, jobExecutionSummariesSQL, ts.scope.id, boolInt(includeArchived))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]JobExecutionSummary)
	for rows.Next() {
		var jobID string
		var attemptID, attemptStatus, attemptStarted, attemptFinished, attemptConfigHash sql.NullString
		var attemptCycleID, attemptCycleStatus sql.NullString
		var attemptResumable sql.NullInt64
		var successID, successStatus, successStarted, successFinished, successConfigHash sql.NullString
		if err := rows.Scan(&jobID,
			&attemptID, &attemptStatus, &attemptStarted, &attemptFinished, &attemptConfigHash, &attemptCycleID, &attemptCycleStatus, &attemptResumable,
			&successID, &successStatus, &successStarted, &successFinished, &successConfigHash,
		); err != nil {
			return nil, err
		}
		summary := JobExecutionSummary{}
		if attemptID.Valid {
			summary.LatestAttempt = &JobScanStatusSummary{
				ID: attemptID.String, Status: attemptStatus.String, ConfigHash: attemptConfigHash.String,
				CycleID: attemptCycleID.String, CycleStatus: attemptCycleStatus.String, Resumable: attemptResumable.Int64 != 0,
				StartedAt: scanTime(attemptStarted.String), FinishedAt: scanTime(attemptFinished.String),
			}
		}
		if successID.Valid {
			summary.LatestSuccessfulScan = &JobScanStatusSummary{
				ID: successID.String, Status: successStatus.String, ConfigHash: successConfigHash.String,
				StartedAt: scanTime(successStarted.String), FinishedAt: scanTime(successFinished.String),
			}
		}
		result[jobID] = summary
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
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
	err := readDB.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,comparison,changes_json FROM scans WHERE id=? AND tenant_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=scans.tenant_id AND purge.job_id=scans.job_id)`, id, ts.scope.id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &v.BaselineScanID, &v.BaselineConfigHash, &v.Comparison, &changesJSON)
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
	var results []byte
	var total sql.NullInt64
	projectionErr := readDB.QueryRowContext(ctx, `SELECT scans.results_json,scans.results_unit_count FROM scans
		WHERE scans.id=? AND scans.tenant_id=? AND NOT EXISTS (
			SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=scans.tenant_id AND purge.job_id=scans.job_id
		)`, id, ts.scope.id).Scan(&results, &total)
	if projectionErr != nil && !errors.Is(projectionErr, sql.ErrNoRows) {
		return page, projectionErr
	}
	if errors.Is(projectionErr, sql.ErrNoRows) {
		return page, nil
	}
	if results != nil && total.Valid {
		page.Total = int(total.Int64)
		if page.Total == 0 {
			return page, nil
		}
		rows, err := readDB.QueryContext(ctx, `SELECT json_each.value FROM scans, json_each(scans.results_json)
			WHERE scans.id=? AND scans.tenant_id=? AND scans.results_json IS NOT NULL AND NOT EXISTS (
				SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=scans.tenant_id AND purge.job_id=scans.job_id
			) ORDER BY json_each.key LIMIT ? OFFSET ?`, id, ts.scope.id, limit, offset)
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
	// Rows written before schema 75 have no units-only projection. Keep their
	// existing compatibility path until the restartable migration backfill
	// fills them in.
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
