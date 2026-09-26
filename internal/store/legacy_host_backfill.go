package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

// legacyHostBackfillBatchSize bounds the writer transaction used to convert
// pre-index snapshots. The checkpoint table makes the operation restartable,
// so a large retained history never needs to be processed in one transaction.
const legacyHostBackfillBatchSize = 100

// A single legacy snapshot is capped independently. These batch limits keep
// the migration from retaining one hundred full snapshots (and their decoded
// host graphs) in one transaction. A single scan may exceed a batch boundary
// when it cannot be split without losing the scan/projection atomicity.
const (
	maxLegacyHostBackfillSnapshotBytes   = 8 << 20
	legacyHostBackfillBatchSnapshotBytes = 16 << 20
	legacyHostBackfillBatchHostRows      = 10_000
	maxLegacyHostBackfillErrorBytes      = 512
)

type legacyHostBackfillLimits struct {
	maxScans         int
	maxSnapshotBytes int64
	maxHostRows      int
}

var defaultLegacyHostBackfillLimits = legacyHostBackfillLimits{
	maxScans:         legacyHostBackfillBatchSize,
	maxSnapshotBytes: legacyHostBackfillBatchSnapshotBytes,
	maxHostRows:      legacyHostBackfillBatchHostRows,
}

type legacyHostBackfillScan struct {
	id            string
	jobID         string
	job           string
	finishedAt    time.Time
	snapshotBytes int64
	snapshot      []byte
}

type legacyHostBackfillDataError struct {
	reason string
}

func (e *legacyHostBackfillDataError) Error() string { return e.reason }

// backfillLegacyScanHostsContext converts each successful scan that predates
// scan_hosts into the same indexed projections written for new scans. A
// checkpoint is committed together with each batch, so interruption resumes
// from the next legacy scan and never replays scanner work.
func backfillLegacyScanHostsContext(ctx context.Context, db *sql.DB) error {
	return backfillLegacyScanHostsContextWithLoggerAndProgress(ctx, db, slog.Default(), nil, defaultLegacyHostBackfillLimits)
}

func backfillLegacyScanHostsContextWithLogger(ctx context.Context, db *sql.DB, logger *slog.Logger) error {
	return backfillLegacyScanHostsContextWithLoggerAndProgress(ctx, db, logger, nil, defaultLegacyHostBackfillLimits)
}

// backfillLegacyScanHostsContextWithLoggerAndProgress is kept separate from
// the migration wrapper so tests can use small limits to prove that the
// resource boundaries split work across committed transactions.
func backfillLegacyScanHostsContextWithLoggerAndProgress(ctx context.Context, db *sql.DB, logger *slog.Logger, progress func(processed, total int64), limits legacyHostBackfillLimits) error {
	if logger == nil {
		logger = slog.Default()
	}
	if limits.maxScans <= 0 {
		limits.maxScans = legacyHostBackfillBatchSize
	}
	if limits.maxSnapshotBytes <= 0 {
		limits.maxSnapshotBytes = legacyHostBackfillBatchSnapshotBytes
	}
	if limits.maxHostRows <= 0 {
		limits.maxHostRows = legacyHostBackfillBatchHostRows
	}
	// Legacy scans update latest_scan_hosts, which refuses those writes until
	// the schema 54 copy completes.
	if err := awaitLatestScanHostsTenantRekeyContext(ctx, db); err != nil {
		return err
	}
	total, err := countLegacyHostBackfillCandidates(ctx, db)
	if err != nil {
		return err
	}
	var processed int64
	if progress != nil {
		progress(processed, total)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT s.id,COALESCE(s.job_id,''),s.job,s.finished_at,COALESCE(length(s.snapshot_json),0)
FROM scans s
WHERE s.status='success'
  AND NOT EXISTS (SELECT 1 FROM scan_hosts h WHERE h.scan_id=s.id)
  AND NOT EXISTS (SELECT 1 FROM legacy_scan_host_backfill b WHERE b.scan_id=s.id)
ORDER BY s.finished_at,s.id LIMIT ?`, limits.maxScans)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		batch, readErr := readLegacyHostBackfillBatch(rows)
		if readErr != nil {
			_ = tx.Rollback()
			return readErr
		}
		if len(batch) == 0 {
			if err := tx.Commit(); err != nil {
				return err
			}
			return nil
		}
		var batchBytes int64
		batchHostRows := 0
		batchScans := 0
		skipped := make([]legacyHostBackfillDataError, 0)
		skippedScanIDs := make([]string, 0)
		for _, item := range batch {
			if err := ctx.Err(); err != nil {
				_ = tx.Rollback()
				return err
			}
			// Oversized snapshots can be checkpointed without ever selecting the
			// blob. This is the important distinction from the old batch reader,
			// which loaded every snapshot before checking its size.
			if item.snapshotBytes > maxLegacyHostBackfillSnapshotBytes {
				if batchScans > 0 && (batchBytes >= limits.maxSnapshotBytes || batchBytes+item.snapshotBytes > limits.maxSnapshotBytes) {
					break
				}
				if err := quarantineLegacyScanTx(ctx, tx, item.id, fmt.Sprintf("snapshot exceeds %d-byte conversion limit", maxLegacyHostBackfillSnapshotBytes)); err != nil {
					_ = tx.Rollback()
					return err
				}
				batchBytes += item.snapshotBytes
				batchScans++
				processed++
				skipped = append(skipped, legacyHostBackfillDataError{reason: fmt.Sprintf("snapshot exceeds %d-byte conversion limit", maxLegacyHostBackfillSnapshotBytes)})
				skippedScanIDs = append(skippedScanIDs, item.id)
				continue
			}
			if batchScans > 0 && (batchBytes >= limits.maxSnapshotBytes || batchBytes+item.snapshotBytes > limits.maxSnapshotBytes) {
				break
			}
			if err := loadLegacyHostBackfillSnapshot(ctx, tx, &item); err != nil {
				_ = tx.Rollback()
				return err
			}
			hosts, decodeErr := decodeLegacyHostBackfillHosts(item)
			if decodeErr != nil {
				if err := quarantineLegacyScanTx(ctx, tx, item.id, decodeErr.Error()); err != nil {
					_ = tx.Rollback()
					return err
				}
				batchBytes += item.snapshotBytes
				batchScans++
				processed++
				skipped = append(skipped, *decodeErr)
				skippedScanIDs = append(skippedScanIDs, item.id)
				continue
			}
			if batchScans > 0 && (batchHostRows >= limits.maxHostRows || (batchHostRows > 0 && batchHostRows+len(hosts) > limits.maxHostRows)) {
				break
			}
			if err := indexLegacyScanHostsTx(ctx, tx, item, hosts); err != nil {
				_ = tx.Rollback()
				return err
			}
			batchBytes += item.snapshotBytes
			batchHostRows += len(hosts)
			batchScans++
			processed++
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		if progress != nil {
			progress(processed, total)
		}
		for index, dataErr := range skipped {
			logger.Warn("legacy scan host indexing skipped", "scan_id", skippedScanIDs[index], "reason", dataErr.Error())
		}
	}
}

func readLegacyHostBackfillBatch(rows *sql.Rows) ([]legacyHostBackfillScan, error) {
	defer rows.Close()
	batch := make([]legacyHostBackfillScan, 0, legacyHostBackfillBatchSize)
	for rows.Next() {
		var item legacyHostBackfillScan
		var finished string
		if err := rows.Scan(&item.id, &item.jobID, &item.job, &finished, &item.snapshotBytes); err != nil {
			return nil, err
		}
		item.finishedAt = scanTime(finished)
		batch = append(batch, item)
	}
	return batch, rows.Err()
}

func indexLegacyScanTx(ctx context.Context, tx *sql.Tx, item legacyHostBackfillScan) error {
	if item.snapshotBytes == 0 && len(item.snapshot) > 0 {
		item.snapshotBytes = int64(len(item.snapshot))
	}
	if item.snapshot == nil && item.snapshotBytes <= maxLegacyHostBackfillSnapshotBytes {
		if err := loadLegacyHostBackfillSnapshot(ctx, tx, &item); err != nil {
			return err
		}
	}
	hosts, decodeErr := decodeLegacyHostBackfillHosts(item)
	if decodeErr != nil {
		return decodeErr
	}
	return indexLegacyScanHostsTx(ctx, tx, item, hosts)
}

func indexLegacyScanHostsTx(ctx context.Context, tx *sql.Tx, item legacyHostBackfillScan, hosts []model.HostObservation) error {
	if len(hosts) > 0 {
		scan := model.Scan{ID: item.id, JobID: item.jobID, Job: item.job, FinishedAt: item.finishedAt, Status: "success", Snapshot: model.Snapshot{Hosts: hosts}}
		if err := saveScanHostsExec(ctx, tx, scan); err != nil {
			return err
		}
		// These observations were reconstructed from a legacy snapshot, so
		// advertise their quality to API consumers even though the common
		// projection writer uses the detailed default.
		if _, err := tx.ExecContext(ctx, `UPDATE scan_hosts SET data_quality='legacy' WHERE scan_id=?`, item.id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE latest_scan_hosts SET data_quality='legacy' WHERE scan_id=?`, item.id); err != nil {
			return err
		}
	}
	return checkpointLegacyScanTx(ctx, tx, item.id)
}

func loadLegacyHostBackfillSnapshot(ctx context.Context, tx *sql.Tx, item *legacyHostBackfillScan) error {
	var snapshot []byte
	if err := tx.QueryRowContext(ctx, `SELECT snapshot_json FROM scans WHERE id=?`, item.id).Scan(&snapshot); err != nil {
		return err
	}
	item.snapshot = snapshot
	if item.snapshotBytes == 0 {
		item.snapshotBytes = int64(len(snapshot))
	}
	return nil
}

func decodeLegacyHostBackfillHosts(item legacyHostBackfillScan) ([]model.HostObservation, *legacyHostBackfillDataError) {
	if item.snapshotBytes > maxLegacyHostBackfillSnapshotBytes || len(item.snapshot) > maxLegacyHostBackfillSnapshotBytes {
		return nil, &legacyHostBackfillDataError{reason: fmt.Sprintf("snapshot exceeds %d-byte conversion limit", maxLegacyHostBackfillSnapshotBytes)}
	}
	var snapshot model.Snapshot
	if err := json.Unmarshal(item.snapshot, &snapshot); err != nil {
		return nil, &legacyHostBackfillDataError{reason: "snapshot JSON is malformed"}
	}
	return legacyHostObservations(snapshot), nil
}

func countLegacyHostBackfillCandidates(ctx context.Context, db *sql.DB) (int64, error) {
	var total int64
	err := db.QueryRowContext(ctx, `SELECT COUNT(*)
FROM scans s
WHERE s.status='success'
  AND NOT EXISTS (SELECT 1 FROM scan_hosts h WHERE h.scan_id=s.id)
  AND NOT EXISTS (SELECT 1 FROM legacy_scan_host_backfill b WHERE b.scan_id=s.id)`).Scan(&total)
	return total, err
}

func checkpointLegacyScanTx(ctx context.Context, tx *sql.Tx, scanID string) error {
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO legacy_scan_host_backfill(scan_id,processed_at,status,error,attempts) VALUES(?,?,?,?,?)`, scanID, sqliteTimestamp(time.Now()), "complete", "", 1)
	return err
}

// quarantineLegacyScanTx records a bounded conversion failure separately from
// a successful (including valid-empty) projection. Quarantined rows are still
// considered processed by the backfill predicate, so a bad historical blob
// cannot make every startup retry the same decode forever.
func quarantineLegacyScanTx(ctx context.Context, tx *sql.Tx, scanID, reason string) error {
	reason = strings.TrimSpace(reason)
	if len(reason) > maxLegacyHostBackfillErrorBytes {
		reason = reason[:maxLegacyHostBackfillErrorBytes]
	}
	if reason == "" {
		reason = "legacy snapshot could not be converted"
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO legacy_scan_host_backfill(scan_id,processed_at,status,error,attempts) VALUES(?,?,?,?,1)
ON CONFLICT(scan_id) DO UPDATE SET processed_at=excluded.processed_at,status='quarantined',error=excluded.error,attempts=legacy_scan_host_backfill.attempts+1`, scanID, sqliteTimestamp(time.Now()), "quarantined", reason)
	return err
}

// legacyHostObservations mirrors the pre-index compatibility projection used
// by the web layer. Keeping the conversion in store lets migration perform it
// once, without importing web or making every Hosts request decode snapshots.
func legacyHostObservations(snapshot model.Snapshot) []model.HostObservation {
	if len(snapshot.Hosts) > 0 {
		hosts := legacyMergeHostsByAddress(snapshot.Hosts)
		restoreLegacyHostScopes(hosts, snapshot.Scopes)
		normalizeLegacyHosts(hosts)
		return hosts
	}
	scopeByKey := make(map[string]model.Scope, len(snapshot.Scopes))
	scopesByProtocol := make(map[string][]model.Scope)
	for _, scope := range snapshot.Scopes {
		target := strings.ToLower(strings.TrimSpace(scope.Target))
		protocol := strings.ToLower(strings.TrimSpace(scope.Protocol))
		if protocol == "" {
			continue
		}
		scopeByKey[target+"\x00"+protocol] = scope
		scopesByProtocol[protocol] = append(scopesByProtocol[protocol], scope)
	}
	byAddress := make(map[string]*model.HostObservation)
	for _, unit := range snapshot.Units {
		addresses := append([]string(nil), unit.Addresses...)
		if len(addresses) == 0 {
			addresses = []string{unit.Target}
		}
		portsByAddress := make(map[string][]model.PortState)
		for _, port := range unit.Ports {
			if len(port.Evidence) == 0 {
				for _, address := range addresses {
					portsByAddress[canonicalLegacyAddress(address)] = append(portsByAddress[canonicalLegacyAddress(address)], port)
				}
				continue
			}
			for _, address := range port.Evidence {
				portsByAddress[canonicalLegacyAddress(address)] = append(portsByAddress[canonicalLegacyAddress(address)], port)
			}
		}
		protocolName := strings.ToLower(strings.TrimSpace(unit.Protocol))
		scope, hasScope := scopeByKey[strings.ToLower(strings.TrimSpace(unit.Target))+"\x00"+protocolName]
		if !hasScope && len(scopesByProtocol[protocolName]) == 1 {
			scope, hasScope = scopesByProtocol[protocolName][0], true
		}
		if !hasScope {
			scope = model.Scope{Target: unit.Target, Protocol: unit.Protocol}
		}
		// A missing scope is uncommon in legacy snapshots. Preserve the
		// observed count without fabricating a port expression that would not
		// round-trip through the strict port parser.
		scannedPortCount := legacyPortCount(scope.Ports)
		if scannedPortCount == 0 {
			seen := make(map[int]struct{}, len(unit.Ports))
			for _, port := range unit.Ports {
				seen[port.Port] = struct{}{}
			}
			scannedPortCount = len(seen)
		}
		for _, rawAddress := range addresses {
			address := canonicalLegacyAddress(rawAddress)
			if net.ParseIP(address) == nil {
				continue
			}
			host := byAddress[address]
			if host == nil {
				host = &model.HostObservation{Address: address, AddressFamily: legacyAddressFamily(address), Status: "up"}
				byAddress[address] = host
			}
			host.SourceTargets = append(host.SourceTargets, unit.Target)
			if net.ParseIP(unit.Target) == nil {
				if _, _, err := net.ParseCIDR(unit.Target); err != nil {
					host.DNSNames = append(host.DNSNames, unit.Target)
				}
			}
			protocol := model.ProtocolObservation{Protocol: strings.ToLower(strings.TrimSpace(unit.Protocol)), ScannedPorts: scope.Ports, ScannedPortCount: scannedPortCount, ServiceDetection: scope.ServiceDetection}
			for _, port := range portsByAddress[address] {
				protocol.Ports = append(protocol.Ports, model.PortObservation{Port: port.Port, State: port.State, Service: legacyServiceObservation(port.Service)})
				legacyAddStateSummary(&protocol, port.State)
			}
			legacyMergeProtocol(&host.Protocols, protocol)
		}
	}
	result := make([]model.HostObservation, 0, len(byAddress))
	for _, host := range byAddress {
		normalizeLegacyHosts([]model.HostObservation{*host})
		result = append(result, *host)
	}
	normalizeLegacyHosts(result)
	return result
}

// restoreLegacyHostScopes mirrors the web compatibility reader for snapshots
// that already contain HostObservation records but predate scope fields on
// each protocol. A legacy host projection must retain the original scan
// expression and coverage even when its positive-port evidence is empty.
func restoreLegacyHostScopes(hosts []model.HostObservation, scopes []model.Scope) {
	byProtocol := make(map[string]model.Scope)
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
			protocol.ScannedPortCount = legacyPortCount(scope.Ports)
			protocol.ServiceDetection = scope.ServiceDetection
		}
	}
}

func normalizeLegacyHosts(hosts []model.HostObservation) {
	for hostIndex := range hosts {
		host := &hosts[hostIndex]
		host.SourceTargets = legacyUniqueStrings(host.SourceTargets)
		host.DNSNames = legacyUniqueStrings(host.DNSNames)
		for protocolIndex := range host.Protocols {
			legacyDedupeProtocol(&host.Protocols[protocolIndex])
		}
	}
	snapshot := model.Snapshot{Hosts: hosts}
	snapshot.Normalize()
	copy(hosts, snapshot.Hosts)
}

func legacyUniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func canonicalLegacyAddress(raw string) string {
	if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
		return ip.String()
	}
	return strings.TrimSpace(raw)
}

func legacyAddressFamily(address string) string {
	ip := net.ParseIP(address)
	if ip != nil && ip.To4() != nil {
		return "IPv4"
	}
	if ip != nil {
		return "IPv6"
	}
	return ""
}

func legacyPortCount(raw string) int {
	ports, err := config.ParsePorts(raw)
	if err != nil {
		return 0
	}
	return len(ports)
}

func legacyServiceObservation(fingerprint string) *model.ServiceObservation {
	if strings.TrimSpace(fingerprint) == "" {
		return nil
	}
	return &model.ServiceObservation{Product: fingerprint, Method: "legacy"}
}

func legacyAddStateSummary(protocol *model.ProtocolObservation, state string) {
	for index := range protocol.StateSummaries {
		if protocol.StateSummaries[index].State == state {
			protocol.StateSummaries[index].Count++
			return
		}
	}
	protocol.StateSummaries = append(protocol.StateSummaries, model.StateSummary{State: state, Count: 1})
}

func legacyMergeProtocol(protocols *[]model.ProtocolObservation, addition model.ProtocolObservation) {
	for index := range *protocols {
		if (*protocols)[index].Protocol != addition.Protocol {
			continue
		}
		(*protocols)[index].Ports = append((*protocols)[index].Ports, addition.Ports...)
		legacyMergeStateSummaries(&(*protocols)[index].StateSummaries, addition.StateSummaries)
		if (*protocols)[index].ScannedPorts == "" {
			(*protocols)[index].ScannedPorts = addition.ScannedPorts
		}
		if (*protocols)[index].ScannedPortCount == 0 {
			(*protocols)[index].ScannedPortCount = addition.ScannedPortCount
		}
		(*protocols)[index].ServiceDetection = (*protocols)[index].ServiceDetection || addition.ServiceDetection
		return
	}
	*protocols = append(*protocols, addition)
}

func legacyMergeStateSummaries(destination *[]model.StateSummary, incoming []model.StateSummary) {
	for _, summary := range incoming {
		found := false
		for index := range *destination {
			if (*destination)[index].State != summary.State {
				continue
			}
			(*destination)[index].Count += summary.Count
			legacyMergeStateReasons(&(*destination)[index].Reasons, summary.Reasons)
			found = true
			break
		}
		if !found {
			*destination = append(*destination, summary)
		}
	}
}

func legacyMergeStateReasons(destination *[]model.StateReason, incoming []model.StateReason) {
	for _, reason := range incoming {
		found := false
		for index := range *destination {
			if (*destination)[index].Reason != reason.Reason {
				continue
			}
			(*destination)[index].Count += reason.Count
			found = true
			break
		}
		if !found {
			*destination = append(*destination, reason)
		}
	}
}

func legacyDedupeProtocol(protocol *model.ProtocolObservation) {
	seen := make(map[int]int, len(protocol.Ports))
	ports := make([]model.PortObservation, 0, len(protocol.Ports))
	for _, incoming := range protocol.Ports {
		if index, exists := seen[incoming.Port]; exists {
			destination := &ports[index]
			if destination.State != "open" && incoming.State == "open" {
				destination.State = incoming.State
			}
			if destination.Service == nil {
				destination.Service = incoming.Service
			}
			continue
		}
		seen[incoming.Port] = len(ports)
		ports = append(ports, incoming)
	}
	protocol.Ports = ports
}

func legacyMergeHostsByAddress(input []model.HostObservation) []model.HostObservation {
	byAddress := make(map[string]model.HostObservation, len(input))
	for _, original := range input {
		address := canonicalLegacyAddress(original.Address)
		if net.ParseIP(address) == nil {
			continue
		}
		addition := cloneLegacyHostObservation(original)
		addition.Address = address
		if addition.AddressFamily == "" {
			addition.AddressFamily = legacyAddressFamily(address)
		}
		for index := range addition.Protocols {
			addition.Protocols[index].Protocol = strings.ToLower(strings.TrimSpace(addition.Protocols[index].Protocol))
		}
		current, exists := byAddress[address]
		if !exists {
			byAddress[address] = addition
			continue
		}
		current.SourceTargets = append(current.SourceTargets, addition.SourceTargets...)
		current.DNSNames = append(current.DNSNames, addition.DNSNames...)
		current.LinkAddresses = append(current.LinkAddresses, addition.LinkAddresses...)
		current.Hostnames = append(current.Hostnames, addition.Hostnames...)
		current.Status, current.StatusReason = legacyMergeHostStatus(current.Status, current.StatusReason, addition.Status, addition.StatusReason)
		if current.ReasonTTL == 0 || addition.ReasonTTL > 0 && addition.ReasonTTL < current.ReasonTTL {
			current.ReasonTTL = addition.ReasonTTL
		}
		if current.LatencyMS == 0 || addition.LatencyMS > 0 && addition.LatencyMS < current.LatencyMS {
			current.LatencyMS = addition.LatencyMS
		}
		for _, protocol := range addition.Protocols {
			legacyMergeProtocol(&current.Protocols, protocol)
		}
		byAddress[address] = current
	}
	result := make([]model.HostObservation, 0, len(byAddress))
	for _, host := range byAddress {
		result = append(result, host)
	}
	return result
}

func cloneLegacyHostObservation(host model.HostObservation) model.HostObservation {
	cloned := host
	cloned.SourceTargets = append([]string(nil), host.SourceTargets...)
	cloned.DNSNames = append([]string(nil), host.DNSNames...)
	cloned.LinkAddresses = append([]model.LinkAddress(nil), host.LinkAddresses...)
	cloned.Hostnames = append([]model.Hostname(nil), host.Hostnames...)
	cloned.Protocols = append([]model.ProtocolObservation(nil), host.Protocols...)
	for protocolIndex := range cloned.Protocols {
		protocol := &cloned.Protocols[protocolIndex]
		protocol.Ports = cloneLegacyPortObservations(protocol.Ports)
		protocol.DiscoveredPorts = cloneLegacyPortObservations(protocol.DiscoveredPorts)
		protocol.UnconfirmedPorts = cloneLegacyPortObservations(protocol.UnconfirmedPorts)
		protocol.StateSummaries = append([]model.StateSummary(nil), protocol.StateSummaries...)
		for summaryIndex := range protocol.StateSummaries {
			protocol.StateSummaries[summaryIndex].Reasons = append([]model.StateReason(nil), protocol.StateSummaries[summaryIndex].Reasons...)
		}
		protocol.NSEOutput = append([]string(nil), protocol.NSEOutput...)
		if protocol.NSEArgs != nil {
			protocol.NSEArgs = make(map[string]string, len(host.Protocols[protocolIndex].NSEArgs))
			for key, value := range host.Protocols[protocolIndex].NSEArgs {
				protocol.NSEArgs[key] = value
			}
		}
	}
	return cloned
}

func cloneLegacyPortObservations(ports []model.PortObservation) []model.PortObservation {
	cloned := append([]model.PortObservation(nil), ports...)
	for index := range cloned {
		if cloned[index].Service != nil {
			service := *cloned[index].Service
			service.CPEs = append([]string(nil), service.CPEs...)
			cloned[index].Service = &service
		}
	}
	return cloned
}

func legacyMergeHostStatus(currentStatus, currentReason, additionStatus, additionReason string) (string, string) {
	currentStatus = strings.ToLower(strings.TrimSpace(currentStatus))
	additionStatus = strings.ToLower(strings.TrimSpace(additionStatus))
	currentReason = strings.TrimSpace(currentReason)
	additionReason = strings.TrimSpace(additionReason)
	currentIncomplete := legacyIncompleteHostStatus(currentStatus)
	additionIncomplete := legacyIncompleteHostStatus(additionStatus)
	if currentIncomplete || additionIncomplete {
		if currentIncomplete && !additionIncomplete {
			return "unreachable", currentReason
		}
		if additionIncomplete && !currentIncomplete {
			return "unreachable", additionReason
		}
		return "unreachable", legacyChooseStatusReason(currentReason, additionReason)
	}
	if currentStatus == "" || currentStatus == "unknown" {
		if additionStatus != "" {
			return additionStatus, legacyChooseStatusReason(currentReason, additionReason)
		}
	}
	return currentStatus, legacyChooseStatusReason(currentReason, additionReason)
}

func legacyIncompleteHostStatus(status string) bool {
	switch status {
	case "unreachable", "down", "timedout", "timed-out", "timeout":
		return true
	default:
		return false
	}
}

func legacyChooseStatusReason(current, addition string) string {
	if current == "" {
		return addition
	}
	if addition == "" || current == addition {
		return current
	}
	if addition < current {
		return addition
	}
	return current
}
