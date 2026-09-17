package store

import (
	"context"
	"database/sql"
	"encoding/json"
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

const maxLegacyHostBackfillSnapshotBytes = 8 << 20

type legacyHostBackfillScan struct {
	id         string
	jobID      string
	job        string
	finishedAt time.Time
	snapshot   []byte
}

// backfillLegacyScanHostsContext converts each successful scan that predates
// scan_hosts into the same indexed projections written for new scans. A
// checkpoint is committed together with each batch, so interruption resumes
// from the next legacy scan and never replays scanner work.
func backfillLegacyScanHostsContext(ctx context.Context, db *sql.DB) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT s.id,COALESCE(s.job_id,''),s.job,s.finished_at,s.snapshot_json
FROM scans s
WHERE s.status='success'
  AND NOT EXISTS (SELECT 1 FROM scan_hosts h WHERE h.scan_id=s.id)
  AND NOT EXISTS (SELECT 1 FROM legacy_scan_host_backfill b WHERE b.scan_id=s.id)
ORDER BY s.finished_at,s.id LIMIT ?`, legacyHostBackfillBatchSize)
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
		for _, item := range batch {
			if err := indexLegacyScanTx(ctx, tx, item); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
}

func readLegacyHostBackfillBatch(rows *sql.Rows) ([]legacyHostBackfillScan, error) {
	defer rows.Close()
	batch := make([]legacyHostBackfillScan, 0, legacyHostBackfillBatchSize)
	for rows.Next() {
		var item legacyHostBackfillScan
		var finished string
		if err := rows.Scan(&item.id, &item.jobID, &item.job, &finished, &item.snapshot); err != nil {
			return nil, err
		}
		item.finishedAt = scanTime(finished)
		batch = append(batch, item)
	}
	return batch, rows.Err()
}

func indexLegacyScanTx(ctx context.Context, tx *sql.Tx, item legacyHostBackfillScan) error {
	var snapshot model.Snapshot
	if len(item.snapshot) <= maxLegacyHostBackfillSnapshotBytes && json.Unmarshal(item.snapshot, &snapshot) == nil {
		hosts := legacyHostObservations(snapshot)
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
	}
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO legacy_scan_host_backfill(scan_id,processed_at) VALUES(?,?)`, item.id, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// legacyHostObservations mirrors the pre-index compatibility projection used
// by the web layer. Keeping the conversion in store lets migration perform it
// once, without importing web or making every Hosts request decode snapshots.
func legacyHostObservations(snapshot model.Snapshot) []model.HostObservation {
	if len(snapshot.Hosts) > 0 {
		hosts := append([]model.HostObservation(nil), snapshot.Hosts...)
		normalizeLegacyHosts(hosts)
		return hosts
	}
	scopeByKey := make(map[string]model.Scope, len(snapshot.Scopes))
	for _, scope := range snapshot.Scopes {
		scopeByKey[strings.ToLower(scope.Target)+"\x00"+strings.ToLower(scope.Protocol)] = scope
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
		scope, hasScope := scopeByKey[strings.ToLower(unit.Target)+"\x00"+strings.ToLower(unit.Protocol)]
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
