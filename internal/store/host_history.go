package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

type Page[T any] struct {
	Items []T
	Total int
}

// ScanHost is an indexed effective-address observation. The complete host
// evidence remains in Host, while the scan_hosts table stores summary columns
// used to filter and paginate without decoding unrelated scan snapshots.
type ScanHost struct {
	ScanID      string
	DataQuality string
	Host        model.HostObservation
}

// LatestScanHost is an indexed host observation enriched with the scan/job
// metadata needed by the global Hosts view.
type LatestScanHost struct {
	ScanHost
	JobID     string
	Job       string
	Archived  bool
	ScannedAt time.Time
}

// scanPageQueries keeps the SQL used by a production paging method in one
// value that query-plan tests can explain verbatim. Tests should not duplicate
// a hand-written approximation of a history query because that can continue to
// pass after the live statement regresses.
type scanPageQueries struct {
	countSQL string
	countArg []any
	pageSQL  string
	pageArg  []any
}

func jobScansPageQueries(jobID string, limit, offset int) scanPageQueries {
	limit, offset = normalizePage(limit, offset)
	return scanPageQueries{
		countSQL: `SELECT COUNT(*) FROM scans WHERE job_id=?`,
		countArg: []any{jobID},
		pageSQL:  `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash,changes_json,snapshot_json FROM scans WHERE job_id=? ORDER BY finished_at DESC,id DESC LIMIT ? OFFSET ?`,
		pageArg:  []any{jobID, limit, offset},
	}
}

type hostFilter struct {
	where      []string
	args       []any
	searchText string
}

func buildHostFilter(query, protocol string, hasOpen *bool) hostFilter {
	filter := hostFilter{}
	if query = strings.TrimSpace(strings.ToLower(query)); query != "" {
		filter.searchText = query
	}
	if protocol == "tcp" {
		filter.where = append(filter.where, "h.tcp_present=1")
		if hasOpen != nil {
			if *hasOpen {
				filter.where = append(filter.where, "(h.tcp_open_ports > 0 OR h.tcp_open_filtered_ports > 0)")
			} else {
				filter.where = append(filter.where, "h.tcp_open_ports = 0 AND h.tcp_open_filtered_ports = 0")
			}
		}
	} else if protocol == "udp" {
		filter.where = append(filter.where, "h.udp_present=1")
		if hasOpen != nil {
			if *hasOpen {
				filter.where = append(filter.where, "(h.udp_open_ports > 0 OR h.udp_open_filtered_ports > 0)")
			} else {
				filter.where = append(filter.where, "h.udp_open_ports = 0 AND h.udp_open_filtered_ports = 0")
			}
		}
	} else if hasOpen != nil {
		if *hasOpen {
			filter.where = append(filter.where, "(h.open_ports > 0 OR h.open_filtered_ports > 0)")
		} else {
			filter.where = append(filter.where, "h.open_ports = 0 AND h.open_filtered_ports = 0")
		}
	}
	return filter
}

// hostSearchMatchQuery quotes a user-provided value as one FTS phrase. The
// trigram tokenizer then supports partial addresses, names, and service text
// without allowing FTS operators to alter the query semantics.
func hostSearchMatchQuery(query string) string {
	return `"` + strings.ReplaceAll(query, `"`, `""`) + `"`
}

func hostSearchPredicate(filter hostFilter, searchTable string, keyColumns string) (join, predicate string, args []any) {
	if filter.searchText == "" {
		return "", "", nil
	}
	join = " JOIN " + searchTable + " hs ON " + keyColumns
	if len([]rune(filter.searchText)) < 3 {
		return join, "hs.content LIKE ? ESCAPE '\\'", []any{"%" + escapeLikePattern(filter.searchText) + "%"}
	}
	return join, searchTable + " MATCH ?", []any{hostSearchMatchQuery(filter.searchText)}
}

// escapeLikePattern keeps the short-query fallback literal. FTS5 handles
// wildcard characters safely when a value is quoted as a phrase, but the
// one- and two-character path uses LIKE for trigram-tokenizer boundaries.
func escapeLikePattern(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	value = strings.ReplaceAll(value, `_`, `\_`)
	return value
}

func scanHostStats(host model.HostObservation) (open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered int) {
	for _, protocol := range host.Protocols {
		switch protocol.Protocol {
		case "tcp":
			tcpPresent = 1
		case "udp":
			udpPresent = 1
		}
		for _, port := range protocol.Ports {
			switch port.State {
			case "open":
				open++
				if protocol.Protocol == "tcp" {
					tcpOpen++
				} else if protocol.Protocol == "udp" {
					udpOpen++
				}
			case "open|filtered":
				openFiltered++
				if protocol.Protocol == "tcp" {
					tcpOpenFiltered++
				} else if protocol.Protocol == "udp" {
					udpOpenFiltered++
				}
			}
		}
	}
	return
}

func normalizePage(limit, offset int) (int, int) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func scanHostsPageQueries(scanID, query, protocol string, hasOpen *bool, limit, offset int) scanPageQueries {
	limit, offset = normalizePage(limit, offset)
	filter := buildHostFilter(query, protocol, hasOpen)
	where := append([]string{"h.scan_id=?"}, filter.where...)
	args := append([]any{scanID}, filter.args...)
	join, predicate, searchArgs := hostSearchPredicate(filter, "scan_host_search", "hs.scan_id=h.scan_id AND hs.address=h.address")
	if predicate != "" {
		where = append(where, predicate)
		args = append(args, searchArgs...)
	}
	whereSQL := strings.Join(where, " AND ")
	return scanPageQueries{
		countSQL: `SELECT COUNT(*) FROM scan_hosts h` + join + ` WHERE ` + whereSQL,
		countArg: append([]any(nil), args...),
		pageSQL:  `SELECT h.address,h.data_quality,h.host_json FROM scan_hosts h` + join + ` WHERE ` + whereSQL + ` ORDER BY h.address LIMIT ? OFFSET ?`,
		pageArg:  append(append([]any(nil), args...), limit, offset),
	}
}

func latestScanHostsPageQueries(query, protocol string, hasOpen *bool, limit, offset int) scanPageQueries {
	limit, offset = normalizePage(limit, offset)
	filter := buildHostFilter(query, protocol, hasOpen)
	where := append([]string(nil), filter.where...)
	if len(where) == 0 {
		where = []string{"1=1"}
	}
	args := append([]any(nil), filter.args...)
	join, predicate, searchArgs := hostSearchPredicate(filter, "latest_host_search", "hs.address=h.address")
	if predicate != "" {
		where = append(where, predicate)
		args = append(args, searchArgs...)
	}
	whereSQL := strings.Join(where, " AND ")
	return scanPageQueries{
		countSQL: `SELECT COUNT(*) FROM latest_scan_hosts h` + join + ` WHERE ` + whereSQL,
		countArg: append([]any(nil), args...),
		pageSQL:  `SELECT h.scan_id,h.address,h.data_quality,h.host_json,h.job_id,h.job,h.finished_at,COALESCE(j.archived,0) FROM latest_scan_hosts h LEFT JOIN jobs j ON j.id=h.job_id` + join + ` WHERE ` + whereSQL + ` ORDER BY COALESCE(j.archived,0) ASC,h.address LIMIT ? OFFSET ?`,
		pageArg:  append(append([]any(nil), args...), limit, offset),
	}
}

func (s *Store) ListJobScans(ctx context.Context, jobID string, limit int) ([]model.Scan, error) {
	page, err := s.ListJobScansPage(ctx, jobID, limit, 0)
	return page.Items, err
}

func (s *Store) ListJobScansPage(ctx context.Context, jobID string, limit, offset int) (Page[model.Scan], error) {
	queries := jobScansPageQueries(jobID, limit, offset)
	var page Page[model.Scan]
	readDB := s.reader()
	if err := readDB.QueryRowContext(ctx, queries.countSQL, queries.countArg...).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := readDB.QueryContext(ctx, queries.pageSQL, queries.pageArg...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var v model.Scan
		var jid sql.NullString
		var revision sql.NullInt64
		var started, finished string
		var snapshot, changesJSON []byte
		var baselineScanID, baselineConfigHash string
		var resumable int
		if err := rows.Scan(&v.ID, &jid, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &baselineScanID, &baselineConfigHash, &changesJSON, &snapshot); err != nil {
			return page, err
		}
		v.Resumable = resumable != 0
		if jid.Valid {
			v.JobID = jid.String
		}
		if revision.Valid {
			v.JobRevision = revision.Int64
		}
		v.StartedAt, v.FinishedAt = scanTime(started), scanTime(finished)
		v.BaselineScanID, v.BaselineConfigHash = baselineScanID, baselineConfigHash
		if len(changesJSON) > 0 && string(changesJSON) != "null" {
			if err := json.Unmarshal(changesJSON, &v.Changes); err != nil {
				return page, err
			}
		}
		if err := json.Unmarshal(snapshot, &v.Snapshot); err != nil {
			return page, err
		}
		page.Items = append(page.Items, v)
	}
	return page, rows.Err()
}

// ListJobScanSummariesPage returns only the metadata needed by a paginated
// history view. Full snapshots are intentionally left to GetScan/results.
func (s *Store) ListJobScanSummariesPage(ctx context.Context, jobID string, limit, offset int) (Page[model.ScanSummary], error) {
	limit, offset = normalizePage(limit, offset)
	var page Page[model.ScanSummary]
	readDB := s.reader()
	if err := readDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE job_id=?`, jobID).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := readDB.QueryContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash FROM scans WHERE job_id=? ORDER BY finished_at DESC,id DESC LIMIT ? OFFSET ?`, jobID, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var v model.ScanSummary
		var jid sql.NullString
		var revision sql.NullInt64
		var started, finished string
		var resumable int
		if err := rows.Scan(&v.ID, &jid, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &v.BaselineScanID, &v.BaselineConfigHash); err != nil {
			return page, err
		}
		v.Resumable = resumable != 0
		if jid.Valid {
			v.JobID = jid.String
		}
		if revision.Valid {
			v.JobRevision = revision.Int64
		}
		v.StartedAt, v.FinishedAt = scanTime(started), scanTime(finished)
		page.Items = append(page.Items, v)
	}
	return page, rows.Err()
}
