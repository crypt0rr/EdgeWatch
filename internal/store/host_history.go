package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/crypt0rr/edgewatch/internal/model"
)

type Page[T any] struct {
	Items []T
	Total int
}

const (
	// MinHostSearchQueryRunes is the shortest searchable non-empty host query.
	MinHostSearchQueryRunes = 3
	// MaxHostSearchQueryRunes caps work and input amplification on host search.
	MaxHostSearchQueryRunes = 256
)

var (
	// ErrHostSearchQueryTooShort reports a non-empty query below the indexed trigram minimum.
	ErrHostSearchQueryTooShort = errors.New("host search must contain at least 3 characters")
	// ErrHostSearchQueryTooLong reports a query beyond the supported search bound.
	ErrHostSearchQueryTooLong = errors.New("host search must not exceed 256 characters")
)

// ValidateHostSearchQuery keeps broad host searches on the indexed FTS path
// and bounds the amount of user input used to construct its query.
func ValidateHostSearchQuery(query string) error {
	query = strings.TrimSpace(query)
	runes := utf8.RuneCountInString(query)
	if runes == 0 {
		return nil
	}
	if runes < MinHostSearchQueryRunes {
		return ErrHostSearchQueryTooShort
	}
	if runes > MaxHostSearchQueryRunes {
		return ErrHostSearchQueryTooLong
	}
	return nil
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

// jobScansPageQueries lists the scans of one of the tenant's jobs. The reads
// of a job's scans put the tenant predicate on the job instead of on
// scans.tenant_id. The two agree: the schema 53 guard trigger requires a scan
// to belong to its job's tenant, and neither tenant can change. Schema 53
// appended scans.tenant_id to the scan row, after the snapshot, so testing it
// would read the snapshot pages of every scan that a count or an offset
// passes, which an index on job_id otherwise answers alone.
func jobScansPageQueries(tenantID, jobID string, limit, offset int) scanPageQueries {
	limit, offset = normalizePage(limit, offset)
	return scanPageQueries{
		countSQL: `SELECT COUNT(*) FROM scans s JOIN jobs j ON j.id=s.job_id AND j.tenant_id=? WHERE s.job_id=?`,
		countArg: []any{tenantID, jobID},
		pageSQL:  `SELECT s.id,s.job_id,s.job_revision,s.job,s.started_at,s.finished_at,s.status,s.error,s.nmap_version,s.scanner_engine,s.scanner_profile_id,s.scanner_profile_revision,s.naabu_version,s.discovery_ports,s.confirmed_ports,s.discovery_duration_ms,s.enrichment_duration_ms,s.config_hash,s.cycle_id,s.cycle_attempt,s.cycle_status,s.resumable,s.completed_probes,s.total_probes,s.completed_units,s.total_units,s.no_progress_attempts,s.baseline_scan_id,s.baseline_config_hash,s.changes_json,s.snapshot_json FROM scans s JOIN jobs j ON j.id=s.job_id AND j.tenant_id=? WHERE s.job_id=? ORDER BY s.finished_at DESC,s.id DESC LIMIT ? OFFSET ?`,
		pageArg:  []any{tenantID, jobID, limit, offset},
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
	return join, searchTable + " MATCH ?", []any{hostSearchMatchQuery(filter.searchText)}
}

// escapeLikePattern keeps the baseline's current-job-name substring match
// literal. Host evidence itself is searched through quoted FTS phrases.
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

// scanHostsPageQueries lists the hosts of one of the tenant's scans. The
// scan join carries the tenant predicate, so the hosts of another tenant's
// scan never match.
func scanHostsPageQueries(tenantID, scanID, query, protocol string, hasOpen *bool, limit, offset int) scanPageQueries {
	limit, offset = normalizePage(limit, offset)
	filter := buildHostFilter(query, protocol, hasOpen)
	where := append([]string{"h.scan_id=?"}, filter.where...)
	args := append([]any{tenantID, scanID}, filter.args...)
	// The FTS projection deliberately mirrors scan_hosts.rowid. Joining on
	// that stable row identifier lets SQLite constrain the host lookup to the
	// MATCH result instead of re-resolving every scan/address pair globally.
	join, predicate, searchArgs := hostSearchPredicate(filter, "scan_host_search", "hs.rowid=h.rowid")
	if predicate != "" {
		where = append(where, predicate)
		args = append(args, searchArgs...)
	}
	whereSQL := strings.Join(where, " AND ")
	return scanPageQueries{
		countSQL: `SELECT COUNT(*) FROM scan_hosts h JOIN scans s ON s.id=h.scan_id AND s.tenant_id=?` + join + ` WHERE ` + whereSQL,
		countArg: append([]any(nil), args...),
		pageSQL:  `SELECT h.address,h.data_quality,h.host_json FROM scan_hosts h JOIN scans s ON s.id=h.scan_id AND s.tenant_id=?` + join + ` WHERE ` + whereSQL + ` ORDER BY h.address LIMIT ? OFFSET ?`,
		pageArg:  append(append([]any(nil), args...), limit, offset),
	}
}

// latestScanHostsPageQueries lists the tenant's host inventory. The
// projection is keyed by (tenant_id, address), so each tenant has its own
// row for an address, and the tenant predicate leads its indexes.
func latestScanHostsPageQueries(tenantID, query, protocol string, hasOpen *bool, limit, offset int) scanPageQueries {
	limit, offset = normalizePage(limit, offset)
	filter := buildHostFilter(query, protocol, hasOpen)
	where := filter.where
	args := append([]any{tenantID}, filter.args...)
	// latest_host_search mirrors latest_scan_hosts.rowid for the same bounded
	// rowid-scoped lookup used by the per-scan history query.
	join, predicate, searchArgs := hostSearchPredicate(filter, "latest_host_search", "hs.rowid=h.rowid")
	if predicate != "" {
		where = append(where, predicate)
		args = append(args, searchArgs...)
	}
	filterSQL := ""
	for _, clause := range where {
		filterSQL += " AND " + clause
	}
	return scanPageQueries{
		countSQL: `SELECT COUNT(*) FROM latest_scan_hosts h` + join + ` WHERE h.tenant_id=?` + filterSQL,
		countArg: append([]any(nil), args...),
		pageSQL:  `SELECT h.scan_id,h.address,h.data_quality,h.host_json,h.job_id,h.job,h.finished_at,COALESCE(j.archived,0) FROM latest_scan_hosts h LEFT JOIN jobs j ON j.id=h.job_id` + join + ` WHERE h.tenant_id=?` + filterSQL + ` ORDER BY COALESCE(j.archived,0) ASC,h.address LIMIT ? OFFSET ?`,
		pageArg:  append(append([]any(nil), args...), limit, offset),
	}
}

// ListJobScans returns the newest complete scans of one of the tenant's
// jobs; a job of another tenant has none.
func (ts *TenantStore) ListJobScans(ctx context.Context, jobID string, limit int) ([]model.Scan, error) {
	page, err := ts.ListJobScansPage(ctx, jobID, limit, 0)
	return page.Items, err
}

// ListJobScansPage returns one page of the complete scans, newest first, of
// one of the tenant's jobs; a job of another tenant has none.
func (ts *TenantStore) ListJobScansPage(ctx context.Context, jobID string, limit, offset int) (Page[model.Scan], error) {
	if err := ts.ready(); err != nil {
		return Page[model.Scan]{}, err
	}
	queries := jobScansPageQueries(ts.scope.id, jobID, limit, offset)
	var page Page[model.Scan]
	readDB := ts.store.reader()
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
// history view of one of the tenant's jobs; a job of another tenant has no
// scans. Full snapshots are intentionally left to GetScan/results. The
// tenant predicate is on the job, as jobScansPageQueries explains.
func (ts *TenantStore) ListJobScanSummariesPage(ctx context.Context, jobID string, limit, offset int) (Page[model.ScanSummary], error) {
	if err := ts.ready(); err != nil {
		return Page[model.ScanSummary]{}, err
	}
	limit, offset = normalizePage(limit, offset)
	var page Page[model.ScanSummary]
	readDB := ts.store.reader()
	if err := readDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans s JOIN jobs j ON j.id=s.job_id AND j.tenant_id=? WHERE s.job_id=?`, ts.scope.id, jobID).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := readDB.QueryContext(ctx, `SELECT s.id,s.job_id,s.job_revision,s.job,s.started_at,s.finished_at,s.status,s.error,s.nmap_version,s.scanner_engine,s.scanner_profile_id,s.scanner_profile_revision,s.naabu_version,s.discovery_ports,s.confirmed_ports,s.discovery_duration_ms,s.enrichment_duration_ms,s.config_hash,s.cycle_id,s.cycle_attempt,s.cycle_status,s.resumable,s.completed_probes,s.total_probes,s.completed_units,s.total_units,s.no_progress_attempts,s.baseline_scan_id,s.baseline_config_hash FROM scans s JOIN jobs j ON j.id=s.job_id AND j.tenant_id=? WHERE s.job_id=? ORDER BY s.finished_at DESC,s.id DESC LIMIT ? OFFSET ?`, ts.scope.id, jobID, limit, offset)
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
		v.TenantID = ts.scope.id
		page.Items = append(page.Items, v)
	}
	return page, rows.Err()
}
