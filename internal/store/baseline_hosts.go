package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// BaselineHost is the effective host evidence for a managed baseline. It is
// kept separately from the immutable source scan because an administrator can
// accept a service/port incident without rewriting historical scan evidence.
// The shape intentionally mirrors ScanHost so the two paths remain
// interchangeable to the web layer.
type BaselineHost struct {
	JobID       string
	DataQuality string
	Host        model.HostObservation
}

// replaceBaselineHostProjectionTx replaces one job's effective baseline host
// projection in the same transaction as the runtime baseline mutation. The
// runtime writer invokes it whenever a baseline is established, changed, or
// receives an accepted/learned overlay so indexed host reads never fall back
// to decoding the complete runtime snapshot.
func replaceBaselineHostProjectionTx(ctx context.Context, tx *sql.Tx, jobID string, snapshot model.Snapshot) error {
	if strings.TrimSpace(jobID) == "" {
		return errors.New("baseline host projection job is required")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM baseline_hosts WHERE job_id=?`, jobID); err != nil {
		return err
	}
	snapshot.Normalize()
	for _, host := range snapshot.Hosts {
		address := normalizeCycleAddress(host.Address)
		if address == "" {
			continue
		}
		host.Address = address
		raw, err := json.Marshal(host)
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
		// Job names are joined at read time so a rename cannot leave stale
		// names searchable in the baseline projection.
		searchText := hostSearchContent("", host)
		open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered := scanHostStats(host)
		if _, err := tx.ExecContext(ctx, `INSERT INTO baseline_hosts(job_id,address,address_family,source_targets_json,dns_names_json,host_json,data_quality,search_text,open_ports,open_filtered_ports,tcp_present,udp_present,tcp_open_ports,tcp_open_filtered_ports,udp_open_ports,udp_open_filtered_ports) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			jobID, address, host.AddressFamily, sourceTargets, dnsNames, raw, "detailed", searchText, open, openFiltered, tcpPresent, udpPresent, tcpOpen, tcpOpenFiltered, udpOpen, udpOpenFiltered); err != nil {
			return err
		}
	}
	return nil
}

func clearBaselineHostProjectionTx(ctx context.Context, tx *sql.Tx, jobID string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM baseline_hosts WHERE job_id=?`, jobID)
	return err
}

// ReplaceBaselineHostProjection is kept for maintenance callers that already
// own a complete baseline snapshot but do not have a surrounding transaction.
// It is a daemon writer and reaches a job of any tenant.
func (ss *SystemStore) ReplaceBaselineHostProjection(ctx context.Context, jobID string, snapshot model.Snapshot) error {
	tx, err := ss.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := replaceBaselineHostProjectionTx(ctx, tx, jobID, snapshot); err != nil {
		return err
	}
	return tx.Commit()
}

// BaselineHostProjectionExists reports whether one of the tenant's jobs has
// a baseline host projection. A job of another tenant has none.
func (ts *TenantStore) BaselineHostProjectionExists(ctx context.Context, jobID string) (bool, error) {
	if err := ts.ready(); err != nil {
		return false, err
	}
	var exists bool
	err := ts.store.reader().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM baseline_hosts b JOIN jobs j ON j.id=b.job_id AND j.tenant_id=? WHERE b.job_id=?)`, ts.scope.id, jobID).Scan(&exists)
	return exists, err
}

// ListBaselineHostsPage filters and paginates the effective overlay of one
// of the tenant's jobs directly in SQLite; a job of another tenant has no
// hosts. Search is intentionally limited to the normalized projection text,
// never the unbounded evidence JSON.
func (ts *TenantStore) ListBaselineHostsPage(ctx context.Context, jobID, query, protocol string, hasOpen *bool, limit, offset int) (Page[ScanHost], error) {
	if err := ts.ready(); err != nil {
		return Page[ScanHost]{}, err
	}
	query = strings.TrimSpace(query)
	if err := ValidateHostSearchQuery(query); err != nil {
		return Page[ScanHost]{}, err
	}
	queries := baselineHostsPageQueries(ts.scope.id, jobID, query, protocol, hasOpen, limit, offset)
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
		var address, quality string
		var raw []byte
		if err := rows.Scan(&address, &quality, &raw); err != nil {
			return page, err
		}
		item, err := decodeScanHost(address, quality, raw)
		if err != nil {
			return page, err
		}
		item.ScanID = ""
		page.Items = append(page.Items, item)
	}
	return page, rows.Err()
}

// baselineHostsPageQueries lists the baseline hosts of one of the tenant's
// jobs. The job join carries the tenant predicate, so the hosts of another
// tenant's job never match, although both tenants may watch the same
// addresses under the same job name.
func baselineHostsPageQueries(tenantID, jobID, query, protocol string, hasOpen *bool, limit, offset int) scanPageQueries {
	limit, offset = normalizePage(limit, offset)
	filter := buildHostFilter(query, protocol, hasOpen)
	where := append([]string{"h.job_id=?"}, filter.where...)
	args := append([]any{tenantID, jobID}, filter.args...)
	if filter.searchText != "" {
		// Use the same bounded FTS document as scan and latest-host queries.
		// The current job name is matched separately so renames are searchable
		// without leaving stale names in the per-host projection. Search rows
		// share the baseline_hosts rowid: an FTS query runs once and its rowids
		// are joined; the store rejects queries too short for trigram matching.
		predicate := `h.rowid IN (SELECT rowid FROM baseline_host_search WHERE baseline_host_search MATCH ?)`
		where = append(where, `(lower(j.name) LIKE ? ESCAPE '\' OR `+predicate+")")
		args = append(args, "%"+escapeLikePattern(filter.searchText)+"%")
		args = append(args, hostSearchMatchQuery(filter.searchText))
	}
	whereSQL := strings.Join(where, " AND ")
	return scanPageQueries{
		countSQL: `SELECT COUNT(*) FROM baseline_hosts h JOIN jobs j ON j.id=h.job_id AND j.tenant_id=? WHERE ` + whereSQL,
		countArg: append([]any(nil), args...),
		pageSQL:  `SELECT h.address,h.data_quality,h.host_json FROM baseline_hosts h JOIN jobs j ON j.id=h.job_id AND j.tenant_id=? WHERE ` + whereSQL + ` ORDER BY h.address LIMIT ? OFFSET ?`,
		pageArg:  append(append([]any(nil), args...), limit, offset),
	}
}

// GetBaselineHost returns one baseline host of one of the tenant's jobs. A
// host of another tenant's job is ErrNotFound, as an unknown host is.
func (ts *TenantStore) GetBaselineHost(ctx context.Context, jobID, address string) (ScanHost, error) {
	if err := ts.ready(); err != nil {
		return ScanHost{}, err
	}
	normalized, err := normalizeStoredHostAddress(address)
	if err != nil {
		return ScanHost{}, fmt.Errorf("%w: host %s", ErrNotFound, address)
	}
	var quality string
	var raw []byte
	err = ts.store.reader().QueryRowContext(ctx, `SELECT h.data_quality,h.host_json FROM baseline_hosts h JOIN jobs j ON j.id=h.job_id AND j.tenant_id=? WHERE h.job_id=? AND h.address=?`, ts.scope.id, jobID, normalized).Scan(&quality, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ScanHost{}, fmt.Errorf("%w: host %s", ErrNotFound, normalized)
	}
	if err != nil {
		return ScanHost{}, err
	}
	item, err := decodeScanHost(normalized, quality, raw)
	if err != nil {
		return ScanHost{}, err
	}
	return item, nil
}
