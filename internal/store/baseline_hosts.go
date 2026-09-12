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
func (s *Store) ReplaceBaselineHostProjection(ctx context.Context, jobID string, snapshot model.Snapshot) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := replaceBaselineHostProjectionTx(ctx, tx, jobID, snapshot); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) BaselineHostProjectionExists(ctx context.Context, jobID string) (bool, error) {
	var exists bool
	err := s.reader().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM baseline_hosts WHERE job_id=?)`, jobID).Scan(&exists)
	return exists, err
}

// ListBaselineHostsPage filters and paginates the effective overlay directly
// in SQLite. Search is intentionally limited to the normalized projection
// text, never the unbounded evidence JSON.
func (s *Store) ListBaselineHostsPage(ctx context.Context, jobID, query, protocol string, hasOpen *bool, limit, offset int) (Page[ScanHost], error) {
	limit, offset = normalizePage(limit, offset)
	filter := buildHostFilter(query, protocol, hasOpen)
	where := append([]string{"h.job_id=?"}, filter.where...)
	args := append([]any{jobID}, filter.args...)
	if filter.searchText != "" {
		where = append(where, `h.search_text LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLikePattern(filter.searchText)+"%")
	}
	var page Page[ScanHost]
	reader := s.reader()
	countQuery := `SELECT COUNT(*) FROM baseline_hosts h WHERE ` + strings.Join(where, " AND ")
	if err := reader.QueryRowContext(ctx, countQuery, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	querySQL := `SELECT h.address,h.data_quality,h.host_json FROM baseline_hosts h WHERE ` + strings.Join(where, " AND ") + ` ORDER BY h.address LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := reader.QueryContext(ctx, querySQL, args...)
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

func (s *Store) GetBaselineHost(ctx context.Context, jobID, address string) (ScanHost, error) {
	normalized, err := normalizeStoredHostAddress(address)
	if err != nil {
		return ScanHost{}, fmt.Errorf("%w: host %s", ErrNotFound, address)
	}
	var quality string
	var raw []byte
	err = s.reader().QueryRowContext(ctx, `SELECT data_quality,host_json FROM baseline_hosts WHERE job_id=? AND address=?`, jobID, normalized).Scan(&quality, &raw)
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
