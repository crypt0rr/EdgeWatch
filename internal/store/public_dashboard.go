package store

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/crypt0rr/edgewatch/internal/model"
)

type PublicDashboard struct {
	Enabled      bool                  `json:"enabled"`
	Title        string                `json:"title"`
	Introduction string                `json:"introduction"`
	UpdatedAt    time.Time             `json:"updated_at"`
	Hosts        []PublicDashboardHost `json:"hosts"`
}

type PublicDashboardHost struct {
	JobID     string    `json:"job_id"`
	Address   string    `json:"address"`
	CreatedAt time.Time `json:"created_at"`
}

// PublicDashboardHostResult combines the selected address, its latest
// successful indexed observation, and scan metadata. Batch callers use this
// type to render the public dashboard without issuing one query per host.
type PublicDashboardHostResult struct {
	Selection PublicDashboardHost
	Host      ScanHost
	Summary   model.ScanSummary
}

// LegacyPublicScan is the bounded metadata projection used when a retained
// scan predates the indexed scan_hosts table. Keeping this query in the store
// ensures the read-only pool is used and prevents the public handler from
// reaching into the writer connection.
type LegacyPublicScan struct {
	ID          string
	JobID       string
	JobRevision int64
	Job         string
	StartedAt   string
	FinishedAt  string
	Status      string
	Error       string
	NmapVersion string
	ConfigHash  string
	Snapshot    []byte
}

func (s *Store) ListLegacyPublicScans(ctx context.Context, jobID string, limit int) ([]LegacyPublicScan, error) {
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return []LegacyPublicScan{}, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := s.reader().QueryContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,config_hash,snapshot_json
FROM scans
WHERE status='success' AND job_id=?
  AND NOT EXISTS (SELECT 1 FROM scan_hosts h WHERE h.scan_id=scans.id)
ORDER BY finished_at DESC,id DESC LIMIT ?`, jobID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]LegacyPublicScan, 0)
	for rows.Next() {
		var scan LegacyPublicScan
		var storedJobID sql.NullString
		var revision sql.NullInt64
		if err := rows.Scan(&scan.ID, &storedJobID, &revision, &scan.Job, &scan.StartedAt, &scan.FinishedAt, &scan.Status, &scan.Error, &scan.NmapVersion, &scan.ConfigHash, &scan.Snapshot); err != nil {
			return nil, err
		}
		if !storedJobID.Valid {
			continue
		}
		scan.JobID = storedJobID.String
		if revision.Valid {
			scan.JobRevision = revision.Int64
		}
		result = append(result, scan)
	}
	return result, rows.Err()
}

func normalizePublicAddress(address string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil {
		return "", errors.New("address must be a valid IP")
	}
	return ip.String(), nil
}

// GetPublicDashboard returns the default tenant's public status page.
func (s *Store) GetPublicDashboard(ctx context.Context) (PublicDashboard, error) {
	var d PublicDashboard
	var id int64
	var enabled int
	var updated string
	reader := s.reader()
	err := reader.QueryRowContext(ctx, `SELECT id,enabled,title,introduction,updated_at FROM public_dashboards WHERE tenant_id=?`, DefaultTenantID).Scan(&id, &enabled, &d.Title, &d.Introduction, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	d.Enabled = enabled != 0
	d.UpdatedAt = scanTime(updated)
	rows, err := reader.QueryContext(ctx, `SELECT job_id,address,created_at FROM public_dashboard_hosts WHERE dashboard_id=? ORDER BY job_id,address`, id)
	if err != nil {
		return d, err
	}
	defer rows.Close()
	for rows.Next() {
		var h PublicDashboardHost
		var created string
		if err := rows.Scan(&h.JobID, &h.Address, &created); err != nil {
			return d, err
		}
		h.CreatedAt = scanTime(created)
		d.Hosts = append(d.Hosts, h)
	}
	if d.Hosts == nil {
		d.Hosts = []PublicDashboardHost{}
	}
	return d, rows.Err()
}

// SavePublicDashboard replaces the explicit publication set in one
// transaction. Publication is intentionally allow-list based: selecting a
// job never implicitly publishes all of its current or future hosts. It does
// not detect a concurrent change; the web console saves through
// SavePublicDashboardIfCurrent.
func (s *Store) SavePublicDashboard(ctx context.Context, dashboard PublicDashboard, hosts []PublicDashboardHost, audit AuditEntry) error {
	return s.savePublicDashboard(ctx, nil, dashboard, hosts, audit)
}

// SavePublicDashboardIfCurrent replaces the publication only while its
// updated_at still equals expectedUpdatedAt, the value the editor loaded.
// Otherwise it returns ErrConflict and changes nothing, so an editor opened
// before another administrator's save cannot silently overwrite it, for
// example by publishing a page that was withdrawn in the meantime.
func (s *Store) SavePublicDashboardIfCurrent(ctx context.Context, expectedUpdatedAt time.Time, dashboard PublicDashboard, hosts []PublicDashboardHost, audit AuditEntry) error {
	return s.savePublicDashboard(ctx, &expectedUpdatedAt, dashboard, hosts, audit)
}

func (s *Store) savePublicDashboard(ctx context.Context, expectedUpdatedAt *time.Time, dashboard PublicDashboard, hosts []PublicDashboardHost, audit AuditEntry) error {
	if strings.TrimSpace(dashboard.Title) == "" {
		dashboard.Title = "EdgeWatch public status"
	}
	if utf8.RuneCountInString(dashboard.Title) > 120 || utf8.RuneCountInString(dashboard.Introduction) > 500 {
		return errors.New("public dashboard text is too long")
	}
	now := time.Now().UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// The default tenant's row always exists after migration; a missing row
	// reads as the zero time, which is also what GET reports for it.
	var dashboardID int64
	var currentRaw string
	var current time.Time
	exists := false
	if err := tx.QueryRowContext(ctx, `SELECT id,updated_at FROM public_dashboards WHERE tenant_id=?`, DefaultTenantID).Scan(&dashboardID, &currentRaw); err == nil {
		exists = true
		current = scanTime(currentRaw)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if expectedUpdatedAt != nil && !expectedUpdatedAt.Equal(current) {
		return ErrConflict
	}
	// updated_at doubles as the revision token, so every save must advance
	// it, even when two saves fall within one clock tick or the clock steps
	// back.
	if !now.After(current) {
		now = current.Add(time.Microsecond)
	}
	enabled, title, introduction, updatedAt := boolInt(dashboard.Enabled), strings.TrimSpace(dashboard.Title), strings.TrimSpace(dashboard.Introduction), now.Format(time.RFC3339Nano)
	if exists {
		if _, err := tx.ExecContext(ctx, `UPDATE public_dashboards SET enabled=?,title=?,introduction=?,updated_at=? WHERE id=?`, enabled, title, introduction, updatedAt, dashboardID); err != nil {
			return err
		}
	} else if err := tx.QueryRowContext(ctx, `INSERT INTO public_dashboards(tenant_id,enabled,title,introduction,updated_at) VALUES(?,?,?,?,?) RETURNING id`, DefaultTenantID, enabled, title, introduction, updatedAt).Scan(&dashboardID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM public_dashboard_hosts WHERE dashboard_id=?`, dashboardID); err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for _, host := range hosts {
		address, err := normalizePublicAddress(host.Address)
		if err != nil {
			return err
		}
		if strings.TrimSpace(host.JobID) == "" {
			return errors.New("public dashboard host job is required")
		}
		key := host.JobID + "\x00" + address
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		if _, err := tx.ExecContext(ctx, `INSERT INTO public_dashboard_hosts(dashboard_id,job_id,address,created_at) VALUES(?,?,?,?)`, dashboardID, host.JobID, address, updatedAt); err != nil {
			return err
		}
	}
	if audit.Action != "" {
		if err := insertAuditEntryExec(ctx, tx, audit, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetLatestSuccessfulJobHosts returns the newest successful observation for
// each selected job/address. The maintained latest_scan_hosts projection
// answers the common case without ranking retained history. A selection can
// still miss that projection when the same address is monitored by more than
// one job (the projection is address-keyed), so those misses are resolved
// through a bounded history query.
func (s *Store) GetLatestSuccessfulJobHosts(ctx context.Context, selections []PublicDashboardHost) ([]PublicDashboardHostResult, error) {
	if len(selections) == 0 {
		return []PublicDashboardHostResult{}, nil
	}
	if len(selections) > 1000 {
		selections = selections[:1000]
	}
	normalized := make([]PublicDashboardHost, 0, len(selections))
	seen := make(map[string]struct{}, len(selections))
	for _, selection := range selections {
		address, err := normalizePublicAddress(selection.Address)
		if err != nil || strings.TrimSpace(selection.JobID) == "" {
			continue
		}
		selection.JobID = strings.TrimSpace(selection.JobID)
		selection.Address = address
		key := selection.JobID + "\x00" + address
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, selection)
	}
	if len(normalized) == 0 {
		return []PublicDashboardHostResult{}, nil
	}
	values := make([]string, len(normalized))
	args := make([]any, 0, len(normalized)*2)
	for i, selection := range normalized {
		values[i] = "(?,?)"
		args = append(args, selection.JobID, selection.Address)
	}
	projectionQuery := `WITH selected(job_id,address) AS (VALUES ` + strings.Join(values, ",") + `)
SELECT selected.job_id,selected.address,h.scan_id,h.data_quality,h.host_json,
       sc.id,sc.job_id,sc.job_revision,sc.job,sc.started_at,sc.finished_at,sc.status,sc.error,sc.nmap_version,sc.config_hash,
       sc.cycle_id,sc.cycle_attempt,sc.cycle_status,sc.resumable,sc.completed_probes,sc.total_probes,sc.completed_units,sc.total_units,sc.no_progress_attempts,
       sc.baseline_scan_id,sc.baseline_config_hash,sc.scanner_engine,sc.scanner_profile_id,sc.scanner_profile_revision,sc.naabu_version,sc.discovery_ports,sc.confirmed_ports,sc.discovery_duration_ms,sc.enrichment_duration_ms
FROM selected
JOIN latest_scan_hosts h ON h.address=selected.address AND h.job_id=selected.job_id
JOIN scans sc ON sc.id=h.scan_id AND sc.job_id=selected.job_id AND sc.status='success'
ORDER BY selected.address,selected.job_id`
	rows, err := s.reader().QueryContext(ctx, projectionQuery, args...)
	if err != nil {
		return nil, err
	}
	results := make([]PublicDashboardHostResult, 0, len(normalized))
	found := make(map[string]struct{}, len(normalized))
	if err := readPublicDashboardHostRows(rows, &results, found); err != nil {
		return nil, err
	}

	if len(found) < len(normalized) {
		missing := make([]PublicDashboardHost, 0, len(normalized)-len(found))
		for _, selection := range normalized {
			key := selection.JobID + "\x00" + selection.Address
			if _, ok := found[key]; !ok {
				missing = append(missing, selection)
			}
		}
		if len(missing) > 0 {
			history, err := s.getLatestSuccessfulJobHostsHistory(ctx, missing)
			if err != nil {
				return nil, err
			}
			for _, item := range history {
				key := item.Selection.JobID + "\x00" + item.Selection.Address
				if _, ok := found[key]; ok {
					continue
				}
				found[key] = struct{}{}
				results = append(results, item)
			}
		}
	}

	sort.Slice(results, func(i, j int) bool {
		left := results[i].Selection.Address + "\x00" + results[i].Selection.JobID
		right := results[j].Selection.Address + "\x00" + results[j].Selection.JobID
		return left < right
	})
	return results, nil
}

// readPublicDashboardHostRows decodes the shared projection shape used by
// the maintained latest-host query and its bounded indexed-history fallback.
func readPublicDashboardHostRows(rows *sql.Rows, results *[]PublicDashboardHostResult, found map[string]struct{}) error {
	defer rows.Close()
	for rows.Next() {
		var selection PublicDashboardHost
		var host ScanHost
		var raw []byte
		var summary model.ScanSummary
		var jobID sql.NullString
		var revision sql.NullInt64
		var resumable int
		var started, finished string
		if err := rows.Scan(&selection.JobID, &selection.Address, &host.ScanID, &host.DataQuality, &raw,
			&summary.ID, &jobID, &revision, &summary.Job, &started, &finished, &summary.Status, &summary.Error, &summary.NmapVersion, &summary.ConfigHash,
			&summary.CycleID, &summary.CycleAttempt, &summary.CycleStatus, &resumable, &summary.CompletedProbes, &summary.TotalProbes, &summary.CompletedUnits, &summary.TotalUnits, &summary.NoProgressTries,
			&summary.BaselineScanID, &summary.BaselineConfigHash, &summary.ScannerEngine, &summary.ScannerProfileID, &summary.ScannerProfileRevision, &summary.NaabuVersion, &summary.DiscoveryPorts, &summary.ConfirmedPorts, &summary.DiscoveryDurationMS, &summary.EnrichmentDurationMS); err != nil {
			return err
		}
		key := selection.JobID + "\x00" + selection.Address
		if _, exists := found[key]; exists {
			continue
		}
		if jobID.Valid {
			summary.JobID = jobID.String
		}
		if revision.Valid {
			summary.JobRevision = revision.Int64
		}
		summary.Resumable = resumable != 0
		summary.StartedAt, summary.FinishedAt = scanTime(started), scanTime(finished)
		decoded, err := decodeScanHost(selection.Address, host.DataQuality, raw)
		if err != nil {
			return err
		}
		host.Host = decoded.Host
		*results = append(*results, PublicDashboardHostResult{Selection: selection, Host: host, Summary: summary})
		found[key] = struct{}{}
	}
	return rows.Err()
}

// getLatestSuccessfulJobHostsHistory resolves selected pairs with an indexed
// newest-row lookup. It is reserved for pairs absent from the maintained
// latest-host projection, such as an address monitored by multiple jobs. The
// correlated lookup is deliberately scoped to each selected address/job pair;
// it avoids materializing and sorting every matching history row for the whole
// dashboard request.
func (s *Store) getLatestSuccessfulJobHostsHistory(ctx context.Context, selections []PublicDashboardHost) ([]PublicDashboardHostResult, error) {
	if len(selections) == 0 {
		return []PublicDashboardHostResult{}, nil
	}
	// Public dashboard writes cap the selection at 1000. Keep the store method
	// bounded as well for trusted callers and avoid SQLite variable-limit errors.
	if len(selections) > 1000 {
		selections = selections[:1000]
	}
	normalized := make([]PublicDashboardHost, 0, len(selections))
	seen := make(map[string]struct{}, len(selections))
	for _, selection := range selections {
		address, err := normalizePublicAddress(selection.Address)
		if err != nil || strings.TrimSpace(selection.JobID) == "" {
			continue
		}
		selection.JobID = strings.TrimSpace(selection.JobID)
		selection.Address = address
		key := selection.JobID + "\x00" + address
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, selection)
	}
	if len(normalized) == 0 {
		return []PublicDashboardHostResult{}, nil
	}
	query, args := latestSuccessfulJobHostsHistoryQuery(normalized)
	rows, err := s.reader().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	results := make([]PublicDashboardHostResult, 0, len(normalized))
	if err := readPublicDashboardHostRows(rows, &results, make(map[string]struct{}, len(normalized))); err != nil {
		return nil, err
	}
	return results, nil
}

func latestSuccessfulJobHostsHistoryQuery(selections []PublicDashboardHost) (string, []any) {
	values := make([]string, len(selections))
	args := make([]any, 0, len(selections)*2)
	for i, selection := range selections {
		values[i] = "(?,?)"
		args = append(args, selection.JobID, selection.Address)
	}
	query := `WITH selected(job_id,address) AS (VALUES ` + strings.Join(values, ",") + `)
SELECT selected.job_id,selected.address,h.scan_id,h.data_quality,h.host_json,
       sc.id,sc.job_id,sc.job_revision,sc.job,sc.started_at,sc.finished_at,sc.status,sc.error,sc.nmap_version,sc.config_hash,
       sc.cycle_id,sc.cycle_attempt,sc.cycle_status,sc.resumable,sc.completed_probes,sc.total_probes,sc.completed_units,sc.total_units,sc.no_progress_attempts,
       sc.baseline_scan_id,sc.baseline_config_hash,sc.scanner_engine,sc.scanner_profile_id,sc.scanner_profile_revision,sc.naabu_version,sc.discovery_ports,sc.confirmed_ports,sc.discovery_duration_ms,sc.enrichment_duration_ms
FROM selected
JOIN scan_hosts h ON h.address=selected.address
 AND h.scan_id=(
   SELECT h2.scan_id
   FROM scan_hosts h2
   JOIN scans sc2 ON sc2.id=h2.scan_id
   WHERE h2.address=selected.address
     AND sc2.job_id=selected.job_id
     AND sc2.status='success'
   ORDER BY sc2.finished_at DESC,sc2.id DESC
   LIMIT 1
 )
JOIN scans sc ON sc.id=h.scan_id AND sc.job_id=selected.job_id AND sc.status='success'
ORDER BY selected.address,selected.job_id`
	return query, args
}

// GetLatestSuccessfulJobHost is deliberately scoped by both job and address;
// a public selection cannot pivot into another job's observation. It remains
// as a compatibility wrapper over the set-based implementation.
func (s *Store) GetLatestSuccessfulJobHost(ctx context.Context, jobID, address string) (ScanHost, model.ScanSummary, error) {
	results, err := s.GetLatestSuccessfulJobHosts(ctx, []PublicDashboardHost{{JobID: jobID, Address: address}})
	if err != nil {
		return ScanHost{}, model.ScanSummary{}, err
	}
	if len(results) == 0 {
		return ScanHost{}, model.ScanSummary{}, ErrNotFound
	}
	return results[0].Host, results[0].Summary, nil
}
