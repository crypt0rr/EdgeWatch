package store

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"strings"
	"time"

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

func (s *Store) GetPublicDashboard(ctx context.Context) (PublicDashboard, error) {
	var d PublicDashboard
	var enabled int
	var updated string
	reader := s.reader()
	err := reader.QueryRowContext(ctx, `SELECT enabled,title,introduction,updated_at FROM public_dashboard WHERE id=1`).Scan(&enabled, &d.Title, &d.Introduction, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	d.Enabled = enabled != 0
	d.UpdatedAt = scanTime(updated)
	rows, err := reader.QueryContext(ctx, `SELECT job_id,address,created_at FROM public_dashboard_hosts WHERE dashboard_id=1 ORDER BY job_id,address`)
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
// job never implicitly publishes all of its current or future hosts.
func (s *Store) SavePublicDashboard(ctx context.Context, dashboard PublicDashboard, hosts []PublicDashboardHost, audit AuditEntry) error {
	if strings.TrimSpace(dashboard.Title) == "" {
		dashboard.Title = "EdgeWatch public status"
	}
	if len(dashboard.Title) > 120 || len(dashboard.Introduction) > 500 {
		return errors.New("public dashboard text is too long")
	}
	now := time.Now().UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO public_dashboard(id,enabled,title,introduction,updated_at) VALUES(1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,title=excluded.title,introduction=excluded.introduction,updated_at=excluded.updated_at`, boolInt(dashboard.Enabled), strings.TrimSpace(dashboard.Title), strings.TrimSpace(dashboard.Introduction), now.Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM public_dashboard_hosts WHERE dashboard_id=1`); err != nil {
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
		if _, err := tx.ExecContext(ctx, `INSERT INTO public_dashboard_hosts(dashboard_id,job_id,address,created_at) VALUES(1,?,?,?)`, host.JobID, address, now.Format(time.RFC3339Nano)); err != nil {
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

// GetLatestSuccessfulJobHosts returns the newest successful indexed
// observation for each selected job/address in one set-based query. Missing
// selections are omitted so callers can apply a bounded legacy fallback.
func (s *Store) GetLatestSuccessfulJobHosts(ctx context.Context, selections []PublicDashboardHost) ([]PublicDashboardHostResult, error) {
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
	values := make([]string, len(normalized))
	args := make([]any, 0, len(normalized)*2)
	for i, selection := range normalized {
		values[i] = "(?,?)"
		args = append(args, selection.JobID, selection.Address)
	}
	query := `WITH selected(job_id,address) AS (VALUES ` + strings.Join(values, ",") + `), ranked AS (
 SELECT selected.job_id AS selected_job_id, selected.address AS selected_address,
        h.scan_id,h.data_quality,h.host_json,
        sc.id,sc.job_id,sc.job_revision,sc.job,sc.started_at,sc.finished_at,sc.status,sc.error,sc.nmap_version,sc.config_hash,
        sc.cycle_id,sc.cycle_attempt,sc.cycle_status,sc.resumable,sc.completed_probes,sc.total_probes,sc.completed_units,sc.total_units,sc.no_progress_attempts,
        sc.baseline_scan_id,sc.baseline_config_hash,sc.scanner_engine,sc.scanner_profile_id,sc.scanner_profile_revision,sc.naabu_version,sc.discovery_ports,sc.confirmed_ports,sc.discovery_duration_ms,sc.enrichment_duration_ms,
        ROW_NUMBER() OVER (PARTITION BY selected.job_id,selected.address ORDER BY sc.finished_at DESC,sc.id DESC) AS rn
 FROM selected
 JOIN scan_hosts h ON h.address=selected.address
 JOIN scans sc ON sc.id=h.scan_id AND sc.job_id=selected.job_id AND sc.status='success'
) SELECT selected_job_id,selected_address,scan_id,data_quality,host_json,
         id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,config_hash,
         cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,
         baseline_scan_id,baseline_config_hash,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms
 FROM ranked WHERE rn=1 ORDER BY selected_address,selected_job_id`
	rows, err := s.reader().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	results := make([]PublicDashboardHostResult, 0, len(normalized))
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
			return nil, err
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
			return nil, err
		}
		host.Host = decoded.Host
		results = append(results, PublicDashboardHostResult{Selection: selection, Host: host, Summary: summary})
	}
	return results, rows.Err()
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
