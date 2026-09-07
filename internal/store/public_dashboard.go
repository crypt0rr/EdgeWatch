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
	err := s.DB.QueryRowContext(ctx, `SELECT enabled,title,introduction,updated_at FROM public_dashboard WHERE id=1`).Scan(&enabled, &d.Title, &d.Introduction, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	d.Enabled = enabled != 0
	d.UpdatedAt = scanTime(updated)
	rows, err := s.DB.QueryContext(ctx, `SELECT job_id,address,created_at FROM public_dashboard_hosts WHERE dashboard_id=1 ORDER BY job_id,address`)
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

// GetLatestSuccessfulJobHost is deliberately scoped by both job and address;
// a public selection cannot pivot into another job's observation.
func (s *Store) GetLatestSuccessfulJobHost(ctx context.Context, jobID, address string) (ScanHost, model.ScanSummary, error) {
	normalized, err := normalizePublicAddress(address)
	if err != nil {
		return ScanHost{}, model.ScanSummary{}, ErrNotFound
	}
	var scanID, dataQuality string
	var raw []byte
	err = s.DB.QueryRowContext(ctx, `SELECT h.scan_id,h.data_quality,h.host_json FROM scan_hosts h JOIN scans sc ON sc.id=h.scan_id WHERE sc.job_id=? AND sc.status='success' AND h.address=? ORDER BY sc.finished_at DESC,sc.id DESC LIMIT 1`, jobID, normalized).Scan(&scanID, &dataQuality, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ScanHost{}, model.ScanSummary{}, ErrNotFound
	}
	if err != nil {
		return ScanHost{}, model.ScanSummary{}, err
	}
	host, err := decodeScanHost(normalized, dataQuality, raw)
	if err != nil {
		return ScanHost{}, model.ScanSummary{}, err
	}
	host.ScanID = scanID
	summary, err := s.GetScanSummary(ctx, scanID)
	if err != nil {
		return ScanHost{}, model.ScanSummary{}, err
	}
	return host, summary, nil
}
