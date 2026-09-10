package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// BaselineExportVersion identifies the portable JSON representation. The
// format is intentionally independent from SQLite schema versions so exports
// remain useful across upgrades.
const BaselineExportVersion = 1

// BaselineExport is a portable, redacted view of every selected managed or
// legacy baseline. It contains no notification URLs, encryption keys, session
// data, or audit secrets. A job with no active baseline is included with a
// null baseline so an all-jobs export also describes readiness.
type BaselineExport struct {
	FormatVersion int                   `json:"format_version"`
	ExportedAt    time.Time             `json:"exported_at"`
	Jobs          []BaselineExportEntry `json:"jobs"`
}

// BaselineExportEntry contains the identity and immutable source metadata
// needed to compare or report a baseline outside EdgeWatch. SourceScan is
// metadata only; the snapshot is copied from runtime state so an accepted
// incident is represented accurately even when it differs from the source
// scan.
type BaselineExportEntry struct {
	JobID              string             `json:"job_id,omitempty"`
	Name               string             `json:"name"`
	Revision           int64              `json:"revision,omitempty"`
	Archived           bool               `json:"archived,omitempty"`
	Legacy             bool               `json:"legacy,omitempty"`
	Status             string             `json:"status"`
	BaselineScanID     string             `json:"baseline_scan_id,omitempty"`
	BaselineConfigHash string             `json:"baseline_config_hash,omitempty"`
	Baseline           *model.Snapshot    `json:"baseline"`
	SourceScan         *model.ScanSummary `json:"source_scan,omitempty"`
}

// ExportBaselines returns the current runtime baseline for one managed job,
// or every managed and legacy job when name is empty. Legacy job_states rows
// are included for portability but are explicitly marked so they cannot be
// mistaken for a newly recreated managed job.
func (s *Store) ExportBaselines(ctx context.Context, name string) (BaselineExport, error) {
	result := BaselineExport{FormatVersion: BaselineExportVersion, ExportedAt: time.Now().UTC(), Jobs: []BaselineExportEntry{}}
	name = strings.TrimSpace(name)
	managed, err := s.ListJobs(ctx, true)
	if err != nil {
		return result, err
	}
	seen := make(map[string]bool, len(managed))
	if name != "" {
		var selected JobRecord
		selectedFound := false
		for _, record := range managed {
			if record.Job.Name == name || record.ID == name {
				selected = record
				selectedFound = true
				break
			}
		}
		if !selectedFound {
			legacy, legacyErr := s.exportLegacyBaseline(ctx, name)
			if legacyErr != nil {
				if !errors.Is(legacyErr, sql.ErrNoRows) {
					return result, legacyErr
				}
				return result, fmt.Errorf("%w: job %s", ErrNotFound, name)
			}
			result.Jobs = append(result.Jobs, legacy)
			return result, nil
		}
		entry, err := s.exportManagedBaseline(ctx, selected)
		if err != nil {
			return result, err
		}
		result.Jobs = append(result.Jobs, entry)
		return result, nil
	}

	for _, record := range managed {
		seen[record.Job.Name] = true
		entry, err := s.exportManagedBaseline(ctx, record)
		if err != nil {
			return result, err
		}
		result.Jobs = append(result.Jobs, entry)
	}
	// Legacy states are deliberately read one row at a time and only decoded
	// once. They have no stable UUID or revision, and are not attached to newly
	// created jobs with the same display name.
	type legacyRow struct {
		name string
		raw  []byte
	}
	legacyRows, err := func() ([]legacyRow, error) {
		rows, err := s.reader().QueryContext(ctx, `SELECT job,state_json FROM job_states ORDER BY job`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		legacyRows := make([]legacyRow, 0)
		for rows.Next() {
			var legacyName string
			var raw []byte
			if err := rows.Scan(&legacyName, &raw); err != nil {
				return nil, err
			}
			legacyRows = append(legacyRows, legacyRow{name: legacyName, raw: raw})
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return legacyRows, nil
	}()
	if err != nil {
		return result, err
	}
	for _, legacy := range legacyRows {
		legacyName := legacy.name
		if seen[legacyName] {
			continue
		}
		entry, err := s.exportLegacyBaselineJSON(ctx, legacyName, legacy.raw)
		if err != nil {
			return result, err
		}
		result.Jobs = append(result.Jobs, entry)
	}
	sort.SliceStable(result.Jobs, func(i, j int) bool {
		if result.Jobs[i].Name != result.Jobs[j].Name {
			return result.Jobs[i].Name < result.Jobs[j].Name
		}
		return result.Jobs[i].JobID < result.Jobs[j].JobID
	})
	return result, nil
}

func (s *Store) exportLegacyBaseline(ctx context.Context, name string) (BaselineExportEntry, error) {
	var raw []byte
	if err := s.reader().QueryRowContext(ctx, `SELECT state_json FROM job_states WHERE job=?`, name).Scan(&raw); err != nil {
		return BaselineExportEntry{}, err
	}
	return s.exportLegacyBaselineJSON(ctx, name, raw)
}

func (s *Store) exportLegacyBaselineJSON(ctx context.Context, name string, raw []byte) (BaselineExportEntry, error) {
	var state model.JobState
	if err := json.Unmarshal(raw, &state); err != nil {
		return BaselineExportEntry{}, err
	}
	entry := BaselineExportEntry{Name: name, Legacy: true, Status: "not_ready", BaselineScanID: state.BaselineScanID, BaselineConfigHash: state.BaselineConfigHash, Baseline: state.Baseline}
	if state.Baseline != nil {
		entry.Status = "ready"
	}
	if state.BaselineScanID != "" {
		if summary, summaryErr := s.GetScanSummary(ctx, state.BaselineScanID); summaryErr == nil {
			entry.SourceScan = &summary
		}
	}
	return entry, nil
}

func (s *Store) exportManagedBaseline(ctx context.Context, record JobRecord) (BaselineExportEntry, error) {
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		return BaselineExportEntry{}, err
	}
	entry := BaselineExportEntry{
		JobID:              record.ID,
		Name:               record.Job.Name,
		Revision:           record.Revision,
		Archived:           record.Archived,
		Status:             "not_ready",
		BaselineScanID:     state.BaselineScanID,
		BaselineConfigHash: state.BaselineConfigHash,
		Baseline:           state.Baseline,
	}
	if state.Baseline != nil {
		entry.Status = "ready"
	}
	if state.BaselineScanID != "" {
		if summary, summaryErr := s.GetScanSummary(ctx, state.BaselineScanID); summaryErr == nil {
			entry.SourceScan = &summary
		}
	}
	return entry, nil
}
