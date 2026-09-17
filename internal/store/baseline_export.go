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
	FormatVersion int `json:"format_version"`
	// ExportedAt is operational metadata for in-process callers. It is omitted
	// from the serialized artifact so two exports of identical state have a
	// byte-identical canonical body.
	ExportedAt time.Time             `json:"-"`
	Jobs       []BaselineExportEntry `json:"jobs"`
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
	ShadowedByJobID    string             `json:"shadowed_by_job_id,omitempty"`
	Status             string             `json:"status"`
	BaselineScanID     string             `json:"baseline_scan_id,omitempty"`
	BaselineConfigHash string             `json:"baseline_config_hash,omitempty"`
	Baseline           *model.Snapshot    `json:"baseline"`
	SourceScan         *model.ScanSummary `json:"source_scan,omitempty"`
}

type exportQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// ExportBaselines returns the current runtime baseline for one managed job,
// or every managed and legacy job when name is empty. Legacy job_states rows
// are included for portability but are explicitly marked so they cannot be
// mistaken for a newly recreated managed job.
func (s *Store) ExportBaselines(ctx context.Context, name string) (BaselineExport, error) {
	result := BaselineExport{FormatVersion: BaselineExportVersion, ExportedAt: time.Now().UTC(), Jobs: []BaselineExportEntry{}}
	name = strings.TrimSpace(name)
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback() }()
	managed, err := listJobsForExport(ctx, tx, true)
	if err != nil {
		return result, err
	}
	seen := make(map[string]string, len(managed))
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
			legacy, legacyErr := exportLegacyBaselineForQuery(ctx, tx, name)
			if legacyErr != nil {
				if !errors.Is(legacyErr, sql.ErrNoRows) {
					return result, legacyErr
				}
				return result, fmt.Errorf("%w: job %s", ErrNotFound, name)
			}
			result.Jobs = append(result.Jobs, legacy)
			return result, nil
		}
		entry, err := exportManagedBaselineForQuery(ctx, tx, selected)
		if err != nil {
			return result, err
		}
		result.Jobs = append(result.Jobs, entry)
		return result, nil
	}

	for _, record := range managed {
		seen[record.Job.Name] = record.ID
		entry, err := exportManagedBaselineForQuery(ctx, tx, record)
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
		rows, err := tx.QueryContext(ctx, `SELECT job,state_json FROM job_states ORDER BY job`)
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
		entry, err := exportLegacyBaselineJSONForQuery(ctx, tx, legacyName, legacy.raw)
		if err != nil {
			return result, err
		}
		if managedID := seen[legacyName]; managedID != "" {
			// Keep both records in an all-jobs export. Name-based lookup still
			// prefers managed jobs, but silently dropping a legacy baseline would
			// make an archival artifact lose state. The explicit link lets
			// consumers disambiguate the shadowed legacy entry.
			entry.ShadowedByJobID = managedID
		}
		result.Jobs = append(result.Jobs, entry)
	}
	sort.SliceStable(result.Jobs, func(i, j int) bool {
		if result.Jobs[i].Name != result.Jobs[j].Name {
			return result.Jobs[i].Name < result.Jobs[j].Name
		}
		// Prefer the managed record when a legacy state has the same display
		// name. Both records remain present, but consumers that render a
		// name-grouped list should see the authoritative UUID-backed entry first.
		if result.Jobs[i].Legacy != result.Jobs[j].Legacy {
			return !result.Jobs[i].Legacy
		}
		return result.Jobs[i].JobID < result.Jobs[j].JobID
	})
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

func (s *Store) exportLegacyBaseline(ctx context.Context, name string) (BaselineExportEntry, error) {
	return exportLegacyBaselineForQuery(ctx, s.reader(), name)
}

func exportLegacyBaselineForQuery(ctx context.Context, queryer exportQueryer, name string) (BaselineExportEntry, error) {
	var raw []byte
	if err := queryer.QueryRowContext(ctx, `SELECT state_json FROM job_states WHERE job=?`, name).Scan(&raw); err != nil {
		return BaselineExportEntry{}, err
	}
	return exportLegacyBaselineJSONForQuery(ctx, queryer, name, raw)
}

func (s *Store) exportLegacyBaselineJSON(ctx context.Context, name string, raw []byte) (BaselineExportEntry, error) {
	return exportLegacyBaselineJSONForQuery(ctx, s.reader(), name, raw)
}

func exportLegacyBaselineJSONForQuery(ctx context.Context, queryer exportQueryer, name string, raw []byte) (BaselineExportEntry, error) {
	var state model.JobState
	if err := json.Unmarshal(raw, &state); err != nil {
		return BaselineExportEntry{}, err
	}
	entry := BaselineExportEntry{Name: name, Legacy: true, Status: "not_ready", BaselineScanID: state.BaselineScanID, BaselineConfigHash: state.BaselineConfigHash, Baseline: state.Baseline}
	if state.Baseline != nil {
		entry.Status = "ready"
	}
	if state.BaselineScanID != "" {
		if summary, summaryErr := getScanSummaryForQuery(ctx, queryer, state.BaselineScanID); summaryErr == nil {
			entry.SourceScan = &summary
		}
	}
	return entry, nil
}

func (s *Store) exportManagedBaseline(ctx context.Context, record JobRecord) (BaselineExportEntry, error) {
	return exportManagedBaselineForQuery(ctx, s.reader(), record)
}

func exportManagedBaselineForQuery(ctx context.Context, queryer exportQueryer, record JobRecord) (BaselineExportEntry, error) {
	var raw []byte
	err := queryer.QueryRowContext(ctx, `SELECT state_json FROM job_runtime WHERE job_id=?`, record.ID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		raw = []byte(`{}`)
	} else if err != nil {
		return BaselineExportEntry{}, err
	}
	var state model.JobState
	if err := json.Unmarshal(raw, &state); err != nil {
		return BaselineExportEntry{}, err
	}
	ensureMaps(&state)
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
		if summary, summaryErr := getScanSummaryForQuery(ctx, queryer, state.BaselineScanID); summaryErr == nil {
			entry.SourceScan = &summary
		}
	}
	return entry, nil
}

func listJobsForExport(ctx context.Context, queryer exportQueryer, includeArchived bool) ([]JobRecord, error) {
	query := `SELECT id,name,definition_json,enabled,archived,revision,created_at,updated_at FROM jobs`
	if !includeArchived {
		query += ` WHERE archived=0`
	}
	query += ` ORDER BY archived ASC,name,id`
	rows, err := queryer.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JobRecord
	for rows.Next() {
		var record JobRecord
		var raw []byte
		var enabled, archived int
		var created, updated string
		if err := rows.Scan(&record.ID, &record.Job.Name, &raw, &enabled, &archived, &record.Revision, &created, &updated); err != nil {
			return nil, err
		}
		job, err := unmarshalJob(raw)
		if err != nil {
			return nil, err
		}
		record.Job = job
		record.Enabled, record.Archived = enabled != 0, archived != 0
		record.CreatedAt, record.UpdatedAt = scanTime(created), scanTime(updated)
		out = append(out, record)
	}
	return out, rows.Err()
}

func getScanSummaryForQuery(ctx context.Context, queryer exportQueryer, id string) (model.ScanSummary, error) {
	var v model.ScanSummary
	var started, finished string
	var jobID sql.NullString
	var revision sql.NullInt64
	var resumable int
	err := queryer.QueryRowContext(ctx, `SELECT id,job_id,job_revision,job,started_at,finished_at,status,error,nmap_version,scanner_engine,scanner_profile_id,scanner_profile_revision,naabu_version,discovery_ports,confirmed_ports,discovery_duration_ms,enrichment_duration_ms,config_hash,cycle_id,cycle_attempt,cycle_status,resumable,completed_probes,total_probes,completed_units,total_units,no_progress_attempts,baseline_scan_id,baseline_config_hash FROM scans WHERE id=?`, id).
		Scan(&v.ID, &jobID, &revision, &v.Job, &started, &finished, &v.Status, &v.Error, &v.NmapVersion, &v.ScannerEngine, &v.ScannerProfileID, &v.ScannerProfileRevision, &v.NaabuVersion, &v.DiscoveryPorts, &v.ConfirmedPorts, &v.DiscoveryDurationMS, &v.EnrichmentDurationMS, &v.ConfigHash, &v.CycleID, &v.CycleAttempt, &v.CycleStatus, &resumable, &v.CompletedProbes, &v.TotalProbes, &v.CompletedUnits, &v.TotalUnits, &v.NoProgressTries, &v.BaselineScanID, &v.BaselineConfigHash)
	if err != nil {
		return v, err
	}
	if jobID.Valid {
		v.JobID = jobID.String
	}
	if revision.Valid {
		v.JobRevision = revision.Int64
	}
	v.Resumable = resumable != 0
	v.StartedAt, v.FinishedAt = scanTime(started), scanTime(finished)
	return v, nil
}
