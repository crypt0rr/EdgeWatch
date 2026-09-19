package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestTimestampNormalizationPreservesChronologicalScanOrdering(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("timestamp-ordering"))
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	for _, id := range []string{"earlier", "later"} {
		if err := s.SaveScan(ctx, model.Scan{
			ID:         id,
			JobID:      record.ID,
			Job:        record.Job.Name,
			StartedAt:  base,
			FinishedAt: base,
			Status:     "success",
			Snapshot:   model.Snapshot{},
		}); err != nil {
			t.Fatal(err)
		}
	}

	// These values represent 100 ms and 900 ms in the same second. Their
	// historical variable-width form sorts in the opposite order lexically.
	if _, err := s.DB.ExecContext(ctx, `UPDATE scans SET started_at=?,finished_at=? WHERE id=?`, "2026-09-19T12:00:00.1Z", "2026-09-19T12:00:00.1Z", "earlier"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scans SET started_at=?,finished_at=? WHERE id=?`, "2026-09-19T12:00:00.9Z", "2026-09-19T12:00:00.9Z", "later"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE timestamp_normalization_state SET complete=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := normalizePersistedTimestampsContext(ctx, s.DB); err != nil {
		t.Fatal(err)
	}

	var finished string
	if err := s.DB.QueryRowContext(ctx, `SELECT finished_at FROM scans WHERE id='earlier'`).Scan(&finished); err != nil {
		t.Fatal(err)
	}
	if finished != "2026-09-19T12:00:00.100000000Z" {
		t.Fatalf("normalized timestamp = %q", finished)
	}
	latest, err := s.GetLatestSuccessfulJobScanSummary(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if latest == nil || latest.ID != "later" {
		t.Fatalf("latest scan = %#v, want later", latest)
	}
}

func TestOpenReportsTemporaryDirectoryFailure(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "tmp"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(root, "edgewatch.db")); err == nil {
		t.Fatal("Open unexpectedly succeeded with a file occupying the temporary directory")
	}
}

func TestTimestampNormalizationHandlesMarkerStatesAndInvalidValues(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM timestamp_normalization_state`); err != nil {
		t.Fatal(err)
	}
	if err := normalizePersistedTimestampsContext(ctx, s.DB); err != nil {
		t.Fatalf("missing marker row: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE timestamp_normalization_state SET complete=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := normalizePersistedTimestampsContext(ctx, s.DB); err != nil {
		t.Fatalf("completed marker: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO scans(id,job_id,job,started_at,finished_at,status,config_hash,snapshot_json) VALUES(?,?,?,?,?,?,?,?)`, "invalid-timestamp", "missing-job", "missing", "not-a-timestamp", "not-a-timestamp", "success", "", `{}`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE timestamp_normalization_state SET complete=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := normalizePersistedTimestampsContext(ctx, s.DB); err != nil {
		t.Fatalf("invalid timestamp: %v", err)
	}
}

func TestSQLiteTimestampUsesFixedWidthUTC(t *testing.T) {
	value := sqliteTimestamp(time.Date(2026, 9, 19, 12, 0, 0, 123456789, time.FixedZone("offset", 2*60*60)))
	if value != "2026-09-19T10:00:00.123456789Z" {
		t.Fatalf("sqlite timestamp = %q", value)
	}
	if normalized, ok := normalizeSQLiteTimestamp("2026-09-19T12:00:00.1+02:00"); !ok || normalized != "2026-09-19T10:00:00.100000000Z" {
		t.Fatalf("normalized timestamp = %q, ok=%v", normalized, ok)
	}
}
