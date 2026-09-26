package store

import (
	"context"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestRuntimeBaselineInfoUsesCompactMetadata(t *testing.T) {
	ctx, s, job, _ := cycleFixture(t)
	_, err := s.UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "baseline-scan"
		state.BaselineConfigHash = "baseline-hash"
		state.BaselineModified = true
		state.Baseline = &model.Snapshot{}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The metadata row is written in the same transaction as the runtime state.
	// Corrupting the large JSON after that commit must not affect the compact
	// host-page marker or force a full decode on the current path.
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_runtime SET state_json=? WHERE job_id=?`, []byte("not-json"), job.ID); err != nil {
		t.Fatal(err)
	}
	info, err := s.RuntimeBaselineInfo(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if info.BaselineScanID != "baseline-scan" || info.BaselineConfigHash != "baseline-hash" || !info.BaselineModified || info.ProjectionVersion != 1 {
		t.Fatalf("compact baseline info = %#v", info)
	}
	if scanID, hash, err := s.RuntimeBaselineMeta(ctx, job.ID); err != nil || scanID != "baseline-scan" || hash != "baseline-hash" {
		t.Fatalf("compatibility metadata = %q, %q, %v", scanID, hash, err)
	}
	if modified, err := s.RuntimeBaselineModified(ctx, job.ID); err != nil || !modified {
		t.Fatalf("compatibility marker = %t, %v", modified, err)
	}
}

func TestRuntimeMetadataMigrationBackfillsLegacyRows(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `DROP TABLE job_runtime_meta; PRAGMA user_version = 36`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO jobs(id,tenant_id,name,definition_json,enabled,archived,revision,created_at,updated_at) VALUES('legacy-meta',?,'legacy-meta','{}',1,0,1,?,?)`, DefaultTenantID, time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_runtime(job_id,state_json,updated_at) VALUES(?,?,?)`, "legacy-meta", []byte(`{"baseline_scan_id":"old-scan","baseline_config_hash":"old-hash","baseline_modified":1}`), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := migrate(s.DB); err != nil {
		t.Fatal(err)
	}
	info, err := s.RuntimeBaselineInfo(ctx, "legacy-meta")
	if err != nil {
		t.Fatal(err)
	}
	if info.BaselineScanID != "old-scan" || info.BaselineConfigHash != "old-hash" || !info.BaselineModified {
		t.Fatalf("backfilled metadata = %#v", info)
	}
	var version int
	if err := s.DB.QueryRowContext(ctx, `SELECT metadata_version FROM job_runtime_meta WHERE job_id=?`, "legacy-meta").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("metadata version = %d", version)
	}
}
