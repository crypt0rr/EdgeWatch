package store

import (
	"testing"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestRuntimeBaselineInfoUsesCompactMetadata(t *testing.T) {
	t.Parallel()
	ctx, s, job, _ := cycleFixture(t)
	_, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
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
	info, err := defaultTenant(s).RuntimeBaselineInfo(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if info.BaselineScanID != "baseline-scan" || info.BaselineConfigHash != "baseline-hash" || !info.BaselineModified || info.ProjectionVersion != 1 {
		t.Fatalf("compact baseline info = %#v", info)
	}
	if scanID, hash, err := defaultTenant(s).RuntimeBaselineMeta(ctx, job.ID); err != nil || scanID != "baseline-scan" || hash != "baseline-hash" {
		t.Fatalf("compatibility metadata = %q, %q, %v", scanID, hash, err)
	}
	if modified, err := defaultTenant(s).RuntimeBaselineModified(ctx, job.ID); err != nil || !modified {
		t.Fatalf("compatibility marker = %t, %v", modified, err)
	}
}
