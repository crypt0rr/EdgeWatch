package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestBaselineReplacementActionsRejectActiveScan(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("baseline-guard"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scan := model.Scan{
		ID:          "baseline-guard-scan",
		JobID:       record.ID,
		JobRevision: record.Revision,
		Job:         record.Job.Name,
		StartedAt:   now,
		FinishedAt:  now,
		Status:      "success",
		ConfigHash:  record.Job.SecurityHash(),
		Snapshot:    model.Snapshot{},
	}
	if err := s.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireJobLeaseForRevision(ctx, record.ID, "baseline-guard-owner", record.Revision, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetRuntime(ctx, record.ID, record.Job.Name); !errors.Is(err, ErrJobScanActive) {
		t.Fatalf("baseline reset while scanning = %v, want ErrJobScanActive", err)
	}
	if _, err := s.ApproveRuntime(ctx, record.ID, record.Job.Name, scan); !errors.Is(err, ErrJobScanActive) {
		t.Fatalf("baseline approval while scanning = %v, want ErrJobScanActive", err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline != nil || state.BaselineScanID != "" {
		t.Fatalf("active baseline action changed runtime state: %#v", state)
	}
}
