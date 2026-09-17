package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestBaselineExpectationGuardsAuditedResetAndApproval(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("runtime-expectation"))
	if err != nil {
		t.Fatal(err)
	}
	audit := AuditEntry{Action: "baseline.test", Detail: "expectation coverage"}

	if events, err := s.ResetRuntimeWithExpectationAndAudit(ctx, record.ID, record.Job.Name, nil, audit, BaselineExpectation{ScanIDSet: true, ModifiedSet: true}); err != nil || len(events) != 1 || events[0].Type != "baseline-reset" {
		t.Fatalf("initial guarded reset = %#v, %v", events, err)
	}
	if _, err := s.ResetRuntimeWithExpectationAndAudit(ctx, record.ID, record.Job.Name, nil, audit, BaselineExpectation{ScanID: "stale", ScanIDSet: true}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale guarded reset = %v, want ErrConflict", err)
	}

	now := time.Now().UTC()
	scan := model.Scan{
		ID: "runtime-expectation-scan", JobID: record.ID, JobRevision: record.Revision,
		Job: record.Job.Name, StartedAt: now, FinishedAt: now, Status: "success",
		ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{},
	}
	if err := s.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if events, err := s.ApproveRuntimeWithExpectationAndAudit(ctx, record.ID, record.Job.Name, scan, nil, audit, BaselineExpectation{ScanIDSet: true, ScanID: ""}); err != nil || len(events) != 1 || events[0].Type != "baseline-approved" {
		t.Fatalf("initial guarded approval = %#v, %v", events, err)
	}
	if _, err := s.ApproveRuntimeWithExpectationAndAudit(ctx, record.ID, record.Job.Name, scan, nil, audit, BaselineExpectation{Modified: true, ModifiedSet: true}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale guarded approval = %v, want ErrConflict", err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineScanID != scan.ID || state.BaselineModified {
		t.Fatalf("approved runtime state = %#v", state)
	}
}
