package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestJobListingLifecycleIdempotenceAndPermanentDeletionGuards(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	alpha, err := s.CreateJobWithEnabledAndAudit(ctx, testJob("alpha"), true, AuditEntry{Action: "job.created", Detail: "alpha"})
	if err != nil {
		t.Fatal(err)
	}
	beta, err := s.CreateJobWithEnabled(ctx, testJob("beta"), false)
	if err != nil {
		t.Fatal(err)
	}

	active, err := s.ListJobs(ctx, false)
	if err != nil || len(active) != 2 || active[0].Job.Name != "alpha" || active[1].Job.Name != "beta" {
		t.Fatalf("active jobs = %#v, %v", active, err)
	}
	if err := s.SetJobArchivedWithRevisionAndAudit(ctx, beta.ID, true, beta.Revision, AuditEntry{Action: "job.archived", Detail: beta.ID}); err != nil {
		t.Fatal(err)
	}
	archived, err := s.GetJob(ctx, beta.ID)
	if err != nil || !archived.Archived || archived.Enabled || archived.Revision != beta.Revision+1 {
		t.Fatalf("archived job = %#v, %v", archived, err)
	}
	all, err := s.ListJobs(ctx, true)
	if err != nil || len(all) != 2 || !all[1].Archived {
		t.Fatalf("all jobs = %#v, %v", all, err)
	}
	active, err = s.ListJobs(ctx, false)
	if err != nil || len(active) != 1 || active[0].ID != alpha.ID {
		t.Fatalf("filtered jobs = %#v, %v", active, err)
	}

	// Repeating a lifecycle action is intentionally idempotent: it records the
	// audit entry but does not create a phantom revision.
	if err := s.SetJobArchivedWithRevisionAndAudit(ctx, beta.ID, true, archived.Revision, AuditEntry{Action: "job.archived.repeat", Detail: beta.ID}); err != nil {
		t.Fatal(err)
	}
	repeated, err := s.GetJob(ctx, beta.ID)
	if err != nil || repeated.Revision != archived.Revision {
		t.Fatalf("idempotent archive changed revision: %#v, %v", repeated, err)
	}
	if err := s.SetJobArchivedWithRevision(ctx, beta.ID, false, archived.Revision); err != nil {
		t.Fatal(err)
	}
	restored, err := s.GetJob(ctx, beta.ID)
	if err != nil || restored.Archived || restored.Enabled || restored.Revision != archived.Revision+1 {
		t.Fatalf("restored job = %#v, %v", restored, err)
	}
	if err := s.SetJobEnabledWithRevisionAndAudit(ctx, beta.ID, true, restored.Revision, AuditEntry{Action: "job.resumed", Detail: beta.ID}); err != nil {
		t.Fatal(err)
	}
	resumed, err := s.GetJob(ctx, beta.ID)
	if err != nil || !resumed.Enabled || resumed.Revision != restored.Revision+1 {
		t.Fatalf("resumed job = %#v, %v", resumed, err)
	}
	if err := s.SetJobEnabledWithRevisionAndAudit(ctx, beta.ID, true, resumed.Revision, AuditEntry{Action: "job.resumed.repeat", Detail: beta.ID}); err != nil {
		t.Fatal(err)
	}
	unchanged, err := s.GetJob(ctx, beta.ID)
	if err != nil || unchanged.Revision != resumed.Revision {
		t.Fatalf("idempotent resume changed revision: %#v, %v", unchanged, err)
	}
	if err := s.SetJobEnabledWithRevision(ctx, beta.ID, false, resumed.Revision-1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale pause error = %v", err)
	}

	if err := s.DeleteJob(ctx, alpha.ID); err == nil || !strings.Contains(err.Error(), "archived") {
		t.Fatalf("active job deletion error = %v", err)
	}
	if err := s.SetJobArchived(ctx, alpha.ID, true); err != nil {
		t.Fatal(err)
	}
	when := time.Now().UTC()
	if err := s.SaveScan(ctx, model.Scan{ID: "alpha-scan", JobID: alpha.ID, Job: alpha.Job.Name, StartedAt: when, FinishedAt: when, Status: "success", Snapshot: model.Snapshot{}}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteJob(ctx, alpha.ID); err == nil || !strings.Contains(err.Error(), "retained scan history") {
		t.Fatal("job with scan history was deleted")
	}
	if err := s.DeleteJob(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing deletion error = %v", err)
	}

	// A job with no retained scans/events can be permanently removed after it
	// has been archived, while its deletion audit remains append-only.
	if err := s.SetJobArchived(ctx, beta.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteJobWithAudit(ctx, beta.ID, AuditEntry{Action: "job.deleted", Detail: beta.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetJob(ctx, beta.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted job lookup = %v", err)
	}
	var audits int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='job.deleted' AND detail=?`, beta.ID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("deletion audit count = %d", audits)
	}
}

func TestJobActiveAndLeaseExpiry(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("lease"))
	if err != nil {
		t.Fatal(err)
	}
	active, err := s.JobActive(ctx, record.ID)
	if err != nil || active {
		t.Fatalf("job initially active = %v, %v", active, err)
	}
	if err := s.AcquireJobLease(ctx, record.ID, "owner", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	active, err = s.JobActive(ctx, record.ID)
	if err != nil || !active {
		t.Fatalf("leased job active = %v, %v", active, err)
	}
	if err := s.DeleteJob(ctx, record.ID); err == nil || !strings.Contains(err.Error(), "archived") {
		t.Fatalf("unarchived job deletion error = %v", err)
	}
	if err := s.SetJobArchived(ctx, record.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteJob(ctx, record.ID); err == nil || !errors.Is(err, ErrJobScanActive) {
		t.Fatalf("active archived job deletion error = %v", err)
	}
	if err := s.ReleaseJobLease(ctx, record.ID, "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "lease-test"
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
}
