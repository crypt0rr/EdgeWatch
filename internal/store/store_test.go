package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestScanStateAndEventPersistence(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	scan := model.Scan{ID: "scan-1", Job: "job", StartedAt: time.Now(), FinishedAt: time.Now(), Status: "success", ConfigHash: "hash", Snapshot: model.Snapshot{}}
	if err := s.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetScan(ctx, "scan-1")
	if err != nil || got.Job != "job" {
		t.Fatalf("scan: %#v %v", got, err)
	}
	events, err := s.UpdateState(ctx, "job", func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "scan-1"
		return []model.Event{{Type: "test", Job: "job", ScanID: "scan-1", CreatedAt: time.Now()}}, nil
	})
	if err != nil || len(events) != 1 {
		t.Fatal(err)
	}
	history, err := s.ListEvents(ctx, "job", 10)
	if err != nil || len(history) != 1 {
		t.Fatalf("events: %#v %v", history, err)
	}
}

func TestRuntimeAndNotificationIntentCommitTogether(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("job"))
	if err != nil {
		t.Fatal(err)
	}
	destinations := []string{"destination-a", "managed:destination-b:2"}
	events, err := s.UpdateRuntimeWithOutbox(ctx, record.ID, destinations, func(state *model.JobState) ([]model.Event, error) {
		state.ConsecutiveFailures = 3
		return []model.Event{{Type: "alert", Job: "job", ScanID: "scan", Message: "changed", CreatedAt: time.Now().UTC()}}, nil
	})
	if err != nil || len(events) != 1 {
		t.Fatalf("runtime transition: %#v %v", events, err)
	}
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != len(destinations) {
		t.Fatalf("notification intent rows = %d, want %d", count, len(destinations))
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil || state.ConsecutiveFailures != 3 {
		t.Fatalf("runtime state: %#v %v", state, err)
	}
}

func TestLeaseCanBeReleased(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.AcquireLease(ctx, "one"); err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireLease(ctx, "two"); err == nil {
		t.Fatal("second lease acquired")
	}
	if err := s.ReleaseLease(ctx, "one"); err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireLease(ctx, "two"); err != nil {
		t.Fatal(err)
	}
}

func TestJobLeasePreventsConcurrentRunsAndExpires(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.AcquireJobLease(ctx, "job", "one", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireJobLease(ctx, "job", "two", time.Now().Add(time.Hour)); !errors.Is(err, ErrJobBusy) {
		t.Fatalf("expected busy, got %v", err)
	}
	if _, err := s.DB.Exec(`UPDATE job_leases SET expires_at=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireJobLease(ctx, "job", "two", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("expired lease not replaced: %v", err)
	}
}

func TestOutboxRetriesAndCompletes(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	event := model.Event{Type: "test", Job: "job", CreatedAt: time.Now()}
	if err := s.QueueEvent(ctx, "destination", event); err != nil {
		t.Fatal(err)
	}
	due, err := s.DueDeliveries(ctx, 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("due %#v %v", due, err)
	}
	if err := s.DeliveryResult(ctx, due[0].ID, errors.New("failed")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE outbox SET next_at=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	due, err = s.DueDeliveries(ctx, 10)
	if err != nil || len(due) != 1 || due[0].Attempts != 1 {
		t.Fatalf("retry %#v %v", due, err)
	}
	if err := s.DeliveryResult(ctx, due[0].ID, nil); err != nil {
		t.Fatal(err)
	}
	due, _ = s.DueDeliveries(ctx, 10)
	if len(due) != 0 {
		t.Fatal("sent delivery remained due")
	}
}

func TestOutboxClaimsAreExclusiveAndRequireOwner(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.QueueEvent(ctx, "destination", model.Event{Type: "claim", Job: "job", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	first, err := s.ClaimDueDeliveries(ctx, 10, "owner-one")
	if err != nil || len(first) != 1 || first[0].ClaimToken != "owner-one" {
		t.Fatalf("first claim %#v %v", first, err)
	}
	second, err := s.ClaimDueDeliveries(ctx, 10, "owner-two")
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 0 {
		t.Fatalf("active claim was handed to another owner: %#v", second)
	}
	if err := s.DeliveryResultClaim(ctx, first[0].ID, "wrong-owner", nil); !errors.Is(err, ErrDeliveryClaimLost) {
		t.Fatalf("wrong owner result = %v, want claim lost", err)
	}
	if err := s.DeliveryResultClaim(ctx, first[0].ID, first[0].ClaimToken, nil); err != nil {
		t.Fatal(err)
	}
	third, err := s.ClaimDueDeliveries(ctx, 10, "owner-three")
	if err != nil {
		t.Fatal(err)
	}
	if len(third) != 0 {
		t.Fatalf("completed delivery remained claimable: %#v", third)
	}
}

func TestDeferredDeliveryDoesNotConsumeAttempts(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.QueueEvent(ctx, "managed:destination:1", model.Event{Type: "defer", Job: "job", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	due, err := s.ClaimDueDeliveries(ctx, 1, "owner")
	if err != nil || len(due) != 1 {
		t.Fatalf("claim %#v %v", due, err)
	}
	if err := s.DeferDelivery(ctx, due[0].ID, due[0].ClaimToken, "key unavailable", time.Minute); err != nil {
		t.Fatal(err)
	}
	var attempts int
	if err := s.DB.QueryRowContext(ctx, `SELECT attempts FROM outbox WHERE id=?`, due[0].ID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Fatalf("deferred attempts = %d, want 0", attempts)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE id=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), due[0].ID); err != nil {
		t.Fatal(err)
	}
	if retry, err := s.ClaimDueDeliveries(ctx, 1, "retry-owner"); err != nil || len(retry) != 1 {
		t.Fatalf("deferred row was not retryable: %#v %v", retry, err)
	}
}

func TestPrunePreservesLegacyAndManagedBaselines(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	old := time.Now().UTC().Add(-48 * time.Hour)
	for _, id := range []string{"legacy-baseline", "managed-baseline", "discard"} {
		if err := s.SaveScan(ctx, model.Scan{ID: id, Job: "legacy", StartedAt: old, FinishedAt: old, Status: "success", Snapshot: model.Snapshot{}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.UpdateState(ctx, "legacy", func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "legacy-baseline"
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	managed, err := s.CreateJob(ctx, testJob("managed"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateRuntime(ctx, managed.ID, func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "managed-baseline"
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prune(ctx, time.Now().UTC().Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"legacy-baseline", "managed-baseline"} {
		if _, err := s.GetScan(ctx, id); err != nil {
			t.Fatalf("baseline scan %s was pruned: %v", id, err)
		}
	}
	if _, err := s.GetScan(ctx, "discard"); err == nil {
		t.Fatal("unreferenced old scan was not pruned")
	}
}

func TestPruneRetentionClassesAndAuditPolicy(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	old := time.Now().UTC().Add(-48 * time.Hour)
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	oldText := old.Format(time.RFC3339Nano)

	job, err := s.CreateJob(ctx, testJob("retention"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetJobEnabledWithRevision(ctx, job.ID, false, job.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_revisions SET created_at=? WHERE job_id=? AND revision=1`, oldText, job.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := s.DB.ExecContext(ctx, `INSERT INTO events(type,job,payload_json,created_at) VALUES(?,?,?,?)`, "old-event", "retention", []byte(`{}`), oldText); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO security_audit(action,detail,created_at) VALUES(?,?,?)`, "old-audit", "keep", oldText); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueEvent(ctx, "sent", model.Event{Type: "sent", Job: "retention", CreatedAt: old}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET sent_at=? WHERE destination=?`, oldText, "sent"); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueEvent(ctx, "failed", model.Event{Type: "failed", Job: "retention", CreatedAt: old}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET attempts=3,next_at=? WHERE destination=?`, oldText, "failed"); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueEvent(ctx, "pending", model.Event{Type: "pending", Job: "retention", CreatedAt: old}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE destination=?`, oldText, "pending"); err != nil {
		t.Fatal(err)
	}

	stats, err := s.PruneWithStats(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Events != 1 || stats.SentOutbox != 1 || stats.FailedOutbox != 1 || stats.Revisions != 1 {
		t.Fatalf("unexpected prune stats: %#v", stats)
	}
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination=?`, "pending").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("pending delivery was pruned")
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action=?`, "old-audit").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("security audit record was pruned")
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_revisions WHERE job_id=?`, job.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("current job revision was pruned; rows=%d", count)
	}
}

func TestPruneRetainsRevisionsReferencedByScans(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	job, err := s.CreateJob(ctx, testJob("revision-reference"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetJobEnabledWithRevision(ctx, job.ID, false, job.Revision); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_revisions SET created_at=? WHERE job_id=? AND revision=1`, old, job.ID); err != nil {
		t.Fatal(err)
	}
	scan := model.Scan{ID: "retained-revision-scan", JobID: job.ID, Job: job.Job.Name, JobRevision: 1, StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), Status: "success", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{}}
	if err := s.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	stats, err := s.PruneWithStats(ctx, time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Revisions != 0 {
		t.Fatalf("referenced revision was pruned: %#v", stats)
	}
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_revisions WHERE job_id=? AND revision=1`, job.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("revision referenced by retained scan was removed")
	}
}

func TestHistoryPagesHaveStableMetadataAndOrdering(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("paged"))
	if err != nil {
		t.Fatal(err)
	}
	when := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if err := s.SaveScan(ctx, model.Scan{ID: string(rune('a' + i)), JobID: record.ID, JobRevision: 1, Job: record.Job.Name, StartedAt: when, FinishedAt: when, Status: "success", Snapshot: model.Snapshot{}}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
			return []model.Event{{Type: "page", Job: record.Job.Name, CreatedAt: when}}, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.ListJobScansPage(ctx, record.ID, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || len(page.Items) != 2 || page.Items[0].ID != "b" || page.Items[1].ID != "a" {
		t.Fatalf("unexpected scan page: total=%d items=%#v", page.Total, page.Items)
	}
	events, err := s.ListJobEventsPage(ctx, record.ID, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if events.Total != 3 || len(events.Items) != 2 {
		t.Fatalf("unexpected event page: total=%d items=%#v", events.Total, events.Items)
	}
}
