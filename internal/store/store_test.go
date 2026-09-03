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
