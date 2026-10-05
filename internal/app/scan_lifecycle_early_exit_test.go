package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestScanLifecycleCompletesWhenCycleStallsAfterStart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, db := newLifecycleTestApp(t, &lifecycleScanner{}, nil)
	record, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("stalled-lifecycle-event"))
	if err != nil {
		t.Fatal(err)
	}
	var events []model.Event
	a.SetEventHandler(func(event model.Event) {
		events = append(events, event)
		if event.Type != "scan.started" {
			return
		}
		plan, err := (&lifecycleScanner{}).Plan(ctx, record.Job)
		if err != nil {
			t.Errorf("create concurrent cycle plan: %v", err)
			return
		}
		cycle, err := db.System().CreateScanCycle(ctx, store.ScanCycleRecord{
			JobID: record.ID, Job: record.Job.Name, JobRevision: record.Revision,
			ConfigHash: record.Job.SecurityHash(), ExecutionHash: record.Job.ExecutionHash(), Plan: plan,
		})
		if err != nil {
			t.Errorf("create concurrent scan cycle: %v", err)
			return
		}
		if _, err := db.DB.ExecContext(ctx, `UPDATE scan_cycles SET status='stalled' WHERE id=?`, cycle.ID); err != nil {
			t.Errorf("stall concurrent scan cycle: %v", err)
		}
	})

	if _, _, err := a.runJobRecord(ctx, record, false); !errors.Is(err, ErrScanCycleStalled) {
		t.Fatalf("scheduled run with a newly stalled cycle = %v, want %v", err, ErrScanCycleStalled)
	}
	assertBalancedScanLifecycle(t, events, record.ID)
	if got := eventByType(events, "scan.completed").Message; !strings.Contains(strings.ToLower(got), "stalled") || strings.Contains(strings.ToLower(got), "success") {
		t.Fatalf("stalled lifecycle message = %q, want truthful stalled outcome without success", got)
	}
	if scans, err := defaultTenant(db).ListJobScans(ctx, record.ID, 10); err != nil || len(scans) != 0 {
		t.Fatalf("stalled attempt persisted scans = %#v, %v", scans, err)
	}
}

func TestScanLifecycleCompletesWhenNotificationDestinationsCannotLoad(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, db := newLifecycleTestApp(t, schedulerFake{}, nil)
	record, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("notification-config-lifecycle-event"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `DROP TABLE managed_notifications`); err != nil {
		t.Fatal(err)
	}
	var events []model.Event
	a.SetEventHandler(func(event model.Event) { events = append(events, event) })
	scan, _, runErr := a.RunJobRecord(ctx, record)
	if runErr == nil {
		t.Fatal("scan unexpectedly finalized after notification destination lookup failed")
	}
	assertBalancedScanLifecycle(t, events, record.ID)
	if got := eventByType(events, "scan.completed").Message; !strings.Contains(strings.ToLower(got), "notification") || strings.Contains(strings.ToLower(got), "success") {
		t.Fatalf("notification lookup lifecycle message = %q, want truthful finalization failure without success", got)
	}
	if scan.ID == "" || eventByType(events, "scan.completed").ScanID != scan.ID {
		t.Fatalf("saved scan %q and terminal lifecycle event do not match: %#v", scan.ID, events)
	}
	if scan.Status != "success" {
		t.Fatalf("test expected the scanner result to be successful before notification routing failed, got %q", scan.Status)
	}
}

func assertBalancedScanLifecycle(t *testing.T, events []model.Event, jobID string) {
	t.Helper()
	if len(events) < 2 || events[0].Type != "scan.started" {
		t.Fatalf("lifecycle events = %#v, want scan.started followed by scan.completed", events)
	}
	var completed []model.Event
	for _, event := range events {
		if event.Type == "scan.completed" {
			completed = append(completed, event)
		}
	}
	if len(completed) != 1 {
		t.Fatalf("scan.completed events = %#v, want exactly one", completed)
	}
	if completed[0].JobID != jobID || completed[0].ScanID == "" || completed[0].ScanID != events[0].ScanID {
		t.Fatalf("unmatched lifecycle events: started=%#v completed=%#v", events[0], completed[0])
	}
	if events[0].CreatedAt.IsZero() || completed[0].CreatedAt.IsZero() || completed[0].CreatedAt.Before(events[0].CreatedAt) {
		t.Fatalf("invalid lifecycle timestamps: started=%s completed=%s", events[0].CreatedAt, completed[0].CreatedAt)
	}
	if completed[0].TenantID != store.DefaultTenantID {
		t.Fatalf("terminal event tenant = %q", completed[0].TenantID)
	}
}

func eventByType(events []model.Event, eventType string) model.Event {
	for _, event := range events {
		if event.Type == eventType {
			return event
		}
	}
	return model.Event{}
}
