package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestStoreHistoryRuntimeAndLeaseWrappers(t *testing.T) {
	ctx, s, job, _ := cycleFixture(t)
	now := time.Now().UTC()
	scan := model.Scan{
		ID: "wrapper-scan", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name,
		StartedAt: now, FinishedAt: now, Status: "success", NmapVersion: "7.99",
		ConfigHash: job.Job.SecurityHash(), Changes: []model.Change{{Key: "port|192.0.2.1|tcp|22", Kind: "port", Severity: "high", Target: "192.0.2.1", Protocol: "tcp", Port: 22}},
		Snapshot: model.Snapshot{Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 22, State: "open"}}}}, Hosts: []model.HostObservation{{Address: "192.0.2.1", Status: "up", Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "22", ScannedPortCount: 1, Ports: []model.PortObservation{{Port: 22, State: "open"}}}}}}},
	}
	second := scan
	second.ID = "wrapper-scan-2"
	second.Status = "timed_out"
	second.FinishedAt = now.Add(-time.Minute)
	if err := s.SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveScan(ctx, second); err != nil {
		t.Fatal(err)
	}

	jobScans, err := s.ListJobScans(ctx, job.ID, 0)
	if err != nil || len(jobScans) != 2 || jobScans[0].ID != scan.ID {
		t.Fatalf("job scans = %#v, %v", jobScans, err)
	}
	jobSummaries, err := s.ListJobScanSummariesPage(ctx, job.ID, 1, 0)
	if err != nil || jobSummaries.Total != 2 || len(jobSummaries.Items) != 1 || jobSummaries.Items[0].ID != scan.ID {
		t.Fatalf("job summaries = %#v, %v", jobSummaries, err)
	}
	allScans, err := s.ListScans(ctx, job.Job.Name, 1)
	if err != nil || len(allScans) != 1 || allScans[0].ID != scan.ID {
		t.Fatalf("legacy scans = %#v, %v", allScans, err)
	}
	allPage, err := s.ListScansPage(ctx, "", 1, -1)
	if err != nil || allPage.Total != 2 || len(allPage.Items) != 1 {
		t.Fatalf("all scan page = %#v, %v", allPage, err)
	}
	legacySummaries, err := s.ListScanSummariesPage(ctx, job.Job.Name, 0, 0)
	if err != nil || legacySummaries.Total != 2 || len(legacySummaries.Items) != 2 {
		t.Fatalf("legacy summaries = %#v, %v", legacySummaries, err)
	}
	if indexed, err := s.SuccessfulScanHostIndexExists(ctx); err != nil || !indexed {
		t.Fatalf("successful host index = %v, %v", indexed, err)
	}

	legacyEvents, err := s.UpdateState(ctx, "legacy-name", func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "legacy-baseline"
		return []model.Event{{Type: "legacy-event", Job: "legacy-name", Message: "legacy transition", CreatedAt: now}}, nil
	})
	if err != nil || len(legacyEvents) != 1 {
		t.Fatalf("legacy state update = %#v, %v", legacyEvents, err)
	}
	legacyState, err := s.State(ctx, "legacy-name")
	if err != nil || legacyState.BaselineScanID != "legacy-baseline" {
		t.Fatalf("legacy state = %#v, %v", legacyState, err)
	}
	if events, err := s.ListEvents(ctx, "legacy-name", 10); err != nil || len(events) != 1 {
		t.Fatalf("legacy events = %#v, %v", events, err)
	}
	if page, err := s.ListEventsPage(ctx, "legacy-name", 10, 0); err != nil || page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("legacy event page = %#v, %v", page, err)
	}

	managedEvents, err := s.UpdateRuntimeForScan(ctx, job.ID, job.Job.SecurityHash(), func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "managed-baseline"
		return []model.Event{{Type: "managed-event", Job: job.Job.Name, Message: "managed transition", CreatedAt: now}}, nil
	})
	if err != nil || len(managedEvents) != 1 {
		t.Fatalf("managed state update = %#v, %v", managedEvents, err)
	}
	managedWithOutbox, err := s.UpdateRuntimeForScanWithOutbox(ctx, job.ID, job.Job.SecurityHash(), []string{"deployment"}, func(state *model.JobState) ([]model.Event, error) {
		state.BaselineConfigHash = "managed-hash"
		return []model.Event{{Type: "managed-outbox-event", Job: job.Job.Name, Message: "queued transition", CreatedAt: now}}, nil
	})
	if err != nil || len(managedWithOutbox) != 1 {
		t.Fatalf("managed outbox update = %#v, %v", managedWithOutbox, err)
	}
	if state, err := s.RuntimeState(ctx, job.ID); err != nil || state.BaselineConfigHash != "managed-hash" {
		t.Fatalf("managed runtime state = %#v, %v", state, err)
	}
	if scanID, hash, err := s.RuntimeBaselineMeta(ctx, job.ID); err != nil || scanID != "managed-baseline" || hash != "managed-hash" {
		t.Fatalf("runtime baseline metadata = %q, %q, %v", scanID, hash, err)
	}
	if events, err := s.ListJobEvents(ctx, job.ID, 10); err != nil || len(events) != 2 {
		t.Fatalf("managed events = %#v, %v", events, err)
	}
	if _, err := s.ListJobEventsPage(ctx, job.ID, 1, 1); err != nil {
		t.Fatal(err)
	}

	if _, err := s.ApproveRuntime(ctx, job.ID, job.Job.Name, scan); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveRuntimeWithOutboxAndAudit(ctx, job.ID, job.Job.Name, scan, []string{"deployment"}, AuditEntry{Action: "baseline.approve", Detail: "wrapper test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(ctx, job.Job.Name, scan); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetBaseline(ctx, job.Job.Name); err != nil {
		t.Fatal(err)
	}
	if state, err := s.State(ctx, job.Job.Name); err != nil || state.Baseline != nil || state.BaselineScanID != "" {
		t.Fatalf("reset legacy baseline = %#v, %v", state, err)
	}

	if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,attempts,next_at) VALUES(?,?,?,?)`, "failed-destination", []byte(`{}`), deliveryMaxAttempts, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if failed, err := s.FailedDeliveries(ctx); err != nil || failed != 1 {
		t.Fatalf("failed deliveries = %d, %v", failed, err)
	}
}

func TestStoreDaemonLeaseHealthTransitions(t *testing.T) {
	ctx, s, _, _ := cycleFixture(t)
	if err := s.AcquireLease(ctx, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := s.Heartbeat(ctx, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := s.Healthy(ctx); err != nil {
		t.Fatalf("fresh lease health = %v", err)
	}
	if err := s.Heartbeat(ctx, "other"); err == nil {
		t.Fatal("heartbeat from another owner succeeded")
	}
	old := time.Now().UTC().Add(-3 * time.Minute).Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(ctx, `UPDATE daemon_lease SET heartbeat=? WHERE id=1`, old); err != nil {
		t.Fatal(err)
	}
	if err := s.Healthy(ctx); err == nil {
		t.Fatal("stale lease was reported healthy")
	}
	if err := s.ReleaseLease(ctx, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := s.Healthy(ctx); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("released lease health error = %v", err)
	}
}

func TestDeliveryRetryPolicyIsDurableAndBounded(t *testing.T) {
	if got := deliveryRetryDelay(1); got != 2*time.Minute {
		t.Fatalf("first delivery retry delay = %s, want 2m", got)
	}
	if got := deliveryRetryDelay(2); got != 4*time.Minute {
		t.Fatalf("second delivery retry delay = %s, want 4m", got)
	}
	if got := deliveryRetryDelay(deliveryMaxAttempts); got != time.Hour {
		t.Fatalf("terminal delivery retry delay = %s, want 1h cap", got)
	}

	ctx := context.Background()
	s := openTestStore(t)
	if err := s.QueueEvent(ctx, "retry-policy", model.Event{Type: "retry-policy", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < deliveryMaxAttempts; attempt++ {
		if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE destination=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), "retry-policy"); err != nil {
			t.Fatal(err)
		}
		due, err := s.ClaimDueDeliveries(ctx, 1, fmt.Sprintf("retry-owner-%d", attempt))
		if err != nil || len(due) != 1 {
			t.Fatalf("retry claim %d = %#v, %v", attempt+1, due, err)
		}
		if err := s.DeliveryResult(ctx, due[0].ID, errors.New("temporary provider failure")); err != nil {
			t.Fatal(err)
		}
	}
	if failed, err := s.FailedDeliveries(ctx); err != nil || failed != 1 {
		t.Fatalf("terminal delivery count = %d, %v", failed, err)
	}
	if due, err := s.ClaimDueDeliveries(ctx, 1, "after-terminal"); err != nil || len(due) != 0 {
		t.Fatalf("terminal delivery was claimable again: %#v, %v", due, err)
	}
}

func TestDeliveryHealthTracksRedactedOutcomesAndTerminalEvent(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	secret := "provider password=super-secret"
	if err := s.QueueEvent(ctx, "destination", model.Event{Type: "health", Job: "job", Message: "first", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	health, err := s.ListDeliveryHealth(ctx)
	if err != nil || health["destination"].Pending != 1 {
		t.Fatalf("pending health = %#v, %v", health, err)
	}

	for attempt := 1; attempt <= deliveryMaxAttempts; attempt++ {
		if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE destination=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), "destination"); err != nil {
			t.Fatal(err)
		}
		due, err := s.ClaimDueDeliveries(ctx, 1, fmt.Sprintf("health-owner-%d", attempt))
		if err != nil || len(due) != 1 {
			t.Fatalf("claim %d = %#v, %v", attempt, due, err)
		}
		if err := s.DeliveryResult(ctx, due[0].ID, errors.New(secret)); err != nil {
			t.Fatal(err)
		}
	}

	health, err = s.ListDeliveryHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	item := health["destination"]
	if item.Pending != 0 || item.Retrying != 0 || item.TerminalFailures != 1 || item.LastErrorCode != "delivery_failed" || item.LastErrorFingerprint == "" {
		t.Fatalf("terminal health = %#v", item)
	}
	var storedError string
	if err := s.DB.QueryRowContext(ctx, `SELECT last_error FROM outbox WHERE destination=?`, "destination").Scan(&storedError); err != nil {
		t.Fatal(err)
	}
	if storedError == secret || strings.Contains(storedError, "super-secret") {
		t.Fatalf("provider error leaked into outbox: %q", storedError)
	}
	var payload []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT payload_json FROM events WHERE type=?`, "notification-delivery-terminal").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), secret) || !strings.Contains(string(payload), "delivery_failed") {
		t.Fatalf("terminal event was not redacted: %s", payload)
	}

	if err := s.QueueEvent(ctx, "destination", model.Event{Type: "health", Job: "job", Message: "second", CreatedAt: time.Now().UTC().Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	due, err := s.ClaimDueDeliveries(ctx, 1, "health-success")
	if err != nil || len(due) != 1 {
		t.Fatalf("success claim = %#v, %v", due, err)
	}
	if err := s.DeliveryResult(ctx, due[0].ID, nil); err != nil {
		t.Fatal(err)
	}
	health, err = s.ListDeliveryHealth(ctx)
	if err != nil || health["destination"].LastSuccessAt.IsZero() {
		t.Fatalf("success health = %#v, %v", health, err)
	}
}

func TestDeliveryDeferralsAreBoundedAndVisible(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.QueueEvent(ctx, "deferred", model.Event{Type: "deferred", Message: "locked", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for deferral := 0; deferral < deliveryMaxDeferrals; deferral++ {
		if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE destination=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), "deferred"); err != nil {
			t.Fatal(err)
		}
		due, err := s.ClaimDueDeliveries(ctx, 1, fmt.Sprintf("defer-owner-%d", deferral))
		if err != nil || len(due) != 1 {
			t.Fatalf("deferral claim %d = %#v, %v", deferral+1, due, err)
		}
		if err := s.DeferDeliveryWithError(ctx, due[0].ID, due[0].ClaimToken, ErrDeliveryDestinationLocked, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	var attempts, deferrals int
	var terminalAt, lastError string
	if err := s.DB.QueryRowContext(ctx, `SELECT attempts,deferrals,terminal_at,last_error FROM outbox WHERE destination=?`, "deferred").Scan(&attempts, &deferrals, &terminalAt, &lastError); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || deferrals != deliveryMaxDeferrals || terminalAt == "" || lastError != "destination_locked" {
		t.Fatalf("bounded deferral state = attempts %d, deferrals %d, terminal %q, error %q", attempts, deferrals, terminalAt, lastError)
	}
	if due, err := s.ClaimDueDeliveries(ctx, 1, "after-deferral-limit"); err != nil || len(due) != 0 {
		t.Fatalf("terminally deferred delivery was claimable: %#v, %v", due, err)
	}
	health, err := s.ListDeliveryHealth(ctx)
	if err != nil || health["deferred"].TerminalFailures != 1 || health["deferred"].Pending != 0 {
		t.Fatalf("bounded deferral health = %#v, %v", health["deferred"], err)
	}
	failed, err := s.FailedDeliveries(ctx)
	if err != nil || failed != 1 {
		t.Fatalf("bounded deferral failures = %d, %v", failed, err)
	}
	var payload []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT payload_json FROM events WHERE type=?`, "notification-delivery-terminal").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), "deferral limit") || !strings.Contains(string(payload), "destination_locked") {
		t.Fatalf("bounded deferral terminal event = %s", payload)
	}
}
