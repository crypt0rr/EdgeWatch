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
	if err := s.System().SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if err := s.System().SaveScan(ctx, second); err != nil {
		t.Fatal(err)
	}

	jobScans, err := defaultTenant(s).ListJobScans(ctx, job.ID, 0)
	if err != nil || len(jobScans) != 2 || jobScans[0].ID != scan.ID {
		t.Fatalf("job scans = %#v, %v", jobScans, err)
	}
	jobSummaries, err := defaultTenant(s).ListJobScanSummariesPage(ctx, job.ID, 1, 0)
	if err != nil || jobSummaries.Total != 2 || len(jobSummaries.Items) != 1 || jobSummaries.Items[0].ID != scan.ID {
		t.Fatalf("job summaries = %#v, %v", jobSummaries, err)
	}
	allScans, err := defaultTenant(s).ListScans(ctx, job.Job.Name, 1)
	if err != nil || len(allScans) != 1 || allScans[0].ID != scan.ID {
		t.Fatalf("legacy scans = %#v, %v", allScans, err)
	}
	allPage, err := defaultTenant(s).ListScansPage(ctx, "", 1, -1)
	if err != nil || allPage.Total != 2 || len(allPage.Items) != 1 {
		t.Fatalf("all scan page = %#v, %v", allPage, err)
	}
	legacySummaries, err := defaultTenant(s).ListScanSummariesPage(ctx, job.Job.Name, 0, 0)
	if err != nil || legacySummaries.Total != 2 || len(legacySummaries.Items) != 2 {
		t.Fatalf("legacy summaries = %#v, %v", legacySummaries, err)
	}
	if indexed, err := defaultTenant(s).SuccessfulScanHostIndexExists(ctx); err != nil || !indexed {
		t.Fatalf("successful host index = %v, %v", indexed, err)
	}

	legacyEvents, err := s.System().UpdateState(ctx, "legacy-name", func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "legacy-baseline"
		return []model.Event{{Type: "legacy-event", Job: "legacy-name", Message: "legacy transition", CreatedAt: now}}, nil
	})
	if err != nil || len(legacyEvents) != 1 {
		t.Fatalf("legacy state update = %#v, %v", legacyEvents, err)
	}
	legacyState, err := defaultTenant(s).State(ctx, "legacy-name")
	if err != nil || legacyState.BaselineScanID != "legacy-baseline" {
		t.Fatalf("legacy state = %#v, %v", legacyState, err)
	}
	if events, err := defaultTenant(s).ListEvents(ctx, "legacy-name", 10); err != nil || len(events) != 1 {
		t.Fatalf("legacy events = %#v, %v", events, err)
	}
	if page, err := defaultTenant(s).ListEventsPage(ctx, "legacy-name", 10, 0); err != nil || page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("legacy event page = %#v, %v", page, err)
	}

	managedEvents, err := s.System().UpdateRuntimeForScan(ctx, job.ID, job.Job.SecurityHash(), func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "managed-baseline"
		return []model.Event{{Type: "managed-event", Job: job.Job.Name, Message: "managed transition", CreatedAt: now}}, nil
	})
	if err != nil || len(managedEvents) != 1 {
		t.Fatalf("managed state update = %#v, %v", managedEvents, err)
	}
	managedWithOutbox, err := s.System().UpdateRuntimeForScanWithOutbox(ctx, job.ID, job.Job.SecurityHash(), []string{"deployment"}, func(state *model.JobState) ([]model.Event, error) {
		state.BaselineConfigHash = "managed-hash"
		return []model.Event{{Type: "managed-outbox-event", Job: job.Job.Name, Message: "queued transition", CreatedAt: now}}, nil
	})
	if err != nil || len(managedWithOutbox) != 1 {
		t.Fatalf("managed outbox update = %#v, %v", managedWithOutbox, err)
	}
	if state, err := defaultTenant(s).RuntimeState(ctx, job.ID); err != nil || state.BaselineConfigHash != "managed-hash" {
		t.Fatalf("managed runtime state = %#v, %v", state, err)
	}
	if scanID, hash, err := defaultTenant(s).RuntimeBaselineMeta(ctx, job.ID); err != nil || scanID != "managed-baseline" || hash != "managed-hash" {
		t.Fatalf("runtime baseline metadata = %q, %q, %v", scanID, hash, err)
	}
	if events, err := defaultTenant(s).ListJobEvents(ctx, job.ID, 10); err != nil || len(events) != 2 {
		t.Fatalf("managed events = %#v, %v", events, err)
	}
	if _, err := defaultTenant(s).ListJobEventsPage(ctx, job.ID, 1, 1); err != nil {
		t.Fatal(err)
	}

	if _, err := defaultTenant(s).ApproveRuntime(ctx, job.ID, job.Job.Name, scan); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).ApproveRuntimeWithOutboxAndAudit(ctx, job.ID, job.Job.Name, scan, []string{"deployment"}, AuditEntry{Action: "baseline.approve", Detail: "wrapper test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().Approve(ctx, job.Job.Name, scan); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().ResetBaseline(ctx, job.Job.Name); err != nil {
		t.Fatal(err)
	}
	if state, err := defaultTenant(s).State(ctx, job.Job.Name); err != nil || state.Baseline != nil || state.BaselineScanID != "" {
		t.Fatalf("reset legacy baseline = %#v, %v", state, err)
	}

	if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,attempts,next_at) VALUES(?,?,?,?)`, "failed-destination", []byte(`{}`), deliveryMaxAttempts, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if failed, err := defaultTenant(s).FailedDeliveries(ctx); err != nil || failed != 1 {
		t.Fatalf("failed deliveries = %d, %v", failed, err)
	}
}

func TestStoreDaemonLeaseHealthTransitions(t *testing.T) {
	ctx, s, _, _ := cycleFixture(t)
	if err := s.System().AcquireLease(ctx, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := s.System().Heartbeat(ctx, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := s.System().Healthy(ctx); err != nil {
		t.Fatalf("fresh lease health = %v", err)
	}
	if err := s.System().Heartbeat(ctx, "other"); err == nil {
		t.Fatal("heartbeat from another owner succeeded")
	}
	old := time.Now().UTC().Add(-3 * time.Minute).Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(ctx, `UPDATE daemon_lease SET heartbeat=? WHERE id=1`, old); err != nil {
		t.Fatal(err)
	}
	if err := s.System().Healthy(ctx); err == nil {
		t.Fatal("stale lease was reported healthy")
	}
	if err := s.System().ReleaseLease(ctx, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := s.System().Healthy(ctx); !errors.Is(err, sql.ErrNoRows) {
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
	if got := deliveryRetryDelay(9); got != 512*time.Minute {
		t.Fatalf("ninth delivery retry delay = %s, want 8h32m", got)
	}
	if got := deliveryRetryDelay(10); got != 12*time.Hour {
		t.Fatalf("tenth delivery retry delay = %s, want 12h cap", got)
	}
	if got := deliveryRetryDelay(deliveryMaxAttempts); got != 12*time.Hour {
		t.Fatalf("terminal delivery retry delay = %s, want 12h cap", got)
	}
	var retryWindow time.Duration
	for attempt := 1; attempt < deliveryMaxAttempts; attempt++ {
		retryWindow += deliveryRetryDelay(attempt)
	}
	if want := 77*time.Hour + 2*time.Minute; retryWindow != want {
		t.Fatalf("delivery retry window = %s, want %s", retryWindow, want)
	}

	ctx := context.Background()
	s := openTestStore(t)
	if err := s.System().QueueEvent(ctx, "retry-policy", model.Event{Type: "retry-policy", TenantID: DefaultTenantID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < deliveryMaxAttempts; attempt++ {
		if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE destination=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), "retry-policy"); err != nil {
			t.Fatal(err)
		}
		due, err := s.System().ClaimDueDeliveries(ctx, 1, fmt.Sprintf("retry-owner-%d", attempt))
		if err != nil || len(due) != 1 {
			t.Fatalf("retry claim %d = %#v, %v", attempt+1, due, err)
		}
		if err := s.System().DeliveryResult(ctx, due[0].ID, errors.New("temporary provider failure")); err != nil {
			t.Fatal(err)
		}
	}
	if failed, err := defaultTenant(s).FailedDeliveries(ctx); err != nil || failed != 1 {
		t.Fatalf("terminal delivery count = %d, %v", failed, err)
	}
	if due, err := s.System().ClaimDueDeliveries(ctx, 1, "after-terminal"); err != nil || len(due) != 0 {
		t.Fatalf("terminal delivery was claimable again: %#v, %v", due, err)
	}
}

func TestDeliveryRetryScheduleSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	databasePath := s.FilePath()
	if err := s.System().QueueEvent(ctx, "restart-retry", model.Event{Type: "restart-retry", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	// Place a pending delivery at the last interval before terminal failure.
	// DeliveryResult must persist the long delay, and reopening the database
	// must preserve both its attempt count and scheduled next-at time.
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET attempts=?,next_at=? WHERE destination=?`, deliveryMaxAttempts-2, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), "restart-retry"); err != nil {
		t.Fatal(err)
	}
	due, err := s.System().ClaimDueDeliveries(ctx, 1, "restart-before-close")
	if err != nil || len(due) != 1 || due[0].Attempts != deliveryMaxAttempts-2 {
		t.Fatalf("pre-restart claim = %#v, %v", due, err)
	}
	beforeFailure := time.Now().UTC()
	if err := s.System().DeliveryResult(ctx, due[0].ID, errors.New("temporary provider outage")); err != nil {
		t.Fatal(err)
	}
	var attempts int
	var nextAtText string
	var terminalAt string
	if err := s.DB.QueryRowContext(ctx, `SELECT attempts,next_at,terminal_at FROM outbox WHERE id=?`, due[0].ID).Scan(&attempts, &nextAtText, &terminalAt); err != nil {
		t.Fatal(err)
	}
	if attempts != deliveryMaxAttempts-1 || terminalAt != "" {
		t.Fatalf("pre-restart retry state = attempts %d, terminal %q", attempts, terminalAt)
	}
	nextAt, err := time.Parse(time.RFC3339Nano, nextAtText)
	if err != nil {
		t.Fatal(err)
	}
	if nextAt.Before(beforeFailure.Add(12*time.Hour)) || nextAt.After(time.Now().UTC().Add(12*time.Hour)) {
		t.Fatalf("persisted retry time = %s, want approximately 12h after failure", nextAt)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	var restartedAttempts int
	var restartedNextAt string
	if err := restarted.DB.QueryRowContext(ctx, `SELECT attempts,next_at FROM outbox WHERE id=?`, due[0].ID).Scan(&restartedAttempts, &restartedNextAt); err != nil {
		t.Fatal(err)
	}
	if restartedAttempts != attempts || restartedNextAt != nextAtText {
		t.Fatalf("restart retry state = attempts %d at %q, want %d at %q", restartedAttempts, restartedNextAt, attempts, nextAtText)
	}
	if retried, err := restarted.System().ClaimDueDeliveries(ctx, 1, "restart-before-due"); err != nil || len(retried) != 0 {
		t.Fatalf("future retry was claimable after restart: %#v, %v", retried, err)
	}
	if _, err := restarted.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE id=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), due[0].ID); err != nil {
		t.Fatal(err)
	}
	retried, err := restarted.System().ClaimDueDeliveries(ctx, 1, "restart-after-due")
	if err != nil || len(retried) != 1 || retried[0].Attempts != attempts {
		t.Fatalf("due retry after restart = %#v, %v", retried, err)
	}
}

func TestIndeterminateDeliveryConsumesDeferralNotAttempt(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.System().QueueEvent(ctx, "indeterminate", model.Event{Type: "indeterminate", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	due, err := s.System().ClaimDueDeliveries(ctx, 1, "indeterminate-owner")
	if err != nil || len(due) != 1 {
		t.Fatalf("indeterminate claim = %#v, %v", due, err)
	}
	if err := s.System().DeliveryResultClaim(ctx, due[0].ID, due[0].ClaimToken, ErrDeliveryIndeterminate); err != nil {
		t.Fatal(err)
	}
	var attempts, deferrals int
	var terminalAt string
	if err := s.DB.QueryRowContext(ctx, `SELECT attempts,deferrals,terminal_at FROM outbox WHERE id=?`, due[0].ID).Scan(&attempts, &deferrals, &terminalAt); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || deferrals != 1 || terminalAt != "" {
		t.Fatalf("indeterminate budgets = attempts %d, deferrals %d, terminal_at %q", attempts, deferrals, terminalAt)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE id=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), due[0].ID); err != nil {
		t.Fatal(err)
	}
	next, err := s.System().ClaimDueDeliveries(ctx, 1, "indeterminate-retry")
	if err != nil || len(next) != 1 || next[0].Attempts != 0 || next[0].Deferrals != 1 {
		t.Fatalf("indeterminate retry = %#v, %v", next, err)
	}
}

func TestDeliveryHealthTracksRedactedOutcomesAndTerminalEvent(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	secret := "provider password=super-secret"
	if err := s.System().QueueEvent(ctx, "destination", model.Event{Type: "health", Job: "job", Message: "first", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	health, err := defaultTenant(s).ListDeliveryHealth(ctx)
	if err != nil || health["destination"].Pending != 1 {
		t.Fatalf("pending health = %#v, %v", health, err)
	}

	for attempt := 1; attempt <= deliveryMaxAttempts; attempt++ {
		if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE destination=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), "destination"); err != nil {
			t.Fatal(err)
		}
		due, err := s.System().ClaimDueDeliveries(ctx, 1, fmt.Sprintf("health-owner-%d", attempt))
		if err != nil || len(due) != 1 {
			t.Fatalf("claim %d = %#v, %v", attempt, due, err)
		}
		if err := s.System().DeliveryResult(ctx, due[0].ID, errors.New(secret)); err != nil {
			t.Fatal(err)
		}
	}

	health, err = defaultTenant(s).ListDeliveryHealth(ctx)
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

	if err := s.System().QueueEvent(ctx, "destination", model.Event{Type: "health", Job: "job", Message: "second", CreatedAt: time.Now().UTC().Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	due, err := s.System().ClaimDueDeliveries(ctx, 1, "health-success")
	if err != nil || len(due) != 1 {
		t.Fatalf("success claim = %#v, %v", due, err)
	}
	if err := s.System().DeliveryResult(ctx, due[0].ID, nil); err != nil {
		t.Fatal(err)
	}
	health, err = defaultTenant(s).ListDeliveryHealth(ctx)
	if err != nil || health["destination"].LastSuccessAt.IsZero() {
		t.Fatalf("success health = %#v, %v", health, err)
	}
}

func TestDeliveryDeferralsAreBoundedAndVisible(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.System().QueueEvent(ctx, "deferred", model.Event{Type: "deferred", Message: "locked", TenantID: DefaultTenantID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for deferral := 0; deferral < deliveryMaxDeferrals; deferral++ {
		if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE destination=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), "deferred"); err != nil {
			t.Fatal(err)
		}
		due, err := s.System().ClaimDueDeliveries(ctx, 1, fmt.Sprintf("defer-owner-%d", deferral))
		if err != nil || len(due) != 1 {
			t.Fatalf("deferral claim %d = %#v, %v", deferral+1, due, err)
		}
		if err := s.System().DeferDeliveryWithError(ctx, due[0].ID, due[0].ClaimToken, ErrDeliveryDestinationLocked, time.Minute); err != nil {
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
	if due, err := s.System().ClaimDueDeliveries(ctx, 1, "after-deferral-limit"); err != nil || len(due) != 0 {
		t.Fatalf("terminally deferred delivery was claimable: %#v, %v", due, err)
	}
	health, err := defaultTenant(s).ListDeliveryHealth(ctx)
	if err != nil || health["deferred"].TerminalFailures != 1 || health["deferred"].Pending != 0 {
		t.Fatalf("bounded deferral health = %#v, %v", health["deferred"], err)
	}
	failed, err := defaultTenant(s).FailedDeliveries(ctx)
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

func TestLockedDeliveryAgingIsBoundedAndWakesOnRecovery(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	locked := "locked-recovery"
	other := "other"
	if err := s.System().QueueEvent(ctx, locked, model.Event{Type: "locked", Message: "held", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := s.System().QueueEvent(ctx, other, model.Event{Type: "other", Message: "untouched", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Minute)
	for deferral := 0; deferral < deliveryMaxDeferrals; deferral++ {
		if _, err := s.DB.ExecContext(ctx, `UPDATE outbox SET next_at=? WHERE destination IN (?,?)`, now.Format(time.RFC3339Nano), locked, other); err != nil {
			t.Fatal(err)
		}
		if err := s.System().AgeLockedDeliveries(ctx, []string{locked, locked, ""}); err != nil {
			t.Fatal(err)
		}
		var attempts, gotDeferrals int
		var terminalAt, lastError string
		if err := s.DB.QueryRowContext(ctx, `SELECT attempts,deferrals,terminal_at,last_error FROM outbox WHERE destination=?`, locked).Scan(&attempts, &gotDeferrals, &terminalAt, &lastError); err != nil {
			t.Fatal(err)
		}
		if attempts != 0 || gotDeferrals != deferral+1 || lastError != "destination_locked" {
			t.Fatalf("locked aging %d = attempts %d, deferrals %d, terminal %q, error %q", deferral+1, attempts, gotDeferrals, terminalAt, lastError)
		}
		if deferral < deliveryMaxDeferrals-1 && terminalAt != "" {
			t.Fatalf("locked delivery became terminal before its grace period: %q", terminalAt)
		}
		var otherDeferrals int
		if err := s.DB.QueryRowContext(ctx, `SELECT deferrals FROM outbox WHERE destination=?`, other).Scan(&otherDeferrals); err != nil {
			t.Fatal(err)
		}
		if otherDeferrals != 0 {
			t.Fatalf("unlisted destination was aged: %d", otherDeferrals)
		}
		if deferral == 0 {
			if err := s.System().WakeLockedDeliveries(ctx, []string{locked}); err != nil {
				t.Fatal(err)
			}
			due, err := s.System().ClaimDueDeliveries(ctx, 1, "locked-recovery")
			if err != nil || len(due) != 1 || due[0].Deferrals != 1 || due[0].Attempts != 0 {
				t.Fatalf("recovered delivery claim = %#v, %v", due, err)
			}
			if err := s.System().ReleaseDeliveryClaim(ctx, due[0].ID, due[0].ClaimToken, 0); err != nil {
				t.Fatal(err)
			}
		}
	}
	if due, err := s.System().ClaimDueDeliveriesExcluding(ctx, 1, "after-locked-terminal", []string{other}); err != nil || len(due) != 0 {
		t.Fatalf("terminal locked delivery was claimable: %#v, %v", due, err)
	}
	health, err := defaultTenant(s).ListDeliveryHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if item := health[locked]; item.TerminalFailures != 1 || item.Pending != 0 || item.Deferrals != 0 || item.LastErrorCode != "destination_locked" {
		t.Fatalf("locked terminal health = %#v", item)
	}
	var eventPayload []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT payload_json FROM events WHERE type=?`, "notification-delivery-terminal").Scan(&eventPayload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(eventPayload), "locked destination grace period") || !strings.Contains(string(eventPayload), "destination_locked") {
		t.Fatalf("locked terminal event = %s", eventPayload)
	}
}
