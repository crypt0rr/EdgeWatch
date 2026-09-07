package store

import (
	"database/sql"
	"errors"
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

	if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,attempts,next_at) VALUES(?,?,3,?)`, "failed-destination", []byte(`{}`), now.Format(time.RFC3339Nano)); err != nil {
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
