package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func insertPurgeTestDelivery(t *testing.T, s *Store, tenantID, eventJobID, windowID, destination, state string) int64 {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	claim, claimUntil, startedAt := "", "", ""
	var sentAt any
	terminalAt, coalescedAt := "", ""
	switch state {
	case "pending":
	case "claimed":
		claim, claimUntil = "purge-claim-"+destination, now.Add(time.Hour).Format(time.RFC3339Nano)
	case "started":
		claim, claimUntil, startedAt = "purge-claim-"+destination, now.Add(time.Hour).Format(time.RFC3339Nano), stamp
	case "sent":
		sentAt = stamp
	case "terminal":
		terminalAt = stamp
	case "coalesced":
		coalescedAt = stamp
	default:
		t.Fatalf("unknown delivery fixture state %q", state)
	}
	payload := fmt.Sprintf(`{"type":"changes-detected","job_id":%q,"scan_id":%q}`, eventJobID, destination)
	result, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,next_at,tenant_id,event_type,event_job_id,change_window_id,claim_token,claim_until,attempt_started_at,sent_at,terminal_at,coalesced_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, destination, payload, now.Add(-time.Minute).Format(time.RFC3339Nano), tenantID, "changes-detected", eventJobID, windowID, claim, claimUntil, startedAt, sentAt, terminalAt, coalescedAt)
	if err != nil {
		t.Fatalf("insert %s delivery fixture: %v", state, err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if state == "started" {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO notification_delivery_health(destination_identity,last_failure_at,last_error_code,updated_at) VALUES(?,?,?,?) ON CONFLICT(destination_identity) DO NOTHING`, destination, "before-purge", "delivery_failed", stamp); err != nil {
			t.Fatalf("insert delivery health fixture: %v", err)
		}
	}
	return id
}

func insertPurgeTestWindowEvidence(t *testing.T, s *Store, windowID string, refs, events int) {
	t.Helper()
	ctx := context.Background()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	for i := 0; i < refs; i++ {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO change_window_refs(window_id,category,change_key,change_json,event_key,event_type,scan_id,event_at) VALUES(?,'new',?,'{}',?,'changes-detected','purge-scan',?)`, windowID, fmt.Sprintf("purge-change-%d", i), fmt.Sprintf("purge-event-%d", i), stamp); err != nil {
			t.Fatalf("insert window reference %d: %v", i, err)
		}
	}
	for i := 0; i < events; i++ {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO change_window_events(window_id,event_key,event_type,scan_id,event_at,details_complete,reported_count) VALUES(?,?,'changes-detected','purge-scan',?,1,1)`, windowID, fmt.Sprintf("purge-event-%d", i), stamp); err != nil {
			t.Fatalf("insert window event %d: %v", i, err)
		}
	}
}

func TestJobHistoryPurgeResumesWindowTailInBoundedBatches(t *testing.T) {
	ctx := context.Background()
	database := freshTestDatabasePath(t)
	s, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	tenant := defaultTenant(s)
	target := createWindowTestJob(t, tenant, "window-tail-target", "UTC")
	survivor := createWindowTestJob(t, tenant, "window-tail-survivor", "UTC")
	now := time.Now().UTC().Truncate(time.Second)
	targetWindow := createTestChangeWindow(t, tenant, target.ID, now.Add(time.Hour), now.Add(2*time.Hour))
	survivorWindow := createTestChangeWindow(t, tenant, survivor.ID, now.Add(3*time.Hour), now.Add(4*time.Hour))
	insertPurgeTestWindowEvidence(t, s, targetWindow.ID, 5, 5)
	insertPurgeTestWindowEvidence(t, s, survivorWindow.ID, 1, 1)
	var startedID int64
	for _, state := range []string{"pending", "claimed", "started", "sent", "terminal", "coalesced"} {
		id := insertPurgeTestDelivery(t, s, tenant.scope.ID(), target.ID, targetWindow.ID, "target-"+state, state)
		if state == "started" {
			startedID = id
		}
	}
	insertPurgeTestDelivery(t, s, tenant.scope.ID(), target.ID, "", "target-job-only", "pending")
	// This row has a mismatched event job but a valid target-window link. The
	// link phase must remove it after the event-job phase has finished.
	insertPurgeTestDelivery(t, s, tenant.scope.ID(), survivor.ID, targetWindow.ID, "target-mismatched-job", "pending")
	insertPurgeTestDelivery(t, s, tenant.scope.ID(), survivor.ID, survivorWindow.ID, "survivor-pending", "pending")
	if err := tenant.SetJobArchived(ctx, target.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := tenant.DeleteJobWithAudit(ctx, target.ID, AuditEntry{Action: "job.deleted", Detail: target.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_history_purges SET phase=? WHERE tenant_id=? AND job_id=?`, jobPurgePhaseDeleteJob, tenant.scope.ID(), target.ID); err != nil {
		t.Fatal(err)
	}

	stopOutbox := errors.New("pause after one bounded outbox batch")
	if _, err := s.System().purgeDeletedJobHistories(ctx, jobHistoryPurgeOptions{batchSize: 2, afterBatch: func(_ context.Context, _, jobID, phase string) error {
		if jobID == target.ID && phase == jobPurgePhaseWindowOutboxJob {
			return stopOutbox
		}
		return nil
	}}); !errors.Is(err, stopOutbox) {
		t.Fatalf("first outbox cleanup interruption = %v, want %v", err, stopOutbox)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE tenant_id=? AND (event_job_id=? OR change_window_id=?)`, tenant.scope.ID(), target.ID, targetWindow.ID) != 6 {
		t.Fatal("the first event-job batch did not remove exactly two of eight target-linked deliveries")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_windows WHERE id=?`, targetWindow.ID) != 1 {
		t.Fatal("the target window was removed before its bounded outbox cleanup finished")
	}

	stopRefs := errors.New("pause after one bounded reference batch")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.System().purgeDeletedJobHistories(ctx, jobHistoryPurgeOptions{batchSize: 2, afterBatch: func(_ context.Context, _, jobID, phase string) error {
		if jobID == target.ID && phase == jobPurgePhaseWindowRefs {
			return stopRefs
		}
		return nil
	}}); !errors.Is(err, stopRefs) {
		t.Fatalf("reference cleanup interruption = %v, want %v", err, stopRefs)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE tenant_id=? AND (event_job_id=? OR change_window_id=?)`, tenant.scope.ID(), target.ID, targetWindow.ID) != 0 {
		t.Fatal("job purge left an event-job or mismatched-window-linked delivery")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_refs WHERE window_id=?`, targetWindow.ID) != 3 || countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, targetWindow.ID) != 5 {
		t.Fatal("window evidence did not remain bounded after the first reference batch")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_windows WHERE id=?`, targetWindow.ID) != 1 {
		t.Fatal("the target window cascaded before its child cleanup completed")
	}

	stopEvents := errors.New("pause after one bounded event batch")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.System().purgeDeletedJobHistories(ctx, jobHistoryPurgeOptions{batchSize: 2, afterBatch: func(_ context.Context, _, jobID, phase string) error {
		if jobID == target.ID && phase == jobPurgePhaseWindowEvents {
			return stopEvents
		}
		return nil
	}}); !errors.Is(err, stopEvents) {
		t.Fatalf("event cleanup interruption = %v, want %v", err, stopEvents)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_events WHERE window_id=?`, targetWindow.ID) != 3 || countRows(t, s.DB, `SELECT COUNT(*) FROM change_windows WHERE id=?`, targetWindow.ID) != 1 {
		t.Fatal("event cleanup or parent deletion exceeded its bounded batch")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if purged, err := s.System().PurgeDeletedJobHistories(ctx); err != nil || purged == 0 {
		t.Fatalf("resume bounded window-tail purge after restart = %d, %v", purged, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM jobs WHERE id=?`, target.ID) != 0 || countRows(t, s.DB, `SELECT COUNT(*) FROM change_windows WHERE id=?`, targetWindow.ID) != 0 || countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE destination LIKE 'target-%'`) != 0 {
		t.Fatal("target job, window, or delivery rows survived resumed purge")
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_windows WHERE id=?`, survivorWindow.ID) != 1 || countRows(t, s.DB, `SELECT COUNT(*) FROM change_window_refs WHERE window_id=?`, survivorWindow.ID) != 1 || countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE destination='survivor-pending'`) != 1 {
		t.Fatal("purging one job removed another job's window evidence or delivery")
	}
	if err := s.System().DeliveryResultClaim(ctx, startedID, "purge-claim-target-started", ErrDeliveryProviderTimeout); !errors.Is(err, ErrDeliveryClaimLost) {
		t.Fatalf("late provider result for a purged started row = %v, want ErrDeliveryClaimLost", err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM notification_delivery_health WHERE destination_identity='target-started' AND last_failure_at='before-purge' AND last_error_code='delivery_failed'`) != 1 {
		t.Fatal("late provider result changed delivery health after its row was purged")
	}
}

func TestJobHistoryPurgeLegacyProjectionPhasesReachWindowTail(t *testing.T) {
	for _, phase := range []string{jobPurgePhaseLatestHosts, jobPurgePhaseRepairHosts, jobPurgePhaseDeleteJob} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			s := openTestStore(t)
			tenant := defaultTenant(s)
			job := createWindowTestJob(t, tenant, "legacy-window-tail-"+phase, "UTC")
			now := time.Now().UTC().Truncate(time.Second)
			window := createTestChangeWindow(t, tenant, job.ID, now.Add(time.Hour), now.Add(2*time.Hour))
			insertPurgeTestWindowEvidence(t, s, window.ID, 1, 1)
			insertPurgeTestDelivery(t, s, tenant.scope.ID(), job.ID, window.ID, "legacy-"+phase, "started")
			if err := tenant.SetJobArchived(ctx, job.ID, true); err != nil {
				t.Fatal(err)
			}
			if err := tenant.DeleteJobWithAudit(ctx, job.ID, AuditEntry{Action: "job.deleted", Detail: job.ID}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.ExecContext(ctx, `UPDATE job_history_purges SET phase=? WHERE tenant_id=? AND job_id=?`, phase, tenant.scope.ID(), job.ID); err != nil {
				t.Fatal(err)
			}
			if purged, err := s.System().PurgeDeletedJobHistories(ctx); err != nil || purged == 0 {
				t.Fatalf("purge from legacy projection phase %s = %d, %v", phase, purged, err)
			}
			if countRows(t, s.DB, `SELECT COUNT(*) FROM jobs WHERE id=?`, job.ID) != 0 || countRows(t, s.DB, `SELECT COUNT(*) FROM change_windows WHERE id=?`, window.ID) != 0 || countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE destination=?`, "legacy-"+phase) != 0 {
				t.Fatalf("purge from legacy phase %s skipped window cleanup", phase)
			}
		})
	}
}

func TestJobHistoryPurgeRemovesSentLegacyPayloadAfterMigration69(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	target := createWindowTestJob(t, tenant, "legacy-sent-purge-target", "UTC")
	survivor := createWindowTestJob(t, tenant, "legacy-sent-purge-survivor", "UTC")
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	payloads := make(map[string][]byte, 2)
	for _, row := range []struct {
		destination string
		jobID       string
	}{
		{destination: "legacy-sent-target", jobID: target.ID},
		{destination: "legacy-sent-survivor", jobID: survivor.ID},
	} {
		payload := []byte(fmt.Sprintf(`{"type":"changes-detected","job_id":%q,"changes":[{"key":"legacy-history"}]}`, row.jobID))
		payloads[row.destination] = payload
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,attempts,next_at,sent_at,tenant_id) VALUES(?,?,1,?,?,?)`, row.destination, payload, stamp, stamp, tenant.scope.ID()); err != nil {
			t.Fatalf("insert legacy sent delivery %s: %v", row.destination, err)
		}
	}
	path := reconstructSchema68(t, s)

	upgraded, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade schema 68 fixture: %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	for _, row := range []struct {
		destination string
		jobID       string
	}{
		{destination: "legacy-sent-target", jobID: target.ID},
		{destination: "legacy-sent-survivor", jobID: survivor.ID},
	} {
		var eventJobID, windowID string
		var sentAt string
		if err := upgraded.DB.QueryRowContext(ctx, `SELECT event_job_id,change_window_id,sent_at FROM outbox WHERE destination=?`, row.destination).Scan(&eventJobID, &windowID, &sentAt); err != nil {
			t.Fatalf("read migrated sent delivery %s: %v", row.destination, err)
		}
		if eventJobID != "" || windowID != "" || sentAt == "" {
			t.Fatalf("schema 68→69 sent history metadata = job %q window %q sent %q; want blank metadata and retained sent marker", eventJobID, windowID, sentAt)
		}
		var payload []byte
		if err := upgraded.DB.QueryRowContext(ctx, `SELECT payload_json FROM outbox WHERE destination=?`, row.destination).Scan(&payload); err != nil {
			t.Fatalf("read migrated sent payload %s: %v", row.destination, err)
		}
		if !bytes.Equal(payload, payloads[row.destination]) {
			t.Fatalf("migration rewrote sent payload %s: got %q, want %q", row.destination, payload, payloads[row.destination])
		}
		var got struct {
			JobID string `json:"job_id"`
		}
		if err := json.Unmarshal(payload, &got); err != nil || got.JobID != row.jobID {
			t.Fatalf("migrated sent payload %s job = %q, decode error %v; want %q", row.destination, got.JobID, err, row.jobID)
		}
	}

	upgradedTenant := defaultTenant(upgraded)
	if err := upgradedTenant.SetJobArchived(ctx, target.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := upgradedTenant.DeleteJobWithAudit(ctx, target.ID, AuditEntry{Action: "job.deleted", Detail: target.ID}); err != nil {
		t.Fatal(err)
	}
	if purged, err := upgraded.System().PurgeDeletedJobHistories(ctx); err != nil || purged == 0 {
		t.Fatalf("purge job with schema 68 sent history = %d, %v", purged, err)
	}
	if countRows(t, upgraded.DB, `SELECT COUNT(*) FROM outbox WHERE destination='legacy-sent-target'`) != 0 {
		t.Fatal("job purge left its sent schema 68 payload row with blank event_job_id")
	}
	if countRows(t, upgraded.DB, `SELECT COUNT(*) FROM outbox WHERE destination='legacy-sent-survivor'`) != 1 {
		t.Fatal("job purge removed another job's sent legacy payload row")
	}
}

func TestTenantPurgeRewindsLegacyPostWindowCheckpointAndResumes(t *testing.T) {
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	windowID := "purge-window-" + secondTenantID
	// Simulate the old tenant-purge order after its window steps committed but
	// before runtime and outbox cleanup: the window is gone while its deliveries
	// and the current/later checkpoint tables still contain rows.
	if _, err := f.store.DB.ExecContext(ctx, `DELETE FROM change_window_refs WHERE window_id=?`, windowID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.ExecContext(ctx, `DELETE FROM change_window_events WHERE window_id=?`, windowID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.ExecContext(ctx, `DELETE FROM change_windows WHERE id=?`, windowID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.ExecContext(ctx, `INSERT INTO runtime_incidents(job_id,key,incident_json) VALUES(?,?,?)`, f.jobB, "legacy-purge-runtime", `{"key":"legacy-purge-runtime"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.ExecContext(ctx, `INSERT INTO events(type,job,scan_id,payload_json,created_at,job_id,tenant_id) VALUES(?,?,?,?,?,?,?)`, "changes-detected", "edge", "legacy-purge-scan", `{"job_id":"`+f.jobB+`"}`, time.Now().UTC().Format(time.RFC3339Nano), f.jobB, secondTenantID); err != nil {
		t.Fatal(err)
	}
	runtimeBefore := countRows(t, f.store.DB, `SELECT COUNT(*) FROM runtime_incidents WHERE job_id=?`, f.jobB)
	scansBefore := countRows(t, f.store.DB, `SELECT COUNT(*) FROM scans WHERE tenant_id=? AND job_id=?`, secondTenantID, f.jobB)
	eventsBefore := countRows(t, f.store.DB, `SELECT COUNT(*) FROM events WHERE tenant_id=?`, secondTenantID)
	var startedID int64
	for _, state := range []string{"pending", "claimed", "started", "sent", "terminal", "coalesced"} {
		id := insertPurgeTestDelivery(t, f.store, secondTenantID, f.jobB, windowID, "tenant-b-"+state, state)
		if state == "started" {
			startedID = id
		}
	}
	// Another tenant's delivery and the target tenant's runtime/event rows
	// provide ownership controls for the rewind and subsequent bounded passes.
	insertPurgeTestDelivery(t, f.store, DefaultTenantID, f.jobA, "purge-window-"+DefaultTenantID, "tenant-a-pending", "pending")
	if _, err := f.store.DB.ExecContext(ctx, `INSERT INTO runtime_incidents(job_id,key,incident_json) VALUES(?,?,?)`, f.jobA, "retained-other-tenant", `{"key":"retained-other-tenant"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.ExecContext(ctx, `INSERT INTO events(type,job,scan_id,payload_json,created_at,job_id,tenant_id) VALUES(?,?,?,?,?,?,?)`, "changes-detected", "edge", "retained-other-scan", `{"job_id":"`+f.jobA+`"}`, time.Now().UTC().Format(time.RFC3339Nano), f.jobA, DefaultTenantID); err != nil {
		t.Fatal(err)
	}
	requestSecondTenantDeletion(t, f)
	if _, err := f.store.DB.ExecContext(ctx, `UPDATE tenants SET purge_phase=? WHERE id=?`, "runtime_incidents", secondTenantID); err != nil {
		t.Fatal(err)
	}
	stopAfterBatch := errors.New("pause after resumed legacy outbox batch")
	if _, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: 2, afterBatch: func(_ context.Context, _ *sql.Conn, phase string) error {
		if phase == "outbox" {
			return stopAfterBatch
		}
		return nil
	}}); !errors.Is(err, stopAfterBatch) {
		t.Fatalf("legacy checkpoint outbox interruption = %v, want %v", err, stopAfterBatch)
	}
	if phase := purgePhaseOf(t, f.store, secondTenantID); phase != "outbox" {
		t.Fatalf("legacy post-window checkpoint rewound to %q, want outbox", phase)
	}
	runtimeCount := countRows(t, f.store.DB, `SELECT COUNT(*) FROM runtime_incidents WHERE job_id=?`, f.jobB)
	scanCount := countRows(t, f.store.DB, `SELECT COUNT(*) FROM scans WHERE tenant_id=? AND job_id=?`, secondTenantID, f.jobB)
	eventCount := countRows(t, f.store.DB, `SELECT COUNT(*) FROM events WHERE tenant_id=?`, secondTenantID)
	if runtimeCount != runtimeBefore || scanCount != scansBefore || eventCount != eventsBefore {
		t.Fatalf("rewind skipped a pending runtime/scan/event phase before outbox cleanup finished: runtime=%d/%d scans=%d/%d events=%d/%d", runtimeCount, runtimeBefore, scanCount, scansBefore, eventCount, eventsBefore)
	}

	database := f.store.Path
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	results, err := restarted.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: 2})
	if err != nil || len(results) != 1 || !results[0].Complete {
		t.Fatalf("resume legacy tenant purge = %+v, %v", results, err)
	}
	if countRows(t, restarted.DB, `SELECT COUNT(*) FROM outbox WHERE tenant_id=?`, secondTenantID) != 0 || countRows(t, restarted.DB, `SELECT COUNT(*) FROM runtime_incidents WHERE job_id=?`, f.jobB) != 0 || countRows(t, restarted.DB, `SELECT COUNT(*) FROM scans WHERE tenant_id=? AND job_id=?`, secondTenantID, f.jobB) != 0 || countRows(t, restarted.DB, `SELECT COUNT(*) FROM events WHERE tenant_id=?`, secondTenantID) != 0 {
		t.Fatal("resumed purge left tenant outbox, current-phase runtime, or later scan/event rows")
	}
	if countRows(t, restarted.DB, `SELECT COUNT(*) FROM outbox WHERE destination='tenant-a-pending'`) != 1 || countRows(t, restarted.DB, `SELECT COUNT(*) FROM runtime_incidents WHERE job_id=? AND key='retained-other-tenant'`, f.jobA) != 1 || countRows(t, restarted.DB, `SELECT COUNT(*) FROM events WHERE tenant_id=? AND scan_id='retained-other-scan'`, DefaultTenantID) != 1 {
		t.Fatal("tenant purge removed another tenant's delivery, runtime incident, or event")
	}
	if err := restarted.System().DeliveryResultClaim(ctx, startedID, "purge-claim-tenant-b-started", ErrDeliveryProviderTimeout); !errors.Is(err, ErrDeliveryClaimLost) {
		t.Fatalf("late provider result for a tenant-purged started row = %v, want ErrDeliveryClaimLost", err)
	}
	if countRows(t, restarted.DB, `SELECT COUNT(*) FROM notification_delivery_health WHERE destination_identity='tenant-b-started' AND last_failure_at='before-purge' AND last_error_code='delivery_failed'`) != 1 {
		t.Fatal("late provider result changed destination health after tenant purge")
	}
}
