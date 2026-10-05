package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
)

func TestJobListingLifecycleIdempotenceAndPermanentDeletionGuards(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	alpha, err := defaultTenant(s).CreateJobWithEnabledAndAudit(ctx, testJob("alpha"), true, AuditEntry{Action: "job.created", Detail: "alpha"})
	if err != nil {
		t.Fatal(err)
	}
	beta, err := defaultTenant(s).CreateJobWithEnabled(ctx, testJob("beta"), false)
	if err != nil {
		t.Fatal(err)
	}

	active, err := defaultTenant(s).ListJobs(ctx, false)
	if err != nil || len(active) != 2 || active[0].Job.Name != "alpha" || active[1].Job.Name != "beta" {
		t.Fatalf("active jobs = %#v, %v", active, err)
	}
	if err := defaultTenant(s).SetJobArchivedWithRevisionAndAudit(ctx, beta.ID, true, beta.Revision, AuditEntry{Action: "job.archived", Detail: beta.ID}); err != nil {
		t.Fatal(err)
	}
	archived, err := defaultTenant(s).GetJob(ctx, beta.ID)
	if err != nil || !archived.Archived || archived.Enabled || archived.Revision != beta.Revision+1 {
		t.Fatalf("archived job = %#v, %v", archived, err)
	}
	all, err := defaultTenant(s).ListJobs(ctx, true)
	if err != nil || len(all) != 2 || !all[1].Archived {
		t.Fatalf("all jobs = %#v, %v", all, err)
	}
	active, err = defaultTenant(s).ListJobs(ctx, false)
	if err != nil || len(active) != 1 || active[0].ID != alpha.ID {
		t.Fatalf("filtered jobs = %#v, %v", active, err)
	}

	// Repeating a lifecycle action is intentionally idempotent: it records the
	// audit entry but does not create a phantom revision.
	if err := defaultTenant(s).SetJobArchivedWithRevisionAndAudit(ctx, beta.ID, true, archived.Revision, AuditEntry{Action: "job.archived.repeat", Detail: beta.ID}); err != nil {
		t.Fatal(err)
	}
	repeated, err := defaultTenant(s).GetJob(ctx, beta.ID)
	if err != nil || repeated.Revision != archived.Revision {
		t.Fatalf("idempotent archive changed revision: %#v, %v", repeated, err)
	}
	if err := defaultTenant(s).SetJobArchivedWithRevision(ctx, beta.ID, false, archived.Revision); err != nil {
		t.Fatal(err)
	}
	restored, err := defaultTenant(s).GetJob(ctx, beta.ID)
	if err != nil || restored.Archived || restored.Enabled || restored.Revision != archived.Revision+1 {
		t.Fatalf("restored job = %#v, %v", restored, err)
	}
	if err := defaultTenant(s).SetJobEnabledWithRevisionAndAudit(ctx, beta.ID, true, restored.Revision, AuditEntry{Action: "job.resumed", Detail: beta.ID}); err != nil {
		t.Fatal(err)
	}
	resumed, err := defaultTenant(s).GetJob(ctx, beta.ID)
	if err != nil || !resumed.Enabled || resumed.Revision != restored.Revision+1 {
		t.Fatalf("resumed job = %#v, %v", resumed, err)
	}
	if err := defaultTenant(s).SetJobEnabledWithRevisionAndAudit(ctx, beta.ID, true, resumed.Revision, AuditEntry{Action: "job.resumed.repeat", Detail: beta.ID}); err != nil {
		t.Fatal(err)
	}
	unchanged, err := defaultTenant(s).GetJob(ctx, beta.ID)
	if err != nil || unchanged.Revision != resumed.Revision {
		t.Fatalf("idempotent resume changed revision: %#v, %v", unchanged, err)
	}
	if err := defaultTenant(s).SetJobEnabledWithRevision(ctx, beta.ID, false, resumed.Revision-1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale pause error = %v", err)
	}

	if err := defaultTenant(s).DeleteJob(ctx, alpha.ID); err == nil || !strings.Contains(err.Error(), "archived") {
		t.Fatalf("active job deletion error = %v", err)
	}
	if err := defaultTenant(s).SetJobArchived(ctx, alpha.ID, true); err != nil {
		t.Fatal(err)
	}
	when := time.Now().UTC()
	if err := s.System().SaveScan(ctx, model.Scan{ID: "alpha-scan", JobID: alpha.ID, Job: alpha.Job.Name, StartedAt: when, FinishedAt: when, Status: "success", Snapshot: model.Snapshot{}}); err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).DeleteJob(ctx, alpha.ID); err != nil {
		t.Fatalf("permanent delete with retained scan history = %v", err)
	}
	if _, err := defaultTenant(s).GetJob(ctx, alpha.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted job lookup = %v", err)
	}
	if err := defaultTenant(s).DeleteJob(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing deletion error = %v", err)
	}

	// The deletion audit remains append-only even after the job is removed.
	if err := defaultTenant(s).SetJobArchived(ctx, beta.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).DeleteJobWithAudit(ctx, beta.ID, AuditEntry{Action: "job.deleted", Detail: beta.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).GetJob(ctx, beta.ID); !errors.Is(err, ErrNotFound) {
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

func TestPermanentJobDeletionPurgesHistoryAndRepairsLatestHosts(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	job, err := tenant.CreateJob(ctx, testJob("delete-history"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := tenant.CreateJob(ctx, testJob("keep-history"))
	if err != nil {
		t.Fatal(err)
	}

	address := "198.51.100.28"
	baseTime := time.Now().UTC().Add(-time.Minute)
	otherScan := model.Scan{
		ID: "keep-history-scan", JobID: other.ID, Job: other.Job.Name,
		StartedAt: baseTime, FinishedAt: baseTime, Status: "success",
		Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: address}}},
	}
	if err := s.System().SaveScan(ctx, otherScan); err != nil {
		t.Fatal(err)
	}
	jobScan := model.Scan{
		ID: "delete-history-scan", JobID: job.ID, Job: job.Job.Name,
		StartedAt: baseTime.Add(time.Second), FinishedAt: baseTime.Add(time.Second), Status: "success",
		Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: address}}},
	}
	if err := s.System().SaveScan(ctx, jobScan); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = jobScan.ID
		state.Baseline = &model.Snapshot{Hosts: []model.HostObservation{{Address: address}}}
		return []model.Event{{Type: "changes-detected", Job: job.Job.Name, ScanID: jobScan.ID, CreatedAt: baseTime.Add(2 * time.Second)}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.System().QueueEvent(ctx, "test-destination", model.Event{
		Type: "changes-detected", JobID: job.ID, Job: job.Job.Name,
		ScanID: jobScan.ID, CreatedAt: baseTime.Add(2 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	otherTenantID := "00000000-0000-0000-0000-000000000999"
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,?,?,?,?)`, otherTenantID, "Other quarantine unit", "other-quarantine-unit", sqliteTimestamp(baseTime), sqliteTimestamp(baseTime)); err != nil {
		t.Fatal(err)
	}
	insertQuarantined := func(epoch, tenantID, jobID string) {
		t.Helper()
		payload := []byte(`{"job_id":"` + jobID + `"}`)
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO restore_quarantined_deliveries(restore_epoch,destination,payload_json,quarantined_at,tenant_id) VALUES(?,?,?,?,?)`, epoch, "test-destination", payload, sqliteTimestamp(baseTime), tenantID); err != nil {
			t.Fatal(err)
		}
	}
	insertQuarantined("deleted-job", tenant.scope.id, job.ID)
	insertQuarantined("other-job", tenant.scope.id, other.ID)
	insertQuarantined("other-tenant", otherTenantID, job.ID)
	cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{
		ID: "delete-history-cycle", JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision,
		ConfigHash: job.Job.SecurityHash(),
		Plan: scanner.WorkPlan{Job: job.Job, Units: []scanner.WorkUnit{{
			Sequence: 0, Protocol: "tcp", Addresses: []string{address}, Ports: "443", PortCount: 1, Probes: 1,
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cycle.ID == "" {
		t.Fatal("created scan cycle has no ID")
	}
	if err := tenant.SetJobArchived(ctx, job.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := tenant.DeleteJobWithAuditAtRevision(ctx, job.ID, job.Revision, AuditEntry{Action: "job.deleted", Detail: job.ID}); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete with stale confirmed revision = %v, want ErrConflict", err)
	}

	var latestJobID, latestScanID string
	queryLatest := func() {
		t.Helper()
		if err := s.DB.QueryRowContext(ctx, `SELECT job_id,scan_id FROM latest_scan_hosts WHERE tenant_id=? AND address=?`, tenant.scope.id, address).Scan(&latestJobID, &latestScanID); err != nil {
			t.Fatal(err)
		}
	}
	queryLatest()
	if latestJobID != job.ID || latestScanID != jobScan.ID {
		t.Fatalf("latest host before delete = %s/%s, want deleted job scan", latestJobID, latestScanID)
	}

	// A failure to append the audit record must roll back every destructive
	// history write, not leave a partly deleted job behind.
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER reject_job_delete_audit BEFORE INSERT ON security_audit
		WHEN NEW.action='job.deleted' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	audit := AuditEntry{Action: "job.deleted", Detail: job.ID}
	if err := tenant.DeleteJobWithAudit(ctx, job.ID, audit); err == nil || !strings.Contains(err.Error(), "audit unavailable") {
		t.Fatalf("delete with rejected audit = %v", err)
	}
	var count int
	for name, statement := range map[string]string{
		"job":                  `SELECT COUNT(*) FROM jobs WHERE id=?`,
		"scan":                 `SELECT COUNT(*) FROM scans WHERE job_id=? AND tenant_id=?`,
		"event":                `SELECT COUNT(*) FROM events WHERE job_id=? AND tenant_id=?`,
		"cycle":                `SELECT COUNT(*) FROM scan_cycles WHERE job_id=?`,
		"outbox":               `SELECT COUNT(*) FROM outbox WHERE tenant_id=? AND json_extract(CAST(payload_json AS TEXT),'$.job_id')=?`,
		"quarantined delivery": `SELECT COUNT(*) FROM restore_quarantined_deliveries WHERE tenant_id=? AND json_extract(CAST(payload_json AS TEXT),'$.job_id')=?`,
	} {
		var args []any
		switch name {
		case "job", "cycle":
			args = []any{job.ID}
		case "outbox", "quarantined delivery":
			args = []any{tenant.scope.id, job.ID}
		default:
			args = []any{job.ID, tenant.scope.id}
		}
		if err := s.DB.QueryRowContext(ctx, statement, args...).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s count after rolled-back delete = %d, %v; want 1", name, count, err)
		}
	}
	queryLatest()
	if latestJobID != job.ID || latestScanID != jobScan.ID {
		t.Fatalf("latest host after rollback = %s/%s, want deleted job scan", latestJobID, latestScanID)
	}
	for label, tenantJob := range map[string][2]string{
		"deleted job":        {tenant.scope.id, job.ID},
		"another job":        {tenant.scope.id, other.ID},
		"another tenant job": {otherTenantID, job.ID},
	} {
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM restore_quarantined_deliveries WHERE tenant_id=? AND json_extract(CAST(payload_json AS TEXT),'$.job_id')=?`, tenantJob[0], tenantJob[1]).Scan(&count); err != nil || count != 1 {
			t.Errorf("quarantined deliveries for %s after rolled-back delete = %d, %v; want 1", label, count, err)
		}
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TRIGGER reject_job_delete_audit`); err != nil {
		t.Fatal(err)
	}
	// A failure in a later purge batch must leave the logical deletion committed,
	// with a resumable marker and no visible job/history.
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER reject_job_quarantine_delete BEFORE DELETE ON restore_quarantined_deliveries
		BEGIN SELECT RAISE(ABORT,'quarantine unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := tenant.DeleteJobWithAudit(ctx, job.ID, audit); err != nil {
		t.Fatalf("queue deletion with deferred quarantine cleanup = %v", err)
	}
	if _, err := tenant.GetJob(ctx, job.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("job lookup while purge is pending = %v, want hidden", err)
	}
	if purgedRows, purgeErr := s.System().PurgeDeletedJobHistories(ctx); purgedRows == 0 || purgeErr == nil || !strings.Contains(purgeErr.Error(), "quarantine unavailable") {
		t.Fatalf("purge with rejected quarantine cleanup = %d rows, %v; want a resumable failure", purgedRows, purgeErr)
	}
	var pendingPhase string
	if err := s.DB.QueryRowContext(ctx, `SELECT phase FROM job_history_purges WHERE tenant_id=? AND job_id=?`, tenant.scope.id, job.ID).Scan(&pendingPhase); err != nil || pendingPhase != jobPurgePhaseQuarantine {
		t.Fatalf("pending phase after quarantine failure = %q, %v; want %q", pendingPhase, err, jobPurgePhaseQuarantine)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE job_id=? AND tenant_id=?`, job.ID, tenant.scope.id).Scan(&count); err != nil || count != 0 {
		t.Fatalf("scan count after quarantine failure = %d, %v; want already erased", count, err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM restore_quarantined_deliveries WHERE tenant_id=? AND json_extract(CAST(payload_json AS TEXT),'$.job_id')=?`, tenant.scope.id, job.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("quarantined delivery count after purge failure = %d, %v; want 1 pending row", count, err)
	}
	for label, tenantJob := range map[string][2]string{
		"another job":        {tenant.scope.id, other.ID},
		"another tenant job": {otherTenantID, job.ID},
	} {
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM restore_quarantined_deliveries WHERE tenant_id=? AND json_extract(CAST(payload_json AS TEXT),'$.job_id')=?`, tenantJob[0], tenantJob[1]).Scan(&count); err != nil || count != 1 {
			t.Errorf("quarantined deliveries for %s after interrupted purge = %d, %v; want 1", label, count, err)
		}
	}
	if _, err := tenant.GetJob(ctx, job.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted managed job lookup = %v", err)
	}
	var pending int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_history_purges WHERE tenant_id=? AND job_id=?`, tenant.scope.id, job.ID).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("pending history purge marker count = %d, %v; want 1", pending, err)
	}
	latestPage, err := tenant.ListLatestScanHostsPage(ctx, "", "", nil, 50, 0)
	if err != nil || latestPage.Total != 0 {
		t.Fatalf("latest hosts exposed while purge is pending = total %d, %v; want hidden", latestPage.Total, err)
	}
	if _, err := tenant.GetScan(ctx, jobScan.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("scan detail visible while purge is pending = %v; want hidden", err)
	}
	if scans, err := tenant.ListJobScans(ctx, job.ID, 50); err != nil || len(scans) != 0 {
		t.Fatalf("job scans visible while purge is pending = %d, %v; want hidden", len(scans), err)
	}
	if events, err := tenant.ListJobEvents(ctx, job.ID, 50); err != nil || len(events) != 0 {
		t.Fatalf("job events visible while purge is pending = %d, %v; want hidden", len(events), err)
	}
	if events, err := tenant.ListEvents(ctx, job.Job.Name, 50); err != nil || len(events) != 0 {
		t.Fatalf("activity entries visible while purge is pending = %d, %v; want hidden", len(events), err)
	}
	historicalHosts, err := tenant.ListScanHostsPage(ctx, jobScan.ID, "", "", nil, 50, 0)
	if err != nil || historicalHosts.Total != 0 {
		t.Fatalf("scan hosts visible while purge is pending = %d, %v; want hidden", historicalHosts.Total, err)
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TRIGGER reject_job_quarantine_delete`); err != nil {
		t.Fatal(err)
	}
	if purgedRows, err := s.System().PurgeDeletedJobHistories(ctx); err != nil || purgedRows == 0 {
		t.Fatalf("resume purge after quarantine cleanup recovers = %d rows, %v", purgedRows, err)
	}
	for name, statement := range map[string]string{
		"scan":                 `SELECT COUNT(*) FROM scans WHERE job_id=? AND tenant_id=?`,
		"host rows":            `SELECT COUNT(*) FROM scan_hosts WHERE scan_id=?`,
		"event":                `SELECT COUNT(*) FROM events WHERE job_id=? AND tenant_id=?`,
		"cycle":                `SELECT COUNT(*) FROM scan_cycles WHERE job_id=?`,
		"cycle work":           `SELECT COUNT(*) FROM scan_cycle_units WHERE cycle_id=?`,
		"outbox":               `SELECT COUNT(*) FROM outbox WHERE tenant_id=? AND json_extract(CAST(payload_json AS TEXT),'$.job_id')=?`,
		"quarantined delivery": `SELECT COUNT(*) FROM restore_quarantined_deliveries WHERE tenant_id=? AND json_extract(CAST(payload_json AS TEXT),'$.job_id')=?`,
	} {
		var args []any
		switch name {
		case "host rows":
			args = []any{jobScan.ID}
		case "cycle work":
			args = []any{cycle.ID}
		case "outbox", "quarantined delivery":
			args = []any{tenant.scope.id, job.ID}
		case "cycle":
			args = []any{job.ID}
		default:
			args = []any{job.ID, tenant.scope.id}
		}
		if err := s.DB.QueryRowContext(ctx, statement, args...).Scan(&count); err != nil || count != 0 {
			t.Errorf("%s count after delete = %d, %v; want 0", name, count, err)
		}
	}
	for label, tenantJob := range map[string][2]string{
		"another job":        {tenant.scope.id, other.ID},
		"another tenant job": {otherTenantID, job.ID},
	} {
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM restore_quarantined_deliveries WHERE tenant_id=? AND json_extract(CAST(payload_json AS TEXT),'$.job_id')=?`, tenantJob[0], tenantJob[1]).Scan(&count); err != nil || count != 1 {
			t.Errorf("quarantined deliveries for %s after delete = %d, %v; want 1", label, count, err)
		}
	}
	queryLatest()
	if latestJobID != other.ID || latestScanID != otherScan.ID {
		t.Fatalf("latest host after delete = %s/%s, want preserved other job scan", latestJobID, latestScanID)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='job.deleted' AND detail=?`, job.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("deletion audit count = %d, %v; want 1", count, err)
	}
	if _, err := tenant.RuntimeState(ctx, job.ID); err != nil {
		t.Fatalf("deleted job runtime state remains readable: %v", err)
	}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(*model.JobState) ([]model.Event, error) {
		return []model.Event{{Type: "late-event", JobID: job.ID, Job: job.Job.Name, CreatedAt: time.Now().UTC()}}, nil
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("late runtime mutation after deletion = %v; want not found", err)
	}
	lateScan := model.Scan{ID: "late-deleted-job-scan", JobID: job.ID, Job: job.Job.Name, StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), Status: "failed"}
	if err := s.System().SaveScan(ctx, lateScan); !errors.Is(err, ErrNotFound) {
		t.Fatalf("late scan write after deletion = %v; want not found", err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE id=?`, lateScan.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("late scan row count = %d, %v; want 0", count, err)
	}
	if err := s.System().QueueEvent(ctx, "late-deleted-job-destination", model.Event{Type: "late-event", JobID: job.ID, Job: job.Job.Name, CreatedAt: time.Now().UTC()}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("late delivery write after deletion = %v; want not found", err)
	}
}

func TestPermanentJobHistoryPurgeResumesWhenCleanupFails(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	job, err := tenant.CreateJob(ctx, testJob("delete-rollback"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().UpdateRuntime(ctx, job.ID, func(state *model.JobState) ([]model.Event, error) {
		return []model.Event{{Type: "test-event", JobID: job.ID, Job: job.Job.Name, CreatedAt: time.Now().UTC()}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.System().QueueEvent(ctx, "delete-rollback-destination", model.Event{
		Type: "test-delivery", JobID: job.ID, Job: job.Job.Name, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := tenant.SetJobArchived(ctx, job.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER reject_job_delete_events BEFORE DELETE ON events
		BEGIN SELECT RAISE(ABORT,'event cleanup unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	err = tenant.DeleteJobWithAudit(ctx, job.ID, AuditEntry{Action: "job.deleted", Detail: job.ID})
	if err != nil {
		t.Fatalf("request permanent deletion = %v", err)
	}
	_, err = s.System().PurgeDeletedJobHistories(ctx)
	if err == nil || !strings.Contains(err.Error(), "event cleanup unavailable") {
		t.Fatalf("purge when history cleanup fails = %v", err)
	}
	if _, err := tenant.GetJob(ctx, job.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("job lookup during pending purge = %v; want hidden", err)
	}
	if active, err := tenant.JobActive(ctx, job.ID); active || !errors.Is(err, ErrNotFound) {
		t.Fatalf("job active check during pending purge = %t, %v; want not found", active, err)
	}
	var pendingPhase string
	if err := s.DB.QueryRowContext(ctx, `SELECT phase FROM job_history_purges WHERE tenant_id=? AND job_id=?`, tenant.scope.id, job.ID).Scan(&pendingPhase); err != nil || pendingPhase != jobPurgePhaseEvents {
		t.Fatalf("pending purge phase = %q, %v; want %q", pendingPhase, err, jobPurgePhaseEvents)
	}
	for name, statement := range map[string]string{
		"event":  `SELECT COUNT(*) FROM events WHERE job_id=?`,
		"outbox": `SELECT COUNT(*) FROM outbox WHERE tenant_id=? AND json_extract(CAST(payload_json AS TEXT),'$.job_id')=?`,
	} {
		var count int
		args := []any{job.ID}
		if name == "outbox" {
			args = []any{tenant.scope.id, job.ID}
		}
		if err := s.DB.QueryRowContext(ctx, statement, args...).Scan(&count); err != nil || count != 1 {
			t.Errorf("%s count after interrupted purge = %d, %v; want 1", name, count, err)
		}
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TRIGGER reject_job_delete_events`); err != nil {
		t.Fatal(err)
	}
	if purgedRows, err := s.System().PurgeDeletedJobHistories(ctx); err != nil || purgedRows == 0 {
		t.Fatalf("resume job history purge = %d rows, %v", purgedRows, err)
	}
	for name, statement := range map[string]string{
		"event":  `SELECT COUNT(*) FROM events WHERE job_id=?`,
		"outbox": `SELECT COUNT(*) FROM outbox WHERE tenant_id=? AND json_extract(CAST(payload_json AS TEXT),'$.job_id')=?`,
	} {
		var count int
		args := []any{job.ID}
		if name == "outbox" {
			args = []any{tenant.scope.id, job.ID}
		}
		if err := s.DB.QueryRowContext(ctx, statement, args...).Scan(&count); err != nil || count != 0 {
			t.Errorf("%s count after resumed purge = %d, %v; want 0", name, count, err)
		}
	}
}

func TestListJobsPlacesArchivedJobsAfterActiveJobs(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	activeLate, err := defaultTenant(s).CreateJob(ctx, testJob("zulu-active"))
	if err != nil {
		t.Fatal(err)
	}
	archivedEarly, err := defaultTenant(s).CreateJob(ctx, testJob("aardvark-archived"))
	if err != nil {
		t.Fatal(err)
	}
	activeEarly, err := defaultTenant(s).CreateJob(ctx, testJob("alpha-active"))
	if err != nil {
		t.Fatal(err)
	}
	archivedLate, err := defaultTenant(s).CreateJob(ctx, testJob("zulu-archived"))
	if err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).SetJobArchived(ctx, archivedEarly.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).SetJobArchived(ctx, archivedLate.ID, true); err != nil {
		t.Fatal(err)
	}

	jobs, err := defaultTenant(s).ListJobs(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 4 {
		t.Fatalf("listed %d jobs, want 4", len(jobs))
	}
	if jobs[0].ID != activeEarly.ID || jobs[1].ID != activeLate.ID || !jobs[2].Archived || !jobs[3].Archived {
		t.Fatalf("job order = %#v, want active jobs first and archived jobs last", jobs)
	}
}

func TestJobActiveAndLeaseExpiry(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("lease"))
	if err != nil {
		t.Fatal(err)
	}
	active, err := defaultTenant(s).JobActive(ctx, record.ID)
	if err != nil || active {
		t.Fatalf("job initially active = %v, %v", active, err)
	}
	if err := s.System().AcquireJobLease(ctx, record.ID, "owner", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	active, err = defaultTenant(s).JobActive(ctx, record.ID)
	if err != nil || !active {
		t.Fatalf("leased job active = %v, %v", active, err)
	}
	if err := defaultTenant(s).DeleteJob(ctx, record.ID); err == nil || !strings.Contains(err.Error(), "archived") {
		t.Fatalf("unarchived job deletion error = %v", err)
	}
	if err := defaultTenant(s).SetJobArchived(ctx, record.ID, true); err == nil || !errors.Is(err, ErrJobScanActive) {
		t.Fatalf("active archive error = %v", err)
	}
	if err := defaultTenant(s).SetJobEnabled(ctx, record.ID, false); err == nil || !errors.Is(err, ErrJobScanActive) {
		t.Fatalf("active pause error = %v", err)
	}
	unchanged, err := defaultTenant(s).GetJob(ctx, record.ID)
	if err != nil || unchanged.Archived || !unchanged.Enabled {
		t.Fatalf("active lifecycle action changed job state: %#v", unchanged)
	}
	if err := s.System().ReleaseJobLease(ctx, record.ID, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).SetJobArchived(ctx, record.ID, true); err != nil {
		t.Fatalf("archive after lease release = %v", err)
	}
	if err := s.System().AcquireJobLease(ctx, record.ID, "owner", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).DeleteJob(ctx, record.ID); err == nil || !errors.Is(err, ErrJobScanActive) {
		t.Fatalf("active archived job deletion error = %v", err)
	}
	if err := s.System().ReleaseJobLease(ctx, record.ID, "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "lease-test"
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
}
