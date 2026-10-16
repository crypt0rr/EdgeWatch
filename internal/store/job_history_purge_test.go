package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestJobHistoryPurgeBatchesYieldsWriterAndResumesAfterRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database := freshTestDatabasePath(t)
	s, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	tenant := defaultTenant(s)
	deleted, err := tenant.CreateJob(ctx, testJob("large-history-delete"))
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	other, err := tenant.CreateJob(ctx, testJob("concurrent-writer"))
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	const hostCount = jobHistoryPurgeBatchSize + 10
	hosts := make([]model.HostObservation, hostCount)
	for i := range hosts {
		hosts[i] = model.HostObservation{Address: fmt.Sprintf("10.20.%d.%d", (i+1)/256, (i+1)%256)}
	}
	finished := time.Now().UTC().Add(-time.Minute)
	for _, scan := range []model.Scan{
		{ID: "older-host-scan", JobID: other.ID, Job: other.Job.Name, StartedAt: finished, FinishedAt: finished, Status: "success", Snapshot: model.Snapshot{Hosts: hosts}},
		{ID: "newer-deleted-host-scan", JobID: deleted.ID, Job: deleted.Job.Name, StartedAt: finished.Add(time.Second), FinishedAt: finished.Add(time.Second), Status: "success", Snapshot: model.Snapshot{Hosts: hosts}},
	} {
		if err := s.System().SaveScan(ctx, scan); err != nil {
			s.Close()
			t.Fatal(err)
		}
	}
	for _, owner := range []JobRecord{deleted, other} {
		incident := model.Incident{
			Change: model.Change{Key: "purge-reviewed-" + owner.Job.Name, Kind: "port", Severity: "warning", Target: "reviewed.example", Protocol: "tcp", Port: 443, Old: "closed", New: "open"},
			ScanID: "review-origin-" + owner.Job.Name, OpenedAt: finished, LastSeenAt: finished,
		}
		if _, err := s.System().UpdateRuntime(ctx, owner.ID, func(state *model.JobState) ([]model.Event, error) {
			state.Incidents[incident.Change.Key] = incident
			return nil, nil
		}); err != nil {
			s.Close()
			t.Fatal(err)
		}
		page, err := tenant.ListIncidentInbox(ctx, IncidentInboxFilter{View: "all_active", JobID: owner.ID, Limit: 10, Now: finished})
		if err != nil || len(page.Items) != 1 {
			s.Close()
			t.Fatalf("review purge fixture for %s = %+v, %v", owner.ID, page, err)
		}
		if _, err := tenant.SaveIncidentReview(ctx, owner.ID, IncidentReviewWrite{
			Key: incident.Change.Key, OccurrenceToken: page.Items[0].OccurrenceToken, ExpectedRevision: 0, Status: "investigating", Note: "private retained review history",
		}, "purge-test-reviewer", "Purge test reviewer", AuditEntry{Action: "incident.review.updated"}); err != nil {
			s.Close()
			t.Fatal(err)
		}
	}
	if err := tenant.SetJobArchived(ctx, deleted.ID, true); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := tenant.DeleteJobWithAudit(ctx, deleted.ID, AuditEntry{Action: "job.deleted", Detail: deleted.ID}); err != nil {
		s.Close()
		t.Fatal(err)
	}

	stopAfterBatch := errors.New("stop after first committed scan-host batch")
	writerMadeProgress := false
	rows, err := s.System().purgeDeletedJobHistories(ctx, jobHistoryPurgeOptions{
		batchSize: jobHistoryPurgeBatchSize,
		afterBatch: func(ctx context.Context, _, _, phase string) error {
			if phase != jobPurgePhaseScanHosts || writerMadeProgress {
				return nil
			}
			// This write is made after the scan-host batch committed. It must not
			// wait for the remainder of the job's retained evidence to be erased.
			if err := tenant.SetJobArchived(ctx, other.ID, true); err != nil {
				return fmt.Errorf("unrelated writer could not make progress: %w", err)
			}
			writerMadeProgress = true
			return stopAfterBatch
		},
	})
	if !errors.Is(err, stopAfterBatch) || !writerMadeProgress || rows < jobHistoryPurgeBatchSize {
		t.Fatalf("interrupted purge = %d rows, %v, writer progressed %v; want committed first batch and interruption", rows, err, writerMadeProgress)
	}
	if _, err := tenant.GetJob(ctx, deleted.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("job visible while history purge is pending = %v; want hidden", err)
	}
	page, err := tenant.ListLatestScanHostsPage(ctx, "", "", nil, hostCount+10, 0)
	if err != nil || page.Total != 0 {
		t.Fatalf("latest host inventory during partial purge = %d rows, %v; want hidden", page.Total, err)
	}
	var scanRows int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_hosts WHERE scan_id='newer-deleted-host-scan'`).Scan(&scanRows); err != nil || scanRows != hostCount-jobHistoryPurgeBatchSize {
		t.Fatalf("remaining scan hosts = %d, %v; want %d after first bounded batch", scanRows, err, hostCount-jobHistoryPurgeBatchSize)
	}
	for _, check := range []struct {
		job  string
		want int
	}{
		{deleted.ID, 0},
		{other.ID, 1},
	} {
		for _, table := range []string{"incident_reviews", "incident_review_history"} {
			var count int
			if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE job_id=?`, check.job).Scan(&count); err != nil || count != check.want {
				t.Errorf("%s rows for job %s after interrupted purge = %d, %v; want %d", table, check.job, count, err, check.want)
			}
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// A daemon restart loads the durable phase and safely continues without
	// restarting an already committed batch.
	restarted, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if purged, err := restarted.System().PurgeDeletedJobHistories(ctx); err != nil || purged == 0 {
		t.Fatalf("resume purge after restart = %d rows, %v", purged, err)
	}
	var jobRows int
	if err := restarted.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE id=?`, deleted.ID).Scan(&jobRows); err != nil || jobRows != 0 {
		t.Fatalf("job row after resumed purge = %d, %v; want deleted", jobRows, err)
	}
	page, err = restarted.Tenant(DefaultTenantScope()).ListLatestScanHostsPage(ctx, "", "", nil, hostCount+10, 0)
	if err != nil || page.Total != hostCount {
		t.Fatalf("latest host inventory after purge = %d rows, %v; want %d", page.Total, err, hostCount)
	}
	for _, host := range page.Items {
		if host.JobID != other.ID || host.ScanID != "older-host-scan" {
			t.Fatalf("repaired host %s belongs to %s/%s, want retained older scan %s", host.Host.Address, host.JobID, host.ScanID, other.ID)
		}
	}
	if err := restarted.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_history_purges WHERE phase<>?`, jobPurgePhaseComplete).Scan(&jobRows); err != nil || jobRows != 0 {
		t.Fatalf("pending purge markers after completion = %d, %v; want 0", jobRows, err)
	}
	if err := restarted.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_history_purges WHERE tenant_id=? AND job_id=? AND phase=?`, tenant.scope.id, deleted.ID, jobPurgePhaseComplete).Scan(&jobRows); err != nil || jobRows != 1 {
		t.Fatalf("completed deletion tombstone = %d, %v; want retained", jobRows, err)
	}
	for _, check := range []struct {
		job  string
		want int
	}{
		{deleted.ID, 0},
		{other.ID, 1},
	} {
		for _, table := range []string{"incident_reviews", "incident_review_history"} {
			var count int
			if err := restarted.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE job_id=?`, check.job).Scan(&count); err != nil || count != check.want {
				t.Errorf("%s rows for job %s after restart = %d, %v; want %d", table, check.job, count, err, check.want)
			}
		}
	}
}

func TestLatestHostProjectionRebuildExcludesPendingJobPurges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	survivor, err := tenant.CreateJob(ctx, testJob("surviving-latest-host"))
	if err != nil {
		t.Fatal(err)
	}
	purging, err := tenant.CreateJob(ctx, testJob("purging-latest-host"))
	if err != nil {
		t.Fatal(err)
	}
	address := "192.0.2.200"
	base := time.Now().UTC().Add(-time.Hour)
	for _, scan := range []model.Scan{
		{ID: "surviving-host-history", JobID: survivor.ID, Job: survivor.Job.Name, StartedAt: base, FinishedAt: base, Status: "success", Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: address}}}},
		{ID: "purging-host-history", JobID: purging.ID, Job: purging.Job.Name, StartedAt: base.Add(time.Minute), FinishedAt: base.Add(time.Minute), Status: "success", Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: address}}}},
	} {
		if err := s.System().SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	stamp := sqliteTimestamp(time.Now().UTC())
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_history_purges(tenant_id,job_id,phase,created_at,updated_at) VALUES(?,?,?,?,?)`, tenant.scope.id, purging.ID, jobPurgePhaseComplete, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM latest_scan_hosts WHERE tenant_id=? AND address=?`, tenant.scope.id, address); err != nil {
		t.Fatal(err)
	}
	rebuildTx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rebuildLatestScanHostsTx(ctx, rebuildTx); err != nil {
		_ = rebuildTx.Rollback()
		t.Fatal(err)
	}
	if err := rebuildTx.Commit(); err != nil {
		t.Fatal(err)
	}
	var jobID, scanID string
	if err := s.DB.QueryRowContext(ctx, `SELECT job_id,scan_id FROM latest_scan_hosts WHERE tenant_id=? AND address=?`, tenant.scope.id, address).Scan(&jobID, &scanID); err != nil {
		t.Fatal(err)
	}
	if jobID != survivor.ID || scanID != "surviving-host-history" {
		t.Fatalf("latest host after rebuild = %s/%s; want surviving scan %s", jobID, scanID, survivor.ID)
	}
	deleteSQL, insertSQL, args := latestScanHostRepairQueries([]latestScanHostKey{{tenantID: tenant.scope.id, address: address}})
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, deleteSQL, args...); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, insertSQL, args...); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT job_id,scan_id FROM latest_scan_hosts WHERE tenant_id=? AND address=?`, tenant.scope.id, address).Scan(&jobID, &scanID); err != nil {
		t.Fatal(err)
	}
	if jobID != survivor.ID || scanID != "surviving-host-history" {
		t.Fatalf("latest host after key repair = %s/%s; want surviving scan %s", jobID, scanID, survivor.ID)
	}
}

func TestJobHistoryPurgeDoesNotAttributeMalformedDeliveryPayloads(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	job, err := tenant.CreateJob(ctx, testJob("malformed-delivery-history"))
	if err != nil {
		t.Fatal(err)
	}
	stamp := sqliteTimestamp(time.Now().UTC())
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,next_at,tenant_id) VALUES('unattributed',x'ff',?,?)`, stamp, tenant.scope.id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO restore_quarantined_deliveries(restore_epoch,destination,payload_json,quarantined_at,tenant_id) VALUES('unattributed','unattributed',x'ff',?,?)`, stamp, tenant.scope.id); err != nil {
		t.Fatal(err)
	}
	if err := tenant.SetJobArchived(ctx, job.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := tenant.DeleteJobWithAudit(ctx, job.ID, AuditEntry{Action: "job.deleted", Detail: job.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().PurgeDeletedJobHistories(ctx); err != nil {
		t.Fatalf("purge malformed delivery payloads: %v", err)
	}
	for name, statement := range map[string]string{
		"outbox":      `SELECT COUNT(*) FROM outbox WHERE destination='unattributed'`,
		"quarantined": `SELECT COUNT(*) FROM restore_quarantined_deliveries WHERE restore_epoch='unattributed'`,
	} {
		var count int
		if err := s.DB.QueryRowContext(ctx, statement).Scan(&count); err != nil || count != 1 {
			t.Errorf("unattributed %s rows after deletion = %d, %v; want preserved", name, count, err)
		}
	}
}

func TestJobHistoryPurgeResumesBetweenHostProjectionPhases(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	job, err := tenant.CreateJob(ctx, testJob("host-projection-phase-purge"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tenant.SetJobArchived(ctx, job.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := tenant.DeleteJobWithAudit(ctx, job.ID, AuditEntry{Action: "job.deleted", Detail: job.ID}); err != nil {
		t.Fatal(err)
	}
	stopLatestHosts := errors.New("pause after latest-host removal")
	if _, err := s.System().purgeDeletedJobHistories(ctx, jobHistoryPurgeOptions{
		batchSize: 1,
		afterBatch: func(_ context.Context, _, _, phase string) error {
			if phase == jobPurgePhaseLatestHosts {
				return stopLatestHosts
			}
			return nil
		},
	}); !errors.Is(err, stopLatestHosts) {
		t.Fatalf("latest-host phase interruption = %v; want %v", err, stopLatestHosts)
	}
	var phase string
	if err := s.DB.QueryRowContext(ctx, `SELECT phase FROM job_history_purges WHERE job_id=?`, job.ID).Scan(&phase); err != nil || phase != jobPurgePhaseRepairHosts {
		t.Fatalf("phase after latest-host interruption = %q, %v; want %q", phase, err, jobPurgePhaseRepairHosts)
	}

	stopRepairHosts := errors.New("pause after latest-host repair")
	if _, err := s.System().purgeDeletedJobHistories(ctx, jobHistoryPurgeOptions{
		batchSize: 1,
		afterBatch: func(_ context.Context, _, _, phase string) error {
			if phase == jobPurgePhaseRepairHosts {
				return stopRepairHosts
			}
			return nil
		},
	}); !errors.Is(err, stopRepairHosts) {
		t.Fatalf("latest-host repair interruption = %v; want %v", err, stopRepairHosts)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT phase FROM job_history_purges WHERE job_id=?`, job.ID).Scan(&phase); err != nil || phase != jobPurgePhaseDeleteJob {
		t.Fatalf("phase after repair interruption = %q, %v; want %q", phase, err, jobPurgePhaseDeleteJob)
	}
	if _, err := s.System().PurgeDeletedJobHistories(ctx); err != nil {
		t.Fatalf("resume after host-projection interruptions: %v", err)
	}
}

func TestJobHistoryPurgeCancellationAndEmptyQueue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	if purged, err := s.System().purgeDeletedJobHistories(ctx, jobHistoryPurgeOptions{}); err != nil || purged != 0 {
		t.Fatalf("empty purge queue with default batch size = %d, %v; want 0, nil", purged, err)
	}

	tenant := defaultTenant(s)
	job, err := tenant.CreateJob(ctx, testJob("cancelled-history-purge"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tenant.SetJobArchived(ctx, job.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := tenant.DeleteJobWithAudit(ctx, job.ID, AuditEntry{Action: "job.deleted", Detail: job.ID}); err != nil {
		t.Fatal(err)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	_, err = s.System().purgeDeletedJobHistories(workerCtx, jobHistoryPurgeOptions{
		batchSize: 1,
		afterBatch: func(_ context.Context, _, _, _ string) error {
			cancel()
			return nil
		},
	})
	cancel()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("purge cancellation between batches = %v; want context.Canceled", err)
	}
	if _, err := s.System().PurgeDeletedJobHistories(ctx); err != nil {
		t.Fatalf("resume after cancellation: %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if purged, err := s.System().PurgeDeletedJobHistories(cancelled); purged != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled purge = %d, %v; want 0, context.Canceled", purged, err)
	}
}

func TestJobHistoryPurgeRejectsUnknownPhaseAndReportsClosedStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.System().purgeJobHistory(ctx, jobHistoryPurgeRecord{tenantID: DefaultTenantID, jobID: "unknown-phase", phase: "unsupported"}, jobHistoryPurgeOptions{}); err == nil || !strings.Contains(err.Error(), "unknown job history purge phase") {
		t.Fatalf("unknown purge phase error = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().PurgeDeletedJobHistories(ctx); err == nil {
		t.Fatal("purge on a closed store succeeded; want the database error")
	}
}

func TestJobHistoryPurgeCoversJobOwnedTablesAndWindowChildren(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	triggerTables := jobHistoryPurgeTriggerTables()
	if err := verifyJobHistoryPurgeTriggerTables(context.Background(), s, triggerTables); err != nil {
		t.Fatal(err)
	}
	if problems := jobHistoryPurgeRegistryProblems(tenancyTables, jobHistoryPurgeSteps, triggerTables); len(problems) != 0 {
		t.Fatalf("job history purge registry problems: %s", strings.Join(problems, "; "))
	}

	for _, table := range []string{"incident_review_history", "scan_cycle_units", "scan_cycle_discovery_checkpoints"} {
		t.Run("missing_"+table, func(t *testing.T) {
			steps := withoutJobHistoryPurgeStep(jobHistoryPurgeSteps, table)
			want := "job-owned table " + table + " has no bounded job-history purge phase"
			if problems := jobHistoryPurgeRegistryProblems(tenancyTables, steps, triggerTables); !containsProblem(problems, want) {
				t.Fatalf("registry problems after removing %s: %v; want %q", table, problems, want)
			}
		})
	}

	t.Run("new_change_window_child_without_step", func(t *testing.T) {
		tables := cloneTenancyTableRegistry(tenancyTables)
		tables["zz_test_change_window_child"] = viaTable("change_windows")
		want := "job-owned table zz_test_change_window_child has no bounded job-history purge phase"
		if problems := jobHistoryPurgeRegistryProblems(tables, jobHistoryPurgeSteps, triggerTables); !containsProblem(problems, want) {
			t.Fatalf("registry problems after adding an unpurged change-window child: %v; want %q", problems, want)
		}
	})

	t.Run("child_before_parent_order", func(t *testing.T) {
		steps := append([]jobHistoryPurgeStep(nil), jobHistoryPurgeSteps...)
		child, parent := -1, -1
		for i, step := range steps {
			switch step.table {
			case "incident_review_history":
				child = i
			case "incident_reviews":
				parent = i
			}
		}
		if child < 0 || parent < 0 {
			t.Fatal("fixture is missing the incident review purge phases")
		}
		steps[child], steps[parent] = steps[parent], steps[child]
		want := "job-owned child incident_review_history is purged after parent incident_reviews"
		if problems := jobHistoryPurgeRegistryProblems(tenancyTables, steps, triggerTables); !containsProblem(problems, want) {
			t.Fatalf("registry problems after reversing child and parent: %v; want %q", problems, want)
		}
	})

	positions := make(map[string]int, len(jobHistoryPurgeSteps))
	phasePositions := make(map[string]int, len(jobHistoryPurgeSteps))
	for i, step := range jobHistoryPurgeSteps {
		phasePositions[step.phase] = i
		if _, exists := positions[step.table]; !exists {
			positions[step.table] = i
		}
	}
	if phasePositions[jobPurgePhaseWindowOutboxLinks] >= positions["change_window_refs"] || phasePositions[jobPurgePhaseWindowOutboxJob] >= positions["change_window_refs"] {
		t.Error("job-history purge deletes change-window evidence before linked outbox deliveries")
	}
}

func jobHistoryPurgeRegistryProblems(tables map[string]tableTenancy, steps []jobHistoryPurgeStep, triggerTables map[string]string) []string {
	owned := map[string]struct{}{"jobs": {}}
	for changed := true; changed; {
		changed = false
		for table, tenancy := range tables {
			if tenancy.class != tenancyVia {
				continue
			}
			if _, parentOwned := owned[tenancy.parent]; !parentOwned {
				continue
			}
			if _, alreadyOwned := owned[table]; alreadyOwned {
				continue
			}
			owned[table] = struct{}{}
			changed = true
		}
	}
	delete(owned, "jobs")

	positions := make(map[string]int, len(steps))
	for i, step := range steps {
		if _, exists := positions[step.table]; !exists {
			positions[step.table] = i
		}
	}

	tablesInOrder := make([]string, 0, len(owned))
	for table := range owned {
		tablesInOrder = append(tablesInOrder, table)
	}
	sort.Strings(tablesInOrder)

	var problems []string
	for _, table := range tablesInOrder {
		tenancy := tables[table]
		if trigger, triggerManaged := triggerTables[table]; triggerManaged {
			if trigger == "" {
				problems = append(problems, fmt.Sprintf("trigger-maintained job-owned table %s has no trigger name", table))
			} else if _, parentHasStep := positions[tenancy.parent]; !parentHasStep {
				problems = append(problems, fmt.Sprintf("trigger-maintained job-owned table %s has no bounded parent phase for %s", table, tenancy.parent))
			}
			continue
		}

		childPosition, hasStep := positions[table]
		if !hasStep {
			problems = append(problems, fmt.Sprintf("job-owned table %s has no bounded job-history purge phase", table))
			continue
		}

		parent := tenancy.parent
		for parent != "" && parent != "jobs" {
			parentTenancy, knownParent := tables[parent]
			if !knownParent {
				break
			}
			if parentPosition, parentHasStep := positions[parent]; parentHasStep {
				if childPosition >= parentPosition {
					problems = append(problems, fmt.Sprintf("job-owned child %s is purged after parent %s", table, parent))
				}
				break
			}
			if _, triggerManaged := triggerTables[parent]; !triggerManaged {
				break
			}
			parent = parentTenancy.parent
		}
	}
	return problems
}

func jobHistoryPurgeTriggerTables() map[string]string {
	triggers := make(map[string]string)
	for _, step := range tenantPurgeSteps {
		if step.trigger != "" {
			triggers[step.table] = step.trigger
		}
	}
	return triggers
}

func verifyJobHistoryPurgeTriggerTables(ctx context.Context, s *Store, triggerTables map[string]string) error {
	for table, trigger := range triggerTables {
		tenancy, ok := tenancyTables[table]
		if !ok || tenancy.class != tenancyVia {
			continue
		}
		var definition string
		if err := s.DB.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='trigger' AND name=? AND tbl_name=?`, trigger, tenancy.parent).Scan(&definition); err != nil {
			return fmt.Errorf("lookup job-owned purge trigger %s for %s: %w", trigger, table, err)
		}
		if !strings.Contains(definition, "AFTER DELETE ON "+tenancy.parent) || !strings.Contains(definition, "DELETE FROM "+table+" WHERE rowid=OLD.rowid") {
			return fmt.Errorf("trigger %s does not remove job-owned rows from %s through parent %s: %s", trigger, table, tenancy.parent, definition)
		}
	}
	return nil
}

func withoutJobHistoryPurgeStep(steps []jobHistoryPurgeStep, table string) []jobHistoryPurgeStep {
	filtered := make([]jobHistoryPurgeStep, 0, len(steps))
	for _, step := range steps {
		if step.table != table {
			filtered = append(filtered, step)
		}
	}
	return filtered
}

func cloneTenancyTableRegistry(tables map[string]tableTenancy) map[string]tableTenancy {
	cloned := make(map[string]tableTenancy, len(tables))
	for table, tenancy := range tables {
		cloned[table] = tenancy
	}
	return cloned
}

func containsProblem(problems []string, want string) bool {
	for _, problem := range problems {
		if problem == want {
			return true
		}
	}
	return false
}
