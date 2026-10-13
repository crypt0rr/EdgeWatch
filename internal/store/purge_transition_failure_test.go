package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func createDeletedPurgeTestJob(t *testing.T, name string) (*Store, *TenantStore, JobRecord) {
	t.Helper()
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	job, err := tenant.CreateJob(ctx, testJob(name))
	if err != nil {
		t.Fatal(err)
	}
	if err := tenant.SetJobArchived(ctx, job.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := tenant.DeleteJobWithAudit(ctx, job.ID, AuditEntry{Action: "job.deleted", Detail: job.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_history_purges SET phase=? WHERE tenant_id=? AND job_id=?`, jobPurgePhaseDeleteJob, tenant.scope.ID(), job.ID); err != nil {
		t.Fatal(err)
	}
	return s, tenant, job
}

func assertJobPurgeStillFinalizing(t *testing.T, s *Store, tenant *TenantStore, jobID string) {
	t.Helper()
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM jobs WHERE tenant_id=? AND id=?`, tenant.scope.ID(), jobID); got != 1 {
		t.Fatalf("job rows after failed finalization = %d; want one retained tombstone", got)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM job_history_purges WHERE tenant_id=? AND job_id=? AND phase=?`, tenant.scope.ID(), jobID, jobPurgePhaseDeleteJob); got != 1 {
		t.Fatalf("job purge marker after failed finalization = %d; want delete_job checkpoint", got)
	}
}

func TestJobHistoryPurgeTailCheckpointFailureKeepsWindowAndRetries(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	tenant := defaultTenant(s)
	job := createWindowTestJob(t, tenant, "purge-tail-checkpoint-failure", "UTC")
	now := time.Now().UTC().Truncate(time.Second)
	window := createTestChangeWindow(t, tenant, job.ID, now.Add(time.Hour), now.Add(2*time.Hour))
	deliveryID := insertPurgeTestDelivery(t, s, tenant.scope.ID(), job.ID, window.ID, "tail-checkpoint-failure", "pending")
	if err := tenant.SetJobArchived(ctx, job.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := tenant.DeleteJobWithAudit(ctx, job.ID, AuditEntry{Action: "job.deleted", Detail: job.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_history_purges SET phase=? WHERE tenant_id=? AND job_id=?`, jobPurgePhaseDeleteJob, tenant.scope.ID(), job.ID); err != nil {
		t.Fatal(err)
	}
	trigger := fmt.Sprintf(`CREATE TRIGGER reject_window_tail_rewind BEFORE UPDATE OF phase ON job_history_purges
WHEN OLD.tenant_id=%q AND OLD.job_id=%q AND NEW.phase=%q
BEGIN SELECT RAISE(ABORT,'injected window tail checkpoint failure'); END`, tenant.scope.ID(), job.ID, jobPurgePhaseWindowOutboxJob)
	if _, err := s.DB.ExecContext(ctx, trigger); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().PurgeDeletedJobHistories(ctx); err == nil || !strings.Contains(err.Error(), "injected window tail checkpoint failure") {
		t.Fatalf("purge with a failed tail rewind = %v; want injected checkpoint failure", err)
	}
	assertJobPurgeStillFinalizing(t, s, tenant, job.ID)
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_windows WHERE id=?`, window.ID) != 1 || countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE id=? AND change_window_id=?`, deliveryID, window.ID) != 1 {
		t.Fatal("failed tail rewind removed the referenced window or delivery")
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TRIGGER reject_window_tail_rewind`); err != nil {
		t.Fatal(err)
	}
	ignoreTrigger := fmt.Sprintf(`CREATE TRIGGER ignore_window_tail_rewind BEFORE UPDATE OF phase ON job_history_purges
WHEN OLD.tenant_id=%q AND OLD.job_id=%q AND NEW.phase=%q
BEGIN SELECT RAISE(IGNORE); END`, tenant.scope.ID(), job.ID, jobPurgePhaseWindowOutboxJob)
	if _, err := s.DB.ExecContext(ctx, ignoreTrigger); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().PurgeDeletedJobHistories(ctx); !errors.Is(err, ErrConflict) {
		t.Fatalf("purge with a lost checkpoint update = %v; want ErrConflict", err)
	}
	assertJobPurgeStillFinalizing(t, s, tenant, job.ID)
	if countRows(t, s.DB, `SELECT COUNT(*) FROM change_windows WHERE id=?`, window.ID) != 1 || countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE id=? AND change_window_id=?`, deliveryID, window.ID) != 1 {
		t.Fatal("ignored tail rewind removed the referenced window or delivery")
	}
	if _, err := s.DB.ExecContext(ctx, `DROP TRIGGER ignore_window_tail_rewind`); err != nil {
		t.Fatal(err)
	}
	if purged, err := s.System().PurgeDeletedJobHistories(ctx); err != nil || purged == 0 {
		t.Fatalf("retry purge after removing checkpoint fault = %d, %v", purged, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM jobs WHERE id=?`, job.ID) != 0 || countRows(t, s.DB, `SELECT COUNT(*) FROM outbox WHERE id=?`, deliveryID) != 0 || countRows(t, s.DB, `SELECT COUNT(*) FROM change_windows WHERE id=?`, window.ID) != 0 {
		t.Fatal("retry did not finish the bounded window-tail purge")
	}
}

func TestJobHistoryPurgeFinalizationFailuresRollbackAndRetry(t *testing.T) {
	ctx := context.Background()
	s, tenant, job := createDeletedPurgeTestJob(t, "purge-finalizer-failure")
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO job_history_purge_host_keys(tenant_id,job_id,address) VALUES(?,?,?)`, tenant.scope.ID(), job.ID, "192.0.2.40"); err != nil {
		t.Fatal(err)
	}
	faults := []struct {
		name    string
		trigger string
		want    error
		message string
	}{
		{
			name: "job delete SQL failure",
			trigger: fmt.Sprintf(`CREATE TRIGGER reject_job_purge_delete BEFORE DELETE ON jobs WHEN OLD.id=%q
BEGIN SELECT RAISE(ABORT,'injected job delete failure'); END`, job.ID),
			message: "injected job delete failure",
		},
		{
			name: "job delete affects no row",
			trigger: fmt.Sprintf(`CREATE TRIGGER ignore_job_purge_delete BEFORE DELETE ON jobs WHEN OLD.id=%q
BEGIN SELECT RAISE(IGNORE); END`, job.ID),
			want: ErrConflict,
		},
		{
			name: "host key cleanup SQL failure",
			trigger: fmt.Sprintf(`CREATE TRIGGER reject_purge_host_key_delete BEFORE DELETE ON job_history_purge_host_keys WHEN OLD.job_id=%q
BEGIN SELECT RAISE(ABORT,'injected host-key cleanup failure'); END`, job.ID),
			message: "injected host-key cleanup failure",
		},
		{
			name: "completion checkpoint SQL failure",
			trigger: fmt.Sprintf(`CREATE TRIGGER reject_purge_complete BEFORE UPDATE OF phase ON job_history_purges WHEN OLD.job_id=%q AND NEW.phase=%q
BEGIN SELECT RAISE(ABORT,'injected completion checkpoint failure'); END`, job.ID, jobPurgePhaseComplete),
			message: "injected completion checkpoint failure",
		},
		{
			name: "completion checkpoint affects no row",
			trigger: fmt.Sprintf(`CREATE TRIGGER ignore_purge_complete BEFORE UPDATE OF phase ON job_history_purges WHEN OLD.job_id=%q AND NEW.phase=%q
BEGIN SELECT RAISE(IGNORE); END`, job.ID, jobPurgePhaseComplete),
			want: ErrConflict,
		},
	}
	for _, fault := range faults {
		t.Run(fault.name, func(t *testing.T) {
			if _, err := s.DB.ExecContext(ctx, fault.trigger); err != nil {
				t.Fatal(err)
			}
			_, err := s.System().PurgeDeletedJobHistories(ctx)
			if fault.want != nil && !errors.Is(err, fault.want) {
				t.Fatalf("purge error = %v; want %v", err, fault.want)
			}
			if fault.message != "" && (err == nil || !strings.Contains(err.Error(), fault.message)) {
				t.Fatalf("purge error = %v; want %q", err, fault.message)
			}
			if err == nil {
				t.Fatal("purge succeeded while its finalization fault was installed")
			}
			assertJobPurgeStillFinalizing(t, s, tenant, job.ID)
			if got := countRows(t, s.DB, `SELECT COUNT(*) FROM job_history_purge_host_keys WHERE tenant_id=? AND job_id=?`, tenant.scope.ID(), job.ID); got != 1 {
				t.Fatalf("host-key checkpoint rows after rolled-back finalization = %d; want one", got)
			}
			if _, err := s.DB.ExecContext(ctx, `DROP TRIGGER `+map[string]string{
				"job delete SQL failure":               "reject_job_purge_delete",
				"job delete affects no row":            "ignore_job_purge_delete",
				"host key cleanup SQL failure":         "reject_purge_host_key_delete",
				"completion checkpoint SQL failure":    "reject_purge_complete",
				"completion checkpoint affects no row": "ignore_purge_complete",
			}[fault.name]); err != nil {
				t.Fatal(err)
			}
		})
	}
	if purged, err := s.System().PurgeDeletedJobHistories(ctx); err != nil || purged == 0 {
		t.Fatalf("retry purge after removing finalization faults = %d, %v", purged, err)
	}
	if countRows(t, s.DB, `SELECT COUNT(*) FROM jobs WHERE id=?`, job.ID) != 0 || countRows(t, s.DB, `SELECT COUNT(*) FROM job_history_purge_host_keys WHERE tenant_id=? AND job_id=?`, tenant.scope.ID(), job.ID) != 0 {
		t.Fatal("final retry did not remove the job and its host-key checkpoint")
	}
}

func TestJobHistoryPurgeSelectorFailureKeepsJobTombstone(t *testing.T) {
	ctx := context.Background()
	s, tenant, job := createDeletedPurgeTestJob(t, "purge-selector-failure")
	if _, err := s.DB.ExecContext(ctx, `DROP TABLE change_window_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().PurgeDeletedJobHistories(ctx); err == nil || !strings.Contains(err.Error(), "change_window_events") {
		t.Fatalf("purge with a missing tail selector table = %v; want selector error", err)
	}
	assertJobPurgeStillFinalizing(t, s, tenant, job.ID)
}

func TestTenantPurgeOutboxRewindFailureKeepsCheckpointAndRetries(t *testing.T) {
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	requestSecondTenantDeletion(t, f)
	insertPurgeTestDelivery(t, f.store, secondTenantID, f.jobB, "legacy-missing-window", "tenant-b-linked", "pending")
	if _, err := f.store.DB.ExecContext(ctx, `UPDATE tenants SET purge_phase='runtime_incidents' WHERE id=?`, secondTenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.ExecContext(ctx, `CREATE TRIGGER ignore_tenant_outbox_rewind BEFORE UPDATE OF purge_phase ON tenants WHEN OLD.id='`+secondTenantID+`' AND NEW.purge_phase='outbox' BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: 2}); !errors.Is(err, ErrConflict) {
		t.Fatalf("tenant purge with a lost rewind update = %v; want ErrConflict", err)
	}
	if phase := purgePhaseOf(t, f.store, secondTenantID); phase != "runtime_incidents" {
		t.Fatalf("checkpoint after ignored rewind = %q; want runtime_incidents", phase)
	}
	if countRows(t, f.store.DB, `SELECT COUNT(*) FROM outbox WHERE tenant_id=? AND destination='tenant-b-linked'`, secondTenantID) != 1 {
		t.Fatal("ignored rewind removed a delivery before the outbox phase")
	}
	if _, err := f.store.DB.ExecContext(ctx, `DROP TRIGGER ignore_tenant_outbox_rewind`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB.ExecContext(ctx, `CREATE TRIGGER reject_tenant_outbox_rewind BEFORE UPDATE OF purge_phase ON tenants WHEN OLD.id='`+secondTenantID+`' AND NEW.purge_phase='outbox' BEGIN SELECT RAISE(ABORT,'injected tenant rewind failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: 2}); err == nil || !strings.Contains(err.Error(), "injected tenant rewind failure") {
		t.Fatalf("tenant purge with a failed rewind = %v; want injected checkpoint failure", err)
	}
	if phase := purgePhaseOf(t, f.store, secondTenantID); phase != "runtime_incidents" {
		t.Fatalf("checkpoint after failed rewind = %q; want runtime_incidents", phase)
	}
	if countRows(t, f.store.DB, `SELECT COUNT(*) FROM outbox WHERE tenant_id=? AND destination='tenant-b-linked'`, secondTenantID) != 1 {
		t.Fatal("failed rewind removed a delivery before reaching the outbox phase")
	}
	if _, err := f.store.DB.ExecContext(ctx, `DROP TRIGGER reject_tenant_outbox_rewind`); err != nil {
		t.Fatal(err)
	}
	results, err := f.store.System().purgeDeletingTenants(ctx, tenantPurgeOptions{batchSize: 2})
	if err != nil || len(results) != 1 || !results[0].Complete {
		t.Fatalf("tenant purge retry after failed rewind = %+v, %v", results, err)
	}
	if countRows(t, f.store.DB, `SELECT COUNT(*) FROM outbox WHERE tenant_id=?`, secondTenantID) != 0 {
		t.Fatal("tenant retry left an outbox row with a dangling window link")
	}
}

func TestTenantPurgeOutboxRewindRejectsCanceledAndReplacedState(t *testing.T) {
	ctx := context.Background()
	f := newTenantPurgeFixture(t)
	requestSecondTenantDeletion(t, f)
	insertPurgeTestDelivery(t, f.store, secondTenantID, f.jobB, "legacy-missing-window", "tenant-b-stale-checkpoint", "pending")
	if _, err := f.store.DB.ExecContext(ctx, `UPDATE tenants SET purge_phase='runtime_incidents' WHERE id=?`, secondTenantID); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := rewindTenantPurgeForOutbox(canceled, f.store.DB, secondTenantID, "runtime_incidents"); !errors.Is(err, context.Canceled) {
		t.Fatalf("rewind with a canceled context = %v; want context.Canceled", err)
	}
	if phase := purgePhaseOf(t, f.store, secondTenantID); phase != "runtime_incidents" {
		t.Fatalf("checkpoint after canceled rewind = %q; want runtime_incidents", phase)
	}
	if _, err := rewindTenantPurgeForOutbox(ctx, f.store.DB, secondTenantID, "events"); !errors.Is(err, ErrConflict) {
		t.Fatalf("rewind with a replaced checkpoint = %v; want ErrConflict", err)
	}
	if phase := purgePhaseOf(t, f.store, secondTenantID); phase != "runtime_incidents" {
		t.Fatalf("checkpoint after stale rewind = %q; want runtime_incidents", phase)
	}
	if _, err := rewindTenantPurgeForOutbox(ctx, f.store.DB, "missing-tenant", "runtime_incidents"); !errors.Is(err, ErrConflict) {
		t.Fatalf("rewind after tenant deletion = %v; want ErrConflict", err)
	}
	if _, err := f.store.DB.ExecContext(ctx, `DROP TABLE outbox`); err != nil {
		t.Fatal(err)
	}
	if _, err := rewindTenantPurgeForOutbox(ctx, f.store.DB, secondTenantID, "runtime_incidents"); err == nil || !strings.Contains(err.Error(), "outbox") {
		t.Fatalf("rewind with an unavailable outbox selector = %v; want query error", err)
	}
	if phase := purgePhaseOf(t, f.store, secondTenantID); phase != "runtime_incidents" {
		t.Fatalf("checkpoint after selector error = %q; want runtime_incidents", phase)
	}
}
