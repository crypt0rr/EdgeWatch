package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	_ "modernc.org/sqlite"
)

func testJob(name string) config.Job {
	return config.NormalizeJob(config.Job{
		Name: name, Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"},
		TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute),
		Timing: "balanced", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1},
	})
}

func TestCreateJobWithEnabledPersistsPausedStateAtomically(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJobWithEnabled(ctx, testJob("paused"), false)
	if err != nil {
		t.Fatal(err)
	}
	if record.Revision != 1 || record.Enabled {
		t.Fatalf("created job state = %#v, want disabled revision 1", record)
	}
	stored, err := s.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Revision != 1 || stored.Enabled {
		t.Fatalf("stored job state = %#v, want disabled revision 1", stored)
	}
	var revisions int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM job_revisions WHERE job_id=?`, record.ID).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	if revisions != 1 {
		t.Fatalf("revision count = %d, want 1", revisions)
	}
}

func TestManagedJobsHonorConfiguredTargetExclusions(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.SetTargetExclusions(config.DefaultTargetExclusions()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateJob(ctx, testJob("blocked")); err == nil || !strings.Contains(err.Error(), "excluded") {
		t.Fatalf("excluded managed target was accepted: %v", err)
	}
	if err := s.SetTargetExclusions([]string{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateJob(ctx, testJob("allowed")); err != nil {
		t.Fatalf("explicit empty exclusion override rejected managed target: %v", err)
	}
}

func TestAuditedMutationsRollBackWhenAuditInsertFails(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	base, err := s.CreateJob(ctx, testJob("audited-base"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_audited_mutation BEFORE INSERT ON security_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateJobWithEnabledAndAudit(ctx, testJob("audited-new"), true, AuditEntry{Action: "job.created", Detail: "audited-new"}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("expected audited create failure, got %v", err)
	}
	if _, err := s.GetJobByName(ctx, "audited-new"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("job committed despite audit failure: %v", err)
	}

	updated := base.Job
	updated.Name = "audited-renamed"
	if _, _, _, err := s.UpdateJobWithEventsWithOutboxAndAudit(ctx, base.ID, base.Revision, updated, true, false, false, nil, AuditEntry{Action: "job.updated", Detail: base.ID}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("expected audited update failure, got %v", err)
	}
	current, err := s.GetJob(ctx, base.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != base.Revision || current.Job.Name != base.Job.Name {
		t.Fatalf("job changed despite audit failure: %#v", current)
	}

	if _, err := s.UpdateRuntime(ctx, base.ID, func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "baseline"
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetRuntimeWithOutboxAndAudit(ctx, base.ID, base.Job.Name, nil, AuditEntry{Action: "baseline.reset", Detail: base.ID}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("expected audited reset failure, got %v", err)
	}
	state, err := s.RuntimeState(ctx, base.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineScanID != "baseline" {
		t.Fatalf("baseline reset committed despite audit failure: %#v", state)
	}
}

func TestManagedJobRevisionAndScopeConfirmation(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("one"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceBaselineHostProjection(ctx, record.ID, model.Snapshot{Hosts: []model.HostObservation{{Address: "127.0.0.1", Status: "up"}}}); err != nil {
		t.Fatal(err)
	}
	changed := record.Job
	changed.Targets = []string{"127.0.0.2"}
	if _, _, err := s.UpdateJob(ctx, record.ID, record.Revision, changed, true, false, false); !errors.Is(err, ErrRebaselineRequired) {
		t.Fatalf("expected rebaseline confirmation, got %v", err)
	}
	if _, _, err := s.UpdateJob(ctx, record.ID, record.Revision-1, record.Job, true, false, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected revision conflict, got %v", err)
	}
	updated, scopeChanged, err := s.UpdateJob(ctx, record.ID, record.Revision, changed, true, false, true)
	if err != nil || !scopeChanged || updated.Revision != 2 {
		t.Fatalf("update %#v changed=%v err=%v", updated, scopeChanged, err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline != nil || state.BaselineScanID != "" {
		t.Fatalf("scope update did not clear runtime state: %#v", state)
	}
	if exists, err := s.BaselineHostProjectionExists(ctx, record.ID); err != nil || exists {
		t.Fatalf("scope update left the old baseline host projection: exists=%v err=%v", exists, err)
	}
	events, err := s.ListJobEvents(ctx, record.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "baseline-reset" {
		t.Fatalf("scope update did not persist reset event: %#v", events)
	}
	staleScan := model.Scan{
		ID: "stale-approval", JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name,
		StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), Status: "success",
		ConfigHash: record.Job.SecurityHash(), Snapshot: model.Snapshot{},
	}
	if err := s.SaveScan(ctx, staleScan); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveRuntime(ctx, record.ID, updated.Job.Name, staleScan); err == nil {
		t.Fatal("stale scan was approved after the job scope changed")
	}
	if err := s.AcquireJobLeaseForRevision(ctx, record.ID, "stale-scan", 1, time.Now().Add(time.Minute)); !errors.Is(err, ErrJobRevisionChanged) {
		t.Fatalf("stale revision acquired a lease: %v", err)
	}
}

// createJobWithOpenIncident stores a job whose runtime has a baseline and one
// open incident, as seen before a confirmed security-scope change.
func createJobWithOpenIncident(ctx context.Context, t *testing.T, s *Store, name string) JobRecord {
	t.Helper()
	record, err := s.CreateJob(ctx, testJob(name))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	key := "port|127.0.0.1|tcp|1"
	baseline := model.Snapshot{Units: []model.Unit{{Target: "127.0.0.1", Protocol: "tcp"}}}
	if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &baseline
		state.BaselineScanID = "old-scope-baseline"
		state.BaselineConfigHash = record.Job.SecurityHash()
		state.Incidents[key] = model.Incident{Change: model.Change{Key: key, Kind: "port", Target: "127.0.0.1", Protocol: "tcp", Port: 1, Old: "closed", New: "open", Severity: "critical"}, OpenedAt: now, LastSeenAt: now}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if page, err := s.ListJobIncidentsPage(ctx, record.ID, 10, 0); err != nil || page.Total != 1 {
		t.Fatalf("incident fixture page = %#v, %v", page, err)
	}
	return record
}

func TestConfirmedRebaselineClearsIncidentProjection(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record := createJobWithOpenIncident(ctx, t, s, "rebaseline-incidents")
	changed := record.Job
	changed.Targets = []string{"127.0.0.2"}
	if _, scopeChanged, _, err := s.UpdateJobWithEvents(ctx, record.ID, record.Revision, changed, true, false, true); err != nil || !scopeChanged {
		t.Fatalf("confirmed rebaseline changed=%v err=%v", scopeChanged, err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil || len(state.Incidents) != 0 {
		t.Fatalf("runtime incidents after rebaseline = %#v, %v", state.Incidents, err)
	}
	// Every incident view and count reads the projection, so it must be
	// cleared with the runtime reset rather than at the next runtime write.
	jobPage, err := s.ListJobIncidentsPage(ctx, record.ID, 10, 0)
	if err != nil || jobPage.Total != 0 || len(jobPage.Items) != 0 {
		t.Fatalf("job incident page after rebaseline = %#v, %v", jobPage, err)
	}
	globalPage, err := s.ListIncidentsPage(ctx, 10, 0)
	if err != nil || globalPage.Total != 0 || len(globalPage.Items) != 0 {
		t.Fatalf("global incident page after rebaseline = %#v, %v", globalPage, err)
	}
	// The runtime row and its metadata carry the same fixed-width timestamp,
	// so the summaries below read the current projection.
	var runtimeUpdated, metaUpdated string
	if err := s.DB.QueryRowContext(ctx, `SELECT r.updated_at,m.updated_at FROM job_runtime r JOIN job_runtime_meta m ON m.job_id=r.job_id WHERE r.job_id=?`, record.ID).Scan(&runtimeUpdated, &metaUpdated); err != nil {
		t.Fatal(err)
	}
	if canonical, ok := normalizeSQLiteTimestamp(runtimeUpdated); !ok || canonical != runtimeUpdated || runtimeUpdated != metaUpdated {
		t.Fatalf("runtime updated_at = %q, metadata updated_at = %q; want the same fixed-width timestamp", runtimeUpdated, metaUpdated)
	}
	summary, err := s.RuntimeStateSummary(ctx, record.ID)
	if err != nil || summary.IncidentCount != 0 || summary.HasBaseline {
		t.Fatalf("job summary after rebaseline = %#v, %v", summary, err)
	}
	summaries, err := s.RuntimeStateSummaries(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if listed, ok := summaries[record.ID]; !ok || listed.IncidentCount != 0 || listed.HasBaseline {
		t.Fatalf("job list summary after rebaseline = %#v (present=%v)", listed, ok)
	}
}

func TestConfirmedRebaselineRollsBackWhenRuntimeResetFails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trigger string
	}{
		{name: "metadata", trigger: `CREATE TRIGGER fail_rebaseline_reset BEFORE UPDATE ON job_runtime_meta BEGIN SELECT RAISE(ABORT, 'runtime metadata unavailable'); END`},
		{name: "incident projection", trigger: `CREATE TRIGGER fail_rebaseline_reset BEFORE DELETE ON runtime_incidents BEGIN SELECT RAISE(ABORT, 'incident projection unavailable'); END`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := openTestStore(t)
			record := createJobWithOpenIncident(ctx, t, s, "rebaseline-rollback")
			if _, err := s.DB.ExecContext(ctx, tc.trigger); err != nil {
				t.Fatal(err)
			}
			changed := record.Job
			changed.Targets = []string{"127.0.0.2"}
			if _, _, _, err := s.UpdateJobWithEvents(ctx, record.ID, record.Revision, changed, true, false, true); err == nil {
				t.Fatal("confirmed rebaseline committed despite a failed runtime reset")
			}
			current, err := s.GetJob(ctx, record.ID)
			if err != nil || current.Revision != record.Revision {
				t.Fatalf("job after failed rebaseline = %#v, %v", current, err)
			}
			state, err := s.RuntimeState(ctx, record.ID)
			if err != nil || state.Baseline == nil || len(state.Incidents) != 1 {
				t.Fatalf("runtime after failed rebaseline = %#v, %v", state, err)
			}
			if page, err := s.ListJobIncidentsPage(ctx, record.ID, 10, 0); err != nil || page.Total != 1 {
				t.Fatalf("incident projection after failed rebaseline = %#v, %v", page, err)
			}
		})
	}
}

func TestEquivalentPortEditPreservesLegacyBaselineWithoutConfirmation(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("legacy-port-scope"))
	if err != nil {
		t.Fatal(err)
	}
	legacy := record.Job
	legacy.TCP.Ports = "2, 1"
	legacyHash := config.NormalizeStoredJob(legacy).LegacySecurityHash()
	if legacyHash == "" {
		t.Fatal("legacy test definition did not produce a compatibility hash")
	}
	definition, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE jobs SET definition_json=? WHERE id=?`, definition, record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_revisions SET definition_json=?,security_hash=? WHERE job_id=? AND revision=?`, definition, legacyHash, record.ID, record.Revision); err != nil {
		t.Fatal(err)
	}
	baseline := model.Snapshot{Units: []model.Unit{{Target: "127.0.0.1", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}, {Port: 2, State: "open"}}}}}
	if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &baseline
		state.BaselineScanID = "legacy-baseline"
		state.BaselineConfigHash = legacyHash
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	current, err := s.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Job.TCP.Ports != "1-2" || current.Job.LegacySecurityHash() != legacyHash {
		t.Fatalf("stored legacy job = ports %q, compatibility hash %q; want 1-2 and %q", current.Job.TCP.Ports, current.Job.LegacySecurityHash(), legacyHash)
	}
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{
		ID: "legacy-cycle", JobID: current.ID, Job: current.Job.Name, JobRevision: current.Revision,
		ConfigHash: legacyHash, ExecutionHash: current.Job.ExecutionHash(),
		Plan: scanner.WorkPlan{Job: current.Job, Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Addresses: []string{"127.0.0.1"}, Ports: "1-2", PortCount: 2, Probes: 2}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	changed := current.Job
	changed.TCP.Ports = "1,2"
	updated, scopeChanged, err := s.UpdateJob(ctx, record.ID, current.Revision, changed, true, false, false)
	if err != nil || scopeChanged {
		t.Fatalf("equivalent port edit = %#v, scopeChanged=%v, err=%v", updated, scopeChanged, err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline == nil || state.BaselineScanID != "legacy-baseline" || state.BaselineConfigHash != updated.Job.SecurityHash() {
		t.Fatalf("equivalent edit did not preserve and safely rehash the baseline: %#v", state)
	}
	if updated.Job.TCP.Ports != "1-2" {
		t.Fatalf("persisted ports = %q, want canonical 1-2", updated.Job.TCP.Ports)
	}
	cycle, err = s.GetScanCycle(ctx, cycle.ID)
	if err != nil || cycle.ConfigHash != updated.Job.SecurityHash() {
		t.Fatalf("paused scan cycle scope hash = %q, err=%v; want canonical %q", cycle.ConfigHash, err, updated.Job.SecurityHash())
	}
}

// createLegacyNotificationJob stores a job as an older version wrote it: a
// non-canonical port expression, no notification selection, and a baseline
// recorded under the legacy scope hash.
func createLegacyNotificationJob(ctx context.Context, t *testing.T, s *Store, name string) (JobRecord, string) {
	t.Helper()
	record, err := s.CreateJob(ctx, testJob(name))
	if err != nil {
		t.Fatal(err)
	}
	legacy := record.Job
	legacy.TCP.Ports = "2, 1"
	legacy.NotificationDestinations = nil
	legacyHash := config.NormalizeStoredJob(legacy).LegacySecurityHash()
	if legacyHash == "" {
		t.Fatal("legacy test definition did not produce a compatibility hash")
	}
	definition, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE jobs SET definition_json=? WHERE id=?`, definition, record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE job_revisions SET definition_json=?,security_hash=? WHERE job_id=? AND revision=?`, definition, legacyHash, record.ID, record.Revision); err != nil {
		t.Fatal(err)
	}
	baseline := model.Snapshot{Units: []model.Unit{{Target: "127.0.0.1", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}}}}}
	if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &baseline
		state.BaselineScanID = "legacy-baseline"
		state.BaselineConfigHash = legacyHash
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	current, err := s.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Job.NotificationDestinations != nil || current.Job.LegacySecurityHash() != legacyHash {
		t.Fatalf("stored legacy job = destinations %#v, compatibility hash %q; want nil and %q", current.Job.NotificationDestinations, current.Job.LegacySecurityHash(), legacyHash)
	}
	return current, legacyHash
}

func TestLegacyNotificationMaterializationMigratesLegacyScopeHash(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	current, legacyHash := createLegacyNotificationJob(ctx, t, s, "legacy-notification-scope")
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{
		ID: "legacy-notification-cycle", JobID: current.ID, Job: current.Job.Name, JobRevision: current.Revision,
		ConfigHash: legacyHash, ExecutionHash: current.Job.ExecutionHash(),
		Plan: scanner.WorkPlan{Job: current.Job, Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Addresses: []string{"127.0.0.1"}, Ports: "1-2", PortCount: 2, Probes: 2}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scan_cycles SET status='paused' WHERE id=?`, cycle.ID); err != nil {
		t.Fatal(err)
	}

	// Daemon startup freezes the nil selection. The rewritten definition uses
	// the canonical port spelling, so the baseline and paused cycle must move
	// to the canonical scope hash with it.
	count, err := s.MaterializeLegacyNotificationSelections(ctx, []string{})
	if err != nil || count != 1 {
		t.Fatalf("materialized job count = %d, %v", count, err)
	}
	stored, err := s.GetJob(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	canonicalHash := stored.Job.SecurityHash()
	if stored.Job.NotificationDestinations == nil || stored.Job.TCP.Ports != "1-2" || stored.Job.LegacySecurityHash() != "" || canonicalHash == legacyHash {
		t.Fatalf("materialized job = destinations %#v, ports %q, compatibility hash %q", stored.Job.NotificationDestinations, stored.Job.TCP.Ports, stored.Job.LegacySecurityHash())
	}
	state, err := s.RuntimeState(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline == nil || state.BaselineScanID != "legacy-baseline" || state.BaselineConfigHash != canonicalHash {
		t.Fatalf("materialization did not preserve and rehash the legacy baseline: %#v", state)
	}
	summary, err := s.RuntimeStateSummary(ctx, current.ID)
	if err != nil || summary.BaselineConfigHash != canonicalHash {
		t.Fatalf("baseline summary hash = %#v, %v; want %q", summary, err, canonicalHash)
	}
	cycle, err = s.GetScanCycle(ctx, cycle.ID)
	if err != nil || cycle.Status != "paused" || cycle.ConfigHash != canonicalHash {
		t.Fatalf("paused scan cycle = status %q, scope hash %q, err=%v; want paused with canonical %q", cycle.Status, cycle.ConfigHash, err, canonicalHash)
	}
}

func TestLegacyNotificationMaterializationRollsBackWhenHashMigrationFails(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	current, legacyHash := createLegacyNotificationJob(ctx, t, s, "legacy-notification-rollback")
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_scope_hash_migration BEFORE UPDATE ON job_runtime BEGIN SELECT RAISE(ABORT, 'runtime unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MaterializeLegacyNotificationSelections(ctx, []string{}); err == nil {
		t.Fatal("materialization committed despite a failed scope hash migration")
	}
	stored, err := s.GetJob(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Revision != current.Revision || stored.Job.NotificationDestinations != nil || stored.Job.LegacySecurityHash() != legacyHash {
		t.Fatalf("job after failed materialization = revision %d, destinations %#v, compatibility hash %q", stored.Revision, stored.Job.NotificationDestinations, stored.Job.LegacySecurityHash())
	}
	state, err := s.RuntimeState(ctx, current.ID)
	if err != nil || state.BaselineConfigHash != legacyHash {
		t.Fatalf("runtime after failed materialization = %#v, %v", state, err)
	}
}

func TestManagedScopeEditIsBlockedWhileScanning(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("busy"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AcquireJobLease(ctx, record.ID, "scan-1", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	defer s.ReleaseJobLease(ctx, record.ID, "scan-1")
	changed := record.Job
	changed.Targets = []string{"127.0.0.2"}
	if _, _, err := s.UpdateJob(ctx, record.ID, record.Revision, changed, true, false, true); !errors.Is(err, ErrJobScanActive) {
		t.Fatalf("expected active scan guard, got %v", err)
	}
	if err := s.SetJobArchivedWithRevision(ctx, record.ID, true, record.Revision); !errors.Is(err, ErrJobScanActive) {
		t.Fatalf("expected active archive guard, got %v", err)
	}
	if err := s.SetJobEnabledWithRevision(ctx, record.ID, false, record.Revision); !errors.Is(err, ErrJobScanActive) {
		t.Fatalf("expected active pause guard, got %v", err)
	}
}

func TestJobLifecycleChangesInvalidateStaleEditors(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("lifecycle"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetJobEnabled(ctx, record.ID, false); err != nil {
		t.Fatal(err)
	}
	if current, err := s.GetJob(ctx, record.ID); err != nil {
		t.Fatal(err)
	} else if current.Revision != record.Revision+1 || current.Enabled {
		t.Fatalf("pause did not create a new revision: %#v", current)
	}
	if _, _, err := s.UpdateJob(ctx, record.ID, record.Revision, record.Job, true, false, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale edit after pause was accepted: %v", err)
	}

	if err := s.SetJobArchived(ctx, record.ID, true); err != nil {
		t.Fatal(err)
	}
	archived, err := s.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if archived.Revision != record.Revision+2 || !archived.Archived || archived.Enabled {
		t.Fatalf("archive did not create a new revision: %#v", archived)
	}
	if _, _, err := s.UpdateJob(ctx, record.ID, record.Revision+1, record.Job, false, false, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale edit after archive was accepted: %v", err)
	}
	if err := s.SetJobArchived(ctx, record.ID, false); err != nil {
		t.Fatal(err)
	}
	restored, err := s.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Revision != record.Revision+3 || restored.Archived || restored.Enabled {
		t.Fatalf("restore changed unexpected lifecycle state: %#v", restored)
	}
}

func TestLifecycleActionsRequireCurrentRevision(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("lifecycle-actions"))
	if err != nil {
		t.Fatal(err)
	}
	changed := record.Job
	changed.Timeout = config.Duration(2 * time.Minute)
	updated, _, err := s.UpdateJob(ctx, record.ID, record.Revision, changed, true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetJobArchivedWithRevision(ctx, record.ID, true, record.Revision); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale archive was accepted: %v", err)
	}
	if err := s.SetJobArchivedWithRevision(ctx, record.ID, true, updated.Revision); err != nil {
		t.Fatalf("current archive failed: %v", err)
	}
	if err := s.SetJobArchivedWithRevision(ctx, record.ID, false, updated.Revision); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale restore was accepted: %v", err)
	}
	archived, err := s.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetJobArchivedWithRevision(ctx, record.ID, false, archived.Revision); err != nil {
		t.Fatalf("current restore failed: %v", err)
	}
	restored, err := s.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetJobEnabledWithRevision(ctx, record.ID, true, restored.Revision); err != nil {
		t.Fatalf("current resume failed: %v", err)
	}
	if err := s.SetJobEnabledWithRevision(ctx, record.ID, false, restored.Revision); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale pause was accepted: %v", err)
	}
}

func TestManagedRuntimeIsolatedFromLegacyState(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("legacy-name"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateState(ctx, "legacy-name", func(state *model.JobState) ([]model.Event, error) { state.BaselineScanID = "old"; return nil, nil }); err != nil {
		t.Fatal(err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineScanID != "" {
		t.Fatalf("managed runtime inherited legacy state: %#v", state)
	}
}

func TestManagedRuntimeRejectsSupersededSecurityScope(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("superseded"))
	if err != nil {
		t.Fatal(err)
	}
	oldHash := record.Job.SecurityHash()
	changed := record.Job
	changed.Targets = []string{"127.0.0.2"}
	if _, _, err := s.UpdateJob(ctx, record.ID, record.Revision, changed, true, false, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateRuntimeForScan(ctx, record.ID, oldHash, func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "stale"
		return nil, nil
	}); !errors.Is(err, ErrJobRevisionChanged) {
		t.Fatalf("superseded scan changed runtime state: %v", err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineScanID != "" {
		t.Fatalf("stale scan mutated current runtime: %#v", state)
	}
}

func TestManagedRuntimeAcceptsLifecycleRevisionWithSameScope(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("lifecycle-runtime"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetJobEnabled(ctx, record.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateRuntimeForScan(ctx, record.ID, record.Job.SecurityHash(), func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "lifecycle-scan"
		return nil, nil
	}); err != nil {
		t.Fatalf("lifecycle-only revision rejected a compatible scan: %v", err)
	}
	state, err := s.RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineScanID != "lifecycle-scan" {
		t.Fatalf("compatible scan did not update runtime: %#v", state)
	}
}

func TestManagedEventsAreIsolatedFromLegacyName(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("same-name"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := s.UpdateState(ctx, record.Job.Name, func(state *model.JobState) ([]model.Event, error) {
		return []model.Event{{Type: "legacy", Job: record.Job.Name, CreatedAt: now}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		return []model.Event{{Type: "managed", Job: record.Job.Name, CreatedAt: now.Add(time.Second)}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	events, err := s.ListJobEvents(ctx, record.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "managed" || events[0].JobID != record.ID {
		t.Fatalf("unexpected managed events %#v", events)
	}
}

func TestExistingSchemaMigratesWithWebTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	// Open creates the v1-compatible tables and upgrades them in one call. The
	// assertion below also protects future migrations from silently skipping the
	// nullable scan identity columns required for legacy rows.
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var version int
	if err := s.DB.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("schema version %d", version)
	}
	for _, table := range []string{"jobs", "job_revisions", "job_runtime", "admins", "users", "user_invites", "sessions", "recovery_codes", "security_audit", "setup_tokens", "managed_notifications", "deployment_notification_ids", "rdap_cache", "scan_hosts", "latest_scan_hosts", "legacy_scan_host_backfill", "scan_host_search", "latest_host_search", "notification_delivery_health", "scan_cycles", "scan_cycle_units", "scan_cycle_discovery_checkpoints", "public_dashboard", "public_dashboard_hosts", "application_update_state", "sse_event_cursor", "startup_state", "totp_replay", "scan_cycle_identity_backfill", "timestamp_normalization_state"} {
		var name string
		if err := s.DB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name); err != nil {
			t.Fatalf("missing %s: %v", table, err)
		}
	}
	var columns int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('admins') WHERE name='display_name'`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if columns != 1 {
		t.Fatalf("administrator display_name column count = %d", columns)
	}
	var defaultValue string
	if err := s.DB.QueryRow(`SELECT dflt_value FROM pragma_table_info('admins') WHERE name='display_name'`).Scan(&defaultValue); err != nil {
		t.Fatal(err)
	}
	if defaultValue != "'admin'" {
		t.Fatalf("administrator display_name default = %q", defaultValue)
	}
	now := time.Now().UTC()
	if err := s.SaveAdmin(context.Background(), Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	admin, err := s.GetAdmin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if admin.DisplayName != "admin" {
		t.Fatalf("default administrator display name = %q", admin.DisplayName)
	}
	admin.DisplayName = "Ada Lovelace"
	if err := s.SaveAdmin(context.Background(), admin); err != nil {
		t.Fatal(err)
	}
	admin, err = s.GetAdmin(context.Background())
	if err != nil || admin.DisplayName != "Ada Lovelace" {
		t.Fatalf("saved administrator display name = %q, err=%v", admin.DisplayName, err)
	}
}

func TestV1DatabaseAddsManagedColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(legacySchema + "\nPRAGMA user_version = 1;"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('scans') WHERE name IN ('job_id','job_revision')`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected managed scan columns, got %d", count)
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('events') WHERE name='job_id'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected managed event column, got %d", count)
	}
}

func TestV9DatabaseAddsSetupTokenIssueTimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v9.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE setup_tokens (id INTEGER PRIMARY KEY CHECK(id=1), token_hash TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT); PRAGMA user_version = 8;`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('setup_tokens') WHERE name='issued_at'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("issued_at column count = %d", count)
	}
}

func TestV10DatabaseAddsAdministratorDisplayName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v10.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE admins (
 id INTEGER PRIMARY KEY CHECK(id=1),
 username TEXT NOT NULL DEFAULT 'admin',
 password_hash TEXT NOT NULL,
 totp_secret TEXT NOT NULL DEFAULT '',
 totp_enabled INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
); PRAGMA user_version = 10;`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('admins') WHERE name='display_name'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("display_name column count = %d", count)
	}
	var defaultValue string
	if err := s.DB.QueryRow(`SELECT dflt_value FROM pragma_table_info('admins') WHERE name='display_name'`).Scan(&defaultValue); err != nil {
		t.Fatal(err)
	}
	if defaultValue != "'admin'" {
		t.Fatalf("display_name default = %q", defaultValue)
	}
}

func TestV11DatabaseMigratesAdministratorIdentityAndLegacySessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v11.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = db.Exec(`
CREATE TABLE admins (
 id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL DEFAULT 'admin',
 password_hash TEXT NOT NULL, totp_secret TEXT NOT NULL DEFAULT '',
 totp_enabled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT 'admin'
);
INSERT INTO admins(id,username,password_hash,totp_secret,totp_enabled,created_at,updated_at,display_name) VALUES(1,'legacy-admin','hash','',0,?,?, 'Legacy Admin');
CREATE TABLE sessions (id_hash TEXT PRIMARY KEY, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, expires_at TEXT NOT NULL, csrf_token TEXT NOT NULL);
INSERT INTO sessions(id_hash,created_at,last_seen_at,expires_at,csrf_token) VALUES('session-hash',?,?,?,'csrf');
CREATE TABLE recovery_codes (id_hash TEXT PRIMARY KEY, used_at TEXT);
INSERT INTO recovery_codes(id_hash,used_at) VALUES('recovery-hash',NULL);
CREATE TABLE security_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
PRAGMA user_version = 11;`, now, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	user, err := s.GetUserByUsername(context.Background(), "legacy-admin")
	if err != nil || user.ID != LegacyAdminUserID || user.DisplayName != "Legacy Admin" || user.Role != RoleAdministrator {
		t.Fatalf("migrated administrator = %#v, err=%v", user, err)
	}
	var userID string
	if err := s.DB.QueryRow(`SELECT user_id FROM sessions WHERE id_hash='session-hash'`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if userID != LegacyAdminUserID {
		t.Fatalf("migrated session user_id = %q", userID)
	}
	var recoveryCount int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM recovery_codes WHERE id_hash='recovery-hash'`).Scan(&recoveryCount); err != nil {
		t.Fatal(err)
	}
	if recoveryCount != 0 {
		t.Fatalf("unsalted recovery code survived schema migration: %d", recoveryCount)
	}
	var updated string
	if err := s.DB.QueryRow(`SELECT updated_at FROM public_dashboard WHERE id=1`).Scan(&updated); err != nil {
		t.Fatal(err)
	}
	if scanTime(updated).IsZero() {
		t.Fatalf("public dashboard timestamp was not parsed: %q", updated)
	}
}
