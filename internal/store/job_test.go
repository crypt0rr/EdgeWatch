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
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJobWithEnabled(ctx, testJob("paused"), false)
	if err != nil {
		t.Fatal(err)
	}
	if record.Revision != 1 || record.Enabled {
		t.Fatalf("created job state = %#v, want disabled revision 1", record)
	}
	stored, err := defaultTenant(s).GetJob(ctx, record.ID)
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

func TestUpdateJobRefreshesLatestHostProjectionName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	insertSecondTenant(t, s)
	secondTenant := s.Tenant(TenantScope{id: secondTenantID})

	active, err := defaultTenant(s).CreateJob(ctx, testJob("alpha-old"))
	if err != nil {
		t.Fatal(err)
	}
	otherTenant, err := secondTenant.CreateJob(ctx, testJob("alpha-old"))
	if err != nil {
		t.Fatal(err)
	}
	paused, err := defaultTenant(s).CreateJobWithEnabled(ctx, testJob("paused-old"), false)
	if err != nil {
		t.Fatal(err)
	}

	saveHostScan := func(id string, job JobRecord, address string, finished time.Time) {
		t.Helper()
		scan := model.Scan{
			ID: id, JobID: job.ID, Job: job.Job.Name, StartedAt: finished.Add(-time.Minute), FinishedAt: finished, Status: "success",
			Snapshot: model.Snapshot{Hosts: []model.HostObservation{{Address: address, AddressFamily: "IPv4"}}},
		}
		if err := s.System().SaveScan(ctx, scan); err != nil {
			t.Fatalf("save scan %s: %v", id, err)
		}
	}
	saveHostScan("scan-alpha-default", active, "198.51.100.9", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	saveHostScan("scan-alpha-other-tenant", otherTenant, "198.51.100.9", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	saveHostScan("scan-paused-default", paused, "198.51.100.10", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))

	active.Job.Name = "alpha-new"
	if _, _, err := defaultTenant(s).UpdateJob(ctx, active.ID, active.Revision, active.Job, active.Enabled, active.Archived, false); err != nil {
		t.Fatalf("rename enabled job: %v", err)
	}
	paused.Job.Name = "paused-new"
	if _, _, err := defaultTenant(s).UpdateJob(ctx, paused.ID, paused.Revision, paused.Job, paused.Enabled, paused.Archived, false); err != nil {
		t.Fatalf("rename paused job: %v", err)
	}

	for _, tc := range []struct {
		query, job, address string
		wantTotal           int
	}{
		{query: "alpha-new", job: "alpha-new", address: "198.51.100.9", wantTotal: 1},
		{query: "paused-new", job: "paused-new", address: "198.51.100.10", wantTotal: 1},
		{query: "alpha-old", wantTotal: 0},
		{query: "paused-old", wantTotal: 0},
	} {
		page, err := defaultTenant(s).ListLatestScanHostsPage(ctx, tc.query, "", nil, 50, 0)
		if err != nil {
			t.Fatalf("search default tenant for %q: %v", tc.query, err)
		}
		if page.Total != tc.wantTotal || len(page.Items) != tc.wantTotal {
			t.Fatalf("default search %q returned total %d, %d items; want %d", tc.query, page.Total, len(page.Items), tc.wantTotal)
		}
		if tc.wantTotal > 0 && (page.Items[0].Job != tc.job || page.Items[0].Host.Address != tc.address) {
			t.Errorf("default search %q returned job/address %q/%q; want %q/%q", tc.query, page.Items[0].Job, page.Items[0].Host.Address, tc.job, tc.address)
		}
	}
	otherPage, err := secondTenant.ListLatestScanHostsPage(ctx, "alpha-old", "", nil, 50, 0)
	if err != nil || otherPage.Total != 1 || len(otherPage.Items) != 1 || otherPage.Items[0].Job != "alpha-old" || otherPage.Items[0].Host.Address != "198.51.100.9" {
		t.Fatalf("other tenant's unchanged host projection = %#v, %v", otherPage, err)
	}
}

func TestManagedJobsHonorConfiguredTargetExclusions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.SetTargetExclusions(config.DefaultTargetExclusions()); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).CreateJob(ctx, testJob("blocked")); err == nil || !strings.Contains(err.Error(), "excluded") {
		t.Fatalf("excluded managed target was accepted: %v", err)
	}
	if err := s.SetTargetExclusions([]string{}); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).CreateJob(ctx, testJob("allowed")); err != nil {
		t.Fatalf("explicit empty exclusion override rejected managed target: %v", err)
	}
}

func TestJobAndProfileWritesClassifyOnlyInputErrorsAsValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	invalid := testJob("invalid-schedule")
	invalid.Schedule = "not a schedule"
	_, err := defaultTenant(s).CreateJob(ctx, invalid)
	var validation *ValidationError
	if !errors.Is(err, ErrValidation) || !errors.As(err, &validation) || !strings.Contains(err.Error(), "invalid schedule") {
		t.Fatalf("invalid job error = %v, want a ValidationError that keeps the validator message", err)
	}
	if inner := errors.Unwrap(err); inner == nil || inner.Error() != err.Error() {
		t.Fatalf("ValidationError does not unwrap to the validator error: %v", inner)
	}
	for name, profileName := range map[string]string{"empty name": "", "line break": "bad\nname"} {
		if _, err := defaultTenant(s).CreateScannerProfile(ctx, profileName, "", config.BuiltinNmapProfile(), "admin"); !errors.Is(err, ErrValidation) {
			t.Fatalf("%s profile error = %v, want ErrValidation", name, err)
		}
	}
	if _, err := defaultTenant(s).UpdateScannerProfile(ctx, BuiltinNmapProfileID, 1, "Built-in", "", config.BuiltinNmapProfile(), "admin"); !errors.Is(err, ErrValidation) {
		t.Fatalf("built-in profile update error = %v, want ErrValidation", err)
	}
	if err := defaultTenant(s).SetScannerProfileArchived(ctx, BuiltinNmapProfileID, true, 1, "admin"); !errors.Is(err, ErrValidation) {
		t.Fatalf("built-in profile archive error = %v, want ErrValidation", err)
	}
	if NewValidationError(nil) != nil {
		t.Fatal("NewValidationError(nil) must stay nil")
	}

	// A storage failure is not a validation error, even though the job itself
	// is valid and the failure text comes from SQLite.
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_job_insert BEFORE INSERT ON jobs BEGIN SELECT RAISE(ABORT, 'database is locked'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).CreateJob(ctx, testJob("storage-failure")); err == nil || errors.Is(err, ErrValidation) {
		t.Fatalf("storage failure error = %v, want a non-validation error", err)
	}
}

func TestAuditedMutationsRollBackWhenAuditInsertFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	base, err := defaultTenant(s).CreateJob(ctx, testJob("audited-base"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_audited_mutation BEFORE INSERT ON security_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).CreateJobWithEnabledAndAudit(ctx, testJob("audited-new"), true, AuditEntry{Action: "job.created", Detail: "audited-new"}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("expected audited create failure, got %v", err)
	}
	if _, err := defaultTenant(s).GetJobByName(ctx, "audited-new"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("job committed despite audit failure: %v", err)
	}

	updated := base.Job
	updated.Name = "audited-renamed"
	if _, _, _, err := defaultTenant(s).UpdateJobWithEventsWithOutboxAndAudit(ctx, base.ID, base.Revision, updated, true, false, false, nil, AuditEntry{Action: "job.updated", Detail: base.ID}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("expected audited update failure, got %v", err)
	}
	current, err := defaultTenant(s).GetJob(ctx, base.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != base.Revision || current.Job.Name != base.Job.Name {
		t.Fatalf("job changed despite audit failure: %#v", current)
	}

	if _, err := s.System().UpdateRuntime(ctx, base.ID, func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "baseline"
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).ResetRuntimeWithOutboxAndAudit(ctx, base.ID, base.Job.Name, nil, AuditEntry{Action: "baseline.reset", Detail: base.ID}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("expected audited reset failure, got %v", err)
	}
	state, err := defaultTenant(s).RuntimeState(ctx, base.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineScanID != "baseline" {
		t.Fatalf("baseline reset committed despite audit failure: %#v", state)
	}
}

func TestManagedJobRevisionAndScopeConfirmation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("one"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.System().ReplaceBaselineHostProjection(ctx, record.ID, model.Snapshot{Hosts: []model.HostObservation{{Address: "127.0.0.1", Status: "up"}}}); err != nil {
		t.Fatal(err)
	}
	changed := record.Job
	changed.Targets = []string{"127.0.0.2"}
	if _, _, err := defaultTenant(s).UpdateJob(ctx, record.ID, record.Revision, changed, true, false, false); !errors.Is(err, ErrRebaselineRequired) {
		t.Fatalf("expected rebaseline confirmation, got %v", err)
	}
	if _, _, err := defaultTenant(s).UpdateJob(ctx, record.ID, record.Revision-1, record.Job, true, false, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected revision conflict, got %v", err)
	}
	updated, scopeChanged, err := defaultTenant(s).UpdateJob(ctx, record.ID, record.Revision, changed, true, false, true)
	if err != nil || !scopeChanged || updated.Revision != 2 {
		t.Fatalf("update %#v changed=%v err=%v", updated, scopeChanged, err)
	}
	state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline != nil || state.BaselineScanID != "" {
		t.Fatalf("scope update did not clear runtime state: %#v", state)
	}
	if exists, err := defaultTenant(s).BaselineHostProjectionExists(ctx, record.ID); err != nil || exists {
		t.Fatalf("scope update left the old baseline host projection: exists=%v err=%v", exists, err)
	}
	events, err := defaultTenant(s).ListJobEvents(ctx, record.ID, 10)
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
	if err := s.System().SaveScan(ctx, staleScan); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).ApproveRuntime(ctx, record.ID, updated.Job.Name, staleScan); err == nil {
		t.Fatal("stale scan was approved after the job scope changed")
	}
	if err := s.System().AcquireJobLeaseForRevision(ctx, record.ID, "stale-scan", 1, time.Now().Add(time.Minute)); !errors.Is(err, ErrJobRevisionChanged) {
		t.Fatalf("stale revision acquired a lease: %v", err)
	}
}

// createJobWithOpenIncident stores a job whose runtime has a baseline and one
// open incident, as seen before a confirmed security-scope change.
func createJobWithOpenIncident(ctx context.Context, t *testing.T, s *Store, name string) JobRecord {
	t.Helper()
	record, err := defaultTenant(s).CreateJob(ctx, testJob(name))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	key := "port|127.0.0.1|tcp|1"
	baseline := model.Snapshot{Units: []model.Unit{{Target: "127.0.0.1", Protocol: "tcp"}}}
	if _, err := s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &baseline
		state.BaselineScanID = "old-scope-baseline"
		state.BaselineConfigHash = record.Job.SecurityHash()
		state.Incidents[key] = model.Incident{Change: model.Change{Key: key, Kind: "port", Target: "127.0.0.1", Protocol: "tcp", Port: 1, Old: "closed", New: "open", Severity: "critical"}, OpenedAt: now, LastSeenAt: now}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if page, err := defaultTenant(s).ListJobIncidentsPage(ctx, record.ID, 10, 0); err != nil || page.Total != 1 {
		t.Fatalf("incident fixture page = %#v, %v", page, err)
	}
	return record
}

func TestConfirmedRebaselineClearsIncidentProjection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record := createJobWithOpenIncident(ctx, t, s, "rebaseline-incidents")
	changed := record.Job
	changed.Targets = []string{"127.0.0.2"}
	if _, scopeChanged, _, err := defaultTenant(s).UpdateJobWithEvents(ctx, record.ID, record.Revision, changed, true, false, true); err != nil || !scopeChanged {
		t.Fatalf("confirmed rebaseline changed=%v err=%v", scopeChanged, err)
	}
	state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
	if err != nil || len(state.Incidents) != 0 {
		t.Fatalf("runtime incidents after rebaseline = %#v, %v", state.Incidents, err)
	}
	// Every incident view and count reads the projection, so it must be
	// cleared with the runtime reset rather than at the next runtime write.
	jobPage, err := defaultTenant(s).ListJobIncidentsPage(ctx, record.ID, 10, 0)
	if err != nil || jobPage.Total != 0 || len(jobPage.Items) != 0 {
		t.Fatalf("job incident page after rebaseline = %#v, %v", jobPage, err)
	}
	globalPage, err := defaultTenant(s).ListIncidentsPage(ctx, 10, 0)
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
	summary, err := defaultTenant(s).RuntimeStateSummary(ctx, record.ID)
	if err != nil || summary.IncidentCount != 0 || summary.HasBaseline {
		t.Fatalf("job summary after rebaseline = %#v, %v", summary, err)
	}
	summaries, err := defaultTenant(s).RuntimeStateSummaries(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if listed, ok := summaries[record.ID]; !ok || listed.IncidentCount != 0 || listed.HasBaseline {
		t.Fatalf("job list summary after rebaseline = %#v (present=%v)", listed, ok)
	}
}

func TestConfirmedRebaselineRollsBackWhenRuntimeResetFails(t *testing.T) {
	t.Parallel()
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
			if _, _, _, err := defaultTenant(s).UpdateJobWithEvents(ctx, record.ID, record.Revision, changed, true, false, true); err == nil {
				t.Fatal("confirmed rebaseline committed despite a failed runtime reset")
			}
			current, err := defaultTenant(s).GetJob(ctx, record.ID)
			if err != nil || current.Revision != record.Revision {
				t.Fatalf("job after failed rebaseline = %#v, %v", current, err)
			}
			state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
			if err != nil || state.Baseline == nil || len(state.Incidents) != 1 {
				t.Fatalf("runtime after failed rebaseline = %#v, %v", state, err)
			}
			if page, err := defaultTenant(s).ListJobIncidentsPage(ctx, record.ID, 10, 0); err != nil || page.Total != 1 {
				t.Fatalf("incident projection after failed rebaseline = %#v, %v", page, err)
			}
		})
	}
}

func TestEquivalentPortEditPreservesLegacyBaselineWithoutConfirmation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("legacy-port-scope"))
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
	if _, err := s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &baseline
		state.BaselineScanID = "legacy-baseline"
		state.BaselineConfigHash = legacyHash
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	current, err := defaultTenant(s).GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Job.TCP.Ports != "1-2" || current.Job.LegacySecurityHash() != legacyHash {
		t.Fatalf("stored legacy job = ports %q, compatibility hash %q; want 1-2 and %q", current.Job.TCP.Ports, current.Job.LegacySecurityHash(), legacyHash)
	}
	cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{
		ID: "legacy-cycle", JobID: current.ID, Job: current.Job.Name, JobRevision: current.Revision,
		ConfigHash: legacyHash, ExecutionHash: current.Job.ExecutionHash(),
		Plan: scanner.WorkPlan{Job: current.Job, Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Addresses: []string{"127.0.0.1"}, Ports: "1-2", PortCount: 2, Probes: 2}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	changed := current.Job
	changed.TCP.Ports = "1,2"
	updated, scopeChanged, err := defaultTenant(s).UpdateJob(ctx, record.ID, current.Revision, changed, true, false, false)
	if err != nil || scopeChanged {
		t.Fatalf("equivalent port edit = %#v, scopeChanged=%v, err=%v", updated, scopeChanged, err)
	}
	state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline == nil || state.BaselineScanID != "legacy-baseline" || state.BaselineConfigHash != updated.Job.SecurityHash() {
		t.Fatalf("equivalent edit did not preserve and safely rehash the baseline: %#v", state)
	}
	if updated.Job.TCP.Ports != "1-2" {
		t.Fatalf("persisted ports = %q, want canonical 1-2", updated.Job.TCP.Ports)
	}
	cycle, err = defaultTenant(s).GetScanCycle(ctx, cycle.ID)
	if err != nil || cycle.ConfigHash != updated.Job.SecurityHash() {
		t.Fatalf("paused scan cycle scope hash = %q, err=%v; want canonical %q", cycle.ConfigHash, err, updated.Job.SecurityHash())
	}
}

// createLegacyNotificationJob stores a job as an older version wrote it: a
// non-canonical port expression, no notification selection, and a baseline
// recorded under the legacy scope hash.
func createLegacyNotificationJob(ctx context.Context, t *testing.T, s *Store, name string) (JobRecord, string) {
	t.Helper()
	record, err := defaultTenant(s).CreateJob(ctx, testJob(name))
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
	if _, err := s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &baseline
		state.BaselineScanID = "legacy-baseline"
		state.BaselineConfigHash = legacyHash
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	current, err := defaultTenant(s).GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Job.NotificationDestinations != nil || current.Job.LegacySecurityHash() != legacyHash {
		t.Fatalf("stored legacy job = destinations %#v, compatibility hash %q; want nil and %q", current.Job.NotificationDestinations, current.Job.LegacySecurityHash(), legacyHash)
	}
	return current, legacyHash
}

func TestLegacyNotificationMaterializationMigratesLegacyScopeHash(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	current, legacyHash := createLegacyNotificationJob(ctx, t, s, "legacy-notification-scope")
	cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{
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
	count, err := defaultTenant(s).MaterializeLegacyNotificationSelections(ctx, []string{})
	if err != nil || count != 1 {
		t.Fatalf("materialized job count = %d, %v", count, err)
	}
	stored, err := defaultTenant(s).GetJob(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	canonicalHash := stored.Job.SecurityHash()
	if stored.Job.NotificationDestinations == nil || stored.Job.TCP.Ports != "1-2" || stored.Job.LegacySecurityHash() != "" || canonicalHash == legacyHash {
		t.Fatalf("materialized job = destinations %#v, ports %q, compatibility hash %q", stored.Job.NotificationDestinations, stored.Job.TCP.Ports, stored.Job.LegacySecurityHash())
	}
	state, err := defaultTenant(s).RuntimeState(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Baseline == nil || state.BaselineScanID != "legacy-baseline" || state.BaselineConfigHash != canonicalHash {
		t.Fatalf("materialization did not preserve and rehash the legacy baseline: %#v", state)
	}
	summary, err := defaultTenant(s).RuntimeStateSummary(ctx, current.ID)
	if err != nil || summary.BaselineConfigHash != canonicalHash {
		t.Fatalf("baseline summary hash = %#v, %v; want %q", summary, err, canonicalHash)
	}
	cycle, err = defaultTenant(s).GetScanCycle(ctx, cycle.ID)
	if err != nil || cycle.Status != "paused" || cycle.ConfigHash != canonicalHash {
		t.Fatalf("paused scan cycle = status %q, scope hash %q, err=%v; want paused with canonical %q", cycle.Status, cycle.ConfigHash, err, canonicalHash)
	}
}

func TestLegacyNotificationMaterializationRollsBackWhenHashMigrationFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	current, legacyHash := createLegacyNotificationJob(ctx, t, s, "legacy-notification-rollback")
	if _, err := s.DB.ExecContext(ctx, `CREATE TRIGGER fail_scope_hash_migration BEFORE UPDATE ON job_runtime BEGIN SELECT RAISE(ABORT, 'runtime unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTenant(s).MaterializeLegacyNotificationSelections(ctx, []string{}); err == nil {
		t.Fatal("materialization committed despite a failed scope hash migration")
	}
	stored, err := defaultTenant(s).GetJob(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Revision != current.Revision || stored.Job.NotificationDestinations != nil || stored.Job.LegacySecurityHash() != legacyHash {
		t.Fatalf("job after failed materialization = revision %d, destinations %#v, compatibility hash %q", stored.Revision, stored.Job.NotificationDestinations, stored.Job.LegacySecurityHash())
	}
	state, err := defaultTenant(s).RuntimeState(ctx, current.ID)
	if err != nil || state.BaselineConfigHash != legacyHash {
		t.Fatalf("runtime after failed materialization = %#v, %v", state, err)
	}
}

func TestManagedScopeEditIsBlockedWhileScanning(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("busy"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.System().AcquireJobLease(ctx, record.ID, "scan-1", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.System().ReleaseJobLease(ctx, record.ID, "scan-1") }()
	changed := record.Job
	changed.Targets = []string{"127.0.0.2"}
	if _, _, err := defaultTenant(s).UpdateJob(ctx, record.ID, record.Revision, changed, true, false, true); !errors.Is(err, ErrJobScanActive) {
		t.Fatalf("expected active scan guard, got %v", err)
	}
	if err := defaultTenant(s).SetJobArchivedWithRevision(ctx, record.ID, true, record.Revision); !errors.Is(err, ErrJobScanActive) {
		t.Fatalf("expected active archive guard, got %v", err)
	}
	if err := defaultTenant(s).SetJobEnabledWithRevision(ctx, record.ID, false, record.Revision); !errors.Is(err, ErrJobScanActive) {
		t.Fatalf("expected active pause guard, got %v", err)
	}
}

func TestJobLifecycleChangesInvalidateStaleEditors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("lifecycle"))
	if err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).SetJobEnabled(ctx, record.ID, false); err != nil {
		t.Fatal(err)
	}
	if current, err := defaultTenant(s).GetJob(ctx, record.ID); err != nil {
		t.Fatal(err)
	} else if current.Revision != record.Revision+1 || current.Enabled {
		t.Fatalf("pause did not create a new revision: %#v", current)
	}
	if _, _, err := defaultTenant(s).UpdateJob(ctx, record.ID, record.Revision, record.Job, true, false, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale edit after pause was accepted: %v", err)
	}

	if err := defaultTenant(s).SetJobArchived(ctx, record.ID, true); err != nil {
		t.Fatal(err)
	}
	archived, err := defaultTenant(s).GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if archived.Revision != record.Revision+2 || !archived.Archived || archived.Enabled {
		t.Fatalf("archive did not create a new revision: %#v", archived)
	}
	if _, _, err := defaultTenant(s).UpdateJob(ctx, record.ID, record.Revision+1, record.Job, false, false, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale edit after archive was accepted: %v", err)
	}
	if err := defaultTenant(s).SetJobArchived(ctx, record.ID, false); err != nil {
		t.Fatal(err)
	}
	restored, err := defaultTenant(s).GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Revision != record.Revision+3 || restored.Archived || restored.Enabled {
		t.Fatalf("restore changed unexpected lifecycle state: %#v", restored)
	}
}

func TestLifecycleActionsRequireCurrentRevision(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("lifecycle-actions"))
	if err != nil {
		t.Fatal(err)
	}
	changed := record.Job
	changed.Timeout = config.Duration(2 * time.Minute)
	updated, _, err := defaultTenant(s).UpdateJob(ctx, record.ID, record.Revision, changed, true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).SetJobArchivedWithRevision(ctx, record.ID, true, record.Revision); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale archive was accepted: %v", err)
	}
	if err := defaultTenant(s).SetJobArchivedWithRevision(ctx, record.ID, true, updated.Revision); err != nil {
		t.Fatalf("current archive failed: %v", err)
	}
	if err := defaultTenant(s).SetJobArchivedWithRevision(ctx, record.ID, false, updated.Revision); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale restore was accepted: %v", err)
	}
	archived, err := defaultTenant(s).GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).SetJobArchivedWithRevision(ctx, record.ID, false, archived.Revision); err != nil {
		t.Fatalf("current restore failed: %v", err)
	}
	restored, err := defaultTenant(s).GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).SetJobEnabledWithRevision(ctx, record.ID, true, restored.Revision); err != nil {
		t.Fatalf("current resume failed: %v", err)
	}
	if err := defaultTenant(s).SetJobEnabledWithRevision(ctx, record.ID, false, restored.Revision); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale pause was accepted: %v", err)
	}
}

func TestManagedRuntimeIsolatedFromLegacyState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("legacy-name"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().UpdateState(ctx, "legacy-name", func(state *model.JobState) ([]model.Event, error) { state.BaselineScanID = "old"; return nil, nil }); err != nil {
		t.Fatal(err)
	}
	state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineScanID != "" {
		t.Fatalf("managed runtime inherited legacy state: %#v", state)
	}
}

func TestManagedRuntimeRejectsSupersededSecurityScope(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("superseded"))
	if err != nil {
		t.Fatal(err)
	}
	oldHash := record.Job.SecurityHash()
	changed := record.Job
	changed.Targets = []string{"127.0.0.2"}
	if _, _, err := defaultTenant(s).UpdateJob(ctx, record.ID, record.Revision, changed, true, false, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().UpdateRuntimeForScan(ctx, record.ID, oldHash, func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "stale"
		return nil, nil
	}); !errors.Is(err, ErrJobRevisionChanged) {
		t.Fatalf("superseded scan changed runtime state: %v", err)
	}
	state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineScanID != "" {
		t.Fatalf("stale scan mutated current runtime: %#v", state)
	}
}

func TestManagedRuntimeAcceptsLifecycleRevisionWithSameScope(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("lifecycle-runtime"))
	if err != nil {
		t.Fatal(err)
	}
	if err := defaultTenant(s).SetJobEnabled(ctx, record.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().UpdateRuntimeForScan(ctx, record.ID, record.Job.SecurityHash(), func(state *model.JobState) ([]model.Event, error) {
		state.BaselineScanID = "lifecycle-scan"
		return nil, nil
	}); err != nil {
		t.Fatalf("lifecycle-only revision rejected a compatible scan: %v", err)
	}
	state, err := defaultTenant(s).RuntimeState(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineScanID != "lifecycle-scan" {
		t.Fatalf("compatible scan did not update runtime: %#v", state)
	}
}

func TestManagedEventsAreIsolatedFromLegacyName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("same-name"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := s.System().UpdateState(ctx, record.Job.Name, func(state *model.JobState) ([]model.Event, error) {
		return []model.Event{{Type: "legacy", Job: record.Job.Name, CreatedAt: now}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		return []model.Event{{Type: "managed", Job: record.Job.Name, CreatedAt: now.Add(time.Second)}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	events, err := defaultTenant(s).ListJobEvents(ctx, record.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "managed" || events[0].JobID != record.ID {
		t.Fatalf("unexpected managed events %#v", events)
	}
}

func TestExistingSchemaMigratesWithWebTables(t *testing.T) {
	t.Parallel()
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
	for _, table := range []string{"jobs", "job_revisions", "job_runtime", "admins", "users", "user_invites", "sessions", "recovery_codes", "security_audit", "setup_tokens", "managed_notifications", "deployment_notification_ids", "rdap_cache", "scan_hosts", "latest_scan_hosts", "legacy_scan_host_backfill", "scan_host_search", "latest_host_search", "notification_delivery_health", "scan_cycles", "scan_cycle_units", "scan_cycle_discovery_checkpoints", "tenants", "public_dashboards", "public_dashboard_hosts", "application_update_state", "sse_event_cursor", "startup_state", "totp_replay", "scan_cycle_identity_backfill", "timestamp_normalization_state"} {
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	if err := s.DB.QueryRow(`SELECT updated_at FROM public_dashboards WHERE id=1`).Scan(&updated); err != nil {
		t.Fatal(err)
	}
	if scanTime(updated).IsZero() {
		t.Fatalf("public dashboard timestamp was not parsed: %q", updated)
	}
}
