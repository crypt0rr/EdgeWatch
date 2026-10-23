package app

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// completingCycleScanner plans a two-unit resumable cycle and completes it
// in one attempt. It counts its plans and unit scans.
type completingCycleScanner struct {
	mu    sync.Mutex
	plans int
	units int
}

func (s *completingCycleScanner) Version(context.Context) string { return "completing-cycle" }
func (s *completingCycleScanner) Scan(context.Context, config.Job) (model.Snapshot, error) {
	return model.Snapshot{}, errors.New("ordinary scan path is not expected")
}
func (s *completingCycleScanner) Plan(ctx context.Context, job config.Job) (scanner.WorkPlan, error) {
	s.mu.Lock()
	s.plans++
	s.mu.Unlock()
	return (&lifecycleScanner{}).Plan(ctx, job)
}
func (s *completingCycleScanner) ScanWorkUnit(_ context.Context, _ config.Job, unit scanner.WorkUnit, _ scanner.ProgressReporter) (model.Snapshot, error) {
	s.mu.Lock()
	s.units++
	s.mu.Unlock()
	port, err := strconv.Atoi(unit.Ports)
	if err != nil {
		return model.Snapshot{}, err
	}
	return model.Snapshot{Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Addresses: unit.Addresses, Ports: []model.PortState{{Port: port, State: "open"}}}}}, nil
}

func (s *completingCycleScanner) counts() (plans, units int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.plans, s.units
}

// A completed resumable cycle is compared only when a scan promotes it. When
// its notification destinations cannot be read, the cycle must stay
// unpromoted, so the next trigger promotes and compares the same cycle
// instead of discarding its result and planning a new one.
func TestRecoveredLegacyResumedCyclePreservesOriginalFinishTime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	probe := &completingCycleScanner{}
	a, db := newLifecycleTestApp(t, probe, nil)
	record, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("cycle-destinations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-2"}}, Units: []model.Unit{{Target: "192.0.2.1", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}}}}}
		state.BaselineScanID = "seed"
		state.BaselineConfigHash = record.Job.SecurityHash()
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	var eventsMu sync.Mutex
	var live []model.Event
	a.SetEventHandler(func(event model.Event) {
		eventsMu.Lock()
		defer eventsMu.Unlock()
		live = append(live, event)
	})

	// The destination read fails once.
	if _, err := db.DB.ExecContext(ctx, `ALTER TABLE managed_notifications RENAME TO managed_notifications_unavailable`); err != nil {
		t.Fatal(err)
	}
	deferred, events, deferErr := a.runJobRecord(ctx, record, false)
	if deferErr == nil || len(events) != 0 || deferred.CycleID == "" || deferred.CycleStatus != "completed" {
		t.Fatalf("run without destinations = %#v, events %#v, err %v", deferred, events, deferErr)
	}
	eventsMu.Lock()
	assertBalancedScanLifecycle(t, live, record.ID)
	if message := eventByType(live, "scan.completed").Message; !strings.Contains(message, "notification destinations were unavailable") {
		t.Fatalf("lifecycle message = %q", message)
	}
	live = nil
	eventsMu.Unlock()
	if scans, err := defaultTenant(db).ListJobScans(ctx, record.ID, 10); err != nil || len(scans) != 0 {
		t.Fatalf("scans after the destination failure = %#v, %v; want the cycle unpromoted", scans, err)
	}
	cycle, err := defaultTenant(db).GetScanCycle(ctx, deferred.CycleID)
	if err != nil || cycle.Status != "completed" {
		t.Fatalf("cycle after the destination failure = %#v, %v", cycle, err)
	}
	originalFinishedAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	originalStartedAt := originalFinishedAt.Add(-2 * time.Hour)
	if _, err := db.DB.ExecContext(ctx, `UPDATE scan_cycles SET started_at=?,attempt_started_at='',attempt_count=2,finished_at=? WHERE id=?`, originalStartedAt.Format(time.RFC3339Nano), originalFinishedAt.Format(time.RFC3339Nano), deferred.CycleID); err != nil {
		t.Fatal(err)
	}
	legacyCycle, err := defaultTenant(db).GetScanCycle(ctx, deferred.CycleID)
	if err != nil || legacyCycle.AttemptCount != 2 || !legacyCycle.AttemptStartedAt.IsZero() || !legacyCycle.FinishedAt.Equal(originalFinishedAt) {
		t.Fatalf("legacy completed cycle = %#v, %v; want two attempts, no recorded attempt start, and finish %s", legacyCycle, err, originalFinishedAt)
	}
	if state, err := defaultTenant(db).RuntimeState(ctx, record.ID); err != nil || len(state.Incidents) != 0 {
		t.Fatalf("runtime after the destination failure = %#v, %v", state, err)
	}
	if _, err := db.DB.ExecContext(ctx, `ALTER TABLE managed_notifications_unavailable RENAME TO managed_notifications`); err != nil {
		t.Fatal(err)
	}

	promoted, events, promoteErr := a.runJobRecord(ctx, record, false)
	if promoteErr != nil || promoted.CycleID != deferred.CycleID || promoted.Status != "success" || promoted.Comparison != model.ScanComparisonCompared {
		t.Fatalf("next run = %#v, err %v; want the completed cycle promoted and compared", promoted, promoteErr)
	}
	if !promoted.StartedAt.Equal(originalStartedAt) {
		t.Fatalf("recovered scan started at %s, want original cycle start %s because the legacy attempt start is unknown", promoted.StartedAt, originalStartedAt)
	}
	if !promoted.FinishedAt.Equal(originalFinishedAt) {
		t.Fatalf("recovered scan finished at %s, want original cycle completion %s", promoted.FinishedAt, originalFinishedAt)
	}
	if promoted.StartedAt.After(promoted.FinishedAt) {
		t.Fatalf("recovered scan interval is inverted: %s to %s", promoted.StartedAt, promoted.FinishedAt)
	}
	var scanStartedAt, scanFinishedAt, lastSuccessAt string
	if err := db.DB.QueryRowContext(ctx, `SELECT started_at,finished_at FROM scans WHERE cycle_id=? AND status='success'`, deferred.CycleID).Scan(&scanStartedAt, &scanFinishedAt); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRowContext(ctx, `SELECT last_success_at FROM job_silence_state WHERE job_id=?`, record.ID).Scan(&lastSuccessAt); err != nil {
		t.Fatal(err)
	}
	parsedScanStartedAt, startErr := time.Parse(time.RFC3339Nano, scanStartedAt)
	parsedScanFinishedAt, scanErr := time.Parse(time.RFC3339Nano, scanFinishedAt)
	parsedLastSuccessAt, successErr := time.Parse(time.RFC3339Nano, lastSuccessAt)
	if startErr != nil || scanErr != nil || successErr != nil || parsedScanStartedAt.After(parsedScanFinishedAt) || !parsedScanStartedAt.Equal(originalStartedAt) || !parsedScanFinishedAt.Equal(originalFinishedAt) || !parsedLastSuccessAt.Equal(originalFinishedAt) {
		t.Fatalf("recovered persisted interval/finish markers = scans %q..%q (%v, %v), silence %q (%v); want %s..%s and preserved finish", scanStartedAt, scanFinishedAt, startErr, scanErr, lastSuccessAt, successErr, originalStartedAt.Format(time.RFC3339Nano), originalFinishedAt.Format(time.RFC3339Nano))
	}
	if !hasEventType(events, "changes-detected") {
		t.Fatalf("promoted cycle was not compared with the baseline: %#v", events)
	}
	if plans, units := probe.counts(); plans != 1 || units != 2 {
		t.Fatalf("scanner planned %d cycles and scanned %d units; want the one cycle reused", plans, units)
	}
	var compared int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE cycle_id=? AND comparison=?`, deferred.CycleID, model.ScanComparisonCompared).Scan(&compared); err != nil || compared != 1 {
		t.Fatalf("compared scans of the cycle = %d, %v; want 1", compared, err)
	}
	if latest, err := defaultTenant(db).GetLatestScanCycle(ctx, record.ID); err != nil || latest.ID != deferred.CycleID {
		t.Fatalf("latest cycle = %#v, %v; want no new cycle", latest, err)
	}
	if state, err := defaultTenant(db).RuntimeState(ctx, record.ID); err != nil || len(state.Incidents) != 1 {
		t.Fatalf("runtime after promotion = %#v, %v", state, err)
	}
}

func TestOldUnpromotedCompletedCycleIsDiscardedAndReplanned(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	probe := &completingCycleScanner{}
	a, db := newLifecycleTestApp(t, probe, nil)
	record, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("old-cycle-replan"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `ALTER TABLE managed_notifications RENAME TO managed_notifications_unavailable`); err != nil {
		t.Fatal(err)
	}
	deferred, _, deferErr := a.runJobRecord(ctx, record, false)
	if deferErr == nil || deferred.CycleID == "" || deferred.CycleStatus != "completed" {
		t.Fatalf("run without destinations = %#v, err %v", deferred, deferErr)
	}
	oldFinished := deferred.FinishedAt
	if _, err := db.DB.ExecContext(ctx, `UPDATE scan_cycles SET expires_at=?,finished_at=? WHERE id=?`, time.Now().UTC().Add(-30*24*time.Hour).Format(time.RFC3339Nano), time.Now().UTC().Add(-30*24*time.Hour).Format(time.RFC3339Nano), deferred.CycleID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `ALTER TABLE managed_notifications_unavailable RENAME TO managed_notifications`); err != nil {
		t.Fatal(err)
	}

	fresh, _, runErr := a.runJobRecord(ctx, record, false)
	if runErr != nil || fresh.Status != "success" || fresh.CycleID == deferred.CycleID {
		t.Fatalf("run after old cycle expiry = %#v, err %v; want a fresh cycle", fresh, runErr)
	}
	if !fresh.StartedAt.After(oldFinished) || !fresh.FinishedAt.After(oldFinished) {
		t.Fatalf("fresh scan timestamps = %s..%s; old cycle ended %s", fresh.StartedAt, fresh.FinishedAt, oldFinished)
	}
	oldCycle, err := defaultTenant(db).GetScanCycle(ctx, deferred.CycleID)
	if err != nil || oldCycle.Status != "discarded" || oldCycle.CompletedUnits != 0 {
		t.Fatalf("old cycle after expiry = %#v, %v", oldCycle, err)
	}
	if plans, units := probe.counts(); plans != 2 || units != 4 {
		t.Fatalf("scanner planned %d cycles and scanned %d units; want the old completed cycle discarded and a new plan", plans, units)
	}
}

func TestRepeatedCompletedCycleFinalizationFailuresPlanFreshCycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	probe := &completingCycleScanner{}
	var logs bytes.Buffer
	a, db := newLifecycleTestApp(t, probe, &logs)
	record, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("cycle-finalization-retry-limit"))
	if err != nil {
		t.Fatal(err)
	}
	budgetCalls := 0
	a.persistenceBudget = func(int) time.Duration {
		budgetCalls++
		if budgetCalls <= 2 {
			return time.Nanosecond
		}
		return scanPersistenceTimeout(0)
	}

	var failedCycleID string
	for attempt := 1; attempt <= 2; attempt++ {
		scan, _, runErr := a.runJobRecord(ctx, record, false)
		if runErr == nil || scan.Status != "failed" || scan.Error != model.ScanFinalizationFailureMessage || scan.CycleStatus != "completed" || !scan.Resumable {
			t.Fatalf("finalization failure %d = %#v, %v", attempt, scan, runErr)
		}
		if attempt == 1 {
			failedCycleID = scan.CycleID
		} else if scan.CycleID != failedCycleID {
			t.Fatalf("retry changed cycle before the failure bound: first=%q second=%q", failedCycleID, scan.CycleID)
		}
	}
	if strings.Contains(logs.String(), "completed scan cycle discarded after repeated result finalization failures") {
		t.Fatal("cycle discard warning was emitted before the retry bound was handled")
	}

	scan, _, runErr := a.runJobRecord(ctx, record, false)
	if runErr != nil || scan.Status != "success" || scan.CycleStatus != "completed" || scan.CycleID == failedCycleID {
		t.Fatalf("run after repeated finalization failures = %#v, %v", scan, runErr)
	}
	warning := logs.String()
	if !strings.Contains(warning, "level=WARN") ||
		!strings.Contains(warning, "completed scan cycle discarded after repeated result finalization failures; planning a fresh scan") ||
		!strings.Contains(warning, "cycle_id="+failedCycleID) ||
		!strings.Contains(warning, "finalization_failures=2") {
		t.Fatalf("retry-bound discard warning does not identify the old cycle: %s", warning)
	}
	oldCycle, err := defaultTenant(db).GetScanCycle(ctx, failedCycleID)
	if err != nil || oldCycle.Status != "discarded" {
		t.Fatalf("old cycle after retry bound = %+v, %v", oldCycle, err)
	}
	if units, err := defaultTenant(db).ListScanCycleUnitSummaries(ctx, failedCycleID); err != nil || len(units) != 0 {
		t.Fatalf("old cycle retained units after discard: %v, %v", units, err)
	}
	var fallbackRows int
	if err := db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE cycle_id=? AND status='failed' AND cycle_status='completed' AND resumable=1 AND error=?`, failedCycleID, model.ScanFinalizationFailureMessage).Scan(&fallbackRows); err != nil || fallbackRows != 2 {
		t.Fatalf("old cycle finalization failure rows = %d, %v; want exactly 2", fallbackRows, err)
	}
	if plans, units := probe.counts(); plans != 2 || units != 4 {
		t.Fatalf("scanner planned %d cycles and scanned %d units; want one retry then one fresh plan", plans, units)
	}
}

// A completed cycle whose finalization fails leaves a failed fallback row
// that finishes after the cycle did, and the run that recovers the cycle
// records its scan at the cycle's own finish time, which is earlier. The
// recovered scan, not the fallback row it superseded, is the job's latest
// attempt, so neither the Jobs list nor the Perimeter report keeps showing
// the job as failed until its next run.
func TestRecoveredCycleAfterFinalizationFailureIsTheLatestAttempt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	probe := &completingCycleScanner{}
	a, db := newLifecycleTestApp(t, probe, nil)
	ts := defaultTenant(db)
	declarePerimeter(t, ts, store.PerimeterKindPrefix, "192.0.2.0/24")
	record, err := ts.CreateJob(ctx, lifecycleJob("cycle-finalization-recovery"))
	if err != nil {
		t.Fatal(err)
	}
	budgetCalls := 0
	a.persistenceBudget = func(int) time.Duration {
		budgetCalls++
		if budgetCalls == 1 {
			return time.Nanosecond
		}
		return scanPersistenceTimeout(0)
	}

	failed, _, failErr := a.runJobRecord(ctx, record, false)
	if failErr == nil || failed.Status != "failed" || failed.Error != model.ScanFinalizationFailureMessage || failed.CycleStatus != "completed" || !failed.Resumable {
		t.Fatalf("first run = %#v, %v; want a finalization failure of the completed cycle", failed, failErr)
	}
	executions, err := ts.ListJobExecutionSummaries(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if attempt := executions[record.ID].LatestAttempt; attempt == nil || attempt.ID != failed.ID || attempt.Status != "failed" {
		t.Fatalf("latest attempt before recovery = %+v; want the unrecovered failure %s", attempt, failed.ID)
	}

	recovered, _, recoverErr := a.runJobRecord(ctx, record, false)
	if recoverErr != nil || recovered.Status != "success" || recovered.CycleID != failed.CycleID || recovered.CycleStatus != "completed" || recovered.Comparison != model.ScanComparisonBaselineEstablished {
		t.Fatalf("recovery run = %#v, %v; want the failed cycle promoted as the first baseline sample", recovered, recoverErr)
	}
	if !recovered.FinishedAt.Before(failed.FinishedAt) {
		t.Fatalf("recovered scan finished at %s, fallback row at %s; want the recovery to keep the cycle's earlier finish time", recovered.FinishedAt, failed.FinishedAt)
	}
	if plans, units := probe.counts(); plans != 1 || units != 2 {
		t.Fatalf("scanner planned %d cycles and scanned %d units; want the failed cycle recovered", plans, units)
	}

	executions, err = ts.ListJobExecutionSummaries(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	execution := executions[record.ID]
	if attempt := execution.LatestAttempt; attempt == nil || attempt.ID != recovered.ID || attempt.Status != "success" || attempt.CycleID != recovered.CycleID {
		t.Fatalf("latest attempt after recovery = %+v; want the recovered scan %s", attempt, recovered.ID)
	}
	if success := execution.LatestSuccessfulScan; success == nil || success.ID != recovered.ID {
		t.Fatalf("latest successful scan after recovery = %+v; want %s", success, recovered.ID)
	}
	// The fallback row stays in the job's history, newest first.
	if scans, err := ts.ListJobScans(ctx, record.ID, 10); err != nil || len(scans) != 2 || scans[0].ID != failed.ID || scans[1].ID != recovered.ID {
		t.Fatalf("job history after recovery = %#v, %v; want the fallback row kept before the recovered scan", scans, err)
	}

	report, err := a.PerimeterReport(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	monitor := perimeterMonitorNamed(t, report.Monitors, record.Job.Name)
	if monitor.State != perimeterCovering || monitor.LastAttemptStatus != "success" || monitor.LastSuccessAt == nil || monitor.Stale || (perimeterMonitor{ref: monitor}).unproven() || report.Totals.UnprovenMonitors != 0 {
		t.Fatalf("perimeter monitor after recovery = %+v, unproven monitors %d; want a proven monitor whose last attempt succeeded", monitor, report.Totals.UnprovenMonitors)
	}
}

func TestCompletedCycleDiscardStorageErrorIsReturnedWithoutLosingProgress(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	probe := &completingCycleScanner{}
	a, db := newLifecycleTestApp(t, probe, nil)
	record, err := defaultTenant(db).CreateJob(ctx, lifecycleJob("cycle-finalization-discard-error"))
	if err != nil {
		t.Fatal(err)
	}
	budgetCalls := 0
	a.persistenceBudget = func(int) time.Duration {
		budgetCalls++
		if budgetCalls <= 2 {
			return time.Nanosecond
		}
		return scanPersistenceTimeout(0)
	}

	var cycleID string
	for attempt := 1; attempt <= 2; attempt++ {
		scan, _, runErr := a.runJobRecord(ctx, record, false)
		if runErr == nil || scan.Status != "failed" || scan.Error != model.ScanFinalizationFailureMessage || scan.CycleStatus != "completed" || !scan.Resumable {
			t.Fatalf("finalization failure %d = %#v, %v", attempt, scan, runErr)
		}
		if attempt == 1 {
			cycleID = scan.CycleID
		} else if scan.CycleID != cycleID {
			t.Fatalf("cycle changed before retry bound: first=%q second=%q", cycleID, scan.CycleID)
		}
	}
	if _, err := db.DB.ExecContext(ctx, `CREATE TRIGGER reject_cycle_discard BEFORE UPDATE OF status ON scan_cycles WHEN NEW.status='discarded' BEGIN SELECT RAISE(ABORT, 'injected cycle discard failure'); END`); err != nil {
		t.Fatal(err)
	}

	scan, _, runErr := a.runJobRecord(ctx, record, false)
	if runErr == nil || scan.Status != "failed" || !strings.Contains(runErr.Error(), "injected cycle discard failure") {
		t.Fatalf("discard storage failure = %#v, %v; want the completed cycle failure returned", scan, runErr)
	}
	if cycle, err := defaultTenant(db).GetScanCycle(ctx, cycleID); err != nil || cycle.Status != "completed" || cycle.CompletedUnits != 2 {
		t.Fatalf("cycle after failed discard = %+v, %v; want completed progress retained", cycle, err)
	}
	if units, err := defaultTenant(db).ListScanCycleUnitSummaries(ctx, cycleID); err != nil || len(units) != 2 {
		t.Fatalf("units after failed discard = %v, %v; want all saved progress retained", units, err)
	}
	if plans, units := probe.counts(); plans != 1 || units != 2 {
		t.Fatalf("scanner planned %d cycles and scanned %d units; discard failure must not start new work", plans, units)
	}
}

// A scan outside a completed cycle keeps the earlier behavior: its result is
// saved as not compared.
func TestCompletedCycleResult(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		scan model.Scan
		want bool
	}{
		{scan: model.Scan{Resumable: true, CycleID: "cycle", CycleStatus: "completed", Status: "success"}, want: true},
		{scan: model.Scan{Resumable: true, CycleID: "cycle", CycleStatus: "completed", Status: "incomplete"}, want: true},
		{scan: model.Scan{Resumable: true, CycleID: "cycle", CycleStatus: "paused", Status: "timed_out"}},
		{scan: model.Scan{Resumable: true, CycleID: "cycle", CycleStatus: "completed", Status: "failed"}},
		{scan: model.Scan{Status: "success"}},
	} {
		if got := completedCycleResult(test.scan); got != test.want {
			t.Errorf("completedCycleResult(%#v) = %t, want %t", test.scan, got, test.want)
		}
	}
}

var _ scanner.ResumableScanner = (*completingCycleScanner)(nil)
