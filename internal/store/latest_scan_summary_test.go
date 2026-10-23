package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestGetLatestSuccessfulJobScanSummaryFiltersAndTies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("latest-summary"))
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	for _, scan := range []model.Scan{
		{ID: "older-success", JobID: record.ID, Job: record.Job.Name, StartedAt: stamp.Add(-time.Minute), FinishedAt: stamp.Add(-time.Minute), Status: "success", Snapshot: model.Snapshot{}},
		{ID: "same-time-a", JobID: record.ID, Job: record.Job.Name, StartedAt: stamp, FinishedAt: stamp, Status: "success", Snapshot: model.Snapshot{}},
		{ID: "same-time-z", JobID: record.ID, Job: record.Job.Name, StartedAt: stamp, FinishedAt: stamp, Status: "success", Snapshot: model.Snapshot{}},
		{ID: "newer-incomplete", JobID: record.ID, Job: record.Job.Name, StartedAt: stamp.Add(time.Minute), FinishedAt: stamp.Add(time.Minute), Status: "incomplete", Snapshot: model.Snapshot{}},
		{ID: "newest-failed", JobID: record.ID, Job: record.Job.Name, StartedAt: stamp.Add(2 * time.Minute), FinishedAt: stamp.Add(2 * time.Minute), Status: "failed", Error: "scanner failed", Snapshot: model.Snapshot{}},
	} {
		if err := s.System().SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}

	latest, err := defaultTenant(s).GetLatestSuccessfulJobScanSummary(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if latest == nil || latest.ID != "same-time-z" || latest.Status != "success" {
		t.Fatalf("latest successful summary = %#v, want same-time-z success", latest)
	}
	if latest.JobID != record.ID || !latest.FinishedAt.Equal(stamp) {
		t.Fatalf("latest summary metadata = %#v", latest)
	}

	noSuccess, err := defaultTenant(s).CreateJob(ctx, testJob("no-success"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := defaultTenant(s).GetLatestSuccessfulJobScanSummary(ctx, noSuccess.ID); err != nil || got != nil {
		t.Fatalf("no-success result = %#v, err=%v; want nil, nil", got, err)
	}
}

func TestListJobExecutionSummariesSeparatesLatestAttemptAndSuccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	stamp := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

	withHistory, err := ts.CreateJob(ctx, testJob("history"))
	if err != nil {
		t.Fatal(err)
	}
	noSuccess, err := ts.CreateJob(ctx, testJob("no-success"))
	if err != nil {
		t.Fatal(err)
	}
	laterSuccess, err := ts.CreateJob(ctx, testJob("later-success"))
	if err != nil {
		t.Fatal(err)
	}
	archived, err := ts.CreateJob(ctx, testJob("archived"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.SetJobArchived(ctx, archived.ID, true); err != nil {
		t.Fatal(err)
	}
	for _, scan := range []model.Scan{
		{ID: "history-success-a", JobID: withHistory.ID, Job: withHistory.Job.Name, StartedAt: stamp, FinishedAt: stamp, Status: "success", ConfigHash: "old-scope"},
		{ID: "history-success-z", JobID: withHistory.ID, Job: withHistory.Job.Name, StartedAt: stamp, FinishedAt: stamp, Status: "success", ConfigHash: "successful-scope"},
		{ID: "history-incomplete", JobID: withHistory.ID, Job: withHistory.Job.Name, StartedAt: stamp.Add(time.Minute), FinishedAt: stamp.Add(time.Minute), Status: "incomplete", ConfigHash: "attempt-scope", CycleID: "resumable-cycle", CycleStatus: "paused", Resumable: true},
		{ID: "no-success-failed", JobID: noSuccess.ID, Job: noSuccess.Job.Name, StartedAt: stamp, FinishedAt: stamp, Status: "failed", Error: "must not be returned"},
		{ID: "later-success-failed", JobID: laterSuccess.ID, Job: laterSuccess.Job.Name, StartedAt: stamp, FinishedAt: stamp, Status: "failed"},
		{ID: "later-success-won", JobID: laterSuccess.ID, Job: laterSuccess.Job.Name, StartedAt: stamp.Add(time.Minute), FinishedAt: stamp.Add(time.Minute), Status: "success"},
		{ID: "archived-success", JobID: archived.ID, Job: archived.Job.Name, StartedAt: stamp, FinishedAt: stamp, Status: "success"},
	} {
		if err := s.System().SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}

	got, err := ts.ListJobExecutionSummaries(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := got[archived.ID]; exists {
		t.Fatalf("archived job appeared without includeArchived: %#v", got[archived.ID])
	}
	if summary := got[withHistory.ID]; summary.LatestAttempt == nil || summary.LatestAttempt.ID != "history-incomplete" || summary.LatestSuccessfulScan == nil || summary.LatestSuccessfulScan.ID != "history-success-z" {
		t.Fatalf("latest attempt/success = %#v; want incomplete and deterministic latest success", summary)
	}
	if attempt := got[withHistory.ID].LatestAttempt; attempt.ConfigHash != "attempt-scope" || attempt.CycleID != "resumable-cycle" || attempt.CycleStatus != "paused" || !attempt.Resumable {
		t.Fatalf("latest attempt cycle metadata = %+v; want matching resumable attempt details", attempt)
	}
	if success := got[withHistory.ID].LatestSuccessfulScan; success.ConfigHash != "successful-scope" {
		t.Fatalf("latest successful config hash = %q, want successful-scope", success.ConfigHash)
	}
	if summary := got[noSuccess.ID]; summary.LatestAttempt == nil || summary.LatestAttempt.ID != "no-success-failed" || summary.LatestSuccessfulScan != nil {
		t.Fatalf("failed-only job summary = %#v; want latest attempt and no success", summary)
	}
	if summary := got[laterSuccess.ID]; summary.LatestAttempt == nil || summary.LatestAttempt.ID != "later-success-won" || summary.LatestAttempt.Status != "success" || summary.LatestSuccessfulScan == nil || summary.LatestSuccessfulScan.ID != "later-success-won" {
		t.Fatalf("later success summary = %#v; want success to become both the latest attempt and latest success", summary)
	}
	if got, err := ts.ListJobExecutionSummaries(ctx, true); err != nil || got[archived.ID].LatestSuccessfulScan == nil || got[archived.ID].LatestSuccessfulScan.ID != "archived-success" {
		t.Fatalf("include archived summary = %#v, err=%v", got[archived.ID], err)
	}
}

// When a completed cycle's finalization fails, the run saves a failed
// fallback row that claims the cycle completed, and the run that recovers
// the cycle saves the promoted scan at the cycle's own finish time, before
// the fallback row. The promoted scan, success or incomplete, supersedes the
// fallback row as the latest attempt. A failure that no run recovered, a
// later failure, a failure outside a cycle, and a promotion of the same
// cycle ID in another unit leave the failure the latest attempt.
func TestListJobExecutionSummariesSkipsRecoveredCycleFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	ts := f.store.Tenant(f.a)
	stamp := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	jobs := map[string]string{}
	for _, name := range []string{"recovered", "recovered-incomplete", "unrecovered", "failed-again", "outside-cycle", "other-unit"} {
		record, err := ts.CreateJob(ctx, testJob(name))
		if err != nil {
			t.Fatal(err)
		}
		jobs[name] = record.ID
	}
	jobs["unit-b"] = f.jobB
	scan := func(id, job, status, cycle, cycleStatus string, finished time.Time) model.Scan {
		scan := model.Scan{ID: id, JobID: jobs[job], Job: job, StartedAt: finished.Add(-time.Hour), FinishedAt: finished, Status: status, CycleID: cycle, CycleStatus: cycleStatus, Resumable: cycle != ""}
		if status == "failed" {
			scan.Error = model.ScanFinalizationFailureMessage
		}
		return scan
	}
	later := stamp.Add(time.Minute)
	for _, saved := range []model.Scan{
		scan("recovered-fallback", "recovered", "failed", "cycle-recovered", "completed", later),
		scan("recovered-success", "recovered", "success", "cycle-recovered", "completed", stamp),
		scan("incomplete-fallback", "recovered-incomplete", "failed", "cycle-incomplete", "completed", later),
		scan("incomplete-promoted", "recovered-incomplete", "incomplete", "cycle-incomplete", "completed", stamp),
		scan("unrecovered-older-success", "unrecovered", "success", "cycle-older", "completed", stamp.Add(-time.Hour)),
		scan("unrecovered-fallback", "unrecovered", "failed", "cycle-unrecovered", "completed", later),
		scan("again-fallback", "failed-again", "failed", "cycle-again", "completed", later),
		scan("again-success", "failed-again", "success", "cycle-again", "completed", stamp),
		scan("again-later-failure", "failed-again", "failed", "", "", later.Add(time.Minute)),
		scan("outside-success", "outside-cycle", "success", "", "", stamp),
		scan("outside-failure", "outside-cycle", "failed", "", "", later),
		scan("other-unit-fallback", "other-unit", "failed", "cycle-shared", "completed", later),
		scan("unit-b-success", "unit-b", "success", "cycle-shared", "completed", stamp),
	} {
		if err := f.store.System().SaveScan(ctx, saved); err != nil {
			t.Fatalf("save %s: %v", saved.ID, err)
		}
	}

	got, err := ts.ListJobExecutionSummaries(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	for job, want := range map[string]struct{ attempt, success string }{
		"recovered":            {"recovered-success", "recovered-success"},
		"recovered-incomplete": {"incomplete-promoted", ""},
		"unrecovered":          {"unrecovered-fallback", "unrecovered-older-success"},
		"failed-again":         {"again-later-failure", "again-success"},
		"outside-cycle":        {"outside-failure", "outside-success"},
		"other-unit":           {"other-unit-fallback", ""},
	} {
		summary := got[jobs[job]]
		var attempt, success string
		if summary.LatestAttempt != nil {
			attempt = summary.LatestAttempt.ID
		}
		if summary.LatestSuccessfulScan != nil {
			success = summary.LatestSuccessfulScan.ID
		}
		if attempt != want.attempt || success != want.success {
			t.Errorf("%s: latest attempt %q, latest success %q; want %q and %q", job, attempt, success, want.attempt, want.success)
		}
	}
	if attempt := got[jobs["recovered"]].LatestAttempt; attempt == nil || attempt.Status != "success" || attempt.CycleID != "cycle-recovered" || attempt.CycleStatus != "completed" || !attempt.FinishedAt.Equal(stamp) {
		t.Fatalf("recovered latest attempt = %+v; want the promoted scan with its cycle's finish time", attempt)
	}
}

func TestListJobExecutionSummariesDoesNotLoadScanJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	record, err := defaultTenant(s).CreateJob(ctx, testJob("status-with-large-snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	if err := s.System().SaveScan(ctx, model.Scan{ID: "large-scan", JobID: record.ID, Job: record.Job.Name, StartedAt: stamp, FinishedAt: stamp, Status: "success"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scans SET snapshot_json=zeroblob(4*1024*1024),changes_json=zeroblob(1024*1024) WHERE id='large-scan'`); err != nil {
		t.Fatal(err)
	}
	limitReadValueLength(t, s, 1<<20)

	summaries, err := defaultTenant(s).ListJobExecutionSummaries(ctx, false)
	if err != nil {
		t.Fatalf("read scan status with bounded SQLite value limit: %v", err)
	}
	if got := summaries[record.ID].LatestSuccessfulScan; got == nil || got.ID != "large-scan" {
		t.Fatalf("latest successful status = %#v", got)
	}
}

func TestListJobExecutionSummariesUsesHistoryIndex(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	plan := explainPlan(t, s.DB, jobExecutionSummariesSQL, DefaultTenantID, 0)
	joined := strings.Join(plan, " | ")
	if strings.Count(joined, scansJobHistoryIndex) < 2 {
		t.Fatalf("execution summary plan does not use the history index for both lookups: %s", joined)
	}
	if strings.Contains(joined, "TEMP B-TREE") {
		t.Fatalf("execution summary plan sorts into a temporary B-tree: %s", joined)
	}
	if reads := scanRowReads(plan, "candidate", "promoted"); len(reads) != 0 {
		t.Fatalf("execution summary plan reads scan rows during its indexed lookups: %q (%s)", reads, joined)
	}
	assertRecoveredCycleFailurePlan(t, "execution summary", plan)
}

// assertRecoveredCycleFailurePlan checks the plan of a latest-scan lookup
// that skips a recovered cycle's fallback row (recoveredCycleFailureSQL):
// only a failed candidate reads its own row, by rowid, for its cycle, and
// the promotion of that cycle comes from scans_cycle_outcome.
func assertRecoveredCycleFailurePlan(t *testing.T, label string, plan []string) {
	t.Helper()
	joined := strings.Join(plan, " | ")
	if !strings.Contains(joined, "SEARCH promoted USING COVERING INDEX "+scansCycleOutcomeIndex+" ") {
		t.Errorf("%s plan does not check the cycle's promotion in %s: %s", label, scansCycleOutcomeIndex, joined)
	}
	for _, step := range plan {
		if fields := strings.Fields(step); len(fields) > 1 && fields[1] == "fallback" && step != "SEARCH fallback USING INTEGER PRIMARY KEY (rowid=?)" {
			t.Errorf("%s plan reads the failed candidate's row other than by rowid: %q (%s)", label, step, joined)
		}
	}
	if !strings.Contains(joined, "SEARCH fallback USING INTEGER PRIMARY KEY (rowid=?)") {
		t.Errorf("%s plan does not read the failed candidate's row by rowid: %s", label, joined)
	}
}
