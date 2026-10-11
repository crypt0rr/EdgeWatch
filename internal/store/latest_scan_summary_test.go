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
		{ID: "history-success-a", JobID: withHistory.ID, Job: withHistory.Job.Name, StartedAt: stamp, FinishedAt: stamp, Status: "success"},
		{ID: "history-success-z", JobID: withHistory.ID, Job: withHistory.Job.Name, StartedAt: stamp, FinishedAt: stamp, Status: "success"},
		{ID: "history-incomplete", JobID: withHistory.ID, Job: withHistory.Job.Name, StartedAt: stamp.Add(time.Minute), FinishedAt: stamp.Add(time.Minute), Status: "incomplete"},
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
	if reads := scanRowReads(plan, "candidate"); len(reads) != 0 {
		t.Fatalf("execution summary plan reads scan rows during its indexed lookups: %q (%s)", reads, joined)
	}
}
