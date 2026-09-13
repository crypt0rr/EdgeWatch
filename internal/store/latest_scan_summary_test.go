package store

import (
	"context"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestGetLatestSuccessfulJobScanSummaryFiltersAndTies(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	record, err := s.CreateJob(ctx, testJob("latest-summary"))
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
		if err := s.SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}

	latest, err := s.GetLatestSuccessfulJobScanSummary(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if latest == nil || latest.ID != "same-time-z" || latest.Status != "success" {
		t.Fatalf("latest successful summary = %#v, want same-time-z success", latest)
	}
	if latest.JobID != record.ID || !latest.FinishedAt.Equal(stamp) {
		t.Fatalf("latest summary metadata = %#v", latest)
	}

	noSuccess, err := s.CreateJob(ctx, testJob("no-success"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetLatestSuccessfulJobScanSummary(ctx, noSuccess.ID); err != nil || got != nil {
		t.Fatalf("no-success result = %#v, err=%v; want nil, nil", got, err)
	}
}
