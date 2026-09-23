package store

import (
	"context"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestPruneUsesCanonicalTimestampCutoff(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	cutoff := time.Date(2026, time.January, 1, 12, 34, 56, 0, time.UTC)
	beforeID := "retention-before-cutoff"
	afterID := "retention-after-cutoff"
	for _, scan := range []model.Scan{
		{
			ID:         beforeID,
			Job:        "retention-timestamps",
			StartedAt:  cutoff.Add(-time.Nanosecond),
			FinishedAt: cutoff.Add(-time.Nanosecond),
			Status:     "success",
			Snapshot:   model.Snapshot{},
		},
		{
			ID:         afterID,
			Job:        "retention-timestamps",
			StartedAt:  cutoff.Add(time.Nanosecond),
			FinishedAt: cutoff.Add(time.Nanosecond),
			Status:     "success",
			Snapshot:   model.Snapshot{},
		},
	} {
		if err := s.SaveScan(ctx, scan); err != nil {
			t.Fatalf("save %s: %v", scan.ID, err)
		}
	}

	stats, err := s.PruneWithStats(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Scans != 1 {
		t.Fatalf("pruned scans = %d, want the one row before cutoff: %#v", stats.Scans, stats)
	}
	if _, err := s.GetScan(ctx, beforeID); err == nil {
		t.Fatal("scan before the cutoff was retained")
	}
	if _, err := s.GetScan(ctx, afterID); err != nil {
		t.Fatalf("scan after the cutoff was pruned: %v", err)
	}
}
