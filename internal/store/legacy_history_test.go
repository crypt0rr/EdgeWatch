package store

import (
	"context"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestListLegacySuccessfulScanSnapshotsPageFiltersIndexedRows(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	indexed := model.Scan{
		ID:         "indexed-snapshot",
		JobID:      "job-indexed",
		Job:        "indexed",
		StartedAt:  now.Add(-time.Minute),
		FinishedAt: now.Add(-time.Minute),
		Status:     "success",
		Snapshot: model.Snapshot{Hosts: []model.HostObservation{{
			Address: "198.51.100.10",
			Protocols: []model.ProtocolObservation{{
				Protocol: "tcp",
				Ports:    []model.PortObservation{{Port: 443, State: "open"}},
			}},
		}}},
	}
	legacy := model.Scan{
		ID:         "legacy-snapshot",
		JobID:      "job-legacy",
		Job:        "legacy",
		StartedAt:  now,
		FinishedAt: now,
		Status:     "success",
		Snapshot: model.Snapshot{Units: []model.Unit{{
			Target:    "legacy.example",
			Protocol:  "tcp",
			Addresses: []string{"198.51.100.11"},
			Ports:     []model.PortState{{Port: 80, State: "open"}},
		}}},
	}
	failed := legacy
	failed.ID = "failed-snapshot"
	failed.Status = "failed"
	failed.FinishedAt = now.Add(time.Minute)
	for _, scan := range []model.Scan{indexed, legacy, failed} {
		if err := s.SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}

	page, err := s.ListLegacySuccessfulScanSnapshotsPage(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("legacy page = %#v, want one row", page)
	}
	if page.Items[0].ID != legacy.ID || page.Items[0].JobID != legacy.JobID || page.Items[0].Job != legacy.Job || page.Items[0].FinishedAt.IsZero() {
		t.Fatalf("legacy item = %#v", page.Items[0])
	}
	if len(page.Items[0].Snapshot) == 0 {
		t.Fatal("legacy raw snapshot was not returned")
	}

	second, err := s.ListLegacySuccessfulScanSnapshotsPage(ctx, 50, 1)
	if err != nil {
		t.Fatal(err)
	}
	if second.Total != page.Total || len(second.Items) != 0 {
		t.Fatalf("paginated tail = %#v", second)
	}
}
