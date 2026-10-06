package store

import (
	"context"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestPruneUsesCanonicalTimestampCutoff(t *testing.T) {
	t.Parallel()
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
		if err := s.System().SaveScan(ctx, scan); err != nil {
			t.Fatalf("save %s: %v", scan.ID, err)
		}
	}

	stats, err := s.System().PruneWithStats(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Scans != 1 {
		t.Fatalf("pruned scans = %d, want the one row before cutoff: %#v", stats.Scans, stats)
	}
	if _, err := defaultTenant(s).GetScan(ctx, beforeID); err == nil {
		t.Fatal("scan before the cutoff was retained")
	}
	if _, err := defaultTenant(s).GetScan(ctx, afterID); err != nil {
		t.Fatalf("scan after the cutoff was pruned: %v", err)
	}
}

func TestRetentionPrunesExpiredQuarantineAndLeavesPurgingTenantRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	cutoff := time.Date(2026, time.January, 1, 12, 34, 56, 0, time.UTC)
	old := sqliteTimestamp(cutoff.Add(-time.Nanosecond))
	recent := sqliteTimestamp(cutoff.Add(time.Nanosecond))
	for _, row := range []struct {
		epoch, timestamp, tenant string
	}{
		{epoch: "expired-default", timestamp: old, tenant: DefaultTenantID},
		{epoch: "recent-default", timestamp: recent, tenant: DefaultTenantID},
		{epoch: "expired-deleting-tenant", timestamp: old, tenant: secondTenantID},
	} {
		if _, err := f.store.DB.ExecContext(ctx, `INSERT INTO restore_quarantined_deliveries(restore_epoch,destination,payload_json,quarantined_at,tenant_id) VALUES(?, 'destination', '{}', ?, ?)`, row.epoch, row.timestamp, row.tenant); err != nil {
			t.Fatal(err)
		}
	}
	setTenantState(t, f.store, secondTenantID, TenantStateDeleting)

	stats, err := f.store.System().PruneWithStats(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if stats.QuarantinedOutbox != 1 || stats.Total() < 1 {
		t.Fatalf("quarantined retention stats = %+v, want one pruned row included in total", stats)
	}
	for epoch, want := range map[string]int{"expired-default": 0, "recent-default": 1, "expired-deleting-tenant": 1} {
		if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM restore_quarantined_deliveries WHERE restore_epoch=?`, epoch); got != want {
			t.Errorf("quarantine rows for %s = %d, want %d", epoch, got, want)
		}
	}
}
