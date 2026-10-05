package store

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"
)

func TestMigration63KeepsLegacyExhaustedDeliveriesTerminal(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	oldRetry := time.Now().UTC().Add(-21 * 24 * time.Hour)
	postBudgetRelease := time.Date(2026, time.October, 3, 0, 20, 0, 0, time.UTC)
	rows := []struct {
		destination string
		attempts    int
		nextAt      time.Time
		sentAt      sql.NullString
	}{
		{destination: "legacy-exhausted", attempts: 8, nextAt: oldRetry},
		{destination: "retrying-under-new-budget", attempts: 10, nextAt: postBudgetRelease},
		{destination: "retrying-under-old-budget", attempts: 7, nextAt: oldRetry},
		{destination: "already-sent", attempts: 8, nextAt: oldRetry, sentAt: sql.NullString{String: oldRetry.Format(time.RFC3339Nano), Valid: true}},
	}
	for _, row := range rows {
		payload := []byte(fmt.Sprintf(`{"type":"migration-test","message":%q}`, row.destination))
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,attempts,next_at,sent_at,tenant_id) VALUES(?,?,?,?,?,?)`,
			row.destination, payload, row.attempts, row.nextAt.Format(time.RFC3339Nano), nullableString(row.sentAt), DefaultTenantID); err != nil {
			t.Fatalf("insert %s: %v", row.destination, err)
		}
	}
	path := s.Path
	if _, err := s.DB.ExecContext(ctx, `PRAGMA user_version=62`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(path)
	if err != nil {
		t.Fatalf("open upgraded database: %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })

	var terminalAt string
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT terminal_at FROM outbox WHERE destination='legacy-exhausted'`).Scan(&terminalAt); err != nil {
		t.Fatal(err)
	}
	if terminalAt == "" {
		t.Fatal("legacy exhausted delivery has no terminal marker after upgrade")
	}
	for _, destination := range []string{"retrying-under-new-budget", "retrying-under-old-budget", "already-sent"} {
		if err := upgraded.DB.QueryRowContext(ctx, `SELECT terminal_at FROM outbox WHERE destination=?`, destination).Scan(&terminalAt); err != nil {
			t.Fatalf("read terminal marker for %s: %v", destination, err)
		}
		if terminalAt != "" {
			t.Fatalf("%s unexpectedly became terminal at %q", destination, terminalAt)
		}
	}

	if failed, err := defaultTenant(upgraded).FailedDeliveries(ctx); err != nil || failed != 1 {
		t.Fatalf("failed deliveries after upgrade = %d, %v; want 1", failed, err)
	}
	due, err := upgraded.System().ClaimDueDeliveries(ctx, 10, "migration-test-owner")
	if err != nil {
		t.Fatalf("claim due deliveries: %v", err)
	}
	got := make(map[string]bool, len(due))
	for _, delivery := range due {
		got[delivery.Destination] = true
	}
	if len(got) != 2 || !got["retrying-under-new-budget"] || !got["retrying-under-old-budget"] {
		t.Fatalf("claimable deliveries after upgrade = %v; want only the two still retrying", got)
	}

	stats, err := upgraded.System().PruneWithStats(ctx, time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("prune old terminal delivery: %v", err)
	}
	if stats.FailedOutbox != 1 {
		t.Fatalf("pruned failed deliveries = %d, want 1", stats.FailedOutbox)
	}
	var remaining int
	if err := upgraded.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE destination='legacy-exhausted'`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("legacy exhausted rows remaining = %d, %v; want 0", remaining, err)
	}
}

func nullableString(value sql.NullString) any {
	if !value.Valid {
		return nil
	}
	return value.String
}
