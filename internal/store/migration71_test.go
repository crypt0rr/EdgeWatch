package store

import (
	"context"
	"strings"
	"testing"
)

func TestMigration71IndexesAllTenantOutboxRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	for _, row := range []struct {
		destination string
		payload     []byte
		tenantID    string
		sentAt      any
	}{
		{destination: "schema71-invalid-payload", payload: []byte{0xff}, tenantID: DefaultTenantID},
		{destination: "schema71-sent-empty-metadata", payload: []byte(`{"type":"changes-detected"}`), tenantID: DefaultTenantID, sentAt: "2026-10-12T00:00:00Z"},
		{destination: "schema71-other-tenant", payload: []byte(`{}`), tenantID: "other-tenant"},
	} {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(destination,payload_json,next_at,sent_at,tenant_id) VALUES(?,?,?, ?,?)`, row.destination, row.payload, "2026-10-11T00:00:00Z", row.sentAt, row.tenantID); err != nil {
			t.Fatalf("insert fixture %s: %v", row.destination, err)
		}
	}
	if _, err := s.DB.ExecContext(ctx, `DROP INDEX outbox_tenant_purge`); err != nil {
		t.Fatal(err)
	}
	if err := reapplyMigration(t, s.DB, 71, migration71Statements()); err != nil {
		t.Fatalf("reapply schema 71: %v", err)
	}
	if got, want := indexKeys(t, s.DB, "outbox_tenant_purge"), "tenant_id,id"; got != want {
		t.Fatalf("outbox_tenant_purge keys = %q, want %q", got, want)
	}

	for _, query := range []struct {
		name      string
		statement string
		args      []any
	}{
		{name: "bounded batch selection", statement: `SELECT rowid FROM outbox WHERE tenant_id=? ORDER BY rowid LIMIT ?`, args: []any{DefaultTenantID, 2}},
		{name: "rewind existence check", statement: `SELECT EXISTS(SELECT 1 FROM outbox WHERE tenant_id=?)`, args: []any{DefaultTenantID}},
	} {
		plan := strings.Join(explainPlan(t, s.DB, query.statement, query.args...), " | ")
		t.Logf("%s query plan: %s", query.name, plan)
		if !strings.Contains(plan, "USING COVERING INDEX outbox_tenant_purge") {
			t.Errorf("%s does not use the all-row tenant index: %s", query.name, plan)
		}
	}

	rows, err := s.DB.QueryContext(ctx, `SELECT destination FROM outbox WHERE tenant_id=? ORDER BY rowid LIMIT ?`, DefaultTenantID, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var destination string
		if err := rows.Scan(&destination); err != nil {
			t.Fatal(err)
		}
		got[destination] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{"schema71-invalid-payload", "schema71-sent-empty-metadata"} {
		if !got[destination] {
			t.Errorf("tenant-only selection omitted %s", destination)
		}
	}
	if got["schema71-other-tenant"] {
		t.Error("tenant-only selection returned another tenant's outbox row")
	}
}
