package store

import (
	"context"
	"testing"
)

func TestAuditContextPersistsRequestAndResolvedClient(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()

	ctx := WithAuditContext(context.Background(), "request-123", "198.51.100.10")
	if err := s.AuditEntry(ctx, AuditEntry{Action: "context.test"}); err != nil {
		t.Fatal(err)
	}
	var requestID, sourceIP string
	if err := s.DB.QueryRowContext(context.Background(), `SELECT request_id,source_ip FROM security_audit WHERE action='context.test'`).Scan(&requestID, &sourceIP); err != nil {
		t.Fatal(err)
	}
	if requestID != "request-123" || sourceIP != "198.51.100.10" {
		t.Fatalf("audit context = request %q source %q", requestID, sourceIP)
	}
}

func TestAuditEntryValuesOverrideContext(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()

	ctx := WithAuditContext(context.Background(), "request-context", "198.51.100.10")
	if err := s.AuditEntry(ctx, AuditEntry{Action: "context.override", RequestID: "request-entry", SourceIP: "203.0.113.20"}); err != nil {
		t.Fatal(err)
	}
	var requestID, sourceIP string
	if err := s.DB.QueryRowContext(context.Background(), `SELECT request_id,source_ip FROM security_audit WHERE action='context.override'`).Scan(&requestID, &sourceIP); err != nil {
		t.Fatal(err)
	}
	if requestID != "request-entry" || sourceIP != "203.0.113.20" {
		t.Fatalf("explicit audit values = request %q source %q", requestID, sourceIP)
	}
}

func TestStandaloneAuditPersistsAfterContextCancellation(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()

	base := WithAuditContext(context.Background(), "cancelled-request", "198.51.100.20")
	ctx, cancel := context.WithCancel(base)
	cancel()
	if err := s.Audit(ctx, "cancelled.audit", "standalone audit"); err != nil {
		t.Fatal(err)
	}
	if err := s.AuditEntry(ctx, AuditEntry{Action: "cancelled.audit.entry"}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.DB.QueryContext(context.Background(), `SELECT action,request_id,source_ip FROM security_audit WHERE action LIKE 'cancelled.audit%' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []struct {
		action, requestID, sourceIP string
	}
	for rows.Next() {
		var row struct {
			action, requestID, sourceIP string
		}
		if err := rows.Scan(&row.action, &row.requestID, &row.sourceIP); err != nil {
			t.Fatal(err)
		}
		got = append(got, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("cancelled audit rows = %d, want 2", len(got))
	}
	for _, row := range got {
		if row.requestID != "cancelled-request" || row.sourceIP != "198.51.100.20" {
			t.Fatalf("cancelled audit context = request %q source %q", row.requestID, row.sourceIP)
		}
	}
}
