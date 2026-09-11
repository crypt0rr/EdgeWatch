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
