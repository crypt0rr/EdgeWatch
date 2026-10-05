package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestMigration31TerminalizesLegacyExhaustedDeliveries(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "schema30.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`CREATE TABLE outbox (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 destination TEXT NOT NULL,
 payload_json BLOB NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 next_at TEXT NOT NULL,
 sent_at TEXT,
 last_error TEXT NOT NULL DEFAULT '',
 claim_token TEXT NOT NULL DEFAULT '',
 claim_until TEXT NOT NULL DEFAULT '',
 UNIQUE(destination,payload_json)
);
PRAGMA user_version=30;`); err != nil {
		t.Fatalf("create schema 30 outbox: %v", err)
	}
	oldRetry := time.Now().UTC().Add(-21 * 24 * time.Hour).Format(time.RFC3339Nano)
	for _, row := range []struct {
		destination string
		attempts    int
		nextAt      string
		sentAt      any
	}{
		{destination: "exhausted", attempts: 8, nextAt: oldRetry},
		{destination: "still-retrying", attempts: 7, nextAt: oldRetry},
		{destination: "already-sent", attempts: 8, nextAt: oldRetry, sentAt: oldRetry},
		{destination: "missing-schedule", attempts: 8},
	} {
		if _, err := db.Exec(`INSERT INTO outbox(destination,payload_json,attempts,next_at,sent_at) VALUES(?,?,?,?,?)`,
			row.destination, []byte(`{}`), row.attempts, row.nextAt, row.sentAt); err != nil {
			t.Fatalf("insert %s: %v", row.destination, err)
		}
	}

	if err := runMigration(context.Background(), db, 31, migration31Statements(), false); err != nil {
		t.Fatalf("run schema 31: %v", err)
	}
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 31 {
		t.Fatalf("schema version = %d, %v; want 31", version, err)
	}
	for _, check := range []struct {
		destination string
		wantMarked  bool
	}{
		{destination: "exhausted", wantMarked: true},
		{destination: "still-retrying"},
		{destination: "already-sent"},
		{destination: "missing-schedule", wantMarked: true},
	} {
		var terminalAt string
		if err := db.QueryRow(`SELECT terminal_at FROM outbox WHERE destination=?`, check.destination).Scan(&terminalAt); err != nil {
			t.Fatalf("read %s terminal state: %v", check.destination, err)
		}
		if (terminalAt != "") != check.wantMarked {
			t.Errorf("%s terminal_at = %q; want marked=%t", check.destination, terminalAt, check.wantMarked)
		}
	}
}
