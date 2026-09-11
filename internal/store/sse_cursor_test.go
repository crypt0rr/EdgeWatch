package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestReserveSSEEventIDsSurvivesRestartAndFollowsDurableEvents(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "edgewatch.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	start, end, err := db.ReserveSSEEventIDs(ctx, 4)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if start != 1 || end != 4 {
		db.Close()
		t.Fatalf("first SSE range = %d-%d, want 1-4", start, end)
	}
	if _, err := db.DB.ExecContext(ctx, `INSERT INTO events(type,job,payload_json,created_at) VALUES(?,?,?,datetime('now'))`, "test", "", []byte(`{}`)); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	nextStart, nextEnd, err := reopened.ReserveSSEEventIDs(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if nextStart != end+1 || nextEnd != end+2 {
		t.Fatalf("restart SSE range = %d-%d, want %d-%d", nextStart, nextEnd, end+1, end+2)
	}
	var cursor int64
	if err := reopened.DB.QueryRowContext(ctx, `SELECT next_id FROM sse_event_cursor WHERE id=1`).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != int64(nextEnd) {
		t.Fatalf("durable SSE cursor = %d, want %d", cursor, nextEnd)
	}
}
