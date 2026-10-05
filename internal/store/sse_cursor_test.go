package store

import (
	"context"
	"testing"
)

func TestReserveSSEEventIDsSurvivesRestartAndFollowsDurableEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := freshTestDatabasePath(t)
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	start, end, err := db.System().ReserveSSEEventIDs(ctx, 4)
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
	nextStart, nextEnd, err := reopened.System().ReserveSSEEventIDs(ctx, 2)
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

func TestStoreSSECursorReservesGlobalRanges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestStore(t)
	cursor := db.SSECursor()

	start, end, err := cursor.Reserve(ctx, 2)
	if err != nil || start != 1 || end != 2 {
		t.Fatalf("first cursor range = %d-%d, %v; want 1-2", start, end, err)
	}
	start, end, err = cursor.ReserveAfter(ctx, 3, 10)
	if err != nil || start != 11 || end != 13 {
		t.Fatalf("range after future marker = %d-%d, %v; want 11-13", start, end, err)
	}

	maxEventID, err := cursor.MaxEventID(ctx)
	if err != nil || maxEventID != 0 {
		t.Fatalf("event high-water mark = %d, %v; want 0 because reservations are not events", maxEventID, err)
	}
	var nextID int64
	if err := db.DB.QueryRowContext(ctx, `SELECT next_id FROM sse_event_cursor WHERE id=1`).Scan(&nextID); err != nil {
		t.Fatal(err)
	}
	if nextID != 13 {
		t.Fatalf("durable next ID = %d, want 13", nextID)
	}
}
