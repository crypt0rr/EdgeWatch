package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const maxSQLiteInt64 = int64(^uint64(0) >> 1)

// ReserveSSEEventIDs reserves a contiguous, durable range of SSE identifiers.
// The cursor is advanced in the same writer transaction that reads the
// durable event high-water mark, so a restarted process starts after both
// persisted events and every range reserved by a previous process. Unused
// identifiers at shutdown are intentionally left as gaps.
func (s *Store) ReserveSSEEventIDs(ctx context.Context, count uint64) (uint64, uint64, error) {
	return s.reserveSSEEventIDs(ctx, count, 0)
}

// ReserveSSEEventIDsAfter is the cursor-aware variant used when an in-memory
// server has already emitted a replay marker beyond its reserved range (for
// example after a client reconnects with a future Last-Event-ID). The durable
// cursor is advanced past that marker before another range is handed out.
func (s *Store) ReserveSSEEventIDsAfter(ctx context.Context, count, minimum uint64) (uint64, uint64, error) {
	return s.reserveSSEEventIDs(ctx, count, minimum)
}

func (s *Store) reserveSSEEventIDs(ctx context.Context, count, minimum uint64) (uint64, uint64, error) {
	if s == nil || s.DB == nil {
		return 0, 0, errors.New("store is unavailable")
	}
	if count == 0 {
		return 0, 0, errors.New("SSE event range must not be empty")
	}
	if count > uint64(maxSQLiteInt64) {
		return 0, 0, errors.New("SSE event range is too large")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var maxEvent, cursor int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id),0) FROM events`).Scan(&maxEvent); err != nil {
		return 0, 0, err
	}
	err = tx.QueryRowContext(ctx, `SELECT next_id FROM sse_event_cursor WHERE id=1`).Scan(&cursor)
	if errors.Is(err, sql.ErrNoRows) {
		cursor = 0
	} else if err != nil {
		return 0, 0, err
	}
	if maxEvent < 0 {
		maxEvent = 0
	}
	if cursor < 0 {
		cursor = 0
	}
	base := maxEvent
	if cursor > base {
		base = cursor
	}
	if minimum > uint64(maxSQLiteInt64) {
		return 0, 0, errors.New("SSE event cursor exhausted")
	}
	if minimum > uint64(base) {
		base = int64(minimum)
	}
	width := int64(count)
	if base > maxSQLiteInt64-width {
		return 0, 0, fmt.Errorf("SSE event cursor exhausted")
	}
	start, end := base+1, base+width
	if _, err := tx.ExecContext(ctx, `INSERT INTO sse_event_cursor(id,next_id) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET next_id=excluded.next_id`, end); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return uint64(start), uint64(end), nil
}
