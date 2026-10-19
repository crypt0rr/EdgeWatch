package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestApplyMigrationDDLExecRespectsCancellation(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := applyMigration(ctx, s.DB, schemaVersion+1, []string{`CREATE TABLE migration_context_cancel_probe AS
WITH RECURSIVE sequence(value) AS (
 VALUES(1) UNION ALL SELECT value+1 FROM sequence WHERE value<100000000
) SELECT SUM(value) FROM sequence`})
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled migration DDL = %v; want context deadline", err)
	}
	if elapsed >= time.Second {
		t.Fatalf("cancelled migration DDL returned after %s; want within 1 s", elapsed)
	}
	if got := countRows(t, s.DB, `PRAGMA user_version`); got != schemaVersion {
		t.Fatalf("schema version after cancelled migration = %d; want unchanged %d", got, schemaVersion)
	}
	if got := countRows(t, s.DB, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='migration_context_cancel_probe'`); got != 0 {
		t.Fatalf("cancelled migration left its table behind: count %d", got)
	}
}
