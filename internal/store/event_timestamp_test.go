package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

func insertRawEvent(t *testing.T, db *sql.DB, jobID, createdAt string) int64 {
	t.Helper()
	result, err := db.ExecContext(context.Background(), `INSERT INTO events(type,job,job_id,scan_id,payload_json,created_at) VALUES(?,?,?,?,?,?)`, "job-silent", "timestamp-test", jobID, "", `{"type":"job-silent"}`, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestEventTimestampNormalizationPreservesOrderingRetentionAndSilence(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	job, err := s.CreateJob(ctx, testJob("event-timestamp-ordering"))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, time.September, 22, 12, 0, 0, 0, time.UTC)
	// RFC3339Nano's variable-width representation sorts the exact-second row
	// ahead of the later half-second row. The canonical representation fixes
	// that while retaining the normal text indexes.
	older := now.Add(-time.Hour).Truncate(time.Second)
	newer := older.Add(500 * time.Millisecond)
	insertRawEvent(t, s.DB, job.ID, older.Format(time.RFC3339Nano))
	newerID := insertRawEvent(t, s.DB, job.ID, newer.Format(time.RFC3339Nano))
	if _, err := s.DB.ExecContext(ctx, `UPDATE timestamp_normalization_state SET complete=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := normalizePersistedTimestampsContext(ctx, s.DB); err != nil {
		t.Fatal(err)
	}

	var firstID int64
	var firstCreated string
	if err := s.DB.QueryRowContext(ctx, `SELECT id,created_at FROM events WHERE job_id=? ORDER BY created_at DESC,id DESC LIMIT 1`, job.ID).Scan(&firstID, &firstCreated); err != nil {
		t.Fatal(err)
	}
	if firstID != newerID || firstCreated != sqliteTimestamp(newer) {
		t.Fatalf("newest event = id %d at %q, want id %d at %q", firstID, firstCreated, newerID, sqliteTimestamp(newer))
	}

	// The fallback silence deduplication path must use that same newest event.
	threshold := 59*time.Minute + 59*time.Second + 750*time.Millisecond
	due, err := s.JobSilenceDue(ctx, job.ID, now.Add(-2*time.Hour), now, threshold)
	if err != nil {
		t.Fatal(err)
	}
	if due {
		t.Fatal("silence watchdog selected the older same-second event")
	}

	stats, err := s.PruneWithStats(ctx, older.Add(250*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Events != 1 {
		t.Fatalf("pruned events = %d, want exactly the older event: %#v", stats.Events, stats)
	}
	var remaining int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE job_id=?`, job.ID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("remaining events = %d, want one", remaining)
	}
}

func TestEventTimestampMigrationRepairsSchema45Rows(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	base := time.Date(2026, time.September, 22, 13, 14, 15, 500000000, time.UTC)
	insertRawEvent(t, s.DB, "legacy-event-job", base.Format(time.RFC3339Nano))
	if _, err := s.DB.ExecContext(ctx, `UPDATE timestamp_normalization_state SET complete=1 WHERE id=1; PRAGMA user_version=45`); err != nil {
		t.Fatal(err)
	}
	if err := migrateContext(ctx, s.DB); err != nil {
		t.Fatal(err)
	}

	var got string
	if err := s.DB.QueryRowContext(ctx, `SELECT created_at FROM events ORDER BY id DESC LIMIT 1`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != sqliteTimestamp(base) {
		t.Fatalf("migrated event timestamp = %q, want %q", got, sqliteTimestamp(base))
	}
	var version int
	if err := s.DB.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
}

func TestEventTimestampWritersUseCanonicalRepresentation(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	guard := regexp.MustCompile(`(?s)INSERT INTO events.{0,500}Format\(time\.RFC3339Nano\)`)
	entries, err := os.ReadDir(filepath.Dir(sourceFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), "_test.go") || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		path := filepath.Join(filepath.Dir(sourceFile), entry.Name())
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if guard.Match(source) {
			t.Fatalf("%s writes an events timestamp with variable-width RFC3339Nano; use sqliteTimestamp", entry.Name())
		}
	}
}
