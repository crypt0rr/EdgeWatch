package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestFileStoreUsesReadOnlyPoolForHistoryQueries(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.ReadDB == nil || s.ReadDB == s.DB {
		t.Fatal("file store did not create a separate read pool")
	}
	var queryOnly int
	if err := s.ReadDB.QueryRowContext(context.Background(), `PRAGMA query_only`).Scan(&queryOnly); err != nil {
		t.Fatal(err)
	}
	if queryOnly != 1 {
		t.Fatalf("query_only = %d, want 1", queryOnly)
	}
	if _, err := s.ReadDB.ExecContext(context.Background(), `CREATE TABLE should_not_exist(id INTEGER)`); err == nil {
		t.Fatal("read pool accepted a write")
	}
}

func TestMemoryStoreKeepsSharedWriterConnection(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.ReadDB != nil {
		t.Fatal("memory store should not create an isolated read pool")
	}
}

func TestOpenReadOnlyExistingUsesSQLiteReadOnlyMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edgewatch.db")
	writer, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.DB.ExecContext(context.Background(), `CREATE TABLE probe(id INTEGER)`); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := OpenReadOnlyExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var queryOnly int
	if err := reader.DB.QueryRowContext(context.Background(), `PRAGMA query_only`).Scan(&queryOnly); err != nil {
		t.Fatal(err)
	}
	if queryOnly != 1 {
		t.Fatalf("query_only = %d, want 1", queryOnly)
	}
	if _, err := reader.DB.ExecContext(context.Background(), `INSERT INTO probe(id) VALUES(1)`); err == nil {
		t.Fatal("read-only database accepted a write")
	}
}

func TestHistoryReadsRemainAvailableWhileWriterTransactionIsHeld(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	job, err := s.CreateJob(ctx, testJob("read-isolation"))
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC()
	if err := s.SaveScan(ctx, model.Scan{ID: "read-isolation-scan", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: stamp, FinishedAt: stamp, Status: "success", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{}}); err != nil {
		t.Fatal(err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE jobs SET updated_at=updated_at WHERE id=?`, job.ID); err != nil {
		t.Fatal(err)
	}

	checks := []struct {
		name string
		read func(context.Context) error
	}{
		{name: "job", read: func(ctx context.Context) error { _, err := s.GetJob(ctx, job.ID); return err }},
		{name: "scan summary", read: func(ctx context.Context) error { _, err := s.GetScanSummary(ctx, "read-isolation-scan"); return err }},
		{name: "events", read: func(ctx context.Context) error { _, err := s.ListEventsPage(ctx, job.Job.Name, 50, 0); return err }},
		{name: "incidents", read: func(ctx context.Context) error { _, err := s.ListIncidentsPage(ctx, 50, 0); return err }},
		{name: "public dashboard", read: func(ctx context.Context) error { _, err := s.GetPublicDashboard(ctx); return err }},
		{name: "host inventory", read: func(ctx context.Context) error {
			_, err := s.ListLatestScanHostsPage(ctx, "", "", nil, 50, 0)
			return err
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			readCtx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- check.read(readCtx) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("read failed while writer transaction was held: %v", err)
				}
			case <-readCtx.Done():
				t.Fatalf("read blocked behind writer transaction: %v", readCtx.Err())
			}
		})
	}
}
