package store

import (
	"context"
	"path/filepath"
	"testing"
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
