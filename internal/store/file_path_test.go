package store

import (
	"path/filepath"
	"testing"
)

// Files kept beside the database, such as the default notification key, are
// derived from FilePath. It must be the normalized database file for every
// open mode, never the DSN in Path.
func TestStoreFilePathIsNormalizedDatabaseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "uri.db")
	writable, err := Open("file://localhost" + path + "?mode=rwc")
	if err != nil {
		t.Fatal(err)
	}
	if got := writable.FilePath(); got != path {
		writable.Close()
		t.Fatalf("writable FilePath = %q, want %q", got, path)
	}
	if err := writable.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenReadOnlyExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reader.FilePath(); got != path {
		reader.Close()
		t.Fatalf("read-only FilePath = %q, want %q", got, path)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	memory, err := Open("file:file-path-memory?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer memory.Close()
	if got := memory.FilePath(); got != "" {
		t.Fatalf("memory FilePath = %q, want empty", got)
	}
	var missing *Store
	if got := missing.FilePath(); got != "" {
		t.Fatalf("nil store FilePath = %q, want empty", got)
	}
}

func TestDatabaseFilePathNormalizesAcceptedDSNs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edgewatch.db")
	for _, dsn := range []string{path, path + "?mode=rwc", "file:" + path + "?mode=rwc", "file://localhost" + path} {
		got, err := DatabaseFilePath(dsn)
		if err != nil || got != path {
			t.Fatalf("DatabaseFilePath(%q) = %q, %v; want %q", dsn, got, err, path)
		}
	}
	for _, dsn := range []string{":memory:", "file::memory:?cache=shared", "file:shared?mode=memory&cache=shared"} {
		if got, err := DatabaseFilePath(dsn); err != nil || got != "" {
			t.Fatalf("DatabaseFilePath(%q) = %q, %v; want no file", dsn, got, err)
		}
	}
	if _, err := DatabaseFilePath(""); err == nil {
		t.Fatal("empty DSN was accepted")
	}
}
