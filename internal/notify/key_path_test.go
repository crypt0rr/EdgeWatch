package notify

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// The default notification key belongs next to the database file for every
// accepted DSN form, mirroring TestSQLiteArtifactPathNormalizesPlainAndURIForms
// in the store package. A file: URI must never place the key under the
// process working directory.
func TestDefaultNotificationKeyFollowsNormalizedDatabasePath(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	base := t.TempDir()
	tests := []struct {
		name string
		dsn  func(dir string) string
		file string
	}{
		{name: "plain path", file: "plain.db", dsn: func(dir string) string { return filepath.Join(dir, "plain.db") }},
		{name: "plain path query", file: "plain.db", dsn: func(dir string) string { return filepath.Join(dir, "plain.db") + "?mode=rwc&_busy_timeout=5000" }},
		{name: "file uri query", file: "uri.db", dsn: func(dir string) string { return "file:" + filepath.Join(dir, "uri.db") + "?mode=rwc" }},
		{name: "localhost uri", file: "local.db", dsn: func(dir string) string { return "file://localhost" + filepath.Join(dir, "local.db") }},
		{name: "encoded filename", file: "literal%2F.db", dsn: func(dir string) string {
			return "file:" + strings.ReplaceAll(filepath.Join(dir, "literal%2F.db"), "%", "%25") + "?mode=rwc"
		}},
	}
	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := filepath.Join(base, "data", string(rune('a'+i)))
			dsn := test.dsn(dir)
			db, err := store.Open(dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := os.Stat(filepath.Join(dir, test.file)); err != nil {
				t.Fatalf("database file was not created beside the expected key directory: %v", err)
			}
			want := filepath.Join(dir, "notification.key")
			notifier, err := New(db, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := notifier.CreateManaged(context.Background(), "Ops", "generic://127.0.0.1:9/ops?disabletls=yes&template=json", true); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(want)
			if err != nil {
				t.Fatalf("notification key was not created next to the database: %v", err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("notification key mode = %v, want 0600", info.Mode().Perm())
			}
			if got := DefaultKeyPath(dsn); got != want {
				t.Fatalf("DefaultKeyPath(%q) = %q, want %q", dsn, got, want)
			}
		})
	}
	entries, err := os.ReadDir(work)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("files were created under the working directory: %v", names)
	}
}

func TestDefaultNotificationKeyPathIgnoresMemoryDatabases(t *testing.T) {
	for _, dsn := range []string{"", ":memory:", ":memory:?cache=shared", "file::memory:?cache=shared", "file:shared?mode=memory&cache=shared"} {
		if got := DefaultKeyPath(dsn); got != "" {
			t.Fatalf("memory database %q selected notification key path %q", dsn, got)
		}
	}
	db, err := store.Open("file:notify-key-memory?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	notifier, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if notifier.keyPath != "" {
		t.Fatalf("memory store selected notification key path %q", notifier.keyPath)
	}
}
