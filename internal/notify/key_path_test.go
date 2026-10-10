package notify

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
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
			if _, err := defaultNotifier(notifier).createManaged(context.Background(), "Ops", "generic://127.0.0.1:9/ops?disabletls=yes&template=json", true, nil); err != nil {
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
	t.Parallel()
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

// CheckKey opens every web-managed destination with the key at a path, paused
// destinations included, without creating a key: the right key opens them
// all, and a missing or other key locks them all.
func TestCheckKeyCountsTheDestinationsTheKeyCannotOpen(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database := storetest.FreshPath(t)
	dir := filepath.Dir(database)
	db, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if destinations, locked, err := CheckKey(ctx, db, filepath.Join(dir, "missing.key")); err != nil || destinations != 0 || locked != 0 {
		t.Fatalf("key check without destinations = %d, %d, %v", destinations, locked, err)
	}
	notifier, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	tenant := notifier.Tenant(db.Tenant(store.DefaultTenantScope()))
	if _, err := tenant.CreateManagedWithAudit(ctx, "Ops", "generic://127.0.0.1:9/ops?disabletls=yes", true, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := tenant.CreateManagedWithAudit(ctx, "Paused", "generic://127.0.0.1:9/paused?disabletls=yes", false, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "notification.key")
	if destinations, locked, err := CheckKey(ctx, db, key); err != nil || destinations != 2 || locked != 0 {
		t.Fatalf("key check with the right key = %d, %d, %v", destinations, locked, err)
	}
	other := filepath.Join(t.TempDir(), "other.key")
	if err := os.WriteFile(other, []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing.key")
	for _, path := range []string{other, missing} {
		if destinations, locked, err := CheckKey(ctx, db, path); err != nil || destinations != 2 || locked != 2 {
			t.Fatalf("key check with %s = %d, %d, %v", filepath.Base(path), destinations, locked, err)
		}
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("the key check created a key: %v", err)
	}
	if _, _, err := CheckKey(ctx, nil, key); err == nil {
		t.Fatal("a key check without a database succeeded")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := CheckKey(canceled, db, key); err == nil {
		t.Fatal("a canceled key check succeeded")
	}
}
