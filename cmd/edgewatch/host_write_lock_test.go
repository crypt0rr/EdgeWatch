package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// hostWriteLockHold is how long another connection holds the write lock:
// long enough that a command whose transaction read before it asked for the
// lock would have failed at once, and well within busy_timeout.
const hostWriteLockHold = time.Second

// The setup token commands run beside the daemon, which writes to the same
// database, as the browser tests do. While another connection holds the
// write lock for a second, each command waits for it and issues its token,
// instead of failing at once with "database is locked (SQLITE_BUSY)".
func TestSetupTokenCommandsWaitForAConcurrentWriter(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		// administrator seeds the first administrator, which the platform
		// setup token needs and the initial setup token must not find.
		administrator bool
		args          []string
		purpose       string
	}{
		{name: "admin platform-setup-token", administrator: true, args: []string{"admin", "platform-setup-token"}, purpose: store.SetupTokenPurposePlatform},
		{name: "admin setup-token", args: []string{"admin", "setup-token", "--force"}, purpose: store.SetupTokenPurposeInitial},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			database := storetest.FreshPath(t)
			if test.administrator {
				s, err := store.Open(database)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC()
				if err := s.SaveAdmin(ctx, store.Admin{Username: "admin", PasswordHash: "hash", CreatedAt: now, UpdatedAt: now}); err != nil {
					s.Close()
					t.Fatal(err)
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			other, err := sql.Open("sqlite", database)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = other.Close() })
			conn, err := other.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
				t.Fatal(err)
			}
			var releaseOnce sync.Once
			release := func() {
				releaseOnce.Do(func() {
					if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
						t.Error(err)
					}
					_ = conn.Close()
				})
			}
			timer := time.AfterFunc(hostWriteLockHold, release)
			defer func() {
				timer.Stop()
				release()
			}()

			started := time.Now()
			if err := run(append(test.args, "--config", configPath)); err != nil {
				t.Fatalf("%s while another connection writes: %v", test.name, err)
			}
			if waited := time.Since(started); waited < hostWriteLockHold/2 {
				t.Fatalf("%s finished after %v without waiting for the writer", test.name, waited)
			}
			release()
			reader, err := store.OpenReadOnlyExisting(database)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			var purpose string
			if err := reader.DB.QueryRowContext(ctx, `SELECT purpose FROM setup_tokens WHERE id=1`).Scan(&purpose); err != nil || purpose != test.purpose {
				t.Fatalf("setup token purpose = %q, %v; want %s", purpose, err, test.purpose)
			}
		})
	}
}
