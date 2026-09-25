package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// A notification test must not report success while an enabled web-managed
// destination cannot be decrypted, for example after restoring the wrong key.
func TestRunNotifyTestFailsWhenManagedDestinationIsLocked(t *testing.T) {
	for _, tc := range []struct {
		name      string
		removeKey bool
	}{
		{name: "wrong key"},
		{name: "missing key", removeKey: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			database := filepath.Join(dir, "edgewatch.db")
			s, err := store.Open(database)
			if err != nil {
				t.Fatal(err)
			}
			notifier, err := notify.New(s, nil)
			if err != nil {
				s.Close()
				t.Fatal(err)
			}
			// The destination is never contacted: it is locked before the test.
			if _, err := notifier.CreateManaged(ctx, "Ops", "generic://127.0.0.1:9/ops?disabletls=yes", true); err != nil {
				s.Close()
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			keyPath := filepath.Join(dir, "notification.key")
			if tc.removeKey {
				if err := os.Remove(keyPath); err != nil {
					t.Fatal(err)
				}
			} else {
				wrong := make([]byte, 32)
				if _, err := rand.Read(wrong); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(wrong)), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			configPath := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			stdout, _, runErr := captureCLIOutput(t, func() error {
				return run([]string{"notify", "test", "--config", configPath, "--output", "json"})
			})
			if !errors.Is(runErr, notify.ErrManagedNotificationLocked) {
				t.Fatalf("notify test error = %v, want a locked-destination failure", runErr)
			}
			var summary map[string]int
			if err := json.Unmarshal([]byte(stdout), &summary); err != nil {
				t.Fatalf("notify test output %q is not a JSON summary: %v", stdout, err)
			}
			if summary["tested"] != 0 || summary["failed"] != 0 || summary["locked"] != 1 {
				t.Fatalf("notify test summary = %v, want one locked and nothing tested", summary)
			}
			if strings.Contains(stdout, "generic://") {
				t.Fatalf("notify test output leaked a destination URL: %q", stdout)
			}

			reader, err := store.OpenReadOnlyExisting(database)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			var actor, detail string
			if err := reader.DB.QueryRowContext(ctx, `SELECT actor_username,detail FROM security_audit WHERE action='notifications.test' ORDER BY id DESC LIMIT 1`).Scan(&actor, &detail); err != nil {
				t.Fatal(err)
			}
			if actor != "host-cli" || detail != "operation=global status=failed" {
				t.Fatalf("notify test audit = actor %q detail %q, want a failed host-cli test", actor, detail)
			}
		})
	}
}

func TestRunNotifyTestPrintsSummaryWhenNothingIsConfigured(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, err := captureCLIOutput(t, func() error {
		return run([]string{"notify", "test", "--config", configPath, "--output", "json"})
	})
	if err != nil {
		t.Fatalf("notify test without destinations: %v", err)
	}
	var summary map[string]int
	if err := json.Unmarshal([]byte(stdout), &summary); err != nil {
		t.Fatalf("notify test output %q is not a JSON summary: %v", stdout, err)
	}
	if len(summary) != 3 || summary["tested"] != 0 || summary["failed"] != 0 || summary["locked"] != 0 {
		t.Fatalf("empty notify test summary = %v", summary)
	}
}
