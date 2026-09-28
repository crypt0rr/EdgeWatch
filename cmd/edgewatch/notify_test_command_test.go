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
	"time"

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
			if _, err := notifier.Tenant(s.Tenant(store.DefaultTenantScope())).CreateManagedWithAudit(ctx, "Ops", "generic://127.0.0.1:9/ops?disabletls=yes", true, store.AuditEntry{}); err != nil {
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
			if summary["tested"] != 0 || summary["failed"] != 0 || summary["locked"] != 1 || summary["deployment_locked"] != 1 {
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

// The notification key is one for the whole deployment, so notify test
// confirms it for every unit and the platform: it fails while an enabled
// web-managed destination of any owner is locked, whichever unit --tenant
// selects for the test messages, and reports that only as a count. With the
// right key it succeeds, and the test messages still go only to the
// selected unit's destinations.
func TestRunNotifyTestChecksTheKeyOfEveryUnitAndThePlatform(t *testing.T) {
	for _, owner := range []string{"unit", "platform"} {
		t.Run(owner, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			database := filepath.Join(dir, "edgewatch.db")
			s, err := store.Open(database)
			if err != nil {
				t.Fatal(err)
			}
			stamp := time.Now().UTC().Format(time.RFC3339Nano)
			if _, err := s.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Other','other',?,?)`, otherTenantID, stamp, stamp); err != nil {
				s.Close()
				t.Fatal(err)
			}
			notifier, err := notify.New(s, nil)
			if err != nil {
				s.Close()
				t.Fatal(err)
			}
			// The destination is never contacted: the default unit, which the
			// test messages go to, has no destination, and --tenant other is
			// tested only while the key is wrong.
			switch owner {
			case "unit":
				scope, err := s.TenantScopeByID(ctx, otherTenantID)
				if err == nil {
					_, err = notifier.Tenant(s.Tenant(scope)).CreateManagedWithAudit(ctx, "Other", "generic://127.0.0.1:9/other?disabletls=yes", true, store.AuditEntry{})
				}
				if err != nil {
					s.Close()
					t.Fatal(err)
				}
			case "platform":
				const platformAdmin = "00000000-0000-0000-0000-00000000fa01"
				if _, err := s.DB.ExecContext(ctx, `INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,enabled,created_at,updated_at) VALUES(?,NULL,'platform','platform',?,'hash',1,?,?)`, platformAdmin, store.RolePlatformAdmin, stamp, stamp); err != nil {
					s.Close()
					t.Fatal(err)
				}
				if _, err := notifier.Platform(s.Platform()).CreateManagedWithAudit(ctx, "Platform", "generic://127.0.0.1:9/platform?disabletls=yes", true, store.AuditEntry{ActorUserID: platformAdmin}); err != nil {
					s.Close()
					t.Fatal(err)
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			keyPath := filepath.Join(dir, "notification.key")
			original, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			wrong := make([]byte, 32)
			if _, err := rand.Read(wrong); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(wrong)), 0o600); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			notifyTest := func(args ...string) (map[string]int, error) {
				t.Helper()
				stdout, _, runErr := captureCLIOutput(t, func() error {
					return run(append([]string{"notify", "test", "--config", configPath, "--output", "json"}, args...))
				})
				if strings.Contains(stdout, "generic://") || (runErr != nil && strings.Contains(runErr.Error(), "generic://")) {
					t.Fatalf("notify test %v leaked a destination URL: %q, %v", args, stdout, runErr)
				}
				var summary map[string]int
				if err := json.Unmarshal([]byte(stdout), &summary); err != nil {
					t.Fatalf("notify test %v output %q is not a JSON summary: %v", args, stdout, err)
				}
				return summary, runErr
			}

			for _, args := range [][]string{nil, {"--tenant", "other"}} {
				summary, err := notifyTest(args...)
				if !errors.Is(err, notify.ErrManagedNotificationLocked) {
					t.Fatalf("notify test %v with the wrong key = %v, want a locked-destination failure", args, err)
				}
				locked := 0
				if owner == "unit" && len(args) > 0 {
					locked = 1
				}
				if summary["tested"] != 0 || summary["failed"] != 0 || summary["locked"] != locked || summary["deployment_locked"] != 1 {
					t.Fatalf("notify test %v summary = %v, want %d locked in the unit and 1 in the deployment", args, summary, locked)
				}
			}

			if err := os.WriteFile(keyPath, original, 0o600); err != nil {
				t.Fatal(err)
			}
			summary, err := notifyTest()
			if err != nil {
				t.Fatalf("notify test with the restored key: %v", err)
			}
			if summary["tested"] != 0 || summary["locked"] != 0 || summary["deployment_locked"] != 0 {
				t.Fatalf("notify test summary with the restored key = %v, want nothing tested or locked", summary)
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
	if len(summary) != 4 || summary["tested"] != 0 || summary["failed"] != 0 || summary["locked"] != 0 || summary["deployment_locked"] != 0 {
		t.Fatalf("empty notify test summary = %v", summary)
	}
}
