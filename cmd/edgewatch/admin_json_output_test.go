package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestAdminCommandsHonorJSONOutput(t *testing.T) {
	tests := []struct {
		name       string
		args       func(configPath, passwordPath string) []string
		seedAdmin  bool
		token      bool
		wantAction string
	}{
		{
			name: "setup token",
			args: func(configPath, _ string) []string {
				return []string{"admin", "setup-token", "--force", "--config", configPath, "--output", "json"}
			},
			token: true,
		},
		{
			name: "reissue setup token",
			args: func(configPath, _ string) []string {
				return []string{"admin", "reissue-setup-token", "--force", "--config", configPath, "--output", "json"}
			},
			token: true,
		},
		{
			name: "platform setup token",
			args: func(configPath, _ string) []string {
				return []string{"admin", "platform-setup-token", "--config", configPath, "--output", "json"}
			},
			seedAdmin: true,
			token:     true,
		},
		{
			name: "reset password",
			args: func(configPath, passwordPath string) []string {
				return []string{"admin", "reset-password", "--config", configPath, "--password-file", passwordPath, "--output", "json"}
			},
			seedAdmin:  true,
			wantAction: "reset-password",
		},
		{
			name: "disable TOTP",
			args: func(configPath, _ string) []string {
				return []string{"admin", "disable-totp", "--config", configPath, "--output", "json"}
			},
			seedAdmin:  true,
			wantAction: "disable-totp",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			database := filepath.Join(dir, "edgewatch.db")
			s, err := store.Open(database)
			if err != nil {
				t.Fatal(err)
			}
			if tc.seedAdmin {
				now := time.Now().UTC()
				if err := s.SaveAdmin(context.Background(), store.Admin{Username: "admin", DisplayName: "Admin", PasswordHash: "fixture-hash", CreatedAt: now, UpdatedAt: now}); err != nil {
					s.Close()
					t.Fatal(err)
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}

			configPath := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			passwordPath := filepath.Join(dir, "password")
			if err := os.WriteFile(passwordPath, []byte("replacement administrator password\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			stdout, stderr, err := captureCLIOutput(t, func() error { return run(tc.args(configPath, passwordPath)) })
			if err != nil {
				t.Fatalf("admin command failed: %v", err)
			}

			if tc.token {
				var result struct {
					Token            string `json:"token"`
					ExpiresInSeconds int    `json:"expires_in_seconds"`
				}
				if err := json.Unmarshal([]byte(stdout), &result); err != nil {
					t.Fatalf("admin command did not write one JSON token result: %v", err)
				}
				if result.Token == "" || result.ExpiresInSeconds != int((15*time.Minute).Seconds()) {
					t.Fatal("admin command returned an incomplete JSON token result")
				}
				if strings.Contains(stderr, result.Token) {
					t.Fatal("admin command wrote its setup token to stderr")
				}
				return
			}

			var result struct {
				Username string `json:"username"`
				Scope    string `json:"scope"`
				Role     string `json:"role"`
				Action   string `json:"action"`
			}
			if err := json.Unmarshal([]byte(stdout), &result); err != nil {
				t.Fatalf("admin command did not write one JSON recovery result: %v", err)
			}
			if result.Username != "admin" || result.Scope != "unit default" || result.Role != store.RoleAdministrator || result.Action != tc.wantAction {
				t.Fatalf("admin recovery JSON fields do not describe the requested action")
			}
		})
	}
}

func TestAdminCommandsRetainTextOutput(t *testing.T) {
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
	stdout, stderr, err := captureCLIOutput(t, func() error {
		return run([]string{"admin", "setup-token", "--force", "--config", configPath, "--output", "text"})
	})
	if err != nil {
		t.Fatalf("setup-token text command failed: %v", err)
	}
	if !strings.HasPrefix(stdout, "EdgeWatch setup token (valid for 15 minutes): ") {
		t.Fatalf("setup-token text output = %q", stdout)
	}
	if strings.Contains(stderr, strings.TrimSpace(strings.TrimPrefix(stdout, "EdgeWatch setup token (valid for 15 minutes): "))) {
		t.Fatal("setup token appeared on stderr")
	}

	adminStore, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := adminStore.SaveAdmin(context.Background(), store.Admin{Username: "admin", DisplayName: "Admin", PasswordHash: "fixture-hash", CreatedAt: now, UpdatedAt: now}); err != nil {
		adminStore.Close()
		t.Fatal(err)
	}
	if err := adminStore.Close(); err != nil {
		t.Fatal(err)
	}
	stdout, _, err = captureCLIOutput(t, func() error {
		return run([]string{"admin", "disable-totp", "--config", configPath, "--output", "text"})
	})
	if err != nil {
		t.Fatalf("disable-totp text command failed: %v", err)
	}
	if stdout != "user \"admin\" (unit default, administrator)\n" {
		t.Fatalf("disable-totp text output = %q", stdout)
	}
}
