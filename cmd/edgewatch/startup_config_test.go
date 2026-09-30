package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

const invalidStartupURL = "not-a-shoutrrr-url"

// startupConfigCase is a configuration that config.Load accepts and that the
// daemon refuses at startup, because a configured key file or notification
// URL is unusable. None of these checks needs the database.
type startupConfigCase struct {
	name string
	// section is the YAML that makes the configuration unusable. It is given
	// the directory of the test and the listen address of the daemon.
	section func(t *testing.T, dir, listen string) string
	// want is the part of the error that names the setting.
	want string
}

func startupConfigCases() []startupConfigCase {
	return []startupConfigCase{
		{name: "missing auth key", want: "web.auth_key_file", section: func(_ *testing.T, dir, listen string) string {
			return fmt.Sprintf("web:\n  listen: %s\n  auth_key_file: %s\n", listen, filepath.Join(dir, "missing-auth.key"))
		}},
		{name: "unsafe auth key", want: "web.auth_key_file", section: func(t *testing.T, dir, listen string) string {
			keyPath := filepath.Join(dir, "secrets", "auth.key")
			writeAuthKeyFile(t, keyPath)
			if err := os.Chmod(keyPath, 0o644); err != nil {
				t.Fatal(err)
			}
			return fmt.Sprintf("web:\n  listen: %s\n  auth_key_file: %s\n", listen, keyPath)
		}},
		{name: "missing notification key", want: "notifications.encryption_key_file", section: func(_ *testing.T, dir, listen string) string {
			return fmt.Sprintf("web:\n  listen: %s\nnotifications:\n  encryption_key_file: %s\n", listen, filepath.Join(dir, "missing-notification.key"))
		}},
		{name: "malformed notification key", want: "notifications.encryption_key_file", section: func(t *testing.T, dir, listen string) string {
			keyPath := filepath.Join(dir, "notification.key")
			if err := os.WriteFile(keyPath, []byte("too short"), 0o600); err != nil {
				t.Fatal(err)
			}
			return fmt.Sprintf("web:\n  listen: %s\nnotifications:\n  encryption_key_file: %s\n", listen, keyPath)
		}},
		{name: "invalid notification URL", want: "notifications.urls", section: func(_ *testing.T, _, listen string) string {
			return fmt.Sprintf("web:\n  listen: %s\nnotifications:\n  urls:\n    - %q\n", listen, invalidStartupURL)
		}},
		{name: "invalid notification URL in urls_file", want: "notifications.urls_file", section: func(t *testing.T, dir, listen string) string {
			urlsFile := filepath.Join(dir, "notification-urls")
			if err := os.WriteFile(urlsFile, []byte(invalidStartupURL+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return fmt.Sprintf("web:\n  listen: %s\nnotifications:\n  urls_file: %s\n", listen, urlsFile)
		}},
	}
}

func writeStartupConfig(t *testing.T, tc startupConfigCase, dir, database, listen string) string {
	t.Helper()
	configPath := filepath.Join(dir, "config.yaml")
	contents := "database: " + database + "\nupdates:\n  enabled: false\nenrichment:\n  rdap:\n    enabled: false\n" + tc.section(t, dir, listen)
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

// config validate reports as invalid every configuration that the daemon
// would refuse at startup without reading the database, with the setting in
// the reason, and exits non-zero. An invalid URL is named by its digest only.
func TestConfigValidateRefusesWhatTheDaemonRefuses(t *testing.T) {
	for _, tc := range startupConfigCases() {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := writeStartupConfig(t, tc, dir, filepath.Join(dir, "edgewatch.db"), "127.0.0.1:8080")
			for _, output := range []string{"json", "text"} {
				stdout, stderr, err := captureCLIOutput(t, func() error {
					return run([]string{"config", "validate", "--config", configPath, "--output", output})
				})
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("config validate --output %s error = %v, want one naming %s", output, err, tc.want)
				}
				var report struct {
					Valid *bool  `json:"valid"`
					Error string `json:"error"`
				}
				if decodeErr := json.Unmarshal([]byte(stdout), &report); decodeErr != nil {
					t.Fatalf("config validate --output %s printed %q: %v", output, stdout, decodeErr)
				}
				if report.Valid == nil || *report.Valid || report.Error != err.Error() {
					t.Fatalf("config validate --output %s printed %q, want \"valid\": false with the reason %q", output, stdout, err)
				}
				if strings.Contains(stdout+stderr+err.Error(), invalidStartupURL) {
					t.Fatalf("config validate revealed the notification URL: stdout=%q stderr=%q err=%v", stdout, stderr, err)
				}
			}
			if _, statErr := os.Stat(filepath.Join(dir, "edgewatch.db")); !os.IsNotExist(statErr) {
				t.Fatalf("config validate created the database (stat err=%v)", statErr)
			}
		})
	}
}

// A configuration that config.Load refuses is reported the same way.
func TestConfigValidateReportsLoadErrors(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+filepath.Join(dir, "edgewatch.db")+"\nretention: 1h\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, err := captureCLIOutput(t, func() error {
		return run([]string{"config", "validate", "--config", configPath, "--output", "json"})
	})
	if err == nil || !strings.Contains(err.Error(), "retention") {
		t.Fatalf("config validate error = %v, want the retention error", err)
	}
	var report map[string]any
	if decodeErr := json.Unmarshal([]byte(stdout), &report); decodeErr != nil || report["valid"] != false || report["error"] != err.Error() {
		t.Fatalf("config validate printed %q (%v), want \"valid\": false with the reason", stdout, decodeErr)
	}
}

// The daemon refuses the same configurations before it opens the database,
// so a refused start never migrates it: the previous release can still open
// the database after a failed upgrade.
func TestDaemonRefusesStartupConfigBeforeMigrating(t *testing.T) {
	for _, tc := range startupConfigCases() {
		t.Run(tc.name, func(t *testing.T) {
			database := storetest.FreshPath(t)
			dir := filepath.Dir(database)
			supported := sqliteUserVersion(t, database)
			// The migration runner accepts the current table shape under an
			// older user_version, as it does for an interrupted upgrade.
			setSQLiteUserVersion(t, database, supported-1)
			configPath := writeStartupConfig(t, tc, dir, database, occupiedLoopbackAddress(t))
			before := snapshotCLIFile(t, database)

			err := run([]string{"daemon", "--config", configPath})
			if err == nil {
				t.Fatal("daemon started with an unusable configuration")
			}
			if got := sqliteUserVersion(t, database); got != supported-1 {
				t.Fatalf("user_version = %d, want %d: the refused daemon migrated the database (error: %v)", got, supported-1, err)
			}
			assertCLIFileUnchanged(t, database, before)
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("daemon error = %v, want one naming %s", err, tc.want)
			}
			if strings.Contains(err.Error(), invalidStartupURL) {
				t.Fatalf("daemon error revealed the notification URL: %v", err)
			}
		})
	}
}
