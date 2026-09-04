package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("443, 1-3,2")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{1, 2, 3, 443}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for _, value := range []string{"", "0", "65536", "5-2", "ssh", "1-2-3"} {
		if _, err := ParsePorts(value); err == nil {
			t.Errorf("expected %q to fail", value)
		}
	}
}

func TestLoadDefaultsAndStrictFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `database: ` + filepath.Join(dir, "db.sqlite") + `
retention: 90d
jobs:
  - name: public
    schedule: "0 */6 * * *"
    targets: ["192.0.2.1", "example.com"]
    tcp:
      ports: "1-65535"
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 1 {
		t.Fatalf("version default %d", cfg.Version)
	}
	if cfg.Web.Listen != "127.0.0.1:8080" {
		t.Fatalf("web listener default %q", cfg.Web.Listen)
	}
	if cfg.Retention.Value() != 90*24*time.Hour {
		t.Fatalf("retention %s", cfg.Retention.Value())
	}
	if cfg.Jobs[0].Baseline.Samples != 1 || !cfg.Jobs[0].AssumesAlive() || !cfg.Jobs[0].RunsOnStart() || cfg.Jobs[0].RunOnStart == nil || cfg.Jobs[0].AssumeAlive == nil {
		t.Fatal("defaults not applied")
	}
	if err := os.WriteFile(path, []byte(strings.Replace(yaml, "tcp:", "assume_alive: false\n    tcp:", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Jobs[0].AssumesAlive() {
		t.Fatal("explicit assume_alive=false was not applied")
	}
	if err := os.WriteFile(path, []byte(strings.Replace(yaml, "tcp:", "unknown: true\n    tcp:", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestWebListenerMustBeLoopback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `database: ` + filepath.Join(dir, "db.sqlite") + `
retention: 90d
web:
  listen: 0.0.0.0:8080
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback validation error, got %v", err)
	}
}

func TestScheduleRejectsEmbeddedTimezonePrefix(t *testing.T) {
	job := NormalizeJob(Job{
		Name:     "prefixed",
		Schedule: "CRON_TZ=UTC 0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.1"},
		TCP:      &Protocol{Ports: "443", Mode: "connect"},
	})
	if err := ValidateJob(job); err == nil || !strings.Contains(err.Error(), "timezone field") {
		t.Fatalf("expected embedded timezone prefix to be rejected, got %v", err)
	}
}

func TestSecurityHashIncludesAssumeAlive(t *testing.T) {
	trueValue, falseValue := true, false
	base := Job{Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1, AssumeAlive: &trueValue, TCP: &Protocol{Ports: "443", Mode: "syn"}}
	changed := base
	changed.AssumeAlive = &falseValue
	if base.SecurityHash() == changed.SecurityHash() {
		t.Fatal("assume_alive change did not alter security hash")
	}
	withoutField := base
	withoutField.AssumeAlive = nil
	if base.SecurityHash() != withoutField.SecurityHash() {
		t.Fatal("omitted assume_alive does not resolve to the default")
	}
}

func TestNotificationEnvironment(t *testing.T) {
	t.Setenv("EDGEWATCH_TEST_URL", "generic://localhost/example")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `version: 1
database: ` + filepath.Join(dir, "db.sqlite") + `
web:
  auth_key_file: /run/secrets/edgewatch-auth-key
notifications:
  encryption_key_file: /run/secrets/edgewatch-notification-key
  urls: ["${EDGEWATCH_TEST_URL}"]
jobs:
  - name: test
    schedule: "0 0 * * *"
    targets: ["192.0.2.1"]
    tcp: {ports: "443"}
`
	os.WriteFile(path, []byte(yaml), 0o600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Notifications.URLs[0] != "generic://localhost/example" {
		t.Fatal("environment not expanded")
	}
	if cfg.Notifications.EncryptionKeyFile != "/run/secrets/edgewatch-notification-key" {
		t.Fatalf("encryption key file not retained: %q", cfg.Notifications.EncryptionKeyFile)
	}
	if cfg.Web.AuthKeyFile != "/run/secrets/edgewatch-auth-key" {
		t.Fatalf("auth key file not retained: %q", cfg.Web.AuthKeyFile)
	}
}
