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
	yaml := `version: 1
database: ` + filepath.Join(dir, "db.sqlite") + `
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
	if cfg.Retention.Value() != 90*24*time.Hour {
		t.Fatalf("retention %s", cfg.Retention.Value())
	}
	if cfg.Jobs[0].Baseline.Samples != 1 || !cfg.Jobs[0].RunsOnStart() {
		t.Fatal("defaults not applied")
	}
	if err := os.WriteFile(path, []byte(strings.Replace(yaml, "tcp:", "unknown: true\n    tcp:", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestNotificationEnvironment(t *testing.T) {
	t.Setenv("EDGEWATCH_TEST_URL", "generic://localhost/example")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `version: 1
database: ` + filepath.Join(dir, "db.sqlite") + `
notifications:
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
}
