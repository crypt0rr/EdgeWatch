package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The metrics endpoint is off by default. web.metrics.enabled needs an
// absolute web.metrics.token_file, and a token file without enabled is
// refused rather than ignored.
func TestMetricsConfiguration(t *testing.T) {
	base := Config{Version: 1, Database: "db", Retention: Duration(24 * time.Hour), Scheduler: Scheduler{MaxConcurrent: 1}, Web: Web{Listen: "127.0.0.1:8080"}}
	if err := base.ValidateDeployment(); err != nil || base.Web.Metrics.Enabled {
		t.Fatalf("default metrics = %+v, %v", base.Web.Metrics, err)
	}
	for _, check := range []struct {
		metrics WebMetrics
		err     string
	}{
		{WebMetrics{Enabled: true, TokenFile: "/run/secrets/metrics-token"}, ""},
		{WebMetrics{Enabled: true}, "web.metrics.enabled requires web.metrics.token_file"},
		{WebMetrics{Enabled: true, TokenFile: "metrics-token"}, "web.metrics.token_file must be an absolute path"},
		{WebMetrics{TokenFile: "/run/secrets/metrics-token"}, "web.metrics.token_file requires web.metrics.enabled: true"},
	} {
		cfg := base
		cfg.Web.Metrics = check.metrics
		err := cfg.ValidateDeployment()
		if check.err == "" && err != nil {
			t.Errorf("%+v rejected: %v", check.metrics, err)
		}
		if check.err != "" && (err == nil || !strings.Contains(err.Error(), check.err)) {
			t.Errorf("%+v = %v, want %q", check.metrics, err, check.err)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("database: "+filepath.Join(dir, "edgewatch.db")+"\nretention: 24h\nweb:\n  metrics:\n    enabled: true\n    token_file: /run/secrets/metrics-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Web.Metrics.Enabled || cfg.Web.Metrics.TokenFile != "/run/secrets/metrics-token" {
		t.Fatalf("loaded metrics = %+v", cfg.Web.Metrics)
	}
	if err := os.WriteFile(path, []byte("database: "+filepath.Join(dir, "edgewatch.db")+"\nretention: 24h\nweb:\n  metrics:\n    token: inline\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("an unknown metrics key was accepted")
	}
}

// ReadMetricsToken accepts an owner-only file with one printable token and
// refuses anything else without repeating the token.
func TestReadMetricsToken(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	token := strings.Repeat("a1", MinMetricsTokenBytes/2)
	for _, check := range []struct{ name, content string }{
		{"plain", token},
		{"newline", token + "\n"},
		{"crlf", token + "\r\n"},
	} {
		got, err := ReadMetricsToken(write(check.name, check.content, 0o400))
		if err != nil || got != token {
			t.Errorf("%s: token = %q, %v", check.name, got, err)
		}
	}
	short := strings.Repeat("s", MinMetricsTokenBytes-1)
	for _, check := range []struct {
		path, want string
	}{
		{"", "no file is configured"},
		{filepath.Join(dir, "missing"), "does not exist"},
		{filepath.Join(write("parent", token, 0o600), "child"), "metrics token file is invalid"},
		{dir, "not a regular file"},
		{write("shared", token, 0o640), "group and other users"},
		{write("short", short, 0o600), "the token must be"},
		{write("long", strings.Repeat("l", MaxMetricsTokenBytes+1), 0o600), "the token must be"},
		{write("huge", strings.Repeat("h", MaxMetricsTokenBytes+10), 0o600), "at most"},
		{write("spaces", strings.Repeat("x", 20)+" "+strings.Repeat("y", 20), 0o600), "printable ASCII"},
		{write("unicode", strings.Repeat("é", MinMetricsTokenBytes), 0o600), "printable ASCII"},
	} {
		_, err := ReadMetricsToken(check.path)
		if !errors.Is(err, ErrMetricsTokenInvalid) || !strings.Contains(err.Error(), check.want) {
			t.Errorf("%q = %v, want %q", check.path, err, check.want)
		}
		if err != nil && (strings.Contains(err.Error(), short) || strings.Contains(err.Error(), token)) {
			t.Errorf("%q: the error repeats the token: %v", check.path, err)
		}
	}
}
