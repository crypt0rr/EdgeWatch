package config

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDurationUnmarshalAcceptsDaysAndRejectsMalformedValues(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want time.Duration
	}{
		{name: "fractional days", raw: "1.5d", want: 36 * time.Hour},
		{name: "duration", raw: "2h30m", want: 2*time.Hour + 30*time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			var got Duration
			if err := got.UnmarshalYAML(&yaml.Node{Value: test.raw}); err != nil {
				t.Fatal(err)
			}
			if got.Value() != test.want {
				t.Fatalf("duration = %s, want %s", got.Value(), test.want)
			}
		})
	}
	for _, raw := range []string{"not-a-dayd", "not-a-duration"} {
		var got Duration
		if err := got.UnmarshalYAML(&yaml.Node{Value: raw}); err == nil {
			t.Fatalf("malformed duration %q was accepted", raw)
		}
	}
}

func TestLoadResolvesNotificationFilesAndReportsMissingEnvironment(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "edgewatch.db")
	secretPath := filepath.Join(dir, "notification-urls.txt")
	if err := os.WriteFile(secretPath, []byte("\n# ignored\ngeneric://file-one\n  generic://file-two  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	contents := "database: " + db + "\nretention: 24h\nnotifications:\n  urls: [\"generic://inline\"]\n  urls_file: " + secretPath + "\n"
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Notifications.URLs) != 3 || cfg.Notifications.URLs[1] != "generic://file-one" || cfg.Notifications.URLs[2] != "generic://file-two" {
		t.Fatalf("resolved notification URLs = %#v", cfg.Notifications.URLs)
	}
	if err := os.WriteFile(configPath, []byte("database: "+db+"\nretention: 24h\nnotifications:\n  urls: [\"${MISSING_EDGEWATCH_ENV}\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "MISSING_EDGEWATCH_ENV") {
		t.Fatalf("missing environment variable error = %v", err)
	}
	if err := os.WriteFile(configPath, []byte("database: "+db+"\nretention: 24h\nnotifications:\n  urls_file: /no/such/notification-urls\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "read notification URLs file") {
		t.Fatalf("missing URLs file error = %v", err)
	}
}

func validCoverageJob() Job {
	return NormalizeJob(Job{
		Name:     "coverage",
		Schedule: "0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"192.0.2.1"},
		TCP:      &Protocol{Ports: "1", Mode: "syn"},
	})
}

func TestValidateJobRejectsEveryInvalidField(t *testing.T) {
	base := validCoverageJob()
	cases := []struct {
		name string
		edit func(*Job)
		want string
	}{
		{"name", func(j *Job) { j.Name = "" }, "job names"},
		{"timezone", func(j *Job) { j.Timezone = "Not/AZone" }, "invalid timezone"},
		{"schedule", func(j *Job) { j.Schedule = "not cron" }, "invalid schedule"},
		{"embedded timezone", func(j *Job) { j.Schedule = "TZ=UTC 0 * * * *" }, "timezone field"},
		{"targets", func(j *Job) { j.Targets = nil }, "at least one target"},
		{"protocol", func(j *Job) { j.TCP = nil }, "tcp or udp"},
		{"max hosts", func(j *Job) { j.MaxExpandedHosts = -1 }, "max_expanded_hosts"},
		{"baseline", func(j *Job) { j.Baseline.Samples = 101 }, "baseline samples"},
		{"confirmations", func(j *Job) { j.Change.Confirmations = 101 }, "change confirmations"},
		{"timeout", func(j *Job) { j.Timeout = Duration(500 * time.Millisecond) }, "timeout"},
		{"resume window", func(j *Job) { j.ResumeWindow = Duration(31 * 24 * time.Hour) }, "resume_window"},
		{"timing", func(j *Job) { j.Timing = "turbo" }, "timing"},
		{"target syntax", func(j *Job) { j.Targets = []string{"bad target"} }, "invalid target"},
		{"duplicate target", func(j *Job) { j.Targets = []string{"192.0.2.1", "192.0.2.1"} }, "duplicate target"},
		{"tcp ports", func(j *Job) { j.TCP.Ports = "" }, "ports are required"},
		{"tcp mode", func(j *Job) { j.TCP.Mode = "invalid" }, "tcp mode"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			job := base
			if base.TCP != nil {
				protocol := *base.TCP
				job.TCP = &protocol
			}
			test.edit(&job)
			if err := ValidateJob(job); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want substring %q", err, test.want)
			}
		})
	}

	udp := base
	udp.TCP = nil
	udp.UDP = &Protocol{Ports: "53", Mode: "syn"}
	if err := ValidateJob(udp); err == nil || !strings.Contains(err.Error(), "udp mode") {
		t.Fatalf("UDP mode validation error = %v", err)
	}
	udp.UDP.Mode = ""
	udp.UDP.Ports = "65536"
	if err := ValidateJob(udp); err == nil || !strings.Contains(err.Error(), "port range") {
		t.Fatalf("UDP port validation error = %v", err)
	}
}

func TestValidateChecksDeploymentAndDuplicateJobs(t *testing.T) {
	base := validCoverageJob()
	deployment := func() Config {
		return Config{Version: 1, Database: "db", Retention: Duration(24 * time.Hour), Scheduler: Scheduler{MaxConcurrent: 1, MaxProbeCount: 1}, Web: Web{Listen: "127.0.0.1:8080"}, Jobs: []Job{base}}
	}
	cases := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"version", func(c *Config) { c.Version = 2 }, "unsupported config version"},
		{"database", func(c *Config) { c.Database = "" }, "database path"},
		{"retention", func(c *Config) { c.Retention = Duration(time.Hour) }, "retention"},
		{"concurrency", func(c *Config) { c.Scheduler.MaxConcurrent = 65 }, "max_concurrent"},
		{"probe budget", func(c *Config) { c.Scheduler.MaxProbeCount = 100_000_001 }, "max_probe_count"},
		{"duplicate jobs", func(c *Config) { c.Jobs = []Job{base, base} }, "job names"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			cfg := deployment()
			test.edit(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want substring %q", err, test.want)
			}
		})
	}
	if err := (Config{Version: 1, Database: "db", Retention: Duration(24 * time.Hour), Scheduler: Scheduler{MaxConcurrent: 1, MaxProbeCount: -1}, Web: Web{Listen: "127.0.0.1:8080"}}).ValidateDeployment(); err == nil {
		t.Fatal("negative probe budget was accepted")
	}
	withoutTargets := base
	withoutTargets.Targets = nil
	if err := (Config{Version: 1, Database: "db", Retention: Duration(24 * time.Hour), Scheduler: Scheduler{MaxConcurrent: 1}, Web: Web{Listen: "127.0.0.1:8080"}, Jobs: []Job{withoutTargets}}).Validate(); err == nil || !strings.Contains(err.Error(), "at least one target") {
		t.Fatalf("job validation without targets = %v", err)
	}
}

func TestValidationHelpersAndEstimateOverflow(t *testing.T) {
	for _, listen := range []string{"", "localhost:8080", "127.0.0.1", "127.0.0.1:nope", "127.0.0.1:0", "127.0.0.1:65536"} {
		if err := validateWebListen(listen); err == nil {
			t.Fatalf("invalid listener %q was accepted", listen)
		}
	}
	for _, target := range []string{"", "bad target", "-bad.example", "bad-.example", "bad..example", strings.Repeat("a", 64) + ".example"} {
		if err := validateTarget(target); err == nil {
			t.Fatalf("invalid target %q was accepted", target)
		}
	}
	if err := validateTarget("host-name.example"); err != nil {
		t.Fatalf("valid target rejected: %v", err)
	}
	if got := saturatingAdd(int64(^uint64(0)>>1), 1); got != int64(^uint64(0)>>1) {
		t.Fatalf("saturating add = %d", got)
	}
	if got := saturatingMul(int64(^uint64(0)>>1), 2); got != int64(^uint64(0)>>1) {
		t.Fatalf("saturating multiply = %d", got)
	}
	if networkAddressCount(&net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}) != int64(^uint64(0)>>1) {
		t.Fatal("large network did not saturate")
	}
	large := NormalizeJob(Job{Targets: []string{"2001:db8::/0"}, TCP: &Protocol{Ports: "1-65535", Mode: "syn"}, UDP: &Protocol{Ports: "1-65535", ServiceDetection: true}})
	estimate, err := EstimateJobWork(large)
	if err != nil || estimate.Probes != int64(^uint64(0)>>1) {
		t.Fatalf("large estimate = %#v, %v", estimate, err)
	}
	if _, err := EstimateJobWork(Job{Targets: []string{"192.0.2.1"}, TCP: &Protocol{Ports: "bad", Mode: "syn"}}); err == nil || !strings.Contains(err.Error(), "tcp") {
		t.Fatalf("invalid TCP estimate error = %v", err)
	}
	if _, err := EstimateJobWork(Job{Targets: []string{"192.0.2.1"}, UDP: &Protocol{Ports: "bad"}}); err == nil || !strings.Contains(err.Error(), "udp") {
		t.Fatalf("invalid UDP estimate error = %v", err)
	}
}

func TestLoadForAdminRejectsMalformedVersionAndDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	write := func(contents string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("version: 2\ndatabase: " + filepath.Join(dir, "db") + "\n")
	if _, err := LoadForAdmin(path); err == nil || !strings.Contains(err.Error(), "unsupported config version") {
		t.Fatalf("unsupported admin version error = %v", err)
	}
	write("version: 1\n")
	if cfg, err := LoadForAdmin(path); err != nil || cfg.Database != "/var/lib/edgewatch/edgewatch.db" {
		t.Fatalf("admin defaults = %#v, error = %v", cfg, err)
	}
	write("database: " + filepath.Join(dir, "db") + "\n: [")
	if _, err := LoadForAdmin(path); err == nil {
		t.Fatal("malformed YAML was accepted by the admin loader")
	}
	write("database: " + filepath.Join(dir, "db") + "\n---\nother: value\n")
	if _, err := LoadForAdmin(path); err == nil || !strings.Contains(err.Error(), "exactly one YAML document") {
		t.Fatalf("trailing YAML document error = %v", err)
	}
	if _, err := LoadForAdmin(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("missing admin configuration was accepted")
	}
	write("database: " + filepath.Join(dir, "db") + "\n---\n[")
	if _, err := LoadForAdmin(path); err == nil || !strings.Contains(err.Error(), "read trailing YAML document") {
		t.Fatalf("malformed trailing YAML error = %v", err)
	}
}

func TestConfigArithmeticAndExplicitResumeWindowEdges(t *testing.T) {
	if saturatingMul(0, 10) != 0 || saturatingMul(-1, 10) != 0 || maxInt64(1, 2) != 2 || maxInt64(2, 1) != 2 || minInt64(1, 2) != 1 || minInt64(2, 1) != 1 {
		t.Fatal("arithmetic helper boundaries returned unexpected values")
	}
	job := Job{ResumeWindow: Duration(2 * time.Hour)}
	if got := job.ResumeWindowValue(); got != 2*time.Hour {
		t.Fatalf("explicit resume window = %s", got)
	}
	if got := (Job{}).ResumeWindowValue(); got != 8*24*time.Hour {
		t.Fatalf("zero resume window default = %s", got)
	}
	for _, target := range []string{"bad/name", "bad\\name", "bad\tname", "bad\nname", "éxample.test"} {
		if err := validateTarget(target); err == nil {
			t.Errorf("invalid target %q was accepted", target)
		}
	}
	if _, err := ParsePorts("1-x"); err == nil || !strings.Contains(err.Error(), "invalid port") {
		t.Fatal("malformed range endpoint was accepted")
	}
	if err := (Config{Version: 1, Database: "db", Retention: Duration(24 * time.Hour), Scheduler: Scheduler{MaxConcurrent: 1, MaxProbeCount: 1}, Web: Web{Listen: "127.0.0.1:8080"}, Jobs: []Job{validCoverageJob()}}).Validate(); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
}
