package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func nmapProfileWithNSE(script string, args map[string]string) ScannerProfile {
	return ScannerProfile{Engine: EngineNmap, NSEProfile: script, NSEArgs: args}
}

func TestNewScannerProfilesSetOnlyTheirScriptsOwnArguments(t *testing.T) {
	t.Parallel()
	for script, args := range map[string]map[string]string{
		"banner":        {"banner.ports": "common", "banner.timeout": "5s"},
		"http-headers":  {"http-headers.path": "index.html", "http-headers.useget": "1"},
		"http-title":    {"http-title.url": "index.html"},
		"ssh-hostkey":   {"ssh_hostkey": "sha256 md5"},
		"ssl-cert":      nil,
		"dns-recursion": nil,
	} {
		if err := ValidateNewScannerProfile(nmapProfileWithNSE(script, args)); err != nil {
			t.Errorf("%s with its own arguments %v: %v", script, args, err)
		}
	}
	for name, test := range map[string]struct {
		profile ScannerProfile
		want    string
	}{
		"a library argument": {nmapProfileWithNSE("banner", map[string]string{"newtargets": "1"}), `"newtargets" is not an argument of banner; use banner.ports, banner.timeout`},
		"another script's":   {nmapProfileWithNSE("banner", map[string]string{"http-title.url": "index.html"}), `"http-title.url" is not an argument of banner`},
		"a short name":       {nmapProfileWithNSE("banner", map[string]string{"timeout": "5s"}), `"timeout" is not an argument of banner`},
		"a file argument":    {nmapProfileWithNSE("ssh-hostkey", map[string]string{"ssh-hostkey.known-hosts": "known_hosts"}), `"ssh-hostkey.known-hosts" is not an argument of ssh-hostkey; use ssh_hostkey`},
		"a script without":   {nmapProfileWithNSE("ssl-cert", map[string]string{"tls.servername": "example.com"}), "is not an argument of ssl-cert, which takes none"},
		"a comma":            {nmapProfileWithNSE("banner", map[string]string{"banner.timeout": "5s,newtargets"}), `"banner.timeout" contains a comma or a quote`},
		"a quote":            {nmapProfileWithNSE("http-title", map[string]string{"http-title.url": `'index.html`}), "contains a comma or a quote"},
		"a double quote":     {nmapProfileWithNSE("http-title", map[string]string{"http-title.url": `"index.html`}), "contains a comma or a quote"},
		// The command contract still applies first.
		"an unsafe value": {nmapProfileWithNSE("banner", map[string]string{"banner.timeout": "@file"}), "contains unsafe characters"},
	} {
		err := ValidateNewScannerProfile(test.profile)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: %v, want %q", name, err, test.want)
		}
		var field *FieldValidationError
		if !errors.As(err, &field) || field.Field != "nse_args" {
			t.Errorf("%s: error %v is not about nse_args", name, err)
		}
	}
}

// A revision saved before the arguments were limited keeps validating, so the
// jobs pinned to it keep scanning, and the daemon names what it passes.
func TestExistingScannerProfilesWithOtherNSEArgumentsStillValidate(t *testing.T) {
	t.Parallel()
	legacy := nmapProfileWithNSE("banner", map[string]string{"timeout": "5s", "newtargets": "1", "banner.ports": "common"})
	if err := ValidateScannerProfile(legacy); err != nil {
		t.Fatalf("an existing revision no longer validates: %v", err)
	}
	if err := ValidateNewScannerProfile(legacy); err == nil {
		t.Fatal("a changed profile kept another script's arguments")
	}
	if got := NSEArgumentsOutsideScript(legacy.NSEProfile, legacy.NSEArgs); !reflect.DeepEqual(got, []string{"newtargets", "timeout"}) {
		t.Fatalf("arguments outside the script = %q", got)
	}
	if got := NSEArgumentsOutsideScript("banner", map[string]string{"banner.ports": "common"}); got != nil {
		t.Fatalf("own arguments reported = %q", got)
	}
	// The built-in profiles set none.
	for _, profile := range []ScannerProfile{BuiltinNaabuProfile(), BuiltinNmapProfile()} {
		if err := ValidateNewScannerProfile(profile); err != nil {
			t.Fatalf("built-in profile: %v", err)
		}
	}
}

// A job's max_expanded_hosts keeps its range, so an upgrade changes neither
// a job nor its hash; scanner.max_job_hosts caps the scans instead.
func TestMaxExpandedHostsKeepsItsRange(t *testing.T) {
	t.Parallel()
	job := func(hosts int) Job {
		return Job{Name: "wide", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"10.0.0.0/24"}, MaxExpandedHosts: hosts, TCP: &Protocol{Ports: "22", Mode: "connect"}}
	}
	if err := ValidateJob(job(1_000_000)); err != nil {
		t.Fatalf("a job allowing 1000000 hosts = %v", err)
	}
	var field *FieldValidationError
	if err := ValidateJob(job(1_000_001)); !errors.As(err, &field) || field.Field != "max_expanded_hosts" {
		t.Fatalf("a job beyond the range = %v", err)
	}
}

func TestScannerMaxJobHostsIsADeploymentSetting(t *testing.T) {
	t.Parallel()
	load := func(setting string) (*Config, error) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		yaml := "database: " + filepath.Join(dir, "db.sqlite") + "\nscanner:\n  sandbox: auto\n" + setting
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		return Load(path)
	}
	cfg, err := load("")
	if err != nil || cfg.Scanner.MaxJobHostsValue() != DefaultMaxJobHosts {
		t.Fatalf("omitted scanner.max_job_hosts = %v, %v", cfg, err)
	}
	cfg, err = load("  max_job_hosts: 262144\n")
	if err != nil || cfg.Scanner.MaxJobHostsValue() != 262_144 {
		t.Fatalf("scanner.max_job_hosts = %v, %v", cfg, err)
	}
	for _, value := range []string{"0", "-1", "1000001"} {
		if _, err := load("  max_job_hosts: " + value + "\n"); err == nil || !strings.Contains(err.Error(), "scanner.max_job_hosts must be between 1 and 1000000") {
			t.Errorf("scanner.max_job_hosts %s = %v", value, err)
		}
	}
}
