package config

import (
	"encoding/json"
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
	if !cfg.RDAPEnabled() || cfg.Enrichment.RDAP.Enabled == nil {
		t.Fatal("RDAP omission did not default to enabled")
	}
	if !cfg.UpdatesEnabled() || cfg.Updates.Enabled == nil {
		t.Fatal("updates omission did not default to enabled")
	}
	if cfg.Retention.Value() != 90*24*time.Hour {
		t.Fatalf("retention %s", cfg.Retention.Value())
	}
	if cfg.Scheduler.MaxProbeCount != DefaultMaxProbeCount {
		t.Fatalf("probe budget default %d", cfg.Scheduler.MaxProbeCount)
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
	if err := os.WriteFile(path, []byte(strings.Replace(yaml, "retention: 90d", "retention: 90d\nupdates:\n  enabled: false", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path)
	if err != nil || cfg.UpdatesEnabled() {
		t.Fatalf("explicit update check disable was not applied: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(yaml, "retention: 90d", "retention: 90d\nenrichment:\n  rdap:\n    enabled: false", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path)
	if err != nil || cfg.RDAPEnabled() {
		t.Fatalf("explicit RDAP disable was not applied: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(yaml, "tcp:", "unknown: true\n    tcp:", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestLoadKeepsInvalidLegacyJobsInactive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `database: ` + filepath.Join(dir, "db.sqlite") + `
retention: 90d
jobs:
  - name: old-job
    schedule: "not a cron schedule"
    targets: []
    tcp:
      ports: "65536"
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("invalid inactive job prevented deployment load: %v", err)
	}
	if len(cfg.Jobs) != 1 || cfg.Jobs[0].Name != "old-job" {
		t.Fatalf("legacy jobs were not retained as metadata: %#v", cfg.Jobs)
	}
}

func TestLoadRejectsTrailingYAMLDocument(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `database: ` + filepath.Join(dir, "db.sqlite") + `
---
retention: 90d
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "exactly one YAML document") {
		t.Fatalf("expected duplicate-document error, got %v", err)
	}
}

func TestLoadForAdminSkipsMonitorValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `database: ` + filepath.Join(dir, "db.sqlite") + `
web:
  listen: 0.0.0.0:8080
notifications:
  urls: ["not-a-shoutrrr-url"]
jobs:
  - name: old-job
    schedule: "not a cron schedule"
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadForAdmin(path); err != nil {
		t.Fatalf("admin loader was coupled to monitor validation: %v", err)
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

func TestResumeWindowDefaultsAndExecutionHash(t *testing.T) {
	job := NormalizeJob(Job{Name: "resume", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &Protocol{Ports: "1", Mode: "syn"}})
	if job.ResumeWindowValue() != 8*24*time.Hour {
		t.Fatalf("resume window default = %s", job.ResumeWindowValue())
	}
	changed := job
	changed.Timing = "fast"
	if job.ExecutionHash() == changed.ExecutionHash() {
		t.Fatal("timing change did not alter execution hash")
	}
	if job.SecurityHash() != changed.SecurityHash() {
		t.Fatal("timing change unexpectedly altered security hash")
	}
	changed.Timeout = Duration(2 * time.Hour)
	if job.ExecutionHash() == changed.ExecutionHash() {
		t.Fatal("timeout change did not alter execution hash")
	}
	changed.ResumeWindow = Duration(31 * 24 * time.Hour)
	if err := ValidateJob(changed); err == nil || !strings.Contains(err.Error(), "resume_window") {
		t.Fatalf("invalid resume window accepted: %v", err)
	}
}

func TestCanonicalTargetsRejectEquivalentForms(t *testing.T) {
	for _, targets := range [][]string{
		{"192.168.1.1/24", "192.168.1.0/24"},
		{"192.168.1.1", "192.168.1.1/32"},
		{"2001:0db8:0:0:0:0:0:1", "2001:db8::1"},
		{"Router.Example", "router.example"},
	} {
		job := NormalizeJob(Job{Name: "duplicate", Schedule: "0 * * * *", Timezone: "UTC", Targets: targets, TCP: &Protocol{Ports: "443", Mode: "connect"}})
		if err := ValidateJob(job); err == nil {
			t.Fatalf("equivalent targets were accepted: %#v (normalized=%#v)", targets, job.Targets)
		}
	}
}

func TestNormalizeJobCanonicalizesTargets(t *testing.T) {
	job := NormalizeJob(Job{Targets: []string{"  192.168.1.1/24 ", "2001:0db8:0:0:0:0:0:1", "Router.Example"}})
	want := []string{"192.168.1.0/24", "2001:db8::1", "router.example"}
	if !reflect.DeepEqual(job.Targets, want) {
		t.Fatalf("canonical targets = %#v, want %#v", job.Targets, want)
	}
}

func TestNormalizeJobCanonicalizesNotificationDestinations(t *testing.T) {
	job := NormalizeJob(Job{NotificationDestinations: []string{" managed:b ", "file:a", "managed:b", ""}})
	want := []string{"file:a", "managed:b"}
	if !reflect.DeepEqual(job.NotificationDestinations, want) {
		t.Fatalf("notification destinations = %#v, want %#v", job.NotificationDestinations, want)
	}
	empty := NormalizeJob(Job{NotificationDestinations: []string{}})
	if empty.NotificationDestinations == nil {
		t.Fatal("explicit empty notification selection became nil")
	}
	legacy := NormalizeJob(Job{})
	if legacy.NotificationDestinations != nil {
		t.Fatalf("omitted notification selection = %#v, want nil", legacy.NotificationDestinations)
	}
}

func TestNotificationDestinationsJSONPreservesSilentSelection(t *testing.T) {
	legacy, err := json.Marshal(Job{})
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := json.Marshal(Job{NotificationDestinations: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(legacy), `"notification_destinations":null`) {
		t.Fatalf("legacy notification selection was not represented as null: %s", legacy)
	}
	if !strings.Contains(string(explicit), `"notification_destinations":[]`) {
		t.Fatalf("explicit empty notification selection was omitted: %s", explicit)
	}
	var roundTrip Job
	if err := json.Unmarshal(explicit, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.NotificationDestinations == nil || len(roundTrip.NotificationDestinations) != 0 {
		t.Fatalf("explicit empty selection did not survive JSON round trip: %#v", roundTrip.NotificationDestinations)
	}
}

func TestNotificationDestinationsDoNotChangeSecurityHash(t *testing.T) {
	base := NormalizeJob(Job{Targets: []string{"192.0.2.1"}, TCP: &Protocol{Ports: "443", Mode: "syn"}})
	changed := base
	changed.NotificationDestinations = []string{"managed:alerts"}
	if base.SecurityHash() != changed.SecurityHash() {
		t.Fatal("notification routing unexpectedly changed the security hash")
	}
}

func TestEstimateJobWorkIncludesProtocolsAndServiceCost(t *testing.T) {
	job := NormalizeJob(Job{
		Targets: []string{"192.0.2.0/30", "router.example"},
		TCP:     &Protocol{Ports: "22,443", Mode: "connect", ServiceDetection: true},
		UDP:     &Protocol{Ports: "53"},
	})
	estimate, err := EstimateJobWork(job)
	if err != nil {
		t.Fatal(err)
	}
	if estimate.Hosts != 5 || estimate.TCPPorts != 2 || estimate.UDPPorts != 1 || estimate.UnknownDNS != 1 {
		t.Fatalf("unexpected work estimate: %#v", estimate)
	}
	// TCP service detection doubles its probes: 5*(2*2 + 1) = 25.
	if estimate.Probes != 25 || estimate.NmapInvocations == 0 || estimate.EstimatedSeconds == 0 {
		t.Fatalf("unexpected probe estimate: %#v", estimate)
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

func TestNaabuOptionsJSONRoundTripPreservesExplicitZeroValues(t *testing.T) {
	original := NaabuOptions{
		ScanType: "connect", Rate: 1000, Workers: 25, Retries: 0,
		TimeoutMS: 1000, WarmUpSeconds: 0, Verify: false, AddressBatchSize: 16,
		RetriesSet: true, WarmUpSecondsSet: true, VerifySet: true,
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "RetriesSet") || strings.Contains(string(raw), "VerifySet") {
		t.Fatalf("presence markers leaked into JSON: %s", raw)
	}
	var roundTrip NaabuOptions
	if err := json.Unmarshal(raw, &roundTrip); err != nil {
		t.Fatal(err)
	}
	ApplyNaabuDefaultsForScanner(&roundTrip)
	if roundTrip.Retries != 0 || roundTrip.WarmUpSeconds != 0 || roundTrip.Verify {
		t.Fatalf("explicit zero/false values were defaulted: %#v", roundTrip)
	}
	if !roundTrip.RetriesSet || !roundTrip.WarmUpSecondsSet || !roundTrip.VerifySet {
		t.Fatalf("presence markers were not restored: %#v", roundTrip)
	}
}

func TestScannerProfileExecutionAndSecurityHashes(t *testing.T) {
	base := NormalizeJob(Job{Targets: []string{"192.0.2.1"}, TCP: &Protocol{Ports: "443", Mode: "syn", Engine: EngineNmap}})
	pinned := base
	protocol := *base.TCP
	pinned.TCP = &protocol
	pinned.TCP.ProfileID = "profile-a"
	pinned.TCP.ProfileRevision = 2
	if base.SecurityHash() != pinned.SecurityHash() {
		t.Fatal("profile provenance unexpectedly changed the monitored security hash")
	}
	if base.ExecutionHash() == pinned.ExecutionHash() {
		t.Fatal("profile provenance did not change the execution hash")
	}
	changed := base
	changedProtocol := *base.TCP
	changed.TCP = &changedProtocol
	changed.TCP.Engine = EngineNaabuNmap
	changed.TCP.Naabu = &NaabuOptions{ScanType: "syn", Rate: 1000, Workers: 25, Retries: 3, TimeoutMS: 1000, WarmUpSeconds: 2, Verify: true, AddressBatchSize: 16}
	if base.SecurityHash() == changed.SecurityHash() {
		t.Fatal("scanner engine change did not change the security hash")
	}
}

func TestNormalizeNaabuForcesFullTCPRange(t *testing.T) {
	job := NormalizeJob(Job{
		Targets: []string{"192.0.2.1"},
		TCP:     &Protocol{Engine: EngineNaabuNmap, Ports: "22", Naabu: &NaabuOptions{}},
	})
	if job.TCP == nil || job.TCP.Ports != NaabuFullPortExpression {
		t.Fatalf("Naabu port scope = %#v, want %q", job.TCP, NaabuFullPortExpression)
	}
	if _, err := ParsePorts(job.TCP.Ports); err != nil {
		t.Fatalf("normalized Naabu scope is not parseable: %v", err)
	}
}

func TestScannerProfileValidationRejectsUnsafeFlagsAndEngineMismatch(t *testing.T) {
	validNaabu := ScannerProfile{Engine: EngineNaabuNmap, Naabu: BuiltinNaabuProfile().Naabu, NaabuArgs: []string{PlaceholderTargetsFile, PlaceholderPorts, PlaceholderStructuredOutput}}
	for _, value := range []string{"-A", "-O", "-R", "-sC", "--traceroute", "-Pn", "--script=default", "$(touch /tmp/x)", "/bin/sh", "evil.example", "evil", "192.0.2.10", "-", "--"} {
		profile := validNaabu
		profile.NaabuArgs = append([]string(nil), validNaabu.NaabuArgs...)
		profile.NaabuArgs = append(profile.NaabuArgs, value)
		if err := ValidateScannerProfile(profile); err == nil {
			t.Errorf("unsafe scanner argument %q was accepted", value)
		}
	}
	profile := ScannerProfile{Engine: EngineNmap, NaabuArgs: []string{"-rate", "100"}}
	if err := ValidateScannerProfile(profile); err == nil || !strings.Contains(err.Error(), "naabu arguments") {
		t.Fatalf("Nmap profile accepted Naabu arguments: %v", err)
	}
}

func TestScannerProfileValidationAllowsSafeScalarOperands(t *testing.T) {
	profile := ScannerProfile{Engine: EngineNmap, NmapArgs: []string{PlaceholderAddress, PlaceholderPorts, PlaceholderStructuredOutput, "--host-timeout", "5m", "--min-rate", "1000"}}
	if err := ValidateScannerProfile(profile); err != nil {
		t.Fatalf("safe scalar operands were rejected: %v", err)
	}
	for _, value := range []string{"--host-timeout=/etc/passwd", "--min-rate=$(touch /tmp/x)", "--max-rate=evil.example", "--max-rate=foo=bar"} {
		profile.NmapArgs = []string{PlaceholderAddress, PlaceholderPorts, PlaceholderStructuredOutput, value}
		if err := ValidateScannerProfile(profile); err == nil {
			t.Errorf("unsafe inline operand %q was accepted", value)
		}
	}
	for _, args := range [][]string{
		{PlaceholderAddress, PlaceholderPorts, PlaceholderStructuredOutput, "--host-timeout"},
		{PlaceholderAddress, PlaceholderPorts, PlaceholderStructuredOutput, "--host-timeout", PlaceholderAddress},
		{PlaceholderAddress, PlaceholderPorts, PlaceholderStructuredOutput, "--host-timeout", "--min-rate"},
	} {
		profile.NmapArgs = args
		if err := ValidateScannerProfile(profile); err == nil {
			t.Errorf("malformed operand list was accepted: %#v", args)
		}
	}
}

func TestScannerProfileValidationRejectsBareScalarTargets(t *testing.T) {
	profile := ScannerProfile{Engine: EngineNmap, NmapArgs: []string{PlaceholderAddress, PlaceholderPorts, PlaceholderStructuredOutput, "123"}}
	if err := ValidateScannerProfile(profile); err == nil {
		t.Fatal("bare numeric positional argument was accepted as a safe profile value")
	}
	profile.NmapArgs = []string{PlaceholderAddress, PlaceholderPorts, PlaceholderStructuredOutput, "connect"}
	if err := ValidateScannerProfile(profile); err == nil {
		t.Fatal("bare enum positional argument was accepted as a safe profile value")
	}
}

func TestScannerProfileValidationRejectsDuplicatePlaceholders(t *testing.T) {
	profile := ScannerProfile{Engine: EngineNmap, NmapArgs: []string{PlaceholderAddress, PlaceholderAddress, PlaceholderPorts, PlaceholderStructuredOutput}}
	if err := ValidateScannerProfile(profile); err == nil {
		t.Fatal("duplicate address placeholder was accepted")
	}
}

func TestScannerProfileValidationRejectsUnknownFlags(t *testing.T) {
	profile := ScannerProfile{Engine: EngineNmap, NmapArgs: []string{PlaceholderAddress, PlaceholderPorts, PlaceholderStructuredOutput, "--not-an-edgewatch-option"}}
	if err := ValidateScannerProfile(profile); err == nil || !strings.Contains(err.Error(), "approved scanner option") {
		t.Fatalf("unknown scanner flag was accepted: %v", err)
	}
}

func TestScannerProfilePreviewDoesNotDuplicateManagedArguments(t *testing.T) {
	profile := ScannerProfile{
		Engine:    EngineNaabuNmap,
		Naabu:     BuiltinNaabuProfile().Naabu,
		NaabuArgs: []string{PlaceholderTargetsFile, PlaceholderPorts, PlaceholderStructuredOutput, "-verbose"},
		NmapArgs:  []string{PlaceholderAddress, PlaceholderPorts, PlaceholderStructuredOutput, "-v"},
	}
	previews, err := RenderScannerProfilePreview(profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(previews) != 2 {
		t.Fatalf("preview count = %d, want Naabu and Nmap", len(previews))
	}
	if got := strings.Count(strings.Join(previews[0].Args, " "), "/tmp/edgewatch-targets.txt"); got != 1 {
		t.Fatalf("Naabu preview rendered target file %d times: %#v", got, previews[0].Args)
	}
	if got := strings.Count(strings.Join(previews[1].Args, " "), "192.0.2.10"); got != 1 {
		t.Fatalf("Nmap preview rendered address %d times: %#v", got, previews[1].Args)
	}
	countArg := func(args []string, want string) int {
		count := 0
		for _, arg := range args {
			if arg == want {
				count++
			}
		}
		return count
	}
	if got := countArg(previews[0].Args, "-p"); got != 1 {
		t.Fatalf("Naabu preview rendered managed port scope %d times: %#v", got, previews[0].Args)
	}
	if got := countArg(previews[1].Args, "-oX"); got != 1 {
		t.Fatalf("Nmap preview rendered structured output %d times: %#v", got, previews[1].Args)
	}
}
