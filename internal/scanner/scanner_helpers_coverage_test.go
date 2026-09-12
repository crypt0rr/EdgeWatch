package scanner

import (
	"reflect"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestScannerArgumentAndOrderingHelpers(t *testing.T) {
	if got := familyForBatch(nil); got != 4 {
		t.Fatalf("empty family = %d", got)
	}
	if got := familyForBatch([]string{"192.0.2.1"}); got != 4 {
		t.Fatalf("IPv4 family = %d", got)
	}
	if got := familyForBatch([]string{"2001:db8::1"}); got != 6 {
		t.Fatalf("IPv6 family = %d", got)
	}

	units := unitsFromMap(map[string]model.Unit{
		"b": {Target: "z", Protocol: "udp"},
		"a": {Target: "a", Protocol: "tcp"},
		"c": {Target: "a", Protocol: "udp"},
	})
	if got := []string{units[0].Target + "/" + units[0].Protocol, units[1].Target + "/" + units[1].Protocol, units[2].Target + "/" + units[2].Protocol}; !reflect.DeepEqual(got, []string{"a/tcp", "a/udp", "z/udp"}) {
		t.Fatalf("units were not sorted: %v", got)
	}
	if got := unitsFromMap(nil); got == nil || len(got) != 0 {
		t.Fatalf("nil unit map = %#v", got)
	}

	pc := config.Protocol{NSEProfile: "http-title", NSEArgs: map[string]string{"z": "last", "a": "first"}}
	args := appendNSEArgs([]string{"-n"}, pc)
	if strings.Join(args, " ") != "-n --script http-title --script-args a=first,z=last" {
		t.Fatalf("NSE args = %v", args)
	}
	if got := appendNSEArgs([]string{"-n"}, config.Protocol{}); !reflect.DeepEqual(got, []string{"-n"}) {
		t.Fatalf("empty NSE args changed command: %v", got)
	}
	if got := appendNSEArgs([]string{"-n"}, config.Protocol{NSEProfile: "banner"}); !reflect.DeepEqual(got, []string{"-n", "--script", "banner"}) {
		t.Fatalf("NSE profile without args = %v", got)
	}

	values := []string{config.PlaceholderAddress, config.PlaceholderAddresses, config.PlaceholderAddressFamily, config.PlaceholderHostDiscovery, config.PlaceholderScanType, config.PlaceholderPorts, config.PlaceholderStructuredOutput, config.PlaceholderServiceDetection, config.PlaceholderNSE, config.PlaceholderTargetsFile, "--verbose"}
	if got := appendTemplateArgs([]string{"-n"}, values); !reflect.DeepEqual(got, []string{"-n", "--verbose"}) {
		t.Fatalf("template placeholders were not omitted: %v", got)
	}
	for value, want := range map[string]string{"conservative": "-T2", "fast": "-T4", "balanced": "-T3"} {
		if got := timingArg(value); got != want {
			t.Errorf("timing %q = %q, want %q", value, got, want)
		}
	}
	for value, want := range map[string]int{"confirmed": 3, "discovered": 2, "unconfirmed": 1, "": 0, "other": 0} {
		if got := verificationRank(value); got != want {
			t.Errorf("verification rank %q = %d, want %d", value, got, want)
		}
	}
	for _, tc := range []struct {
		protocol string
		pc       config.Protocol
		want     string
	}{
		{"udp", config.Protocol{Mode: "syn"}, "-sU"},
		{"tcp", config.Protocol{Mode: "connect"}, "-sT"},
		{"tcp", config.Protocol{Mode: "syn"}, "-sS"},
	} {
		if got := nmapScanTypeArgs(tc.protocol, tc.pc); len(got) != 1 || got[0] != tc.want {
			t.Errorf("scan type %q/%#v = %v", tc.protocol, tc.pc, got)
		}
	}
	for phase, want := range map[string]string{"discovery": "tcp discovery", "pipeline": "tcp pipeline", "udp": "udp"} {
		if got := phaseLabel(phase); got != want {
			t.Errorf("phase label %q = %q, want %q", phase, got, want)
		}
	}
	// Capability detection is intentionally environment-specific; invoking it
	// still exercises the /proc parsing path without assuming the test runner's
	// capabilities.
	_ = New("nmap").NaabuSYNSupported()
}

func TestRenderNmapTemplateCoversManagedBranches(t *testing.T) {
	pc := config.Protocol{Ports: "22,443", Mode: "connect", ServiceDetection: true, NSEProfile: "ssl-cert", NSEArgs: map[string]string{"name": "value"}}
	template := []string{
		"--verbose", config.PlaceholderAddresses, config.PlaceholderAddressFamily,
		config.PlaceholderHostDiscovery, config.PlaceholderScanType, config.PlaceholderPorts,
		config.PlaceholderStructuredOutput, config.PlaceholderServiceDetection, config.PlaceholderNSE,
		config.PlaceholderTargetsFile,
	}
	args := renderNmapTemplate(template, 6, "tcp", pc, true, []string{"2001:db8::1", "2001:db8::2"})
	joined := strings.Join(args, " ")
	for _, expected := range []string{"--verbose", "2001:db8::1", "2001:db8::2", "-6", "-Pn", "-sT", "-p 22,443", "-oX -", "-sV", "--script ssl-cert", "name=value"} {
		if !strings.Contains(joined, expected) {
			t.Errorf("rendered template missing %q: %v", expected, args)
		}
	}
	if strings.Contains(joined, config.PlaceholderTargetsFile) {
		t.Fatal("Naabu target placeholder leaked into Nmap command")
	}
	withoutAddress := renderNmapTemplate([]string{"--verbose"}, 4, "tcp", config.Protocol{}, false, []string{"192.0.2.1"})
	if len(withoutAddress) != 2 || withoutAddress[1] != "192.0.2.1" {
		t.Fatalf("implicit address append = %v", withoutAddress)
	}
	noAlive := renderNmapTemplate([]string{config.PlaceholderHostDiscovery}, 4, "tcp", config.Protocol{}, false, nil)
	if len(noAlive) != 0 {
		t.Fatalf("false host-discovery placeholder emitted args: %v", noAlive)
	}
}

func TestMaterializeNaabuDiscoveryHostsIsIdempotent(t *testing.T) {
	targets := []resolvedTarget{{Name: "edge.example", ConfiguredTarget: "edge.example", Addresses: []string{"192.0.2.1"}, Hostname: true}}
	job := config.Job{Targets: []string{"edge.example"}, TCP: &config.Protocol{Engine: config.EngineNaabuNmap, ServiceDetection: true, Naabu: &config.NaabuOptions{ScanType: "connect"}}}
	existing := map[string]model.HostObservation{"192.0.2.1": {
		Address: "192.0.2.1", Protocols: []model.ProtocolObservation{{Protocol: "udp", ScanType: "nmap"}},
	}}
	first := materializeNaabuDiscoveryHosts(targets, []string{"192.0.2.1"}, map[string]map[int]bool{"192.0.2.1": {22: true, 443: true}}, existing, *job.TCP.Naabu, job)
	second := materializeNaabuDiscoveryHosts(targets, []string{"192.0.2.1"}, map[string]map[int]bool{"192.0.2.1": {22: true, 443: true}}, first, *job.TCP.Naabu, job)
	host := second["192.0.2.1"]
	if len(host.Protocols) != 2 {
		t.Fatalf("materialized protocols = %#v", host.Protocols)
	}
	var naabu model.ProtocolObservation
	for _, protocol := range host.Protocols {
		if protocol.ScanType == "naabu" {
			naabu = protocol
		}
	}
	if naabu.ScanType != "naabu" {
		t.Fatalf("Naabu protocol missing: %#v", host.Protocols)
	}
	if len(naabu.DiscoveredPorts) != 2 || naabu.ScannedPortCount != 65535 || len(naabu.StateSummaries) != 1 || naabu.StateSummaries[0].Count != 65533 {
		t.Fatalf("Naabu evidence = %#v", naabu)
	}
	if len(host.SourceTargets) != 1 || len(host.DNSNames) != 1 || host.SourceTargets[0] != "edge.example" {
		t.Fatalf("target attribution = %#v", host)
	}
}

func TestScannerOutputSanitizationAndFingerprint(t *testing.T) {
	if got := sanitizeStderr("  short message  "); got != "short message" {
		t.Fatalf("sanitized stderr = %q", got)
	}
	if got := sanitizeStderr(strings.Repeat("x", 600)); !strings.HasPrefix(got, strings.Repeat("x", 500)) || !strings.HasSuffix(got, "…") {
		t.Fatalf("long stderr = %q", got)
	}
	first := commandFingerprint([]string{"-p", "22", "192.0.2.1"})
	second := commandFingerprint([]string{"-p", "22", "198.51.100.2"})
	if first != second || first == "" {
		t.Fatalf("address was not removed from command fingerprint: %q/%q", first, second)
	}
}

func TestNaabuTemplateAndSmallNormalizationHelpers(t *testing.T) {
	options := config.NaabuOptions{ScanType: "syn"}
	for _, assumeAlive := range []bool{true, false} {
		args := renderNaabuTemplate([]string{
			config.PlaceholderTargetsFile,
			config.PlaceholderPorts,
			config.PlaceholderAddressFamily,
			config.PlaceholderHostDiscovery,
			config.PlaceholderScanType,
			config.PlaceholderAddress,
			config.PlaceholderAddresses,
			config.PlaceholderServiceDetection,
			config.PlaceholderNSE,
			"--custom",
		}, "/tmp/targets", options, assumeAlive)
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "-list /tmp/targets") || !strings.Contains(joined, "-p -") || !strings.Contains(joined, "-scan-type s") || !strings.Contains(joined, "--custom") {
			t.Fatalf("Naabu template rendering = %v", args)
		}
		wantDiscovery := "-with-host-discovery"
		if assumeAlive || options.ScanType == "connect" {
			wantDiscovery = "-skip-host-discovery"
		}
		if !strings.Contains(joined, wantDiscovery) {
			t.Fatalf("Naabu host discovery rendering = %v", args)
		}
	}
	if got := naabuArgsWithTemplate(config.NaabuOptions{ScanType: "connect", Rate: 10, Workers: 2, Retries: 1, TimeoutMS: 100, Verify: true}, "/tmp/targets", true, []string{config.PlaceholderTargetsFile, config.PlaceholderPorts, config.PlaceholderStructuredOutput}); !strings.Contains(strings.Join(got, " "), "-skip-host-discovery") {
		t.Fatalf("Naabu template default discovery flag missing: %v", got)
	}
	if got := naabuArgsWithTemplate(config.NaabuOptions{ScanType: "connect", Rate: 10, Workers: 2, Retries: 1, TimeoutMS: 100}, "/tmp/targets", false, nil); !strings.Contains(strings.Join(got, " "), "-skip-host-discovery") || strings.Contains(strings.Join(got, " "), "-with-host-discovery") {
		t.Fatalf("Naabu connect mode must not request host discovery: %v", got)
	}

	if got := dedupeStrings([]string{"a", "a", "b", "b", "c"}); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("dedupeStrings = %v", got)
	}
	values := map[string]string{"key": "value"}
	cloned := cloneStringMap(values)
	cloned["key"] = "changed"
	if values["key"] != "value" || cloneStringMap(nil) != nil {
		t.Fatalf("cloneStringMap did not isolate values: %#v", cloned)
	}
}
