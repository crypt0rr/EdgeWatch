package scanner

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
)

func testNaabuOptions() config.NaabuOptions {
	options := config.NaabuOptions{ScanType: "connect", Rate: 1000, Workers: 25, Retries: 3, TimeoutMS: 1000, WarmUpSeconds: 2, AddressBatchSize: 16}
	config.ApplyNaabuDefaultsForScanner(&options)
	return options
}

func writeNaabuFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "naabu")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunNaabuSuccessParsesJSONAndReportsLiveness(t *testing.T) {
	path := writeNaabuFixture(t, "printf '%s\\n' '{\"ip\":\"192.0.2.1\",\"port\":443,\"protocol\":\"tcp\",\"mac_address\":\"aa:bb\"}' >&1\nprintf '%s\\n' 'discovery complete' >&2\n")
	n := NewWithNaabu("missing-nmap", path)
	var reports []invocationProgress
	results, stderr, err := n.runNaabu(context.Background(), testNaabuOptions(), nil, []string{"192.0.2.1"}, true, func(progress invocationProgress) {
		reports = append(reports, progress)
	})
	if err != nil {
		t.Fatalf("runNaabu success = %v (stderr %q)", err, stderr)
	}
	if len(results) != 1 || results[0].IP != "192.0.2.1" || results[0].Port != 443 || results[0].MacAddress != "aa:bb" {
		t.Fatalf("parsed results = %#v", results)
	}
	if !strings.Contains(stderr, "discovery complete") {
		t.Fatalf("stderr = %q", stderr)
	}
	if len(reports) == 0 || reports[len(reports)-1].Alive {
		t.Fatalf("liveness reports = %#v", reports)
	}
	foundOutput := false
	for _, report := range reports {
		if strings.Contains(report.Output, "discovery complete") {
			foundOutput = true
		}
	}
	if !foundOutput {
		t.Fatalf("diagnostic output was not reported: %#v", reports)
	}
}

func TestRunNaabuRejectsInvalidProfileAndStartFailures(t *testing.T) {
	n := NewWithNaabu("missing-nmap", writeNaabuFixture(t, "exit 0\n"))
	if _, _, err := n.runNaabu(context.Background(), testNaabuOptions(), []string{"--script"}, []string{"192.0.2.1"}, true); err == nil || !IsConfigurationError(err) {
		t.Fatalf("invalid profile error = %v", err)
	}

	n.NaabuPath = filepath.Join(t.TempDir(), "does-not-exist")
	if _, _, err := n.runNaabu(context.Background(), testNaabuOptions(), nil, []string{"192.0.2.1"}, true); err == nil {
		t.Fatal("missing Naabu executable unexpectedly succeeded")
	}
	// An empty path uses the fixed image path rather than the ambient PATH.
	n.NaabuPath = ""
	if _, _, err := n.runNaabu(context.Background(), testNaabuOptions(), nil, []string{"192.0.2.1"}, true); err == nil {
		t.Fatal("empty Naabu path unexpectedly found an ambient executable")
	}
}

func TestRunNaabuProcessAndJSONFailures(t *testing.T) {
	n := NewWithNaabu("missing-nmap", writeNaabuFixture(t, "printf '%s\\n' 'not-json'\n"))
	if _, _, err := n.runNaabu(context.Background(), testNaabuOptions(), nil, []string{"192.0.2.1"}, true); err == nil || !strings.Contains(err.Error(), "parse naabu JSON") {
		t.Fatalf("malformed JSON error = %v", err)
	}

	n.NaabuPath = writeNaabuFixture(t, "printf '%s\\n' 'scanner failed' >&2\nexit 7\n")
	if _, stderr, err := n.runNaabu(context.Background(), testNaabuOptions(), nil, []string{"192.0.2.1"}, true); err == nil || !strings.Contains(stderr, "scanner failed") {
		t.Fatalf("process failure = %v (stderr %q)", err, stderr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	n.NaabuPath = writeNaabuFixture(t, "sleep 1\n")
	if _, _, err := n.runNaabu(ctx, testNaabuOptions(), nil, []string{"192.0.2.1"}, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v", err)
	}
}

func TestRunNaabuDiagnosticOutputLimitFailsSafely(t *testing.T) {
	// Use a shell loop instead of allocating a large string in the test
	// process. The scanner's bounded stderr writer should terminate the child
	// and return a diagnostic-limit error.
	n := NewWithNaabu("missing-nmap", writeNaabuFixture(t, "while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\n' >&2; done\n"))
	_, stderr, err := n.runNaabu(context.Background(), testNaabuOptions(), nil, []string{"192.0.2.1"}, true)
	if err == nil || !strings.Contains(err.Error(), "diagnostic output exceeded") {
		t.Fatalf("diagnostic limit error = %v (stderr bytes %d)", err, len(stderr))
	}
}

func TestNaabuDiscoveryValidationAndPartialResults(t *testing.T) {
	validTarget := resolvedTarget{Name: "192.0.2.1", Addresses: []string{"192.0.2.1"}}
	job := config.NormalizeJob(config.Job{
		Name: "discovery", Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Naabu: &config.NaabuOptions{ScanType: "connect"}},
	})
	n := NewWithNaabu("missing-nmap", writeNaabuFixture(t, "exit 0\n"))
	if _, err := n.scanNaabuDiscoveryResolved(context.Background(), config.Job{}, []resolvedTarget{validTarget}, nil); err == nil || !IsConfigurationError(err) {
		t.Fatalf("missing TCP discovery error = %v", err)
	}
	if _, err := n.scanNaabuDiscoveryResolved(context.Background(), job, []resolvedTarget{{Name: "empty"}}, nil); err == nil || !strings.Contains(err.Error(), "no effective targets") {
		t.Fatalf("empty target discovery error = %v", err)
	}
	invalidOptions := job
	invalidOptions.TCP.Naabu.Rate = 100_001
	if _, err := n.scanNaabuDiscoveryResolved(context.Background(), invalidOptions, []resolvedTarget{validTarget}, nil); err == nil || !strings.Contains(err.Error(), "rate") {
		t.Fatalf("invalid options discovery error = %v", err)
	}
	job.TCP.Naabu.Rate = 1000
	if _, err := n.scanNaabuDiscoveryResolved(context.Background(), job, []resolvedTarget{validTarget}, nil); err != nil {
		// The fixture above is intentionally empty: no discoveries are still a
		// successful full-range result, exercising the zero-port path.
		t.Fatalf("empty JSONL discovery = %v", err)
	}

	falseAlive := job
	falseAlive.AssumeAlive = boolPtr(false)
	if _, err := n.scanNaabuDiscoveryResolved(context.Background(), falseAlive, []resolvedTarget{validTarget}, nil); err == nil || !strings.Contains(err.Error(), "cannot use host discovery") {
		t.Fatalf("connect host discovery error = %v", err)
	}

	for _, test := range []struct {
		name string
		line string
		want string
	}{
		{name: "invalid address", line: `{"ip":"not-an-ip","port":22}`, want: "invalid address"},
		{name: "unexpected address", line: `{"ip":"192.0.2.2","port":22}`, want: "unexpected address"},
		{name: "invalid port", line: `{"ip":"192.0.2.1","port":0}`, want: "invalid port"},
		{name: "non tcp", line: `{"ip":"192.0.2.1","port":22,"protocol":"udp"}`, want: "non-TCP protocol"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeNaabuFixture(t, "printf '%s\\n' '"+test.line+"'\n")
			scanner := NewWithNaabu("missing-nmap", path)
			_, err := scanner.scanNaabuDiscoveryResolved(context.Background(), job, []resolvedTarget{validTarget}, nil)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("discovery error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestNaabuPipelineResolvedReportsEmptyDiscoveryAndUDPFallback(t *testing.T) {
	targets := []resolvedTarget{
		{Name: "edge.example", ConfiguredTarget: "edge.example", Addresses: []string{"192.0.2.2", "192.0.2.1"}, Aggregate: true, Hostname: true},
	}
	job := config.NormalizeJob(config.Job{
		Name: "empty-pipeline", Targets: []string{"edge.example"}, MaxExpandedHosts: 2,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Naabu: &config.NaabuOptions{ScanType: "connect", AddressBatchSize: 1}},
	})
	n := NewWithNaabu("missing-nmap", writeNaabuFixture(t, "exit 0\n"))
	var progress []Progress
	snapshot, err := n.scanNaabuPipelineResolved(context.Background(), job, targets, func(update Progress) { progress = append(progress, update) })
	if err != nil {
		t.Fatalf("empty pipeline = %v", err)
	}
	if len(snapshot.Hosts) != 2 || len(snapshot.Units) != 1 || len(snapshot.Units[0].Addresses) != 2 {
		t.Fatalf("empty pipeline snapshot = %#v", snapshot)
	}
	if len(progress) == 0 || progress[len(progress)-1].Phase != "complete" {
		t.Fatalf("pipeline progress = %#v", progress)
	}
	for _, host := range snapshot.Hosts {
		if host.Status != "unknown" || host.StatusReason != "scan-complete" || len(host.Protocols) != 1 || host.Protocols[0].ScannedPortCount != 65535 {
			t.Fatalf("empty discovery host = %#v", host)
		}
	}

	noTCP, err := n.scanNaabuPipelineResolved(context.Background(), config.Job{}, targets, nil)
	if err != nil || len(noTCP.Units) != 0 || len(noTCP.Hosts) != 0 {
		t.Fatalf("no-TCP pipeline fallback = %#v, %v", noTCP, err)
	}
}

func TestNaabuPipelineBudgetAllowsEnrichmentAtLimit(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "nmap-ran")
	naabuPath := filepath.Join(dir, "naabu")
	if err := os.WriteFile(naabuPath, []byte("#!/bin/sh\nprintf '%s\\n' '{\"ip\":\"192.0.2.1\",\"port\":22,\"protocol\":\"tcp\"}'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	nmapPath := filepath.Join(dir, "nmap")
	if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\ntouch "+marker+"\nprintf '%s' '"+sampleXML+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := NewWithNaabu(nmapPath, naabuPath)
	job := config.NormalizeJob(config.Job{
		Name: "budget-at-limit", Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{ScanType: "connect"}},
	})
	var checks [][2]int64
	snapshot, err := n.ScanWithProgressBudget(context.Background(), job, nil, func(discovery, enrichment int64) error {
		checks = append(checks, [2]int64{discovery, enrichment})
		return nil
	})
	if err != nil {
		t.Fatalf("budgeted pipeline at limit = %v", err)
	}
	if len(snapshot.Units) != 1 || len(checks) != 1 || checks[0] != [2]int64{65535, 1} {
		t.Fatalf("budget checks = %#v, snapshot units = %#v", checks, snapshot.Units)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("Nmap enrichment was not invoked at the budget limit: %v", err)
	}
}

func TestNaabuPipelineBudgetRejectsEnrichmentBeforeNmap(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "nmap-ran")
	naabuPath := filepath.Join(dir, "naabu")
	naabuScript := "#!/bin/sh\nprintf '%s\\n' '{\"ip\":\"192.0.2.1\",\"port\":22,\"protocol\":\"tcp\"}' '{\"ip\":\"192.0.2.2\",\"port\":22,\"protocol\":\"tcp\"}'\n"
	if err := os.WriteFile(naabuPath, []byte(naabuScript), 0o700); err != nil {
		t.Fatal(err)
	}
	nmapPath := filepath.Join(dir, "nmap")
	if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\ntouch "+marker+"\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := NewWithNaabu(nmapPath, naabuPath)
	n.Resolver = fakeResolver{ips: []net.IP{net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.1")}}
	job := config.NormalizeJob(config.Job{
		Name: "budget-over", Targets: []string{"edge.example"}, MaxExpandedHosts: 2,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{ScanType: "connect"}},
	})
	budgetErr := errors.New("enrichment budget exceeded")
	var checks [][2]int64
	_, err := n.ScanWithProgressBudget(context.Background(), job, nil, func(discovery, enrichment int64) error {
		checks = append(checks, [2]int64{discovery, enrichment})
		if enrichment > 1 {
			return budgetErr
		}
		return nil
	})
	if !errors.Is(err, budgetErr) {
		t.Fatalf("over-budget pipeline error = %v", err)
	}
	if len(checks) != 1 || checks[0] != [2]int64{2 * 65535, 2} {
		t.Fatalf("over-budget checks = %#v", checks)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("Nmap enrichment started despite budget rejection (stat error %v)", statErr)
	}
}

func boolPtr(value bool) *bool { return &value }
