package scanner

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
)

func TestNaabuArgsUseFixedFullRangeAndDiscoveryPolicy(t *testing.T) {
	options := config.NaabuOptions{ScanType: "connect", Rate: 1000, Workers: 25, Retries: 3, TimeoutMS: 1000, WarmUpSeconds: 2, Verify: true}
	withDiscovery := naabuArgs(options, "/tmp/targets", true)
	for _, expected := range []string{"-list", "/tmp/targets", "-p", "-", "-json", "-silent", "-no-stdin", "-disable-update-check", "-scan-type", "c", "-verify", "-skip-host-discovery"} {
		if !slices.Contains(withDiscovery, expected) {
			t.Fatalf("Naabu args omitted %q: %v", expected, withDiscovery)
		}
	}
	if slices.Contains(withDiscovery, "-with-host-discovery") {
		t.Fatalf("connect mode was paired with Naabu host discovery: %v", withDiscovery)
	}
	timeoutIndex := slices.Index(withDiscovery, "-timeout")
	if timeoutIndex < 0 || timeoutIndex+1 >= len(withDiscovery) || withDiscovery[timeoutIndex+1] != "1000ms" {
		t.Fatalf("Naabu timeout must preserve milliseconds: %v", withDiscovery)
	}
	synDiscovery := naabuArgs(config.NaabuOptions{ScanType: "syn", Rate: 1000, Workers: 25, Retries: 3, TimeoutMS: 1000, WarmUpSeconds: 2, Verify: true}, "/tmp/targets", false)
	if !slices.Contains(synDiscovery, "-with-host-discovery") || slices.Contains(synDiscovery, "-skip-host-discovery") {
		t.Fatalf("SYN host-discovery policy was not rendered: %v", synDiscovery)
	}
}

func TestNaabuConnectHostDiscoveryIsRejected(t *testing.T) {
	connect := config.NaabuOptions{ScanType: "connect"}
	if err := validateNaabuInvocation(connect, false, true); err == nil || !strings.Contains(err.Error(), "cannot use host discovery") {
		t.Fatalf("connect plus host discovery error = %v", err)
	}
	if err := validateNaabuInvocation(connect, true, false); err != nil {
		t.Fatalf("connect with assumed-live targets was rejected: %v", err)
	}
	syn := config.NaabuOptions{ScanType: "syn"}
	if err := validateNaabuInvocation(syn, true, false); err == nil || !strings.Contains(err.Error(), "NET_RAW") {
		t.Fatalf("SYN capability error = %v", err)
	}
	if err := validateNaabuInvocation(syn, false, true); err != nil {
		t.Fatalf("SYN with capabilities was rejected: %v", err)
	}
}

func TestNaabuConnectHostDiscoveryFailsBeforeProcessStart(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	naabuPath := filepath.Join(dir, "naabu")
	script := "#!/bin/sh\ntouch " + marker + "\n"
	if err := os.WriteFile(naabuPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	alive := false
	job := config.NormalizeJob(config.Job{
		Name:             "connect-discovery",
		Targets:          []string{"192.0.2.1"},
		AssumeAlive:      &alive,
		MaxExpandedHosts: 1,
		TCP:              &config.Protocol{Engine: config.EngineNaabuNmap, Naabu: &config.NaabuOptions{ScanType: "connect"}},
	})
	_, err := NewWithNaabu("missing-nmap", naabuPath).Scan(context.Background(), job)
	if err == nil || !strings.Contains(err.Error(), "cannot use host discovery") {
		t.Fatalf("connect discovery result = %v", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("Naabu process started despite unsupported mode (stat error %v)", statErr)
	}
}

func TestNaabuConfirmationUsesResolvedConnectMode(t *testing.T) {
	job := config.NormalizeJob(config.Job{TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Naabu: &config.NaabuOptions{ScanType: "connect"}}})
	if job.TCP == nil {
		t.Fatal("missing TCP configuration")
	}
	args := nmapEnrichmentArgs(4, "tcp", *job.TCP, "balanced", true, []string{"192.0.2.1"})
	if !slices.Contains(args, "-sT") || slices.Contains(args, "-sS") {
		t.Fatalf("Naabu confirmation did not use connect mode: %v", args)
	}
	if naabu := naabuArgs(*job.TCP.Naabu, "/tmp/targets", true); !slices.Contains(naabu, "c") {
		t.Fatalf("Naabu discovery did not use connect scan type: %v", naabu)
	}
}

func TestNaabuProfilePlaceholdersRenderManagedArguments(t *testing.T) {
	options := config.NaabuOptions{ScanType: "connect", Rate: 1000, Workers: 25, Retries: 3, TimeoutMS: 1000, WarmUpSeconds: 2, Verify: true}
	template := []string{config.PlaceholderTargetsFile, config.PlaceholderPorts, config.PlaceholderStructuredOutput, config.PlaceholderHostDiscovery, "-verbose"}
	args := naabuArgsWithTemplate(options, "/tmp/targets", false, template)
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "{targets_file}") || strings.Contains(joined, "{ports}") || strings.Contains(joined, "{structured_output}") {
		t.Fatalf("placeholder leaked into Naabu command: %v", args)
	}
	count := func(want string) int {
		var total int
		for _, value := range args {
			if value == want {
				total++
			}
		}
		return total
	}
	if count("-list") != 1 || count("-p") != 1 || count("-json") != 1 || !strings.Contains(joined, "-skip-host-discovery") || strings.Contains(joined, "-with-host-discovery") {
		t.Fatalf("Naabu placeholders were not rendered exactly once: %v", args)
	}
	timeoutIndex := slices.Index(args, "-timeout")
	if timeoutIndex < 0 || timeoutIndex+1 >= len(args) || args[timeoutIndex+1] != "1000ms" {
		t.Fatalf("custom Naabu profile must preserve timeout milliseconds: %v", args)
	}
}

func TestNaabuCustomProfileKeepsHostDiscoveryDefaultWhenOmitted(t *testing.T) {
	options := config.NaabuOptions{ScanType: "connect", Rate: 1000, Workers: 25, Retries: 3, TimeoutMS: 1000, WarmUpSeconds: 2, Verify: true}
	template := []string{config.PlaceholderTargetsFile, config.PlaceholderPorts, config.PlaceholderStructuredOutput}
	args := naabuArgsWithTemplate(options, "/tmp/targets", false, template)
	if !slices.Contains(args, "-skip-host-discovery") {
		t.Fatalf("custom Naabu connect profile omitted safe host-discovery default: %v", args)
	}
	if slices.Contains(args, "-with-host-discovery") {
		t.Fatalf("custom Naabu connect profile unexpectedly requested host discovery: %v", args)
	}
}

func TestParseNaabuJSONRejectsMalformedAndOversizedLines(t *testing.T) {
	if _, err := parseNaabuJSON([]byte(`{"ip":"192.0.2.1","port":22}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := parseNaabuJSON([]byte(`{"ip":`)); err == nil {
		t.Fatal("malformed Naabu JSON was accepted")
	}
	if _, err := parseNaabuJSON([]byte(strings.Repeat("x", 1<<20))); err == nil {
		t.Fatal("oversized Naabu JSON line was accepted")
	}
}

func TestCappedBufferInvokesOnExceededOnce(t *testing.T) {
	calls := 0
	buffer := cappedBuffer{limit: 4, onExceeded: func() { calls++ }}
	if written, err := buffer.Write([]byte("12345")); written != 5 || err == nil {
		t.Fatalf("first capped write = (%d, %v), want all bytes and an error", written, err)
	}
	if buffer.String() != "1234" {
		t.Fatalf("buffer retained %q, want the bounded prefix", buffer.String())
	}
	if _, err := buffer.Write([]byte("6")); err == nil {
		t.Fatal("second capped write unexpectedly succeeded")
	}
	if calls != 1 {
		t.Fatalf("onExceeded called %d times, want once", calls)
	}
}

func TestNaabuPipelineKeepsDiscoveryEvidenceOutOfUnits(t *testing.T) {
	dir := t.TempDir()
	naabuPath := filepath.Join(dir, "naabu")
	if err := os.WriteFile(naabuPath, []byte("#!/bin/sh\nprintf '%s\\n' '{\"ip\":\"192.0.2.1\",\"port\":22,\"protocol\":\"tcp\"}'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	nmapPath := filepath.Join(dir, "nmap")
	if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\nprintf '%s' '"+sampleXML+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := NewWithNaabu(nmapPath, naabuPath)
	job := config.NormalizeJob(config.Job{
		Name: "pipeline", Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Mode: "syn", ServiceDetection: true, Naabu: &config.NaabuOptions{ScanType: "connect", Verify: true}},
	})
	snapshot, err := n.Scan(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Units) != 1 || len(snapshot.Units[0].Ports) != 1 || snapshot.Units[0].Ports[0].Port != 22 {
		t.Fatalf("unexpected authoritative units: %#v", snapshot.Units)
	}
	if len(snapshot.Hosts) != 1 || len(snapshot.Hosts[0].Protocols) != 1 {
		t.Fatalf("unexpected host evidence: %#v", snapshot.Hosts)
	}
	protocol := snapshot.Hosts[0].Protocols[0]
	if len(protocol.DiscoveredPorts) != 1 || protocol.DiscoveredPorts[0].Verification != "discovered" || len(protocol.Ports) != 1 || protocol.Ports[0].Verification != "confirmed" {
		t.Fatalf("discovery/confirmation evidence was not merged: %#v", protocol)
	}
}

func TestNaabuPipelinePreservesDistinctDNSConfirmationPorts(t *testing.T) {
	dir := t.TempDir()
	naabuPath := filepath.Join(dir, "naabu")
	naabuScript := "#!/bin/sh\nprintf '%s\\n' '{\"ip\":\"192.0.2.1\",\"port\":22,\"protocol\":\"tcp\"}' '{\"ip\":\"192.0.2.2\",\"port\":443,\"protocol\":\"tcp\"}'\n"
	if err := os.WriteFile(naabuPath, []byte(naabuScript), 0o700); err != nil {
		t.Fatal(err)
	}
	nmapPath := filepath.Join(dir, "nmap")
	nmapScript := `#!/bin/sh
case "$*" in
  *"-p 22"*) printf '%s' '<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>' ;;
  *"-p 443"*) printf '%s' '<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>' ;;
esac
`
	if err := os.WriteFile(nmapPath, []byte(nmapScript), 0o700); err != nil {
		t.Fatal(err)
	}
	n := NewWithNaabu(nmapPath, naabuPath)
	n.Resolver = fakeResolver{ips: []net.IP{net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.1")}}
	job := config.NormalizeJob(config.Job{
		Name: "dns-pipeline", Targets: []string{"edge.example"}, MaxExpandedHosts: 2,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Mode: "syn", Naabu: &config.NaabuOptions{ScanType: "connect"}},
	})
	snapshot, err := n.Scan(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Units) != 1 || snapshot.Units[0].Target != "edge.example" || len(snapshot.Units[0].Ports) != 2 {
		t.Fatalf("DNS aggregate lost confirmed ports: %#v", snapshot.Units)
	}
	for _, port := range snapshot.Units[0].Ports {
		if port.State != "open" || len(port.Evidence) != 1 {
			t.Fatalf("unexpected aggregate port evidence: %#v", port)
		}
		if port.Port == 22 && port.Evidence[0] != "192.0.2.1" {
			t.Fatalf("port 22 evidence = %#v", port)
		}
		if port.Port == 443 && port.Evidence[0] != "192.0.2.2" {
			t.Fatalf("port 443 evidence = %#v", port)
		}
	}
	if len(snapshot.Hosts) != 2 {
		t.Fatalf("DNS host observations = %#v", snapshot.Hosts)
	}
	for _, host := range snapshot.Hosts {
		if len(host.Protocols) != 1 || len(host.Protocols[0].Ports) != 1 || len(host.Protocols[0].DiscoveredPorts) != 1 {
			t.Fatalf("per-address DNS evidence = %#v", host)
		}
	}
}

func TestNaabuPipelineWithNoDiscoveriesCompletesFullCoverage(t *testing.T) {
	dir := t.TempDir()
	naabuPath := filepath.Join(dir, "naabu")
	if err := os.WriteFile(naabuPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := NewWithNaabu(filepath.Join(dir, "missing-nmap"), naabuPath)
	job := config.NormalizeJob(config.Job{
		Name: "empty", Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{ScanType: "connect"}},
	})
	snapshot, err := n.Scan(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Units) != 1 || len(snapshot.Units[0].Ports) != 0 || len(snapshot.Hosts) != 1 {
		t.Fatalf("empty full-range scan was not successful: %#v", snapshot)
	}
	protocol := snapshot.Hosts[0].Protocols[0]
	if protocol.ScannedPortCount != 65535 || len(protocol.StateSummaries) != 1 || protocol.StateSummaries[0].Count != 65535 {
		t.Fatalf("full-range non-open summary missing: %#v", protocol)
	}
}

func TestNaabuResultAddressNormalization(t *testing.T) {
	if got := normalizeAddress(net.ParseIP("2001:0db8::1").String()); got != "2001:db8::1" {
		t.Fatalf("normalized address = %q", got)
	}
}

func TestNaabuVersionReadsDiagnosticOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "naabu")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s\\n' '[INF] Current Version: 2.6.1' >&2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := NewWithNaabu("missing-nmap", path).NaabuVersion(context.Background()); got != "2.6.1" {
		t.Fatalf("Naabu version = %q, want 2.6.1", got)
	}
}

func TestRunNaabuReportsOutputAndHeartbeat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "naabu")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s\\n' 'working' >&2\nsleep 2\nprintf '%s\\n' '{\"ip\":\"192.0.2.1\",\"port\":22,\"protocol\":\"tcp\"}'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := NewWithNaabu("missing-nmap", path)
	options := config.BuiltinNaabuProfile().Naabu
	updates := make(chan invocationProgress, 32)
	results, _, err := n.runNaabu(context.Background(), options, nil, []string{"192.0.2.1"}, true, func(update invocationProgress) {
		select {
		case updates <- update:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Port != 22 {
		t.Fatalf("Naabu result = %#v", results)
	}
	seenOutput, seenAlive, seenTerminal := false, false, false
	for {
		select {
		case update := <-updates:
			if update.Output == "working" {
				seenOutput = true
			}
			if update.Alive {
				seenAlive = true
			} else {
				seenTerminal = true
			}
		case <-time.After(200 * time.Millisecond):
			if seenTerminal {
				if !seenOutput || !seenAlive {
					t.Fatalf("Naabu heartbeat updates: output=%t alive=%t terminal=%t", seenOutput, seenAlive, seenTerminal)
				}
				return
			}
		}
	}
}

func TestNaabuDiscoveryWorkUnitDoesNotRunNmap(t *testing.T) {
	dir := t.TempDir()
	naabuPath := filepath.Join(dir, "naabu")
	if err := os.WriteFile(naabuPath, []byte("#!/bin/sh\nprintf '%s\\n' '{\"ip\":\"192.0.2.1\",\"port\":22,\"protocol\":\"tcp\"}'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := NewWithNaabu(filepath.Join(dir, "missing-nmap"), naabuPath)
	job := config.NormalizeJob(config.Job{Name: "discovery", Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1, TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{ScanType: "connect"}}})
	unit := WorkUnit{Sequence: 0, Engine: config.EngineNaabuNmap, Phase: "discovery", Protocol: "tcp", Family: 4, Targets: []ResolvedTarget{{Name: "192.0.2.1", ConfiguredTarget: "192.0.2.1", Addresses: []string{"192.0.2.1"}}}, Addresses: []string{"192.0.2.1"}, Ports: "1-65535", PortCount: 65535, Probes: 65535}
	snapshot, err := n.ScanWorkUnit(context.Background(), job, unit, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Hosts) != 1 || len(snapshot.Hosts[0].Protocols) != 1 || len(snapshot.Hosts[0].Protocols[0].DiscoveredPorts) != 1 {
		t.Fatalf("discovery checkpoint = %#v", snapshot)
	}
	if len(snapshot.Units) != 1 || len(snapshot.Units[0].Ports) != 0 {
		t.Fatalf("discovery checkpoint affected authoritative units: %#v", snapshot.Units)
	}
}

func TestNaabuPipelineWithUDPReportsCumulativeProgress(t *testing.T) {
	dir := t.TempDir()
	naabuPath := filepath.Join(dir, "naabu")
	if err := os.WriteFile(naabuPath, []byte("#!/bin/sh\nprintf '%s\\n' '{\"ip\":\"192.0.2.1\",\"port\":22,\"protocol\":\"tcp\"}'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	nmapPath := filepath.Join(dir, "nmap")
	// The same valid XML is sufficient for both phases; the UDP parser simply
	// ignores the TCP port while still recording a successful host response.
	if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\nprintf '%s' '"+sampleXML+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := NewWithNaabu(nmapPath, naabuPath)
	job := config.NormalizeJob(config.Job{
		Name: "pipeline-udp", Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Mode: "connect", Naabu: &config.NaabuOptions{ScanType: "connect"}},
		UDP: &config.Protocol{Ports: "53"},
	})
	var updates []Progress
	if _, err := n.ScanWithProgress(context.Background(), job, func(progress Progress) { updates = append(updates, progress) }); err != nil {
		t.Fatal(err)
	}
	if len(updates) == 0 {
		t.Fatal("pipeline emitted no progress")
	}
	last := updates[len(updates)-1]
	if last.TotalProbes != 65536 || last.CompletedProbes != 65536 || last.TotalInvocations != 2 || last.CompletedInvocations != 2 || last.Phase != "complete" {
		t.Fatalf("cumulative Naabu/UDP progress = %#v", last)
	}
	previousCompleted, previousTotal := int64(0), int64(0)
	for _, update := range updates {
		if update.CompletedProbes < previousCompleted || update.TotalProbes < previousTotal {
			t.Fatalf("progress regressed across phases: previous probes=%d/%d update=%#v", previousCompleted, previousTotal, update)
		}
		previousCompleted = update.CompletedProbes
		previousTotal = update.TotalProbes
	}
}
