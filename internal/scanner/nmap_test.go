package scanner

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

const sampleXML = `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.7" extrainfo="Ubuntu" method="probed"><cpe>cpe:/a:openbsd:openssh:9.7</cpe></service></port><port protocol="tcp" portid="23"><state state="closed"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`

func TestParseXML(t *testing.T) {
	r, err := parseXML([]byte(sampleXML), "tcp", true)
	if err != nil {
		t.Fatal(err)
	}
	p := r.Units["192.0.2.1"].Ports
	if len(p) != 1 || p[0].Port != 22 || p[0].Service == "" {
		t.Fatalf("unexpected ports %#v", p)
	}
}

func TestParseXMLCapturesHostEvidenceAndSummaries(t *testing.T) {
	data := []byte(`<?xml version="1.0"?><nmaprun><host><status state="up" reason="arp-response" reason_ttl="64"/><address addr="198.51.100.10" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Example Vendor"/><hostnames><hostname name="edge.example" type="user"/></hostnames><hostscript><script id="smb-os-discovery" output="OS: Example&#10;Computer name: edge"/></hostscript><times srtt="2500"/><ports><extraports state="closed" count="2"><extrareasons reason="conn-refused" count="2"/></extraports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="https" product="Example" version="1.2" extrainfo="TLS" method="probed" conf="9" tunnel="ssl" ostype="Linux" devicetype="general purpose"><cpe>cpe:/a:example:server:1.2</cpe></service></port><port protocol="tcp" portid="8443"><state state="open|filtered" reason="no-response"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	run, err := parseXMLWithConfig(data, "tcp", config.Protocol{Ports: "1-1000,8443", Mode: "syn", ServiceDetection: true})
	if err != nil {
		t.Fatal(err)
	}
	host := run.Hosts["198.51.100.10"]
	if host.StatusReason != "arp-response" || host.ReasonTTL != 64 || host.LatencyMS != 2.5 || host.Hostnames[0].Name != "edge.example" {
		t.Fatalf("host evidence missing: %#v", host)
	}
	if len(host.LinkAddresses) != 1 || host.LinkAddresses[0].Vendor != "Example Vendor" {
		t.Fatalf("link evidence missing: %#v", host.LinkAddresses)
	}
	protocol := host.Protocols[0]
	if protocol.ScannedPortCount != 1001 || len(protocol.Ports) != 2 || protocol.Ports[0].Reason != "syn-ack" || protocol.Ports[0].Service == nil || protocol.Ports[0].Service.Confidence != 9 {
		t.Fatalf("protocol evidence missing: %#v", protocol)
	}
	if len(protocol.StateSummaries) != 3 || protocol.StateSummaries[0].State != "closed" || protocol.StateSummaries[0].Reasons[0].Reason != "conn-refused" {
		t.Fatalf("state summaries missing: %#v", protocol.StateSummaries)
	}
	if len(protocol.NSEOutput) != 1 || protocol.NSEOutput[0] != "smb-os-discovery: OS: Example Computer name: edge" {
		t.Fatalf("host NSE evidence missing: %#v", protocol.NSEOutput)
	}
}

func TestHostEvidenceDoesNotChangeSnapshotHash(t *testing.T) {
	base := model.Snapshot{Units: []model.Unit{{Target: "198.51.100.10", Protocol: "tcp", Addresses: []string{"198.51.100.10"}, Ports: []model.PortState{{Port: 443, State: "open"}}}}}
	withEvidence := base
	withEvidence.Hosts = []model.HostObservation{{Address: "198.51.100.10", StatusReason: "arp-response", LatencyMS: 1.2, Protocols: []model.ProtocolObservation{{Protocol: "tcp", ScannedPorts: "1-65535", Ports: []model.PortObservation{{Port: 443, State: "open", Reason: "syn-ack"}}}}}}
	if base.Hash() != withEvidence.Hash() {
		t.Fatal("host evidence changed the snapshot hash")
	}
}

func TestScanPreservesPerAddressEvidenceForDNS(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	output := `<?xml version="1.0"?><nmaprun><host><status state="up" reason="syn-ack"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/></port></ports></host><host><status state="up" reason="syn-ack"/><address addr="192.0.2.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open|filtered" reason="no-response"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`
	if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\nprintf '%s' '"+output+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	n.Resolver = fakeResolver{[]net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}}
	job := config.NormalizeJob(config.Job{Name: "dns", Targets: []string{"edge.example"}, MaxExpandedHosts: 2, TCP: &config.Protocol{Ports: "22,443", Mode: "syn"}})
	snapshot, err := n.Scan(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Hosts) != 2 || snapshot.Hosts[0].SourceTargets[0] != "edge.example" || snapshot.Hosts[0].DNSNames[0] != "edge.example" || snapshot.Hosts[0].Protocols[0].Ports[0].Port != 443 || snapshot.Hosts[1].Protocols[0].Ports[0].Port != 22 {
		t.Fatalf("unexpected DNS host evidence: %#v", snapshot.Hosts)
	}
	if len(snapshot.Units) != 1 || len(snapshot.Units[0].Ports) != 2 {
		t.Fatalf("unexpected DNS aggregate unit: %#v", snapshot.Units)
	}
}
func TestParseXMLRejectsMalformed(t *testing.T) {
	if _, err := parseXML([]byte("<nmaprun>"), "tcp", false); err == nil {
		t.Fatal("malformed XML accepted")
	}
}

func TestParseXMLRejectsTimedOutHost(t *testing.T) {
	data := []byte(`<?xml version="1.0"?><nmaprun><host timedout="true"><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	if _, err := parseXMLWithConfig(data, "tcp", config.Protocol{Ports: "443", Mode: "connect"}); err == nil || !strings.Contains(err.Error(), "192.0.2.10") || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timed-out host was accepted or error was unhelpful: %v", err)
	}
}

type fakeResolver struct{ ips []net.IP }

func (f fakeResolver) LookupIP(context.Context, string, string) ([]net.IP, error) { return f.ips, nil }
func TestResolveHostnameAndCIDRLimit(t *testing.T) {
	n := New("nmap")
	n.Resolver = fakeResolver{[]net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}}
	job := config.Job{Targets: []string{"Example.COM"}, MaxExpandedHosts: 2}
	got, err := n.resolve(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Name != "example.com" || !reflect.DeepEqual(got[0].Addresses, []string{"192.0.2.1", "2001:db8::1"}) {
		t.Fatalf("unexpected %#v", got)
	}
	job = config.Job{Targets: []string{"192.0.2.0/30"}, MaxExpandedHosts: 3}
	if _, err := n.resolve(context.Background(), job); err == nil {
		t.Fatal("CIDR limit not enforced")
	}
}

func TestResolveRejectsExcludedAddresses(t *testing.T) {
	n := New("nmap")
	if err := n.SetTargetExclusions(config.DefaultTargetExclusions()); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"127.0.0.1", "169.254.169.254", "::1"} {
		if _, err := n.resolve(context.Background(), config.Job{Targets: []string{target}, MaxExpandedHosts: 4}); err == nil || !strings.Contains(err.Error(), "excluded") {
			t.Fatalf("excluded target %q resolved without error: %v", target, err)
		}
	}
	n.Resolver = fakeResolver{[]net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("127.0.0.1")}}
	if _, err := n.resolve(context.Background(), config.Job{Targets: []string{"edge.example"}, MaxExpandedHosts: 4}); err == nil || !strings.Contains(err.Error(), "resolved to excluded") {
		t.Fatalf("DNS result containing excluded address was accepted: %v", err)
	}
	if err := n.SetTargetExclusions([]string{}); err != nil {
		t.Fatal(err)
	}
	if _, err := n.resolve(context.Background(), config.Job{Targets: []string{"127.0.0.1"}, MaxExpandedHosts: 1}); err != nil {
		t.Fatalf("explicit empty exclusion override rejected target: %v", err)
	}
}

func TestAggregatePrefersConfirmedOpen(t *testing.T) {
	target := resolvedTarget{Name: "example.com", Addresses: []string{"192.0.2.1", "192.0.2.2"}, Aggregate: true}
	parsed := map[string]model.Unit{"192.0.2.1": {Ports: []model.PortState{{Port: 53, State: "open|filtered"}}}, "192.0.2.2": {Ports: []model.PortState{{Port: 53, State: "open"}}}}
	got := aggregate(target, parsed, "udp")
	if got.Ports[0].State != "open" {
		t.Fatalf("got %s", got.Ports[0].State)
	}
}

func TestNmapArgsHostDiscovery(t *testing.T) {
	protocol := config.Protocol{Ports: "22", Mode: "syn"}
	addresses := []string{"192.0.2.1"}

	withAssumption := nmapArgs(4, "tcp", protocol, "balanced", true, addresses)
	if !slices.Contains(withAssumption, "-Pn") {
		t.Fatalf("assume_alive=true args: %v", withAssumption)
	}
	if !slices.Contains(withAssumption, "--reason") {
		t.Fatalf("nmap args omitted --reason: %v", withAssumption)
	}

	withDiscovery := nmapArgs(4, "tcp", protocol, "balanced", false, addresses)
	if slices.Contains(withDiscovery, "-Pn") {
		t.Fatalf("assume_alive=false args: %v", withDiscovery)
	}
}

func TestNmapProfilePlaceholdersRenderManagedArguments(t *testing.T) {
	pc := config.Protocol{Ports: "22,443", Mode: "connect", ServiceDetection: true, NmapArgs: []string{
		config.PlaceholderAddresses, config.PlaceholderPorts, config.PlaceholderStructuredOutput,
		config.PlaceholderHostDiscovery, config.PlaceholderScanType, config.PlaceholderServiceDetection,
	}}
	args := nmapArgs(4, "tcp", pc, "balanced", true, []string{"192.0.2.1", "192.0.2.2"})
	joined := strings.Join(args, " ")
	if strings.Contains(joined, config.PlaceholderAddresses) || strings.Contains(joined, config.PlaceholderPorts) {
		t.Fatalf("placeholder leaked into command: %v", args)
	}
	if strings.Count(joined, "-p") != 1 || strings.Count(joined, "22,443") != 1 || strings.Count(joined, "-oX") != 1 {
		t.Fatalf("managed arguments were not rendered exactly once: %v", args)
	}
	if !strings.Contains(joined, "192.0.2.1") || !strings.Contains(joined, "192.0.2.2") || !strings.Contains(joined, "-sT") || !strings.Contains(joined, "-sV") || !strings.Contains(joined, "-Pn") {
		t.Fatalf("profile placeholders were not rendered: %v", args)
	}
}

func TestNmapCustomProfileKeepsTypedDefaultsWhenPlaceholdersOmitted(t *testing.T) {
	pc := config.Protocol{Ports: "443", Mode: "syn", ServiceDetection: true, NmapArgs: []string{
		config.PlaceholderAddress, config.PlaceholderPorts, config.PlaceholderStructuredOutput, "--host-timeout", "5m",
	}}
	args := nmapArgs(6, "tcp", pc, "balanced", true, []string{"2001:db8::10"})
	joined := strings.Join(args, " ")
	for _, expected := range []string{"-Pn", "-6", "-sS", "-sV", "--version-light", "--host-timeout", "5m"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("custom Nmap profile omitted typed default %q: %v", expected, args)
		}
	}
	if strings.Contains(joined, config.PlaceholderAddress) || strings.Contains(joined, config.PlaceholderPorts) {
		t.Fatalf("placeholder leaked into custom Nmap command: %v", args)
	}
}

func TestScanProtocolRecordsOmittedHostWithoutDroppingBatch(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	output := `<?xml version="1.0"?><nmaprun><host><status state="up" reason="arp-response"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/></port></ports></host><host><status state="up" reason="arp-response"/><address addr="192.0.2.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`
	script := "#!/bin/sh\nprintf '%s' '" + output + "'\n"
	if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	target := resolvedTarget{Name: "batch", Addresses: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}}
	result, err := n.scanProtocolBatchDetailedProgress(context.Background(), []resolvedTarget{target}, "tcp", config.Protocol{Ports: "22,80", Mode: "syn"}, "balanced", false, nil)
	if err != nil {
		t.Fatalf("partial host response failed the batch: %v", err)
	}
	if len(result.Units) != 2 {
		t.Fatalf("units = %#v, want the two reported hosts only", result.Units)
	}
	missing, ok := result.Hosts["192.0.2.3"]
	if !ok || missing.Status != "unreachable" || missing.StatusReason != "nmap-omitted" {
		t.Fatalf("missing host observation = %#v", missing)
	}
	if len(missing.Protocols) != 1 || missing.Protocols[0].StateSummaries[0].State != "unreachable" {
		t.Fatalf("missing host scope evidence = %#v", missing.Protocols)
	}
}

func TestScanProtocolFailsWhenEntireInvocationOmitsHosts(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	output := `<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/></runstats></nmaprun>`
	script := "#!/bin/sh\nprintf '%s' '" + output + "'\n"
	if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	target := resolvedTarget{Name: "192.0.2.1", Addresses: []string{"192.0.2.1"}}
	_, err := n.scanProtocol(context.Background(), target, "tcp", config.Protocol{Ports: "22", Mode: "syn"}, "balanced", false)
	if err == nil || !strings.Contains(err.Error(), "omitted expected address") {
		t.Fatalf("expected empty invocation failure, got %v", err)
	}
}

func TestParseXMLRecordsDownHostAsUnreachable(t *testing.T) {
	data := []byte(`<?xml version="1.0"?><nmaprun><host><status state="down" reason="no-response" reason_ttl="64"/><address addr="192.0.2.9" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	run, err := parseXMLWithConfig(data, "tcp", config.Protocol{Ports: "1-100", Mode: "connect"})
	if err != nil {
		t.Fatal(err)
	}
	host, ok := run.Hosts["192.0.2.9"]
	if !ok || host.Status != "unreachable" || host.StatusReason != "no-response" || host.ReasonTTL != 64 {
		t.Fatalf("down host observation = %#v", host)
	}
	if _, ok := run.Units["192.0.2.9"]; ok {
		t.Fatal("down host unexpectedly produced a comparison unit")
	}
	if len(host.Protocols) != 1 || host.Protocols[0].StateSummaries[0].State != "unreachable" {
		t.Fatalf("down host protocol evidence = %#v", host.Protocols)
	}
}

func TestScanBatchesExpandedCIDRTargets(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	countPath := filepath.Join(dir, "invocations")
	var hosts strings.Builder
	for i := 0; i < 4; i++ {
		fmt.Fprintf(&hosts, `<host><status state="up"/><address addr="192.0.2.%d" addrtype="ipv4"/></host>`, i)
	}
	output := `<?xml version="1.0"?><nmaprun>` + hosts.String() + `<runstats><finished exit="success"/></runstats></nmaprun>`
	script := "#!/bin/sh\nprintf x >> '" + countPath + "'\nprintf '%s' '" + output + "'\n"
	if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	job := config.NormalizeJob(config.Job{
		Name: "cidr", Targets: []string{"192.0.2.0/30"}, MaxExpandedHosts: 4,
		TCP: &config.Protocol{Ports: "22", Mode: "syn"}, Timing: "balanced",
	})
	snapshot, err := n.Scan(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	invocations, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(invocations) != 1 {
		t.Fatalf("nmap invocations = %d, want one batch: %q", len(invocations), invocations)
	}
	if len(snapshot.Units) != 4 {
		t.Fatalf("snapshot units = %d, want four expanded hosts: %#v", len(snapshot.Units), snapshot.Units)
	}
}

func TestScanWithProgressReportsBoundedWork(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\nprintf '%s' '"+sampleXML+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	job := config.NormalizeJob(config.Job{
		Name: "progress", Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1,
		TCP: &config.Protocol{Ports: "22-23", Mode: "syn"}, Timing: "balanced",
	})
	var updates []Progress
	if _, err := n.ScanWithProgress(context.Background(), job, func(progress Progress) { updates = append(updates, progress) }); err != nil {
		t.Fatal(err)
	}
	if len(updates) < 4 {
		t.Fatalf("progress updates = %#v, want resolving, scanning, invocation, complete", updates)
	}
	first, last := updates[0], updates[len(updates)-1]
	if first.Phase != "resolving" || last.Phase != "complete" {
		t.Fatalf("progress phases = %#v ... %#v", first, last)
	}
	if last.TotalProbes != 2 || last.CompletedProbes != 2 || last.TotalInvocations != 1 || last.CompletedInvocations != 1 {
		t.Fatalf("progress totals = %#v", last)
	}
}

func TestScanWithProgressReportsLiveProcessHeartbeatAndNmapOutput(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	script := "#!/bin/sh\necho 'About 42.0% done; ETC: 00:01' >&2\nsleep 2\nprintf '%s' '" + sampleXML + "'\n"
	if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	job := config.NormalizeJob(config.Job{
		Name: "live-progress", Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1,
		TCP: &config.Protocol{Ports: "22-23", Mode: "syn"}, Timing: "balanced",
	})
	var updates []Progress
	if _, err := n.ScanWithProgress(context.Background(), job, func(progress Progress) { updates = append(updates, progress) }); err != nil {
		t.Fatal(err)
	}
	foundLive, foundOutput, foundFraction, foundComplete := false, false, false, false
	for _, update := range updates {
		if update.ProcessAlive && update.Protocol == "tcp" {
			foundLive = true
		}
		if strings.Contains(update.LastOutput, "About 42.0%") {
			foundOutput = true
		}
		if update.ProcessAlive && update.ProcessProgressPercent > 0 {
			foundFraction = true
		}
		if update.Phase == "complete" && !update.ProcessAlive {
			foundComplete = true
		}
	}
	if !foundLive || !foundOutput || !foundFraction || !foundComplete {
		t.Fatalf("live progress updates missing: live=%v output=%v fraction=%v complete=%v updates=%#v", foundLive, foundOutput, foundFraction, foundComplete, updates)
	}
}

func TestScanWithProgressReportsXMLTaskProgress(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	prefix := `<?xml version="1.0"?><nmaprun><taskprogress task="Connect Scan" percent="37.50"/>`
	suffix := `<host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>`
	script := "#!/bin/sh\nout=\"\"\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"-oX\" ]; then out=\"$2\"; shift 2; else shift; fi\ndone\nprintf '%s' '" + prefix + "' > \"$out\"\nsleep 1\nprintf '%s' '" + suffix + "' >> \"$out\"\n"
	if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	job := config.NormalizeJob(config.Job{
		Name: "xml-progress", Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1,
		TCP: &config.Protocol{Ports: "22", Mode: "connect"}, Timing: "balanced",
	})
	var updates []Progress
	if _, err := n.ScanWithProgress(context.Background(), job, func(progress Progress) { updates = append(updates, progress) }); err != nil {
		t.Fatal(err)
	}
	foundFraction, foundOutput := false, false
	for _, update := range updates {
		if update.ProcessAlive && update.ProcessProgressPercent == 37 {
			foundFraction = true
		}
		if strings.Contains(update.LastOutput, "Nmap Connect Scan: 37.50% complete") {
			foundOutput = true
		}
	}
	if !foundFraction || !foundOutput {
		t.Fatalf("XML task progress missing: fraction=%v output=%v updates=%#v", foundFraction, foundOutput, updates)
	}
}

func TestNmapXMLProgressParserHandlesSplitRecords(t *testing.T) {
	parser := &nmapXMLProgressParser{}
	var got []struct {
		line     string
		fraction float64
	}
	emit := func(line string, fraction float64) {
		got = append(got, struct {
			line     string
			fraction float64
		}{line: line, fraction: fraction})
	}
	parser.feed([]byte(`<nmaprun><taskprogress task="Connect`), emit)
	parser.feed([]byte(` Scan" percent="125.0"/></nmaprun>`), emit)
	if len(got) != 1 || got[0].fraction != 1 || !strings.Contains(got[0].line, "100.00%") {
		t.Fatalf("split XML progress = %#v", got)
	}
}
