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
func TestParseXMLRejectsMalformed(t *testing.T) {
	if _, err := parseXML([]byte("<nmaprun>"), "tcp", false); err == nil {
		t.Fatal("malformed XML accepted")
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

	withDiscovery := nmapArgs(4, "tcp", protocol, "balanced", false, addresses)
	if slices.Contains(withDiscovery, "-Pn") {
		t.Fatalf("assume_alive=false args: %v", withDiscovery)
	}
}

func TestScanProtocolFailsWhenDiscoveryOmitsHost(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	output := `<?xml version="1.0"?><nmaprun><host><status state="down"/><address addr="192.0.2.1" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>`
	script := "#!/bin/sh\nprintf '%s' '" + output + "'\n"
	if err := os.WriteFile(nmapPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	target := resolvedTarget{Name: "192.0.2.1", Addresses: []string{"192.0.2.1"}}
	_, err := n.scanProtocol(context.Background(), target, "tcp", config.Protocol{Ports: "22", Mode: "syn"}, "balanced", false)
	if err == nil || !strings.Contains(err.Error(), "omitted expected address") {
		t.Fatalf("expected safe discovery failure, got %v", err)
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
