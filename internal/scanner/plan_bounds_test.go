//go:build linux

package scanner

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

// legacyResolvedTargets expands the network targets of a unit into the one
// literal target per address that plans held before networks were grouped.
func legacyResolvedTargets(targets []ResolvedTarget) []ResolvedTarget {
	var out []ResolvedTarget
	for _, target := range targets {
		if _, _, err := net.ParseCIDR(target.Name); err != nil || target.Aggregate || target.Hostname {
			out = append(out, target)
			continue
		}
		for _, address := range target.Addresses {
			out = append(out, ResolvedTarget{Name: address, ConfiguredTarget: target.ConfiguredTarget, Addresses: []string{address}})
		}
	}
	return out
}

// echoNmap reports every address it is given as up with TCP port 1 open and
// UDP port 53 open|filtered.
const echoNmap = `#!/bin/sh
out=''
hosts=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -oX) out="$2"; shift 2; continue ;;
    *.*.*.*|*:*) hosts="$hosts $1" ;;
  esac
  shift
done
{
  printf '<?xml version="1.0"?><nmaprun>'
  for host in $hosts; do
    type=ipv4
    case "$host" in *:*) type=ipv6 ;; esac
    printf '<host><status state="up"/><address addr="%s" addrtype="%s"/><ports><port protocol="tcp" portid="1"><state state="open"/></port><port protocol="udp" portid="53"><state state="open|filtered"/></port></ports></host>' "$host" "$type"
  done
  printf '<runstats><finished exit="success"/></runstats></nmaprun>'
} > "$out"
`

// A CIDR is pinned as one target with all of its addresses. The plan covers
// the same scopes and units, and a unit's grouped targets scan exactly as the
// one literal target per address that earlier plans held, which is what a
// release from before the grouping does when it resumes the cycle.
func TestPlanGroupsNetworksWithoutChangingTheScan(t *testing.T) {
	t.Parallel()
	nmap := filepath.Join(t.TempDir(), "nmap")
	writeScript(t, nmap, echoNmap)
	n := New(nmap)
	n.Resolver = fakeResolver{ips: []net.IP{net.ParseIP("10.0.0.9"), net.ParseIP("10.0.0.1")}}
	job := config.NormalizeJob(config.Job{
		Name: "grouped", Targets: []string{"10.0.0.0/30", "10.0.0.2", "10.0.0.0/31", "2001:db8::/126", "edge.example"}, MaxExpandedHosts: 64,
		TCP: &config.Protocol{Ports: "1-3", Mode: "connect"}, UDP: &config.Protocol{Ports: "53"}, Timing: "balanced",
	})
	plan, err := n.Plan(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	wantTargets := []ResolvedTarget{
		{Name: "10.0.0.0/30", ConfiguredTarget: "10.0.0.0/30", Addresses: []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{Name: "10.0.0.2", ConfiguredTarget: "10.0.0.2", Addresses: []string{"10.0.0.2"}},
		{Name: "10.0.0.0/31", ConfiguredTarget: "10.0.0.0/31", Addresses: []string{"10.0.0.0", "10.0.0.1"}},
		{Name: "2001:db8::/126", ConfiguredTarget: "2001:db8::/126", Addresses: []string{"2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"}},
		{Name: "edge.example", ConfiguredTarget: "edge.example", Addresses: []string{"10.0.0.1", "10.0.0.9"}, Aggregate: true, Hostname: true},
	}
	if !reflect.DeepEqual(plan.Targets, wantTargets) {
		t.Fatalf("plan targets = %#v", plan.Targets)
	}
	// Every address of a CIDR remains a scope of its own, as before.
	var wantScopes []model.Scope
	for _, protocol := range []struct{ name, ports string }{{"tcp", "1-3"}, {"udp", "53"}} {
		for _, target := range []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.2", "10.0.0.0", "10.0.0.1", "2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3", "edge.example"} {
			wantScopes = append(wantScopes, model.Scope{Target: target, Protocol: protocol.name, Ports: protocol.ports})
		}
	}
	if !reflect.DeepEqual(plan.Scopes, wantScopes) {
		t.Fatalf("plan scopes = %#v", plan.Scopes)
	}
	if len(plan.Units) != 4 || plan.TotalProbes != 5*3+4*3+5+4 {
		t.Fatalf("plan units = %d, probes %d", len(plan.Units), plan.TotalProbes)
	}
	wantIPv4 := []ResolvedTarget{
		{Name: "10.0.0.0/30", ConfiguredTarget: "10.0.0.0/30", Addresses: []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{Name: "10.0.0.2", ConfiguredTarget: "10.0.0.2", Addresses: []string{"10.0.0.2"}},
		{Name: "10.0.0.0/31", ConfiguredTarget: "10.0.0.0/31", Addresses: []string{"10.0.0.0", "10.0.0.1"}},
		{Name: "edge.example", ConfiguredTarget: "edge.example", Addresses: []string{"10.0.0.1", "10.0.0.9"}, Aggregate: true, Hostname: true},
	}
	if unit := plan.Units[0]; unit.Protocol != "tcp" || unit.Family != 4 || !reflect.DeepEqual(unit.Addresses, []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.9"}) || !reflect.DeepEqual(unit.Targets, wantIPv4) {
		t.Fatalf("IPv4 unit = %#v", unit)
	}
	for _, unit := range plan.Units {
		pc, _ := protocolForJob(job, unit.Protocol)
		pc.Ports = unit.Ports
		grouped, err := n.scanProtocolBatchDetailedProgressWithTemplate(context.Background(), importResolvedTargets(unit.Targets), unit.Protocol, pc, job.Timing, true, false, pc.NmapArgs, nil)
		if err != nil {
			t.Fatal(err)
		}
		legacy, err := n.scanProtocolBatchDetailedProgressWithTemplate(context.Background(), importResolvedTargets(legacyResolvedTargets(unit.Targets)), unit.Protocol, pc, job.Timing, true, false, pc.NmapArgs, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(grouped.Units) == 0 || !reflect.DeepEqual(grouped, legacy) {
			t.Fatalf("unit %d scans differently grouped:\n%#v\nthan as literal targets:\n%#v", unit.Sequence, grouped, legacy)
		}
	}
	// A split keeps the grouping for the addresses of each half.
	first, second, ok := SplitWorkUnit(plan.Units[0])
	if !ok || !reflect.DeepEqual(first.Targets[0], ResolvedTarget{Name: "10.0.0.0/30", ConfiguredTarget: "10.0.0.0/30", Addresses: []string{"10.0.0.0", "10.0.0.1"}}) || len(second.Addresses) != 3 {
		t.Fatalf("split = %#v, %#v", first, second)
	}
}

// TestPlanOfTheLargestScopeStaysSmall measures the heap, so it does not run in
// parallel with other tests.
func TestPlanOfTheLargestScopeStaysSmall(t *testing.T) {
	if testing.Short() {
		t.Skip("plans the largest accepted scope")
	}
	n := New("nmap")
	job := config.NormalizeJob(config.Job{Name: "largest", Targets: []string{"10.0.0.0/16"}, MaxExpandedHosts: config.DefaultMaxJobHosts, TCP: &config.Protocol{Ports: "1-5", Mode: "connect"}})
	if size := 1 << 16; size != config.DefaultMaxJobHosts {
		t.Fatalf("the test plans %d hosts, but a job may expand to %d by default", size, config.DefaultMaxJobHosts)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	plan, err := n.Plan(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	stored := plan
	stored.Units = nil
	planJSON, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	unitBytes := 0
	for _, unit := range plan.Units {
		raw, err := json.Marshal(unit)
		if err != nil {
			t.Fatal(err)
		}
		unitBytes += len(raw)
	}
	// The scopes, one per address, take most of plan_json.
	if len(planJSON) > 8<<20 || unitBytes > 4<<20 {
		t.Fatalf("plan_json = %d bytes and unit rows %d bytes for %d hosts", len(planJSON), unitBytes, config.DefaultMaxJobHosts)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<20 {
		t.Fatalf("planning %d hosts allocated %d MiB", config.DefaultMaxJobHosts, allocated>>20)
	}
	if len(plan.Units) != 512 {
		t.Fatalf("units = %d", len(plan.Units))
	}
}

// scanner.max_job_hosts caps every job's expansion whatever the job allows,
// and the error names the setting; a job's own lower limit still applies.
func TestPlanStopsAtTheDeploymentHostCeiling(t *testing.T) {
	t.Parallel()
	n := New("nmap")
	job := config.NormalizeJob(config.Job{Name: "wide", Targets: []string{"10.0.0.0/15"}, MaxExpandedHosts: 1_000_000, TCP: &config.Protocol{Ports: "22", Mode: "connect"}})
	_, err := n.Plan(context.Background(), job)
	if !IsConfigurationError(err) || !strings.HasSuffix(err.Error(), "expanded targets exceed scanner.max_job_hosts=65536") {
		t.Fatalf("plan beyond the default ceiling = %v", err)
	}
	n.SetMaxJobHosts(8)
	job.Targets = []string{"10.0.0.0/29", "192.0.2.1"}
	if _, err := n.Plan(context.Background(), job); err == nil || !strings.HasSuffix(err.Error(), "expanded targets exceed scanner.max_job_hosts=8") {
		t.Fatalf("plan beyond a configured ceiling = %v", err)
	}
	if _, err := n.resolve(context.Background(), job); err == nil || !strings.Contains(err.Error(), "scanner.max_job_hosts=8") {
		t.Fatalf("a direct scan's resolution beyond the ceiling = %v", err)
	}
	job.Targets = []string{"10.0.0.0/29"}
	if plan, err := n.Plan(context.Background(), job); err != nil || len(plan.Units) != 1 {
		t.Fatalf("plan within the ceiling = %v", err)
	}
	job.MaxExpandedHosts = 4
	if _, err := n.Plan(context.Background(), job); err == nil || !strings.HasSuffix(err.Error(), "expanded targets exceed max_expanded_hosts=4") {
		t.Fatalf("plan beyond the job's own limit = %v", err)
	}
}
