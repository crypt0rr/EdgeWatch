package scanner_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/engine"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
)

type dualStackResolver struct{ ips []net.IP }

func (r dualStackResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return r.ips, nil
}

// dualStackNmap answers one host for the invocation's address family, with
// 22/tcp open and the product read from a per-family file next to the script.
const dualStackNmap = `#!/bin/sh
six=0
for arg in "$@"; do
  case "$arg" in
    --version|-V) echo "Nmap version 7.95"; exit 0 ;;
    -6) six=1 ;;
  esac
done
if [ "$six" = 1 ]; then
  read -r product < "${0%/*}/v6product"
  address='2001:db8::10'; family=ipv6
else
  read -r product < "${0%/*}/v4product"
  address='192.0.2.10'; family=ipv4
fi
printf '<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="%s" addrtype="%s"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="%s" version="9.6" method="probed"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>' "$address" "$family" "$product"
`

// A managed job with a dual-stack DNS target always takes the resumable path,
// because the planner scans each address family in its own work unit. Its
// merged snapshot must compare exactly like the single-invocation scan, so a
// service change on the IPv6 address is reported whatever the fragment
// order.
func TestResumableDualStackScanReportsServiceChangeLikeDirectScan(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "nmap")
	if err := os.WriteFile(path, []byte(dualStackNmap), 0o700); err != nil {
		t.Fatal(err)
	}
	product := func(family, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, family+"product"), []byte(value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	n := scanner.New(path)
	n.Resolver = dualStackResolver{ips: []net.IP{net.ParseIP("2001:db8::10"), net.ParseIP("192.0.2.10")}}
	job := config.NormalizeJob(config.Job{
		Name: "dual", Targets: []string{"edge.example"}, MaxExpandedHosts: 4,
		TCP: &config.Protocol{Ports: "22", Mode: "connect", ServiceDetection: true},
	})
	resumable := func(reverse bool) model.Snapshot {
		t.Helper()
		plan, err := n.Plan(ctx, job)
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Units) != 2 || plan.Units[0].Family != 4 || plan.Units[1].Family != 6 {
			t.Fatalf("plan units = %#v, want one unit per address family", plan.Units)
		}
		fragments := make([]model.Snapshot, len(plan.Units))
		for index, unit := range plan.Units {
			fragment, err := n.ScanWorkUnit(ctx, job, unit, nil)
			if err != nil {
				t.Fatal(err)
			}
			fragments[index] = fragment
		}
		if reverse {
			fragments[0], fragments[1] = fragments[1], fragments[0]
		}
		return scanner.MergeWorkSnapshots(plan, fragments)
	}
	direct := func() model.Snapshot {
		t.Helper()
		snapshot, err := n.Scan(ctx, job)
		if err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	service := func(snapshot model.Snapshot) string {
		for _, unit := range snapshot.Units {
			if unit.Target == "edge.example" && unit.Protocol == "tcp" {
				for _, port := range unit.Ports {
					if port.Port == 22 {
						return port.Service
					}
				}
			}
		}
		return "<missing>"
	}

	product("v4", "OpenSSH")
	product("v6", "OpenSSH")
	baseline := resumable(false)
	if got, want := service(baseline), service(direct()); got != "ssh | OpenSSH | 9.6 |" || got != want {
		t.Fatalf("baseline service: resumable %q, direct %q", got, want)
	}

	product("v6", "Dropbear")
	const changed = "ssh | Dropbear | 9.6 | || ssh | OpenSSH | 9.6 |"
	want := fmt.Sprintf("%+v", engine.Diff(baseline, direct(), false))
	for _, reverse := range []bool{false, true} {
		merged := resumable(reverse)
		if got := service(merged); got != changed {
			t.Fatalf("reverse=%t: resumable service = %q, want %q", reverse, got, changed)
		}
		changes := engine.Diff(baseline, merged, false)
		if len(changes) != 1 || changes[0].Key != "service|edge.example|tcp|22" || changes[0].New != changed {
			t.Fatalf("reverse=%t: resumable changes = %+v, want the IPv6 service change", reverse, changes)
		}
		if got := fmt.Sprintf("%+v", changes); got != want {
			t.Fatalf("reverse=%t: resumable changes = %s, direct changes = %s", reverse, got, want)
		}
	}
}
