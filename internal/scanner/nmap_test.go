package scanner

import (
	"context"
	"net"
	"reflect"
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
