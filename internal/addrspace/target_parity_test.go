package addrspace_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/addrspace"
	"github.com/crypt0rr/edgewatch/internal/config"
)

// TestTargetRangeMatchesTheScanner checks every target against the scanner's
// own reading: config.CanonicalTarget, then net.ParseIP or net.ParseCIDR on
// the canonical form, compared through the strings that net writes.
func TestTargetRangeMatchesTheScanner(t *testing.T) {
	t.Parallel()
	for _, target := range []string{
		"192.0.2.1",
		" 192.0.2.1 ",
		"192.0.2.77/24",
		"192.0.2.77/32",
		"192.0.2.0/024",
		"0.0.0.0",
		"0.0.0.0/0",
		"255.255.255.255",
		"2001:DB8::1",
		"2001:db8::1/32",
		"2001:db8::1/128",
		"::",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/112",
		"::ffff:192.0.2.1",
		"::ffff:192.0.2.77/120",
		"::ffff:192.0.2.77/128",
		"::ffff:0:0/96",
		"::ffff:0:0/95",
		"::ffff:0:0/127",
		"fe80::1%eth0",
		"fe80::%eth0/64",
		"Example.COM",
		"10.0.0.1-10",
		"192.0.2.0/33",
		"010.0.0.1",
		"",
	} {
		canonical := config.CanonicalTarget(target)
		var want addrspace.Range
		wantOK := true
		if ip := net.ParseIP(canonical); ip != nil {
			addr := netip.MustParseAddr(ip.String())
			want = addrspace.Range{From: addr, To: addr}
		} else if _, network, err := net.ParseCIDR(canonical); err == nil {
			want = addrspace.FromPrefix(netip.MustParsePrefix(network.String()))
		} else {
			wantOK = false
		}
		got, ok := addrspace.TargetRange(target)
		if got != want || ok != wantOK {
			t.Errorf("TargetRange(%q) = %v, %v, want %v, %v (canonical %q)", target, got, ok, want, wantOK, canonical)
		}
	}
}
