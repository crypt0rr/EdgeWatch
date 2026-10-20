package addrspace

import (
	"math"
	"math/big"
	"math/bits"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// rng parses "from-to", a CIDR, or a single address into a Range.
func rng(value string) Range {
	if from, to, ok := strings.Cut(value, "-"); ok {
		return Range{From: netip.MustParseAddr(from), To: netip.MustParseAddr(to)}
	}
	if strings.Contains(value, "/") {
		return FromPrefix(netip.MustParsePrefix(value))
	}
	addr := netip.MustParseAddr(value)
	return Range{From: addr, To: addr}
}

func rngs(values ...string) []Range {
	var out []Range
	for _, value := range values {
		out = append(out, rng(value))
	}
	return out
}

func prefixes(values ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, value := range values {
		out = append(out, netip.MustParsePrefix(value))
	}
	return out
}

func TestRangeValid(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		input Range
		want  bool
	}{
		{name: "zero", input: Range{}, want: false},
		{name: "missing end", input: Range{From: netip.MustParseAddr("192.0.2.1")}, want: false},
		{name: "missing start", input: Range{To: netip.MustParseAddr("192.0.2.1")}, want: false},
		{name: "single address", input: rng("192.0.2.1"), want: true},
		{name: "IPv6", input: rng("2001:db8::-2001:db8::ff"), want: true},
		{name: "reversed", input: rng("192.0.2.9-192.0.2.1"), want: false},
		{name: "mixed families", input: Range{From: netip.MustParseAddr("255.255.255.255"), To: netip.MustParseAddr("::")}, want: false},
		{name: "IPv4 and its mapped form", input: Range{From: netip.MustParseAddr("192.0.2.1"), To: netip.MustParseAddr("::ffff:192.0.2.1")}, want: false},
		{name: "zone on start", input: Range{From: netip.MustParseAddr("fe80::1%eth0"), To: netip.MustParseAddr("fe80::2")}, want: false},
		{name: "zone on end", input: Range{From: netip.MustParseAddr("fe80::1"), To: netip.MustParseAddr("fe80::2%eth0")}, want: false},
	} {
		if got := test.input.Valid(); got != test.want {
			t.Errorf("%s: Valid() = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestFromPrefix(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		input netip.Prefix
		want  Range
	}{
		{input: netip.MustParsePrefix("10.0.0.0/8"), want: rng("10.0.0.0-10.255.255.255")},
		{input: netip.MustParsePrefix("10.1.2.3/8"), want: rng("10.0.0.0-10.255.255.255")},
		{input: netip.MustParsePrefix("192.0.2.0/25"), want: rng("192.0.2.0-192.0.2.127")},
		{input: netip.MustParsePrefix("192.0.2.77/32"), want: rng("192.0.2.77-192.0.2.77")},
		{input: netip.MustParsePrefix("0.0.0.0/0"), want: rng("0.0.0.0-255.255.255.255")},
		{input: netip.MustParsePrefix("255.255.255.255/32"), want: rng("255.255.255.255-255.255.255.255")},
		{input: netip.MustParsePrefix("::/0"), want: rng("::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		{input: netip.MustParsePrefix("2001:db8::1/32"), want: rng("2001:db8::-2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")},
		{input: netip.MustParsePrefix("2001:db8::/61"), want: rng("2001:db8::-2001:db8:0:7:ffff:ffff:ffff:ffff")},
		{input: netip.MustParsePrefix("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"), want: rng("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		// FromPrefix keeps the family it is given; TargetRange unmaps.
		{input: netip.MustParsePrefix("::ffff:192.0.2.0/120"), want: rng("::ffff:192.0.2.0-::ffff:192.0.2.255")},
		{input: netip.Prefix{}, want: Range{}},
		{input: netip.PrefixFrom(netip.MustParseAddr("192.0.2.0"), 33), want: Range{}},
	} {
		got := FromPrefix(test.input)
		if got != test.want {
			t.Errorf("FromPrefix(%s) = %v, want %v", test.input, got, test.want)
		}
		if test.input.IsValid() && !got.Valid() {
			t.Errorf("FromPrefix(%s) = %v, which is not valid", test.input, got)
		}
	}
}

func TestMerge(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		input []Range
		want  []Range
	}{
		{name: "nil", input: nil, want: nil},
		{name: "empty", input: []Range{}, want: nil},
		{name: "only invalid ranges", input: []Range{{}, rng("192.0.2.9-192.0.2.1")}, want: nil},
		{name: "single", input: rngs("192.0.2.0/24"), want: rngs("192.0.2.0/24")},
		{name: "unsorted and disjoint", input: rngs("198.51.100.0/24", "192.0.2.0/24"), want: rngs("192.0.2.0/24", "198.51.100.0/24")},
		{name: "overlapping", input: rngs("192.0.2.0-192.0.2.100", "192.0.2.50-192.0.2.200"), want: rngs("192.0.2.0-192.0.2.200")},
		{name: "adjacent", input: rngs("192.0.2.128/25", "192.0.2.0/25"), want: rngs("192.0.2.0/24")},
		{name: "one address apart", input: rngs("192.0.2.0-192.0.2.9", "192.0.2.11-192.0.2.20"), want: rngs("192.0.2.0-192.0.2.9", "192.0.2.11-192.0.2.20")},
		{name: "contained", input: rngs("10.0.0.0/8", "10.1.0.0/16", "10.2.3.4"), want: rngs("10.0.0.0/8")},
		{name: "duplicates", input: rngs("192.0.2.0/24", "192.0.2.0/24"), want: rngs("192.0.2.0/24")},
		{name: "same start, longer second", input: rngs("192.0.2.0/25", "192.0.2.0/24"), want: rngs("192.0.2.0/24")},
		{name: "chain", input: rngs("10.0.0.3", "10.0.0.1", "10.0.0.2", "10.0.0.0"), want: rngs("10.0.0.0-10.0.0.3")},
		{name: "IPv4 edges", input: rngs("0.0.0.0", "255.255.255.255", "0.0.0.1-255.255.255.254"), want: rngs("0.0.0.0/0")},
		{name: "families never join at the IPv4 top", input: rngs("::", "255.255.255.255"), want: rngs("255.255.255.255", "::")},
		{name: "IPv4 before IPv6", input: rngs("2001:db8::/32", "192.0.2.0/24"), want: rngs("192.0.2.0/24", "2001:db8::/32")},
		{name: "mapped IPv6 stays apart from IPv4", input: rngs("::ffff:192.0.2.0/120", "192.0.2.0/24"), want: rngs("192.0.2.0/24", "::ffff:192.0.2.0/120")},
		{name: "IPv6 adjacent", input: rngs("2001:db8::/33", "2001:db8:8000::/33"), want: rngs("2001:db8::/32")},
		{name: "IPv6 edges", input: rngs("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"), want: rngs("::/0")},
		{name: "invalid ranges dropped", input: []Range{{}, rng("192.0.2.0/24"), {From: netip.MustParseAddr("192.0.2.1"), To: netip.MustParseAddr("::1")}}, want: rngs("192.0.2.0/24")},
	} {
		input := slices.Clone(test.input)
		got := Merge(test.input)
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("%s: Merge = %v, want %v", test.name, got, test.want)
		}
		if !reflect.DeepEqual(test.input, input) {
			t.Errorf("%s: Merge modified its input", test.name)
		}
	}
}

func TestSubtract(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		a, b []Range
		want []Range
	}{
		{name: "empty a", a: nil, b: rngs("192.0.2.0/24"), want: nil},
		{name: "empty b merges a", a: rngs("192.0.2.128/25", "192.0.2.0/25"), b: nil, want: rngs("192.0.2.0/24")},
		{name: "b covers a", a: rngs("192.0.2.0/25"), b: rngs("192.0.2.0/24"), want: nil},
		{name: "equal", a: rngs("192.0.2.0/24"), b: rngs("192.0.2.0/24"), want: nil},
		{name: "hole", a: rngs("192.0.2.0/24"), b: rngs("192.0.2.10-192.0.2.19"), want: rngs("192.0.2.0-192.0.2.9", "192.0.2.20-192.0.2.255")},
		{name: "head", a: rngs("192.0.2.0/24"), b: rngs("192.0.1.0-192.0.2.9"), want: rngs("192.0.2.10-192.0.2.255")},
		{name: "tail", a: rngs("192.0.2.0/24"), b: rngs("192.0.2.250-192.0.3.9"), want: rngs("192.0.2.0-192.0.2.249")},
		{name: "several holes", a: rngs("192.0.2.0/24"), b: rngs("192.0.2.0", "192.0.2.5-192.0.2.6", "192.0.2.255"), want: rngs("192.0.2.1-192.0.2.4", "192.0.2.7-192.0.2.254")},
		{name: "b spans two ranges of a", a: rngs("192.0.2.0/24", "192.0.4.0/24"), b: rngs("192.0.2.128-192.0.4.127"), want: rngs("192.0.2.0/25", "192.0.4.128/25")},
		{name: "disjoint", a: rngs("192.0.2.0/24"), b: rngs("198.51.100.0/24", "10.0.0.0/8"), want: rngs("192.0.2.0/24")},
		{name: "IPv4 space edges", a: rngs("0.0.0.0/0"), b: rngs("0.0.0.0", "255.255.255.255"), want: rngs("0.0.0.1-255.255.255.254")},
		{name: "IPv4 does not remove IPv6", a: rngs("::/0"), b: rngs("0.0.0.0/0"), want: rngs("::/0")},
		{name: "mapped IPv6 does not remove IPv4", a: rngs("192.0.2.0/24"), b: rngs("::ffff:192.0.2.0/120"), want: rngs("192.0.2.0/24")},
		{name: "per family", a: rngs("192.0.2.0/24", "2001:db8::/126"), b: rngs("192.0.2.0/25", "2001:db8::1"), want: rngs("192.0.2.128/25", "2001:db8::", "2001:db8::2-2001:db8::3")},
		{name: "IPv6 space edges", a: rngs("::/0"), b: rngs("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: rngs("::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe")},
		{name: "IPv6 middle", a: rngs("::/0"), b: rngs("8000::/1"), want: rngs("::/1")},
	} {
		got := Subtract(test.a, test.b)
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("%s: Subtract = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestIntersect(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		a, b []Range
		want []Range
	}{
		{name: "empty a", a: nil, b: rngs("192.0.2.0/24"), want: nil},
		{name: "empty b", a: rngs("192.0.2.0/24"), b: nil, want: nil},
		{name: "contained", a: rngs("192.0.2.0/24"), b: rngs("192.0.2.10-192.0.2.19"), want: rngs("192.0.2.10-192.0.2.19")},
		{name: "partial overlap", a: rngs("192.0.2.0-192.0.2.100"), b: rngs("192.0.2.50-192.0.2.200"), want: rngs("192.0.2.50-192.0.2.100")},
		{name: "touching ends", a: rngs("192.0.2.0-192.0.2.10"), b: rngs("192.0.2.10-192.0.2.20"), want: rngs("192.0.2.10")},
		{name: "adjacent but not overlapping", a: rngs("192.0.2.0/25"), b: rngs("192.0.2.128/25"), want: nil},
		{name: "one range of b over two of a", a: rngs("192.0.2.0/24", "192.0.4.0/24"), b: rngs("192.0.2.128-192.0.4.127"), want: rngs("192.0.2.128/25", "192.0.4.0/25")},
		{name: "IPv4 edges", a: rngs("0.0.0.0/0"), b: rngs("0.0.0.0", "255.255.255.255"), want: rngs("0.0.0.0", "255.255.255.255")},
		{name: "families never meet", a: rngs("0.0.0.0/0"), b: rngs("::/0"), want: nil},
		{name: "mapped IPv6 is not IPv4", a: rngs("192.0.2.0/24"), b: rngs("::ffff:192.0.2.0/120"), want: nil},
		{name: "per family", a: rngs("192.0.2.0/24", "2001:db8::/32"), b: rngs("192.0.2.0/25", "::/0"), want: rngs("192.0.2.0/25", "2001:db8::/32")},
		{name: "IPv6 edges", a: rngs("::/0"), b: rngs("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: rngs("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
	} {
		got := Intersect(test.a, test.b)
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("%s: Intersect = %v, want %v", test.name, got, test.want)
		}
		if reverse := Intersect(test.b, test.a); !reflect.DeepEqual(reverse, test.want) {
			t.Errorf("%s: Intersect reversed = %v, want %v", test.name, reverse, test.want)
		}
	}
}

func TestCountCapped(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name          string
		input         []Range
		limit         uint64
		want          uint64
		wantSaturated bool
	}{
		{name: "empty", input: nil, limit: 10, want: 0},
		{name: "empty with no room", input: nil, limit: 0, want: 0},
		{name: "one address with no room", input: rngs("192.0.2.1"), limit: 0, want: 0, wantSaturated: true},
		{name: "one CIDR", input: rngs("192.0.2.0/24"), limit: math.MaxUint64, want: 256},
		{name: "overlaps count twice", input: rngs("192.0.2.0/24", "192.0.2.0/25"), limit: math.MaxUint64, want: 384},
		{name: "exactly at the limit", input: rngs("192.0.2.0/24"), limit: 256, want: 256},
		{name: "one above the limit", input: rngs("192.0.2.0/24", "198.51.100.1"), limit: 256, want: 256, wantSaturated: true},
		{name: "invalid ranges count nothing", input: []Range{{}, rng("192.0.2.9-192.0.2.1"), rng("192.0.2.1")}, limit: 10, want: 1},
		{name: "IPv4 space", input: rngs("0.0.0.0/0"), limit: math.MaxUint64, want: 1 << 32},
		{name: "IPv4 space twice", input: rngs("0.0.0.0/0", "0.0.0.0/0"), limit: math.MaxUint64, want: 1 << 33},
		{name: "IPv6 /65", input: rngs("2001:db8::/65"), limit: math.MaxUint64, want: 1 << 63},
		{name: "IPv6 two /65 overflow uint64", input: rngs("2001:db8::/65", "2001:db8:0:0:8000::/65"), limit: math.MaxUint64, want: math.MaxUint64, wantSaturated: true},
		{name: "IPv6 /64 is 2^64", input: rngs("2001:db8::/64"), limit: math.MaxUint64, want: math.MaxUint64, wantSaturated: true},
		{name: "IPv6 space", input: rngs("::/0"), limit: math.MaxUint64, want: math.MaxUint64, wantSaturated: true},
		{name: "IPv6 range above 2^64", input: rngs("::-1::"), limit: 1000, want: 1000, wantSaturated: true},
		{name: "largest uint64 count", input: rngs("::-::ffff:ffff:ffff:fffe"), limit: math.MaxUint64, want: math.MaxUint64},
		{name: "saturated stops early", input: rngs("::/0", "192.0.2.1"), limit: 5, want: 5, wantSaturated: true},
	} {
		got, saturated := CountCapped(test.input, test.limit)
		if got != test.want || saturated != test.wantSaturated {
			t.Errorf("%s: CountCapped = %d, %v, want %d, %v", test.name, got, saturated, test.want, test.wantSaturated)
		}
	}
}

func TestCover(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		input Range
		want  []netip.Prefix
	}{
		{input: Range{}, want: nil},
		{input: rng("192.0.2.9-192.0.2.1"), want: nil},
		{input: rng("192.0.2.1"), want: prefixes("192.0.2.1/32")},
		{input: rng("192.0.2.0/24"), want: prefixes("192.0.2.0/24")},
		{input: rng("192.0.2.1-192.0.2.6"), want: prefixes("192.0.2.1/32", "192.0.2.2/31", "192.0.2.4/31", "192.0.2.6/32")},
		{input: rng("192.0.2.0-192.0.3.15"), want: prefixes("192.0.2.0/24", "192.0.3.0/28")},
		{input: rng("192.0.1.255-192.0.4.0"), want: prefixes("192.0.1.255/32", "192.0.2.0/23", "192.0.4.0/32")},
		{input: rng("0.0.0.0-255.255.255.255"), want: prefixes("0.0.0.0/0")},
		{input: rng("0.0.0.0"), want: prefixes("0.0.0.0/32")},
		{input: rng("255.255.255.255"), want: prefixes("255.255.255.255/32")},
		{input: rng("255.255.255.254-255.255.255.255"), want: prefixes("255.255.255.254/31")},
		{input: rng("::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: prefixes("::/0")},
		{input: rng("::"), want: prefixes("::/128")},
		{input: rng("::-::2"), want: prefixes("::/127", "::2/128")},
		{input: rng("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: prefixes("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127")},
		{input: rng("2001:db8::-2001:db8:1::"), want: prefixes("2001:db8::/48", "2001:db8:1::/128")},
		{input: rng("::ffff:192.0.2.0/120"), want: prefixes("::ffff:192.0.2.0/120")},
	} {
		if got := Cover(test.input); !reflect.DeepEqual(got, test.want) {
			t.Errorf("Cover(%v) = %v, want %v", test.input, got, test.want)
		}
	}
}

func TestCoverInnerSpaceNeedsTwoCIDRsPerBit(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		input Range
		want  int
	}{
		{input: rng("0.0.0.1-255.255.255.254"), want: 62},
		{input: rng("::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"), want: 254},
	} {
		got := Cover(test.input)
		if len(got) != test.want {
			t.Fatalf("Cover(%v) gave %d CIDRs, want %d", test.input, len(got), test.want)
		}
		assertCoverRoundTrips(t, test.input, got)
	}
}

func TestPack(t *testing.T) {
	t.Parallel()
	slash24s := func(first, count int) [][]netip.Prefix {
		var out [][]netip.Prefix
		for third := first; third < first+count; third++ {
			out = append(out, []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(third), 0}), 24)})
		}
		return out
	}
	for _, test := range []struct {
		name       string
		uncovered  []Range
		perMonitor uint64
		limit      int
		want       [][]netip.Prefix
		wantTotal  int
		// wantFirst is the address count of the first set, when not 0.
		wantFirst uint64
	}{
		{name: "nothing uncovered", uncovered: nil, perMonitor: 305, limit: 64, want: nil, wantTotal: 0},
		{name: "no room per monitor", uncovered: rngs("10.0.0.0/24"), perMonitor: 0, limit: 64, want: nil, wantTotal: 0},
		{name: "a /20 at 305 needs 16 monitors of one /24", uncovered: rngs("10.0.0.0/20"), perMonitor: 305, limit: 64, want: slash24s(0, 16), wantTotal: 16},
		{
			name:       "a /24, /27 and /28 at 305 share one monitor of 304 addresses",
			uncovered:  rngs("10.0.4.0/28", "10.0.0.0/24", "10.0.2.0/27"),
			perMonitor: 305, limit: 64,
			want:      [][]netip.Prefix{prefixes("10.0.0.0/24", "10.0.2.0/27", "10.0.4.0/28")},
			wantTotal: 1, wantFirst: 304,
		},
		{name: "truncated at the limit with the full total", uncovered: rngs("10.0.0.0/16"), perMonitor: 305, limit: 64, want: slash24s(0, 64), wantTotal: 256},
		{name: "limit 0 still counts", uncovered: rngs("10.0.0.0/16"), perMonitor: 305, limit: 0, want: nil, wantTotal: 256},
		{name: "negative limit still counts", uncovered: rngs("10.0.0.0/24", "10.1.0.0/24"), perMonitor: 305, limit: -1, want: nil, wantTotal: 2},
		{
			name:       "a /20 and a separate /27 at 305 need 16 monitors",
			uncovered:  rngs("10.0.32.0/27", "10.0.0.0/20"),
			perMonitor: 305, limit: 64,
			want:      append([][]netip.Prefix{prefixes("10.0.0.0/24", "10.0.32.0/27")}, slash24s(1, 15)...),
			wantTotal: 16, wantFirst: 288,
		},
		{
			name:       "a smaller CIDR joins the monitor of a split piece",
			uncovered:  rngs("10.0.0.0/23", "10.0.4.0/27"),
			perMonitor: 305, limit: 64,
			want:      [][]netip.Prefix{prefixes("10.0.0.0/24", "10.0.4.0/27"), prefixes("10.0.1.0/24")},
			wantTotal: 2,
		},
		{
			name:       "a smaller CIDR below a split piece joins it in address order",
			uncovered:  rngs("10.0.1.0/24", "10.0.0.0/27"),
			perMonitor: 305, limit: 64,
			want:      [][]netip.Prefix{prefixes("10.0.0.0/27", "10.0.1.0/24")},
			wantTotal: 1,
		},
		{
			name:       "CIDRs of P addresses open their monitors before smaller CIDRs",
			uncovered:  rngs("10.0.0.0/25", "10.0.1.0/24"),
			perMonitor: 300, limit: 64,
			want:      [][]netip.Prefix{prefixes("10.0.1.0/24"), prefixes("10.0.0.0/25")},
			wantTotal: 2,
		},
		{
			name:       "smaller CIDRs fill the pieces of one split CIDR first fit",
			uncovered:  rngs("10.0.0.0/22", "10.0.8.0/27", "10.0.8.64/27", "10.0.9.0/28", "10.0.9.32/28", "10.0.10.0/29"),
			perMonitor: 305, limit: 64,
			want: [][]netip.Prefix{
				prefixes("10.0.0.0/24", "10.0.8.0/27", "10.0.9.0/28"),
				prefixes("10.0.1.0/24", "10.0.8.64/27", "10.0.9.32/28"),
				prefixes("10.0.2.0/24", "10.0.10.0/29"),
				prefixes("10.0.3.0/24"),
			},
			wantTotal: 4, wantFirst: 304,
		},
		{
			name:       "smaller CIDRs fill pieces beyond the limit without building them",
			uncovered:  rngs("10.0.0.0/22", "10.0.8.0/27", "10.0.8.64/27", "10.0.9.0/28"),
			perMonitor: 305, limit: 1,
			want:      [][]netip.Prefix{prefixes("10.0.0.0/24", "10.0.8.0/27", "10.0.9.0/28")},
			wantTotal: 4,
		},
		{
			name:       "IPv4 and IPv6 never share a monitor",
			uncovered:  rngs("2001:db8::/125", "10.0.0.0/24"),
			perMonitor: 305, limit: 64,
			want:      [][]netip.Prefix{prefixes("10.0.0.0/24"), prefixes("2001:db8::/125")},
			wantTotal: 2,
		},
		{
			name:       "small IPv4 and IPv6 CIDRs pack apart, IPv4 first",
			uncovered:  rngs("2001:db8::/126", "10.0.0.0/30", "2001:db8::100/126", "10.0.0.8/30"),
			perMonitor: 305, limit: 64,
			want:      [][]netip.Prefix{prefixes("10.0.0.0/30", "10.0.0.8/30"), prefixes("2001:db8::/126", "2001:db8::100/126")},
			wantTotal: 2,
		},
		{
			name:       "IPv6 sets follow the IPv4 sets within the limit",
			uncovered:  rngs("2001:db8::/120", "10.0.0.0/23"),
			perMonitor: 305, limit: 2,
			want:      slash24s(0, 2),
			wantTotal: 3,
		},
		{
			name:       "the IPv4 top and the IPv6 bottom stay apart",
			uncovered:  rngs("255.255.255.255", "::"),
			perMonitor: 305, limit: 64,
			want:      [][]netip.Prefix{prefixes("255.255.255.255/32"), prefixes("::/128")},
			wantTotal: 2,
		},
		{
			name:       "first fit returns to an earlier monitor",
			uncovered:  rngs("10.0.0.0/27", "10.0.1.0/27", "10.0.2.0/28", "10.0.3.0/29"),
			perMonitor: 40, limit: 64,
			want:      [][]netip.Prefix{prefixes("10.0.0.0/27", "10.0.3.0/29"), prefixes("10.0.1.0/27"), prefixes("10.0.2.0/28")},
			wantTotal: 3,
		},
		{
			name:       "monitors beyond the limit keep their capacity",
			uncovered:  rngs("10.0.0.0/27", "10.0.1.0/27", "10.0.2.0/29", "10.0.3.0/29"),
			perMonitor: 40, limit: 1,
			want:      [][]netip.Prefix{prefixes("10.0.0.0/27", "10.0.2.0/29")},
			wantTotal: 2,
		},
		{
			name:       "uncovered ranges are merged and covered first",
			uncovered:  rngs("10.0.0.0/26", "10.0.0.64-10.0.0.70", "10.0.0.32/27"),
			perMonitor: 305, limit: 64,
			want:      [][]netip.Prefix{prefixes("10.0.0.0/26", "10.0.0.64/30", "10.0.0.68/31", "10.0.0.70/32")},
			wantTotal: 1,
		},
		{name: "one address per monitor", uncovered: rngs("10.0.0.0/30"), perMonitor: 1, limit: 64, want: [][]netip.Prefix{prefixes("10.0.0.0/32"), prefixes("10.0.0.1/32"), prefixes("10.0.0.2/32"), prefixes("10.0.0.3/32")}, wantTotal: 4},
		{name: "IPv4 space at one address per monitor", uncovered: rngs("0.0.0.0/0"), perMonitor: 1, limit: 2, want: [][]netip.Prefix{prefixes("0.0.0.0/32"), prefixes("0.0.0.1/32")}, wantTotal: 1 << 32},
		{name: "IPv4 top at one address per monitor", uncovered: rngs("255.255.255.254/31"), perMonitor: 1, limit: 64, want: [][]netip.Prefix{prefixes("255.255.255.254/32"), prefixes("255.255.255.255/32")}, wantTotal: 2},
		{name: "largest per-monitor size", uncovered: rngs("0.0.0.0/0", "10.0.0.0/8"), perMonitor: math.MaxUint64, limit: 64, want: [][]netip.Prefix{prefixes("0.0.0.0/0")}, wantTotal: 1},
		{name: "IPv6 total stops at MaxInt", uncovered: rngs("::/0"), perMonitor: 305, limit: 2, want: [][]netip.Prefix{prefixes("::/120"), prefixes("::100/120")}, wantTotal: math.MaxInt},
		{name: "IPv6 top", uncovered: rngs("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fe00/119"), perMonitor: 256, limit: 64, want: [][]netip.Prefix{prefixes("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fe00/120"), prefixes("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00/120")}, wantTotal: 2},
		{
			name:       "a smaller CIDR joins the first piece of a huge IPv6 range",
			uncovered:  rngs("2001:db9::/126", "2001:db8::/64"),
			perMonitor: 305, limit: 2,
			want:      [][]netip.Prefix{prefixes("2001:db8::/120", "2001:db9::/126"), prefixes("2001:db8::100/120")},
			wantTotal: 1 << 56,
		},
		{name: "IPv6 total saturates across ranges", uncovered: rngs("::/4", "8000::/4"), perMonitor: 1 << 62, limit: 0, want: nil, wantTotal: math.MaxInt},
	} {
		sets, total := Pack(test.uncovered, test.perMonitor, test.limit)
		if !reflect.DeepEqual(sets, test.want) || total != test.wantTotal {
			t.Errorf("%s: Pack = %v, %d, want %v, %d", test.name, sets, total, test.want, test.wantTotal)
		}
		for index, set := range sets {
			if _, saturated := CountCapped(prefixRanges(set), test.perMonitor); saturated {
				t.Errorf("%s: set %d holds more than %d addresses", test.name, index, test.perMonitor)
			}
		}
		if test.wantFirst != 0 {
			if count, _ := CountCapped(prefixRanges(sets[0]), math.MaxUint64); count != test.wantFirst {
				t.Errorf("%s: the first set holds %d addresses, want %d", test.name, count, test.wantFirst)
			}
		}
	}
}

// referencePack builds every set of Pack's documented packing the plain way:
// it lists each P-sized piece of each family, then places each smaller CIDR
// with a linear first-fit search. It is only for small inputs.
func referencePack(uncovered []Range, perMonitor uint64) [][]netip.Prefix {
	shift := bits.Len64(perMonitor) - 1
	merged := Merge(uncovered)
	var out [][]netip.Prefix
	for _, ipv6 := range []bool{false, true} {
		var sets [][]netip.Prefix
		var free []uint64
		var small []netip.Prefix
		for _, r := range merged {
			if r.From.Is6() != ipv6 {
				continue
			}
			for _, prefix := range Cover(r) {
				if prefix.Addr().BitLen()-prefix.Bits() < shift {
					small = append(small, prefix)
					continue
				}
				for piece := netip.PrefixFrom(prefix.Addr(), prefix.Addr().BitLen()-shift); piece.IsValid() && prefix.Contains(piece.Addr()); piece = netip.PrefixFrom(lastAddr(piece).Next(), piece.Bits()) {
					sets = append(sets, []netip.Prefix{piece})
					free = append(free, perMonitor-uint64(1)<<shift)
				}
			}
		}
		for _, prefix := range small {
			size := uint64(1) << (prefix.Addr().BitLen() - prefix.Bits())
			index := slices.IndexFunc(free, func(room uint64) bool { return room >= size })
			if index < 0 {
				sets, free = append(sets, nil), append(free, perMonitor)
				index = len(sets) - 1
			}
			sets[index] = append(sets[index], prefix)
			free[index] -= size
		}
		for _, set := range sets {
			slices.SortFunc(set, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
		}
		out = append(out, sets...)
	}
	return out
}

// referenceFits reports whether the CIDRs of at least P addresses that Pack
// splits make at most limit pieces, so that referencePack can build them.
func referenceFits(uncovered []Range, perMonitor, limit uint64) bool {
	shift := bits.Len64(perMonitor) - 1
	var pieces uint64
	for _, r := range Merge(uncovered) {
		for _, prefix := range Cover(r) {
			extra := prefix.Addr().BitLen() - prefix.Bits() - shift
			if extra < 0 {
				continue
			}
			if extra >= bits.Len64(limit) {
				return false
			}
			if pieces += uint64(1) << extra; pieces > limit {
				return false
			}
		}
	}
	return true
}

// assertPackMatchesReference fails the test unless Pack gives the
// reference's total and its first limit sets.
func assertPackMatchesReference(t *testing.T, uncovered []Range, perMonitor uint64, limit int) {
	t.Helper()
	want := referencePack(uncovered, perMonitor)
	sets, total := Pack(uncovered, perMonitor, limit)
	if total != len(want) {
		t.Fatalf("Pack(%v, %d) total = %d, the reference packer needs %d", uncovered, perMonitor, total, len(want))
	}
	want = want[:min(len(want), max(limit, 0))]
	if !slices.EqualFunc(sets, want, slices.Equal) {
		t.Fatalf("Pack(%v, %d, %d) = %v, the reference packer gives %v", uncovered, perMonitor, limit, sets, want)
	}
}

// Pack agrees with the reference packer on many small spaces of both
// families, whose ranges overlap, touch and leave gaps.
func TestPackMatchesReference(t *testing.T) {
	t.Parallel()
	random := rand.New(rand.NewPCG(1612, 76))
	sizes := []uint64{1, 2, 3, 7, 8, 40, 255, 256, 257, 300, 305, 511, 1024, 4096}
	ipv6Base := netip.MustParseAddr("2001:db8::").As16()
	for iteration := range 400 {
		var uncovered []Range
		for range 1 + random.IntN(10) {
			from := random.Uint32N(1 << 13)
			to := from + random.Uint32N(600)
			if random.IntN(3) == 0 {
				low, high := ipv6Base, ipv6Base
				low[14], low[15] = byte(from>>8), byte(from)
				high[14], high[15] = byte(to>>8), byte(to)
				uncovered = append(uncovered, Range{From: netip.AddrFrom16(low), To: netip.AddrFrom16(high)})
				continue
			}
			uncovered = append(uncovered, Range{From: netip.AddrFrom4([4]byte{10, 0, byte(from >> 8), byte(from)}), To: netip.AddrFrom4([4]byte{10, 0, byte(to >> 8), byte(to)})})
		}
		perMonitor := sizes[random.IntN(len(sizes))]
		if iteration%4 == 0 {
			perMonitor = 1 + random.Uint64N(5000)
		}
		assertPackMatchesReference(t, uncovered, perMonitor, random.IntN(40))
	}
}

func TestPackNeverIncludesExcludedSpace(t *testing.T) {
	t.Parallel()
	declared := rngs("192.0.2.0/24")
	excluded := rngs("192.0.2.10", "192.0.2.128/26")
	uncovered := Subtract(declared, excluded)
	sets, total := Pack(uncovered, 305, 64)
	if total != 1 || len(sets) != 1 {
		t.Fatalf("Pack = %v, %d, want one monitor", sets, total)
	}
	if overlap := Intersect(prefixRanges(sets[0]), excluded); overlap != nil {
		t.Fatalf("Pack included excluded addresses %v", overlap)
	}
	if got, _ := CountCapped(prefixRanges(sets[0]), math.MaxUint64); got != 256-1-64 {
		t.Fatalf("Pack placed %d addresses, want %d", got, 256-1-64)
	}
	again, againTotal := Pack(uncovered, 305, 64)
	if !reflect.DeepEqual(again, sets) || againTotal != total {
		t.Fatalf("Pack is not deterministic: %v, %d then %v, %d", sets, total, again, againTotal)
	}
}

func TestTargetRanges(t *testing.T) {
	t.Parallel()
	targets := []string{
		"192.0.2.1",
		" 192.0.2.2\t",
		"192.0.2.77/24",
		"198.51.100.9/32",
		"192.0.2.0/024",
		"2001:DB8::1",
		"2001:db8::1/32",
		"::ffff:203.0.113.9",
		"::ffff:203.0.113.77/120",
		"::ffff:0:0/96",
		"::ffff:0:0/95",
		"0.0.0.0",
		"::",
		"192.0.2.0/24",
		"fe80::1%eth0",
		"fe80::%eth0/64",
		"example.com",
		"10.0.0.1-10",
		"192.0.2.0/33",
		"010.0.0.1",
		"AS64496",
		"",
	}
	ranges, dnsNames := TargetRanges(targets)
	want := rngs(
		"192.0.2.1",
		"192.0.2.2",
		"192.0.2.0/24",
		"198.51.100.9",
		"192.0.2.0/24",
		"2001:db8::1",
		"2001:db8::/32",
		"203.0.113.9",
		"203.0.113.0/24",
		"0.0.0.0/0",
		// Shorter than /96, the masked network is no longer mapped, so it
		// stays IPv6 for net.ParseCIDR too.
		"::fffe:0:0/95",
		"0.0.0.0",
		"::",
		"192.0.2.0/24",
	)
	if !reflect.DeepEqual(ranges, want) {
		t.Errorf("TargetRanges ranges = %v, want %v", ranges, want)
	}
	if dnsNames != 8 {
		t.Errorf("TargetRanges dnsNames = %d, want 8", dnsNames)
	}
	if ranges, dnsNames := TargetRanges(nil); ranges != nil || dnsNames != 0 {
		t.Errorf("TargetRanges(nil) = %v, %d", ranges, dnsNames)
	}
}

func prefixRanges(set []netip.Prefix) []Range {
	out := make([]Range, 0, len(set))
	for _, prefix := range set {
		out = append(out, FromPrefix(prefix))
	}
	return out
}

func assertCoverRoundTrips(t *testing.T, r Range, cover []netip.Prefix) {
	t.Helper()
	if len(cover) == 0 || len(cover) > 2*r.From.BitLen() {
		t.Fatalf("Cover(%v) gave %d CIDRs", r, len(cover))
	}
	for index, prefix := range cover {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().BitLen() != r.From.BitLen() {
			t.Fatalf("Cover(%v) gave the unaligned or foreign CIDR %v", r, prefix)
		}
		if index == 0 {
			continue
		}
		previous := cover[index-1]
		if lastAddr(previous).Next() != prefix.Addr() {
			t.Fatalf("Cover(%v) leaves a gap or overlap between %v and %v", r, previous, prefix)
		}
		// Two sibling CIDRs would form their parent, so the cover would
		// not be the fewest.
		if previous.Bits() == prefix.Bits() && previous.Bits() > 0 {
			parent := netip.PrefixFrom(previous.Addr(), previous.Bits()-1).Masked()
			if parent.Contains(prefix.Addr()) {
				t.Fatalf("Cover(%v) did not join the siblings %v and %v", r, previous, prefix)
			}
		}
	}
	if got := Merge(prefixRanges(cover)); !reflect.DeepEqual(got, []Range{r}) {
		t.Fatalf("Cover(%v) round-trips to %v", r, got)
	}
}

// fuzzRanges decodes up to 48 ranges of nine bytes each. The first byte picks
// the family and, for IPv6, where the other eight bytes land, so that ranges
// overlap often and reach both ends of each family and the mapped space.
func fuzzRanges(raw []byte) []Range {
	var out []Range
	for len(raw) >= 9 && len(out) < 48 {
		flags, from, to := raw[0], raw[1:5], raw[5:9]
		raw = raw[9:]
		var a, b netip.Addr
		if flags&1 == 0 {
			a, b = netip.AddrFrom4([4]byte(from)), netip.AddrFrom4([4]byte(to))
		} else {
			var lowA, lowB [16]byte
			switch flags >> 1 & 3 {
			case 0: // near ::
				copy(lowA[12:], from)
				copy(lowB[12:], to)
			case 1: // near the last address
				for i := range 12 {
					lowA[i], lowB[i] = 0xff, 0xff
				}
				copy(lowA[12:], from)
				copy(lowB[12:], to)
			case 2: // large blocks
				copy(lowA[:4], from)
				copy(lowB[:4], to)
				for i := 4; i < 16; i++ {
					lowB[i] = 0xff
				}
			case 3: // IPv4-mapped
				lowA[10], lowA[11], lowB[10], lowB[11] = 0xff, 0xff, 0xff, 0xff
				copy(lowA[12:], from)
				copy(lowB[12:], to)
			}
			a, b = netip.AddrFrom16(lowA), netip.AddrFrom16(lowB)
		}
		if b.Less(a) {
			a, b = b, a
		}
		out = append(out, Range{From: a, To: b})
	}
	return out
}

func bigCount(r []Range) *big.Int {
	total := new(big.Int)
	for _, item := range r {
		from, to := item.From.As16(), item.To.As16()
		size := new(big.Int).Sub(new(big.Int).SetBytes(to[:]), new(big.Int).SetBytes(from[:]))
		total.Add(total, size.Add(size, big.NewInt(1)))
	}
	return total
}

func fuzzSeed(ranges ...string) []byte {
	var out []byte
	for _, value := range ranges {
		r := rng(value)
		if r.From.Is4() {
			from, to := r.From.As4(), r.To.As4()
			out = append(append(append(out, 0), from[:]...), to[:]...)
			continue
		}
		from, to := r.From.As16(), r.To.As16()
		out = append(append(append(out, 1), from[12:]...), to[12:]...)
	}
	return out
}

func FuzzSubtractCover(f *testing.F) {
	f.Add(fuzzSeed("10.0.0.0/20"), fuzzSeed("10.0.4.0/24"), uint64(305), uint8(64))
	f.Add(fuzzSeed("10.0.0.0/24", "10.0.2.0/27", "10.0.4.0/28"), []byte(nil), uint64(305), uint8(64))
	f.Add(fuzzSeed("10.0.0.0/16"), fuzzSeed("10.0.0.10", "10.0.128.0/26"), uint64(305), uint8(64))
	f.Add(fuzzSeed("0.0.0.0/0"), fuzzSeed("0.0.0.0", "255.255.255.255"), uint64(1), uint8(3))
	f.Add(fuzzSeed("::-::ffff:ffff"), fuzzSeed("::1"), uint64(0), uint8(8))
	f.Add([]byte{3, 0, 0, 0, 0, 255, 255, 255, 255}, []byte{5, 0, 0, 0, 1, 255, 255, 255, 254}, uint64(1<<40), uint8(5))
	f.Add([]byte{7, 192, 0, 2, 0, 192, 0, 2, 255, 0, 192, 0, 2, 0, 192, 0, 2, 255}, []byte{1, 0, 0, 0, 0, 0, 0, 0, 9}, uint64(math.MaxUint64), uint8(255))
	f.Add(fuzzSeed("10.0.0.0/20", "10.0.32.0/27"), []byte(nil), uint64(305), uint8(64))
	f.Add(fuzzSeed("10.0.0.0/27", "10.0.1.0/24", "10.0.8.0/22", "10.0.16.0/29"), fuzzSeed("10.0.9.0/28"), uint64(300), uint8(3))
	f.Add(fuzzSeed("10.0.0.0/24", "::-::ff", "255.255.255.0/30", "::1:0-::1:7"), []byte(nil), uint64(305), uint8(64))
	f.Fuzz(func(t *testing.T, rawA, rawB []byte, perMonitor uint64, limit uint8) {
		a, b := fuzzRanges(rawA), fuzzRanges(rawB)
		merged := Merge(a)
		sub, inter := Subtract(a, b), Intersect(a, b)

		// Subtract and Intersect split Merge(a) exactly, in canonical form.
		if got := Merge(append(slices.Clone(sub), inter...)); !reflect.DeepEqual(got, merged) {
			t.Fatalf("Subtract ∪ Intersect = %v, want Merge(a) = %v", got, merged)
		}
		for name, ranges := range map[string][]Range{"Merge": merged, "Subtract": sub, "Intersect": inter} {
			if got := Merge(ranges); !reflect.DeepEqual(got, ranges) {
				t.Fatalf("%s is not canonical: %v merges to %v", name, ranges, got)
			}
		}
		if overlap := Intersect(sub, b); overlap != nil {
			t.Fatalf("Subtract kept %v of b", overlap)
		}
		if rest := Subtract(inter, b); rest != nil {
			t.Fatalf("Intersect holds %v outside b", rest)
		}
		if reverse := Intersect(b, a); !reflect.DeepEqual(reverse, inter) {
			t.Fatalf("Intersect is not symmetric: %v and %v", inter, reverse)
		}

		// Cover round-trips every range exactly with the fewest CIDRs.
		for _, r := range append(slices.Clone(sub), inter...) {
			assertCoverRoundTrips(t, r, Cover(r))
		}

		// CountCapped never overflows and saturates exactly above limit.
		all := append(slices.Clone(a), b...)
		count, saturated := CountCapped(all, perMonitor)
		exact := bigCount(all)
		perMonitorBig := new(big.Int).SetUint64(perMonitor)
		if over := exact.Cmp(perMonitorBig) > 0; over != saturated || count > perMonitor {
			t.Fatalf("CountCapped = %d, %v for %s addresses at limit %d", count, saturated, exact, perMonitor)
		}
		if !saturated && new(big.Int).SetUint64(count).Cmp(exact) != 0 {
			t.Fatalf("CountCapped = %d, want %s", count, exact)
		}

		// Pack stays within perMonitor and the uncovered space, numbers its
		// sets up to the limit, keeps the families apart, and is
		// deterministic.
		sets, total := Pack(sub, perMonitor, int(limit))
		again, againTotal := Pack(sub, perMonitor, int(limit))
		if !reflect.DeepEqual(sets, again) || total != againTotal {
			t.Fatalf("Pack is not deterministic")
		}
		if perMonitor == 0 {
			if sets != nil || total != 0 {
				t.Fatalf("Pack with no room = %v, %d", sets, total)
			}
			return
		}
		if len(sets) != min(total, int(limit)) {
			t.Fatalf("Pack built %d sets for a total of %d at limit %d", len(sets), total, limit)
		}
		var placed []Range
		for index, set := range sets {
			ranges := prefixRanges(set)
			if len(set) == 0 {
				t.Fatalf("Pack built the empty set %d", index)
			}
			if !slices.IsSortedFunc(set, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) }) {
				t.Fatalf("Pack set %d %v is not in address order", index, set)
			}
			for _, prefix := range set {
				if prefix.Addr().Is4() != set[0].Addr().Is4() {
					t.Fatalf("Pack set %d %v mixes IPv4 and IPv6", index, set)
				}
			}
			if index > 0 && sets[index-1][0].Addr().Is6() && set[0].Addr().Is4() {
				t.Fatalf("Pack set %d %v follows an IPv6 set", index, set)
			}
			if _, over := CountCapped(ranges, perMonitor); over {
				t.Fatalf("Pack set %d %v holds more than %d addresses", index, set, perMonitor)
			}
			placed = append(placed, ranges...)
		}
		if rest := Subtract(placed, sub); rest != nil {
			t.Fatalf("Pack placed %v outside the uncovered space", rest)
		}
		if overlap := Intersect(placed, b); overlap != nil {
			t.Fatalf("Pack placed the subtracted space %v", overlap)
		}
		if placedCount, mergedCount := bigCount(placed), bigCount(Merge(placed)); placedCount.Cmp(mergedCount) != 0 {
			t.Fatalf("Pack placed an address twice")
		}
		if total <= int(limit) && !reflect.DeepEqual(Merge(placed), sub) {
			t.Fatalf("Pack placed %v, want all of %v", Merge(placed), sub)
		}
		if total < math.MaxInt {
			needed := new(big.Int).Mul(big.NewInt(int64(total)), perMonitorBig)
			if needed.Cmp(bigCount(sub)) < 0 {
				t.Fatalf("Pack total %d cannot hold %s addresses at %d each", total, bigCount(sub), perMonitor)
			}
		}

		// Pack builds what a packer that builds every set builds, while its
		// split pieces are few enough to build.
		if referenceFits(sub, perMonitor, 1<<12) {
			assertPackMatchesReference(t, sub, perMonitor, int(limit))
		}
	})
}
