// Package addrspace does arithmetic on inclusive ranges of IP addresses: it
// merges, subtracts, intersects and counts ranges, covers a range with the
// fewest aligned CIDRs, and packs address space into target sets of a fixed
// size. It also reads the IP and CIDR targets of a job the way config
// validation and the scanner parse them.
//
// Every Range holds addresses of one family, and no function joins IPv4 and
// IPv6 addresses into one range. An IPv4-mapped IPv6 address is an IPv6
// address here; TargetRanges unmaps it to IPv4, as the scanner does. The
// package does no I/O.
package addrspace

import (
	"encoding/binary"
	"math"
	"math/bits"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// Range is the inclusive span of addresses from From to To.
type Range struct{ From, To netip.Addr }

// Valid reports whether r has two valid ends of one family without a zone,
// and From is not after To. The functions of this package skip a range that
// is not valid.
func (r Range) Valid() bool {
	return r.From.IsValid() && r.To.IsValid() &&
		r.From.BitLen() == r.To.BitLen() &&
		r.From.Zone() == "" && r.To.Zone() == "" &&
		r.From.Compare(r.To) <= 0
}

// FromPrefix returns the range of every address in p, with its host bits
// masked. It returns the zero Range, which is not valid, for an invalid
// prefix.
func FromPrefix(p netip.Prefix) Range {
	if !p.IsValid() {
		return Range{}
	}
	p = p.Masked()
	return Range{From: p.Addr(), To: lastAddr(p)}
}

// Merge returns the valid ranges of r in address order, IPv4 before IPv6,
// with overlapping and adjacent ranges of one family joined. Merge, Subtract
// and Intersect all return this canonical form, which is nil when no address
// remains. Merge does not modify r.
func Merge(r []Range) []Range {
	sorted := make([]Range, 0, len(r))
	for _, item := range r {
		if item.Valid() {
			sorted = append(sorted, item)
		}
	}
	slices.SortFunc(sorted, func(a, b Range) int {
		if order := a.From.Compare(b.From); order != 0 {
			return order
		}
		return a.To.Compare(b.To)
	})
	var out []Range
	for _, item := range sorted {
		if n := len(out); n > 0 {
			last := &out[n-1]
			// Next of the family's last address is the zero Addr, which
			// never equals a valid From, so the families stay apart.
			if item.From.BitLen() == last.To.BitLen() && (item.From.Compare(last.To) <= 0 || item.From == last.To.Next()) {
				if item.To.Compare(last.To) > 0 {
					last.To = item.To
				}
				continue
			}
		}
		out = append(out, item)
	}
	return out
}

// Subtract returns the addresses of a that are not in b, merged.
func Subtract(a, b []Range) []Range {
	a, b = Merge(a), Merge(b)
	var out []Range
	next := 0
	for _, r := range a {
		for next < len(b) && b[next].To.Less(r.From) {
			next++
		}
		// A range of b that overlaps r has r's family: Compare orders every
		// IPv4 address before every IPv6 address, so a range of the other
		// family ends before r.From or starts after r.To.
		from, open := r.From, true
		for k := next; open && k < len(b) && b[k].From.Compare(r.To) <= 0; k++ {
			if from.Less(b[k].From) {
				out = append(out, Range{From: from, To: b[k].From.Prev()})
			}
			if b[k].To.Less(r.To) {
				from = b[k].To.Next()
			} else {
				open = false
			}
		}
		if open {
			out = append(out, Range{From: from, To: r.To})
		}
	}
	return out
}

// Intersect returns the addresses that are in both a and b, merged.
func Intersect(a, b []Range) []Range {
	a, b = Merge(a), Merge(b)
	var out []Range
	for i, j := 0, 0; i < len(a) && j < len(b); {
		from, to := a[i].From, a[i].To
		if from.Less(b[j].From) {
			from = b[j].From
		}
		if b[j].To.Less(to) {
			to = b[j].To
		}
		// Ranges of different families give from after to, so they add
		// nothing.
		if from.Compare(to) <= 0 {
			out = append(out, Range{From: from, To: to})
		}
		if a[i].To.Less(b[j].To) {
			i++
		} else {
			j++
		}
	}
	return out
}

// CountCapped returns the number of addresses in r, counting each range as
// given: an address that two ranges share counts twice, so Merge r first to
// count its union. The count stops at limit, and saturated reports that the
// true count is above limit. A range that is not valid counts nothing. The
// arithmetic cannot overflow, so IPv6 ranges of any size are safe.
func CountCapped(r []Range, limit uint64) (count uint64, saturated bool) {
	for _, item := range r {
		if !item.Valid() {
			continue
		}
		// The range holds To-From+1 addresses, which is at least 2^64 when
		// the difference does not fit below the largest uint64.
		hi, lo := span(item)
		if hi != 0 || lo == math.MaxUint64 {
			return limit, true
		}
		sum, carry := bits.Add64(count, lo+1, 0)
		if carry != 0 || sum > limit {
			return limit, true
		}
		count = sum
	}
	return count, false
}

// Cover returns the fewest CIDRs that hold exactly the addresses of r, in
// address order, each aligned on its own size. It returns nil for a range
// that is not valid.
func Cover(r Range) []netip.Prefix {
	if !r.Valid() {
		return nil
	}
	var out []netip.Prefix
	for from := r.From; ; {
		prefix := largestPrefix(from, r.To)
		out = append(out, prefix)
		last := lastAddr(prefix)
		if last == r.To {
			return out
		}
		from = last.Next()
	}
}

// Pack divides the addresses of uncovered into target sets of at most
// perMonitor addresses, one set per monitor. It returns the first limit sets
// and total, the number of sets that the whole space needs.
//
// The packing is deterministic, and no set mixes IPv4 and IPv6: Pack packs
// the IPv4 space first and the IPv6 space after it, each on its own. Within a
// family, Pack takes the CIDRs that Cover gives for the merged ranges, in
// address order, and lets P be the largest power of two not above
// perMonitor. Each CIDR of P or more addresses splits into aligned CIDRs of
// size P, and each of those opens a set of its own; Pack counts these sets
// instead of building more than limit of them. Each smaller CIDR then joins,
// in address order, the first set, in the order the sets open, that still
// has room for it, a set of a split CIDR included, and opens a new set only
// when none has. Pack returns the sets in the order they open, and each set
// lists its CIDRs in address order.
//
// A perMonitor of 0 holds no address: Pack returns no set and a total of 0,
// so a caller checks the size before it packs. A limit of 0 or less returns
// no set but still the total. The total stops at math.MaxInt, which only an
// IPv6 space can reach.
func Pack(uncovered []Range, perMonitor uint64, limit int) (sets [][]netip.Prefix, total int) {
	if perMonitor == 0 {
		return nil, 0
	}
	merged := Merge(uncovered)
	// Merge orders every IPv4 range before every IPv6 range.
	split := slices.IndexFunc(merged, func(r Range) bool { return r.From.Is6() })
	if split < 0 {
		split = len(merged)
	}
	for _, family := range [][]Range{merged[:split], merged[split:]} {
		familySets, familyTotal := packFamily(family, perMonitor, limit-len(sets))
		sets = append(sets, familySets...)
		total = addCapped(total, familyTotal)
	}
	return sets, total
}

// monitorRun is a run of sets that opened one after another and have the
// same free capacity: the sets of the pieces of one split CIDR, or a single
// set. Runs form a list, in the order their sets open, through next.
type monitorRun struct {
	// count is the number of sets in the run, which stops at math.MaxInt.
	count int
	// first is the index of the run's first set in the order the sets open,
	// which stops at math.MaxInt.
	first int
	// free is the capacity that each set of the run has left.
	free uint64
	// next is the position of the following run, or -1 for the last.
	next int
}

// packFamily packs merged ranges of one family as Pack describes.
func packFamily(merged []Range, perMonitor uint64, limit int) (sets [][]netip.Prefix, total int) {
	shift := bits.Len64(perMonitor) - 1 // P is 2^shift.
	var runs []monitorRun
	tail := -1
	open := func(run monitorRun) {
		run.next = -1
		runs = append(runs, run)
		if tail >= 0 {
			runs[tail].next = len(runs) - 1
		}
		tail = len(runs) - 1
	}
	// Each CIDR of at least P addresses opens its sets first, so a smaller
	// CIDR at a lower address can still join one of them.
	var small []netip.Prefix
	for _, r := range merged {
		for _, prefix := range Cover(r) {
			hostBits := prefix.Addr().BitLen() - prefix.Bits()
			if hostBits < shift {
				small = append(small, prefix)
				continue
			}
			pieces := math.MaxInt
			if hostBits-shift < bits.UintSize-1 {
				pieces = 1 << (hostBits - shift)
			}
			piece := netip.PrefixFrom(prefix.Addr(), prefix.Addr().BitLen()-shift)
			for n := 0; n < pieces && len(sets) < limit; n++ {
				sets = append(sets, []netip.Prefix{piece})
				piece = netip.PrefixFrom(lastAddr(piece).Next(), piece.Bits())
			}
			open(monitorRun{count: pieces, first: total, free: perMonitor - 1<<shift})
			total = addCapped(total, pieces)
		}
	}
	// firstFit[k] is the run from which to look for room for 2^k addresses,
	// or -1 for the first run: no earlier set has room, because free capacity
	// only shrinks and a run that a split leaves behind its first set keeps
	// that set's former capacity.
	var firstFit [64]int
	for k := range firstFit {
		firstFit[k] = -1
	}
	for _, prefix := range small {
		hostBits := prefix.Addr().BitLen() - prefix.Bits()
		size := uint64(1) << hostBits
		at := firstFit[hostBits]
		if at < 0 && len(runs) > 0 {
			at = 0
		}
		for at >= 0 && runs[at].free < size {
			at = runs[at].next
		}
		if at < 0 {
			// No set has room: open one, at the end of the order.
			if total < limit {
				sets = append(sets, nil)
			}
			open(monitorRun{count: 1, first: total, free: perMonitor})
			total = addCapped(total, 1)
			at = tail
		} else if runs[at].count > 1 {
			// The run's first set takes the CIDR; the others keep their
			// capacity as the run that follows it.
			rest := runs[at]
			rest.count--
			rest.first = addCapped(rest.first, 1)
			runs = append(runs, rest)
			runs[at].count, runs[at].next = 1, len(runs)-1
			if tail == at {
				tail = len(runs) - 1
			}
		}
		firstFit[hostBits] = at
		runs[at].free -= size
		if index := runs[at].first; index < limit {
			sets[index] = append(sets[index], prefix)
		}
	}
	// A smaller CIDR can join the set of a split CIDR at a higher address.
	for _, set := range sets {
		slices.SortFunc(set, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	}
	return sets, total
}

// TargetRanges returns the range of every IP and CIDR target in targets, in
// target order, and counts every other target, which the scanner resolves
// through DNS, as a DNS name. Overlapping targets keep a range each.
func TargetRanges(targets []string) (ranges []Range, dnsNames int) {
	for _, target := range targets {
		if r, ok := TargetRange(target); ok {
			ranges = append(ranges, r)
			continue
		}
		dnsNames++
	}
	return ranges, dnsNames
}

// TargetRange returns the addresses of one IP or CIDR target, and false for
// any other target. It trims the target and parses it with net.ParseIP and
// net.ParseCIDR, as config.CanonicalTarget and the scanner do, so a value
// with an IPv6 zone is not an address, and a CIDR keeps every address of its
// masked network. An IPv4-mapped address or prefix becomes IPv4, as it does
// for the scanner, and an unspecified address is still an address.
func TargetRange(target string) (Range, bool) {
	target = strings.TrimSpace(target)
	if ip := net.ParseIP(target); ip != nil {
		addr, _ := netip.AddrFromSlice(ip)
		addr = addr.Unmap()
		return Range{From: addr, To: addr}, true
	}
	_, network, err := net.ParseCIDR(target)
	if err != nil {
		return Range{}, false
	}
	addr, _ := netip.AddrFromSlice(network.IP)
	ones, _ := network.Mask.Size()
	// Masking a mapped address to fewer than 96 bits clears part of the
	// ::ffff: marker, so only a prefix of at least 96 bits is still mapped.
	if addr.Is4In6() && ones >= 96 {
		addr, ones = addr.Unmap(), ones-96
	}
	return FromPrefix(netip.PrefixFrom(addr, ones)), true
}

// largestPrefix returns the largest CIDR that starts at from and ends no
// later than to, which is not before from.
func largestPrefix(from, to netip.Addr) netip.Prefix {
	for size := from.BitLen() - alignment(from); ; size++ {
		prefix := netip.PrefixFrom(from, size)
		if lastAddr(prefix).Compare(to) <= 0 {
			return prefix
		}
	}
}

// alignment returns the number of trailing zero bits of a, which is the
// family's bit length for the first address.
func alignment(a netip.Addr) int {
	if a.Is4() {
		b := a.As4()
		return bits.TrailingZeros32(binary.BigEndian.Uint32(b[:]))
	}
	b := a.As16()
	if lo := binary.BigEndian.Uint64(b[8:]); lo != 0 {
		return bits.TrailingZeros64(lo)
	}
	return 64 + bits.TrailingZeros64(binary.BigEndian.Uint64(b[:8]))
}

// lastAddr returns the last address of p, in p's family.
func lastAddr(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		b := p.Addr().As4()
		setHostBits(b[:], p.Bits())
		return netip.AddrFrom4(b)
	}
	b := p.Addr().As16()
	setHostBits(b[:], p.Bits())
	return netip.AddrFrom16(b)
}

func setHostBits(b []byte, networkBits int) {
	for i := range b {
		switch {
		case networkBits >= 8:
			networkBits -= 8
		case networkBits > 0:
			b[i] |= 0xff >> networkBits
			networkBits = 0
		default:
			b[i] = 0xff
		}
	}
}

// span returns To-From of a valid range as a 128-bit number.
func span(r Range) (hi, lo uint64) {
	from, to := r.From.As16(), r.To.As16()
	lo, borrow := bits.Sub64(binary.BigEndian.Uint64(to[8:]), binary.BigEndian.Uint64(from[8:]), 0)
	hi, _ = bits.Sub64(binary.BigEndian.Uint64(to[:8]), binary.BigEndian.Uint64(from[:8]), borrow)
	return hi, lo
}

func addCapped(total, n int) int {
	if n > math.MaxInt-total {
		return math.MaxInt
	}
	return total + n
}
