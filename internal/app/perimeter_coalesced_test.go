package app

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"sort"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/addrspace"
)

// perimeterCoalescedSuggestionSetsReference is perimeterCoalescedSuggestionSets
// as it was before it clipped the gaps to each candidate and searched base
// for containment: it merges the whole gap list for every candidate and
// subtracts base for every expansion step. It is kept only to prove that the
// faster version returns the same plans.
func perimeterCoalescedSuggestionSetsReference(base, gaps []addrspace.Range, perMonitor uint64) (sets []perimeterCoalescedSet, total int, truncated bool) {
	if len(gaps) == 0 || perMonitor == 0 {
		return nil, 0, false
	}
	maxAddresses := min(perMonitor, uint64(1<<(32-perimeterMaxCoalescedPrefixBits)))
	minPrefixBits := max(perimeterMaxCoalescedPrefixBits, 32-(bits.Len64(maxAddresses)-1))
	if !perimeterCoalescingCanIncludeCoveredReference(base, gaps, minPrefixBits) {
		return nil, 0, false
	}
	seen := make(map[netip.Prefix]struct{})
	var current perimeterCoalescedSet
	var currentAddresses uint64
	tooMany := false

	flush := func() {
		if len(current.targets) == 0 {
			return
		}
		sets = append(sets, current)
		current = perimeterCoalescedSet{}
		currentAddresses = 0
	}
	add := func(piece netip.Prefix) bool {
		candidate := piece
		for candidate.Bits() > minPrefixBits {
			parent := netip.PrefixFrom(candidate.Addr(), candidate.Bits()-1).Masked()
			parentRange := addrspace.FromPrefix(parent)
			if len(addrspace.Subtract([]addrspace.Range{parentRange}, base)) != 0 {
				break
			}
			candidate = parent
		}
		if _, exists := seen[candidate]; exists {
			return true
		}

		candidateRange := addrspace.FromPrefix(candidate)
		addresses := uint64(1) << uint(32-candidate.Bits())
		gapAddresses, _ := addrspace.CountCapped(addrspace.Intersect([]addrspace.Range{candidateRange}, gaps), addresses)
		alreadyCovered := int(addresses - gapAddresses)
		if len(current.targets) > 0 && (currentAddresses+addresses > perMonitor || len(current.targets) >= perimeterMaxCoalescedTargets) {
			flush()
			if len(sets) >= perimeterMaxCoalescedSuggestions {
				tooMany = true
				return false
			}
		}
		seen[candidate] = struct{}{}
		current.targets = append(current.targets, candidate)
		currentAddresses += addresses
		current.alreadyCovered += alreadyCovered
		return true
	}

	var walkPrefix func(netip.Prefix, func(netip.Prefix) bool) bool
	walkPrefix = func(prefix netip.Prefix, visit func(netip.Prefix) bool) bool {
		if prefix.Bits() >= minPrefixBits {
			return visit(prefix)
		}
		childBits := prefix.Bits() + 1
		left := netip.PrefixFrom(prefix.Addr(), childBits).Masked()
		right := netip.PrefixFrom(addrspace.FromPrefix(left).To.Next(), childBits).Masked()
		return walkPrefix(left, visit) && walkPrefix(right, visit)
	}
	for _, gap := range gaps {
		for _, prefix := range addrspace.Cover(gap) {
			if !walkPrefix(prefix, add) {
				break
			}
		}
		if tooMany {
			break
		}
	}
	if tooMany {
		return nil, perimeterMaxCoalescedSuggestions + 1, true
	}
	flush()
	return sets, len(sets), false
}

// perimeterCoalescingCanIncludeCoveredReference is the preflight of the
// reference, as it was.
func perimeterCoalescingCanIncludeCoveredReference(base, gaps []addrspace.Range, minPrefixBits int) bool {
	if len(base) == 0 || len(gaps) == 0 || minPrefixBits >= 32 {
		return false
	}
	gaps = addrspace.Intersect(base, gaps)
	covered := addrspace.Subtract(base, gaps)
	if len(gaps) == 0 || len(covered) == 0 {
		return false
	}
	fits := func(a, b netip.Addr) bool {
		if !a.Is4() || !b.Is4() {
			return false
		}
		aBytes, bBytes := a.As4(), b.As4()
		commonBits := 32
		for index := range aBytes {
			if difference := aBytes[index] ^ bBytes[index]; difference != 0 {
				commonBits = index*8 + bits.LeadingZeros8(difference)
				break
			}
		}
		if commonBits < minPrefixBits {
			return false
		}
		candidate := addrspace.FromPrefix(netip.PrefixFrom(a, commonBits).Masked())
		index := sort.Search(len(base), func(index int) bool { return base[index].To.Compare(candidate.From) >= 0 })
		return index < len(base) && base[index].From.Compare(candidate.From) <= 0 && base[index].To.Compare(candidate.To) >= 0
	}
	gapIndex, coveredIndex := 0, 0
	for gapIndex < len(gaps) && coveredIndex < len(covered) {
		gap, cover := gaps[gapIndex], covered[coveredIndex]
		switch {
		case gap.To.Less(cover.From):
			if fits(gap.To, cover.From) {
				return true
			}
			gapIndex++
		case cover.To.Less(gap.From):
			if fits(cover.To, gap.From) {
				return true
			}
			coveredIndex++
		default:
			if gap.To.Less(cover.To) {
				gapIndex++
			} else {
				coveredIndex++
			}
		}
	}
	return false
}

// perimeterTestV4 returns the IPv4 address with the numeric value n.
func perimeterTestV4(n uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
}

// randomPerimeterCoalescingCase returns a declared IPv4 range of 16 to 4,096
// addresses with random exclusions as base, its gaps after random coverage,
// and a per-monitor size from one host to the selected-TCP cap. Coverage is
// random spans, random aligned blocks, or every few addresses, so gaps range
// from one block to thousands of fragments.
func randomPerimeterCoalescingCase(rng *rand.Rand) (base, gaps []addrspace.Range, perMonitor uint64) {
	prefixBits := 20 + rng.IntN(9)
	size := uint32(1) << (32 - prefixBits)
	first := uint32(10)<<24 | rng.Uint32N(1<<24)&^(size-1)
	span := func(offset, length uint32) addrspace.Range {
		length = min(length, size-offset)
		return addrspace.Range{From: perimeterTestV4(first + offset), To: perimeterTestV4(first + offset + length - 1)}
	}
	whole := span(0, size)

	var exclusions []addrspace.Range
	for range rng.IntN(4) {
		exclusions = append(exclusions, span(rng.Uint32N(size), 1+rng.Uint32N(min(size, 48))))
	}
	var covered []addrspace.Range
	switch rng.IntN(3) {
	case 0:
		for range rng.IntN(64) {
			covered = append(covered, span(rng.Uint32N(size), 1+rng.Uint32N(min(size, 40))))
		}
	case 1:
		for range rng.IntN(24) {
			blockBits := uint32(rng.IntN(int(bits.Len32(size))))
			block := uint32(1) << blockBits
			covered = append(covered, span(rng.Uint32N(size)&^(block-1), block))
		}
	default:
		stride, phase := 2+rng.Uint32N(7), rng.Uint32N(2)
		from, to := rng.Uint32N(size), rng.Uint32N(size)
		for offset := min(from, to) + phase; offset <= max(from, to); offset += stride {
			covered = append(covered, span(offset, 1))
		}
	}
	base = addrspace.Subtract([]addrspace.Range{whole}, exclusions)
	gaps = addrspace.Subtract(base, covered)
	sizes := []uint64{1, 2, 3, 5, 8, 16, 17, 31, 64, 100, 256, 305, 1024, 4096}
	return base, gaps, sizes[rng.IntN(len(sizes))]
}

// The faster plan is the reference plan, for every random base, gap set, and
// budget, and it keeps the bounds the console and docs promise.
func TestPerimeterCoalescedSuggestionSetsMatchReference(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1673, 1674))
	var planned, cut int
	for index := range 1000 {
		base, gaps, perMonitor := randomPerimeterCoalescingCase(rng)
		sets, total, truncated := perimeterCoalescedSuggestionSets(base, gaps, perMonitor)
		wantSets, wantTotal, wantTruncated := perimeterCoalescedSuggestionSetsReference(base, gaps, perMonitor)
		if !reflect.DeepEqual(sets, wantSets) || total != wantTotal || truncated != wantTruncated {
			t.Fatalf("case %d (base %v, %d gaps, %d per monitor): plan = %v, %d, %v; reference %v, %d, %v", index, base, len(gaps), perMonitor, sets, total, truncated, wantSets, wantTotal, wantTruncated)
		}
		checkPerimeterCoalescedPlan(t, fmt.Sprintf("case %d", index), base, gaps, perMonitor, sets, total, truncated)
		if truncated {
			cut++
		} else if len(sets) > 0 {
			planned++
		}
	}
	t.Logf("%d complete plans, %d capped plans", planned, cut)
	// The cases must exercise complete plans and the cap, not only the
	// preflight's early return.
	if planned < 100 || cut < 25 {
		t.Fatalf("random cases gave %d complete plans and %d capped plans; widen the generator", planned, cut)
	}
}

// checkPerimeterCoalescedPlan fails unless the plan is the cap's empty answer,
// or no plan, or a complete plan whose targets are aligned IPv4 blocks of at
// most a /24 and the budget, inside base, without overlap, at most 16 per
// monitor and 16 monitors, that hold every gap and count every covered
// address they repeat.
func checkPerimeterCoalescedPlan(t *testing.T, name string, base, gaps []addrspace.Range, perMonitor uint64, sets []perimeterCoalescedSet, total int, truncated bool) {
	t.Helper()
	if truncated {
		if sets != nil || total != perimeterMaxCoalescedSuggestions+1 {
			t.Fatalf("%s: capped plan = %v, total %d", name, sets, total)
		}
		return
	}
	if total != len(sets) || total > perimeterMaxCoalescedSuggestions {
		t.Fatalf("%s: plan has %d sets, total %d", name, len(sets), total)
	}
	if len(sets) == 0 {
		return
	}
	maxAddresses := min(perMonitor, 1<<(32-perimeterMaxCoalescedPrefixBits))
	var targets []addrspace.Range
	var targetAddresses uint64
	repeated := 0
	for _, set := range sets {
		if len(set.targets) == 0 || len(set.targets) > perimeterMaxCoalescedTargets {
			t.Fatalf("%s: monitor has %d targets", name, len(set.targets))
		}
		var monitorAddresses uint64
		covered := 0
		for _, target := range set.targets {
			addresses := uint64(1) << (32 - target.Bits())
			if !target.Addr().Is4() || target != target.Masked() || target.Bits() < perimeterMaxCoalescedPrefixBits || addresses > maxAddresses {
				t.Fatalf("%s: target %s is not an aligned IPv4 block of at most %d addresses", name, target, maxAddresses)
			}
			r := addrspace.FromPrefix(target)
			if len(addrspace.Subtract([]addrspace.Range{r}, base)) != 0 {
				t.Fatalf("%s: target %s leaves base %v", name, target, base)
			}
			gapAddresses, _ := addrspace.CountCapped(addrspace.Intersect([]addrspace.Range{r}, gaps), addresses)
			covered += int(addresses - gapAddresses)
			monitorAddresses += addresses
			targets = append(targets, r)
		}
		if monitorAddresses > perMonitor || covered != set.alreadyCovered {
			t.Fatalf("%s: monitor %v holds %d addresses (budget %d) and repeats %d covered addresses, reported %d", name, set.targets, monitorAddresses, perMonitor, covered, set.alreadyCovered)
		}
		targetAddresses += monitorAddresses
		repeated += set.alreadyCovered
	}
	if union, _ := addrspace.CountCapped(addrspace.Merge(targets), targetAddresses+1); union != targetAddresses {
		t.Fatalf("%s: targets overlap: %d addresses in %d", name, union, targetAddresses)
	}
	if missed := addrspace.Subtract(gaps, targets); len(missed) != 0 {
		t.Fatalf("%s: plan misses gaps %v", name, missed)
	}
	if repeated == 0 {
		t.Fatalf("%s: a coalesced plan repeats no covered address", name)
	}
}

// alternatingPerimeterGaps returns a /16 as base and its odd addresses as
// gaps: 32,768 single-address gaps, each next to a covered address.
func alternatingPerimeterGaps() (base, gaps []addrspace.Range) {
	whole := addrspace.FromPrefix(netip.MustParsePrefix("10.70.0.0/16"))
	gaps = make([]addrspace.Range, 0, 1<<15)
	for host := 1; host < 1<<16; host += 2 {
		addr := netip.AddrFrom4([4]byte{10, 70, byte(host >> 8), byte(host)})
		gaps = append(gaps, addrspace.Range{From: addr, To: addr})
	}
	return []addrspace.Range{whole}, gaps
}

var perimeterCoalescedBenchmarkSink int

// The selected-TCP case is the slowest: its 4,096-address monitors make the
// complete plan sixteen monitors of sixteen /24 targets each.
func BenchmarkPerimeterCoalescedSuggestionSetsAlternatingSlash16(b *testing.B) {
	base, gaps := alternatingPerimeterGaps()
	for _, mode := range []struct {
		name       string
		perMonitor uint64
	}{{"selected_tcp", 4096}, {"udp", 1024}, {"full_tcp", 305}} {
		b.Run(mode.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				sets, total, _ := perimeterCoalescedSuggestionSets(base, gaps, mode.perMonitor)
				perimeterCoalescedBenchmarkSink = total + len(sets)
			}
		})
	}
}
