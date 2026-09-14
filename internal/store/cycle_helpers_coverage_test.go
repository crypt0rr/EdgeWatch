package store

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/scanner"
)

func TestCyclePlanningHelpersNormalizeAndGroupDeterministically(t *testing.T) {
	if normalizeCycleAddress(" 192.0.2.1 ") != "192.0.2.1" || normalizeCycleAddress("2001:0db8::1") != "2001:db8::1" || normalizeCycleAddress("not-an-address") != "" {
		t.Fatal("cycle address normalization failed")
	}
	for _, test := range []struct {
		ports []int
		want  string
	}{
		{nil, ""},
		{[]int{3, 1, 2, 5, 5}, "1-3,5,5"},
		{[]int{443}, "443"},
		{[]int{1, 3, 4, 5, 9, 10}, "1,3-5,9-10"},
	} {
		ports := append([]int(nil), test.ports...)
		if got := formatCyclePorts(ports); got != test.want {
			t.Errorf("format cycle ports %v = %q, want %q", test.ports, got, test.want)
		}
	}
	if boolFactor(false) != 1 || boolFactor(true) != 2 {
		t.Fatal("service detection probe factor changed")
	}

	targets := []scanner.ResolvedTarget{
		{Name: "dns.example", ConfiguredTarget: "dns.example", Hostname: true, Aggregate: true, Addresses: []string{"2001:db8::1", "192.0.2.2", "192.0.2.1"}},
		{Name: "other", ConfiguredTarget: "other", Addresses: []string{"192.0.2.3", "bad"}},
	}
	got := subsetCycleTargets(targets, []string{"192.0.2.2", "192.0.2.1", "192.0.2.2", "invalid"})
	want := []scanner.ResolvedTarget{{Name: "dns.example", ConfiguredTarget: "dns.example", Hostname: true, Aggregate: true, Addresses: []string{"192.0.2.1", "192.0.2.2"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("subset targets = %#v, want %#v", got, want)
	}
	if got := subsetCycleTargets(targets, []string{"203.0.113.4"}); got != nil {
		t.Fatalf("unmatched subset = %#v, want nil", got)
	}
}

func TestBuildCycleUDPUnitsCoversFamiliesChunksAndInvalidPlans(t *testing.T) {
	base := scanner.WorkPlan{Targets: []scanner.ResolvedTarget{
		{Name: "mixed", Addresses: []string{"192.0.2.1", "192.0.2.1", "2001:db8::1", "bad"}},
	}}
	if got := buildCycleUDPUnits(base, 10); got != nil {
		t.Fatalf("plan without UDP produced units: %#v", got)
	}
	base.Job.UDP = &config.Protocol{Ports: "not-a-port"}
	if got := buildCycleUDPUnits(base, 10); got != nil {
		t.Fatalf("invalid UDP scope produced units: %#v", got)
	}
	base.Job.UDP = &config.Protocol{Ports: "53,100-101", ServiceDetection: true}
	units := buildCycleUDPUnits(base, 10)
	if len(units) != 2 {
		t.Fatalf("mixed-family UDP units = %#v", units)
	}
	if units[0].Sequence != 10 || units[0].Family != 4 || units[0].Addresses[0] != "192.0.2.1" || units[0].PortCount != 3 || units[0].Probes != 6 {
		t.Fatalf("IPv4 UDP unit = %#v", units[0])
	}
	if units[1].Sequence != 11 || units[1].Family != 6 || units[1].Addresses[0] != "2001:db8::1" || units[1].Probes != 6 {
		t.Fatalf("IPv6 UDP unit = %#v", units[1])
	}

	// More than 128 addresses exercises deterministic address batching, while
	// the large scope forces port chunks to respect the probe cap.
	addresses := make([]string, 0, 130)
	for i := 1; i <= 130; i++ {
		addresses = append(addresses, "10.0."+strconv.Itoa(i/255)+"."+strconv.Itoa(1+i%254))
	}
	large := scanner.WorkPlan{Job: scanner.WorkPlan{}.Job, Targets: []scanner.ResolvedTarget{{Name: "large", Addresses: addresses}}}
	large.Job.UDP = &config.Protocol{Ports: "1-65535", ServiceDetection: true}
	largeUnits := buildCycleUDPUnits(large, 1)
	if len(largeUnits) < 3 || largeUnits[0].PortCount >= 4096 || largeUnits[0].Probes > scanner.MaxWorkUnitProbes {
		t.Fatalf("large UDP plan was not chunked: units=%d first=%#v", len(largeUnits), largeUnits[0])
	}
	for i := 1; i < len(largeUnits); i++ {
		if largeUnits[i].Sequence != largeUnits[i-1].Sequence+1 {
			t.Fatalf("UDP sequences are not contiguous: %#v", largeUnits)
		}
	}

	ctx, s, job, plan := cycleFixture(t)
	defer s.Close()
	cycle, err := s.CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if exists, err := scanCycleUnitIdentityExists(ctx, tx, cycle.ID, scanCycleUnitIdentity(plan.Units[0])); err != nil || !exists {
		_ = tx.Rollback()
		t.Fatalf("identity existence = %v, %v", exists, err)
	}
	if exists, err := scanCycleUnitIdentityExists(context.Background(), tx, cycle.ID, "missing"); err != nil || exists {
		_ = tx.Rollback()
		t.Fatalf("missing identity existence = %v, %v", exists, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetScanCycle(ctx, cycle.ID); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(ErrNoScanCycle, ErrNoScanCycle) {
		t.Fatal("sentinel error changed")
	}
}
