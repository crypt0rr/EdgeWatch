package app

import (
	"errors"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestResumableMetadataAndProgressAreMonotonic(t *testing.T) {
	run := &activeRun{scan: model.ActiveScan{ProgressPercent: 40, CycleCompletedProbes: 8, CycleTotalProbes: 10, CycleCompletedUnits: 2, CycleTotalUnits: 3}}
	cycle := store.ScanCycleRecord{ID: "cycle-1", AttemptCount: 2, Status: "running", CompletedProbes: 6, TotalProbes: 12, CompletedUnits: 1, TotalUnits: 2, NoProgressAttempts: 1}
	setActiveCycle(run, cycle, "scanning", 3)
	if run.scan.CycleID != cycle.ID || run.scan.CycleAttempt != 2 || run.scan.Phase != "scanning" || run.scan.CurrentUnit != 3 {
		t.Fatalf("cycle metadata = %#v", run.scan)
	}
	if run.scan.CycleCompletedProbes != 8 || run.scan.CycleTotalProbes != 12 || run.scan.CycleCompletedUnits != 2 || run.scan.CycleTotalUnits != 3 || run.scan.ProgressPercent != 50 {
		t.Fatalf("monotonic cycle progress = %#v", run.scan)
	}

	setActiveCycleProgress(run, cycle, scanner.Progress{CompletedProbes: 12, TotalProbes: 12}, scanner.WorkUnit{Ports: "1-65535", Addresses: []string{"192.0.2.1"}})
	if run.scan.CycleStatus != "running" || run.scan.CurrentUnitPorts != "1-65535" || run.scan.CurrentUnitAddresses != 1 || run.scan.ProgressPercent != 100 {
		t.Fatalf("active progress = %#v", run.scan)
	}
	setActiveCycle(nil, cycle, "ignored", 1)
	setActiveCycleProgress(nil, cycle, scanner.Progress{}, scanner.WorkUnit{})
}

func TestExpiredCycleAttemptCopiesDurableFailureMetadata(t *testing.T) {
	var scan model.Scan
	cycle := store.ScanCycleRecord{ID: "expired", Status: "expired", AttemptCount: 4, CompletedProbes: 12, TotalProbes: 20, CompletedUnits: 2, TotalUnits: 5, NoProgressAttempts: 3}
	handled, snapshot, err := expiredCycleAttempt(&scan, cycle)
	if !handled || err == nil || len(snapshot.Units) != 0 {
		t.Fatalf("expired result = handled %v snapshot %#v err %v", handled, snapshot, err)
	}
	if scan.Status != "timed_out" || scan.CycleID != cycle.ID || scan.CycleStatus != cycle.Status || scan.CycleAttempt != 4 || scan.CompletedUnits != 2 || scan.TotalUnits != 5 || scan.NoProgressTries != 3 {
		t.Fatalf("expired metadata = %#v", scan)
	}
}

func TestRetryableResumableErrorClassifiesNilAndConfigurationMarkers(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "transient", err: errors.New("connection reset"), want: true},
		{name: "invalid port", err: errors.New("invalid port expression"), want: false},
		{name: "permission", err: errors.New("permission denied"), want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryableResumableError(tc.err); got != tc.want {
				t.Fatalf("retryableResumableError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
