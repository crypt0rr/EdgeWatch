package sandbox

import (
	"context"
	"testing"
)

// Shared health capacity excludes quarantined leases and identities in use
// without a lease, and treats every active lease as reachable.
func TestScannerIdentityPoolReachableKeepsActiveLeases(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		status *ScannerIdentityPoolStatus
		want   int
	}{
		{"idle pool", &ScannerIdentityPoolStatus{MaxParallel: 64, Free: 64}, 64},
		{"own scans running", &ScannerIdentityPoolStatus{MaxParallel: 64, Active: 25, OwnActive: 25, Free: 39}, 64},
		{"quarantined and unleased use", &ScannerIdentityPoolStatus{MaxParallel: 64, Active: 3, Quarantined: 20, InUseByOtherProcesses: 5, Free: 36}, 39},
		{"overcommitted counts", &ScannerIdentityPoolStatus{MaxParallel: 1, Active: 1, Quarantined: 1, InUseByOtherProcesses: 2}, 0},
		{"nil status", nil, 0},
	} {
		if got := test.status.Reachable(); got != test.want {
			t.Errorf("%s: reachable = %d, want %d", test.name, got, test.want)
		}
	}
}

func TestScannerIdentityPoolDaemonReachabilitySubtractsOtherActiveLeases(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		status *ScannerIdentityPoolStatus
		want   int
	}{
		{"idle pool", &ScannerIdentityPoolStatus{MaxParallel: 64, Free: 64}, 64},
		{"daemon scans", &ScannerIdentityPoolStatus{MaxParallel: 64, Active: 25, OwnActive: 25, Free: 39}, 64},
		{"active lease held by another process", &ScannerIdentityPoolStatus{MaxParallel: 64, Active: 1, Free: 63}, 63},
		{"mixed active leases", &ScannerIdentityPoolStatus{MaxParallel: 64, Active: 25, OwnActive: 20, Quarantined: 3, InUseByOtherProcesses: 2}, 54},
		{"overcommitted counts", &ScannerIdentityPoolStatus{MaxParallel: 1, Active: 1, Quarantined: 1, InUseByOtherProcesses: 2}, 0},
		{"nil status", nil, 0},
	} {
		if got := test.status.ReachableByDaemon(); got != test.want {
			t.Errorf("%s: daemon reachable = %d, want %d", test.name, got, test.want)
		}
	}
}

// An unavailable policy reports the pool as unavailable and leases no
// scanner identity, so it cannot start a scanner.
func TestNewUnavailableRefusesScannerIdentities(t *testing.T) {
	t.Parallel()
	const reason = "EdgeWatch runs as UID 1000 rather than UID 0, so it cannot start scanner processes under leased identities"
	policy := NewUnavailable(reason)
	status := policy.Status()
	if status.Mode != ModeAuto || status.State != StateUnavailable || status.Reason != reason {
		t.Fatalf("status = %+v", status)
	}
	if pool := status.IdentityPool; pool == nil || pool.State != StateUnavailable || pool.Reason != reason || pool.MaxParallel != ScannerIdentityPoolCapacity {
		t.Fatalf("identity pool = %+v", pool)
	}
	if policy.Enforced() {
		t.Fatal("an unavailable policy reports enforcement")
	}
	if err := policy.Require(); err != nil {
		t.Fatalf("auto mode refused the daemon: %v", err)
	}
	if reservation, err := ReserveScannerIdentity(context.Background(), policy); err == nil || reservation != nil {
		t.Fatalf("unavailable policy reserved an identity: %v, %v", reservation, err)
	}
}
