package sandbox

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"testing"
)

type invocationImplementationProbe struct {
	calls            []string
	startedErr       error
	startFailedErr   error
	cancelErr        error
	verifyErr        error
	finishErr        error
	startFailedClean bool
	finishClean      bool
	cancelCommand    *exec.Cmd
}

func (probe *invocationImplementationProbe) started() error {
	probe.calls = append(probe.calls, "started")
	return probe.startedErr
}

func (probe *invocationImplementationProbe) startFailed(cleanupSucceeded bool) error {
	probe.calls = append(probe.calls, "start-failed")
	probe.startFailedClean = cleanupSucceeded
	return probe.startFailedErr
}

func (probe *invocationImplementationProbe) cancel(command *exec.Cmd) error {
	probe.calls = append(probe.calls, "cancel")
	probe.cancelCommand = command
	return probe.cancelErr
}

func (probe *invocationImplementationProbe) verifyProcessTree() error {
	probe.calls = append(probe.calls, "verify")
	return probe.verifyErr
}

func (probe *invocationImplementationProbe) finish(cleanupSucceeded bool) error {
	probe.calls = append(probe.calls, "finish")
	probe.finishClean = cleanupSucceeded
	return probe.finishErr
}

type identityLeaseProbe struct {
	uid, gid      int
	identityOK    bool
	releaseErr    error
	quarantineErr error
	releases      int
	quarantines   int
}

func (probe *identityLeaseProbe) identity() (int, int, bool) {
	return probe.uid, probe.gid, probe.identityOK
}

func (probe *identityLeaseProbe) release() error {
	probe.releases++
	return probe.releaseErr
}

func (probe *identityLeaseProbe) quarantine() error {
	probe.quarantines++
	return probe.quarantineErr
}

func TestScannerInvocationPublicLifecycleDelegatesAndPreservesCleanupProof(t *testing.T) {
	startErr := errors.New("start acknowledgement failed")
	startFailedErr := errors.New("start failure cleanup failed")
	cancelErr := errors.New("supervisor cancellation failed")
	verifyErr := errors.New("process tree proof failed")
	finishErr := errors.New("artifact cleanup failed")
	probe := &invocationImplementationProbe{
		startedErr: startErr, startFailedErr: startFailedErr,
		cancelErr: cancelErr, verifyErr: verifyErr, finishErr: finishErr,
	}
	invocation := &ScannerInvocation{implementation: probe}
	command := &exec.Cmd{}

	if err := invocation.Started(); !errors.Is(err, startErr) {
		t.Fatalf("Started() = %v, want %v", err, startErr)
	}
	if err := invocation.StartFailed(true); !errors.Is(err, startFailedErr) || !probe.startFailedClean {
		t.Fatalf("StartFailed(true) = %v, cleanup proof %v; want %v and true", err, probe.startFailedClean, startFailedErr)
	}
	if err := invocation.Cancel(command); !errors.Is(err, cancelErr) || probe.cancelCommand != command {
		t.Fatalf("Cancel() = %v, command %p; want %v and %p", err, probe.cancelCommand, cancelErr, command)
	}
	if err := invocation.VerifyProcessTree(); !errors.Is(err, verifyErr) {
		t.Fatalf("VerifyProcessTree() = %v, want %v", err, verifyErr)
	}
	invocation.InstallCancellation(command)
	if command.Cancel == nil {
		t.Fatal("InstallCancellation did not install a command cancellation callback")
	}
	if err := command.Cancel(); !errors.Is(err, cancelErr) || probe.cancelCommand != command {
		t.Fatalf("installed cancellation = %v, command %p; want %v and %p", err, probe.cancelCommand, cancelErr, command)
	}
	if err := invocation.Finish(false); !errors.Is(err, finishErr) || probe.finishClean {
		t.Fatalf("Finish(false) = %v, cleanup proof %v; want %v and false", err, probe.finishClean, finishErr)
	}
	wantCalls := []string{"started", "start-failed", "cancel", "verify", "cancel", "finish"}
	if !reflect.DeepEqual(probe.calls, wantCalls) {
		t.Fatalf("delegated calls = %v, want %v", probe.calls, wantCalls)
	}
}

func TestScannerInvocationNilAndUnimplementedLifecycle(t *testing.T) {
	var nilInvocation *ScannerInvocation
	if err := nilInvocation.Started(); err != nil {
		t.Fatalf("nil Started() = %v", err)
	}
	if err := nilInvocation.StartFailed(false); err != nil {
		t.Fatalf("nil StartFailed() = %v", err)
	}
	if err := nilInvocation.Cancel(nil); err != nil {
		t.Fatalf("nil Cancel(nil) = %v", err)
	}
	if err := nilInvocation.VerifyProcessTree(); err != nil {
		t.Fatalf("nil VerifyProcessTree() = %v", err)
	}
	if err := nilInvocation.Finish(false); err != nil {
		t.Fatalf("nil Finish() = %v", err)
	}
	nilInvocation.InstallCancellation(nil)

	invocation := &ScannerInvocation{}
	if err := invocation.Cancel(nil); err != nil {
		t.Fatalf("unimplemented Cancel(nil) = %v", err)
	}
	if err := invocation.VerifyProcessTree(); err != nil {
		t.Fatalf("unimplemented VerifyProcessTree() = %v", err)
	}
	if err := invocation.Finish(true); err != nil {
		t.Fatalf("unimplemented Finish() = %v", err)
	}
	invocation.InstallCancellation(nil)
}

func TestScannerIdentityReservationClaimsAndFinishesLeaseSafely(t *testing.T) {
	lease := &identityLeaseProbe{uid: 61007, gid: 61008, identityOK: true}
	reservation := &ScannerIdentityReservation{lease: lease}
	uid, gid, ok := reservation.Identity()
	if !ok || uid != 61007 || gid != 61008 {
		t.Fatalf("Identity() = %d:%d, %v; want 61007:61008", uid, gid, ok)
	}

	policy := &Policy{status: Status{Mode: ModeAuto, UID: UID, GID: GID, ProcessUID: uidPointer(UID), Capabilities: []string{"NET_RAW"}}, ambient: []uintptr{12}}
	copy := policy.WithScannerIdentityReservation(reservation)
	if copy == policy || copy.status.UID != 61007 || copy.status.GID != 61008 || copy.status.ProcessUID != nil || copy.identityReservation != reservation {
		t.Fatalf("reservation policy copy = %+v; want leased identity without a process UID", copy)
	}
	copy.status.Capabilities[0] = "changed"
	copy.ambient[0] = 99
	if policy.status.Capabilities[0] != "NET_RAW" || policy.ambient[0] != 12 {
		t.Fatal("reservation policy copy mutated its source slices")
	}
	if policy.WithScannerIdentityReservation(nil).identityReservation != nil {
		t.Fatal("nil reservation was not retained as nil")
	}
	if (*Policy)(nil).WithScannerIdentityReservation(reservation) != nil {
		t.Fatal("nil policy copy should remain nil")
	}
	if reservation.take() != lease {
		t.Fatal("take() did not return the active lease")
	}
	if reservation.take() != nil {
		t.Fatal("reservation returned the same lease twice")
	}
	if err := reservation.Finish(true); err == nil {
		t.Fatal("claimed reservation was finished by the setup owner")
	}
	if lease.releases != 0 || lease.quarantines != 0 {
		t.Fatalf("claimed lease was changed by Finish: releases=%d quarantines=%d", lease.releases, lease.quarantines)
	}
}

func TestScannerIdentityReservationReleaseAndQuarantineResults(t *testing.T) {
	t.Run("successful cleanup releases exactly once", func(t *testing.T) {
		lease := &identityLeaseProbe{uid: 61000, gid: 61000, identityOK: true}
		reservation := &ScannerIdentityReservation{lease: lease}
		if err := reservation.Finish(true); err != nil {
			t.Fatal(err)
		}
		if lease.releases != 1 || lease.quarantines != 0 {
			t.Fatalf("lease actions = release %d, quarantine %d", lease.releases, lease.quarantines)
		}
		if _, _, ok := reservation.Identity(); ok {
			t.Fatal("finished reservation still exposed its identity")
		}
		if err := reservation.Finish(true); err == nil {
			t.Fatal("finished reservation was reused")
		}
	})

	t.Run("uncertain cleanup quarantines", func(t *testing.T) {
		lease := &identityLeaseProbe{uid: 61000, gid: 61000, identityOK: true}
		reservation := &ScannerIdentityReservation{lease: lease}
		if err := reservation.Finish(false); err != nil {
			t.Fatal(err)
		}
		if lease.releases != 0 || lease.quarantines != 1 {
			t.Fatalf("lease actions = release %d, quarantine %d", lease.releases, lease.quarantines)
		}
	})

	t.Run("release error also quarantines and returns release error", func(t *testing.T) {
		releaseErr := errors.New("durable release failed")
		lease := &identityLeaseProbe{uid: 61000, gid: 61000, identityOK: true, releaseErr: releaseErr}
		reservation := &ScannerIdentityReservation{lease: lease}
		if err := reservation.Finish(true); !errors.Is(err, releaseErr) {
			t.Fatalf("Finish(true) = %v, want %v", err, releaseErr)
		}
		if lease.releases != 1 || lease.quarantines != 1 {
			t.Fatalf("lease actions = release %d, quarantine %d", lease.releases, lease.quarantines)
		}
	})
}

func TestReserveScannerIdentityDoesNotLeaseExplicitOffPolicy(t *testing.T) {
	reservation, err := ReserveScannerIdentity(context.Background(), &Policy{status: Status{Mode: ModeOff}})
	if err != nil || reservation != nil {
		t.Fatalf("ReserveScannerIdentity(off) = %v, %v; want nil, nil", reservation, err)
	}
	reservation, err = ReserveScannerIdentity(context.Background(), nil)
	if err != nil || reservation != nil {
		t.Fatalf("ReserveScannerIdentity(nil) = %v, %v; want nil, nil", reservation, err)
	}
	reservation, err = ReserveScannerIdentity(context.Background(), &Policy{status: Status{Mode: ModeAuto}})
	if err == nil || reservation != nil {
		t.Fatalf("ReserveScannerIdentity(auto without an enforced lease) = %v, %v; want a fail-closed error", reservation, err)
	}
}

func TestPrepareScannerInvocationRejectsInvalidCommandBeforeLeasing(t *testing.T) {
	allocatorCalls := 0
	policy := &Policy{
		status: Status{Mode: ModeAuto},
		identityAllocator: func(context.Context) (identityLease, error) {
			allocatorCalls++
			return &identityLeaseProbe{uid: 61000, gid: 61000, identityOK: true}, nil
		},
	}
	invocation, err := PrepareScannerInvocation(context.Background(), nil, policy, false)
	if err == nil || invocation != nil {
		t.Fatalf("PrepareScannerInvocation(nil command) = %v, %v; want a fail-closed error", invocation, err)
	}
	if allocatorCalls != 0 {
		t.Fatalf("invalid command reserved a scanner identity %d times", allocatorCalls)
	}
}
