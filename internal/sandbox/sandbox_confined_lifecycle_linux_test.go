//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type confinedLifecycleProbe struct {
	events         []string
	prepareErr     error
	startedErr     error
	startFailedErr error
	proofErr       error
	finishErr      error
}

func (probe *confinedLifecycleProbe) started() error {
	probe.events = append(probe.events, "started")
	return probe.startedErr
}

func (probe *confinedLifecycleProbe) startFailed(cleanupSucceeded bool) error {
	probe.events = append(probe.events, "start-failed:"+strconvBool(cleanupSucceeded))
	return probe.startFailedErr
}

func (probe *confinedLifecycleProbe) cancel(*exec.Cmd) error {
	probe.events = append(probe.events, "cancel")
	return nil
}

func (probe *confinedLifecycleProbe) verifyProcessTree() error {
	probe.events = append(probe.events, "verify")
	return probe.proofErr
}

func (probe *confinedLifecycleProbe) finish(cleanupSucceeded bool) error {
	probe.events = append(probe.events, "finish:"+strconvBool(cleanupSucceeded))
	return probe.finishErr
}

func strconvBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func withConfinedLifecycleProbe(t *testing.T, probe *confinedLifecycleProbe) {
	t.Helper()
	previous := prepareScannerInvocation
	previousConfine := confineProcess
	prepareScannerInvocation = func(context.Context, *exec.Cmd, *Policy, bool) (*ScannerInvocation, error) {
		probe.events = append(probe.events, "prepare")
		if probe.prepareErr != nil {
			return nil, probe.prepareErr
		}
		return &ScannerInvocation{implementation: probe}, nil
	}
	// Exercise the lifecycle orchestration without trying to change the test
	// process's credentials. The fake invocation still receives a policy that
	// represents an enforced scanner; OS credential enforcement is covered by
	// the sandbox helper and the image verifier.
	confineProcess = nil
	t.Cleanup(func() {
		prepareScannerInvocation = previous
		confineProcess = previousConfine
	})
}

func TestRunConfinedScannerInvocationLifecycle(t *testing.T) {
	policy := &Policy{profile: Scanner, status: Status{Mode: ModeAuto}, enforce: true}

	t.Run("preparation error prevents command start", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "must-not-run")
		wantErr := errors.New("identity reservation unavailable")
		probe := &confinedLifecycleProbe{prepareErr: wantErr}
		withConfinedLifecycleProbe(t, probe)
		err := runConfined(policy, []string{"/bin/sh", "-c", "touch \"$MARKER\""}, []string{"MARKER=" + marker})
		if !errors.Is(err, wantErr) {
			t.Fatalf("runConfined preparation error = %v; want %v", err, wantErr)
		}
		if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("command ran after reservation failure: %v", statErr)
		}
		if !reflect.DeepEqual(probe.events, []string{"prepare"}) {
			t.Fatalf("lifecycle after preparation failure = %v; want prepare only", probe.events)
		}
	})

	t.Run("start failure releases only because no child could start", func(t *testing.T) {
		program := filepath.Join(t.TempDir(), "not-an-executable")
		if err := os.WriteFile(program, []byte("not an executable"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(program, 0o700); err != nil {
			t.Fatal(err)
		}
		probe := &confinedLifecycleProbe{}
		withConfinedLifecycleProbe(t, probe)
		err := runConfined(policy, []string{program}, nil)
		if err == nil || !strings.Contains(err.Error(), "exec format error") {
			t.Fatalf("runConfined start failure = %v; want exec format error", err)
		}
		if !reflect.DeepEqual(probe.events, []string{"prepare", "start-failed:true"}) {
			t.Fatalf("lifecycle after command start failure = %v", probe.events)
		}
	})

	t.Run("readiness failure cancels and proves before cleanup release", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "command-ran")
		wantErr := errors.New("private temporary readiness failed")
		probe := &confinedLifecycleProbe{startedErr: wantErr}
		withConfinedLifecycleProbe(t, probe)
		err := runConfined(policy, []string{"/bin/sh", "-c", "touch \"$MARKER\""}, []string{"MARKER=" + marker})
		if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "start scanner probe") {
			t.Fatalf("runConfined readiness failure = %v; want wrapped %v", err, wantErr)
		}
		if _, statErr := os.Stat(marker); statErr != nil {
			t.Fatalf("started command fixture did not complete while cleanup proof ran: %v", statErr)
		}
		if !reflect.DeepEqual(probe.events, []string{"prepare", "started", "cancel", "verify", "finish:true"}) {
			t.Fatalf("readiness failure lifecycle = %v; want cancel, proof, then successful cleanup", probe.events)
		}
	})

	t.Run("normal wait failure preserves diagnostics after positive cleanup proof", func(t *testing.T) {
		probe := &confinedLifecycleProbe{}
		withConfinedLifecycleProbe(t, probe)
		err := runConfined(policy, []string{"/bin/sh", "-c", "echo controlled-probe-failure >&2; exit 7"}, nil)
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 || !strings.Contains(err.Error(), "controlled-probe-failure") {
			t.Fatalf("runConfined command error = %v; want exit 7 with bounded last-line detail", err)
		}
		if !reflect.DeepEqual(probe.events, []string{"prepare", "started", "verify", "finish:true"}) {
			t.Fatalf("failed command lifecycle = %v; want proof before release", probe.events)
		}
	})

	t.Run("missing process-tree proof quarantines", func(t *testing.T) {
		proofErr := errors.New("supervisor result was incomplete")
		probe := &confinedLifecycleProbe{proofErr: proofErr}
		withConfinedLifecycleProbe(t, probe)
		err := runConfined(policy, []string{"/bin/true"}, nil)
		if !errors.Is(err, proofErr) {
			t.Fatalf("runConfined proof failure = %v; want %v", err, proofErr)
		}
		if !reflect.DeepEqual(probe.events, []string{"prepare", "started", "verify", "finish:false"}) {
			t.Fatalf("proof failure lifecycle = %v; want lease quarantine", probe.events)
		}
	})

	t.Run("release failure is returned after proof", func(t *testing.T) {
		releaseErr := errors.New("durable lease release failed")
		probe := &confinedLifecycleProbe{finishErr: releaseErr}
		withConfinedLifecycleProbe(t, probe)
		err := runConfined(policy, []string{"/bin/true"}, nil)
		if !errors.Is(err, releaseErr) {
			t.Fatalf("runConfined release failure = %v; want %v", err, releaseErr)
		}
		if !reflect.DeepEqual(probe.events, []string{"prepare", "started", "verify", "finish:true"}) {
			t.Fatalf("release failure lifecycle = %v; want verified cleanup before release", probe.events)
		}
	})
}

func TestScannerInvocationNilFallbackAndUnsupportedPlatformContracts(t *testing.T) {
	var invocation *ScannerInvocation
	for name, call := range map[string]func() error{
		"started":      func() error { return invocation.Started() },
		"start failed": func() error { return invocation.StartFailed(true) },
		"verify":       func() error { return invocation.VerifyProcessTree() },
		"finish":       func() error { return invocation.Finish(true) },
		"cancel nil":   func() error { return invocation.Cancel(nil) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err != nil {
				t.Fatalf("nil invocation %s = %v; want no-op", name, err)
			}
		})
	}
	command := &exec.Cmd{}
	invocation.InstallCancellation(command)
	if command.Cancel != nil {
		t.Fatal("nil invocation installed a cancellation hook")
	}

	// An explicit Off command has no supervisor. The public invocation wrapper
	// must preserve its established direct-child cancellation behavior.
	command = exec.Command("/bin/sleep", "10")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := invocation.Cancel(command); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("unconfined direct-child cancellation = %v", err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("direct-child cancellation left the command running")
	}

	previousPrepare, previousReserve := prepareScannerInvocation, reserveScannerIdentity
	prepareScannerInvocation, reserveScannerIdentity = nil, nil
	t.Cleanup(func() {
		prepareScannerInvocation, reserveScannerIdentity = previousPrepare, previousReserve
	})
	auto := &Policy{profile: Scanner, status: Status{Mode: ModeAuto}}
	if reservation, err := ReserveScannerIdentity(context.Background(), auto); reservation != nil || err == nil {
		t.Fatalf("identity reservation without platform support = %v, %v; want fail-closed error", reservation, err)
	}
	if reservation, err := ReserveScannerIdentity(context.Background(), &Policy{profile: Scanner, status: Status{Mode: ModeOff}}); reservation != nil || err != nil {
		t.Fatalf("explicit Off identity reservation = %v, %v; want no-op", reservation, err)
	}
	if prepared, err := PrepareScannerInvocation(context.Background(), exec.Command("/bin/true"), auto, false); prepared != nil || err == nil {
		t.Fatalf("scanner invocation without platform support = %v, %v; want fail-closed error", prepared, err)
	}
	if prepared, err := PrepareScannerInvocation(context.Background(), exec.Command("/bin/true"), &Policy{profile: Scanner, status: Status{Mode: ModeOff}}, false); prepared != nil || err != nil {
		t.Fatalf("explicit Off scanner invocation = %v, %v; want no-op", prepared, err)
	}
}
