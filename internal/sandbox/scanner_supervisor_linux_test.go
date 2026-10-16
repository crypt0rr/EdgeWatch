//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type supervisorTestLease struct {
	releases      int
	quarantines   int
	releaseErr    error
	quarantineErr error
	identityOK    bool
	events        *[]string
}

func (lease *supervisorTestLease) identity() (int, int, bool) {
	if lease == nil || !lease.identityOK {
		return 0, 0, false
	}
	return 61000, 61000, true
}

func (lease *supervisorTestLease) release() error {
	lease.releases++
	if lease.events != nil {
		*lease.events = append(*lease.events, "release")
	}
	return lease.releaseErr
}

func (lease *supervisorTestLease) quarantine() error {
	lease.quarantines++
	if lease.events != nil {
		*lease.events = append(*lease.events, "quarantine")
	}
	return lease.quarantineErr
}

func newTestSupervisorInvocation(t *testing.T, lease identityLease) (*scannerSupervisorInvocation, *os.File, string) {
	t.Helper()
	configPath := t.TempDir() + "/launch.json"
	configWrite, err := os.Create(configPath)
	if err != nil {
		t.Fatal(err)
	}
	configRead, err := os.Open(os.DevNull)
	if err != nil {
		_ = configWrite.Close()
		t.Fatal(err)
	}
	resultFDs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		_ = configRead.Close()
		_ = configWrite.Close()
		t.Fatal(err)
	}
	peerFD, err := unix.Dup(resultFDs[1])
	if err != nil {
		_ = unix.Close(resultFDs[0])
		_ = unix.Close(resultFDs[1])
		_ = configRead.Close()
		_ = configWrite.Close()
		t.Fatal(err)
	}
	invocation := &scannerSupervisorInvocation{
		lease: lease, config: []byte(`{"version":1,"path":"/usr/bin/nmap"}`),
		configRead: configRead, configWrite: configWrite,
		resultRead:  os.NewFile(uintptr(resultFDs[0]), "test supervisor result"),
		resultWrite: os.NewFile(uintptr(resultFDs[1]), "test supervisor result child"),
	}
	peer := os.NewFile(uintptr(peerFD), "test supervisor peer")
	t.Cleanup(func() {
		invocation.closeParentFiles()
		_ = peer.Close()
	})
	return invocation, peer, configPath
}

func sendSupervisorTestFrame(t *testing.T, peer *os.File, frame []byte) {
	t.Helper()
	n, err := unix.SendmsgN(int(peer.Fd()), frame, nil, nil, 0)
	if err != nil || n != len(frame) {
		t.Fatalf("send completion frame wrote %d bytes, %v; want %d", n, err, len(frame))
	}
}

func validSupervisorTestFrame() []byte {
	frame := make([]byte, 16)
	copy(frame, scannerSupervisorMagic)
	frame[8] = 1
	return frame
}

func TestScannerSupervisorInvocationRequiresProofAndCleanupBeforeRelease(t *testing.T) {
	t.Run("verified and cleaned invocation releases once", func(t *testing.T) {
		lease := &supervisorTestLease{identityOK: true}
		invocation, peer, configPath := newTestSupervisorInvocation(t, lease)
		if err := invocation.started(); err != nil {
			t.Fatal(err)
		}
		if got, err := os.ReadFile(configPath); err != nil || !bytes.Equal(got, invocation.config) {
			t.Fatalf("supervisor request = %q, %v; want %q", got, err, invocation.config)
		}
		if err := sendScannerSupervisorResult(int(peer.Fd()), true); err != nil {
			t.Fatalf("send trusted completion proof: %v", err)
		}
		// A duplicate datagram must not cause a second receive or state change.
		if err := sendScannerSupervisorResult(int(peer.Fd()), true); err != nil {
			t.Fatalf("send duplicate completion proof: %v", err)
		}
		if err := invocation.verifyProcessTree(); err != nil {
			t.Fatalf("verify supervisor completion: %v", err)
		}
		if lease.releases != 0 || lease.quarantines != 0 {
			t.Fatalf("proof released identity before artifact cleanup: releases=%d quarantines=%d", lease.releases, lease.quarantines)
		}
		if err := invocation.verifyProcessTree(); err != nil {
			t.Fatalf("cached completion proof: %v", err)
		}
		if err := invocation.finish(true); err != nil {
			t.Fatalf("finish cleaned invocation: %v", err)
		}
		if err := invocation.finish(true); err != nil {
			t.Fatalf("idempotent finish: %v", err)
		}
		if lease.releases != 1 || lease.quarantines != 0 {
			t.Fatalf("successful lifecycle accounting = releases %d, quarantines %d; want 1, 0", lease.releases, lease.quarantines)
		}
	})

	t.Run("cleanup failure quarantines after proof", func(t *testing.T) {
		lease := &supervisorTestLease{identityOK: true}
		invocation, peer, _ := newTestSupervisorInvocation(t, lease)
		if err := invocation.started(); err != nil {
			t.Fatal(err)
		}
		sendSupervisorTestFrame(t, peer, validSupervisorTestFrame())
		if err := invocation.verifyProcessTree(); err != nil {
			t.Fatal(err)
		}
		if err := invocation.finish(false); err == nil || !strings.Contains(err.Error(), "cleanup failed") {
			t.Fatalf("finish with failed artifact cleanup = %v, want cleanup error", err)
		}
		if lease.releases != 0 || lease.quarantines != 1 {
			t.Fatalf("failed cleanup accounting = releases %d, quarantines %d; want 0, 1", lease.releases, lease.quarantines)
		}
		if err := invocation.finish(true); err != nil || lease.releases != 0 || lease.quarantines != 1 {
			t.Fatalf("idempotent finish changed quarantined lease: err=%v releases=%d quarantines=%d", err, lease.releases, lease.quarantines)
		}
	})

	t.Run("release error quarantines", func(t *testing.T) {
		lease := &supervisorTestLease{identityOK: true, releaseErr: errors.New("durable release failed")}
		invocation, peer, _ := newTestSupervisorInvocation(t, lease)
		if err := invocation.started(); err != nil {
			t.Fatal(err)
		}
		sendSupervisorTestFrame(t, peer, validSupervisorTestFrame())
		if err := invocation.finish(true); err == nil || !strings.Contains(err.Error(), "durable release failed") {
			t.Fatalf("finish with release error = %v, want release error", err)
		}
		if lease.releases != 1 || lease.quarantines != 1 {
			t.Fatalf("release-error accounting = releases %d, quarantines %d; want 1, 1", lease.releases, lease.quarantines)
		}
	})
}

func TestScannerSupervisorCancellationProvesThenCleansBeforeReleasing(t *testing.T) {
	var events []string
	lease := &supervisorTestLease{identityOK: true, events: &events}
	invocation, peer, _ := newTestSupervisorInvocation(t, lease)
	if err := invocation.started(); err != nil {
		t.Fatal(err)
	}
	child := &exec.Cmd{Process: &os.Process{Pid: 4242}}
	waitCalls := 0
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM
	ops := scannerSupervisorOps{
		waitForExit: func(pid int) (bool, error) {
			events = append(events, "observe-exit")
			if pid != child.Process.Pid {
				t.Fatalf("observed pid %d, want %d", pid, child.Process.Pid)
			}
			waitCalls++
			return waitCalls > 1, nil
		},
		killGroup: func(pid int, signal syscall.Signal) error {
			events = append(events, "kill-group")
			if pid != child.Process.Pid || signal != syscall.SIGKILL {
				t.Fatalf("kill group pid/signal = %d/%v, want %d/SIGKILL", pid, signal, child.Process.Pid)
			}
			return nil
		},
		waitChild: func(got *exec.Cmd) error {
			events = append(events, "wait-leader")
			if got != child {
				t.Fatalf("waited for command %p, want %p", got, child)
			}
			return nil
		},
		reapChildren: func(timeout time.Duration) error {
			events = append(events, "reap-descendants")
			if timeout != scannerSupervisorTimeout {
				t.Fatalf("reaper timeout = %s, want %s", timeout, scannerSupervisorTimeout)
			}
			return nil
		},
		sendResult: func(fd int, clean bool) error {
			events = append(events, "send-proof")
			if fd != int(peer.Fd()) || !clean {
				t.Fatalf("proof fd/clean = %d/%t, want %d/true", fd, clean, peer.Fd())
			}
			return sendScannerSupervisorResult(fd, clean)
		},
		now: func() time.Time { return time.Unix(1, 0) },
	}
	interrupted, childErr, superviseErr := superviseScannerChild(child, int(peer.Fd()), signals, make(chan time.Time), ops)
	if superviseErr != nil || !interrupted || childErr != nil {
		t.Fatalf("supervise cancellation = interrupted %t, child error %v, error %v", interrupted, childErr, superviseErr)
	}
	if err := invocation.verifyProcessTree(); err != nil {
		t.Fatalf("accept cancellation proof: %v", err)
	}
	events = append(events, "proof-accepted")
	if lease.releases != 0 || lease.quarantines != 0 {
		t.Fatalf("proof alone changed lease: releases=%d quarantines=%d", lease.releases, lease.quarantines)
	}
	artifact := t.TempDir() + "/invocation-output"
	if err := os.WriteFile(artifact, []byte("private scan artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	events = append(events, "cleanup")
	if err := os.Remove(artifact); err != nil {
		t.Fatalf("clean proven invocation artifact: %v", err)
	}
	if err := invocation.finish(true); err != nil {
		t.Fatalf("release after proof and cleanup: %v", err)
	}
	want := []string{"observe-exit", "kill-group", "observe-exit", "kill-group", "wait-leader", "reap-descendants", "send-proof", "proof-accepted", "cleanup", "release"}
	if !equalStrings(events, want) {
		t.Fatalf("cancellation lifecycle ordering = %v, want %v", events, want)
	}
	if lease.releases != 1 || lease.quarantines != 0 {
		t.Fatalf("canceled clean lifecycle accounting = releases %d, quarantines %d; want 1, 0", lease.releases, lease.quarantines)
	}
}

func TestScannerSupervisorInvocationQuarantinesInvalidCompletionProof(t *testing.T) {
	short := validSupervisorTestFrame()[:8]
	badMagic := validSupervisorTestFrame()
	badMagic[0] ^= 0xff
	badStatus := validSupervisorTestFrame()
	badStatus[8] = 0
	reserved := validSupervisorTestFrame()
	reserved[15] = 1

	tests := []struct {
		name  string
		frame []byte
		eof   bool
	}{
		{name: "truncated frame", frame: short},
		{name: "wrong magic", frame: badMagic},
		{name: "failure status", frame: badStatus},
		{name: "nonzero reserved byte", frame: reserved},
		{name: "control EOF", eof: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lease := &supervisorTestLease{identityOK: true}
			invocation, peer, _ := newTestSupervisorInvocation(t, lease)
			if err := invocation.started(); err != nil {
				t.Fatal(err)
			}
			if test.eof {
				if err := peer.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				sendSupervisorTestFrame(t, peer, test.frame)
			}
			proofErr := invocation.verifyProcessTree()
			if proofErr == nil {
				t.Fatal("invalid or absent completion proof was accepted")
			}
			if repeatErr := invocation.verifyProcessTree(); repeatErr != proofErr {
				t.Fatalf("cached proof error = %v, want original %v", repeatErr, proofErr)
			}
			if err := invocation.finish(true); err == nil {
				t.Fatal("finish accepted invalid completion proof")
			}
			if lease.releases != 0 || lease.quarantines != 1 {
				t.Fatalf("invalid proof accounting = releases %d, quarantines %d; want 0, 1", lease.releases, lease.quarantines)
			}
		})
	}
}

func TestScannerSupervisorVerificationUnavailableQuarantinesLease(t *testing.T) {
	lease := &supervisorTestLease{identityOK: true}
	invocation := &scannerSupervisorInvocation{lease: lease}
	if err := invocation.verifyProcessTree(); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("verify before start = %v, want unavailable error", err)
	}
	if err := invocation.verifyProcessTree(); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("cached verify before start = %v, want unavailable error", err)
	}
	if err := invocation.finish(true); err != nil {
		t.Fatalf("finish without a started supervisor: %v", err)
	}
	if lease.releases != 0 || lease.quarantines != 1 {
		t.Fatalf("unavailable supervisor accounting = releases %d, quarantines %d; want 0, 1", lease.releases, lease.quarantines)
	}
}

func TestScannerSupervisorInvocationStartFailureAndInvalidState(t *testing.T) {
	t.Run("failed start releases only after successful setup cleanup", func(t *testing.T) {
		lease := &supervisorTestLease{identityOK: true}
		invocation, _, _ := newTestSupervisorInvocation(t, lease)
		if err := invocation.startFailed(true); err != nil {
			t.Fatal(err)
		}
		if err := invocation.startFailed(false); err != nil {
			t.Fatalf("idempotent start failure: %v", err)
		}
		if lease.releases != 1 || lease.quarantines != 0 {
			t.Fatalf("failed-start accounting = releases %d, quarantines %d; want 1, 0", lease.releases, lease.quarantines)
		}
	})

	t.Run("failed cleanup quarantines", func(t *testing.T) {
		lease := &supervisorTestLease{identityOK: true}
		invocation, _, _ := newTestSupervisorInvocation(t, lease)
		if err := invocation.startFailed(false); err != nil {
			t.Fatal(err)
		}
		if lease.releases != 0 || lease.quarantines != 1 {
			t.Fatalf("failed-start cleanup accounting = releases %d, quarantines %d; want 0, 1", lease.releases, lease.quarantines)
		}
	})
	t.Run("release error quarantines", func(t *testing.T) {
		lease := &supervisorTestLease{identityOK: true, releaseErr: errors.New("release store unavailable")}
		invocation, _, _ := newTestSupervisorInvocation(t, lease)
		if err := invocation.startFailed(true); !errors.Is(err, lease.releaseErr) {
			t.Fatalf("failed-start release error = %v, want %v", err, lease.releaseErr)
		}
		if lease.releases != 1 || lease.quarantines != 1 {
			t.Fatalf("failed-start release-error accounting = releases %d, quarantines %d; want 1, 1", lease.releases, lease.quarantines)
		}
	})

	t.Run("started invocation rejects start-failed transition", func(t *testing.T) {
		lease := &supervisorTestLease{identityOK: true}
		invocation, _, _ := newTestSupervisorInvocation(t, lease)
		if err := invocation.started(); err != nil {
			t.Fatal(err)
		}
		if err := invocation.startFailed(true); err == nil {
			t.Fatal("started invocation accepted start-failed transition")
		}
		if lease.releases != 0 || lease.quarantines != 0 {
			t.Fatalf("invalid start-failed transition changed lease: releases=%d quarantines=%d", lease.releases, lease.quarantines)
		}
	})
}

func TestScannerSupervisorCancelSignalsOnlyTheSupervisorProcess(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	invocation := &scannerSupervisorInvocation{}
	if err := invocation.cancel(cmd); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("cancel supervisor process: %v", err)
	}
	err := cmd.Wait()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("supervisor wait error = %v, want signal termination", err)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGTERM {
		t.Fatalf("supervisor wait status = %#v; want SIGTERM", exitErr.Sys())
	}
	if err := invocation.cancel(nil); err != nil {
		t.Fatalf("cancel without a process: %v", err)
	}
}

func TestScannerSupervisorProtocolParsersFailClosed(t *testing.T) {
	t.Run("arguments", func(t *testing.T) {
		valid, err := parseScannerSupervisorArgs([]string{"--files", "1", "--request-fd", "4", "--result-fd", "5"})
		if err != nil || valid != (scannerSupervisorRequest{files: 1, requestFD: 4, resultFD: 5}) {
			t.Fatalf("parse valid supervisor args = %+v, %v", valid, err)
		}
		invalid := [][]string{
			{"--files"},
			{"--files", "0", "--files", "0", "--request-fd", "3", "--result-fd", "4"},
			{"--files", "0", "--request-fd", "4", "--result-fd", "5"},
			{"--files", "bad", "--request-fd", "3", "--result-fd", "4"},
			{"--files", "0", "--request-fd", "3", "--result-fd", "4", "--extra", "x"},
		}
		for _, args := range invalid {
			if got, err := parseScannerSupervisorArgs(args); err == nil {
				t.Errorf("parse invalid supervisor args %q = %+v, want error", args, got)
			}
		}
	})

	t.Run("launch request", func(t *testing.T) {
		valid := scannerLaunchRequest{
			Version: 1, Path: "/usr/bin/nmap", Args: []string{"/usr/bin/nmap", "-V"},
			Files: 1, UID: scannerIdentityStart, GID: scannerIdentityStart,
		}
		encoded, err := json.Marshal(valid)
		if err != nil {
			t.Fatal(err)
		}
		request := scannerSupervisorRequest{files: 1, requestFD: 4, resultFD: 5}
		if got, err := decodeScannerLaunchRequest(encoded, request); err != nil || got.Path != valid.Path || len(got.Args) != 2 {
			t.Fatalf("decode valid launch request = %+v, %v", got, err)
		}
		if _, err := decodeScannerLaunchRequest(nil, request); err == nil || !strings.Contains(err.Error(), "unavailable or too large") {
			t.Fatalf("decode empty request = %v, want bounded-input error", err)
		}
		if _, err := decodeScannerLaunchRequest(bytes.Repeat([]byte{'x'}, scannerSupervisorMaxConfig+1), request); err == nil {
			t.Fatal("oversized launch request accepted")
		}
		if _, err := decodeScannerLaunchRequest([]byte(`{"unknown":true}`), request); err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("decode unknown-field request = %v, want malformed error", err)
		}
		if _, err := decodeScannerLaunchRequest(append(append([]byte(nil), encoded...), []byte(` {}`)...), request); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("decode trailing JSON = %v, want invalid error", err)
		}
		invalid := []struct {
			name   string
			change func(*scannerLaunchRequest)
		}{
			{name: "version", change: func(request *scannerLaunchRequest) { request.Version++ }},
			{name: "relative path", change: func(request *scannerLaunchRequest) { request.Path = "nmap"; request.Args[0] = "nmap" }},
			{name: "argv path mismatch", change: func(request *scannerLaunchRequest) { request.Args[0] = "/usr/bin/other" }},
			{name: "descriptor count", change: func(request *scannerLaunchRequest) { request.Files++ }},
			{name: "uid outside lease pool", change: func(request *scannerLaunchRequest) { request.UID = scannerIdentityStart - 1 }},
			{name: "gid differs from uid", change: func(request *scannerLaunchRequest) { request.GID++ }},
			{name: "too many ambient capabilities", change: func(request *scannerLaunchRequest) { request.AmbientCaps = make([]uintptr, 9) }},
		}
		for _, test := range invalid {
			t.Run(test.name, func(t *testing.T) {
				requestCopy := valid
				requestCopy.Args = append([]string(nil), valid.Args...)
				test.change(&requestCopy)
				data, err := json.Marshal(requestCopy)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := decodeScannerLaunchRequest(data, request); err == nil || !strings.Contains(err.Error(), "invalid") {
					t.Fatalf("decode invalid launch request = %v, want invalid error", err)
				}
			})
		}
	})

	t.Run("completion frame", func(t *testing.T) {
		if err := validateScannerSupervisorResult(validSupervisorTestFrame()); err != nil {
			t.Fatalf("validate success frame: %v", err)
		}
		for _, frame := range [][]byte{
			validSupervisorTestFrame()[:8],
			[]byte("xxxxxxxxxxxxxxx1"),
			append(validSupervisorTestFrame()[:8], 0),
		} {
			if err := validateScannerSupervisorResult(frame); err == nil {
				t.Errorf("validate malformed completion frame %x succeeded", frame)
			}
		}
	})
}

type partialSupervisorWriter struct {
	maxWrite  int
	writeErr  error
	writeZero bool
	data      bytes.Buffer
}

func (writer *partialSupervisorWriter) Write(data []byte) (int, error) {
	if writer.writeErr != nil {
		return 0, writer.writeErr
	}
	if writer.writeZero {
		return 0, nil
	}
	if writer.maxWrite > 0 && len(data) > writer.maxWrite {
		data = data[:writer.maxWrite]
	}
	return writer.data.Write(data)
}

func TestScannerSupervisorWriteAllHandlesPartialAndFailedWrites(t *testing.T) {
	t.Run("partial writes complete", func(t *testing.T) {
		writer := &partialSupervisorWriter{maxWrite: 2}
		if err := writeAll(writer, []byte("request")); err != nil || writer.data.String() != "request" {
			t.Fatalf("writeAll = %v, wrote %q", err, writer.data.String())
		}
	})
	t.Run("writer error", func(t *testing.T) {
		want := errors.New("pipe failed")
		if err := writeAll(&partialSupervisorWriter{writeErr: want}, []byte("request")); !errors.Is(err, want) {
			t.Fatalf("writeAll error = %v, want %v", err, want)
		}
	})
	t.Run("zero progress", func(t *testing.T) {
		if err := writeAll(&partialSupervisorWriter{writeZero: true}, []byte("request")); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("writeAll zero write = %v, want ErrShortWrite", err)
		}
	})
}

func TestScannerSupervisorResultWaitHandlesInvalidReadyEOFAndTimeout(t *testing.T) {
	if err := waitScannerSupervisorResult(-1, time.Second); err == nil {
		t.Fatal("invalid descriptor was accepted")
	}
	if err := waitScannerSupervisorResult(0, 0); err == nil {
		t.Fatal("nonpositive timeout was accepted")
	}

	t.Run("readable socket", func(t *testing.T) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fds[0])
		peer := os.NewFile(uintptr(fds[1]), "wait peer")
		defer peer.Close()
		sendSupervisorTestFrame(t, peer, []byte("ready"))
		if err := waitScannerSupervisorResult(fds[0], time.Second); err != nil {
			t.Fatalf("wait for readable socket: %v", err)
		}
	})

	t.Run("closed peer is readable EOF", func(t *testing.T) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fds[0])
		if err := unix.Close(fds[1]); err != nil {
			t.Fatal(err)
		}
		if err := waitScannerSupervisorResult(fds[0], time.Second); err != nil {
			t.Fatalf("wait for peer EOF readiness: %v", err)
		}
	})

	t.Run("deadline", func(t *testing.T) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fds[0])
		defer unix.Close(fds[1])
		started := time.Now()
		if err := waitScannerSupervisorResult(fds[0], 15*time.Millisecond); err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("wait without completion = %v, want timeout", err)
		}
		if time.Since(started) > time.Second {
			t.Fatalf("short result deadline took %s", time.Since(started))
		}
	})
}

func TestScannerSupervisorChildProofOrderingAndFailurePaths(t *testing.T) {
	child := &exec.Cmd{Process: &os.Process{Pid: 4242}}
	never := make(chan time.Time)
	baseOps := func(events *[]string) scannerSupervisorOps {
		return scannerSupervisorOps{
			waitForExit: func(pid int) (bool, error) {
				*events = append(*events, "observe-exit")
				if pid != child.Process.Pid {
					t.Fatalf("waited for pid %d, want %d", pid, child.Process.Pid)
				}
				return true, nil
			},
			killGroup: func(pid int, signal syscall.Signal) error {
				*events = append(*events, "kill-group")
				if pid != child.Process.Pid || signal != syscall.SIGKILL {
					t.Fatalf("kill group pid/signal = %d/%v; want %d/SIGKILL", pid, signal, child.Process.Pid)
				}
				return nil
			},
			waitChild: func(got *exec.Cmd) error {
				*events = append(*events, "wait-leader")
				if got != child {
					t.Fatalf("waited for command %p, want %p", got, child)
				}
				return nil
			},
			reapChildren: func(timeout time.Duration) error {
				*events = append(*events, "reap-descendants")
				if timeout != scannerSupervisorTimeout {
					t.Fatalf("reaper timeout = %s, want %s", timeout, scannerSupervisorTimeout)
				}
				return nil
			},
			sendResult: func(fd int, clean bool) error {
				*events = append(*events, "send-proof")
				if fd != 9 || !clean {
					t.Fatalf("proof fd/clean = %d/%t, want 9/true", fd, clean)
				}
				return nil
			},
			now: func() time.Time { return time.Unix(1, 0) },
		}
	}

	t.Run("proof follows group kill leader wait and descendant reap", func(t *testing.T) {
		var events []string
		interrupted, childErr, err := superviseScannerChild(child, 9, nil, never, baseOps(&events))
		if err != nil || interrupted || childErr != nil {
			t.Fatalf("supervise clean child = interrupted %t, child error %v, error %v", interrupted, childErr, err)
		}
		want := []string{"observe-exit", "kill-group", "wait-leader", "reap-descendants", "send-proof"}
		if !equalStrings(events, want) {
			t.Fatalf("supervisor ordering = %v, want %v", events, want)
		}
	})

	t.Run("cancellation kills then proves completed cleanup", func(t *testing.T) {
		var events []string
		ops := baseOps(&events)
		observations := 0
		ops.waitForExit = func(int) (bool, error) {
			events = append(events, "observe-exit")
			observations++
			return observations > 1, nil
		}
		signals := make(chan os.Signal, 1)
		signals <- syscall.SIGTERM
		interrupted, childErr, err := superviseScannerChild(child, 9, signals, never, ops)
		if err != nil || !interrupted || childErr != nil {
			t.Fatalf("supervise cancelled child = interrupted %t, child error %v, error %v", interrupted, childErr, err)
		}
		want := []string{"observe-exit", "kill-group", "observe-exit", "kill-group", "wait-leader", "reap-descendants", "send-proof"}
		if !equalStrings(events, want) {
			t.Fatalf("cancel supervisor ordering = %v, want %v", events, want)
		}
	})

	t.Run("cancellation deadline withholds proof", func(t *testing.T) {
		var events []string
		ops := baseOps(&events)
		ops.waitForExit = func(int) (bool, error) {
			events = append(events, "observe-exit")
			return false, nil
		}
		times := []time.Time{time.Unix(10, 0), time.Unix(10, 0).Add(scannerSupervisorTimeout)}
		ops.now = func() time.Time {
			current := times[0]
			times = times[1:]
			return current
		}
		signals := make(chan os.Signal, 1)
		signals <- syscall.SIGTERM
		interrupted, childErr, err := superviseScannerChild(child, 9, signals, never, ops)
		if err == nil || !strings.Contains(err.Error(), "cleanup is unproven") || !interrupted || childErr != nil {
			t.Fatalf("supervise stuck child = interrupted %t, child error %v, error %v", interrupted, childErr, err)
		}
		want := []string{"observe-exit", "kill-group", "kill-group"}
		if !equalStrings(events, want) {
			t.Fatalf("deadline cleanup = %v, want %v with no wait/reap/proof", events, want)
		}
	})

	t.Run("wait error kills group and withholds proof", func(t *testing.T) {
		var events []string
		ops := baseOps(&events)
		wantErr := errors.New("waitid failed")
		ops.waitForExit = func(int) (bool, error) {
			events = append(events, "observe-exit")
			return false, wantErr
		}
		_, _, err := superviseScannerChild(child, 9, nil, never, ops)
		if !errors.Is(err, wantErr) {
			t.Fatalf("supervise wait error = %v, want %v", err, wantErr)
		}
		want := []string{"observe-exit", "kill-group"}
		if !equalStrings(events, want) {
			t.Fatalf("wait-error cleanup = %v, want %v", events, want)
		}
	})

	t.Run("group-kill error reaps leader but withholds descendant proof", func(t *testing.T) {
		var events []string
		ops := baseOps(&events)
		wantErr := errors.New("group kill failed")
		ops.killGroup = func(int, syscall.Signal) error {
			events = append(events, "kill-group")
			return wantErr
		}
		_, _, err := superviseScannerChild(child, 9, nil, never, ops)
		if !errors.Is(err, wantErr) {
			t.Fatalf("supervise group-kill error = %v, want %v", err, wantErr)
		}
		want := []string{"observe-exit", "kill-group", "wait-leader"}
		if !equalStrings(events, want) {
			t.Fatalf("group-kill cleanup = %v, want %v", events, want)
		}
	})

	t.Run("reap failure withholds proof", func(t *testing.T) {
		var events []string
		ops := baseOps(&events)
		wantErr := errors.New("descendant remains")
		ops.reapChildren = func(time.Duration) error {
			events = append(events, "reap-descendants")
			return wantErr
		}
		_, _, err := superviseScannerChild(child, 9, nil, never, ops)
		if !errors.Is(err, wantErr) {
			t.Fatalf("supervise reap error = %v, want %v", err, wantErr)
		}
		want := []string{"observe-exit", "kill-group", "wait-leader", "reap-descendants"}
		if !equalStrings(events, want) {
			t.Fatalf("reap-error ordering = %v, want %v", events, want)
		}
	})

	t.Run("proof-send failure is returned", func(t *testing.T) {
		var events []string
		ops := baseOps(&events)
		wantErr := errors.New("result socket closed")
		ops.sendResult = func(int, bool) error {
			events = append(events, "send-proof")
			return wantErr
		}
		_, _, err := superviseScannerChild(child, 9, nil, never, ops)
		if !errors.Is(err, wantErr) {
			t.Fatalf("supervise proof-send error = %v, want %v", err, wantErr)
		}
		want := []string{"observe-exit", "kill-group", "wait-leader", "reap-descendants", "send-proof"}
		if !equalStrings(events, want) {
			t.Fatalf("proof-send ordering = %v, want %v", events, want)
		}
	})

	t.Run("child exit error still proves process cleanup", func(t *testing.T) {
		var events []string
		ops := baseOps(&events)
		childErrWant := errors.New("scanner exit status 3")
		ops.waitChild = func(*exec.Cmd) error {
			events = append(events, "wait-leader")
			return childErrWant
		}
		interrupted, childErr, err := superviseScannerChild(child, 9, nil, never, ops)
		if err != nil || interrupted || !errors.Is(childErr, childErrWant) {
			t.Fatalf("supervise failed scanner = interrupted %t, child error %v, error %v", interrupted, childErr, err)
		}
		want := []string{"observe-exit", "kill-group", "wait-leader", "reap-descendants", "send-proof"}
		if !equalStrings(events, want) {
			t.Fatalf("failed-child ordering = %v, want %v", events, want)
		}
	})

	t.Run("missing process or operation fails closed", func(t *testing.T) {
		if _, _, err := superviseScannerChild(nil, 9, nil, never, scannerSupervisorOps{}); err == nil {
			t.Fatal("nil child was accepted")
		}
		if _, _, err := superviseScannerChild(child, 9, nil, never, scannerSupervisorOps{}); err == nil {
			t.Fatal("missing operations were accepted")
		}
	})
}

func TestScannerSupervisorResultSenderEmitsOnlyExplicitSuccessProof(t *testing.T) {
	for _, test := range []struct {
		name      string
		clean     bool
		wantValid bool
	}{
		{name: "success", clean: true, wantValid: true},
		{name: "unclean", clean: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fds[0])
			defer unix.Close(fds[1])
			if err := sendScannerSupervisorResult(fds[0], test.clean); err != nil {
				t.Fatalf("send result frame: %v", err)
			}
			message := make([]byte, 16)
			n, _, flags, _, err := unix.Recvmsg(fds[1], message, nil, 0)
			if err != nil || flags&unix.MSG_TRUNC != 0 || n != len(message) {
				t.Fatalf("receive result frame = n %d flags %#x err %v", n, flags, err)
			}
			gotValid := validateScannerSupervisorResult(message) == nil
			if gotValid != test.wantValid {
				t.Fatalf("result clean=%t validated=%t; want %t", test.clean, gotValid, test.wantValid)
			}
		})
	}
	if err := sendScannerSupervisorResult(-1, true); err == nil {
		t.Fatal("result sender accepted an invalid descriptor")
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func TestScannerSupervisorReaperFindsNoChildrenAndBoundsLiveChildWait(t *testing.T) {
	if err := reapScannerChildren(100 * time.Millisecond); err != nil {
		t.Fatalf("reap without children: %v", err)
	}
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := reapScannerChildren(15 * time.Millisecond); err == nil || !strings.Contains(err.Error(), "deadline") {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("reap with live controlled child = %v, want bounded deadline", err)
	}
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("stop controlled child after bounded reaper check: %v", err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("controlled child unexpectedly exited successfully")
	}
}

func TestPrepareLinuxScannerInvocationBuildsBoundLaunchRequestBeforeStart(t *testing.T) {
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	lease := &supervisorTestLease{identityOK: true}
	allocatorCalls := 0
	policy := &Policy{
		profile: Scanner,
		status:  Status{Mode: ModeAuto, State: StateEnforced},
		enforce: true,
		helper:  helper,
		ambient: []uintptr{unix.CAP_NET_RAW, unix.CAP_NET_ADMIN},
		identityAllocator: func(context.Context) (identityLease, error) {
			allocatorCalls++
			return lease, nil
		},
	}
	command := exec.Command("/bin/true", "--version")
	command.Env = []string{"EDGEWATCH_TEST_VALUE=present"}
	command.Dir = t.TempDir()
	command.SysProcAttr = &syscall.SysProcAttr{AmbientCaps: []uintptr{unix.CAP_NET_RAW, unix.CAP_NET_ADMIN}}
	wantAmbientCaps := append([]uintptr(nil), command.SysProcAttr.AmbientCaps...)

	invocation, err := prepareLinuxScannerInvocation(context.Background(), command, policy, true)
	if err != nil {
		t.Fatalf("prepare scanner invocation: %v", err)
	}
	implementation, ok := invocation.implementation.(*scannerSupervisorInvocation)
	if !ok {
		t.Fatalf("invocation implementation is %T, want scanner supervisor", invocation.implementation)
	}
	if allocatorCalls != 1 || implementation.request.UID != 61000 || implementation.request.GID != 61000 ||
		!implementation.request.Session || implementation.request.Files != 0 ||
		!reflect.DeepEqual(implementation.request.Env, command.Env) || implementation.request.Dir != command.Dir ||
		!reflect.DeepEqual(implementation.request.AmbientCaps, wantAmbientCaps) {
		t.Fatalf("launch request does not preserve invocation identity/session/environment: calls=%d request=%+v", allocatorCalls, implementation.request)
	}
	var encoded scannerLaunchRequest
	if err := json.Unmarshal(implementation.config, &encoded); err != nil || !reflect.DeepEqual(encoded, implementation.request) {
		t.Fatalf("bounded launch config = %+v, %v; want %+v", encoded, err, implementation.request)
	}
	if command.Path != helper || len(command.Args) != 9 || command.Args[1] != ExecCommand || command.Args[2] != scannerSupervisorFlag || command.SysProcAttr != nil || len(command.ExtraFiles) != 2 {
		t.Fatalf("outer command = path %q args %q sysproc %#v extra files %d; want supervisor wrapper before Start", command.Path, command.Args, command.SysProcAttr, len(command.ExtraFiles))
	}
	if err := invocation.StartFailed(true); err != nil {
		t.Fatalf("release lease after outer supervisor did not start: %v", err)
	}
	if lease.releases != 1 || lease.quarantines != 0 {
		t.Fatalf("setup-failure lease actions = release %d, quarantine %d", lease.releases, lease.quarantines)
	}
}

func TestBuildScannerChildCommandPreservesValidatedIsolationContract(t *testing.T) {
	dataFile, err := os.CreateTemp(t.TempDir(), "scanner-child-data-")
	if err != nil {
		t.Fatal(err)
	}
	defer dataFile.Close()
	childFiles := []*os.File{dataFile}
	for _, session := range []bool{false, true} {
		name := "process group"
		if session {
			name = "new session"
		}
		t.Run(name, func(t *testing.T) {
			launch := scannerLaunchRequest{
				Version: 1, Path: "/bin/true", Args: []string{"/bin/true", "--fixed-arg"},
				Env: []string{"EDGEWATCH_CHILD=isolated"}, Dir: t.TempDir(), Files: len(childFiles),
				UID: scannerIdentityStart + 3, GID: scannerIdentityStart + 3,
				AmbientCaps: []uintptr{unix.CAP_NET_RAW, unix.CAP_NET_ADMIN}, Session: session,
			}
			wantArgs := append([]string(nil), launch.Args...)
			wantEnv := append([]string(nil), launch.Env...)
			wantCaps := append([]uintptr(nil), launch.AmbientCaps...)
			child := buildScannerChildCommand(launch, childFiles)
			if child.Path != launch.Path || !reflect.DeepEqual(child.Args, wantArgs) || !reflect.DeepEqual(child.Env, wantEnv) || child.Dir != launch.Dir {
				t.Fatalf("child command path/args/env/dir = %q/%q/%q/%q", child.Path, child.Args, child.Env, child.Dir)
			}
			if child.Stdin != os.Stdin || child.Stdout != os.Stdout || child.Stderr != os.Stderr || !reflect.DeepEqual(child.ExtraFiles, childFiles) {
				t.Fatal("child command changed inherited standard or scanner data descriptors")
			}
			attributes := child.SysProcAttr
			if attributes == nil || attributes.Credential == nil || attributes.Credential.Uid != launch.UID || attributes.Credential.Gid != launch.GID || len(attributes.Credential.Groups) != 0 ||
				attributes.Pdeathsig != syscall.SIGKILL || !reflect.DeepEqual(attributes.AmbientCaps, wantCaps) {
				t.Fatalf("child credentials/capabilities/parent-death attributes = %+v", attributes)
			}
			if session {
				if !attributes.Setsid || !attributes.Setctty || attributes.Ctty != 0 || attributes.Setpgid {
					t.Fatalf("session child process attributes = %+v", attributes)
				}
			} else if !attributes.Setpgid || attributes.Setsid || attributes.Setctty || attributes.Ctty != 0 {
				t.Fatalf("process-group child attributes = %+v", attributes)
			}
			launch.Args[1] = "mutated"
			launch.Env[0] = "mutated"
			launch.AmbientCaps[0] = 0
			if !reflect.DeepEqual(child.Args, wantArgs) || !reflect.DeepEqual(child.Env, wantEnv) || !reflect.DeepEqual(attributes.AmbientCaps, wantCaps) {
				t.Fatal("child command retained mutable launch-request slices")
			}
		})
	}
}

func TestPrepareLinuxScannerInvocationRejectsInvalidInputsBeforeLease(t *testing.T) {
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		ctx     context.Context
		policy  *Policy
		command func() *exec.Cmd
	}{
		{name: "cancelled context", ctx: cancelledScannerContext(), policy: scannerPreparationPolicy(helper), command: func() *exec.Cmd { return exec.Command("/bin/true") }},
		{name: "invalid command path", ctx: context.Background(), policy: scannerPreparationPolicy(helper), command: func() *exec.Cmd { return &exec.Cmd{Path: "relative", Args: []string{"relative"}} }},
		{name: "command start error", ctx: context.Background(), policy: scannerPreparationPolicy(helper), command: func() *exec.Cmd {
			command := exec.Command("/bin/true")
			command.Err = errors.New("invalid command")
			return command
		}},
		{name: "nil command", ctx: context.Background(), policy: scannerPreparationPolicy(helper), command: func() *exec.Cmd { return nil }},
		{name: "missing command arguments", ctx: context.Background(), policy: scannerPreparationPolicy(helper), command: func() *exec.Cmd {
			return &exec.Cmd{Path: "/bin/true"}
		}},
		{name: "NUL in executable path", ctx: context.Background(), policy: scannerPreparationPolicy(helper), command: func() *exec.Cmd {
			return &exec.Cmd{Path: "/bin/true\x00invalid", Args: []string{"/bin/true"}}
		}},
		{name: "too many inherited files", ctx: context.Background(), policy: scannerPreparationPolicy(helper), command: func() *exec.Cmd {
			return &exec.Cmd{Path: "/bin/true", Args: []string{"/bin/true"}, ExtraFiles: make([]*os.File, maxInheritedFiles-1)}
		}},
		{name: "wrong process profile", ctx: context.Background(), policy: func() *Policy {
			policy := scannerPreparationPolicy(helper)
			policy.profile = Notifier
			return policy
		}(), command: func() *exec.Cmd { return exec.Command("/bin/true") }},
		{name: "unenforced policy", ctx: context.Background(), policy: func() *Policy {
			policy := scannerPreparationPolicy(helper)
			policy.enforce = false
			return policy
		}(), command: func() *exec.Cmd { return exec.Command("/bin/true") }},
		{name: "relative supervisor executable", ctx: context.Background(), policy: scannerPreparationPolicy("relative-helper"), command: func() *exec.Cmd { return exec.Command("/bin/true") }},
		{name: "missing supervisor executable", ctx: context.Background(), policy: scannerPreparationPolicy("/does/not/exist/edgewatch"), command: func() *exec.Cmd { return exec.Command("/bin/true") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var allocatorCalls int
			if test.policy != nil {
				test.policy.identityAllocator = func(context.Context) (identityLease, error) {
					allocatorCalls++
					return &supervisorTestLease{identityOK: true}, nil
				}
			}
			invocation, err := prepareLinuxScannerInvocation(test.ctx, test.command(), test.policy, false)
			if err == nil || invocation != nil {
				t.Fatalf("prepareLinuxScannerInvocation() = %v, %v; want refusal before creating an invocation", invocation, err)
			}
			if allocatorCalls != 0 {
				t.Fatalf("invalid request acquired a lease %d times", allocatorCalls)
			}
		})
	}

	t.Run("nil and explicit off policies leave command and allocator untouched", func(t *testing.T) {
		for _, policy := range []*Policy{nil, {profile: Scanner, status: Status{Mode: ModeOff}}} {
			command := exec.Command("/bin/true")
			path, args := command.Path, append([]string(nil), command.Args...)
			if invocation, err := prepareLinuxScannerInvocation(context.Background(), command, policy, false); err != nil || invocation != nil {
				t.Fatalf("unconfined policy returned invocation %v, error %v", invocation, err)
			}
			if command.Path != path || !reflect.DeepEqual(command.Args, args) {
				t.Fatalf("unconfined policy mutated command to %q %q", command.Path, command.Args)
			}
		}
	})

	t.Run("unavailable reservation refuses before acquiring a replacement lease", func(t *testing.T) {
		policy := scannerPreparationPolicy(helper)
		policy.identityReservation = &ScannerIdentityReservation{}
		policy.identityAllocator = func(context.Context) (identityLease, error) {
			t.Fatal("unavailable reservation acquired a replacement lease")
			return nil, nil
		}
		if invocation, err := prepareLinuxScannerInvocation(context.Background(), exec.Command("/bin/true"), policy, false); err == nil || invocation != nil {
			t.Fatalf("unavailable reservation returned invocation %v, error %v", invocation, err)
		}
	})
}

func TestPrepareLinuxScannerInvocationReleasesOrQuarantinesFailedSetupLease(t *testing.T) {
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("oversized serialized request releases unreserved lease", func(t *testing.T) {
		lease := &supervisorTestLease{identityOK: true}
		policy := scannerPreparationPolicy(helper)
		policy.identityAllocator = func(context.Context) (identityLease, error) { return lease, nil }
		command := exec.Command("/bin/true")
		command.Env = []string{"EDGEWATCH_TEST_VALUE=" + strings.Repeat("x", scannerSupervisorMaxConfig)}
		if invocation, err := prepareLinuxScannerInvocation(context.Background(), command, policy, false); err == nil || invocation != nil {
			t.Fatalf("oversized launch request returned %v, %v; want refusal", invocation, err)
		}
		if lease.releases != 1 || lease.quarantines != 0 {
			t.Fatalf("oversized request lease actions = release %d, quarantine %d", lease.releases, lease.quarantines)
		}
	})

	t.Run("unavailable identity is quarantined", func(t *testing.T) {
		lease := &supervisorTestLease{identityOK: false}
		policy := scannerPreparationPolicy(helper)
		policy.identityAllocator = func(context.Context) (identityLease, error) { return lease, nil }
		if invocation, err := prepareLinuxScannerInvocation(context.Background(), exec.Command("/bin/true"), policy, false); err == nil || invocation != nil {
			t.Fatalf("invalid lease returned invocation %v, %v; want refusal", invocation, err)
		}
		if lease.releases != 0 || lease.quarantines != 1 {
			t.Fatalf("unavailable lease actions = release %d, quarantine %d", lease.releases, lease.quarantines)
		}
	})

	t.Run("malformed wrapped command releases unreserved lease", func(t *testing.T) {
		lease := &supervisorTestLease{identityOK: true}
		policy := scannerPreparationPolicy(helper)
		policy.identityAllocator = func(context.Context) (identityLease, error) { return lease, nil }
		command := &exec.Cmd{Path: helper, Args: []string{helper, ExecCommand, "--files", "0"}}
		if invocation, err := prepareLinuxScannerInvocation(context.Background(), command, policy, false); err == nil || invocation != nil {
			t.Fatalf("malformed wrapped command returned invocation %v, %v; want refusal", invocation, err)
		}
		if lease.releases != 1 || lease.quarantines != 0 {
			t.Fatalf("malformed wrapper lease actions = release %d, quarantine %d", lease.releases, lease.quarantines)
		}
	})
}

func scannerPreparationPolicy(helper string) *Policy {
	return &Policy{
		profile: Scanner,
		status:  Status{Mode: ModeAuto, State: StateEnforced},
		enforce: true,
		helper:  helper,
		ambient: []uintptr{unix.CAP_NET_RAW},
	}
}

func cancelledScannerContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
