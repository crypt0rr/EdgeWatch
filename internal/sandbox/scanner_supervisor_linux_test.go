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
	"path/filepath"
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
	livenessFile  *os.File
	events        *[]string
}

type supervisorLeaseWithoutLiveness struct{}

func (supervisorLeaseWithoutLiveness) identity() (int, int, bool) { return 61000, 61000, true }
func (supervisorLeaseWithoutLiveness) release() error             { return nil }
func (supervisorLeaseWithoutLiveness) quarantine() error          { return nil }

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

func (lease *supervisorTestLease) inheritedScannerLivenessFile() (*os.File, error) {
	if lease == nil || lease.livenessFile == nil {
		return nil, errors.New("test liveness reference is unavailable")
	}
	return lease.livenessFile, nil
}

func TestScannerLivenessLeaseAndArgumentDescriptorContracts(t *testing.T) {
	if _, err := scannerLivenessFileForLease(nil); err == nil {
		t.Fatal("nil identity lease returned a liveness reference")
	}
	if _, err := scannerLivenessFileForLease(supervisorLeaseWithoutLiveness{}); err == nil {
		t.Fatal("identity lease without liveness support was accepted")
	}
	if _, err := scannerLivenessFileForLease(&supervisorTestLease{}); err == nil {
		t.Fatal("lease without an inherited liveness reference was accepted")
	}
	device, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	if _, err := scannerLivenessFileForLease(&supervisorTestLease{livenessFile: device}); err == nil {
		t.Fatal("non-lock file was accepted as the lease liveness reference")
	}

	cmd := exec.Command("/bin/true")
	if fd, err := appendScannerLivenessFile(nil, scannerLivenessTestFile(t)); err == nil || fd != -1 {
		t.Fatalf("nil command liveness append = fd %d, %v", fd, err)
	}
	if fd, err := appendScannerLivenessFile(cmd, nil); err == nil || fd != -1 {
		t.Fatalf("nil liveness file append = fd %d, %v", fd, err)
	}

	file := scannerLivenessTestFile(t)
	if fd, err := appendScannerLivenessFile(cmd, file); err != nil || fd != 3 {
		t.Fatalf("append first liveness file = fd %d, %v; want fd 3", fd, err)
	}
	if fd, err := appendScannerLivenessFile(cmd, file); err != nil || fd != 3 {
		t.Fatalf("reuse identical liveness file = fd %d, %v; want fd 3", fd, err)
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, file)
	if fd, err := appendScannerLivenessFile(cmd, file); err == nil || fd != -1 {
		t.Fatalf("duplicate liveness file references = fd %d, %v", fd, err)
	}
	cmd.ExtraFiles = cmd.ExtraFiles[:1]

	alias, err := os.Open(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer alias.Close()
	cmd.ExtraFiles = append(cmd.ExtraFiles, alias)
	if fd, err := appendScannerLivenessFile(cmd, file); err == nil || fd != -1 {
		t.Fatalf("aliased liveness file descriptor = fd %d, %v", fd, err)
	}
	cmd.ExtraFiles = nil
	closed, err := os.Open(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if fd, err := appendScannerLivenessFile(cmd, closed); err == nil || fd != -1 {
		t.Fatalf("closed liveness file = fd %d, %v", fd, err)
	}
	cmd.ExtraFiles = []*os.File{nil}
	if fd, err := appendScannerLivenessFile(cmd, file); err == nil || fd != -1 {
		t.Fatalf("nil existing inherited file = fd %d, %v", fd, err)
	}
}

func TestStartThroughIdentityOnlyHelperRequiresAndPassesLiveness(t *testing.T) {
	startThroughIdentityOnlyHelper(nil, "/usr/local/bin/edgewatch", nil)

	missing := exec.Command(filepath.Join(t.TempDir(), "missing"))
	startThroughIdentityOnlyHelper(missing, "/usr/local/bin/edgewatch", func() (*os.File, error) {
		t.Fatal("liveness provider called for a missing probe executable")
		return nil, nil
	})
	if missing.Err == nil {
		t.Fatal("missing probe executable was accepted")
	}

	cmd := exec.Command("/bin/true")
	startThroughIdentityOnlyHelper(cmd, "/usr/local/bin/edgewatch", nil)
	if cmd.Err == nil || !strings.Contains(cmd.Err.Error(), "no liveness reference") {
		t.Fatalf("missing liveness provider error = %v", cmd.Err)
	}

	device, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	cmd = exec.Command("/bin/true")
	startThroughIdentityOnlyHelper(cmd, "/usr/local/bin/edgewatch", func() (*os.File, error) {
		return device, nil
	})
	if cmd.Err == nil || !strings.Contains(cmd.Err.Error(), "liveness reference is unavailable") {
		t.Fatalf("invalid liveness provider error = %v", cmd.Err)
	}

	cmd = exec.Command("/bin/true")
	file := scannerLivenessTestFile(t)
	cmd.ExtraFiles = []*os.File{file, file}
	startThroughIdentityOnlyHelper(cmd, "/usr/local/bin/edgewatch", func() (*os.File, error) {
		return file, nil
	})
	if cmd.Err == nil || !strings.Contains(cmd.Err.Error(), "liveness reference is invalid") {
		t.Fatalf("duplicate liveness reference error = %v", cmd.Err)
	}

	cmd = exec.Command("/bin/true")
	cmd.ExtraFiles = make([]*os.File, maxInheritedFiles)
	startThroughIdentityOnlyHelper(cmd, "/usr/local/bin/edgewatch", func() (*os.File, error) {
		return file, nil
	})
	if cmd.Err == nil || !strings.Contains(cmd.Err.Error(), "liveness reference is invalid") {
		t.Fatalf("descriptor-limit liveness error = %v", cmd.Err)
	}
}

func TestScannerIdentityReservationLivenessFileRequiresActiveLivenessLease(t *testing.T) {
	var nilReservation *ScannerIdentityReservation
	if _, err := nilReservation.livenessFile(); err == nil {
		t.Fatal("nil reservation returned a liveness file")
	}
	if _, err := (&ScannerIdentityReservation{}).livenessFile(); err == nil {
		t.Fatal("empty reservation returned a liveness file")
	}
	if _, err := (&ScannerIdentityReservation{lease: &identityLeaseProbe{uid: 61000, gid: 61000, identityOK: true}}).livenessFile(); err == nil {
		t.Fatal("lease without a scanner liveness method was accepted")
	}

	file := scannerLivenessTestFile(t)
	lease := &supervisorTestLease{identityOK: true, livenessFile: file}
	reservation := &ScannerIdentityReservation{lease: lease}
	got, err := reservation.livenessFile()
	if err != nil || got != file {
		t.Fatalf("active reservation liveness file = %v, %v; want exact lease file", got, err)
	}
	if err := reservation.Finish(true); err != nil {
		t.Fatalf("finish active reservation: %v", err)
	}
	if _, err := reservation.livenessFile(); err == nil {
		t.Fatal("finished reservation still exposed the liveness file")
	}
}

func TestAddScannerNoEscapeHelperValidatesExistingHelperArguments(t *testing.T) {
	helper := "/usr/local/bin/edgewatch"
	valid := func(flags ...string) *exec.Cmd {
		args := []string{helper, ExecCommand, "--profile", string(Scanner)}
		args = append(args, flags...)
		return &exec.Cmd{Path: helper, Args: args, ExtraFiles: []*os.File{scannerLivenessTestFile(t)}}
	}
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "duplicate file count", args: []string{"--files", "1", "--files", "1", "--", "/bin/true"}, want: "file count is invalid"},
		{name: "missing file count", args: []string{"--files"}, want: "file count is invalid"},
		{name: "missing separator", args: []string{"--files", "1"}, want: "helper arguments are invalid"},
		{name: "missing file count flag", args: []string{"--", "/bin/true"}, want: "helper arguments are invalid"},
		{name: "duplicate liveness descriptor", args: []string{"--files", "1", "--liveness-fd", "3", "--liveness-fd", "3", "--", "/bin/true"}, want: "liveness descriptor is invalid"},
		{name: "missing liveness descriptor value", args: []string{"--files", "1", "--liveness-fd"}, want: "liveness descriptor is invalid"},
		{name: "duplicate seccomp flag", args: []string{"--files", "1", "--seccomp", "--seccomp", "--", "/bin/true"}, want: "seccomp flag is duplicated"},
		{name: "preconfigured notification descriptor", args: []string{"--files", "1", "--seccomp-notify-fd", "4", "--", "/bin/true"}, want: "notification descriptor is already set"},
		{name: "private helper count mismatch", args: []string{"--files", "0", "--private-tmp", "--", "/bin/true"}, want: "private temporary descriptor layout is invalid"},
		{name: "changed liveness descriptor", args: []string{"--files", "1", "--liveness-fd", "4", "--", "/bin/true"}, want: "liveness descriptor changed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := valid(test.args...)
			if err := addScannerNoEscapeHelper(command, helper, 3); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid helper arguments error = %v, want %q", err, test.want)
			}
		})
	}

	command := valid("--files", "99", "--", "/bin/true")
	if err := addScannerNoEscapeHelper(command, helper, 3); err != nil {
		t.Fatalf("rewrite existing helper without liveness/seccomp flags: %v", err)
	}
	request, err := parseExecArgs(command.Args[2:])
	if err != nil || request.files != 1 || request.livenessFD != 3 || !request.seccomp {
		t.Fatalf("rewritten helper request = %+v, %v; want files=1 liveness=3 seccomp", request, err)
	}

	command = exec.Command("/usr/bin/naabu", "-host", "127.0.0.1")
	if err := addScannerNoEscapeHelper(command, helper, 3); err != nil {
		t.Fatalf("wrap ordinary scanner command: %v", err)
	}
	separator := -1
	for index, arg := range command.Args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if command.Path != helper || separator < 0 || command.Args[1] != ExecCommand || command.Args[separator+1] != "/usr/bin/naabu" {
		t.Fatalf("wrapped scanner command = path %q args %q", command.Path, command.Args)
	}
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

func TestTerminateAndReapScannerChildOnlyReportsVerifiedCleanup(t *testing.T) {
	for _, test := range []struct {
		name      string
		resultFD  bool
		wantError string
	}{
		{name: "result delivered", resultFD: true},
		{name: "result channel failure", wantError: "cleanup proof write failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			child := exec.Command("/bin/sleep", "30")
			child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
				_ = child.Wait()
				t.Fatal(err)
			}
			defer unix.Close(pair[0])
			defer unix.Close(pair[1])
			resultFD := 1 << 20
			if test.resultFD {
				resultFD = pair[0]
			}
			cause := errors.New("injected broker reply failure")
			gotErr := terminateAndReapScannerChild(child, resultFD, cause)
			if gotErr == nil || !strings.Contains(gotErr.Error(), cause.Error()) {
				t.Fatalf("cleanup result = %v, want wrapped cause", gotErr)
			}
			if test.wantError != "" {
				if !strings.Contains(gotErr.Error(), test.wantError) {
					t.Fatalf("cleanup result = %v, want %q", gotErr, test.wantError)
				}
				return
			}
			var frame [16]byte
			n, _, _, _, recvErr := unix.Recvmsg(pair[1], frame[:], nil, 0)
			if recvErr != nil || n != len(frame) || string(frame[:8]) != scannerSupervisorMagic || frame[8] != 1 {
				t.Fatalf("cleanup proof frame = %x, bytes %d, err %v", frame, n, recvErr)
			}
			if err := syscall.Kill(-child.Process.Pid, 0); !errors.Is(err, syscall.ESRCH) {
				t.Fatalf("scanner process group remains after proof: %v", err)
			}
		})
	}
}

func TestReceiveScannerNotificationListenerHandlesChannelAndCancellationStates(t *testing.T) {
	t.Run("invalid parameters", func(t *testing.T) {
		if _, interrupted, err := receiveScannerNotificationListener(-1, nil, 0, 0, nil, time.Second); err == nil || interrupted {
			t.Fatalf("invalid listener wait = interrupted %v, error %v", interrupted, err)
		}
		if _, interrupted, err := receiveScannerNotificationListener(3, &exec.Cmd{}, 0, 0, nil, time.Second); err == nil || interrupted {
			t.Fatalf("missing child process = interrupted %v, error %v", interrupted, err)
		}
		if _, interrupted, err := receiveScannerNotificationListener(3, &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}, 0, 0, nil, 0); err == nil || interrupted {
			t.Fatalf("zero timeout = interrupted %v, error %v", interrupted, err)
		}
	})

	t.Run("closed listener descriptor fails closed", func(t *testing.T) {
		child := startNotificationWaitChild(t)
		defer stopNotificationWaitChild(child)
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(pair[1])
		if err := unix.Close(pair[0]); err != nil {
			t.Fatal(err)
		}
		fd, interrupted, err := receiveScannerNotificationListener(pair[0], child, uint32(os.Geteuid()), uint32(os.Getegid()), nil, time.Second)
		if err == nil || interrupted || fd >= 0 {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
			t.Fatalf("closed listener descriptor = fd %d, interrupted %v, error %v; want fail-closed error", fd, interrupted, err)
		}
	})

	t.Run("valid authenticated frame", func(t *testing.T) {
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(pair[0])
		defer unix.Close(pair[1])
		if err := unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
			t.Fatal(err)
		}
		passed, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer passed.Close()
		if err := sendSeccompNotificationListener(pair[1], int(passed.Fd())); err != nil {
			t.Fatal(err)
		}
		child := &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
		fd, interrupted, err := receiveScannerNotificationListener(pair[0], child, uint32(os.Geteuid()), uint32(os.Getegid()), nil, time.Second)
		if err != nil || interrupted {
			t.Fatalf("valid listener frame = fd %d, interrupted %v, error %v", fd, interrupted, err)
		}
		defer unix.Close(fd)
	})

	t.Run("cancellation before listener frame", func(t *testing.T) {
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(pair[0])
		defer unix.Close(pair[1])
		child := startNotificationWaitChild(t)
		defer stopNotificationWaitChild(child)
		signals := make(chan os.Signal, 1)
		signals <- syscall.SIGTERM
		fd, interrupted, err := receiveScannerNotificationListener(pair[0], child, uint32(os.Geteuid()), uint32(os.Getegid()), signals, time.Second)
		if err == nil || !interrupted {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
			t.Fatalf("canceled listener wait = fd %d, interrupted %v, error %v", fd, interrupted, err)
		}
	})

	t.Run("closed helper channel", func(t *testing.T) {
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(pair[0])
		if err := unix.Close(pair[1]); err != nil {
			t.Fatal(err)
		}
		child := startNotificationWaitChild(t)
		defer stopNotificationWaitChild(child)
		if fd, interrupted, err := receiveScannerNotificationListener(pair[0], child, uint32(os.Geteuid()), uint32(os.Getegid()), nil, time.Second); err == nil || interrupted {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
			t.Fatalf("closed helper channel = fd %d, interrupted %v, error %v", fd, interrupted, err)
		}
	})

	t.Run("helper exits without frame", func(t *testing.T) {
		pair := make([]int, 2)
		if err := unix.Pipe2(pair, unix.O_CLOEXEC); err != nil {
			t.Fatal(err)
		}
		defer unix.Close(pair[0])
		// Keep the pipe writer open so Poll cannot report HUP when the child
		// exits. This exercises the independent Waitid check used when a helper
		// descendant still holds the control channel open.
		defer unix.Close(pair[1])
		child := exec.Command("/bin/true")
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		// Keep the control peer open and observe the helper exit without reaping
		// it. This forces receiveScannerNotificationListener through its Waitid
		// exit check instead of racing the helper's channel close.
		deadline := time.Now().Add(time.Second)
		for {
			var info unix.Siginfo
			if err := unix.Waitid(unix.P_PID, child.Process.Pid, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil); err != nil {
				t.Fatalf("observe helper exit without reaping: %v", err)
			}
			if info.Signo != 0 {
				break
			}
			if time.Now().After(deadline) {
				_ = child.Process.Kill()
				_ = child.Wait()
				t.Fatal("helper did not exit before listener wait")
			}
			time.Sleep(time.Millisecond)
		}
		poll := []unix.PollFd{{Fd: int32(pair[0]), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
		if n, err := unix.Poll(poll, 0); err != nil || n != 0 {
			t.Fatalf("control pipe signaled before listener wait = %d events %#x, error %v", n, poll[0].Revents, err)
		}
		if fd, interrupted, err := receiveScannerNotificationListener(pair[0], child, uint32(os.Geteuid()), uint32(os.Getegid()), nil, time.Second); err == nil || interrupted {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
			_ = child.Process.Kill()
			_ = child.Wait()
			t.Fatalf("exited helper channel = fd %d, interrupted %v, error %v", fd, interrupted, err)
		}
		if err := child.Wait(); err != nil {
			t.Fatalf("reap helper that exited before listener handoff: %v", err)
		}
	})
}

func startNotificationWaitChild(t *testing.T) *exec.Cmd {
	t.Helper()
	child := exec.Command("/bin/sleep", "30")
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	return child
}

func stopNotificationWaitChild(child *exec.Cmd) {
	if child == nil || child.Process == nil {
		return
	}
	_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
	_ = child.Wait()
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
			Version: 1, Path: "/usr/bin/edgewatch", Args: []string{"/usr/bin/edgewatch", ExecCommand, "--profile", string(Scanner), "--files", "1", "--identity-only", "--seccomp", "--liveness-fd", "3", "--", "/bin/true"},
			Files: 1, LivenessFD: 3, UID: scannerIdentityStart, GID: scannerIdentityStart,
		}
		encoded, err := json.Marshal(valid)
		if err != nil {
			t.Fatal(err)
		}
		request := scannerSupervisorRequest{files: 1, requestFD: 4, resultFD: 5}
		if got, err := decodeScannerLaunchRequest(encoded, request); err != nil || got.Path != valid.Path || !reflect.DeepEqual(got.Args, valid.Args) || got.LivenessFD != valid.LivenessFD {
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
			{name: "liveness descriptor outside files", change: func(request *scannerLaunchRequest) { request.LivenessFD = 4 }},
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

	t.Run("notification descriptor follows data and private control descriptors", func(t *testing.T) {
		baseArgs := []string{"/usr/local/bin/edgewatch", ExecCommand, "--profile", string(Scanner), "--files", "1", "--identity-only", "--seccomp", "--liveness-fd", "3", "--", "/bin/true"}
		updated, err := appendSeccompNotificationControl(baseArgs, 4)
		if err != nil {
			t.Fatalf("append identity-only notification descriptor: %v", err)
		}
		identity, err := parseExecArgs(updated[2:])
		if err != nil || identity.notifyFD != 4 || identity.files != 1 {
			t.Fatalf("identity-only request = %+v, %v; want data=1 notify=4", identity, err)
		}

		privateArgs := []string{"/usr/local/bin/edgewatch", ExecCommand, "--profile", string(Scanner), "--files", "1", "--private-tmp", "--private-root-fd", "4", "--private-leaf-fd", "5", "--control-fd", "6", "--seccomp", "--liveness-fd", "3", "--", "/usr/local/bin/naabu"}
		updated, err = appendSeccompNotificationControl(privateArgs, 7)
		if err != nil {
			t.Fatalf("append private-temporary notification descriptor: %v", err)
		}
		private, err := parseExecArgs(updated[2:])
		if err != nil || private.notifyFD != 7 || private.files != 1 || private.controlFD != 6 {
			t.Fatalf("private request = %+v, %v; want data=1 control=6 notify=7", private, err)
		}
		launch := scannerLaunchRequest{
			Version: 1, Path: privateArgs[0], Args: updated, Files: 4, LivenessFD: 3,
			UID: scannerIdentityStart, GID: scannerIdentityStart,
		}
		encoded, err := json.Marshal(launch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeScannerLaunchRequest(encoded, scannerSupervisorRequest{files: 4}); err == nil {
			t.Fatal("parent launch request containing supervisor-only notification fd was accepted")
		}
		launch.Args = privateArgs
		encoded, err = json.Marshal(launch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeScannerLaunchRequest(encoded, scannerSupervisorRequest{files: 4}); err != nil {
			t.Fatalf("decode private helper request with separate controls: %v", err)
		}
	})

	t.Run("private helper keeps data count separate from setup controls", func(t *testing.T) {
		helper := "/usr/local/bin/edgewatch"
		command := &exec.Cmd{
			Path:       helper,
			Args:       []string{helper, ExecCommand, "--profile", string(Scanner), "--files", "1", "--private-tmp", "--private-root-fd", "4", "--private-leaf-fd", "5", "--control-fd", "6", "--seccomp", "--liveness-fd", "3", "--", "/usr/local/bin/naabu"},
			ExtraFiles: make([]*os.File, 4),
		}
		if err := addScannerNoEscapeHelper(command, helper, 3); err != nil {
			t.Fatalf("preserve private helper descriptor layout: %v", err)
		}
		request, err := parseExecArgs(command.Args[2:])
		if err != nil || request.files != 1 || request.controlFD != 6 || request.livenessFD != 3 {
			t.Fatalf("private helper request = %+v, %v; want data=1, liveness=3, control=6", request, err)
		}
	})

	t.Run("append rejects unexpected or wrong-offset notification fd", func(t *testing.T) {
		args := []string{"/usr/local/bin/edgewatch", ExecCommand, "--profile", string(Scanner), "--files", "1", "--identity-only", "--seccomp", "--liveness-fd", "3", "--", "/bin/true"}
		if _, err := appendSeccompNotificationControl(args, 2); err == nil {
			t.Fatal("notification descriptor below fd 3 was accepted")
		}
		if _, err := appendSeccompNotificationControl([]string{"/usr/local/bin/edgewatch"}, 4); err == nil {
			t.Fatal("short helper request was accepted")
		}
		wrongCommand := append([]string(nil), args...)
		wrongCommand[1] = "status"
		if _, err := appendSeccompNotificationControl(wrongCommand, 4); err == nil {
			t.Fatal("non-helper command was accepted for a notification descriptor")
		}
		if _, err := appendSeccompNotificationControl(args, 5); err == nil {
			t.Fatal("wrong notification descriptor offset was accepted")
		}
		withNotify := append(append([]string(nil), args[:len(args)-2]...), "--seccomp-notify-fd", "4", "--", "/bin/true")
		if _, err := appendSeccompNotificationControl(withNotify, 4); err == nil {
			t.Fatal("duplicate notification descriptor was accepted")
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

func TestReceiveScannerNotificationListenerTimeoutAndWaitFailure(t *testing.T) {
	t.Run("timeout while helper remains alive", func(t *testing.T) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fds[0])
		defer unix.Close(fds[1])
		child := exec.Command("/bin/sleep", "5")
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = child.Process.Kill()
			_ = child.Wait()
		})
		started := time.Now()
		if _, canceled, err := receiveScannerNotificationListener(fds[0], child, 61000, 61000, nil, 15*time.Millisecond); err == nil || canceled || !strings.Contains(err.Error(), "startup timed out") {
			t.Fatalf("listener timeout result = canceled %t, error %v", canceled, err)
		}
		if time.Since(started) > time.Second {
			t.Fatalf("short listener startup timeout took %s", time.Since(started))
		}
	})

	t.Run("wait status error fails closed", func(t *testing.T) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fds[0])
		defer unix.Close(fds[1])
		child := &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
		if _, canceled, err := receiveScannerNotificationListener(fds[0], child, 61000, 61000, nil, 15*time.Millisecond); err == nil || canceled || !strings.Contains(err.Error(), "exit could not be verified") {
			t.Fatalf("unverifiable helper result = canceled %t, error %v", canceled, err)
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

	t.Run("notification failure kills and proves the process tree before returning error", func(t *testing.T) {
		var events []string
		ops := baseOps(&events)
		observations := 0
		ops.waitForExit = func(int) (bool, error) {
			events = append(events, "observe-exit")
			observations++
			return observations > 1, nil
		}
		ops.serviceNotifications = func() error {
			events = append(events, "service-notification")
			return errors.New("unexpected notification")
		}
		watchdog := make(chan time.Time, 1)
		watchdog <- time.Now()
		interrupted, childErr, err := superviseScannerChild(child, 9, nil, watchdog, ops)
		if err == nil || !strings.Contains(err.Error(), "seccomp notification failed") || interrupted || childErr != nil {
			t.Fatalf("supervise unexpected notification = interrupted %t, child error %v, error %v", interrupted, childErr, err)
		}
		want := []string{"observe-exit", "service-notification", "kill-group", "observe-exit", "kill-group", "wait-leader", "reap-descendants", "send-proof"}
		if !equalStrings(events, want) {
			t.Fatalf("notification failure cleanup = %v, want %v", events, want)
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
	lease := &supervisorTestLease{identityOK: true, livenessFile: scannerLivenessTestFile(t)}
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
		!implementation.request.Session || implementation.request.Files != 1 || implementation.request.LivenessFD != 3 ||
		!reflect.DeepEqual(implementation.request.Env, command.Env) || implementation.request.Dir != command.Dir ||
		!reflect.DeepEqual(implementation.request.AmbientCaps, wantAmbientCaps) {
		t.Fatalf("launch request does not preserve invocation identity/session/environment: calls=%d request=%+v", allocatorCalls, implementation.request)
	}
	var encoded scannerLaunchRequest
	if err := json.Unmarshal(implementation.config, &encoded); err != nil || !reflect.DeepEqual(encoded, implementation.request) {
		t.Fatalf("bounded launch config = %+v, %v; want %+v", encoded, err, implementation.request)
	}
	if command.Path != helper || len(command.Args) != 9 || command.Args[1] != ExecCommand || command.Args[2] != scannerSupervisorFlag || command.SysProcAttr != nil || len(command.ExtraFiles) != 3 || command.Args[4] != "1" || command.Args[6] != "4" || command.Args[8] != "5" {
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
	livenessFile := scannerLivenessTestFile(t)
	childFiles := []*os.File{dataFile, livenessFile}
	for _, session := range []bool{false, true} {
		name := "process group"
		if session {
			name = "new session"
		}
		t.Run(name, func(t *testing.T) {
			launch := scannerLaunchRequest{
				Version: 1, Path: "/usr/bin/edgewatch", Args: []string{"/usr/bin/edgewatch", ExecCommand, "--profile", string(Scanner), "--files", "2", "--identity-only", "--seccomp", "--liveness-fd", "4", "--", "/bin/true", "--fixed-arg"},
				Env: []string{"EDGEWATCH_CHILD=isolated"}, Dir: t.TempDir(), Files: len(childFiles), LivenessFD: 4,
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
		lease := &supervisorTestLease{identityOK: true, livenessFile: scannerLivenessTestFile(t)}
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
		lease := &supervisorTestLease{identityOK: true, livenessFile: scannerLivenessTestFile(t)}
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

func TestPrepareScannerInvocationFailsClosedOnUnusableLivenessOwnership(t *testing.T) {
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	newPolicy := func() *Policy {
		policy := scannerPreparationPolicy(helper)
		policy.identityAllocator = func(context.Context) (identityLease, error) {
			return &supervisorTestLease{identityOK: true}, nil
		}
		return policy
	}
	t.Run("reserved identity has no liveness reference", func(t *testing.T) {
		lease := &supervisorTestLease{identityOK: true}
		policy := newPolicy()
		policy.identityReservation = &ScannerIdentityReservation{lease: lease}
		if invocation, err := prepareLinuxScannerInvocation(context.Background(), exec.Command("/bin/true"), policy, false); err == nil || invocation != nil || !strings.Contains(err.Error(), "liveness reference is unavailable") {
			t.Fatalf("prepare with liveness-less reservation = %v, %v; want fail-closed reservation error", invocation, err)
		}
		if lease.releases != 0 || lease.quarantines != 0 {
			t.Fatalf("unclaimed reservation was consumed: release=%d quarantine=%d", lease.releases, lease.quarantines)
		}
	})

	t.Run("unreserved lease has no liveness reference", func(t *testing.T) {
		lease := &supervisorTestLease{identityOK: true}
		policy := newPolicy()
		policy.identityAllocator = func(context.Context) (identityLease, error) { return lease, nil }
		if invocation, err := prepareLinuxScannerInvocation(context.Background(), exec.Command("/bin/true"), policy, false); err == nil || invocation != nil || !strings.Contains(err.Error(), "liveness reference is unavailable") {
			t.Fatalf("prepare with liveness-less lease = %v, %v; want fail-closed lease error", invocation, err)
		}
		if lease.releases != 0 || lease.quarantines != 1 {
			t.Fatalf("lease without a liveness proof actions = release %d quarantine %d; want quarantine", lease.releases, lease.quarantines)
		}
	})

	t.Run("closed liveness descriptor quarantines unproven lease", func(t *testing.T) {
		file := scannerLivenessTestFile(t)
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		lease := &supervisorTestLease{identityOK: true, livenessFile: file}
		policy := newPolicy()
		policy.identityAllocator = func(context.Context) (identityLease, error) { return lease, nil }
		if invocation, err := prepareLinuxScannerInvocation(context.Background(), exec.Command("/bin/true"), policy, false); err == nil || invocation != nil || !strings.Contains(err.Error(), "liveness reference is unavailable") {
			t.Fatalf("prepare with closed liveness descriptor = %v, %v; want refusal", invocation, err)
		}
		if lease.releases != 0 || lease.quarantines != 1 {
			t.Fatalf("closed-descriptor setup actions = release %d quarantine %d; want quarantine", lease.releases, lease.quarantines)
		}
	})

	t.Run("invalid inherited data descriptor releases unstarted lease", func(t *testing.T) {
		file := scannerLivenessTestFile(t)
		defer file.Close()
		lease := &supervisorTestLease{identityOK: true, livenessFile: file}
		policy := newPolicy()
		policy.identityAllocator = func(context.Context) (identityLease, error) { return lease, nil }
		command := &exec.Cmd{Path: "/bin/true", Args: []string{"/bin/true"}, ExtraFiles: []*os.File{nil}}
		if invocation, err := prepareLinuxScannerInvocation(context.Background(), command, policy, false); err == nil || invocation != nil || !strings.Contains(err.Error(), "inherited scanner descriptor is unavailable") {
			t.Fatalf("prepare with nil inherited data descriptor = %v, %v; want refusal", invocation, err)
		}
		if lease.releases != 1 || lease.quarantines != 0 {
			t.Fatalf("nil-data-descriptor setup actions = release %d quarantine %d; want release", lease.releases, lease.quarantines)
		}
	})

	t.Run("already claimed reservation cannot be transferred twice", func(t *testing.T) {
		file := scannerLivenessTestFile(t)
		defer file.Close()
		lease := &supervisorTestLease{identityOK: true, livenessFile: file}
		policy := newPolicy()
		policy.identityReservation = &ScannerIdentityReservation{lease: lease, claimed: true}
		if invocation, err := prepareLinuxScannerInvocation(context.Background(), exec.Command("/bin/true"), policy, false); err == nil || invocation != nil || !strings.Contains(err.Error(), "reserved identity is unavailable") {
			t.Fatalf("prepare with already-claimed reservation = %v, %v; want refusal", invocation, err)
		}
		if lease.releases != 0 || lease.quarantines != 0 {
			t.Fatalf("failed second transfer changed first reservation: release=%d quarantine=%d", lease.releases, lease.quarantines)
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
