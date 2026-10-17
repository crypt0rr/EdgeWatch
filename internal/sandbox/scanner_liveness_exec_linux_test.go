//go:build linux

package sandbox

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const scannerLivenessCloseChildEnv = "EDGEWATCH_TEST_SCANNER_LIVENESS_CLOSE_CHILD"
const scannerLivenessNetlinkChildEnv = "EDGEWATCH_TEST_SCANNER_LIVENESS_NETLINK_CHILD"

func TestNotifierLandlockAndSeccompExecWithoutScannerLease(t *testing.T) {
	if _, err := landlockVersion(); err != nil {
		t.Skipf("kernel cannot apply Landlock: %v", err)
	}
	if err := seccompSupport(); err != nil {
		t.Skipf("kernel cannot install the seccomp filter: %v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, ExecCommand,
		"--profile", string(Notifier), "--files", "0", "--seccomp", "--", "/bin/true")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("notifier Landlock+seccomp helper without scanner lease failed: %v; output=%q", err, output)
	}
}

func TestScannerSeccompExecStillRequiresValidLivenessLease(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("missing lease", func(t *testing.T) {
		command := exec.Command(executable, ExecCommand,
			"--profile", string(Scanner), "--files", "0", "--identity-only", "--seccomp", "--", "/bin/true")
		output, err := command.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "usage: sandbox-exec") {
			t.Fatalf("scanner helper without a lease = %v, output=%q; want fail-closed usage error", err, output)
		}
	})
	t.Run("invalid lease", func(t *testing.T) {
		invalidLease, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer invalidLease.Close()
		command := exec.Command(executable, ExecCommand,
			"--profile", string(Scanner), "--files", "1", "--identity-only", "--seccomp", "--liveness-fd", "3", "--", "/bin/true")
		command.ExtraFiles = []*os.File{invalidLease}
		output, err := command.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "scanner liveness reference is invalid") {
			t.Fatalf("scanner helper with an invalid lease = %v, output=%q; want fail-closed liveness error", err, output)
		}
	})
}

// TestScannerLivenessSeccompCloseChild runs inside a test binary already
// confined by sandbox-exec. Calling unix.Close directly verifies the kernel
// returns EPERM for the protected descriptor while it remains usable.
func TestScannerLivenessSeccompCloseChild(t *testing.T) {
	if os.Getenv(scannerLivenessCloseChildEnv) != "1" {
		return
	}
	if err := validateScannerLivenessDescriptor(3); err != nil {
		t.Fatalf("inherited liveness descriptor: %v", err)
	}
	if err := unix.Close(3); !errors.Is(err, unix.EPERM) {
		t.Fatalf("close protected liveness descriptor = %v, want EPERM", err)
	}
	if err := validateScannerLivenessDescriptor(3); err != nil {
		t.Fatalf("protected liveness descriptor did not survive denied close: %v", err)
	}
}

// TestScannerLivenessSeccompNetlinkChild runs inside the scanner helper after
// the liveness filter is installed. Route discovery needs sendmsg, while the
// syscall remains safe because scanner descendants cannot create Unix sockets
// or inherit a Unix socket descriptor.
func TestScannerLivenessSeccompNetlinkChild(t *testing.T) {
	if os.Getenv(scannerLivenessNetlinkChildEnv) != "1" {
		return
	}
	if err := validateScannerLivenessDescriptor(3); err != nil {
		t.Fatalf("inherited liveness descriptor: %v", err)
	}
	netlinkFD, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("scanner could not create route-netlink socket: %v", err)
	}
	if err := unix.Close(netlinkFD); err != nil {
		t.Fatalf("close route-netlink socket: %v", err)
	}
	if _, _, errno := unix.RawSyscall6(unix.SYS_SENDMSG, ^uintptr(0), 0, 0, 0, 0, 0); !errors.Is(errno, unix.EBADF) {
		t.Fatalf("sendmsg with an invalid descriptor = %v, want EBADF (proving syscall is allowed)", errno)
	}
	if _, _, errno := unix.RawSyscall6(unix.SYS_SENDMMSG, ^uintptr(0), 0, 0, 0, 0, 0); !errors.Is(errno, unix.EBADF) {
		t.Fatalf("sendmmsg with an invalid descriptor = %v, want EBADF (proving syscall is allowed)", errno)
	}
	if fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0); !errors.Is(err, unix.EPERM) {
		if err == nil {
			_ = unix.Close(fd)
		}
		t.Fatalf("Unix socket creation = fd %d, %v; want EPERM", fd, err)
	}
	if pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0); !errors.Is(err, unix.EPERM) {
		if err == nil {
			_ = unix.Close(pair[0])
			_ = unix.Close(pair[1])
		}
		t.Fatalf("Unix socketpair creation = %v, want EPERM", err)
	}
}

func TestScannerLivenessSeccompDeniesCloseOnInheritedDescriptor(t *testing.T) {
	if err := seccompSupport(); err != nil {
		t.Skipf("kernel cannot install the scanner seccomp filter: %v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	liveness := scannerLivenessTestFile(t)
	command := exec.Command(executable, ExecCommand, "--profile", string(Scanner), "--files", "1", "--identity-only", "--seccomp", "--liveness-fd", "3", "--", executable, "-test.run=^TestScannerLivenessSeccompCloseChild$")
	command.Env = append(os.Environ(), scannerLivenessCloseChildEnv+"=1")
	command.ExtraFiles = []*os.File{liveness}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("scanner helper child close test failed: %v; output=%q", err, output)
	}
}

func TestScannerHelperRejectsInheritedUnixSocket(t *testing.T) {
	if err := seccompSupport(); err != nil {
		t.Skipf("kernel cannot install the scanner seccomp filter: %v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	liveness := scannerLivenessTestFile(t)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[1])
	inheritedSocket := os.NewFile(uintptr(pair[0]), "test inherited Unix socket")
	if inheritedSocket == nil {
		_ = unix.Close(pair[0])
		t.Fatal("wrap test inherited Unix socket")
	}
	defer inheritedSocket.Close()
	command := exec.Command(executable, ExecCommand, "--profile", string(Scanner), "--files", "2", "--identity-only", "--seccomp", "--liveness-fd", "3", "--", executable, "-test.run=^TestScannerLivenessSeccompCloseChild$")
	command.ExtraFiles = []*os.File{liveness, inheritedSocket}
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "inherited Unix socket descriptor is not allowed") {
		t.Fatalf("scanner helper with inherited Unix socket = %v, output=%q; want fail-closed refusal", err, output)
	}
}

func TestScannerLivenessSeccompPreservesNetlinkSendmsg(t *testing.T) {
	if err := seccompSupport(); err != nil {
		t.Skipf("kernel cannot install the scanner seccomp filter: %v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	liveness := scannerLivenessTestFile(t)
	command := exec.Command(executable, ExecCommand, "--profile", string(Scanner), "--files", "1", "--identity-only", "--seccomp", "--liveness-fd", "3", "--", executable, "-test.run=^TestScannerLivenessSeccompNetlinkChild$")
	command.Env = append(os.Environ(), scannerLivenessNetlinkChildEnv+"=1")
	command.ExtraFiles = []*os.File{liveness}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("scanner helper netlink boundary test failed: %v; output=%q", err, output)
	}
}

// TestScannerLivenessReferenceSurvivesExecAndDescendantLifetime exercises the
// real helper and kernel OFD lock. A scanner descendant keeps the scope live
// after the direct scanner process exits.
func TestScannerLivenessReferenceSurvivesExecAndDescendantLifetime(t *testing.T) {
	if err := seccompSupport(); err != nil {
		t.Skipf("kernel cannot install the scanner seccomp filter: %v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	liveness := scannerLivenessTestFile(t)
	probe, err := os.OpenFile(liveness.Name(), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = probe.Close() })
	pidReader, pidWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pidReader.Close() })
	script := `/bin/sleep 30 & printf '%s\n' "$!" >&4; wait`
	command := exec.Command(executable, ExecCommand, "--profile", string(Scanner), "--files", "2", "--identity-only", "--seccomp", "--liveness-fd", "3", "--", "/bin/sh", "-c", script)
	command.Env = []string{"PATH=/bin:/usr/bin", "HOME=/nonexistent"}
	command.ExtraFiles = []*os.File{liveness, pidWriter}
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		_ = pidReader.Close()
		_ = pidWriter.Close()
		t.Fatal(err)
	}
	defer devNull.Close()
	// Use real file descriptors instead of io.Discard, which makes os/exec
	// create pipes that the deliberately surviving descendant would keep open.
	command.Stdout, command.Stderr = devNull, devNull
	if err := command.Start(); err != nil {
		_ = pidWriter.Close()
		t.Fatalf("start scanner helper: %v", err)
	}
	if err := pidWriter.Close(); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("close parent copy of descendant PID channel: %v", err)
	}
	if err := liveness.Close(); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("close daemon copy of liveness reference: %v", err)
	}
	var childPID int
	var childStart uint64
	waited := false
	t.Cleanup(func() {
		if command.Process != nil && !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
		if childPID > 0 {
			state, start, statErr := linuxProcessStartTime(childPID)
			if statErr == nil && start == childStart && state != "Z" {
				_ = syscall.Kill(childPID, syscall.SIGKILL)
			}
		}
	})

	type pidResult struct {
		text string
		err  error
	}
	pidResultCh := make(chan pidResult, 1)
	go func() {
		line, readErr := bufio.NewReader(pidReader).ReadString('\n')
		pidResultCh <- pidResult{text: line, err: readErr}
	}()
	var pidText string
	select {
	case result := <-pidResultCh:
		if result.err != nil {
			_ = command.Process.Kill()
			waitErr := command.Wait()
			waited = true
			t.Fatalf("scanner helper did not report its descendant: %v; exit=%v", result.err, waitErr)
		}
		pidText = strings.TrimSpace(result.text)
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		waitErr := command.Wait()
		waited = true
		t.Fatalf("scanner helper did not start its descendant before timeout; exit=%v", waitErr)
	}
	childPID, err = strconv.Atoi(pidText)
	if err != nil || childPID <= 0 {
		t.Fatalf("descendant PID %q is invalid: %v", pidText, err)
	}
	childState, start, err := linuxProcessStartTime(childPID)
	if err != nil || childState == "Z" {
		t.Fatalf("scanner descendant is not live: state=%q start=%d err=%v", childState, start, err)
	}
	childStart = start
	if err := setScannerIdentityOFDLock(int(probe.Fd()), unix.F_WRLCK, true); !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EACCES) {
		t.Fatalf("independent exclusive lock while scanner runs = %v, want blocked", err)
	}

	if err := command.Process.Kill(); err != nil {
		t.Fatalf("terminate scanner leader: %v", err)
	}
	_ = command.Wait()
	waited = true
	childState, start, err = linuxProcessStartTime(childPID)
	if err != nil || start != childStart || childState == "Z" {
		t.Fatalf("descendant did not outlive scanner leader: state=%q start=%d err=%v", childState, start, err)
	}
	if err := setScannerIdentityOFDLock(int(probe.Fd()), unix.F_WRLCK, true); !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EACCES) {
		t.Fatalf("independent exclusive lock after scanner leader exit = %v, want blocked by descendant", err)
	}

	if err := syscall.Kill(childPID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("terminate scanner descendant: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state, currentStart, statErr := linuxProcessStartTime(childPID)
		if errors.Is(statErr, os.ErrNotExist) || statErr == nil && (currentStart != childStart || state == "Z") {
			break
		}
		if statErr != nil {
			t.Fatalf("inspect terminated scanner descendant: %v", statErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := setScannerIdentityOFDLock(int(probe.Fd()), unix.F_WRLCK, true); err != nil {
		t.Fatalf("independent exclusive lock after descendant exit = %v, want available", err)
	}
}

func linuxProcessStartTime(pid int) (string, uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", 0, err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 || end+2 >= len(data) {
		return "", 0, errors.New("process stat record is malformed")
	}
	fields := strings.Fields(string(data[end+2:]))
	if len(fields) <= 19 {
		return "", 0, errors.New("process stat record is truncated")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return "", 0, errors.New("process start time is invalid")
	}
	return fields[0], start, nil
}
