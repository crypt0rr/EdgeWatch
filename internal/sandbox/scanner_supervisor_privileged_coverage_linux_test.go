//go:build linux

package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const scannerSupervisorPrivilegedCoverageEnv = "EDGEWATCH_TEST_PRIVILEGED_SCANNER_SUPERVISOR"
const scannerSupervisorPrivilegedCoverageChildEnv = "EDGEWATCH_TEST_PRIVILEGED_SCANNER_SUPERVISOR_CHILD"
const scannerSupervisorPrivilegedCoverageExpectedErrorEnv = "EDGEWATCH_TEST_PRIVILEGED_SCANNER_SUPERVISOR_EXPECTED_ERROR"
const scannerSupervisorPrivilegedBrokerModeEnv = "EDGEWATCH_TEST_PRIVILEGED_SCANNER_BROKER_MODE"
const scannerSupervisorPrivilegedBrokerControlFDEnv = "EDGEWATCH_TEST_PRIVILEGED_SCANNER_BROKER_CONTROL_FD"
const scannerSupervisorPrivilegedBrokerStaleReplyMode = "stale-reply-after-injection"
const scannerSupervisorPrivilegedCoverageExpectNotificationENOENT = "notification-reply-enoent"
const scannerSupervisorPrivilegedBrokerEventSize = 16

type privilegedSupervisorCoverageLease struct {
	releases     int
	quarantines  int
	livenessFile *os.File
	releaseCheck func() error
}

func (lease *privilegedSupervisorCoverageLease) identity() (int, int, bool) {
	return ScannerIdentityPoolUIDStart, ScannerIdentityPoolUIDStart, true
}

func (lease *privilegedSupervisorCoverageLease) release() error {
	lease.releases++
	if lease.releaseCheck != nil {
		return lease.releaseCheck()
	}
	return nil
}

func (lease *privilegedSupervisorCoverageLease) quarantine() error {
	lease.quarantines++
	return nil
}

func (lease *privilegedSupervisorCoverageLease) inheritedScannerLivenessFile() (*os.File, error) {
	if lease == nil || lease.livenessFile == nil {
		return nil, errors.New("test liveness reference is unavailable")
	}
	return lease.livenessFile, nil
}

// TestScannerSupervisorPrivilegedCoverageChild re-enters the production
// supervisor through the ordinary Go test harness so coverage counters flush
// to the parent test's coverage directory.
func TestScannerSupervisorPrivilegedCoverageChild(t *testing.T) {
	if os.Getenv(scannerSupervisorPrivilegedCoverageChildEnv) != "1" {
		return
	}
	var err error
	if os.Getenv(scannerSupervisorPrivilegedBrokerModeEnv) == scannerSupervisorPrivilegedBrokerStaleReplyMode {
		controlFD, parseErr := strconv.Atoi(os.Getenv(scannerSupervisorPrivilegedBrokerControlFDEnv))
		if parseErr != nil || controlFD < 3 {
			t.Fatalf("invalid privileged broker control descriptor: %v", parseErr)
		}
		control := os.NewFile(uintptr(controlFD), "privileged broker test control")
		if control == nil {
			t.Fatal("privileged broker test control descriptor is unavailable")
		}
		defer control.Close()
		err = execScannerSupervisorWithBrokerFactory(flag.Args(), func(listenerFD int) *seccompNotificationBroker {
			return &seccompNotificationBroker{
				listenerFD: listenerFD,
				afterAddFD: func(_ uint64, traceePID uint32, sourceFD, targetFD int) error {
					_, sourceErr := unix.FcntlInt(uintptr(sourceFD), unix.F_GETFD, 0)
					if !errors.Is(sourceErr, unix.EBADF) {
						return errors.New("broker source descriptor remained open after injection")
					}
					var event [scannerSupervisorPrivilegedBrokerEventSize]byte
					event[0] = 1
					binary.LittleEndian.PutUint32(event[4:8], traceePID)
					binary.LittleEndian.PutUint32(event[8:12], uint32(sourceFD))
					binary.LittleEndian.PutUint32(event[12:16], uint32(targetFD))
					if n, writeErr := control.Write(event[:]); writeErr != nil || n != len(event) {
						return errors.New("write privileged broker injection barrier failed")
					}
					var acknowledgement [1]byte
					if _, readErr := io.ReadFull(control, acknowledgement[:]); readErr != nil || acknowledgement[0] != 1 {
						return errors.New("read privileged broker injection barrier acknowledgement failed")
					}
					return nil
				},
			}
		})
	} else {
		err = execScannerSupervisor(flag.Args())
	}
	expected := os.Getenv(scannerSupervisorPrivilegedCoverageExpectedErrorEnv)
	if expected == scannerSupervisorPrivilegedCoverageExpectNotificationENOENT {
		if err == nil || !errors.Is(err, unix.ENOENT) || !strings.Contains(err.Error(), "reply to seccomp notification with injected socket") {
			t.Fatalf("production supervisor error = %v; want the real stale-ID NOTIF_SEND ENOENT after ADDFD", err)
		}
		return
	}
	if expected == "" {
		if err != nil {
			t.Fatalf("run production scanner supervisor: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatalf("production scanner supervisor error = %v; want %q", err, expected)
	}
}

// TestScannerSupervisorPrivilegedLifecycleCoverage is selected explicitly in
// a disposable root container with the scanner control capabilities. It
// exercises successful exit, scanner failure with valid cleanup proof, and
// bounded cancellation. The ordinary rootless suite skips these OS-level
// cases while retaining its separate fail-closed start-failure coverage.
func TestScannerSupervisorPrivilegedLifecycleCoverage(t *testing.T) {
	if os.Getenv(scannerSupervisorPrivilegedCoverageEnv) != "1" {
		t.Skip("requires explicit privileged scanner supervisor coverage run")
	}
	env := systemEnvironment()
	required := capabilityMask(unix.CAP_SETUID, unix.CAP_SETGID, unix.CAP_KILL, unix.CAP_NET_RAW)
	if env.euid != 0 || env.effective&required != required {
		t.Fatalf("explicit privileged supervisor run lacks required root control capabilities: euid=%d effective=%#x required=%#x", env.euid, env.effective, required)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name             string
		program          []string
		supervisorError  string
		cancelSupervisor bool
	}{
		{name: "successful child exit", program: []string{"/bin/true"}},
		{name: "failed scanner still proves cleanup", program: []string{"/bin/false"}, supervisorError: "scanner exited unsuccessfully"},
		{name: "cancellation kills and reaps child", program: []string{"/bin/sleep", "10"}, supervisorError: "scanner process tree was cancelled", cancelSupervisor: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runPrivilegedScannerSupervisorCase(t, executable, test.program, test.supervisorError, test.cancelSupervisor)
		})
	}
	t.Run("failed real notification reply reaps descendants before lease release", func(t *testing.T) {
		runPrivilegedScannerNotificationReplyFailureCase(t, executable)
	})
}

func runPrivilegedScannerNotificationReplyFailureCase(t *testing.T, executable string) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/nmap"); err != nil {
		t.Fatalf("privileged image is missing the bundled Nmap used by this regression: %v", err)
	}
	livenessFile := scannerLivenessTestFile(t)
	livenessPath := livenessFile.Name()
	lockProbe, err := os.OpenFile(livenessPath, os.O_RDWR, 0)
	if err != nil {
		_ = livenessFile.Close()
		t.Fatal(err)
	}
	pidReader, pidWriter, err := os.Pipe()
	if err != nil {
		_ = lockProbe.Close()
		_ = livenessFile.Close()
		t.Fatal(err)
	}
	controlFDs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		_ = pidReader.Close()
		_ = pidWriter.Close()
		_ = lockProbe.Close()
		_ = livenessFile.Close()
		t.Fatal(err)
	}
	controlRead := os.NewFile(uintptr(controlFDs[0]), "notification regression control parent")
	controlWrite := os.NewFile(uintptr(controlFDs[1]), "notification regression control child")
	configRead, configWrite, err := os.Pipe()
	if err != nil {
		_ = pidReader.Close()
		_ = pidWriter.Close()
		_ = controlRead.Close()
		_ = controlWrite.Close()
		_ = lockProbe.Close()
		_ = livenessFile.Close()
		t.Fatal(err)
	}
	resultFDs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		_ = pidReader.Close()
		_ = pidWriter.Close()
		_ = controlRead.Close()
		_ = controlWrite.Close()
		_ = configRead.Close()
		_ = configWrite.Close()
		_ = lockProbe.Close()
		_ = livenessFile.Close()
		t.Fatal(err)
	}
	resultRead := os.NewFile(uintptr(resultFDs[0]), "notification regression supervisor result")
	resultWrite := os.NewFile(uintptr(resultFDs[1]), "notification regression supervisor result child")
	// The shell keeps a real descendant alive while Nmap makes the exact
	// AF_UNIX datagram request intercepted by the production filter. The
	// descriptor and PID channels are inherited scanner data, while the
	// broker barrier is supervisor-only.
	script := `/bin/sleep 60 & printf '%s\n' "$!" >&4; exec /usr/bin/nmap -n --privileged -sS -p 1 --reason 127.0.0.1 >/dev/null 2>&1`
	launchArgs := []string{executable, ExecCommand, "--profile", string(Scanner), "--files", "2", "--identity-only", "--seccomp", "--liveness-fd", "3", "--", "/bin/sh", "-c", script}
	launch := scannerLaunchRequest{
		Version: 1, Path: executable, Args: launchArgs, Env: []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"},
		Files: 2, LivenessFD: 3, UID: uint32(ScannerIdentityPoolUIDStart), GID: uint32(ScannerIdentityPoolUIDStart),
		AmbientCaps: []uintptr{unix.CAP_NET_RAW},
	}
	configuration, err := json.Marshal(launch)
	if err != nil {
		t.Fatal(err)
	}
	request, err := parseScannerSupervisorArgs([]string{"--files", "2", "--request-fd", "5", "--result-fd", "6"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeScannerLaunchRequest(configuration, request); err != nil {
		t.Fatalf("notification regression launch request is invalid: %v", err)
	}
	lease := &privilegedSupervisorCoverageLease{livenessFile: livenessFile}
	implementation := &scannerSupervisorInvocation{
		lease: lease, request: launch, config: configuration,
		configRead: configRead, configWrite: configWrite,
		resultRead: resultRead, resultWrite: resultWrite,
	}
	invocation := &ScannerInvocation{implementation: implementation}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	testArgs := []string{"-test.run=^TestScannerSupervisorPrivilegedCoverageChild$"}
	if coverageDir := currentTestCoverageDirectory(); coverageDir != "" {
		testArgs = append(testArgs, "-test.gocoverdir="+coverageDir)
	}
	testArgs = append(testArgs, "--", "--files", "2", "--request-fd", "5", "--result-fd", "6")
	command := exec.CommandContext(ctx, executable, testArgs...)
	command.Env = append(os.Environ(),
		scannerSupervisorPrivilegedCoverageChildEnv+"=1",
		scannerSupervisorPrivilegedCoverageExpectedErrorEnv+"="+scannerSupervisorPrivilegedCoverageExpectNotificationENOENT,
		scannerSupervisorPrivilegedBrokerModeEnv+"="+scannerSupervisorPrivilegedBrokerStaleReplyMode,
		scannerSupervisorPrivilegedBrokerControlFDEnv+"=7",
	)
	command.ExtraFiles = []*os.File{livenessFile, pidWriter, configRead, resultWrite, controlWrite}
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	command.Stdout, command.Stderr = devNull, devNull
	command.WaitDelay = time.Second
	var waited bool
	var scannerProcessGroup int
	var sleepPID int
	var sleepStart uint64
	completed := false
	closeFiles := func() {
		_ = pidReader.Close()
		_ = pidWriter.Close()
		_ = controlRead.Close()
		_ = controlWrite.Close()
		_ = configRead.Close()
		_ = configWrite.Close()
		_ = resultRead.Close()
		_ = resultWrite.Close()
		_ = lockProbe.Close()
		_ = livenessFile.Close()
	}
	t.Cleanup(func() {
		if !completed {
			if scannerProcessGroup == 0 && command.Process != nil {
				scannerProcessGroup = privilegedSupervisorFirstChild(command.Process.Pid)
			}
			if scannerProcessGroup > 0 {
				_ = syscall.Kill(-scannerProcessGroup, syscall.SIGKILL)
			}
			if command.Process != nil && !waited {
				_ = command.Process.Kill()
				_ = command.Wait()
			}
			if sleepPID > 0 {
				_ = syscall.Kill(sleepPID, syscall.SIGKILL)
			}
		}
		closeFiles()
		if !implementation.finished {
			_ = invocation.Finish(false)
		}
	})
	if err := command.Start(); err != nil {
		if finishErr := invocation.StartFailed(true); finishErr != nil {
			t.Fatalf("start notification supervisor child: %v; release setup lease: %v", err, finishErr)
		}
		t.Fatalf("start notification supervisor child: %v", err)
	}
	if err := invocation.Started(); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		waited = true
		_ = invocation.Finish(false)
		t.Fatalf("acknowledge notification supervisor launch: %v", err)
	}
	_ = pidWriter.Close()
	_ = controlWrite.Close()
	_ = configRead.Close()
	_ = resultWrite.Close()
	if err := livenessFile.Close(); err != nil {
		t.Fatalf("close daemon liveness copy after supervisor start: %v", err)
	}

	readable, err := waitPrivilegedPipeReadable(int(pidReader.Fd()), scannerSupervisorTimeout)
	if err != nil || !readable {
		t.Fatalf("scanner shell did not publish its descendant PID: readable=%t error=%v", readable, err)
	}
	pidLine, err := bufio.NewReader(pidReader).ReadString('\n')
	if err != nil {
		t.Fatalf("read scanner descendant PID: %v", err)
	}
	sleepPID, err = strconv.Atoi(strings.TrimSpace(pidLine))
	if err != nil || sleepPID <= 0 {
		t.Fatalf("scanner published invalid descendant PID %q: %v", strings.TrimSpace(pidLine), err)
	}
	sleepState, sleepStart, err := linuxProcessStartTime(sleepPID)
	if err != nil || sleepState == "Z" {
		t.Fatalf("liveness-holding descendant is not alive before injection: state=%q error=%v", sleepState, err)
	}
	if err := setScannerIdentityOFDLock(int(lockProbe.Fd()), unix.F_WRLCK, true); !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EACCES) {
		t.Fatalf("exclusive liveness probe before injection = %v; want blocked by scanner tree", err)
	}

	readable, err = waitPrivilegedPipeReadable(int(controlRead.Fd()), scannerSupervisorTimeout)
	if err != nil || !readable {
		t.Fatalf("broker did not reach the post-ADDFD barrier: readable=%t error=%v", readable, err)
	}
	var event [scannerSupervisorPrivilegedBrokerEventSize]byte
	if _, err := io.ReadFull(controlRead, event[:]); err != nil {
		t.Fatalf("read broker post-injection event: %v", err)
	}
	traceePID := int(binary.LittleEndian.Uint32(event[4:8]))
	sourceFD := int(binary.LittleEndian.Uint32(event[8:12]))
	targetFD := int(binary.LittleEndian.Uint32(event[12:16]))
	if event[0] != 1 || traceePID <= 0 || sourceFD < 3 || targetFD < 5 {
		t.Fatalf("invalid post-ADDFD event: type=%d tracee=%d source=%d target=%d", event[0], traceePID, sourceFD, targetFD)
	}
	scannerProcessGroup = privilegedProcessTGID(traceePID)
	if scannerProcessGroup <= 0 {
		t.Fatalf("cannot identify Nmap thread group from seccomp notification TID %d", traceePID)
	}
	nmapState, nmapStart, err := linuxProcessStartTime(scannerProcessGroup)
	if err != nil || nmapState == "Z" {
		t.Fatalf("Nmap target is not live at the post-ADDFD barrier: state=%q error=%v", nmapState, err)
	}
	if err := syscall.Kill(scannerProcessGroup, syscall.SIGKILL); err != nil {
		t.Fatalf("kill Nmap only after successful ADDFD: %v", err)
	}
	if err := waitPrivilegedProcessExit(scannerProcessGroup, 0, scannerSupervisorTimeout); err != nil {
		t.Fatalf("killed Nmap process did not exit before stale-ID reply: %v", err)
	}
	if state, currentStart, statErr := linuxProcessStartTime(scannerProcessGroup); statErr == nil && currentStart == nmapStart && state != "Z" {
		t.Fatalf("Nmap target remained runnable after SIGKILL: state=%q", state)
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("inspect Nmap target after SIGKILL: %v", statErr)
	}
	state, currentSleepStart, err := linuxProcessStartTime(sleepPID)
	if err != nil || currentSleepStart != sleepStart || state == "Z" {
		t.Fatalf("descendant did not remain alive after Nmap exit and before supervisor cleanup: state=%q start=%d error=%v", state, currentSleepStart, err)
	}
	if err := setScannerIdentityOFDLock(int(lockProbe.Fd()), unix.F_WRLCK, true); !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EACCES) {
		t.Fatalf("exclusive liveness probe after Nmap exit but before cleanup = %v; want blocked by surviving descendant", err)
	}
	if _, err := controlRead.Write([]byte{1}); err != nil {
		t.Fatalf("release broker to issue real stale-ID NOTIF_SEND: %v", err)
	}

	lease.releaseCheck = func() error {
		if err := livenessFile.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			return fmt.Errorf("close parent liveness reference before lease assertion: %w", err)
		}
		if currentState, currentStart, statErr := linuxProcessStartTime(sleepPID); statErr == nil && currentStart == sleepStart {
			return fmt.Errorf("lease release attempted before descendant reaping: pid=%d state=%s", sleepPID, currentState)
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("inspect descendant before lease release: %w", statErr)
		}
		if err := setScannerIdentityOFDLock(int(lockProbe.Fd()), unix.F_WRLCK, true); err != nil {
			return fmt.Errorf("lease release attempted before liveness lock became available: %w", err)
		}
		return setScannerIdentityOFDLock(int(lockProbe.Fd()), unix.F_UNLCK, true)
	}

	if err := command.Wait(); err != nil {
		waited = true
		t.Fatalf("privileged stale-reply supervisor child failed: %v", err)
	}
	waited = true
	if err := invocation.VerifyProcessTree(); err != nil {
		t.Fatalf("supervisor did not produce cleanup proof after real reply failure: %v", err)
	}
	if err := invocation.Finish(true); err != nil {
		t.Fatalf("release identity only after verified descendant cleanup: %v", err)
	}
	if lease.releases != 1 || lease.quarantines != 0 {
		t.Fatalf("stale-reply lease actions = release %d, quarantine %d; want one release and no quarantine", lease.releases, lease.quarantines)
	}
	if err := waitPrivilegedProcessExit(sleepPID, sleepStart, scannerSupervisorTimeout); err != nil {
		t.Fatalf("supervisor proof did not reap liveness-holding descendant: %v", err)
	}
	if err := setScannerIdentityOFDLock(int(lockProbe.Fd()), unix.F_WRLCK, true); err != nil {
		t.Fatalf("exclusive liveness probe after cleanup proof = %v, want available", err)
	}
	if err := setScannerIdentityOFDLock(int(lockProbe.Fd()), unix.F_UNLCK, true); err != nil {
		t.Fatalf("unlock liveness probe after cleanup proof: %v", err)
	}
	completed = true
}

func waitPrivilegedPipeReadable(fd int, timeout time.Duration) (bool, error) {
	if fd < 0 || timeout <= 0 {
		return false, errors.New("invalid privileged test pipe wait")
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
	milliseconds := int((timeout + time.Millisecond - 1) / time.Millisecond)
	ready, err := unix.Poll(poll, milliseconds)
	if err != nil {
		return false, err
	}
	return ready > 0 && poll[0].Revents&unix.POLLIN != 0, nil
}

func privilegedSupervisorFirstChild(pid int) int {
	if pid <= 0 {
		return 0
	}
	path := fmt.Sprintf("/proc/%d/task/%d/children", pid, pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var child int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &child); err != nil {
		return 0
	}
	return child
}

func privilegedProcessTGID(pid int) int {
	if pid <= 0 {
		return 0
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Tgid:") {
			group, parseErr := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Tgid:")))
			if parseErr == nil && group > 0 {
				return group
			}
		}
	}
	return 0
}

func waitPrivilegedProcessExit(pid int, start uint64, timeout time.Duration) error {
	if pid <= 0 || timeout <= 0 {
		return errors.New("invalid privileged test process wait")
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, currentStart, err := linuxProcessStartTime(pid)
		if errors.Is(err, os.ErrNotExist) || (err == nil && start != 0 && currentStart != start) || (err == nil && start == 0 && state == "Z") {
			return nil
		}
		if err != nil {
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("process %d did not exit before deadline", pid)
}

func runPrivilegedScannerSupervisorCase(t *testing.T, executable string, program []string, expectedError string, cancelSupervisor bool) {
	t.Helper()
	livenessFile := scannerLivenessTestFile(t)
	launchArgs := []string{executable, ExecCommand, "--profile", string(Scanner), "--files", "1", "--identity-only", "--seccomp", "--liveness-fd", "3", "--"}
	launchArgs = append(launchArgs, program...)
	launch := scannerLaunchRequest{
		Version:    1,
		Path:       executable,
		Args:       launchArgs,
		Env:        []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"},
		Files:      1,
		LivenessFD: 3,
		UID:        uint32(ScannerIdentityPoolUIDStart),
		GID:        uint32(ScannerIdentityPoolUIDStart),
	}
	configuration, err := json.Marshal(launch)
	if err != nil {
		t.Fatal(err)
	}
	request, err := parseScannerSupervisorArgs([]string{"--files", "1", "--request-fd", "4", "--result-fd", "5"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeScannerLaunchRequest(configuration, request); err != nil {
		t.Fatalf("privileged launch request is invalid: %v", err)
	}
	configRead, configWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	resultFDs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		_ = configRead.Close()
		_ = configWrite.Close()
		t.Fatal(err)
	}
	resultRead := os.NewFile(uintptr(resultFDs[0]), "privileged scanner supervisor result")
	resultWrite := os.NewFile(uintptr(resultFDs[1]), "privileged scanner supervisor child result")
	lease := &privilegedSupervisorCoverageLease{livenessFile: livenessFile}
	implementation := &scannerSupervisorInvocation{
		lease: lease, request: launch, config: configuration,
		configRead: configRead, configWrite: configWrite,
		resultRead: resultRead, resultWrite: resultWrite,
	}
	invocation := &ScannerInvocation{implementation: implementation}
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	testArgs := []string{"-test.run=^TestScannerSupervisorPrivilegedCoverageChild$"}
	if coverageDir := currentTestCoverageDirectory(); coverageDir != "" {
		testArgs = append(testArgs, "-test.gocoverdir="+coverageDir)
	}
	testArgs = append(testArgs, "--", "--files", "1", "--request-fd", "4", "--result-fd", "5")
	command := exec.CommandContext(ctx, executable, testArgs...)
	command.Env = append(os.Environ(), scannerSupervisorPrivilegedCoverageChildEnv+"=1", scannerSupervisorPrivilegedCoverageExpectedErrorEnv+"="+expectedError)
	command.ExtraFiles = []*os.File{livenessFile, configRead, resultWrite}
	command.Stdout, command.Stderr = &stdout, &stderr
	command.WaitDelay = time.Second
	var waited bool
	t.Cleanup(func() {
		if command.Process != nil && !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
		if !implementation.finished {
			_ = invocation.Finish(false)
		}
	})
	if err := command.Start(); err != nil {
		if finishErr := invocation.StartFailed(true); finishErr != nil {
			t.Fatalf("start supervisor test child: %v; release setup lease: %v", err, finishErr)
		}
		t.Fatalf("start supervisor test child: %v", err)
	}
	if err := invocation.Started(); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		waited = true
		_ = invocation.Finish(false)
		t.Fatalf("acknowledge supervisor launch: %v", err)
	}
	if cancelSupervisor {
		// The fixed sleep target keeps the supervisor alive long enough to
		// receive SIGTERM and exercise its bounded kill/wait/reap path.
		time.Sleep(250 * time.Millisecond)
		if err := invocation.Cancel(command); err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			waited = true
			_ = invocation.Finish(false)
			t.Fatalf("cancel scanner supervisor: %v", err)
		}
	}
	if err := command.Wait(); err != nil {
		waited = true
		_ = invocation.Finish(false)
		t.Fatalf("privileged supervisor test child failed: %v; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	waited = true
	if err := invocation.VerifyProcessTree(); err != nil {
		_ = invocation.Finish(false)
		t.Fatalf("supervisor did not produce cleanup proof: %v; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if err := invocation.Finish(true); err != nil {
		t.Fatalf("finish proved scanner invocation: %v", err)
	}
	if lease.releases != 1 || lease.quarantines != 0 {
		t.Fatalf("proved scanner lease actions = release %d, quarantine %d; want one release and no quarantine", lease.releases, lease.quarantines)
	}
}
