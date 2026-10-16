//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const scannerSupervisorPrivilegedCoverageEnv = "EDGEWATCH_TEST_PRIVILEGED_SCANNER_SUPERVISOR"
const scannerSupervisorPrivilegedCoverageChildEnv = "EDGEWATCH_TEST_PRIVILEGED_SCANNER_SUPERVISOR_CHILD"
const scannerSupervisorPrivilegedCoverageExpectedErrorEnv = "EDGEWATCH_TEST_PRIVILEGED_SCANNER_SUPERVISOR_EXPECTED_ERROR"

type privilegedSupervisorCoverageLease struct {
	releases    int
	quarantines int
}

func (lease *privilegedSupervisorCoverageLease) identity() (int, int, bool) {
	return ScannerIdentityPoolUIDStart, ScannerIdentityPoolUIDStart, true
}

func (lease *privilegedSupervisorCoverageLease) release() error {
	lease.releases++
	return nil
}

func (lease *privilegedSupervisorCoverageLease) quarantine() error {
	lease.quarantines++
	return nil
}

// TestScannerSupervisorPrivilegedCoverageChild re-enters the production
// supervisor through the ordinary Go test harness so coverage counters flush
// to the parent test's coverage directory.
func TestScannerSupervisorPrivilegedCoverageChild(t *testing.T) {
	if os.Getenv(scannerSupervisorPrivilegedCoverageChildEnv) != "1" {
		return
	}
	err := execScannerSupervisor(flag.Args())
	expected := os.Getenv(scannerSupervisorPrivilegedCoverageExpectedErrorEnv)
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
	required := capabilityMask(unix.CAP_SETUID, unix.CAP_SETGID, unix.CAP_KILL)
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
}

func runPrivilegedScannerSupervisorCase(t *testing.T, executable string, program []string, expectedError string, cancelSupervisor bool) {
	t.Helper()
	launchArgs := []string{executable, ExecCommand, "--profile", string(Scanner), "--files", "0", "--identity-only", "--seccomp", "--"}
	launchArgs = append(launchArgs, program...)
	launch := scannerLaunchRequest{
		Version: 1,
		Path:    executable,
		Args:    launchArgs,
		Env:     []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"},
		UID:     uint32(ScannerIdentityPoolUIDStart),
		GID:     uint32(ScannerIdentityPoolUIDStart),
	}
	configuration, err := json.Marshal(launch)
	if err != nil {
		t.Fatal(err)
	}
	request, err := parseScannerSupervisorArgs([]string{"--files", "0", "--request-fd", "3", "--result-fd", "4"})
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
	lease := &privilegedSupervisorCoverageLease{}
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
	testArgs = append(testArgs, "--", "--files", "0", "--request-fd", "3", "--result-fd", "4")
	command := exec.CommandContext(ctx, executable, testArgs...)
	command.Env = append(os.Environ(), scannerSupervisorPrivilegedCoverageChildEnv+"=1", scannerSupervisorPrivilegedCoverageExpectedErrorEnv+"="+expectedError)
	command.ExtraFiles = []*os.File{configRead, resultWrite}
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
