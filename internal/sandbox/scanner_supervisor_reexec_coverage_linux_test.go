//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const scannerSupervisorCoverageChildEnv = "EDGEWATCH_TEST_SCANNER_SUPERVISOR_COVERAGE"
const scannerSupervisorCoverageExpectedErrorEnv = "EDGEWATCH_TEST_SCANNER_SUPERVISOR_EXPECTED_ERROR"

type scannerSupervisorCoverageLease struct {
	releases    int
	quarantines int
}

func (lease *scannerSupervisorCoverageLease) identity() (int, int, bool) {
	return ScannerIdentityPoolUIDStart, ScannerIdentityPoolUIDStart, true
}

func (lease *scannerSupervisorCoverageLease) release() error {
	lease.releases++
	return nil
}

func (lease *scannerSupervisorCoverageLease) quarantine() error {
	lease.quarantines++
	return nil
}

// TestScannerSupervisorCoverageChild runs the production supervisor entry
// point in a re-executed test binary. The Go test harness passes its coverage
// directory to the child, which then returns through m.Run so its counters are
// merged into the parent package profile.
func TestScannerSupervisorCoverageChild(t *testing.T) {
	if os.Getenv(scannerSupervisorCoverageChildEnv) != "1" {
		return
	}
	args := flag.Args()
	err := execScannerSupervisor(args)
	expected := os.Getenv(scannerSupervisorCoverageExpectedErrorEnv)
	if expected == "" {
		if err != nil && !strings.HasPrefix(err.Error(), "scanner supervisor: start scanner child:") {
			t.Fatalf("scanner supervisor returned unexpected error: %v (args %q)", err, args)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatalf("scanner supervisor error = %v; want %q (args %q)", err, expected, args)
	}
}

func TestScannerSupervisorReexecCoverageAndFailClosedStart(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	livenessFile := scannerLivenessTestFile(t)
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
	resultRead := os.NewFile(uintptr(resultFDs[0]), "scanner supervisor coverage result")
	resultWrite := os.NewFile(uintptr(resultFDs[1]), "scanner supervisor coverage child result")
	lease := &scannerSupervisorCoverageLease{}
	launch := scannerLaunchRequest{
		Version:    1,
		Path:       executable,
		Args:       []string{executable, ExecCommand, "--profile", string(Scanner), "--files", "1", "--identity-only", "--seccomp", "--liveness-fd", "3", "--", "/bin/true"},
		Env:        []string{"PATH=/usr/bin:/bin"},
		Files:      1,
		LivenessFD: 3,
		UID:        uint32(ScannerIdentityPoolUIDStart),
		GID:        uint32(ScannerIdentityPoolUIDStart),
	}
	configuration, err := json.Marshal(launch)
	if err != nil {
		_ = configRead.Close()
		_ = configWrite.Close()
		_ = resultRead.Close()
		_ = resultWrite.Close()
		t.Fatal(err)
	}
	request, err := parseScannerSupervisorArgs([]string{"--files", "1", "--request-fd", "4", "--result-fd", "5"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeScannerLaunchRequest(configuration, request); err != nil {
		t.Fatalf("test launch request is invalid before re-exec: %v; json=%s", err, configuration)
	}
	implementation := &scannerSupervisorInvocation{
		lease: lease, request: launch, config: configuration,
		configRead: configRead, configWrite: configWrite,
		resultRead: resultRead, resultWrite: resultWrite,
	}
	invocation := &ScannerInvocation{implementation: implementation}
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args := []string{"-test.run=^TestScannerSupervisorCoverageChild$"}
	if coverageDir := currentTestCoverageDirectory(); coverageDir != "" {
		args = append(args, "-test.gocoverdir="+coverageDir)
	}
	args = append(args, "--", "--files", "1", "--request-fd", "4", "--result-fd", "5")
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = append(os.Environ(), scannerSupervisorCoverageChildEnv+"=1")
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
			t.Fatalf("start supervisor helper: %v; release setup lease: %v", err, finishErr)
		}
		t.Fatalf("start supervisor helper: %v", err)
	}
	if err := invocation.Started(); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		waited = true
		_ = invocation.Finish(false)
		t.Fatalf("acknowledge supervisor launch: %v", err)
	}
	waitErr := command.Wait()
	waited = true
	if waitErr != nil {
		_ = invocation.Finish(false)
		t.Fatalf("supervisor test child failed: %v; stdout=%q stderr=%q", waitErr, stdout.String(), stderr.String())
	}

	proofErr := invocation.VerifyProcessTree()
	if proofErr == nil {
		if err := invocation.Finish(true); err != nil {
			t.Fatalf("finish verified supervisor: %v", err)
		}
		if lease.releases != 1 || lease.quarantines != 0 {
			t.Fatalf("verified supervisor lease actions = release %d, quarantine %d", lease.releases, lease.quarantines)
		}
		return
	}
	if !strings.Contains(proofErr.Error(), "did not prove process-tree cleanup") {
		t.Fatalf("failed-start proof error = %v; want fail-closed completion frame", proofErr)
	}
	if err := invocation.Finish(false); err != nil {
		t.Fatalf("quarantine after failed scanner start: %v", err)
	}
	if lease.releases != 0 || lease.quarantines != 1 {
		t.Fatalf("unproven supervisor lease actions = release %d, quarantine %d", lease.releases, lease.quarantines)
	}
}

func TestScannerSupervisorCancellationBeforeStartedReleasesUnlaunchedIdentity(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	livenessFile := scannerLivenessTestFile(t)
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
	resultRead := os.NewFile(uintptr(resultFDs[0]), "scanner supervisor pre-launch result")
	resultWrite := os.NewFile(uintptr(resultFDs[1]), "scanner supervisor pre-launch child result")
	marker := filepath.Join(t.TempDir(), "scanner-started")
	launch := scannerLaunchRequest{
		Version: 1, Path: "/bin/sh", Args: []string{"/bin/sh", "-c", "printf started > \"$MARKER\""},
		Env: []string{"PATH=/usr/bin:/bin", "MARKER=" + marker}, Files: 1, LivenessFD: 3,
		UID: uint32(ScannerIdentityPoolUIDStart), GID: uint32(ScannerIdentityPoolUIDStart),
	}
	configuration, err := json.Marshal(launch)
	if err != nil {
		t.Fatal(err)
	}
	lease := &scannerSupervisorCoverageLease{}
	implementation := &scannerSupervisorInvocation{
		lease: lease, request: launch, config: configuration,
		configRead: configRead, configWrite: configWrite,
		resultRead: resultRead, resultWrite: resultWrite,
	}
	invocation := &ScannerInvocation{implementation: implementation}
	args := []string{"-test.run=^TestScannerSupervisorCoverageChild$"}
	if coverageDir := currentTestCoverageDirectory(); coverageDir != "" {
		args = append(args, "-test.gocoverdir="+coverageDir)
	}
	args = append(args, "--", "--files", "1", "--request-fd", "4", "--result-fd", "5")
	command := exec.Command(executable, args...)
	command.Env = append(os.Environ(), scannerSupervisorCoverageChildEnv+"=1", scannerSupervisorCoverageExpectedErrorEnv+"=launch request is unavailable or too large")
	command.ExtraFiles = []*os.File{livenessFile, configRead, resultWrite}
	command.WaitDelay = time.Second
	if err := command.Start(); err != nil {
		_ = invocation.StartFailed(true)
		t.Fatalf("start scanner supervisor: %v", err)
	}
	if err := invocation.Cancel(command); err != nil {
		t.Fatal(err)
	}
	if err := invocation.Started(); !errors.Is(err, context.Canceled) {
		t.Fatalf("acknowledge canceled launch = %v, want context.Canceled", err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("supervisor re-exec test process failed: %v", err)
	}
	if err := invocation.VerifyProcessTree(); err != nil {
		t.Fatalf("prove no scanner child started: %v", err)
	}
	if err := invocation.Finish(true); err != nil {
		t.Fatalf("release unlaunched scanner identity: %v", err)
	}
	if lease.releases != 1 || lease.quarantines != 0 {
		t.Fatalf("pre-launch cancellation actions = release %d, quarantine %d; want release", lease.releases, lease.quarantines)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scanner child ran after pre-launch cancellation; marker stat error = %v", err)
	}
}

func TestScannerSupervisorReexecRejectsMalformedControlInput(t *testing.T) {
	validLaunch := scannerLaunchRequest{
		Version:    1,
		Path:       "/usr/bin/edgewatch",
		Args:       []string{"/usr/bin/edgewatch", ExecCommand, "--profile", string(Scanner), "--files", "1", "--identity-only", "--seccomp", "--liveness-fd", "3", "--", "/bin/true"},
		Env:        []string{"PATH=/usr/bin:/bin"},
		Files:      1,
		LivenessFD: 3,
		UID:        uint32(ScannerIdentityPoolUIDStart),
		GID:        uint32(ScannerIdentityPoolUIDStart),
	}
	validConfiguration, err := json.Marshal(validLaunch)
	if err != nil {
		t.Fatal(err)
	}
	wrongIdentity := validLaunch
	wrongIdentity.GID++
	wrongIdentityConfiguration, err := json.Marshal(wrongIdentity)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name           string
		args           []string
		configuration  []byte
		wantError      string
		wantCleanProof bool
	}{
		{name: "invalid argument frame", args: []string{"--files", "0"}, wantError: "usage: sandbox-exec"},
		{name: "empty configuration", args: []string{"--files", "1", "--request-fd", "4", "--result-fd", "5"}, wantError: "launch request is unavailable or too large", wantCleanProof: true},
		{name: "malformed JSON", args: []string{"--files", "1", "--request-fd", "4", "--result-fd", "5"}, configuration: []byte("{"), wantError: "launch request is malformed", wantCleanProof: true},
		{name: "invalid lease identity", args: []string{"--files", "1", "--request-fd", "4", "--result-fd", "5"}, configuration: wrongIdentityConfiguration, wantError: "launch request is invalid", wantCleanProof: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runScannerSupervisorCoverageChild(t, test.args, test.configuration, test.wantError, test.wantCleanProof)
		})
	}
	// A valid request reaches child.Start. Rootless CI cannot change to the
	// leased UID/GID because Go must clear supplementary groups, so the existing
	// start-failure path is expected to prove that no scanner child was started.
	runScannerSupervisorCoverageChild(t, []string{"--files", "1", "--request-fd", "4", "--result-fd", "5"}, validConfiguration, "scanner supervisor: start scanner child:", true)
}

func runScannerSupervisorCoverageChild(t *testing.T, helperArgs []string, configuration []byte, expectedError string, wantCleanProof bool) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	livenessFile := scannerLivenessTestFile(t)
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
	resultRead := os.NewFile(uintptr(resultFDs[0]), "scanner supervisor coverage result")
	resultWrite := os.NewFile(uintptr(resultFDs[1]), "scanner supervisor coverage child result")
	lease := &scannerSupervisorCoverageLease{}
	implementation := &scannerSupervisorInvocation{
		lease: lease, config: configuration, configRead: configRead, configWrite: configWrite,
		resultRead: resultRead, resultWrite: resultWrite,
	}
	invocation := &ScannerInvocation{implementation: implementation}
	cleanup := true
	t.Cleanup(func() {
		if cleanup && !implementation.finished {
			_ = invocation.Finish(false)
		}
	})

	args := []string{"-test.run=^TestScannerSupervisorCoverageChild$"}
	if coverageDir := currentTestCoverageDirectory(); coverageDir != "" {
		args = append(args, "-test.gocoverdir="+coverageDir)
	}
	args = append(args, "--")
	args = append(args, helperArgs...)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = append(os.Environ(), scannerSupervisorCoverageChildEnv+"=1", scannerSupervisorCoverageExpectedErrorEnv+"="+expectedError)
	command.ExtraFiles = []*os.File{livenessFile, configRead, resultWrite}
	command.WaitDelay = time.Second
	if err := command.Start(); err != nil {
		if finishErr := invocation.StartFailed(true); finishErr != nil {
			t.Fatalf("start supervisor helper: %v; release setup lease: %v", err, finishErr)
		}
		cleanup = false
		t.Fatalf("start supervisor helper: %v", err)
	}
	if err := invocation.Started(); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = invocation.Finish(false)
		cleanup = false
		t.Fatalf("acknowledge supervisor launch: %v", err)
	}
	if err := command.Wait(); err != nil {
		_ = invocation.Finish(false)
		cleanup = false
		t.Fatalf("supervisor test child failed: %v", err)
	}
	proofErr := invocation.VerifyProcessTree()
	if wantCleanProof {
		if proofErr != nil {
			t.Fatalf("no-child start failure did not prove cleanup: %v", proofErr)
		}
		if err := invocation.Finish(true); err != nil {
			t.Fatalf("finish no-child start failure: %v", err)
		}
		cleanup = false
		if lease.releases != 1 || lease.quarantines != 0 {
			t.Fatalf("no-child proof actions = release %d, quarantine %d", lease.releases, lease.quarantines)
		}
		return
	}
	if proofErr == nil || !strings.Contains(proofErr.Error(), "did not prove process-tree cleanup") {
		t.Fatalf("malformed supervisor input proof = %v; want fail-closed refusal", proofErr)
	}
	if err := invocation.Finish(false); err == nil || !strings.Contains(err.Error(), "cleanup failed; identity quarantined") {
		t.Fatalf("finish malformed supervisor input = %v; want fail-closed quarantine", err)
	}
	cleanup = false
	if lease.releases != 0 || lease.quarantines != 1 {
		t.Fatalf("unproven input actions = release %d, quarantine %d", lease.releases, lease.quarantines)
	}
}

func currentTestCoverageDirectory() string {
	coverageFlag := flag.Lookup("test.gocoverdir")
	if coverageFlag == nil || coverageFlag.Value == nil {
		return ""
	}
	directory := coverageFlag.Value.String()
	if directory == "" {
		return ""
	}
	if absolute, err := filepath.Abs(directory); err == nil {
		return absolute
	}
	return directory
}
