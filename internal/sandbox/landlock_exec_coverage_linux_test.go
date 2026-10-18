//go:build linux

package sandbox

import (
	"flag"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const landlockExecCoverageChildEnv = "EDGEWATCH_TEST_LANDLOCK_EXEC_COVERAGE"

// TestLandlockExecCoverageChild exercises setup branches that normally end in
// syscall.Exec. A missing target makes those branches return a controlled
// error, allowing the instrumented test process to flush real counters.
func TestLandlockExecCoverageChild(t *testing.T) {
	mode := os.Getenv(landlockExecCoverageChildEnv)
	if mode == "" {
		return
	}

	args := []string{"--profile", "scanner", "--files", "1", "--liveness-fd", "3"}
	switch mode {
	case "resource-only":
		args = append(args, "--resource-only", "--file-size-limit", "16777216", "--seccomp")
	case "identity-only":
		args = append(args, "--identity-only", "--seccomp")
	default:
		t.Fatalf("unknown Landlock coverage mode %q", mode)
	}
	const missingProgram = "/edgewatch-coverage-program-does-not-exist"
	err := execLandlocked(append(args, "--", missingProgram))
	if err == nil || !strings.Contains(err.Error(), "execute "+missingProgram) {
		t.Fatalf("execLandlocked(%s) error = %v, want controlled exec failure", mode, err)
	}
	if got, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0); err != nil || got != 1 {
		t.Fatalf("execLandlocked(%s) no_new_privs = %d, %v; want 1", mode, got, err)
	}
	if got, err := unix.PrctlRetInt(unix.PR_GET_SECCOMP, 0, 0, 0, 0); err != nil || got != 2 {
		t.Fatalf("execLandlocked(%s) seccomp = %d, %v; want filter mode 2", mode, got, err)
	}
}

func TestLandlockExecSetupFailuresFlushChildCoverage(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	coverageDir := ""
	if coverageFlag := flag.Lookup("test.gocoverdir"); coverageFlag != nil {
		coverageDir = coverageFlag.Value.String()
	}
	for _, mode := range []string{"resource-only", "identity-only"} {
		t.Run(mode, func(t *testing.T) {
			livenessFile := scannerLivenessTestFile(t)
			args := []string{"-test.run=^TestLandlockExecCoverageChild$"}
			if coverageDir != "" {
				args = append(args, "-test.gocoverdir="+coverageDir)
			}
			command := exec.Command(executable, args...)
			command.Env = replaceTestEnv(os.Environ(), landlockExecCoverageChildEnv, mode)
			command.ExtraFiles = []*os.File{livenessFile}
			if coverageDir != "" {
				command.Env = replaceTestEnv(command.Env, "GOCOVERDIR", coverageDir)
			}
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("Landlock helper process: %v; output=%q", err, output)
			}
			if coverageDir == "" {
				return
			}
			entries, err := os.ReadDir(coverageDir)
			if err != nil {
				t.Fatalf("read child coverage directory: %v", err)
			}
			wantPID := strconv.Itoa(command.ProcessState.Pid())
			for _, entry := range entries {
				parts := strings.Split(entry.Name(), ".")
				if len(parts) >= 4 && parts[0] == "covcounters" && parts[2] == wantPID {
					return
				}
			}
			t.Fatalf("Landlock helper process %s emitted no coverage counters in %q", wantPID, coverageDir)
		})
	}
}
