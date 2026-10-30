//go:build linux

package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/sandbox"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == sandbox.ExecCommand {
		if err := sandbox.Exec(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(126)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// writeScript writes a script that the test then runs. A process that a
// parallel test forks while the script is open for writing inherits the
// descriptor until it executes its own program, and running the script
// meanwhile fails with "text file busy". Go forks only while it holds
// syscall.ForkLock exclusively, so holding it shared while the script is
// written keeps every fork out of that window.
func writeScript(t *testing.T, path, script string) {
	t.Helper()
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
}

// writeFakeHelper writes a stand-in for the EdgeWatch executable whose
// sandbox-exec command records its arguments and inherited descriptor in dir
// and then runs body.
func writeFakeHelper(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "edgewatch")
	writeScript(t, path, "#!/bin/sh\nprintf '%s\\n' \"$@\" > "+filepath.Join(dir, "args")+"\n"+body)
	return path
}

func writeFakeScanner(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	writeScript(t, path, "#!/bin/sh\nexit 99\n")
	return path
}

func accessMode(t *testing.T, file *os.File) int {
	t.Helper()
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	return flags & unix.O_ACCMODE
}

func TestConfinedNmapGetsPrivilegedAndAnInheritedXMLFile(t *testing.T) {
	t.Parallel()
	n := New("/usr/bin/nmap")
	policy := sandbox.NewEnforced(unix.CAP_NET_RAW)
	n.SetSandbox(policy)
	args := []string{"-n", "-oX", "-", "-p", "22", "192.0.2.1"}
	cmd := exec.Command(n.Path, args...)
	path, release, err := prepareNmapXMLOutput(cmd, policy, "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	confineNmap(cmd, policy)
	if len(cmd.Args) < 2 || cmd.Args[1] != "--privileged" {
		t.Fatalf("confined Nmap args = %q, want --privileged first", cmd.Args)
	}
	if args[0] != "-n" || len(args) != 6 {
		t.Fatalf("confining changed the scan's own arguments, which the fingerprint uses: %q", args)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil || cmd.SysProcAttr.Credential.Uid != sandbox.UID {
		t.Fatalf("confined Nmap attributes = %+v", cmd.SysProcAttr)
	}
	if !strings.Contains(strings.Join(cmd.Args, " "), "-oX /dev/fd/3") || len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0].Name() != path {
		t.Fatalf("confined XML output args = %q, extra files %v", cmd.Args, cmd.ExtraFiles)
	}
	if accessMode(t, cmd.ExtraFiles[0]) != unix.O_WRONLY {
		t.Fatal("the XML file is not passed write-only")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o602 {
		t.Fatalf("XML file mode = %o, want write-only for the confined process", info.Mode().Perm())
	}
	release()
	if err := cmd.ExtraFiles[0].Close(); err == nil {
		t.Fatal("release left the inherited XML file open")
	}
}

func TestUnconfinedNmapKeepsItsArguments(t *testing.T) {
	t.Parallel()
	n := New("/usr/bin/nmap")
	cmd := exec.Command(n.Path, "-n", "-oX", "-", "192.0.2.1")
	path, release, err := prepareNmapXMLOutput(cmd, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	release()
	confineNmap(cmd, nil)
	if strings.Contains(strings.Join(cmd.Args, " "), "--privileged") || cmd.SysProcAttr != nil {
		t.Fatalf("unconfined Nmap = %q %+v", cmd.Args, cmd.SysProcAttr)
	}
	if cmd.Args[len(cmd.Args)-2] != path || len(cmd.ExtraFiles) != 0 {
		t.Fatalf("unconfined XML output = %q, extra %v", cmd.Args, cmd.ExtraFiles)
	}
}

func TestUnavailableScannerIdentityRefusesNaabuBeforeExecution(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	workDir := filepath.Join(dir, "work")
	if err := os.Mkdir(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "started")
	naabu := filepath.Join(dir, "naabu")
	writeScript(t, naabu, fmt.Sprintf("#!/bin/sh\nprintf ran > %q\n", marker))
	n := NewWithNaabu("missing-nmap", naabu)
	n.workDir = workDir
	n.SetSandbox(sandbox.Detect(sandbox.Options{Mode: sandbox.ModeAuto}))
	results, stderr, err := n.runNaabu(context.Background(), testNaabuOptions(), nil, []string{"192.0.2.1"})
	if err == nil || !strings.Contains(err.Error(), "distinct scanner identity is unavailable") {
		t.Fatalf("Naabu with unavailable identity = results %#v, stderr %q, error %v", results, stderr, err)
	}
	if len(results.ports) != 0 {
		t.Fatalf("unavailable scanner returned results: %#v", results)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Naabu executed without its required identity: %v", err)
	}
	entries, err := os.ReadDir(workDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed launch left invocation input files %v, %v", entries, err)
	}
}

func TestUnavailableScannerIdentityRefusesVersionProbeBeforeExecution(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	path := filepath.Join(dir, "nmap")
	writeScript(t, path, fmt.Sprintf("#!/bin/sh\nprintf ran > %q\n", marker))
	policy := sandbox.Detect(sandbox.Options{Mode: sandbox.ModeAuto})
	if out, err := runScannerVersionProbe(context.Background(), path, policy, "--version"); err == nil {
		t.Fatalf("version probe output %q, want unavailable-identity error", out)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("version probe executed without its required identity: %v", err)
	}
}

func TestModeOffNaabuRunsWithTheCurrentIdentity(t *testing.T) {
	naabu := writeNaabuFixture(t, `printf 'uid=' >&2
id -u >&2
printf '%s\n' '{"ip":"192.0.2.1","port":443,"protocol":"tcp"}'
`)
	n := NewWithNaabu("missing-nmap", naabu)
	n.SetSandbox(sandbox.Detect(sandbox.Options{Mode: sandbox.ModeOff}))
	results, stderr, err := n.runNaabu(context.Background(), testNaabuOptions(), nil, []string{"192.0.2.1"})
	if err != nil {
		t.Fatalf("mode-off Naabu = %v (stderr %q)", err, stderr)
	}
	if !strings.Contains(stderr, fmt.Sprintf("uid=%d", os.Geteuid())) {
		t.Fatalf("mode-off Naabu did not use the current identity %d: %q", os.Geteuid(), stderr)
	}
	if got := results.ports["192.0.2.1"]; len(got) != 1 || got[0] != 443 {
		t.Fatalf("mode-off result = %#v", results)
	}
}

func TestNaabuArgsUseTheInheritedTargetsPath(t *testing.T) {
	t.Parallel()
	args := naabuArgsWithTemplate(testNaabuOptions(), "/dev/fd/3", nil)
	if len(args) < 2 || args[0] != "-list" || args[1] != "/dev/fd/3" {
		t.Fatalf("Naabu args = %q", args)
	}
}

func TestRestrictedNmapStartsThroughSandboxExecWithItsXMLFile(t *testing.T) {
	t.Parallel()
	const helper = "/usr/local/bin/edgewatch"
	nmap := writeFakeScanner(t, "nmap")
	for name, test := range map[string]struct {
		policy     *sandbox.Policy
		privileged bool
		mode       os.FileMode
	}{
		"identity and Landlock": {policy: sandbox.NewEnforced(unix.CAP_NET_RAW).WithLandlock(helper, 6), privileged: true, mode: 0o602},
		// The process runs as the daemon, which owns the file.
		"Landlock only": {policy: (*sandbox.Policy)(nil).WithLandlock(helper, 6), mode: 0o600},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cmd := exec.Command(nmap, "-n", "-oX", "-", "192.0.2.1")
			path, release, err := prepareNmapXMLOutput(cmd, test.policy, "")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(path)
			defer release()
			confineNmap(cmd, test.policy)
			want := []string{helper, sandbox.ExecCommand, "--profile", "scanner", "--files", "1", "--file-size-limit", strconv.Itoa(nmapOutputFileSizeLimit), "--", nmap}
			if test.privileged {
				want = append(want, "--privileged")
			}
			want = append(want, "-n", "-oX", "/dev/fd/3", "192.0.2.1")
			if cmd.Path != helper || !reflect.DeepEqual(cmd.Args, want) {
				t.Fatalf("restricted Nmap = %q, want %q", cmd.Args, want)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != test.mode || accessMode(t, cmd.ExtraFiles[0]) != unix.O_WRONLY {
				t.Fatalf("XML file mode = %o", info.Mode().Perm())
			}
		})
	}
}

func TestRestrictedNmapInvocationSharesTheXMLFileBeforeStarting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// The stand-in writes the XML through the descriptor named after -oX, and
	// refuses to run when it was started before the file was shared.
	helper := writeFakeHelper(t, dir, `[ "$5" = 1 ] || exit 9
while [ "$#" -gt 0 ]; do
  if [ "$1" = -oX ]; then printf '%s' '<nmaprun></nmaprun>' > "$2"; fi
  shift
done
`)
	policy := (*sandbox.Policy)(nil).WithLandlock(helper, 6)
	cmd := exec.CommandContext(context.Background(), writeFakeScanner(t, "nmap"), "-n", "-oX", "-", "192.0.2.1")
	stdout, stderr, err := runNmapInvocation(context.Background(), cmd, policy, "", nil, nil)
	if err != nil {
		t.Fatalf("restricted invocation = %v (stderr %q)", err, stderr)
	}
	if string(stdout) != "<nmaprun></nmaprun>" {
		t.Fatalf("XML = %q", stdout)
	}
	args, err := os.ReadFile(filepath.Join(dir, "args"))
	if err != nil || !strings.HasPrefix(string(args), sandbox.ExecCommand+"\n--profile\nscanner\n--files\n1\n--file-size-limit\n"+strconv.Itoa(nmapOutputFileSizeLimit)+"\n--\n") {
		t.Fatalf("sandbox-exec arguments = %q, %v", args, err)
	}
}

func TestRestrictedNmapFinalSizeCheckCatchesWriterAfterEmptyInitialPoll(t *testing.T) {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || abi < 1 {
		t.Skipf("Landlock is unavailable: %v", errno)
	}
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	policy := (*sandbox.Policy)(nil).WithLandlock(helper, int(abi))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	gateReader, gateWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer gateReader.Close()
	defer gateWriter.Close()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", xmlOutputScript+
		"IFS= read -r _ <&3\n"+
		"head -c 33554432 /dev/zero > \"$out\"\n"+
		"printf 'writer-finished\\n' >&2\n", "sh", "-oX", "-", "192.0.2.1")
	// FD 3 gates the child until the controlled initial poll has completed.
	// prepareNmapXMLOutput adds the XML output as FD 4; both are inherited by
	// this test child through the same Landlock helper path as Nmap.
	cmd.ExtraFiles = append(cmd.ExtraFiles, gateReader)
	released := make(chan error, 1)
	afterInitialPoll := func() {
		_, writeErr := gateWriter.Write([]byte("continue\n"))
		if closeErr := gateWriter.Close(); writeErr == nil {
			writeErr = closeErr
		}
		released <- writeErr
	}
	// A one-hour interval ensures the recurring poll cannot run before this
	// writer exits. The initial poll sees an empty file because the child waits
	// on FD 3 until afterInitialPoll releases it. The bound error must therefore
	// come from the final post-exit size check, independent of scheduler timing.
	_, stderr, err := runNmapInvocationWithProgressPollInterval(ctx, cmd, policy, "", nil, nil, time.Hour, afterInitialPoll)
	select {
	case releaseErr := <-released:
		if releaseErr != nil {
			t.Fatalf("release writer after initial poll: %v", releaseErr)
		}
	default:
		t.Fatal("the child was not released after the initial empty-file poll")
	}
	if !strings.Contains(stderr, "writer-finished") {
		t.Fatalf("the writer did not reach its completion marker; stderr = %q", stderr)
	}
	if err == nil || !strings.Contains(err.Error(), "nmap XML output exceeded 16777216 bytes") {
		t.Fatalf("restricted writer = %v (stderr %q), want stable post-exit XML size error", err, stderr)
	}
	if ctx.Err() != nil {
		t.Fatalf("the writer was canceled before it exited: %v", ctx.Err())
	}
}

func TestRestrictedNaabuReadsTargetsThroughSandboxExec(t *testing.T) {
	t.Parallel()
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || abi < 1 {
		t.Skipf("Landlock is unavailable: %v", errno)
	}
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	n := NewWithNaabu("nmap", "/bin/true")
	n.SetSandbox((*sandbox.Policy)(nil).WithLandlock(helper, int(abi)))
	results, stderr, err := n.runNaabu(context.Background(), testNaabuOptions(), nil, []string{"192.0.2.1"})
	if err != nil {
		t.Fatalf("restricted Naabu = %v (stderr %q)", err, stderr)
	}
	if len(results.ports) != 0 {
		t.Fatalf("results = %#v", results)
	}
}

func TestRestrictedScannerThatIsMissingIsAConfigurationError(t *testing.T) {
	t.Parallel()
	n := NewWithNaabu("nmap", filepath.Join(t.TempDir(), "naabu"))
	n.SetSandbox((*sandbox.Policy)(nil).WithLandlock("/usr/local/bin/edgewatch", 6))
	_, _, err := n.runNaabu(context.Background(), testNaabuOptions(), nil, []string{"192.0.2.1"})
	if !IsConfigurationError(err) {
		t.Fatalf("missing restricted Naabu = %v, want a configuration error", err)
	}
	cmd := exec.Command(filepath.Join(t.TempDir(), "nmap"), "-n", "-oX", "-", "192.0.2.1")
	if _, _, err := runNmapInvocation(context.Background(), cmd, (*sandbox.Policy)(nil).WithLandlock("/usr/local/bin/edgewatch", 6), "", nil, nil); !IsConfigurationError(err) {
		t.Fatalf("missing restricted Nmap = %v, want a configuration error", err)
	}
}
