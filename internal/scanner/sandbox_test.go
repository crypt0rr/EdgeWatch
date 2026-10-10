//go:build linux

package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/sandbox"
	"golang.org/x/sys/unix"
)

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

func TestConfinedNaabuReadsTargetsThroughItsDescriptor(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("as UID 0 the confined start succeeds; the container matrix covers it")
	}
	n := NewWithNaabu("nmap", "/bin/true")
	n.SetSandbox(sandbox.NewEnforced(unix.CAP_NET_RAW))
	// An unprivileged test process cannot change identity, so the confined
	// start is refused after the targets were shared, never run unconfined.
	_, _, err := n.runNaabu(context.Background(), testNaabuOptions(), nil, []string{"192.0.2.1"}, true)
	if err == nil || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("confined Naabu start = %v, want the identity change refused", err)
	}
}

func TestNaabuArgsUseTheInheritedTargetsPath(t *testing.T) {
	t.Parallel()
	args := naabuArgsWithTemplate(testNaabuOptions(), "/dev/fd/3", true, nil)
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
			want := []string{helper, sandbox.ExecCommand, "--profile", "scanner", "--files", "1", "--", nmap}
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
	if err != nil || !strings.HasPrefix(string(args), sandbox.ExecCommand+"\n--profile\nscanner\n--files\n1\n--\n") {
		t.Fatalf("sandbox-exec arguments = %q, %v", args, err)
	}
}

func TestRestrictedNaabuReadsTargetsThroughSandboxExec(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	helper := writeFakeHelper(t, dir, "cat /dev/fd/3 > "+filepath.Join(dir, "targets")+"\nprintf '%s\\n' '{\"ip\":\"192.0.2.1\",\"port\":443,\"protocol\":\"tcp\"}'\n")
	naabu := writeFakeScanner(t, "naabu")
	n := NewWithNaabu("nmap", naabu)
	n.SetSandbox((*sandbox.Policy)(nil).WithLandlock(helper, 6))
	results, stderr, err := n.runNaabu(context.Background(), testNaabuOptions(), nil, []string{"192.0.2.1"}, true)
	if err != nil {
		t.Fatalf("restricted Naabu = %v (stderr %q)", err, stderr)
	}
	if len(results.ports["192.0.2.1"]) != 1 {
		t.Fatalf("results = %#v", results)
	}
	args, err := os.ReadFile(filepath.Join(dir, "args"))
	if err != nil || !strings.HasPrefix(string(args), sandbox.ExecCommand+"\n--profile\nscanner\n--files\n1\n--tmp\n--\n"+naabu+"\n-list\n/dev/fd/3\n") {
		t.Fatalf("sandbox-exec arguments = %q, %v", args, err)
	}
	if targets, err := os.ReadFile(filepath.Join(dir, "targets")); err != nil || string(targets) != "192.0.2.1\n" {
		t.Fatalf("inherited targets = %q, %v", targets, err)
	}
}

func TestRestrictedScannerThatIsMissingIsAConfigurationError(t *testing.T) {
	t.Parallel()
	n := NewWithNaabu("nmap", filepath.Join(t.TempDir(), "naabu"))
	n.SetSandbox((*sandbox.Policy)(nil).WithLandlock("/usr/local/bin/edgewatch", 6))
	_, _, err := n.runNaabu(context.Background(), testNaabuOptions(), nil, []string{"192.0.2.1"}, true)
	if !IsConfigurationError(err) {
		t.Fatalf("missing restricted Naabu = %v, want a configuration error", err)
	}
	cmd := exec.Command(filepath.Join(t.TempDir(), "nmap"), "-n", "-oX", "-", "192.0.2.1")
	if _, _, err := runNmapInvocation(context.Background(), cmd, (*sandbox.Policy)(nil).WithLandlock("/usr/local/bin/edgewatch", 6), "", nil, nil); !IsConfigurationError(err) {
		t.Fatalf("missing restricted Nmap = %v, want a configuration error", err)
	}
}
