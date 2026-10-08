//go:build linux

package scanner

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/sandbox"
	"golang.org/x/sys/unix"
)

func TestConfinedNmapGetsPrivilegedAndAnInheritedXMLFile(t *testing.T) {
	t.Parallel()
	n := New("/usr/bin/nmap")
	policy := sandbox.NewEnforced(unix.CAP_NET_RAW)
	n.SetSandbox(policy)
	args := []string{"-n", "-oX", "-", "-p", "22", "192.0.2.1"}
	cmd := exec.Command(n.Path, args...)
	n.confineNmap(cmd)
	if len(cmd.Args) < 2 || cmd.Args[1] != "--privileged" {
		t.Fatalf("confined Nmap args = %q, want --privileged first", cmd.Args)
	}
	if args[0] != "-n" || len(args) != 6 {
		t.Fatalf("confining changed the scan's own arguments, which the fingerprint uses: %q", args)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil || cmd.SysProcAttr.Credential.Uid != sandbox.UID {
		t.Fatalf("confined Nmap attributes = %+v", cmd.SysProcAttr)
	}
	path, release, err := prepareNmapXMLOutput(cmd, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	if !strings.Contains(strings.Join(cmd.Args, " "), "-oX /dev/fd/3") || len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0].Name() != path {
		t.Fatalf("confined XML output args = %q, extra files %v", cmd.Args, cmd.ExtraFiles)
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
	n.confineNmap(cmd)
	if strings.Contains(strings.Join(cmd.Args, " "), "--privileged") || cmd.SysProcAttr != nil {
		t.Fatalf("unconfined Nmap = %q %+v", cmd.Args, cmd.SysProcAttr)
	}
	path, release, err := prepareNmapXMLOutput(cmd, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	release()
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
