//go:build linux

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func capabilityMask(capabilities ...uintptr) uint64 {
	var mask uint64
	for _, capability := range capabilities {
		mask |= 1 << capability
	}
	return mask
}

// containerEnvironment describes UID 0 in the bundled Compose deployment.
func containerEnvironment(extra ...uintptr) (environment, *[]uintptr) {
	var probed []uintptr
	caps := capabilityMask(append([]uintptr{unix.CAP_NET_RAW, unix.CAP_SETUID, unix.CAP_SETGID, unix.CAP_KILL}, extra...)...)
	return environment{
		euid: 0, effective: caps, permitted: caps, noNewPrivs: true,
		probe: func(ambient []uintptr) error {
			probed = append([]uintptr(nil), ambient...)
			return nil
		},
	}, &probed
}

func TestDetectEnforcesWithTheContainerNetworkCapabilities(t *testing.T) {
	t.Parallel()
	env, probed := containerEnvironment()
	policy := detect("", env)
	if !policy.Enforced() {
		t.Fatalf("policy = %+v, want enforced", policy.Status())
	}
	want := Status{Mode: ModeAuto, State: StateEnforced, UID: UID, GID: GID, ProcessUID: UID, Capabilities: []string{"NET_RAW"}, NoNewPrivileges: true}
	if got := policy.Status(); !reflect.DeepEqual(got, want) {
		t.Fatalf("status = %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(*probed, []uintptr{unix.CAP_NET_RAW}) {
		t.Fatalf("probe ambient = %v, want NET_RAW only", *probed)
	}

	// The SYN override adds NET_ADMIN, which a confined Naabu then keeps.
	synEnv, synProbed := containerEnvironment(unix.CAP_NET_ADMIN)
	syn := detect(ModeRequired, synEnv)
	if got := syn.Status(); got.State != StateEnforced || got.Mode != ModeRequired || !reflect.DeepEqual(got.Capabilities, []string{"NET_RAW", "NET_ADMIN"}) {
		t.Fatalf("SYN status = %+v", got)
	}
	if !reflect.DeepEqual(*synProbed, []uintptr{unix.CAP_NET_RAW, unix.CAP_NET_ADMIN}) {
		t.Fatalf("SYN probe ambient = %v", *synProbed)
	}
	if err := syn.Require(); err != nil {
		t.Fatalf("required and enforced: %v", err)
	}
}

func TestDetectExplainsWhyScannerProcessesStayUnconfined(t *testing.T) {
	t.Parallel()
	notRoot, _ := containerEnvironment()
	notRoot.euid = 1000
	missingControl, _ := containerEnvironment()
	missingControl.effective = capabilityMask(unix.CAP_NET_RAW, unix.CAP_SETUID)
	unreadable, _ := containerEnvironment()
	unreadable.capErr = errors.New("capget failed")
	refused, _ := containerEnvironment()
	refused.probe = func([]uintptr) error { return syscall.EPERM }
	for name, test := range map[string]struct {
		mode   string
		env    environment
		reason string
	}{
		"not root":        {mode: ModeAuto, env: notRoot, reason: "runs as UID 1000 rather than 0"},
		"missing control": {mode: ModeAuto, env: missingControl, reason: "does not grant SETGID, KILL"},
		"unreadable caps": {mode: ModeAuto, env: unreadable, reason: "capabilities could not be read: capget failed"},
		"probe refused":   {mode: ModeRequired, env: refused, reason: "a test process could not start as UID 65532: operation not permitted"},
		"unknown mode":    {mode: "strict", env: refused, reason: `scanner.sandbox "strict" is not auto, required, or off`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			policy := detect(test.mode, test.env)
			status := policy.Status()
			if policy.Enforced() || status.State != StateUnavailable || !strings.Contains(status.Reason, test.reason) || status.ProcessUID != test.env.euid {
				t.Fatalf("status = %+v, want unavailable because %q", status, test.reason)
			}
			err := policy.Require()
			if test.mode == ModeRequired {
				if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), test.reason) {
					t.Fatalf("Require = %v, want ErrUnavailable naming the reason", err)
				}
			} else if err != nil {
				t.Fatalf("Require in %s mode = %v, want nil", test.mode, err)
			}
		})
	}
}

func TestDetectOffNeverProbes(t *testing.T) {
	t.Parallel()
	env, _ := containerEnvironment()
	env.probe = func([]uintptr) error {
		t.Fatal("off mode started a probe process")
		return nil
	}
	policy := detect(" OFF ", env)
	if policy.Enforced() || policy.Status().State != StateDisabled || policy.Require() != nil {
		t.Fatalf("off policy = %+v", policy.Status())
	}
}

func TestNilPolicyStartsProcessesUnconfined(t *testing.T) {
	t.Parallel()
	var policy *Policy
	cmd := exec.Command("/bin/true")
	policy.Confine(cmd)
	if cmd.SysProcAttr != nil {
		t.Fatalf("nil policy changed the process attributes: %+v", cmd.SysProcAttr)
	}
	if policy.Enforced() || policy.Require() != nil || policy.Status().State != StateDisabled {
		t.Fatalf("nil policy status = %+v", policy.Status())
	}
}

func TestConfineKeepsTerminalAttributesAndClearsGroups(t *testing.T) {
	t.Parallel()
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	NewEnforced(unix.CAP_NET_RAW).Confine(cmd)
	attrs := cmd.SysProcAttr
	if !attrs.Setsid || !attrs.Setctty {
		t.Fatalf("Confine dropped terminal attributes: %+v", attrs)
	}
	if attrs.Credential == nil || attrs.Credential.Uid != UID || attrs.Credential.Gid != GID || attrs.Credential.Groups == nil || len(attrs.Credential.Groups) != 0 || attrs.Credential.NoSetGroups {
		t.Fatalf("credential = %+v, want UID/GID %d with no supplementary groups", attrs.Credential, UID)
	}
	if !reflect.DeepEqual(attrs.AmbientCaps, []uintptr{unix.CAP_NET_RAW}) {
		t.Fatalf("ambient capabilities = %v", attrs.AmbientCaps)
	}

	unconfined := exec.Command("/bin/true")
	(&Policy{status: Status{Mode: ModeAuto, State: StateUnavailable}}).Confine(unconfined)
	if unconfined.SysProcAttr != nil {
		t.Fatal("an unavailable sandbox changed the process attributes")
	}
}

func TestInheritFileSharesOnlyTheNeededAccess(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	open := func(name string) *os.File {
		t.Helper()
		file, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		return file
	}
	targets, output := open("targets"), open("output.xml")
	cmd := exec.Command("/bin/true")
	policy := NewEnforced(unix.CAP_NET_RAW)
	targetsPath, err := policy.InheritFile(cmd, targets, Read)
	if err != nil {
		t.Fatal(err)
	}
	outputPath, err := policy.InheritFile(cmd, output, Write)
	if err != nil {
		t.Fatal(err)
	}
	if targetsPath != "/dev/fd/3" || outputPath != "/dev/fd/4" || len(cmd.ExtraFiles) != 2 || cmd.ExtraFiles[0] != targets || cmd.ExtraFiles[1] != output {
		t.Fatalf("paths %q %q, extra files %v", targetsPath, outputPath, cmd.ExtraFiles)
	}
	for file, want := range map[*os.File]os.FileMode{targets: 0o604, output: 0o602} {
		info, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode = %o, want %o", file.Name(), info.Mode().Perm(), want)
		}
	}

	plain := exec.Command("/bin/true")
	other := open("unconfined")
	path, err := (*Policy)(nil).InheritFile(plain, other, Write)
	if err != nil || path != other.Name() || len(plain.ExtraFiles) != 0 {
		t.Fatalf("unconfined InheritFile = %q, %v, extra %v", path, err, plain.ExtraFiles)
	}
	if info, _ := other.Stat(); info.Mode().Perm() != 0o600 {
		t.Fatalf("unconfined file mode changed to %o", info.Mode().Perm())
	}

	closed := open("closed")
	_ = closed.Close()
	if _, err := policy.InheritFile(exec.Command("/bin/true"), closed, Read); err == nil {
		t.Fatal("sharing a closed file succeeded")
	}
}

func TestReadNoNewPrivs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if !readNoNewPrivs(write("set", "Name:\tedgewatch\nNoNewPrivs:\t1\nSeccomp:\t2\n")) {
		t.Fatal("NoNewPrivs 1 was not read as set")
	}
	if readNoNewPrivs(write("unset", "NoNewPrivs:\t0\n")) || readNoNewPrivs(write("absent", "Name:\tedgewatch\n")) || readNoNewPrivs(filepath.Join(dir, "missing")) {
		t.Fatal("an unset, absent, or unreadable NoNewPrivs was read as set")
	}
}

func TestValidModeAndCapabilityNames(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"", "auto", "REQUIRED", " off "} {
		if !ValidMode(mode) {
			t.Errorf("ValidMode(%q) = false", mode)
		}
	}
	if ValidMode("strict") {
		t.Error("ValidMode accepted strict")
	}
	if got := capabilityName(unix.CAP_SYS_ADMIN); got != "CAP_21" {
		t.Errorf("unknown capability name = %q", got)
	}
}

func TestProbeRunsTheBinaryConfined(t *testing.T) {
	t.Parallel()
	// A test binary never starts itself as the probe, and an unprivileged
	// process is reported unavailable before any probe.
	if err := probeProcess(nil); err == nil || !strings.Contains(err.Error(), "test binary") {
		t.Fatalf("probe from a test binary = %v, want it skipped", err)
	}
	policy := Detect(ModeAuto)
	if policy.Enforced() || policy.Status().State != StateUnavailable {
		t.Fatalf("unprivileged Detect = %+v, want unavailable", policy.Status())
	}
}
