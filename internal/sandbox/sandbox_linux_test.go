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

// containerEnvironment describes UID 0 in the bundled Compose deployment on
// a kernel with Landlock ABI 6.
func containerEnvironment(extra ...uintptr) (environment, *[]uintptr) {
	var probed []uintptr
	caps := capabilityMask(append([]uintptr{unix.CAP_NET_RAW, unix.CAP_SETUID, unix.CAP_SETGID, unix.CAP_KILL}, extra...)...)
	return environment{
		euid: 0, effective: caps, permitted: caps, noNewPrivs: true,
		landlockABI: 6, executable: "/usr/local/bin/edgewatch",
		run: func(policy *Policy, _, _ []string) error {
			if !policy.Restricted() {
				probed = append([]uintptr(nil), policy.ambient...)
			}
			return nil
		},
	}, &probed
}

// failing runs succeed except where policy confines as fail selects, which
// return err.
func failing(fail func(*Policy) bool, err error) func(*Policy, []string, []string) error {
	return func(policy *Policy, _, _ []string) error {
		if fail(policy) {
			return err
		}
		return nil
	}
}

func identityOnly(policy *Policy) bool { return !policy.Restricted() }

func withLandlock(policy *Policy) bool { return policy.Restricted() }

var enforcedLandlock = LandlockStatus{Mode: ModeAuto, State: StateEnforced, ABI: 6}

func TestDetectEnforcesWithTheContainerNetworkCapabilities(t *testing.T) {
	t.Parallel()
	env, probed := containerEnvironment()
	policy := detect(Options{}, env)
	if !policy.Enforced() || !policy.Restricted() {
		t.Fatalf("policy = %+v, want enforced", policy.Status())
	}
	want := Status{Mode: ModeAuto, State: StateEnforced, UID: UID, GID: GID, ProcessUID: UID, Capabilities: []string{"NET_RAW"}, NoNewPrivileges: true, Landlock: enforcedLandlock, Seccomp: SeccompStatus{State: StateEnforced}, Limits: &ProcessLimits{OOMScoreAdj: ScannerOOMScoreAdj, MaxOpenFiles: ScannerMaxOpenFiles}}
	if got := policy.Status(); !reflect.DeepEqual(got, want) {
		t.Fatalf("status = %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(*probed, []uintptr{unix.CAP_NET_RAW}) {
		t.Fatalf("probe ambient = %v, want NET_RAW only", *probed)
	}

	// The SYN override adds NET_ADMIN, which a confined Naabu then keeps.
	synEnv, synProbed := containerEnvironment(unix.CAP_NET_ADMIN)
	syn := detect(Options{Mode: ModeRequired, Landlock: ModeRequired}, synEnv)
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
	refused.run = failing(identityOnly, syscall.EPERM)
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
			policy := detect(Options{Mode: test.mode}, test.env)
			status := policy.Status()
			if policy.Enforced() || status.State != StateUnavailable || !strings.Contains(status.Reason, test.reason) || status.ProcessUID != test.env.euid {
				t.Fatalf("status = %+v, want unavailable because %q", status, test.reason)
			}
			// Landlock restricts the files of a process whatever its
			// identity, so it still applies.
			if !policy.Restricted() || !policy.InheritsFiles() || status.Landlock != enforcedLandlock {
				t.Fatalf("Landlock = %+v, want it to restrict the unconfined identity", status.Landlock)
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
	env.run = func(*Policy, []string, []string) error {
		t.Fatal("off mode started a probe process")
		return nil
	}
	policy := detect(Options{Mode: " OFF ", Landlock: ModeAuto, Probes: []Probe{{Args: []string{"/usr/bin/nmap", "--version"}}}}, env)
	status := policy.Status()
	if policy.Enforced() || policy.Restricted() || status.State != StateDisabled || policy.Require() != nil {
		t.Fatalf("off policy = %+v", status)
	}
	// scanner.sandbox off turns off Landlock too.
	if status.Landlock.State != StateDisabled || status.Landlock.Reason != "scanner.sandbox is off" {
		t.Fatalf("Landlock with the sandbox off = %+v", status.Landlock)
	}
}

func TestDetectProbesEachScannerWithLandlock(t *testing.T) {
	t.Parallel()
	env, _ := containerEnvironment()
	var probed [][]string
	var identity []string
	env.run = func(policy *Policy, command, _ []string) error {
		if !policy.Restricted() {
			identity = command
			return nil
		}
		if !policy.Enforced() || policy.helper != "/usr/local/bin/edgewatch" {
			t.Errorf("probe policy = %+v, want the scanner policy", policy.Status())
		}
		probed = append(probed, command)
		return nil
	}
	nmap, naabu := []string{"/usr/bin/nmap", "--version"}, []string{"/usr/local/bin/naabu", "-version"}
	policy := detect(Options{Probes: []Probe{{Args: nmap}, {}, {Args: naabu}}}, env)
	if !policy.Restricted() || !reflect.DeepEqual(probed, [][]string{nmap, naabu}) {
		t.Fatalf("probed %q, policy %+v", probed, policy.Status())
	}
	// Without an identity probe, the EdgeWatch version command confirms the
	// identity change.
	if !reflect.DeepEqual(identity, []string{"/usr/local/bin/edgewatch", "version"}) {
		t.Fatalf("identity probe = %q", identity)
	}
}

func TestDetectAddsTheSeccompFilterWhenItWorks(t *testing.T) {
	t.Parallel()
	nmap := []Probe{{Args: []string{"/usr/bin/nmap", "--version"}}}
	env, _ := containerEnvironment()
	var filtered []bool
	env.run = func(policy *Policy, command, _ []string) error {
		if policy.Restricted() {
			filtered = append(filtered, policy.seccomp)
		}
		return nil
	}
	policy := detect(Options{Probes: nmap}, env)
	if !policy.seccomp || policy.Status().Seccomp.State != StateEnforced || !reflect.DeepEqual(filtered, []bool{true}) {
		t.Fatalf("seccomp = %v %+v, probes with the filter %v", policy.seccomp, policy.Status().Seccomp, filtered)
	}

	// A scanner that fails only with the filter keeps Landlock.
	env.run = failing(func(policy *Policy) bool { return policy.seccomp }, errors.New("signal: bad system call"))
	policy = detect(Options{Probes: nmap}, env)
	status := policy.Status()
	if policy.seccomp || !policy.Restricted() || status.Landlock.State != StateEnforced || status.Seccomp.State != StateUnavailable ||
		status.Seccomp.Reason != "nmap could not start with the seccomp filter: signal: bad system call" {
		t.Fatalf("status without the filter = %+v", status)
	}

	// A kernel without the filter's actions keeps Landlock.
	env, _ = containerEnvironment()
	env.seccompErr = unix.ENOSYS
	if got := detect(Options{Probes: nmap}, env).Status(); got.Landlock.State != StateEnforced || got.Seccomp.State != StateUnavailable || !strings.Contains(got.Seccomp.Reason, "does not provide seccomp filters") {
		t.Fatalf("status without seccomp support = %+v", got)
	}

	// Without Landlock, nothing installs the filter.
	env.landlockErr = unix.ENOSYS
	if got := detect(Options{Probes: nmap}, env).Status().Seccomp; got.State != StateUnavailable || got.Reason != "the seccomp filter applies only with Landlock" {
		t.Fatalf("seccomp without Landlock = %+v", got)
	}
	if got := detect(Options{Landlock: ModeOff}, env).Status().Seccomp; got.State != StateDisabled {
		t.Fatalf("seccomp with Landlock off = %+v", got)
	}
	if got := detect(Options{Mode: ModeOff}, env).Status().Seccomp; got.State != StateDisabled {
		t.Fatalf("seccomp with the sandbox off = %+v", got)
	}

	// The filter reaches sandbox-exec as an argument.
	cmd := exec.Command("/bin/true")
	NewEnforced().WithLandlock("/usr/local/bin/edgewatch", 6).WithSeccomp().Confine(cmd)
	if want := []string{"/usr/local/bin/edgewatch", ExecCommand, "--profile", "scanner", "--files", "0", "--seccomp", "--", "/bin/true"}; !reflect.DeepEqual(cmd.Args, want) {
		t.Fatalf("filtered command = %q, want %q", cmd.Args, want)
	}
}

func TestDetectConfinesTheNotificationProcessWithoutCapabilities(t *testing.T) {
	t.Parallel()
	env, _ := containerEnvironment(unix.CAP_NET_ADMIN)
	type run struct {
		restricted, enforced bool
		uid                  int
		ambient              []uintptr
		command, environment []string
	}
	var runs []run
	env.run = func(policy *Policy, command, environment []string) error {
		runs = append(runs, run{policy.Restricted(), policy.Enforced(), policy.Status().UID, policy.ambient, command, environment})
		return nil
	}
	check := Probe{Name: "the notification process", Self: true, Args: []string{"notify-check"}, Env: []string{"SSL_CERT_FILE=/etc/ca.pem"}}
	policy := detect(Options{Profile: Notifier, Mode: ModeRequired, Landlock: ModeAuto, IdentityProbe: check, Probes: []Probe{check}}, env)
	status := policy.Status()
	if !policy.Enforced() || !policy.Restricted() || status.UID != NotifierUID || status.GID != NotifierGID || len(status.Capabilities) != 0 || status.Landlock.State != StateEnforced || policy.Require() != nil {
		t.Fatalf("notification policy = %+v", status)
	}
	want := []string{"/usr/local/bin/edgewatch", "notify-check"}
	if len(runs) != 2 || runs[0].restricted || !runs[1].restricted || !runs[0].enforced || runs[0].uid != NotifierUID || len(runs[0].ambient) != 0 ||
		!reflect.DeepEqual(runs[0].command, want) || !reflect.DeepEqual(runs[1].command, want) || !reflect.DeepEqual(runs[1].environment, check.Env) {
		t.Fatalf("notification probes = %+v", runs)
	}

	// A check that fails as the notification identity names the setting.
	env.run = failing(identityOnly, errors.New("exit status 1: read SSL_CERT_FILE: permission denied"))
	refused := detect(Options{Profile: Notifier, Mode: ModeRequired, IdentityProbe: check}, env)
	err := refused.Require()
	if refused.Enforced() || !strings.Contains(refused.Status().Reason, "a test notification process could not start as UID 65531: exit status 1: read SSL_CERT_FILE: permission denied") ||
		!errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "set notifications.sandbox to auto to start the notification process unconfined") {
		t.Fatalf("refused notification policy = %+v, %v", refused.Status(), err)
	}
	// Landlock still restricts the process; its probe failing is reported
	// by name.
	env.run = failing(withLandlock, errors.New("exit status 1"))
	if got := detect(Options{Profile: Notifier, Probes: []Probe{check}}, env).Status().Landlock; got.State != StateUnavailable || got.Reason != "the notification process could not start with Landlock: exit status 1" {
		t.Fatalf("notification Landlock = %+v", got)
	}
	off := detect(Options{Profile: Notifier, Mode: ModeOff}, env).Status()
	if off.State != StateDisabled || off.Reason != "notifications.sandbox is off" || off.Landlock.Reason != "notifications.sandbox is off" {
		t.Fatalf("notification sandbox off = %+v", off)
	}
}

func TestDetectExplainsWhyLandlockIsUnavailable(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		mode   string
		change func(*environment)
		state  string
		reason string
		// noIdentity is set when the cause also keeps the identity
		// sandbox from its probe.
		noIdentity bool
	}{
		"no syscall":  {change: func(env *environment) { env.landlockErr = unix.ENOSYS }, state: StateUnavailable, reason: "the kernel does not provide Landlock, or the container's seccomp profile blocks it"},
		"not enabled": {change: func(env *environment) { env.landlockErr = unix.EOPNOTSUPP }, state: StateUnavailable, reason: "add landlock to the lsm= boot parameter"},
		"other error": {change: func(env *environment) { env.landlockErr = unix.EINVAL }, state: StateUnavailable, reason: "Landlock could not be detected: invalid argument"},
		"executable":  {change: func(env *environment) { env.executableErr = errors.New("no /proc") }, state: StateUnavailable, reason: "the EdgeWatch executable cannot start scanner processes with Landlock: no /proc", noIdentity: true},
		"probe failed": {mode: ModeRequired, change: func(env *environment) {
			env.run = failing(withLandlock, errors.New("exit status 1: denied"))
		}, state: StateUnavailable, reason: "nmap could not start with Landlock: exit status 1: denied"},
		"unknown mode": {mode: "strict", state: StateUnavailable, reason: `scanner.landlock "strict" is not auto, required, or off`},
		"off": {mode: ModeOff, change: func(env *environment) {
			env.run = failing(withLandlock, errors.New("off mode started a Landlock probe"))
		}, state: StateDisabled, reason: "scanner.landlock is off"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env, _ := containerEnvironment()
			if test.change != nil {
				test.change(&env)
			}
			policy := detect(Options{Landlock: test.mode, Probes: []Probe{{Args: []string{"/usr/bin/nmap", "--version"}}}}, env)
			status := policy.Status()
			if policy.Restricted() || status.Landlock.State != test.state || !strings.Contains(status.Landlock.Reason, test.reason) {
				t.Fatalf("Landlock = %+v, want %s because %q", status.Landlock, test.state, test.reason)
			}
			// The identity sandbox does not depend on Landlock.
			if policy.Enforced() == test.noIdentity || (status.State == StateEnforced) == test.noIdentity {
				t.Fatalf("status = %+v, want the identity sandbox enforced: %v", status, !test.noIdentity)
			}
			err := policy.Require()
			if test.mode == ModeRequired {
				if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), test.reason) || !strings.Contains(err.Error(), "set scanner.landlock to auto") {
					t.Fatalf("Require = %v, want ErrUnavailable naming the reason", err)
				}
			} else if err != nil {
				t.Fatalf("Require in %q mode = %v, want nil", test.mode, err)
			}
		})
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
	if policy.Enforced() || policy.Restricted() || policy.InheritsFiles() || policy.Require() != nil || policy.Status().State != StateDisabled || policy.Status().Landlock.State != StateDisabled {
		t.Fatalf("nil policy status = %+v", policy.Status())
	}
}

func TestConfineStartsTheProgramThroughSandboxExec(t *testing.T) {
	t.Parallel()
	const helper = "/usr/local/bin/edgewatch"
	inherited, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inherited.Close() })
	cmd := exec.Command("/bin/true", "-x", "--", "value")
	cmd.ExtraFiles = []*os.File{inherited}
	policy := NewEnforced(unix.CAP_NET_RAW).WithLandlock(helper, 6)
	policy.Confine(cmd)
	want := []string{helper, ExecCommand, "--profile", "scanner", "--files", "1", "--", "/bin/true", "-x", "--", "value"}
	if cmd.Path != helper || !reflect.DeepEqual(cmd.Args, want) {
		t.Fatalf("command = %q %q, want %q", cmd.Path, cmd.Args, want)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil || cmd.SysProcAttr.Credential.Uid != UID {
		t.Fatalf("a restricted process lost its confined identity: %+v", cmd.SysProcAttr)
	}
	if status := policy.Status(); !status.NoNewPrivileges || status.Landlock.ABI != 6 || !reflect.DeepEqual(status.Capabilities, []string{"NET_RAW"}) {
		t.Fatalf("restricted status = %+v", status)
	}

	// The notification process runs as its own identity without
	// capabilities, restricted with its own Landlock paths.
	notifier := exec.Command("/bin/true", "notify-send")
	NewEnforcedFor(Notifier).WithLandlock(helper, 6).Confine(notifier)
	if notifier.SysProcAttr == nil || notifier.SysProcAttr.Credential == nil || notifier.SysProcAttr.Credential.Uid != NotifierUID || notifier.SysProcAttr.Credential.Gid != NotifierGID || len(notifier.SysProcAttr.AmbientCaps) != 0 {
		t.Fatalf("notification process attributes = %+v", notifier.SysProcAttr)
	}
	if want := []string{helper, ExecCommand, "--profile", "notifier", "--files", "0", "--", "/bin/true", "notify-send"}; !reflect.DeepEqual(notifier.Args, want) {
		t.Fatalf("notification process = %q, want %q", notifier.Args, want)
	}

	// A scanner that keeps temporary files, Naabu, may create them below
	// /tmp; the notification process never may.
	naabu := exec.Command("/bin/true", "-list", "/dev/fd/3")
	NewEnforced(unix.CAP_NET_RAW).WithLandlock(helper, 6).WithSeccomp().ConfineWithTemporaryFiles(naabu)
	if want := []string{helper, ExecCommand, "--profile", "scanner", "--files", "0", "--tmp", "--seccomp", "--", "/bin/true", "-list", "/dev/fd/3"}; !reflect.DeepEqual(naabu.Args, want) {
		t.Fatalf("scanner with temporary files = %q, want %q", naabu.Args, want)
	}
	notifierTemporary := exec.Command("/bin/true", "notify-send")
	NewEnforcedFor(Notifier).WithLandlock(helper, 6).ConfineWithTemporaryFiles(notifierTemporary)
	if want := []string{helper, ExecCommand, "--profile", "notifier", "--files", "0", "--", "/bin/true", "notify-send"}; !reflect.DeepEqual(notifierTemporary.Args, want) {
		t.Fatalf("notification process with temporary files = %q, want %q", notifierTemporary.Args, want)
	}
	identityOnly := exec.Command("/bin/true")
	NewEnforced(unix.CAP_NET_RAW).ConfineWithTemporaryFiles(identityOnly)
	if identityOnly.Path != "/bin/true" || identityOnly.SysProcAttr == nil || identityOnly.SysProcAttr.Credential.Uid != UID {
		t.Fatalf("identity-only scanner with temporary files = %q %+v", identityOnly.Args, identityOnly.SysProcAttr)
	}

	// Without the confined identity, Landlock alone restricts the process.
	alone := exec.Command("/bin/true")
	(*Policy)(nil).WithLandlock(helper, 6).Confine(alone)
	if alone.Path != helper || alone.SysProcAttr != nil {
		t.Fatalf("Landlock-only command = %q %+v", alone.Args, alone.SysProcAttr)
	}

	// A missing program fails the start with its own error and never
	// starts unrestricted.
	missing := exec.Command(filepath.Join(t.TempDir(), "nmap"))
	policy.Confine(missing)
	if missing.Path == helper || missing.Err == nil || !errors.Is(missing.Start(), os.ErrNotExist) {
		t.Fatalf("missing program = %q, err %v", missing.Args, missing.Err)
	}
	failed := exec.Command("/bin/true")
	failed.Err = errors.New("lookup failed")
	policy.Confine(failed)
	if failed.Path == helper {
		t.Fatal("a command that cannot start was wrapped")
	}
}

func TestLandlockReportsTheScannerLimits(t *testing.T) {
	t.Parallel()
	want := ProcessLimits{OOMScoreAdj: ScannerOOMScoreAdj, MaxOpenFiles: ScannerMaxOpenFiles}
	for name, policy := range map[string]*Policy{
		"identity and Landlock": NewEnforced(unix.CAP_NET_RAW).WithLandlock("/usr/local/bin/edgewatch", 6),
		"Landlock only":         (*Policy)(nil).WithLandlock("/usr/local/bin/edgewatch", 6),
		"with seccomp":          NewEnforced().WithLandlock("/usr/local/bin/edgewatch", 6).WithSeccomp(),
	} {
		status := policy.Status()
		if status.Limits == nil || *status.Limits != want {
			t.Fatalf("%s: limits = %+v, want %+v", name, status.Limits, want)
		}
		// The status is a copy.
		status.Limits.OOMScoreAdj = 0
		if policy.Status().Limits.OOMScoreAdj != ScannerOOMScoreAdj {
			t.Fatalf("%s: changing a status changed the policy", name)
		}
	}
	// Without Landlock nothing sets them, and the notification process keeps
	// its own.
	for name, policy := range map[string]*Policy{
		"identity only": NewEnforced(unix.CAP_NET_RAW),
		"notifier":      NewEnforcedFor(Notifier).WithLandlock("/usr/local/bin/edgewatch", 6),
		"nil":           nil,
	} {
		if limits := policy.Status().Limits; limits != nil {
			t.Fatalf("%s: limits = %+v, want none", name, limits)
		}
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

	// Landlock alone passes the descriptor and leaves the file's mode: the
	// process runs as the file's owner.
	restricted := exec.Command("/bin/true")
	own := open("landlock")
	path, err = (*Policy)(nil).WithLandlock("/usr/local/bin/edgewatch", 6).InheritFile(restricted, own, Write)
	if err != nil || path != "/dev/fd/3" || len(restricted.ExtraFiles) != 1 {
		t.Fatalf("Landlock-only InheritFile = %q, %v, extra %v", path, err, restricted.ExtraFiles)
	}
	if info, _ := own.Stat(); info.Mode().Perm() != 0o600 {
		t.Fatalf("Landlock-only file mode changed to %o", info.Mode().Perm())
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
	if err := systemEnvironment().runProbe(nil, Probe{Self: true, Args: []string{"version"}}); err == nil || !strings.Contains(err.Error(), "test binary") {
		t.Fatalf("probe from a test binary = %v, want it skipped", err)
	}
	policy := Detect(Options{Mode: ModeAuto})
	if policy.Enforced() || policy.Status().State != StateUnavailable {
		t.Fatalf("unprivileged Detect = %+v, want unavailable", policy.Status())
	}
	// Nor does a test binary start scanner processes through sandbox-exec.
	if policy.Restricted() || !strings.Contains(policy.Status().Landlock.Reason, "test binary") {
		t.Fatalf("Detect from a test binary = %+v, want Landlock unavailable", policy.Status().Landlock)
	}
}

// TestDetectWithoutThePlatformHooks covers the platforms that install no
// hooks. It replaces package hooks, so it must not run in parallel.
func TestDetectWithoutThePlatformHooks(t *testing.T) {
	detect, confine, name, restrict := detectPlatform, confineProcess, nameCapability, execRestricted
	t.Cleanup(func() {
		detectPlatform, confineProcess, nameCapability, execRestricted = detect, confine, name, restrict
	})
	detectPlatform, confineProcess, nameCapability, execRestricted = nil, nil, nil, nil

	if got := Detect(Options{}); got.Enforced() || got.Status().State != StateUnavailable || got.Status().Reason != "the sandbox requires Linux" || got.Status().ProcessUID != os.Geteuid() || got.Status().Landlock.Reason != "Landlock requires Linux" {
		t.Fatalf("auto without hooks = %+v", got.Status())
	}
	if got := Detect(Options{Mode: "off"}).Status(); got.State != StateDisabled || got.Reason != "scanner.sandbox is off" || got.Landlock.State != StateDisabled {
		t.Fatalf("off without hooks = %+v", got)
	}
	if got := Detect(Options{Profile: Notifier, Mode: "off"}).Status(); got.Reason != "notifications.sandbox is off" {
		t.Fatalf("notification sandbox off without hooks = %+v", got)
	}
	if got := Detect(Options{Landlock: "off"}).Status(); got.State != StateUnavailable || got.Landlock.State != StateDisabled || got.Landlock.Reason != "scanner.landlock is off" {
		t.Fatalf("Landlock off without hooks = %+v", got)
	}
	if err := Detect(Options{Mode: ModeRequired}).Require(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("required without hooks = %v", err)
	}
	if err := Detect(Options{Landlock: ModeRequired}).Require(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("required Landlock without hooks = %v", err)
	}
	if err := Exec([]string{"--profile", "scanner", "--files", "0", "--", "/bin/true"}); err == nil || !strings.Contains(err.Error(), "requires Linux") {
		t.Fatalf("Exec without hooks = %v", err)
	}
	cmd := exec.Command("/bin/true")
	NewEnforced(unix.CAP_NET_RAW).Confine(cmd)
	if cmd.SysProcAttr != nil {
		t.Fatalf("Confine without hooks changed the command: %+v", cmd.SysProcAttr)
	}
	if got := capabilityName(unix.CAP_NET_RAW); got != "CAP_13" {
		t.Fatalf("capability name without hooks = %q", got)
	}
}
