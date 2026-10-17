//go:build linux

package sandbox

import (
	"context"
	"encoding/json"
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
			if !policy.Restricted() && policy.identityOnlyHelper == "" {
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

func identityOnly(policy *Policy) bool {
	return !policy.Restricted() && policy.identityOnlyHelper == ""
}

func withLandlock(policy *Policy) bool { return policy.Restricted() }

var enforcedLandlock = LandlockStatus{Mode: ModeAuto, State: StateEnforced, ABI: 6}

func TestDetectEnforcesWithTheContainerNetworkCapabilities(t *testing.T) {
	t.Parallel()
	env, probed := containerEnvironment()
	policy := detect(Options{}, env)
	if !policy.Enforced() || !policy.Restricted() {
		t.Fatalf("policy = %+v, want enforced", policy.Status())
	}
	want := Status{Mode: ModeAuto, State: StateEnforced, IdentityPool: scannerIdentityPoolStatus(StateEnforced, ""), Capabilities: []string{"NET_RAW"}, NoNewPrivileges: true, Landlock: enforcedLandlock, Seccomp: SeccompStatus{State: StateEnforced}, Limits: &ProcessLimits{OOMScoreAdj: ScannerOOMScoreAdj, MaxOpenFiles: ScannerMaxOpenFiles}}
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

func TestScannerStatusJSONReportsPoolWithoutAStableInvocationUID(t *testing.T) {
	t.Parallel()
	env, _ := containerEnvironment()
	status := detect(Options{}, env).Status()
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"uid", "gid", "process_uid"} {
		if _, ok := fields[key]; ok {
			t.Errorf("scanner status exposed a stable %s: %s", key, encoded)
		}
	}
	var pool ScannerIdentityPoolStatus
	if err := json.Unmarshal(fields["identity_pool"], &pool); err != nil {
		t.Fatalf("identity_pool = %s: %v", fields["identity_pool"], err)
	}
	if pool.State != StateEnforced || pool.Strategy == "" || pool.UIDStart != ScannerIdentityPoolUIDStart || pool.UIDEnd != ScannerIdentityPoolUIDEnd || pool.MaxParallel != ScannerIdentityPoolCapacity {
		t.Fatalf("identity_pool = %+v", pool)
	}
	if status.Seccomp.State != StateEnforced {
		t.Fatalf("seccomp = %+v, want enforced independently of Landlock", status.Seccomp)
	}

	// Explicit Off is the only scanner mode that reports the daemon's stable
	// process UID and disables the pool and seccomp boundary.
	off := detect(Options{Mode: ModeOff}, env).Status()
	if off.ProcessUID == nil || *off.ProcessUID != 0 || off.IdentityPool == nil || off.IdentityPool.State != StateDisabled || off.Seccomp.State != StateDisabled {
		t.Fatalf("off scanner status = %+v", off)
	}
}

func TestDetectReportsActionableScannerIdentityPoolReasons(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		change      func(*environment)
		mode        string
		want        string
		wantSeccomp string
		forbid      []string
	}{
		"missing control capabilities": {
			change: func(env *environment) {
				env.effective &^= capabilityMask(unix.CAP_SETUID, unix.CAP_SETGID, unix.CAP_KILL)
			},
			want:        "SETUID, SETGID, KILL",
			wantSeccomp: StateEnforced,
		},
		"partially mapped pool": {
			change: func(env *environment) {
				env.identityRangeErr = scannerIdentityUnmappedError{id: ScannerIdentityPoolUIDStart}
			},
			want:        "60000 is not mapped",
			wantSeccomp: StateEnforced,
		},
		"unverifiable map does not expose its error": {
			change:      func(env *environment) { env.identityRangeErr = errors.New("read /private/uid_map: secret-token") },
			want:        "check the runtime's UID/GID mappings",
			wantSeccomp: StateEnforced,
			forbid:      []string{"/private", "secret-token"},
		},
		"non-root daemon": {
			change:      func(env *environment) { env.euid = 1000 },
			want:        "EdgeWatch runs as UID 1000",
			wantSeccomp: StateEnforced,
		},
		"invalid daemon UID is sanitized": {
			change:      func(env *environment) { env.euid = -1 },
			want:        "scanner identity isolation requires EdgeWatch to run as UID 0",
			wantSeccomp: StateEnforced,
			forbid:      []string{"UID -1"},
		},
		"invalid scanner mode": {
			mode:        "unexpected",
			want:        "scanner.sandbox must be auto, required, or off",
			wantSeccomp: StateEnforced,
		},
		"capability read failure is sanitized": {
			change: func(env *environment) {
				env.capErr = errors.New("read /private/capabilities: secret-token")
			},
			want:        "the daemon's capabilities could not be verified",
			wantSeccomp: StateEnforced,
			forbid:      []string{"/private", "secret-token"},
		},
		"pre-v3 allocator refuses unsafe namespace transition": {
			change: func(env *environment) {
				env.run = failing(func(*Policy) bool { return true }, errors.New("scanner identity allocator: PID namespace changed with unsafe or occupied scope"))
			},
			want:        "PID namespace change",
			wantSeccomp: StateUnavailable,
		},
		"v3 allocator waits for exclusive private-scope proof": {
			change: func(env *environment) {
				env.run = failing(func(*Policy) bool { return true }, errors.New("scanner identity allocator: PID namespace changed without exclusive private-scope proof"))
			},
			want:        "stop all other EdgeWatch processes and containers using the data volume",
			wantSeccomp: StateUnavailable,
			forbid:      []string{"host reboot", "/private"},
		},
		"v3 refusal lookalike stays generic and sanitized": {
			change: func(env *environment) {
				env.run = failing(func(*Policy) bool { return true }, errors.New("scanner identity allocator: PID namespace changed without exclusive private-scope proof at /private/journal: secret-token"))
			},
			want:        "check the allocator state",
			wantSeccomp: StateUnavailable,
			forbid:      []string{"/private", "secret-token", "inherited liveness references"},
		},
		"probe error does not expose a path": {
			change: func(env *environment) {
				env.run = failing(func(*Policy) bool { return true }, errors.New("open /private/config.yaml: secret-token"))
			},
			want:        "check the allocator state",
			wantSeccomp: StateUnavailable,
			forbid:      []string{"/private", "secret-token"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env, _ := containerEnvironment()
			if test.change != nil {
				test.change(&env)
			}
			status := detect(Options{Mode: test.mode}, env).Status()
			if status.State != StateUnavailable || status.IdentityPool == nil || status.IdentityPool.State != StateUnavailable {
				t.Fatalf("status = %+v, want unavailable scanner identity pool", status)
			}
			if status.Landlock.State != StateUnavailable || status.Seccomp.State != test.wantSeccomp {
				t.Fatalf("Landlock = %+v, seccomp = %+v, want Landlock unavailable and seccomp %q independently", status.Landlock, status.Seccomp, test.wantSeccomp)
			}
			if status.Reason != status.IdentityPool.Reason || !strings.Contains(status.IdentityPool.Reason, test.want) {
				t.Fatalf("status reason = %q, pool reason = %q, want both to contain %q", status.Reason, status.IdentityPool.Reason, test.want)
			}
			for _, forbidden := range test.forbid {
				if strings.Contains(status.IdentityPool.Reason, forbidden) || strings.Contains(status.Reason, forbidden) || strings.Contains(status.Seccomp.Reason, forbidden) {
					t.Fatalf("scanner status %+v exposed %q", status, forbidden)
				}
			}
		})
	}
}

func TestDetectSanitizesKnownAllocatorFailuresFromRealProbePath(t *testing.T) {
	previousPrepare := prepareScannerInvocation
	t.Cleanup(func() { prepareScannerInvocation = previousPrepare })
	for _, test := range []struct {
		name, allocatorError, want string
	}{
		{
			name:           "pre-v3 unsafe scope",
			allocatorError: "scanner identity allocator: PID namespace changed with unsafe or occupied scope",
			want:           "For pre-v3 lease state, a host reboot may be needed",
		},
		{
			name:           "v3 missing exclusive proof",
			allocatorError: "scanner identity allocator: PID namespace changed without exclusive private-scope proof",
			want:           "stop all other EdgeWatch processes and containers using the data volume",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepareCalls := 0
			prepareScannerInvocation = func(context.Context, *exec.Cmd, *Policy, bool) (*ScannerInvocation, error) {
				prepareCalls++
				return nil, errors.New(test.allocatorError)
			}
			env, _ := containerEnvironment()
			env.run = runConfined
			// Keep the second, independent seccomp probe out of this test. It is
			// covered separately; this exercises the allocator failure through
			// runConfined -> PrepareScannerInvocation -> detectIdentity.
			env.seccompErr = errors.New("skip independent seccomp probe")
			status := detect(Options{}, env).Status()
			if prepareCalls != 1 {
				t.Fatalf("PrepareScannerInvocation calls = %d, want one actual scanner probe", prepareCalls)
			}
			if status.State != StateUnavailable || status.IdentityPool == nil || status.IdentityPool.State != StateUnavailable {
				t.Fatalf("status = %+v, want unavailable scanner identity pool", status)
			}
			if status.Reason != status.IdentityPool.Reason || !strings.Contains(status.Reason, test.want) {
				t.Fatalf("status reason = %q, pool reason = %q, want both to contain %q", status.Reason, status.IdentityPool.Reason, test.want)
			}
		})
	}
}

func TestAutoAllowsDaemonButUnavailableScannerPolicyFailsClosed(t *testing.T) {
	t.Parallel()
	notRoot, _ := containerEnvironment()
	notRoot.euid = 1000
	policy := detect(Options{Mode: ModeAuto}, notRoot)
	status := policy.Status()
	if policy.Enforced() || policy.Restricted() || status.State != StateUnavailable || !strings.Contains(status.Reason, "runs as UID 1000") || status.ProcessUID != nil {
		t.Fatalf("auto status = %+v, want an unavailable scanner pool", status)
	}
	if err := policy.Require(); err != nil {
		t.Fatalf("auto daemon startup should remain available: %v", err)
	}
	cmd := exec.Command("/bin/true")
	if invocation, err := PrepareScannerInvocation(context.Background(), cmd, policy, false); err == nil || invocation != nil {
		t.Fatalf("scanner invocation = %v, %v; want fail-closed before process start", invocation, err)
	}
	if cmd.Process != nil || cmd.Path != "/bin/true" {
		t.Fatalf("unavailable scanner command changed or started: %+v", cmd)
	}

	required := detect(Options{Mode: ModeRequired}, notRoot)
	if err := required.Require(); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "set scanner.sandbox to auto") {
		t.Fatalf("required daemon startup = %v, want fail-closed ErrUnavailable", err)
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

func TestConfineWithFileSizeLimitFallbacks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		policy  *Policy
		limit   uint64
		want    bool
		wantErr string
		wantID  bool
	}{
		{name: "nil policy retains caller output checks", policy: nil, limit: 16 << 20},
		{name: "no helper retains caller output checks", policy: &Policy{profile: Scanner}, limit: 16 << 20},
		{name: "identity-only no-helper fallback keeps credentials and caller checks", policy: &Policy{profile: Scanner, enforce: true, ambient: []uintptr{unix.CAP_NET_RAW}}, limit: 16 << 20, wantID: true},
		{name: "non-scanner profile rejected", policy: &Policy{profile: Notifier}, limit: 16 << 20, wantErr: "file-size limit is only supported for the scanner profile"},
		{name: "zero limit rejected", policy: &Policy{profile: Scanner}, wantErr: "scanner file-size limit must be greater than zero"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command("/usr/local/bin/nmap", "-oX", "/dev/fd/3")
			pathBefore := cmd.Path
			argsBefore := append([]string(nil), cmd.Args...)
			got := test.policy.ConfineWithFileSizeLimit(cmd, test.limit)
			if got != test.want {
				t.Fatalf("ConfineWithFileSizeLimit() = %t, want %t", got, test.want)
			}
			if cmd.Path != pathBefore || !reflect.DeepEqual(cmd.Args, argsBefore) || cmd.Process != nil {
				t.Fatalf("command changed on fallback/rejection: path=%q args=%q process=%v", cmd.Path, cmd.Args, cmd.Process)
			}
			if test.wantID {
				if attr := cmd.SysProcAttr; attr == nil || attr.Credential == nil || attr.Credential.Uid != uint32(UID) || attr.Credential.Gid != uint32(GID) || len(attr.Credential.Groups) != 0 || !reflect.DeepEqual(attr.AmbientCaps, []uintptr{unix.CAP_NET_RAW}) {
					t.Fatalf("identity-only fallback process attributes = %+v, want scanner identity and NET_RAW", attr)
				}
			} else if cmd.SysProcAttr != nil {
				t.Fatalf("unconfined fallback/rejection changed process attributes: %+v", cmd.SysProcAttr)
			}
			if test.wantErr == "" {
				if cmd.Err != nil {
					t.Fatalf("fallback command error = %v, want nil", cmd.Err)
				}
			} else if cmd.Err == nil || cmd.Err.Error() != test.wantErr {
				t.Fatalf("command error = %v, want %q", cmd.Err, test.wantErr)
			}
		})
	}
}

func TestDetectUsesHarmlessProbeInsteadOfStartingScannerBinaries(t *testing.T) {
	t.Parallel()
	env, _ := containerEnvironment()
	var commands [][]string
	env.run = func(policy *Policy, command, _ []string) error {
		commands = append(commands, append([]string(nil), command...))
		if policy.identityOnlyHelper != "" {
			return nil
		}
		if policy.Restricted() && (!policy.Enforced() || policy.helper != "/usr/local/bin/edgewatch") {
			t.Errorf("probe policy = %+v, want the scanner policy", policy.Status())
		}
		return nil
	}
	policy := detect(Options{Probes: []Probe{{Args: []string{"/usr/bin/nmap", "--version"}}, {Args: []string{"/usr/local/bin/naabu", "-version"}}}}, env)
	want := [][]string{{"/bin/true"}, {"/bin/true"}, {"/bin/true"}}
	if !policy.Restricted() || !reflect.DeepEqual(commands, want) {
		t.Fatalf("probe commands = %q, policy %+v; want only harmless probes %q", commands, policy.Status(), want)
	}
}

func TestDetectAddsTheSeccompFilterWhenItWorks(t *testing.T) {
	t.Parallel()
	nmap := []Probe{{Args: []string{"/usr/bin/nmap", "--version"}}}
	env, _ := containerEnvironment()
	var filtered []bool
	var identityOnlySeccompProbe bool
	env.run = func(policy *Policy, command, _ []string) error {
		if policy.identityOnlyHelper != "" {
			identityOnlySeccompProbe = policy.seccomp && !policy.enforce
			return nil
		}
		if policy.Restricted() {
			filtered = append(filtered, policy.seccomp)
		}
		return nil
	}
	policy := detect(Options{Probes: nmap}, env)
	if !policy.seccomp || policy.Status().Seccomp.State != StateEnforced || !reflect.DeepEqual(filtered, []bool{true}) || !identityOnlySeccompProbe {
		t.Fatalf("seccomp = %v %+v, Landlock probes %v, identity-only probe %t", policy.seccomp, policy.Status().Seccomp, filtered, identityOnlySeccompProbe)
	}

	// A scanner helper that cannot install its required filter is unavailable;
	// falling back to Landlock alone would not isolate same-UID descendants.
	env.run = failing(func(policy *Policy) bool { return policy.seccomp }, errors.New("signal: bad system call"))
	policy = detect(Options{Probes: nmap}, env)
	status := policy.Status()
	if policy.Enforced() || policy.Restricted() || status.State != StateUnavailable || status.Landlock.State != StateUnavailable || status.Seccomp.State != StateUnavailable ||
		!strings.Contains(status.Seccomp.Reason, "the scanner identity probe could not start") || !strings.Contains(status.Seccomp.Reason, "signal: bad system call") {
		t.Fatalf("status without the filter = %+v", status)
	}

	// A kernel without seccomp cannot launch scanners safely, even with
	// Landlock: descendants sharing the leased identity could still inspect
	// one another through procfs.
	env, _ = containerEnvironment()
	env.seccompErr = unix.ENOSYS
	if got := detect(Options{Probes: nmap}, env).Status(); got.State != StateUnavailable || got.Landlock.State != StateUnavailable || got.Seccomp.State != StateUnavailable || !strings.Contains(got.Seccomp.Reason, "does not provide seccomp filters") {
		t.Fatalf("status without seccomp support = %+v; want scanner launches unavailable", got)
	}

	// Without Landlock, the identity-only helper still installs the scanner
	// no-escape filter.
	env, _ = containerEnvironment()
	env.landlockErr = unix.ENOSYS
	if got := detect(Options{Probes: nmap}, env).Status().Seccomp; got.State != StateEnforced {
		t.Fatalf("seccomp without Landlock = %+v, want enforced", got)
	}
	if got := detect(Options{Landlock: ModeOff}, env).Status().Seccomp; got.State != StateEnforced {
		t.Fatalf("seccomp with Landlock off = %+v, want enforced", got)
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
		"executable":  {change: func(env *environment) { env.executableErr = errors.New("no /proc") }, state: StateUnavailable, reason: "scanner identity isolation is unavailable", noIdentity: true},
		"probe failed": {mode: ModeRequired, change: func(env *environment) {
			env.run = failing(withLandlock, errors.New("exit status 1: denied"))
		}, state: StateUnavailable, reason: "the scanner identity probe could not start with Landlock: exit status 1: denied"},
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
	if policy.Restricted() || policy.Status().IdentityPool == nil || policy.Status().IdentityPool.State != StateUnavailable || !strings.Contains(policy.Status().Landlock.Reason, "scanner identity isolation is unavailable") {
		t.Fatalf("Detect from a test binary = %+v, want scanner identity isolation unavailable", policy.Status())
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

	if got := Detect(Options{}); got.Enforced() || got.Status().State != StateUnavailable || got.Status().Reason != "the sandbox requires Linux" || got.Status().ProcessUID != nil || got.Status().Landlock.Reason != "Landlock requires Linux" || got.Status().IdentityPool == nil || got.Status().IdentityPool.State != StateUnavailable {
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
