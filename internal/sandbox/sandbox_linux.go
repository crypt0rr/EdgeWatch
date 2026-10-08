//go:build linux

package sandbox

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// controlCapabilities are the capabilities the daemon needs to start a
// confined process as another identity and to stop it: KILL is what lets UID
// 0 signal a process of another UID once filesystem and process capabilities
// are dropped.
var controlCapabilities = []uintptr{unix.CAP_SETUID, unix.CAP_SETGID, unix.CAP_KILL}

// networkCapabilities are the capabilities a confined scanner keeps when the
// daemon holds them: the same raw-packet privileges an unconfined scanner
// started by UID 0 would have.
var networkCapabilities = []uintptr{unix.CAP_NET_RAW, unix.CAP_NET_ADMIN}

const probeTimeout = 10 * time.Second

// environment is what Detect inspects, so tests can describe a runtime.
type environment struct {
	euid       int
	effective  uint64
	permitted  uint64
	capErr     error
	noNewPrivs bool
	// landlockABI is the kernel's Landlock ABI version, or landlockErr why
	// it has none.
	landlockABI int
	landlockErr error
	// seccompErr is why the kernel cannot run the seccomp filter, or nil.
	seccompErr error
	// executable is the EdgeWatch executable, or executableErr why it cannot
	// start sandboxed processes.
	executable    string
	executableErr error
	// run starts command confined by policy in environment and reports
	// whether it succeeded.
	run func(policy *Policy, command, environment []string) error
}

// command returns the command line of probe.
func (env environment) command(probe Probe) ([]string, error) {
	if !probe.Self {
		return probe.Args, nil
	}
	if env.executableErr != nil {
		return nil, env.executableErr
	}
	return append([]string{env.executable}, probe.Args...), nil
}

// runProbe runs probe confined by policy.
func (env environment) runProbe(policy *Policy, probe Probe) error {
	command, err := env.command(probe)
	if err != nil {
		return err
	}
	if len(command) == 0 {
		return nil
	}
	return env.run(policy, command, probe.Env)
}

func probeName(probe Probe) string {
	if probe.Name != "" {
		return probe.Name
	}
	if len(probe.Args) == 0 || probe.Self {
		return "edgewatch"
	}
	return filepath.Base(probe.Args[0])
}

func init() {
	detectPlatform = func(options Options) *Policy { return detect(options, systemEnvironment()) }
	confineProcess = confineLinux
	nameCapability = linuxCapabilityName
	execRestricted = execLandlocked
	hardenProcess = hardenLinux
}

// hardenLinux sets a soft and hard core file size limit of zero, which the
// processes this one starts inherit and cannot raise, and clears the dumpable
// flag, which execve sets again for the program it runs.
func hardenLinux() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("make the process non-dumpable: %w", err)
	}
	return nil
}

func detect(options Options, env environment) *Policy {
	profile := profileOrScanner(options.Profile)
	spec := profile.spec()
	mode := normalizedMode(options.Mode)
	status := Status{Mode: mode, ProcessUID: env.euid}
	if mode == ModeOff {
		status.State = StateDisabled
		status.Reason = spec.sandboxSetting + " is off"
		status.Landlock = LandlockStatus{Mode: normalizedMode(options.Landlock), State: StateDisabled, Reason: spec.sandboxSetting + " is off"}
		status.Seccomp = SeccompStatus{State: StateDisabled, Reason: seccompWithoutLandlock}
		return &Policy{profile: profile, status: status}
	}
	return detectLandlock(detectIdentity(profile, mode, status, options.IdentityProbe, env), options, env)
}

// detectIdentity decides whether the processes of profile start as its
// confined identity.
func detectIdentity(profile Profile, mode string, status Status, probe Probe, env environment) *Policy {
	spec := profile.spec()
	unavailable := func(reason string) *Policy {
		status.State = StateUnavailable
		status.Reason = reason
		return &Policy{profile: profile, status: status}
	}
	if !ValidMode(mode) {
		return unavailable(fmt.Sprintf("%s %q is not auto, required, or off", spec.sandboxSetting, mode))
	}
	if env.euid != 0 {
		return unavailable(fmt.Sprintf("EdgeWatch runs as UID %d rather than 0, so it cannot start %s as another identity", env.euid, spec.processes))
	}
	if env.capErr != nil {
		return unavailable(fmt.Sprintf("the daemon's capabilities could not be read: %v", env.capErr))
	}
	var missing []string
	for _, capability := range controlCapabilities {
		if env.effective&(1<<capability) == 0 {
			missing = append(missing, capabilityName(capability))
		}
	}
	if len(missing) > 0 {
		return unavailable(fmt.Sprintf("the container does not grant %s, which EdgeWatch needs to start and stop %s as UID %d; add them to cap_add", strings.Join(missing, ", "), spec.processes, spec.uid))
	}
	var ambient []uintptr
	for _, capability := range networkCapabilities {
		if spec.keepsNetwork && env.permitted&(1<<capability) != 0 {
			ambient = append(ambient, capability)
		}
	}
	if len(probe.Args) == 0 {
		probe = Probe{Self: true, Args: []string{"version"}}
	}
	policy := NewEnforcedFor(profile, ambient...)
	if err := env.runProbe(policy, probe); err != nil {
		return unavailable(fmt.Sprintf("%s could not start as UID %d: %v", spec.testProcess, spec.uid, err))
	}
	policy.status.Mode = mode
	policy.status.NoNewPrivileges = env.noNewPrivs
	return policy
}

// detectLandlock decides whether the processes also start restricted with
// Landlock. When they cannot, policy keeps its identity confinement.
func detectLandlock(policy *Policy, options Options, env environment) *Policy {
	spec := policy.profileName().spec()
	mode := normalizedMode(options.Landlock)
	status := LandlockStatus{Mode: mode}
	unrestricted := func(state, reason string) *Policy {
		status.State, status.Reason = state, reason
		policy.status.Landlock = status
		policy.status.Seccomp = SeccompStatus{State: state, Reason: seccompWithoutLandlock}
		return policy
	}
	switch {
	case mode == ModeOff:
		return unrestricted(StateDisabled, spec.landlockSetting+" is off")
	case !ValidMode(mode):
		return unrestricted(StateUnavailable, fmt.Sprintf("%s %q is not auto, required, or off", spec.landlockSetting, mode))
	case env.landlockErr != nil:
		return unrestricted(StateUnavailable, landlockUnavailableReason(env.landlockErr))
	case env.executableErr != nil:
		return unrestricted(StateUnavailable, fmt.Sprintf("the EdgeWatch executable cannot start %s with Landlock: %v", spec.processes, env.executableErr))
	}
	restricted := policy.WithLandlock(env.executable, env.landlockABI)
	restricted.status.Landlock.Mode = mode
	probe := func(candidate *Policy) (string, error) {
		for _, probe := range options.Probes {
			if err := env.runProbe(candidate, probe); err != nil {
				return probeName(probe), err
			}
		}
		return "", nil
	}
	// The seccomp filter rides on the Landlock restriction. When the probes
	// fail with it, Landlock may still apply alone.
	seccompReason := ""
	if env.seccompErr != nil {
		seccompReason = seccompUnavailableReason(env.seccompErr)
	} else {
		filtered := restricted.WithSeccomp()
		name, err := probe(filtered)
		if err == nil {
			return filtered
		}
		seccompReason = fmt.Sprintf("%s could not start with the seccomp filter: %v", name, err)
	}
	if name, err := probe(restricted); err != nil {
		return unrestricted(StateUnavailable, fmt.Sprintf("%s could not start with Landlock: %v", name, err))
	}
	restricted.status.Seccomp = SeccompStatus{State: StateUnavailable, Reason: seccompReason}
	return restricted
}

// landlockUnavailableReason explains why the kernel offers no Landlock ABI.
func landlockUnavailableReason(err error) string {
	switch {
	case errors.Is(err, unix.ENOSYS):
		return "the kernel does not provide Landlock, or the container's seccomp profile blocks it"
	case errors.Is(err, unix.EOPNOTSUPP):
		return "Landlock is built into the kernel but not enabled; add landlock to the lsm= boot parameter"
	default:
		return fmt.Sprintf("Landlock could not be detected: %v", err)
	}
}

// confineLinux starts cmd's process as uid and gid with no supplementary
// groups and the ambient capabilities.
func confineLinux(cmd *exec.Cmd, uid, gid int, ambient []uintptr) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// An empty, non-nil Groups clears the supplementary groups. Keeping UID
	// 0's groups would give the process the root group's access.
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}
	cmd.SysProcAttr.AmbientCaps = append([]uintptr(nil), ambient...)
}

func systemEnvironment() environment {
	env := environment{euid: os.Geteuid(), run: runConfined}
	env.landlockABI, env.landlockErr = landlockVersion()
	env.seccompErr = seccompSupport()
	env.executable, env.executableErr = os.Executable()
	if env.executableErr == nil {
		env.executableErr = refuseTestBinary(env.executable)
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		env.capErr = err
	} else {
		env.effective = uint64(data[0].Effective) | uint64(data[1].Effective)<<32
		env.permitted = uint64(data[0].Permitted) | uint64(data[1].Permitted)<<32
	}
	env.noNewPrivs = readNoNewPrivs("/proc/self/status")
	return env
}

func readNoNewPrivs(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if value, ok := strings.CutPrefix(scanner.Text(), "NoNewPrivs:"); ok {
			return strings.TrimSpace(value) == "1"
		}
	}
	return false
}

// refuseTestBinary keeps a Go test binary from running its whole test suite
// as a probe or as the sandbox-exec command. Tests describe the runtime
// instead.
func refuseTestBinary(executable string) error {
	if strings.HasSuffix(filepath.Base(executable), ".test") {
		return errors.New("a test binary does not start sandboxed processes")
	}
	return nil
}

// maxProbeDiagnostic bounds the diagnostic output a failed probe reports.
const maxProbeDiagnostic = 4 << 10

// defaultProbeEnvironment is the environment of a probe that sets none.
var defaultProbeEnvironment = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "XDG_CONFIG_HOME=/nonexistent"}

// runConfined runs command as policy starts its processes: as the confined
// identity, which the kernel refuses before the process starts when the
// runtime does not allow the identity change or an ambient capability, and
// through the sandbox-exec command when the policy restricts it with
// Landlock. A command that fails reports its last diagnostic line. A command
// whose executable does not exist is skipped: that program is not installed.
func runConfined(policy *Policy, command, environment []string) error {
	if _, err := os.Stat(command[0]); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Env = environment
	if cmd.Env == nil {
		cmd.Env = defaultProbeEnvironment
	}
	cmd.Stdout = io.Discard
	diagnostic := &boundedBuffer{limit: maxProbeDiagnostic}
	cmd.Stderr = diagnostic
	policy.Confine(cmd)
	if err := cmd.Run(); err != nil {
		if detail := lastLine(diagnostic.String()); detail != "" {
			return fmt.Errorf("%w: %s", err, detail)
		}
		return err
	}
	return nil
}

// boundedBuffer keeps the first limit bytes written to it.
type boundedBuffer struct {
	limit int
	data  []byte
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - len(b.data); room > 0 {
		b.data = append(b.data, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string { return string(b.data) }

func lastLine(text string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func linuxCapabilityName(capability uintptr) string {
	switch capability {
	case unix.CAP_NET_RAW:
		return "NET_RAW"
	case unix.CAP_NET_ADMIN:
		return "NET_ADMIN"
	case unix.CAP_SETUID:
		return "SETUID"
	case unix.CAP_SETGID:
		return "SETGID"
	case unix.CAP_KILL:
		return "KILL"
	default:
		return fmt.Sprintf("CAP_%d", capability)
	}
}
