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
// scanner process as another identity and to stop it: KILL is what lets UID 0
// signal a process of another UID once filesystem and process capabilities
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
	// probe starts a short-lived process confined with ambient and reports
	// whether it ran.
	probe func(ambient []uintptr) error
	// landlockABI is the kernel's Landlock ABI version, or landlockErr why
	// it has none.
	landlockABI int
	landlockErr error
	// executable is the EdgeWatch executable, or executableErr why it could
	// not be found.
	executable    string
	executableErr error
	// probeLandlock runs command as policy, which restricts it with
	// Landlock, starts it, and reports whether it ran.
	probeLandlock func(policy *Policy, command []string) error
}

func init() {
	detectPlatform = func(options Options) *Policy { return detect(options, systemEnvironment()) }
	confineProcess = confineLinux
	nameCapability = linuxCapabilityName
	execRestricted = execLandlocked
}

func detect(options Options, env environment) *Policy {
	mode := normalizedMode(options.Mode)
	status := Status{Mode: mode, ProcessUID: env.euid}
	if mode == ModeOff {
		status.State = StateDisabled
		status.Reason = "scanner.sandbox is off"
		status.Landlock = LandlockStatus{Mode: normalizedMode(options.Landlock), State: StateDisabled, Reason: "scanner.sandbox is off"}
		return &Policy{status: status}
	}
	return detectLandlock(detectIdentity(mode, status, env), options, env)
}

// detectIdentity decides whether scanner processes start as the confined
// identity.
func detectIdentity(mode string, status Status, env environment) *Policy {
	unavailable := func(reason string) *Policy {
		status.State = StateUnavailable
		status.Reason = reason
		return &Policy{status: status}
	}
	if !ValidMode(mode) {
		return unavailable(fmt.Sprintf("scanner.sandbox %q is not auto, required, or off", mode))
	}
	if env.euid != 0 {
		return unavailable(fmt.Sprintf("EdgeWatch runs as UID %d rather than 0, so it cannot start scanner processes as another identity", env.euid))
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
		return unavailable(fmt.Sprintf("the container does not grant %s, which EdgeWatch needs to start and stop scanner processes as UID %d; add them to cap_add", strings.Join(missing, ", "), UID))
	}
	var ambient []uintptr
	for _, capability := range networkCapabilities {
		if env.permitted&(1<<capability) != 0 {
			ambient = append(ambient, capability)
		}
	}
	if err := env.probe(ambient); err != nil {
		return unavailable(fmt.Sprintf("a test process could not start as UID %d: %v", UID, err))
	}
	policy := NewEnforced(ambient...)
	policy.status.Mode = mode
	policy.status.NoNewPrivileges = env.noNewPrivs
	return policy
}

// detectLandlock decides whether scanner processes also start restricted
// with Landlock. When they cannot, policy keeps its identity confinement.
func detectLandlock(policy *Policy, options Options, env environment) *Policy {
	mode := normalizedMode(options.Landlock)
	status := LandlockStatus{Mode: mode}
	unrestricted := func(state, reason string) *Policy {
		status.State, status.Reason = state, reason
		policy.status.Landlock = status
		return policy
	}
	switch {
	case mode == ModeOff:
		return unrestricted(StateDisabled, "scanner.landlock is off")
	case !ValidMode(mode):
		return unrestricted(StateUnavailable, fmt.Sprintf("scanner.landlock %q is not auto, required, or off", mode))
	case env.landlockErr != nil:
		return unrestricted(StateUnavailable, landlockUnavailableReason(env.landlockErr))
	case env.executableErr != nil:
		return unrestricted(StateUnavailable, fmt.Sprintf("the EdgeWatch executable cannot start scanner processes with Landlock: %v", env.executableErr))
	}
	restricted := policy.WithLandlock(env.executable, env.landlockABI)
	restricted.status.Landlock.Mode = mode
	for _, command := range options.Probes {
		if len(command) == 0 {
			continue
		}
		if err := env.probeLandlock(restricted, command); err != nil {
			return unrestricted(StateUnavailable, fmt.Sprintf("%s could not start with Landlock: %v", filepath.Base(command[0]), err))
		}
	}
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

// confineLinux starts cmd's process as UID and GID with no supplementary
// groups and the ambient capabilities.
func confineLinux(cmd *exec.Cmd, ambient []uintptr) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// An empty, non-nil Groups clears the supplementary groups. Keeping UID
	// 0's groups would give the process the root group's access.
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: UID, Gid: GID, Groups: []uint32{}}
	cmd.SysProcAttr.AmbientCaps = append([]uintptr(nil), ambient...)
}

func systemEnvironment() environment {
	env := environment{euid: os.Geteuid(), probe: probeProcess, probeLandlock: probeLandlocked}
	env.landlockABI, env.landlockErr = landlockVersion()
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

// probeProcess runs the EdgeWatch binary's version command confined. The
// kernel refuses the identity change or an ambient capability the daemon does
// not hold before the process starts, so a successful run proves that scanner
// processes can be confined the same way.
func probeProcess(ambient []uintptr) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if err := refuseTestBinary(executable); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "version")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	NewEnforced(ambient...).Confine(cmd)
	return cmd.Run()
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

// probeLandlocked runs command as policy starts scanner processes, through
// the sandbox-exec command. A scanner whose executable or shared libraries
// lie outside the paths the restriction allows fails here, at startup,
// instead of failing every scan. A command whose executable does not exist is
// skipped: that scanner is not installed.
func probeLandlocked(policy *Policy, command []string) error {
	if _, err := os.Stat(command[0]); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "XDG_CONFIG_HOME=/nonexistent"}
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
