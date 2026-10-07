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
}

// Detect decides how scanner processes start in this runtime for the
// configured scanner.sandbox mode. Unless the mode is off, it starts a
// short-lived confined process to confirm that the runtime allows the
// identity change and the capabilities.
func Detect(mode string) *Policy {
	return detect(mode, systemEnvironment())
}

func detect(mode string, env environment) *Policy {
	mode = normalizedMode(mode)
	status := Status{Mode: mode, ProcessUID: env.euid}
	if mode == ModeOff {
		status.State = StateDisabled
		status.Reason = "scanner.sandbox is off"
		return &Policy{status: status}
	}
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

// Confine makes cmd start its process confined. It keeps any process
// attributes already set, such as the session and controlling terminal of a
// pseudo-terminal. When the policy is not enforced, cmd is unchanged.
func (p *Policy) Confine(cmd *exec.Cmd) {
	if !p.Enforced() {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// An empty, non-nil Groups clears the supplementary groups. Keeping UID
	// 0's groups would give the process the root group's access.
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: UID, Gid: GID, Groups: []uint32{}}
	cmd.SysProcAttr.AmbientCaps = append([]uintptr(nil), p.ambient...)
}

func systemEnvironment() environment {
	env := environment{euid: os.Geteuid(), probe: probeProcess}
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
	// A Go test binary would run its whole test suite as the probe. Tests
	// describe the runtime instead.
	if strings.HasSuffix(filepath.Base(executable), ".test") {
		return errors.New("the probe does not run from a test binary")
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

func capabilityName(capability uintptr) string {
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
