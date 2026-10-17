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
	"strconv"
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
	// identityRangeErr is why the configured per-invocation scanner UID/GID
	// range cannot be used in this runtime.
	identityRangeErr error
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

// hardenLinux limits ordinary core-file output, excludes memory mappings from
// core dumps, and clears the dumpable flag, which execve sets again for the
// program it runs. The coredump filter is set or its inherited zero value is
// checked before the process becomes non-dumpable, so startup fails if a
// nonzero filter cannot be cleared or the current value cannot be verified.
func hardenLinux() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	if err := setAndVerifyZeroCoredumpFilter(); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("make the process non-dumpable: %w", err)
	}
	return nil
}

const procCoredumpFilter = "/proc/self/coredump_filter"

// coredumpFilterIO separates the value update/verification from process
// hardening. The production implementation below always opens the fixed
// proc control file; the per-call interface lets tests exercise the decision
// paths without changing the test process's limits or dumpability.
type coredumpFilterIO interface {
	openForWrite() (io.WriteCloser, error)
	read() ([]byte, error)
}

type procCoredumpFilterIO struct{}

func (procCoredumpFilterIO) openForWrite() (io.WriteCloser, error) {
	return os.OpenFile(procCoredumpFilter, os.O_WRONLY, 0)
}

func (procCoredumpFilterIO) read() ([]byte, error) {
	return os.ReadFile(procCoredumpFilter)
}

func setAndVerifyZeroCoredumpFilter() error {
	return setAndVerifyZeroCoredumpFilterWith(procCoredumpFilterIO{})
}

func setAndVerifyZeroCoredumpFilterWith(filterIO coredumpFilterIO) error {
	file, err := filterIO.openForWrite()
	if err != nil {
		return verifyInheritedZeroCoredumpFilter(filterIO, fmt.Errorf("open %s: %w", procCoredumpFilter, err))
	}
	written, writeErr := io.WriteString(file, "0")
	closeErr := file.Close()
	if writeErr != nil {
		return verifyInheritedZeroCoredumpFilter(filterIO, fmt.Errorf("set %s to zero: %w", procCoredumpFilter, writeErr))
	}
	if written != 1 {
		return verifyInheritedZeroCoredumpFilter(filterIO, fmt.Errorf("set %s to zero: wrote %d of 1 byte", procCoredumpFilter, written))
	}
	if closeErr != nil {
		return verifyInheritedZeroCoredumpFilter(filterIO, fmt.Errorf("close %s after setting it: %w", procCoredumpFilter, closeErr))
	}
	filter, err := readCoredumpFilterWith(filterIO)
	if err != nil {
		return fmt.Errorf("read back %s: %w", procCoredumpFilter, err)
	}
	if filter != 0 {
		return fmt.Errorf("verify %s: value is %#x, want zero", procCoredumpFilter, filter)
	}
	return nil
}

// verifyInheritedZeroCoredumpFilter permits a process that inherited the
// already-zero filter to continue when its context cannot write the proc
// control file, such as an EdgeWatch child after Landlock is applied. A
// failed write is never accepted unless the current filter can be read back
// as zero; a nonzero or unreadable filter remains a startup error.
func verifyInheritedZeroCoredumpFilter(filterIO coredumpFilterIO, setErr error) error {
	filter, err := readCoredumpFilterWith(filterIO)
	if err != nil {
		return errors.Join(setErr, fmt.Errorf("read back %s after setting it failed: %w", procCoredumpFilter, err))
	}
	if filter != 0 {
		return fmt.Errorf("%w; current filter is %#x, want zero", setErr, filter)
	}
	return nil
}

func readCoredumpFilter() (uint64, error) {
	return readCoredumpFilterWith(procCoredumpFilterIO{})
}

func readCoredumpFilterWith(filterIO coredumpFilterIO) (uint64, error) {
	contents, err := filterIO.read()
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(string(contents))
	filter, err := strconv.ParseUint(value, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("parse value %q: %w", value, err)
	}
	return filter, nil
}

// limitScannerResources makes the kernel's out-of-memory killer choose the
// calling scanner process before any other EdgeWatch process, and lowers its
// open file limits to ScannerMaxOpenFiles. It is best effort: a runtime that
// refuses oom_score_adj still runs the scanner restricted. A process may
// write its oom_score_adj only while it owns its /proc entries, which a
// non-dumpable process does not, so it becomes dumpable again first. The
// scanner it executes is dumpable anyway, because execve resets the flag; the
// zero core file size limit and coredump filter it inherits still restrict
// core output and exclude normal memory mappings.
func limitScannerResources() {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err == nil {
		if file, err := os.OpenFile("/proc/self/oom_score_adj", os.O_WRONLY, 0); err == nil {
			_, _ = file.WriteString(strconv.Itoa(ScannerOOMScoreAdj))
			_ = file.Close()
		}
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err == nil {
		limit.Max = min(limit.Max, ScannerMaxOpenFiles)
		limit.Cur = min(limit.Cur, limit.Max)
		_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &limit)
	}
}

func detect(options Options, env environment) *Policy {
	profile := profileOrScanner(options.Profile)
	spec := profile.spec()
	mode := normalizedMode(options.Mode)
	status := Status{Mode: mode}
	if profile == Scanner {
		status.IdentityPool = scannerIdentityPoolStatus(StateUnavailable, "scanner identity leases have not been verified")
	} else {
		status.ProcessUID = uidPointer(env.euid)
	}
	if mode == ModeOff {
		status.State = StateDisabled
		status.Reason = spec.sandboxSetting + " is off"
		status.ProcessUID = uidPointer(env.euid)
		if profile == Scanner {
			status.IdentityPool = scannerIdentityPoolStatus(StateDisabled, spec.sandboxSetting+" is off")
		}
		status.Landlock = LandlockStatus{Mode: normalizedMode(options.Landlock), State: StateDisabled, Reason: spec.sandboxSetting + " is off"}
		status.Seccomp = SeccompStatus{State: StateDisabled, Reason: seccompWithoutLandlock}
		return &Policy{profile: profile, status: status}
	}
	identity := detectIdentity(profile, mode, status, options.IdentityProbe, env)
	if env.executableErr == nil {
		identity.temporaryHelper = env.executable
	}
	if profile == Scanner {
		identity = detectScannerSeccomp(identity, scannerSandboxProbe(), env)
	}
	return detectLandlock(identity, options, env)
}

func scannerSandboxProbe() Probe {
	// Never run Nmap or Naabu from Detect: version checks and other scanner
	// commands must acquire their own invocation identity lease.
	return Probe{Name: "the scanner identity probe", Args: []string{"/bin/true"}}
}

func scannerIdentityRootUnavailableReason(uid int) string {
	if uid < 0 || uint64(uid) > uint64(^uint32(0)) {
		return "scanner identity isolation requires EdgeWatch to run as UID 0"
	}
	return fmt.Sprintf("EdgeWatch runs as UID %d rather than UID 0, so it cannot start scanner processes under leased identities", uid)
}

func scannerIdentityRangeUnavailableReason(err error) string {
	var unmapped scannerIdentityUnmappedError
	if errors.As(err, &unmapped) && unmapped.id >= ScannerIdentityPoolUIDStart && unmapped.id <= ScannerIdentityPoolUIDEnd {
		return fmt.Sprintf("scanner UID/GID %d is not mapped; map the full UID/GID range %d–%d in the container user namespace", unmapped.id, ScannerIdentityPoolUIDStart, ScannerIdentityPoolUIDEnd)
	}
	return fmt.Sprintf("the scanner UID/GID range %d–%d cannot be verified in the container user namespace; check the runtime's UID/GID mappings", ScannerIdentityPoolUIDStart, ScannerIdentityPoolUIDEnd)
}

func scannerIdentityProbeUnavailableReason(err error) string {
	// detectIdentity calls this only after the probe returns a non-nil error.
	switch err.Error() {
	case "scanner identity allocator: PID namespace changed with unsafe or occupied scope":
		return "the scanner identity allocator could not verify an empty prior scope after a PID namespace change; stop other EdgeWatch processes using the data volume and preserve the lease journal and boot marker. For pre-v3 lease state, a host reboot may be needed before the allocator can prove prior-boot processes are gone; do not delete or edit state files"
	case "scanner identity allocator: PID namespace changed without exclusive private-scope proof":
		return "the scanner identity allocator could not prove the previous private scope safe after a PID namespace change; ensure the supported private scanner runtime is active, stop all other EdgeWatch processes and containers using the data volume so inherited liveness references close, then retry. The v3 allocator can archive and reset the prior scope once it proves exclusivity; preserve the journal and boot marker and do not delete or edit state files"
	}
	return "the scanner identity probe could not start under a leased identity; check the allocator state, UID/GID mappings, and SETUID, SETGID, and KILL capabilities"
}

func scannerSeccompProbeUnavailableReason(err error) string {
	if err != nil && strings.Contains(err.Error(), "signal: bad system call") {
		return "the scanner identity probe could not start with the required seccomp filter (signal: bad system call); check the runtime's seccomp policy"
	}
	return "the scanner identity probe could not start with the required seccomp filter; check the runtime's seccomp policy"
}

// detectIdentity decides whether the processes of profile start as its
// confined identity.
func detectIdentity(profile Profile, mode string, status Status, probe Probe, env environment) *Policy {
	spec := profile.spec()
	identityTarget := fmt.Sprintf("UID %d", spec.uid)
	if profile == Scanner {
		identityTarget = "a leased scanner identity"
	}
	unavailable := func(reason string) *Policy {
		status.State = StateUnavailable
		status.Reason = reason
		if profile == Scanner {
			status.IdentityPool = scannerIdentityPoolStatus(StateUnavailable, reason)
		}
		return &Policy{profile: profile, status: status}
	}
	if !ValidMode(mode) {
		if profile == Scanner {
			return unavailable("scanner.sandbox must be auto, required, or off")
		}
		return unavailable(fmt.Sprintf("%s %q is not auto, required, or off", spec.sandboxSetting, mode))
	}
	if env.euid != 0 {
		if profile == Scanner {
			return unavailable(scannerIdentityRootUnavailableReason(env.euid))
		}
		return unavailable(fmt.Sprintf("EdgeWatch runs as UID %d rather than 0, so it cannot start %s under %s", env.euid, spec.processes, identityTarget))
	}
	if profile == Scanner && env.identityRangeErr != nil {
		return unavailable(scannerIdentityRangeUnavailableReason(env.identityRangeErr))
	}
	if profile == Scanner && env.executableErr != nil {
		return unavailable("the EdgeWatch executable is unavailable for scanner identity supervision")
	}
	if env.capErr != nil {
		if profile == Scanner {
			return unavailable("the daemon's capabilities could not be verified; check the container runtime's capability settings")
		}
		return unavailable(fmt.Sprintf("the daemon's capabilities could not be read: %v", env.capErr))
	}
	var missing []string
	for _, capability := range controlCapabilities {
		if env.effective&(1<<capability) == 0 {
			missing = append(missing, capabilityName(capability))
		}
	}
	if len(missing) > 0 {
		return unavailable(fmt.Sprintf("the container does not grant %s, which EdgeWatch needs to start and stop %s under %s; add them to cap_add", strings.Join(missing, ", "), spec.processes, identityTarget))
	}
	var ambient []uintptr
	for _, capability := range networkCapabilities {
		if spec.keepsNetwork && env.permitted&(1<<capability) != 0 {
			ambient = append(ambient, capability)
		}
	}
	if profile == Scanner {
		probe = scannerSandboxProbe()
	} else if len(probe.Args) == 0 {
		probe = Probe{Self: true, Args: []string{"version"}}
	}
	policy := NewEnforcedFor(profile, ambient...)
	if err := env.runProbe(policy, probe); err != nil {
		if profile == Scanner {
			return unavailable(scannerIdentityProbeUnavailableReason(err))
		}
		return unavailable(fmt.Sprintf("%s could not start as UID %d: %v", spec.testProcess, spec.uid, err))
	}
	policy.status.Mode = mode
	policy.status.NoNewPrivileges = env.noNewPrivs
	if profile == Scanner {
		policy.status.ProcessUID = nil
		policy.status.UID, policy.status.GID = 0, 0
		policy.status.IdentityPool = scannerIdentityPoolStatus(StateEnforced, "")
	}
	return policy
}

// detectScannerSeccomp independently probes the no-escape filter used by the
// trusted scanner supervisor. Scanner isolation requires this filter even
// when Landlock is disabled or unavailable.
func detectScannerSeccomp(policy *Policy, probe Probe, env environment) *Policy {
	if policy.profileName() != Scanner || policy.status.Mode == ModeOff {
		return policy
	}
	setUnavailable := func(reason string) *Policy {
		policy.status.Seccomp = SeccompStatus{State: StateUnavailable, Reason: reason}
		if policy.enforce {
			policy.enforce = false
			policy.status.State = StateUnavailable
			policy.status.Reason = reason
			policy.status.IdentityPool = scannerIdentityPoolStatus(StateUnavailable, reason)
		}
		return policy
	}
	if env.seccompErr != nil {
		return setUnavailable(seccompUnavailableReason(env.seccompErr))
	}
	if env.executableErr != nil {
		return setUnavailable("the EdgeWatch executable cannot install the required scanner seccomp filter")
	}
	if len(probe.Args) == 0 {
		probe = Probe{Self: true, Args: []string{"version"}}
	}
	candidate := *policy
	candidate.enforce = false
	candidate.helper = ""
	candidate.identityOnlyHelper = env.executable
	candidate.seccomp = true
	candidate.status.Seccomp = SeccompStatus{State: StateEnforced}
	if err := env.runProbe(&candidate, probe); err != nil {
		return setUnavailable(scannerSeccompProbeUnavailableReason(err))
	}
	policy.seccomp = true
	policy.status.Seccomp = SeccompStatus{State: StateEnforced}
	return policy
}

// detectLandlock decides whether the processes also start restricted with
// Landlock. When they cannot, policy keeps its identity confinement.
func detectLandlock(policy *Policy, options Options, env environment) *Policy {
	spec := policy.profileName().spec()
	scanner := policy.profileName() == Scanner
	mode := normalizedMode(options.Landlock)
	status := LandlockStatus{Mode: mode}
	unrestricted := func(state, reason string) *Policy {
		status.State, status.Reason = state, reason
		policy.status.Landlock = status
		if !scanner {
			policy.status.Seccomp = SeccompStatus{State: state, Reason: seccompWithoutLandlock}
		}
		return policy
	}
	if scanner && mode != ModeOff && !policy.enforce {
		return unrestricted(StateUnavailable, "scanner identity isolation is unavailable")
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
	probes := options.Probes
	if scanner {
		probes = []Probe{scannerSandboxProbe()}
	}
	probe := func(candidate *Policy) (string, error) {
		for _, probe := range probes {
			if err := env.runProbe(candidate, probe); err != nil {
				return probeName(probe), err
			}
		}
		return "", nil
	}
	// Scanner seccomp is also tested without Landlock because the supervisor
	// needs the no-escape filter on kernels where Landlock is unavailable.
	// Notifier seccomp remains part of the Landlock helper path.
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
	if scanner && policy.status.Seccomp.State == StateEnforced {
		// The filter itself works, but its combination with Landlock did not.
		// Auto can safely fall back to the identity-only helper. Required
		// Landlock remains unavailable and Policy.Require refuses startup.
		policy.status.Landlock = LandlockStatus{Mode: mode, State: StateUnavailable, Reason: "the scanner helper could not combine Landlock with the required seccomp filter"}
		policy.temporaryHelper = env.executable
		return policy
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
	env.identityRangeErr = validateScannerIdentityRangeMapping(scannerIdentityStart, scannerIdentityCount)
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
	var invocation *ScannerInvocation
	if policy != nil && policy.profileName() == Scanner && policy.status.Mode != ModeOff && policy.identityOnlyHelper == "" {
		var err error
		invocation, err = PrepareScannerInvocation(ctx, cmd, policy, false)
		if err != nil {
			return err
		}
	}
	if invocation == nil {
		if policy != nil && policy.profileName() == Scanner && policy.status.Mode != ModeOff && !policy.enforce && policy.identityOnlyHelper == "" {
			return fmt.Errorf("%w: scanner identity isolation is unavailable", ErrUnavailable)
		}
		if err := cmd.Run(); err != nil {
			if detail := lastLine(diagnostic.String()); detail != "" {
				return fmt.Errorf("%w: %s", err, detail)
			}
			return err
		}
		return nil
	}
	invocation.InstallCancellation(cmd)
	if err := cmd.Start(); err != nil {
		return errors.Join(err, invocation.StartFailed(true))
	}
	if err := invocation.Started(); err != nil {
		_ = invocation.Cancel(cmd)
		waitErr := cmd.Wait()
		proofErr := invocation.VerifyProcessTree()
		finishErr := invocation.Finish(proofErr == nil)
		return errors.Join(fmt.Errorf("start scanner probe: %w", err), waitErr, proofErr, finishErr)
	}
	waitErr := cmd.Wait()
	proofErr := invocation.VerifyProcessTree()
	finishErr := invocation.Finish(proofErr == nil)
	if err := errors.Join(waitErr, proofErr, finishErr); err != nil {
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
