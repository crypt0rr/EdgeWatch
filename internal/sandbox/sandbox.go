// Package sandbox starts scanner processes as an unprivileged identity that
// keeps only the network capabilities a scan needs, and restricts the files
// they can open with Landlock. It confines the notification process the same
// way, as its own identity and without capabilities.
//
// Nmap, its NSE scripts, and Naabu parse responses from the networks they
// scan. When the daemon runs as UID 0, as the container does, a scanner
// process started the ordinary way inherits that identity and can read the
// database and the encryption keys. A confined scanner process runs as UID
// and GID 65532 with no supplementary groups. It holds the container's
// NET_RAW, and NET_ADMIN when the container grants it, as ambient
// capabilities and nothing else. The data directory and the key files belong
// to UID 0, so a confined process can read none of them. The private files a
// scanner reads or writes are passed to it as inherited descriptors.
//
// When the kernel provides Landlock, a scanner process also starts through
// the hidden sandbox-exec command, which restricts its own process to the
// system files a scanner reads and the files it inherits, and then executes
// the scanner in place. The restriction holds whatever identity the process
// has, so it also covers a scanner process that keeps UID 0 because the
// identity change is unavailable, or the identity of a daemon that runs as
// another user and owns the database.
package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// The scanner.sandbox and scanner.landlock modes. Auto confines scanner
// processes when the runtime allows it and otherwise starts them as before.
// Required refuses to start scanner work without confinement. Off never
// confines them; scanner.sandbox off also turns off Landlock.
const (
	ModeAuto     = "auto"
	ModeRequired = "required"
	ModeOff      = "off"
)

// The states a Status reports.
const (
	StateEnforced    = "enforced"
	StateDisabled    = "disabled"
	StateUnavailable = "unavailable"
)

// UID and GID identify confined scanner processes. They own no file in the
// image or the data directory; the container runtime matrix tests the image
// with the same unprivileged identity.
const (
	UID = 65532
	GID = 65532
)

// The resource limits of a scanner process restricted with Landlock, which
// the sandbox-exec command sets before it restricts the process.
const (
	// ScannerOOMScoreAdj is the oom_score_adj of a restricted scanner
	// process, the highest there is: when memory runs out, the kernel's
	// out-of-memory killer stops a scanner before the daemon, which every
	// business unit shares.
	ScannerOOMScoreAdj = 1000
	// ScannerMaxOpenFiles bounds the descriptors a restricted scanner process
	// can hold, and so the sockets it can open at once. Nmap raises its own
	// soft limit to the hard limit; Naabu holds about one socket for each of
	// at most 1024 workers.
	ScannerMaxOpenFiles = 65536
)

// NotifierUID and NotifierGID identify the confined notification process. It
// has an identity of its own, so a compromised scanner process can neither
// signal it nor read the destination URL from its memory.
const (
	NotifierUID = 65531
	NotifierGID = 65531
)

// Profile names the kind of process a policy confines.
type Profile string

const (
	// Scanner confines Nmap and Naabu as UID and GID, with the raw-packet
	// capabilities the daemon holds.
	Scanner Profile = "scanner"
	// Notifier confines the notification process as NotifierUID and
	// NotifierGID, without capabilities and without any file it can write.
	Notifier Profile = "notifier"
)

// profileSpec describes how a profile confines its processes.
type profileSpec struct {
	uid, gid int
	// keepsNetwork keeps the raw-packet capabilities the daemon holds.
	keepsNetwork bool
	// processes names the confined processes, and testProcess the probe that
	// confirms the identity change, in reasons.
	processes, testProcess string
	// sandboxSetting and landlockSetting select the identity and Landlock
	// modes.
	sandboxSetting, landlockSetting string
}

func (profile Profile) spec() profileSpec {
	if profile == Notifier {
		return profileSpec{
			uid: NotifierUID, gid: NotifierGID, processes: "the notification process", testProcess: "a test notification process",
			sandboxSetting: "notifications.sandbox", landlockSetting: "notifications.sandbox",
		}
	}
	return profileSpec{
		uid: UID, gid: GID, keepsNetwork: true, processes: "scanner processes", testProcess: "a test process",
		sandboxSetting: "scanner.sandbox", landlockSetting: "scanner.landlock",
	}
}

func (profile Profile) valid() bool {
	return profile == Scanner || profile == Notifier
}

func profileOrScanner(profile Profile) Profile {
	if profile == "" {
		return Scanner
	}
	return profile
}

// seccompWithoutLandlock is why the seccomp filter does not apply: the
// sandbox-exec command that installs it runs only with Landlock.
const seccompWithoutLandlock = "the seccomp filter applies only with Landlock"

// ExecCommand is the hidden EdgeWatch command through which a process
// restricted with Landlock starts.
const ExecCommand = "sandbox-exec"

// ErrUnavailable reports that a sandbox setting, such as scanner.sandbox, is
// required but the processes cannot be confined that way.
var ErrUnavailable = errors.New("the sandbox is unavailable")

// Status describes how the processes of a profile start.
type Status struct {
	// Mode is the configured mode, such as scanner.sandbox.
	Mode string `json:"mode"`
	// State is enforced, disabled, or unavailable.
	State string `json:"state"`
	// UID and GID are the identity of the confined processes.
	UID int `json:"uid,omitempty"`
	GID int `json:"gid,omitempty"`
	// ProcessUID is the UID the processes run as: UID when confined,
	// otherwise the daemon's own.
	ProcessUID int `json:"process_uid"`
	// Capabilities are the capabilities a confined process keeps.
	Capabilities []string `json:"capabilities,omitempty"`
	// NoNewPrivileges reports whether the processes run with
	// no_new_privs: the daemon's, which they inherit, or the one the Landlock
	// restriction sets.
	NoNewPrivileges bool `json:"no_new_privileges,omitempty"`
	// Reason explains a disabled or unavailable sandbox.
	Reason string `json:"reason,omitempty"`
	// Landlock describes the restriction of the files the processes can
	// open.
	Landlock LandlockStatus `json:"landlock"`
	// Seccomp describes the filter of the system calls the processes can
	// make, which the Landlock restriction installs.
	Seccomp SeccompStatus `json:"seccomp"`
	// Limits are the resource limits the Landlock restriction gives scanner
	// processes. Nil when it does not apply them.
	Limits *ProcessLimits `json:"limits,omitempty"`
}

// ProcessLimits are the resource limits of a restricted scanner process.
type ProcessLimits struct {
	// OOMScoreAdj is the process's oom_score_adj.
	OOMScoreAdj int `json:"oom_score_adj"`
	// MaxOpenFiles is the most descriptors the process can hold.
	MaxOpenFiles int `json:"max_open_files"`
}

// SeccompStatus describes the seccomp filter of the processes.
type SeccompStatus struct {
	// State is enforced, disabled, or unavailable.
	State string `json:"state"`
	// Reason explains a disabled or unavailable filter.
	Reason string `json:"reason,omitempty"`
}

// LandlockStatus describes how the files the processes can open are
// restricted.
type LandlockStatus struct {
	// Mode is the configured Landlock mode, such as scanner.landlock.
	Mode string `json:"mode"`
	// State is enforced, disabled, or unavailable.
	State string `json:"state"`
	// ABI is the kernel's Landlock ABI version, which decides the access
	// rights the restriction covers.
	ABI int `json:"abi,omitempty"`
	// Reason explains a disabled or unavailable restriction.
	Reason string `json:"reason,omitempty"`
}

// Options configures Detect.
type Options struct {
	// Profile is the kind of process to confine. Empty is Scanner.
	Profile Profile
	// Mode is the identity mode, such as scanner.sandbox.
	Mode string
	// Landlock is the Landlock mode, such as scanner.landlock.
	Landlock string
	// IdentityProbe is the command Detect runs as the confined identity,
	// without Landlock, to confirm that the runtime allows the identity
	// change. Empty runs the EdgeWatch version command.
	IdentityProbe Probe
	// Probes are commands, such as a scanner's version command, that Detect
	// runs confined as the processes would be, to confirm that each can
	// start and work with the Landlock restriction.
	Probes []Probe
}

// Probe is a short-lived command that Detect runs confined. A probe whose
// executable does not exist is skipped.
type Probe struct {
	// Name names the probed process in reasons. Empty uses the
	// executable's name.
	Name string
	// Args is the command and its arguments. With Self, they are the
	// arguments of the EdgeWatch executable.
	Args []string
	Self bool
	// Env is the command's environment. Nil gives it only a fixed PATH and
	// HOME.
	Env []string
}

// The platform hooks. Only Linux installs them, because the sandbox relies on
// Linux identity changes, ambient capabilities, and Landlock; elsewhere Detect
// reports the sandbox as unavailable, Confine leaves commands unchanged, and
// Exec fails.
var (
	detectPlatform func(options Options) *Policy
	confineProcess func(cmd *exec.Cmd, uid, gid int, ambient []uintptr)
	nameCapability func(capability uintptr) string
	execRestricted func(args []string) error
	hardenProcess  func() error
)

// HardenProcess keeps the calling process, and every process it starts, from
// dumping core, and makes the calling process non-dumpable, so that a process
// of the same identity without CAP_SYS_PTRACE can neither trace it nor read
// its memory. A core dump of the daemon, the notification process, or a
// scanner would hold the keys, a destination URL, or scan data, and the
// host's core handler would keep it outside the container. Elsewhere than
// Linux it does nothing.
func HardenProcess() error {
	if hardenProcess == nil {
		return nil
	}
	return hardenProcess()
}

// Detect decides how the processes of a profile start in this runtime for the
// configured modes. Unless a mode is off, it starts short-lived confined
// processes to confirm that the runtime allows the identity change, the
// capabilities, and the Landlock restriction.
func Detect(options Options) *Policy {
	options.Profile = profileOrScanner(options.Profile)
	options.Mode = normalizedMode(options.Mode)
	options.Landlock = normalizedMode(options.Landlock)
	if detectPlatform != nil {
		return detectPlatform(options)
	}
	spec := options.Profile.spec()
	status := Status{
		Mode: options.Mode, State: StateUnavailable, ProcessUID: os.Geteuid(), Reason: "the sandbox requires Linux",
		Landlock: LandlockStatus{Mode: options.Landlock, State: StateUnavailable, Reason: "Landlock requires Linux"},
		Seccomp:  SeccompStatus{State: StateUnavailable, Reason: seccompWithoutLandlock},
	}
	switch {
	case options.Mode == ModeOff:
		status.State, status.Reason = StateDisabled, spec.sandboxSetting+" is off"
		status.Landlock.State, status.Landlock.Reason = StateDisabled, spec.sandboxSetting+" is off"
	case options.Landlock == ModeOff:
		status.Landlock.State, status.Landlock.Reason = StateDisabled, spec.landlockSetting+" is off"
	}
	return &Policy{profile: options.Profile, status: status}
}

// Exec runs the sandbox-exec command: it restricts its own process with
// Landlock and then executes the program in its place. It returns only when
// the program cannot be started.
func Exec(args []string) error {
	if execRestricted == nil {
		return errors.New(ExecCommand + " requires Linux")
	}
	return execRestricted(args)
}

// Confine makes cmd start its process confined. Call it after InheritFile:
// a process restricted with Landlock can reopen only the files it inherits by
// then, and creates no file. Confine keeps any process attributes already
// set, such as the session and controlling terminal of a pseudo-terminal.
// When the policy confines nothing, cmd is unchanged.
func (p *Policy) Confine(cmd *exec.Cmd) {
	p.confine(cmd, false)
}

// ConfineWithTemporaryFiles is Confine for a scanner process that keeps
// temporary files of its own, such as Naabu: the Landlock restriction also
// lets it create, change, and remove files below /tmp, none of which it can
// execute.
func (p *Policy) ConfineWithTemporaryFiles(cmd *exec.Cmd) {
	p.confine(cmd, true)
}

func (p *Policy) confine(cmd *exec.Cmd, temporary bool) {
	if p == nil {
		return
	}
	if p.enforce && confineProcess != nil {
		spec := p.profileName().spec()
		confineProcess(cmd, spec.uid, spec.gid, p.ambient)
	}
	if p.helper != "" {
		startThroughHelper(cmd, p.helper, p.profileName(), p.seccomp, temporary && p.profileName() == Scanner)
	}
}

// startThroughHelper makes cmd start the sandbox-exec command of the EdgeWatch
// executable helper, which restricts itself for profile, with /tmp when
// temporary is set and the seccomp filter when seccomp is set, and then
// executes cmd's program with cmd's arguments and the descriptors cmd
// passes. A program that does not exist makes cmd's start fail with that
// error instead, so callers still recognize a missing scanner, and never
// starts it without the restriction.
func startThroughHelper(cmd *exec.Cmd, helper string, profile Profile, seccomp, temporary bool) {
	if cmd.Err != nil {
		return
	}
	if _, err := os.Stat(cmd.Path); err != nil {
		cmd.Err = err
		return
	}
	args := []string{helper, ExecCommand, "--profile", string(profile), "--files", strconv.Itoa(len(cmd.ExtraFiles))}
	if temporary {
		args = append(args, "--tmp")
	}
	if seccomp {
		args = append(args, "--seccomp")
	}
	args = append(args, "--", cmd.Path)
	cmd.Args = append(args, cmd.Args[1:]...)
	cmd.Path = helper
}

func capabilityName(capability uintptr) string {
	if nameCapability != nil {
		return nameCapability(capability)
	}
	return fmt.Sprintf("CAP_%d", capability)
}

// Policy decides how the processes of a profile start. A nil Policy, like a
// policy that confines nothing, starts them unconfined.
type Policy struct {
	profile Profile
	status  Status
	enforce bool
	ambient []uintptr
	// helper is the EdgeWatch executable whose sandbox-exec command restricts
	// the processes with Landlock. Empty starts them without it.
	helper string
	// seccomp makes sandbox-exec also install the seccomp filter.
	seccomp bool
}

func (p *Policy) profileName() Profile {
	if p == nil {
		return Scanner
	}
	return profileOrScanner(p.profile)
}

// Access is how a confined process uses a file it inherits.
type Access int

const (
	// Read lets the process open the file for reading.
	Read Access = iota
	// Write lets the process open the file for writing.
	Write
)

// ValidMode reports whether mode is a scanner.sandbox value. The empty value
// is auto.
func ValidMode(mode string) bool {
	switch normalizedMode(mode) {
	case ModeAuto, ModeRequired, ModeOff:
		return true
	default:
		return false
	}
}

func normalizedMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return ModeAuto
	}
	return mode
}

// NewEnforced returns a policy that confines scanner processes with the given
// ambient capabilities, without Landlock and without checking that the
// runtime allows it. Detect is the entry point that checks.
func NewEnforced(ambient ...uintptr) *Policy {
	return NewEnforcedFor(Scanner, ambient...)
}

// NewEnforcedFor returns a policy that confines the processes of profile as
// its identity with the given ambient capabilities, without Landlock and
// without checking that the runtime allows it.
func NewEnforcedFor(profile Profile, ambient ...uintptr) *Policy {
	profile = profileOrScanner(profile)
	spec := profile.spec()
	names := make([]string, 0, len(ambient))
	for _, capability := range ambient {
		names = append(names, capabilityName(capability))
	}
	return &Policy{
		profile: profile,
		status: Status{
			Mode: ModeAuto, State: StateEnforced, UID: spec.uid, GID: spec.gid, ProcessUID: spec.uid, Capabilities: names,
			Landlock: LandlockStatus{Mode: ModeOff, State: StateDisabled, Reason: spec.landlockSetting + " is off"},
			Seccomp:  SeccompStatus{State: StateDisabled, Reason: seccompWithoutLandlock},
		},
		enforce: true,
		ambient: append([]uintptr(nil), ambient...),
	}
}

// WithLandlock returns a copy of p that also starts its processes through the
// sandbox-exec command of the EdgeWatch executable helper, which restricts
// them with Landlock ABI abi, without checking that the kernel allows it. A
// nil p gives a policy that only restricts scanner processes with Landlock.
func (p *Policy) WithLandlock(helper string, abi int) *Policy {
	restricted := &Policy{profile: Scanner, status: Status{Mode: ModeOff, State: StateDisabled, ProcessUID: os.Geteuid(), Reason: "scanner.sandbox is off"}}
	if p != nil {
		copied := *p
		copied.status.Capabilities = append([]string(nil), p.status.Capabilities...)
		copied.ambient = append([]uintptr(nil), p.ambient...)
		restricted = &copied
	}
	restricted.helper = helper
	restricted.seccomp = false
	restricted.status.NoNewPrivileges = true
	restricted.status.Landlock = LandlockStatus{Mode: ModeAuto, State: StateEnforced, ABI: abi}
	restricted.status.Seccomp = SeccompStatus{State: StateUnavailable, Reason: "the seccomp filter was not requested"}
	restricted.status.Limits = nil
	if restricted.profileName() == Scanner {
		restricted.status.Limits = &ProcessLimits{OOMScoreAdj: ScannerOOMScoreAdj, MaxOpenFiles: ScannerMaxOpenFiles}
	}
	return restricted
}

// WithSeccomp returns a copy of p, which must restrict its processes with
// Landlock, whose sandbox-exec command also installs the seccomp filter,
// without checking that the kernel allows it.
func (p *Policy) WithSeccomp() *Policy {
	filtered := *p
	filtered.status.Capabilities = append([]string(nil), p.status.Capabilities...)
	filtered.ambient = append([]uintptr(nil), p.ambient...)
	filtered.seccomp = true
	filtered.status.Seccomp = SeccompStatus{State: StateEnforced}
	return &filtered
}

// Enforced reports whether the processes start as the confined identity with
// only the ambient capabilities.
func (p *Policy) Enforced() bool {
	return p != nil && p.enforce
}

// Restricted reports whether the processes start restricted with Landlock.
func (p *Policy) Restricted() bool {
	return p != nil && p.helper != ""
}

// InheritsFiles reports whether scanner processes open their private files
// through inherited descriptors, because the confined identity or the
// Landlock restriction keeps them out of the scanner's temporary directory.
func (p *Policy) InheritsFiles() bool {
	return p.Enforced() || p.Restricted()
}

// Status reports how the processes start.
func (p *Policy) Status() Status {
	if p == nil {
		return Status{
			Mode: ModeOff, State: StateDisabled, ProcessUID: os.Geteuid(), Reason: "the processes are not confined",
			Landlock: LandlockStatus{Mode: ModeOff, State: StateDisabled, Reason: "the processes are not confined"},
			Seccomp:  SeccompStatus{State: StateDisabled, Reason: "the processes are not confined"},
		}
	}
	status := p.status
	status.Capabilities = append([]string(nil), p.status.Capabilities...)
	if p.status.Limits != nil {
		limits := *p.status.Limits
		status.Limits = &limits
	}
	return status
}

// Require reports ErrUnavailable, with the reason, when the identity or the
// Landlock mode is required and the processes cannot be confined that way.
func (p *Policy) Require() error {
	if p == nil {
		return nil
	}
	spec := p.profileName().spec()
	if p.status.Mode == ModeRequired && !p.enforce {
		return fmt.Errorf("%w: %s; set %s to auto to start %s unconfined", ErrUnavailable, p.status.Reason, spec.sandboxSetting, spec.processes)
	}
	if p.status.Landlock.Mode == ModeRequired && p.helper == "" {
		return fmt.Errorf("%w: %s; set %s to auto to start %s without Landlock", ErrUnavailable, p.status.Landlock.Reason, spec.landlockSetting, spec.processes)
	}
	return nil
}

// InheritFile passes f to the process cmd starts and returns the path by which
// that process opens it. A confined process cannot reach the scanner's
// temporary directory inside the data directory, so it opens the file through
// its inherited descriptor. For the confined identity, the file's
// other-permission bits allow exactly the access it needs; the Landlock
// restriction lets the process reopen the file with the access f was opened
// with, so open f read-only for Read and write-only for Write. The caller
// keeps f open until the process has exited. When the policy confines
// nothing, the process opens f by its name, as before.
func (p *Policy) InheritFile(cmd *exec.Cmd, f *os.File, access Access) (string, error) {
	if !p.InheritsFiles() {
		return f.Name(), nil
	}
	if p.enforce {
		mode := os.FileMode(0o604)
		if access == Write {
			mode = 0o602
		}
		if err := f.Chmod(mode); err != nil {
			return "", fmt.Errorf("share scanner file: %w", err)
		}
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, f)
	return fmt.Sprintf("/dev/fd/%d", 2+len(cmd.ExtraFiles)), nil
}
