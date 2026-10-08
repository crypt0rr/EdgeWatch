// Package sandbox starts scanner processes as an unprivileged identity that
// keeps only the network capabilities a scan needs, and restricts the files
// they can open with Landlock.
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

// ExecCommand is the hidden EdgeWatch command through which a scanner process
// restricted with Landlock starts.
const ExecCommand = "sandbox-exec"

// ErrUnavailable reports that scanner.sandbox or scanner.landlock is required
// but scanner processes cannot be confined that way.
var ErrUnavailable = errors.New("the scanner sandbox is unavailable")

// Status describes how scanner processes start.
type Status struct {
	// Mode is the configured scanner.sandbox mode.
	Mode string `json:"mode"`
	// State is enforced, disabled, or unavailable.
	State string `json:"state"`
	// UID and GID are the identity of confined scanner processes.
	UID int `json:"uid,omitempty"`
	GID int `json:"gid,omitempty"`
	// ProcessUID is the UID scanner processes run as: UID when confined,
	// otherwise the daemon's own.
	ProcessUID int `json:"process_uid"`
	// Capabilities are the capabilities a confined scanner process keeps.
	Capabilities []string `json:"capabilities,omitempty"`
	// NoNewPrivileges reports whether scanner processes run with
	// no_new_privs: the daemon's, which they inherit, or the one the Landlock
	// restriction sets.
	NoNewPrivileges bool `json:"no_new_privileges,omitempty"`
	// Reason explains a disabled or unavailable sandbox.
	Reason string `json:"reason,omitempty"`
	// Landlock describes the restriction of the files scanner processes can
	// open.
	Landlock LandlockStatus `json:"landlock"`
}

// LandlockStatus describes how the files scanner processes can open are
// restricted.
type LandlockStatus struct {
	// Mode is the configured scanner.landlock mode.
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
	// Mode is the scanner.sandbox mode.
	Mode string
	// Landlock is the scanner.landlock mode.
	Landlock string
	// Probes are scanner commands, such as a version command, that Detect
	// runs confined as scanner processes would be, to confirm that each
	// scanner can start with the Landlock restriction. A probe whose
	// executable does not exist is skipped.
	Probes [][]string
}

// The platform hooks. Only Linux installs them, because the sandbox relies on
// Linux identity changes, ambient capabilities, and Landlock; elsewhere Detect
// reports the sandbox as unavailable, Confine leaves commands unchanged, and
// Exec fails.
var (
	detectPlatform func(options Options) *Policy
	confineProcess func(cmd *exec.Cmd, ambient []uintptr)
	nameCapability func(capability uintptr) string
	execRestricted func(args []string) error
)

// Detect decides how scanner processes start in this runtime for the
// configured scanner.sandbox and scanner.landlock modes. Unless a mode is off,
// it starts short-lived confined processes to confirm that the runtime allows
// the identity change, the capabilities, and the Landlock restriction.
func Detect(options Options) *Policy {
	options.Mode = normalizedMode(options.Mode)
	options.Landlock = normalizedMode(options.Landlock)
	if detectPlatform != nil {
		return detectPlatform(options)
	}
	status := Status{
		Mode: options.Mode, State: StateUnavailable, ProcessUID: os.Geteuid(), Reason: "the scanner sandbox requires Linux",
		Landlock: LandlockStatus{Mode: options.Landlock, State: StateUnavailable, Reason: "Landlock requires Linux"},
	}
	switch {
	case options.Mode == ModeOff:
		status.State, status.Reason = StateDisabled, "scanner.sandbox is off"
		status.Landlock.State, status.Landlock.Reason = StateDisabled, "scanner.sandbox is off"
	case options.Landlock == ModeOff:
		status.Landlock.State, status.Landlock.Reason = StateDisabled, "scanner.landlock is off"
	}
	return &Policy{status: status}
}

// Exec runs the sandbox-exec command: it restricts its own process with
// Landlock and then executes the scanner in its place. It returns only when
// the scanner cannot be started.
func Exec(args []string) error {
	if execRestricted == nil {
		return errors.New(ExecCommand + " requires Linux")
	}
	return execRestricted(args)
}

// Confine makes cmd start its process confined. Call it after InheritFile:
// a process restricted with Landlock can reopen only the files it inherits by
// then. Confine keeps any process attributes already set, such as the session
// and controlling terminal of a pseudo-terminal. When the policy confines
// nothing, cmd is unchanged.
func (p *Policy) Confine(cmd *exec.Cmd) {
	if p == nil {
		return
	}
	if p.enforce && confineProcess != nil {
		confineProcess(cmd, p.ambient)
	}
	if p.helper != "" {
		startThroughHelper(cmd, p.helper)
	}
}

// startThroughHelper makes cmd start the sandbox-exec command of the EdgeWatch
// executable helper, which restricts itself and then executes cmd's program
// with cmd's arguments and the descriptors cmd passes. A program that does
// not exist makes cmd's start fail with that error instead, so callers still
// recognize a missing scanner, and never starts it without the restriction.
func startThroughHelper(cmd *exec.Cmd, helper string) {
	if cmd.Err != nil {
		return
	}
	if _, err := os.Stat(cmd.Path); err != nil {
		cmd.Err = err
		return
	}
	args := []string{helper, ExecCommand, "--files", strconv.Itoa(len(cmd.ExtraFiles)), "--", cmd.Path}
	cmd.Args = append(args, cmd.Args[1:]...)
	cmd.Path = helper
}

func capabilityName(capability uintptr) string {
	if nameCapability != nil {
		return nameCapability(capability)
	}
	return fmt.Sprintf("CAP_%d", capability)
}

// Policy decides how scanner processes start. A nil Policy, like a policy
// that confines nothing, starts them unconfined.
type Policy struct {
	status  Status
	enforce bool
	ambient []uintptr
	// helper is the EdgeWatch executable whose sandbox-exec command restricts
	// scanner processes with Landlock. Empty starts them without it.
	helper string
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
	names := make([]string, 0, len(ambient))
	for _, capability := range ambient {
		names = append(names, capabilityName(capability))
	}
	return &Policy{
		status: Status{
			Mode: ModeAuto, State: StateEnforced, UID: UID, GID: GID, ProcessUID: UID, Capabilities: names,
			Landlock: LandlockStatus{Mode: ModeOff, State: StateDisabled, Reason: "scanner.landlock is off"},
		},
		enforce: true,
		ambient: append([]uintptr(nil), ambient...),
	}
}

// WithLandlock returns a copy of p that also starts scanner processes through
// the sandbox-exec command of the EdgeWatch executable helper, which restricts
// them with Landlock ABI abi, without checking that the kernel allows it. A
// nil p gives a policy that only restricts them with Landlock.
func (p *Policy) WithLandlock(helper string, abi int) *Policy {
	restricted := &Policy{status: Status{Mode: ModeOff, State: StateDisabled, ProcessUID: os.Geteuid(), Reason: "scanner.sandbox is off"}}
	if p != nil {
		copied := *p
		copied.status.Capabilities = append([]string(nil), p.status.Capabilities...)
		copied.ambient = append([]uintptr(nil), p.ambient...)
		restricted = &copied
	}
	restricted.helper = helper
	restricted.status.NoNewPrivileges = true
	restricted.status.Landlock = LandlockStatus{Mode: ModeAuto, State: StateEnforced, ABI: abi}
	return restricted
}

// Enforced reports whether scanner processes start as the confined identity
// with only the ambient capabilities.
func (p *Policy) Enforced() bool {
	return p != nil && p.enforce
}

// Restricted reports whether scanner processes start restricted with
// Landlock.
func (p *Policy) Restricted() bool {
	return p != nil && p.helper != ""
}

// InheritsFiles reports whether scanner processes open their private files
// through inherited descriptors, because the confined identity or the
// Landlock restriction keeps them out of the scanner's temporary directory.
func (p *Policy) InheritsFiles() bool {
	return p.Enforced() || p.Restricted()
}

// Status reports how scanner processes start.
func (p *Policy) Status() Status {
	if p == nil {
		return Status{
			Mode: ModeOff, State: StateDisabled, ProcessUID: os.Geteuid(), Reason: "scanner processes are not confined",
			Landlock: LandlockStatus{Mode: ModeOff, State: StateDisabled, Reason: "scanner processes are not confined"},
		}
	}
	status := p.status
	status.Capabilities = append([]string(nil), p.status.Capabilities...)
	return status
}

// Require reports ErrUnavailable, with the reason, when scanner.sandbox or
// scanner.landlock is required and scanner processes cannot be confined that
// way.
func (p *Policy) Require() error {
	if p == nil {
		return nil
	}
	if p.status.Mode == ModeRequired && !p.enforce {
		return fmt.Errorf("%w: %s; set scanner.sandbox to auto to start scanner processes unconfined", ErrUnavailable, p.status.Reason)
	}
	if p.status.Landlock.Mode == ModeRequired && p.helper == "" {
		return fmt.Errorf("%w: %s; set scanner.landlock to auto to start scanner processes without Landlock", ErrUnavailable, p.status.Landlock.Reason)
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
