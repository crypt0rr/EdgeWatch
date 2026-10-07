// Package sandbox starts scanner processes as an unprivileged identity that
// keeps only the network capabilities a scan needs.
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
package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// The scanner.sandbox modes. Auto confines scanner processes when the runtime
// allows it and otherwise starts them as before, with a warning. Required
// refuses to start scanner work without confinement. Off never confines them.
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

// ErrUnavailable reports that scanner.sandbox is required but scanner
// processes cannot be confined.
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
	// NoNewPrivileges reports whether the daemon runs with no_new_privs,
	// which every scanner process inherits.
	NoNewPrivileges bool `json:"no_new_privileges,omitempty"`
	// Reason explains a disabled or unavailable sandbox.
	Reason string `json:"reason,omitempty"`
}

// Policy decides how scanner processes start. A nil Policy, like a policy
// that is not enforced, starts them unconfined.
type Policy struct {
	status  Status
	enforce bool
	ambient []uintptr
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
// ambient capabilities, without checking that the runtime allows it. Detect
// is the entry point that checks.
func NewEnforced(ambient ...uintptr) *Policy {
	names := make([]string, 0, len(ambient))
	for _, capability := range ambient {
		names = append(names, capabilityName(capability))
	}
	return &Policy{
		status:  Status{Mode: ModeAuto, State: StateEnforced, UID: UID, GID: GID, ProcessUID: UID, Capabilities: names},
		enforce: true,
		ambient: append([]uintptr(nil), ambient...),
	}
}

// Enforced reports whether scanner processes start confined.
func (p *Policy) Enforced() bool {
	return p != nil && p.enforce
}

// Status reports how scanner processes start.
func (p *Policy) Status() Status {
	if p == nil {
		return Status{Mode: ModeOff, State: StateDisabled, ProcessUID: os.Geteuid(), Reason: "scanner processes are not confined"}
	}
	status := p.status
	status.Capabilities = append([]string(nil), p.status.Capabilities...)
	return status
}

// Require reports ErrUnavailable, with the reason, when scanner.sandbox is
// required and scanner processes cannot be confined.
func (p *Policy) Require() error {
	if p == nil || p.status.Mode != ModeRequired || p.enforce {
		return nil
	}
	return fmt.Errorf("%w: %s; set scanner.sandbox to auto to start scanner processes unconfined", ErrUnavailable, p.status.Reason)
}

// InheritFile passes f to the process cmd starts and returns the path by which
// that process opens it. A confined process cannot reach the scanner's
// temporary directory inside the data directory, so it opens the file through
// its inherited descriptor, and the file's other-permission bits allow exactly
// the access it needs. The caller keeps f open until the process has exited.
// When the policy is not enforced, the process opens f by its name, as
// before.
func (p *Policy) InheritFile(cmd *exec.Cmd, f *os.File, access Access) (string, error) {
	if !p.Enforced() {
		return f.Name(), nil
	}
	mode := os.FileMode(0o604)
	if access == Write {
		mode = 0o602
	}
	if err := f.Chmod(mode); err != nil {
		return "", fmt.Errorf("share scanner file: %w", err)
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, f)
	return fmt.Sprintf("/dev/fd/%d", 2+len(cmd.ExtraFiles)), nil
}
