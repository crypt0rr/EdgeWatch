//go:build !linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
)

// Detect reports that scanner processes cannot be confined: the sandbox
// relies on Linux identity changes and ambient capabilities.
func Detect(mode string) *Policy {
	mode = normalizedMode(mode)
	if mode == ModeOff {
		return &Policy{status: Status{Mode: mode, State: StateDisabled, ProcessUID: os.Geteuid(), Reason: "scanner.sandbox is off"}}
	}
	return &Policy{status: Status{Mode: mode, State: StateUnavailable, ProcessUID: os.Geteuid(), Reason: "the scanner sandbox requires Linux"}}
}

// Confine leaves cmd unchanged; scanner processes are never confined outside
// Linux.
func (p *Policy) Confine(*exec.Cmd) {}

func capabilityName(capability uintptr) string {
	return fmt.Sprintf("CAP_%d", capability)
}
