package scanner

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/creack/pty"
)

// scannerWaitDelay bounds how long an invocation waits, after a scanner has
// exited or been stopped, for every one of the scanner's outputs to close:
// its pipes and Nmap's terminal share the one deadline. A process that still
// holds an output then can only be one that left the scanner's process
// group, and the invocation fails rather than waiting for it.
const scannerWaitDelay = 5 * time.Second

// The platform hooks. Unix installs them; elsewhere a scanner starts without a
// process group of its own or a pseudo-terminal, stopping it stops it alone,
// and the directory of a process's scan files is neither checked nor locked.
var (
	// processGroupAttributes returns a copy of attrs that starts the
	// process as the leader of a new process group: of a new session whose
	// controlling terminal is the process's standard input when session is
	// set.
	processGroupAttributes = func(attrs *syscall.SysProcAttr, _ bool) *syscall.SysProcAttr { return attrs }
	// killProcessGroup kills every process of the group that process leads.
	killProcessGroup = func(process *os.Process) error { return process.Kill() }
	// waitForProcessExit blocks until cmd's process has exited, without
	// reaping it, and reports whether it did.
	waitForProcessExit = func(*exec.Cmd) bool { return false }
	// openTerminal opens the private pseudo-terminal that runNmapInvocation
	// starts Nmap on. Tests replace it to make it fail.
	openTerminal = func(*pty.Winsize) (*os.File, *os.File, error) {
		return nil, nil, errors.New("pseudo-terminals require Unix")
	}
	// ownedByCurrentUser reports whether this process's effective user owns
	// the file info describes.
	ownedByCurrentUser = func(os.FileInfo) bool { return true }
	// lockDirectory takes an exclusive lock on the directory dir, which it
	// holds until the returned file is closed or the process exits.
	lockDirectory = os.Open
	// directoryLocked reports whether another process holds the lock that
	// lockDirectory takes on dir.
	directoryLocked = func(string) (bool, error) { return true, nil }
)

// startInProcessGroup makes cmd start its scanner as the leader of a process
// group of its own, in a new session with a controlling terminal when
// session is set, so that stopping the scanner also stops every process it
// started. It copies the process attributes that the sandbox set, such as
// the identity and the ambient capabilities, rather than changing them in
// place. Cancellation stops the whole group, and cmd.Wait waits at most
// scannerWaitDelay for the output pipes after the scanner has gone.
func startInProcessGroup(cmd *exec.Cmd, session bool) {
	cmd.SysProcAttr = processGroupAttributes(cmd.SysProcAttr, session)
	if cmd.Cancel != nil {
		cmd.Cancel = func() error { return stopProcessGroup(cmd) }
	}
	cmd.WaitDelay = scannerWaitDelay
}

// stopProcessGroup kills cmd's scanner and every process of its process
// group.
func stopProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return killProcessGroup(cmd.Process)
}

// waitProcessGroup waits for cmd's scanner to exit, kills whatever else is
// still in its process group, such as a background process that ignores the
// hangup of the scanner's terminal, and then reaps the scanner. A scanner
// that exits normally leaves nothing behind, so this changes nothing for it.
func waitProcessGroup(cmd *exec.Cmd) error {
	_, err := waitProcessGroupUntil(cmd)
	return err
}

// waitProcessGroupUntil is waitProcessGroup, and also returns the deadline by
// which the scanner's other outputs, such as Nmap's terminal, must close:
// scannerWaitDelay after the scanner exited, the deadline cmd.Wait gives its
// pipes. Where the exit cannot be observed before cmd.Wait reaps the
// scanner, the deadline counts from then.
func waitProcessGroupUntil(cmd *exec.Cmd) (time.Time, error) {
	exited := cmd.Process != nil && waitForProcessExit(cmd)
	exitedAt := time.Now()
	if exited {
		_ = stopProcessGroup(cmd)
	}
	err := cmd.Wait()
	if !exited {
		exitedAt = time.Now()
	}
	return exitedAt.Add(scannerWaitDelay), err
}
