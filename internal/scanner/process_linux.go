//go:build linux

package scanner

import (
	"errors"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func init() {
	waitForProcessExit = waitWithoutReaping
	setParentDeathSignal = killWithParent
}

// killWithParent sets the parent-death signal to SIGKILL. The kernel keeps it
// across the sandbox's change of identity, which the child makes before it
// sets the signal, and across the executions of sandbox-exec and the
// scanner, which are neither set-user-ID nor file-capability programs. It
// fires when the thread that started the scanner exits; the daemon has no
// goroutine that ends while it holds a thread of its own.
func killWithParent(attrs *syscall.SysProcAttr) {
	attrs.Pdeathsig = syscall.SIGKILL
}

// waitWithoutReaping is waitForProcessExit. The exited process keeps its
// process ID, and so its process group's, until cmd.Wait reaps it, so
// stopping the group meanwhile cannot reach a process that reused the ID.
// Elsewhere than Linux a process cannot be waited for without reaping it, so
// a scanner's process group is then stopped only when the scan is cancelled
// or exceeds a bound.
func waitWithoutReaping(cmd *exec.Cmd) bool {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, cmd.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if !errors.Is(err, unix.EINTR) {
			return err == nil
		}
	}
}
