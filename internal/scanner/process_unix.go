//go:build unix

package scanner

import (
	"errors"
	"os"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func init() {
	processGroupAttributes = unixProcessGroupAttributes
	killProcessGroup = killUnixProcessGroup
	openTerminal = openPseudoTerminal
	ownedByCurrentUser = ownedByEffectiveUser
	lockDirectory = flockDirectory
	directoryLocked = flockedDirectory
}

// setParentDeathSignal makes the kernel kill the process once the thread
// that started it is gone. Only Linux has a parent-death signal.
var setParentDeathSignal = func(*syscall.SysProcAttr) {}

// unixProcessGroupAttributes is processGroupAttributes. In its own process
// group, a scanner no longer receives the hangup or the quit of the terminal
// that EdgeWatch runs in, so on Linux it is also killed when EdgeWatch dies.
func unixProcessGroupAttributes(attrs *syscall.SysProcAttr, session bool) *syscall.SysProcAttr {
	var copied syscall.SysProcAttr
	if attrs != nil {
		copied = *attrs
	}
	setParentDeathSignal(&copied)
	if session {
		copied.Setsid, copied.Setctty, copied.Ctty = true, true, 0
		copied.Setpgid, copied.Pgid = false, 0
	} else {
		copied.Setpgid, copied.Pgid = true, 0
	}
	return &copied
}

// killUnixProcessGroup is killProcessGroup. A group that cannot be signaled
// falls back to the process itself.
func killUnixProcessGroup(process *os.Process) error {
	err := syscall.Kill(-process.Pid, syscall.SIGKILL)
	if err == nil || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return process.Kill()
}

// openPseudoTerminal opens a pseudo-terminal of the given size. pty.Open
// leaves the master in blocking mode, in which closing it waits for a
// pending read, so the master is replaced by a non-blocking duplicate:
// closing that ends a read that a process still holding the terminal would
// otherwise keep waiting.
func openPseudoTerminal(size *pty.Winsize) (master, terminal *os.File, err error) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		return nil, nil, err
	}
	defer ptmx.Close()
	fd, err := unix.FcntlInt(ptmx.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err == nil {
		err = pty.Setsize(ptmx, size)
		if err == nil {
			err = unix.SetNonblock(fd, true)
		}
		if err != nil {
			_ = unix.Close(fd)
		}
	}
	if err != nil {
		_ = tty.Close()
		return nil, nil, err
	}
	return os.NewFile(uintptr(fd), ptmx.Name()), tty, nil
}

// ownedByEffectiveUser is ownedByCurrentUser.
func ownedByEffectiveUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

// flockDirectory is lockDirectory, with flock.
func flockDirectory(dir string) (*os.File, error) {
	file, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

// flockedDirectory is directoryLocked.
func flockedDirectory(dir string) (bool, error) {
	file, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer file.Close()
	err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return true, nil
	}
	return false, err
}
