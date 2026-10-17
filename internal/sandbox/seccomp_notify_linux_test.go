//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestReceiveSeccompNotificationListenerSetsCloseOnExec(t *testing.T) {
	if err := seccompNotificationSizesSupported(); err != nil {
		t.Skipf("kernel seccomp notification ABI is unavailable: %v", err)
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	if err := unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		t.Fatal(err)
	}
	passed, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer passed.Close()
	message := []byte(seccompNotificationMagic)
	n, err := unix.SendmsgN(pair[1], message, unix.UnixRights(int(passed.Fd())), nil, 0)
	if err != nil || n != len(message) {
		t.Fatalf("send listener test frame = %d bytes, %v", n, err)
	}
	listenerFD, err := receiveSeccompNotificationListener(pair[0], os.Getpid(), uint32(os.Geteuid()), uint32(os.Getegid()), time.Second)
	if err != nil {
		t.Fatalf("receive listener: %v", err)
	}
	defer unix.Close(listenerFD)
	flags, err := unix.FcntlInt(uintptr(listenerFD), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("received listener descriptor flags = %#x, %v; want FD_CLOEXEC", flags, err)
	}
}

func TestSeccompNotificationBrokerTreatsExitedFilterAsEOF(t *testing.T) {
	if err := seccompNotificationSupport(); err != nil {
		t.Skipf("kernel seccomp notification support is unavailable: %v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	liveness := scannerLivenessTestFile(t)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(pair[0]), "seccomp EOF test parent")
	childSocket := os.NewFile(uintptr(pair[1]), "seccomp EOF test child")
	if err := unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		_ = parent.Close()
		_ = childSocket.Close()
		t.Fatal(err)
	}
	command := exec.Command(executable, ExecCommand,
		"--profile", string(Scanner), "--files", "1", "--identity-only", "--seccomp",
		"--liveness-fd", "3", "--seccomp-notify-fd", "4", "--", "/bin/true")
	command.Env = []string{}
	command.Dir = "/"
	command.ExtraFiles = []*os.File{liveness, childSocket}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := command.Start(); err != nil {
		_ = parent.Close()
		_ = childSocket.Close()
		t.Fatalf("start scanner helper: %v", err)
	}
	_ = childSocket.Close()
	waited := false
	t.Cleanup(func() {
		_ = parent.Close()
		if !waited {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			_ = command.Wait()
		}
	})
	listenerFD, err := receiveSeccompNotificationListener(pair[0], command.Process.Pid,
		uint32(os.Geteuid()), uint32(os.Getegid()), scannerSupervisorTimeout)
	if err != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_ = command.Wait()
		waited = true
		t.Fatalf("receive scanner seccomp listener: %v", err)
	}
	defer unix.Close(listenerFD)
	if err := command.Wait(); err != nil {
		waited = true
		t.Fatalf("scanner helper /bin/true exit: %v", err)
	}
	waited = true
	deadline := time.Now().Add(scannerSupervisorTimeout)
	for {
		poll := []unix.PollFd{{Fd: int32(listenerFD), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
		ready, pollErr := unix.Poll(poll, 100)
		if pollErr != nil && pollErr != unix.EINTR {
			t.Fatalf("poll exited scanner filter listener: %v", pollErr)
		}
		if ready > 0 {
			if poll[0].Revents&unix.POLLHUP == 0 || poll[0].Revents&(unix.POLLIN|unix.POLLERR|unix.POLLNVAL) != 0 {
				t.Fatalf("exited scanner filter listener events = %#x, want HUP only", poll[0].Revents)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("exited scanner filter listener did not report POLLHUP")
		}
	}
	broker := seccompNotificationBroker{listenerFD: listenerFD}
	if err := broker.serveOne(); err != nil {
		t.Fatalf("closed filter listener should be ordinary EOF after child exit, got %v", err)
	}
}

func TestSeccompNotificationProbeRetriesInterruptedAddFDThenRepliesWithInjectedFD(t *testing.T) {
	if err := seccompNotificationSizesSupported(); err != nil {
		t.Skipf("kernel seccomp notification ABI is unavailable: %v", err)
	}
	addFDCalls := 0
	replyCalls := 0
	err := probeSeccompNotificationSupportWithBrokerFactory(func(listenerFD int) *seccompNotificationBroker {
		return &seccompNotificationBroker{
			listenerFD: listenerFD,
			ioctl: func(fd int, request uintptr, argument unsafe.Pointer) (uintptr, syscall.Errno) {
				switch request {
				case unix.SECCOMP_IOCTL_NOTIF_ADDFD:
					addFDCalls++
					if addFDCalls == 1 {
						// Exercise the bounded retry branch, then let the real kernel
						// inject the descriptor on the next call.
						return 0, syscall.EINTR
					}
				case unix.SECCOMP_IOCTL_NOTIF_SEND:
					replyCalls++
				}
				value, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), request, uintptr(argument))
				return value, errno
			},
		}
	})
	if err != nil {
		t.Fatalf("seccomp notification support probe with one interrupted ADDFD: %v", err)
	}
	if addFDCalls != 3 || replyCalls != 2 {
		t.Fatalf("probe ioctl counts = ADDFD %d, NOTIF_SEND %d; want 3 and 2", addFDCalls, replyCalls)
	}
}
