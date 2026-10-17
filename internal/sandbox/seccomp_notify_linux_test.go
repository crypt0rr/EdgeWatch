//go:build linux

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"strings"
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
	if err := sendSeccompNotificationListener(pair[1], int(passed.Fd())); err != nil {
		t.Fatalf("send listener: %v", err)
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

func TestSeccompNotificationDescriptorValidation(t *testing.T) {
	seqpacket, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(seqpacket[0])
	defer unix.Close(seqpacket[1])
	stream, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(stream)
	internet, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(internet)
	regular, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()

	for _, test := range []struct {
		name string
		fd   int
		want bool
	}{
		{name: "negative descriptor", fd: -1, want: true},
		{name: "regular file", fd: int(regular.Fd()), want: true},
		{name: "Unix stream", fd: stream, want: true},
		{name: "Internet datagram", fd: internet, want: true},
		{name: "Unix seqpacket", fd: seqpacket[0]},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateSeccompNotificationControlDescriptor(test.fd)
			if (err != nil) != test.want {
				t.Fatalf("validate control descriptor %d = %v, want error %v", test.fd, err, test.want)
			}
		})
	}

	closed, err := unix.Dup(int(regular.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(closed); err != nil {
		t.Fatal(err)
	}
	if err := validateScannerSocketDescriptor(closed); err != nil {
		t.Fatalf("closed inherited descriptor should be harmless: %v", err)
	}
	if err := validateScannerSocketDescriptor(int(regular.Fd())); err != nil {
		t.Fatalf("regular inherited descriptor: %v", err)
	}
	if err := validateScannerSocketDescriptor(internet); err != nil {
		t.Fatalf("Internet socket should remain available for scanning: %v", err)
	}
	if err := validateScannerSocketDescriptor(stream); err == nil {
		t.Fatal("inherited Unix socket was accepted")
	}
	if err := validateScannerSocketDescriptors(-1); err == nil {
		t.Fatal("negative inherited descriptor count was accepted")
	}
	if err := validateScannerSocketDescriptors(0); err != nil {
		t.Fatalf("standard descriptors should pass when they are not Unix sockets: %v", err)
	}
	if err := validateScannerSocketDescriptorsForRequest(execRequest{files: 0}); err != nil {
		t.Fatalf("ordinary scanner descriptor set: %v", err)
	}
	if err := validateScannerSocketDescriptorsForRequest(execRequest{files: 0, privateTemp: true, controlFD: 4}); err == nil {
		t.Fatal("invalid private temporary control descriptor layout was accepted")
	}
}

func TestValidateScannerPrivateTemporaryDescriptorContract(t *testing.T) {
	rootPath := t.TempDir()
	leafPath := t.TempDir()
	namespacePath := t.TempDir()
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	leaf, err := os.Open(leafPath)
	if err != nil {
		t.Fatal(err)
	}
	defer leaf.Close()
	namespace, err := os.Open(namespacePath)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	files := pair[0] - 5
	if files < 0 || files > maxInheritedFiles || pair[1] != pair[0]+1 {
		t.Skipf("test descriptor layout cannot fit the bounded private helper range: %v", pair)
	}
	base := execRequest{
		files: files, privateTemp: true, privateRootFD: int(root.Fd()),
		privateLeafFD: int(leaf.Fd()), controlFD: pair[0], notifyFD: pair[1],
	}
	if err := validateScannerSocketDescriptorsForRequest(base); err != nil {
		t.Fatalf("valid private leaf and listener descriptors: %v", err)
	}
	create := base
	create.privateCreate = true
	create.privateNamespaceFD = int(namespace.Fd())
	if err := validateScannerSocketDescriptorsForRequest(create); err != nil {
		t.Fatalf("valid private namespace create descriptors: %v", err)
	}
	invalidRoot := base
	regular, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	invalidRoot.privateRootFD = int(regular.Fd())
	if err := validateScannerSocketDescriptorsForRequest(invalidRoot); err == nil {
		t.Fatal("regular file was accepted as the private root directory")
	}
	invalidNotify := base
	invalidNotify.notifyFD = int(regular.Fd())
	if err := validateScannerSocketDescriptorsForRequest(invalidNotify); err == nil {
		t.Fatal("non-socket notification descriptor was accepted")
	}
}

func TestSeccompNotificationListenerSendAndProbeRejectInvalidContracts(t *testing.T) {
	listener, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := sendSeccompNotificationListener(-1, int(listener.Fd())); err == nil {
		t.Fatal("negative listener channel was accepted")
	}
	if err := sendSeccompNotificationListener(3, -1); err == nil {
		t.Fatal("negative listener descriptor was accepted")
	}
	if err := sendSeccompNotificationListener(1<<20, int(listener.Fd())); err == nil {
		t.Fatal("closed listener channel was accepted")
	}
	for _, args := range [][]string{nil, {"--wrong", "3"}, {"--control-fd", "4"}, {"--control-fd", "3", "extra"}} {
		if err := execSeccompNotificationProbe(args); err == nil {
			t.Fatalf("probe args %q were accepted", args)
		}
	}
	if err := probeSeccompNotificationSupportWithBrokerFactory(nil); err == nil {
		t.Fatal("nil broker factory was accepted")
	}
}

func TestSeccompNotificationProbeCleansUpInvalidBrokerFactory(t *testing.T) {
	if err := seccompNotificationSupport(); err != nil {
		t.Skipf("kernel seccomp notification support is unavailable: %v", err)
	}
	tests := []struct {
		name    string
		factory func(int) *seccompNotificationBroker
	}{
		{name: "nil broker", factory: func(int) *seccompNotificationBroker { return nil }},
		{name: "wrong listener", factory: func(fd int) *seccompNotificationBroker { return &seccompNotificationBroker{listenerFD: fd + 1} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := probeSeccompNotificationSupportWithBrokerFactory(test.factory)
			if err == nil || !strings.Contains(err.Error(), "invalid listener") {
				t.Fatalf("probe with invalid broker = %v, want fail-closed listener error", err)
			}
		})
	}
}

func TestReceiveSeccompNotificationListenerRejectsBadFramesAndCredentials(t *testing.T) {
	if err := seccompNotificationSizesSupported(); err != nil {
		t.Skipf("kernel seccomp notification ABI is unavailable: %v", err)
	}
	passed, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer passed.Close()
	second, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	tests := []struct {
		name      string
		message   []byte
		fds       []int
		helperPID int
		uid       uint32
		gid       uint32
		timestamp bool
	}{
		{name: "short frame", message: []byte("short"), fds: []int{int(passed.Fd())}},
		{name: "wrong magic", message: []byte("BADFRAME"), fds: []int{int(passed.Fd())}},
		{name: "missing descriptor", message: []byte(seccompNotificationMagic)},
		{name: "multiple descriptors", message: []byte(seccompNotificationMagic), fds: []int{int(passed.Fd()), int(second.Fd())}},
		{name: "unexpected timestamp control", message: []byte(seccompNotificationMagic), timestamp: true},
		{name: "wrong helper process", message: []byte(seccompNotificationMagic), fds: []int{int(passed.Fd())}, helperPID: os.Getpid() + 1},
		{name: "wrong uid", message: []byte(seccompNotificationMagic), fds: []int{int(passed.Fd())}, uid: uint32(os.Geteuid()) + 1},
		{name: "wrong gid", message: []byte(seccompNotificationMagic), fds: []int{int(passed.Fd())}, gid: uint32(os.Getegid()) + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pair[0])
			defer unix.Close(pair[1])
			if err := unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
				t.Fatal(err)
			}
			if test.timestamp {
				if err := unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err != nil {
					t.Skipf("SO_TIMESTAMPNS unavailable: %v", err)
				}
			}
			var rights []byte
			if len(test.fds) != 0 {
				rights = unix.UnixRights(test.fds...)
			}
			n, err := unix.SendmsgN(pair[1], test.message, rights, nil, 0)
			if err != nil || n != len(test.message) {
				t.Fatalf("send malformed listener frame = %d, %v", n, err)
			}
			helperPID, uid, gid := os.Getpid(), uint32(os.Geteuid()), uint32(os.Getegid())
			if test.helperPID != 0 {
				helperPID = test.helperPID
			}
			if test.uid != 0 {
				uid = test.uid
			}
			if test.gid != 0 {
				gid = test.gid
			}
			fd, err := receiveSeccompNotificationListener(pair[0], helperPID, uid, gid, time.Second)
			if err == nil {
				_ = unix.Close(fd)
				t.Fatal("malformed listener handoff was accepted")
			}
		})
	}
	if _, err := receiveSeccompNotificationListener(-1, os.Getpid(), uint32(os.Geteuid()), uint32(os.Getegid()), time.Second); err == nil {
		t.Fatal("negative listener channel was accepted")
	}
	if _, err := receiveSeccompNotificationListener(3, 0, uint32(os.Geteuid()), uint32(os.Getegid()), time.Second); err == nil {
		t.Fatal("invalid helper process was accepted")
	}
	if _, err := receiveSeccompNotificationListener(3, os.Getpid(), uint32(os.Geteuid()), uint32(os.Getegid()), 0); err == nil {
		t.Fatal("zero listener timeout was accepted")
	}
}

func TestReceiveSeccompNotificationListenerTimesOutAndRejectsClosedPeer(t *testing.T) {
	for _, test := range []struct {
		name      string
		closePeer bool
		timeout   time.Duration
	}{
		{name: "empty channel timeout", timeout: time.Millisecond},
		{name: "closed helper channel", closePeer: true, timeout: time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pair[0])
			if !test.closePeer {
				defer unix.Close(pair[1])
			} else if err := unix.Close(pair[1]); err != nil {
				t.Fatal(err)
			}
			if err := unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
				t.Fatal(err)
			}
			if fd, err := receiveSeccompNotificationListener(pair[0], os.Getpid(), uint32(os.Geteuid()), uint32(os.Getegid()), test.timeout); err == nil {
				_ = unix.Close(fd)
				t.Fatal("listener receive succeeded without a valid helper frame")
			}
		})
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

func TestSeccompNotificationProbeReapsTraceeAfterPostInjectionReplyFailure(t *testing.T) {
	if err := seccompNotificationSupport(); err != nil {
		t.Skipf("kernel seccomp notification support is unavailable: %v", err)
	}
	var traceeTID uint32
	var sourceFD int
	err := probeSeccompNotificationSupportWithBrokerFactory(func(listenerFD int) *seccompNotificationBroker {
		return &seccompNotificationBroker{
			listenerFD: listenerFD,
			ioctl: func(fd int, request uintptr, argument unsafe.Pointer) (uintptr, syscall.Errno) {
				if request == unix.SECCOMP_IOCTL_NOTIF_SEND {
					return 0, syscall.EIO
				}
				value, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), request, uintptr(argument))
				return value, errno
			},
			afterAddFD: func(_ uint64, tid uint32, source, _ int) error {
				traceeTID, sourceFD = tid, source
				if _, err := unix.FcntlInt(uintptr(source), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
					return errors.New("broker source descriptor remained open after injection")
				}
				return nil
			},
		}
	})
	if err == nil || !strings.Contains(err.Error(), "reply to seccomp notification with injected socket") {
		t.Fatalf("probe after post-injection reply failure = %v, want broker reply error", err)
	}
	if traceeTID == 0 || sourceFD < 0 {
		t.Fatalf("post-injection boundary was not reached: tracee TID=%d source FD=%d", traceeTID, sourceFD)
	}
	if err := syscall.Kill(int(traceeTID), 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("tracee task remained after probe cleanup: %v", err)
	}
}
