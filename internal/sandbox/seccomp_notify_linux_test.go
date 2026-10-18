//go:build linux

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
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

func TestSeccompNotificationProbeRequiresAsyncPreemptionOff(t *testing.T) {
	t.Setenv("GODEBUG", "")
	err := execSeccompNotificationProbe([]string{"--control-fd", "3"})
	if err == nil || !strings.Contains(err.Error(), "async preemption to be disabled") {
		t.Fatalf("probe without its required runtime setting = %v, want async-preemption refusal", err)
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

func TestSeccompNotificationProbeReportsWaitErrorWhenTimeoutKillsTracee(t *testing.T) {
	if err := seccompNotificationSupport(); err != nil {
		t.Skipf("kernel seccomp notification support is unavailable: %v", err)
	}
	var traceeTID uint32
	var sourceFD int
	addFDCalls, replyCalls := 0, 0
	err := probeSeccompNotificationSupportWithBrokerFactory(func(listenerFD int) *seccompNotificationBroker {
		return &seccompNotificationBroker{
			listenerFD: listenerFD,
			ioctl: func(_ int, request uintptr, argument unsafe.Pointer) (uintptr, syscall.Errno) {
				switch request {
				case unix.SECCOMP_IOCTL_NOTIF_ADDFD:
					addFDCalls++
					return 42, 0
				case unix.SECCOMP_IOCTL_NOTIF_SEND:
					replyCalls++
					response := (*seccompNotificationResponse)(argument)
					if response.Value != 42 {
						t.Errorf("probe reply descriptor = %d, want injected descriptor 42", response.Value)
					}
					// Report a successful reply to the probe loop without waking the
					// real tracee. This deterministically exercises timeout cleanup.
					return 0, 0
				default:
					t.Errorf("unexpected seccomp notification ioctl %#x", request)
					return 0, syscall.EIO
				}
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
	if err == nil || !strings.Contains(err.Error(), "seccomp notification probe timed out (probe cleanup: signal: killed)") {
		t.Fatalf("probe timeout result = %v, want timeout with killed-child cleanup error", err)
	}
	if addFDCalls != 1 || replyCalls != 1 {
		t.Fatalf("probe ioctl counts = ADDFD %d, NOTIF_SEND %d; want 1 each", addFDCalls, replyCalls)
	}
	if traceeTID == 0 || sourceFD < 0 {
		t.Fatalf("timeout cleanup did not reach the injected reply: tracee TID=%d source FD=%d", traceeTID, sourceFD)
	}
	if err := syscall.Kill(int(traceeTID), 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("tracee task remained after timeout cleanup: %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(sourceFD), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("broker source descriptor %d remained open after timeout cleanup: %v", sourceFD, err)
	}
}

func TestSeccompNotificationBrokerRejectsInvalidListenerAndBoundsAddFDRetries(t *testing.T) {
	var unavailable *seccompNotificationBroker
	if err := unavailable.serveOne(); err == nil || !strings.Contains(err.Error(), "listener is unavailable") {
		t.Fatalf("nil broker result = %v; want unavailable listener", err)
	}
	if err := (&seccompNotificationBroker{listenerFD: -1}).serveOne(); err == nil || !strings.Contains(err.Error(), "listener is unavailable") {
		t.Fatalf("negative listener result = %v; want unavailable listener", err)
	}
	if err := (&seccompNotificationBroker{listenerFD: 1 << 20}).serveOne(); err == nil || !strings.Contains(err.Error(), "listener failed") {
		t.Fatalf("invalid listener descriptor result = %v; want fail-closed poll result", err)
	}

	tests := []struct {
		name       string
		addFD      func(int) (uintptr, syscall.Errno)
		wantError  string
		wantCalls  int
		afterAddFD func(uint64, uint32, int, int) error
	}{
		{
			name:      "non-interrupted kernel error is returned",
			addFD:     func(int) (uintptr, syscall.Errno) { return 0, syscall.EIO },
			wantError: "inject broker datagram socket: input/output error", wantCalls: 1,
		},
		{
			name:      "interrupted injection stops at its fixed retry bound",
			addFD:     func(int) (uintptr, syscall.Errno) { return 0, syscall.EINTR },
			wantError: "interrupted retry limit exceeded", wantCalls: seccompNotificationAddFDRetryLimit,
		},
		{
			name:      "out of range kernel descriptor is rejected",
			addFD:     func(int) (uintptr, syscall.Errno) { return uintptr(^uint(0)>>1) + 1, 0 },
			wantError: "invalid scanner socket descriptor", wantCalls: 1,
		},
		{
			name:      "pre-reply failure does not send a response",
			addFD:     func(int) (uintptr, syscall.Errno) { return 42, 0 },
			wantError: "pre-reply hook failed", wantCalls: 1,
			afterAddFD: func(_ uint64, _ uint32, sourceFD, targetFD int) error {
				if targetFD != 42 {
					return errors.New("unexpected returned target descriptor")
				}
				if _, err := unix.FcntlInt(uintptr(sourceFD), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
					return errors.New("broker source descriptor remained open after addfd")
				}
				return errors.New("injected pre-reply failure")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls, replies, sourceFD := 0, 0, -1
			broker := &seccompNotificationBroker{listenerFD: 9, afterAddFD: test.afterAddFD}
			broker.ioctl = func(_ int, request uintptr, argument unsafe.Pointer) (uintptr, syscall.Errno) {
				switch request {
				case unix.SECCOMP_IOCTL_NOTIF_ADDFD:
					calls++
					add := (*seccompNotificationAddFD)(argument)
					sourceFD = int(add.SourceFD)
					if add.TargetFlag != unix.O_CLOEXEC || add.Flags != 0 || add.TargetFD != 0 {
						t.Fatalf("ADDFD request = %+v; want dynamic close-on-exec target", *add)
					}
					return test.addFD(calls)
				case unix.SECCOMP_IOCTL_NOTIF_SEND:
					replies++
					response := (*seccompNotificationResponse)(argument)
					if response.ID != 17 {
						t.Fatalf("reply ID = %d, want notification ID 17", response.ID)
					}
				}
				return 0, 0
			}
			err := broker.injectINETDatagram(17, 23)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("injection result = %v, want %q", err, test.wantError)
			}
			if calls != test.wantCalls || replies != 0 {
				t.Fatalf("ioctl calls = addfd %d, reply %d; want %d and 0", calls, replies, test.wantCalls)
			}
			if sourceFD < 0 {
				t.Fatal("ADDFD source descriptor was not captured")
			}
			if _, err := unix.FcntlInt(uintptr(sourceFD), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Fatalf("broker source descriptor %d remained open after failure: %v", sourceFD, err)
			}
		})
	}
}

func runMalformedSeccompNotificationTestChild(shape string) error {
	if err := seccompNotificationSizesSupported(); err != nil {
		return err
	}
	arch, err := currentSeccompArchitecture()
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompArch},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: arch.audit},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: seccompNumber},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: arch.numbers["socket"]},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	listener, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, uintptr(unsafe.Pointer(&program)))
	if errno != 0 {
		return errno
	}
	if err := sendSeccompNotificationListener(3, int(listener)); err != nil {
		_ = unix.Close(int(listener))
		return err
	}
	if err := unix.Close(int(listener)); err != nil {
		return err
	}
	if err := unix.Close(3); err != nil {
		return err
	}
	domain, socketType := unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC
	switch shape {
	case "wrong-domain":
		// The default AF_INET socket is intentionally outside the broker's
		// exact AF_UNIX datagram request contract.
	case "wrong-type":
		domain, socketType = unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC
	case "wrong-protocol":
		domain, socketType = unix.AF_UNIX, seccompNotificationSocketType
		_, err := unix.Socket(domain, socketType, 1)
		return err
	default:
		return errors.New("malformed seccomp notification test child shape is invalid")
	}
	_, err = unix.Socket(domain, socketType, 0)
	return err
}

func TestSeccompNotificationBrokerRejectsUnexpectedSocketArguments(t *testing.T) {
	if err := seccompNotificationSupport(); err != nil {
		t.Skipf("kernel seccomp notification support is unavailable: %v", err)
	}
	for _, shape := range []string{"wrong-domain", "wrong-type", "wrong-protocol"} {
		t.Run(shape, func(t *testing.T) {
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			parent := os.NewFile(uintptr(pair[0]), "malformed notification parent")
			childSocket := os.NewFile(uintptr(pair[1]), "malformed notification child")
			if err := unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
				_ = parent.Close()
				_ = childSocket.Close()
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], malformedSeccompNotificationChild, shape)
			command.Env = []string{}
			command.ExtraFiles = []*os.File{childSocket}
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
			if err := command.Start(); err != nil {
				_ = parent.Close()
				_ = childSocket.Close()
				t.Fatalf("start malformed-notification child: %v", err)
			}
			_ = childSocket.Close()
			listenerFD, receiveErr := receiveSeccompNotificationListener(pair[0], command.Process.Pid,
				uint32(os.Geteuid()), uint32(os.Getegid()), scannerSupervisorTimeout)
			if receiveErr != nil {
				_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
				_ = command.Wait()
				_ = parent.Close()
				t.Fatalf("receive malformed-notification listener: %v", receiveErr)
			}
			if err := waitForSeccompNotificationReady(listenerFD); err != nil {
				_ = unix.Close(listenerFD)
				_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
				_ = command.Wait()
				_ = parent.Close()
				t.Fatalf("wait for malformed seccomp request: %v", err)
			}
			broker := seccompNotificationBroker{listenerFD: listenerFD}
			serveErr := broker.serveOne()
			_ = unix.Close(listenerFD)
			_ = parent.Close()
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			waitErr := command.Wait()
			if serveErr == nil || !strings.Contains(serveErr.Error(), "unexpected seccomp notification request") {
				t.Fatalf("broker result for %s = %v; want fail-closed request rejection", shape, serveErr)
			}
			if waitErr == nil {
				t.Fatalf("malformed-request child %s exited successfully after broker refusal", shape)
			}
		})
	}
}

func waitForSeccompNotificationReady(listenerFD int) error {
	deadline := time.Now().Add(time.Second)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errors.New("malformed-notification child did not issue its seccomp request")
		}
		wait := int((remaining + time.Millisecond - 1) / time.Millisecond)
		if wait > int(seccompNotificationPollTimeout/time.Millisecond) {
			wait = int(seccompNotificationPollTimeout / time.Millisecond)
		}
		poll := []unix.PollFd{{Fd: int32(listenerFD), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
		_, err := unix.Poll(poll, wait)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if poll[0].Revents&unix.POLLIN != 0 {
			return nil
		}
		if poll[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return errors.New("malformed-notification listener closed before a request")
		}
	}
}

func TestSeccompNotificationProbeStopsAtBrokerRequestLimit(t *testing.T) {
	if err := seccompNotificationSupport(); err != nil {
		t.Skipf("kernel seccomp notification support is unavailable: %v", err)
	}
	err := probeSeccompNotificationSupportWithBrokerFactory(func(listenerFD int) *seccompNotificationBroker {
		return &seccompNotificationBroker{listenerFD: listenerFD, served: seccompNotificationLimit}
	})
	if err == nil || !strings.Contains(err.Error(), "seccomp notification request limit exceeded") {
		t.Fatalf("probe past broker request limit = %v; want fail-closed request-limit error", err)
	}
}
