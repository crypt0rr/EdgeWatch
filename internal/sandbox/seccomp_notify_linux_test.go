//go:build linux

package sandbox

import (
	"os"
	"testing"
	"time"

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
