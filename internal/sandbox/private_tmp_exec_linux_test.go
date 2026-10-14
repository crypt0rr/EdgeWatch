//go:build linux

package sandbox

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPreparePrivateTemporaryExecValidatesPinnedHandshakeBeforeRestrictions(t *testing.T) {
	temporary, initialization, packet := newPrivateTemporaryProtocolFixture(t)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	if n, err := unix.Write(pair[1], packet); err != nil || n != len(packet) {
		t.Fatalf("write init packet: n=%d err=%v", n, err)
	}
	request := execRequest{
		profile: Scanner, files: 1, privateTemp: true,
		privateRootFD: int(temporary.namespace.Fd()), privateLeafFD: int(temporary.leaf.Fd()),
		controlFD: pair[0], argv: []string{"/bin/true"},
	}
	before := append([]string(nil), os.Environ()...)
	setup, err := preparePrivateTemporaryExec(request)
	if err != nil {
		t.Fatalf("prepare valid private exec: %v", err)
	}
	if setup.initialization.name != initialization.name || setup.stat.Ino != temporary.leafStat.Ino {
		t.Fatalf("prepared private exec state = %+v", setup)
	}
	wantTemp := "/tmp/" + temporary.namespaceName + "/" + temporary.name
	if values := environmentValues(setup.environment, "TMPDIR"); len(values) != 1 || values[0] != wantTemp {
		t.Fatalf("private exec TMPDIR = %q, want %q", values, wantTemp)
	}
	if !reflect.DeepEqual(os.Environ(), before) {
		t.Fatal("pre-exec setup changed the helper process environment")
	}

	wrongInode := initialization
	wrongInode.leaf.Ino++
	badPacket, err := encodePrivateTemporaryInit(wrongInode.namespaceName, wrongInode.name, wrongInode.nonce, &wrongInode.namespace, &wrongInode.leaf)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := unix.Write(pair[1], badPacket); err != nil || n != len(badPacket) {
		t.Fatalf("write mismatched init packet: n=%d err=%v", n, err)
	}
	if _, err := preparePrivateTemporaryExec(request); err == nil || !strings.Contains(err.Error(), "leaf descriptor changed") {
		t.Fatalf("pre-exec setup accepted mismatched inode: %v", err)
	}

	stream, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(stream[0])
	defer unix.Close(stream[1])
	request.controlFD = stream[0]
	if _, err := preparePrivateTemporaryExec(request); err == nil || !strings.Contains(err.Error(), "control channel is invalid") {
		t.Fatalf("pre-exec setup accepted a stream control channel: %v", err)
	}
}

func TestPreparePrivateTemporaryExecRejectsClosedInitializationChannel(t *testing.T) {
	temporary, _, _ := newPrivateTemporaryProtocolFixture(t)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	if err := unix.Shutdown(pair[1], unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	request := execRequest{
		profile: Scanner, files: 1, privateTemp: true,
		privateRootFD: int(temporary.namespace.Fd()), privateLeafFD: int(temporary.leaf.Fd()),
		controlFD: pair[0], argv: []string{"/bin/true"},
	}
	if _, err := preparePrivateTemporaryExec(request); err == nil {
		t.Fatal("pre-exec helper accepted a closed initialization channel")
	}
}

func TestPrivateTemporaryLandlockPlanKeepsOnlyDataDescriptors(t *testing.T) {
	request := execRequest{profile: Scanner, files: 2, privateTemp: true, privateRootFD: 5, privateLeafFD: 6, controlFD: 7, landlock: true}
	paths, inherited := privateTemporaryLandlockRules(request)
	if !reflect.DeepEqual(inherited, []int{3, 4}) {
		t.Fatalf("Landlock inherited descriptors = %v, want only data descriptors 3 and 4", inherited)
	}
	for _, path := range paths {
		if path.path == "/tmp" || strings.HasPrefix(path.path, "/tmp/") {
			t.Fatalf("Landlock plan includes broad temporary path %q", path.path)
		}
	}
	if err := restrictPrivateTemporary(execRequest{landlock: false}, -1); err != nil {
		t.Fatalf("identity-only helper unexpectedly applied Landlock: %v", err)
	}
}

func TestClosePrivateTemporaryControlDescriptorsDoesNotCloseDataFiles(t *testing.T) {
	data, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	dataFD := int(data.Fd())
	rootFD, err := unix.FcntlInt(uintptr(dataFD), unix.F_DUPFD_CLOEXEC, 100)
	if err != nil {
		t.Fatal(err)
	}
	leafFD, err := unix.FcntlInt(uintptr(dataFD), unix.F_DUPFD_CLOEXEC, rootFD+1)
	if err != nil {
		_ = unix.Close(rootFD)
		t.Fatal(err)
	}
	controlFD, err := unix.FcntlInt(uintptr(dataFD), unix.F_DUPFD_CLOEXEC, leafFD+1)
	if err != nil {
		_ = unix.Close(rootFD)
		_ = unix.Close(leafFD)
		t.Fatal(err)
	}
	if err := closePrivateTemporaryControlDescriptors(rootFD, leafFD, controlFD, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(dataFD), unix.F_GETFD, 0); err != nil {
		t.Fatalf("scanner data descriptor was closed: %v", err)
	}
	for _, descriptor := range []int{rootFD, leafFD, controlFD} {
		if _, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Errorf("control descriptor %d remained open: %v", descriptor, err)
		}
	}
	if err := closePrivateTemporaryControlDescriptors(rootFD, -1, controlFD); err == nil {
		t.Fatal("control close reported success after one descriptor was already closed")
	}
}
