//go:build linux

package sandbox

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const privateTemporaryCoverageChildEnv = "EDGEWATCH_TEST_PRIVATE_TEMP_COVERAGE_CHILD"

// TestPrivateTemporaryCoverageHelper is selected in a re-executed test binary
// so Go's test runtime can flush the helper's counters into the parent test's
// coverage directory. It returns normally after a controlled exec failure;
// the production helper path and environment remain unchanged.
func TestPrivateTemporaryCoverageHelper(t *testing.T) {
	var request execRequest
	var err error
	switch os.Getenv(privateTemporaryCoverageChildEnv) {
	case "create":
		request = execRequest{
			privateCreate:      true,
			privateRootFD:      3,
			privateNamespaceFD: 4,
			controlFD:          5,
			argv:               []string{"/edgewatch-coverage-helper-executable-does-not-exist"},
		}
		err = execPrivateTemporaryCreate(request)
	case "exec":
		request = execRequest{
			privateTemp:   true,
			privateRootFD: 3,
			privateLeafFD: 4,
			controlFD:     5,
			argv:          []string{"/edgewatch-coverage-helper-executable-does-not-exist"},
		}
		err = execPrivateTemporary(request)
	default:
		return
	}
	if err == nil || !strings.Contains(err.Error(), "execute /edgewatch-coverage-helper-executable-does-not-exist") {
		t.Fatalf("private temporary %s helper error = %v, want controlled exec failure", os.Getenv(privateTemporaryCoverageChildEnv), err)
	}
}

// TestPrivateTemporaryCreateHelperReexecContributesCoverage exercises the
// real child-only create helper through the test binary. Passing the test
// runner's own -test.gocoverdir lets the helper process emit counters that go
// test merges into its ordinary coverprofile.
func TestPrivateTemporaryCreateHelperReexecContributesCoverage(t *testing.T) {
	temporary := newPrivateTemporaryCreateFixture(t)
	t.Cleanup(func() {
		if temporary.leaf != nil {
			return
		}
		var named unix.Stat_t
		if err := unix.Fstatat(int(temporary.namespace.Fd()), temporary.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return
		}
		if named.Mode != unix.S_IFDIR|privateScannerTemporaryMode || named.Uid != uint32(os.Geteuid()) || named.Gid != uint32(os.Getegid()) || named.Dev != temporary.namespaceStat.Dev {
			t.Errorf("refusing to pin unexpected helper-created leaf: %+v", named)
			return
		}
		fd, err := unix.Openat(int(temporary.namespace.Fd()), temporary.name, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Errorf("pin helper-created leaf during cleanup: %v", err)
			return
		}
		var pinned unix.Stat_t
		if err := unix.Fstat(fd, &pinned); err != nil || !sameObject(&named, &pinned) {
			_ = unix.Close(fd)
			t.Errorf("helper-created leaf changed before cleanup: stat=%+v, err=%v", pinned, err)
			return
		}
		temporary.leaf = os.NewFile(uintptr(fd), "private temporary coverage cleanup leaf")
		temporary.leafStat = pinned
	})
	packet := privateTemporaryCreateInitPacket(t, temporary)
	runPrivateTemporaryCoverageChild(t, "create", packet, []*os.File{temporary.root, temporary.namespace}, func(message []byte) error {
		device, inode, uid, gid, mode, err := decodePrivateTemporaryCreateMessage(message, temporary.name, temporary.nonce)
		if err != nil {
			return err
		}
		leafFD, err := unix.Openat(int(temporary.namespace.Fd()), temporary.name, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		var leaf unix.Stat_t
		if err := unix.Fstat(leafFD, &leaf); err != nil || uint64(leaf.Dev) != device || leaf.Ino != inode || leaf.Uid != uid || leaf.Gid != gid || leaf.Mode != mode {
			_ = unix.Close(leafFD)
			if err != nil {
				return os.NewSyscallError("verify helper-created leaf", err)
			}
			return fmt.Errorf("helper-created leaf does not match readiness message: %+v", leaf)
		}
		temporary.leaf = os.NewFile(uintptr(leafFD), "private temporary coverage leaf")
		temporary.leafStat = leaf
		return nil
	})
}

// TestPrivateTemporaryExecHelperReexecContributesCoverage exercises the
// regular private-temp helper, including its parent handshake and control-FD
// closure, through a child test process whose counters are merged by go test.
func TestPrivateTemporaryExecHelperReexecContributesCoverage(t *testing.T) {
	temporary, _, packet := newPrivateTemporaryProtocolFixture(t)
	runPrivateTemporaryCoverageChild(t, "exec", packet, []*os.File{temporary.namespace, temporary.leaf}, func(message []byte) error {
		device, inode, uid, gid, mode, err := decodePrivateTemporaryMessage(message, temporary.name, temporary.nonce)
		if err != nil {
			return err
		}
		if uint64(temporary.leafStat.Dev) != device || temporary.leafStat.Ino != inode || temporary.leafStat.Uid != uid || temporary.leafStat.Gid != gid || temporary.leafStat.Mode != mode {
			return fmt.Errorf("private temporary leaf changed: %+v", temporary.leafStat)
		}
		return nil
	})
}

func runPrivateTemporaryCoverageChild(t *testing.T, mode string, packet []byte, descriptors []*os.File, acceptReady func([]byte) error) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("create private temporary control socket: %v", err)
	}
	childControl := os.NewFile(uintptr(pair[0]), "private temporary coverage child control")
	parentControl := os.NewFile(uintptr(pair[1]), "private temporary coverage parent control")
	t.Cleanup(func() {
		_ = childControl.Close()
		_ = parentControl.Close()
	})
	if n, err := unix.SendmsgN(int(parentControl.Fd()), packet, nil, nil, 0); err != nil || n != len(packet) {
		t.Fatalf("send private temporary initialization: wrote %d bytes, %v", n, err)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	args := []string{"-test.run=^TestPrivateTemporaryCoverageHelper$"}
	coverageDir := ""
	if coverageFlag := flag.Lookup("test.gocoverdir"); coverageFlag != nil {
		coverageDir = coverageFlag.Value.String()
	}
	if coverageDir != "" {
		args = append(args, "-test.gocoverdir="+coverageDir)
	}
	command := exec.Command(executable, args...)
	command.Env = replaceTestEnv(os.Environ(), privateTemporaryCoverageChildEnv, mode)
	if coverageDir != "" {
		command.Env = replaceTestEnv(command.Env, "GOCOVERDIR", coverageDir)
	}
	command.ExtraFiles = append(descriptors, childControl)
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start private temporary test helper: %v", err)
	}
	childPID := command.Process.Pid
	_ = childControl.Close()
	waited := false
	t.Cleanup(func() {
		if waited {
			return
		}
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	ready := []unix.PollFd{{Fd: int32(parentControl.Fd()), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
	readyCount, err := unix.Poll(ready, 10000)
	if err != nil || readyCount != 1 || ready[0].Revents&unix.POLLIN == 0 {
		t.Fatalf("wait for private temporary helper readiness: poll=%d revents=%#x err=%v stdout=%q stderr=%q", readyCount, ready[0].Revents, err, stdout.String(), stderr.String())
	}
	message := make([]byte, privateTemporaryMessageMax)
	n, _, flags, _, err := unix.Recvmsg(int(parentControl.Fd()), message, nil, 0)
	if err != nil || n == 0 || flags&unix.MSG_TRUNC != 0 {
		t.Fatalf("read private temporary helper readiness: bytes=%d flags=%#x err=%v stdout=%q stderr=%q", n, flags, err, stdout.String(), stderr.String())
	}
	if err := acceptReady(message[:n]); err != nil {
		t.Fatalf("validate private temporary helper readiness: %v", err)
	}
	if n, err := unix.Write(int(parentControl.Fd()), []byte{1}); err != nil || n != 1 {
		t.Fatalf("acknowledge helper readiness: wrote %d bytes, %v", n, err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("wait for private temporary test helper: %v; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	waited = true

	if coverageDir != "" {
		entries, err := os.ReadDir(coverageDir)
		if err != nil {
			t.Fatalf("read Go coverage directory: %v", err)
		}
		wantPID := strconv.Itoa(childPID)
		found := false
		for _, entry := range entries {
			parts := strings.Split(entry.Name(), ".")
			if len(parts) >= 4 && parts[0] == "covcounters" && parts[2] == wantPID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("test helper emitted no coverage counter file for pid %s in %q", wantPID, coverageDir)
		}
	}
}

func replaceTestEnv(environment []string, key, value string) []string {
	prefix := key + "="
	filtered := make([]string, 0, len(environment)+1)
	for _, item := range environment {
		if !strings.HasPrefix(item, prefix) {
			filtered = append(filtered, item)
		}
	}
	return append(filtered, prefix+value)
}
