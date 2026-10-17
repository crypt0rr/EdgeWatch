//go:build linux

package sandbox

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	privateTemporaryPrivilegedCoverageEnv      = "EDGEWATCH_TEST_PRIVILEGED_PRIVATE_TEMP"
	privateTemporaryPrivilegedCoverageChildEnv = "EDGEWATCH_TEST_PRIVILEGED_PRIVATE_TEMP_CHILD"
	privateTemporaryPrivilegedPeerPathEnv      = "EDGEWATCH_TEST_PRIVILEGED_PRIVATE_TEMP_PEER_PATH"
	privateTemporaryPrivilegedCoverageUID      = 60000
	privateTemporaryPrivilegedCoverageGID      = 60000
)

// TestPrivateTemporaryPrivilegedCoverageChild runs the production private-temp
// helper paths in a re-executed, instrumented test process. The selected test
// returns normally after a controlled exec failure so Go can flush its real
// counters to the shared coverage directory.
func TestPrivateTemporaryPrivilegedCoverageChild(t *testing.T) {
	mode := os.Getenv(privateTemporaryPrivilegedCoverageChildEnv)
	if mode == "" {
		return
	}
	if os.Geteuid() != privateTemporaryPrivilegedCoverageUID || os.Getegid() != privateTemporaryPrivilegedCoverageGID {
		t.Fatalf("private-temp helper identity = %d:%d, want %d:%d", os.Geteuid(), os.Getegid(), privateTemporaryPrivilegedCoverageUID, privateTemporaryPrivilegedCoverageGID)
	}
	switch mode {
	case "create":
		err := execPrivateTemporaryCreate(execRequest{
			privateCreate:      true,
			privateRootFD:      3,
			privateNamespaceFD: 4,
			controlFD:          5,
			seccomp:            true,
			argv:               []string{"/edgewatch-private-temp-coverage-executable-does-not-exist"},
		})
		if err == nil || !strings.Contains(err.Error(), "execute /edgewatch-private-temp-coverage-executable-does-not-exist") {
			t.Fatalf("private-temp create helper error = %v, want controlled exec failure", err)
		}
	case "populate":
		setup, err := preparePrivateTemporaryCreateExec(execRequest{
			privateRootFD:      3,
			privateNamespaceFD: 4,
			controlFD:          5,
		})
		if err != nil {
			t.Fatalf("prepare private-temp leaf as scanner identity: %v", err)
		}
		leafPath := filepath.Join("/tmp", setup.initialization.namespaceName, setup.initialization.name)
		var leaf unix.Stat_t
		if err := unix.Fstatat(4, setup.initialization.name, &leaf, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			t.Fatalf("inspect created private-temp leaf: %v", err)
		}
		if leaf.Uid != privateTemporaryPrivilegedCoverageUID || leaf.Gid != privateTemporaryPrivilegedCoverageGID || leaf.Mode != unix.S_IFDIR|privateScannerTemporaryMode {
			t.Fatalf("created private-temp leaf identity = %+v", leaf)
		}
		if err := helperSendPrivateTemporaryCreateReady(5, setup.initialization.name, setup.initialization.nonce, &leaf); err != nil {
			t.Fatalf("complete controlled private-temp handshake: %v", err)
		}
		if err := os.Chmod(leafPath, 0o755); err != nil {
			t.Fatalf("change scanner-owned leaf mode: %v", err)
		}
		nestedPath := leafPath
		for depth := 0; depth < 40; depth++ {
			nestedPath = filepath.Join(nestedPath, "nested")
			if err := os.Mkdir(nestedPath, 0o700); err != nil {
				t.Fatalf("create controlled nested scanner artifact at depth %d: %v", depth+1, err)
			}
		}
		if err := os.WriteFile(filepath.Join(nestedPath, "artifact"), []byte("coverage fixture\n"), 0o600); err != nil {
			t.Fatalf("write controlled scanner artifact: %v", err)
		}
	case "peer-create":
		path := os.Getenv(privateTemporaryPrivilegedPeerPathEnv)
		if path == "" {
			t.Fatal("peer namespace-entry test path is unavailable")
		}
		if err := unix.Mkdir(path, 0o700); !errors.Is(err, unix.EACCES) {
			t.Fatalf("peer mkdir in sealed namespace = %v, want permission denied", err)
		}
	case "exec":
		err := execPrivateTemporary(execRequest{
			privateTemp:   true,
			privateRootFD: 3,
			privateLeafFD: 4,
			controlFD:     5,
			seccomp:       true,
			argv:          []string{"/edgewatch-private-temp-coverage-executable-does-not-exist"},
		})
		if err == nil || !strings.Contains(err.Error(), "execute /edgewatch-private-temp-coverage-executable-does-not-exist") {
			t.Fatalf("private-temp exec helper error = %v, want controlled exec failure", err)
		}
	case "cleanup":
		var leaf unix.Stat_t
		if err := unix.Fstat(3, &leaf); err != nil {
			t.Fatalf("inspect inherited private-temp cleanup descriptor: %v", err)
		}
		args := []string{
			"--cleanup-private-tmp",
			"--device", strconv.FormatUint(uint64(leaf.Dev), 10),
			"--inode", strconv.FormatUint(leaf.Ino, 10),
			"--leaf-uid", strconv.FormatUint(uint64(leaf.Uid), 10),
			"--leaf-gid", strconv.FormatUint(uint64(leaf.Gid), 10),
			"--leaf-mode", strconv.FormatUint(uint64(privateScannerTemporaryMode), 8),
			"--uid", strconv.Itoa(os.Geteuid()),
			"--gid", strconv.Itoa(os.Getegid()),
		}
		if err := execLandlocked(args); err != nil {
			t.Fatalf("run production private-temp cleanup helper: %v", err)
		}
	default:
		t.Fatalf("unknown private-temp coverage child mode %q", mode)
	}
}

// TestPrivateTemporaryPrivilegedLifecycleCoverage is intended for the
// disposable pinned-image coverage run. It needs only the existing scanner
// SETUID/SETGID capabilities and keeps Landlock disabled for this
// identity-only fixture so the Go coverage directory remains writable.
func TestPrivateTemporaryPrivilegedLifecycleCoverage(t *testing.T) {
	if os.Getenv(privateTemporaryPrivilegedCoverageEnv) != "1" {
		t.Skip("requires explicit privileged private-temp coverage run")
	}
	env := systemEnvironment()
	required := capabilityMask(unix.CAP_SETUID, unix.CAP_SETGID)
	forbidden := capabilityMask(unix.CAP_SYS_PTRACE, unix.CAP_DAC_OVERRIDE, unix.CAP_DAC_READ_SEARCH)
	if env.euid != 0 || env.effective&required != required || env.effective&forbidden != 0 {
		t.Fatalf("privileged private-temp run has unexpected credentials/capabilities: euid=%d effective=%#x", env.euid, env.effective)
	}
	coverageDir := currentTestCoverageDirectory()
	if coverageDir == "" {
		t.Fatal("privileged private-temp run has no Go coverage directory")
	}
	info, err := os.Stat(coverageDir)
	if err != nil {
		t.Fatalf("stat Go coverage directory: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != privateTemporaryPrivilegedCoverageUID || stat.Gid != uint32(os.Getegid()) || info.Mode().Perm() != 0o770 {
		t.Fatalf("coverage directory ownership/mode = %+v/%#o, want %d:%d/0770", stat, info.Mode().Perm(), privateTemporaryPrivilegedCoverageUID, os.Getegid())
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("create helper handshake and controlled exec failure", func(t *testing.T) {
		temporary := newPrivilegedPrivateTemporaryFixture(t)
		if err := runPrivateTemporaryPrivilegedCreateChild(t, executable, coverageDir, temporary, "create"); err != nil {
			t.Fatal(err)
		}
		if temporary.leaf == nil {
			t.Fatal("create helper did not leave a pinned scanner-owned leaf")
		}
		cleanupPrivilegedPrivateTemporaryFixture(t, executable, coverageDir, temporary)
	})
	t.Run("scanner-owned nested artifact cleanup", func(t *testing.T) {
		temporary := newPrivilegedPrivateTemporaryFixture(t)
		if err := runPrivateTemporaryPrivilegedCreateChild(t, executable, coverageDir, temporary, "populate"); err != nil {
			t.Fatal(err)
		}
		if temporary.leaf == nil {
			t.Fatal("prepare helper did not leave a pinned scanner-owned leaf")
		}
		assertPrivilegedPeerCannotCreateNamespaceEntry(t, executable, coverageDir, temporary)
		if err := runPrivateTemporaryPrivilegedCleanupChild(t, executable, coverageDir, temporary.leaf); err != nil {
			t.Fatal(err)
		}
		if err := removePrivilegedPrivateTemporaryLeaf(temporary); err != nil {
			t.Fatal(err)
		}
		if err := temporary.removeNamespace(); err != nil {
			t.Fatal(err)
		}
		temporary.cleaned = true
		if err := temporary.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("normal private-temp helper handshake and controlled exec failure", func(t *testing.T) {
		temporary := newPrivilegedPrivateTemporaryExecFixture(t)
		if err := runPrivateTemporaryPrivilegedExecChild(t, executable, coverageDir, temporary); err != nil {
			t.Fatal(err)
		}
	})
}

func newPrivilegedPrivateTemporaryFixture(t *testing.T) *linuxPrivateTemporaryDirectory {
	t.Helper()
	temporary := &linuxPrivateTemporaryDirectory{
		filesystem:    realPrivateTemporaryFilesystemOps(),
		uid:           privateTemporaryPrivilegedCoverageUID,
		gid:           privateTemporaryPrivilegedCoverageGID,
		leafMode:      privateScannerTemporaryMode,
		namespaceMode: privateScannerNamespaceMode,
		childCreates:  true,
	}
	if err := temporary.createNamespace(); err != nil {
		t.Fatalf("create private-temp privileged fixture namespace: %v", err)
	}
	if err := temporary.newChildCreatedNames(); err != nil {
		_ = temporary.Close()
		t.Fatalf("choose private-temp privileged fixture names: %v", err)
	}
	t.Cleanup(func() {
		if !temporary.cleaned {
			cleanupPrivilegedPrivateTemporaryFixture(t, mustExecutable(t), currentTestCoverageDirectory(), temporary)
		}
		if err := temporary.Close(); err != nil {
			t.Errorf("close private-temp privileged fixture: %v", err)
		}
	})
	return temporary
}

func newPrivilegedPrivateTemporaryExecFixture(t *testing.T) *linuxPrivateTemporaryDirectory {
	t.Helper()
	temporary := &linuxPrivateTemporaryDirectory{
		filesystem:    realPrivateTemporaryFilesystemOps(),
		uid:           uint32(os.Geteuid()),
		gid:           uint32(os.Getegid()),
		leafMode:      privateTemporaryMode,
		namespaceMode: privateNamespaceMode,
	}
	if err := temporary.createNamespace(); err != nil {
		t.Fatalf("create normal-mode private-temp fixture namespace: %v", err)
	}
	if err := temporary.createLeaf(); err != nil {
		_ = temporary.Close()
		t.Fatalf("create normal-mode private-temp fixture leaf: %v", err)
	}
	if _, err := rand.Read(temporary.nonce[:]); err != nil {
		_ = temporary.Cleanup(context.Background())
		_ = temporary.Close()
		t.Fatalf("create normal-mode private-temp fixture nonce: %v", err)
	}
	t.Cleanup(func() {
		if !temporary.cleaned {
			ctx, cancel := context.WithTimeout(context.Background(), privateTemporaryCleanupTimeout)
			if err := temporary.Cleanup(ctx); err != nil {
				t.Errorf("clean normal-mode private-temp fixture: %v", err)
			}
			cancel()
		}
		if err := temporary.Close(); err != nil {
			t.Errorf("close normal-mode private-temp fixture: %v", err)
		}
	})
	return temporary
}

func runPrivateTemporaryPrivilegedCreateChild(t *testing.T, executable, coverageDir string, temporary *linuxPrivateTemporaryDirectory, mode string) error {
	t.Helper()
	packet := privateTemporaryCreateInitPacket(t, temporary)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("create private-temp privileged control socket: %w", err)
	}
	childControl := os.NewFile(uintptr(pair[0]), "private-temp privileged child control")
	parentControl := os.NewFile(uintptr(pair[1]), "private-temp privileged parent control")
	defer childControl.Close()
	defer parentControl.Close()
	if n, err := unix.SendmsgN(int(parentControl.Fd()), packet, nil, nil, 0); err != nil || n != len(packet) {
		return fmt.Errorf("send private-temp privileged initialization: wrote %d bytes: %w", n, err)
	}
	command, stdout, stderr, cancel, err := privateTemporaryPrivilegedCommand(t, executable, coverageDir, mode, []*os.File{temporary.root, temporary.namespace, childControl})
	if err != nil {
		return err
	}
	defer cancel()
	if err := command.Start(); err != nil {
		return fmt.Errorf("start private-temp privileged child: %w", err)
	}
	childPID := command.Process.Pid
	_ = childControl.Close()
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	ready := []unix.PollFd{{Fd: int32(parentControl.Fd()), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
	count, err := unix.Poll(ready, int(privateTemporaryStartupTimeout/time.Millisecond*2))
	if err != nil || count != 1 || ready[0].Revents&unix.POLLIN == 0 {
		return fmt.Errorf("wait for private-temp privileged readiness: count=%d revents=%#x err=%v stdout=%q stderr=%q", count, ready[0].Revents, err, stdout.String(), stderr.String())
	}
	message := make([]byte, privateTemporaryMessageMax)
	n, _, flags, _, err := unix.Recvmsg(int(parentControl.Fd()), message, nil, 0)
	if err != nil || n == 0 || flags&unix.MSG_TRUNC != 0 {
		return fmt.Errorf("read private-temp privileged readiness: bytes=%d flags=%#x err=%v stdout=%q stderr=%q", n, flags, err, stdout.String(), stderr.String())
	}
	if mode == "create" {
		if _, _, _, _, _, err := decodePrivateTemporaryCreateMessage(message[:n], temporary.name, temporary.nonce); err != nil {
			return fmt.Errorf("validate create-helper readiness: %w", err)
		}
	} else {
		if _, _, _, _, _, err := decodePrivateTemporaryCreateMessage(message[:n], temporary.name, temporary.nonce); err != nil {
			return fmt.Errorf("validate prepare-helper readiness: %w", err)
		}
	}
	if err := temporary.pinChildCreatedLeaf(message[:n]); err != nil {
		return fmt.Errorf("pin private-temp privileged leaf: %w", err)
	}
	if err := temporary.sealScannerNamespace(); err != nil {
		return fmt.Errorf("seal private-temp privileged namespace: %w", err)
	}
	if n, err := unix.Write(int(parentControl.Fd()), []byte{1}); err != nil || n != 1 {
		return fmt.Errorf("acknowledge private-temp privileged readiness: wrote %d bytes: %w", n, err)
	}
	waitErr := command.Wait()
	waited = true
	if waitErr != nil {
		return fmt.Errorf("wait for private-temp privileged child: %w; stdout=%q stderr=%q", waitErr, stdout.String(), stderr.String())
	}
	if !privateTemporaryCoverageCountersContainPID(coverageDir, childPID) {
		return fmt.Errorf("private-temp child pid %d emitted no coverage counters", childPID)
	}
	return nil
}

func assertPrivilegedPeerCannotCreateNamespaceEntry(t *testing.T, executable, coverageDir string, temporary *linuxPrivateTemporaryDirectory) {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Fstat(int(temporary.namespace.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Mode != unix.S_IFDIR|privateNamespaceMode || temporary.namespaceMode != privateNamespaceMode {
		t.Fatalf("ready namespace mode=%#o state=%#o, want %#o", stat.Mode, temporary.namespaceMode, unix.S_IFDIR|privateNamespaceMode)
	}
	peerPath := filepath.Join("/tmp", temporary.namespaceName, "peer-entry")
	command, stdout, stderr, cancel, err := privateTemporaryPrivilegedCommand(t, executable, coverageDir, "peer-create", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	command.Env = replaceTestEnv(command.Env, privateTemporaryPrivilegedPeerPathEnv, peerPath)
	if err := command.Start(); err != nil {
		t.Fatalf("start namespace peer: %v", err)
	}
	childPID := command.Process.Pid
	if err := command.Wait(); err != nil {
		t.Fatalf("namespace peer check: %v; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if !privateTemporaryCoverageCountersContainPID(coverageDir, childPID) {
		t.Fatalf("namespace peer pid %d emitted no coverage counters", childPID)
	}
	if _, err := os.Lstat(peerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("peer entry exists in sealed namespace: %v", err)
	}
}

func runPrivateTemporaryPrivilegedCleanupChild(t *testing.T, executable, coverageDir string, leaf *os.File) error {
	t.Helper()
	command, stdout, stderr, cancel, err := privateTemporaryPrivilegedCommand(t, executable, coverageDir, "cleanup", []*os.File{leaf})
	if err != nil {
		return err
	}
	defer cancel()
	if err := command.Start(); err != nil {
		return fmt.Errorf("start private-temp cleanup child: %w", err)
	}
	childPID := command.Process.Pid
	if err := command.Wait(); err != nil {
		return fmt.Errorf("wait for private-temp cleanup child: %w; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if !privateTemporaryCoverageCountersContainPID(coverageDir, childPID) {
		return fmt.Errorf("private-temp cleanup child pid %d emitted no coverage counters", childPID)
	}
	return nil
}

func runPrivateTemporaryPrivilegedExecChild(t *testing.T, executable, coverageDir string, temporary *linuxPrivateTemporaryDirectory) error {
	t.Helper()
	var namespace, leaf unix.Stat_t
	if err := unix.Fstat(int(temporary.namespace.Fd()), &namespace); err != nil {
		return fmt.Errorf("inspect private-temp namespace for helper exec: %w", err)
	}
	if err := unix.Fstat(int(temporary.leaf.Fd()), &leaf); err != nil {
		return fmt.Errorf("inspect private-temp leaf for helper exec: %w", err)
	}
	packet, err := encodePrivateTemporaryInit(temporary.namespaceName, temporary.name, temporary.nonce, &namespace, &leaf)
	if err != nil {
		return fmt.Errorf("encode private-temp helper initialization: %w", err)
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("create private-temp helper-exec control socket: %w", err)
	}
	childControl := os.NewFile(uintptr(pair[0]), "private-temp exec child control")
	parentControl := os.NewFile(uintptr(pair[1]), "private-temp exec parent control")
	defer childControl.Close()
	defer parentControl.Close()
	if n, err := unix.SendmsgN(int(parentControl.Fd()), packet, nil, nil, 0); err != nil || n != len(packet) {
		return fmt.Errorf("send private-temp helper initialization: wrote %d bytes: %w", n, err)
	}
	command, stdout, stderr, cancel, err := privateTemporaryPrivilegedCommand(t, executable, coverageDir, "exec", []*os.File{temporary.namespace, temporary.leaf, childControl})
	if err != nil {
		return err
	}
	defer cancel()
	if err := command.Start(); err != nil {
		return fmt.Errorf("start private-temp exec helper child: %w", err)
	}
	childPID := command.Process.Pid
	_ = childControl.Close()
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	ready := []unix.PollFd{{Fd: int32(parentControl.Fd()), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
	count, err := unix.Poll(ready, int(privateTemporaryStartupTimeout/time.Millisecond*2))
	if err != nil || count != 1 || ready[0].Revents&unix.POLLIN == 0 {
		return fmt.Errorf("wait for private-temp helper-exec readiness: count=%d revents=%#x err=%v stdout=%q stderr=%q", count, ready[0].Revents, err, stdout.String(), stderr.String())
	}
	message := make([]byte, privateTemporaryMessageMax)
	n, _, flags, _, err := unix.Recvmsg(int(parentControl.Fd()), message, nil, 0)
	if err != nil || n == 0 || flags&unix.MSG_TRUNC != 0 {
		return fmt.Errorf("read private-temp helper-exec readiness: bytes=%d flags=%#x err=%v stdout=%q stderr=%q", n, flags, err, stdout.String(), stderr.String())
	}
	device, inode, uid, gid, mode, err := decodePrivateTemporaryMessage(message[:n], temporary.name, temporary.nonce)
	if err != nil {
		return fmt.Errorf("validate private-temp helper-exec readiness: %w", err)
	}
	if device != uint64(leaf.Dev) || inode != leaf.Ino || uid != leaf.Uid || gid != leaf.Gid || mode != leaf.Mode {
		return fmt.Errorf("private-temp helper-exec readiness does not match pinned leaf: device=%d inode=%d uid=%d gid=%d mode=%#o", device, inode, uid, gid, mode)
	}
	if n, err := unix.Write(int(parentControl.Fd()), []byte{1}); err != nil || n != 1 {
		return fmt.Errorf("acknowledge private-temp helper-exec readiness: wrote %d bytes: %w", n, err)
	}
	if err := command.Wait(); err != nil {
		return fmt.Errorf("wait for private-temp exec helper child: %w; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	waited = true
	if !privateTemporaryCoverageCountersContainPID(coverageDir, childPID) {
		return fmt.Errorf("private-temp exec helper child pid %d emitted no coverage counters", childPID)
	}
	return nil
}

func privateTemporaryPrivilegedCommand(t *testing.T, executable, coverageDir, mode string, files []*os.File) (*exec.Cmd, *strings.Builder, *strings.Builder, context.CancelFunc, error) {
	t.Helper()
	args := []string{"-test.run=^TestPrivateTemporaryPrivilegedCoverageChild$", "-test.gocoverdir=" + coverageDir}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = replaceTestEnv(os.Environ(), privateTemporaryPrivilegedCoverageChildEnv, mode)
	command.Env = replaceTestEnv(command.Env, "GOCOVERDIR", coverageDir)
	command.ExtraFiles = files
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid:    privateTemporaryPrivilegedCoverageUID,
		Gid:    privateTemporaryPrivilegedCoverageGID,
		Groups: []uint32{},
	}}
	command.WaitDelay = time.Second
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	return command, &stdout, &stderr, cancel, nil
}

func privateTemporaryCoverageCountersContainPID(directory string, pid int) bool {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false
	}
	wantPID := strconv.Itoa(pid)
	for _, entry := range entries {
		parts := strings.Split(entry.Name(), ".")
		if len(parts) >= 4 && parts[0] == "covcounters" && parts[2] == wantPID {
			return true
		}
	}
	return false
}

func removePrivilegedPrivateTemporaryLeaf(temporary *linuxPrivateTemporaryDirectory) error {
	if temporary.leaf == nil {
		return errors.New("private-temp privileged leaf is not pinned")
	}
	if err := temporary.verifyLeafPinned(&temporary.leafStat); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(temporary.namespace.Fd()), temporary.name, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("remove cleaned private-temp privileged leaf: %w", err)
	}
	if err := temporary.verifyLeafRemoved(); err != nil {
		return err
	}
	return nil
}

func cleanupPrivilegedPrivateTemporaryFixture(t *testing.T, executable, coverageDir string, temporary *linuxPrivateTemporaryDirectory) {
	t.Helper()
	if temporary == nil || temporary.cleaned || temporary.namespace == nil {
		return
	}
	if temporary.leaf == nil && temporary.name != "" {
		err := temporary.pinChildCreatedLeafForCleanup()
		if err != nil && err != errPrivateTemporaryLeafAbsent {
			t.Errorf("pin exact private-temp fixture leaf for cleanup: %v", err)
			return
		}
	}
	if temporary.leaf != nil {
		if err := runPrivateTemporaryPrivilegedCleanupChild(t, executable, coverageDir, temporary.leaf); err != nil {
			t.Errorf("cleanup private-temp fixture through scanner identity: %v", err)
			return
		}
		if err := removePrivilegedPrivateTemporaryLeaf(temporary); err != nil {
			t.Errorf("remove private-temp fixture leaf: %v", err)
			return
		}
	}
	if err := temporary.removeNamespace(); err != nil {
		t.Errorf("remove private-temp fixture namespace: %v", err)
		return
	}
	temporary.cleaned = true
}
