//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	privateTemporaryPrefix         = "edgewatch-naabu-"
	privateNamespacePrefix         = "edgewatch-naabu-root-"
	privateNamespaceMode           = 0o711
	privateTemporaryMode           = 0o1777
	privateTemporaryFallbackMode   = 0o700
	privateTemporaryNonceSize      = 16
	privateTemporaryInitMagic      = "EWTINI01"
	privateTemporaryMessageMagic   = "EWTMP001"
	privateTemporaryMessageMax     = 256
	privateTemporaryStartupTimeout = 5 * time.Second
	privateTemporaryCleanupTimeout = 5 * time.Second
	privateTemporaryCleanupEntries = 100000
	privateTemporaryCleanupDepth   = 32
)

// linuxPrivateTemporaryDirectory owns one Naabu invocation namespace and its
// parent-created leaf. The helper verifies the pinned leaf and grants
// Landlock access only to it. Control descriptors never become scanner data
// descriptors.
type linuxPrivateTemporaryDirectory struct {
	filesystem    privateTemporaryFilesystemOps
	name          string
	namespaceName string
	nonce         [privateTemporaryNonceSize]byte
	root          *os.File
	namespace     *os.File
	leaf          *os.File
	parent        *os.File
	child         *os.File
	helper        string
	uid           uint32
	gid           uint32
	rootStat      unix.Stat_t
	namespaceStat unix.Stat_t
	leafStat      unix.Stat_t
	private       bool
	started       bool
	accepted      bool
	cleaned       bool
	landlocked    bool
	leafMode      uint32
}

// privateTemporaryFilesystemOps groups only the syscalls used while creating
// and pinning the invocation namespace and leaf. Each temporary-directory
// instance receives the concrete unix functions by default; tests may replace
// an instance's functions to exercise rollback after real filesystem changes.
// The helper protocol, Landlock setup, and scanner execution do not use this
// seam.
type privateTemporaryFilesystemOps struct {
	open     func(string, int, uint32) (int, error)
	fstat    func(int, *unix.Stat_t) error
	mkdirat  func(int, string, uint32) error
	openat   func(int, string, int, uint32) (int, error)
	fchmod   func(int, uint32) error
	fstatat  func(int, string, *unix.Stat_t, int) error
	unlinkat func(int, string, int) error
	close    func(int) error
}

func realPrivateTemporaryFilesystemOps() privateTemporaryFilesystemOps {
	return privateTemporaryFilesystemOps{
		open:     unix.Open,
		fstat:    unix.Fstat,
		mkdirat:  unix.Mkdirat,
		openat:   unix.Openat,
		fchmod:   unix.Fchmod,
		fstatat:  unix.Fstatat,
		unlinkat: unix.Unlinkat,
		close:    unix.Close,
	}
}

// preparePrivateTemporaryDirectory is the Linux policy backend for Naabu. It
// puts the unique TMPDIR below a parent-owned invocation namespace. The parent
// creates and pins the leaf before the child starts, so every startup and
// cancellation path has an authoritative cleanup anchor. The helper verifies
// that same leaf and, when enabled, restricts Naabu to it with Landlock.
func (policy *Policy) preparePrivateTemporaryDirectory(ctx context.Context, cmd *exec.Cmd) (*PrivateTemporaryDirectory, error) {
	temporary, err := prepareLinuxPrivateTemporaryDirectory(ctx, cmd, policy)
	if err != nil {
		return nil, err
	}
	return &PrivateTemporaryDirectory{implementation: temporary}, nil
}

func prepareLinuxPrivateTemporaryDirectory(ctx context.Context, cmd *exec.Cmd, policy *Policy) (*linuxPrivateTemporaryDirectory, error) {
	return prepareLinuxPrivateTemporaryDirectoryWithFilesystem(ctx, cmd, policy, realPrivateTemporaryFilesystemOps())
}

func prepareLinuxPrivateTemporaryDirectoryWithFilesystem(ctx context.Context, cmd *exec.Cmd, policy *Policy, filesystem privateTemporaryFilesystemOps) (*linuxPrivateTemporaryDirectory, error) {
	if ctx == nil {
		return nil, errors.New("prepare Naabu temporary directory: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cmd == nil || cmd.Path == "" || len(cmd.Args) == 0 {
		return nil, errors.New("prepare Naabu temporary directory: invalid command")
	}
	temporary := &linuxPrivateTemporaryDirectory{
		filesystem: filesystem,
		uid:        uint32(os.Geteuid()),
		gid:        uint32(os.Getegid()),
	}
	if policy != nil && policy.Enforced() {
		temporary.uid, temporary.gid = uint32(policy.status.UID), uint32(policy.status.GID)
	}
	helper := ""
	landlocked := false
	if policy != nil {
		helper = policy.temporaryHelper
		landlocked = policy.helper != ""
		if helper == "" && landlocked {
			helper = policy.helper
		}
		if helper == "" && (policy.Enforced() || policy.Restricted()) {
			return nil, errors.New("prepare Naabu temporary directory: sandbox helper is unavailable")
		}
		if helper != "" && policy.profileName() != Scanner {
			return nil, errors.New("prepare Naabu temporary directory: scanner policy is required")
		}
	}
	if helper != "" {
		if !filepathIsAbsolute(helper) {
			return nil, errors.New("prepare Naabu temporary directory: sandbox helper path is invalid")
		}
		if cmd.Err != nil {
			return nil, fmt.Errorf("prepare Naabu temporary directory: scanner executable is unavailable: %w", cmd.Err)
		}
		if _, err := os.Stat(cmd.Path); err != nil {
			return nil, fmt.Errorf("prepare Naabu temporary directory: scanner executable is unavailable: %w", err)
		}
		temporary.private, temporary.landlocked = true, landlocked
		temporary.leafMode = privateTemporaryMode
	} else {
		temporary.leafMode = privateTemporaryFallbackMode
	}
	if err := temporary.createNamespace(); err != nil {
		_ = temporary.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = temporary.Cleanup(ctx)
		_ = temporary.Close()
		return nil, err
	}
	if err := temporary.createLeaf(); err != nil {
		_ = temporary.Cleanup(ctx)
		_ = temporary.Close()
		return nil, errors.New("prepare Naabu temporary directory: create and pin leaf failed")
	}
	if err := ctx.Err(); err != nil {
		_ = temporary.Cleanup(ctx)
		_ = temporary.Close()
		return nil, err
	}
	if err := setEnvironment(cmd, "TMPDIR", temporary.path()); err != nil {
		_ = temporary.Cleanup(ctx)
		_ = temporary.Close()
		return nil, errors.New("prepare Naabu temporary directory: set environment failed")
	}
	if helper == "" {
		return temporary, nil
	}
	var random [privateTemporaryNonceSize]byte
	if _, err := rand.Read(random[:]); err != nil {
		_ = temporary.Cleanup(ctx)
		_ = temporary.Close()
		return nil, errors.New("prepare Naabu temporary directory: random name unavailable")
	}
	copy(temporary.nonce[:], random[:])
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		_ = temporary.Cleanup(ctx)
		_ = temporary.Close()
		return nil, errors.New("prepare Naabu temporary directory: control channel unavailable")
	}
	temporary.parent = os.NewFile(uintptr(pair[0]), "private temporary control")
	temporary.child = os.NewFile(uintptr(pair[1]), "private temporary control child")
	temporary.helper = helper
	if err := temporary.configureCommand(cmd, policy); err != nil {
		_ = temporary.Cleanup(ctx)
		_ = temporary.Close()
		return nil, err
	}
	return temporary, nil
}

func (temporary *linuxPrivateTemporaryDirectory) createLeaf() error {
	if temporary.namespace == nil || temporary.leafMode&unix.S_IFMT != 0 {
		return errors.New("private invocation namespace is unavailable")
	}
	for attempt := 0; attempt < 8; attempt++ {
		if err := temporary.newLeafName(); err != nil {
			return err
		}
		if err := temporary.createLeafNamed(); errors.Is(err, unix.EEXIST) {
			continue
		} else if err != nil {
			return err
		}
		return nil
	}
	return errors.New("unique leaf name unavailable")
}

func (temporary *linuxPrivateTemporaryDirectory) createLeafNamed() error {
	if !validPrivateTemporaryName(temporary.name) {
		return errors.New("invalid private temporary leaf name")
	}
	namespaceFD := int(temporary.namespace.Fd())
	if err := temporary.filesystem.mkdirat(namespaceFD, temporary.name, 0o700); err != nil {
		return err
	}
	fd, err := temporary.filesystem.openat(namespaceFD, temporary.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		// The parent created this entry while holding the only write access to
		// its 0711 namespace. If pinning failed, remove only an empty directory
		// at that name; never adopt a replacement object or follow a symlink.
		var created unix.Stat_t
		if statErr := temporary.filesystem.fstatat(namespaceFD, temporary.name, &created, unix.AT_SYMLINK_NOFOLLOW); statErr == nil &&
			created.Mode&unix.S_IFMT == unix.S_IFDIR && created.Uid == uint32(os.Geteuid()) && created.Gid == uint32(os.Getegid()) {
			_ = temporary.filesystem.unlinkat(namespaceFD, temporary.name, unix.AT_REMOVEDIR)
		}
		return errors.New("pin created private temporary leaf failed")
	}
	var stat unix.Stat_t
	rollback := func() {
		if temporary.leaf == nil {
			var pinned unix.Stat_t
			var named unix.Stat_t
			if temporary.filesystem.fstat(fd, &pinned) == nil && temporary.filesystem.fstatat(namespaceFD, temporary.name, &named, unix.AT_SYMLINK_NOFOLLOW) == nil && sameObject(&pinned, &named) {
				_ = temporary.filesystem.unlinkat(namespaceFD, temporary.name, unix.AT_REMOVEDIR)
			}
		}
		_ = temporary.filesystem.close(fd)
	}
	if err := temporary.filesystem.fchmod(fd, temporary.leafMode); err != nil {
		rollback()
		return err
	}
	if err := temporary.filesystem.fstat(fd, &stat); err != nil || stat.Mode != unix.S_IFDIR|temporary.leafMode || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		rollback()
		return errors.New("created leaf identity is unexpected")
	}
	var named unix.Stat_t
	if err := temporary.filesystem.fstatat(namespaceFD, temporary.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameObject(&stat, &named) || named.Mode != stat.Mode || named.Uid != stat.Uid || named.Gid != stat.Gid {
		rollback()
		return errors.New("created leaf entry changed")
	}
	temporary.leafStat = stat
	temporary.leaf = os.NewFile(uintptr(fd), "private temporary directory")
	return nil
}

func (temporary *linuxPrivateTemporaryDirectory) createNamespace() error {
	rootFD, err := temporary.filesystem.open("/tmp", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("prepare Naabu temporary directory: temporary root unavailable")
	}
	temporary.root = os.NewFile(uintptr(rootFD), "temporary filesystem root")
	if err := temporary.filesystem.fstat(rootFD, &temporary.rootStat); err != nil {
		return errors.New("prepare Naabu temporary directory: temporary root identity unavailable")
	}
	for attempt := 0; attempt < 8; attempt++ {
		var random [privateTemporaryNonceSize]byte
		if _, err := rand.Read(random[:]); err != nil {
			return errors.New("prepare Naabu temporary directory: random namespace unavailable")
		}
		name := privateNamespacePrefix + hex.EncodeToString(random[:])
		if err := temporary.filesystem.mkdirat(rootFD, name, 0o700); errors.Is(err, unix.EEXIST) {
			continue
		} else if err != nil {
			return errors.New("prepare Naabu temporary directory: create invocation namespace failed")
		}
		fd, err := temporary.filesystem.openat(rootFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			_ = temporary.filesystem.unlinkat(rootFD, name, unix.AT_REMOVEDIR)
			return errors.New("prepare Naabu temporary directory: pin invocation namespace failed")
		}
		if err := temporary.filesystem.fchmod(fd, privateNamespaceMode); err != nil {
			_ = temporary.filesystem.close(fd)
			_ = temporary.filesystem.unlinkat(rootFD, name, unix.AT_REMOVEDIR)
			return errors.New("prepare Naabu temporary directory: restrict invocation namespace failed")
		}
		var stat, named unix.Stat_t
		if err := temporary.filesystem.fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != privateNamespaceMode || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
			_ = temporary.filesystem.close(fd)
			_ = temporary.filesystem.unlinkat(rootFD, name, unix.AT_REMOVEDIR)
			return errors.New("prepare Naabu temporary directory: invocation namespace identity is unexpected")
		}
		if err := temporary.filesystem.fstatat(rootFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameObject(&stat, &named) {
			_ = temporary.filesystem.close(fd)
			_ = temporary.filesystem.unlinkat(rootFD, name, unix.AT_REMOVEDIR)
			return errors.New("prepare Naabu temporary directory: invocation namespace entry changed")
		}
		temporary.namespaceName = name
		temporary.namespaceStat = stat
		temporary.namespace = os.NewFile(uintptr(fd), "private temporary invocation namespace")
		return nil
	}
	return errors.New("prepare Naabu temporary directory: unique invocation namespace unavailable")
}

func (temporary *linuxPrivateTemporaryDirectory) newLeafName() error {
	var random [privateTemporaryNonceSize]byte
	if _, err := rand.Read(random[:]); err != nil {
		return errors.New("prepare Naabu temporary directory: random leaf name unavailable")
	}
	temporary.name = privateTemporaryPrefix + hex.EncodeToString(random[:])
	return nil
}

func (temporary *linuxPrivateTemporaryDirectory) path() string {
	return "/tmp/" + temporary.namespaceName + "/" + temporary.name
}

func (temporary *linuxPrivateTemporaryDirectory) configureCommand(cmd *exec.Cmd, policy *Policy) error {
	if temporary.child == nil || temporary.namespace == nil || temporary.leaf == nil || len(cmd.ExtraFiles) > maxInheritedFiles {
		return errors.New("prepare Naabu temporary directory: too many inherited descriptors")
	}
	originalPath := cmd.Path
	originalArgs := append([]string(nil), cmd.Args...)
	dataFiles := len(cmd.ExtraFiles)
	rootFD := 3 + dataFiles
	leafFD := rootFD + 1
	controlFD := leafFD + 1
	cmd.ExtraFiles = append(cmd.ExtraFiles, temporary.namespace, temporary.leaf, temporary.child)
	if policy != nil && policy.enforce {
		spec := policy.profileName().spec()
		confineProcess(cmd, spec.uid, spec.gid, policy.ambient)
	}
	args := []string{temporary.helper, ExecCommand, "--profile", string(Scanner), "--files", strconv.Itoa(dataFiles),
		"--private-tmp", "--private-root-fd", strconv.Itoa(rootFD), "--private-leaf-fd", strconv.Itoa(leafFD), "--control-fd", strconv.Itoa(controlFD)}
	if temporary.landlocked {
		args = append(args, "--landlock")
	}
	if policy != nil && policy.seccomp && temporary.landlocked {
		args = append(args, "--seccomp")
	}
	args = append(args, "--", originalPath)
	args = append(args, originalArgs[1:]...)
	cmd.Path, cmd.Args = temporary.helper, args
	return nil
}

// Started closes the parent's copy of the control socket's child endpoint and
// sends the bounded private-namespace initialization packet. Call it only
// after cmd.Start succeeds.
func (temporary *linuxPrivateTemporaryDirectory) Started() error {
	if temporary == nil || temporary.started {
		return nil
	}
	temporary.started = true
	if temporary.child != nil {
		child := temporary.child
		temporary.child = nil
		if err := child.Close(); err != nil {
			return errors.New("prepare Naabu temporary directory: close child control endpoint failed")
		}
	}
	if !temporary.private {
		return nil
	}
	message, err := encodePrivateTemporaryInit(temporary.namespaceName, temporary.name, temporary.nonce, &temporary.namespaceStat, &temporary.leafStat)
	if err != nil {
		return err
	}
	n, err := unix.SendmsgN(int(temporary.parent.Fd()), message, nil, nil, 0)
	if err != nil || n != len(message) {
		return errors.New("prepare Naabu temporary directory: send private namespace initialization failed")
	}
	return nil
}

// WaitReady validates the helper's bounded readiness packet and pins its
// directory descriptor before acknowledging that the scanner may exec.
func (temporary *linuxPrivateTemporaryDirectory) WaitReady(ctx context.Context) error {
	if ctx == nil {
		return errors.New("prepare Naabu temporary directory: context is nil")
	}
	if temporary == nil || !temporary.private || temporary.accepted {
		return nil
	}
	if temporary.parent == nil {
		return errors.New("prepare Naabu temporary directory: control channel is unavailable")
	}
	startupCtx, cancel := context.WithTimeout(ctx, privateTemporaryStartupTimeout)
	defer cancel()
	for {
		if err := startupCtx.Err(); err != nil {
			return errors.New("prepare Naabu temporary directory: helper readiness timed out or was cancelled")
		}
		poll := []unix.PollFd{{Fd: int32(temporary.parent.Fd()), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
		_, err := unix.Poll(poll, 100)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return errors.New("prepare Naabu temporary directory: control channel failed")
		}
		if poll[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) == 0 {
			continue
		}
		break
	}
	message := make([]byte, privateTemporaryMessageMax)
	control := make([]byte, unix.CmsgSpace(16*4))
	n, controlN, flags, _, err := unix.Recvmsg(int(temporary.parent.Fd()), message, control, 0)
	if err != nil {
		return errors.New("prepare Naabu temporary directory: readiness message failed")
	}
	controlErr := closeReceivedDescriptors(control[:controlN])
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || controlErr != nil {
		return errors.New("prepare Naabu temporary directory: malformed readiness message")
	}
	var leaf, named unix.Stat_t
	if err := unix.Fstat(int(temporary.leaf.Fd()), &leaf); err != nil || !sameObject(&temporary.leafStat, &leaf) || leaf.Mode != temporary.leafStat.Mode || leaf.Uid != temporary.leafStat.Uid || leaf.Gid != temporary.leafStat.Gid {
		return errors.New("prepare Naabu temporary directory: pinned directory changed")
	}
	if err := temporary.checkNamespaceEntry(); err != nil {
		return err
	}
	if err := unix.Fstatat(int(temporary.namespace.Fd()), temporary.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameObject(&leaf, &named) || named.Mode != leaf.Mode || named.Uid != leaf.Uid || named.Gid != leaf.Gid {
		return errors.New("prepare Naabu temporary directory: directory identity changed")
	}
	device, inode, uid, gid, mode, err := decodePrivateTemporaryMessage(message[:n], temporary.name, temporary.nonce)
	if err != nil {
		return err
	}
	if !privateTemporaryStatMatches(&leaf, device, inode, uid, gid, mode) || !privateTemporaryStatMatches(&named, device, inode, uid, gid, mode) {
		return errors.New("prepare Naabu temporary directory: helper returned an unexpected directory")
	}
	if n, err := unix.Write(int(temporary.parent.Fd()), []byte{1}); err != nil || n != 1 {
		return errors.New("prepare Naabu temporary directory: helper acknowledgement failed")
	}
	temporary.accepted = true
	return nil
}

// Cleanup removes contents through a fixed helper running as the scanner
// identity, then removes the parent-owned leaf and namespace by pinned name.
// The helper receives no path and no namespace authority.
func (temporary *linuxPrivateTemporaryDirectory) Cleanup(ctx context.Context) error {
	if ctx == nil {
		return errors.New("cleanup Naabu temporary directory: context is nil")
	}
	if temporary == nil || temporary.cleaned {
		return nil
	}
	if temporary.child != nil {
		_ = temporary.child.Close()
		temporary.child = nil
	}
	if temporary.parent != nil {
		_ = temporary.parent.Close()
		temporary.parent = nil
	}
	if temporary.root == nil || temporary.namespace == nil {
		return nil
	}
	if temporary.leaf == nil {
		if temporary.name != "" {
			var unexpected unix.Stat_t
			if err := unix.Fstatat(int(temporary.namespace.Fd()), temporary.name, &unexpected, unix.AT_SYMLINK_NOFOLLOW); err == nil || !errors.Is(err, unix.ENOENT) {
				return errors.New("cleanup Naabu temporary directory: refusing to remove an unpinned leaf")
			}
		}
		if err := temporary.ensureDirectoryEmpty(temporary.namespace); err != nil {
			return err
		}
		if err := temporary.removeNamespace(); err != nil {
			return err
		}
		temporary.cleaned = true
		return nil
	}
	var leaf unix.Stat_t
	if err := unix.Fstat(int(temporary.leaf.Fd()), &leaf); err != nil {
		return errors.New("cleanup Naabu temporary directory: pinned directory is unavailable")
	}
	if leaf.Mode != unix.S_IFDIR|temporary.leafMode || !sameObject(&temporary.leafStat, &leaf) {
		return errors.New("cleanup Naabu temporary directory: pinned directory ownership changed")
	}
	if err := temporary.checkNamespaceEntry(); err != nil {
		return err
	}
	var named unix.Stat_t
	if err := unix.Fstatat(int(temporary.namespace.Fd()), temporary.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return errors.New("cleanup Naabu temporary directory: pinned directory was moved")
		}
		return errors.New("cleanup Naabu temporary directory: directory entry is unavailable")
	}
	if !sameObject(&leaf, &named) || named.Mode != leaf.Mode {
		return errors.New("cleanup Naabu temporary directory: directory entry identity changed")
	}
	if temporary.private {
		if err := temporary.cleanupWithHelper(ctx, &leaf); err != nil {
			return err
		}
	} else if err := cleanPrivateDirectoryContents(int(temporary.leaf.Fd()), &leaf, temporary.uid, temporary.gid); err != nil {
		return fmt.Errorf("cleanup Naabu temporary directory: safe removal failed: %w", err)
	}
	if err := temporary.verifyLeafEmptyAndPinned(&leaf); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(temporary.namespace.Fd()), temporary.name, unix.AT_REMOVEDIR); err != nil {
		return errors.New("cleanup Naabu temporary directory: remove parent-owned leaf failed")
	}
	if err := temporary.verifyLeafRemoved(); err != nil {
		return err
	}
	if err := temporary.removeNamespace(); err != nil {
		return err
	}
	temporary.cleaned = true
	return nil
}

func (temporary *linuxPrivateTemporaryDirectory) checkNamespaceEntry() error {
	var namespace, named unix.Stat_t
	currentRoot, err := unix.Open("/tmp", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("cleanup Naabu temporary directory: temporary root is unavailable")
	}
	defer unix.Close(currentRoot)
	var root unix.Stat_t
	if err := unix.Fstat(currentRoot, &root); err != nil || !sameObject(&temporary.rootStat, &root) {
		return errors.New("cleanup Naabu temporary directory: temporary root identity changed")
	}
	if err := unix.Fstat(int(temporary.namespace.Fd()), &namespace); err != nil || !sameObject(&temporary.namespaceStat, &namespace) || namespace.Mode&unix.S_IFMT != unix.S_IFDIR || namespace.Mode&0o7777 != privateNamespaceMode {
		return errors.New("cleanup Naabu temporary directory: invocation namespace identity changed")
	}
	if err := unix.Fstatat(int(temporary.root.Fd()), temporary.namespaceName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameObject(&namespace, &named) || named.Mode&0o7777 != privateNamespaceMode {
		return errors.New("cleanup Naabu temporary directory: invocation namespace entry changed")
	}
	return nil
}

func (temporary *linuxPrivateTemporaryDirectory) verifyLeafRemoved() error {
	var current unix.Stat_t
	if err := unix.Fstatat(int(temporary.namespace.Fd()), temporary.name, &current, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return errors.New("cleanup Naabu temporary directory: leaf was not removed")
	}
	return nil
}

func (temporary *linuxPrivateTemporaryDirectory) verifyLeafEmptyAndPinned(expected *unix.Stat_t) error {
	var current unix.Stat_t
	if err := unix.Fstat(int(temporary.leaf.Fd()), &current); err != nil || !sameObject(expected, &current) || current.Mode != expected.Mode {
		return errors.New("cleanup Naabu temporary directory: pinned leaf changed during cleanup")
	}
	if err := temporary.checkNamespaceEntry(); err != nil {
		return err
	}
	var named unix.Stat_t
	if err := unix.Fstatat(int(temporary.namespace.Fd()), temporary.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameObject(expected, &named) || named.Mode != expected.Mode {
		return errors.New("cleanup Naabu temporary directory: leaf entry changed during cleanup")
	}
	return temporary.ensureDirectoryEmpty(temporary.leaf)
}

func (temporary *linuxPrivateTemporaryDirectory) ensureDirectoryEmpty(directory *os.File) error {
	if directory == nil {
		return errors.New("cleanup Naabu temporary directory: directory descriptor is unavailable")
	}
	duplicate, err := unix.Openat(int(directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("cleanup Naabu temporary directory: open directory for verification failed")
	}
	file := os.NewFile(uintptr(duplicate), "private temporary empty check")
	defer file.Close()
	entries, readErr := file.ReadDir(1)
	if len(entries) != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) {
		return errors.New("cleanup Naabu temporary directory: directory is not empty")
	}
	return nil
}

func (temporary *linuxPrivateTemporaryDirectory) removeNamespace() error {
	if err := temporary.checkNamespaceEntry(); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(temporary.root.Fd()), temporary.namespaceName, unix.AT_REMOVEDIR); err != nil {
		return errors.New("cleanup Naabu temporary directory: remove invocation namespace failed")
	}
	return nil
}

func (temporary *linuxPrivateTemporaryDirectory) cleanupWithHelper(ctx context.Context, leaf *unix.Stat_t) error {
	if temporary.helper == "" || temporary.leaf == nil {
		return errors.New("cleanup Naabu temporary directory: cleanup helper is unavailable")
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), privateTemporaryCleanupTimeout)
	defer cancel()
	args := []string{temporary.helper, ExecCommand, "--cleanup-private-tmp", "--device", strconv.FormatUint(uint64(leaf.Dev), 10),
		"--inode", strconv.FormatUint(leaf.Ino, 10), "--leaf-uid", strconv.FormatUint(uint64(leaf.Uid), 10),
		"--leaf-gid", strconv.FormatUint(uint64(leaf.Gid), 10), "--uid", strconv.FormatUint(uint64(temporary.uid), 10),
		"--gid", strconv.FormatUint(uint64(temporary.gid), 10)}
	if temporary.landlocked {
		args = append(args, "--landlock")
	}
	cmd := exec.CommandContext(cleanupCtx, temporary.helper, args[1:]...)
	cmd.Args = args
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "XDG_CONFIG_HOME=/nonexistent"}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, io.Discard, io.Discard
	cmd.ExtraFiles = []*os.File{temporary.leaf}
	if uint32(os.Geteuid()) != temporary.uid || uint32(os.Getegid()) != temporary.gid {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: temporary.uid, Gid: temporary.gid, Groups: []uint32{}}}
	}
	if err := cmd.Run(); err != nil {
		return errors.New("cleanup Naabu temporary directory: trusted cleanup helper failed")
	}
	return nil
}

// Close releases this process's pinned descriptors without attempting
// cleanup. Cleanup must be called after the scanner process has been reaped.
func (temporary *linuxPrivateTemporaryDirectory) Close() error {
	if temporary == nil {
		return nil
	}
	var errs []error
	for _, file := range []*os.File{temporary.child, temporary.parent, temporary.leaf, temporary.namespace, temporary.root} {
		if file != nil {
			if err := file.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	temporary.child, temporary.parent, temporary.leaf, temporary.namespace, temporary.root = nil, nil, nil, nil, nil
	return errors.Join(errs...)
}

func filepathIsAbsolute(path string) bool { return strings.HasPrefix(path, "/") }

func privateTemporaryStatMatches(stat *unix.Stat_t, device, inode uint64, uid, gid uint32, mode uint32) bool {
	return uint64(stat.Dev) == device && stat.Ino == inode && stat.Uid == uid && stat.Gid == gid && stat.Mode == mode
}

type privateTemporaryInit struct {
	namespaceName string
	name          string
	nonce         [privateTemporaryNonceSize]byte
	namespace     unix.Stat_t
	leaf          unix.Stat_t
}

func encodePrivateTemporaryInit(namespaceName, name string, nonce [privateTemporaryNonceSize]byte, namespace, leaf *unix.Stat_t) ([]byte, error) {
	if !validPrivateNamespaceName(namespaceName) || !validPrivateTemporaryName(name) || namespace == nil || leaf == nil ||
		namespace.Mode != unix.S_IFDIR|privateNamespaceMode || leaf.Mode != unix.S_IFDIR|privateTemporaryMode ||
		namespace.Uid != leaf.Uid || namespace.Gid != leaf.Gid {
		return nil, errors.New("invalid private temporary initialization")
	}
	message := make([]byte, len(privateTemporaryInitMagic)+1+len(namespaceName)+1+len(name)+2*(8+8+4+4+4)+privateTemporaryNonceSize)
	index := copy(message, privateTemporaryInitMagic)
	message[index] = byte(len(namespaceName))
	index++
	index += copy(message[index:], namespaceName)
	message[index] = byte(len(name))
	index++
	index += copy(message[index:], name)
	index = encodeTemporaryStat(message, index, namespace)
	index = encodeTemporaryStat(message, index, leaf)
	copy(message[index:], nonce[:])
	return message, nil
}

func encodeTemporaryStat(message []byte, index int, stat *unix.Stat_t) int {
	binary.LittleEndian.PutUint64(message[index:index+8], uint64(stat.Dev))
	index += 8
	binary.LittleEndian.PutUint64(message[index:index+8], stat.Ino)
	index += 8
	binary.LittleEndian.PutUint32(message[index:index+4], stat.Uid)
	index += 4
	binary.LittleEndian.PutUint32(message[index:index+4], stat.Gid)
	index += 4
	binary.LittleEndian.PutUint32(message[index:index+4], stat.Mode)
	index += 4
	return index
}

func decodeTemporaryStat(message []byte, index int) (unix.Stat_t, int) {
	stat := unix.Stat_t{
		Dev:  uint64(binary.LittleEndian.Uint64(message[index : index+8])),
		Ino:  binary.LittleEndian.Uint64(message[index+8 : index+16]),
		Uid:  binary.LittleEndian.Uint32(message[index+16 : index+20]),
		Gid:  binary.LittleEndian.Uint32(message[index+20 : index+24]),
		Mode: binary.LittleEndian.Uint32(message[index+24 : index+28]),
	}
	return stat, index + 28
}

func decodePrivateTemporaryInit(message []byte) (privateTemporaryInit, error) {
	const fixed = 2 + 2*(8+8+4+4+4) + privateTemporaryNonceSize
	if len(message) < len(privateTemporaryInitMagic)+fixed || len(message) > privateTemporaryMessageMax || string(message[:len(privateTemporaryInitMagic)]) != privateTemporaryInitMagic {
		return privateTemporaryInit{}, errors.New("malformed private temporary initialization")
	}
	index := len(privateTemporaryInitMagic)
	namespaceLength := int(message[index])
	index++
	if namespaceLength <= 0 || index+namespaceLength+1 > len(message) {
		return privateTemporaryInit{}, errors.New("malformed private temporary namespace name")
	}
	namespaceName := string(message[index : index+namespaceLength])
	index += namespaceLength
	nameLength := int(message[index])
	index++
	if nameLength <= 0 || index+nameLength+fixed-2 != len(message) {
		return privateTemporaryInit{}, errors.New("malformed private temporary leaf name")
	}
	name := string(message[index : index+nameLength])
	index += nameLength
	if !validPrivateNamespaceName(namespaceName) || !validPrivateTemporaryName(name) {
		return privateTemporaryInit{}, errors.New("invalid private temporary name")
	}
	var request privateTemporaryInit
	request.namespaceName, request.name = namespaceName, name
	request.namespace, index = decodeTemporaryStat(message, index)
	request.leaf, index = decodeTemporaryStat(message, index)
	copy(request.nonce[:], message[index:])
	if request.namespace.Mode != unix.S_IFDIR|privateNamespaceMode || request.leaf.Mode != unix.S_IFDIR|privateTemporaryMode ||
		request.namespace.Uid != request.leaf.Uid || request.namespace.Gid != request.leaf.Gid {
		return privateTemporaryInit{}, errors.New("unexpected private temporary directory modes")
	}
	return request, nil
}

func readPrivateTemporaryInit(controlFD int) (privateTemporaryInit, error) {
	message := make([]byte, privateTemporaryMessageMax)
	control := make([]byte, unix.CmsgSpace(16*4))
	n, controlN, flags, _, err := unix.Recvmsg(controlFD, message, control, 0)
	controlErr := closeReceivedDescriptors(control[:controlN])
	if err != nil || n == 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || controlErr != nil {
		return privateTemporaryInit{}, errors.New("read private temporary initialization failed")
	}
	return decodePrivateTemporaryInit(message[:n])
}

func validatePrivateTemporaryLocation(namespaceFD, leafFD int, initialization privateTemporaryInit) error {
	if !validPrivateNamespaceName(initialization.namespaceName) {
		return errors.New("private temporary invocation namespace name is invalid")
	}
	var namespace, leaf unix.Stat_t
	if err := unix.Fstat(namespaceFD, &namespace); err != nil || !privateTemporaryStatMatches(&namespace,
		uint64(initialization.namespace.Dev), initialization.namespace.Ino,
		initialization.namespace.Uid, initialization.namespace.Gid, initialization.namespace.Mode) ||
		namespace.Mode != unix.S_IFDIR|privateNamespaceMode {
		return errors.New("private temporary invocation namespace descriptor changed")
	}
	if err := unix.Fstat(leafFD, &leaf); err != nil || !privateTemporaryStatMatches(&leaf,
		uint64(initialization.leaf.Dev), initialization.leaf.Ino,
		initialization.leaf.Uid, initialization.leaf.Gid, initialization.leaf.Mode) ||
		leaf.Mode != unix.S_IFDIR|privateTemporaryMode || leaf.Uid != namespace.Uid || leaf.Gid != namespace.Gid {
		return errors.New("private temporary leaf descriptor changed")
	}
	rootFD, err := unix.Open("/tmp", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("private temporary filesystem root is unavailable")
	}
	defer unix.Close(rootFD)
	var root, entry unix.Stat_t
	if err := unix.Fstat(rootFD, &root); err != nil || root.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("private temporary filesystem root is unexpected")
	}
	if err := unix.Fstatat(rootFD, initialization.namespaceName, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameObject(&namespace, &entry) || entry.Mode != unix.S_IFDIR|privateNamespaceMode {
		return errors.New("private temporary invocation namespace entry changed")
	}
	if err := unix.Fstatat(namespaceFD, initialization.name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameObject(&leaf, &entry) || entry.Mode != unix.S_IFDIR|privateTemporaryMode {
		return errors.New("private temporary leaf entry changed")
	}
	return nil
}

func closeReceivedDescriptors(control []byte) error {
	if len(control) == 0 {
		return nil
	}
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return err
	}
	var closeErr error
	for _, message := range messages {
		fds, parseErr := unix.ParseUnixRights(&message)
		if parseErr == nil {
			for _, fd := range fds {
				if err := unix.Close(fd); err != nil && closeErr == nil {
					closeErr = err
				}
			}
		}
		if parseErr != nil && closeErr == nil {
			closeErr = parseErr
		}
	}
	if closeErr == nil {
		closeErr = errors.New("unexpected control message")
	}
	return closeErr
}

func sameObject(left, right *unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode&unix.S_IFMT == right.Mode&unix.S_IFMT && left.Uid == right.Uid && left.Gid == right.Gid
}

func decodePrivateTemporaryMessage(message []byte, expectedName string, expectedNonce [privateTemporaryNonceSize]byte) (uint64, uint64, uint32, uint32, uint32, error) {
	if len(message) < len(privateTemporaryMessageMagic)+1+8+8+4+4+privateTemporaryNonceSize || len(message) > privateTemporaryMessageMax || string(message[:len(privateTemporaryMessageMagic)]) != privateTemporaryMessageMagic {
		return 0, 0, 0, 0, 0, errors.New("prepare Naabu temporary directory: malformed readiness message")
	}
	index := len(privateTemporaryMessageMagic)
	nameLength := int(message[index])
	index++
	if nameLength != len(expectedName) || index+nameLength+8+8+4+4+privateTemporaryNonceSize != len(message) {
		return 0, 0, 0, 0, 0, errors.New("prepare Naabu temporary directory: malformed readiness message")
	}
	if string(message[index:index+nameLength]) != expectedName {
		return 0, 0, 0, 0, 0, errors.New("prepare Naabu temporary directory: helper returned an unexpected name")
	}
	index += nameLength
	device := binary.LittleEndian.Uint64(message[index : index+8])
	index += 8
	inode := binary.LittleEndian.Uint64(message[index : index+8])
	index += 8
	uid := binary.LittleEndian.Uint32(message[index : index+4])
	index += 4
	gid := binary.LittleEndian.Uint32(message[index : index+4])
	index += 4
	if !bytes.Equal(message[index:], expectedNonce[:]) {
		return 0, 0, 0, 0, 0, errors.New("prepare Naabu temporary directory: readiness nonce mismatch")
	}
	return device, inode, uid, gid, unix.S_IFDIR | privateTemporaryMode, nil
}

func encodePrivateTemporaryMessage(name string, nonce [privateTemporaryNonceSize]byte, stat *unix.Stat_t) ([]byte, error) {
	if !validPrivateTemporaryName(name) || len(name) > 255 || stat == nil {
		return nil, errors.New("invalid private temporary directory name")
	}
	message := make([]byte, len(privateTemporaryMessageMagic)+1+len(name)+8+8+4+4+privateTemporaryNonceSize)
	index := copy(message, privateTemporaryMessageMagic)
	message[index] = byte(len(name))
	index++
	index += copy(message[index:], name)
	binary.LittleEndian.PutUint64(message[index:index+8], uint64(stat.Dev))
	index += 8
	binary.LittleEndian.PutUint64(message[index:index+8], stat.Ino)
	index += 8
	binary.LittleEndian.PutUint32(message[index:index+4], stat.Uid)
	index += 4
	binary.LittleEndian.PutUint32(message[index:index+4], stat.Gid)
	index += 4
	copy(message[index:], nonce[:])
	return message, nil
}

func validPrivateTemporaryName(name string) bool {
	if !strings.HasPrefix(name, privateTemporaryPrefix) || len(name) != len(privateTemporaryPrefix)+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(name, privateTemporaryPrefix))
	return err == nil
}

func validPrivateNamespaceName(name string) bool {
	if !strings.HasPrefix(name, privateNamespacePrefix) || len(name) != len(privateNamespacePrefix)+privateTemporaryNonceSize*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(name, privateNamespacePrefix))
	return err == nil
}

type privateTemporaryCleanupRequest struct {
	device   uint64
	inode    uint64
	leafUID  uint32
	leafGID  uint32
	uid      uint32
	gid      uint32
	landlock bool
}

func parsePrivateTemporaryCleanupArgs(args []string) (privateTemporaryCleanupRequest, error) {
	const usage = "usage: sandbox-exec --cleanup-private-tmp --device N --inode N --leaf-uid N --leaf-gid N --uid N --gid N [--landlock]"
	values := map[string]string{}
	landlock := false
	for index := 0; index < len(args); index++ {
		if args[index] == "--landlock" {
			if landlock {
				return privateTemporaryCleanupRequest{}, errors.New(usage)
			}
			landlock = true
			continue
		}
		if index+1 >= len(args) || !strings.HasPrefix(args[index], "--") {
			return privateTemporaryCleanupRequest{}, errors.New(usage)
		}
		key := args[index]
		if _, exists := values[key]; exists {
			return privateTemporaryCleanupRequest{}, errors.New(usage)
		}
		values[key] = args[index+1]
		index++
	}
	expected := map[string]bool{"--device": true, "--inode": true, "--leaf-uid": true, "--leaf-gid": true, "--uid": true, "--gid": true}
	if len(values) != len(expected) {
		return privateTemporaryCleanupRequest{}, errors.New(usage)
	}
	for key := range values {
		if !expected[key] || values[key] == "" {
			return privateTemporaryCleanupRequest{}, errors.New(usage)
		}
	}
	device, errDevice := strconv.ParseUint(values["--device"], 10, 64)
	inode, errInode := strconv.ParseUint(values["--inode"], 10, 64)
	leafUID, errLeafUID := strconv.ParseUint(values["--leaf-uid"], 10, 32)
	leafGID, errLeafGID := strconv.ParseUint(values["--leaf-gid"], 10, 32)
	uid, errUID := strconv.ParseUint(values["--uid"], 10, 32)
	gid, errGID := strconv.ParseUint(values["--gid"], 10, 32)
	if errDevice != nil || errInode != nil || errLeafUID != nil || errLeafGID != nil || errUID != nil || errGID != nil {
		return privateTemporaryCleanupRequest{}, errors.New(usage)
	}
	return privateTemporaryCleanupRequest{
		device: device, inode: inode, leafUID: uint32(leafUID), leafGID: uint32(leafGID),
		uid: uint32(uid), gid: uint32(gid), landlock: landlock,
	}, nil
}

func cleanupPrivateTemporaryDirectoryWithDescriptor(args []string, descriptor int) error {
	request, err := parsePrivateTemporaryCleanupArgs(args)
	if err != nil {
		return err
	}
	return cleanupPrivateTemporaryDirectoryRequestWithDescriptor(request, descriptor)
}

func cleanupPrivateTemporaryDirectoryRequestWithDescriptor(request privateTemporaryCleanupRequest, descriptor int) error {
	leafFD, err := unix.FcntlInt(uintptr(descriptor), unix.F_DUPFD_CLOEXEC, 4)
	if err != nil {
		return errors.New("cleanup Naabu temporary directory: leaf descriptor unavailable")
	}
	defer unix.Close(leafFD)
	stat, err := validatePrivateTemporaryCleanupLeaf(request, leafFD)
	if err != nil {
		return err
	}
	if request.landlock {
		if err := restrictSelfWithPrivateDirectory(profilePaths(Scanner, os.Getenv), nil, leafFD); err != nil {
			return fmt.Errorf("cleanup Naabu temporary directory: restrict cleaner: %w", err)
		}
	}
	return cleanPrivateDirectoryContents(leafFD, &stat, request.uid, request.gid)
}

// cleanupPrivateTemporaryDirectoryFD validates a pinned leaf and removes its
// bounded contents. The production helper calls it with the inherited leaf
// descriptor after applying the requested policy; tests can exercise the same
// identity and cleanup path without changing thread-local Landlock state.
func cleanupPrivateTemporaryDirectoryFD(request privateTemporaryCleanupRequest, leafFD int) error {
	stat, err := validatePrivateTemporaryCleanupLeaf(request, leafFD)
	if err != nil {
		return err
	}
	return cleanPrivateDirectoryContents(leafFD, &stat, request.uid, request.gid)
}

func validatePrivateTemporaryCleanupLeaf(request privateTemporaryCleanupRequest, leafFD int) (unix.Stat_t, error) {
	if uint32(os.Geteuid()) != request.uid || uint32(os.Getegid()) != request.gid {
		return unix.Stat_t{}, errors.New("cleanup Naabu temporary directory: invalid ownership")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(leafFD, &stat); err != nil || uint64(stat.Dev) != request.device || stat.Ino != request.inode || stat.Uid != request.leafUID || stat.Gid != request.leafGID || stat.Mode != unix.S_IFDIR|privateTemporaryMode {
		return unix.Stat_t{}, errors.New("cleanup Naabu temporary directory: pinned directory identity changed")
	}
	return stat, nil
}

type cleanupBudget struct{ entries int }

func cleanPrivateDirectoryContents(leafFD int, expected *unix.Stat_t, owner, group uint32) error {
	if expected == nil || (expected.Mode != unix.S_IFDIR|privateTemporaryMode && expected.Mode != unix.S_IFDIR|privateTemporaryFallbackMode) {
		return errors.New("invalid private temporary leaf")
	}
	var current unix.Stat_t
	if err := unix.Fstat(leafFD, &current); err != nil || !sameObject(expected, &current) || current.Mode != expected.Mode {
		return errors.New("private temporary leaf identity changed")
	}
	duplicate, err := unix.Openat(leafFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("open private temporary directory failed")
	}
	budget := cleanupBudget{}
	if err := removePrivateDirectoryContents(duplicate, expected.Dev, owner, group, 0, &budget); err != nil {
		return err
	}
	if err := unix.Fstat(leafFD, &current); err != nil || !sameObject(expected, &current) || current.Mode != expected.Mode {
		return errors.New("private temporary leaf changed during cleanup")
	}
	return nil
}

func removePrivateDirectoryContents(fd int, device uint64, owner, group uint32, depth int, budget *cleanupBudget) error {
	if depth > privateTemporaryCleanupDepth {
		_ = unix.Close(fd)
		return errors.New("private temporary directory is too deep")
	}
	directory := os.NewFile(uintptr(fd), "private temporary contents")
	defer directory.Close()
	for {
		entries, err := directory.ReadDir(128)
		for _, entry := range entries {
			budget.entries++
			if budget.entries > privateTemporaryCleanupEntries {
				return errors.New("private temporary directory has too many entries")
			}
			if entry.Name() == "." || entry.Name() == ".." || strings.ContainsRune(entry.Name(), '/') || strings.ContainsRune(entry.Name(), '\x00') {
				return errors.New("private temporary directory contains an invalid entry")
			}
			var item unix.Stat_t
			if err := unix.Fstatat(int(directory.Fd()), entry.Name(), &item, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return errors.New("inspect private temporary entry failed")
			}
			if uint64(item.Dev) != device || item.Uid != owner || item.Gid != group {
				return errors.New("private temporary entry ownership changed")
			}
			if item.Mode&unix.S_IFMT == unix.S_IFDIR {
				child, err := unix.Openat(int(directory.Fd()), entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
				if err != nil {
					return errors.New("open private temporary subdirectory failed")
				}
				var opened unix.Stat_t
				if err := unix.Fstat(child, &opened); err != nil || !sameObject(&item, &opened) {
					_ = unix.Close(child)
					return errors.New("private temporary subdirectory identity changed")
				}
				if err := removePrivateDirectoryContents(child, device, owner, group, depth+1, budget); err != nil {
					return err
				}
				var current unix.Stat_t
				if err := unix.Fstatat(int(directory.Fd()), entry.Name(), &current, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameObject(&item, &current) {
					return errors.New("private temporary subdirectory changed during cleanup")
				}
				if err := unix.Unlinkat(int(directory.Fd()), entry.Name(), unix.AT_REMOVEDIR); err != nil {
					return errors.New("remove private temporary subdirectory failed")
				}
				continue
			}
			if item.Mode&unix.S_IFMT != unix.S_IFREG && item.Mode&unix.S_IFMT != unix.S_IFLNK {
				return errors.New("private temporary directory contains an unsupported entry")
			}
			var current unix.Stat_t
			if err := unix.Fstatat(int(directory.Fd()), entry.Name(), &current, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameObject(&item, &current) {
				return errors.New("private temporary entry changed during cleanup")
			}
			if err := unix.Unlinkat(int(directory.Fd()), entry.Name(), 0); err != nil {
				return errors.New("remove private temporary entry failed")
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return errors.New("read private temporary directory failed")
		}
	}
}

func helperSendPrivateTemporaryReady(controlFD int, name string, nonce [privateTemporaryNonceSize]byte, stat *unix.Stat_t) error {
	message, err := encodePrivateTemporaryMessage(name, nonce, stat)
	if err != nil {
		return err
	}
	n, err := unix.SendmsgN(controlFD, message, nil, nil, 0)
	if err != nil || n != len(message) {
		return errors.New("send private temporary readiness failed")
	}
	var reply [2]byte
	n, err = unix.Read(controlFD, reply[:])
	if err != nil || n != 1 || reply[0] != 1 {
		return errors.New("private temporary readiness was not acknowledged")
	}
	return nil
}
