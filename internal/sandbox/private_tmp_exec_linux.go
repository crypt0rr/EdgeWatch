//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

type privateTemporaryExecSetup struct {
	initialization privateTemporaryInit
	stat           unix.Stat_t
	environment    []string
}

// preparePrivateTemporaryExec checks the parent-pinned descriptors and
// handshake packet before the helper applies thread-local restrictions.
func preparePrivateTemporaryExec(request execRequest) (privateTemporaryExecSetup, error) {
	controlType, err := unix.GetsockoptInt(request.controlFD, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || controlType != unix.SOCK_SEQPACKET {
		return privateTemporaryExecSetup{}, errors.New("private temporary control channel is invalid")
	}
	initialization, err := readPrivateTemporaryInit(request.controlFD)
	if err != nil {
		return privateTemporaryExecSetup{}, err
	}
	if err := validatePrivateTemporaryLocation(request.privateRootFD, request.privateLeafFD, initialization); err != nil {
		return privateTemporaryExecSetup{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(request.privateLeafFD, &stat); err != nil {
		return privateTemporaryExecSetup{}, errors.New("inspect private temporary leaf failed")
	}
	path := "/tmp/" + initialization.namespaceName + "/" + initialization.name
	environment, err := privateTemporaryExecutionEnvironment(os.Environ(), path)
	if err != nil {
		return privateTemporaryExecSetup{}, errors.New("set private temporary directory failed")
	}
	return privateTemporaryExecSetup{initialization: initialization, stat: stat, environment: environment}, nil
}

type privateTemporaryCreateExecSetup struct {
	initialization privateTemporaryInit
	rootStat       unix.Stat_t
	namespaceStat  unix.Stat_t
	leafStat       unix.Stat_t
	environment    []string
}

func preparePrivateTemporaryCreateExec(request execRequest) (privateTemporaryCreateExecSetup, error) {
	controlType, err := unix.GetsockoptInt(request.controlFD, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || controlType != unix.SOCK_SEQPACKET {
		return privateTemporaryCreateExecSetup{}, errors.New("private temporary control channel is invalid")
	}
	initialization, err := readPrivateTemporaryCreateInit(request.controlFD)
	if err != nil {
		return privateTemporaryCreateExecSetup{}, err
	}
	rootFD, namespaceFD := request.privateRootFD, request.privateNamespaceFD
	var root, namespace unix.Stat_t
	if err := unix.Fstat(rootFD, &root); err != nil || !privateTemporaryStatMatches(&root,
		uint64(initialization.root.Dev), initialization.root.Ino,
		initialization.root.Uid, initialization.root.Gid, initialization.root.Mode) {
		return privateTemporaryCreateExecSetup{}, errors.New("private temporary root descriptor changed")
	}
	if err := unix.Fstat(namespaceFD, &namespace); err != nil || !privateTemporaryStatMatches(&namespace,
		uint64(initialization.namespace.Dev), initialization.namespace.Ino,
		initialization.namespace.Uid, initialization.namespace.Gid, initialization.namespace.Mode) ||
		namespace.Mode != unix.S_IFDIR|privateScannerNamespaceMode || namespace.Dev != root.Dev {
		return privateTemporaryCreateExecSetup{}, errors.New("private temporary invocation namespace descriptor changed")
	}
	currentRootFD, err := unix.Open("/tmp", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return privateTemporaryCreateExecSetup{}, errors.New("private temporary filesystem root is unavailable")
	}
	defer unix.Close(currentRootFD)
	var currentRoot, namedNamespace unix.Stat_t
	if err := unix.Fstat(currentRootFD, &currentRoot); err != nil || !sameObject(&root, &currentRoot) {
		return privateTemporaryCreateExecSetup{}, errors.New("private temporary filesystem root changed")
	}
	if err := unix.Fstatat(rootFD, initialization.namespaceName, &namedNamespace, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameObject(&namespace, &namedNamespace) || namedNamespace.Mode != namespace.Mode {
		return privateTemporaryCreateExecSetup{}, errors.New("private temporary invocation namespace entry changed")
	}
	var existing unix.Stat_t
	if err := unix.Fstatat(namespaceFD, initialization.name, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil || !errors.Is(err, unix.ENOENT) {
		return privateTemporaryCreateExecSetup{}, errors.New("private temporary leaf name is already present")
	}
	if err := unix.Mkdirat(namespaceFD, initialization.name, privateScannerTemporaryMode); err != nil {
		return privateTemporaryCreateExecSetup{}, errors.New("create scanner-owned private temporary leaf failed")
	}
	leafFD, err := unix.Openat(namespaceFD, initialization.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		rollbackCreatedTemporaryLeaf(namespaceFD, initialization.name)
		return privateTemporaryCreateExecSetup{}, errors.New("pin scanner-owned private temporary leaf failed")
	}
	rollback := true
	defer func() {
		_ = unix.Close(leafFD)
		if rollback {
			rollbackCreatedTemporaryLeaf(namespaceFD, initialization.name)
		}
	}()
	if err := unix.Fchmod(leafFD, privateScannerTemporaryMode); err != nil {
		return privateTemporaryCreateExecSetup{}, errors.New("set scanner-owned private temporary leaf mode failed")
	}
	var leaf, namedLeaf unix.Stat_t
	if err := unix.Fstat(leafFD, &leaf); err != nil || leaf.Mode != unix.S_IFDIR|privateScannerTemporaryMode || leaf.Uid != uint32(os.Geteuid()) || leaf.Gid != uint32(os.Getegid()) || leaf.Dev != namespace.Dev {
		return privateTemporaryCreateExecSetup{}, errors.New("scanner-owned private temporary leaf identity is unexpected")
	}
	if err := unix.Fstatat(namespaceFD, initialization.name, &namedLeaf, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameObject(&leaf, &namedLeaf) || namedLeaf.Mode != leaf.Mode || namedLeaf.Uid != leaf.Uid || namedLeaf.Gid != leaf.Gid {
		return privateTemporaryCreateExecSetup{}, errors.New("scanner-owned private temporary leaf entry changed")
	}
	path := "/tmp/" + initialization.namespaceName + "/" + initialization.name
	environment, err := privateTemporaryExecutionEnvironment(os.Environ(), path)
	if err != nil {
		return privateTemporaryCreateExecSetup{}, errors.New("set private temporary directory failed")
	}
	rollback = false
	return privateTemporaryCreateExecSetup{initialization: initialization, rootStat: root, namespaceStat: namespace, leafStat: leaf, environment: environment}, nil
}

func execPrivateTemporaryCreate(request execRequest) error {
	runtime.LockOSThread()
	limitScannerResources()
	rootFD, namespaceFD, controlFD := request.privateRootFD, request.privateNamespaceFD, request.controlFD
	defer func() {
		_ = closePrivateTemporaryControlDescriptors(rootFD, namespaceFD, controlFD)
	}()
	setup, err := preparePrivateTemporaryCreateExec(request)
	if err != nil {
		return fmt.Errorf("%s: %w", ExecCommand, err)
	}
	var leafFD int
	// The parent will pin the leaf itself from the namespace descriptor before
	// acknowledging readiness. Until then, the helper retains this directory
	// descriptor only so it can install the leaf-only Landlock rule.
	leafFD, err = unix.Openat(namespaceFD, setup.initialization.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("scanner-owned private temporary leaf is unavailable")
	}
	defer func() {
		if leafFD >= 0 {
			_ = unix.Close(leafFD)
		}
	}()
	var leaf unix.Stat_t
	if err := unix.Fstat(leafFD, &leaf); err != nil || !sameObject(&setup.leafStat, &leaf) || leaf.Mode != setup.leafStat.Mode {
		return errors.New("scanner-owned private temporary leaf changed before readiness")
	}
	if request.landlock {
		if err := restrictPrivateTemporary(request, leafFD); err != nil {
			return fmt.Errorf("%s: %w", ExecCommand, err)
		}
	}
	if err := helperSendPrivateTemporaryCreateReady(controlFD, setup.initialization.name, setup.initialization.nonce, &leaf); err != nil {
		return fmt.Errorf("%s: %w", ExecCommand, err)
	}
	if err := closePrivateTemporaryControlDescriptors(rootFD, namespaceFD, controlFD, leafFD); err != nil {
		return fmt.Errorf("%s: close private temporary control descriptor: %w", ExecCommand, err)
	}
	rootFD, namespaceFD, controlFD, leafFD = -1, -1, -1, -1
	if request.seccomp {
		if !request.landlock {
			if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
				return fmt.Errorf("%s: set no_new_privs: %w", ExecCommand, err)
			}
		}
		if err := installSeccompFilter(); err != nil {
			return fmt.Errorf("%s: %w", ExecCommand, err)
		}
	}
	if err := syscall.Exec(request.argv[0], request.argv, setup.environment); err != nil {
		return fmt.Errorf("%s: execute %s: %w", ExecCommand, request.argv[0], err)
	}
	return nil
}

func rollbackCreatedTemporaryLeaf(namespaceFD int, name string) {
	var named unix.Stat_t
	if err := unix.Fstatat(namespaceFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || named.Mode&unix.S_IFMT != unix.S_IFDIR || named.Uid != uint32(os.Geteuid()) || named.Gid != uint32(os.Getegid()) {
		return
	}
	fd, err := unix.Openat(namespaceFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	var pinned unix.Stat_t
	if err := unix.Fstat(fd, &pinned); err == nil && sameObject(&named, &pinned) {
		_ = unix.Unlinkat(namespaceFD, name, unix.AT_REMOVEDIR)
	}
	_ = unix.Close(fd)
}

// privateTemporaryLandlockRules returns only scanner data descriptors and
// the normal scanner profile. The namespace, leaf, and control descriptors
// remain outside the inherited data-file rules.
func privateTemporaryLandlockRules(request execRequest) ([]landlockPath, []int) {
	inherited := make([]int, request.files)
	for index := range inherited {
		inherited[index] = 3 + index
	}
	return profilePaths(Scanner, os.Getenv), inherited
}

func restrictPrivateTemporary(request execRequest, leafFD int) error {
	if !request.landlock {
		return nil
	}
	paths, inherited := privateTemporaryLandlockRules(request)
	return restrictSelfWithPrivateDirectory(paths, inherited, leafFD)
}

// closePrivateTemporaryControlDescriptors closes every helper-only descriptor
// even if one close reports an error. Scanner data descriptors are untouched.
func closePrivateTemporaryControlDescriptors(descriptors ...int) error {
	var closeErr error
	for _, descriptor := range descriptors {
		if descriptor >= 0 {
			if err := unix.Close(descriptor); err != nil && closeErr == nil {
				closeErr = err
			}
		}
	}
	return closeErr
}
