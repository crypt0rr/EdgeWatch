//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const (
	scannerIdentityTransitionLock = "transition.lock"
	scannerIdentityLivenessLock   = "liveness.lock"

	// Linux fcntl command values from include/uapi/asm-generic/fcntl.h. x/sys
	// does not expose the OFD locking commands on every supported architecture.
	scannerFcntlOFDSetLK  = 37
	scannerFcntlOFDSetLKW = 38
)

// scannerIdentityScopeLock holds the short cross-process transition gate,
// allocator lock, and a shared reference to this durable scanner-identity
// scope. The liveness lock is an OFD lock: scanner descendants inherit its
// read-only descriptor and keep the lock alive until the last copy closes.
type scannerIdentityScopeLock struct {
	directoryFD int
	markerFD    int
	gateFD      int
	allocatorFD int
	keeper      *os.File
	inherited   *os.File
	lockedAlloc bool
	lockedGate  bool
}

func (scope *scannerIdentityScopeLock) close() {
	if scope == nil {
		return
	}
	if scope.lockedAlloc && scope.allocatorFD >= 0 {
		_ = unix.Flock(scope.allocatorFD, unix.LOCK_UN)
		scope.lockedAlloc = false
	}
	if scope.allocatorFD >= 0 {
		_ = unix.Close(scope.allocatorFD)
		scope.allocatorFD = -1
	}
	if scope.inherited != nil {
		_ = scope.inherited.Close()
		scope.inherited = nil
	}
	if scope.keeper != nil {
		_ = scope.keeper.Close()
		scope.keeper = nil
	}
	if scope.lockedGate && scope.gateFD >= 0 {
		_ = unix.Flock(scope.gateFD, unix.LOCK_UN)
		scope.lockedGate = false
	}
	if scope.gateFD >= 0 {
		_ = unix.Close(scope.gateFD)
		scope.gateFD = -1
	}
	if scope.markerFD >= 0 {
		_ = unix.Close(scope.markerFD)
		scope.markerFD = -1
	}
	if scope.directoryFD >= 0 {
		_ = unix.Close(scope.directoryFD)
		scope.directoryFD = -1
	}
}

func (scope *scannerIdentityScopeLock) takeInheritedLivenessFile() (*os.File, error) {
	if scope == nil {
		return nil, errors.New("scanner identity scope lock is unavailable")
	}
	if scope.inherited == nil {
		return nil, errors.New("scanner identity inherited liveness reference is unavailable")
	}
	flags, err := unix.FcntlInt(scope.inherited.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return nil, errors.New("scanner identity inherited liveness reference is not read-only")
	}
	inherited := scope.inherited
	scope.inherited = nil
	return inherited, nil
}

func (scope *scannerIdentityScopeLock) downgradeLiveness(directoryFD int) error {
	if scope == nil || scope.keeper == nil || scope.inherited != nil {
		return errors.New("scanner identity exclusive liveness scope is unavailable")
	}
	keeper, inherited, err := downgradeScannerIdentityLiveness(directoryFD, scope.keeper)
	if err != nil {
		return err
	}
	if err := scope.keeper.Close(); err != nil {
		_ = inherited.Close()
		_ = keeper.Close()
		return errors.New("scanner identity exclusive liveness descriptor could not be closed")
	}
	scope.keeper, scope.inherited = keeper, inherited
	return nil
}

func (scope *scannerIdentityScopeLock) retainRuntimeReference(allocator *scannerIdentityAllocator) error {
	if scope == nil || allocator == nil || scope.keeper == nil {
		return errors.New("scanner identity runtime liveness reference is unavailable")
	}
	allocator.runtimeLivenessMu.Lock()
	defer allocator.runtimeLivenessMu.Unlock()
	if allocator.runtimeLivenessReference == nil {
		allocator.runtimeLivenessReference = scope.keeper
		scope.keeper = nil
		return nil
	}
	return nil
}

// retainScannerIdentityRuntimeReference creates and releases a short
// validation lease while preserving the allocator's process-lifetime shared
// OFD reference. Detect calls this before the daemon reports a usable scanner
// policy, including when the probe executable is absent from the image.
func retainScannerIdentityRuntimeReference(ctx context.Context, allocator *scannerIdentityAllocator) error {
	if allocator == nil || !allocator.persistRuntimeLiveness {
		return errors.New("scanner identity runtime liveness is not configured")
	}
	lease, err := allocator.acquire(ctx)
	if err != nil {
		return err
	}
	if err := lease.release(); err != nil {
		return errors.New("scanner identity runtime liveness could not be retained")
	}
	allocator.runtimeLivenessMu.Lock()
	retained := allocator.runtimeLivenessReference != nil
	allocator.runtimeLivenessMu.Unlock()
	if !retained {
		return errors.New("scanner identity runtime liveness reference is missing")
	}
	return nil
}

func (allocator *scannerIdentityAllocator) runtimeLivenessFile() (*os.File, error) {
	if allocator == nil {
		return nil, errors.New("scanner identity runtime liveness is unavailable")
	}
	allocator.runtimeLivenessMu.Lock()
	file := allocator.runtimeLivenessReference
	allocator.runtimeLivenessMu.Unlock()
	if err := validateScannerLivenessParentFile(file); err != nil {
		return nil, err
	}
	return file, nil
}

func (scope *scannerIdentityScopeLock) releaseTransitionGate() error {
	if scope == nil || !scope.lockedGate || scope.gateFD < 0 {
		return errors.New("scanner identity transition gate is unavailable")
	}
	if err := unix.Flock(scope.gateFD, unix.LOCK_UN); err != nil {
		return errors.New("scanner identity transition gate could not be released")
	}
	scope.lockedGate = false
	return nil
}

func (scope *scannerIdentityScopeLock) lockAllocator(ctx context.Context) error {
	if ctx == nil || scope == nil || scope.directoryFD < 0 || scope.allocatorFD >= 0 || !scope.lockedGate || scope.keeper == nil {
		return errors.New("scanner identity allocator lock order is invalid")
	}
	fd, err := openScannerIdentityLock(scope.directoryFD)
	if err != nil {
		return errors.New("scanner identity allocator lock is unavailable")
	}
	if err := lockScannerIdentity(ctx, fd); err != nil {
		_ = unix.Close(fd)
		return err
	}
	scope.allocatorFD = fd
	scope.lockedAlloc = true
	return nil
}

func openScannerIdentityTransitionLock(directoryFD int) (int, error) {
	return openScannerIdentityNamedLock(directoryFD, scannerIdentityTransitionLock)
}

// beginScannerIdentityScopeLock takes ownership of directoryFD and markerFD,
// then takes the transition gate before inspecting liveness. All attach and
// recovery paths use this order so a downgrade cannot race a scope change.
func beginScannerIdentityScopeLock(ctx context.Context, directoryFD, markerFD int) (*scannerIdentityScopeLock, bool, error) {
	if ctx == nil || directoryFD < 0 || markerFD < 0 {
		return nil, false, errors.New("scanner identity scope lock inputs are invalid")
	}
	gateFD, err := openScannerIdentityTransitionLock(directoryFD)
	if err != nil {
		return nil, false, errors.New("scanner identity transition lock is unavailable")
	}
	if err := lockScannerIdentity(ctx, gateFD); err != nil {
		_ = unix.Close(gateFD)
		return nil, false, err
	}
	keeper, inherited, exclusive, err := acquireScannerIdentityLiveness(ctx, directoryFD)
	if err != nil {
		_ = unix.Flock(gateFD, unix.LOCK_UN)
		_ = unix.Close(gateFD)
		return nil, false, err
	}
	return &scannerIdentityScopeLock{
		directoryFD: directoryFD,
		markerFD:    markerFD,
		gateFD:      gateFD,
		allocatorFD: -1,
		keeper:      keeper,
		inherited:   inherited,
		lockedGate:  true,
	}, exclusive, nil
}

func openScannerIdentityLivenessFile(directoryFD int, writable bool) (*os.File, error) {
	flags := unix.O_RDONLY
	if writable {
		flags = unix.O_RDWR
	}
	fd, err := unix.Openat(directoryFD, scannerIdentityLivenessLock, unix.O_CLOEXEC|unix.O_NOFOLLOW|flags, 0)
	if errors.Is(err, unix.ENOENT) && writable {
		fd, err = unix.Openat(directoryFD, scannerIdentityLivenessLock, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err == nil {
			if chmodErr := unix.Fchmod(fd, 0o600); chmodErr != nil {
				_ = unix.Close(fd)
				return nil, errors.New("scanner identity liveness lock mode cannot be set")
			}
			if syncErr := unix.Fsync(directoryFD); syncErr != nil {
				_ = unix.Close(fd)
				return nil, errors.New("scanner identity liveness lock creation is not durable")
			}
		}
	}
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o600 || stat.Size != 0 {
		_ = unix.Close(fd)
		return nil, errors.New("scanner identity liveness lock metadata is invalid")
	}
	return os.NewFile(uintptr(fd), scannerIdentityLivenessLock), nil
}

func openScannerIdentityNamedLock(directoryFD int, name string) (int, error) {
	fd, err := unix.Openat(directoryFD, name, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(directoryFD, name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return -1, err
	}
	if created {
		if err := unix.Fchmod(fd, 0o600); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		if err := unix.Fsync(directoryFD); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o600 || stat.Size != 0 {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("scanner identity %s metadata is invalid", name)
	}
	return fd, nil
}

func setScannerIdentityOFDLock(fd int, lockType int16, nonblocking bool) error {
	command := scannerFcntlOFDSetLKW
	if nonblocking {
		command = scannerFcntlOFDSetLK
	}
	lock := unix.Flock_t{Type: lockType, Whence: int16(unix.SEEK_SET), Start: 0, Len: 0}
	return unix.FcntlFlock(uintptr(fd), command, &lock)
}

func acquireScannerIdentityLiveness(ctx context.Context, directoryFD int) (keeper, inherited *os.File, exclusive bool, err error) {
	if ctx == nil {
		return nil, nil, false, errors.New("scanner identity liveness: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, false, err
	}
	keeper, err = openScannerIdentityLivenessFile(directoryFD, true)
	if err != nil {
		return nil, nil, false, errors.New("scanner identity liveness lock is unavailable")
	}
	if err = setScannerIdentityOFDLock(int(keeper.Fd()), unix.F_WRLCK, true); err == nil {
		exclusive = true
	} else if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EACCES) {
		if closeErr := keeper.Close(); closeErr != nil {
			return nil, nil, false, errors.New("scanner identity liveness descriptor could not be reset")
		}
		// The long-lived parent keeper is read-only too. Only a temporary
		// exclusive recovery attempt uses a read-write descriptor.
		keeper, err = openScannerIdentityLivenessFile(directoryFD, false)
		if err != nil || setScannerIdentityOFDLock(int(keeper.Fd()), unix.F_RDLCK, true) != nil {
			if keeper != nil {
				_ = keeper.Close()
			}
			return nil, nil, false, errors.New("scanner identity liveness lock is unavailable")
		}
	} else {
		_ = keeper.Close()
		return nil, nil, false, errors.New("scanner identity liveness lock failed")
	}

	if exclusive {
		// The caller holds the exclusive transition gate while it validates and
		// updates durable scope. It downgrades this keeper before taking the
		// allocator lock for a lease reservation.
		return keeper, nil, true, nil
	}
	inherited, err = openScannerIdentityLivenessFile(directoryFD, false)
	if err == nil {
		err = setScannerIdentityOFDLock(int(inherited.Fd()), unix.F_RDLCK, true)
	}
	if err != nil {
		_ = keeper.Close()
		if inherited != nil {
			_ = inherited.Close()
		}
		return nil, nil, false, errors.New("scanner identity liveness reference could not be established")
	}
	return keeper, inherited, false, nil
}

func downgradeScannerIdentityLiveness(directoryFD int, keeper *os.File) (newKeeper, inherited *os.File, err error) {
	if keeper == nil {
		return nil, nil, errors.New("scanner identity liveness keeper is unavailable")
	}
	if err := setScannerIdentityOFDLock(int(keeper.Fd()), unix.F_RDLCK, true); err != nil {
		return nil, nil, errors.New("scanner identity liveness lock could not be downgraded")
	}
	inherited, err = openScannerIdentityLivenessFile(directoryFD, false)
	if err == nil {
		err = setScannerIdentityOFDLock(int(inherited.Fd()), unix.F_RDLCK, true)
	}
	if err != nil {
		if inherited != nil {
			_ = inherited.Close()
		}
		return nil, nil, errors.New("scanner identity inherited liveness reference could not be established")
	}
	newKeeper, err = openScannerIdentityLivenessFile(directoryFD, false)
	if err == nil {
		err = setScannerIdentityOFDLock(int(newKeeper.Fd()), unix.F_RDLCK, true)
	}
	if err != nil {
		if newKeeper != nil {
			_ = newKeeper.Close()
		}
		_ = inherited.Close()
		return nil, nil, errors.New("scanner identity read-only keeper could not be established")
	}
	return newKeeper, inherited, nil
}

// validateScannerLivenessDescriptor verifies the inherited descriptor in the
// scanner helper after credentials have changed. The helper cannot require
// the descriptor owner to match its own UID: the durable lock file is owned by
// the daemon. It does require the exact narrow file shape, read-only access,
// and an inheritable descriptor so the final scanner exec keeps the OFD lock.
func validateScannerLivenessDescriptor(fd int) error {
	if fd < 3 || fd >= 3+maxInheritedFiles {
		return errors.New("scanner liveness descriptor is outside the inherited range")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return errors.New("scanner liveness descriptor is not read-only")
	}
	descriptorFlags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || descriptorFlags&unix.FD_CLOEXEC != 0 {
		return errors.New("scanner liveness descriptor is not inherited")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size != 0 || stat.Mode&0o7777 != 0o600 {
		return errors.New("scanner liveness descriptor metadata is invalid")
	}
	return nil
}

func validateScannerLivenessParentFile(file *os.File) error {
	if file == nil {
		return errors.New("scanner liveness reference is unavailable")
	}
	flags, flagErr := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	descriptorFlags, descriptorErr := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	var stat unix.Stat_t
	if flagErr != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || descriptorErr != nil || descriptorFlags&unix.FD_CLOEXEC == 0 || unix.Fstat(int(file.Fd()), &stat) != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size != 0 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o600 {
		return errors.New("scanner liveness reference metadata is invalid")
	}
	return nil
}
