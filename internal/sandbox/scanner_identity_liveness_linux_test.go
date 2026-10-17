//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func scannerIdentityLockTestDirectory(t *testing.T) int {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "scanner-identities")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func scannerLivenessTestFile(t *testing.T) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), scannerIdentityLivenessLock)
	created, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := setScannerIdentityOFDLock(int(file.Fd()), unix.F_RDLCK, true); err != nil {
		_ = file.Close()
		t.Fatalf("lock test liveness descriptor: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func TestScannerIdentityLivenessSharedReferencesBlockRecovery(t *testing.T) {
	directoryFD := scannerIdentityLockTestDirectory(t)
	keeper, inherited, exclusive, err := acquireScannerIdentityLiveness(context.Background(), directoryFD)
	if err != nil {
		t.Fatal(err)
	}
	if !exclusive || inherited != nil {
		t.Fatalf("initial empty scope should be exclusively held, exclusive=%t inherited=%v", exclusive, inherited)
	}
	readOnlyKeeper, inherited, err := downgradeScannerIdentityLiveness(directoryFD, keeper)
	if err != nil {
		_ = keeper.Close()
		t.Fatal(err)
	}
	if err := keeper.Close(); err != nil {
		_ = readOnlyKeeper.Close()
		_ = inherited.Close()
		t.Fatal(err)
	}
	keeper = readOnlyKeeper
	defer keeper.Close()
	defer inherited.Close()

	if flags, err := unix.FcntlInt(inherited.Fd(), unix.F_GETFL, 0); err != nil {
		t.Fatal(err)
	} else if flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatalf("scanner reference is not read-only: flags=%#x", flags)
	}
	if err := setScannerIdentityOFDLock(int(inherited.Fd()), unix.F_WRLCK, true); !errors.Is(err, unix.EBADF) {
		t.Fatalf("read-only scanner reference must not permit write-lock upgrade, got %v", err)
	}

	secondKeeper, secondInherited, secondExclusive, err := acquireScannerIdentityLiveness(context.Background(), directoryFD)
	if err != nil {
		t.Fatal(err)
	}
	if secondExclusive || secondInherited == nil {
		t.Fatalf("live reference must permit only shared attach, exclusive=%t inherited=%v", secondExclusive, secondInherited)
	}
	_ = secondKeeper.Close()
	_ = secondInherited.Close()

	probe, err := openScannerIdentityLivenessFile(directoryFD, true)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if err := setScannerIdentityOFDLock(int(probe.Fd()), unix.F_WRLCK, true); !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EACCES) {
		t.Fatalf("exclusive recovery should be blocked by a shared scope reference, got %v", err)
	}
}

func TestScannerIdentityLeaseExposesOnlyItsReadOnlyLivenessReference(t *testing.T) {
	lease, err := newTestScannerIdentityAllocator(t, 1).acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	file, err := lease.inheritedScannerLivenessFile()
	if err != nil {
		t.Fatalf("read-only inherited liveness reference: %v", err)
	}
	if file != lease.livenessRef {
		t.Fatal("lease returned a different liveness reference")
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatalf("inherited liveness reference flags = %#x, %v; want read-only", flags, err)
	}
	if err := lease.release(); err != nil {
		t.Fatalf("release liveness lease: %v", err)
	}
	if _, err := lease.inheritedScannerLivenessFile(); err == nil {
		t.Fatal("finished lease still exposed its liveness reference")
	}
}

func TestScannerIdentityScopeLockEnforcesGateLivenessAllocatorOrder(t *testing.T) {
	directoryFD := scannerIdentityLockTestDirectory(t)
	ownedDirectoryFD, err := unix.Dup(directoryFD)
	if err != nil {
		t.Fatal(err)
	}
	ownedMarkerFD, err := unix.Dup(directoryFD)
	if err != nil {
		_ = unix.Close(ownedDirectoryFD)
		t.Fatal(err)
	}
	scope, exclusive, err := beginScannerIdentityScopeLock(context.Background(), ownedDirectoryFD, ownedMarkerFD)
	if err != nil {
		_ = unix.Close(ownedDirectoryFD)
		_ = unix.Close(ownedMarkerFD)
		t.Fatal(err)
	}
	if !exclusive {
		scope.close()
		t.Fatal("fresh scope should hold the exclusive recovery lock")
	}
	if err := scope.downgradeLiveness(directoryFD); err != nil {
		scope.close()
		t.Fatal(err)
	}
	if err := scope.lockAllocator(context.Background()); err != nil {
		scope.close()
		t.Fatal(err)
	}
	inherited, err := scope.takeInheritedLivenessFile()
	if err != nil {
		scope.close()
		t.Fatal(err)
	}
	if err := scope.releaseTransitionGate(); err != nil {
		_ = inherited.Close()
		scope.close()
		t.Fatal(err)
	}
	scope.close()

	probe, err := openScannerIdentityLivenessFile(directoryFD, true)
	if err != nil {
		_ = inherited.Close()
		t.Fatal(err)
	}
	if err := setScannerIdentityOFDLock(int(probe.Fd()), unix.F_WRLCK, true); !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EACCES) {
		_ = probe.Close()
		_ = inherited.Close()
		t.Fatalf("transferred inherited reference did not keep scope live, got %v", err)
	}
	if err := inherited.Close(); err != nil {
		_ = probe.Close()
		t.Fatal(err)
	}
	if err := setScannerIdentityOFDLock(int(probe.Fd()), unix.F_WRLCK, true); err != nil {
		_ = probe.Close()
		t.Fatalf("recovery could not acquire the released scope lock: %v", err)
	}
	_ = probe.Close()
}

func TestScannerIdentityLivenessSurvivesParentCloseInExecChild(t *testing.T) {
	directoryFD := scannerIdentityLockTestDirectory(t)
	keeper, _, exclusive, err := acquireScannerIdentityLiveness(context.Background(), directoryFD)
	if err != nil {
		t.Fatal(err)
	}
	if !exclusive {
		t.Fatal("first scope reference did not obtain the exclusive recovery lock")
	}
	readOnlyKeeper, inherited, err := downgradeScannerIdentityLiveness(directoryFD, keeper)
	if err != nil {
		_ = keeper.Close()
		t.Fatal(err)
	}
	if err := keeper.Close(); err != nil {
		_ = readOnlyKeeper.Close()
		_ = inherited.Close()
		t.Fatal(err)
	}
	keeper = readOnlyKeeper
	var expected unix.Stat_t
	if err := unix.Fstat(int(inherited.Fd()), &expected); err != nil {
		_ = keeper.Close()
		_ = inherited.Close()
		t.Fatal(err)
	}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		_ = keeper.Close()
		_ = inherited.Close()
		t.Fatal(err)
	}
	defer readyRead.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestScannerIdentityLivenessExecChild$")
	child.Env = append(os.Environ(),
		"EDGEWATCH_SCANNER_LIVENESS_CHILD=1",
		"EDGEWATCH_SCANNER_LIVENESS_DEV="+strconv.FormatUint(uint64(expected.Dev), 10),
		"EDGEWATCH_SCANNER_LIVENESS_INO="+strconv.FormatUint(expected.Ino, 10),
	)
	child.ExtraFiles = []*os.File{inherited, readyWrite}
	if err := child.Start(); err != nil {
		_ = keeper.Close()
		_ = inherited.Close()
		_ = readyWrite.Close()
		t.Fatal(err)
	}
	if err := readyWrite.Close(); err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		t.Fatal(err)
	}
	childDone := false
	t.Cleanup(func() {
		if !childDone {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
		_ = inherited.Close()
		_ = keeper.Close()
	})
	if err := waitScannerIdentityChildReady(readyRead); err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		childDone = true
		t.Fatalf("exec child did not validate inherited fd 3: %v", err)
	}
	if err := inherited.Close(); err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		childDone = true
		t.Fatal(err)
	}
	if err := keeper.Close(); err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		childDone = true
		t.Fatal(err)
	}

	probe, err := openScannerIdentityLivenessFile(directoryFD, true)
	if err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		childDone = true
		t.Fatal(err)
	}
	defer probe.Close()
	if err := setScannerIdentityOFDLock(int(probe.Fd()), unix.F_WRLCK, true); !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EACCES) {
		_ = child.Process.Kill()
		_ = child.Wait()
		childDone = true
		t.Fatalf("exec child should keep recovery blocked after parent descriptors close, got %v", err)
	}
	_ = child.Process.Kill()
	_ = child.Wait()
	childDone = true

	deadline := time.Now().Add(time.Second)
	for {
		err = setScannerIdentityOFDLock(int(probe.Fd()), unix.F_WRLCK, true)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EACCES) {
			t.Fatalf("exclusive recovery probe failed unexpectedly after child exit: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("exec child exit did not release the inherited OFD reference")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestScannerIdentityLivenessExecChild(t *testing.T) {
	if os.Getenv("EDGEWATCH_SCANNER_LIVENESS_CHILD") != "1" {
		return
	}
	expectedDevice, err := strconv.ParseUint(os.Getenv("EDGEWATCH_SCANNER_LIVENESS_DEV"), 10, 64)
	if err != nil {
		t.Fatalf("parse expected liveness device: %v", err)
	}
	expectedInode, err := strconv.ParseUint(os.Getenv("EDGEWATCH_SCANNER_LIVENESS_INO"), 10, 64)
	if err != nil {
		t.Fatalf("parse expected liveness inode: %v", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(3, &stat); err != nil {
		t.Fatalf("stat inherited liveness fd 3: %v", err)
	}
	if uint64(stat.Dev) != expectedDevice || stat.Ino != expectedInode {
		t.Fatalf("fd 3 is not the pinned liveness file: dev=%d ino=%d", stat.Dev, stat.Ino)
	}
	statusFlags, err := unix.FcntlInt(3, unix.F_GETFL, 0)
	if err != nil || statusFlags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatalf("fd 3 is not read-only: flags=%#x err=%v", statusFlags, err)
	}
	descriptorFlags, err := unix.FcntlInt(3, unix.F_GETFD, 0)
	if err != nil || descriptorFlags&unix.FD_CLOEXEC != 0 {
		t.Fatalf("fd 3 did not survive exec without close-on-exec: flags=%#x err=%v", descriptorFlags, err)
	}
	if _, err := unix.Write(3, []byte("forbidden")); !errors.Is(err, unix.EBADF) {
		t.Fatalf("fd 3 write must fail with EBADF, got %v", err)
	}
	ready := os.NewFile(4, "liveness child readiness")
	if ready == nil {
		t.Fatal("readiness fd 4 is unavailable")
	}
	if _, err := ready.Write([]byte("ok")); err != nil {
		t.Fatalf("write readiness fd 4: %v", err)
	}
	time.Sleep(30 * time.Second)
}

func waitScannerIdentityChildReady(pipe *os.File) error {
	if pipe == nil {
		return errors.New("readiness pipe is unavailable")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		poll := []unix.PollFd{{Fd: int32(pipe.Fd()), Events: unix.POLLIN | unix.POLLHUP}}
		count, err := unix.Poll(poll, 50)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		if count == 0 || poll[0].Revents&unix.POLLIN == 0 {
			if poll[0].Revents&unix.POLLHUP != 0 {
				return errors.New("child closed readiness pipe without a frame")
			}
			continue
		}
		frame := make([]byte, 2)
		n, err := unix.Read(int(pipe.Fd()), frame)
		if err != nil {
			return err
		}
		if n != len(frame) || string(frame) != "ok" {
			return errors.New("child readiness frame is invalid")
		}
		return nil
	}
	return errors.New("child readiness timed out")
}

func TestScannerIdentityScopeLocksArePermanentValidatedFiles(t *testing.T) {
	directoryFD := scannerIdentityLockTestDirectory(t)
	gateFD, err := openScannerIdentityTransitionLock(directoryFD)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(gateFD); err != nil {
		t.Fatal(err)
	}
	liveness, err := openScannerIdentityLivenessFile(directoryFD, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := liveness.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{scannerIdentityTransitionLock, scannerIdentityLivenessLock} {
		var stat unix.Stat_t
		if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			t.Fatalf("permanent lock %s was removed: %v", name, err)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o600 || stat.Size != 0 {
			t.Fatalf("permanent lock %s has unsafe metadata: %+v", name, stat)
		}
	}
}

func TestScannerIdentityLockFilesRejectUnsafeMetadata(t *testing.T) {
	for _, lock := range []struct {
		name string
		open func(int) (int, error)
	}{
		{name: scannerIdentityTransitionLock, open: openScannerIdentityTransitionLock},
		{name: scannerIdentityLivenessLock, open: func(directoryFD int) (int, error) {
			file, err := openScannerIdentityLivenessFile(directoryFD, true)
			if err != nil {
				return -1, err
			}
			fd := int(file.Fd())
			if err := file.Close(); err != nil {
				return -1, err
			}
			return fd, nil
		}},
	} {
		for _, metadata := range []string{"symlink", "wrong mode", "hard link", "nonempty"} {
			t.Run(lock.name+"/"+metadata, func(t *testing.T) {
				parent := t.TempDir()
				if err := os.Chmod(parent, 0o700); err != nil {
					t.Fatal(err)
				}
				directory := filepath.Join(parent, "scanner-identities")
				if err := os.Mkdir(directory, 0o700); err != nil {
					t.Fatal(err)
				}
				directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(directoryFD)
				path := filepath.Join(directory, lock.name)
				outside := filepath.Join(parent, "outside")
				mode := os.FileMode(0o600)
				if metadata == "wrong mode" {
					mode = 0o640
				}
				contents := []byte(nil)
				if metadata == "nonempty" {
					contents = []byte("not a lock file")
				}
				if metadata == "symlink" {
					if err := os.WriteFile(outside, contents, mode); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, path); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.WriteFile(path, contents, mode); err != nil {
						t.Fatal(err)
					}
					if metadata == "hard link" {
						if err := os.Link(path, outside); err != nil {
							t.Fatal(err)
						}
					}
				}
				fd, err := lock.open(directoryFD)
				if err == nil {
					_ = unix.Close(fd)
					t.Fatalf("accepted lock file with %s metadata", metadata)
				}
			})
		}
	}
}

func TestScannerLivenessDescriptorValidationEnforcesTheInheritedFileContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), scannerIdentityLivenessLock)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	readOnly, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	fd := int(readOnly.Fd())
	if fd < 3 || fd >= 3+maxInheritedFiles {
		t.Skipf("test liveness fd %d is outside the scanner launch descriptor range", fd)
	}
	if err := validateScannerLivenessParentFile(readOnly); err != nil {
		t.Fatalf("valid daemon reference: %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	if err := validateScannerLivenessDescriptor(fd); err != nil {
		t.Fatalf("valid inherited descriptor: %v", err)
	}

	if err := validateScannerLivenessDescriptor(-1); err == nil {
		t.Fatal("negative descriptor was accepted")
	}
	outside, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3+maxInheritedFiles)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(outside)
	if err := validateScannerLivenessDescriptor(outside); err == nil {
		t.Fatal("descriptor outside the inherited range was accepted")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	if err := validateScannerLivenessDescriptor(fd); err == nil {
		t.Fatal("close-on-exec liveness descriptor was accepted")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}

	writable, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writable.Close()
	if err := validateScannerLivenessDescriptor(int(writable.Fd())); err == nil {
		t.Fatal("writable inherited liveness descriptor was accepted")
	}
	if err := validateScannerLivenessParentFile(writable); err == nil {
		t.Fatal("writable daemon liveness descriptor was accepted")
	}
	if err := validateScannerLivenessParentFile(nil); err == nil {
		t.Fatal("missing daemon liveness descriptor was accepted")
	}

	device, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	deviceFD, err := unix.FcntlInt(device.Fd(), unix.F_DUPFD, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(deviceFD)
	if deviceFD < 3 || deviceFD >= 3+maxInheritedFiles {
		t.Skipf("test device fd %d is outside the scanner launch descriptor range", deviceFD)
	}
	if err := validateScannerLivenessDescriptor(deviceFD); err == nil {
		t.Fatal("non-regular liveness descriptor was accepted")
	}
}

func TestScannerIdentityLivenessMethodsFailClosedOnInvalidInputs(t *testing.T) {
	var nilContext context.Context
	directoryFD := scannerIdentityLockTestDirectory(t)
	if _, _, _, err := acquireScannerIdentityLiveness(nilContext, directoryFD); err == nil {
		t.Fatal("nil liveness context was accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := acquireScannerIdentityLiveness(canceled, directoryFD); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled liveness acquisition = %v, want context canceled", err)
	}
	if _, _, err := beginScannerIdentityScopeLock(nilContext, directoryFD, directoryFD); err == nil {
		t.Fatal("nil scope-lock context was accepted")
	}
	if _, _, err := beginScannerIdentityScopeLock(context.Background(), -1, directoryFD); err == nil {
		t.Fatal("invalid scope-lock directory was accepted")
	}
	if _, err := (*scannerIdentityScopeLock)(nil).takeInheritedLivenessFile(); err == nil {
		t.Fatal("nil scope returned an inherited descriptor")
	}
	if _, err := (&scannerIdentityScopeLock{}).takeInheritedLivenessFile(); err == nil {
		t.Fatal("scope without inherited descriptor returned one")
	}
	if err := (*scannerIdentityScopeLock)(nil).downgradeLiveness(directoryFD); err == nil {
		t.Fatal("nil scope downgraded its liveness lock")
	}
	if err := (*scannerIdentityScopeLock)(nil).releaseTransitionGate(); err == nil {
		t.Fatal("nil scope released a transition gate")
	}
	if err := (&scannerIdentityScopeLock{gateFD: -1}).releaseTransitionGate(); err == nil {
		t.Fatal("unlocked scope released a transition gate")
	}
	if err := (&scannerIdentityScopeLock{directoryFD: -1, allocatorFD: -1}).lockAllocator(context.Background()); err == nil {
		t.Fatal("invalid scope acquired the allocator lock")
	}
	if err := (*scannerIdentityScopeLock)(nil).retainRuntimeReference(nil); err == nil {
		t.Fatal("nil scope retained a runtime liveness reference")
	}
	if _, err := (*scannerIdentityAllocator)(nil).runtimeLivenessFile(); err == nil {
		t.Fatal("nil allocator returned a runtime liveness file")
	}
	if err := retainScannerIdentityRuntimeReference(context.Background(), nil); err == nil {
		t.Fatal("nil allocator retained a runtime reference")
	}
}

func TestScannerIdentityLivenessTransitionsFailClosedAtBoundaries(t *testing.T) {
	var nilContext context.Context
	directoryFD := scannerIdentityLockTestDirectory(t)
	if _, _, _, err := acquireScannerIdentityLiveness(context.Background(), -1); err == nil {
		t.Fatal("liveness acquisition accepted an invalid state directory")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := beginScannerIdentityScopeLock(ctx, directoryFD, directoryFD); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled transition-gate acquisition = %v, want context canceled", err)
	}
	if err := retainScannerIdentityRuntimeReference(nilContext, &scannerIdentityAllocator{persistRuntimeLiveness: true}); err == nil {
		t.Fatal("runtime liveness retention accepted a nil context")
	}
	if _, err := (&scannerIdentityAllocator{}).runtimeLivenessFile(); err == nil {
		t.Fatal("allocator without its process-lifetime reference returned a file")
	}

	writable, err := openScannerIdentityLivenessFile(directoryFD, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := setScannerIdentityOFDLock(int(writable.Fd()), unix.F_WRLCK, true); err != nil {
		_ = writable.Close()
		t.Fatal(err)
	}
	if _, err := (&scannerIdentityScopeLock{inherited: writable}).takeInheritedLivenessFile(); err == nil {
		_ = writable.Close()
		t.Fatal("writable inherited reference was transferred to a scanner")
	}
	if _, _, err := downgradeScannerIdentityLiveness(directoryFD, nil); err == nil {
		_ = writable.Close()
		t.Fatal("nil keeper was downgraded")
	}
	closed, err := os.Open(os.DevNull)
	if err != nil {
		_ = writable.Close()
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		_ = writable.Close()
		t.Fatal(err)
	}
	if _, _, err := downgradeScannerIdentityLiveness(directoryFD, closed); err == nil {
		_ = writable.Close()
		t.Fatal("closed keeper was downgraded")
	}
	if err := writable.Close(); err != nil {
		t.Fatal(err)
	}

	keeper, err := openScannerIdentityLivenessFile(directoryFD, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := setScannerIdentityOFDLock(int(keeper.Fd()), unix.F_WRLCK, true); err != nil {
		_ = keeper.Close()
		t.Fatal(err)
	}
	if err := unix.Unlinkat(directoryFD, scannerIdentityLivenessLock, 0); err != nil {
		_ = keeper.Close()
		t.Fatal(err)
	}
	if _, _, err := downgradeScannerIdentityLiveness(directoryFD, keeper); err == nil {
		_ = keeper.Close()
		t.Fatal("missing inherited-reference file allowed a downgrade")
	}
	if err := keeper.Close(); err != nil {
		t.Fatal(err)
	}

	gateFD, err := openScannerIdentityTransitionLock(directoryFD)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(gateFD, unix.LOCK_EX); err != nil {
		_ = unix.Close(gateFD)
		t.Fatal(err)
	}
	if err := unix.Close(gateFD); err != nil {
		t.Fatal(err)
	}
	if err := (&scannerIdentityScopeLock{gateFD: gateFD, lockedGate: true}).releaseTransitionGate(); err == nil {
		t.Fatal("transition gate release succeeded on a closed descriptor")
	}
}
