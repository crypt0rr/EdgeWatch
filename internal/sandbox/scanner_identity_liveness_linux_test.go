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
