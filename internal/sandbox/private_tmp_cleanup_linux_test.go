//go:build linux

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func pinScannerCleanupTestLeaf(t *testing.T, temporary *linuxPrivateTemporaryDirectory) {
	t.Helper()
	if err := unix.Mkdirat(int(temporary.namespace.Fd()), temporary.name, privateScannerTemporaryMode); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fchmodat(int(temporary.namespace.Fd()), temporary.name, privateScannerTemporaryMode, 0); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Openat(int(temporary.namespace.Fd()), temporary.name, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	temporary.leaf = os.NewFile(uintptr(fd), "scanner-owned cleanup test leaf")
	temporary.leafStat = stat
	temporary.leafMode = privateScannerTemporaryMode
	temporary.private = true
	temporary.childCreates = true
	temporary.uid, temporary.gid = uint32(os.Geteuid()), uint32(os.Getegid())
}

func TestPrivateTemporaryCleanupUsesOwnerHelperThenPinnedParentRemoval(t *testing.T) {
	temporary := newPrivateTemporaryCreateFixture(t)
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	temporary.helper = helper
	temporary.landlocked = false
	pinScannerCleanupTestLeaf(t, temporary)
	nested := filepath.Join(temporary.path(), "ipranger-map", "leveldb")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "CURRENT"), []byte("MANIFEST-000001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(temporary.leaf.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_PATH == 0 {
		t.Fatalf("cleanup parent leaf descriptor flags = %#x, %v; want O_PATH", flags, err)
	}
	if err := temporary.Cleanup(context.Background()); err != nil {
		t.Fatalf("clean populated scanner leaf through owner helper: %v", err)
	}
	if !temporary.cleaned {
		t.Fatal("successful cleanup did not mark the invocation namespace clean")
	}
	if _, err := os.Lstat(temporary.path()); !os.IsNotExist(err) {
		t.Fatalf("scanner leaf remains after helper cleanup and pinned parent removal: %v", err)
	}
	if _, err := os.Lstat(filepath.Join("/tmp", temporary.namespaceName)); !os.IsNotExist(err) {
		t.Fatalf("invocation namespace remains after cleanup: %v", err)
	}
}

func TestPrivateTemporaryCleanupStillUsesAtomicRmdirAsEmptyCheck(t *testing.T) {
	temporary := newPrivateTemporaryCreateFixture(t)
	noOpHelper := filepath.Join(t.TempDir(), "cleanup-helper")
	if err := os.WriteFile(noOpHelper, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	temporary.helper = noOpHelper
	temporary.landlocked = false
	pinScannerCleanupTestLeaf(t, temporary)
	marker := filepath.Join(temporary.path(), "late-entry")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := temporary.Cleanup(context.Background())
	if err == nil {
		t.Fatal("cleanup accepted a leaf that remained nonempty after helper success")
	}
	if got, want := err.Error(), "cleanup Naabu temporary directory: remove parent-owned leaf failed"; got != want {
		t.Fatalf("cleanup failure = %q, want atomic AT_REMOVEDIR refusal %q", got, want)
	}
	if temporary.cleaned {
		t.Fatal("cleanup marked the invocation complete after atomic rmdir rejected a remaining entry")
	}
	if temporary.leaf == nil {
		t.Fatal("cleanup discarded the pinned leaf after atomic rmdir rejected a remaining entry")
	}
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Fatalf("failed atomic leaf removal did not preserve the unexpected entry: %v", statErr)
	}
	if _, statErr := os.Lstat(filepath.Join("/tmp", temporary.namespaceName)); statErr != nil {
		t.Fatalf("failed atomic leaf removal removed its containing namespace: %v", statErr)
	}
	// The fixture cleanup retries with the in-process owner path so no test
	// residue remains; production callers retain/quarantine this lease instead.
}

func TestPrivateTemporaryCleanupHelperFailurePreservesPinnedState(t *testing.T) {
	temporary := newPrivateTemporaryCreateFixture(t)
	temporary.helper = "/bin/false"
	temporary.landlocked = false
	pinScannerCleanupTestLeaf(t, temporary)
	marker := filepath.Join(temporary.path(), "keep-on-helper-failure")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := temporary.Cleanup(context.Background()); err == nil {
		t.Fatal("cleanup accepted a failed owner helper")
	}
	if temporary.cleaned || temporary.leaf == nil {
		t.Fatalf("failed helper changed cleanup state: cleaned=%t leaf=%v", temporary.cleaned, temporary.leaf)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("failed helper did not preserve the leaf entry: %v", err)
	}
	if _, err := os.Lstat(filepath.Join("/tmp", temporary.namespaceName)); err != nil {
		t.Fatalf("failed helper removed the containing namespace: %v", err)
	}
}
