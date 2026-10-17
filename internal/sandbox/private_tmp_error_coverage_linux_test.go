//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMkdiratWithFilesystemGroupRejectsQuerySentinel(t *testing.T) {
	called := false
	created, err := mkdiratWithFilesystemGroup(func(int, string, uint32) error {
		called = true
		return nil
	}, -1, "must-not-create", 0o700, ^uint32(0))
	if err == nil || created || called {
		t.Fatalf("mkdiratWithFilesystemGroup() = created %t, err %v, called %t; want fail-closed without creating", created, err, called)
	}
	if !strings.Contains(err.Error(), "filesystem group change could not be verified") {
		t.Fatalf("unexpected filesystem-group error: %v", err)
	}
}

func TestCreateNamespaceDefaultsModesAndRejectsScannerSetupMode(t *testing.T) {
	t.Run("unconfined default mode", func(t *testing.T) {
		rootPath := t.TempDir()
		filesystem := realPrivateTemporaryFilesystemOps()
		open := filesystem.open
		filesystem.open = func(path string, flags int, mode uint32) (int, error) {
			if path == "/tmp" {
				path = rootPath
			}
			return open(path, flags, mode)
		}
		temporary := &linuxPrivateTemporaryDirectory{filesystem: filesystem, uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}
		if err := temporary.createNamespace(); err != nil {
			_ = temporary.Close()
			t.Fatalf("create namespace with default mode: %v", err)
		}
		if temporary.namespaceMode != privateNamespaceMode {
			t.Fatalf("default namespace mode = %#o, want %#o", temporary.namespaceMode, privateNamespaceMode)
		}
		if err := filesystem.unlinkat(int(temporary.root.Fd()), temporary.namespaceName, unix.AT_REMOVEDIR); err != nil {
			_ = temporary.Close()
			t.Fatalf("remove test namespace: %v", err)
		}
		if err := temporary.Close(); err != nil {
			t.Fatalf("close namespace: %v", err)
		}
	})

	t.Run("leased scanner default mode", func(t *testing.T) {
		rootPath := t.TempDir()
		if err := os.Chmod(rootPath, 0o700); err != nil {
			t.Fatal(err)
		}
		filesystem := realPrivateTemporaryFilesystemOps()
		open := filesystem.open
		rootFD := -1
		filesystem.open = func(path string, flags int, mode uint32) (int, error) {
			if path == "/tmp" {
				fd, err := open(rootPath, flags, mode)
				rootFD = fd
				return fd, err
			}
			return open(path, flags, mode)
		}
		fstat := filesystem.fstat
		filesystem.fstat = func(fd int, stat *unix.Stat_t) error {
			if err := fstat(fd, stat); err != nil {
				return err
			}
			if fd == rootFD {
				// Model the trusted root-owned /tmp contract while keeping the
				// actual fixture directory private and writable by this test.
				stat.Uid = 0
			}
			return nil
		}
		temporary := &linuxPrivateTemporaryDirectory{
			filesystem:   filesystem,
			uid:          uint32(os.Geteuid()),
			gid:          uint32(os.Getegid()),
			childCreates: true,
		}
		if err := temporary.createNamespace(); err != nil {
			_ = temporary.Close()
			t.Fatalf("create namespace with scanner setup default mode: %v", err)
		}
		if temporary.namespaceMode != privateScannerNamespaceSetupMode {
			t.Fatalf("default scanner namespace mode = %#o, want %#o", temporary.namespaceMode, privateScannerNamespaceSetupMode)
		}
		var namespace unix.Stat_t
		if err := unix.Fstat(int(temporary.namespace.Fd()), &namespace); err != nil {
			_ = temporary.Close()
			t.Fatal(err)
		}
		if namespace.Gid != uint32(os.Getegid()) || namespace.Mode != unix.S_IFDIR|privateScannerNamespaceSetupMode {
			t.Fatalf("scanner setup namespace = gid %d mode %#o", namespace.Gid, namespace.Mode)
		}
		if err := filesystem.unlinkat(int(temporary.root.Fd()), temporary.namespaceName, unix.AT_REMOVEDIR); err != nil {
			_ = temporary.Close()
			t.Fatalf("remove scanner setup namespace: %v", err)
		}
		if err := temporary.Close(); err != nil {
			t.Fatalf("close scanner setup namespace: %v", err)
		}
	})

	t.Run("invalid leased scanner setup mode", func(t *testing.T) {
		temporary := &linuxPrivateTemporaryDirectory{childCreates: true, namespaceMode: privateNamespaceMode}
		if err := temporary.createNamespace(); err == nil || !strings.Contains(err.Error(), "scanner namespace setup mode is invalid") {
			t.Fatalf("create namespace with unsafe setup mode = %v; want rejection", err)
		}
	})
}

func TestSealScannerNamespaceRejectsUnavailableAndChangedIdentities(t *testing.T) {
	var unavailable *linuxPrivateTemporaryDirectory
	if err := unavailable.sealScannerNamespace(); err == nil || !strings.Contains(err.Error(), "scanner namespace is unavailable") {
		t.Fatalf("seal nil scanner namespace = %v; want unavailable error", err)
	}

	temporary := newPrivateTemporaryCreateFixture(t)
	originalStat := temporary.namespaceStat
	temporary.namespaceStat.Ino++
	if err := temporary.sealScannerNamespace(); err == nil || !strings.Contains(err.Error(), "changed before sealing") {
		t.Fatalf("seal changed pinned namespace = %v; want identity error", err)
	}
	temporary.namespaceStat = originalStat

	originalName := temporary.namespaceName
	temporary.namespaceName = "missing-private-namespace-entry"
	if err := temporary.sealScannerNamespace(); err == nil || !strings.Contains(err.Error(), "entry changed before sealing") {
		t.Fatalf("seal missing namespace entry = %v; want entry error", err)
	}
	temporary.namespaceName = originalName

	if err := temporary.sealScannerNamespace(); err != nil {
		t.Fatalf("seal intact scanner namespace: %v", err)
	}
}

func TestCleanupBudgetRejectsExpiredDeadline(t *testing.T) {
	budget := cleanupBudget{deadline: time.Now().Add(-time.Second)}
	if err := budget.visit(); err == nil || !strings.Contains(err.Error(), "time budget") {
		t.Fatalf("visit expired cleanup budget = %v; want deadline error", err)
	}
}

func TestValidatePrivateTemporaryCleanupLeafRejectsUnsupportedMode(t *testing.T) {
	_, fd, stat := newPrivateTemporaryCleanupCoverageLeaf(t)
	request := privateTemporaryCleanupRequest{
		device: uint64(stat.Dev), inode: stat.Ino,
		leafUID: stat.Uid, leafGID: stat.Gid, leafMode: 0o755,
		uid: uint32(os.Geteuid()), gid: uint32(os.Getegid()),
	}
	if _, err := validatePrivateTemporaryCleanupLeaf(request, fd); err == nil || !strings.Contains(err.Error(), "invalid expected leaf mode") {
		t.Fatalf("cleanup validation with unsupported mode = %v; want rejection", err)
	}
}

func TestRemovePrivateDirectoryContentsRejectsNonDirectoryDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = removePrivateDirectoryContents(fd, 0, uint32(os.Geteuid()), uint32(os.Getegid()), nil)
	if err == nil || !strings.Contains(err.Error(), "read private temporary directory failed") {
		t.Fatalf("remove contents from regular-file descriptor = %v; want safe read failure", err)
	}
	contents, readErr := os.ReadFile(path)
	if readErr != nil || string(contents) != "preserve" {
		t.Fatalf("rejected cleanup changed file: %q, %v", contents, readErr)
	}
}

func TestChmodPinnedPrivateDirectoryDoesNotFallbackForInvalidDescriptor(t *testing.T) {
	err := chmodPinnedPrivateDirectory(-1, privateScannerTemporaryMode)
	if !errors.Is(err, unix.EBADF) {
		t.Fatalf("chmod invalid pinned descriptor = %v; want EBADF without procfd fallback", err)
	}
}

func TestCleanupWithHelperUsesPinnedLeafModeWhenUnset(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "cleanup-helper")
	// This controlled helper succeeds only if cleanupWithHelper supplies the
	// pinned leaf's actual mode rather than an empty or guessed value.
	script := "#!/bin/sh\ncase \"$*\" in *\"--leaf-mode 700\"*) exit 0 ;; *) exit 42 ;; esac\n"
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	leafPath := filepath.Join(dir, "leaf")
	if err := os.Mkdir(leafPath, privateScannerTemporaryMode); err != nil {
		t.Fatal(err)
	}
	leaf, err := os.Open(leafPath)
	if err != nil {
		t.Fatal(err)
	}
	defer leaf.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(leaf.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	temporary := &linuxPrivateTemporaryDirectory{
		helper: helper, leaf: leaf,
		uid: uint32(os.Geteuid()), gid: uint32(os.Getegid()),
	}
	if err := temporary.cleanupWithHelper(context.Background(), &stat); err != nil {
		t.Fatalf("cleanup helper did not receive the pinned leaf mode: %v", err)
	}
}
