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

func TestValidateScannerIdentityRangeMappingFromPaths(t *testing.T) {
	root := t.TempDir()
	uidPath := filepath.Join(root, "uid_map")
	gidPath := filepath.Join(root, "gid_map")
	write := func(path, value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("every candidate UID and GID is mapped across ranges", func(t *testing.T) {
		write(uidPath, "0 100000 60000\n60000 300000 32\n60032 400000 32\n")
		write(gidPath, "0 200000 60000\n60000 500000 64\n")
		if err := validateScannerIdentityRangeMappingFromPaths(60000, 64, uidPath, gidPath); err != nil {
			t.Fatalf("validate complete scanner identity range: %v", err)
		}
	})

	t.Run("unavailable UID map fails closed", func(t *testing.T) {
		if err := validateScannerIdentityRangeMappingFromPaths(60000, 64, filepath.Join(root, "missing-uid"), gidPath); err == nil || !strings.Contains(err.Error(), "UID mapping is unavailable") {
			t.Fatalf("missing UID map error = %v; want unavailable UID mapping", err)
		}
	})

	t.Run("malformed GID map fails closed", func(t *testing.T) {
		write(uidPath, "60000 300000 64\n")
		write(gidPath, "not-a-map\n")
		if err := validateScannerIdentityRangeMappingFromPaths(60000, 64, uidPath, gidPath); err == nil || !strings.Contains(err.Error(), "GID mapping is unavailable") {
			t.Fatalf("malformed GID map error = %v; want unavailable GID mapping", err)
		}
	})

	t.Run("unmapped final candidate rejects the whole pool", func(t *testing.T) {
		write(uidPath, "60000 300000 64\n")
		write(gidPath, "60000 500000 63\n")
		err := validateScannerIdentityRangeMappingFromPaths(60000, 64, uidPath, gidPath)
		if err == nil || !strings.Contains(err.Error(), "required UID/GID 60063 is not mapped") {
			t.Fatalf("partially mapped pool error = %v; want final unmapped candidate", err)
		}
	})
}

func TestLockScannerIdentityCancellationAndInvalidDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allocator.lock")
	first, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(first)
	second, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(second)
	if err := unix.Flock(first, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer cancel()
	if err := lockScannerIdentity(ctx, second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended lock result = %v; want context deadline", err)
	}
	if err := unix.Flock(first, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := lockScannerIdentity(context.Background(), second); err != nil {
		t.Fatalf("lock after prior owner released: %v", err)
	}
	if err := unix.Flock(second, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := lockScannerIdentity(context.Background(), -1); err == nil || !strings.Contains(err.Error(), "allocator lock failed") {
		t.Fatalf("invalid descriptor result = %v; want lock failure", err)
	}
}

func TestReleasedScannerIdentityLeaseCannotBeReused(t *testing.T) {
	lease, err := newTestScannerIdentityAllocator(t, 1).acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := lease.identity(); !ok {
		t.Fatal("active lease did not expose its identity")
	}
	if err := lease.release(); err != nil {
		t.Fatal(err)
	}
	if uid, gid, ok := lease.identity(); ok || uid != 0 || gid != 0 {
		t.Fatalf("released identity = %d:%d, %t; want unavailable", uid, gid, ok)
	}
	if err := lease.release(); err == nil || !strings.Contains(err.Error(), "lease is unavailable") {
		t.Fatalf("second release = %v; want unavailable lease", err)
	}
	if err := lease.quarantine(); err == nil || !strings.Contains(err.Error(), "lease is unavailable") {
		t.Fatalf("quarantine after release = %v; want unavailable lease", err)
	}
}

func TestScannerIdentityCensusFailsClosedWhenSourcesAreUnavailable(t *testing.T) {
	root := t.TempDir()
	accounts := filepath.Join(root, "accounts")
	if err := os.Mkdir(accounts, 0o700); err != nil {
		t.Fatal(err)
	}
	passwdPath := filepath.Join(accounts, "passwd")
	groupPath := filepath.Join(accounts, "group")
	for _, path := range []string{passwdPath, groupPath} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	procRoot := filepath.Join(root, "proc")
	if err := os.Mkdir(procRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Run("unavailable proc tree", func(t *testing.T) {
		if _, err := scannerIdentitiesInUseAt(filepath.Join(root, "missing-proc"), passwdPath, groupPath, 61000, 64); err == nil {
			t.Fatal("unavailable process census was accepted")
		}
	})

	t.Run("unavailable local account source", func(t *testing.T) {
		if _, err := scannerIdentitiesInUseAt(procRoot, filepath.Join(root, "missing-passwd"), groupPath, 61000, 64); err == nil {
			t.Fatal("unavailable passwd source was accepted")
		}
	})
}

func TestWriteScannerIdentityFileDoesNotReplaceUnexpectedDirectory(t *testing.T) {
	root := t.TempDir()
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := os.Mkdir(filepath.Join(root, "leases.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeScannerIdentityFile(fd, "leases.json", []byte(`{"version":2}`)); err == nil {
		t.Fatal("atomic state writer replaced an unexpected directory")
	}
	info, err := os.Stat(filepath.Join(root, "leases.json"))
	if err != nil || !info.IsDir() {
		t.Fatalf("unexpected state path after failed write = %v, %v; want original directory intact", info, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "leases.json" {
		t.Fatalf("failed atomic write left temporary state behind: %v", entries)
	}
}
