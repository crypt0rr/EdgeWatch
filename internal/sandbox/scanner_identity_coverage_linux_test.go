//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestScannerIdentityAcquireCancellationAndUnsafeLockFailClosed(t *testing.T) {
	t.Run("nil context is rejected before any state is created", func(t *testing.T) {
		allocator := newTestScannerIdentityAllocator(t, 1)
		var nilContext context.Context
		lease, err := allocator.acquire(nilContext)
		if lease != nil || err == nil || !strings.Contains(err.Error(), "context is nil") {
			t.Fatalf("nil-context acquire = %v, %v; want fail-closed refusal", lease, err)
		}
		if _, statErr := os.Stat(allocator.directory); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("nil-context acquire touched allocator state: %v", statErr)
		}
	})

	for _, call := range []int{2, 3} {
		t.Run(map[int]string{2: "before process census", 3: "after process census"}[call], func(t *testing.T) {
			allocator := newTestScannerIdentityAllocator(t, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			controlled := &cancelOnErrCallContext{Context: ctx, cancel: cancel, call: call}
			lease, err := allocator.acquire(controlled)
			if lease != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled acquire = %v, %v; want context.Canceled", lease, err)
			}
			journal, readErr := readTestScannerIdentityJournal(allocator)
			if errors.Is(readErr, os.ErrNotExist) {
				return // Both cancellation points precede journal initialization.
			}
			if readErr != nil || len(journal.Leases) != 0 {
				t.Fatalf("canceled acquire retained a lease: journal=%+v read error=%v", journal, readErr)
			}
		})
	}

	t.Run("symlinked allocator lock is rejected before journal mutation", func(t *testing.T) {
		allocator := newTestScannerIdentityAllocator(t, 1)
		if err := os.Mkdir(allocator.directory, 0o700); err != nil {
			t.Fatal(err)
		}
		lockPath := filepath.Join(allocator.directory, scannerIdentityLock)
		if err := os.Symlink("/dev/null", lockPath); err != nil {
			t.Fatal(err)
		}
		lease, err := allocator.acquire(context.Background())
		if lease != nil || err == nil || !strings.Contains(err.Error(), "allocator lock is unavailable") {
			t.Fatalf("acquire with symlink lock = %v, %v; want fail-closed lock refusal", lease, err)
		}
		if _, err := os.Lstat(lockPath); err != nil {
			t.Fatalf("failed acquisition changed the lock entry: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(allocator.directory, scannerIdentityJournalName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed lock validation wrote a journal: %v", err)
		}
	})
}

func TestScannerIdentityAccountAndProcSnapshotRejectMalformedAccounts(t *testing.T) {
	root := t.TempDir()
	passwd := filepath.Join(root, "passwd")
	group := filepath.Join(root, "group")
	for _, test := range []struct {
		name  string
		path  string
		value string
	}{
		{name: "passwd numeric field", path: passwd, value: "edgewatch:x:not-a-uid:61000::/:/sbin/nologin\n"},
		{name: "group numeric field", path: group, value: "edgewatch:x:not-a-gid:scanner\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(test.path, []byte(test.value), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := addScannerAccountsInUse(test.path, 3, 61000, 64, make(map[uint32]struct{})); err == nil || !strings.Contains(err.Error(), "invalid local account ID") {
				t.Fatalf("malformed account ID result = %v; want fail-closed parse error", err)
			}
		})
	}

	procRoot := filepath.Join(root, "proc")
	if err := os.Mkdir(procRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"passwd": "# local accounts\n\nedgewatch:x:61000:61000::/:/sbin/nologin\n",
		"group":  "# local groups\n\nedgewatch:x:61001:scanner\n",
	} {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	processDir := filepath.Join(procRoot, "404")
	if err := os.Mkdir(processDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(processDir, "status"), []byte("Uid:\tmalformed\t61002\nGid:\t61003\tmalformed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	used, err := scannerIdentitiesInUseAt(procRoot, filepath.Join(root, "passwd"), filepath.Join(root, "group"), 61000, 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint32{61000, 61001, 61002, 61003} {
		if _, ok := used[id]; !ok {
			t.Errorf("account/process identity %d was not reserved: %v", id, used)
		}
	}
}

func TestScannerIdentityProductionCensusIncludesRootAndConfiguredRange(t *testing.T) {
	usedRoot, err := scannerIdentitiesInUse(0, 1)
	if err != nil {
		t.Fatalf("inspect live processes and local accounts: %v", err)
	}
	if _, ok := usedRoot[0]; !ok {
		t.Fatalf("root identity was not reserved by the production census: %v", usedRoot)
	}

	usedPool, err := scannerIdentitiesInUse(scannerIdentityStart, scannerIdentityCount)
	if err != nil {
		t.Fatalf("inspect configured scanner identity range: %v", err)
	}
	for uid := range usedPool {
		if uid < scannerIdentityStart || uid >= scannerIdentityStart+scannerIdentityCount {
			t.Fatalf("production census returned out-of-pool UID %d: %v", uid, usedPool)
		}
	}
}

func TestScannerIdentityMissingMarkerAfterPriorBootResetsOnlyOldLeases(t *testing.T) {
	allocator := newTestScannerIdentityAllocator(t, 1)
	directoryFD, markerFD, err := openScannerIdentityDirectories(allocator.directory, allocator.markerDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directoryFD)
	defer unix.Close(markerFD)

	old := scannerIdentityJournal{
		Version: scannerIdentityVersion, BootID: testScannerBootID2, PIDNamespace: 17,
		Leases: map[uint32]scannerIdentityJournalEntry{
			allocator.uidStart: {GID: allocator.uidStart, Token: "0123456789abcdef0123456789abcdef", State: "quarantined"},
		},
	}
	if err := writeScannerIdentityJournal(directoryFD, old); err != nil {
		t.Fatalf("write prior-boot journal without marker: %v", err)
	}

	journal, privateRuntime, err := allocator.loadOrInitialize(directoryFD, markerFD, testScannerBootID, 17, false)
	if err != nil {
		t.Fatalf("reset missing marker from prior-boot journal: %v", err)
	}
	if privateRuntime || journal.BootID != testScannerBootID || journal.PIDNamespace != 17 || journal.PrivateRuntime || len(journal.Leases) != 0 {
		t.Fatalf("reinitialized prior-boot state = %+v private=%t; want empty current-boot scope", journal, privateRuntime)
	}
	marker, err := readScannerIdentityMarker(markerFD)
	if err != nil || marker.BootID != testScannerBootID || marker.PIDNamespace != 17 || marker.PrivateRuntime {
		t.Fatalf("reinitialized marker = %+v, %v", marker, err)
	}
}
