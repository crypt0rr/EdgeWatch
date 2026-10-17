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

	for _, call := range []int{3, 5} {
		t.Run(map[int]string{3: "before process census", 5: "after process census"}[call], func(t *testing.T) {
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

func TestScannerIdentityAcquireDurableWriteFailuresPreserveReservationContract(t *testing.T) {
	t.Run("lease commit failure returns no identity and permits a later safe retry", func(t *testing.T) {
		allocator := newTestScannerIdentityAllocator(t, 1)
		restoreScannerIdentityDirectoryMode(t, allocator.directory)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		controlled := &scannerIdentityModeChangeContext{
			Context: ctx, directory: allocator.directory, changeOnCall: 6,
		}
		lease, err := allocator.acquire(controlled)
		if controlled.calls != controlled.changeOnCall || controlled.changeErr != nil {
			t.Fatalf("make allocator state directory read-only: calls=%d, err=%v", controlled.calls, controlled.changeErr)
		}
		if !controlled.writeBlocked {
			if err == nil && lease != nil {
				if restoreErr := os.Chmod(allocator.directory, 0o700); restoreErr != nil {
					t.Fatalf("restore allocator state directory: %v", restoreErr)
				}
				if releaseErr := lease.release(); releaseErr != nil {
					t.Fatalf("release lease after permission probe: %v", releaseErr)
				}
				t.Skip("filesystem permissions do not block writes to a 0500 directory in this test environment")
			}
			t.Fatalf("read-only mode did not block writes, but acquire returned %v, %v", lease, err)
		}
		if lease != nil || err == nil || !strings.Contains(err.Error(), "durable lease write failed") {
			t.Fatalf("acquire after durable lease write failure = %v, %v; want no lease and write refusal", lease, err)
		}
		if err := os.Chmod(allocator.directory, 0o700); err != nil {
			t.Fatalf("restore allocator state directory: %v", err)
		}
		journal, err := readTestScannerIdentityJournal(allocator)
		if err != nil || len(journal.Leases) != 0 {
			t.Fatalf("failed lease commit changed the journal: %+v, %v", journal, err)
		}
		retry, err := allocator.acquire(context.Background())
		if err != nil {
			t.Fatalf("retry after a failed, uncommitted lease: %v", err)
		}
		if err := retry.release(); err != nil {
			t.Fatalf("release successful retry lease: %v", err)
		}
	})

	t.Run("cancellation rollback failure leaves the committed UID unavailable", func(t *testing.T) {
		allocator := newTestScannerIdentityAllocator(t, 1)
		restoreScannerIdentityDirectoryMode(t, allocator.directory)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		controlled := &scannerIdentityModeChangeContext{
			Context: ctx, cancel: cancel, directory: allocator.directory, changeOnCall: 7, cancelOnChange: true,
		}
		lease, err := allocator.acquire(controlled)
		if controlled.calls != controlled.changeOnCall || controlled.changeErr != nil {
			t.Fatalf("make allocator state directory read-only: calls=%d, err=%v", controlled.calls, controlled.changeErr)
		}
		if !controlled.writeBlocked {
			if errors.Is(err, context.Canceled) && lease == nil {
				if restoreErr := os.Chmod(allocator.directory, 0o700); restoreErr != nil {
					t.Fatalf("restore allocator state directory: %v", restoreErr)
				}
				journal, readErr := readTestScannerIdentityJournal(allocator)
				if readErr != nil || len(journal.Leases) != 0 {
					t.Fatalf("canceled acquire did not roll back when permissions were bypassed: %+v, %v", journal, readErr)
				}
				t.Skip("filesystem permissions do not block writes to a 0500 directory in this test environment")
			}
			t.Fatalf("read-only mode did not block writes, but acquire returned %v, %v", lease, err)
		}
		if lease != nil || err == nil || !strings.Contains(err.Error(), "cancellation rollback failed; identity remains reserved") {
			t.Fatalf("acquire after rollback failure = %v, %v; want retained durable reservation", lease, err)
		}
		if err := os.Chmod(allocator.directory, 0o700); err != nil {
			t.Fatalf("restore allocator state directory: %v", err)
		}
		journal, err := readTestScannerIdentityJournal(allocator)
		if err != nil || len(journal.Leases) != 1 || journal.Leases[allocator.uidStart].State != "active" {
			t.Fatalf("failed rollback did not retain active reservation: %+v, %v", journal, err)
		}
		if retry, retryErr := allocator.acquire(context.Background()); retry != nil || !errors.Is(retryErr, errScannerIdentityPoolExhausted) {
			t.Fatalf("acquire reused uncertain UID after rollback failure = %v, %v; want pool exhaustion", retry, retryErr)
		}
	})
}

func TestScannerIdentityReleaseAndQuarantineDurableWriteFailuresDoNotFreeUID(t *testing.T) {
	for _, operation := range []string{"release", "quarantine"} {
		t.Run(operation, func(t *testing.T) {
			allocator := newTestScannerIdentityAllocator(t, 1)
			restoreScannerIdentityDirectoryMode(t, allocator.directory)
			lease, err := allocator.acquire(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			writeBlocked := false
			probeErr := error(nil)
			allocator.privateRuntime = func() (bool, error) {
				// This trusted probe runs after the allocator has opened and
				// validated its private directory and acquired its lock. Revoking
				// directory write permission then exercises the atomic journal
				// commit failure without a production syscall hook.
				if err := os.Chmod(allocator.directory, 0o500); err != nil {
					return false, err
				}
				writeBlocked, probeErr = scannerIdentityDirectoryWriteBlocked(allocator.directory)
				return false, probeErr
			}
			if operation == "release" {
				err = lease.release()
			} else {
				err = lease.quarantine()
			}
			if chmodErr := os.Chmod(allocator.directory, 0o700); chmodErr != nil {
				t.Fatalf("restore allocator state directory: %v", chmodErr)
			}
			if probeErr != nil {
				t.Fatalf("probe allocator directory permissions: %v", probeErr)
			}
			if !writeBlocked && err == nil {
				t.Skip("filesystem permissions do not block writes to a 0500 directory in this test environment")
			}
			if !writeBlocked {
				t.Fatalf("read-only mode did not block writes, but %s returned %v", operation, err)
			}
			want := map[string]string{
				"release":    "durable release failed",
				"quarantine": "durable quarantine failed",
			}[operation]
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("%s after durable journal failure = %v; want %q", operation, err, want)
			}
			assertScannerIdentityLeaseStillReserved(t, allocator, lease.uid, "active")
			if operation == "release" {
				if _, _, ok := lease.identity(); !ok {
					t.Fatal("failed durable release marked the lease finished")
				}
			} else if _, _, ok := lease.identity(); ok {
				t.Fatal("quarantine failure left the in-memory lease available")
			}
			allocator.privateRuntime = func() (bool, error) { return false, nil }
			if retry, retryErr := allocator.acquire(context.Background()); retry != nil || !errors.Is(retryErr, errScannerIdentityPoolExhausted) {
				t.Fatalf("%s failure allowed UID reuse = %v, %v; want pool exhaustion", operation, retry, retryErr)
			}
		})
	}
}

func TestScannerIdentityMarkerCommitFailuresPreserveRecoverableState(t *testing.T) {
	t.Run("empty journal recovery refuses a marker write and retries safely", func(t *testing.T) {
		allocator := newTestScannerIdentityAllocator(t, 1)
		restoreScannerIdentityDirectoryMode(t, allocator.markerDir)
		lease, err := allocator.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := lease.release(); err != nil {
			t.Fatal(err)
		}
		markerPath := filepath.Join(allocator.markerDir, scannerIdentityMarker)
		if err := os.Remove(markerPath); err != nil {
			t.Fatal(err)
		}

		writeBlocked := false
		var probeErr error
		allocator.inUse = func(uint32, uint32) (map[uint32]struct{}, error) {
			if err := os.Chmod(allocator.markerDir, 0o500); err != nil {
				return nil, err
			}
			writeBlocked, probeErr = scannerIdentityDirectoryWriteBlocked(allocator.markerDir)
			return map[uint32]struct{}{}, probeErr
		}
		recovered, err := allocator.acquire(context.Background())
		if probeErr != nil {
			t.Fatalf("probe marker-parent permissions: %v", probeErr)
		}
		if chmodErr := os.Chmod(allocator.markerDir, 0o700); chmodErr != nil {
			t.Fatalf("restore marker parent: %v", chmodErr)
		}
		if !writeBlocked {
			if err == nil && recovered != nil {
				if releaseErr := recovered.release(); releaseErr != nil {
					t.Fatalf("release lease after permission probe: %v", releaseErr)
				}
				t.Skip("filesystem permissions do not block writes to a 0500 directory in this test environment")
			}
			t.Fatalf("read-only mode did not block marker writes, but acquire returned %v, %v", recovered, err)
		}
		if recovered != nil || err == nil || !strings.Contains(err.Error(), "durable marker write failed") {
			t.Fatalf("empty-journal marker recovery = %v, %v; want fail-closed marker write error", recovered, err)
		}
		journal, err := readTestScannerIdentityJournal(allocator)
		if err != nil || len(journal.Leases) != 0 || journal.PIDNamespace != 17 {
			t.Fatalf("failed marker recovery changed the empty journal: %+v, %v", journal, err)
		}
		if _, err := os.Lstat(markerPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed marker recovery created an anchor: %v", err)
		}

		allocator.inUse = func(uint32, uint32) (map[uint32]struct{}, error) { return map[uint32]struct{}{}, nil }
		retry, err := allocator.acquire(context.Background())
		if err != nil {
			t.Fatalf("retry empty-journal marker recovery: %v", err)
		}
		if err := retry.release(); err != nil {
			t.Fatalf("release retry lease: %v", err)
		}
	})

	t.Run("journal-first private-scope transition completes after marker write refusal", func(t *testing.T) {
		allocator := usePrivateScannerRuntime(newTestScannerIdentityAllocator(t, 1))
		restoreScannerIdentityDirectoryMode(t, allocator.markerDir)
		lease, err := allocator.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := lease.release(); err != nil {
			t.Fatal(err)
		}

		transition := newScannerIdentityAllocatorForTest(allocator.directory, allocator.uidStart, allocator.count, testScannerBootID, 18)
		usePrivateScannerRuntime(transition)
		writeBlocked := false
		var probeErr error
		transition.inUse = func(uint32, uint32) (map[uint32]struct{}, error) {
			if err := os.Chmod(allocator.markerDir, 0o500); err != nil {
				return nil, err
			}
			writeBlocked, probeErr = scannerIdentityDirectoryWriteBlocked(allocator.markerDir)
			return map[uint32]struct{}{}, probeErr
		}
		next, err := transition.acquire(context.Background())
		if probeErr != nil {
			t.Fatalf("probe marker-parent permissions: %v", probeErr)
		}
		if chmodErr := os.Chmod(allocator.markerDir, 0o700); chmodErr != nil {
			t.Fatalf("restore marker parent: %v", chmodErr)
		}
		if !writeBlocked {
			if err == nil && next != nil {
				if releaseErr := next.release(); releaseErr != nil {
					t.Fatalf("release lease after permission probe: %v", releaseErr)
				}
				t.Skip("filesystem permissions do not block writes to a 0500 directory in this test environment")
			}
			t.Fatalf("read-only mode did not block transition marker writes, but acquire returned %v, %v", next, err)
		}
		if next != nil || err == nil || !strings.Contains(err.Error(), "durable marker write failed") {
			t.Fatalf("namespace transition with marker refusal = %v, %v; want no lease and recoverable failure", next, err)
		}
		journal, err := readTestScannerIdentityJournal(transition)
		if err != nil || journal.PIDNamespace != 18 || len(journal.Leases) != 0 {
			t.Fatalf("failed marker commit did not retain only the empty journal transition: %+v, %v", journal, err)
		}
		marker, err := readScannerIdentityMarkerAtPath(allocator.markerDir)
		if err != nil || marker.PIDNamespace != 17 {
			t.Fatalf("failed transition unexpectedly changed the old marker: %+v, %v", marker, err)
		}

		transition.inUse = func(uint32, uint32) (map[uint32]struct{}, error) { return map[uint32]struct{}{}, nil }
		retry, err := transition.acquire(context.Background())
		if err != nil {
			t.Fatalf("complete journal-first transition on retry: %v", err)
		}
		marker, err = readScannerIdentityMarkerAtPath(allocator.markerDir)
		if err != nil || marker.PIDNamespace != 18 {
			t.Fatalf("retry did not complete matching marker transition: %+v, %v", marker, err)
		}
		if err := retry.release(); err != nil {
			t.Fatalf("release retry lease: %v", err)
		}
	})
}

type scannerIdentityModeChangeContext struct {
	context.Context
	cancel         context.CancelFunc
	directory      string
	changeOnCall   int
	cancelOnChange bool
	calls          int
	changeErr      error
	writeBlocked   bool
}

func (ctx *scannerIdentityModeChangeContext) Err() error {
	ctx.calls++
	if ctx.calls == ctx.changeOnCall {
		if ctx.cancelOnChange {
			ctx.cancel()
		}
		if ctx.changeErr = os.Chmod(ctx.directory, 0o500); ctx.changeErr == nil {
			ctx.writeBlocked, ctx.changeErr = scannerIdentityDirectoryWriteBlocked(ctx.directory)
		}
	}
	return ctx.Context.Err()
}

func scannerIdentityDirectoryWriteBlocked(directory string) (bool, error) {
	probePath := filepath.Join(directory, ".write-permission-probe")
	file, err := os.OpenFile(probePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrPermission) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(probePath)
		return false, err
	}
	if err := os.Remove(probePath); err != nil {
		return false, err
	}
	return false, nil
}

func restoreScannerIdentityDirectoryMode(t *testing.T, directory string) {
	t.Helper()
	t.Cleanup(func() {
		if err := os.Chmod(directory, 0o700); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("restore allocator state directory mode: %v", err)
		}
	})
}
