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

func TestOpenScannerIdentityDirectoriesRejectsUncreatableChildWithoutMutation(t *testing.T) {
	root := t.TempDir()
	markerDir := filepath.Join(root, "data")
	if err := os.Mkdir(markerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(markerDir, strings.Repeat("x", 256))

	directoryFD, markerFD, err := openScannerIdentityDirectories(path, markerDir)
	if err == nil {
		_ = unix.Close(directoryFD)
		_ = unix.Close(markerFD)
		t.Fatal("allocator accepted a child name that the filesystem cannot create")
	}
	if directoryFD != -1 || markerFD != -1 || !strings.Contains(err.Error(), "private directory cannot be created") {
		t.Fatalf("uncreatable allocator child = fds %d/%d, error %v; want closed descriptors and fail-closed create error", directoryFD, markerFD, err)
	}
	entries, readErr := os.ReadDir(markerDir)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("failed child creation mutated marker parent: entries=%v err=%v", entries, readErr)
	}
}

func TestScannerIdentityAcquireWithCanceledContextDoesNotInitializeState(t *testing.T) {
	allocator := newTestScannerIdentityAllocator(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lease, err := allocator.acquire(ctx)
	if lease != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire with already-canceled context = %v, %v; want no lease and context.Canceled", lease, err)
	}
	if _, statErr := os.Stat(allocator.directory); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("canceled acquire initialized durable state: %v", statErr)
	}
}

func TestOpenScannerIdentityLockRejectsDirectoryEntryWithoutMutation(t *testing.T) {
	path, markerDir, directory := scannerIdentityDirectoryFixture(t)
	directoryFD, markerFD, err := openScannerIdentityDirectories(path, markerDir)
	if err != nil {
		t.Fatalf("open isolated allocator directory: %v", err)
	}
	defer unix.Close(directoryFD)
	defer unix.Close(markerFD)

	lockPath := filepath.Join(directory, scannerIdentityLock)
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		t.Fatal(err)
	}
	lockFD, err := openScannerIdentityLock(directoryFD)
	if err == nil {
		_ = unix.Close(lockFD)
		t.Fatal("directory-shaped allocator lock was accepted")
	}
	if lockFD != -1 {
		t.Fatalf("refused directory lock returned descriptor %d", lockFD)
	}
	info, statErr := os.Lstat(lockPath)
	if statErr != nil || !info.IsDir() {
		t.Fatalf("refused allocator lock entry changed: info=%v err=%v", info, statErr)
	}
}

func TestEnsureScannerIdentityDirectoryValidatesFixedAnchorReadOnly(t *testing.T) {
	before, statErr := os.Lstat(scannerIdentityMarkerDir)
	err := ensureScannerIdentityDirectory()
	if errors.Is(statErr, os.ErrNotExist) {
		if err == nil || !strings.Contains(err.Error(), "durable state directory is unavailable") {
			t.Fatalf("missing fixed allocator anchor validation = %v; want fail-closed unavailable result", err)
		}
		if _, afterErr := os.Lstat(scannerIdentityMarkerDir); !errors.Is(afterErr, os.ErrNotExist) {
			t.Fatalf("read-only anchor validation created the production path: %v", afterErr)
		}
		return
	}
	if statErr != nil && err == nil {
		t.Fatalf("anchor validation accepted an unstatable fixed path: %v", statErr)
	}
	if statErr == nil {
		if err == nil && (!before.IsDir() || before.Mode()&0o0022 != 0 || before.Mode().Perm()&0o300 != 0o300) {
			t.Fatalf("fixed allocator anchor accepted unsafe metadata: mode=%#o", before.Mode().Perm())
		}
		after, afterErr := os.Lstat(scannerIdentityMarkerDir)
		if afterErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
			t.Fatalf("fixed anchor validation mutated state: before=%v after=%v err=%v", before, after, afterErr)
		}
	}
}

func TestScannerIdentityLifecycleKeepsLeaseWhenTrustedParentIsUnavailable(t *testing.T) {
	for _, operation := range []string{"release", "quarantine"} {
		t.Run(operation, func(t *testing.T) {
			allocator := newTestScannerIdentityAllocator(t, 1)
			lease, err := allocator.acquire(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			movedParent := allocator.markerDir + "-held"
			if err := os.Rename(allocator.markerDir, movedParent); err != nil {
				t.Fatalf("move owned marker parent for failure probe: %v", err)
			}
			restored := false
			restoreParent := func() error {
				if restored {
					return nil
				}
				if err := os.Rename(movedParent, allocator.markerDir); err != nil {
					return err
				}
				restored = true
				return nil
			}
			t.Cleanup(func() {
				if err := restoreParent(); err != nil {
					t.Errorf("restore owned marker parent: %v", err)
				}
			})

			if operation == "release" {
				err = lease.release()
			} else {
				err = lease.quarantine()
			}
			if err == nil || !strings.Contains(err.Error(), "trusted parent is unavailable") {
				t.Fatalf("%s with missing trusted parent = %v; want fail-closed open refusal", operation, err)
			}
			stateDir := filepath.Join(movedParent, filepath.Base(allocator.directory))
			journal := readScannerIdentityJournalAtPathOrFatal(t, stateDir)
			entry, exists := journal.Leases[lease.uid]
			if !exists || entry.State != "active" {
				t.Fatalf("%s with missing trusted parent changed the durable reservation: %+v", operation, journal.Leases)
			}
			if operation == "release" {
				if _, _, ok := lease.identity(); !ok {
					t.Fatal("failed release marked its lease finished")
				}
			} else if _, _, ok := lease.identity(); ok {
				t.Fatal("failed quarantine left its in-memory lease available")
			}
			if err := restoreParent(); err != nil {
				t.Fatalf("restore marker parent before retry: %v", err)
			}
			if operation == "release" {
				if err := lease.release(); err != nil {
					t.Fatalf("retry release after restoring parent: %v", err)
				}
			} else if retry, retryErr := allocator.acquire(context.Background()); retry != nil || !errors.Is(retryErr, errScannerIdentityPoolExhausted) {
				t.Fatalf("failed quarantine allowed UID reuse = %v, %v; want reservation retained", retry, retryErr)
			}
		})
	}
}

func TestScannerIdentityNonPID1ReuseRejectsMalformedAttestedLease(t *testing.T) {
	bootstrap := usePrivateScannerRuntime(newTestScannerIdentityAllocator(t, 1))
	lease, err := bootstrap.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	uid, _, ok := lease.identity()
	if !ok {
		t.Fatal("bootstrap lease has no identity")
	}
	uidValue := uint32(uid)
	if err := lease.release(); err != nil {
		t.Fatalf("release bootstrap lease: %v", err)
	}

	journal, err := readTestScannerIdentityJournal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if !journal.PrivateRuntime || journal.PIDNamespace != 17 || len(journal.Leases) != 0 {
		t.Fatalf("bootstrap did not leave the expected empty private scope: %+v", journal)
	}
	journal.Leases[uidValue] = scannerIdentityJournalEntry{GID: uidValue, Token: "not-a-lease-token", State: "active"}
	writeTestScannerIdentityJournalOrFatal(t, bootstrap, journal)
	before, err := os.ReadFile(filepath.Join(bootstrap.directory, scannerIdentityJournalName))
	if err != nil {
		t.Fatal(err)
	}

	reader := newScannerIdentityAllocatorForTest(bootstrap.directory, bootstrap.uidStart, bootstrap.count, testScannerBootID, 17)
	reader.privateScope = func(namespace uint64) (bool, error) { return namespace == 17, nil }
	lease, err = reader.acquire(context.Background())
	if lease != nil || err == nil || !strings.Contains(err.Error(), "journal contains an invalid lease") {
		t.Fatalf("same-scope non-PID1 acquire with malformed durable lease = %v, %v; want fail-closed journal validation", lease, err)
	}
	after, err := os.ReadFile(filepath.Join(bootstrap.directory, scannerIdentityJournalName))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("refused non-PID1 reuse mutated the durable journal: before=%s after=%s", before, after)
	}
}

func TestScannerIdentityNonPID1ReuseFailsClosedWhenScopeProbeErrors(t *testing.T) {
	bootstrap := usePrivateScannerRuntime(newTestScannerIdentityAllocator(t, 1))
	lease, err := bootstrap.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.release(); err != nil {
		t.Fatalf("release bootstrap lease: %v", err)
	}

	before, err := os.ReadFile(filepath.Join(bootstrap.directory, scannerIdentityJournalName))
	if err != nil {
		t.Fatal(err)
	}
	reader := newScannerIdentityAllocatorForTest(bootstrap.directory, bootstrap.uidStart, bootstrap.count, testScannerBootID, 17)
	reader.privateScope = func(uint64) (bool, error) { return false, errors.New("synthetic mount inspection failure") }
	lease, err = reader.acquire(context.Background())
	if lease != nil || err == nil || !strings.Contains(err.Error(), "private runtime scope cannot be verified") {
		t.Fatalf("same-scope non-PID1 acquire with failed scope probe = %v, %v; want fail-closed scope refusal", lease, err)
	}
	after, err := os.ReadFile(filepath.Join(bootstrap.directory, scannerIdentityJournalName))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("scope-probe refusal mutated the durable journal: before=%s after=%s", before, after)
	}
}
