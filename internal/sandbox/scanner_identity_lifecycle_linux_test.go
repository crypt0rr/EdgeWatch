//go:build linux

package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestScannerIdentityLeaseLifecycleFailsClosedOnChangedScope(t *testing.T) {
	tests := []struct {
		name      string
		private   bool
		change    func(*testing.T, *scannerIdentityAllocator, *scannerIdentityLease)
		wantError string
	}{
		{
			name: "boot changed",
			change: func(_ *testing.T, allocator *scannerIdentityAllocator, _ *scannerIdentityLease) {
				allocator.bootID = func() (string, error) { return testScannerBootID2, nil }
			},
			wantError: "boot changed while lease was active",
		},
		{
			name: "boot probe failed",
			change: func(_ *testing.T, allocator *scannerIdentityAllocator, _ *scannerIdentityLease) {
				allocator.bootID = func() (string, error) { return "", errors.New("probe failed") }
			},
			wantError: "boot changed while lease was active",
		},
		{
			name: "PID namespace changed",
			change: func(_ *testing.T, allocator *scannerIdentityAllocator, _ *scannerIdentityLease) {
				allocator.pidNamespace = func() (uint64, error) { return 18, nil }
			},
			wantError: "PID namespace changed while lease was active",
		},
		{
			name: "PID namespace probe failed",
			change: func(_ *testing.T, allocator *scannerIdentityAllocator, _ *scannerIdentityLease) {
				allocator.pidNamespace = func() (uint64, error) { return 0, errors.New("probe failed") }
			},
			wantError: "PID namespace changed while lease was active",
		},
		{
			name:    "private runtime attestation changed",
			private: true,
			change: func(_ *testing.T, allocator *scannerIdentityAllocator, _ *scannerIdentityLease) {
				allocator.privateRuntime = func() (bool, error) { return false, nil }
				allocator.privateScope = func(uint64) (bool, error) { return false, nil }
			},
			wantError: "PID namespace changed while lease was active",
		},
	}

	for _, operation := range []string{"release", "quarantine"} {
		for _, test := range tests {
			t.Run(operation+"/"+test.name, func(t *testing.T) {
				allocator := newTestScannerIdentityAllocator(t, 1)
				if test.private {
					usePrivateScannerRuntime(allocator)
				}
				lease, err := allocator.acquire(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				test.change(t, allocator, lease)

				err = finishScannerIdentityLease(lease, operation)
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("%s changed-scope result = %v; want error containing %q", operation, err, test.wantError)
				}
				assertScannerIdentityLeaseStillReserved(t, allocator, lease.uid, "active")
				if operation == "release" {
					if _, _, ok := lease.identity(); !ok {
						t.Fatal("failed release marked the lease finished")
					}
				}
			})
		}
	}
}

func TestScannerIdentityLeaseLifecycleRejectsChangedDurableState(t *testing.T) {
	tests := []struct {
		name      string
		change    func(*testing.T, *scannerIdentityAllocator, *scannerIdentityLease)
		wantError string
		wantState string
	}{
		{
			name: "marker missing",
			change: func(t *testing.T, allocator *scannerIdentityAllocator, _ *scannerIdentityLease) {
				if err := os.Remove(filepath.Join(allocator.markerDir, scannerIdentityMarker)); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "boot marker is unavailable or changed",
		},
		{
			name: "marker scope changed",
			change: func(t *testing.T, allocator *scannerIdentityAllocator, _ *scannerIdentityLease) {
				writeTestScannerIdentityMarker(t, allocator, testScannerBootID, 18, false)
			},
			wantError: "boot marker is unavailable or changed",
		},
		{
			name: "journal missing",
			change: func(t *testing.T, allocator *scannerIdentityAllocator, _ *scannerIdentityLease) {
				if err := os.Remove(filepath.Join(allocator.directory, scannerIdentityJournalName)); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "journal is unavailable",
		},
		{
			name: "journal format version changed",
			change: func(t *testing.T, allocator *scannerIdentityAllocator, _ *scannerIdentityLease) {
				journal := readTestScannerIdentityJournalOrFatal(t, allocator)
				journal.Version++
				writeTestScannerIdentityJournalOrFatal(t, allocator, journal)
			},
			wantError: "journal scope changed",
		},
		{
			name: "journal token changed",
			change: func(t *testing.T, allocator *scannerIdentityAllocator, lease *scannerIdentityLease) {
				journal := readTestScannerIdentityJournalOrFatal(t, allocator)
				entry := journal.Leases[lease.uid]
				entry.Token = "ffffffffffffffffffffffffffffffff"
				journal.Leases[lease.uid] = entry
				writeTestScannerIdentityJournalOrFatal(t, allocator, journal)
			},
			wantError: "lease ownership changed",
		},
		{
			name: "journal lease already quarantined",
			change: func(t *testing.T, allocator *scannerIdentityAllocator, lease *scannerIdentityLease) {
				journal := readTestScannerIdentityJournalOrFatal(t, allocator)
				entry := journal.Leases[lease.uid]
				entry.State = "quarantined"
				journal.Leases[lease.uid] = entry
				writeTestScannerIdentityJournalOrFatal(t, allocator, journal)
			},
			wantError: "lease ownership changed",
			wantState: "quarantined",
		},
		{
			name: "invalid lease record",
			change: func(t *testing.T, allocator *scannerIdentityAllocator, lease *scannerIdentityLease) {
				journal := readTestScannerIdentityJournalOrFatal(t, allocator)
				entry := journal.Leases[lease.uid]
				entry.GID++
				journal.Leases[lease.uid] = entry
				writeTestScannerIdentityJournalOrFatal(t, allocator, journal)
			},
			wantError: "journal contains an invalid lease",
		},
		{
			name: "lock replaced by symlink",
			change: func(t *testing.T, allocator *scannerIdentityAllocator, _ *scannerIdentityLease) {
				lock := filepath.Join(allocator.directory, scannerIdentityLock)
				if err := os.Remove(lock); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/dev/null", lock); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "allocator lock is unavailable",
		},
	}

	for _, operation := range []string{"release", "quarantine"} {
		for _, test := range tests {
			t.Run(operation+"/"+test.name, func(t *testing.T) {
				allocator := newTestScannerIdentityAllocator(t, 1)
				lease, err := allocator.acquire(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				test.change(t, allocator, lease)

				err = finishScannerIdentityLease(lease, operation)
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("%s changed-state result = %v; want error containing %q", operation, err, test.wantError)
				}
				if test.name != "journal missing" {
					wantState := test.wantState
					if wantState == "" {
						wantState = "active"
					}
					assertScannerIdentityLeaseStillReserved(t, allocator, lease.uid, wantState)
				}
			})
		}
	}
}

func TestScannerIdentityLeaseLifecycleRejectsMissingDirectoryAndInvalidCalls(t *testing.T) {
	lease, err := newTestScannerIdentityAllocator(t, 1).acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	allocator := lease.allocator
	moved := allocator.directory + "-held"
	if err := os.Rename(allocator.directory, moved); err != nil {
		t.Fatal(err)
	}
	if err := lease.release(); err == nil || !strings.Contains(err.Error(), "journal is unavailable") {
		t.Fatalf("release after allocator directory loss = %v; want missing journal refusal", err)
	}
	journal := readScannerIdentityJournalAtPathOrFatal(t, moved)
	if journal.Leases[lease.uid].State != "active" {
		t.Fatalf("directory-loss handling changed the durable reservation: %+v", journal.Leases)
	}

	var nilLease *scannerIdentityLease
	if err := nilLease.release(); err == nil || !strings.Contains(err.Error(), "lease is unavailable") {
		t.Fatalf("nil lease release = %v; want unavailable lease", err)
	}
	if err := nilLease.quarantine(); err == nil || !strings.Contains(err.Error(), "lease is unavailable") {
		t.Fatalf("nil lease quarantine = %v; want unavailable lease", err)
	}
	if err := lease.update("active"); err == nil || !strings.Contains(err.Error(), "invalid state") {
		t.Fatalf("invalid update state = %v; want refusal", err)
	}
	if _, _, ok := lease.identity(); !ok {
		t.Fatal("a failed lifecycle attempt unexpectedly finished the lease")
	}
}

func TestScannerIdentityPrivateScopeTransitionRejectsUnsafeJournalState(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, *scannerIdentityAllocator, *scannerIdentityScope, *scannerIdentityJournal)
	}{
		{name: "untrusted current runtime", prepare: func(_ *testing.T, _ *scannerIdentityAllocator, _ *scannerIdentityScope, _ *scannerIdentityJournal) {}},
		{name: "previous runtime was not private", prepare: func(_ *testing.T, _ *scannerIdentityAllocator, marker *scannerIdentityScope, _ *scannerIdentityJournal) {
			marker.PrivateRuntime = false
		}},
		{name: "unknown journal version", prepare: func(_ *testing.T, _ *scannerIdentityAllocator, _ *scannerIdentityScope, journal *scannerIdentityJournal) {
			journal.Version++
		}},
		{name: "wrong journal boot", prepare: func(_ *testing.T, _ *scannerIdentityAllocator, _ *scannerIdentityScope, journal *scannerIdentityJournal) {
			journal.BootID = testScannerBootID2
		}},
		{name: "journal not private", prepare: func(_ *testing.T, _ *scannerIdentityAllocator, _ *scannerIdentityScope, journal *scannerIdentityJournal) {
			journal.PrivateRuntime = false
		}},
		{name: "nil lease map", prepare: func(_ *testing.T, _ *scannerIdentityAllocator, _ *scannerIdentityScope, journal *scannerIdentityJournal) {
			journal.Leases = nil
		}},
		{name: "occupied journal", prepare: func(_ *testing.T, allocator *scannerIdentityAllocator, _ *scannerIdentityScope, journal *scannerIdentityJournal) {
			journal.Leases[allocator.uidStart] = scannerIdentityJournalEntry{GID: allocator.uidStart, Token: "0123456789abcdef0123456789abcdef", State: "active"}
		}},
		{name: "inconsistent transition namespace", prepare: func(_ *testing.T, _ *scannerIdentityAllocator, _ *scannerIdentityScope, journal *scannerIdentityJournal) {
			journal.PIDNamespace = 99
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allocator, markerFD, directoryFD, marker, journal := emptyPrivateScannerScopeFixture(t)
			privateRuntime := test.name != "untrusted current runtime"
			test.prepare(t, allocator, &marker, &journal)
			if _, err := allocator.transitionEmptyPrivateScope(directoryFD, markerFD, testScannerBootID, 18, privateRuntime, marker, journal); err == nil {
				t.Fatal("unsafe scope transition succeeded")
			}
			persisted := readTestScannerIdentityJournalOrFatal(t, allocator)
			if persisted.PIDNamespace != 17 || len(persisted.Leases) != 0 {
				t.Fatalf("rejected transition changed persistent journal: %+v", persisted)
			}
		})
	}
}

func TestScannerIdentityPrivateScopeTransitionPersistsJournalBeforeMarker(t *testing.T) {
	allocator, _, directoryFD, marker, journal := emptyPrivateScannerScopeFixture(t)
	procFD := openProcDirectoryOrFatal(t)
	defer unix.Close(procFD)
	if _, err := allocator.transitionEmptyPrivateScope(directoryFD, procFD, testScannerBootID, 18, true, marker, journal); err == nil || !strings.Contains(err.Error(), "transition marker failed") {
		t.Fatalf("transition with unavailable marker directory = %v; want marker failure", err)
	}
	persisted := readTestScannerIdentityJournalOrFatal(t, allocator)
	if persisted.PIDNamespace != 18 || len(persisted.Leases) != 0 {
		t.Fatalf("journal-first transition was not persisted before marker failure: %+v", persisted)
	}

	restarted := usePrivateScannerRuntime(newScannerIdentityAllocatorForTest(allocator.directory, allocator.uidStart, allocator.count, testScannerBootID, 18))
	lease, err := restarted.acquire(context.Background())
	if err != nil {
		t.Fatalf("finish exact empty journal-first transition: %v", err)
	}
	completedMarker, err := readScannerIdentityMarkerAtPath(allocator.markerDir)
	if err != nil || completedMarker.PIDNamespace != 18 || !completedMarker.PrivateRuntime {
		t.Fatalf("recovered transition marker = %+v, %v", completedMarker, err)
	}
	if err := lease.release(); err != nil {
		t.Fatal(err)
	}
}

func TestScannerIdentityPrivateScopeRecoveryArchivesPriorJournal(t *testing.T) {
	allocator := usePrivateScannerRuntime(newTestScannerIdentityAllocator(t, 1))
	oldLease, err := allocator.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	prior, err := os.ReadFile(filepath.Join(allocator.directory, scannerIdentityJournalName))
	if err != nil {
		t.Fatal(err)
	}
	if err := oldLease.closeLivenessReference(); err != nil {
		t.Fatal(err)
	}

	// Simulate a process crash after the archive is durable but before the
	// journal reset. The same archive must be verified and reused on retry.
	directoryFD, markerFD, err := openScannerIdentityDirectories(allocator.directory, allocator.markerDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := archiveScannerIdentityJournal(directoryFD, prior); err != nil {
		_ = unix.Close(directoryFD)
		_ = unix.Close(markerFD)
		t.Fatal(err)
	}
	_ = unix.Close(directoryFD)
	_ = unix.Close(markerFD)

	restarted := usePrivateScannerRuntime(newScannerIdentityAllocatorForTest(allocator.directory, allocator.uidStart, allocator.count, testScannerBootID, 18))
	newLease, err := restarted.acquire(context.Background())
	if err != nil {
		t.Fatalf("recover new private namespace after all inherited refs closed: %v", err)
	}
	defer newLease.release()

	hash := sha256.Sum256(prior)
	archivePath := filepath.Join(allocator.directory, "leases.recovery-"+hex.EncodeToString(hash[:])+".json")
	archived, err := os.ReadFile(archivePath)
	if err != nil || string(archived) != string(prior) {
		t.Fatalf("prior journal archive differs from exact source bytes: err=%v", err)
	}
	var archiveStat unix.Stat_t
	if err := unix.Lstat(archivePath, &archiveStat); err != nil {
		t.Fatal(err)
	}
	if archiveStat.Mode&unix.S_IFMT != unix.S_IFREG || archiveStat.Nlink != 1 || archiveStat.Uid != uint32(os.Geteuid()) || archiveStat.Mode&0o7777 != 0o600 {
		t.Fatalf("journal archive has unsafe metadata: %+v", archiveStat)
	}
	journal, err := readTestScannerIdentityJournal(restarted)
	if err != nil || journal.PIDNamespace != 18 || len(journal.Leases) != 1 {
		t.Fatalf("recovered journal = %+v, %v", journal, err)
	}
}

func TestScannerIdentityLegacyMigrationCompletesJournalFirstNamespaceCrash(t *testing.T) {
	allocator := usePrivateScannerRuntime(newTestScannerIdentityAllocator(t, 1))
	directoryFD, markerFD, err := openScannerIdentityDirectories(allocator.directory, allocator.markerDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directoryFD)
	defer unix.Close(markerFD)

	legacyMarker, err := json.Marshal(scannerIdentityScope{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeScannerIdentityFile(markerFD, scannerIdentityMarker, legacyMarker); err != nil {
		t.Fatal(err)
	}
	legacyJournal, err := json.Marshal(scannerIdentityJournal{
		Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17,
		PrivateRuntime: true, Leases: make(map[uint32]scannerIdentityJournalEntry),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeScannerIdentityFile(directoryFD, scannerIdentityJournalName, legacyJournal); err != nil {
		t.Fatal(err)
	}

	// This is the durable state left when the v3 journal commit for a private
	// namespace migration reached disk but the old v2 marker remained.
	procFD := openProcDirectoryOrFatal(t)
	if _, err := initializeScannerIdentityScope(directoryFD, procFD, testScannerBootID, 18, true, "interrupted migration"); err == nil {
		t.Fatal("migration fixture unexpectedly wrote a marker through /proc")
	}
	_ = unix.Close(procFD)
	markerAfterCrash, err := readScannerIdentityMarker(markerFD)
	if err != nil || markerAfterCrash.Version != scannerIdentityLegacyVersion || markerAfterCrash.PIDNamespace != 17 {
		t.Fatalf("migration marker fixture = %+v, %v", markerAfterCrash, err)
	}
	journalAfterCrash, err := readScannerIdentityJournal(directoryFD)
	if err != nil || journalAfterCrash.Version != scannerIdentityVersion || journalAfterCrash.PIDNamespace != 18 || !journalAfterCrash.PrivateRuntime || len(journalAfterCrash.Leases) != 0 {
		t.Fatalf("migration journal fixture = %+v, %v", journalAfterCrash, err)
	}

	restarted := usePrivateScannerRuntime(newScannerIdentityAllocatorForTest(allocator.directory, allocator.uidStart, allocator.count, testScannerBootID, 18))
	lease, err := restarted.acquire(context.Background())
	if err != nil {
		t.Fatalf("complete journal-first v2-to-v3 migration: %v", err)
	}
	defer lease.release()
	marker, err := readScannerIdentityMarkerAtPath(allocator.markerDir)
	if err != nil || marker.Version != scannerIdentityVersion || marker.PIDNamespace != 18 || !marker.PrivateRuntime {
		t.Fatalf("completed migration marker = %+v, %v", marker, err)
	}
}

func TestScannerIdentityScopeInitializationRecoversOnlyEmptyJournal(t *testing.T) {
	allocator := newTestScannerIdentityAllocator(t, 1)
	directoryFD, markerFD, err := openScannerIdentityDirectories(allocator.directory, allocator.markerDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directoryFD)
	defer unix.Close(markerFD)
	procFD := openProcDirectoryOrFatal(t)
	defer unix.Close(procFD)

	if _, err := initializeScannerIdentityScope(directoryFD, procFD, testScannerBootID, 17, false, "initialize"); err == nil || !strings.Contains(err.Error(), "durable marker write failed") {
		t.Fatalf("initialization with unavailable marker directory = %v; want marker failure", err)
	}
	journal := readTestScannerIdentityJournalOrFatal(t, allocator)
	if journal.BootID != testScannerBootID || journal.PIDNamespace != 17 || len(journal.Leases) != 0 {
		t.Fatalf("failed initialization did not leave only the expected empty journal: %+v", journal)
	}
	lease, err := allocator.acquire(context.Background())
	if err != nil {
		t.Fatalf("complete interrupted empty initialization: %v", err)
	}
	if err := lease.release(); err != nil {
		t.Fatal(err)
	}
}

func finishScannerIdentityLease(lease *scannerIdentityLease, operation string) error {
	switch operation {
	case "release":
		return lease.release()
	case "quarantine":
		return lease.quarantine()
	default:
		return errors.New("unknown test operation")
	}
}

func assertScannerIdentityLeaseStillReserved(t *testing.T, allocator *scannerIdentityAllocator, uid uint32, wantState string) {
	t.Helper()
	journal := readTestScannerIdentityJournalOrFatal(t, allocator)
	entry, ok := journal.Leases[uid]
	if !ok || entry.State != wantState {
		t.Fatalf("lease %d after rejected lifecycle operation = %+v (present=%t); want reserved state %q", uid, entry, ok, wantState)
	}
}

func readTestScannerIdentityJournalOrFatal(t *testing.T, allocator *scannerIdentityAllocator) scannerIdentityJournal {
	t.Helper()
	journal, err := readTestScannerIdentityJournal(allocator)
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func readScannerIdentityJournalAtPathOrFatal(t *testing.T, directory string) scannerIdentityJournal {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(directory, scannerIdentityJournalName))
	if err != nil {
		t.Fatal(err)
	}
	var journal scannerIdentityJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		t.Fatal(err)
	}
	return journal
}

func writeTestScannerIdentityJournalOrFatal(t *testing.T, allocator *scannerIdentityAllocator, journal scannerIdentityJournal) {
	t.Helper()
	if err := writeTestScannerIdentityJournal(allocator, journal); err != nil {
		t.Fatal(err)
	}
}

func writeTestScannerIdentityMarker(t *testing.T, allocator *scannerIdentityAllocator, bootID string, namespace uint64, private bool) {
	t.Helper()
	fd, err := unix.Open(allocator.markerDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := writeScannerIdentityMarker(fd, bootID, namespace, private); err != nil {
		t.Fatal(err)
	}
}

func emptyPrivateScannerScopeFixture(t *testing.T) (*scannerIdentityAllocator, int, int, scannerIdentityScope, scannerIdentityJournal) {
	t.Helper()
	allocator := usePrivateScannerRuntime(newTestScannerIdentityAllocator(t, 1))
	lease, err := allocator.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.release(); err != nil {
		t.Fatal(err)
	}
	directoryFD, markerFD, err := openScannerIdentityDirectories(allocator.directory, allocator.markerDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(directoryFD)
		_ = unix.Close(markerFD)
	})
	marker, err := readScannerIdentityMarker(markerFD)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := readScannerIdentityJournal(directoryFD)
	if err != nil {
		t.Fatal(err)
	}
	return allocator, markerFD, directoryFD, marker, journal
}

func openProcDirectoryOrFatal(t *testing.T) int {
	t.Helper()
	fd, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

func readScannerIdentityMarkerAtPath(path string) (scannerIdentityScope, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return scannerIdentityScope{}, err
	}
	defer unix.Close(fd)
	return readScannerIdentityMarker(fd)
}
