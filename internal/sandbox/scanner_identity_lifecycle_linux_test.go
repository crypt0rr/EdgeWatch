//go:build linux

package sandbox

import (
	"bytes"
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

func TestScannerIdentityLeaseReleaseReportsUnexpectedLivenessClose(t *testing.T) {
	allocator := newTestScannerIdentityAllocator(t, 1)
	lease, err := allocator.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.livenessRef.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.inheritedScannerLivenessFile(); err == nil {
		t.Fatal("closed liveness descriptor remained transferable")
	}
	if err := lease.release(); err == nil || !strings.Contains(err.Error(), "liveness reference close failed") {
		t.Fatalf("release after unexpected reference close = %v; want a liveness-close error", err)
	}
	if !lease.finished || lease.livenessRef != nil {
		t.Fatalf("durably released lease state = finished %t, reference %v", lease.finished, lease.livenessRef)
	}
	journal := readTestScannerIdentityJournalOrFatal(t, allocator)
	if _, present := journal.Leases[lease.uid]; present {
		t.Fatalf("durably released lease %d remains reserved", lease.uid)
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
	t.Cleanup(func() {
		if err := newLease.release(); err != nil {
			t.Errorf("release recovered lease: %v", err)
		}
	})

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
	t.Cleanup(func() {
		if err := lease.release(); err != nil {
			t.Errorf("release migrated lease: %v", err)
		}
	})
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

func TestScannerIdentityLoadOrInitializeHandlesLegacyScopeTransitions(t *testing.T) {
	tests := []struct {
		name            string
		marker          scannerIdentityScope
		journal         scannerIdentityJournal
		pidNamespace    uint64
		privateRuntime  bool
		exclusive       bool
		wantError       string
		wantPrivate     bool
		wantInitialized bool
	}{
		{
			name:         "shared reference refuses legacy state",
			marker:       scannerIdentityScope{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			journal:      scannerIdentityJournal{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{}},
			pidNamespace: 17, privateRuntime: true, wantError: "requires exclusive offline migration",
		},
		{
			name:         "same scope empty v2 journal migrates",
			marker:       scannerIdentityScope{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			journal:      scannerIdentityJournal{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{}},
			pidNamespace: 17, privateRuntime: true, exclusive: true, wantPrivate: true, wantInitialized: true,
		},
		{
			name:         "private namespace empty v2 journal migrates",
			marker:       scannerIdentityScope{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			journal:      scannerIdentityJournal{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{}},
			pidNamespace: 18, privateRuntime: true, exclusive: true, wantPrivate: true, wantInitialized: true,
		},
		{
			name:   "occupied v2 journal refuses automatic reset",
			marker: scannerIdentityScope{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			journal: scannerIdentityJournal{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{
				60000: {GID: 60000, Token: "0123456789abcdef0123456789abcdef", State: "active"},
			}},
			pidNamespace: 18, privateRuntime: true, exclusive: true, wantError: "same-boot legacy leases require offline migration",
		},
		{
			name:         "marker and journal scope disagreement refuses",
			marker:       scannerIdentityScope{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			journal:      scannerIdentityJournal{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 18, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{}},
			pidNamespace: 18, privateRuntime: true, exclusive: true, wantError: "legacy scope records disagree",
		},
		{
			name:         "same namespace cannot regain private attestation",
			marker:       scannerIdentityScope{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			journal:      scannerIdentityJournal{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{}},
			pidNamespace: 17, privateRuntime: false, exclusive: true, wantError: "private runtime cannot be re-attested",
		},
		{
			name:         "namespace change requires private runtime",
			marker:       scannerIdentityScope{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			journal:      scannerIdentityJournal{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{}},
			pidNamespace: 18, privateRuntime: false, exclusive: true, wantError: "PID namespace migration requires a private runtime",
		},
		{
			name:   "invalid legacy lease is refused",
			marker: scannerIdentityScope{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			journal: scannerIdentityJournal{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{
				60000: {GID: 60001, Token: "0123456789abcdef0123456789abcdef", State: "active"},
			}},
			pidNamespace: 17, privateRuntime: true, exclusive: true, wantError: "journal contains an invalid lease",
		},
		{
			name:         "missing lease map refuses legacy transition",
			marker:       scannerIdentityScope{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			journal:      scannerIdentityJournal{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			pidNamespace: 17, privateRuntime: true, exclusive: true, wantError: "migration state is inconsistent",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScannerIdentityRecoveryFixture(t)
			markerBytes, err := json.Marshal(test.marker)
			if err != nil {
				t.Fatal(err)
			}
			journalBytes, err := json.Marshal(test.journal)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker), markerBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName), journalBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			directoryFD, markerFD, err := openScannerIdentityDirectories(fixture.allocator.directory, fixture.allocator.markerDir)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(directoryFD)
			defer unix.Close(markerFD)
			journal, privateRuntime, err := fixture.allocator.loadOrInitializeWithLiveness(
				directoryFD, markerFD, testScannerBootID, test.pidNamespace, test.privateRuntime, test.exclusive,
			)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("legacy scope result = %+v private=%t error=%v; want error containing %q", journal, privateRuntime, err, test.wantError)
				}
				gotMarker, markerErr := os.ReadFile(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker))
				gotJournal, journalErr := os.ReadFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName))
				if markerErr != nil || journalErr != nil || !bytes.Equal(gotMarker, markerBytes) || !bytes.Equal(gotJournal, journalBytes) {
					t.Fatalf("refused legacy transition changed durable state: marker=%v journal=%v", markerErr, journalErr)
				}
				return
			}
			if err != nil || privateRuntime != test.wantPrivate || !test.wantInitialized {
				t.Fatalf("legacy scope migration = %+v private=%t error=%v", journal, privateRuntime, err)
			}
			persistedMarker, markerErr := readScannerIdentityMarkerAtPath(fixture.allocator.markerDir)
			persistedJournal, journalErr := readTestScannerIdentityJournal(fixture.allocator)
			if markerErr != nil || journalErr != nil || persistedMarker.Version != scannerIdentityVersion || persistedJournal.Version != scannerIdentityVersion ||
				persistedMarker.PIDNamespace != test.pidNamespace || persistedJournal.PIDNamespace != test.pidNamespace || len(persistedJournal.Leases) != 0 {
				t.Fatalf("migrated scope marker=%+v (%v) journal=%+v (%v)", persistedMarker, markerErr, persistedJournal, journalErr)
			}
		})
	}
}

func TestScannerIdentityLoadOrInitializeRecoversOnlyProvenStaleScopes(t *testing.T) {
	tests := []struct {
		name             string
		marker           *scannerIdentityScope
		journal          scannerIdentityJournal
		journalRaw       []byte
		bootID           string
		pidNamespace     uint64
		privateRuntime   bool
		exclusive        bool
		wantError        string
		wantArchive      bool
		wantJournalBoot  string
		wantJournalPIDNS uint64
		wantLeaseCount   int
	}{
		{
			name:   "same scope retains active leases when shared",
			marker: &scannerIdentityScope{Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			journal: scannerIdentityJournal{Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{
				60000: {GID: 60000, Token: "0123456789abcdef0123456789abcdef", State: "active"},
			}},
			bootID: testScannerBootID, pidNamespace: 17, privateRuntime: true, wantJournalBoot: testScannerBootID, wantJournalPIDNS: 17, wantLeaseCount: 1,
		},
		{
			name:   "exclusive same scope archives and clears stale lease",
			marker: &scannerIdentityScope{Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			journal: scannerIdentityJournal{Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{
				60000: {GID: 60000, Token: "0123456789abcdef0123456789abcdef", State: "quarantined"},
			}},
			bootID: testScannerBootID, pidNamespace: 17, privateRuntime: true, exclusive: true, wantArchive: true, wantJournalBoot: testScannerBootID, wantJournalPIDNS: 17,
		},
		{
			name:   "exclusive private namespace change archives old scope",
			marker: &scannerIdentityScope{Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			journal: scannerIdentityJournal{Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{
				60000: {GID: 60000, Token: "0123456789abcdef0123456789abcdef", State: "active"},
			}},
			bootID: testScannerBootID, pidNamespace: 18, privateRuntime: true, exclusive: true, wantArchive: true, wantJournalBoot: testScannerBootID, wantJournalPIDNS: 18,
		},
		{
			name:    "shared reference refuses private namespace change",
			marker:  &scannerIdentityScope{Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			journal: scannerIdentityJournal{Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{}},
			bootID:  testScannerBootID, pidNamespace: 18, privateRuntime: true, wantError: "exclusive private-scope proof",
		},
		{
			name:    "native runtime cannot reset private namespace",
			marker:  &scannerIdentityScope{Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			journal: scannerIdentityJournal{Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{}},
			bootID:  testScannerBootID, pidNamespace: 18, privateRuntime: false, exclusive: true, wantError: "exclusive private-scope proof",
		},
		{
			name:   "prior boot marker archives leases before reset",
			marker: &scannerIdentityScope{Version: scannerIdentityVersion, BootID: testScannerBootID2, PIDNamespace: 17, PrivateRuntime: true},
			journal: scannerIdentityJournal{Version: scannerIdentityVersion, BootID: testScannerBootID2, PIDNamespace: 17, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{
				60000: {GID: 60000, Token: "0123456789abcdef0123456789abcdef", State: "active"},
			}},
			bootID: testScannerBootID, pidNamespace: 18, privateRuntime: true, exclusive: true, wantArchive: true, wantJournalBoot: testScannerBootID, wantJournalPIDNS: 18,
		},
		{
			name:    "prior boot marker refuses shared liveness reference",
			marker:  &scannerIdentityScope{Version: scannerIdentityVersion, BootID: testScannerBootID2, PIDNamespace: 17, PrivateRuntime: true},
			journal: scannerIdentityJournal{Version: scannerIdentityVersion, BootID: testScannerBootID2, PIDNamespace: 17, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{}},
			bootID:  testScannerBootID, pidNamespace: 18, privateRuntime: true, wantError: "requires exclusive recovery",
		},
		{
			name: "missing marker with prior boot journal archives before reset",
			journal: scannerIdentityJournal{Version: scannerIdentityVersion, BootID: testScannerBootID2, PIDNamespace: 17, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{
				60000: {GID: 60000, Token: "0123456789abcdef0123456789abcdef", State: "active"},
			}},
			bootID: testScannerBootID, pidNamespace: 18, privateRuntime: true, exclusive: true, wantArchive: true, wantJournalBoot: testScannerBootID, wantJournalPIDNS: 18,
		},
		{
			name:       "malformed prior boot journal is archived before safe reset",
			marker:     &scannerIdentityScope{Version: scannerIdentityVersion, BootID: testScannerBootID2, PIDNamespace: 17, PrivateRuntime: true},
			journalRaw: []byte(`{"version":3,"boot_id":"not-a-boot-id","pid_namespace":17,"private_runtime":true,"leases":{"60000":{"gid":60000,"token":"damaged","state":"active"}}}`),
			bootID:     testScannerBootID, pidNamespace: 18, privateRuntime: true, exclusive: true, wantArchive: true, wantJournalBoot: testScannerBootID, wantJournalPIDNS: 18,
		},
		{
			name:    "journal first v2 transition completes only empty target",
			marker:  &scannerIdentityScope{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			journal: scannerIdentityJournal{Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 18, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{}},
			bootID:  testScannerBootID, pidNamespace: 18, privateRuntime: true, exclusive: true, wantJournalBoot: testScannerBootID, wantJournalPIDNS: 18,
		},
		{
			name:    "journal first transition refuses mismatched target",
			marker:  &scannerIdentityScope{Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true},
			journal: scannerIdentityJournal{Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 18, PrivateRuntime: true, Leases: map[uint32]scannerIdentityJournalEntry{}},
			bootID:  testScannerBootID, pidNamespace: 18, privateRuntime: false, exclusive: true, wantError: "migration state is inconsistent",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScannerIdentityRecoveryFixture(t)
			var markerBytes []byte
			if test.marker != nil {
				var err error
				markerBytes, err = json.Marshal(test.marker)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker), markerBytes, 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker)); err != nil {
				t.Fatal(err)
			}
			journalBytes := test.journalRaw
			if journalBytes == nil {
				var err error
				journalBytes, err = json.Marshal(test.journal)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName), journalBytes, 0o600); err != nil {
				t.Fatal(err)
			}

			directoryFD, markerFD, err := openScannerIdentityDirectories(fixture.allocator.directory, fixture.allocator.markerDir)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(directoryFD)
			defer unix.Close(markerFD)
			journal, privateRuntime, err := fixture.allocator.loadOrInitializeWithLiveness(
				directoryFD, markerFD, test.bootID, test.pidNamespace, test.privateRuntime, test.exclusive,
			)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("scope transition = %+v private=%t error=%v; want %q", journal, privateRuntime, err, test.wantError)
				}
				return
			}
			if err != nil || !privateRuntime && test.privateRuntime || journal.Version != scannerIdentityVersion ||
				journal.BootID != test.wantJournalBoot || journal.PIDNamespace != test.wantJournalPIDNS || len(journal.Leases) != test.wantLeaseCount {
				t.Fatalf("scope transition = %+v private=%t error=%v", journal, privateRuntime, err)
			}
			persistedMarker, markerErr := readScannerIdentityMarkerAtPath(fixture.allocator.markerDir)
			if markerErr != nil || persistedMarker.Version != scannerIdentityVersion || persistedMarker.BootID != test.wantJournalBoot || persistedMarker.PIDNamespace != test.wantJournalPIDNS {
				t.Fatalf("persisted marker = %+v, %v", persistedMarker, markerErr)
			}
			if test.wantArchive {
				assertScannerIdentityArchive(t, fixture.allocator.directory, scannerIdentityJournalArchiveName(journalBytes), journalBytes)
			}
		})
	}
}

func TestScannerIdentityChangedNamespaceRejectsUnprovenJournalScope(t *testing.T) {
	tests := []struct {
		name    string
		journal scannerIdentityJournal
	}{
		{
			name: "v3 marker cannot prove nonempty v2 leases are stale",
			journal: scannerIdentityJournal{
				Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true,
				Leases: map[uint32]scannerIdentityJournalEntry{
					60000: {GID: 60000, Token: "0123456789abcdef0123456789abcdef", State: "active"},
				},
			},
		},
		{
			name: "unknown journal version cannot prove old scope",
			journal: scannerIdentityJournal{
				Version: scannerIdentityVersion + 1, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true,
				Leases: map[uint32]scannerIdentityJournalEntry{
					60000: {GID: 60000, Token: "0123456789abcdef0123456789abcdef", State: "active"},
				},
			},
		},
		{
			name: "v3 journal scope must match its marker",
			journal: scannerIdentityJournal{
				Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 19, PrivateRuntime: true,
				Leases: map[uint32]scannerIdentityJournalEntry{
					60000: {GID: 60000, Token: "0123456789abcdef0123456789abcdef", State: "active"},
				},
			},
		},
		{
			name: "nonempty target-scope v3 journal is not an interrupted empty transition",
			journal: scannerIdentityJournal{
				Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 18, PrivateRuntime: true,
				Leases: map[uint32]scannerIdentityJournalEntry{
					60000: {GID: 60000, Token: "0123456789abcdef0123456789abcdef", State: "active"},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScannerIdentityRecoveryFixture(t)
			allocator := fixture.allocator
			markerBytes, err := json.Marshal(scannerIdentityScope{
				Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			journalBytes, err := json.Marshal(test.journal)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(allocator.markerDir, scannerIdentityMarker), markerBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(allocator.directory, scannerIdentityJournalName), journalBytes, 0o600); err != nil {
				t.Fatal(err)
			}

			lease, err := allocator.acquire(context.Background())
			if err == nil || lease != nil {
				t.Fatalf("acquire from an unproven old scope = lease %v, error %v; want refusal without a lease", lease, err)
			}
			gotMarker, markerErr := os.ReadFile(filepath.Join(allocator.markerDir, scannerIdentityMarker))
			gotJournal, journalErr := os.ReadFile(filepath.Join(allocator.directory, scannerIdentityJournalName))
			if markerErr != nil || journalErr != nil || !bytes.Equal(gotMarker, markerBytes) || !bytes.Equal(gotJournal, journalBytes) {
				t.Fatalf("refused namespace recovery changed source records: marker=%v journal=%v", markerErr, journalErr)
			}
			entries, err := os.ReadDir(allocator.directory)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), "leases.recovery-") {
					t.Fatalf("refused namespace recovery created journal archive %q", entry.Name())
				}
			}
		})
	}
}

func TestScannerIdentityChangedNamespaceCompletesOnlyProvenEmptyIntermediateScopes(t *testing.T) {
	tests := []struct {
		name          string
		markerVersion int
	}{
		{name: "v3 scope rollover", markerVersion: scannerIdentityVersion},
		{name: "empty v2 migration rollover", markerVersion: scannerIdentityLegacyVersion},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScannerIdentityRecoveryFixture(t)
			allocator := fixture.allocator
			allocator.pidNamespace = func() (uint64, error) { return 19, nil }
			markerBytes, err := json.Marshal(scannerIdentityScope{
				Version: test.markerVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			journalBytes, err := json.Marshal(scannerIdentityJournal{
				Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 18, PrivateRuntime: true,
				Leases: make(map[uint32]scannerIdentityJournalEntry),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(allocator.markerDir, scannerIdentityMarker), markerBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(allocator.directory, scannerIdentityJournalName), journalBytes, 0o600); err != nil {
				t.Fatal(err)
			}

			lease, err := allocator.acquire(context.Background())
			if err != nil || lease == nil {
				t.Fatalf("complete safe empty intermediate scope: lease=%v error=%v", lease, err)
			}
			t.Cleanup(func() {
				if err := lease.release(); err != nil {
					t.Errorf("release recovered scanner identity: %v", err)
				}
			})
			marker, err := readScannerIdentityMarkerAtPath(allocator.markerDir)
			if err != nil || marker.Version != scannerIdentityVersion || marker.BootID != testScannerBootID || marker.PIDNamespace != 19 || !marker.PrivateRuntime {
				t.Fatalf("recovered marker = %+v, %v", marker, err)
			}
			journal, err := readTestScannerIdentityJournal(allocator)
			if err != nil || journal.Version != scannerIdentityVersion || journal.BootID != testScannerBootID || journal.PIDNamespace != 19 || !journal.PrivateRuntime || len(journal.Leases) != 1 {
				t.Fatalf("recovered journal = %+v, %v", journal, err)
			}
		})
	}
}

func TestScannerIdentityAutomaticRecoveryRequiresExplicitOfflineV2Evidence(t *testing.T) {
	fixture := newScannerIdentityRecoveryFixture(t)
	allocator := fixture.allocator
	allocator.pidNamespace = func() (uint64, error) { return 19, nil }
	directoryFD, markerFD, err := openScannerIdentityDirectories(allocator.directory, allocator.markerDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := archiveScannerIdentityJournal(directoryFD, fixture.journalBytes); err != nil {
		_ = unix.Close(directoryFD)
		_ = unix.Close(markerFD)
		t.Fatal(err)
	}
	if err := archiveScannerIdentityMarker(markerFD, fixture.markerBytes); err != nil {
		_ = unix.Close(directoryFD)
		_ = unix.Close(markerFD)
		t.Fatal(err)
	}
	intermediate, err := json.Marshal(scannerIdentityJournal{
		Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 18, PrivateRuntime: true,
		Leases: make(map[uint32]scannerIdentityJournalEntry),
	})
	if err != nil {
		_ = unix.Close(directoryFD)
		_ = unix.Close(markerFD)
		t.Fatal(err)
	}
	if err := writeScannerIdentityFile(directoryFD, scannerIdentityJournalName, intermediate); err != nil {
		_ = unix.Close(directoryFD)
		_ = unix.Close(markerFD)
		t.Fatal(err)
	}
	_ = unix.Close(directoryFD)
	_ = unix.Close(markerFD)

	lease, err := allocator.acquire(context.Background())
	if err == nil || lease != nil {
		t.Fatalf("automatic recovery of an offline nonempty-v2 migration = lease %v error %v; want explicit offline confirmation", lease, err)
	}
	gotMarker, markerErr := os.ReadFile(filepath.Join(allocator.markerDir, scannerIdentityMarker))
	gotJournal, journalErr := os.ReadFile(filepath.Join(allocator.directory, scannerIdentityJournalName))
	if markerErr != nil || journalErr != nil || !bytes.Equal(gotMarker, fixture.markerBytes) || !bytes.Equal(gotJournal, intermediate) {
		t.Fatalf("automatic refusal changed offline migration source: marker=%v journal=%v", markerErr, journalErr)
	}
	assertScannerIdentityArchive(t, allocator.directory, scannerIdentityJournalArchiveName(fixture.journalBytes), fixture.journalBytes)
	assertScannerIdentityArchive(t, allocator.markerDir, scannerIdentityMarkerArchiveName(fixture.markerBytes), fixture.markerBytes)

	if err := recoverLegacyScannerIdentityScope(context.Background(), allocator, false, 1); err == nil {
		t.Fatal("offline recovery without explicit confirmation succeeded")
	}
	gotMarker, markerErr = os.ReadFile(filepath.Join(allocator.markerDir, scannerIdentityMarker))
	gotJournal, journalErr = os.ReadFile(filepath.Join(allocator.directory, scannerIdentityJournalName))
	if markerErr != nil || journalErr != nil || !bytes.Equal(gotMarker, fixture.markerBytes) || !bytes.Equal(gotJournal, intermediate) {
		t.Fatalf("unconfirmed offline recovery changed source: marker=%v journal=%v", markerErr, journalErr)
	}

	if err := recoverLegacyScannerIdentityScope(context.Background(), allocator, true, 1); err != nil {
		t.Fatalf("confirmed offline recovery of archived v2 state: %v", err)
	}
	marker, err := readScannerIdentityMarkerAtPath(allocator.markerDir)
	if err != nil || marker.Version != scannerIdentityVersion || marker.BootID != testScannerBootID || marker.PIDNamespace != 19 || !marker.PrivateRuntime {
		t.Fatalf("offline recovered marker = %+v, %v", marker, err)
	}
	journal, err := readTestScannerIdentityJournal(allocator)
	if err != nil || journal.Version != scannerIdentityVersion || journal.BootID != testScannerBootID || journal.PIDNamespace != 19 || !journal.PrivateRuntime || len(journal.Leases) != 0 {
		t.Fatalf("offline recovered journal = %+v, %v", journal, err)
	}
	assertScannerIdentityArchive(t, allocator.directory, scannerIdentityJournalArchiveName(fixture.journalBytes), fixture.journalBytes)
	assertScannerIdentityArchive(t, allocator.markerDir, scannerIdentityMarkerArchiveName(fixture.markerBytes), fixture.markerBytes)
}

func TestScannerIdentityAutomaticRecoveryRefusesCorruptLegacyMarkerArchive(t *testing.T) {
	fixture := newScannerIdentityRecoveryFixture(t)
	allocator := fixture.allocator
	allocator.pidNamespace = func() (uint64, error) { return 19, nil }
	directoryFD, markerFD, err := openScannerIdentityDirectories(allocator.directory, allocator.markerDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directoryFD)
	defer unix.Close(markerFD)
	if err := archiveScannerIdentityJournal(directoryFD, fixture.journalBytes); err != nil {
		t.Fatal(err)
	}
	intermediate, err := json.Marshal(scannerIdentityJournal{
		Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 18, PrivateRuntime: true,
		Leases: make(map[uint32]scannerIdentityJournalEntry),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeScannerIdentityFile(directoryFD, scannerIdentityJournalName, intermediate); err != nil {
		t.Fatal(err)
	}
	corruptArchive := []byte(`{"not":"the archived marker"}`)
	archivePath := filepath.Join(allocator.markerDir, scannerIdentityMarkerArchiveName(fixture.markerBytes))
	if err := os.WriteFile(archivePath, corruptArchive, 0o600); err != nil {
		t.Fatal(err)
	}

	lease, err := allocator.acquire(context.Background())
	if err == nil || lease != nil {
		t.Fatalf("automatic recovery with a corrupt legacy marker archive = lease %v error %v; want fail-closed refusal", lease, err)
	}
	if !strings.Contains(err.Error(), "legacy migration archive cannot be verified") {
		t.Fatalf("automatic recovery error = %v, want archive verification failure", err)
	}
	gotMarker, markerErr := os.ReadFile(filepath.Join(allocator.markerDir, scannerIdentityMarker))
	gotJournal, journalErr := os.ReadFile(filepath.Join(allocator.directory, scannerIdentityJournalName))
	gotArchive, archiveErr := os.ReadFile(archivePath)
	if markerErr != nil || journalErr != nil || archiveErr != nil ||
		!bytes.Equal(gotMarker, fixture.markerBytes) || !bytes.Equal(gotJournal, intermediate) || !bytes.Equal(gotArchive, corruptArchive) {
		t.Fatalf("refused automatic recovery changed source evidence: marker=%v journal=%v archive=%v", markerErr, journalErr, archiveErr)
	}
}

func TestScannerIdentityAcquirePreservesLeasesWhenArchiveOrResetCannotCommit(t *testing.T) {
	for _, test := range []struct {
		name          string
		private       bool
		priorPIDNS    uint64
		wantError     string
		archiveAction string
	}{
		{name: "ordinary stale lease archive conflict", priorPIDNS: 18, wantError: "stale lease journal archive failed", archiveAction: "conflict"},
		{name: "private namespace archive conflict", private: true, priorPIDNS: 17, wantError: "stale private journal archive failed", archiveAction: "conflict"},
		{name: "stale lease reset write failure", priorPIDNS: 18, wantError: "stale lease recovery failed", archiveAction: "readonly"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScannerIdentityRecoveryFixture(t)
			allocator := fixture.allocator
			allocator.privateRuntime = func() (bool, error) { return test.private, nil }
			allocator.pidNamespace = func() (uint64, error) { return 18, nil }
			writeTestScannerIdentityMarker(t, allocator, testScannerBootID, test.priorPIDNS, test.private)
			journal := scannerIdentityJournal{
				Version: scannerIdentityVersion, BootID: testScannerBootID,
				PIDNamespace: test.priorPIDNS, PrivateRuntime: test.private,
				Leases: map[uint32]scannerIdentityJournalEntry{
					60000: {GID: 60000, Token: "0123456789abcdef0123456789abcdef", State: "active"},
				},
			}
			writeTestScannerIdentityJournalOrFatal(t, allocator, journal)
			journalBytes, err := os.ReadFile(filepath.Join(allocator.directory, scannerIdentityJournalName))
			if err != nil {
				t.Fatal(err)
			}
			archiveName := scannerIdentityJournalArchiveName(journalBytes)
			archivePath := filepath.Join(allocator.directory, archiveName)
			switch test.archiveAction {
			case "conflict":
				if err := os.WriteFile(archivePath, []byte("preserve conflicting evidence"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "readonly":
				directoryFD, _, err := openScannerIdentityDirectories(allocator.directory, allocator.markerDir)
				if err != nil {
					t.Fatal(err)
				}
				if err := archiveScannerIdentityJournal(directoryFD, journalBytes); err != nil {
					_ = unix.Close(directoryFD)
					t.Fatal(err)
				}
				if err := unix.Close(directoryFD); err != nil {
					t.Fatal(err)
				}
				allocator.inUse = func(uint32, uint32) (map[uint32]struct{}, error) {
					if err := os.Chmod(allocator.directory, 0o500); err != nil {
						return nil, err
					}
					return map[uint32]struct{}{}, nil
				}
				t.Cleanup(func() {
					if err := os.Chmod(allocator.directory, 0o700); err != nil {
						t.Errorf("restore scanner identity directory mode: %v", err)
					}
				})
			}

			if lease, err := allocator.acquire(context.Background()); err == nil || lease != nil || !strings.Contains(err.Error(), test.wantError) {
				if lease != nil {
					_ = lease.quarantine()
				}
				t.Fatalf("acquire with uncommittable stale-state transition = lease %v, error %v; want %q", lease, err, test.wantError)
			}
			if err := os.Chmod(allocator.directory, 0o700); err != nil {
				t.Fatal(err)
			}
			gotJournal, err := os.ReadFile(filepath.Join(allocator.directory, scannerIdentityJournalName))
			if err != nil || !bytes.Equal(gotJournal, journalBytes) {
				t.Fatalf("refused stale transition changed lease journal: %v", err)
			}
			if test.archiveAction == "conflict" {
				gotArchive, err := os.ReadFile(archivePath)
				if err != nil || string(gotArchive) != "preserve conflicting evidence" {
					t.Fatalf("refused stale transition changed conflicting archive: %q, %v", gotArchive, err)
				}
			} else {
				assertScannerIdentityArchive(t, allocator.directory, archiveName, journalBytes)
			}
			assertScannerIdentityLeaseStillReserved(t, allocator, 60000, "active")
		})
	}
}

func TestScannerIdentityLoadOrInitializeRefusesUnpreservablePriorBootState(t *testing.T) {
	for _, test := range []struct {
		name       string
		unreadable bool
	}{
		{name: "unreadable journal", unreadable: true},
		{name: "conflicting prior-boot archive"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScannerIdentityRecoveryFixture(t)
			allocator := fixture.allocator
			allocator.privateRuntime = func() (bool, error) { return true, nil }
			allocator.pidNamespace = func() (uint64, error) { return 18, nil }
			writeTestScannerIdentityMarker(t, allocator, testScannerBootID2, 17, true)
			journal := scannerIdentityJournal{
				Version: scannerIdentityVersion, BootID: testScannerBootID2, PIDNamespace: 17, PrivateRuntime: true,
				Leases: map[uint32]scannerIdentityJournalEntry{
					60000: {GID: 60000, Token: "0123456789abcdef0123456789abcdef", State: "active"},
				},
			}
			writeTestScannerIdentityJournalOrFatal(t, allocator, journal)
			journalPath := filepath.Join(allocator.directory, scannerIdentityJournalName)
			var journalBytes []byte
			var archivePath string
			if test.unreadable {
				if err := os.Remove(journalPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(journalPath, 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				var err error
				journalBytes, err = os.ReadFile(journalPath)
				if err != nil {
					t.Fatal(err)
				}
				archivePath = filepath.Join(allocator.directory, scannerIdentityJournalArchiveName(journalBytes))
				if err := os.WriteFile(archivePath, []byte("preserve conflicting prior-boot evidence"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			directoryFD, markerFD, err := openScannerIdentityDirectories(allocator.directory, allocator.markerDir)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(directoryFD)
			defer unix.Close(markerFD)
			_, _, err = allocator.loadOrInitializeWithLiveness(directoryFD, markerFD, testScannerBootID, 18, true, true)
			want := "prior-boot journal archive failed"
			if test.unreadable {
				want = "unreadable prior-boot journal cannot be replaced"
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("prior-boot recovery with unpreservable evidence = %v; want %q", err, want)
			}
			marker, markerErr := readScannerIdentityMarkerAtPath(allocator.markerDir)
			if markerErr != nil || marker.BootID != testScannerBootID2 || marker.PIDNamespace != 17 {
				t.Fatalf("refused recovery changed the old marker: %+v, %v", marker, markerErr)
			}
			if test.unreadable {
				if info, err := os.Lstat(journalPath); err != nil || !info.IsDir() {
					t.Fatalf("refused recovery changed unreadable journal evidence: %v", err)
				}
			} else {
				got, err := os.ReadFile(journalPath)
				if err != nil || !bytes.Equal(got, journalBytes) {
					t.Fatalf("refused recovery changed prior-boot journal: %v", err)
				}
				archive, err := os.ReadFile(archivePath)
				if err != nil || string(archive) != "preserve conflicting prior-boot evidence" {
					t.Fatalf("refused recovery changed conflicting archive: %q, %v", archive, err)
				}
			}
		})
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
