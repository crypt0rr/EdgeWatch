//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type scannerIdentityRecoveryFixture struct {
	allocator    *scannerIdentityAllocator
	markerBytes  []byte
	journalBytes []byte
}

func newScannerIdentityRecoveryFixture(t *testing.T) scannerIdentityRecoveryFixture {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "scanner-identities")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	allocator := newScannerIdentityAllocatorForTest(directory, 60000, 64, testScannerBootID, 18)
	allocator.privateRuntime = func() (bool, error) { return true, nil }
	allocator.inUse = func(uint32, uint32) (map[uint32]struct{}, error) { return map[uint32]struct{}{}, nil }
	markerBytes, err := json.Marshal(scannerIdentityScope{
		Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	journalBytes, err := json.Marshal(scannerIdentityJournal{
		Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true,
		Leases: map[uint32]scannerIdentityJournalEntry{
			60000: {GID: 60000, Token: "0123456789abcdef0123456789abcdef", State: "active"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	directoryFD, markerFD, err := openScannerIdentityDirectories(directory, parent)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeScannerIdentityFile(markerFD, scannerIdentityMarker, markerBytes); err != nil {
		_ = unix.Close(directoryFD)
		_ = unix.Close(markerFD)
		t.Fatal(err)
	}
	if err := writeScannerIdentityFile(directoryFD, scannerIdentityJournalName, journalBytes); err != nil {
		_ = unix.Close(directoryFD)
		_ = unix.Close(markerFD)
		t.Fatal(err)
	}
	_ = unix.Close(directoryFD)
	_ = unix.Close(markerFD)
	return scannerIdentityRecoveryFixture{allocator: allocator, markerBytes: markerBytes, journalBytes: journalBytes}
}

func TestRecoverLegacyScannerIdentityScopeArchivesAndMigratesV2(t *testing.T) {
	fixture := newScannerIdentityRecoveryFixture(t)
	if err := recoverLegacyScannerIdentityScope(context.Background(), fixture.allocator, true, 1); err != nil {
		t.Fatalf("recover valid v2 state: %v", err)
	}
	marker, err := readScannerIdentityMarkerAtPath(fixture.allocator.markerDir)
	if err != nil || marker.Version != scannerIdentityVersion || marker.PIDNamespace != 18 || !marker.PrivateRuntime {
		t.Fatalf("migrated marker = %+v, %v", marker, err)
	}
	journal, err := readTestScannerIdentityJournal(fixture.allocator)
	if err != nil || journal.Version != scannerIdentityVersion || journal.PIDNamespace != 18 || !journal.PrivateRuntime || len(journal.Leases) != 0 {
		t.Fatalf("migrated journal = %+v, %v", journal, err)
	}
	assertScannerIdentityArchive(t, fixture.allocator.directory, scannerIdentityJournalArchiveName(fixture.journalBytes), fixture.journalBytes)
	assertScannerIdentityArchive(t, fixture.allocator.markerDir, scannerIdentityMarkerArchiveName(fixture.markerBytes), fixture.markerBytes)

	// A retry after a successful marker commit is a no-op success.
	if err := recoverLegacyScannerIdentityScope(context.Background(), fixture.allocator, true, 1); err != nil {
		t.Fatalf("repeat completed recovery: %v", err)
	}
}

func TestRecoverLegacyScannerIdentityScopeResumesOnlyArchivedJournalFirstState(t *testing.T) {
	fixture := newScannerIdentityRecoveryFixture(t)
	directoryFD, markerFD, err := openScannerIdentityDirectories(fixture.allocator.directory, fixture.allocator.markerDir)
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
	if err := writeScannerIdentityJournal(directoryFD, scannerIdentityJournal{
		Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 18, PrivateRuntime: true,
		Leases: make(map[uint32]scannerIdentityJournalEntry),
	}); err != nil {
		_ = unix.Close(directoryFD)
		_ = unix.Close(markerFD)
		t.Fatal(err)
	}
	_ = unix.Close(directoryFD)
	_ = unix.Close(markerFD)

	if err := recoverLegacyScannerIdentityScope(context.Background(), fixture.allocator, true, 1); err != nil {
		t.Fatalf("resume exact journal-first migration: %v", err)
	}
	marker, err := readScannerIdentityMarkerAtPath(fixture.allocator.markerDir)
	if err != nil || marker.Version != scannerIdentityVersion || marker.PIDNamespace != 18 || !marker.PrivateRuntime {
		t.Fatalf("resumed marker = %+v, %v", marker, err)
	}
	assertScannerIdentityArchive(t, fixture.allocator.directory, scannerIdentityJournalArchiveName(fixture.journalBytes), fixture.journalBytes)
	assertScannerIdentityArchive(t, fixture.allocator.markerDir, scannerIdentityMarkerArchiveName(fixture.markerBytes), fixture.markerBytes)
}

func TestScannerIdentityArchiveInstallRetriesCrashResidueWithoutReplacingEvidence(t *testing.T) {
	fixture := newScannerIdentityRecoveryFixture(t)
	directoryFD, markerFD, err := openScannerIdentityDirectories(fixture.allocator.directory, fixture.allocator.markerDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directoryFD)
	defer unix.Close(markerFD)

	for _, test := range []struct {
		name      string
		directory string
		fd        int
		data      []byte
		archive   func(int, []byte) error
	}{
		{
			name:      scannerIdentityJournalArchiveName(fixture.journalBytes),
			directory: fixture.allocator.directory,
			fd:        directoryFD,
			data:      fixture.journalBytes,
			archive:   archiveScannerIdentityJournal,
		},
		{
			name:      scannerIdentityMarkerArchiveName(fixture.markerBytes),
			directory: fixture.allocator.markerDir,
			fd:        markerFD,
			data:      fixture.markerBytes,
			archive:   archiveScannerIdentityMarker,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			// A crash before the atomic install can leave an incomplete uniquely
			// named temporary file. It is not trusted as an archive and must not
			// prevent a retry from installing the source bytes under the hash name.
			temporaryPath := filepath.Join(test.directory, test.name+".tmp-crashed")
			if err := os.WriteFile(temporaryPath, []byte("partial temporary evidence"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := test.archive(test.fd, test.data); err != nil {
				t.Fatalf("retry after pre-install crash residue: %v", err)
			}
			archivePath := filepath.Join(test.directory, test.name)
			assertScannerIdentityArchive(t, test.directory, test.name, test.data)
			var before unix.Stat_t
			if err := unix.Lstat(archivePath, &before); err != nil {
				t.Fatal(err)
			}

			// A crash after rename leaves a complete hash-named archive. Retry
			// verifies and fsyncs it without replacing the preserved inode.
			if err := test.archive(test.fd, test.data); err != nil {
				t.Fatalf("retry after completed archive install: %v", err)
			}
			var after unix.Stat_t
			if err := unix.Lstat(archivePath, &after); err != nil {
				t.Fatal(err)
			}
			if before.Ino != after.Ino {
				t.Fatal("idempotent archive retry replaced the installed evidence")
			}
			gotTemporary, err := os.ReadFile(temporaryPath)
			if err != nil || string(gotTemporary) != "partial temporary evidence" {
				t.Fatalf("crash residue changed: %q, %v", gotTemporary, err)
			}
		})
	}
}

func TestScannerIdentityArchiveInstallPreservesConflictingFinalEvidence(t *testing.T) {
	for _, test := range []struct {
		name      string
		archive   func(int, []byte) error
		archiveN  func([]byte) string
		data      func(scannerIdentityRecoveryFixture) []byte
		directory func(scannerIdentityRecoveryFixture) string
	}{
		{
			name:     "journal",
			archive:  archiveScannerIdentityJournal,
			archiveN: scannerIdentityJournalArchiveName,
			data: func(fixture scannerIdentityRecoveryFixture) []byte {
				return fixture.journalBytes
			},
			directory: func(fixture scannerIdentityRecoveryFixture) string {
				return fixture.allocator.directory
			},
		},
		{
			name:     "marker",
			archive:  archiveScannerIdentityMarker,
			archiveN: scannerIdentityMarkerArchiveName,
			data: func(fixture scannerIdentityRecoveryFixture) []byte {
				return fixture.markerBytes
			},
			directory: func(fixture scannerIdentityRecoveryFixture) string {
				return fixture.allocator.markerDir
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScannerIdentityRecoveryFixture(t)
			conflictingBytes := []byte("partial final archive evidence")
			path := filepath.Join(test.directory(fixture), test.archiveN(test.data(fixture)))
			if err := os.WriteFile(path, conflictingBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			directoryFD, markerFD, err := openScannerIdentityDirectories(fixture.allocator.directory, fixture.allocator.markerDir)
			if err != nil {
				t.Fatal(err)
			}
			fd := directoryFD
			if test.name == "marker" {
				fd = markerFD
			}
			err = test.archive(fd, test.data(fixture))
			_ = unix.Close(directoryFD)
			_ = unix.Close(markerFD)
			if err == nil || !strings.Contains(err.Error(), "conflicts with existing evidence") {
				t.Fatalf("archive over partial final evidence = %v; want fail-closed conflict", err)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(got, conflictingBytes) {
				t.Fatalf("conflicting evidence was replaced: %q, %v", got, readErr)
			}
			marker, markerErr := os.ReadFile(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker))
			journal, journalErr := os.ReadFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName))
			if markerErr != nil || !bytes.Equal(marker, fixture.markerBytes) || journalErr != nil || !bytes.Equal(journal, fixture.journalBytes) {
				t.Fatalf("conflicting archive changed source records: marker=%v journal=%v", markerErr, journalErr)
			}
		})
	}
}

func TestRecoverLegacyScannerIdentityScopeRejectsUnprovenContextWithoutStateChanges(t *testing.T) {
	tests := []struct {
		name      string
		confirmed bool
		processID int
		prepare   func(*scannerIdentityRecoveryFixture)
		want      string
	}{
		{name: "missing operator confirmation", confirmed: false, processID: 1, want: "explicit confirmation"},
		{name: "not pid 1", confirmed: true, processID: 2, want: "private runtime PID 1"},
		{name: "not private runtime", confirmed: true, processID: 1, prepare: func(f *scannerIdentityRecoveryFixture) {
			f.allocator.privateRuntime = func() (bool, error) { return false, nil }
		}, want: "private scanner runtime"},
		{name: "scanner UID still in use", confirmed: true, processID: 1, prepare: func(f *scannerIdentityRecoveryFixture) {
			f.allocator.inUse = func(uint32, uint32) (map[uint32]struct{}, error) { return map[uint32]struct{}{60000: {}}, nil }
		}, want: "in-use or uninspectable"},
		{name: "census unavailable", confirmed: true, processID: 1, prepare: func(f *scannerIdentityRecoveryFixture) {
			f.allocator.inUse = func(uint32, uint32) (map[uint32]struct{}, error) { return nil, errors.New("private probe detail") }
		}, want: "in-use or uninspectable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScannerIdentityRecoveryFixture(t)
			if test.prepare != nil {
				test.prepare(&fixture)
			}
			beforeMarker, err := os.ReadFile(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker))
			if err != nil {
				t.Fatal(err)
			}
			beforeJournal, err := os.ReadFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName))
			if err != nil {
				t.Fatal(err)
			}
			err = recoverLegacyScannerIdentityScope(context.Background(), fixture.allocator, test.confirmed, test.processID)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("recovery error = %v, want %q", err, test.want)
			}
			afterMarker, err := os.ReadFile(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker))
			if err != nil {
				t.Fatal(err)
			}
			afterJournal, err := os.ReadFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(afterMarker, beforeMarker) || !bytes.Equal(afterJournal, beforeJournal) {
				t.Fatal("refused recovery changed marker or journal")
			}
			if matches, err := filepath.Glob(filepath.Join(fixture.allocator.directory, "leases.recovery-*.json")); err != nil || len(matches) != 0 {
				t.Fatalf("refused recovery left journal archives %v (err %v)", matches, err)
			}
		})
	}
}

func TestRecoverLegacyScannerIdentityScopeRefusesBusyLivenessAndBadCrashEvidence(t *testing.T) {
	t.Run("busy liveness reference", func(t *testing.T) {
		fixture := newScannerIdentityRecoveryFixture(t)
		directoryFD, _, err := openScannerIdentityDirectories(fixture.allocator.directory, fixture.allocator.markerDir)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(directoryFD)
		live, err := openScannerIdentityLivenessFile(directoryFD, true)
		if err != nil {
			t.Fatal(err)
		}
		defer live.Close()
		if err := setScannerIdentityOFDLock(int(live.Fd()), unix.F_RDLCK, true); err != nil {
			t.Fatal(err)
		}
		if err := recoverLegacyScannerIdentityScope(context.Background(), fixture.allocator, true, 1); err == nil || !strings.Contains(err.Error(), "live liveness reference") {
			t.Fatalf("recovery with live OFD reference = %v; want fail-closed refusal", err)
		}
		assertUnchangedRecoverySource(t, fixture)
	})

	t.Run("journal-first state without both exact archives", func(t *testing.T) {
		fixture := newScannerIdentityRecoveryFixture(t)
		directoryFD, _, err := openScannerIdentityDirectories(fixture.allocator.directory, fixture.allocator.markerDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeScannerIdentityJournal(directoryFD, scannerIdentityJournal{
			Version: scannerIdentityVersion, BootID: testScannerBootID, PIDNamespace: 18, PrivateRuntime: true,
			Leases: make(map[uint32]scannerIdentityJournalEntry),
		}); err != nil {
			_ = unix.Close(directoryFD)
			t.Fatal(err)
		}
		_ = unix.Close(directoryFD)
		beforeMarker, err := os.ReadFile(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker))
		if err != nil {
			t.Fatal(err)
		}
		beforeJournal, err := os.ReadFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName))
		if err != nil {
			t.Fatal(err)
		}
		if err := recoverLegacyScannerIdentityScope(context.Background(), fixture.allocator, true, 1); err == nil || !strings.Contains(err.Error(), "archived marker") {
			t.Fatalf("recovery without exact archives = %v; want fail-closed refusal", err)
		}
		afterMarker, err := os.ReadFile(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker))
		if err != nil {
			t.Fatal(err)
		}
		afterJournal, err := os.ReadFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(beforeMarker, afterMarker) || !bytes.Equal(beforeJournal, afterJournal) {
			t.Fatal("unproven journal-first state was modified")
		}
	})
}

func assertUnchangedRecoverySource(t *testing.T, fixture scannerIdentityRecoveryFixture) {
	t.Helper()
	marker, err := os.ReadFile(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker))
	if err != nil || !bytes.Equal(marker, fixture.markerBytes) {
		t.Fatalf("recovery marker changed: %v", err)
	}
	journal, err := os.ReadFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName))
	if err != nil || !bytes.Equal(journal, fixture.journalBytes) {
		t.Fatalf("recovery journal changed: %v", err)
	}
	if matches, err := filepath.Glob(filepath.Join(fixture.allocator.directory, "leases.recovery-*.json")); err != nil || len(matches) != 0 {
		t.Fatalf("recovery created journal archive(s) %v (err %v)", matches, err)
	}
}

func assertScannerIdentityArchive(t *testing.T, directory, name string, want []byte) {
	t.Helper()
	path := filepath.Join(directory, name)
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("archive %s does not preserve exact source bytes: %v", name, err)
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o600 {
		t.Fatalf("archive %s metadata is unsafe: %+v, %v", name, stat, err)
	}
}
