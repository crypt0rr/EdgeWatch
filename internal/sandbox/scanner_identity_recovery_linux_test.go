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

func TestRecoverLegacyScannerIdentityScopeDoesNotMigrateWhenArchiveConflicts(t *testing.T) {
	for _, test := range []struct {
		name      string
		archive   func(int, []byte) error
		archiveN  func([]byte) string
		data      func(scannerIdentityRecoveryFixture) []byte
		directory func(scannerIdentityRecoveryFixture) string
		wantError string
	}{
		{
			name:      "journal archive conflict",
			archive:   archiveScannerIdentityJournal,
			archiveN:  scannerIdentityJournalArchiveName,
			data:      func(f scannerIdentityRecoveryFixture) []byte { return f.journalBytes },
			directory: func(f scannerIdentityRecoveryFixture) string { return f.allocator.directory },
			wantError: "could not preserve the legacy journal",
		},
		{
			name:      "marker archive conflict",
			archive:   archiveScannerIdentityMarker,
			archiveN:  scannerIdentityMarkerArchiveName,
			data:      func(f scannerIdentityRecoveryFixture) []byte { return f.markerBytes },
			directory: func(f scannerIdentityRecoveryFixture) string { return f.allocator.markerDir },
			wantError: "could not preserve the legacy marker",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScannerIdentityRecoveryFixture(t)
			conflict := []byte("preserve conflicting archive evidence")
			archivePath := filepath.Join(test.directory(fixture), test.archiveN(test.data(fixture)))
			if err := os.WriteFile(archivePath, conflict, 0o600); err != nil {
				t.Fatal(err)
			}
			err := recoverLegacyScannerIdentityScope(context.Background(), fixture.allocator, true, 1)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("offline recovery with conflicting archive = %v; want %q", err, test.wantError)
			}
			marker, markerErr := os.ReadFile(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker))
			journal, journalErr := os.ReadFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName))
			if markerErr != nil || !bytes.Equal(marker, fixture.markerBytes) || journalErr != nil || !bytes.Equal(journal, fixture.journalBytes) {
				t.Fatalf("refused archive conflict changed legacy source state: marker=%v journal=%v", markerErr, journalErr)
			}
			gotConflict, err := os.ReadFile(archivePath)
			if err != nil || !bytes.Equal(gotConflict, conflict) {
				t.Fatalf("refused archive conflict replaced evidence: %q, %v", gotConflict, err)
			}
			if test.name == "marker archive conflict" {
				assertScannerIdentityArchive(t, fixture.allocator.directory, scannerIdentityJournalArchiveName(fixture.journalBytes), fixture.journalBytes)
			}
		})
	}
}

func TestOfflineScannerIdentityRecoveryRequiresOperatorConfirmation(t *testing.T) {
	err := recoverScannerIdentityStateOfflineLinux(false)
	if err == nil || !strings.Contains(err.Error(), "--confirm-all-volume-users-stopped") {
		t.Fatalf("offline recovery without explicit confirmation = %v; want confirmation requirement", err)
	}
}

func TestOfflineScannerIdentityRecoveryRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root-only recovery preflight is not applicable to root test runs")
	}
	err := recoverScannerIdentityStateOfflineLinux(true)
	if err == nil || !strings.Contains(err.Error(), "requires root") {
		t.Fatalf("offline recovery as an unprivileged process = %v; want root refusal", err)
	}
}

func TestOfflineScannerIdentityRecoveryRequiresPlatformHook(t *testing.T) {
	previous := recoverScannerIdentityState
	recoverScannerIdentityState = nil
	t.Cleanup(func() { recoverScannerIdentityState = previous })
	if err := RecoverScannerIdentityStateOffline(true); err == nil || !strings.Contains(err.Error(), "requires Linux") {
		t.Fatalf("offline recovery without a platform hook = %v; want Linux-only refusal", err)
	}
}

func TestRecoverLegacyScannerIdentityScopeRejectsUnavailablePreflightInputs(t *testing.T) {
	tests := []struct {
		name  string
		setup func(scannerIdentityRecoveryFixture) (context.Context, *scannerIdentityAllocator)
		want  string
	}{
		{name: "nil context", setup: func(f scannerIdentityRecoveryFixture) (context.Context, *scannerIdentityAllocator) {
			return nil, f.allocator
		}, want: "inputs are unavailable"},
		{name: "canceled context", setup: func(f scannerIdentityRecoveryFixture) (context.Context, *scannerIdentityAllocator) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, f.allocator
		}, want: "inputs are unavailable"},
		{name: "nil allocator", setup: func(scannerIdentityRecoveryFixture) (context.Context, *scannerIdentityAllocator) {
			return context.Background(), nil
		}, want: "inputs are unavailable"},
		{name: "invalid boot ID", setup: func(f scannerIdentityRecoveryFixture) (context.Context, *scannerIdentityAllocator) {
			f.allocator.bootID = func() (string, error) { return "invalid", nil }
			return context.Background(), f.allocator
		}, want: "verify the kernel boot"},
		{name: "unavailable PID namespace", setup: func(f scannerIdentityRecoveryFixture) (context.Context, *scannerIdentityAllocator) {
			f.allocator.pidNamespace = func() (uint64, error) { return 0, nil }
			return context.Background(), f.allocator
		}, want: "verify the PID namespace"},
		{name: "unavailable private runtime", setup: func(f scannerIdentityRecoveryFixture) (context.Context, *scannerIdentityAllocator) {
			f.allocator.privateRuntime = func() (bool, error) { return false, errors.New("private probe detail") }
			return context.Background(), f.allocator
		}, want: "requires the private scanner runtime"},
		{name: "unavailable UID map", setup: func(f scannerIdentityRecoveryFixture) (context.Context, *scannerIdentityAllocator) {
			f.allocator.validateMap = func(uint32, uint32) error { return errors.New("map probe detail") }
			return context.Background(), f.allocator
		}, want: "verify the scanner UID mapping"},
		{name: "missing state directory", setup: func(f scannerIdentityRecoveryFixture) (context.Context, *scannerIdentityAllocator) {
			f.allocator.directory = filepath.Join(filepath.Dir(f.allocator.directory), "missing-state")
			return context.Background(), f.allocator
		}, want: "requires existing legacy state"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScannerIdentityRecoveryFixture(t)
			ctx, allocator := test.setup(fixture)
			err := recoverLegacyScannerIdentityScope(ctx, allocator, true, 1)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("recovery preflight error = %v, want %q", err, test.want)
			}
			if test.name != "missing state directory" {
				assertUnchangedRecoverySource(t, fixture)
			}
		})
	}
}

func TestRecoverLegacyScannerIdentityScopeRejectsSymlinkTrustedParentWithoutMutation(t *testing.T) {
	fixture := newScannerIdentityRecoveryFixture(t)
	alias := filepath.Join(filepath.Dir(fixture.allocator.markerDir), "trusted-parent-alias")
	if err := os.Symlink(fixture.allocator.markerDir, alias); err != nil {
		t.Fatal(err)
	}
	fixture.allocator.directory = filepath.Join(alias, filepath.Base(fixture.allocator.directory))
	fixture.allocator.markerDir = alias

	err := recoverLegacyScannerIdentityScope(context.Background(), fixture.allocator, true, 1)
	if err == nil || !strings.Contains(err.Error(), "cannot open the trusted state directory") {
		t.Fatalf("recovery through a symlinked trusted parent = %v; want fail-closed refusal", err)
	}
	assertUnchangedRecoverySource(t, fixture)
}

func TestRecoverLegacyScannerIdentityScopeRejectsUnprovenDurableStates(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, *scannerIdentityRecoveryFixture) context.Context
		want    string
	}{
		{
			name: "cancellation after preflight census",
			prepare: func(t *testing.T, fixture *scannerIdentityRecoveryFixture) context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				fixture.allocator.inUse = func(uint32, uint32) (map[uint32]struct{}, error) {
					cancel()
					return map[uint32]struct{}{}, nil
				}
				return ctx
			},
			want: "canceled before state inspection",
		},
		{
			name: "second census finds a running scanner",
			prepare: func(t *testing.T, fixture *scannerIdentityRecoveryFixture) context.Context {
				calls := 0
				fixture.allocator.inUse = func(uint32, uint32) (map[uint32]struct{}, error) {
					calls++
					if calls == 1 {
						return map[uint32]struct{}{}, nil
					}
					return map[uint32]struct{}{60000: {}}, nil
				}
				return context.Background()
			},
			want: "in-use or uninspectable",
		},
		{
			name: "second census becomes uninspectable",
			prepare: func(t *testing.T, fixture *scannerIdentityRecoveryFixture) context.Context {
				calls := 0
				fixture.allocator.inUse = func(uint32, uint32) (map[uint32]struct{}, error) {
					calls++
					if calls == 1 {
						return map[uint32]struct{}{}, nil
					}
					return nil, errors.New("private census details")
				}
				return context.Background()
			},
			want: "in-use or uninspectable",
		},
		{
			name: "missing marker",
			prepare: func(t *testing.T, fixture *scannerIdentityRecoveryFixture) context.Context {
				if err := os.Remove(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker)); err != nil {
					t.Fatal(err)
				}
				return context.Background()
			},
			want: "marker is missing",
		},
		{
			name: "malformed marker",
			prepare: func(t *testing.T, fixture *scannerIdentityRecoveryFixture) context.Context {
				if err := os.WriteFile(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
				return context.Background()
			},
			want: "marker is invalid",
		},
		{
			name: "missing journal",
			prepare: func(t *testing.T, fixture *scannerIdentityRecoveryFixture) context.Context {
				if err := os.Remove(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName)); err != nil {
					t.Fatal(err)
				}
				return context.Background()
			},
			want: "journal is missing",
		},
		{
			name: "malformed journal",
			prepare: func(t *testing.T, fixture *scannerIdentityRecoveryFixture) context.Context {
				if err := os.WriteFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
				return context.Background()
			},
			want: "journal is missing",
		},
		{
			name: "invalid legacy lease",
			prepare: func(t *testing.T, fixture *scannerIdentityRecoveryFixture) context.Context {
				journal, err := json.Marshal(scannerIdentityJournal{
					Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true,
					Leases: map[uint32]scannerIdentityJournalEntry{60000: {GID: 60001, Token: "not-a-token", State: "active"}},
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName), journal, 0o600); err != nil {
					t.Fatal(err)
				}
				return context.Background()
			},
			want: "journal entries are invalid",
		},
		{
			name: "empty legacy journal is not an offline recovery target",
			prepare: func(t *testing.T, fixture *scannerIdentityRecoveryFixture) context.Context {
				journal, err := json.Marshal(scannerIdentityJournal{
					Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true,
					Leases: make(map[uint32]scannerIdentityJournalEntry),
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName), journal, 0o600); err != nil {
					t.Fatal(err)
				}
				return context.Background()
			},
			want: "not an occupied same-boot v2 journal",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScannerIdentityRecoveryFixture(t)
			ctx := context.Background()
			if test.prepare != nil {
				ctx = test.prepare(t, &fixture)
			}
			beforeMarker, markerErr := os.ReadFile(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker))
			beforeJournal, journalErr := os.ReadFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName))
			err := recoverLegacyScannerIdentityScope(ctx, fixture.allocator, true, 1)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("recovery error = %v, want %q", err, test.want)
			}
			afterMarker, afterMarkerErr := os.ReadFile(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker))
			afterJournal, afterJournalErr := os.ReadFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName))
			if (markerErr == nil) != (afterMarkerErr == nil) || markerErr == nil && !bytes.Equal(beforeMarker, afterMarker) {
				t.Fatalf("refusal changed marker: %v", afterMarkerErr)
			}
			if (journalErr == nil) != (afterJournalErr == nil) || journalErr == nil && !bytes.Equal(beforeJournal, afterJournal) {
				t.Fatalf("refusal changed journal: %v", afterJournalErr)
			}
			if matches, err := filepath.Glob(filepath.Join(fixture.allocator.directory, "leases.recovery-*.json")); err != nil || len(matches) != 0 {
				t.Fatalf("refusal left recovery archives %v (err %v)", matches, err)
			}
		})
	}
}

func TestRecoverLegacyScannerIdentityScopeFailsClosedOnLockRaces(t *testing.T) {
	for _, test := range []struct {
		name      string
		lockName  string
		busy      bool
		wantError string
	}{
		{name: "busy transition gate", lockName: scannerIdentityTransitionLock, busy: true, wantError: "transition lock is busy"},
		{name: "transition lock symlink", lockName: scannerIdentityTransitionLock, wantError: "transition lock is unavailable"},
		{name: "liveness lock symlink", lockName: scannerIdentityLivenessLock, wantError: "liveness lock is unavailable"},
		{name: "busy allocator lock", lockName: scannerIdentityLock, busy: true, wantError: "allocator lock is busy"},
		{name: "allocator lock symlink", lockName: scannerIdentityLock, wantError: "allocator lock is unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScannerIdentityRecoveryFixture(t)
			beforeMarker, err := os.ReadFile(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker))
			if err != nil {
				t.Fatal(err)
			}
			beforeJournal, err := os.ReadFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName))
			if err != nil {
				t.Fatal(err)
			}
			directoryFD, _, err := openScannerIdentityDirectories(fixture.allocator.directory, fixture.allocator.markerDir)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(directoryFD)
			lockPath := filepath.Join(fixture.allocator.directory, test.lockName)
			if test.busy {
				var fd int
				if test.lockName == scannerIdentityTransitionLock {
					fd, err = openScannerIdentityTransitionLock(directoryFD)
				} else {
					fd, err = openScannerIdentityLock(directoryFD)
				}
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(fd)
				if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := unix.Flock(fd, unix.LOCK_UN); err != nil {
						t.Errorf("unlock recovery lock: %v", err)
					}
				}()
			} else if err := os.Symlink(os.DevNull, lockPath); err != nil {
				t.Fatal(err)
			}

			err = recoverLegacyScannerIdentityScope(context.Background(), fixture.allocator, true, 1)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("recovery lock error = %v, want %q", err, test.wantError)
			}
			afterMarker, markerErr := os.ReadFile(filepath.Join(fixture.allocator.markerDir, scannerIdentityMarker))
			afterJournal, journalErr := os.ReadFile(filepath.Join(fixture.allocator.directory, scannerIdentityJournalName))
			if markerErr != nil || !bytes.Equal(beforeMarker, afterMarker) || journalErr != nil || !bytes.Equal(beforeJournal, afterJournal) {
				t.Fatalf("lock refusal changed source records: marker=%v journal=%v", markerErr, journalErr)
			}
		})
	}
}

func TestLockScannerIdentityOfflineIsNonblocking(t *testing.T) {
	if err := lockScannerIdentityOffline(-1); err == nil {
		t.Fatal("negative lock descriptor was accepted")
	}
	file, err := os.CreateTemp(t.TempDir(), "offline-lock-")
	if err != nil {
		t.Fatal(err)
	}
	if err := lockScannerIdentityOffline(int(file.Fd())); err != nil {
		t.Fatalf("acquire empty offline lock: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
			t.Errorf("unlock offline recovery test descriptor: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Errorf("close offline recovery test descriptor: %v", err)
		}
	})
	second, err := unix.Open(filepath.Join(filepath.Dir(file.Name()), filepath.Base(file.Name())), unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(second)
	if err := lockScannerIdentityOffline(second); err == nil {
		t.Fatal("busy offline lock blocked or was accepted")
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

func TestScannerIdentityArchiveVerifiersRejectUnsafeEvidence(t *testing.T) {
	data := []byte("exact scanner identity evidence")
	directory := t.TempDir()
	directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directoryFD)

	if err := archiveScannerIdentityJournal(-1, data); err == nil {
		t.Fatal("journal archive accepted a negative directory descriptor")
	}
	if err := archiveScannerIdentityJournal(directoryFD, bytes.Repeat([]byte{'x'}, scannerIdentityMaxBytes+1)); err == nil {
		t.Fatal("journal archive accepted data beyond its bound")
	}
	if err := archiveScannerIdentityMarker(-1, data); err == nil {
		t.Fatal("marker archive accepted a negative directory descriptor")
	}
	if err := archiveScannerIdentityMarker(directoryFD, bytes.Repeat([]byte{'x'}, 257)); err == nil {
		t.Fatal("marker archive accepted data beyond its bound")
	}
	if err := installScannerIdentityArchive(-1, "archive.json", data, int64(len(data))); err == nil {
		t.Fatal("archive installer accepted a negative directory descriptor")
	}
	if err := installScannerIdentityArchive(directoryFD, "", data, int64(len(data))); err == nil {
		t.Fatal("archive installer accepted an empty archive name")
	}
	if err := installScannerIdentityArchive(directoryFD, "oversized.json", data, -1); err == nil {
		t.Fatal("archive installer accepted a negative size bound")
	}
	if err := installScannerIdentityArchive(directoryFD, "oversized.json", data, int64(len(data)-1)); err == nil {
		t.Fatal("archive installer accepted data beyond its size bound")
	}
	if err := verifyScannerIdentityArchive(directoryFD, "missing.json", data, int64(len(data))); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("missing archive verification = %v, want ENOENT", err)
	}

	for _, test := range []struct {
		name string
		make func(string) error
	}{
		{
			name: "symlink archive",
			make: func(path string) error { return os.Symlink("missing-target", path) },
		},
		{
			name: "directory archive",
			make: func(path string) error { return os.Mkdir(path, 0o700) },
		},
		{
			name: "unsafe mode",
			make: func(path string) error { return os.WriteFile(path, data, 0o644) },
		},
		{
			name: "content mismatch",
			make: func(path string) error { return os.WriteFile(path, []byte("different evidence"), 0o600) },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(directory, test.name)
			if err := test.make(path); err != nil {
				t.Fatal(err)
			}
			if err := verifyScannerIdentityArchive(directoryFD, test.name, data, int64(len(data))); err == nil {
				t.Fatal("unsafe archive evidence was accepted")
			}
		})
	}

	archiveName := scannerIdentityJournalArchiveName(data)
	archivePath := filepath.Join(directory, archiveName)
	if err := os.WriteFile(archivePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(archivePath, archivePath+".alias"); err != nil {
		t.Fatal(err)
	}
	if err := verifyScannerIdentityArchive(directoryFD, archiveName, data, int64(len(data))); err == nil {
		t.Fatal("multiply linked archive evidence was accepted")
	}
}

func TestScannerIdentityArchiveInstallFailsClosedWhenDirectoryIsReadOnly(t *testing.T) {
	fixture := newScannerIdentityRecoveryFixture(t)
	directoryFD, _, err := openScannerIdentityDirectories(fixture.allocator.directory, fixture.allocator.markerDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directoryFD)

	if err := os.Chmod(fixture.allocator.directory, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(fixture.allocator.directory, 0o700); err != nil {
			t.Errorf("restore archive test directory mode: %v", err)
		}
	})

	err = installScannerIdentityArchive(directoryFD, "read-only.json", []byte("evidence"), 32)
	if err == nil || !strings.Contains(err.Error(), "temporary file cannot be created") {
		t.Fatalf("archive install in a read-only state directory = %v; want fail-closed create error", err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.allocator.directory, "read-only.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed archive install created final evidence: %v", err)
	}
}

func TestVerifyArchivedLegacyScannerIdentityJournalFailsClosedOnCandidates(t *testing.T) {
	fixture := newScannerIdentityRecoveryFixture(t)
	marker := scannerIdentityScope{
		Version: scannerIdentityLegacyVersion, BootID: testScannerBootID, PIDNamespace: 17, PrivateRuntime: true,
	}
	if err := verifyArchivedLegacyScannerIdentityJournal(-1, marker, testScannerBootID, fixture.allocator); err == nil {
		t.Fatal("legacy archive verifier accepted an invalid directory descriptor")
	}
	regular, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyArchivedLegacyScannerIdentityJournal(int(regular.Fd()), marker, testScannerBootID, fixture.allocator); err == nil {
		_ = regular.Close()
		t.Fatal("legacy archive verifier accepted a non-directory descriptor")
	}
	_ = regular.Close()

	directoryFD, markerFD, err := openScannerIdentityDirectories(fixture.allocator.directory, fixture.allocator.markerDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(markerFD)
	if err := writeScannerIdentityFile(directoryFD, "leases.recovery-not-a-digest.json", []byte("untrusted candidate")); err != nil {
		_ = unix.Close(directoryFD)
		t.Fatal(err)
	}
	malformed := []byte("{")
	if err := writeScannerIdentityFile(directoryFD, scannerIdentityJournalArchiveName(malformed), malformed); err != nil {
		_ = unix.Close(directoryFD)
		t.Fatal(err)
	}
	_ = unix.Close(directoryFD)
	if fd, markerFD, openErr := openScannerIdentityDirectories(fixture.allocator.directory, fixture.allocator.markerDir); openErr != nil {
		t.Fatal(openErr)
	} else {
		if err := verifyArchivedLegacyScannerIdentityJournal(fd, marker, testScannerBootID, fixture.allocator); err == nil {
			_ = unix.Close(fd)
			_ = unix.Close(markerFD)
			t.Fatal("unrelated and malformed archives established migration evidence")
		}
		_ = unix.Close(fd)
		_ = unix.Close(markerFD)
	}

	fd, markerFD, err := openScannerIdentityDirectories(fixture.allocator.directory, fixture.allocator.markerDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(markerFD)
	if err := archiveScannerIdentityJournal(fd, fixture.journalBytes); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	if err := verifyArchivedLegacyScannerIdentityJournal(fd, marker, testScannerBootID, fixture.allocator); err != nil {
		_ = unix.Close(fd)
		t.Fatalf("exact archived v2 journal was rejected: %v", err)
	}
	_ = unix.Close(fd)
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
