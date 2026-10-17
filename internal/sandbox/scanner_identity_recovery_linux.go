//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// recoverScannerIdentityStateOfflineLinux migrates only a valid, nonempty v2
// journal. The v2 protocol did not propagate liveness references, so the
// explicit operator assertion is required even when the current v3 lock is
// uncontended. The command must run as PID 1 in the deployment's private
// scanner runtime; a host process cannot attest that scope.
func recoverScannerIdentityStateOfflineLinux(confirmAllVolumeUsersStopped bool) error {
	if !confirmAllVolumeUsersStopped {
		return errors.New("scanner identity recovery requires --confirm-all-volume-users-stopped")
	}
	if os.Geteuid() != 0 {
		return errors.New("scanner identity recovery requires root")
	}
	return recoverLegacyScannerIdentityScope(context.Background(), productionScannerIdentityAllocator(), true, os.Getpid())
}

func recoverLegacyScannerIdentityScope(ctx context.Context, allocator *scannerIdentityAllocator, confirmed bool, processID int) error {
	if !confirmed {
		return errors.New("scanner identity recovery requires explicit confirmation")
	}
	if processID != 1 {
		return errors.New("scanner identity recovery requires the private runtime PID 1")
	}
	if ctx == nil || ctx.Err() != nil || allocator == nil || allocator.directory == "" || allocator.markerDir == "" ||
		allocator.bootID == nil || allocator.pidNamespace == nil || allocator.privateRuntime == nil || allocator.validateMap == nil || allocator.inUse == nil {
		return errors.New("scanner identity recovery inputs are unavailable")
	}
	bootID, err := allocator.bootID()
	if err != nil || !validBootID(bootID) {
		return errors.New("scanner identity recovery cannot verify the kernel boot")
	}
	pidNamespace, err := allocator.pidNamespace()
	if err != nil || pidNamespace == 0 {
		return errors.New("scanner identity recovery cannot verify the PID namespace")
	}
	privateRuntime, err := allocator.privateRuntime()
	if err != nil || !privateRuntime {
		return errors.New("scanner identity recovery requires the private scanner runtime")
	}
	if err := allocator.validateMap(allocator.uidStart, allocator.count); err != nil {
		return errors.New("scanner identity recovery cannot verify the scanner UID mapping")
	}
	if _, err := os.Lstat(allocator.directory); err != nil {
		return errors.New("scanner identity recovery requires existing legacy state")
	}

	// Do the procfs check before opening lock files so a detected live or
	// uninspectable pool cannot leave additional persistent state behind.
	used, err := allocator.inUse(allocator.uidStart, allocator.count)
	if err != nil || len(used) != 0 {
		return errors.New("scanner identity recovery found an in-use or uninspectable scanner identity")
	}

	directoryFD, markerFD, err := openScannerIdentityDirectories(allocator.directory, allocator.markerDir)
	if err != nil {
		return errors.New("scanner identity recovery cannot open the trusted state directory")
	}
	defer unix.Close(directoryFD)
	defer unix.Close(markerFD)

	// Offline recovery is deliberately fail-fast. An operator must stop every
	// daemon that shares the volume; this command must not queue behind it.
	gateFD, err := openScannerIdentityTransitionLock(directoryFD)
	if err != nil {
		return errors.New("scanner identity recovery transition lock is unavailable")
	}
	defer unix.Close(gateFD)
	if err := lockScannerIdentityOffline(gateFD); err != nil {
		return errors.New("scanner identity recovery transition lock is busy")
	}
	defer func() { _ = unix.Flock(gateFD, unix.LOCK_UN) }()

	liveness, err := openScannerIdentityLivenessFile(directoryFD, true)
	if err != nil {
		return errors.New("scanner identity recovery liveness lock is unavailable")
	}
	defer liveness.Close()
	if err := setScannerIdentityOFDLock(int(liveness.Fd()), unix.F_WRLCK, true); err != nil {
		return errors.New("scanner identity recovery refused while a live liveness reference exists or OFD locks are unavailable")
	}

	allocatorFD, err := openScannerIdentityLock(directoryFD)
	if err != nil {
		return errors.New("scanner identity recovery allocator lock is unavailable")
	}
	defer unix.Close(allocatorFD)
	if err := lockScannerIdentityOffline(allocatorFD); err != nil {
		return errors.New("scanner identity recovery allocator lock is busy")
	}
	defer func() { _ = unix.Flock(allocatorFD, unix.LOCK_UN) }()
	if err := ctx.Err(); err != nil {
		return errors.New("scanner identity recovery was canceled before state inspection")
	}
	used, err = allocator.inUse(allocator.uidStart, allocator.count)
	if err != nil || len(used) != 0 {
		return errors.New("scanner identity recovery found an in-use or uninspectable scanner identity")
	}

	markerBytes, err := readScannerIdentityFile(markerFD, scannerIdentityMarker, 256)
	if err != nil {
		return errors.New("scanner identity recovery marker is missing, malformed, or unsafe")
	}
	marker, err := readScannerIdentityMarker(markerFD)
	if err != nil {
		return errors.New("scanner identity recovery marker is invalid")
	}
	journal, journalBytes, err := readScannerIdentityJournalWithData(directoryFD)
	if err != nil {
		return errors.New("scanner identity recovery journal is missing, malformed, or unsafe")
	}

	if marker.Version == scannerIdentityVersion && journal.Version == scannerIdentityVersion &&
		marker.BootID == bootID && journal.BootID == bootID && marker.PIDNamespace == pidNamespace &&
		journal.PIDNamespace == pidNamespace && marker.PrivateRuntime && journal.PrivateRuntime &&
		journal.Leases != nil && len(journal.Leases) == 0 {
		if err := allocator.validateJournal(journal); err != nil {
			return errors.New("scanner identity recovery current journal entries are invalid")
		}
		// A retry after the marker commit observes a complete empty current
		// scope. Treat that already-completed migration as an idempotent success.
		return nil
	}

	if marker.Version == scannerIdentityLegacyVersion && journal.Version == scannerIdentityVersion {
		// The journal is committed before the marker. Resume only the exact
		// empty current-scope journal whose old marker and archived v2 source
		// records match. If the runtime namespace changed again while the
		// explicit migration was interrupted, retarget the empty journal only
		// after the same archived-source checks and operator confirmation. Never
		// infer a migration from inode or procfs evidence.
		if marker.BootID != bootID || journal.BootID != bootID || marker.PIDNamespace == 0 || journal.PIDNamespace == 0 ||
			!journal.PrivateRuntime || journal.Leases == nil || len(journal.Leases) != 0 {
			return errors.New("scanner identity recovery journal-first migration state is inconsistent")
		}
		if err := allocator.validateJournal(journal); err != nil {
			return errors.New("scanner identity recovery current journal entries are invalid")
		}
		if err := verifyScannerIdentityMarkerArchive(markerFD, markerBytes); err != nil {
			return errors.New("scanner identity recovery archived marker is missing or invalid")
		}
		if err := verifyArchivedLegacyScannerIdentityJournal(directoryFD, marker, bootID, allocator); err != nil {
			return errors.New("scanner identity recovery archived legacy journal is missing or invalid")
		}
		if journal.PIDNamespace != pidNamespace {
			if _, err := initializeScannerIdentityScope(directoryFD, markerFD, bootID, pidNamespace, true, "resume offline legacy migration"); err != nil {
				return err
			}
			return nil
		}
		if err := writeScannerIdentityMarker(markerFD, bootID, pidNamespace, true); err != nil {
			return errors.New("scanner identity recovery could not commit the migrated marker")
		}
		return nil
	}

	if marker.Version != scannerIdentityLegacyVersion || journal.Version != scannerIdentityLegacyVersion ||
		marker.BootID != bootID || journal.BootID != bootID || marker.PIDNamespace != journal.PIDNamespace ||
		marker.PrivateRuntime != journal.PrivateRuntime || len(journal.Leases) == 0 {
		return errors.New("scanner identity recovery state is not an occupied same-boot v2 journal")
	}
	if err := allocator.validateJournal(journal); err != nil {
		return errors.New("scanner identity recovery journal entries are invalid")
	}

	// Preserve both exact legacy records before the journal-first v3 commit.
	// Content-addressed archives make retries after either archive or the
	// journal commit idempotent without replacing or deleting original data.
	if err := archiveScannerIdentityJournal(directoryFD, journalBytes); err != nil {
		return errors.New("scanner identity recovery could not preserve the legacy journal")
	}
	if err := archiveScannerIdentityMarker(markerFD, markerBytes); err != nil {
		return errors.New("scanner identity recovery could not preserve the legacy marker")
	}
	if _, err := initializeScannerIdentityScope(directoryFD, markerFD, bootID, pidNamespace, true, "offline legacy migration"); err != nil {
		return err
	}
	return nil
}

func lockScannerIdentityOffline(fd int) error {
	if fd < 0 {
		return errors.New("scanner identity offline lock descriptor is invalid")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	return nil
}

func scannerIdentityMarkerArchiveName(data []byte) string {
	hash := sha256.Sum256(data)
	return "scanner-identities.boot.recovery-" + hex.EncodeToString(hash[:]) + ".json"
}

func verifyScannerIdentityMarkerArchive(markerFD int, data []byte) error {
	name := scannerIdentityMarkerArchiveName(data)
	existing, err := readScannerIdentityFile(markerFD, name, 256)
	if err != nil || !bytes.Equal(existing, data) {
		return errors.New("scanner identity marker archive does not match")
	}
	fd, err := unix.Openat(markerFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	return unix.Fsync(markerFD)
}

func verifyArchivedLegacyScannerIdentityJournal(directoryFD int, marker scannerIdentityScope, bootID string, allocator *scannerIdentityAllocator) error {
	duplicate, err := unix.Dup(directoryFD)
	if err != nil {
		return err
	}
	unix.CloseOnExec(duplicate)
	directory := os.NewFile(uintptr(duplicate), scannerIdentityDirectory)
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "leases.recovery-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		data, readErr := readScannerIdentityFile(directoryFD, name, scannerIdentityMaxBytes)
		if readErr != nil || scannerIdentityJournalArchiveName(data) != name {
			continue
		}
		var archived scannerIdentityJournal
		if decodeScannerIdentityJSON(data, &archived) != nil || archived.Version != scannerIdentityLegacyVersion ||
			archived.BootID != bootID || archived.PIDNamespace != marker.PIDNamespace ||
			archived.PrivateRuntime != marker.PrivateRuntime || len(archived.Leases) == 0 || allocator.validateJournal(archived) != nil {
			continue
		}
		fd, openErr := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return openErr
		}
		if syncErr := unix.Fsync(fd); syncErr != nil {
			_ = unix.Close(fd)
			return syncErr
		}
		if closeErr := unix.Close(fd); closeErr != nil {
			return closeErr
		}
		return unix.Fsync(directoryFD)
	}
	return errors.New("no matching archived v2 scanner identity journal")
}

func scannerIdentityJournalArchiveName(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("leases.recovery-%s.json", hex.EncodeToString(hash[:]))
}
