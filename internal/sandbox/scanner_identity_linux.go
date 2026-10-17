//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	scannerIdentityDirectory     = "/var/lib/edgewatch/scanner-identities"
	scannerIdentityMarkerDir     = "/var/lib/edgewatch"
	scannerIdentityStart         = uint32(ScannerIdentityPoolUIDStart)
	scannerIdentityCount         = uint32(ScannerIdentityPoolCapacity)
	scannerIdentityJournalName   = "leases.json"
	scannerIdentityMarker        = "scanner-identities.boot"
	scannerIdentityLock          = "allocator.lock"
	scannerIdentityVersion       = 3
	scannerIdentityLegacyVersion = 2
	scannerIdentityMaxBytes      = 64 << 10
)

var (
	errScannerIdentityPoolExhausted = errors.New("scanner identity pool is exhausted")
	productionScannerAllocatorOnce  sync.Once
	productionScannerAllocator      *scannerIdentityAllocator
)

// scannerIdentityAllocator serializes scanner UID/GID leases across daemon
// processes and records every lease before a scanner can start. A lease that
// is not explicitly released after the supervisor proves the scanner subtree
// is gone remains occupied until the kernel boot ID changes.
//
// Production uses scannerIdentityDirectory. Tests use a private directory and
// controlled boot/PID-namespace identities; callers cannot configure the
// production path or pool.
type scannerIdentityAllocator struct {
	directory                string
	markerDir                string
	uidStart                 uint32
	count                    uint32
	bootID                   func() (string, error)
	pidNamespace             func() (uint64, error)
	privateRuntime           func() (bool, error)
	privateScope             func(uint64) (bool, error)
	validateMap              func(uint32, uint32) error
	inUse                    func(uint32, uint32) (map[uint32]struct{}, error)
	persistRuntimeLiveness   bool
	runtimeLivenessMu        sync.Mutex
	runtimeLivenessReference *os.File
}

type scannerIdentityJournal struct {
	Version        int                                    `json:"version"`
	BootID         string                                 `json:"boot_id"`
	PIDNamespace   uint64                                 `json:"pid_namespace_inode"`
	PrivateRuntime bool                                   `json:"private_runtime"`
	Leases         map[uint32]scannerIdentityJournalEntry `json:"leases"`
}

type scannerIdentityJournalEntry struct {
	GID   uint32 `json:"gid"`
	Token string `json:"token"`
	State string `json:"state"`
}

type scannerIdentityLease struct {
	allocator      *scannerIdentityAllocator
	uid            uint32
	gid            uint32
	token          string
	bootID         string
	pidNS          uint64
	privateRuntime bool
	livenessRef    *os.File
	finished       bool
}

func productionScannerIdentityAllocator() *scannerIdentityAllocator {
	productionScannerAllocatorOnce.Do(func() {
		productionScannerAllocator = &scannerIdentityAllocator{
			directory:              scannerIdentityDirectory,
			markerDir:              scannerIdentityMarkerDir,
			uidStart:               scannerIdentityStart,
			count:                  scannerIdentityCount,
			bootID:                 currentBootID,
			pidNamespace:           currentPIDNamespaceInode,
			privateRuntime:         currentPrivateScannerRuntime,
			privateScope:           currentPrivateScannerNamespace,
			validateMap:            validateScannerIdentityRangeMapping,
			inUse:                  scannerIdentitiesInUse,
			persistRuntimeLiveness: true,
		}
	})
	return productionScannerAllocator
}

func newScannerIdentityAllocatorForTest(directory string, uidStart, count uint32, bootID string, pidNamespace uint64) *scannerIdentityAllocator {
	return &scannerIdentityAllocator{
		directory: directory, markerDir: filepath.Dir(directory), uidStart: uidStart, count: count,
		bootID:         func() (string, error) { return bootID, nil },
		pidNamespace:   func() (uint64, error) { return pidNamespace, nil },
		privateRuntime: func() (bool, error) { return false, nil },
		privateScope:   func(uint64) (bool, error) { return false, nil },
		validateMap:    func(uint32, uint32) error { return nil },
		inUse:          func(uint32, uint32) (map[uint32]struct{}, error) { return map[uint32]struct{}{}, nil },
	}
}

func (allocator *scannerIdentityAllocator) acquire(ctx context.Context) (*scannerIdentityLease, error) {
	if ctx == nil {
		return nil, errors.New("acquire scanner identity: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if allocator == nil || allocator.directory == "" || allocator.markerDir == "" || allocator.count == 0 || allocator.uidStart == 0 ||
		uint64(allocator.uidStart)+uint64(allocator.count) > 1<<32 || allocator.bootID == nil || allocator.pidNamespace == nil || allocator.privateRuntime == nil || allocator.privateScope == nil || allocator.validateMap == nil || allocator.inUse == nil {
		return nil, errors.New("acquire scanner identity: allocator is invalid")
	}
	bootID, err := allocator.bootID()
	if err != nil || !validBootID(bootID) {
		return nil, errors.New("acquire scanner identity: kernel boot identity is unavailable")
	}
	pidNamespace, err := allocator.pidNamespace()
	if err != nil || pidNamespace == 0 {
		return nil, errors.New("acquire scanner identity: PID namespace identity is unavailable")
	}
	privateRuntime, err := allocator.privateRuntime()
	if err != nil {
		return nil, errors.New("acquire scanner identity: private runtime scope is unavailable")
	}
	if err := allocator.validateMap(allocator.uidStart, allocator.count); err != nil {
		return nil, err
	}
	directoryFD, markerFD, err := openScannerIdentityDirectories(allocator.directory, allocator.markerDir)
	if err != nil {
		return nil, err
	}
	scope, exclusive, err := beginScannerIdentityScopeLock(ctx, directoryFD, markerFD)
	if err != nil {
		_ = unix.Close(directoryFD)
		_ = unix.Close(markerFD)
		return nil, err
	}
	defer scope.close()
	if err := scope.lockAllocator(ctx); err != nil {
		return nil, err
	}
	defer func() {
		if scope.lockedAlloc {
			_ = unix.Flock(scope.allocatorFD, unix.LOCK_UN)
		}
	}()
	// Do not create or rewrite durable scope state until the current identity
	// census succeeds. The transition gate and allocator lock already serialize
	// joins and mutations while the read-only process preflight runs.
	identitiesInUse, err := allocator.inUse(allocator.uidStart, allocator.count)
	if err != nil {
		return nil, errors.New("acquire scanner identity: current identity use cannot be inspected")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	journal, privateRuntime, err := allocator.loadOrInitializeWithLiveness(directoryFD, markerFD, bootID, pidNamespace, privateRuntime, exclusive)
	if err != nil {
		return nil, err
	}
	if exclusive {
		if err := scope.downgradeLiveness(directoryFD); err != nil {
			return nil, err
		}
	}
	if allocator.persistRuntimeLiveness {
		if err := scope.retainRuntimeReference(allocator); err != nil {
			return nil, err
		}
	}
	for offset := uint32(0); offset < allocator.count; offset++ {
		uid := allocator.uidStart + offset
		if _, occupied := journal.Leases[uid]; occupied {
			continue
		}
		if _, used := identitiesInUse[uid]; used {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var tokenBytes [16]byte
		if _, err := rand.Read(tokenBytes[:]); err != nil {
			return nil, errors.New("acquire scanner identity: lease token is unavailable")
		}
		token := hex.EncodeToString(tokenBytes[:])
		journal.Leases[uid] = scannerIdentityJournalEntry{GID: uid, Token: token, State: "active"}
		if err := writeScannerIdentityJournal(directoryFD, journal); err != nil {
			return nil, errors.New("acquire scanner identity: durable lease write failed")
		}
		livenessRef, err := scope.takeInheritedLivenessFile()
		if err != nil {
			delete(journal.Leases, uid)
			_ = writeScannerIdentityJournal(directoryFD, journal)
			return nil, err
		}
		lease := &scannerIdentityLease{allocator: allocator, uid: uid, gid: uid, token: token, bootID: bootID, pidNS: pidNamespace, privateRuntime: privateRuntime, livenessRef: livenessRef}
		if err := ctx.Err(); err != nil {
			delete(journal.Leases, uid)
			if writeErr := writeScannerIdentityJournal(directoryFD, journal); writeErr != nil {
				// Keep the durable reservation rather than risk reuse after an
				// interrupted acquire whose rollback could not be committed.
				return nil, errors.New("acquire scanner identity: cancellation rollback failed; identity remains reserved")
			}
			_ = livenessRef.Close()
			return nil, err
		}
		return lease, nil
	}
	return nil, errScannerIdentityPoolExhausted
}

func (lease *scannerIdentityLease) identity() (int, int, bool) {
	if lease == nil || lease.finished {
		return 0, 0, false
	}
	return int(lease.uid), int(lease.gid), true
}

func (lease *scannerIdentityLease) inheritedScannerLivenessFile() (*os.File, error) {
	if lease == nil || lease.finished || lease.livenessRef == nil {
		return nil, errors.New("scanner identity liveness reference is unavailable")
	}
	flags, err := unix.FcntlInt(lease.livenessRef.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return nil, errors.New("scanner identity liveness reference is not read-only")
	}
	return lease.livenessRef, nil
}

// quarantine keeps an invocation's identity unavailable after supervisor,
// process-tree, or cleanup uncertainty. It is intentionally not reversible
// during the same boot.
func (lease *scannerIdentityLease) quarantine() error {
	if lease == nil || lease.finished {
		return errors.New("quarantine scanner identity: lease is unavailable")
	}
	// Quarantine is terminal in memory even if its durable write fails: callers
	// must never turn uncertain cleanup into an ordinary release. Keep the
	// liveness reference open so a later allocator still sees the scope as live.
	lease.finished = true
	if err := lease.update("quarantined"); err != nil {
		return err
	}
	return nil
}

func (lease *scannerIdentityLease) closeLivenessReference() error {
	if lease != nil && lease.livenessRef != nil {
		err := lease.livenessRef.Close()
		lease.livenessRef = nil
		return err
	}
	return nil
}

// release is called only after the trusted supervisor reports successful
// cleanup and reaping. Callers must quarantine instead whenever that proof is
// absent; the journal token prevents one invocation from releasing another's
// reservation.
func (lease *scannerIdentityLease) release() error {
	if lease == nil || lease.finished {
		return errors.New("release scanner identity: lease is unavailable")
	}
	allocator := lease.allocator
	directoryFD, markerFD, err := openScannerIdentityDirectories(allocator.directory, allocator.markerDir)
	if err != nil {
		return err
	}
	defer unix.Close(directoryFD)
	defer unix.Close(markerFD)
	lockFD, err := openScannerIdentityLock(directoryFD)
	if err != nil {
		return errors.New("release scanner identity: allocator lock is unavailable")
	}
	defer unix.Close(lockFD)
	if err := unix.Flock(lockFD, unix.LOCK_EX); err != nil {
		return errors.New("release scanner identity: allocator lock failed")
	}
	defer func() { _ = unix.Flock(lockFD, unix.LOCK_UN) }()
	bootID, err := allocator.bootID()
	if err != nil || bootID != lease.bootID {
		return errors.New("release scanner identity: boot changed while lease was active")
	}
	pidNamespace, err := allocator.pidNamespace()
	if err != nil || pidNamespace != lease.pidNS {
		return errors.New("release scanner identity: PID namespace changed while lease was active")
	}
	privateRuntime, privateErr := allocator.privateRuntimeForLease(lease, bootID, pidNamespace)
	if privateErr != nil || privateRuntime != lease.privateRuntime {
		return errors.New("release scanner identity: PID namespace changed while lease was active")
	}
	marker, err := readScannerIdentityMarker(markerFD)
	if err != nil || marker.BootID != bootID || marker.PIDNamespace != pidNamespace || marker.PrivateRuntime != privateRuntime {
		return errors.New("release scanner identity: boot marker is unavailable or changed")
	}
	journal, err := readScannerIdentityJournal(directoryFD)
	if err != nil {
		return errors.New("release scanner identity: journal is unavailable")
	}
	if journal.Version != scannerIdentityVersion || journal.BootID != bootID || journal.PIDNamespace != pidNamespace || journal.PrivateRuntime != privateRuntime {
		return errors.New("release scanner identity: journal scope changed")
	}
	if err := allocator.validateJournal(journal); err != nil {
		return err
	}
	entry, ok := journal.Leases[lease.uid]
	if !ok || entry.GID != lease.gid || entry.Token != lease.token || entry.State != "active" {
		return errors.New("release scanner identity: lease ownership changed")
	}
	delete(journal.Leases, lease.uid)
	if err := writeScannerIdentityJournal(directoryFD, journal); err != nil {
		return errors.New("release scanner identity: durable release failed")
	}
	lease.finished = true
	if err := lease.closeLivenessReference(); err != nil {
		return errors.New("release scanner identity: liveness reference close failed")
	}
	return nil
}

func (lease *scannerIdentityLease) update(state string) error {
	if state != "quarantined" {
		return errors.New("update scanner identity: invalid state")
	}
	allocator := lease.allocator
	directoryFD, markerFD, err := openScannerIdentityDirectories(allocator.directory, allocator.markerDir)
	if err != nil {
		return err
	}
	defer unix.Close(directoryFD)
	defer unix.Close(markerFD)
	lockFD, err := openScannerIdentityLock(directoryFD)
	if err != nil {
		return errors.New("update scanner identity: allocator lock is unavailable")
	}
	defer unix.Close(lockFD)
	if err := unix.Flock(lockFD, unix.LOCK_EX); err != nil {
		return errors.New("update scanner identity: allocator lock failed")
	}
	defer func() { _ = unix.Flock(lockFD, unix.LOCK_UN) }()
	bootID, err := allocator.bootID()
	if err != nil || bootID != lease.bootID {
		return errors.New("update scanner identity: boot changed while lease was active")
	}
	pidNamespace, err := allocator.pidNamespace()
	if err != nil || pidNamespace != lease.pidNS {
		return errors.New("update scanner identity: PID namespace changed while lease was active")
	}
	privateRuntime, privateErr := allocator.privateRuntimeForLease(lease, bootID, pidNamespace)
	if privateErr != nil || privateRuntime != lease.privateRuntime {
		return errors.New("update scanner identity: PID namespace changed while lease was active")
	}
	marker, err := readScannerIdentityMarker(markerFD)
	if err != nil || marker.BootID != bootID || marker.PIDNamespace != pidNamespace || marker.PrivateRuntime != privateRuntime {
		return errors.New("update scanner identity: boot marker is unavailable or changed")
	}
	journal, err := readScannerIdentityJournal(directoryFD)
	if err != nil {
		return errors.New("update scanner identity: journal is unavailable")
	}
	if journal.Version != scannerIdentityVersion || journal.BootID != bootID || journal.PIDNamespace != pidNamespace || journal.PrivateRuntime != privateRuntime {
		return errors.New("update scanner identity: journal scope changed")
	}
	if err := allocator.validateJournal(journal); err != nil {
		return err
	}
	entry, ok := journal.Leases[lease.uid]
	if !ok || entry.GID != lease.gid || entry.Token != lease.token || entry.State != "active" {
		return errors.New("update scanner identity: lease ownership changed")
	}
	entry.State = state
	journal.Leases[lease.uid] = entry
	if err := writeScannerIdentityJournal(directoryFD, journal); err != nil {
		return errors.New("update scanner identity: durable quarantine failed")
	}
	return nil
}

func (allocator *scannerIdentityAllocator) loadOrInitialize(directoryFD, markerFD int, bootID string, pidNamespace uint64, privateRuntime bool) (scannerIdentityJournal, bool, error) {
	return allocator.loadOrInitializeWithLiveness(directoryFD, markerFD, bootID, pidNamespace, privateRuntime, true)
}

func (allocator *scannerIdentityAllocator) loadOrInitializeWithLiveness(directoryFD, markerFD int, bootID string, pidNamespace uint64, privateRuntime, exclusiveLiveness bool) (scannerIdentityJournal, bool, error) {
	marker, markerErr := readScannerIdentityMarker(markerFD)
	journal, journalData, journalErr := readScannerIdentityJournalWithData(directoryFD)
	if !privateRuntime && markerErr == nil && journalErr == nil &&
		(marker.Version == scannerIdentityVersion || marker.Version == scannerIdentityLegacyVersion) && journal.Version == marker.Version &&
		marker.BootID == bootID && journal.BootID == bootID &&
		marker.PIDNamespace == pidNamespace && journal.PIDNamespace == pidNamespace &&
		marker.PrivateRuntime && journal.PrivateRuntime && journal.Leases != nil {
		// PID 1 establishes private-runtime scope. Other processes in the same
		// namespace may reuse that attested scope only after validating both
		// durable records under the allocator lock and confirming their current
		// PID namespace and /tmp mount still match it.
		if err := allocator.validateJournal(journal); err != nil {
			return scannerIdentityJournal{}, false, err
		}
		matches, err := allocator.privateScope(pidNamespace)
		if err != nil {
			return scannerIdentityJournal{}, false, errors.New("scanner identity allocator: private runtime scope cannot be verified")
		}
		privateRuntime = matches
	}
	if markerErr == nil && journalErr == nil && marker.BootID == bootID && journal.BootID == bootID &&
		marker.Version == scannerIdentityLegacyVersion && journal.Version == scannerIdentityLegacyVersion {
		if !exclusiveLiveness {
			return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: legacy scope requires exclusive offline migration")
		}
		if marker.Version != scannerIdentityLegacyVersion || journal.Version != scannerIdentityLegacyVersion || journal.Leases == nil {
			return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: legacy scope migration state is inconsistent")
		}
		if err := allocator.validateJournal(journal); err != nil {
			return scannerIdentityJournal{}, privateRuntime, err
		}
		if len(journal.Leases) != 0 {
			return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: same-boot legacy leases require offline migration")
		}
		if marker.PIDNamespace != journal.PIDNamespace || marker.PrivateRuntime != journal.PrivateRuntime {
			return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: legacy scope records disagree")
		}
		if marker.PIDNamespace == pidNamespace && marker.PrivateRuntime != privateRuntime {
			return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: legacy private runtime cannot be re-attested")
		}
		if marker.PIDNamespace != pidNamespace && (!privateRuntime || !marker.PrivateRuntime) {
			return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: legacy PID namespace migration requires a private runtime")
		}
		journal, err := initializeScannerIdentityScope(directoryFD, markerFD, bootID, pidNamespace, privateRuntime, "migrate empty legacy scope")
		return journal, privateRuntime, err
	}
	if markerErr == nil && journalErr == nil && marker.Version == scannerIdentityLegacyVersion && journal.Version == scannerIdentityVersion {
		// Automatic v2 migration starts only from an empty v2 journal. An
		// interrupted offline migration of a nonempty v2 journal is distinct:
		// its exact source marker was archived first and it must be resumed only
		// through the explicitly confirmed offline command.
		if exclusiveLiveness && marker.BootID == bootID && journal.BootID == bootID && journal.PIDNamespace != 0 && journal.PrivateRuntime == privateRuntime && journal.Leases != nil && len(journal.Leases) == 0 {
			if err := allocator.validateJournal(journal); err != nil {
				return scannerIdentityJournal{}, privateRuntime, err
			}
			archived, err := hasArchivedScannerIdentityMarker(markerFD)
			if err != nil {
				return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: legacy migration archive cannot be verified")
			}
			if archived {
				return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: archived legacy migration requires explicit offline recovery")
			}
			if marker.PIDNamespace == pidNamespace && marker.PrivateRuntime != privateRuntime {
				return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: legacy private runtime cannot be re-attested")
			}
			if marker.PIDNamespace != pidNamespace && (!privateRuntime || !marker.PrivateRuntime || !journal.PrivateRuntime) {
				return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: legacy PID namespace migration requires a private runtime")
			}
			if journal.PIDNamespace != pidNamespace {
				if !privateRuntime || !marker.PrivateRuntime || !journal.PrivateRuntime {
					return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: legacy scope migration state is inconsistent")
				}
				journal, err := initializeScannerIdentityScope(directoryFD, markerFD, bootID, pidNamespace, true, "resume empty legacy scope migration")
				return journal, true, err
			}
			if err := writeScannerIdentityMarker(markerFD, bootID, pidNamespace, privateRuntime); err != nil {
				return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: migrated marker write failed")
			}
			return journal, privateRuntime, nil
		}
		return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: legacy scope migration state is inconsistent")
	}
	switch {
	case errors.Is(markerErr, unix.ENOENT) && errors.Is(journalErr, unix.ENOENT):
		if !exclusiveLiveness {
			return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: scope is not initialized")
		}
		journal, err := initializeScannerIdentityScope(directoryFD, markerFD, bootID, pidNamespace, privateRuntime, "initialize")
		return journal, privateRuntime, err
	case markerErr != nil:
		if errors.Is(markerErr, unix.ENOENT) && journalErr == nil {
			if exclusiveLiveness && journal.Version == scannerIdentityVersion && journal.BootID == bootID && journal.PIDNamespace == pidNamespace && journal.PrivateRuntime == privateRuntime && journal.Leases != nil && len(journal.Leases) == 0 {
				// A crash between the initial empty journal and marker commits is
				// recoverable because no UID could have been handed out yet.
				if err := allocator.validateJournal(journal); err != nil {
					return scannerIdentityJournal{}, privateRuntime, err
				}
				if err := writeScannerIdentityMarker(markerFD, bootID, pidNamespace, privateRuntime); err != nil {
					return scannerIdentityJournal{}, privateRuntime, errors.New("complete scanner identity allocator initialization: durable marker write failed")
				}
				return journal, privateRuntime, nil
			}
			if exclusiveLiveness && (journal.Version == scannerIdentityVersion || journal.Version == scannerIdentityLegacyVersion) && validBootID(journal.BootID) && journal.BootID != bootID {
				// The journal itself records a prior kernel boot, so its scanner
				// processes cannot still exist. Reinitialize durably before making
				// the new scope visible in the anchor.
				if journalData != nil && (journalErr != nil || journalHasLeases(journal)) {
					if err := archiveScannerIdentityJournal(directoryFD, journalData); err != nil {
						return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: prior-boot journal archive failed")
					}
				}
				journal, err := initializeScannerIdentityScope(directoryFD, markerFD, bootID, pidNamespace, privateRuntime, "reset after boot change")
				return journal, privateRuntime, err
			}
		}
		return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: boot marker is missing or invalid")
	case marker.BootID != bootID:
		if !exclusiveLiveness {
			return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: prior boot transition requires exclusive recovery")
		}
		if journalErr != nil && journalData == nil && !errors.Is(journalErr, unix.ENOENT) {
			return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: unreadable prior-boot journal cannot be replaced")
		}
		// A changed kernel boot ID proves every process from the old lease set
		// has exited. Reset only after recording the new scope under the lock.
		if journalData != nil && (journalErr != nil || journalHasLeases(journal)) {
			if err := archiveScannerIdentityJournal(directoryFD, journalData); err != nil {
				return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: prior-boot journal archive failed")
			}
		}
		journal, err := initializeScannerIdentityScope(directoryFD, markerFD, bootID, pidNamespace, privateRuntime, "reset after boot change")
		return journal, privateRuntime, err
	case journalErr != nil:
		return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: same-boot lease journal is missing or invalid")
	case marker.PIDNamespace != pidNamespace ||
		(marker.Version == scannerIdentityVersion && journal.Version == scannerIdentityVersion && journal.PIDNamespace != pidNamespace):
		if !exclusiveLiveness || !privateRuntime || !marker.PrivateRuntime || !journal.PrivateRuntime ||
			marker.Version != scannerIdentityVersion || journal.Version != scannerIdentityVersion ||
			journal.BootID != marker.BootID || journal.PrivateRuntime != marker.PrivateRuntime || journal.PIDNamespace == 0 || journal.Leases == nil {
			return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: PID namespace changed without exclusive private-scope proof")
		}
		if err := allocator.validateJournal(journal); err != nil {
			return scannerIdentityJournal{}, privateRuntime, err
		}
		if journalHasLeases(journal) && journal.PIDNamespace != marker.PIDNamespace {
			return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: PID namespace changed without matching old lease scope")
		}
		if journalHasLeases(journal) {
			if err := archiveScannerIdentityJournal(directoryFD, journalData); err != nil {
				return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: stale private journal archive failed")
			}
		}
		journal, err := initializeScannerIdentityScope(directoryFD, markerFD, bootID, pidNamespace, true, "recover stale private scope")
		return journal, true, err
	case journal.Version != scannerIdentityVersion || journal.BootID != bootID || journal.PIDNamespace != pidNamespace || journal.PrivateRuntime != privateRuntime || journal.Leases == nil:
		return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: journal scope or version is invalid")
	default:
		if err := allocator.validateJournal(journal); err != nil {
			return scannerIdentityJournal{}, privateRuntime, err
		}
		if !exclusiveLiveness {
			return journal, privateRuntime, nil
		}
		if len(journal.Leases) == 0 {
			return journal, privateRuntime, nil
		}
		if err := archiveScannerIdentityJournal(directoryFD, journalData); err != nil {
			return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: stale lease journal archive failed")
		}
		journal.Leases = make(map[uint32]scannerIdentityJournalEntry)
		if err := writeScannerIdentityJournal(directoryFD, journal); err != nil {
			return scannerIdentityJournal{}, privateRuntime, errors.New("scanner identity allocator: stale lease recovery failed")
		}
		return journal, privateRuntime, nil
	}
}

func hasArchivedScannerIdentityMarker(markerFD int) (bool, error) {
	markerBytes, err := readScannerIdentityFile(markerFD, scannerIdentityMarker, 256)
	if err != nil {
		return false, err
	}
	archivedBytes, err := readScannerIdentityFile(markerFD, scannerIdentityMarkerArchiveName(markerBytes), 256)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil || !bytes.Equal(archivedBytes, markerBytes) {
		return false, errors.New("scanner identity marker archive is invalid")
	}
	return true, nil
}

func (allocator *scannerIdentityAllocator) privateRuntimeForLease(lease *scannerIdentityLease, bootID string, pidNamespace uint64) (bool, error) {
	privateRuntime, err := allocator.privateRuntime()
	if err != nil || privateRuntime || lease == nil || !lease.privateRuntime || bootID != lease.bootID || pidNamespace != lease.pidNS {
		return privateRuntime, err
	}
	return allocator.privateScope(pidNamespace)
}

// transitionEmptyPrivateScope permits a same-boot PID namespace change only
// when both the durable previous scope and the current runtime have an
// isolated /tmp, the previous journal contains no lease, and any interrupted
// journal-first transition is exactly recognizable. Nonempty state always
// fails closed because a prior scanner subtree may still exist.
func (allocator *scannerIdentityAllocator) transitionEmptyPrivateScope(directoryFD, markerFD int, bootID string, pidNamespace uint64, privateRuntime bool, marker scannerIdentityScope, journal scannerIdentityJournal) (scannerIdentityJournal, error) {
	if !privateRuntime || !marker.PrivateRuntime || journal.Version != scannerIdentityVersion || journal.BootID != bootID || !journal.PrivateRuntime || journal.Leases == nil || len(journal.Leases) != 0 {
		return scannerIdentityJournal{}, errors.New("scanner identity allocator: PID namespace changed with unsafe or occupied scope")
	}
	if err := allocator.validateJournal(journal); err != nil {
		return scannerIdentityJournal{}, err
	}
	switch journal.PIDNamespace {
	case marker.PIDNamespace:
		// Begin a new isolated container scope. Persist the empty journal first;
		// if marker persistence fails, the next acquire recognizes and completes
		// only this empty, private, same-boot transition.
		journal.PIDNamespace = pidNamespace
		if err := writeScannerIdentityJournal(directoryFD, journal); err != nil {
			return scannerIdentityJournal{}, errors.New("scanner identity allocator: empty private scope transition journal failed")
		}
	case pidNamespace:
		// The journal commit completed but the matching marker commit did not.
	default:
		return scannerIdentityJournal{}, errors.New("scanner identity allocator: PID namespace transition state is inconsistent")
	}
	if err := writeScannerIdentityMarker(markerFD, bootID, pidNamespace, true); err != nil {
		return scannerIdentityJournal{}, errors.New("scanner identity allocator: empty private scope transition marker failed")
	}
	return journal, nil
}

func initializeScannerIdentityScope(directoryFD, markerFD int, bootID string, pidNamespace uint64, privateRuntime bool, operation string) (scannerIdentityJournal, error) {
	journal := scannerIdentityJournal{Version: scannerIdentityVersion, BootID: bootID, PIDNamespace: pidNamespace, PrivateRuntime: privateRuntime, Leases: make(map[uint32]scannerIdentityJournalEntry)}
	if err := writeScannerIdentityJournal(directoryFD, journal); err != nil {
		return scannerIdentityJournal{}, fmt.Errorf("%s scanner identity allocator: durable journal write failed", operation)
	}
	if err := writeScannerIdentityMarker(markerFD, bootID, pidNamespace, privateRuntime); err != nil {
		return scannerIdentityJournal{}, fmt.Errorf("%s scanner identity allocator: durable marker write failed", operation)
	}
	return journal, nil
}

func (allocator *scannerIdentityAllocator) validateJournal(journal scannerIdentityJournal) error {
	for uid, entry := range journal.Leases {
		token, tokenErr := hex.DecodeString(entry.Token)
		if uid < allocator.uidStart || uid-allocator.uidStart >= allocator.count || entry.GID != uid || tokenErr != nil || len(token) != 16 || (entry.State != "active" && entry.State != "quarantined") {
			return errors.New("scanner identity allocator: journal contains an invalid lease")
		}
	}
	return nil
}

type scannerIdentityScope struct {
	Version        int    `json:"version"`
	BootID         string `json:"boot_id"`
	PIDNamespace   uint64 `json:"pid_namespace_inode"`
	PrivateRuntime bool   `json:"private_runtime"`
}

func readScannerIdentityMarker(directoryFD int) (scannerIdentityScope, error) {
	data, err := readScannerIdentityFile(directoryFD, scannerIdentityMarker, 256)
	if err != nil {
		return scannerIdentityScope{}, err
	}
	var scope scannerIdentityScope
	if err := decodeScannerIdentityJSON(data, &scope); err != nil || (scope.Version != scannerIdentityVersion && scope.Version != scannerIdentityLegacyVersion) || !validBootID(scope.BootID) || scope.PIDNamespace == 0 {
		return scannerIdentityScope{}, errors.New("invalid scanner identity boot marker")
	}
	return scope, nil
}

func readScannerIdentityJournal(directoryFD int) (scannerIdentityJournal, error) {
	journal, _, err := readScannerIdentityJournalWithData(directoryFD)
	return journal, err
}

func readScannerIdentityJournalWithData(directoryFD int) (scannerIdentityJournal, []byte, error) {
	data, err := readScannerIdentityFile(directoryFD, scannerIdentityJournalName, scannerIdentityMaxBytes)
	if err != nil {
		return scannerIdentityJournal{}, nil, err
	}
	var journal scannerIdentityJournal
	if err := decodeScannerIdentityJSON(data, &journal); err != nil {
		return scannerIdentityJournal{}, data, errors.New("invalid scanner identity journal")
	}
	return journal, data, nil
}

func journalHasLeases(journal scannerIdentityJournal) bool {
	return len(journal.Leases) != 0
}

// archiveScannerIdentityJournal preserves the exact prior journal before a
// proven-dead scope is reset. Its hash-based name makes the operation
// idempotent across a crash and retry; an existing archive is trusted only
// after its private metadata and bytes match the source exactly.
func archiveScannerIdentityJournal(directoryFD int, data []byte) error {
	if directoryFD < 0 || len(data) > scannerIdentityMaxBytes {
		return errors.New("invalid scanner identity journal archive input")
	}
	return installScannerIdentityArchive(directoryFD, scannerIdentityJournalArchiveName(data), data, scannerIdentityMaxBytes)
}

// archiveScannerIdentityMarker preserves the exact prior marker before an
// offline legacy migration. The content-addressed name makes retry after a
// crash idempotent; an existing archive is reused only if its bytes match.
func archiveScannerIdentityMarker(markerFD int, data []byte) error {
	const maximum = 256
	if markerFD < 0 || len(data) > maximum {
		return errors.New("invalid scanner identity marker archive input")
	}
	return installScannerIdentityArchive(markerFD, scannerIdentityMarkerArchiveName(data), data, maximum)
}

// installScannerIdentityArchive writes and syncs a uniquely named temporary
// file before atomically installing the deterministic content-addressed name.
// A crash before rename can leave only an unrelated temporary file; a crash
// after rename leaves a complete archive that a retry verifies byte-for-byte.
// Existing conflicting evidence is never replaced.
func installScannerIdentityArchive(directoryFD int, name string, data []byte, maximum int64) error {
	if directoryFD < 0 || name == "" || maximum < 0 || int64(len(data)) > maximum {
		return errors.New("invalid scanner identity archive input")
	}
	if err := verifyScannerIdentityArchive(directoryFD, name, data, maximum); err == nil {
		return nil
	} else if !errors.Is(err, unix.ENOENT) {
		return errors.New("scanner identity archive conflicts with existing evidence")
	}

	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return errors.New("scanner identity archive temporary name is unavailable")
	}
	temporaryName := name + ".tmp-" + hex.EncodeToString(random[:])
	fd, err := unix.Openat(directoryFD, temporaryName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("scanner identity archive temporary file cannot be created")
	}
	file := os.NewFile(uintptr(fd), temporaryName)
	temporaryExists := true
	defer func() {
		if temporaryExists {
			_ = file.Close()
			_ = unix.Unlinkat(directoryFD, temporaryName, 0)
		}
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o600 || stat.Size != 0 {
		return errors.New("scanner identity archive temporary metadata is invalid")
	}
	for remaining := data; len(remaining) > 0; {
		written, writeErr := file.Write(remaining)
		if writeErr != nil || written == 0 {
			return errors.New("scanner identity archive temporary write failed")
		}
		remaining = remaining[written:]
	}
	if err := file.Sync(); err != nil {
		return errors.New("scanner identity archive temporary file is not durable")
	}
	if err := file.Close(); err != nil {
		return errors.New("scanner identity archive temporary file cannot be closed")
	}
	if err := unix.Renameat2(directoryFD, temporaryName, directoryFD, name, unix.RENAME_NOREPLACE); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return errors.New("scanner identity archive cannot be installed atomically")
		}
		if verifyErr := verifyScannerIdentityArchive(directoryFD, name, data, maximum); verifyErr != nil {
			return errors.New("scanner identity archive conflicts with existing evidence")
		}
		if err := unix.Unlinkat(directoryFD, temporaryName, 0); err != nil {
			return errors.New("scanner identity archive temporary file cannot be removed")
		}
		temporaryExists = false
		return unix.Fsync(directoryFD)
	}
	temporaryExists = false
	return unix.Fsync(directoryFD)
}

func verifyScannerIdentityArchive(directoryFD int, name string, want []byte, maximum int64) error {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o600 || stat.Size < 0 || stat.Size > maximum {
		return errors.New("invalid scanner identity archive metadata")
	}
	got, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(got)) > maximum || !bytes.Equal(got, want) {
		return errors.New("scanner identity archive content does not match")
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return unix.Fsync(directoryFD)
}

func decodeScannerIdentityJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("scanner identity JSON has trailing data")
	}
	return nil
}

func readScannerIdentityFile(directoryFD int, name string, maximum int64) ([]byte, error) {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o600 || stat.Size < 0 || stat.Size > maximum {
		return nil, errors.New("invalid scanner identity file metadata")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, errors.New("scanner identity file read failed")
	}
	return data, nil
}

func writeScannerIdentityMarker(markerFD int, bootID string, pidNamespace uint64, privateRuntime bool) error {
	data, err := json.Marshal(scannerIdentityScope{Version: scannerIdentityVersion, BootID: bootID, PIDNamespace: pidNamespace, PrivateRuntime: privateRuntime})
	if err != nil {
		return err
	}
	return writeScannerIdentityFile(markerFD, scannerIdentityMarker, data)
}

func writeScannerIdentityJournal(directoryFD int, journal scannerIdentityJournal) error {
	data, err := json.Marshal(journal)
	if err != nil || len(data) > scannerIdentityMaxBytes {
		return errors.New("scanner identity journal is too large")
	}
	return writeScannerIdentityFile(directoryFD, scannerIdentityJournalName, data)
}

func writeScannerIdentityFile(directoryFD int, name string, data []byte) error {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temporaryName := name + ".tmp-" + hex.EncodeToString(random[:])
	fd, err := unix.Openat(directoryFD, temporaryName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporaryName)
	defer func() {
		_ = file.Close()
		_ = unix.Unlinkat(directoryFD, temporaryName, 0)
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o600 {
		return errors.New("scanner identity temporary file metadata is invalid")
	}
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil || written == 0 {
			return errors.New("scanner identity temporary file write failed")
		}
		data = data[written:]
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(directoryFD, temporaryName, directoryFD, name); err != nil {
		return err
	}
	return unix.Fsync(directoryFD)
}

func openScannerIdentityDirectories(path, markerDir string) (int, int, error) {
	if filepath.Clean(filepath.Dir(path)) != filepath.Clean(markerDir) || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return -1, -1, errors.New("scanner identity allocator paths must be sibling directories")
	}
	if path == scannerIdentityDirectory && markerDir == scannerIdentityMarkerDir {
		if err := ensureScannerIdentityDirectory(); err != nil {
			return -1, -1, err
		}
	}
	markerFD, err := unix.Open(markerDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, -1, errors.New("scanner identity allocator trusted parent is unavailable")
	}
	if err := validateScannerIdentityParent(markerFD); err != nil {
		_ = unix.Close(markerFD)
		return -1, -1, err
	}
	name := filepath.Base(path)
	created := false
	if err := unix.Mkdirat(markerFD, name, 0o700); err == nil {
		created = true
	} else if !errors.Is(err, unix.EEXIST) {
		_ = unix.Close(markerFD)
		return -1, -1, errors.New("scanner identity allocator private directory cannot be created")
	}
	directoryFD, err := unix.Openat(markerFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		_ = unix.Close(markerFD)
		return -1, -1, errors.New("scanner identity allocator private directory is unavailable")
	}
	if created {
		if err := unix.Fchmod(directoryFD, 0o700); err != nil {
			_ = unix.Close(directoryFD)
			_ = unix.Close(markerFD)
			return -1, -1, errors.New("scanner identity allocator private directory mode cannot be set")
		}
		if err := unix.Fsync(markerFD); err != nil {
			_ = unix.Close(directoryFD)
			_ = unix.Close(markerFD)
			return -1, -1, errors.New("scanner identity allocator directory creation is not durable")
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(directoryFD, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o700 {
		_ = unix.Close(directoryFD)
		_ = unix.Close(markerFD)
		return -1, -1, errors.New("scanner identity allocator directory is not private to the daemon")
	}
	return directoryFD, markerFD, nil
}

func validateScannerIdentityParent(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o0022 != 0 || stat.Mode&0o300 != 0o300 {
		return errors.New("scanner identity allocator parent must be daemon-owned and not group/other writable")
	}
	return nil
}

func ensureScannerIdentityDirectory() error {
	return ensureScannerIdentityDirectoryAt(scannerIdentityMarkerDir)
}

// ensureScannerIdentityDirectoryAt validates the durable state anchor before
// the allocator creates or opens its private child directory. Production
// supplies the fixed /var/lib/edgewatch path; the path parameter keeps the
// ownership and mode contract testable with isolated directories.
func ensureScannerIdentityDirectoryAt(path string) error {
	// The allocator is durable state, not RuntimeDirectory state: a service
	// restart must not erase leases for a same-boot orphaned process tree.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("scanner identity allocator durable state directory is unavailable")
	}
	defer unix.Close(fd)
	if err := validateScannerIdentityParent(fd); err != nil {
		return err
	}
	return nil
}

func openScannerIdentityLock(directoryFD int) (int, error) {
	fd, err := unix.Openat(directoryFD, scannerIdentityLock, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(directoryFD, scannerIdentityLock, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return -1, err
	}
	if created {
		if err := unix.Fchmod(fd, 0o600); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		if err := unix.Fsync(directoryFD); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o600 || stat.Size != 0 {
		_ = unix.Close(fd)
		return -1, errors.New("scanner identity allocator lock metadata is invalid")
	}
	return fd, nil
}

func lockScannerIdentity(ctx context.Context, fd int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return errors.New("scanner identity allocator lock failed")
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func validateScannerIdentityRangeMapping(uidStart, count uint32) error {
	return validateScannerIdentityRangeMappingFromPaths(uidStart, count, "/proc/self/uid_map", "/proc/self/gid_map")
}

// validateScannerIdentityRangeMappingFromPaths checks every candidate UID and
// GID against the mappings visible to this process. Keeping the paths explicit
// makes the production preflight contract testable with isolated map fixtures.
func validateScannerIdentityRangeMappingFromPaths(uidStart, count uint32, uidPath, gidPath string) error {
	uidRanges, err := readIDMap(uidPath)
	if err != nil {
		return errors.New("scanner identity allocator: UID mapping is unavailable")
	}
	gidRanges, err := readIDMap(gidPath)
	if err != nil {
		return errors.New("scanner identity allocator: GID mapping is unavailable")
	}
	for offset := uint32(0); offset < count; offset++ {
		id := uidStart + offset
		if !idMapped(uidRanges, id) || !idMapped(gidRanges, id) {
			return scannerIdentityUnmappedError{id: id}
		}
	}
	return nil
}

type scannerIdentityUnmappedError struct{ id uint32 }

func (err scannerIdentityUnmappedError) Error() string {
	return fmt.Sprintf("scanner identity allocator: required UID/GID %d is not mapped", err.id)
}

type idMapRange struct{ inside, outside, length uint64 }

func readIDMap(path string) ([]idMapRange, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result []idMapRange
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 {
			return nil, errors.New("invalid Linux ID map")
		}
		inside, e1 := strconv.ParseUint(fields[0], 10, 32)
		outside, e2 := strconv.ParseUint(fields[1], 10, 32)
		length, e3 := strconv.ParseUint(fields[2], 10, 32)
		if e1 != nil || e2 != nil || e3 != nil || length == 0 || inside+length > 1<<32 || outside+length > 1<<32 {
			return nil, errors.New("invalid Linux ID map range")
		}
		result = append(result, idMapRange{inside: inside, outside: outside, length: length})
	}
	if len(result) == 0 {
		return nil, errors.New("empty Linux ID map")
	}
	return result, nil
}

func idMapped(ranges []idMapRange, id uint32) bool {
	value := uint64(id)
	for _, mapping := range ranges {
		if value >= mapping.inside && value < mapping.inside+mapping.length {
			return true
		}
	}
	return false
}

func scannerIdentitiesInUse(uidStart, count uint32) (map[uint32]struct{}, error) {
	return scannerIdentitiesInUseAt("/proc", "/etc/passwd", "/etc/group", uidStart, count)
}

// scannerIdentitiesInUseAt reads one process/account snapshot. Production
// always supplies the fixed procfs and local account paths above; keeping the
// reader explicit also lets tests exercise the live-process fail-closed rule
// against a controlled proc-like tree.
func scannerIdentitiesInUseAt(procRoot, passwdPath, groupPath string, uidStart, count uint32) (map[uint32]struct{}, error) {
	// Do not take an identity already present in the current namespace. The
	// install documentation must reserve the fixed pool against services that
	// may be launched later by the host's account manager.
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	used := make(map[uint32]struct{})
	if err := addScannerLocalAccountsInUse(passwdPath, groupPath, uidStart, count, used); err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil {
			continue
		}
		processPath := filepath.Join(procRoot, entry.Name())
		data, err := os.ReadFile(filepath.Join(processPath, "status"))
		if err != nil {
			if _, statErr := os.Stat(processPath); statErr == nil {
				return nil, errors.New("a live process status is unreadable")
			}
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "Uid:") && !strings.HasPrefix(line, "Gid:") {
				continue
			}
			for _, field := range strings.Fields(strings.TrimPrefix(strings.TrimPrefix(line, "Uid:"), "Gid:")) {
				id, err := strconv.ParseUint(field, 10, 32)
				if err == nil && id >= uint64(uidStart) && id < uint64(uidStart)+uint64(count) {
					used[uint32(id)] = struct{}{}
				}
			}
		}
	}
	return used, nil
}

func addScannerAccountsInUse(path string, idField, uidStart, count uint32, used map[uint32]struct{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if uint32(len(fields)) < idField {
			return errors.New("invalid local account database")
		}
		id, err := strconv.ParseUint(fields[idField-1], 10, 32)
		if err != nil {
			return errors.New("invalid local account ID")
		}
		if id >= uint64(uidStart) && id < uint64(uidStart)+uint64(count) {
			used[uint32(id)] = struct{}{}
		}
	}
	return nil
}

func addScannerLocalAccountsInUse(passwdPath, groupPath string, uidStart, count uint32, used map[uint32]struct{}) error {
	// Both passwd and group records put their numeric UID/GID in field three.
	if err := addScannerAccountsInUse(passwdPath, 3, uidStart, count, used); err != nil {
		return err
	}
	return addScannerAccountsInUse(groupPath, 3, uidStart, count, used)
}

func currentBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(data)), err
}

func currentPIDNamespaceInode() (uint64, error) {
	var stat unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &stat); err != nil {
		return 0, err
	}
	return stat.Ino, nil
}

// currentPrivateScannerRuntime recognizes the deployment boundary used to
// permit an empty allocator journal to move between container PID namespaces:
// this process is PID 1 and /tmp is one private tmpfs mount. The compose
// deployment leaves Docker's default private PID namespace enabled and mounts
// a per-container /tmp tmpfs; native installations do not satisfy this test.
// It is deliberately only used for empty-journal scope transitions, never to
// reclaim a lease or treat an occupied journal as safe.
func currentPrivateScannerRuntime() (bool, error) {
	return privateScannerRuntimeFor(os.Getpid(), currentPIDNamespaceInode, currentPrivateScannerNamespace)
}

// privateScannerRuntimeFor implements the PID 1 bootstrap rule. Production
// passes the actual PID and fixed procfs probes above; non-PID1 callers cannot
// establish a new persistent container scope, even if their own /tmp appears
// private. Existing scopes are reused only through the locked journal path.
func privateScannerRuntimeFor(processID int, namespaceInode func() (uint64, error), privateScope func(uint64) (bool, error)) (bool, error) {
	if processID != 1 {
		return false, nil
	}
	if namespaceInode == nil || privateScope == nil {
		return false, errors.New("private scanner runtime probes are unavailable")
	}
	namespace, err := namespaceInode()
	if err != nil {
		return false, err
	}
	if namespace == 0 {
		return false, errors.New("private scanner runtime namespace is unavailable")
	}
	return privateScope(namespace)
}

// currentPrivateScannerNamespace verifies that this process's own PID
// namespace and temporary mount still match the private runtime established
// by PID 1. It does not inspect /proc/1: the daemon is deliberately
// non-dumpable, so a separate health process may be denied access to that
// proc entry even in the same PID namespace. This does not establish a new
// private scope; callers may use it only with a validated same-scope marker
// and journal, or a lease created within that scope.
func currentPrivateScannerNamespace(namespace uint64) (bool, error) {
	currentNamespace, err := currentPIDNamespaceInode()
	if err != nil {
		return false, err
	}
	mountInfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false, err
	}
	return matchesPrivateScannerScope(namespace, currentNamespace, mountInfo), nil
}

func matchesPrivateScannerScope(expectedNamespace, currentNamespace uint64, mountInfo []byte) bool {
	return expectedNamespace != 0 && currentNamespace == expectedNamespace && hasPrivateScannerTemporaryMount(mountInfo)
}

func hasPrivateScannerTemporaryMount(mountInfo []byte) bool {
	found := false
	for _, line := range strings.Split(string(mountInfo), "\n") {
		fields := strings.Fields(line)
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 6 || len(fields) <= separator+1 || fields[3] != "/" || fields[4] != "/tmp" {
			continue
		}
		if found || fields[separator+1] != "tmpfs" {
			return false
		}
		found = true
		for _, optional := range fields[6:separator] {
			if strings.HasPrefix(optional, "shared:") || strings.HasPrefix(optional, "master:") || strings.HasPrefix(optional, "propagate_from:") {
				return false
			}
		}
	}
	return found
}

func validBootID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
