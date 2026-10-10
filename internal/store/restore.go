package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ErrRestoreSidecars is returned when a restore would leave SQLite sidecars
// from a different database next to the replacement file. SQLite does not
// expose a portable database identity in its WAL/SHM files, so an existing
// sidecar is treated as ambiguous rather than guessed to be safe.
var ErrRestoreSidecars = errors.New("restore refused because SQLite sidecars are present")

// ErrRestoreDaemonLive is returned when the destination database still has a
// recently-heartbeating EdgeWatch daemon owner. Replacing the file in that
// state would leave the running process attached to the old inode while new
// commands open the replacement, splitting the installation's state.
var ErrRestoreDaemonLive = errors.New("restore refused because an EdgeWatch daemon is active")

// ErrRestoreDestinationUnreadable means the existing destination cannot be
// inspected for an active daemon lease. Operators may use the explicit
// unreadable-destination recovery option after stopping EdgeWatch; source
// validation and staged verification still run before replacement.
var ErrRestoreDestinationUnreadable = errors.New("restore destination is unreadable")

// ErrRestoreKeyMismatch is returned when the configured keys cannot open
// encrypted secrets in the backup: web-managed notification destinations or
// TOTP seeds. Restoring it would lock those destinations, so that their alerts
// are dropped after the delivery deferrals run out, and lock the accounts out
// of TOTP until the host disables it.
var ErrRestoreKeyMismatch = errors.New("restore refused because the configured keys cannot open the backup's secrets")

// RestoreKeyCheck counts the encrypted secrets of a staged backup copy and
// those that the configured keys cannot open. It carries counts only, never
// a secret, a URL, or an account.
type RestoreKeyCheck struct {
	// Destinations is the number of web-managed notification destinations of
	// every business unit and of the platform, paused or not, and
	// DestinationsLocked the number of them the notification key cannot open.
	Destinations       int `json:"destinations"`
	DestinationsLocked int `json:"destinations_locked"`
	// TOTPSecrets is the number of accounts with a stored TOTP seed, and
	// TOTPUnreadable the number of those seeds the authentication key cannot
	// open.
	TOTPSecrets    int `json:"totp_secrets"`
	TOTPUnreadable int `json:"totp_unreadable"`
}

// Mismatch reports whether a key cannot open a secret of the copy.
func (check RestoreKeyCheck) Mismatch() bool {
	return check.DestinationsLocked > 0 || check.TOTPUnreadable > 0
}

// RestoreKeyMismatchError reports the counts of a refused key check. It
// wraps ErrRestoreKeyMismatch.
type RestoreKeyMismatchError struct {
	Check RestoreKeyCheck
}

func (e *RestoreKeyMismatchError) Error() string {
	if e == nil {
		return ErrRestoreKeyMismatch.Error()
	}
	var parts []string
	if e.Check.DestinationsLocked > 0 {
		parts = append(parts, fmt.Sprintf("the notification key cannot open %d of %d web-managed destinations", e.Check.DestinationsLocked, e.Check.Destinations))
	}
	if e.Check.TOTPUnreadable > 0 {
		parts = append(parts, fmt.Sprintf("the authentication key cannot open %d of %d TOTP seeds", e.Check.TOTPUnreadable, e.Check.TOTPSecrets))
	}
	if len(parts) == 0 {
		return ErrRestoreKeyMismatch.Error()
	}
	return ErrRestoreKeyMismatch.Error() + ": " + strings.Join(parts, "; ")
}

func (e *RestoreKeyMismatchError) Unwrap() error { return ErrRestoreKeyMismatch }

// StagedInspection opens the staged database copy at path, read-only, and
// counts its secrets that the configured keys cannot open. The store does
// not decrypt the secrets itself; the caller supplies the keys.
type StagedInspection func(ctx context.Context, path string) (RestoreKeyCheck, error)

// checkStagedKeys runs inspect on the staged copy at path. A copy whose
// secrets a key cannot open is refused with a RestoreKeyMismatchError unless
// allowMismatch is set; the counts are returned either way.
func checkStagedKeys(ctx context.Context, path string, inspect StagedInspection, allowMismatch bool) (*RestoreKeyCheck, error) {
	if inspect == nil {
		return nil, nil
	}
	check, err := inspect(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("check the configured keys against the backup: %w", err)
	}
	if check.Mismatch() && !allowMismatch {
		return &check, &RestoreKeyMismatchError{Check: check}
	}
	return &check, nil
}

// PendingDeliveryPolicy controls what happens to unsent notification rows
// copied from a backup. A restore is an epoch boundary: replaying an older
// outbox by accident can send stale incident or lifecycle alerts. The zero
// value is deliberately normalized to quarantine.
type PendingDeliveryPolicy string

const (
	PendingDeliveriesQuarantine PendingDeliveryPolicy = "quarantine"
	PendingDeliveriesDiscard    PendingDeliveryPolicy = "discard"
	PendingDeliveriesPreserve   PendingDeliveryPolicy = "preserve"
)

// ParsePendingDeliveryPolicy validates the operator-facing restore policy.
func ParsePendingDeliveryPolicy(value string) (PendingDeliveryPolicy, error) {
	policy := PendingDeliveryPolicy(strings.ToLower(strings.TrimSpace(value)))
	if policy == "" {
		return PendingDeliveriesQuarantine, nil
	}
	switch policy {
	case PendingDeliveriesQuarantine, PendingDeliveriesDiscard, PendingDeliveriesPreserve:
		return policy, nil
	default:
		return "", fmt.Errorf("invalid pending-deliveries policy %q (want quarantine, discard, or preserve)", value)
	}
}

// RestoreSidecar describes one SQLite companion file found during a restore
// preflight. NewerThanDatabase is a useful diagnostic, but does not make an
// artifact safe: a sidecar can be foreign even when its timestamp is older.
type RestoreSidecar struct {
	Kind              string    `json:"kind"`
	Path              string    `json:"path"`
	Bytes             int64     `json:"bytes"`
	ModifiedAt        time.Time `json:"modified_at"`
	NewerThanDatabase bool      `json:"newer_than_database"`
}

// RestorePreflight is a read-only description of the files that would be
// involved in a database restore. It intentionally does not open SQLite, so
// inspecting a candidate cannot replay a WAL or change the database bytes.
type RestorePreflight struct {
	SourcePath          string           `json:"source_path"`
	DestinationPath     string           `json:"destination_path"`
	SourceExists        bool             `json:"source_exists"`
	DestinationExists   bool             `json:"destination_exists"`
	SourceSidecars      []RestoreSidecar `json:"source_sidecars"`
	DestinationSidecars []RestoreSidecar `json:"destination_sidecars"`
	Safe                bool             `json:"safe"`
}

// RestoreOptions controls the one intentionally dangerous recovery path.
// AllowSidecarReplay must only be used when the operator has verified that
// the database and companion files are an intentional SQLite recovery set.
// Normal single-file restores refuse sidecars instead.
type RestoreOptions struct {
	AllowSidecarReplay bool
	// AllowActiveDaemon is an emergency escape hatch for an operator who has
	// independently stopped or isolated the daemon but its heartbeat row has
	// not yet gone stale. It is never inferred from sidecar state.
	AllowActiveDaemon bool
	// AllowUnreadableDestination is an explicit stopped-daemon recovery escape
	// hatch for a damaged destination that cannot be opened to inspect its
	// lease. It never skips source or staged-database validation.
	AllowUnreadableDestination bool
	// PendingDeliveries applies an explicit restore epoch policy to unsent
	// notification rows. Empty uses the safe quarantine default.
	PendingDeliveries PendingDeliveryPolicy
	// InspectStaged, when set, runs on the sanitized staged copy before the
	// destination is replaced, and counts the secrets that the configured
	// keys cannot open. A copy with such a secret is refused unless
	// AllowKeyMismatch is set.
	InspectStaged StagedInspection
	// AllowKeyMismatch restores a copy whose secrets InspectStaged found
	// that the keys cannot open. It is never inferred.
	AllowKeyMismatch bool
}

// RestoreResult describes a successfully replaced database file.
type RestoreResult struct {
	Path                      string                `json:"path"`
	Bytes                     int64                 `json:"bytes"`
	RestoredAt                time.Time             `json:"restored_at"`
	RestoreEpoch              string                `json:"restore_epoch"`
	PendingDeliveriesPolicy   PendingDeliveryPolicy `json:"pending_deliveries_policy"`
	PendingDeliveriesAffected int                   `json:"pending_deliveries_affected"`
	SidecarsPresent           []string              `json:"sidecars_present,omitempty"`
	SidecarsRemoved           []string              `json:"sidecars_removed,omitempty"`
	SidecarsWarning           string                `json:"sidecars_warning,omitempty"`
	// KeyCheck is the result of RestoreOptions.InspectStaged, when it ran.
	KeyCheck *RestoreKeyCheck `json:"key_check,omitempty"`
}

// RestoreSidecarError includes the exact paths that made a restore
// ambiguous, while still allowing callers to use errors.Is with
// ErrRestoreSidecars.
type RestoreSidecarError struct {
	Paths []string
}

func (e *RestoreSidecarError) Error() string {
	if e == nil || len(e.Paths) == 0 {
		return ErrRestoreSidecars.Error()
	}
	return fmt.Sprintf("%s: %s", ErrRestoreSidecars, strings.Join(e.Paths, ", "))
}

func (e *RestoreSidecarError) Unwrap() error { return ErrRestoreSidecars }

// PreflightRestore inspects source, destination, and all SQLite sidecars
// without opening either database. Existing sidecars are reported rather than
// removed; this keeps the inspection safe even when the daemon was not
// stopped. It is only the first restore check: use DryRunRestore to predict
// whether Restore would proceed.
func PreflightRestore(ctx context.Context, source, destination string) (RestorePreflight, error) {
	result := RestorePreflight{SourceSidecars: []RestoreSidecar{}, DestinationSidecars: []RestoreSidecar{}}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	sourcePath, err := restorePath(source)
	if err != nil {
		return result, fmt.Errorf("restore source: %w", err)
	}
	destinationPath, err := restorePath(destination)
	if err != nil {
		return result, fmt.Errorf("restore destination: %w", err)
	}
	if sourcePath == destinationPath {
		return result, errors.New("restore source and destination must be different")
	}
	result.SourcePath, result.DestinationPath = sourcePath, destinationPath

	sourceInfo, err := regularFileInfo(sourcePath, true)
	if err != nil {
		return result, fmt.Errorf("restore source: %w", err)
	}
	if err := validateSQLiteRestoreSource(sourcePath); err != nil {
		return result, err
	}
	result.SourceExists = sourceInfo != nil
	destinationInfo, err := regularFileInfo(destinationPath, false)
	if err != nil {
		return result, fmt.Errorf("restore destination: %w", err)
	}
	result.DestinationExists = destinationInfo != nil

	result.SourceSidecars, err = inspectRestoreSidecars(sourcePath, sourceInfo)
	if err != nil {
		return result, fmt.Errorf("restore source sidecars: %w", err)
	}
	result.DestinationSidecars, err = inspectRestoreSidecars(destinationPath, destinationInfo)
	if err != nil {
		return result, fmt.Errorf("restore destination sidecars: %w", err)
	}
	result.Safe = len(result.SourceSidecars) == 0 && len(result.DestinationSidecars) == 0
	return result, nil
}

// RestoreDryRun reports what Restore would do with the same source,
// destination, and options. It runs every refusal check and the staged-copy
// validation and delivery policy on a private copy that is then discarded, so
// it stops only before the destination is replaced.
type RestoreDryRun struct {
	RestorePreflight
	// Safe reports whether Restore would replace the destination. It shadows
	// the file-level RestorePreflight.Safe, which covers sidecars only.
	Safe                      bool                  `json:"safe"`
	Refusal                   string                `json:"refusal,omitempty"`
	SourceSchemaVersion       int                   `json:"source_schema_version,omitempty"`
	PendingDeliveriesPolicy   PendingDeliveryPolicy `json:"pending_deliveries_policy,omitempty"`
	PendingDeliveriesAffected int                   `json:"pending_deliveries_affected"`
	// KeyCheck is the result of RestoreOptions.InspectStaged, when it ran.
	KeyCheck *RestoreKeyCheck `json:"key_check,omitempty"`
}

// DryRunRestore predicts Restore without replacing the destination. The
// returned error is the refusal Restore would return; the report is filled in
// as far as the checks progressed either way. Like Restore, it needs a
// writable destination directory for the private staging copy.
func DryRunRestore(ctx context.Context, source, destination string, options RestoreOptions) (RestoreDryRun, error) {
	staged, err := stageRestore(ctx, source, destination, options)
	staged.discard()
	result := RestoreDryRun{
		RestorePreflight:          staged.preflight,
		Safe:                      err == nil,
		SourceSchemaVersion:       staged.schemaVersion,
		PendingDeliveriesPolicy:   staged.policy,
		PendingDeliveriesAffected: staged.pending,
		KeyCheck:                  staged.keyCheck,
	}
	if err != nil {
		result.Refusal = err.Error()
	}
	return result, err
}

// stagedRestore is a sanitized private copy of the restore source that has
// passed every refusal check. Only Restore goes on to rename it over the
// destination.
type stagedRestore struct {
	preflight     RestorePreflight
	policy        PendingDeliveryPolicy
	dir           string
	path          string
	unlock        func()
	bytes         int64
	schemaVersion int
	epoch         string
	restoredAt    time.Time
	pending       int
	keyCheck      *RestoreKeyCheck
}

// discard removes the private staging directory and everything left in it.
func (s stagedRestore) discard() {
	if s.dir != "" {
		_ = os.RemoveAll(s.dir)
	}
	if s.unlock != nil {
		s.unlock()
	}
}

// Restore replaces destination with a private, atomically copied source
// database. The caller must stop EdgeWatch first. By default any WAL, SHM, or
// rollback-journal companion on either path causes a refusal; allowing replay
// is an explicit recovery-only escape hatch and is never inferred from file
// timestamps. Unsent notification deliveries are quarantined by default at a
// new restore epoch; callers must explicitly select discard or preserve.
func Restore(ctx context.Context, source, destination string, options RestoreOptions) (RestoreResult, error) {
	var result RestoreResult
	staged, err := stageRestore(ctx, source, destination, options)
	defer staged.discard()
	if err != nil {
		return result, err
	}
	preflight := staged.preflight
	// Move destination sidecars out of the way only after every staged check and
	// sanitization has succeeded. If the replacement itself fails, restore the
	// sidecars in reverse order so a rejected restore leaves the destination
	// artifact set unchanged.
	movedSidecars, err := moveDestinationSidecars(preflight.DestinationSidecars, staged.dir)
	if err != nil {
		return result, err
	}
	restoreMovedSidecars := true
	defer restoreSidecarsOnFailure(&restoreMovedSidecars, movedSidecars)
	if err := os.Rename(staged.path, preflight.DestinationPath); err != nil {
		return result, fmt.Errorf("replace restored database: %w", err)
	}
	restoreMovedSidecars = false
	if err := os.Chmod(preflight.DestinationPath, 0o600); err != nil {
		return result, err
	}
	if err := syncDirectory(filepath.Dir(preflight.DestinationPath)); err != nil {
		return result, fmt.Errorf("sync restored database directory: %w", err)
	}
	result = RestoreResult{
		Path:                      preflight.DestinationPath,
		Bytes:                     staged.bytes,
		RestoredAt:                staged.restoredAt,
		RestoreEpoch:              staged.epoch,
		PendingDeliveriesPolicy:   staged.policy,
		PendingDeliveriesAffected: staged.pending,
		KeyCheck:                  staged.keyCheck,
	}
	if !preflight.Safe {
		for _, sidecar := range preflight.SourceSidecars {
			result.SidecarsPresent = append(result.SidecarsPresent, sidecar.Path)
		}
		for _, sidecar := range preflight.DestinationSidecars {
			result.SidecarsRemoved = append(result.SidecarsRemoved, sidecar.Path)
		}
		sort.Strings(result.SidecarsPresent)
		sort.Strings(result.SidecarsRemoved)
		result.SidecarsWarning = "SQLite source sidecars were replayed; old destination sidecars were removed"
	}
	return result, nil
}

// stageRestore runs every restore refusal check and prepares the sanitized
// staged copy that Restore renames over the destination. Restore and
// DryRunRestore share it, so a refusal added here applies to both. The staged
// value carries the preflight report even on error, and its staging directory
// must always be discarded by the caller.
func stageRestore(ctx context.Context, source, destination string, options RestoreOptions) (stagedRestore, error) {
	var staged stagedRestore
	policy, err := ParsePendingDeliveryPolicy(string(options.PendingDeliveries))
	if err != nil {
		return staged, err
	}
	staged.policy = policy
	staged.preflight, err = PreflightRestore(ctx, source, destination)
	if err != nil {
		return staged, err
	}
	// Serialize restore operations for this database directory. Besides
	// preventing two restores from replacing the destination concurrently,
	// this makes it safe to remove staging directories left by a process that
	// was killed before its deferred cleanup could run.
	parent := filepath.Dir(staged.preflight.DestinationPath)
	unlock, lockSupported, err := acquireRestoreStagingGuard(ctx, parent)
	if err != nil {
		return staged, fmt.Errorf("acquire restore staging guard: %w", err)
	}
	staged.unlock = unlock
	if lockSupported {
		if err := cleanupStaleRestoreStagingDirs(parent); err != nil {
			return staged, err
		}
	}
	// Preflight was intentionally repeated after the lock: another restore
	// may have changed the destination while this invocation waited for it.
	staged.preflight, err = PreflightRestore(ctx, source, destination)
	if err != nil {
		return staged, err
	}
	preflight := staged.preflight
	// Surface an invalid source schema before reporting an unrelated sidecar
	// refusal. This is intentionally limited to sources that already have
	// SQLite companions: opening a sidecar-free source for validation could
	// itself create WAL/SHM artifacts and change the very preflight state we
	// are about to enforce.
	if len(preflight.SourceSidecars) > 0 {
		if err := validateRestoreSourceSchema(ctx, preflight.SourcePath); err != nil {
			return staged, err
		}
	}
	if !preflight.Safe && !options.AllowSidecarReplay {
		paths := make([]string, 0, len(preflight.SourceSidecars)+len(preflight.DestinationSidecars))
		for _, sidecar := range preflight.SourceSidecars {
			paths = append(paths, sidecar.Path)
		}
		for _, sidecar := range preflight.DestinationSidecars {
			paths = append(paths, sidecar.Path)
		}
		sort.Strings(paths)
		return staged, &RestoreSidecarError{Paths: paths}
	}
	if err := checkRestoreDestinationDaemon(ctx, preflight, options); err != nil {
		return staged, err
	}
	if err := ctx.Err(); err != nil {
		return staged, err
	}

	parentInfo, err := os.Stat(parent)
	if err != nil {
		return staged, fmt.Errorf("restore destination directory: %w", err)
	}
	if !parentInfo.IsDir() {
		return staged, errors.New("restore destination parent is not a directory")
	}
	staged.dir, err = os.MkdirTemp(parent, ".edgewatch-restore-")
	if err != nil {
		return staged, fmt.Errorf("create restore staging directory: %w", err)
	}
	if err := os.Chmod(staged.dir, 0o700); err != nil {
		return staged, err
	}
	staged.path = filepath.Join(staged.dir, filepath.Base(preflight.DestinationPath))
	staged.bytes, err = copyRestoreFile(ctx, preflight.SourcePath, staged.path)
	if err != nil {
		return staged, err
	}
	// Sidecar replay is an explicit recovery operation. Copy the complete
	// SQLite artifact set into the private staging directory before opening it;
	// copying only the main file would silently lose WAL-only transactions.
	if options.AllowSidecarReplay {
		for _, sidecar := range preflight.SourceSidecars {
			// SQLite companions are tied to the database basename. Preserve the
			// suffix (-wal, -shm, or -journal) while renaming them to the staged
			// destination basename; copying the source basename would make SQLite
			// ignore an otherwise valid WAL during validation and replay.
			suffix := strings.TrimPrefix(sidecar.Path, preflight.SourcePath)
			destinationSidecar := staged.path + suffix
			if _, err := copyRestoreFile(ctx, sidecar.Path, destinationSidecar); err != nil {
				return staged, fmt.Errorf("copy restore source %s: %w", sidecar.Kind, err)
			}
		}
	}
	staged.schemaVersion, err = validateStagedRestore(ctx, staged.path)
	if err != nil {
		return staged, err
	}
	staged.epoch = uuid.NewString()
	staged.restoredAt = time.Now().UTC()
	staged.pending, err = applyRestoreDeliveryPolicy(ctx, staged.path, policy, staged.epoch, staged.restoredAt)
	if err != nil {
		return staged, err
	}
	// The key check opens the sanitized copy read-only, so what it counts is
	// exactly what would replace the destination. Any sidecar its connection
	// creates stays in the private staging directory.
	staged.keyCheck, err = checkStagedKeys(ctx, staged.path, options.InspectStaged, options.AllowKeyMismatch)
	if err != nil {
		return staged, err
	}
	// Re-check immediately before replacing the destination. This closes the
	// normal window where a daemon could start while the source is being copied;
	// the operator-facing escape hatch remains explicit for intentional recovery.
	if err := checkRestoreDestinationDaemon(ctx, preflight, options); err != nil {
		return staged, err
	}
	return staged, nil
}

// cleanupStaleRestoreStagingDirs removes only private staging directories
// created by prior restore commands. Callers must hold the destination's
// restore staging guard so a concurrent restore cannot have its work removed.
func cleanupStaleRestoreStagingDirs(parent string) error {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return fmt.Errorf("list restore staging directories: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		randomSuffix := strings.TrimPrefix(name, restoreStagingDirPrefix)
		if !entry.IsDir() || !strings.HasPrefix(name, restoreStagingDirPrefix) || len(randomSuffix) < 1 || len(randomSuffix) > 10 || !isRestoreStagingSuffix(randomSuffix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect restore staging directory %q: %w", name, err)
		}
		// os.MkdirTemp creates these private directories with 0700
		// permissions. Requiring that exact mode avoids deleting an
		// unrelated directory that happens to use the reserved prefix.
		if info.Mode().Perm() != 0o700 {
			continue
		}
		path := filepath.Join(parent, name)
		if err := recoverMovedRestoreSidecars(parent, path); err != nil {
			return fmt.Errorf("recover interrupted restore sidecars: %w", err)
		}
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove stale restore staging directory: %w", err)
		}
	}
	return nil
}

const restoreStagingDirPrefix = ".edgewatch-restore-"

func isRestoreStagingSuffix(suffix string) bool {
	for _, character := range suffix {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// recoverMovedRestoreSidecars puts destination sidecars back when a process
// died after moving them into staging but before replacing the database. The
// staged database is still present in that case. Once it has been renamed to
// the destination, the old sidecars belong to the replaced database and may
// be discarded with the rest of the staging directory.
func recoverMovedRestoreSidecars(parent, stagingDir string) error {
	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		return err
	}
	var moved []os.DirEntry
	databaseName := ""
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "previous-") {
			name := strings.TrimPrefix(entry.Name(), "previous-")
			foundSuffix := false
			for _, suffix := range []string{"-wal", "-shm", "-journal"} {
				if strings.HasSuffix(name, suffix) {
					name = strings.TrimSuffix(name, suffix)
					foundSuffix = true
					break
				}
			}
			// A database itself may start with "previous-". Only the
			// known SQLite sidecar suffixes identify a moved sidecar.
			if !foundSuffix {
				continue
			}
			if name == "" {
				return fmt.Errorf("unrecognized staged previous sidecar %q", entry.Name())
			}
			moved = append(moved, entry)
			if databaseName != "" && databaseName != name {
				return errors.New("staged previous sidecars refer to different databases")
			}
			databaseName = name
			continue
		}
	}
	if len(moved) == 0 {
		return nil
	}
	stagedDatabase := filepath.Join(stagingDir, databaseName)
	info, err := os.Lstat(stagedDatabase)
	if errors.Is(err, os.ErrNotExist) {
		// The staged database was already renamed into place; the old
		// destination sidecars can be discarded with this stale directory.
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("staged database %q is not a regular file", databaseName)
	}
	for _, entry := range moved {
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("staged previous sidecar %q is not a regular file", entry.Name())
		}
		destination := filepath.Join(parent, strings.TrimPrefix(entry.Name(), "previous-"))
		if _, err := os.Lstat(destination); err == nil {
			return fmt.Errorf("cannot restore previous sidecar because %q already exists", filepath.Base(destination))
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, entry := range moved {
		from := filepath.Join(stagingDir, entry.Name())
		to := filepath.Join(parent, strings.TrimPrefix(entry.Name(), "previous-"))
		if err := os.Rename(from, to); err != nil {
			return err
		}
	}
	return nil
}

// checkRestoreDestinationDaemon refuses a restore over a destination whose
// daemon is still active or that cannot be inspected, unless the operator
// passed the matching explicit recovery option.
func checkRestoreDestinationDaemon(ctx context.Context, preflight RestorePreflight, options RestoreOptions) error {
	if !preflight.DestinationExists || options.AllowActiveDaemon {
		return nil
	}
	err := refuseActiveDaemon(ctx, preflight.DestinationPath)
	if err != nil && errors.Is(err, ErrRestoreDestinationUnreadable) && options.AllowUnreadableDestination {
		return nil
	}
	return err
}

func validateRestoreSourceSchema(ctx context.Context, path string) error {
	reader, err := OpenReadOnlyExistingContext(ctx, path)
	if err != nil {
		return fmt.Errorf("validate restore source database: %w", err)
	}
	defer reader.Close()
	if _, err := reader.Verify(ctx); err != nil {
		return fmt.Errorf("validate restore source database: %w", err)
	}
	return nil
}

func restoreSidecarsOnFailure(pending *bool, sidecars []movedRestoreSidecar) {
	if *pending {
		_ = restoreDestinationSidecars(sidecars)
	}
}

type movedRestoreSidecar struct {
	original string
	moved    string
}

func moveDestinationSidecars(sidecars []RestoreSidecar, tempDir string) ([]movedRestoreSidecar, error) {
	moved := make([]movedRestoreSidecar, 0, len(sidecars))
	for _, sidecar := range sidecars {
		movedPath := filepath.Join(tempDir, "previous-"+filepath.Base(sidecar.Path))
		if err := os.Rename(sidecar.Path, movedPath); err != nil {
			_ = restoreDestinationSidecars(moved)
			return nil, fmt.Errorf("stage destination %s sidecar: %w", sidecar.Kind, err)
		}
		moved = append(moved, movedRestoreSidecar{original: sidecar.Path, moved: movedPath})
	}
	return moved, nil
}

func restoreDestinationSidecars(sidecars []movedRestoreSidecar) error {
	var firstErr error
	for index := len(sidecars) - 1; index >= 0; index-- {
		item := sidecars[index]
		if err := os.Rename(item.moved, item.original); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// validateStagedRestore performs all read-only checks before the staged file
// can be sanitized or atomically renamed over the destination. This keeps a
// corrupt, foreign, or newer-schema source from replacing a healthy database.
// It returns the staged schema version for the dry-run report.
func validateStagedRestore(ctx context.Context, path string) (int, error) {
	staged, err := OpenReadOnlyExistingContext(ctx, path)
	if err != nil {
		return 0, fmt.Errorf("open staged restore database for validation: %w", err)
	}
	defer staged.Close()
	verification, err := staged.Verify(ctx)
	if err != nil {
		return verification.SchemaVersion, fmt.Errorf("validate staged restore database: %w", err)
	}
	return verification.SchemaVersion, nil
}

const restoreQuarantineSchema = `
CREATE TABLE IF NOT EXISTS restore_quarantined_deliveries (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 restore_epoch TEXT NOT NULL,
 destination TEXT NOT NULL,
 payload_json BLOB NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 deferrals INTEGER NOT NULL DEFAULT 0,
 next_at TEXT NOT NULL DEFAULT '',
 last_error TEXT NOT NULL DEFAULT '',
 quarantined_at TEXT NOT NULL
);`

const restoreEpochSchema = `
CREATE TABLE IF NOT EXISTS restore_epochs (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 epoch TEXT NOT NULL UNIQUE,
 restored_at TEXT NOT NULL,
 pending_delivery_policy TEXT NOT NULL,
 pending_delivery_count INTEGER NOT NULL DEFAULT 0
);`

// applyRestoreDeliveryPolicy mutates only the staged copy. It is intentionally
// performed before the atomic rename so a cancelled or failed sanitization
// cannot leave the destination half-restored. The quarantine table is additive
// and is also created by the next normal schema migration; creating it here
// keeps older backup schemas safe without running application migrations in a
// host recovery command. The same transaction also clears the copied sessions
// and lease rows and revokes the copied activation links and setup token, so
// Restore and DryRunRestore sanitize the copy identically.
func applyRestoreDeliveryPolicy(ctx context.Context, path string, policy PendingDeliveryPolicy, epoch string, restoredAt time.Time) (int, error) {
	staged, err := OpenExistingContext(ctx, path)
	if err != nil {
		return 0, fmt.Errorf("open staged restore database: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = staged.Close()
		}
	}()

	tx, err := staged.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin restore delivery policy: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, restoreQuarantineSchema); err != nil {
		return 0, fmt.Errorf("create restore quarantine: %w", err)
	}
	if _, err := tx.ExecContext(ctx, restoreEpochSchema); err != nil {
		return 0, fmt.Errorf("create restore epoch: %w", err)
	}

	pending := 0
	if exists, err := tableExistsTx(ctx, tx, "outbox"); err != nil {
		return 0, err
	} else if exists {
		columns, err := restoreTableColumnsTx(ctx, tx, "outbox")
		if err != nil {
			return 0, err
		}
		// From schema 53 each delivery has a tenant, and a quarantined
		// delivery keeps it. A backup from before schema 53 has no tenant
		// column in either table; the migration after the restore attributes
		// both to the default tenant.
		tenant := ""
		if columns["tenant_id"] {
			if err := ensureRestoreQuarantineTenantTx(ctx, tx); err != nil {
				return 0, err
			}
			tenant = ",tenant_id"
		}
		// Pending means a row that can still be claimed. Older backup schemas
		// predate terminal_at, so use the retry ceiling recorded by schema 31
		// to distinguish exhausted deliveries there.
		pendingPredicate := `sent_at IS NULL`
		var pendingArgs []any
		if columns["terminal_at"] {
			pendingPredicate += ` AND terminal_at=''`
		} else if columns["attempts"] {
			pendingPredicate += ` AND attempts < ?`
			pendingArgs = append(pendingArgs, 8)
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE `+pendingPredicate, pendingArgs...).Scan(&pending); err != nil {
			return 0, fmt.Errorf("count pending deliveries: %w", err)
		}
		switch policy {
		case PendingDeliveriesDiscard:
			if _, err := tx.ExecContext(ctx, `DELETE FROM outbox WHERE `+pendingPredicate, pendingArgs...); err != nil {
				return 0, fmt.Errorf("discard pending deliveries: %w", err)
			}
		case PendingDeliveriesQuarantine:
			deferrals := "0"
			if columns["deferrals"] {
				deferrals = "COALESCE(deferrals,0)"
			}
			query := `INSERT INTO restore_quarantined_deliveries(restore_epoch,destination,payload_json,attempts,deferrals,next_at,last_error,quarantined_at` + tenant + `)
SELECT ?,destination,payload_json,attempts,` + deferrals + `,next_at,last_error,?` + tenant + ` FROM outbox WHERE ` + pendingPredicate
			args := append([]any{epoch, restoredAt.Format(time.RFC3339Nano)}, pendingArgs...)
			if _, err := tx.ExecContext(ctx, query, args...); err != nil {
				return 0, fmt.Errorf("quarantine pending deliveries: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM outbox WHERE `+pendingPredicate, pendingArgs...); err != nil {
				return 0, fmt.Errorf("remove quarantined deliveries: %w", err)
			}
		case PendingDeliveriesPreserve:
			// Preserve is explicit. The daemon's normal startup claim cleanup
			// makes any copied leases immediately eligible without replaying a
			// row more than once.
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO restore_epochs(epoch,restored_at,pending_delivery_policy,pending_delivery_count) VALUES(?,?,?,?)`, epoch, restoredAt.Format(time.RFC3339Nano), policy, pending); err != nil {
		return 0, fmt.Errorf("record restore epoch: %w", err)
	}
	// Sessions are bearer credentials. A restored backup may contain sessions
	// that were revoked after the backup was taken, so retaining them would
	// resurrect access across the restore boundary. Clearing the copied table
	// is deliberately compatible with older schemas and lets users establish
	// fresh sessions after the restored daemon starts.
	if exists, err := tableExistsTx(ctx, tx, "sessions"); err != nil {
		return 0, err
	} else if exists {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
			return 0, fmt.Errorf("invalidate restored sessions: %w", err)
		}
	}
	if err := revokeRestoredLinksTx(ctx, tx, restoredAt); err != nil {
		return 0, err
	}
	if err := clearRestoredLeasesTx(ctx, tx); err != nil {
		return 0, err
	}
	if err := insertRestoreAuditTx(ctx, tx, policy, pending, epoch, restoredAt); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit restore delivery policy: %w", err)
	}
	// A copied WAL-mode database may put the policy transaction in a temporary
	// WAL. Checkpoint it before the staged file is renamed; otherwise the atomic
	// rename would omit the sanitized state when the sidecar is cleaned up.
	if _, err := staged.DB.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return 0, fmt.Errorf("checkpoint staged restore database: %w", err)
	}
	if err := staged.Close(); err != nil {
		closed = true
		return 0, fmt.Errorf("close staged restore database: %w", err)
	}
	closed = true
	if err := syncRestoreFile(path); err != nil {
		return 0, fmt.Errorf("sync staged restore database: %w", err)
	}
	return pending, nil
}

// revokeRestoredLinksTx marks every activation and password-reset link and
// the setup token copied from the backup used at restoredAt, as sessions are
// cleared. They are one-time credentials: a link or token that was used or
// revoked after the backup was taken is unused in the backup, so keeping
// them would let it be redeemed again after the restore. Administrators
// issue new links from the console, and the host issues a new setup token;
// the daemon prints a new initial setup token at startup when no
// administrator exists. Both tables have had used_at since they were
// created, and a backup from before either table existed has nothing to
// revoke.
func revokeRestoredLinksTx(ctx context.Context, tx *sql.Tx, restoredAt time.Time) error {
	stamp := restoredAt.UTC().Format(time.RFC3339Nano)
	for _, credential := range []struct{ table, query string }{
		{table: "user_invites", query: `UPDATE user_invites SET used_at=? WHERE used_at IS NULL`},
		{table: "setup_tokens", query: `UPDATE setup_tokens SET used_at=? WHERE used_at IS NULL`},
	} {
		exists, err := tableExistsTx(ctx, tx, credential.table)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if _, err := tx.ExecContext(ctx, credential.query, stamp); err != nil {
			return fmt.Errorf("revoke restored %s: %w", credential.table, err)
		}
	}
	return nil
}

// clearRestoredLeasesTx removes the daemon lease and the scan leases copied
// from the backup. A backup taken from a running daemon carries that daemon's
// fresh heartbeat, but the process that wrote it is attached to the source
// database, not to the staged copy, and nothing else can have the private
// staged copy open. Keeping the copied rows would make the restored daemon
// wait out the old heartbeat, make a repeat restore see a live daemon on a
// stopped destination, and keep jobs busy until the copied scan leases expire.
// The destination's own daemon lease is checked separately before and after
// staging, so a live destination is still refused.
func clearRestoredLeasesTx(ctx context.Context, tx *sql.Tx) error {
	for _, lease := range []struct{ table, query string }{
		{table: "daemon_lease", query: `DELETE FROM daemon_lease`},
		{table: "job_leases", query: `DELETE FROM job_leases`},
	} {
		exists, err := tableExistsTx(ctx, tx, lease.table)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if _, err := tx.ExecContext(ctx, lease.query); err != nil {
			return fmt.Errorf("clear restored %s: %w", lease.table, err)
		}
	}
	return nil
}

// ensureRestoreQuarantineTenantTx gives the quarantine the schema 53 tenant
// column when the staged database has the column on its outbox but created
// the quarantine table only now, in its schema-35 shape. The migration does
// not run again on a restored database that is already at schema 53.
func ensureRestoreQuarantineTenantTx(ctx context.Context, tx *sql.Tx) error {
	columns, err := restoreTableColumnsTx(ctx, tx, "restore_quarantined_deliveries")
	if err != nil || columns["tenant_id"] {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE restore_quarantined_deliveries ADD COLUMN tenant_id TEXT DEFAULT '`+DefaultTenantID+`'`); err != nil {
		return fmt.Errorf("add restore quarantine tenant: %w", err)
	}
	return nil
}

func tableExistsTx(ctx context.Context, tx *sql.Tx, table string) (bool, error) {
	var name string
	err := tx.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect %s table: %w", table, err)
	}
	return name != "", nil
}

func restoreTableColumnsTx(ctx context.Context, tx *sql.Tx, table string) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, fmt.Errorf("inspect %s columns: %w", table, err)
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inspect %s columns: %w", table, err)
	}
	return columns, nil
}

func insertRestoreAuditTx(ctx context.Context, tx *sql.Tx, policy PendingDeliveryPolicy, pending int, epoch string, restoredAt time.Time) error {
	if exists, err := tableExistsTx(ctx, tx, "security_audit"); err != nil {
		return err
	} else if !exists {
		if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS security_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL)`); err != nil {
			return fmt.Errorf("create restore audit table: %w", err)
		}
	}
	columns, err := restoreTableColumnsTx(ctx, tx, "security_audit")
	if err != nil {
		return err
	}
	const action = "database.restore.pending_deliveries"
	names := []string{"action", "detail"}
	values := []any{action, fmt.Sprintf("epoch=%s pending_deliveries=%s count=%d", epoch, policy, pending)}
	if columns["actor_username"] {
		names, values = append(names, "actor_username"), append(values, "host-cli")
	}
	if columns["category"] {
		names, values = append(names, "category"), append(values, auditCategory(action))
	}
	if columns["tenant_id"] {
		// This entry contains the deployment-wide pending-delivery count, so
		// keep it in platform scope rather than attributing it to one tenant.
		names, values = append(names, "tenant_id"), append(values, nil)
	}
	if columns["actor_kind"] {
		// The restore runs from the host CLI.
		names, values = append(names, "actor_kind"), append(values, AuditActorHost)
	}
	names, values = append(names, "created_at"), append(values, restoredAt.Format(time.RFC3339Nano))
	query := `INSERT INTO security_audit(` + strings.Join(names, ",") + `) VALUES(?` + strings.Repeat(",?", len(names)-1) + `)`
	if _, err := tx.ExecContext(ctx, query, values...); err != nil {
		return fmt.Errorf("record restore audit: %w", err)
	}
	return nil
}

func syncRestoreFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func refuseActiveDaemon(ctx context.Context, destination string) error {
	before := snapshotSQLiteSidecars(destination)
	reader, err := OpenReadOnlyExistingContext(ctx, destination)
	if err != nil {
		return fmt.Errorf("%w: %v; confirm EdgeWatch is stopped and rerun with unreadable-destination recovery", ErrRestoreDestinationUnreadable, err)
	}
	status, err := reader.System().DaemonLeaseStatus(ctx)
	closeErr := reader.Close()
	if err != nil {
		return fmt.Errorf("%w: check destination daemon lease: %v; confirm EdgeWatch is stopped and rerun with unreadable-destination recovery", ErrRestoreDestinationUnreadable, err)
	}
	if closeErr != nil {
		return fmt.Errorf("%w: close destination daemon lease check: %v; confirm EdgeWatch is stopped and rerun with unreadable-destination recovery", ErrRestoreDestinationUnreadable, closeErr)
	}
	if !status.Active {
		// SQLite may create an empty WAL/SHM pair when a live-safe read-only
		// connection first observes a WAL-mode database. A restore preflight
		// must not turn that read into a persistent sidecar refusal, so remove
		// only companions created by this probe and only when the WAL is empty.
		cleanupSQLiteProbeSidecars(destination, before)
		// A probe sidecar that is still present means another connection had
		// the destination open. Replacing the file now would leave that
		// connection's WAL and WAL index next to the restored database.
		var left []string
		for _, suffix := range []string{"-wal", "-shm"} {
			if before[suffix] {
				continue
			}
			if _, err := os.Lstat(destination + suffix); err == nil {
				left = append(left, destination+suffix)
			}
		}
		if len(left) > 0 {
			return fmt.Errorf("another connection has the destination database open: %w", &RestoreSidecarError{Paths: left})
		}
		return nil
	}
	return fmt.Errorf("%w (owner %s heartbeat %s)", ErrRestoreDaemonLive, status.Owner, status.Heartbeat.UTC().Format(time.RFC3339Nano))
}

func snapshotSQLiteSidecars(database string) map[string]bool {
	result := make(map[string]bool, 3)
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		_, err := os.Lstat(database + suffix)
		result[suffix] = err == nil
	}
	return result
}

// cleanupSQLiteProbeSidecars removes the empty WAL/SHM pair that a read-only
// probe created, but only while it can prove that no other SQLite connection
// has the database open. Another process, or another store in this process,
// may have attached to those files after the probe created them; unlinking
// them would send that connection's commits to deleted inodes. A rollback
// journal is never removed: a read-only connection never creates one, so it
// always belongs to another connection's transaction.
func cleanupSQLiteProbeSidecars(database string, before map[string]bool) {
	candidates := make([]string, 0, 2)
	for _, suffix := range []string{"-wal", "-shm"} {
		if !before[suffix] {
			candidates = append(candidates, database+suffix)
		}
	}
	if len(candidates) == 0 || !sqliteWALEmpty(database) {
		return
	}
	openDatabases.withUnused(database, func() {
		removed := false
		withExclusiveSQLiteDatabase(database, func() {
			// Check again under the lock: a writer may have committed between
			// the first check and the lock.
			if !sqliteWALEmpty(database) {
				return
			}
			for _, path := range candidates {
				if err := os.Remove(path); err == nil {
					removed = true
				} else if !errors.Is(err, os.ErrNotExist) {
					return
				}
			}
		})
		if removed {
			_ = syncDirectory(filepath.Dir(database))
		}
	})
}

func sqliteWALEmpty(database string) bool {
	info, err := os.Stat(database + "-wal")
	if err != nil {
		return errors.Is(err, os.ErrNotExist)
	}
	return info.Size() == 0
}

func restorePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("path is required")
	}
	decoded, err := sqliteArtifactPath(path)
	if err != nil {
		return "", err
	}
	path = decoded
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	if absolute == "." || absolute == string(filepath.Separator) {
		return "", errors.New("path must name a database file")
	}
	return absolute, nil
}

func regularFileInfo(path string, required bool) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if required {
			return nil, os.ErrNotExist
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("database path must not be a symbolic link: %s", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("database path is not a regular file: %s", path)
	}
	return info, nil
}

func inspectRestoreSidecars(database string, databaseInfo os.FileInfo) ([]RestoreSidecar, error) {
	result := make([]RestoreSidecar, 0, 3)
	for _, candidate := range []struct {
		kind   string
		suffix string
	}{
		{kind: "wal", suffix: "-wal"},
		{kind: "shm", suffix: "-shm"},
		{kind: "journal", suffix: "-journal"},
	} {
		path := database + candidate.suffix
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("database sidecar must not be a symbolic link: %s", path)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("database sidecar is not a regular file: %s", path)
		}
		newerThanDatabase := false
		if databaseInfo != nil {
			newerThanDatabase = info.ModTime().After(databaseInfo.ModTime())
		}
		result = append(result, RestoreSidecar{
			Kind:              candidate.kind,
			Path:              path,
			Bytes:             info.Size(),
			ModifiedAt:        info.ModTime().UTC(),
			NewerThanDatabase: newerThanDatabase,
		})
	}
	return result, nil
}

func copyRestoreFile(ctx context.Context, source, destination string) (int64, error) {
	in, err := os.Open(source)
	if err != nil {
		return 0, fmt.Errorf("open restore source: %w", err)
	}
	defer in.Close()
	pathInfo, err := os.Lstat(source)
	if err != nil {
		return 0, fmt.Errorf("stat restore source: %w", err)
	}
	inInfo, err := in.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat opened restore source: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !os.SameFile(pathInfo, inInfo) {
		return 0, errors.New("restore source changed while it was being opened")
	}
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, fmt.Errorf("create restore staging file: %w", err)
	}
	bytes, copyErr := copyWithContext(ctx, out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil {
		return bytes, fmt.Errorf("copy restore source: %w", copyErr)
	}
	if syncErr != nil {
		return bytes, fmt.Errorf("sync restore staging file: %w", syncErr)
	}
	if closeErr != nil {
		return bytes, fmt.Errorf("close restore staging file: %w", closeErr)
	}
	return bytes, nil
}

func validateSQLiteRestoreSource(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open restore source: %w", err)
	}
	defer file.Close()
	var header [16]byte
	if _, err := io.ReadFull(file, header[:]); err != nil {
		return fmt.Errorf("read restore source header: %w", err)
	}
	if string(header[:]) != "SQLite format 3\x00" {
		return errors.New("restore source is not a SQLite database")
	}
	return nil
}

func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 128*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			written, writeErr := destination.Write(buffer[:read])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != read {
				return total, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, readErr
		}
	}
}
