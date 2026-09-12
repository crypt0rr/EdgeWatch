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
	// PendingDeliveries applies an explicit restore epoch policy to unsent
	// notification rows. Empty uses the safe quarantine default.
	PendingDeliveries PendingDeliveryPolicy
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
	SidecarsWarning           string                `json:"sidecars_warning,omitempty"`
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
// removed; this makes a dry-run safe even when the daemon was not stopped.
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

// Restore replaces destination with a private, atomically copied source
// database. The caller must stop EdgeWatch first. By default any WAL, SHM, or
// rollback-journal companion on either path causes a refusal; allowing replay
// is an explicit recovery-only escape hatch and is never inferred from file
// timestamps. Unsent notification deliveries are quarantined by default at a
// new restore epoch; callers must explicitly select discard or preserve.
func Restore(ctx context.Context, source, destination string, options RestoreOptions) (RestoreResult, error) {
	var result RestoreResult
	policy, err := ParsePendingDeliveryPolicy(string(options.PendingDeliveries))
	if err != nil {
		return result, err
	}
	preflight, err := PreflightRestore(ctx, source, destination)
	if err != nil {
		return result, err
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
		return result, &RestoreSidecarError{Paths: paths}
	}
	if preflight.DestinationExists && !options.AllowActiveDaemon {
		if err := refuseActiveDaemon(ctx, preflight.DestinationPath); err != nil {
			return result, err
		}
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	parent := filepath.Dir(preflight.DestinationPath)
	parentInfo, err := os.Stat(parent)
	if err != nil {
		return result, fmt.Errorf("restore destination directory: %w", err)
	}
	if !parentInfo.IsDir() {
		return result, errors.New("restore destination parent is not a directory")
	}
	tempDir, err := os.MkdirTemp(parent, ".edgewatch-restore-")
	if err != nil {
		return result, fmt.Errorf("create restore staging directory: %w", err)
	}
	defer os.RemoveAll(tempDir)
	if err := os.Chmod(tempDir, 0o700); err != nil {
		return result, err
	}
	tempPath := filepath.Join(tempDir, filepath.Base(preflight.DestinationPath))
	bytes, err := copyRestoreFile(ctx, preflight.SourcePath, tempPath)
	if err != nil {
		return result, err
	}
	restoreEpoch := uuid.NewString()
	restoredAt := time.Now().UTC()
	pending, err := applyRestoreDeliveryPolicy(ctx, tempPath, policy, restoreEpoch, restoredAt)
	if err != nil {
		return result, err
	}
	// Re-check immediately before replacing the destination. This closes the
	// normal window where a daemon could start while the source is being copied;
	// the operator-facing escape hatch remains explicit for intentional recovery.
	if preflight.DestinationExists && !options.AllowActiveDaemon {
		if err := refuseActiveDaemon(ctx, preflight.DestinationPath); err != nil {
			return result, err
		}
	}
	if err := os.Rename(tempPath, preflight.DestinationPath); err != nil {
		return result, fmt.Errorf("replace restored database: %w", err)
	}
	if err := os.Chmod(preflight.DestinationPath, 0o600); err != nil {
		return result, err
	}
	if err := syncDirectory(parent); err != nil {
		return result, fmt.Errorf("sync restored database directory: %w", err)
	}
	result = RestoreResult{
		Path:                      preflight.DestinationPath,
		Bytes:                     bytes,
		RestoredAt:                restoredAt,
		RestoreEpoch:              restoreEpoch,
		PendingDeliveriesPolicy:   policy,
		PendingDeliveriesAffected: pending,
	}
	if !preflight.Safe {
		for _, sidecar := range preflight.SourceSidecars {
			result.SidecarsPresent = append(result.SidecarsPresent, sidecar.Path)
		}
		for _, sidecar := range preflight.DestinationSidecars {
			result.SidecarsPresent = append(result.SidecarsPresent, sidecar.Path)
		}
		sort.Strings(result.SidecarsPresent)
		result.SidecarsWarning = "SQLite sidecars were explicitly allowed to remain; verify that replay is intentional"
	}
	return result, nil
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
// host recovery command.
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
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL`).Scan(&pending); err != nil {
			return 0, fmt.Errorf("count pending deliveries: %w", err)
		}
		switch policy {
		case PendingDeliveriesDiscard:
			if _, err := tx.ExecContext(ctx, `DELETE FROM outbox WHERE sent_at IS NULL`); err != nil {
				return 0, fmt.Errorf("discard pending deliveries: %w", err)
			}
		case PendingDeliveriesQuarantine:
			columns, err := restoreTableColumnsTx(ctx, tx, "outbox")
			if err != nil {
				return 0, err
			}
			deferrals := "0"
			if columns["deferrals"] {
				deferrals = "COALESCE(deferrals,0)"
			}
			query := `INSERT INTO restore_quarantined_deliveries(restore_epoch,destination,payload_json,attempts,deferrals,next_at,last_error,quarantined_at)
SELECT ?,destination,payload_json,attempts,` + deferrals + `,next_at,last_error,? FROM outbox WHERE sent_at IS NULL`
			if _, err := tx.ExecContext(ctx, query, epoch, restoredAt.Format(time.RFC3339Nano)); err != nil {
				return 0, fmt.Errorf("quarantine pending deliveries: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM outbox WHERE sent_at IS NULL`); err != nil {
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
	detail := fmt.Sprintf("epoch=%s pending_deliveries=%s count=%d", epoch, policy, pending)
	if columns["actor_username"] {
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_audit(action,detail,actor_username,created_at) VALUES(?,?,?,?)`, "database.restore.pending_deliveries", detail, "host-cli", restoredAt.Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("record restore audit: %w", err)
		}
		return nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO security_audit(action,detail,created_at) VALUES(?,?,?)`, "database.restore.pending_deliveries", detail, restoredAt.Format(time.RFC3339Nano)); err != nil {
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
	reader, err := OpenReadOnlyExistingContext(ctx, destination)
	if err != nil {
		return fmt.Errorf("check destination daemon lease: %w", err)
	}
	defer reader.Close()
	status, err := reader.DaemonLeaseStatus(ctx)
	if err != nil {
		return fmt.Errorf("check destination daemon lease: %w", err)
	}
	if !status.Active {
		return nil
	}
	return fmt.Errorf("%w (owner %s heartbeat %s)", ErrRestoreDaemonLive, status.Owner, status.Heartbeat.UTC().Format(time.RFC3339Nano))
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
