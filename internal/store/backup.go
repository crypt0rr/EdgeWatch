package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DatabaseVerification is the bounded result of the SQLite consistency checks
// used by the verify command. SQLite reports integrity_check as one row, while
// foreign_key_check returns one row per violating relationship.
type DatabaseVerification struct {
	SchemaVersion        int                   `json:"schema_version"`
	SchemaSupported      bool                  `json:"schema_supported"`
	EdgeWatchSchema      bool                  `json:"edgewatch_schema"`
	IntegrityCheck       string                `json:"integrity_check"`
	ForeignKeyViolations []ForeignKeyViolation `json:"foreign_key_violations"`
	FTSBackfill          []FTSBackfillProgress `json:"fts_backfill,omitempty"`
	// AutoVacuum is the database's auto-vacuum mode, as autoVacuumModeName
	// names it: incremental for a database that v0.18.31 or later created,
	// none for an older one, which keeps the pages it frees in the file.
	AutoVacuum string `json:"auto_vacuum"`
}

// autoVacuumModeName names a value of PRAGMA auto_vacuum.
func autoVacuumModeName(mode int) string {
	switch mode {
	case 0:
		return "none"
	case 1:
		return "full"
	case 2:
		return "incremental"
	}
	return fmt.Sprintf("unknown (%d)", mode)
}

// FTSBackfillProgress is the durable, read-only diagnostic state for one
// host-search projection, for the schema 54 copy of the latest host
// projection (latest_scan_hosts_tenant_rekey), or for the schema 55 cleanup
// after deleted tenants (legacy_tenant_purge_maintenance, see
// migration55.go). A non-complete row is expected while a cancelled
// migration is waiting to resume, or while the daemon runs that cleanup; it
// is not itself an integrity failure.
type FTSBackfillProgress struct {
	TableName     string `json:"table_name"`
	LastRowID     int64  `json:"last_rowid"`
	ProcessedRows int64  `json:"processed_rows"`
	Initialized   bool   `json:"initialized"`
	Complete      bool   `json:"complete"`
	UpdatedAt     string `json:"updated_at"`
}

// ForeignKeyViolation describes the four columns returned by
// PRAGMA foreign_key_check. RowID is zero when SQLite reports a NULL rowid for
// a WITHOUT ROWID table.
type ForeignKeyViolation struct {
	Table       string `json:"table"`
	RowID       int64  `json:"row_id,omitempty"`
	ParentTable string `json:"parent_table"`
	ForeignKey  int64  `json:"foreign_key"`
}

// VerificationError indicates that SQLite completed a consistency check but
// found a problem. The result remains available to callers so a CLI can print
// useful machine-readable diagnostics before returning a non-zero exit code.
type VerificationError struct {
	IntegrityCheck       string
	ForeignKeyViolations int
	SchemaVersion        int
	SchemaChecked        bool
	SchemaSupported      bool
	EdgeWatchSchema      bool
}

func (e *VerificationError) Error() string {
	if e == nil {
		return "database verification failed"
	}
	parts := make([]string, 0, 2)
	if e.IntegrityCheck != "" && e.IntegrityCheck != "ok" {
		parts = append(parts, "integrity_check: "+e.IntegrityCheck)
	}
	if e.ForeignKeyViolations > 0 {
		parts = append(parts, fmt.Sprintf("foreign_key_check: %d violation(s)", e.ForeignKeyViolations))
	}
	if e.SchemaChecked && !e.SchemaSupported {
		parts = append(parts, fmt.Sprintf("unsupported schema version: %d", e.SchemaVersion))
	}
	if e.SchemaChecked && !e.EdgeWatchSchema {
		parts = append(parts, "not an EdgeWatch database")
	}
	if len(parts) == 0 {
		return "database verification failed"
	}
	return strings.Join(parts, "; ")
}

// The SQLite consistency checks that verification runs. integrity_check
// reads every page and checks every index; quick_check skips the comparison
// of each index with its table, which makes it much faster on a large
// database while still finding damaged pages.
const (
	IntegrityCheck = "integrity_check"
	QuickCheck     = "quick_check"
)

// Verify runs SQLite's full integrity and foreign-key checks against the
// read-only connection. It intentionally does not mutate the database, making
// it safe to use against a live daemon or immediately after restoring a
// backup. Using the reader also prevents a diagnostic command from consuming
// the single writer connection while a scan is committing.
func (s *Store) Verify(ctx context.Context) (DatabaseVerification, error) {
	return s.verify(ctx, IntegrityCheck)
}

// verify is Verify with the consistency check to run, IntegrityCheck or
// QuickCheck. Both put their result in IntegrityCheck, which is "ok" for a
// database without damage.
func (s *Store) verify(ctx context.Context, check string) (DatabaseVerification, error) {
	result := DatabaseVerification{ForeignKeyViolations: []ForeignKeyViolation{}, FTSBackfill: []FTSBackfillProgress{}}
	if check != IntegrityCheck && check != QuickCheck {
		return result, fmt.Errorf("unknown database check %q", check)
	}
	if s == nil || s.DB == nil {
		return result, errors.New("database is not open")
	}
	reader := s.reader()
	var schemaVersionValue int
	if err := reader.QueryRowContext(ctx, "PRAGMA user_version").Scan(&schemaVersionValue); err != nil {
		return result, err
	}
	result.SchemaVersion = schemaVersionValue
	result.SchemaSupported = schemaVersionValue >= 1 && schemaVersionValue <= schemaVersion
	result.EdgeWatchSchema = detectEdgeWatchSchema(ctx, reader)
	var autoVacuum int
	if err := reader.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&autoVacuum); err != nil {
		return result, err
	}
	result.AutoVacuum = autoVacuumModeName(autoVacuum)
	if err := reader.QueryRowContext(ctx, `PRAGMA `+check).Scan(&result.IntegrityCheck); err != nil {
		return result, err
	}
	rows, err := reader.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var violation ForeignKeyViolation
		var rowID, foreignKey sql.NullInt64
		if err := rows.Scan(&violation.Table, &rowID, &violation.ParentTable, &foreignKey); err != nil {
			return result, err
		}
		if rowID.Valid {
			violation.RowID = rowID.Int64
		}
		if foreignKey.Valid {
			violation.ForeignKey = foreignKey.Int64
		}
		result.ForeignKeyViolations = append(result.ForeignKeyViolations, violation)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	var ftsTableCount int
	if err := reader.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='fts_backfill_state'`).Scan(&ftsTableCount); err != nil {
		return result, err
	}
	if ftsTableCount > 0 {
		ftsRows, err := reader.QueryContext(ctx, `SELECT table_name,last_rowid,processed_rows,initialized,complete,updated_at FROM fts_backfill_state ORDER BY table_name`)
		if err != nil {
			return result, err
		}
		defer func() { _ = ftsRows.Close() }()
		for ftsRows.Next() {
			var progress FTSBackfillProgress
			var initialized, complete int
			if err := ftsRows.Scan(&progress.TableName, &progress.LastRowID, &progress.ProcessedRows, &initialized, &complete, &progress.UpdatedAt); err != nil {
				return result, err
			}
			progress.Initialized = initialized != 0
			progress.Complete = complete != 0
			result.FTSBackfill = append(result.FTSBackfill, progress)
		}
		if err := ftsRows.Err(); err != nil {
			return result, err
		}
	}
	if result.IntegrityCheck != "ok" || len(result.ForeignKeyViolations) > 0 || !result.SchemaSupported || !result.EdgeWatchSchema {
		return result, &VerificationError{
			IntegrityCheck:       result.IntegrityCheck,
			ForeignKeyViolations: len(result.ForeignKeyViolations),
			SchemaVersion:        result.SchemaVersion,
			SchemaChecked:        true,
			SchemaSupported:      result.SchemaSupported,
			EdgeWatchSchema:      result.EdgeWatchSchema,
		}
	}
	return result, nil
}

// detectEdgeWatchSchema distinguishes a supported EdgeWatch database from an
// arbitrary SQLite file before a restore can replace the live installation.
// The scans/events/outbox/daemon_lease set is present in the original v1
// schema and every later migration; checking a few stable columns avoids
// accepting an unrelated file that happens to use one familiar table name.
func detectEdgeWatchSchema(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) bool {
	// Keep the probe to one bounded query. Besides avoiding a second metadata
	// cursor while verifying a live database, this makes a cancelled or damaged
	// connection fail atomically instead of leaving a partial schema decision.
	const probe = `SELECT CASE WHEN
		(SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('scans','events','outbox','daemon_lease')) = 4
		AND (SELECT COUNT(*) FROM pragma_table_info('scans') WHERE name IN ('id','job','started_at','finished_at','status','config_hash','snapshot_json')) = 7
		THEN 1 ELSE 0 END`
	var valid int
	if err := queryer.QueryRowContext(ctx, probe).Scan(&valid); err != nil {
		// A metadata read failure is treated as an unsupported schema. Verify
		// still completes its remaining checks and returns a structured
		// VerificationError, while a restore remains fail-closed.
		return false
	}
	return valid != 0
}

// BackupOptions selects the check that a backup passes before it is
// published.
type BackupOptions struct {
	// FullIntegrityCheck runs SQLite's integrity_check on the new file
	// instead of the faster quick_check. Its time grows with the size of the
	// database.
	FullIntegrityCheck bool
}

// BackupResult describes a published backup and the checks that it passed:
// the SQLite consistency check named by Check, the foreign-key check, and the
// EdgeWatch schema detection that a restore also runs.
type BackupResult struct {
	Path          string `json:"path"`
	Bytes         int64  `json:"bytes"`
	SchemaVersion int    `json:"schema_version"`
	// Check is the consistency check that the backup passed, QuickCheck or
	// IntegrityCheck, and IntegrityCheck its result, which is always "ok".
	Check                string `json:"check"`
	IntegrityCheck       string `json:"integrity_check"`
	ForeignKeyViolations int    `json:"foreign_key_violations"`
}

// Backup creates a verified backup with BackupWithOptions and its default
// quick_check, and returns the published path.
func (s *Store) Backup(ctx context.Context, output string) (string, error) {
	result, err := s.BackupWithOptions(ctx, output, BackupOptions{})
	return result.Path, err
}

// BackupWithOptions creates a consistent single-file SQLite snapshot while
// the store is live. VACUUM INTO reads one SQLite snapshot (including WAL
// content) and writes it to a private temporary directory. The new file is
// then checked as a restore would check it: a SQLite consistency check, the
// foreign-key check, and the schema detection. Only a file that passes is
// published, atomically, under output, so a failed check leaves nothing
// there. Existing destination files are refused to avoid accidental
// overwrites; operators can choose a new timestamped path instead.
func (s *Store) BackupWithOptions(ctx context.Context, output string, options BackupOptions) (BackupResult, error) {
	var result BackupResult
	if s == nil || s.DB == nil {
		return result, errors.New("database is not open")
	}
	path, err := filepath.Abs(filepath.Clean(strings.TrimSpace(output)))
	if err != nil {
		return result, err
	}
	if strings.TrimSpace(output) == "" || path == "." {
		return result, errors.New("backup output path is required")
	}
	current := ""
	if !isSQLiteMemoryPath(s.Path) {
		current, err = sqliteArtifactPath(s.Path)
		if err != nil {
			return result, err
		}
		current, err = filepath.Abs(filepath.Clean(current))
		if err != nil {
			return result, err
		}
	}
	// Refuse the database and all SQLite sidecars. A sidecar destination could
	// otherwise corrupt a live database even though VACUUM INTO itself is safe.
	if current != "" && (path == current || strings.HasPrefix(path, current+"-")) {
		return result, errors.New("backup output must be different from the SQLite database and its sidecars")
	}
	// VACUUM INTO obtains a consistent snapshot, but it still holds a read
	// transaction for the duration of the copy. Run it through an independent
	// connection for on-disk stores so the daemon's writer pool remains
	// available for scan commits and notification state. OpenExisting performs
	// no migrations or repair work, which keeps backup a read-only operation.
	backupSource := s
	var sourceStore *Store
	if !isSQLiteMemoryPath(s.Path) {
		sourceStore, err = OpenExistingContext(ctx, s.Path)
		if err != nil {
			return result, fmt.Errorf("open SQLite backup source: %w", err)
		}
		backupSource = sourceStore
		defer sourceStore.Close()
	}
	check := QuickCheck
	if options.FullIntegrityCheck {
		check = IntegrityCheck
	}
	// The private modes are set, and the checks run, on the temporary file
	// inside the private directory, before it is published. Nothing is done
	// to the published path afterwards: SQLite sidecar names next to it
	// belong to whatever else uses that directory, never to this backup.
	path, err = AtomicWriteFile(path, ".edgewatch-backup-", func(tempPath string) error {
		if _, err := backupSource.DB.ExecContext(ctx, `VACUUM INTO ?`, tempPath); err != nil {
			return fmt.Errorf("create SQLite backup: %w", err)
		}
		if err := enforcePrivateSQLiteArtifacts(tempPath); err != nil {
			return err
		}
		verification, err := verifyDatabaseFile(ctx, tempPath, check)
		result.SchemaVersion = verification.SchemaVersion
		if err != nil {
			return fmt.Errorf("verify SQLite backup: %w", err)
		}
		info, err := os.Stat(tempPath)
		if err != nil {
			return err
		}
		result.Bytes = info.Size()
		result.Check, result.IntegrityCheck = check, verification.IntegrityCheck
		result.ForeignKeyViolations = len(verification.ForeignKeyViolations)
		return nil
	}, nil)
	if err != nil {
		return BackupResult{SchemaVersion: result.SchemaVersion}, err
	}
	result.Path = path
	return result, nil
}

// verifyDatabaseFile opens the database file at path read-only and runs the
// verification checks with the consistency check named by check.
func verifyDatabaseFile(ctx context.Context, path, check string) (DatabaseVerification, error) {
	reader, err := OpenReadOnlyExistingContext(ctx, path)
	if err != nil {
		return DatabaseVerification{ForeignKeyViolations: []ForeignKeyViolation{}, FTSBackfill: []FTSBackfillProgress{}}, err
	}
	verification, err := reader.verify(ctx, check)
	return verification, errors.Join(err, reader.Close())
}

// BackupFileOptions controls VerifyBackupFile.
type BackupFileOptions struct {
	// LiveDatabase is the configured database, which VerifyBackupFile
	// refuses to copy: the live file and its sidecars change while the
	// daemon runs, and Verify checks it in place.
	LiveDatabase string
	// InspectStaged and AllowKeyMismatch check the configured keys against
	// the private copy as a restore does; see RestoreOptions.
	InspectStaged    StagedInspection
	AllowKeyMismatch bool
}

// BackupFileVerification is the report of VerifyBackupFile. Valid reports
// whether the file passed every check that a restore runs on its source:
// the SQLite header, no sidecars, the consistency and foreign-key checks,
// a supported EdgeWatch schema, and, when requested, the key check. The
// checks of the restore destination, such as its daemon lease, do not
// apply. Error is the reason of a failed check.
type BackupFileVerification struct {
	SourcePath     string           `json:"source_path"`
	Bytes          int64            `json:"bytes"`
	SourceSidecars []RestoreSidecar `json:"source_sidecars"`
	DatabaseVerification
	KeyCheck *RestoreKeyCheck `json:"key_check,omitempty"`
	Valid    bool             `json:"valid"`
	Error    string           `json:"error,omitempty"`
}

// VerifyBackupFile checks a backup file without opening the live database or
// reading its daemon lease, so it works while the daemon runs. It reads the
// source once, into a private directory below the system temporary
// directory (TMPDIR), and checks that copy, so SQLite never opens the source
// and no sidecar is created next to it. The report is filled in as far as
// the checks progressed, and the returned error is the first failed check.
func VerifyBackupFile(ctx context.Context, source string, options BackupFileOptions) (BackupFileVerification, error) {
	report, err := verifyBackupFile(ctx, source, options)
	report.Valid = err == nil
	if err != nil {
		report.Error = err.Error()
	}
	return report, err
}

func verifyBackupFile(ctx context.Context, source string, options BackupFileOptions) (BackupFileVerification, error) {
	report := BackupFileVerification{
		SourceSidecars:       []RestoreSidecar{},
		DatabaseVerification: DatabaseVerification{ForeignKeyViolations: []ForeignKeyViolation{}, FTSBackfill: []FTSBackfillProgress{}},
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	sourcePath, err := restorePath(source)
	if err != nil {
		return report, fmt.Errorf("backup file: %w", err)
	}
	report.SourcePath = sourcePath
	if strings.TrimSpace(options.LiveDatabase) != "" {
		live, err := restorePath(options.LiveDatabase)
		if err != nil {
			return report, fmt.Errorf("configured database: %w", err)
		}
		if live == sourcePath {
			return report, errors.New("the backup file is the configured database; run verify without --from to check it in place")
		}
	}
	info, err := regularFileInfo(sourcePath, true)
	if err != nil {
		return report, fmt.Errorf("backup file: %w", err)
	}
	report.Bytes = info.Size()
	if err := validateSQLiteRestoreSource(sourcePath); err != nil {
		return report, err
	}
	// A backup written by the backup command has no sidecars. A file with
	// them is a raw copy, whose transactions may sit in its WAL; a restore
	// refuses it unless sidecar replay is allowed, so it is not valid here.
	report.SourceSidecars, err = inspectRestoreSidecars(sourcePath, info)
	if err != nil {
		return report, fmt.Errorf("backup file sidecars: %w", err)
	}
	if len(report.SourceSidecars) > 0 {
		paths := make([]string, 0, len(report.SourceSidecars))
		for _, sidecar := range report.SourceSidecars {
			paths = append(paths, sidecar.Path)
		}
		return report, &RestoreSidecarError{Paths: paths}
	}
	dir, err := os.MkdirTemp("", ".edgewatch-verify-")
	if err != nil {
		return report, fmt.Errorf("create backup verification directory: %w", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return report, err
	}
	staged := filepath.Join(dir, "payload")
	if _, err := copyRestoreFile(ctx, sourcePath, staged); err != nil {
		return report, err
	}
	verification, err := verifyDatabaseFile(ctx, staged, IntegrityCheck)
	report.DatabaseVerification = verification
	if err != nil {
		return report, fmt.Errorf("verify backup file: %w", err)
	}
	report.KeyCheck, err = checkStagedKeys(ctx, staged, options.InspectStaged, options.AllowKeyMismatch)
	return report, err
}
