package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// DatabaseVerification is the bounded result of the SQLite consistency checks
// used by the verify command. SQLite reports integrity_check as one row, while
// foreign_key_check returns one row per violating relationship.
type DatabaseVerification struct {
	IntegrityCheck       string                `json:"integrity_check"`
	ForeignKeyViolations []ForeignKeyViolation `json:"foreign_key_violations"`
	FTSBackfill          []FTSBackfillProgress `json:"fts_backfill,omitempty"`
}

// FTSBackfillProgress is the durable, read-only diagnostic state for one
// host-search projection. A non-complete row is expected while a cancelled
// migration is waiting to resume; it is not itself an integrity failure.
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
	if len(parts) == 0 {
		return "database verification failed"
	}
	return strings.Join(parts, "; ")
}

// Verify runs SQLite's full integrity and foreign-key checks against the
// read-only connection. It intentionally does not mutate the database, making
// it safe to use against a live daemon or immediately after restoring a
// backup. Using the reader also prevents a diagnostic command from consuming
// the single writer connection while a scan is committing.
func (s *Store) Verify(ctx context.Context) (DatabaseVerification, error) {
	result := DatabaseVerification{ForeignKeyViolations: []ForeignKeyViolation{}, FTSBackfill: []FTSBackfillProgress{}}
	if s == nil || s.DB == nil {
		return result, errors.New("database is not open")
	}
	reader := s.reader()
	if err := reader.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result.IntegrityCheck); err != nil {
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
	if result.IntegrityCheck != "ok" || len(result.ForeignKeyViolations) > 0 {
		return result, &VerificationError{IntegrityCheck: result.IntegrityCheck, ForeignKeyViolations: len(result.ForeignKeyViolations)}
	}
	return result, nil
}

// Backup creates a consistent single-file SQLite snapshot while the store is
// live. VACUUM INTO reads one SQLite snapshot (including WAL content), writes
// to a private temporary directory, and atomically renames the completed file
// into place. Existing destination files are refused to avoid accidental
// overwrites; operators can choose a new timestamped path instead.
func (s *Store) Backup(ctx context.Context, output string) (string, error) {
	if s == nil || s.DB == nil {
		return "", errors.New("database is not open")
	}
	path, err := filepath.Abs(filepath.Clean(strings.TrimSpace(output)))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(output) == "" || path == "." {
		return "", errors.New("backup output path is required")
	}
	current := ""
	if !isSQLiteMemoryPath(s.Path) {
		current, err = sqliteArtifactPath(s.Path)
		if err != nil {
			return "", err
		}
		current, err = filepath.Abs(filepath.Clean(current))
		if err != nil {
			return "", err
		}
	}
	// Refuse the database and all SQLite sidecars. A sidecar destination could
	// otherwise corrupt a live database even though VACUUM INTO itself is safe.
	if current != "" && (path == current || strings.HasPrefix(path, current+"-")) {
		return "", errors.New("backup output must be different from the SQLite database and its sidecars")
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
			return "", fmt.Errorf("open SQLite backup source: %w", err)
		}
		backupSource = sourceStore
		defer sourceStore.Close()
	}
	return AtomicWriteFile(path, ".edgewatch-backup-", func(tempPath string) error {
		if _, err := backupSource.DB.ExecContext(ctx, `VACUUM INTO ?`, tempPath); err != nil {
			return fmt.Errorf("create SQLite backup: %w", err)
		}
		return enforcePrivateSQLiteArtifacts(tempPath)
	}, func(finalPath string) error {
		return enforcePrivateSQLiteArtifacts(finalPath)
	})
}
