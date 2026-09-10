package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DatabaseVerification is the bounded result of the SQLite consistency checks
// used by the verify command. SQLite reports integrity_check as one row, while
// foreign_key_check returns one row per violating relationship.
type DatabaseVerification struct {
	IntegrityCheck       string                `json:"integrity_check"`
	ForeignKeyViolations []ForeignKeyViolation `json:"foreign_key_violations"`
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
// writer connection. It intentionally does not mutate the database, making it
// safe to use against a live daemon or immediately after restoring a backup.
func (s *Store) Verify(ctx context.Context) (DatabaseVerification, error) {
	result := DatabaseVerification{ForeignKeyViolations: []ForeignKeyViolation{}}
	if s == nil || s.DB == nil {
		return result, errors.New("database is not open")
	}
	if err := s.DB.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result.IntegrityCheck); err != nil {
		return result, err
	}
	rows, err := s.DB.QueryContext(ctx, `PRAGMA foreign_key_check`)
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
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if err != nil {
		return "", fmt.Errorf("backup output directory: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("backup output parent is not a directory")
	}
	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("backup output must not be a symbolic link")
		}
		return "", errors.New("backup output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	tempDir, err := os.MkdirTemp(parent, ".edgewatch-backup-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tempDir)
	if err := os.Chmod(tempDir, 0o700); err != nil {
		return "", err
	}
	tempPath := filepath.Join(tempDir, "edgewatch.db")
	if _, err := s.DB.ExecContext(ctx, `VACUUM INTO ?`, tempPath); err != nil {
		return "", fmt.Errorf("create SQLite backup: %w", err)
	}
	if err := enforcePrivateSQLiteArtifacts(tempPath); err != nil {
		return "", err
	}
	file, err := os.OpenFile(tempPath, os.O_RDWR, 0o600)
	if err != nil {
		return "", err
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil {
		return "", syncErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	// Recheck immediately before the atomic rename. This still refuses a
	// concurrent destination creation rather than replacing an operator file.
	if _, err := os.Lstat(path); err == nil {
		return "", errors.New("backup output was created concurrently")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return "", err
	}
	if err := enforcePrivateSQLiteArtifacts(path); err != nil {
		return "", err
	}
	return path, nil
}

// BackupInfo is useful to callers that want a concise audit/CLI response
// without opening and decoding the backup contents.
type BackupInfo struct {
	Path      string    `json:"path"`
	Bytes     int64     `json:"bytes"`
	CreatedAt time.Time `json:"created_at"`
}
