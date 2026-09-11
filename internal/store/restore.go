package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ErrRestoreSidecars is returned when a restore would leave SQLite sidecars
// from a different database next to the replacement file. SQLite does not
// expose a portable database identity in its WAL/SHM files, so an existing
// sidecar is treated as ambiguous rather than guessed to be safe.
var ErrRestoreSidecars = errors.New("restore refused because SQLite sidecars are present")

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
}

// RestoreResult describes a successfully replaced database file.
type RestoreResult struct {
	Path            string    `json:"path"`
	Bytes           int64     `json:"bytes"`
	RestoredAt      time.Time `json:"restored_at"`
	SidecarsPresent []string  `json:"sidecars_present,omitempty"`
	SidecarsWarning string    `json:"sidecars_warning,omitempty"`
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
// timestamps.
func Restore(ctx context.Context, source, destination string, options RestoreOptions) (RestoreResult, error) {
	var result RestoreResult
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
	if err := os.Rename(tempPath, preflight.DestinationPath); err != nil {
		return result, fmt.Errorf("replace restored database: %w", err)
	}
	if err := os.Chmod(preflight.DestinationPath, 0o600); err != nil {
		return result, err
	}
	if err := syncDirectory(parent); err != nil {
		return result, fmt.Errorf("sync restored database directory: %w", err)
	}
	result = RestoreResult{Path: preflight.DestinationPath, Bytes: bytes, RestoredAt: time.Now().UTC()}
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

func restorePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("path is required")
	}
	if strings.HasPrefix(path, "file:") {
		decoded, err := sqliteArtifactPath(path)
		if err != nil {
			return "", err
		}
		path = decoded
	}
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
