package store

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// AtomicWriteFile creates a new owner-only file without ever replacing an
// existing destination. The writer receives a private temporary path; once it
// succeeds, the file is fsynced, atomically renamed, and the parent directory
// is synced so the directory entry survives a host crash.
//
// afterRename is optional and is run after the destination becomes visible.
// It is useful for format-specific companion-artifact checks (for example,
// SQLite mode enforcement) while retaining the common destination-safety and
// rename sequence for every export/backup writer.
func AtomicWriteFile(path, tempPrefix string, writer func(string) error, afterRename func(string) error) (string, error) {
	if writer == nil {
		return "", errors.New("atomic writer is required")
	}
	path, err := atomicOutputPath(path)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(tempPrefix) == "" {
		tempPrefix = ".edgewatch-output-"
	}
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if err != nil {
		return "", fmt.Errorf("output directory: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("output parent is not a directory")
	}
	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("output must not be a symbolic link")
		}
		return "", errors.New("output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	tempDir, err := os.MkdirTemp(parent, tempPrefix)
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tempDir)
	if err := os.Chmod(tempDir, 0o700); err != nil {
		return "", err
	}
	tempPath := filepath.Join(tempDir, "payload")
	if err := writer(tempPath); err != nil {
		return "", err
	}
	if err := os.Chmod(tempPath, 0o600); err != nil {
		return "", err
	}
	if err := syncFile(tempPath); err != nil {
		return "", err
	}
	if _, err := os.Lstat(path); err == nil {
		return "", errors.New("output was created concurrently")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return "", err
	}
	if afterRename != nil {
		if err := afterRename(path); err != nil {
			return "", err
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return "", err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return "", fmt.Errorf("sync output directory: %w", err)
	}
	return path, nil
}

func atomicOutputPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("output path is required")
	}
	abs, err := filepath.Abs(filepath.Clean(strings.TrimSpace(path)))
	if err != nil {
		return "", err
	}
	if abs == "." || abs == string(filepath.Separator) {
		return "", errors.New("output path is required")
	}
	return abs, nil
}

func syncFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0o600)
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

// syncDirectory makes an atomic rename durable. Without syncing the parent,
// a host crash after Rename can leave the directory entry missing even though
// the file itself was fully fsynced.
func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// AtomicWriteJSON is kept in the store package so command-line exports and
// other future JSON artifacts can share the same crash-safe destination
// semantics without exporting a JSON-specific file writer.
func AtomicWriteJSON(path, prefix string, marshal func(io.Writer) error) (string, error) {
	if marshal == nil {
		return "", errors.New("atomic JSON marshaler is required")
	}
	return AtomicWriteFile(path, prefix, func(tempPath string) error {
		file, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		writeErr := marshal(file)
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	}, nil)
}
