package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func backup(ctx context.Context, s *store.Store, output, format string) error {
	path, err := s.Backup(ctx, output)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return printValue(format, map[string]any{"path": path, "bytes": info.Size()})
}

func verify(ctx context.Context, s *store.Store, format string) error {
	result, err := s.Verify(ctx)
	if printErr := printValue(format, result); printErr != nil {
		return printErr
	}
	return err
}

func exportBaseline(ctx context.Context, s *store.Store, job, output, format string) error {
	if strings.TrimSpace(output) == "" {
		return errors.New("--out is required")
	}
	export, err := s.ExportBaselines(ctx, job)
	if err != nil {
		return err
	}
	path, err := writeJSONFile(output, export)
	if err != nil {
		return err
	}
	if format == "json" {
		return printValue(format, map[string]any{"path": path, "jobs": len(export.Jobs), "format_version": export.FormatVersion})
	}
	fmt.Printf("baseline export written to %s (%d jobs)\n", path, len(export.Jobs))
	return nil
}

// writeJSONFile writes an export atomically with owner-only permissions. The
// destination must not already exist; refusing replacement prevents a typo in
// a scheduled backup/export command from destroying an older archive.
func writeJSONFile(output string, value any) (string, error) {
	path, err := filepath.Abs(filepath.Clean(strings.TrimSpace(output)))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(output) == "" {
		return "", errors.New("output path is required")
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
	tempDir, err := os.MkdirTemp(parent, ".edgewatch-export-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tempDir)
	if err := os.Chmod(tempDir, 0o700); err != nil {
		return "", err
	}
	tempPath := filepath.Join(tempDir, "export.json")
	file, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(value)
	syncErr := file.Sync()
	closeErr := file.Close()
	if encodeErr != nil {
		return "", encodeErr
	}
	if syncErr != nil {
		return "", syncErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if _, err := os.Lstat(path); err == nil {
		return "", errors.New("output was created concurrently")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return "", err
	}
	if err := syncOutputDirectory(parent); err != nil {
		return "", fmt.Errorf("sync output directory: %w", err)
	}
	return path, nil
}

func syncOutputDirectory(path string) error {
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
