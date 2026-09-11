package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/crypt0rr/edgewatch/internal/store"
)

const hostCLIActor = "host-cli"

// auditHostCommand records host-authorized data operations without making
// their success depend on the audit store. Read-only commands use a short
// independent writable connection solely for the audit insert; a read-only
// filesystem therefore leaves the useful verify/export result intact.
func auditHostCommand(ctx context.Context, database string, current *store.Store, currentWritable bool, entry store.AuditEntry) {
	entry.ActorUsername = hostCLIActor
	auditor := current
	closeAuditor := false
	if !currentWritable {
		var err error
		auditor, err = store.OpenExistingContext(ctx, database)
		if err != nil {
			logAuditFailure(entry.Action)
			return
		}
		closeAuditor = true
	}
	if auditor == nil {
		logAuditFailure(entry.Action)
		return
	}
	if err := auditor.AuditEntry(ctx, entry); err != nil {
		logAuditFailure(entry.Action)
	}
	if closeAuditor {
		if err := auditor.Close(); err != nil {
			logAuditFailure(entry.Action)
		}
	}
}

func logAuditFailure(action string) {
	slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})).Warn("security audit write unavailable", "action", action)
}

// hostAuditDetail deliberately includes only bounded, non-secret metadata.
// In particular it keeps the full database path, notification URLs, provider
// errors, and command arguments out of the append-only audit table.
func hostAuditDetail(label, path string, operationErr error) string {
	status := "success"
	if operationErr != nil {
		status = "failed"
	}
	return fmt.Sprintf("%s=%s status=%s", label, auditPathName(path), status)
}

func auditPathName(path string) string {
	name := filepath.Base(filepath.Clean(strings.TrimSpace(path)))
	if name == "." || name == string(filepath.Separator) || name == "" {
		return "unnamed"
	}
	name = strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._-", r) {
			return r
		}
		return '_'
	}, name)
	runes := []rune(name)
	if len(runes) > 96 {
		runes = runes[:96]
	}
	if len(runes) == 0 {
		return "unnamed"
	}
	return string(runes)
}

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
