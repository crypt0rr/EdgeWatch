package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/crypt0rr/edgewatch/internal/store"
)

const hostCLIActor = "host-cli"

// auditHostCommand records an explicitly mutating host-authorized operation
// using the already-open writable store. Read-only commands intentionally do
// not call this helper: adding an audit row would make verify, health, status,
// history, and baseline export mutate the database they promise to inspect.
func auditHostCommand(ctx context.Context, current *store.Store, entry store.AuditEntry) {
	if current == nil {
		logAuditFailure(entry.Action)
		return
	}
	entry.ActorUsername = hostCLIActor
	if err := current.AuditEntry(ctx, entry); err != nil {
		logAuditFailure(entry.Action)
	}
}

// auditHostCommandOnExisting is the explicit audited-write path for a
// successful operation that intentionally did not keep a writable store open,
// such as restore. It is never used by read-only inspection commands.
func auditHostCommandOnExisting(ctx context.Context, database string, entry store.AuditEntry) {
	auditor, err := store.OpenExistingContext(ctx, database)
	if err != nil {
		logAuditFailure(entry.Action)
		return
	}
	defer func() {
		if err := auditor.Close(); err != nil {
			logAuditFailure(entry.Action)
		}
	}()
	auditHostCommand(ctx, auditor, entry)
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

// scanAuditDetail records a host CLI scan with the same job ID the web run
// action audits, plus the outcome. The status is the scan's own terminal
// status; a run that returned an error is failed unless the scan was canceled
// or timed out. Targets and scanner arguments are never included.
func scanAuditDetail(jobID, scanStatus string, runErr error) string {
	status := scanStatus
	switch {
	case runErr != nil && status != "canceled" && status != "timed_out":
		status = "failed"
	case status == "":
		status = "success"
	}
	return fmt.Sprintf("job=%s status=%s", auditPathName(jobID), status)
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
	return store.AtomicWriteJSON(output, ".edgewatch-export-", func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	})
}
