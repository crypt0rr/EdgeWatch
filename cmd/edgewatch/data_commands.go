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

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/store"
)

const hostCLIActor = "host-cli"

// hostAuditor keeps the audit record of a host command: the TenantStore of
// the tenant whose data the command used, which records it in that tenant,
// or the Store for a command on the whole database, such as backup or
// restore.
type hostAuditor interface {
	AuditEntry(context.Context, store.AuditEntry) error
}

// auditHostCommand records an explicitly mutating host-authorized operation
// using the already-open writable store. Read-only commands intentionally do
// not call this helper: adding an audit row would make verify, health, status,
// history, and baseline export mutate the database they promise to inspect.
func auditHostCommand(ctx context.Context, current hostAuditor, entry store.AuditEntry) {
	if current == nil {
		logAuditFailure(entry.Action)
		return
	}
	entry.ActorUsername = hostCLIActor
	entry.ActorKind = store.AuditActorHost
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

// backup writes a backup that passed its checks, quick_check or with
// fullCheck integrity_check, and prints its path, size, schema version, and
// check results. A backup that fails a check is not published.
func backup(ctx context.Context, s *store.Store, output, format string, fullCheck bool) error {
	result, err := s.BackupWithOptions(ctx, output, store.BackupOptions{FullIntegrityCheck: fullCheck})
	if err != nil {
		return err
	}
	return printValue(format, result)
}

// verifyBackupFile is verify --from: it checks a backup file on a private
// copy, without the configured database, and with the configured keys. It
// prints the report even when a check fails, then fails.
func verifyBackupFile(ctx context.Context, cfg *config.Config, from string, allowKeyMismatch bool, format string) error {
	report, err := store.VerifyBackupFile(ctx, from, store.BackupFileOptions{LiveDatabase: cfg.Database, InspectStaged: stagedKeyCheck(cfg), AllowKeyMismatch: allowKeyMismatch})
	if printErr := printValue(format, report); printErr != nil {
		return errors.Join(err, printErr)
	}
	return keyMismatchHint(err)
}

// stagedKeyCheck opens a staged copy of a backup, read-only, with the keys
// that the daemon uses for cfg: notifications.encryption_key_file or
// notification.key beside the database, and web.auth_key_file or auth.key
// beside the database. It counts the web-managed destinations and TOTP seeds
// that they cannot open, and never creates a key.
func stagedKeyCheck(cfg *config.Config) store.StagedInspection {
	notificationKey := strings.TrimSpace(cfg.Notifications.EncryptionKeyFile)
	if notificationKey == "" {
		notificationKey = notify.DefaultKeyPath(cfg.Database)
	}
	authKey := strings.TrimSpace(cfg.Web.AuthKeyFile)
	if authKey == "" {
		authKey = store.DefaultAuthKeyPath(cfg.Database)
	}
	return func(ctx context.Context, path string) (store.RestoreKeyCheck, error) {
		var check store.RestoreKeyCheck
		staged, err := store.OpenReadOnlyExistingContext(ctx, path)
		if err != nil {
			return check, err
		}
		defer staged.Close()
		// The copy lies in a private directory, so its default key, beside
		// it, would never be the configured one.
		staged.SetAuthKeyPath(authKey)
		check.Destinations, check.DestinationsLocked, err = notify.CheckKey(ctx, staged, notificationKey)
		if err != nil {
			return check, err
		}
		check.TOTPSecrets, check.TOTPUnreadable, err = staged.System().TOTPKeyCheck(ctx)
		return check, err
	}
}

// keyMismatchHint names the files and the option that a refused key check
// leaves the operator.
func keyMismatchHint(err error) error {
	if errors.Is(err, store.ErrRestoreKeyMismatch) {
		return fmt.Errorf("%w; put the notification.key and auth.key that belong to the backup in place, or pass --allow-key-mismatch to accept the locked secrets", err)
	}
	return err
}

func verify(ctx context.Context, s *store.Store, format string) error {
	result, err := s.Verify(ctx)
	if printErr := printValue(format, result); printErr != nil {
		return printErr
	}
	return err
}

// exportBaseline writes the baselines of the jobs of the tenant of ts, or of
// its one job named job, to output.
func exportBaseline(ctx context.Context, ts *store.TenantStore, job, output, format string) error {
	if strings.TrimSpace(output) == "" {
		return errors.New("--out is required")
	}
	export, err := ts.ExportBaselines(ctx, job)
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
